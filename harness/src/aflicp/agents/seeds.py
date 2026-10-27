import ast
import hashlib
import json
import shutil
from collections import Counter
from pathlib import Path
from ..common import ICPError, atomic_write, file_hash, save_json, tree_manifest
from ..llm.client import require_review
from ..seeds.corpus import merge_corpus
from ..seeds.sandbox import run_generator

ALLOWED_IMPORTS = {"struct", "math", "itertools", "typing", "dataclasses", "aflicp.seeds.sdk"}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__", "open", "input", "breakpoint"}


def validate_program(source):
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise ICPError("Seed program syntax error: " + str(exc), "generator", True) from exc
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name not in ALLOWED_IMPORTS:
                    raise ICPError("Seed program import is not allowlisted: " + alias.name)
        if isinstance(node, ast.ImportFrom) and node.module not in ALLOWED_IMPORTS:
            raise ICPError("Seed program import is not allowlisted: " + str(node.module))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_CALLS:
            raise ICPError("Seed program uses prohibited dynamic/file operation: " + node.func.id)
        if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            raise ICPError("Seed program dunder access is prohibited")
    functions = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "generate"]
    if len(functions) != 1:
        raise ICPError("Seed program must define exactly one generate(context) function")


def prepare(store, model, bundle):
    c0 = Path(store.config["paths"]["user_seeds"])
    originals = sorted(p for p in c0.rglob("*") if p.is_file() and not p.is_symlink()) if c0.is_dir() else []
    if not originals:
        raise ICPError("User C0 directory is empty or missing")
    for attempt in range(store.config["repair"]["generator_max_retries"] + 1):
        try:
            cached_input = store.config.get("reuse", {}).get("corpus_input")
            if cached_input:
                gate_path = store.config.get("reuse", {}).get("corpus_validation")
                if not gate_path:
                    raise ICPError("Cached corpus requires reuse.corpus_validation manifest")
                gate = json.loads(Path(gate_path).read_text())
                if gate.get("status") != "validated" or gate.get("knowledge_bundle_id") != bundle.manifest["bundle_id"]:
                    raise ICPError("Cached corpus gate is not validated for this knowledge bundle")
                input_path = Path(cached_input).resolve()
                if tree_manifest(input_path) != gate.get("input_hashes"):
                    raise ICPError("Cached corpus file hashes do not match manifest")
                source_hashes = sorted(file_hash(p) for p in c0.rglob("*") if p.is_file() and not p.is_symlink() and p.stat().st_size)
                if source_hashes != sorted(gate.get("c0_hashes", [])):
                    raise ICPError("Cached corpus was prepared from different user C0 seeds")
                destination = store.root / "corpus" / "input"
                destination.mkdir(parents=True)
                for source in sorted(input_path.iterdir()):
                    if not source.is_file() or source.is_symlink() or not source.stat().st_size:
                        raise ICPError("Cached -i corpus must contain only nonempty regular binary files")
                    shutil.copyfile(source, destination / source.name)
                if not any(destination.iterdir()):
                    raise ICPError("Cached -i corpus is empty")
                _snapshot_c0(store, c0)
                report = {"mode": "reused-corpus", "final_count": len(list(destination.iterdir())), "c0_hashes": source_hashes,
                          "input_hashes": tree_manifest(destination), "knowledge_bundle_id": bundle.manifest["bundle_id"]}
                save_json(store.root / "corpus" / "corpus-manifest.json", report)
                store.register("corpus", destination, "validated_cache", [bundle.manifest["bundle_id"]])
                return report

            generator_source = store.config.get("reuse", {}).get("generator_source")
            if generator_source:
                validation_path = store.config.get("reuse", {}).get("generator_validation")
                if not validation_path:
                    raise ICPError("Reused generator requires reuse.generator_validation")
                gate = json.loads(Path(validation_path).read_text())
                if gate.get("status") != "validated" or gate.get("source_sha256") != file_hash(generator_source) or gate.get("knowledge_bundle_id") != bundle.manifest["bundle_id"] or gate.get("reviewer_passed") is not True:
                    raise ICPError("Generator validation record does not match source, reviewer and knowledge")
                program = Path(generator_source).read_text()
                review = {"status": "validated-reuse-gate", "validation_manifest": str(validation_path)}
            else:
                response = model.call("coding", "seed_generator", {"knowledge": bundle.select_context("seed"),
                    "candidate_budget": store.config["seeds"]["candidate_budget"], "random_seed": store.config["seeds"]["random_seed"],
                    "max_seed_bytes": store.config["seeds"]["max_seed_bytes"], "max_sequence_messages": store.config["seeds"]["max_sequence_messages"],
                    "diagnostics": store.tasks.get("generator_diagnostics", [])})
                program = response.get("source_code")
                validate_program(program)
                review = model.call("coding", "seed_review", {"source_code": program, "knowledge": bundle.select_context("seed")})
                require_review(review)
                store.tasks.setdefault("generator_review", []).append(review)
            validate_program(program)
            attempt_root = store.root / "generator" / ("attempt-%03d" % (attempt + 1))
            attempt_root.mkdir(parents=True, exist_ok=False)
            atomic_write(attempt_root / "generator.py", program)
            save_json(attempt_root / "review.json", review)
            _snapshot_c0(store, c0)
            output, manifest = run_generator(store.config, store.root, bundle, program, attempt_root)
            shutil.copyfile(attempt_root / "generator.py", store.root / "generator" / "generator.py")
            save_json(attempt_root / "execution.json", manifest)
            report = merge_corpus(c0, output, store.root / "corpus" / "input", bundle, store.config)
            store.register("corpus", store.root / "corpus" / "input", "seed_synthesis_agent", [bundle.manifest["bundle_id"]])
            save_json(store.root / "corpus" / "corpus-report.json", report)
            return report
        except (ICPError, OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
            staging = store.root / "corpus" / ".input-staging-input"
            if staging.is_dir():
                shutil.rmtree(staging)
            item = store.diagnostic("seeds", exc, attempt=attempt)
            store.tasks.setdefault("generator_diagnostics", []).append(item)
            store.save()
    raise ICPError("Seed generation/validation budget exhausted")


def _snapshot_c0(store, c0):
    user_snapshot = store.root / "corpus" / "user"
    if user_snapshot.exists():
        return
    user_snapshot.mkdir(parents=True)
    snapshot_index = []
    for index, original in enumerate(sorted(p for p in c0.rglob("*") if p.is_file() and not p.is_symlink())):
        if original.stat().st_size == 0:
            continue
        name = "%06d-user.bin" % index
        shutil.copyfile(original, user_snapshot / name)
        snapshot_index.append({"source_name": str(original.relative_to(c0)), "path": name,
                               "sha256": file_hash(user_snapshot / name), "bytes": original.stat().st_size})
    save_json(store.root / "corpus" / "user-manifest.json", snapshot_index)
