"""Command line entry point for deterministic preparation and campaigns."""
import argparse
import json
import shutil
import sys
import tarfile
import time
from pathlib import Path

from . import __version__
from .agents import adaptation, seeds, specification
from .analysis import analyze
from .artifacts import RunStore
from .common import ICPError, file_hash, read_json, save_json, tree_manifest
from .config import load_config
from .llm.client import ModelClient
from .orchestrator import create_store, load_store, prepare, status
from .runners.campaign import CampaignRunner
from .targets.manager import TargetManager
from .knowledge.bundle import KnowledgeBundle


def _latest_run(config):
    root = Path(config["paths"]["output_root"]) / "runs"
    runs = sorted((path for path in root.iterdir() if path.is_dir()), reverse=True) if root.is_dir() else []
    if not runs:
        raise ICPError("No run exists under configured output_root")
    return runs[0].name


def _store(config_path, run_id, offline):
    config = load_config(config_path, offline)
    if not run_id:
        raise ICPError("--run-id is required for this command", "configuration")
    return load_store(config_path, run_id, offline)


def _dump(value):
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))


def _validate(config_path, offline):
    config = load_config(config_path, offline)
    missing = [spec["path"] for spec in config["specifications"] if not Path(spec["path"]).is_file()]
    if missing:
        raise ICPError("Configured PDF files do not exist: " + ", ".join(missing), "configuration")
    seeds_path = Path(config["paths"]["user_seeds"])
    if not seeds_path.is_dir():
        raise ICPError("paths.user_seeds is not a directory", "configuration")
    if not any(p.is_file() and not p.is_symlink() and p.stat().st_size for p in seeds_path.rglob("*")):
        raise ICPError("paths.user_seeds contains no nonempty regular files", "configuration")
    result = {"status": "valid", "protocol": config["protocol"], "specifications": len(config["specifications"]),
              "user_seed_files": sum(1 for p in seeds_path.rglob("*") if p.is_file() and not p.is_symlink() and p.stat().st_size),
              "offline": config["offline"], "output_root": config["paths"]["output_root"],
              "note": "This command validates configuration only; it does not fetch/build a target or contact an LLM."}
    _dump(result)


def _step(store, name):
    model = ModelClient(store.config, store.root)
    if name == "specification":
        path = specification.prepare(store, model)
        return {"knowledge": str(path), "bundle_id": store.manifest.get("knowledge_bundle_id")}
    if name == "adapter":
        bundle = KnowledgeBundle(store.require("knowledge"))
        module = adaptation.prepare(store, model, bundle)
        engine_root = store.config["paths"].get("engine_root", str(Path(__file__).parents[3]))
        profile = adaptation.build_engine(store, engine_root, module)
        return {"adapter": str(module), "adapter_sha256": profile["adapter_sha256"]}
    if name == "seeds":
        bundle = KnowledgeBundle(store.require("knowledge"))
        return seeds.prepare(store, model, bundle)
    if name == "target":
        engine = read_json(store.root / "adapter" / "build-profile.json")
        source = Path(store.config["paths"]["user_seeds"])
        corpus = store.root / "corpus" / "user"
        corpus.mkdir(parents=True, exist_ok=True)
        if not any(corpus.iterdir()):
            files = sorted(p for p in source.rglob("*") if p.is_file() and not p.is_symlink() and p.stat().st_size)
            for i, path in enumerate(files):
                shutil.copyfile(path, corpus / ("%06d-user.bin" % i))
        profile = TargetManager(store).prepare(engine["binaries"]["afl-fuzz"]["path"], corpus)
        return {"target_profile": profile["target_id"], "target_sha256": profile["executable_hash"]}
    raise ICPError("Unknown preparation stage: " + name, "configuration")


def _usage_summary(run_root, start_line=0):
    path = Path(run_root) / "usage" / "usage.jsonl"
    totals = {"provider_calls": 0, "cache_hits": 0, "input_tokens": 0, "output_tokens": 0, "charged_cost": {}}
    if not path.exists():
        return totals
    for line in path.read_text().splitlines()[start_line:]:
        if not line:
            continue
        entry = json.loads(line)
        if entry.get("cached"):
            totals["cache_hits"] += 1
            continue
        totals["provider_calls"] += 1
        usage = entry.get("tokens") or {}
        totals["input_tokens"] += int(usage.get("prompt_tokens", usage.get("input_tokens", 0)) or 0)
        totals["output_tokens"] += int(usage.get("completion_tokens", usage.get("output_tokens", 0)) or 0)
        cost = entry.get("cost")
        if isinstance(cost, dict) and cost.get("amount") is not None:
            currency = cost.get("currency", "unknown")
            totals["charged_cost"][currency] = totals["charged_cost"].get(currency, 0.0) + float(cost["amount"])
    return totals


def _experiment(config_path, offline):
    config = load_config(config_path, offline)
    repetitions = config["experiment"]["repetitions"]
    summaries = []
    store = prepare(config)
    engine = read_json(store.root / "adapter" / "build-profile.json")
    expected = {"adapter_sha256": engine["adapter_sha256"], "fuzzer_sha256": engine["binaries"]["afl-fuzz"]["sha256"],
                "target_sha256": read_json(store.require("target_profile"))["executable_hash"],
                "c0_hashes": sorted(item["sha256"] for item in read_json(store.root / "corpus" / "user-manifest.json")),
                "corpus_hashes": tree_manifest(store.require("corpus"))}
    preparation_usage = _usage_summary(store.root)
    for index in range(repetitions):
        usage_path = store.root / "usage" / "usage.jsonl"
        usage_start = len(usage_path.read_text().splitlines()) if usage_path.exists() else 0
        campaign = CampaignRunner(store).run()
        result = analyze(store, ModelClient(store.config, store.root)) if store.config["evidence"]["enabled"] else None
        summaries.append({"repetition": index + 1, "run_id": store.manifest["run_id"], "campaign_id": campaign["campaign_id"],
                          "identity": expected, "analysis": result, "llm_usage": _usage_summary(store.root, usage_start)})
    report = {"schema_version": "1.0", "protocol": config["protocol"], "repetitions": summaries,
              "adapter_sha256": expected["adapter_sha256"], "fuzzer_sha256": expected["fuzzer_sha256"],
              "c0_sha256": expected["c0_hashes"], "corpus_sha256_by_file": expected["corpus_hashes"],
              "target_sha256": expected["target_sha256"], "preparation_llm_usage": preparation_usage,
              "created_at": time.time(), "note": "LLM token and charged-cost values are reported separately from fuzzing duration and execution metrics."}
    path = Path(config["paths"]["output_root"]) / "experiments" / ("%s-%d.json" % (config["protocol"].lower(), int(time.time())))
    save_json(path, report)
    _dump({"report": str(path), "status": "completed", "repetitions": len(summaries)})


def _export(store, destination):
    destination = Path(destination).resolve()
    if store.root == destination or store.root in destination.parents:
        raise ICPError("Export archive must be outside the run directory")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(destination, "w:gz") as archive:
        for path in sorted(store.root.rglob("*")):
            if path.is_symlink() or not path.is_file():
                continue
            relative = Path(store.root.name) / path.relative_to(store.root)
            info = archive.gettarinfo(str(path), arcname=str(relative))
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            with path.open("rb") as stream:
                archive.addfile(info, stream)
    return {"archive": str(destination), "sha256": file_hash(destination), "bytes": destination.stat().st_size}


def build_parser():
    parser = argparse.ArgumentParser(prog="aflicp", description="Deterministic, artifact-tracked ICS fuzzing workflow")
    parser.add_argument("--version", action="version", version="aflicp " + __version__)
    commands = parser.add_subparsers(dest="command", required=True)
    def config_options(command_parser, with_run=False):
        command_parser.add_argument("--config", required=True, help="YAML/JSON campaign configuration")
        command_parser.add_argument("--offline", action="store_true", help="Require locally cached inputs/models/toolchains")
        if with_run:
            command_parser.add_argument("--run-id", required=True, help="Existing prepared run ID")
    validate_parser = commands.add_parser("validate-config")
    config_options(validate_parser)
    prepare_parser = commands.add_parser("prepare", help="Run the deterministic preparation DAG")
    config_options(prepare_parser)
    run_parser = commands.add_parser("run", help="Run one configured campaign against the local lab target")
    config_options(run_parser, True)
    resume_parser = commands.add_parser("resume", help="Resume a stopped campaign with identical binaries and evidence")
    config_options(resume_parser, True)
    analyze_parser = commands.add_parser("analyze", help="Replay and source-review completed local campaign evidence")
    config_options(analyze_parser, True)
    status_parser = commands.add_parser("status")
    config_options(status_parser, True)
    experiment_parser = commands.add_parser("experiment", help="Run identical configured repetitions")
    config_options(experiment_parser)
    export_parser = commands.add_parser("export", help="Archive all run artifacts for transfer/reproduction")
    config_options(export_parser, True)
    export_parser.add_argument("--output", required=True, help="Destination .tar.gz outside the run directory")
    for stage in ("target", "specification", "adapter", "seeds"):
        group = commands.add_parser(stage, help="Prepare a single deterministic DAG stage")
        sub = group.add_subparsers(dest="stage_command", required=True)
        stage_prepare = sub.add_parser("prepare")
        config_options(stage_prepare, True)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "validate-config":
            _validate(args.config, args.offline)
        elif args.command == "prepare":
            store = prepare(load_config(args.config, args.offline))
            _dump({"run_id": store.manifest["run_id"], "status": store.manifest["status"], "root": str(store.root)})
        elif args.command in ("run", "resume"):
            store = _store(args.config, args.run_id, args.offline)
            _dump(CampaignRunner(store).run(resume=args.command == "resume"))
        elif args.command == "analyze":
            store = _store(args.config, args.run_id, args.offline)
            _dump(analyze(store, ModelClient(store.config, store.root)))
        elif args.command == "status":
            store = _store(args.config, args.run_id, args.offline)
            _dump(status(store))
        elif args.command == "experiment":
            _experiment(args.config, args.offline)
        elif args.command == "export":
            _dump(_export(_store(args.config, args.run_id, args.offline), args.output))
        elif args.command in ("target", "specification", "adapter", "seeds"):
            store = _store(args.config, args.run_id, args.offline)
            _dump(_step(store, args.command))
        return 0
    except ICPError as exc:
        print(json.dumps({"status": "error", "category": exc.category, "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "error", "category": "input_or_artifact", "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(json.dumps({"status": "interrupted", "message": "Interrupted by operator"}), file=sys.stderr)
        return 130

