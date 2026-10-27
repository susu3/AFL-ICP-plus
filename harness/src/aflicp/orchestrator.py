"""Deterministic dependency graph for the four specialist agents and target support."""
import os
import shutil
import time
from pathlib import Path
from . import __version__
from .agents import adaptation, seeds, specification
from .artifacts import RunStore
from .common import ICPError, file_hash, read_json, save_json
from .config import load_config
from .knowledge.bundle import KnowledgeBundle
from .llm.client import ModelClient
from .runners.campaign import CampaignRunner
from .targets.manager import TargetManager

DAG = {
    "document_and_knowledge": [], "protocol_adapter_and_engine": ["document_and_knowledge"],
    "initial_seeds": ["document_and_knowledge"], "target_profile": ["protocol_adapter_and_engine"],
    "representative_target_validation": ["target_profile", "initial_seeds"],
    "launch_barrier": ["document_and_knowledge", "protocol_adapter_and_engine", "initial_seeds", "representative_target_validation"],
    "campaign": ["launch_barrier"], "post_campaign_reasoning": ["campaign"]}
TASK_INPUTS = {"document_and_knowledge": (), "protocol_adapter_and_engine": ("knowledge",),
               "initial_seeds": ("knowledge",), "target_profile": ("engine", "corpus"),
               "representative_target_validation": ("engine", "corpus", "target_profile"),
               "launch_barrier": ("knowledge", "adapter_source", "engine", "corpus", "target_profile")}


def _task(store, name, action, max_retries=0):
    entry = store.tasks.setdefault(name, {"task_id": name, "status": "PENDING", "input_artifact_ids": [],
                                          "output_artifact_ids": [], "attempts": 0, "diagnostics": []})
    entry["input_artifact_ids"] = sorted(store.manifest["artifacts"][artifact]["artifact_id"]
                                         for artifact in TASK_INPUTS.get(name, ()) if artifact in store.manifest.get("artifacts", {}))
    if entry.get("status") == "VALIDATED" and entry.get("output_artifact_ids"):
        return None
    for attempt in range(max_retries + 1):
        entry.update({"status": "RUNNING", "attempts": attempt + 1, "started_at": time.time()})
        store.save()
        try:
            before_ids = {artifact["artifact_id"] for artifact in store.manifest.get("artifacts", {}).values()}
            value = action()
            after_ids = {artifact["artifact_id"] for artifact in store.manifest.get("artifacts", {}).values()}
            entry.update({"status": "VALIDATED", "completed_at": time.time(), "result": str(value) if value is not None else None,
                          "output_artifact_ids": sorted(after_ids - before_ids)})
            store.save()
            return value
        except BaseException as exc:
            diagnostic = store.diagnostic(name, exc, attempt=attempt)
            entry["diagnostics"].append(diagnostic)
            entry["status"] = "RETRY_PENDING" if getattr(exc, "retryable", False) and attempt < max_retries else "FAILED"
            store.save()
            if entry["status"] == "FAILED":
                raise
    return None


def create_store(config):
    store = RunStore.create(config)
    save_json(store.root / "dag.json", {"schema_version": "1.0", "dag": DAG, "created_by": __version__})
    return store


def load_store(config_path, run_id, offline=False):
    config = load_config(config_path, offline)
    root = (Path(config["paths"]["output_root"]) / "runs" / run_id).resolve()
    expected = (Path(config["paths"]["output_root"]) / "runs").resolve()
    if expected not in root.parents or not root.is_dir():
        raise ICPError("Run ID is not an existing child of configured output_root")
    return RunStore(root)


def _knowledge(store):
    root = store.require("knowledge")
    return KnowledgeBundle(root)


def _write_c0_snapshot(store):
    source = Path(store.config["paths"]["user_seeds"])
    if not source.is_dir():
        raise ICPError("paths.user_seeds does not exist")
    originals = sorted(p for p in source.rglob("*") if p.is_file() and not p.is_symlink() and p.stat().st_size)
    if not originals:
        raise ICPError("User C0 contains no nonempty regular file")
    destination = store.root / "corpus" / "user"
    if destination.exists():
        return destination
    destination.mkdir(parents=True)
    index = []
    for number, item in enumerate(originals):
        name = "%06d-user.bin" % number
        shutil.copyfile(item, destination / name)
        index.append({"source_name": str(item.relative_to(source)), "path": name, "sha256": file_hash(destination / name), "bytes": item.stat().st_size})
    save_json(store.root / "corpus" / "user-manifest.json", index)
    return destination


def launch_barrier(store):
    for name in ("knowledge", "adapter_source", "engine", "corpus", "target_profile"):
        store.require(name)
    knowledge = KnowledgeBundle(store.require("knowledge"))
    if knowledge.manifest.get("bundle_id") != store.manifest.get("knowledge_bundle_id"):
        raise ICPError("Knowledge and resolved run manifest refer to different bundle IDs")
    target = read_json(store.require("target_profile"))
    if not target.get("validation_report") or target["validation_report"].get("status") != "passed":
        raise ICPError("Target representative interaction validation has not passed")
    profile = read_json(store.root / "adapter" / "build-profile.json")
    if profile["protocol"] != store.config["protocol"] or file_hash(profile["adapter_module"]) != profile["adapter_sha256"]:
        raise ICPError("Adapter build profile does not match selected protocol/module")
    input_dir = store.require("corpus")
    files = [p for p in input_dir.iterdir() if p.is_file() and not p.is_symlink()]
    if not files or any(p.stat().st_size == 0 for p in files) or any(not p.name.endswith(".bin") for p in files):
        raise ICPError("Final AFLNet input directory must contain only nonempty raw binary .bin files")
    report = {"status": "passed", "knowledge_bundle_id": knowledge.manifest["bundle_id"],
              "adapter_sha256": profile["adapter_sha256"], "target_sha256": target["executable_hash"],
              "input_hashes": {p.name: file_hash(p) for p in sorted(files)}, "checked_at": time.time()}
    save_json(store.root / "launch-barrier.json", report)
    store.manifest["launch_barrier"] = report
    store.manifest["status"] = "ready"
    inputs = [store.manifest["artifacts"][name]["artifact_id"] for name in
              ("knowledge", "adapter_source", "engine", "corpus", "target_profile")]
    store.register("launch_barrier", store.root / "launch-barrier.json", "deterministic_launch_barrier", inputs)
    store.save()
    return report


def prepare(config, model=None, store=None):
    store = store or create_store(config)
    model = model or ModelClient(store.config, store.root)
    engine_root = store.config["paths"].get("engine_root", str(Path(__file__).parents[3]))
    _task(store, "document_and_knowledge", lambda: specification.prepare(store, model))
    bundle = _knowledge(store)
    def prepare_adapter():
        source = adaptation.prepare(store, model, bundle)
        engine = adaptation.build_engine(store, engine_root, source)
        return engine["binaries"]["afl-fuzz"]["path"]
    _task(store, "protocol_adapter_and_engine", prepare_adapter)
    _task(store, "initial_seeds", lambda: seeds.prepare(store, model, bundle))
    c0 = _write_c0_snapshot(store)
    binary = read_json(store.root / "adapter" / "build-profile.json")["binaries"]["afl-fuzz"]["path"]
    def target_profile():
        profile = TargetManager(store).prepare(binary, c0)
        store.register("target_profile", store.root / "target" / "target-profile.json", "target_manager",
                       [store.manifest["artifacts"][name]["artifact_id"] for name in ("engine", "corpus")])
        return profile["executable_path"]
    _task(store, "target_profile", target_profile)
    def validate_target():
        report = CampaignRunner(store).validate_target()
        store.register("target_profile", store.root / "target" / "target-profile.json", "representative_interaction_validation",
                       [store.manifest["artifacts"][name]["artifact_id"] for name in ("engine", "corpus")])
        return report["status"]
    _task(store, "representative_target_validation", validate_target)
    _task(store, "launch_barrier", lambda: launch_barrier(store))
    store.manifest["status"] = "prepared"
    store.save()
    return store


def config_path_for_run(store):
    return store.root / "config.resolved.json"


def status(store):
    return {"run_id": store.manifest["run_id"], "status": store.manifest.get("status"),
            "evidence_complete": store.manifest.get("evidence_complete"), "tasks": store.tasks,
            "artifacts": store.manifest.get("artifacts", {}), "active_campaign": store.manifest.get("active_campaign")}
