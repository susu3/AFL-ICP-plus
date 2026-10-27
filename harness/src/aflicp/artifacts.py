import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from . import __version__
from .common import ICPError, append_jsonl, digest, file_hash, read_json, save_json, tree_manifest
from .config import fingerprint


@dataclass
class ArtifactRef:
    artifact_id: str
    artifact_type: str
    path: str
    sha256: str
    producer: str
    input_artifact_ids: list = field(default_factory=list)
    schema_version: str = "1.0"
    producer_version: str = __version__


class RunStore:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.manifest = read_json(self.root / "run_manifest.json")
        self.tasks = read_json(self.root / "task_state.json")
        self.config = read_json(self.root / "config.resolved.json")

    @classmethod
    def create(cls, config):
        root = Path(config["paths"]["output_root"]) / "runs" / (time.strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:10])
        root.mkdir(parents=True, exist_ok=False)
        save_json(root / "config.resolved.json", config)
        save_json(root / "run_manifest.json", {"schema_version": "1.0", "run_id": root.name,
                  "config_hash": fingerprint(config), "created_at": time.time(), "status": "preparing", "artifacts": {},
                  "implementation_version": __version__, "evidence_complete": False})
        save_json(root / "task_state.json", {})
        return cls(root)

    def save(self):
        save_json(self.root / "run_manifest.json", self.manifest)
        save_json(self.root / "task_state.json", self.tasks)

    def diagnostic(self, stage, error, **details):
        entry = {"time": time.time(), "stage": stage, "category": getattr(error, "category", "validation"),
                 "description": str(error), "retryable": getattr(error, "retryable", False), **details}
        append_jsonl(self.root / "diagnostics.jsonl", entry)
        return entry

    def register(self, name, path, producer, dependencies=()):
        path = Path(path).resolve()
        sha = digest(tree_manifest(path)) if path.is_dir() else file_hash(path)
        artifact = ArtifactRef(digest({"name": name, "sha256": sha, "inputs": list(dependencies)}), name,
                               str(path), sha, producer, list(dependencies))
        self.manifest["artifacts"][name] = asdict(artifact)
        self.save()
        return artifact.artifact_id

    def require(self, name):
        ref = self.manifest["artifacts"].get(name)
        if not ref:
            raise ICPError("Missing validated dependency: " + name)
        path = Path(ref["path"])
        if not path.exists():
            raise ICPError("Artifact missing: " + str(path))
        actual = digest(tree_manifest(path)) if path.is_dir() else file_hash(path)
        if actual != ref["sha256"]:
            raise ICPError("Artifact changed after validation: " + name)
        return path
