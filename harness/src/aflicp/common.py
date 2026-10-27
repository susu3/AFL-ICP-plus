import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path


class ICPError(Exception):
    def __init__(self, message, category="preparation", retryable=False):
        super().__init__(message)
        self.category, self.retryable = category, retryable


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def file_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def atomic_write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = value if isinstance(value, bytes) else value.encode("utf-8")
    fd, temporary = tempfile.mkstemp(prefix=".staging-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save_json(path, value):
    atomic_write(path, json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n")


def read_json(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def append_jsonl(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as stream:
        stream.write(canonical(value) + b"\n")
        stream.flush()


def load_mapping(text):
    # JSON is a strict YAML subset and keeps the core package dependency-free.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml
        except ImportError as exc:
            raise ICPError("YAML input requires PyYAML; JSON is supported without dependencies", "configuration") from exc
        return yaml.safe_load(text)


def contained(root, relative):
    root = Path(root).resolve()
    path = (root / relative).resolve()
    if path != root and root not in path.parents:
        raise ICPError("Path escapes artifact root: " + str(relative))
    return path


def tree_manifest(root):
    root = Path(root)
    return {str(p.relative_to(root)): file_hash(p) for p in sorted(root.rglob("*")) if p.is_file() and not p.is_symlink()}


def command(argv, cwd=None, env=None, timeout=300, log=None):
    try:
        result = subprocess.run([str(x) for x in argv], cwd=cwd, env=env, timeout=timeout,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ICPError(str(exc), "execution", retryable=True) from exc
    if log:
        atomic_write(log, result.stdout)
    if result.returncode:
        raise ICPError("Command failed (%d): %s\n%s" % (result.returncode, argv[0], result.stdout.decode(errors="replace")[-12000:]), "execution", True)
    return result.stdout.decode(errors="replace")
