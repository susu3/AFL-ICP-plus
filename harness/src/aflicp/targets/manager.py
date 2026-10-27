"""Known-recipe target manager. It never executes commands from a target README."""
import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
import urllib.parse
from pathlib import Path
from ..common import ICPError, command, file_hash, save_json


def _safe_repository(value):
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme:
        if parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.username or parsed.password:
            raise ICPError("Repository URL must be HTTPS github.com or a local path")
    elif not Path(value).exists():
        raise ICPError("Repository path does not exist")


def _copy_source_tree(source, destination):
    source = Path(source).resolve()
    for path in source.rglob("*"):
        if path.is_symlink():
            raise ICPError("Target source snapshots containing symlinks are not accepted")
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns(".git", "*.o", "*.a", ".libs", "autom4te.cache"))


def _checkout(store, repository, ref):
    if not ref:
        raise ICPError("target.ref is required so the tested source can be reproduced")
    _safe_repository(repository)
    cache = Path(store.config["paths"]["output_root"]) / "cache" / "repositories" / hashlib.sha256((repository + "\0" + ref).encode()).hexdigest()[:24]
    if cache.is_dir():
        resolved = command(["git", "rev-parse", "HEAD"], cwd=cache, timeout=5).strip()
        expected = command(["git", "rev-parse", ref], cwd=cache, timeout=5).strip()
        if resolved != expected:
            raise ICPError("Repository cache does not match configured revision")
        return cache, resolved
    if store.config["offline"] and urllib.parse.urlsplit(repository).scheme:
        raise ICPError("Offline mode has no cached repository at the requested ref", "offline")
    cache.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="checkout-", dir=str(cache.parent)))
    shutil.rmtree(staging)
    try:
        command(["git", "clone", "--no-tags", "--no-checkout", repository, str(staging)],
                timeout=store.config.get("target", {}).get("checkout_timeout_seconds", 600),
                log=store.root / "target" / "checkout.log")
        command(["git", "checkout", "--detach", ref], cwd=staging, timeout=120,
                log=store.root / "target" / "checkout-ref.log")
        commit = command(["git", "rev-parse", "HEAD"], cwd=staging, timeout=5).strip()
        if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
            raise ICPError("Git did not resolve to a full immutable commit")
        os.replace(staging, cache)
        return cache, commit
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise


def _patch_modbus_server(source, port):
    path = Path(source) / "tests" / "random-test-server.c"
    if not path.is_file():
        raise ICPError("Known libmodbus recipe requires tests/random-test-server.c")
    original = path.read_text()
    if "modbus_new_tcp(\"127.0.0.1\", port)" in original:
        return "already-parameterized"
    old_call = 'modbus_new_tcp("127.0.0.1", 1502)'
    if old_call not in original:
        raise ICPError("libmodbus target source differs from the supported pinned recipe; refusing a guessed patch")
    signature = re.search(r"int\s+main\s*\(\s*void\s*\)\s*\{", original)
    if not signature:
        raise ICPError("Cannot identify known libmodbus server main signature")
    replacement = ('int main(int argc, char **argv) {\n'
        '    char *end = NULL;\n'
        '    long port;\n'
        '    if (argc != 2) { fprintf(stderr, "Usage: %s port\\n", argv[0]); return 2; }\n'
        '    port = strtol(argv[1], &end, 10);\n'
        '    if (!end || *end || port < 1 || port > 65535) return 2;\n')
    updated = original[:signature.start()] + replacement + original[signature.end():]
    updated = updated.replace(old_call, 'modbus_new_tcp("127.0.0.1", (int)port)', 1)
    if "#include <stdlib.h>" not in updated:
        updated = "#include <stdlib.h>\n" + updated
    path.write_text(updated)
    return hashlib.sha256((original + "\0" + updated).encode()).hexdigest()


class TargetManager:
    def __init__(self, store):
        self.store = store
        self.config = store.config
        self.target = self.config["target"]

    def prepare(self, fuzzer, corpus):
        target_root = self.store.root / "target"
        target_root.mkdir(parents=True, exist_ok=True)
        source = None
        commit = None
        if self.target.get("executable"):
            executable = Path(self.target["executable"]).resolve()
            if not executable.is_file() or not os.access(executable, os.X_OK):
                raise ICPError("Configured target executable is not executable")
            argv = self.target.get("launch_argv", [])
            if not isinstance(argv, list) or any(not isinstance(a, str) for a in argv):
                raise ICPError("target.launch_argv must be an argv list")
        else:
            if self.target.get("recipe") != "libmodbus":
                raise ICPError("No validated recipe exists for this target; provide a local executable or source profile")
            if self.target.get("source"):
                original = Path(self.target["source"]).resolve()
                if not original.is_dir():
                    raise ICPError("target.source is not a directory")
                source_hash = file_hash(original / ".git" / "HEAD") if (original / ".git" / "HEAD").exists() else None
                source = target_root / "source"
                if source.exists():
                    raise ICPError("Target source snapshot already exists")
                _copy_source_tree(original, source)
                if (original / ".git").is_dir():
                    commit = command(["git", "rev-parse", "HEAD"], cwd=original, timeout=5).strip()
            elif self.target.get("repository"):
                cache, commit = _checkout(self.store, self.target["repository"], self.target.get("ref"))
                source = target_root / "source"
                _copy_source_tree(cache, source)
            else:
                raise ICPError("Provide target.executable, target.source, or target.repository")
            patch_hash = _patch_modbus_server(source, int(self.target["port"]))
            build_image = self.target.get("build_image")
            docker = shutil.which("docker")
            if not docker:
                raise ICPError("A configured Docker runtime is required to build downloaded target source")
            if not build_image:
                raise ICPError("target.build_image must name the locally available pinned Linux/LLVM toolchain image")
            image_id = command([docker, "image", "inspect", "--format", "{{.Id}}", build_image], timeout=20).strip()
            if not image_id:
                raise ICPError("Configured build image is unavailable")
            engine = Path(fuzzer).resolve().parent
            if not (engine / "afl-clang-fast").is_file():
                raise ICPError("Target recipe requires a built afl-clang-fast in engine snapshot")
            uid = str(os.getuid()) + ":" + str(os.getgid())
            script = ("cd /src && ./autogen.sh && CC=/engine/afl-clang-fast AFL_PATH=/engine ./configure --enable-static "
                      "&& make clean all && cd tests && AFL_PATH=/engine /engine/afl-clang-fast random-test-server.c "
                      "-I../src ../src/.libs/libmodbus.a -o server")
            argv = [docker, "run", "--rm", "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                    "--pids-limit=256", "--memory=%dm" % self.target.get("build_memory_mb", 4096), "--cpus=%s" % self.target.get("build_cpus", 2),
                    "--user", uid, "--env", "CC=/engine/afl-clang-fast", "--env", "AFL_PATH=/engine",
                    "--mount", "type=bind,src=%s,dst=/src" % source.resolve(), "--mount",
                    "type=bind,src=%s,dst=/engine,readonly" % engine, image_id, "/bin/sh", "-lc", script]
            command(argv, timeout=self.target.get("build_timeout_seconds", 1800), log=target_root / "build.log")
            executable = source / "tests/server"
            if not executable.is_file() or not os.access(executable, os.X_OK):
                raise ICPError("Build did not create the native target server executable")
            self.patch_hash = patch_hash
            self.image_id = image_id
        self.executable = executable
        self.argv = [str(executable)] + [str(arg).replace("{port}", str(self.target["port"])) for arg in (argv if self.target.get("executable") else ["{port}"])]
        profile = {"schema_version": "1.0", "target_id": self.target.get("id", self.target.get("repository", str(executable))),
                   "repository": self.target.get("repository"), "requested_ref": self.target.get("ref"), "resolved_commit": commit,
                   "source_hash": self._source_hash(source), "recipe_version": "libmodbus-known-recipe-v1" if source else "prebuilt-v1",
                   "build_image_id": getattr(self, "image_id", self.target.get("build_image_id")),
                   "build_profile": self.target.get("build_profile", "prebuilt"), "executable_path": str(executable),
                   "executable_hash": file_hash(executable), "launch_argv": self.argv,
                   "environment_env": {key: value["from_env"] for key, value in self.target.get("environment", {}).items()}, "transport": "tcp",
                   "host": self.target["host"], "port": self.target["port"], "startup_wait_us": self.config["campaign"]["startup_wait_us"],
                   "cleanup_script": self.target.get("cleanup_script"), "cleanup_configuration": self.target.get("cleanup", {}),
                   "applied_patch_hashes": [getattr(self, "patch_hash", None)],
                   "validation_report": None}
        save_json(target_root / "target-profile.json", profile)
        self.store.register("target_profile", target_root / "target-profile.json", "target_manager")
        return profile

    @staticmethod
    def _source_hash(source):
        if not source:
            return None
        digest = hashlib.sha256()
        for path in sorted(Path(source).rglob("*")):
            if path.is_file() and not path.is_symlink() and ".git" not in path.parts:
                digest.update(str(path.relative_to(source)).encode()); digest.update(bytes.fromhex(file_hash(path)))
        return digest.hexdigest()
