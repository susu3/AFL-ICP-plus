import json
import os
import shutil
import stat
import time
from pathlib import Path
from ..common import ICPError, atomic_write, command, digest, save_json


def run_generator(config, root, bundle, program, attempt_root):
    docker = shutil.which("docker")
    sandbox = config["seeds"]["sandbox"]
    if not docker:
        raise ICPError("Docker is required for generated-code isolation; no unsandboxed fallback is permitted", "sandbox")
    image = sandbox.get("image")
    if not image:
        raise ICPError("seeds.sandbox.image is required", "configuration")
    inspect = command([docker, "image", "inspect", "--format", "{{.Id}}", image], timeout=20).strip()
    if not inspect:
        raise ICPError("Configured generator image is not present locally", "sandbox")
    if config["offline"] and not inspect.startswith("sha256:"):
        raise ICPError("Cannot identify local sandbox image", "sandbox")
    base = Path(attempt_root)
    source_dir, output = base / "program", base / "generated_raw"
    source_dir.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    atomic_write(source_dir / "generator.py", program)
    input_path = source_dir / "context.json"
    save_json(input_path, {"bundle_id": bundle.manifest["bundle_id"], "protocol": bundle.protocol,
                           "client_schema": bundle.roles["client"]["packets"], "server_schema": bundle.roles["server"]["packets"],
                           "random_seed": config["seeds"]["random_seed"]})
    # The mounted run-local output is writable only by the disposable non-root container.
    os.chmod(output, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
    argv = [docker, "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--pids-limit=64", "--memory=%dm" % sandbox["memory_mb"], "--cpus=%s" % sandbox["cpu_limit"],
            "--user", "65534:65534", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
            "--mount", "type=bind,src=%s,dst=/input,readonly" % source_dir.resolve(),
            "--mount", "type=bind,src=%s,dst=/output" % output.resolve(),
            "--entrypoint", "python3", inspect, "-m", "aflicp.seeds.worker", "/input/generator.py", "/input/context.json", "/output",
            str(config["seeds"]["candidate_budget"]), str(config["seeds"]["max_seed_bytes"]),
            str(config["seeds"]["max_sequence_messages"])]
    environment = {k: v for k, v in os.environ.items() if k in ("PATH", "DOCKER_HOST", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY")}
    log = base / "sandbox.log"
    command(argv, env=environment, timeout=sandbox["timeout_seconds"], log=log)
    result_path = output / "worker-result.json"
    if result_path.is_symlink() or not result_path.is_file() or result_path.stat().st_size > 1024:
        raise ICPError("Generator worker result must be a small regular file")
    result = json.loads(result_path.read_text())
    if not isinstance(result, dict) or type(result.get("candidate_count")) is not int or not 0 <= result["candidate_count"] <= config["seeds"]["candidate_budget"]:
        raise ICPError("Generator worker returned an invalid candidate count")
    metadata = {"image": image, "image_id": inspect, "program_hash": digest(program.encode()), "context_hash": digest(input_path.read_bytes()),
                "seed_count": result["candidate_count"], "sandbox_limits": sandbox, "completed_at": time.time()}
    save_json(base / "generator-manifest.json", metadata)
    return output, metadata
