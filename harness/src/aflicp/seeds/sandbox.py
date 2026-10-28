"""Run the generated seed program in a restricted local Linux sandbox."""
import json
import os
import resource
import shutil
import stat
import subprocess
import time
from pathlib import Path

from ..common import ICPError, atomic_write, command, digest, save_json


def _prepare_inputs(config, bundle, program, attempt_root):
    base = Path(attempt_root)
    source_dir, output = base / "program", base / "generated_raw"
    source_dir.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    atomic_write(source_dir / "generator.py", program)
    input_path = source_dir / "context.json"
    save_json(input_path, {"bundle_id": bundle.manifest["bundle_id"], "protocol": bundle.protocol,
                           "client_schema": bundle.roles["client"]["packets"], "server_schema": bundle.roles["server"]["packets"],
                           "random_seed": config["seeds"]["random_seed"]})
    os.chmod(output, stat.S_IRWXU)
    return base, source_dir, output, input_path


def _run_bubblewrap(config, source_dir, output, base):
    bwrap = shutil.which("bwrap")
    if not bwrap:
        raise ICPError("bubblewrap (bwrap) is required for local no-network seed-generator isolation", "sandbox")
    if os.geteuid() == 0:
        raise ICPError("Run AFL-ICP+ as an unprivileged Linux user; bubblewrap seed isolation refuses root execution", "sandbox")
    python = Path("/usr/bin/python3")
    if not python.is_file():
        raise ICPError("/usr/bin/python3 is required by the local generator sandbox", "sandbox")

    package_dir = Path(__file__).resolve().parents[1]
    sandbox = config["seeds"]["sandbox"]
    args = [bwrap, "--die-with-parent", "--new-session", "--unshare-user", "--unshare-net", "--unshare-pid", "--unshare-ipc",
            "--unshare-uts", "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev",
            "--tmpfs", "/tmp", "--tmpfs", "/run", "--tmpfs", "/root", "--tmpfs", "/home",
            "--dir", "/tmp/input", "--dir", "/tmp/lib", "--dir", "/tmp/output",
            "--ro-bind", str(source_dir.resolve()), "/tmp/input", "--ro-bind", str(package_dir), "/tmp/lib/aflicp",
            "--bind", str(output.resolve()), "/tmp/output", "--chdir", "/tmp", "--uid", "65534", "--gid", "65534",
            str(python), "-B", "-m", "aflicp.seeds.worker", "/tmp/input/generator.py", "/tmp/input/context.json", "/tmp/output",
            str(config["seeds"]["candidate_budget"]), str(config["seeds"]["max_seed_bytes"]),
            str(config["seeds"]["max_sequence_messages"])]
    environment = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "PYTHONPATH": "/tmp/lib",
                   "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"}
    timeout = int(sandbox["timeout_seconds"])
    memory = int(sandbox["memory_mb"]) * 1024 * 1024
    max_file = int(config["seeds"]["max_seed_bytes"]) + 65536

    def set_limits():
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        resource.setrlimit(resource.RLIMIT_CPU, (timeout, timeout + 1))
        resource.setrlimit(resource.RLIMIT_FSIZE, (max_file, max_file))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        if hasattr(resource, "RLIMIT_NPROC"):
            resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))

    log = base / "sandbox.log"
    try:
        result = subprocess.run(args, env=environment, cwd="/", stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=timeout, check=False, preexec_fn=set_limits)
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        raise ICPError("Local seed sandbox failed: " + str(exc), "sandbox", True) from exc
    atomic_write(log, result.stdout)
    if result.returncode:
        raise ICPError("Local seed sandbox exited with status %d\n%s" %
                       (result.returncode, result.stdout.decode(errors="replace")[-12000:]), "sandbox", True)
    return {"backend": "bubblewrap", "limits": sandbox}


def _run_docker(config, source_dir, output, base):
    docker = shutil.which("docker")
    sandbox = config["seeds"]["sandbox"]
    if not docker:
        raise ICPError("Docker was selected for seed isolation but is not installed", "sandbox")
    image = sandbox.get("image")
    if not image:
        raise ICPError("seeds.sandbox.image is required when backend=docker", "configuration")
    inspect = command([docker, "image", "inspect", "--format", "{{.Id}}", image], timeout=20).strip()
    if not inspect:
        raise ICPError("Configured generator image is not present locally", "sandbox")
    if config["offline"] and not inspect.startswith("sha256:"):
        raise ICPError("Cannot identify local sandbox image", "sandbox")
    argv = [docker, "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--pids-limit=64", "--memory=%dm" % sandbox["memory_mb"], "--cpus=%s" % sandbox["cpu_limit"],
            "--user", "65534:65534", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
            "--mount", "type=bind,src=%s,dst=/input,readonly" % source_dir.resolve(),
            "--mount", "type=bind,src=%s,dst=/output" % output.resolve(),
            "--entrypoint", "python3", inspect, "-m", "aflicp.seeds.worker", "/input/generator.py", "/input/context.json", "/output",
            str(config["seeds"]["candidate_budget"]), str(config["seeds"]["max_seed_bytes"]),
            str(config["seeds"]["max_sequence_messages"])]
    environment = {k: v for k, v in os.environ.items() if k in ("PATH", "DOCKER_HOST", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY")}
    command(argv, env=environment, timeout=sandbox["timeout_seconds"], log=base / "sandbox.log")
    return {"backend": "docker", "image": image, "image_id": inspect, "limits": sandbox}


def run_generator(config, root, bundle, program, attempt_root):
    base, source_dir, output, input_path = _prepare_inputs(config, bundle, program, attempt_root)
    backend = config["seeds"]["sandbox"].get("backend", "bubblewrap")
    if backend == "bubblewrap":
        sandbox_metadata = _run_bubblewrap(config, source_dir, output, base)
    elif backend == "docker":
        sandbox_metadata = _run_docker(config, source_dir, output, base)
    else:
        raise ICPError("Unsupported seed sandbox backend: " + str(backend), "configuration")

    result_path = output / "worker-result.json"
    if result_path.is_symlink() or not result_path.is_file() or result_path.stat().st_size > 1024:
        raise ICPError("Generator worker result must be a small regular file")
    result = json.loads(result_path.read_text())
    if not isinstance(result, dict) or type(result.get("candidate_count")) is not int or not 0 <= result["candidate_count"] <= config["seeds"]["candidate_budget"]:
        raise ICPError("Generator worker returned an invalid candidate count")
    metadata = dict(sandbox_metadata)
    metadata.update({"program_hash": digest(program.encode()), "context_hash": digest(input_path.read_bytes()),
                     "seed_count": result["candidate_count"], "sandbox_limits": config["seeds"]["sandbox"],
                     "completed_at": time.time()})
    save_json(base / "generator-manifest.json", metadata)
    return output, metadata
