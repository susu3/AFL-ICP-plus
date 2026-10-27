import os
import subprocess
import sys
import time
from pathlib import Path
from ..common import ICPError, read_json


class WriterHandle:
    def __init__(self, root, config, campaign_id, counter=None):
        self.root, self.config, self.campaign_id = Path(root), config, campaign_id
        self.env = os.environ.copy()
        for key in list(self.env):
            if any(part in key.upper() for part in ("API_KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")):
                self.env.pop(key, None)
        self.process = None
        self.socket_path = Path("/tmp") / ("aflicp-" + campaign_id[:24] + ".sock")
        self.counter = counter

    def start(self, initial_execution=0, initial_sample=0, identity=None):
        if not self.config["evidence"]["enabled"]:
            return
        ready = self.root / "interactions" / "writer-ready"
        ready.parent.mkdir(parents=True, exist_ok=True)
        for stale in (ready, self.root / "interactions" / "writer-status.json", self.root / "interactions" / "writer-heartbeat"):
            try:
                stale.unlink()
            except FileNotFoundError:
                pass
        identity_path = self.root / "interactions" / ("identity-" + self.campaign_id + ".json")
        from ..common import save_json
        save_json(identity_path, identity or {})
        args = [sys.executable, "-m", "aflicp.runners.evidence_writer", "--root", str(self.root), "--campaign-id", self.campaign_id,
                "--max-record-bytes", str(self.config["evidence"]["max_record_bytes"]),
                "--queue-capacity-bytes", str(self.config["evidence"]["queue_capacity_bytes"]),
                "--pack-segment-bytes", str(self.config["evidence"]["pack_segment_bytes"]), "--identity-file", str(identity_path)]
        with (self.root / "interactions" / "writer.stdout.log").open("ab") as stdout, \
             (self.root / "interactions" / "writer.stderr.log").open("ab") as stderr:
            self.process = subprocess.Popen(args, env=self.env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if ready.exists() and ready.read_text() == self.campaign_id:
                break
            if self.process.poll() is not None:
                raise ICPError("Evidence writer exited before ready")
            time.sleep(.02)
        else:
            self.process.terminate(); self.process.wait(timeout=2)
            raise ICPError("Evidence writer did not become ready")
        self.env.update({"AFLICP_EVIDENCE_SOCKET": str(self.socket_path),
                         "AFLICP_SAMPLE_INTERVAL": str(self.config["evidence"]["periodic_interval"]),
                         "AFLICP_MAX_RECORD_BYTES": str(self.config["evidence"]["max_record_bytes"]),
                         "AFLICP_QUEUE_BYTES": str(self.config["evidence"]["queue_capacity_bytes"]),
                         "AFLICP_EXECUTION_START": str(initial_execution), "AFLICP_SAMPLE_START": str(initial_sample),
                         "AFLICP_SAVE_BITMAP": str(int(self.config["evidence"]["save_coverage_bitmap"]))})
        if self.counter:
            self.env["AFLICP_COUNTER_PATH"] = str(self.counter)

    def check(self):
        if self.process and self.process.poll() is not None:
            status = self.root / "interactions" / "writer-status.json"
            details = read_json(status) if status.exists() else {}
            raise ICPError("Evidence writer failed: " + str(details))
        if self.process:
            heartbeat = self.root / "interactions" / "writer-heartbeat"
            if not heartbeat.exists():
                return
            age = time.time() - heartbeat.stat().st_mtime
            if age > self.config["evidence"]["writer_stall_timeout_seconds"]:
                self.process.kill(); self.process.wait()
                raise ICPError("Evidence writer made no progress within the configured stall timeout; campaign must be marked incomplete")

    def finish(self, timeout=30):
        if not self.process:
            return
        try:
            code = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            self.process.kill(); self.process.wait()
            raise ICPError("Evidence writer did not drain and acknowledge finish") from exc
        status = self.root / "interactions" / "writer-status.json"
        details = read_json(status) if status.exists() else {}
        if code or details.get("status") != "complete":
            raise ICPError("Evidence writer incomplete: " + str(details))
        self.root.joinpath("interactions", "writer-ready").unlink(missing_ok=True)
