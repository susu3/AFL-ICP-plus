import json
import os
import signal
import subprocess
import time
import uuid
from pathlib import Path
from ..common import ICPError, atomic_write, command, file_hash, read_json, save_json
from .writer_client import WriterHandle


def command_for(store, profile, fuzzer, input_dir, output_dir):
    target = profile["target"]
    campaign = store.config["campaign"]
    argv = [str(fuzzer), "-i", str(input_dir), "-o", str(output_dir), "-P", store.config["protocol"],
            "-N", "tcp://%s/%d" % (target["host"], target["port"]),
            "-D", str(campaign["startup_wait_us"]), "-W", str(campaign["poll_wait_ms"]), "-w", str(campaign["socket_timeout_us"]),
            "-t", str(campaign["execution_timeout_ms"]), "-m", str(campaign["memory_limit_mb"]),
            "-q", str(campaign.get("state_selection", 2)), "-s", str(campaign.get("seed_selection", 1)),
            "-h", str(campaign.get("seed_schedule", 1)), "-b", str(campaign.get("feedback", 3)), "-E", "-K"]
    if target.get("cleanup_script"):
        argv += ["-c", str(target["cleanup_script"])]
    argv += [str(x) for x in campaign["aflnet_arguments"]]
    argv += ["--", *profile["launch_argv"]]
    return argv


class CampaignRunner:
    def __init__(self, store):
        self.store = store

    def _preflight(self):
        required = ("knowledge", "adapter_source", "engine", "corpus", "target_profile")
        for name in required:
            self.store.require(name)
        engine = read_json(self.store.root / "adapter" / "build-profile.json")
        target_path = self.store.require("target_profile")
        target = read_json(target_path)
        fuzzer = engine["binaries"]["afl-fuzz"]["path"]
        if file_hash(fuzzer) != engine["binaries"]["afl-fuzz"]["sha256"]:
            raise ICPError("AFLNet executable changed after adapter integration")
        if file_hash(target["executable_path"]) != target["executable_hash"]:
            raise ICPError("Target binary changed after profile validation")
        return engine, target, fuzzer

    def validate_target(self):
        engine, profile, fuzzer = self._preflight()
        output = self.store.root / "target" / "dry-run-validation"
        if output.exists():
            raise ICPError("Target dry-run output already exists")
        argv = command_for(self.store, {"target": profile, "launch_argv": profile["launch_argv"]}, fuzzer,
                           self.store.root / "corpus" / "user", output)
        env = os.environ.copy(); env["AFLICP_DRY_RUN_ONLY"] = "1"
        for name, env_name in profile.get("environment_env", {}).items():
            if env_name not in os.environ:
                raise ICPError("Missing target runtime environment variable: " + env_name, "configuration")
            env[name] = os.environ[env_name]
        timeout = self.store.config["campaign"]["execution_timeout_ms"] / 1000 * max(1, len(list((self.store.root / "corpus" / "user").iterdir()))) + 120
        try:
            stdout = command(argv, env=env, timeout=timeout, log=self.store.root / "target" / "dry-run.log")
        except ICPError:
            save_json(self.store.root / "target" / "validation.json", {"status": "failed", "argv": argv, "at": time.time()})
            raise
        report = {"status": "passed", "mode": "AFLICP_DRY_RUN_ONLY", "argv": argv,
                  "engine_hash": file_hash(fuzzer), "target_hash": profile["executable_hash"],
                  "c0_hashes": [file_hash(p) for p in sorted((self.store.root / "corpus" / "user").iterdir()) if p.is_file()],
                  "validated_at": time.time(), "output_tail": stdout[-4000:]}
        save_json(self.store.root / "target" / "validation.json", report)
        profile["validation_report"] = report
        save_json(self.store.root / "target" / "target-profile.json", profile)
        self.store.register("target_profile", self.store.root / "target" / "target-profile.json", "target_validation")
        return report

    @staticmethod
    def _stop_process_group(process):
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except OSError:
            return
        time.sleep(.1)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass

    def _persist_campaign(self, campaign):
        history = self.store.manifest.setdefault("campaign_history", [])
        replacement = [entry for entry in history if entry.get("campaign_id") != campaign["campaign_id"]]
        replacement.append(campaign)
        self.store.manifest["campaign_history"] = replacement
        self.store.manifest["active_campaign"] = campaign
        save_json(self.store.root / "campaign.json", campaign)
        save_json(self.store.root / "campaigns" / (campaign["campaign_id"] + ".json"), campaign)
        self.store.save()

    def run(self, resume=False):
        engine, profile, fuzzer = self._preflight()
        self.store.require("launch_barrier")
        if self.store.manifest.get("status") not in ("prepared", "ready", "campaign_completed", "campaign_incomplete", "analyzed", "analysis_incomplete"):
            raise ICPError("Campaign cannot start before the validated launch barrier")
        run_id = self.store.manifest["run_id"]
        campaign_id = run_id + "-campaign-" + uuid.uuid4().hex[:8]
        output = self.store.root / "fuzz" / campaign_id
        input_dir = self.store.root / "corpus" / "input"
        if resume:
            prior = self.store.manifest.get("active_campaign")
            if not prior or prior.get("status") != "incomplete" or not Path(prior["output"]).is_dir():
                raise ICPError("No stopped campaign in this run is available for resume")
            campaign_id = prior["campaign_id"]
            output = Path(prior["output"])
            input_dir = Path(prior["input"])
            if prior.get("fuzzer_hash") != file_hash(fuzzer):
                raise ICPError("Cannot resume with a different fuzzer/adapter binary")
        else:
            if output.exists():
                raise ICPError("Campaign output already exists")
            output.parent.mkdir(parents=True, exist_ok=True)
        interaction_root = self.store.root / "interactions" / "campaigns" / campaign_id
        interaction_root.mkdir(parents=True, exist_ok=True)
        counter = interaction_root / "execution-counter.json"
        initial_execution = initial_sample = 0
        if counter.exists():
            persisted = read_json(counter)
            initial_execution, initial_sample = persisted["execution_id"], persisted["sample_count"]
        identity = {"target_artifact_id": self.store.manifest["artifacts"]["target_profile"]["artifact_id"],
                    "adapter_artifact_id": self.store.manifest["artifacts"]["adapter_source"]["artifact_id"],
                    "knowledge_bundle_id": self.store.manifest.get("knowledge_bundle_id")}
        argv = command_for(self.store, {"target": profile, "launch_argv": profile["launch_argv"]}, fuzzer, input_dir, output)
        if resume:
            argv[argv.index(str(input_dir))] = "-"
        for name, env_name in profile.get("environment_env", {}).items():
            if env_name not in os.environ:
                raise ICPError("Missing target runtime environment variable: " + env_name, "configuration")
        writer = WriterHandle(interaction_root, self.store.config, campaign_id, counter)
        writer.start(initial_execution, initial_sample, identity)
        env = writer.env
        env["AFLICP_CAMPAIGN_ID"] = campaign_id
        for name, env_name in profile.get("environment_env", {}).items():
            env[name] = os.environ[env_name]
        campaign = {"campaign_id": campaign_id, "output": str(output), "input": str(input_dir), "argv": argv,
                    "evidence_root": str(interaction_root),
                    "started_at": time.time(), "duration_seconds": self.store.config["campaign"]["duration_seconds"],
                    "engine_hash": file_hash(fuzzer), "fuzzer_hash": file_hash(fuzzer), "adapter_hash": engine["adapter_sha256"],
                    "target_hash": profile["executable_hash"], "knowledge_bundle_id": self.store.manifest.get("knowledge_bundle_id"),
                    "corpus_hash": self.store.manifest["artifacts"]["corpus"]["sha256"], "resume": resume,
                    "evidence_enabled": self.store.config["evidence"]["enabled"], "status": "running"}
        self.store.manifest["evidence_complete"] = False
        self.store.manifest["active_campaign"] = campaign
        self.store.manifest["status"] = "campaign_running"
        self._persist_campaign(campaign)
        try:
            stdout_path = self.store.root / "fuzz" / (campaign_id + ".stdout.log")
            stderr_path = self.store.root / "fuzz" / (campaign_id + ".stderr.log")
            with stdout_path.open("ab") as stdout, stderr_path.open("ab") as stderr:
                process = subprocess.Popen(argv, env=env, cwd=Path(fuzzer).parent, stdin=subprocess.DEVNULL,
                                           stdout=stdout, stderr=stderr, start_new_session=True)
                campaign["pid"] = process.pid
                self._persist_campaign(campaign)
                deadline = time.monotonic() + self.store.config["campaign"]["duration_seconds"]
                try:
                    while process.poll() is None and time.monotonic() < deadline:
                        writer.check()
                        time.sleep(min(1.0, max(0.05, deadline - time.monotonic())))
                    if process.poll() is None:
                        process.send_signal(signal.SIGINT)
                    try:
                        code = process.wait(timeout=self.store.config["campaign"]["stop_timeout_seconds"])
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                        raise ICPError("Fuzzer failed to stop cleanly; campaign evidence is incomplete")
                    if code != 0:
                        raise ICPError("Fuzzer exited with status %d" % code)
                    self._stop_process_group(process)
                    writer.finish(self.store.config["campaign"]["stop_timeout_seconds"])
                except BaseException:
                    if process.poll() is None:
                        process.send_signal(signal.SIGINT)
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill(); process.wait()
                    self._stop_process_group(process)
                    try:
                        writer.finish(5)
                    except Exception:
                        pass
                    raise
        except BaseException:
            campaign["status"] = "incomplete"
            self.store.manifest["evidence_complete"] = False
            self.store.manifest["status"] = "campaign_incomplete"
            self._persist_campaign(campaign)
            if writer.process and writer.process.poll() is None:
                writer.process.terminate()
                try:
                    writer.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    writer.process.kill(); writer.process.wait()
            raise
        campaign["status"] = "completed"
        campaign["completed_at"] = time.time()
        writer_status = interaction_root / "interactions" / "writer-status.json"
        campaign["evidence"] = read_json(writer_status) if writer_status.exists() else {"status": "disabled"}
        self.store.manifest["status"] = "campaign_completed"
        self.store.manifest["active_campaign"] = campaign
        self.store.manifest["evidence_complete"] = not self.store.config["evidence"]["enabled"] or campaign["evidence"].get("status") == "complete"
        self.store.save()
        self._persist_campaign(campaign)
        return campaign
