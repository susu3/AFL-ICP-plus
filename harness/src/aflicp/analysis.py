"""Source-grounded, replay-gated analysis of local campaign evidence."""
import hashlib
import json
import os
import select
import signal
import socket
import struct
import subprocess
import time
from pathlib import Path

from .common import ICPError, append_jsonl, file_hash, read_json, save_json
from .knowledge.bundle import KnowledgeBundle
from .runners.evidence_writer import HEADER, MAGIC, validate_payload


def _campaign_records(store, campaign_id=None):
    base = store.root / "interactions" / "campaigns"
    records = []
    if not base.is_dir():
        return records
    for index_path in sorted(base.glob("*/interactions/records-*.jsonl")):
        campaign_root = index_path.parent.parent
        if campaign_id is not None and campaign_root.name != campaign_id:
            continue
        for line_no, line in enumerate(index_path.read_text().splitlines(), 1):
            try:
                item = json.loads(line)
                if item.get("campaign_id") != campaign_root.name:
                    raise ICPError("Evidence campaign identity mismatch", "evidence")
                pack_path = index_path.parent / ("records-%04d.pack" % item["segment"])
                raw = pack_path.read_bytes()
                start, length = item["offset"], item["length"]
                if type(start) is not int or type(length) is not int or start < 0 or length < HEADER.size or start + length > len(raw):
                    raise ICPError("Evidence index points outside record pack", "evidence")
                frame = raw[start:start + length]
                if hashlib.sha256(frame).hexdigest() != item.get("sha256"):
                    raise ICPError("Evidence frame hash does not match index", "evidence")
                magic, version, flags, payload_length = HEADER.unpack_from(frame)
                if magic != MAGIC or version != 1 or flags != 0 or payload_length != len(frame) - HEADER.size:
                    raise ICPError("Evidence frame header is inconsistent", "evidence")
                payload = validate_payload(frame[HEADER.size:], store.config["evidence"]["max_record_bytes"])
                for key in ("campaign_id", "target_artifact_id", "adapter_artifact_id", "knowledge_bundle_id"):
                    if item.get(key) is not None:
                        payload[key] = item[key]
                payload["record_sha256"] = item["sha256"]
                payload["pack_path"] = str(pack_path)
                payload["pack_offset"] = start
                records.append(payload)
            except (ValueError, KeyError, OSError, TypeError, struct.error) as exc:
                raise ICPError("Invalid evidence index %s:%d: %s" % (index_path, line_no, exc), "evidence") from exc
    records.sort(key=lambda r: (r.get("campaign_id", ""), r["execution_id"]))
    return records


def _afl_findings(campaign):
    output = Path(campaign["output"])
    found = []
    for category in ("crashes", "hangs", "replayable-crashes", "replayable-hangs"):
        folder = output / category
        if folder.is_dir():
            for path in sorted(folder.iterdir()):
                if path.is_file() and not path.name.startswith("README"):
                    found.append({"category": category, "path": str(path), "sha256": file_hash(path), "bytes": path.stat().st_size})
    return found


def _start_target(profile, store, log):
    environment = {k: v for k, v in os.environ.items()
                   if not any(word in k.upper() for word in ("API_KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"))}
    for name, env_name in profile.get("environment_env", {}).items():
        if env_name not in os.environ:
            raise ICPError("Missing target runtime environment variable: " + env_name, "configuration")
        environment[name] = os.environ[env_name]
    argv = profile["launch_argv"]
    process = subprocess.Popen(argv, cwd=Path(profile["executable_path"]).parent, env=environment,
                               stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                               start_new_session=True)
    deadline = time.monotonic() + max(2.0, store.config["campaign"]["startup_wait_us"] / 1000000.0 + 2.0)
    last_error = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            exit_status = process.returncode
            _terminate(process)
            raise ICPError("Target exited before replay readiness (status %s)" % exit_status, "replay")
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(.1)
        try:
            if probe.connect_ex((profile["host"], profile["port"])) == 0:
                probe.close()
                return process
        except OSError as exc:
            last_error = exc
        finally:
            probe.close()
        time.sleep(.05)
    _terminate(process)
    raise ICPError("Target did not become ready for replay: " + str(last_error or "connection refused"), "replay")


def _collect(sock, config):
    poll_ms = max(1, int(config["campaign"]["poll_wait_ms"]))
    timeout_us = max(1000, int(config["campaign"]["socket_timeout_us"]))
    readable, _, exceptional = select.select([sock], [], [sock], poll_ms / 1000.0)
    if exceptional:
        return 1, b""
    if not readable:
        return 0, b""
    result = bytearray()
    sock.settimeout(timeout_us / 1000000.0)
    while True:
        try:
            part = sock.recv(1000)
        except socket.timeout:
            break
        except OSError:
            return 1, bytes(result)
        if not part:
            break
        result.extend(part)
    return 0, bytes(result)


def _terminate(process):
    # Targets are launched in a new session, so terminate the whole process
    # group even if its leader exited after forking a worker/child process.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except OSError:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            os.killpg(process.pid, 0)
        except OSError:
            break
        time.sleep(.05)
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            if process.poll() is None:
                process.kill()
    if process.poll() is None:
        process.wait()


def replay(record, profile, store, replay_log):
    requests = record["requests"]
    if not requests or any(request["sent_length"] is None or request["sent_length"] != request["planned_length"]
                           for request in requests):
        return {"status": "not_replayable", "reason": "capture includes a missing or partial send"}
    expected_windows = record["receive_windows"]
    replayed = []
    for iteration in range(store.config["analysis"]["replay_count"]):
        process = None
        log_stream = Path(replay_log).open("ab")
        try:
            process = _start_target(profile, store, log_stream)
            observed = []
            with socket.create_connection((profile["host"], profile["port"]),
                                          timeout=max(.1, store.config["campaign"]["execution_timeout_ms"] / 1000.0)) as sock:
                status, data = _collect(sock, store.config)
                observed.append({"after_request_index": -1, "receive_status": status, "data_hex": data.hex(), "tail": False})
                for index, request in enumerate(requests):
                    sock.sendall(bytes.fromhex(request["planned_hex"]))
                    status, data = _collect(sock, store.config)
                    observed.append({"after_request_index": index, "receive_status": status, "data_hex": data.hex(), "tail": False})
                status, data = _collect(sock, store.config)
                observed.append({"after_request_index": len(requests) - 1, "receive_status": status, "data_hex": data.hex(), "tail": True})
            expected = [{"after_request_index": w["after_request_index"], "receive_status": w["receive_status"],
                         "data_hex": w["data_hex"], "tail": w["tail"]} for w in expected_windows]
            replayed.append({"iteration": iteration + 1, "matched": observed == expected, "windows": observed,
                             "target_exit_status": process.poll()})
        except (OSError, ICPError, ValueError) as exc:
            replayed.append({"iteration": iteration + 1, "matched": False, "error": str(exc)})
        finally:
            if process:
                _terminate(process)
            log_stream.close()
    matches = sum(1 for attempt in replayed if attempt.get("matched"))
    return {"status": "matched" if matches else "not_matched", "matching_replays": matches,
            "attempts": replayed, "comparison": "request-boundary receive-window status and exact bytes"}


def _source_evidence(bundle, candidate):
    evidence, errors = [], []
    citations = candidate.get("specification_evidence", [])
    if not isinstance(citations, list) or not citations:
        errors.append("candidate has no source citations")
        citations = []
    for item in citations:
        if not isinstance(item, dict):
            errors.append("malformed source citation")
            continue
        identity, quote = item.get("source_ref"), item.get("quote")
        source = bundle.sources.get(identity)
        if not source or not isinstance(quote, str) or not quote.strip() or quote not in source["text"]:
            errors.append("unverified source citation: " + str(identity))
            continue
        evidence.append({"source_ref": identity, **source, "quote": quote})
    return evidence, errors


def _select_records(records, maximum):
    # Deterministic priority: new coverage first, then periodic records, then
    # execution identity. Exact exchange duplicates are analyzed once.
    def rank(record):
        triggers = record["trigger_bits"]
        return (0 if triggers & 1 else 1, record["campaign_id"], record["execution_id"])
    ordered, seen = [], set()
    for record in sorted(records, key=rank):
        key = hashlib.sha256(json.dumps({"requests": record["requests"], "windows": record["receive_windows"],
                                        "states": record["state_sequence"]}, sort_keys=True).encode()).hexdigest()
        if key not in seen:
            seen.add(key)
            ordered.append(record)
    return ordered[:maximum], len(ordered)


def analyze(store, model):
    if store.manifest.get("status") not in ("campaign_completed", "analysis_incomplete", "analyzed"):
        raise ICPError("Analysis requires a completed campaign")
    campaign = store.manifest.get("active_campaign")
    if not campaign or campaign.get("status") != "completed":
        raise ICPError("No completed campaign is recorded")
    if store.config["evidence"]["enabled"] and store.manifest.get("evidence_complete") is not True:
        raise ICPError("Runtime evidence is incomplete; source-grounded confirmation is disabled")
    bundle = KnowledgeBundle(store.require("knowledge"))
    profile = read_json(store.require("target_profile"))
    all_records = _campaign_records(store, campaign["campaign_id"])
    selected, unique_count = _select_records(all_records, store.config["analysis"]["max_records"])
    analysis_root = store.root / "analysis" / "revisions"
    analysis_root.mkdir(parents=True, exist_ok=True)
    revisions = [int(path.name[1:]) for path in analysis_root.glob("v*") if path.is_dir() and path.name[1:].isdigit()]
    revision_root = analysis_root / ("v%03d" % (max(revisions, default=0) + 1))
    revision_root.mkdir(parents=True, exist_ok=False)
    finding_path = revision_root / "findings.jsonl"
    confirmed, candidates, replay_errors = [], [], []
    model_incomplete = False
    replay_log = finding_path.parent / "target-replay.log"
    analysis_errors = []
    for record in selected:
        replay_result = replay(record, profile, store, replay_log)
        trigger = "%s/exec/%d" % (record.get("campaign_id", "unknown"), record["execution_id"])
        if replay_result.get("status") != "matched":
            replay_errors.append({"triggering_interaction": trigger, "replay": replay_result})
            continue
        exchange = {key: value for key, value in record.items() if key not in ("coverage_bitmap_hex", "pack_path", "pack_offset")}
        exchange["coverage_bitmap"] = {"bytes": len(record.get("coverage_bitmap_hex", "")) // 2,
                                       "sha256": hashlib.sha256(bytes.fromhex(record.get("coverage_bitmap_hex", ""))).hexdigest()}
        data = {"protocol": bundle.protocol, "triggering_interaction": trigger,
                "exchange": exchange, "replay_report": replay_result,
                "client_behavior": bundle.roles["client"], "server_behavior": bundle.roles["server"],
                "original_specification_sources": bundle.sources}
        try:
            proposal = model.call("reasoning", "finding", data)
        except ICPError as exc:
            analysis_errors.append({"triggering_interaction": trigger, "stage": "finding", "error": str(exc)})
            continue
        model_incomplete = model_incomplete or proposal.get("analysis_incomplete") is True
        proposed = proposal.get("candidates")
        if not isinstance(proposed, list):
            raise ICPError("Finding analysis did not return a candidate list", "model_format")
        for item in proposed:
            if not isinstance(item, dict) or item.get("category") not in (
                    "confirmed_non_conformance", "confirmed_memory_error", "confirmed_vulnerability", "candidate"):
                raise ICPError("Finding candidate has an invalid structured category", "model_format")
            item["triggering_interaction"] = trigger
            source_evidence, citation_errors = _source_evidence(bundle, item)
            try:
                reviewer = model.call("reasoning", "finding_review", {"candidate": item, "source_evidence": source_evidence,
                                       "exchange": record, "replay_report": replay_result,
                                       "client_behavior": bundle.roles["client"], "server_behavior": bundle.roles["server"]})
            except ICPError as exc:
                reviewer = {"is_valid": False, "confirmation_status": "needs_confirmation", "issues": [str(exc)],
                            "unresolved_questions": ["Reviewer call failed; no confirmation issued"]}
                analysis_errors.append({"triggering_interaction": trigger, "stage": "review", "error": str(exc)})
            confirmation = reviewer.get("confirmation_status")
            allowed_confirmations = ("confirmed_non_conformance", "confirmed_memory_error", "confirmed_vulnerability")
            if (citation_errors or reviewer.get("is_valid") is not True or reviewer.get("issues") or
                    reviewer.get("unresolved_questions") or confirmation not in allowed_confirmations):
                confirmation = "needs_confirmation"
            if replay_result.get("matching_replays", 0) < 1:
                confirmation = "needs_confirmation"
            output = {"candidate": item, "review": reviewer, "verified_source_evidence": source_evidence,
                      "citation_validation_errors": citation_errors, "replay": replay_result,
                      "confirmation_status": confirmation,
                      "analysis_label": "confirmed" if confirmation in ("confirmed_non_conformance", "confirmed_memory_error", "confirmed_vulnerability") else "not_confirmed"}
            append_jsonl(finding_path, output)
            (confirmed if output["analysis_label"] == "confirmed" else candidates).append(output)
    afl_findings = _afl_findings(campaign)
    if store.config["evidence"]["enabled"] and not all_records:
        analysis_errors.append({"stage": "evidence", "error": "No complete sampled execution records are available for semantic analysis"})
    partial = bool(replay_errors or analysis_errors or model_incomplete or len(selected) < unique_count)
    report = {"schema_version": "1.0", "run_id": store.manifest["run_id"], "campaign_id": campaign["campaign_id"],
              "status": "partial" if partial else "complete", "records_total": len(all_records),
              "unique_records": unique_count, "records_selected": len(selected), "finding_count": len(confirmed),
              "unconfirmed_count": len(candidates), "replay_failures": replay_errors,
              "records_omitted_by_limit": max(0, unique_count - len(selected)), "model_analysis_incomplete": model_incomplete,
              "analysis_errors": analysis_errors, "aflnet_crash_hang_artifacts": afl_findings,
              "finding_file": str(finding_path), "completed_at": time.time(),
              "note": "AFLNet crash/hang inputs are referenced in place, never recopied or rewritten."}
    save_json(store.root / "analysis" / "report.json", report)
    store.manifest["status"] = "analyzed" if report["status"] == "complete" else "analysis_incomplete"
    store.manifest["analysis"] = report
    store.save()
    return report
