import json
import os
import shutil
import stat
from pathlib import Path
from ..common import ICPError, canonical, file_hash, save_json


def _candidate_metadata(path):
    sidecar = path.with_suffix(".json")
    if sidecar.is_symlink() or not sidecar.is_file() or sidecar.stat().st_size > 1024 * 1024:
        return {}
    return json.loads(sidecar.read_text()) if sidecar.exists() else {}


def _validate_field_values(fields, values):
    if not isinstance(values, dict):
        return "field variants must map field names to values"
    for field in fields:
        name, kind, length = field["field_name"], field["field_type"], field["field_length"]
        if name not in values:
            if field.get("dependency"):
                continue
            if "default_value" in field:
                continue
            return "missing field variant " + name
        value = values[name]
        if kind.startswith("uint") or kind.startswith("int"):
            if type(value) is not int:
                return "integer variant type mismatch for " + name
            bits = int(kind[kind.find("t") + 1:])
            low, high = (0, 2 ** bits - 1) if kind.startswith("uint") else (-2 ** (bits - 1), 2 ** (bits - 1) - 1)
            if not low <= value <= high:
                return "integer variant outside field width for " + name
            valid_range = field.get("valid_range")
            if valid_range and not valid_range["min"] <= value <= valid_range["max"]:
                return "integer variant outside declared valid_range for " + name
            if "allowed_values" in field and value not in field["allowed_values"]:
                return "integer variant outside allowed_values for " + name
        elif kind in ("byte[]", "string"):
            if kind == "byte[]" and not isinstance(value, (str, bytes, bytearray)):
                return "byte[] variant must be hex text or bytes for " + name
            if isinstance(value, str) and (len(value) % 2 or any(char not in "0123456789ABCDEF" for char in value)):
                return "byte[] hex variant must be even-length uppercase hex for " + name
            if kind == "string" and not isinstance(value, str):
                return "string variant must be text for " + name
            size = len(bytes.fromhex(value)) if kind == "byte[]" and isinstance(value, str) else len(value.encode() if isinstance(value, str) else bytes(value))
            if type(length) is int and size != length:
                return "variant length mismatch for " + name
        elif kind == "struct":
            reason = _validate_field_values(field["fields"], value)
            if reason:
                return reason
        elif kind == "array":
            if not isinstance(value, list):
                return "array variant must be a list for " + name
            for item in value:
                reason = _validate_field_values([field["items"]], {field["items"]["field_name"]: item})
                if reason:
                    return reason
    return None


def _check_candidate(path, meta, message_map, max_bytes, max_count, supported_path_ids):
    if not isinstance(meta, dict):
        return "metadata root is not an object"
    if not path.is_file() or path.is_symlink():
        return "not a regular generated file"
    size = path.stat().st_size
    if not size:
        return "empty"
    if size > max_bytes:
        return "oversize"
    message_ids = meta.get("message_ids")
    if not isinstance(message_ids, list) or any(not isinstance(identity, str) for identity in message_ids):
        return "message_ids must be a list of protocol message identifiers"
    if len(message_ids) > max_count:
        return "too many messages"
    if not message_ids or any(i not in message_map for i in message_ids):
        return "unknown or missing client message metadata"
    lengths = meta.get("message_lengths", [])
    if not isinstance(lengths, list) or len(lengths) != len(message_ids) or any(type(n) is not int or n <= 0 for n in lengths) or sum(lengths) != size:
        return "message boundaries do not match bytes"
    variants = meta.get("field_variants")
    if not isinstance(variants, dict) or set(variants) != set(message_ids):
        return "field_variants must contain exactly the generated message IDs"
    for message_id in message_ids:
        values = variants.get(message_id)
        try:
            reason = _validate_field_values(message_map[message_id]["fields"], values)
        except (TypeError, ValueError, KeyError):
            return "field variant encoding is malformed for " + message_id
        if reason:
            return message_id + ": " + reason
    state_path = meta.get("state_path_id")
    if state_path is not None and state_path not in supported_path_ids:
        return "state_path_id is not a documented client/server state or transition ID"
    return None


def _flatten_variants(value, prefix=""):
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            result.update(_flatten_variants(item, prefix + ("." if prefix else "") + str(key)))
        return result
    return {prefix: value}


def _features(meta):
    ids = meta["message_ids"]
    features = {"message:" + identity for identity in ids}
    features.add("sequence-length:" + str(len(ids)))
    features.add("sequence:" + file_hash_from_bytes(canonical(ids)))
    if meta.get("state_path_id"):
        features.add("state-path:" + meta["state_path_id"])
    for message_id, fields in meta.get("field_variants", {}).items():
        for field_name, value in _flatten_variants(fields).items():
            features.add("field:%s:%s:%s" % (message_id, field_name, file_hash_from_bytes(canonical(value))))
    return features


def file_hash_from_bytes(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()


def merge_corpus(user_dir, raw_dir, destination, bundle, config):
    user_dir, raw_dir, destination = Path(user_dir), Path(raw_dir), Path(destination)
    if not user_dir.is_dir():
        raise ICPError("User C0 seed directory does not exist", "configuration")
    if destination.exists():
        raise ICPError("Refusing to replace an existing published corpus")
    parent = destination.parent
    staging = parent / (".input-staging-" + destination.name)
    if staging.exists():
        raise ICPError("Stale staging corpus exists; inspect it before continuing")
    staging.mkdir(parents=True)
    report = {"c0": [], "generated": [], "duplicates": [], "excluded": [], "coverage_claims": {}}
    seen = {}
    originals = sorted(p for p in user_dir.rglob("*") if p.is_file() and not p.is_symlink())
    for source in originals:
        sha = file_hash(source)
        if source.stat().st_size == 0:
            report["excluded"].append({"path": str(source), "reason": "empty user C0 sample (preserved in source directory)"})
            continue
        if sha in seen:
            report["duplicates"].append({"path": str(source.relative_to(user_dir)), "sha256": sha, "kept": seen[sha]})
            continue
        name = "%06d-c0.bin" % len(report["c0"])
        shutil.copyfile(source, staging / name)
        seen[sha] = ("user", name)
        report["c0"].append({"source_name": str(source.relative_to(user_dir)), "path": name, "sha256": sha, "bytes": source.stat().st_size})
    candidates = sorted(raw_dir.glob("candidate-*.bin"))
    messages, states = set(), set()
    supported_path_ids = {obj["id"] for role in ("client", "server")
                          for obj in bundle.roles[role]["state_ast"]["states"] + bundle.roles[role]["state_ast"]["transitions"]}
    message_map = {m["message_id"]: m for m in bundle.roles["client"]["packets"]["messages"]}
    pending = []
    for source in candidates:
        meta_path = source.with_suffix(".json")
        try:
            meta = _candidate_metadata(source)
        except (OSError, ValueError) as exc:
            report["excluded"].append({"path": source.name, "reason": "metadata parse failed: " + str(exc)}); continue
        reason = _check_candidate(source, meta, message_map,
                                  config["seeds"]["max_seed_bytes"], config["seeds"]["max_sequence_messages"], supported_path_ids)
        if reason:
            report["excluded"].append({"path": source.name, "reason": reason}); continue
        sha = file_hash(source)
        if sha in seen:
            report["duplicates"].append({"path": source.name, "sha256": sha, "kept": seen[sha]}); continue
        pending.append({"source": source, "meta": meta, "sha256": sha, "features": _features(meta)})
    covered = set()
    target_size = max(len(report["c0"]), int(config["seeds"]["preferred_corpus_size"]))
    for item in pending:
        novel = item["features"] - covered
        if len(report["c0"]) + len(report["generated"]) >= target_size and not novel:
            report["excluded"].append({"path": item["source"].name, "reason": "soft corpus target reached; no new message/field/sequence/state diversity"})
            continue
        name = "%06d-generated.bin" % len(report["generated"])
        shutil.copyfile(item["source"], staging / name)
        seen[item["sha256"]] = ("generated", name)
        covered.update(item["features"])
        meta = item["meta"]
        messages.update(meta["message_ids"])
        if meta.get("state_path_id"):
            states.add(meta["state_path_id"])
        report["generated"].append({"path": name, "metadata": item["source"].with_suffix(".json").name,
                                    "sha256": item["sha256"], "bytes": item["source"].stat().st_size,
                                    "message_ids": meta["message_ids"], "sequence_length": len(meta["message_ids"]),
                                    "field_variants": meta["field_variants"], "state_path_id": meta.get("state_path_id")})
    report["coverage_claims"] = {"observed_message_ids": sorted(messages), "uncovered_message_ids": sorted(
        m["message_id"] for m in bundle.roles["client"]["packets"]["messages"] if m["message_id"] not in messages),
        "observed_state_path_ids": sorted(states), "note": "Metadata is checked against the manifest and byte lengths, not independently decoded protocol semantics."}
    field_values = {}
    sequence_lengths = set()
    sequence_signatures = set()
    for item in report["generated"]:
        sequence_lengths.add(item["sequence_length"])
        sequence_signatures.add(tuple(item["message_ids"]))
        for message_id, variants in item["field_variants"].items():
            for field_name, value in _flatten_variants(variants).items():
                field_values.setdefault(message_id + "." + field_name, set()).add(file_hash_from_bytes(canonical(value)))
    report["diversity"] = {"message_types": sorted(messages), "field_value_counts": {k: len(v) for k, v in sorted(field_values.items())},
                           "sequence_lengths": sorted(sequence_lengths), "distinct_message_sequences": len(sequence_signatures),
                           "state_path_ids": sorted(states), "preferred_size": target_size,
                           "preferred_size_is_soft": True}
    report["final_count"] = len(report["c0"]) + len(report["generated"])
    lengths = {item["sequence_length"] for item in report["generated"]}
    if not report["generated"]:
        shutil.rmtree(staging)
        raise ICPError("No valid generated seed survived validation and duplicate removal")
    if 1 not in lengths or not any(length > 1 for length in lengths):
        shutil.rmtree(staging)
        raise ICPError("Generated corpus must include both message-level and multi-message sequence seeds")
    if not report["final_count"]:
        shutil.rmtree(staging)
        raise ICPError("No usable seed files remain")
    # AFLNet -i reads only files at the input directory's top level.
    for item in report["c0"] + report["generated"]:
        (staging / item["path"]).chmod(0o600)
    os.replace(staging, destination)
    save_json(destination.parent / "corpus-manifest.json", report)
    return report
