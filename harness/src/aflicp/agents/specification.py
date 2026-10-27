import json
from pathlib import Path
from ..common import ICPError, atomic_write, canonical, digest, read_json, save_json
from ..knowledge.bundle import FILES, KnowledgeBundle, publish_bundle
from ..llm.client import require_review
from ..specification.documents import prepare_documents


def _merge_messages(destination, additions):
    if not isinstance(additions, list):
        raise ICPError("Packet messages must be a list")
    by_id = {m["message_id"]: m for m in destination}
    for message in additions:
        identity = message.get("message_id")
        if identity not in by_id:
            destination.append(message); by_id[identity] = message; continue
        old = by_id[identity]
        def content(item):
            return {k: v for k, v in item.items() if k in ("message_id", "message_name", "description", "fields", "response_kind", "unsolicited_reason")}
        if canonical(content(old)) != canonical(content(message)):
            raise ICPError("Conflicting source definitions for packet " + str(identity))
        for key in ("source_refs", "constraint_refs", "response_to"):
            if key in old or key in message:
                old[key] = sorted(set(old.get(key, []) + message.get(key, [])))


def _merge_markdown(parts):
    by_id, order = {}, []
    import re
    for value in parts:
        if not value.strip():
            continue
        tokens = re.split(r"(?m)^## ([^\n]+)\n", value.strip())
        if (len(tokens) - 1) % 2:
            raise ICPError("Malformed structured Markdown sections")
        for i in range(1, len(tokens), 2):
            identity, body = tokens[i].strip(), tokens[i + 1].strip()
            old = by_id.get(identity)
            if old is None:
                by_id[identity] = body; order.append(identity)
            elif canonical(old) != canonical(body):
                raise ICPError("Conflicting constraint text for " + identity)
    return "\n\n".join("## " + identity + "\n" + by_id[identity] for identity in order)


def _merge_mermaid(parts):
    lines = ["stateDiagram-v2"]
    for value in parts:
        if not isinstance(value, str) or not value.strip():
            raise ICPError("Mermaid contribution must be a string")
        rows = value.strip().splitlines()
        if rows[0].strip() != "stateDiagram-v2":
            raise ICPError("Mermaid contribution must start with stateDiagram-v2")
        lines.extend(row for row in rows[1:] if row.strip())
    return "\n".join(lines) + "\n"


def _write_parts(folder, protocol, segment_contributions):
    merged = {}
    for role, paths in FILES.items():
        packets = None
        diagrams, markdown = [], []
        for contribution in segment_contributions:
            files = contribution["files"]
            packet = files[paths["packets"]]
            if not isinstance(packet, dict) or packet.get("protocol") != protocol or packet.get("role") != role or packet.get("direction") != ("request" if role == "client" else "response"):
                raise ICPError("Partial packet roots disagree with bundle protocol/role")
            if packets is None:
                packets = {"schema_version": "1.0", "protocol": protocol, "role": role,
                           "direction": "request" if role == "client" else "response",
                           "endian": packet.get("endian"), "messages": []}
            if packet.get("schema_version") != packets["schema_version"] or packet.get("endian") != packets["endian"]:
                raise ICPError("Packet root version or endian changes across specification segments")
            _merge_messages(packets["messages"], packet.get("messages", []))
            diagrams.append(files[paths["state_machine"]])
            markdown.append(files[paths["dependencies"]])
        if packets is None:
            raise ICPError("No synthesis contributions")
        relative = paths["packets"]
        save_json(folder / relative, packets)
        atomic_write(folder / paths["state_machine"], _merge_mermaid(diagrams))
        atomic_write(folder / paths["dependencies"], _merge_markdown(markdown))
        merged.update({relative: True, paths["state_machine"]: True, paths["dependencies"]: True})
    return merged


def _cross_summary(bundle):
    result = {"protocol": bundle.protocol, "client": {}, "server": {}, "sources": {}}
    for role in ("client", "server"):
        schema = bundle.roles[role]
        result[role] = {
            "messages": [{k: m.get(k) for k in ("message_id", "message_name", "response_to", "response_kind", "constraint_refs", "source_refs")}
                         | {"field_summary": [{"field_name": f["field_name"], "field_type": f["field_type"], "field_length": f["field_length"],
                                              "constraint_refs": f.get("constraint_refs", []), "source_refs": f["source_refs"]} for f in m["fields"]]} for m in schema["packets"]["messages"]],
            "states": schema["state_ast"]["states"], "transitions": schema["state_ast"]["transitions"],
            "constraints": [{k: c[k] for k in ("id", "owner", "kind", "message_refs", "state_refs", "related_constraints", "source_refs")} for c in schema["rules"]]}
    result["sources"] = {k: {"document_id": v["document_id"], "document_hash": v["document_hash"], "page_number": v["page_number"],
                             "segment_id": v["segment_id"], "heading_path": v["heading_path"], "text": v["text"][:1200]}
                         for k, v in bundle.sources.items()}
    return result


def prepare(store, model):
    reused = store.config.get("reuse", {}).get("knowledge_bundle")
    if reused:
        bundle = KnowledgeBundle(reused)
        if bundle.protocol != store.config["protocol"]:
            raise ICPError("Reused knowledge bundle protocol differs from config")
        store.register("knowledge", bundle.root, "validated_cache")
        store.manifest["knowledge_bundle_id"] = bundle.manifest["bundle_id"]
        store.save()
        return bundle.root

    sources, segments = prepare_documents(store.config, store.root, model)
    relevant = [segment for segment in segments if segment["relevance"] == "relevant"]
    if not relevant:
        raise ICPError("No source segments were labeled relevant; complete specification is retained for diagnosis")
    previous, diagnostics = {}, []
    maximum = store.config["repair"]["specification_max_retries"]
    final_folder = store.root / "knowledge_versions" / "v000"
    final_folder.mkdir(parents=True, exist_ok=False)
    save_json(final_folder / "sources.json", sources)
    contributions = []
    for index, segment in enumerate(relevant):
        segment_path = store.root / segment["markdown_path"]
        evidence = {identity: sources[identity] for identity in segment["source_refs"]}
        segment_diags = []
        for attempt in range(maximum + 1):
            try:
                result = model.call("text", "synthesis", {"protocol": store.config["protocol"], "segment": segment,
                    "source_evidence": evidence, "segment_markdown": segment_path.read_text(),
                    "prior_object_ids": previous, "diagnostics": segment_diags,
                    "contract": (Path(__file__).parent.parent / "schemas" / "knowledge-contract.md").read_text()})
                if result.get("unresolved_questions"):
                    raise ICPError("Synthesis has unresolved source questions: " + json.dumps(result["unresolved_questions"], ensure_ascii=False), "source_ambiguity", False)
                expected = {path for paths in FILES.values() for path in paths.values()}
                if not isinstance(result.get("files"), dict) or set(result["files"]) != expected:
                    raise ICPError("Synthesis must return exactly the six contracted files", "model_format", True)
                review = model.call("text", "knowledge_review", {"protocol": store.config["protocol"],
                    "segment": segment, "partial_artifacts": result["files"], "source_evidence": evidence,
                    "contract": (Path(__file__).parent.parent / "schemas" / "knowledge-contract.md").read_text()})
                require_review(review)
                contributions.append({"segment_id": segment["segment_id"], "files": result["files"], "review": review})
                ids = []
                for relative, value in result["files"].items():
                    if relative.endswith(".json"):
                        ids.extend(x.get("message_id") for x in value.get("messages", []))
                    elif relative.endswith(".mmd"):
                        import re
                        ids.extend(re.findall(r'"id":"([^"]+)"', value))
                    else:
                        import re
                        ids.extend(re.findall(r"(?m)^## ([^\n]+)", value))
                previous[segment["segment_id"]] = sorted(set(x for x in ids if x))
                break
            except (ICPError, ValueError, KeyError, TypeError) as exc:
                item = store.diagnostic("specification_segment", exc, segment_id=segment["segment_id"], attempt=attempt)
                segment_diags.append(item)
                if attempt == maximum:
                    raise ICPError("Specification synthesis/review budget exhausted at " + segment["segment_id"]) from exc

    _write_parts(final_folder, store.config["protocol"], contributions)
    try:
        bundle = KnowledgeBundle(final_folder, store.config["protocol"], published=False)
    except ICPError as exc:
        store.diagnostic("knowledge_cross_validation", exc)
        raise
    final_review, review_diagnostics = None, []
    for attempt in range(maximum + 1):
        try:
            final_review = model.call("text", "knowledge_review", {"cross_schema_summary": _cross_summary(bundle),
                "segment_review_ids": [{"segment_id": x["segment_id"], "review": x["review"]} for x in contributions],
                "prior_review_diagnostics": review_diagnostics,
                "scope": "Check whole-bundle cross-role identities, paired events, request-response associations, unique constraint ownership, and both-role behavior. Source-grounded clause checks were independently completed against each supplied page segment."})
            require_review(final_review)
            break
        except (ICPError, ValueError, KeyError, TypeError) as exc:
            diagnostic = store.diagnostic("knowledge_final_review", exc, attempt=attempt)
            review_diagnostics.append(diagnostic)
            if attempt == maximum:
                raise ICPError("Whole-bundle reviewer did not approve within the configured retry budget") from exc
    review = final_review
    published = publish_bundle(final_folder, store.config["protocol"], review)
    store.manifest["knowledge_bundle_id"] = published.manifest["bundle_id"]
    store.register("knowledge", final_folder, "specification_formalization_agent")
    store.save()
    return final_folder
