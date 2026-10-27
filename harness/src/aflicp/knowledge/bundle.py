from pathlib import Path
from ..common import ICPError, contained, digest, file_hash, read_json, save_json
from .parsers import mermaid, constraints
from .validation import validate_packets

FILES = {"client": {"packets": "client/requests.json", "state_machine": "client/state_machine.mmd", "dependencies": "client/contextual_dependencies.md"},
         "server": {"packets": "server/responses.json", "state_machine": "server/state_machine.mmd", "dependencies": "server/contextual_dependencies.md"}}


class KnowledgeBundle:
    def __init__(self, root, protocol=None, published=True):
        self.root = Path(root).resolve()
        self.manifest = read_json(self.root / "manifest.json") if published else {}
        if published and self.manifest.get("status") != "validated":
            raise ICPError("Knowledge bundle not validated")
        self.protocol = protocol or self.manifest["protocol"]
        self.sources = read_json(self.root / "sources.json")
        self.objects, self.roles = {}, {}
        for role, paths in FILES.items():
            if published:
                for name, relative in paths.items():
                    record = self.manifest[role][name]
                    if record["path"] != relative or file_hash(contained(self.root, relative)) != record["sha256"]:
                        raise ICPError("Knowledge hash/path mismatch: " + relative)
            packets = read_json(self.root / paths["packets"])
            validate_packets(packets, role, self.protocol)
            state_text = (self.root / paths["state_machine"]).read_text()
            dependencies_text = (self.root / paths["dependencies"]).read_text()
            model, rules = mermaid(state_text, role), constraints(dependencies_text, role)
            self.roles[role] = {"packets": packets, "state_machine": state_text, "dependencies": dependencies_text,
                                "state_ast": model, "rules": rules}
            for obj in packets["messages"] + model["states"] + model["transitions"] + rules:
                identity = obj.get("message_id", obj.get("id"))
                if identity in self.objects:
                    raise ICPError("Duplicate object: " + identity)
                self.objects[identity] = obj
        for identity, source in self.sources.items():
            if not identity.startswith("source.") or not source.get("document_id") or type(source.get("page_number")) is not int or source["page_number"] < 1 or not source.get("document_hash") or not source.get("segment_id") or not source.get("text"):
                raise ICPError("Invalid source provenance: " + identity)
        for obj in self.objects.values():
            self._check_refs(obj)
        self._check_events()
        if published:
            payload = {"protocol": self.protocol, "files": {r: self.manifest[r] for r in FILES},
                       "sources_hash": file_hash(self.root / "sources.json"), "verification": self.manifest["verification_hash"]}
            if digest(payload) != self.manifest["bundle_id"]:
                raise ICPError("Bundle ID mismatch")
            report = read_json(self.root / "verification.json")
            if file_hash(self.root / "verification.json") != self.manifest["verification_hash"] or report.get("is_valid") is not True or report.get("issues") or report.get("unresolved_questions"):
                raise ICPError("Invalid knowledge verification report")

    def _check_refs(self, obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in ("source_refs", "constraint_refs", "message_refs", "state_refs", "related_constraints", "response_to"):
                    if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
                        raise ICPError("Reference list required: " + key)
                    for identity in value:
                        self.resolve_ref(identity)
                elif key == "message_ref":
                    message = self.resolve_ref(value)
                    if "message_id" not in message:
                        raise ICPError("message_ref must reference a packet")
                self._check_refs(value)
        elif isinstance(obj, list):
            for value in obj:
                self._check_refs(value)

    def _check_events(self):
        events = {}
        for role, schema in self.roles.items():
            for transition in schema["state_ast"]["transitions"]:
                for event in transition["events"]:
                    identity, kind = event.get("id", ""), event.get("kind")
                    if not identity.startswith("event.") or kind not in ("send", "receive", "local"):
                        raise ICPError("Invalid event metadata")
                    if kind != "local" and not event.get("message_ref"):
                        raise ICPError("Wire event needs message_ref")
                    if kind != "local":
                        events.setdefault(identity, []).append((role, kind, event["message_ref"]))
        for identity, items in events.items():
            if len({i[2] for i in items}) != 1 or {i[1] for i in items} != {"send", "receive"} or {i[0] for i in items} != {"client", "server"}:
                raise ICPError("Cross-role event mismatch: " + identity)

    def resolve_ref(self, identity):
        if identity in self.objects:
            return self.objects[identity]
        if identity in self.sources:
            return self.sources[identity]
        raise ICPError("Dangling reference: " + str(identity))

    def get_role_schema(self, role):
        return self.roles[role]

    def select_context(self, task, evidence_query=None):
        # Both roles are always available, preventing accidental cross-role information loss.
        primary = "server" if task in ("reasoning", "response_parser") else "client"
        return {"primary_role": primary, "client": self.roles["client"], "server": self.roles["server"],
                "sources": self.sources, "query": evidence_query}


def publish_bundle(root, protocol, review):
    root = Path(root)
    KnowledgeBundle(root, protocol, published=False)
    from ..llm.client import require_review
    require_review(review)
    save_json(root / "verification.json", review)
    files = {role: {name: {"path": relative, "sha256": file_hash(root / relative)} for name, relative in paths.items()} for role, paths in FILES.items()}
    verification = file_hash(root / "verification.json")
    payload = {"protocol": protocol, "files": files, "sources_hash": file_hash(root / "sources.json"), "verification": verification}
    save_json(root / "manifest.json", {"schema_version": "1.0", "protocol": protocol, "status": "validated",
              "bundle_id": digest(payload), **files, "verification_hash": verification,
              "source_document_ids": sorted({s["document_id"] for s in read_json(root / "sources.json").values()})})
    return KnowledgeBundle(root)
