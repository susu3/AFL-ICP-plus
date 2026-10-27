import json
import re
from ..common import ICPError, load_mapping


def mermaid(text, role):
    lines = text.strip().splitlines()
    if not lines or lines[0].strip() != "stateDiagram-v2":
        raise ICPError("Mermaid must start with stateDiagram-v2")
    states, transitions, pending = {}, [], None
    for number, raw in enumerate(lines[1:], 2):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("%% @"):
            if pending:
                raise ICPError("Unattached Mermaid metadata at line " + str(number))
            match = re.fullmatch(r"%% @(state|transition) (.+)", line)
            if not match:
                raise ICPError("Invalid Mermaid metadata")
            pending = (match[1], json.loads(match[2]))
            continue
        if line.startswith("%%"):
            continue
        state = re.fullmatch(r'state "([^"\n]+)" as ([A-Za-z][A-Za-z0-9_]*)', line)
        transition = re.fullmatch(r"(\[\*\]|[A-Za-z][A-Za-z0-9_]*)\s*-->\s*(\[\*\]|[A-Za-z][A-Za-z0-9_]*)(?:\s*:\s*(.+))?", line)
        kind = "state" if state else "transition" if transition else None
        if not kind or not pending or pending[0] != kind:
            raise ICPError("Unsupported/unannotated Mermaid syntax at line %d: %s" % (number, line))
        meta = pending[1]
        pending = None
        if not isinstance(meta, dict) or not str(meta.get("id", "")).startswith(role + "." + kind + "."):
            raise ICPError("Invalid Mermaid object ID")
        if not isinstance(meta.get("source_refs"), list) or not meta["source_refs"]:
            raise ICPError("Mermaid source_refs required")
        if state:
            if state[2] in states:
                raise ICPError("Duplicate Mermaid state alias")
            states[state[2]] = {**meta, "label": state[1]}
        else:
            if not isinstance(meta.get("events"), list):
                raise ICPError("Transition events must be a list")
            transitions.append({**meta, "from": transition[1], "to": transition[2], "label": transition[3]})
    if pending:
        raise ICPError("Unattached Mermaid metadata")
    for transition in transitions:
        if any(s != "[*]" and s not in states for s in (transition["from"], transition["to"])):
            raise ICPError("Mermaid transition references an undeclared state")
    # Protocols such as Modbus/TCP do not define a session state machine.
    # Header-only stateDiagram-v2 is the explicit representation of that fact.
    return {"states": list(states.values()), "transitions": transitions}


def constraints(text, role):
    rules = []
    sections = re.split(r"(?m)^## ([^\n]+)\n", text)
    for i in range(1, len(sections), 2):
        identity, body = sections[i].strip(), sections[i + 1]
        if not identity.startswith(role + ".constraint."):
            raise ICPError("Invalid constraint heading: " + identity)
        match = re.match(r"\s*```yaml\s*\n(.*?)\n```\s*\n(.+)", body, re.S)
        if not match:
            raise ICPError("Constraint requires YAML metadata and natural-language body: " + identity)
        metadata = load_mapping(match[1])
        if not isinstance(metadata, dict) or metadata.get("owner") != role or not metadata.get("kind"):
            raise ICPError("Constraint owner/kind invalid")
        for key in ("message_refs", "state_refs", "related_constraints", "source_refs"):
            if not isinstance(metadata.get(key), list):
                raise ICPError("Constraint requires list: " + key)
        if not metadata["source_refs"]:
            raise ICPError("Constraint has no source")
        rules.append({"id": identity, **metadata, "body": match[2].strip()})
    if not rules:
        raise ICPError("No structured constraints")
    return rules
