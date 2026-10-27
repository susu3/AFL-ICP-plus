import re
from ..common import ICPError


def validate_packets(packet, role, protocol):
    direction = "request" if role == "client" else "response"
    for key, expected in (("schema_version", "1.0"), ("role", role), ("direction", direction), ("protocol", protocol)):
        if packet.get(key) != expected:
            raise ICPError("Packet " + key + " mismatch")
    if packet.get("endian") not in ("big", "little") or not isinstance(packet.get("messages"), list) or not packet["messages"]:
        raise ICPError("Packet endian/messages invalid")
    for message in packet["messages"]:
        if not message.get("message_id", "").startswith(role + "." + direction + ".") or not message.get("message_name"):
            raise ICPError("Message id/name invalid")
        if not isinstance(message.get("source_refs"), list) or not message["source_refs"]:
            raise ICPError("Message source_refs required")
        if role == "server":
            if message.get("response_kind") not in ("normal", "exception", "other") or not isinstance(message.get("response_to"), list):
                raise ICPError("Response association invalid")
            if not message["response_to"] and not message.get("unsolicited_reason"):
                raise ICPError("Unsolicited response needs explanation")
        validate_fields(message.get("fields"))


def validate_fields(fields):
    if not isinstance(fields, list) or not fields:
        raise ICPError("Nonempty fields list required")
    names = set()
    for field in fields:
        name, kind, length = field.get("field_name"), field.get("field_type"), field.get("field_length")
        if not name or name in names:
            raise ICPError("Duplicate/missing field name")
        names.add(name)
        integer = re.fullmatch(r"(u?int)(8|16|32|64)", str(kind))
        if not integer and kind not in ("byte[]", "string", "struct", "array"):
            raise ICPError("Unsupported field type: " + str(kind))
        if not ((type(length) is int and length >= 0) or length == "variable"):
            raise ICPError("Field length invalid")
        if type(field.get("dependency")) is not bool:
            raise ICPError("Field dependency must be boolean")
        if not isinstance(field.get("source_refs"), list) or not field["source_refs"]:
            raise ICPError("Field source_refs required")
        if "endian" in field and field["endian"] not in ("big", "little"):
            raise ICPError("Field endian invalid")
        if "bit_mask" in field and not re.fullmatch(r"0x[0-9A-F]+", field["bit_mask"]):
            raise ICPError("bit_mask must use canonical uppercase hex digits")
        if integer:
            bits = int(integer[2])
            low, high = (0, 2 ** bits - 1) if integer[1] == "uint" else (-2 ** (bits - 1), 2 ** (bits - 1) - 1)
            if length != bits // 8:
                raise ICPError("Integer length mismatch")
            values = list(field.get("allowed_values", []))
            if "default_value" in field:
                values.append(field["default_value"])
            if "valid_range" in field:
                bounds = field["valid_range"]
                values += [bounds["min"], bounds["max"]]
                if bounds["min"] > bounds["max"]:
                    raise ICPError("Inverted valid_range")
            if any(type(v) is not int or not low <= v <= high for v in values):
                raise ICPError("Integer value/range outside width")
        if kind == "struct":
            validate_fields(field.get("fields"))
        if kind == "array":
            if not isinstance(field.get("items"), dict):
                raise ICPError("Array requires items field definition")
            validate_fields([field["items"]])
