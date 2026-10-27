"""Trusted seed generator SDK. Field metadata never enters -i corpus files."""
import random
from dataclasses import dataclass, field


@dataclass
class SeedCase:
    messages: list
    message_ids: list
    field_variants: dict = field(default_factory=dict)
    state_path_id: str = None


@dataclass
class GeneratorContext:
    bundle_id: str
    protocol: str
    client_schema: dict
    server_schema: dict
    rng: random.Random
    candidate_budget: int
    max_seed_bytes: int
    max_sequence_messages: int


def encode_message(message, values, endian="big"):
    """Encode static fields; protocol-specific dependent lengths stay in generator logic."""
    data = bytearray()
    for field in message["fields"]:
        name, kind, length = field["field_name"], field["field_type"], field["field_length"]
        if name not in values:
            if "default_value" in field:
                value = field["default_value"]
            elif not field["dependency"]:
                raise ValueError("Missing field: " + name)
            else:
                continue
        else:
            value = values[name]
        order = field.get("endian", endian)
        if kind.startswith("uint") or kind.startswith("int"):
            size = int(kind[kind.find("t") + 1:]) // 8
            data.extend(int(value).to_bytes(size, order, signed=kind.startswith("int")))
        elif kind == "byte[]":
            content = bytes.fromhex(value) if isinstance(value, str) else bytes(value)
            if type(length) is int and len(content) != length:
                raise ValueError("Byte field length mismatch: " + name)
            data.extend(content)
        elif kind == "string":
            content = value.encode("utf-8") if isinstance(value, str) else bytes(value)
            if type(length) is int and len(content) != length:
                raise ValueError("String field length mismatch: " + name)
            data.extend(content)
        elif kind == "struct":
            nested = encode_message({"fields": field["fields"]}, value, order)
            if type(length) is int and len(nested) != length:
                raise ValueError("Struct length mismatch: " + name)
            data.extend(nested)
        elif kind == "array":
            items = value if isinstance(value, list) else [value]
            item = field["items"]
            for element in items:
                data.extend(encode_message({"fields": [item]}, {item["field_name"]: element}, order))
        else:
            raise ValueError("Unsupported field type: " + kind)
    if type(message.get("field_length")) is int and len(data) != message["field_length"]:
        raise ValueError("Encoded message length mismatch")
    return bytes(data)
