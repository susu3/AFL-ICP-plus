"""Runs inside the isolated generator sandbox. The controller never imports generated code."""
import importlib.util
import json
import random
import sys
from pathlib import Path
from .sdk import GeneratorContext


def main():
    generator_path, input_path, output_path, limit, max_bytes, max_messages = sys.argv[1:]
    config = json.loads(Path(input_path).read_text())
    output = Path(output_path)
    output.mkdir(parents=True, exist_ok=True)
    module_spec = importlib.util.spec_from_file_location("generated_seed_program", generator_path)
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    context = GeneratorContext(config["bundle_id"], config["protocol"], config["client_schema"], config["server_schema"],
                               random.Random(config["random_seed"]), int(limit), int(max_bytes), int(max_messages))
    generate = getattr(module, "generate", None)
    if not callable(generate):
        raise ValueError("Generator must define generate(context)")
    count = 0
    for case in generate(context):
        if count >= context.candidate_budget:
            break
        if not case.messages or len(case.messages) > context.max_sequence_messages:
            raise ValueError("Invalid SeedCase message count")
        if any(not isinstance(message, (bytes, bytearray, memoryview)) for message in case.messages):
            raise TypeError("SeedCase.messages must contain bytes-like message buffers")
        messages = [bytes(message) for message in case.messages]
        payload = b"".join(messages)
        if not payload or len(payload) > context.max_seed_bytes or len(case.message_ids) != len(messages):
            raise ValueError("Seed length, emptiness or message metadata invalid")
        path = output / ("candidate-%06d.bin" % count)
        path.write_bytes(payload)
        (output / ("candidate-%06d.json" % count)).write_text(json.dumps({
            "message_ids": case.message_ids, "field_variants": case.field_variants,
            "state_path_id": case.state_path_id, "message_lengths": [len(x) for x in messages]}, sort_keys=True))
        count += 1
    (output / "worker-result.json").write_text(json.dumps({"candidate_count": count}))


if __name__ == "__main__":
    main()
