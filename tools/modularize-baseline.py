"""One-time, exact mechanical extraction of the baseline protocol block.

Kept as a reproducible migration, not run by builds. Refuses unexpected input.
"""
from pathlib import Path

root = Path(__file__).resolve().parent.parent
source = root / "aflnet.c"
text = source.read_text()
begin = text.index("// Protocol-specific functions for extracting requests and responses")
end = text.index("// kl_messages manipulating functions")
block = text[begin:end]
assert "extract_requests_modbus" in block and not (root / "protocols/builtins/legacy_ics.c").exists()
block = block.replace("extract_requests_modbus(", "legacy_extract_requests_modbus(").replace("extract_response_codes_modbus(", "legacy_extract_response_codes_modbus(")
header = '#include <ctype.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include "../../alloc-inl.h"\n#include "../../aflnet.h"\nextern u32 get_mapped_message_code(u32);\n'
(root / "protocols/builtins/legacy_ics.c").write_text(header + block)
source.write_text(text[:begin] + "/* Protocol parsers are linked from protocols/builtins or protocols/generated. */\n\n" + text[end:])
