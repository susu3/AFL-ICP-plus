# Dual-role knowledge bundle contract

See `docs/IMPLEMENTATION.md`, sections 8.3–8.6. JSON role root: schema_version=1.0, protocol, role, direction, endian, nonempty messages. Message roots use message_id/message_name/description/fields/constraint_refs/source_refs. Responses additionally require response_to and response_kind. Field types: uint8/16/32/64, int8/16/32/64, byte[], string, struct, array; integer lengths match widths; dependency is boolean. All messages/fields cite source IDs.

Both Mermaid files start `stateDiagram-v2`, use annotated flat states/transitions and source refs. Both Markdown files contain stable role-owned constraint headings, YAML metadata, and a natural-language body. Do not execute constraint prose.
