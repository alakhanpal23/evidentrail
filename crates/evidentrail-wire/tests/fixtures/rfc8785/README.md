# RFC 8785 conformance fixtures

These byte-for-byte input/output pairs are copied from the JSON
Canonicalization Scheme reference repository at commit
[`dc406ceaf94b5fa554fcabb92c091089c2357e83`](https://github.com/cyberphone/json-canonicalization/tree/dc406ceaf94b5fa554fcabb92c091089c2357e83/testdata).
They correspond to the primitive-serialization example and UTF-16 property
sorting example in [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html).

The fixture files have a final LF for repository hygiene. Tests remove only
that final LF from expected canonical output before comparing bytes.
