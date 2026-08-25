# Local-file plan V1 golden

`golden.json` is the exact RFC 8785 body for the synthetic semantic plan built
in `tests/local_file_plan_contract.rs`. Its final repository LF is not part of
the canonical body. The plan explicitly commits the typed repository identity;
binding verification never substitutes a source or binding digest for it.

The frozen identities use
`SHA-256(u64_le(domain length) || domain || u64_le(body length) || body)`:

- domain `evidentrail/local-file-query-plan-id/v1`:
  `plan_0217f383900cee3170a1bf56963410b4ee0a124e123b073b328fafcb60008585`
- domain `evidentrail/local-file-query-plan-digest/v1`:
  `plan_sha256_df94986191b31f9334a94321b5d3231910689c7b74f2cb064fdbbe4c2bb79634`

`locator_identity.json` freezes the sensitive locator identity material. Its
`evidentrail/local-file-source-member/v1` hash is the opaque envelope-member bytes
`da9f6152e48fd2bc2708ba12af7c857ea05ee425d3842aae47600903592f3729`.
`source_identity_material.json` freezes the pinned adapter/proof kind, locator,
runtime/certification profile, and every represented Unix snapshot fact. Its
`evidentrail/local-file-source-identity/v1` hash is
`source_sha256_2df73541d15fdfc0aca3770d5bb2d5fc1a2118134be8665b4f1f45240cc07ff8`.
The profile pins macOS, APFS, architecture, deadline semantics, and an immutable
governed certification-matrix digest. It is not a live-host attestation and
does not carry an OS build string. Execution still needs a separate live record
of the observed profile/build and a matrix-membership check.

The `adversarial` directory retains otherwise valid documents with duplicate
fields, an unknown nested field, and padded Base64. Tests add mutations for
version, contract, hash-token, timestamp, canonical integer, pinned semantic,
canonical-byte, size, and declared-identity failures. The golden deliberately
uses Unix object identifiers above JSON's safe-integer range to freeze their
canonical decimal-string encoding. Locator root/components are sensitive
Base64url-no-pad byte strings; `source_member` is only the derived opaque
32-byte token.
