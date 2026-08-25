# Approved local-file binding V1 golden

`golden.json` is the exact canonical self-contained artifact. Its declared
binding digest is independently derived from `digest_material.json`, which
contains the same contract and authority material with only the derived digest
omitted.

The digest uses
`SHA-256(u64_le(domain length) || domain || u64_le(body length) || body)` with
domain `evidentrail/approved-local-file-binding-digest/v1` and is
`binding_sha256_b6ec2c85f43706f0fb135e084bcf9f8a510e6e64c75656aa76fa3cbe82193d6c`.

The exact approved root and complete root-relative member are sensitive
Base64url-no-pad path material. They grant no glob, crawl, wildcard, or sibling
authority. The artifact carries no credential, display label, or free-form
OS/build string. Its runtime profile references a governed matrix but is not
live-host attestation. The adversarial fixtures freeze recursive
duplicate/unknown-field rejection and noncanonical Base64 rejection.
