# External adjudicated corpus V3 intake

Run:

```sh
cargo run -p evidentrail-cli --example v3_external_corpus_import -- \
  manifest.jsonl /absolute/artifact/root
```

Each JSONL case is strict schema version 3 and names a relative artifact path
plus its SHA-256 digest. It must include organization/project/family/split
keys, two distinct annotators, a distinct adjudicator, affirmative independent
adjudication, consent or license lineage, and at least one diagnostic
requirement. Every acceptable alternative contains exact byte-range citations
with independent SHA-256 digests.

The importer canonicalizes paths under the supplied root, rejects split
leakage within an organization/project/family, hashes source artifacts without
loading them whole, and verifies each bounded citation range. A valid import is
still marked non-certifying until it contains at least 50 incidents across five
organizations. The repository currently contains no such external corpus.

Certification intake additionally requires a named steward independent of the
V3 implementation owners, two independent annotators and a separate
adjudicator per incident, authentic question/cause/impact/fix-or-check fields,
acceptable evidence alternatives with exact citation ranges, consent or
license lineage, retention policy, and a stable revocation identity. Artifacts
and hidden labels stay in encrypted access-controlled storage outside source
control; implementation owners receive aggregate results only.

Organization/project/service/incident/fault/trace and near-duplicate families
must be grouped before immutable split assignment. Revocation removes the
incident, changes the frozen corpus digest, and invalidates every certification
run that used the prior digest. Synthetic and local dogfood fixtures remain
contract and performance evidence only.
