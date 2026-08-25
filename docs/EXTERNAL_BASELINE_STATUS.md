# External baseline status

**Observed:** August 24, 2026  
**Purpose:** Reproducibility ledger only. This is not a product-quality score or
a claim that the greenfield system beats an external method.

## Pinned `legacy-drain` baseline

- repository: `/opt/evidentrail-bench/legacy-drain`
- commit: `5a84fb050e074b15474fdb264c9e97faaa66c9f5`
- worktree: clean before and after the checks
- relationship to this repository: external subprocess/benchmark target only;
  no product crate links, vendors, copies, wraps, or invokes its implementation

The pinned baseline passes its ordinary workspace test suite in the current
environment:

```text
64 passed; 0 failed; 6 ignored
```

The ignored cases require held-out LogHub/GitHub datasets or are an explicit
scale benchmark. They were not run, so this result does not reproduce the
published downstream diagnosis evaluation.

## Public subprocess harness now available

`evidentrail-bench-harness` is a benchmark-only crate; no product crate depends on
it. It provides a shell-free public subprocess boundary with an exact declared
executable/build artifact digest, explicit working directory, cleared and
allowlisted environment, exact synthetic/public stdin artifact, independent
stdin/stdout/stderr byte caps, a wall deadline, kill-and-reap behavior, typed
exit categories, and binary-safe stdout/stderr artifact commitments.

For V1 public cases, subprocess stdin must equal the case spec's sole declared
source artifact; multi-source cases fail closed until canonical ordering and
framing exist. The harness deterministically derives canonical public-case and
public run-manifest artifacts instead of accepting claimed digests. It also
builds an occurrence-aware source-record map from the exact stdin framing and
checks each entry against the sealed ledger and its acquisition receipt before
an invocation can be constructed. These are local reproducibility bindings,
not signatures or remote attestation.

Executable verification currently hashes the named path immediately before
and after spawn. This is self-asserted reproducibility evidence, not remote
attestation and not proof against a hostile path-replacement race. Generic
receipts accept only explicit, bound peak-RSS observations; the forced macOS
case below instead records both arms through one pinned `/usr/bin/time -l`
observer. Neither path is independent attestation, and the harness never
guesses or defaults a missing value.

The adapter at the commit above fixes the CLI arguments to
`--grouper drain --format json --samples N`. It explicitly rejects invalid
UTF-8 and records the pinned CLI's blank-line, terminator, and raw-text
normalization behavior. A bounded V1 parser now validates exactly the pinned
JSON field schema, required nullable fields, JSON-safe integer widths,
aggregate counts, deterministic group/sample ordering, numeric invariants,
and caller-selected limits below fixed hard ceilings. Unknown fields,
duplicate keys or occurrence positions, malformed JSON, and inconsistent
counts fail closed with contentless diagnostics.

The parser binds its receipt to the executable build, public invocation,
stdin, parser identity, and exact stdout/stderr artifacts. Raw stdout remains
opaque candidate content in the ordinary `--samples 2` arm. The source map
does contain exact framed source bytes and occurrence-aware EventIds, but that
ordinary output can omit members and its transformed sample fields are not
independently promoted into evidence. Its V1 result therefore remains
explicitly `MembershipUnprovable`: no template, slot summary, group count, or
sampled line is fabricated into an EventId, candidate set, evidence recall, or
quality score.

A separate, explicitly metered full-membership instrumentation arm derives
`--samples N` from the retained nonblank record count. It is bounded to 4,096
records, 4 MiB input, and a 16 MiB stdout capture, and rejects unsupported
inputs before invocation. Its current exact replay of pinned `parse_line`
semantics is ASCII-only; invalid UTF-8, non-ASCII UTF-8, empty retained input,
and cap failures are explicit cohort outcomes rather than silently dropped
cases. The normalizer verifies each sample's retained index, normalized text,
level, and timestamp, requires each group sample vector to equal its count,
requires a global bijection over all retained indices, and joins those
occurrences to the source-record map's EventIds.

That full arm has a distinct adapter, invocation, normalizer, stdout artifact,
and resource envelope. Every retained occurrence and its source bytes are
charged to the candidate budget; its full execution/output must receive its
own time, memory, and output accounting. Group membership is labeled
`PatternRepresented`, while emitted sample renderings are labeled
`TransformedSample`. Neither is `SourceExact` or `ShownVerbatim`, so the
artifact supports occurrence/resource/compression accounting but deliberately
does not auto-credit exact-event diagnostic recall. A representation-fidelity
evaluation or downstream-agent VDS remains required for a quality score.

## Governed representation-fidelity bridge now available

`evidentrail-bench` now freezes a public, score-free representation submission before
hidden annotations are admitted. It binds the public run/case/method,
retrieval, normalizer, rendered-candidate bytes and digest, externally observed
resource vector, and occurrence-aware representation claims. A
`SourceExactShownVerbatim` claim must identify a unique, non-overlapping byte
range in the frozen rendered artifact whose bytes exactly equal the sealed
ledger event, including whitespace, terminators, invalid UTF-8, and NULs.
The hidden-manifest case join carries the exact public run-manifest artifact
digest, and governed evaluation rejects a same-case submission from any other
run before consulting the annotation policy.

The governed side has exactly one closed fidelity rule per diagnostic
requirement. Exact byte-proven claims are eligible directly. A transformed
sample can be checked against that requirement's hidden expected event and
transformed-artifact digest, but the current public receipt does not prove that
the per-event transform is reader-visible in the rendered byte artifact.
Therefore even an exact hidden match can only be rejected or deferred; it
cannot receive static recall credit. Pattern-only material has the same closed
choices. The default rejects both classes, while a policy may defer a
completely represented alternative to a typed `NeedsDownstreamVds` outcome. A
deferred case emits no partial scalar score. Missing occurrences remain misses
rather than being upgraded to a downstream-study request.

The static exact path now also admits one closed reversible representation:
`ascii_byte_escape_v1`. Its independent benchmark decoder accepts only the
canonical lowercase single-line grammar, binds the codec identity and exact
half-open data range plus its canonical `data_encoding`/`data` field-prefix
context into the submission artifact, decodes that rendered range, and
requires a byte-for-byte match with the sealed ledger event. Including the
nonempty field context in overlap checks gives even a zero-byte source event
an occurrence-specific proof. Malformed or substituted context, noncanonical
escape text, mutation, overlap, duplicate ranges, and unknown codecs fail
closed. Invalid UTF-8, NUL, CRLF, tabs, backslashes, empty events, and duplicate
identical occurrences are scoreable only when each occurrence has its own
valid field-context proof. This does not relax transformed or pattern-only
handling.

An acyclic benchmark-only bridge accepts typed canonical first-party
passthrough and compiled Log Brief renderer outputs. It cross-checks their
structured event order, renderer/tokenizer identities, complete rendered
artifact, and per-event canonical encoded fields before constructing the same
governed reversible claims. Both borrowed render results and the owned product
artifacts produced by `into_owned` use the same bridge. Passthrough and compiled
outputs retain distinct method and renderer identities; retained-raw compiled
events are not fabricated into the displayed candidate set. The receipt also
reports the sealed ledger's full occurrence/byte input-universe charge
separately from displayed evidence occurrence/source bytes and from rendered
token/runtime measurements. The generic submission calls the displayed set a
candidate set, but this is final-render accounting, not the pre-ranking
candidate-generator proposal union. Input-universe accounting also does not
substitute for the still-open proposal-recall/cost benchmark. Duplicate payload
occurrences are charged independently. V1 explicitly rejects an entirely empty
ledger as an unsupported benchmark cohort because the generic governed
submission requires at least one claim; this is distinct from a zero-byte
event, which has the field-context proof described above.

The first-party integration test now obtains those owned renderer artifacts
from the actual `MemoryProductV1::create_deterministic_result_v1` owner for one
canonical public case. The same exact source, sealed ledger, plan, and raw
question bytes exercise a high-budget passthrough result, a lower-budget
compiled result, and a typed zero-token `NeedsMore` result. Before either
displayed representation is frozen, a case-bound bridge verifies the canonical
public case and run artifacts, occurrence-aware source-record map, acquisition
receipt, question digest, plan digest, and selected declared budget point.
Product expansion remains byte-exact through the owner. In the compiled arm,
only packet members displayed in the final Log Brief receive reversible claims;
retained-raw members receive no static credit, while the separate input-universe
charge still covers every ledger occurrence and source byte.

A typed matched-representation scaffold now joins two already-governed results
only when their public run manifests are pairwise comparable, their canonical
run/case artifacts and hidden case binding agree, their method identities are
distinct, and their outcomes bind the frozen submissions exactly. It keeps the
two public method identities and both complete five-dimensional resource
envelopes on every returned outcome. Costs remain separate, and the scaffold
can order only exact static-recall ratios; it does not produce an overall
scalar winner. If either arm needs downstream VDS, the whole comparison returns
`NeedsDownstreamVds` and exposes no recall ordering. Wall time and peak RSS must
be explicit nonzero observations, and the returned arm receipts label the
current measurements as self-asserted reproducibility inputs rather than
independent attestation. The synthetic contract tests use fixed nonzero values
solely to exercise validation and do not publish them as measurements.

The full-membership `legacy-drain` bridge freezes its separately executed and
charged arm under the distinct
`legacy-drain-full-membership-adapter` method identity. The compact arm cannot
be substituted for it. This bridge proves representation and resource
provenance; it does not itself author the hidden transformed-acceptance policy
or run a downstream reader. Consequently the pinned smoke below remains
non-scoreable despite complete occurrence membership.

This adapter covers only the pinned open-source `legacy-drain` CLI. It must not
be described as a result for the hosted/current Evidentrail product. Any future
hosted API arm is separate and opt-in, with its own credentials, terms, and
data-policy review.

## Current hosted-interface pins (not invoked)

For later opt-in harness design only, the current official CLI release is
`v0.2.12`, published August 15, 2026 from commit
`eff49fc3d19c3a5c9771e762cb58adb855e10fe9`. Its Darwin arm64 release asset has
SHA-256
`882c1976ee5e6474b0af50bb88d2e0c8980d9b3d758007dc3de2b66dacb3ca60`.
The current `evidentrail-sdk` main pin is
`e24b9835010f047ba5a17c90f106b53358c7f317`, and its OpenAPI 0.2.0 raw artifact
has SHA-256
`57de2ecf62ac5fdf7a20e0918b7171242a26446503e8f1bfd2e4e7bfa2b8d188`.
Nothing in this repository installed or invoked that CLI or hosted API, and
these pins carry no reproducibility or quality result.

## Opt-in pinned local smoke evidence

On August 24, 2026, the ignored local smoke test was run explicitly after the
checkout was confirmed clean and at the pinned commit. The checkout was still
clean afterward. This is reproducibility evidence for one opaque CLI artifact,
not a benchmark score.

Build command and environment:

```text
cwd: /opt/evidentrail-bench/legacy-drain
cargo build --locked -p legacy-drain --bin legacy-drain
rustc 1.98.0 (88d9e12ae 2026-08-18), aarch64-apple-darwin
cargo 1.98.0 (797e8a9bc 2026-08-05)
```

Observed executable and invocation:

```text
HEAD: 5a84fb050e074b15474fdb264c9e97faaa66c9f5
executable: /opt/evidentrail-bench/legacy-drain/target/debug/legacy-drain
executable SHA-256: 40a83db59cf20246381363eddb2d27c56a386d9e4dcf32ac8115f55b9445d220
cwd: /opt/evidentrail-bench/legacy-drain
environment: cleared; no bindings
argv: --grouper drain --format json --samples 2
canonical public run-manifest SHA-256: 56d564c6416b96944999192cac0e4644d4801080089aee0a0d69b33342ddd7a2
canonical public case SHA-256: 6cb9233c12421837be94ce0a6079f8dd22d0d89c450d604af14ff5786ac78f5c
stdin SHA-256: 88c0b98f60e7a2f2e589f12fd8be06cc1558c00c350e40235071c434d1c94cc5
source-record map SHA-256: 1263aa89bb9d831b74b4ada5ef2294f182db40d0dbb6d1a9ae0cac8468d1392a
retained-record map SHA-256: 7eabdfa379bca8a10122953fcd58f33bcdc3872415e84ca21a47d7c4fdf272f4
compact invocation SHA-256: 10a922f860774c83be65a93c33c24f8f48a48d6ee6c3ffe7e72ec6e38c0a069e
```

The exact declared single-source synthetic input was valid ASCII/UTF-8 with
six logical lines, five retained nonblank lines, one dropped blank line, five
LF terminators including one CRLF, and no final LF. Three retained lines form
one group, so the compact sample cap of two exposes only four of the five
occurrences overall. The adapter also confirmed that invalid UTF-8 is
unsupported. The source map proves exact input framing; the normalization
record describes where the external CLI transforms it.

Two isolated executions both exited successfully and produced identical raw
artifacts:

```text
stdout bytes: 1570
stdout SHA-256: 006b9081701d6992f0895973a9894fa62eeaa78a7a54fe8c853fa75805b6a8d1
stderr bytes: 0
stderr SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

Both raw outputs also passed the strict bounded V1 schema parser and produced
the same score-free opaque normalization receipt:

```text
normalizer contract SHA-256: 2448caaf2425b3211cecfaf083dc719fa75e30f9612d4ce6cb42647655c27000
normalization receipt SHA-256: 830eb9517109160da633ed5402d6543394c27a7302785a6e22f1cf8a03ecd77b
parsed structural facts: 5 original records, 2 groups/templates, 4 samples, 2 slots, 5 slot samples
membership: unprovable
candidate membership scoreable: false
```

The same declared case was then run as the distinct full-membership
instrumentation arm. This was a second, charged execution—not an unmetered
sidecar used to credit the compact arm:

```text
argv: --grouper drain --format json --samples 5
adapter contract SHA-256: 0fccb08e86077721af2ef9b11a37769bf0011c647f1afb5124888b21d48d4f57
normalizer contract SHA-256: 0a814fad482a88699b2c53aa1d4a3a8513f37fc183340157d0f36e5f0da44d6f
invocation SHA-256: e8fb4ed0fcdb1aa4c566ac81510f3adc4abc70b7e787a1661751baab3ecfe28c
stdout bytes: 1732
stdout SHA-256: dc7c13ff6b661f78048f92df916e07d5736259c745ce1e060d0460cf48be37b8
normalization artifact SHA-256: 95c3b36943115e770a233882d8b0330ba92d2121dd6dda9e299a7eb5817a27af
complete occurrence membership: 5
charged candidate source bytes: 252
representation: PatternRepresented + TransformedSample
SourceExact / ShownVerbatim: false
diagnostic evidence recall scoreable: false
```

The full stdout is both larger and digest-distinct from the compact stdout,
which exercises the actual compact-versus-complete information boundary.

### Score-free same-case preparation

A second ignored test exercised the actual `MemoryProductV1` owner and the
verified pinned full-membership executable on that same canonical public case.
The two run manifests bind the same case, dataset, seed, and five declared cap
dimensions, while retaining distinct system/build and method identities. The
hermetic helper used by the default suite has a separate fixture-only system,
adapter revision, and method identity; it cannot be mistaken for the pinned
checkout arm.

The opt-in local preparation observed:

```text
public case SHA-256: b173068cc7c57853d4280733abaa6095d36a5fe68f08f37a750b87f1f814d56c
first-party executable/build SHA-256: 3164c3dae1675baa149b62da7a9362f42fb9744286450aa1b9b1eb391bf095c7
first-party run-manifest SHA-256: 932ad43d65e2951bc044a0d8f3e8dc6035cbedde57af502092b289a18aa760bb
first-party rendered artifact SHA-256: 616100edb9e6efb4959ef45356d5f69254527823e78617d3ea753437d130d228
first-party canonical UTF-8-byte tokens: 1751
first-party timing scope: first_party_preacquired_ledger_to_owned_render
legacy-drain executable/build SHA-256: 40a83db59cf20246381363eddb2d27c56a386d9e4dcf32ac8115f55b9445d220
legacy-drain run-manifest SHA-256: 0ebb6ad02773d886f6fef0afa52297cd2acff833e674d29e54c9a44bfb326d1c
legacy-drain invocation SHA-256: ee933b4a5cc20c3eddf0de50f891799d3759511a721a2ebe2d5fe9f9a46efee7
legacy-drain full-membership artifact SHA-256: 0b24e02116357568f4d183abfcbe87445e82d980a309d8875900b17a2fced957
legacy-drain stdout SHA-256: dc7c13ff6b661f78048f92df916e07d5736259c745ce1e060d0460cf48be37b8
legacy-drain canonical UTF-8-byte tokens: 1732
legacy-drain timing scope: drain_raw_public_stdin_to_captured_full_membership_output
peak RSS: missing (typed finalization blocker)
cost ordering: ineligible_unequal_execution_scopes
```

Both token counts are bound to the exact whole rendered artifact, tokenizer
identity, byte count, and measurement contract. The two executions are charged
separately. However, their wall-time scopes are deliberately not treated as
comparable: the first-party clock covers product creation from an already
sealed ledger, while the subprocess clock covers raw-public-stdin parsing,
compression, and captured output. `PreparedPinnedDrainMatchedCaseV1` and its
finalized form expose both scope identities and always return
`cost_ordering_eligible = false`; no Pareto/runtime claim can be emitted from
these receipts. A later run must measure equivalent end-to-end scopes.

The preparation cannot finalize without one nonzero peak-RSS observation per
arm. Each injected observation must bind its arm, system artifact, executable
build, canonical run manifest, public case, measurement-mechanism artifact,
and byte unit. Such observations remain self-asserted reproducibility inputs,
not independent attestation. No anonymous fixture value was inserted into the
opt-in result.

This preparation is still not a quality comparison. Full `legacy-drain`
membership remains `PatternRepresented`/`TransformedSample`, so it needs
downstream VDS or a sound representation-fidelity decision before diagnostic
quality can be compared. Neither arm exposes the pre-ranking producer proposal
union, so candidate proposal recall/cost also remains blocked.

The smoke remains ignored by default and is rerun explicitly with:

```text
cargo test -p evidentrail-bench-harness --test pinned_legacy_drain_smoke pinned_local_legacy_drain_is_deterministic_and_non_scoring -- --ignored --exact
cargo test -p evidentrail-bench-harness --test pinned_legacy_drain_smoke pinned_local_legacy_drain_prepares_exact_matched_case_without_peak_rss_fabrication -- --ignored --exact --nocapture
```

The compact arm still rejects its byte-identity candidate normalizer and emits
no EventId membership. The full arm proves complete occurrence membership but
does not turn a coarse pattern representation into exact displayed evidence.
No evidence recall, quality conclusion, or hosted-Evidentrail result was constructed.

Strict current-toolchain Clippy does not pass at this commit. Rust 1.98 reports
new warnings-as-errors in the external `drain3_rust` crate: two explicit loop
counters, one `?` rewrite, one over-indented documentation list item, and one
manual `div_ceil`. We do not patch the pinned competitor checkout merely to
make our comparison environment green. A future matched run must record this
toolchain fact and execute the already-tested binary/build artifact.

## Gate before any comparison claim

The same-case preparation now proves the public case/run bindings and obtains
an actual first-party owned artifact, but a Evidentrail-versus-greenfield result is
admissible only after the governed harness can also prove:

1. identical public case cohort and dataset identity;
2. identical seed and all five resource-budget dimensions;
3. score-free external output submitted before hidden annotation access;
4. exact case coverage with no missing, duplicate, or extra results; and
5. paired governed scoring with acquisition and presentation accounting kept
   separate from diagnostic recall;
6. equivalent end-to-end timing scopes plus bound peak-RSS observations; and
7. explicit producer proposal-union accounting if candidate recall/cost is
   claimed.

Until those gates pass, the published `legacy-drain` numbers are context, not a
score for this implementation.

The remaining blockers to an honest matched, score-bearing run are:

1. preregistered, independently adjudicated per-case transformed-fidelity
   policies and/or a governed downstream-agent VDS for pattern-only cases;
   complete occurrence accounting alone does not prove diagnostic utility;
2. execution of each external declared renderer and tokenizer with bound
   artifacts rather than merely self-asserted identities; the first-party
   product-owned renderer path is now exercised, but that does not attest the
   external arm;
3. use of one comparable resource observer across every case in the eventual
   preregistered cohort; the macOS observer below closes this dimension only
   for the frozen constrained case and is not a portable attestation; and
4. execution of both systems over the exact paired public cohort followed by
   governed evaluation. No such score has been produced yet.

For the narrower candidate-generation comparison, the earlier small matched
case took exact passthrough and therefore did not create a production proposal
universe. The forced compiled-path case below now freezes the exact first-party
proposal receipt and a conservative Drain occurrence upper bound. A
preregistered multi-case governed proposal-recall/cost join is still required;
the full input-universe charge and final displayed-member set may not stand in
for proposals considered before ranking. This remains separate from the
downstream-VDS blocker for external pattern quality.

## Forced compiled-path producer-universe evidence

A second, frozen synthetic case now closes the earlier passthrough limitation.
It contains 200 exact source occurrences across four runtime lanes and three
stream kinds, totals 151,072 bytes, and has input SHA-256
`bf329d44a03d7654f6996a4eec96a6fb2cdd93d3dbdbfb25e1d6930abe01fe0f`.
Its bounded question and 180,000 canonical UTF-8-byte-unit budget force the
actual first-party compiled product path. Fresh block reconstruction, proposal
receipt/accounting, selection certification, mandatory evidence, and the
selected UUID failure block are all checked against the exact ledger before
the harness admits the artifact. The frozen proposal identity includes
proposal-compiler policy V3 and the one-quarter breadth-only source/time facet
weight. Compiled brief/renderer contract V2 presents diagnostic evidence,
then reconstruction evidence, then breadth, with a checked order-consistent
marginal sum and closed semantic role codes.

The first-party arm now also runs through a separate shell-free benchmark
helper. That child accepts only the frozen 151,072 raw public bytes,
deterministically reconstructs this case's specified mixed-lane ledger, invokes
the actual `MemoryProductV1` production API, and writes only the owned canonical
render to stdout. The parent independently creates and validates the same owned
product artifact and admits the child receipt only after an exact byte-for-byte
comparison. The child helper build and the parent oracle executable are hashed
and bound separately; both are self-asserted local path-hash evidence, not
process/dependency attestation. This is a frozen-case reconstruction contract,
not proof of a general first-party raw-log parser or acquisition path.

Both subprocesses are now launched, without a shell, under the same canonical
`/usr/bin/time -l` executable and the same versioned report parser. The harness
hashes the observer before spawn and after reap, captures its report in an
atomically created mode-0600 file under a mode-0700 directory, strictly accepts
one nonzero unsigned `maximum resident set size` value, and removes the exact
file and directory. The unit is bytes. This is macOS direct-timed-process
`time -l` semantics; it does not claim a child-tree aggregate. Observer and
target path hashing remain self-asserted local reproducibility evidence, not
attestation or proof against a hostile replacement race.

The opt-in run against the unchanged pinned checkout observed:

```text
generator SHA-256: 951add65d55c0314f75d8a1a7753e430e4af951246d063f797bdaed13c020544
public input SHA-256: bf329d44a03d7654f6996a4eec96a6fb2cdd93d3dbdbfb25e1d6930abe01fe0f
public case SHA-256: 72c50a900d1b3cc33258914517f63059cf485e630698c05feef61403bc1073cc

first-party complete pre-selection proposal packets: 14
first-party unique proposal members: 17 events / 9,602 source bytes
first-party displayed packets: 13
first-party proposal receipt SHA-256: b348812bd235c0f1bcbd0e6d6a8f7653953fc80a0ae9000d90da1e52964c496f
first-party helper build SHA-256: b508d8bbd83773d788bab5625804d639a454bd9fa82a8bb1c5f8f4fcf104c7f2
parent oracle executable SHA-256: 1cf9bed3260438b0e991bb6b81bc3d2756fb8a927da74143d9556097635532e5
first-party adapter contract SHA-256: da25882befecb190b633f19ab902c9e5fd6e07695921cfd096953f49437b509e
first-party run-manifest SHA-256: b31e525ee3464d69291955ba8b5a6f6e77728673d8a6ce76d6089f7cdb5a0686
first-party invocation SHA-256: 8c0cf1f7b5fea6f76e2f2b19be9f7f4f17220b8e4fb30c466733cf14fed1171f
first-party subprocess receipt SHA-256: 3ca0224291e11dc5fe02c7cac5f5f23aa6fb341a51c83db11a518530a2201630
first-party complete rendered artifact: 13,936 canonical UTF-8-byte units
first-party captured stdout SHA-256: f194c3320913076c7f06fd4a944ebff3317029f5d2ddd8aece0f278f2412f1fd
first-party wall scope: raw_public_stdin_to_captured_process_output

Drain full-membership pattern groups: 8
Drain complete occurrence partition: 200 events / 151,072 source bytes
Drain run-manifest SHA-256: 8ecd4ef26d1d2f28fdb61a58374a67a4d28a20afd02c46f65b10f1f74122d8bb
Drain invocation SHA-256: f3245df6640206ae6d1a0723a85adc0b1c56d69c6213d32d346e6965f8ee8af0
Drain full-membership artifact SHA-256: 693fb7302511b7e8fdf516e4ff79054a5328e0f485a996e53d548eab1c3507a6
Drain full stdout: 179,637 bytes / canonical UTF-8-byte units
Drain stdout SHA-256: d68a6a7653291e5971661b531065711079fd53db0643837044e131e70492ca4f
Drain wall scope: raw_public_stdin_to_captured_process_output

observer canonical path: /usr/bin/time
observer executable SHA-256 before/after both arms: fc8c6dcfe9e6eba13390456e7f6875c0634c7a16784128c92c6dabf4f1159f36
observer report-format SHA-256: 202ec6a586d2dba084c30da891d1a3991f5fd8128b1d30ec20e3e2e46570f457
observer mechanism SHA-256: 5f9bd893ccb9514c85acbb0ed93831ae8f5db0c163c4ef10fa56f02a0a8f24ef
trial-zero first-party observed peak RSS: 8,273,920 bytes
trial-zero first-party peak-RSS receipt SHA-256: 0b4e2920bb61c1a35c97083340a23344e97d0fad18a8fffe5e1142e17cdca7b9
trial-zero Drain observed peak RSS: 8,208,384 bytes
trial-zero Drain peak-RSS receipt SHA-256: a0739874d9984e536ee2bd87e4307a9b8cb3429265bc010ad4f4065377419222
trial-zero finalized constrained receipt SHA-256: 4309a637e6c6a0e1337e0b8bd0d965f48066aa257c2a8330040c8d1f9e5ff5dd
cost ordering: eligible_common_process_scope_and_peak_rss_observer
```

The finalized case above is trial zero of a fixed three-trial repeatability
envelope. Its preregistered external-arm order alternates Drain→first-party,
first-party→Drain, Drain→first-party. Trial zero is the original governed
preparation rather than an unreported warm-up. Every trial retains both raw
captured-output receipts, raw wall-time nanoseconds, nonzero RSS bytes, and the
observer raw-report digest/count. The receipt rejects missing, duplicate,
reordered, foreign-build, foreign-case, foreign-invocation, output-mutated, or
observer-mismatched trials before computing exact integer summaries.

```text
trial 0 order: pinned_drain_then_first_party
  first-party wall/RSS: 556,061,875 ns / 8,273,920 bytes
  Drain wall/RSS: 416,419,334 ns / 8,208,384 bytes
trial 1 order: first_party_then_pinned_drain
  first-party wall/RSS: 551,344,708 ns / 7,847,936 bytes
  Drain wall/RSS: 416,332,750 ns / 8,421,376 bytes
trial 2 order: pinned_drain_then_first_party
  first-party wall/RSS: 549,714,208 ns / 7,979,008 bytes
  Drain wall/RSS: 416,049,542 ns / 9,191,424 bytes

first-party wall ns min/median/max/MAD: 549,714,208 / 551,344,708 / 556,061,875 / 1,630,500
first-party RSS bytes min/median/max/MAD: 7,847,936 / 7,979,008 / 8,273,920 / 131,072
Drain wall ns min/median/max/MAD: 416,049,542 / 416,332,750 / 416,419,334 / 86,584
Drain RSS bytes min/median/max/MAD: 8,208,384 / 8,421,376 / 9,191,424 / 212,992

first-party stdout in every trial: f194c3320913076c7f06fd4a944ebff3317029f5d2ddd8aece0f278f2412f1fd
Drain stdout in every trial: d68a6a7653291e5971661b531065711079fd53db0643837044e131e70492ca4f
paired repeatability receipt SHA-256: ca22f8e20cf69c7c3ec498d401cef37784dbf45034e495dee43ecad3ad5611cb
paired receipt policy label: proposal_compiler_v3_pre_provider_correlation_fix
```

These observations were recorded on August 24, 2026. They are separate
resource/output dimensions, not deterministic performance constants, a
scalar winner, or a quality conclusion. RSS remains direct-process-only and
self-asserted; no child-tree aggregate or independent attestation is claimed.
Stable input, method, invocation, output, proposal, observer-mechanism, and
universe identities are frozen independently from the variable observations.

This envelope is specifically the proposal-compiler-policy-V3 build identified
above, before a subsequently discovered provider-correlation selection
residual is fixed. It is preserved as pre-fix evidence and is not a final
release freeze. A future principled policy change requires an exact rebuild,
rebind, and rerun even if this forced case's public input bytes are unchanged.

The label-free proposal bridge freezes these exact public artifacts before any
governed annotation:

```text
first-party universe SHA-256: c00e487b898a8e873f1852cab522a23676e9a72edf9049c0f8428cf9ac8b9d65
Drain occurrence-upper-bound universe SHA-256: e9b5be56b8061011df4f9b26016e5984ad51b4ea2662c15785e41794bf1ac8c0
paired bridge SHA-256: b833d34b89c1ac68e74c90655b5407f7ceddbfa4b7c0c34d87aa3261c0ab9728
```

The first-party side is the exact budget-independent production proposal API.
The Drain side is deliberately typed as a separately charged, post-hoc complete
occurrence-membership upper bound reconstructed from `--samples 200`. It is not
an original Drain pre-ranking API, source-exact visibility, representation
recall, downstream VDS, hosted Evidentrail behavior, or a score. Thus this run proves
that an honest same-frozen-input/ledger proposal comparison can now be constructed;
it still does not prove a product-quality win. The two wall measurements now
share the same process envelope for this exact case: child startup, raw stdin
delivery, case-specific work, bounded output capture, and reap. That does not
claim equal internal work or general acquisition/parser parity. Because the
same observer mechanism now binds nonzero byte-valued peak RSS for both arms,
the typed receipt admits exact five-dimensional resource/Pareto ordering for
this constrained case. It emits no scalar winner, and the different proposal
semantics remain explicit. A preregistered hidden annotation and a sound
decision for transformed/pattern representation are still required before any
diagnostic-quality comparison.

This forced smoke remains ignored by default and was rerun explicitly with:

```text
CARGO_TARGET_DIR=/tmp/evidentrail-bench-repeat-target.oiaFml cargo test -p evidentrail-bench-harness --test pinned_legacy_drain_smoke pinned_local_legacy_drain_prepares_constrained_compiled_case -- --ignored --exact --nocapture
```

The external checkout was clean at
`5a84fb050e074b15474fdb264c9e97faaa66c9f5` immediately before and after the
successful run. No hosted Evidentrail endpoint was contacted.

### Post-fix proposal-compiler V4 observation

The provider-correlation top-2 policy challenger was admitted only after its
selector/compiler tree passed the focused gates. The paired harness no longer
uses a descriptive policy label as authority. It derives a typed identity from
the production candidate-config digest, compiler-config digest, compiler
policy name, and compiler policy version; the ignored smoke freezes the
expected identity below and rejects a mismatch before observer construction or
either arm's subprocess execution. After the first-party baseline preparation,
the harness also reconciles the production proposal audit's candidate and
compiler config digests against that same identity before any repeated trial.

```text
first-party selector/compiler policy identity SHA-256: 1afbae0b9a6006c4bdc0939d683114404acbfff6baabca7cdec2605562025a0c
proposal compiler policy version bytes: 34 (ASCII "4")
```

Execution-history limitation: one complete unmeasured three-trial preflight
schedule—six subprocess executions, one execution of each arm in each
trial—preceded the reported V4 schedule. That preflight passed the frozen V4
policy admission and completed the paired runner, then failed at a stale V3
producer-universe assertion outside the runner. Its process had already exited
before the assertion was corrected, so its raw wall-time and peak-RSS values
are irrecoverable. No receipt or comparison result from that failed test
process was admitted or recorded. The recoverable public facts were:

```text
preflight first-party universe SHA-256: 99332c0b3ca43c71b0522b8bda763f3f5aba2aa7bda5a3007d786b9f7c844c71
preflight Drain universe SHA-256: e9b5be56b8061011df4f9b26016e5984ad51b4ea2662c15785e41794bf1ac8c0
preflight paired bridge SHA-256: 0cbe95dd28f42b1464639bc515913c442726746b5d7a953fd9f011fcebefdda5
preflight first-party packets / Drain groups: 14 / 8
preflight raw wall/RSS observations: unavailable after process exit
```

Accordingly, the receipt's trial-zero property means only that there is no
unreported warm-up *inside the reported three-trial schedule*. It does not
attest that the host had no prior executions. The following wall/RSS values
are warm-state-qualified observations and must not be presented as cold-start
measurements. The preflight history is documented here but is not committed by
the V4 receipt itself.

The subsequent successful V4 schedule observed:

```text
generator SHA-256: 951add65d55c0314f75d8a1a7753e430e4af951246d063f797bdaed13c020544
public input SHA-256: bf329d44a03d7654f6996a4eec96a6fb2cdd93d3dbdbfb25e1d6930abe01fe0f
public case SHA-256: 72c50a900d1b3cc33258914517f63059cf485e630698c05feef61403bc1073cc

first-party complete pre-selection proposal packets: 14
first-party unique proposal members: 17 events / 9,602 source bytes
first-party displayed packets: 13
first-party proposal receipt SHA-256: 0ad894f894cd9b80f8a3e04c19d92d52f6732f2760e221b033900a8653c072ac
first-party producer universe SHA-256: 99332c0b3ca43c71b0522b8bda763f3f5aba2aa7bda5a3007d786b9f7c844c71
first-party helper build SHA-256: ca3b7cd67c008bd24cbd7c7d7bd6618f64a2bd9766f8e1610862b0cf0eaa1e23
parent oracle executable SHA-256: 977ee72a24cd54093984126d862949ff974c41ad2dfa4f406890fc8c0f07fd1f
first-party adapter contract SHA-256: da25882befecb190b633f19ab902c9e5fd6e07695921cfd096953f49437b509e
first-party run-manifest SHA-256: 407e1e674bf6998e6a28605d17b8e1f05153e49fdfeefb62df0e956f09037e35
first-party invocation SHA-256: 92310610af05784fdbe00116f16260ec8c387e0a2a4970e51efd18c7574373a4
first-party subprocess receipt SHA-256: 195e2ab4866feb8964f63cc51b11fc688307cc2e626c237381bfec4a52ce7fd9
first-party rendered artifact: 13,936 canonical UTF-8-byte units
first-party stdout SHA-256: f194c3320913076c7f06fd4a944ebff3317029f5d2ddd8aece0f278f2412f1fd

Drain full-membership pattern groups: 8
Drain complete occurrence partition: 200 events / 151,072 source bytes
Drain executable SHA-256: 40a83db59cf20246381363eddb2d27c56a386d9e4dcf32ac8115f55b9445d220
Drain run-manifest SHA-256: 8ecd4ef26d1d2f28fdb61a58374a67a4d28a20afd02c46f65b10f1f74122d8bb
Drain invocation SHA-256: f3245df6640206ae6d1a0723a85adc0b1c56d69c6213d32d346e6965f8ee8af0
Drain full-membership artifact SHA-256: 693fb7302511b7e8fdf516e4ff79054a5328e0f485a996e53d548eab1c3507a6
Drain stdout: 179,637 bytes / canonical UTF-8-byte units
Drain stdout SHA-256: d68a6a7653291e5971661b531065711079fd53db0643837044e131e70492ca4f
Drain occurrence-upper-bound universe SHA-256: e9b5be56b8061011df4f9b26016e5984ad51b4ea2662c15785e41794bf1ac8c0
V4 paired producer bridge SHA-256: 0cbe95dd28f42b1464639bc515913c442726746b5d7a953fd9f011fcebefdda5

observer executable SHA-256: fc8c6dcfe9e6eba13390456e7f6875c0634c7a16784128c92c6dabf4f1159f36
observer report-format SHA-256: 202ec6a586d2dba084c30da891d1a3991f5fd8128b1d30ec20e3e2e46570f457
observer mechanism SHA-256: 5f9bd893ccb9514c85acbb0ed93831ae8f5db0c163c4ef10fa56f02a0a8f24ef
trial-zero first-party peak RSS: 8,617,984 bytes
trial-zero first-party peak-RSS receipt SHA-256: 1639db455a49a6eac10682cf6e3d82c0fef054cd9ca2d3cf1050440690653aed
trial-zero Drain peak RSS: 9,912,320 bytes
trial-zero Drain peak-RSS receipt SHA-256: 93f45c40fc1e30897101c8ba19336785cbd7fb771be3f538821efc2aa77505c9
finalized constrained receipt SHA-256: a47785a7c1fe9bc8cf08ae4bc4a31c41cc6d8b4745e83fd60c4af4fbe79cd57c
```

The exact reported schedule and integer summaries were:

```text
trial 0 order: pinned_drain_then_first_party
  first-party wall/RSS: 570,279,583 ns / 8,617,984 bytes
  Drain wall/RSS: 426,642,625 ns / 9,912,320 bytes
trial 1 order: first_party_then_pinned_drain
  first-party wall/RSS: 557,136,917 ns / 8,077,312 bytes
  Drain wall/RSS: 417,571,667 ns / 8,388,608 bytes
trial 2 order: pinned_drain_then_first_party
  first-party wall/RSS: 552,749,459 ns / 8,486,912 bytes
  Drain wall/RSS: 417,747,250 ns / 9,437,184 bytes

first-party wall ns min/median/max/MAD: 552,749,459 / 557,136,917 / 570,279,583 / 4,387,458
first-party RSS bytes min/median/max/MAD: 8,077,312 / 8,486,912 / 8,617,984 / 131,072
Drain wall ns min/median/max/MAD: 417,571,667 / 417,747,250 / 426,642,625 / 175,583
Drain RSS bytes min/median/max/MAD: 8,388,608 / 9,437,184 / 9,912,320 / 475,136

first-party stdout in every reported trial: f194c3320913076c7f06fd4a944ebff3317029f5d2ddd8aece0f278f2412f1fd
Drain stdout in every reported trial: d68a6a7653291e5971661b531065711079fd53db0643837044e131e70492ca4f
post-fix V4 paired repeatability receipt SHA-256: f16a12e07668166db3d5c60fe6cd96530e44e5aa160b718af71667733946359b
```

The V4 policy changed the first-party proposal receipt/universe identities but
did not change this forced case's first-party final rendered bytes. Every Drain
expectation remained unchanged: checkout commit, executable, run/invocation,
normalizer/full-membership artifact, stdout, occurrence universe, counts, and
source-byte accounting. This is resource/output reproducibility evidence only:
no scalar winner, diagnostic-quality score, representation-fidelity result,
downstream VDS result, child-tree RSS aggregate, independent attestation,
hosted-Evidentrail claim, or cold-start performance claim is made.

The successful V4 run used the same ignored command shown above. The external
checkout was clean at `5a84fb050e074b15474fdb264c9e97faaa66c9f5`
before the preflight attempt, between attempts, and after the successful
schedule. No external checkout file was modified and no hosted Evidentrail endpoint
was contacted.

## Pinned open-engine paired deterministic-reader checkpoint — 2026-08-24

The forced public synthetic case was subsequently passed through the
provider-neutral paired-reader boundary using the actual clean local
`legacy-drain` checkout and the hermetic deterministic reader. The exact Git
HEAD is the 40-character
`5a84fb050e074b15474fdb264c9e97faaa66c9f5`; a spelling with an additional
trailing `e` is not the checked-out object. The executable remained pinned to
SHA-256
`40a83db59cf20246381363eddb2d27c56a386d9e4dcf32ac8115f55b9445d220`.
The checkout was clean before and after the run.

The opt-in command was:

```text
cargo test -p evidentrail-bench-harness --test pinned_paired_reader_smoke pinned_actual_constrained_pair_runs_deterministic_reader -- --ignored --exact --nocapture --test-threads=1
```

The receipt and reader-input identities were:

```text
public case SHA-256: 72c50a900d1b3cc33258914517f63059cf485e630698c05feef61403bc1073cc
first-party production proposal receipt SHA-256: 0ad894f894cd9b80f8a3e04c19d92d52f6732f2760e221b033900a8653c072ac
Drain full-membership normalization receipt SHA-256: 693fb7302511b7e8fdf516e4ff79054a5328e0f485a996e53d548eab1c3507a6
finalized product receipt SHA-256: 48bcb0311b10d9d025fe1fcd69fe13814cd7e7030551fded84fe68cb8a74f9ec
paired reader-input SHA-256: dffbb1532476de4b5a1b582b58bedac649dd20f2c0f610b513d2c5b045af8125
first-party reader-method binding SHA-256: f97d415625b2eb376b95f61622f6371708be5f78ffea6d4494d24d5b429f0279
Drain reader-method binding SHA-256: 0fbc3769f7d704d6c9333a622f8b7e5f00023f18b48f3c3dfb09c12104d928a7
hosted model-message template SHA-256: f9557a9d9aa679d1c10d5a24f94b08ba98c8f756d4b24c47fe1d9bf0399ca3ff
first-party model-message SHA-256: aa1800e77140f5a18a24c7d9f35dda2bcea9c63f6c5ae45fdc8a4fc113f232d0
Drain model-message SHA-256: c4fe1e6e4b5a2df3cf18dc49ec86dec2c88d588bddc9a34c59b1ee0cab90b743
deterministic reader configuration SHA-256: 377cfcde3cd334dddaec814bd0019c9fef77d6f77ef5b44853bada9474a551ad
two-trial paired reader repeatability SHA-256: c24c285b743e002bb8da085797c2210a4e314a88d485ef163c88ba73e2fe10f8
first-party / Drain answer SHA-256: 392ecde9480b94ac902af2eee2e5b1db979a0376f832488d987e1f0911e73930 / 392ecde9480b94ac902af2eee2e5b1db979a0376f832488d987e1f0911e73930
governed paired receipt SHA-256: ba63ec05d946abb49487e6c43492534cb2d957a85c273164d9d94fd5067e5f05
```

The same reader executable, build/configuration identity, prompt contract,
canonical UTF-8-byte tokenizer, and caps were applied to both arms: 8 MiB
stdin/prompt, 1 MiB stdout/answer, 64 KiB stderr, 10 seconds wall time, 2 GiB
direct-process peak RSS, exactly one call, and no retry. Two executions of each
arm produced the same answer artifact shown above. The run-specific observed
resource dimensions were:

```text
first-party prompt / answer: 29,018 / 308 canonical UTF-8-byte units
first-party wall / direct-process peak RSS: 448,272,042 ns / 1,982,464 bytes
Drain prompt / answer: 360,361 / 308 canonical UTF-8-byte units
Drain wall / direct-process peak RSS: 448,614,958 ns / 2,310,144 bytes
```

The governed fixture-reader dimensions were retained separately, without a
scalar or winner:

```text
first-party: cause=true, root-cause granularity=true, diagnosis=true
first-party citations: 2 valid / 0 invalid
first-party diagnostic requirements: 2/2; weight 3,000,000/3,000,000
Drain: cause=true, root-cause granularity=true, diagnosis=true
Drain citations: 0 valid / 2 invalid
Drain diagnostic requirements: 0/2; weight 0/3,000,000
both: unsupported claims=0, forbidden claims=0, abstention=not exercised, uncertainty=125,000 micros
```

Drain's full-membership output remains pattern/transformed representation. Its
source-exact citation catalog is deliberately empty, so the deterministic
fixture's handles are invalid for that arm. This is a contract and provenance
check, not evidence that another reader would give the same answer or a
comparative product-quality result.

The benchmark-only hosted-reader JSONL contract is now specified but not
executed. It binds exact provider, model, tokenizer, adapter-implementation,
model-message-template, request/response-schema, decoding, byte/token/time/RSS,
redaction, and fail-closed policy identities. Its canonical JSONL is only a
subprocess transport: the future adapter must decode the pinned UTF-8 system
and user messages before a provider call. Credentials are out-of-band and may
not enter requests, receipts, Debug, or errors; unknown fields, missing usage,
provider/rate-limit errors, timeout, cap violations, tool actions, partial
output, and nondeterminism fail closed with zero retries.

No hosted reader or hosted Evidentrail endpoint was contacted. No scalar winner,
fairness conclusion, comparative quality claim, child-tree RSS aggregate,
independent attestation, cold-start statement, model-token claim, or release
truth determined by an LLM judge is made.
