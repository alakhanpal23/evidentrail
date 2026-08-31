# Streaming product V3 engineering status

**As of:** August 30, 2026

V3 is an internal, code-first milestone. It is not a release certification or
a broad accuracy/performance claim.

## Implemented

- `compile_explicit_stream_v3<R: Read, B: RetainedEventStoreV3>` incrementally
  parses arbitrary reader chunks with a 1,000,000-record and 1 GiB source-byte
  ceiling. LF, CRLF, blank records, invalid UTF-8, NUL, and an unterminated last
  record remain exact.
- Retrieval/result storage namespaces are fixed from fresh caller randomness,
  question digest, budget, and V3 build context before acquisition. The sealed
  store manifest binds the final source digest, completion digest, exact counts,
  and every event locator, independent of reader chunking.
- `StreamingProductV3<B>` is the shared compiler path. Acquisition derives the
  canonical source-exact EventId and writes directly to the packed backend; it
  does not build a full-input `EventLedger`. One eligible partition delegates
  to the unchanged V1 framer/candidate/compiler/renderer path. Larger inputs use
  deterministic borrowed scans and materialize only a reducer-bounded working
  ledger; partition count alone cannot produce V1 `PrimaryBlockCountCap`.
- `PackedMemoryEventStoreV3` uses one zeroizing byte arena, fixed-width event
  metadata, and sorted EventId/acquisition/lane locator views. It performs no
  filesystem I/O.
- `DurablePackedRepositoryV3` is independent of the V2 repository codec. Its
  V4 packed-layout revision retains product V3 semantics while grouping
  independently sealed pages into immutable `.v3p` acquisition packs. A pack
  closes at 65,536 records, 16 MiB plaintext, or an oversized singleton. Index
  shards use the same format with a 64 MiB encrypted-plaintext ceiling and a
  16 MiB in-process construction cap. Each pack contains a fixed authenticated
  header, independently encrypted frames, one encrypted offset directory, and
  a fixed footer.
- One authority operation reserves every nonce in a pack, including the
  directory nonce, and binds the result identity, pack ordinal, prior-pack
  commitment, ordered canonical frame digests, and frame count. A pack is
  written to one create-only temporary file, fully synchronized once, installed
  create-only, directory-synchronized once, and only then acknowledged.
  Exact retries require canonical byte identity. Recovery authenticates every
  installed pack, reuses authenticated partial index packs, removes only
  incomplete temporary files, and completes a pending nonce transition only
  when its exact authenticated pack exists.
- Experimental one-object `.v3` repositories are returned as
  `EVIDENTRAIL_STORE_V3_OBSOLETE_FORMAT`. There is no migration or plaintext rewrite;
  cleanup remains explicit and authority-first. V2 repository APIs and readers
  remain unchanged.
- Restart reconstructs page locators, lane/EventId indexes, manifests,
  commitments, and lifecycle state solely from authenticated disk objects plus
  the external authority record. It completes interrupted nonce, seal, rename,
  publication, and authority-first destruction transitions without trusting
  temporary-object presence.
- Every clear V3 page header is the complete additional AEAD associated data;
  entries and exact bytes are ciphertext. Header-only mutation is covered by a
  dedicated authentication test.
- Multi-lane analysis uses independent lane identity and lane sequence fields.
  A rolling V1 framing pass retains only the unresolved tail block, and the
  4,096-block/32 MiB partition limits are applied only at atomic boundaries.
- `evidentrail brief` accepts `--retention memory|durable`. Memory remains the
  retention default. The ordinary memory CLI remains on V1 until the internal
  `EVIDENTRAIL_STREAMING_V3=1` rollout gate is enabled; explicit durable brief writes
  use the separate V3 root and fail closed without macOS Keychain authority.
- A `needs_more` decision destroys the V3 backend and publishes no aliases.

## Verified locally

- Arbitrary 1-byte versus 64 KiB reader chunking produces identical output and
  authenticated manifest digests.
- Hostile byte/terminator preservation, deterministic locators, publication
  gating, exact encrypted reads, and authority-first destruction pass focused
  contracts.
- A 5,000-block input crosses partitions without returning
  `PrimaryBlockCountCap` solely because of total input size.
- A 4,102-event, two-lane interleaved fixture keeps a three-record Python
  traceback atomic across the former event-count partition boundary.
- The explicit 1,000,000-record start/middle/end evidence corpus passes on the
  refactored memory path. A non-certifying local debug-test observation reported
  208,125,952 bytes maximum RSS (about 198.5 MiB), below the 512 MiB engineering
  target. This is a single observation, not the frozen paired performance study.
- The V3 fault matrix exercises before/after nonce reservation, every
  frame-encryption boundary, temp create/write/sync, create-only install,
  directory sync, acknowledgement,
  data commit, seal, publication reservation/rename/sync/authority update,
  authenticated recovery, and key-first cleanup for every V3 object class.
- A 65,537-record contract closes exactly two acquisition packs, verifies
  lookup on both sides of the boundary after disk-only restart, and reconciles
  pack/page/index/sync/encrypted/decrypted/written-byte counters. Oversized
  singleton pages, partial installed-index recovery, pre/post-install replay,
  authenticated header/ciphertext corruption, and obsolete-layout rejection
  have focused contracts.
- Contentless instrumentation is disabled by default. The profiled probe emits
  reconciled store timings for page construction, encryption, nonce authority,
  write/full-sync/rename/directory-sync, checkpoint/index work, scans and
  decryption, plus product timings for atomic framing, global analysis,
  projection, V1 compilation, seal and publication.
- The existing product/store/CLI suites and the workspace all-target suite are
  the required regression gates for this change.

The native August 30 release-mode point screen exercised the superseded
one-object-per-page layout at 10K, 100K, and 1M. Its RSS and storage point gates
passed, while throughput and 10K overhead failed. None of those observations
carry forward to the V4 packed layout; the full point screen must be rerun and
must still block the 5-warmup/30-pair BCa phase on any failure. See the
[native validation](../validation/v3/NATIVE_V3_VALIDATION.md) and
[`native-v3-study.json`](../validation/v3/native-v3-study.json).

## Production gates still external or non-certifying

No qualifying independently adjudicated incident corpus is present. The strict
external importer is implemented, but synthetic fixtures cannot satisfy that
gate. The throughput screen also fails, so the 30-pair/20,000-resample study was
not run or represented as complete. Signed-Keychain/cold-boot certification
still requires an approved executable and rebootable host. Until the corpus,
throughput, and platform gates pass, the CLI memory default must not switch to
V3 and no broad accuracy or product-ready claim may be made.

`validation/v3/run_frozen_paired_study.py` takes five release-mode diagnostic
observations at 100K and 1M, checks numeric receipt reconciliation, selects the
first applicable ordered optimization remedy at a 10% phase share, and runs the
paired BCa phase only after all point gates pass. Time Profiler/File Activity
captures remain host-generated diagnostic attachments; they are not synthesized
by the harness.
