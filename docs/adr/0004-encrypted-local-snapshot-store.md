# ADR 0004: Encrypted local snapshot store

**Status:** Proposed; implementation-blocking

**Date:** August 24, 2026

**Applies to:** Phase 1 `evidentrail-store` on macOS

## Scope

Phase 1 needs a local expansion snapshot for the authorized exact ledger. The
store persists authorized retained bytes, which are not always source bytes:
`SourceExact` may retain source bytes, `PostPolicy` retains only the authorized
transformation, and `OmittedByPolicy` retains accounting without payload or a
content-derived hash. The policy-aware sink may return `SinkAck` only after that
outcome is durably committed, or after it is retained in an explicitly selected
memory-only backend.

This ADR specifies the encrypted backend. It is a short-lived local expansion
cache, not a log archive, general observability store, replay system, remote
service, or customer-data ingestion pipeline. Phase 1 implementation and tests
use synthetic fixtures and explicitly selected local test files only. Enabling
real customer-log ingestion is a separate release and governance decision.

The store has no network client, provider client, model client, telemetry
transport, or source-path input. It never silently requeries a source.

This decision refines the normative requirements in the
[local data policy](../LOCAL_DATA_POLICY.md),
[threat model](../THREAT_MODEL.md), and
[authorized-ledger ADR](0002-authorized-ledger-and-three-receipts.md). Those
documents take precedence if this ADR accidentally weakens a requirement.

## Security and product invariants

1. No intentional plaintext file is created at any write, recovery, compaction,
   deletion, or error step.
2. A result uses a fresh random data-encryption key (DEK). Payload objects use
   AEAD with a unique nonce and exact, canonical associated data (AAD).
3. Key material is never stored in the result directory, configuration,
   environment, command line, diagnostics, telemetry, panic output, or support
   bundles.
4. A returned `SinkAck` follows a successful ciphertext write and durability
   barrier for that frame. A barrier failure poisons the writer and returns no
   acknowledgment.
5. A result is expandable only after it is sealed and published. Every returned
   byte is authenticated and linked to the requested result and evidence
   reference.
6. Default expiry is 30 minutes from result creation. Reads do not extend it.
7. Logical deletion destroys the per-result key record before attempting
   ciphertext removal. We claim cryptographic erasure under the trusted-Keychain
   assumption, not forensic physical erasure from SSDs or backups.
8. Active Evidentrail data roots and their aliases are never eligible sources.
9. Public errors and diagnostic events are typed and contentless.
10. Failure is closed: a locked, unavailable, corrupt, or inconsistent secure
    store cannot fall back to plaintext or silently switch storage modes.

## Threat boundary

| In scope | Control or expected result |
|---|---|
| Offline theft or copying of the result directory | Payload remains AEAD ciphertext; DEK envelopes are not on disk. |
| A different OS user reading the store | User-only directory/file modes plus normal macOS account isolation. |
| Accidental disclosure through names, indexes, errors, diagnostics, or crash residue | Random names, minimal public headers, ciphertext-only staging, contentless errors, and canary tests. |
| Disk ciphertext/header modification, frame swapping, deletion, duplication, reordering, or truncation | AAD, an authenticated frame chain, a sealed manifest, and a Keychain-anchored manifest commitment cause fail-closed open. |
| Whole-result rollback on disk | The sealed manifest digest and counts are retained in the per-result Keychain record and compared on every open. |
| Cross-result or cross-reference expansion | Result ID, object kind, schema, sequence, and reference identity are authenticated and reconciled. |
| Crash between filesystem/key operations | Explicit states and idempotent startup recovery; only authenticated prefixes survive. |
| Source recursion through direct paths, symlinks, globs, aliases, or hard links | Pre-open resolved-root checks plus post-open device/inode checks. |
| Resource exhaustion from lengths, file counts, or malformed framing | Checked fixed-width lengths, configured caps, bounded segment count, and checks before allocation. |

The following are outside this design's confidentiality boundary: root or kernel
attackers; a compromised Evidentrail process or dependency; the signed-in user's live
process memory or authorized Keychain access; malicious provider binaries;
register, swap, core-dump, or microarchitectural recovery beyond the limited
memory-hygiene controls below; denial of service through deletion or corruption;
and the behavior of a downstream agent after Evidentrail intentionally returns
evidence. Advisory locks coordinate cooperating Evidentrail processes; they are not an
access-control boundary against the same user.

The OS Keychain and its authenticated item operations are trusted. Deleting a
Keychain item is treated as making that managed secret unavailable; this is not
a claim about physical flash erasure. Sudden-power-loss durability is also not
claimed until the `F_FULLFSYNC` gate below is resolved.

## Decision

Use a random per-result directory containing small, append-only packed segment
files. Every authorized outcome is an independently authenticated frame. A
sealed encrypted manifest indexes those frames. A per-result DEK encrypts frames
and the manifest. A long-lived installation key-encryption key (KEK) in the
macOS data-protection Keychain derives per-result wrapping/seal keys that protect
the DEK and final seal commitment. Their protected values live in a separate
per-result Keychain item, never beside ciphertext.

This is deliberately not one file per event:

- Per-event files multiply inode and directory writes, expose event cardinality
  at filesystem granularity, and make cleanup and permission checking expensive.
- One monolithic AEAD blob would require rewriting prior ciphertext before each
  `SinkAck` or delaying acknowledgments until the whole acquisition finishes.
- Packed segments with independent frames preserve the per-envelope durability
  boundary, allow authenticated prefix recovery, and keep the file count
  bounded.

The provisional Phase 1 rotation target is the first of 8 MiB ciphertext or
4,096 outcome frames. A single authorized record may receive a dedicated
segment when it fits the separately configured record cap. These are benchmark
parameters, not security claims; changing them must not change acknowledgment,
length, nonce, or authentication semantics.

### Result and key identifiers

Add a distinct `ResultId([u8; 32])`. Do not reuse the current hash-shaped
`RetrievalId`: current constructors permit deterministic bytes, while the
filesystem/access boundary requires a cryptographically random, non-derived
identifier. The encrypted manifest maps the `ResultId` to its `RetrievalId`.

Generate `ResultId` using `getrandom::fill`. It does not derive from content, a
path, a query, a clock, or another identifier. Encode a result directory as a
fixed `r_` prefix plus 64 lowercase hexadecimal characters; reject any
non-canonical spelling before path construction. Use `create_new` and a Keychain
add operation keyed by that same random ID to detect the otherwise unexpected
collision, then restart result creation with a fresh value. Do not add a second
public key handle: the local-data policy permits the random result ID in minimal
unencrypted indexing and no extra locator is necessary.

`ResultId` is a locator, not an authentication secret. Treat it as sensitive
local metadata: no `Display` implementation, a manually redacted `Debug`, and an
explicit `to_token()` only at the user-facing result boundary.

### Store layout

The root is resolved through a platform API, never by concatenating a home
directory string. The Phase 1 default is the application cache directory because
the snapshot is short-lived and nonessential to application startup. OS cache
purging therefore causes the same generic unavailable result as deletion; it is
an availability event, not a source requery. If the product later promises
availability for the entire TTL, the placement decision must be reopened because
Apple permits the cache directory to be purged.

```text
<platform-cache>/ai.evidentrail/snapshots-v1/        mode 0700
  store.lock                                  mode 0600, no payload
  .creating-r_<64 hex>/                       mode 0700
    public.v1                                 mode 0600, C1 metadata only
    result.lock                               mode 0600, no payload
    00000000.open                             mode 0600, framed ciphertext
    manifest.<random>.tmp                     mode 0600, ciphertext only
  r_<64 hex>/                                 mode 0700, sealed result
    public.v1
    result.lock
    00000000.seg
    00000001.seg
    manifest.v1
  .deleting-<random>/                         mode 0700, crypto-erased residue
```

Create directories with `DirBuilderExt::mode(0o700)` and files with
`OpenOptionsExt::mode(0o600)` plus `create_new(true)`. A restrictive umask is
additional defense, not the mechanism. Verify owner, type, and mode before use;
reject symlinks and non-regular store objects. All temporary and final renames
stay under the same root and filesystem.

There is no plaintext SQLite database or global content index. `public.v1` is a
fixed binary cleanup hint containing only format/suite versions, random
`ResultId`, KEK version, schema version, and creation/expiry times. It contains no
source, path, question, cursor, event ID, content hash, policy text, or payload.
It is immutable after creation and untrusted: it can cause conservative early
deletion, but cannot authorize an open or postpone expiry beyond the
authenticated Keychain record.

### Key hierarchy and provider boundary

The hierarchy is:

```text
macOS data-protection Keychain
  installation KEK vN (32 random bytes)
    HKDF-SHA-256 derives one result wrapping key and one seal key
      wrapping key protects one fresh result DEK (32 random bytes)
        result DEK encrypts segment frames and the manifest
      seal key protects the final manifest/chain binding
```

Use generic-password Keychain items with fixed, non-content service names:

- KEK service `ai.evidentrail.snapshot-kek.v1`, account `root-v<N>`;
- result service `ai.evidentrail.snapshot-envelope.v1`, account equal to the canonical
  random `ResultId` token.

For every add, get, update, and delete query, request the data-protection
Keychain, set synchronization explicitly false, and use
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Do not place result, source, or
query data in labels, descriptions, or comments. A locked device therefore
makes the backend unavailable. It does not trigger a weaker accessibility class.

The result Keychain item contains a versioned protected record:

```text
ResultKeyRecordV1 {
  root_key_version,
  result_id,
  created_unix_nanos,
  expires_unix_nanos,
  dek_wrap_nonce,
  wrapped_result_dek,
  state: Creating | Sealed {
    seal_nonce,
    encrypted_seal_binding,
  },
}
```

Its outer record codec is also fixed-width and canonical. It rejects unknown
versions, nonzero reserved fields, duplicate/trailing data, invalid state
transitions, and lengths outside the small Keychain-record cap before invoking
HKDF or AEAD.

Use HKDF-SHA-256 with the root KEK as input keying material, the canonical
`ResultId` bytes as salt, and separate info strings
`evidentrail.snapshot.dek-wrap-key.v1 || key_version` and
`evidentrail.snapshot.seal-key.v1 || key_version` to derive two 32-byte keys.
Implementation V1 freezes `key_version` as a nonzero unsigned 32-bit integer
encoded in exactly four big-endian bytes with no delimiter. The
unique result context gives every result independent AEAD keys even if random
nonces repeat across different results. Derived keys are zeroizing and never
leave the provider.

The DEK wrap uses the selected AEAD suite once with a fresh random nonce. Its AAD
is the exact canonical encoding of domain `evidentrail.snapshot.dek-wrap.v1`, record
version, KEK version, `ResultId`, creation time, and expiry time.
The wrapped DEK remains byte-for-byte immutable when the result seals. Sealing
encrypts `SealBinding { manifest_digest, final_frame_commitment, frame_count,
segment_count }` under the distinct seal key, a fresh nonce, and the analogous
`evidentrail.snapshot.seal-binding.v1` AAD, then atomically updates only the Keychain
record state. This avoids reusing the DEK-wrap key/nonce across state changes.
The root KEK never leaves the provider. The returned DEK is held in a
`Zeroizing` owner for only the active write/read operation.

The provider interface should express the state transition rather than expose a
generic password API:

```rust
pub trait KeyProvider: Send + Sync {
    fn ensure_root_key(&self) -> Result<KeyVersion, KeyError>;

    fn create_result_key(
        &self,
        context: &CreatingKeyContext,
    ) -> Result<ResultKey, KeyError>;

    fn open_result_key(
        &self,
        id: &ResultId,
        context: &ExpectedKeyContext,
    ) -> Result<OpenedResultKey, KeyError>;

    fn seal_result_key(
        &self,
        id: &ResultId,
        seal: &SealBinding,
    ) -> Result<(), KeyError>;

    fn destroy_result_key(&self, id: &ResultId) -> Result<(), KeyError>;

    fn list_managed_records(&self) -> Result<Vec<KeyRecordMetadata>, KeyError>;
}
```

`destroy_result_key` is idempotent. `open_result_key` returns both a zeroizing
DEK and the authenticated state/expiry/seal binding. `seal_result_key` permits
exactly `Creating -> Sealed`; it rejects a different second seal. Root-key loss
does not silently create a replacement while result records exist.
`CreatingKeyContext` contains the already generated `ResultId`, so the
synchronized contentless skeleton exists before the provider adds an item.

Use `security-framework` on macOS, not a library that reads Keychain database
files directly. Its `PasswordOptions` is not `Send` or `Sync`; construct options
inside each serialized provider operation rather than retaining them across
threads. A required implementation spike must verify data-protection selection,
access-control application, non-synchronization, item enumeration, atomic update,
duplicate handling, deletion, locked-Keychain behavior, and prompts for both
signed and unsigned CLI binaries. The high-level crate API is evidence of API
surface, not proof of those runtime behaviors.

`EphemeralKeyProvider` is an in-memory map of random result IDs to zeroizing key
records. It is compiled only under `cfg(test)` or a non-default internal test
feature and cannot be selected by a release CLI. It models locked, unavailable,
duplicate, missing, corrupt, and failed-update states. Fixed test keys are
allowed only in separate golden-vector tests; the normal ephemeral provider uses
the injected cryptographic random source.

Create and sync the contentless staging skeleton before adding the result
Keychain item. A normal crash can then never create an unlocatable key-only
item. Service-scoped enumeration remains required to clean an orphan caused by
external deletion of the skeleton.

### Cryptographic suite

The provisional suite ID `1` is XChaCha20-Poly1305 with a 256-bit key, 192-bit
random nonce, and 128-bit tag, implemented by RustCrypto
`chacha20poly1305` 0.11.0. Use combined mode or `encrypt_in_place_detached` with
the canonical AAD. Generate every DEK, KEK, identifier, and nonce with
`getrandom` 0.4.3. A random-source failure is fatal. Track every frame and
manifest nonce used under a result DEK and reject an injected duplicate;
recovery reconstructs that set before appending. Each derived wrapping/seal key
protects exactly one object, so it has no second nonce to collide with.

XChaCha20-Poly1305 is selected because its extended nonce supports random nonce
generation without a durable global counter. RFC 8439 specifies the underlying
IETF ChaCha20-Poly1305 construction; it does not itself standardize XChaCha. The
XChaCha rationale comes from the libsodium construction documentation. The cited
2020 NCC Group report reviewed older RustCrypto code, so it is useful lineage,
not an audit guarantee for version 0.11.0. Dependency pinning, lockfile review,
`cargo audit`, license review, and known-answer tests are still release gates.

Use `zeroize` 1.9.0 `Zeroizing`/`ZeroizeOnDrop` owners for DEKs, KEKs returned
inside a provider, plaintext frames, and decrypted manifests. Preallocate the
bounded final capacity to avoid copies from reallocation. This prevents the
compiler from removing the selected overwrite; it does not guarantee removal of
old reallocations, stack/register spills, swap, cores, or microarchitectural
copies. Types holding plaintext or keys must have manually redacted `Debug` and
must not implement `Clone` unless the copy is strictly necessary and tested.

Suite IDs are part of the wire format. Writers emit only the current suite;
readers either support an explicitly retained old suite or fail closed. There is
no silent in-place cipher migration. If FIPS-validated cryptography becomes a
requirement, this choice must be reopened for an independently designed and
validated AES-GCM provider; XChaCha20-Poly1305 must not be described as FIPS
approved.

### Segment and envelope format

Do not use JSON, a language-native struct dump, or a map serializer for the
outer framing/AAD. Implement a small fixed-width codec with checked offsets. All
integers are big-endian, all reserved bytes are zero on write and rejected if
nonzero on read, and all lengths are validated against configuration before
allocation or arithmetic.

Each segment consists of one cleartext `SegmentHeaderV1` followed by zero or
more independently encrypted frames:

```text
SegmentHeaderV1 (fixed width, exact bytes included in every frame AAD)
  magic[8]                 = "EVRSNP01"
  outer_version:u16        = 1
  suite_id:u16             = 1
  payload_schema:u16
  flags:u16                = 0
  result_id[32]
  segment_sequence:u64
  created_unix_nanos:i64
  expires_unix_nanos:i64
  prior_segment_commitment[32]
  reserved[16]             = all zero

FrameHeaderV1 (fixed width, exact bytes included in this frame AAD)
  magic[4]                 = "FRM1"
  header_version:u16       = 1
  object_kind:u16
  global_sequence:u64
  segment_frame_sequence:u32
  plaintext_length:u32
  ciphertext_length:u32    = plaintext_length + 16
  nonce[24]
  previous_frame_commitment[32]
  reserved[8]              = all zero

Frame
  FrameHeaderV1
  ciphertext[plaintext_length]
  tag[16]
```

The exact AAD byte string is:

```text
"evidentrail.snapshot.frame.v1" || SegmentHeaderV1 || FrameHeaderV1
```

Segment and global sequences start at zero and are contiguous. Segment zero uses
an all-zero prior-segment commitment; each later segment carries the preceding
segment's final commitment. The first frame's previous commitment is:

```text
SHA-256("evidentrail.snapshot.segment-start.v1" || SegmentHeaderV1)
```

Each frame's commitment is:

```text
SHA-256("evidentrail.snapshot.frame-commit.v1" ||
        SegmentHeaderV1 || FrameHeaderV1 || ciphertext || tag)
```

The next frame authenticates that value as its previous commitment. The
manifest contains the ordered segment descriptors, digest of each complete
segment, total frame count, and final commitment. This detects removal,
duplication, reordering, swapping, and truncation after seal; AEAD alone would
not prove that a valid frame was absent.
The final manifest digest and counts are also sealed into the Keychain record,
which prevents replacement by an older, internally valid disk manifest.

Object kinds in v1 are the non-sensitive outer types `AuthorizedOutcome` and
`AcquisitionSeal`; the three authorization dispositions remain inside
ciphertext. The encrypted plaintext contains all sensitive identity and
provenance: `RetrievalId`, `SourceRecordId`, authorized bytes when any, `EventId`
and exactness basis when persisted, transformation receipt when applicable, and
receipt assignment. An `OmittedByPolicy` plaintext contains only the non-content
`SourceRecordId`, policy digest, disposition, and accounting; it has no payload,
`EventId`, or content-derived hash.

The manifest is a separate AEAD object:

```text
ManifestHeaderV1 (fixed width)
  magic[8]                 = "EVRMNF01"
  outer_version:u16        = 1
  suite_id:u16             = 1
  payload_schema:u16
  object_kind:u16          = Manifest
  result_id[32]
  object_sequence:u64      = 0
  created_unix_nanos:i64
  expires_unix_nanos:i64
  plaintext_length:u32
  ciphertext_length:u32    = plaintext_length + 16
  nonce[24]
  reserved[16]             = all zero

ManifestObject
  ManifestHeaderV1
  ciphertext[plaintext_length]
  tag[16]
```

Its exact AAD is `"evidentrail.snapshot.manifest.v1" || ManifestHeaderV1`. The seal
stores `SHA-256("evidentrail.snapshot.manifest-commit.v1" || ManifestHeaderV1 ||
ciphertext || tag)` as `manifest_digest`. The encrypted manifest contains:

- the ordered segment list, segment digests, frame ranges, and final chain root;
- a `SourceRecordId -> committed outcome` table for idempotent retry;
- an `EventId -> segment/frame/offset/exactness` expansion index;
- acquisition completion and the reconciled acquisition receipt;
- policy and binding digests required to interpret authorized bytes.

The encrypted manifest codec must be deterministic, versioned, reject duplicate
fields/unknown required variants, and enforce size/depth limits. The exact codec
is an unresolved implementation choice; the fixed outer format and AAD do not
depend on it.

### Write, acknowledgment, and publication protocol

There is one writer per result. It holds an exclusive per-result advisory lock
and keeps the DEK only for the active operation.

For each authorized outcome:

1. Reconcile the result, acquisition sequence, and `SourceRecordId`; return the
   prior committed acknowledgment for an exact retry, and reject a conflicting
   duplicate.
2. Encode the bounded plaintext directly into a zeroizing buffer.
3. Generate a fresh nonce, construct the exact header/AAD, and AEAD-encrypt in
   memory. No plaintext buffer reaches a filesystem API.
4. Append the header and ciphertext/tag with `write_all`. On a short write,
   interruption, or error, return no acknowledgment and poison the writer until
   recovery.
5. Call `File::sync_all` on the active segment. If this is the first durable
   frame in a newly created segment, also sync the containing result directory
   so the segment name is durable.
6. Only after all required barriers succeed, construct and return `SinkAck`.

`sync_data` is insufficient here because file length and metadata are required.
Dropping/closing a file is not a durability barrier. A future group-commit path
requires an explicit batch sink API and may release all batch acknowledgments
only after the shared barrier succeeds. The current single-record
`EnvelopeSink::accept` must not acknowledge buffered plaintext or unsynchronized
ciphertext.

When rotating a segment, sync the file, rename `.open` to `.seg` in the same
directory, and sync the directory. A crash before rename still leaves a
recoverable authenticated `.open`; the suffix is state, not authenticity.

To seal a result:

1. Append the encrypted acquisition-seal frame and sync it.
2. Close/rename the active segment and sync the result directory.
3. Write the encrypted manifest to a random `create_new` temporary file, call
   `sync_all`, rename it to `manifest.v1`, and sync the result directory.
4. Update the Keychain result record from `Creating` to `Sealed`, binding the
   manifest digest, final frame commitment, and counts.
5. Rename the staging directory to its final random `ResultId` name and sync the
   store root directory.
6. Return `ResultId` only after the final root-directory barrier succeeds.

Never overwrite an existing final or temporary name. A rename must remain on the
same filesystem. Parent-directory synchronization is required because file
synchronization alone does not make a directory entry durable on systems with
that behavior.

On macOS, `File::sync_all` ultimately has the limitations Apple documents for
`fsync`: drive caches and sudden power loss can still lose or reorder data.
Apple documents `F_FULLFSYNC` as a stronger but still best-effort request. The
workspace forbids unsafe code, and this ADR does not bless an unreviewed FFI
call. Until a safe audited wrapper and APFS fault test pass, the precise claim is
"barrier issued and verified on restart after process termination," not
"survives every OS crash or power loss."

### Acknowledgment ambiguity and crash recovery

A process may die after the segment barrier but before its caller observes the
returned `SinkAck`. No local synchronous API can distinguish that case from an
observed acknowledgment after restart. The store therefore provides
at-least-once retry semantics keyed by `(ResultId, SourceRecordId)`:

- every returned acknowledgment has a committed frame;
- a committed frame may exist without an acknowledgment observed by the caller;
- retrying the same identity and outcome returns the same logical
  acknowledgment without adding a duplicate;
- retrying the same identity with different bytes or disposition fails closed.

Do not describe this as process-wide exactly-once delivery. A stronger guarantee
would require a durable protocol with the adapter/caller, not a different file
format.

Startup recovery takes the global store lock before accepting new writers. It
never decrypts into a temporary file and never presents an unsealed result.

| Filesystem state | Keychain state | Recovery action |
|---|---|---|
| Missing/invalid skeleton | none | Remove ciphertext-free residue. |
| `.creating` skeleton | missing | Remove the directory; no authorized bytes could have been committed under a usable key. |
| `.creating` with frames | `Creating` | Verify headers and the longest contiguous AEAD-authenticated prefix, truncate only an invalid suffix, sync, and expose it only through `recover_pending`; resume idempotently or seal with an explicit interrupted/partial completion. Preserve it until then or expiry. |
| `.creating` with valid manifest | `Creating` | Verify all frames/manifest, complete the Keychain seal transition, then publish. |
| `.creating` with valid manifest | matching `Sealed` | Verify the Keychain seal binding, publish, and sync the root. |
| Final result | matching `Sealed` | Verify on open; no mutation. |
| Final result | `Creating` | Treat as interrupted publication; verify manifest, complete seal, or crypto-erase on any mismatch. |
| Any result directory | missing/corrupt/mismatched key record | Return generic unavailable. Destroy any item at the scoped result account; only after key unavailability is confirmed, remove ciphertext best effort. Otherwise leave cleanup pending. |
| No result directory | managed key record | Destroy the orphan after a bounded creation grace and a second locked rescan. |
| `.deleting-*` | any | Idempotently destroy the key first, then remove files and sync the root. |
| Duplicate directories or conflicting states for one `ResultId` | any | Fail closed for that result, destroy its key, and remove every copy. |

Recovery must not label a recovered prefix `Complete`. The current schema needs a
typed abnormal-termination representation or a documented mapping to a partial
sink failure before automatic sealing can ship. Until that schema gate is
resolved, `recover_pending` preserves or explicitly deletes the result; it does
not invent provider completeness.

### Access, expiry, and deletion

Expansion accepts only a parsed `ResultId` and a typed evidence reference. It
never accepts a raw filesystem path. The open sequence is:

1. acquire a shared result lock and verify final-directory/file type and modes;
2. parse bounded public framing, then obtain the matching Keychain record;
3. check authenticated `ResultId`, creation/expiry, and `Sealed`
   state;
4. decrypt/authenticate the manifest and compare its digest/counts/chain root
   with the Keychain seal binding;
5. reconcile the reference and exactness basis, then authenticate only the
   required frame(s);
6. hash/reconcile the returned authorized bytes as required by the evidence
   contract; and
7. recheck expiry immediately before returning a zeroizing byte buffer.

Unknown, malformed, expired, forged, cross-result, missing-key, cache-purged, or
tampered results all map to public `ResultUnavailable`. Authentication failure
never triggers provider access. A source may be deleted or rotated after sealing
and expansion must still use the authenticated snapshot.

At creation, calculate a checked absolute expiry and an in-process monotonic
deadline. Expire when either deadline is reached; a backward wall-clock jump
cannot extend a live process's TTL. Persist the absolute expiry in the public
header, wrapped key record, segment AAD, and manifest. Access never rewrites it
or updates a last-access timestamp. If expiry is crossed during expansion, erase
the plaintext buffer and return unavailable.

The startup and periodic sweeper handles expired final results, interrupted
creations, `.deleting` directories, orphan key records, stale temporary files,
and inactive lock files. Cleanup uses the authenticated Keychain expiry when
available. An unauthenticated public expiry may request earlier deletion but may
not extend retention. Keychain unavailability prevents open and new persistent
acquisition; cleanup remains pending until key destruction can be confirmed.

Deletion takes an exclusive result lock and rechecks expiry, then:

1. calls idempotent `destroy_result_key` and drops any in-memory DEK;
2. renames the result directory to a fresh `.deleting-*` name and syncs the
   store root;
3. removes ciphertext/index/lock files best effort; and
4. syncs the store root again.

If step 1 fails, deletion is pending and must not be reported complete. If step
1 succeeds but later removal fails, return a typed
`CryptoErasedCleanupPending`; confidentiality deletion is complete under the
Keychain assumption, while disk cleanup remains retriable. `delete` is
idempotent. Readers holding a shared lock finish only if their final expiry check
passes; an exclusive delete waits for them. No API promises secure physical
overwrite.

An explicitly selected memory-only backend is chosen before acquisition starts
and implements the same receipt/TTL/expansion semantics without filesystem or
Keychain artifacts. A persistent writer never switches to it mid-result. A
Keychain failure before `begin` either uses that already selected backend or
fails before acquisition; a failure after `begin` poisons the persistent writer.

### Source-recursion exclusion

The application owns an `InternalPathRegistry` that combines snapshot,
diagnostic, telemetry-queue, support-bundle, and any key-envelope filesystem
roots. `SnapshotStore::reserved_roots()` contributes the canonical store root,
all active aliases discovered at initialization, and device/inode identities for
store files.

Every file adapter must:

1. reject a selected path or resolved glob whose canonical target is within a
   reserved root;
2. open without following a final symlink where the platform permits;
3. inspect the opened handle and reject a device/inode matching an active store
   file, closing the hard-link escape; and
4. revalidate the approved source identity after open before reading bytes.

Path-string prefix tests alone are insufficient. Tests cover direct selection,
parent globs, `..`, symlinks, case variants on case-insensitive volumes, hard
links, store relocation, and replacement between pre-open and post-open checks.
If a user intentionally needs an internal diagnostic artifact, it must first be
copied outside all active roots and approved as a new binding.

### Contentless errors and diagnostics

Do not use free-form `anyhow` context, provider stderr, source snippets, paths,
result/key identifiers, AEAD errors, or raw OS/Keychain messages in public or
diagnostic formatting. Plaintext, key, source, reference, and internal path
types have redacted manual `Debug` implementations.

```rust
pub struct StoreError {
    code: StoreErrorCode,
    stage: StoreStage,
    // A private numeric OS code may guide local branching but is not formatted.
    private_os_code: Option<i32>,
}

pub enum StoreErrorCode {
    Unavailable,
    KeychainUnavailable,
    DurabilityFailure,
    CapacityExceeded,
    IntegrityFailure,
    Expired,
    Busy,
    CleanupPending,
    InvalidConfiguration,
}
```

Manual `Display` and `Debug` emit only stable code and fixed stage. The public
expansion boundary deliberately collapses `Expired`, `IntegrityFailure`, missing,
and cross-result cases to `ResultUnavailable` to avoid an oracle. Contentless
diagnostic events may include component/schema versions, fixed stage/code,
counts, ciphertext bytes, configured caps, and elapsed time. They never include
IDs, filenames, paths, questions, policy strings, key material, or free-form
error chains.

## Rust crate and API recommendation

Create `crates/evidentrail-store` only after this ADR is accepted. Keep the crate
synchronous in Phase 1 because `EnvelopeSink::accept` is synchronous and the
durability boundary must be obvious. Forbid unsafe code as in the workspace.

```rust
pub struct StoreConfig {
    pub root: StoreRoot,
    pub ttl: Duration,
    pub max_record_bytes: u32,
    pub max_segment_bytes: u64,
    pub max_frames_per_segment: u32,
    pub durability: DurabilityMode,
}

pub struct SnapshotStore<K, C, R, D> {
    // Key provider, clock, random source, and durability/filesystem adapter.
    // Fields remain private.
}

impl<K, C, R, D> SnapshotStore<K, C, R, D> {
    pub fn initialize(&self) -> Result<RecoveryReport, StoreError>;
    pub fn begin(&self, start: BeginResult) -> Result<ResultWriter<'_>, StoreError>;
    pub fn open(&self, id: ResultId) -> Result<ResultLease<'_>, StoreError>;
    pub fn recover_pending(&self) -> Result<Vec<PendingResult>, StoreError>;
    pub fn delete(&self, id: ResultId) -> Result<DeleteOutcome, StoreError>;
    pub fn sweep(&self) -> Result<SweepReport, StoreError>;
    pub fn reserved_roots(&self) -> SourceExclusionSet;
}

impl ResultWriter<'_> {
    pub fn persist_outcome(
        &mut self,
        outcome: DurableAuthorizedOutcome<'_>,
    ) -> Result<SinkAck, StoreError>;

    pub fn seal(
        self,
        completion: FetchCompletion,
        receipt: AcquisitionReceipt,
    ) -> Result<ResultId, StoreError>;

    pub fn abort(self) -> Result<DeleteOutcome, StoreError>;
}

impl ResultLease<'_> {
    pub fn expand(
        &self,
        reference: &EvidenceReference,
    ) -> Result<Zeroizing<Vec<u8>>, StoreError>;
}
```

The production implementation additionally injects private `Clock`,
`RandomSource`, `Durability`, and `FaultPoint` traits. Production clocks/random
sources have only OS-backed implementations; deterministic implementations are
test-only. `Durability` wraps `write_all`, file sync, rename, directory sync,
truncate, and remove so every failure can be injected without weakening the
public API.

Recommended dependencies, pinned in `Cargo.lock` and verified on the workspace
MSRV Rust 1.85:

| Dependency | Decision and use |
|---|---|
| `chacha20poly1305 = 0.11.0` | Use `XChaCha20Poly1305` and `AeadInPlace`; current provisional suite. |
| `getrandom = 0.4.3` | Direct OS CSPRNG for keys, IDs, nonces, and temporary suffixes. |
| `zeroize = 1.9.0` | Zeroizing owners and drop hygiene, with its documented limitations. |
| `security-framework = 3.7.0` (macOS target only) | Data-protection Keychain operations; runtime behavior remains gated by the integration spike. |
| `sha2 = 0.10.9` | Already present; frame/segment/manifest commitments, never a substitute for AEAD. |
| `hkdf = 0.12.4` | RFC 5869 HKDF-SHA-256 derivation of domain-separated per-result wrapping/seal keys; matches the existing `sha2` generation. |
| `directories = 6.0.0` | Resolve the platform cache directory rather than hardcoding a home path. |
| `fs4 = 1.1.0`, default synchronous feature only | Provisional cross-process shared/exclusive advisory locks because Rust 1.85 predates stable `std::fs::File` locks. Admit only after contention/crash review. |

Do not add a generic database, memory-mapped plaintext, direct Keychain-database
reader, or temporary-file abstraction whose permissions/persist/rename semantics
have not been verified. The fixed outer codec can use `to_be_bytes`/checked
slices without another serialization dependency.

## Acceptance and fault-injection gates

All tests use synthetic canaries. A Keychain integration suite uses a dedicated
test service/account namespace and deletes its items after the run. It must never
use personal or customer logs.

### Cryptographic and format tests

- RFC 5869/implementation known-answer tests cover wrapping/seal key derivation.
  AEAD known-answer and round-trip tests cover each object kind, empty authorized
  bytes, invalid UTF-8, NUL bytes, maximum-size input, duplicate log records, and
  `PostPolicy` exactness.
- `OmittedByPolicy` fixtures prove that no payload, `EventId`, or content-derived
  hash appears in plaintext schema, ciphertext metadata, public metadata, or
  receipts.
- Flip every header field class, nonce, ciphertext, and tag; delete, duplicate,
  reorder, or cross-copy frames and segments; swap result IDs/key records;
  truncate every byte boundary; and roll back the manifest. Every mutation fails
  closed or yields only the valid unsealed prefix during recovery.
- Replace a whole sealed disk result with a prior valid copy. The Keychain seal
  mismatch must reject it.
- Inject RNG failure and repeated IDs/nonces. Failure is closed;
  duplicate frame nonces are never written.
- Fuzz all public/segment/frame/manifest decoders with bounded allocation and no
  panic, integer overflow, path construction, or attacker-controlled recursion.

### Acknowledgment and crash tests

A subprocess harness arms a hard exit at each transition: skeleton directory
creation; public-header write/file sync/directory sync; Keychain record creation;
partial and complete frame header/ciphertext writes; segment sync; immediately
before and after the caller observes an acknowledgment; segment rename/directory
sync; seal-frame sync; manifest temporary write/sync/rename/directory sync;
Keychain seal update; final-directory rename/root sync; key destruction;
`.deleting` rename; each unlink; and final root sync.

After every exit, restart and assert:

- no plaintext canary exists on disk, in a filename/public header, diagnostic,
  panic output, support artifact, or CI artifact;
- every observed `SinkAck` has one recoverable matching committed outcome;
- a committed-but-unobserved outcome is idempotent on retry and never duplicated;
- an incomplete frame is ignored/truncated only after all earlier frames verify;
- an unsealed result is never expanded or labeled complete;
- a sealed result either verifies fully or returns generic unavailable; and
- recovery converges after a second run without creating another key or result.

The filesystem adapter injects short writes, `EINTR`, `ENOSPC`, `EIO`, permission
errors, failed file sync, failed directory sync, failed rename, failed truncate,
and failed unlink. Any failed durability operation returns no new acknowledgment
and poisons the writer. Run the same suite on a real APFS volume. A separate
power-cut/reboot harness plus the safe `F_FULLFSYNC` decision is required before
making a sudden-power-loss claim.

### Lifecycle, isolation, and concurrency tests

- Verify modes 0700/0600 at creation and after recovery; reject symlinks,
  non-regular objects, wrong owner, and permissive modes.
- Exercise a locked/deleted/replaced root KEK and locked, missing, corrupt,
  mismatched, duplicate, or failed-update result records. No path writes
  plaintext and no implicit memory-only fallback occurs.
- Verify the 30-minute default, shorter configuration, organization cap for any
  longer value, no extension on access, boundary equality, expiry during read,
  backward wall jump during a live process, and cleanup after restart.
- Race two writers, readers with expiry, reader versus delete, two deletes, and
  sweeper versus create/seal/delete. There is at most one published result and
  deletion remains idempotent.
- Verify direct-path, parent-glob, symlink, hard-link, case-alias, `..`, relocated
  store, and check/open race exclusions by opened file identity.
- Remove or rotate the source after seal; expansion still returns authenticated
  authorized bytes. Tamper or expire the snapshot; no provider call occurs.
- Scan cache names, cleartext headers, interrupted files, diagnostics, telemetry
  queues, panic output, process artifacts produced by the harness, support
  bundles, and CI outputs for source/path/question/credential/provider-error
  canaries. Any occurrence outside ciphertext or expected user-facing expansion
  blocks release.

Performance tests compare packed segments with a per-event-file experimental
arm and report ciphertext bytes, file count, append latency, sync latency, seal
latency, recovery time, and delete time across event-size/cardinality strata.
They tune segment caps only; they cannot relax the acknowledgment barrier or
security gates.

## Unresolved choices and required spikes

These are explicit blockers or bounded follow-ups, not implicit assumptions:

1. **Power-loss durability:** choose and review a safe `F_FULLFSYNC` mechanism
   compatible with `unsafe_code = "forbid"`, measure its cost, and run APFS
   fault tests; otherwise keep the narrower documented durability claim.
2. **Keychain runtime behavior:** verify protected/non-synchronizing attributes,
   `AccessibleWhenUnlockedThisDeviceOnly`, enumeration, update/delete,
   concurrent processes, locked state, and prompts for signed and unsigned CLI
   binaries. Failure of any required property blocks the persistent backend.
3. **Cross-process locking:** admit `fs4` only after crash release, shared versus
   exclusive contention, rename/delete, network-volume rejection, and MSRV tests.
4. **Encrypted manifest codec:** select a deterministic, bounded, versioned
   representation and freeze golden vectors. The outer fixed codec is decided.
5. **Interrupted acquisition schema:** add or select a truthful typed completion
   state before recovery may automatically publish an interrupted prefix.
6. **Cache availability:** the Phase 1 cache location permits OS purging. A
   stronger within-TTL availability promise would require revisiting placement,
   backup exclusion, and cleanup semantics.
7. **Clock rollback across restart:** monotonic time protects a live process, but
   wall-clock rollback across reboot can extend an absolute TTL. Decide whether
   to add a Keychain-authenticated high-water clock and fail closed on rollback;
   do not claim rollback resistance until tested.
8. **FIPS/regulated environments:** determine whether a validated crypto module
   is a requirement before external release. If so, design a separate suite and
   migration policy rather than relabeling the provisional XChaCha suite.
9. **Segment parameters:** validate the provisional 8 MiB/4,096-frame rotation
   values on the benchmark matrix. This cannot change correctness semantics.

## Consequences

The design keeps the trusted storage surface small, makes every acknowledged
authorization outcome independently recoverable, anchors whole-result integrity
outside the disk cache, and supports fast key-first deletion. Packed segments
reduce filesystem churn without turning the snapshot into a template-compression
or archive product.

Costs are a Keychain item per live result, a filesystem barrier per synchronous
`SinkAck` in the current API, an encrypted manifest, explicit recovery logic, and
macOS-specific integration work. Those costs are intentional until measurement
supports a batch API. The design cannot guarantee availability against deletion,
confidentiality against the signed-in live-process attacker, forensic SSD
erasure, or universal sudden-power-loss survival.

## Primary sources and implementation references

Security and cryptography:

- IETF, [RFC 8439: ChaCha20 and Poly1305 for IETF Protocols](https://datatracker.ietf.org/doc/html/rfc8439).
- IETF, [RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function](https://datatracker.ietf.org/doc/html/rfc5869).
- libsodium, [XChaCha20-Poly1305 construction](https://doc.libsodium.org/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction).
- RustCrypto, [`chacha20poly1305` 0.11.0 documentation](https://docs.rs/chacha20poly1305/0.11.0/chacha20poly1305/).
- RustCrypto, [`hkdf` 0.12.4 documentation](https://docs.rs/hkdf/0.12.4/hkdf/).
- NCC Group, [RustCrypto AES/GCM and ChaCha20+Poly1305 implementation review](https://pentestreports.com/files/reports/nccgroup/NCC_Group_MobileCoin_RustCrypto_AESGCM_ChaCha20Poly1305_Implementation_Review_2020-02-12_v1.0.pdf). The audited commit is older than the recommended crate.
- RustCrypto, [`zeroize` 1.9.0 documentation and limitations](https://docs.rs/zeroize/1.9.0/zeroize/).
- Rust `getrandom` project, [`getrandom` 0.4.3 supported targets and MSRV](https://docs.rs/getrandom/0.4.3/getrandom/).
- NIST, [SP 800-38D: GCM and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final), relevant only to the unresolved regulated AES-GCM alternative.

Apple Keychain:

- Apple, [`kSecUseDataProtectionKeychain`](https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain).
- Apple, [`kSecAttrAccessible`](https://developer.apple.com/documentation/security/ksecattraccessible).
- Apple, [`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`](https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly).
- Apple, [`kSecAttrSynchronizable`](https://developer.apple.com/documentation/security/ksecattrsynchronizable).
- Apple, [Restricting keychain item accessibility](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility).
- `security-framework` maintainers, [`PasswordOptions` 3.7.0](https://docs.rs/security-framework/3.7.0/security_framework/passwords/struct.PasswordOptions.html) and [`ProtectionMode` source](https://docs.rs/security-framework/3.7.0/src/security_framework/access_control.rs.html).

Filesystem and Rust APIs:

- Apple, [`fsync(2)` manual page](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fsync.2.html) and [`fcntl(2)` / `F_FULLFSYNC`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fcntl.2.html).
- Apple, [Reducing disk writes](https://developer.apple.com/documentation/xcode/reducing-disk-writes), including the best-effort limitation of `F_FULLFSYNC`.
- Apple, [File System Programming Guide: file-system basics](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html).
- Rust 1.85, [`File::sync_all`](https://doc.rust-lang.org/1.85.0/std/fs/struct.File.html#method.sync_all), [`rename`](https://doc.rust-lang.org/1.85.0/std/fs/fn.rename.html), and [`OpenOptionsExt::mode`](https://doc.rust-lang.org/1.85.0/std/os/unix/fs/trait.OpenOptionsExt.html#tymethod.mode).
- Linux man-pages project, [`fsync(2)` directory-entry note](https://man7.org/linux/man-pages/man2/fsync.2.html), used as the cross-platform reason to make directory synchronization explicit and then verify it on macOS.
- `directories` maintainers, [`ProjectDirs` 6.0.0](https://docs.rs/directories/6.0.0/directories/struct.ProjectDirs.html).
- `fs4` maintainers, [`fs4` 1.1.0](https://docs.rs/fs4/1.1.0/fs4/), a provisional lock dependency rather than an accepted security boundary.
