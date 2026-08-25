# Local file adapter release plan

**Status:** implementation-ready release blocker  
**Scope:** one explicitly approved regular file on a certified Unix platform  
**Depends on:** [source adapter contract](SOURCE_ADAPTER_CONTRACT.md),
[wire contract plan](WIRE_CONTRACT_PLAN.md),
[local data policy](LOCAL_DATA_POLICY.md), [threat model](THREAT_MODEL.md), and
[encrypted-store ADR](adr/0004-encrypted-local-snapshot-store.md)

## Release decision

Do not release the current `FileSnapshotAdapter + ExecutionContext` API. It lets
the caller supply unrelated plan/source digests and fixes the target identity
and high-water mark only when `execute` opens the file. Component framing tests
remain useful, but `FixedSnapshotVerified` is not an earned product proof.

V1 is deliberately smaller than the general source contract:

- adapter kind `local-file`, contract version 1, with the implementation version
  pinned in every binding, plan, envelope, and certification record;
- one literal file, one root, one member, and the whole-file range beginning at
  offset zero;
- no glob, recursive discovery, rotation manifest, tail/continuation,
  compression, follow mode, or cloud/provider variant;
- regular local files only; and
- Unix-family code only, enabled per tested OS/filesystem allowlist. The first
  release target is macOS on APFS. Linux remains disabled until the same matrix
  passes there; Windows is unsupported in V1.

## Required flow and authority

```text
explicit user path
  -> metadata-only LocalFileDiscoveryV1             (not authority)
  -> user-approved ApprovedLocalFileBindingV1       (authority)
  -> binding-intersected LocalFileQueryPlanMaterialV1
  -> evidentrail-wire canonicalize + derive/verify IDs
  -> VerifiedExecutableLocalFilePlanV1              (only executable type)
  -> pre-first-byte path/handle/registry revalidation
  -> acknowledged exact-envelope stream
  -> PlannedUnixFileSnapshotVerifiedV1 | Partial
```

Discovery may use `symlink_metadata`, canonicalization, and metadata calls. It
must not call `read`, sample a record, infer format, crawl a directory, or turn a
candidate into authority. The approval UI may intentionally show the selected
path; ordinary errors, diagnostics, telemetry, `Debug`, and `Display` may not.

The approved binding is repository-scoped and contains exactly:

- binding ID/version/digest, repository identity, exact adapter kind/version,
  and policy version;
- one canonical root and one canonical root-relative member locator;
- the root's Unix device/inode identity;
- maximum source bytes, records, per-record bytes, wall time, and binding expiry;
- snapshot mode `whole_file_fixed_high_water_v1`; and
- the internal-path policy version/digest current at approval.

The binding contains no credential and no wildcard. A request can only reduce
its caps. A changed member, root, repository, policy, or adapter requires a new
approval or plan.

## Minimal type and API transition

Finish the current semantic types in `evidentrail-schema` before changing ingestion:

```rust
pub struct UnixFileObjectIdV1 {
    pub device: u64,
    pub inode: u64,
}

pub struct UnixFileSnapshotV1 {
    pub root: UnixFileObjectIdV1,
    pub file: UnixFileObjectIdV1,
    pub file_type: UnixFileTypeV1, // V1 accepts Regular only
    pub mode: u32,
    pub link_count: u64,
    pub size: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
    pub changed_seconds: i64,
    pub changed_nanoseconds: i64,
    pub start_offset: u64,          // V1 requires 0
    pub high_water_exclusive: u64, // V1 equals planned size
}

pub struct LocalFilePlanCapsV1 {
    source_bytes: u64,
    records: u64,
    per_record_bytes: u64,
    wall_time_millis: u64,
}
```

Extend, rather than duplicate, the existing
`LocalFileQueryPlanMaterialV1`. Add `retrieval_id`, the exact sensitive member
locator, `UnixFileSnapshotV1`, requested/declared ordering, snapshot mode,
internal-path policy digest, and wall-time cap. Retain `SourceIdentityV1`, policy
version/digest, creation time, and exclusive `execute_before`. Keep
`authorized_continuation` in the schema for version stability, but V1 planning
returns `Unsupported` unless it is `None`.

The executable locator uses Unix path bytes, not lossy UTF-8. It stores the
canonical root plus validated relative components; it rejects absolute member
paths, empty components, `.` and `..`. Its manual `Debug` reports presence and
component count only. `SourceMember` remains the canonical opaque envelope
identity derived from this locator; it is not reparsed as an unchecked path.

`evidentrail-wire` owns the only constructible executable wrapper:

```rust
pub struct VerifiedExecutableLocalFilePlanV1 { /* private */ }

pub fn verify_local_file_plan_v1(
    canonical_bytes: &[u8],
    declared_plan_id: PlanId,
    declared_plan_digest: PlanDigest,
) -> Result<VerifiedExecutableLocalFilePlanV1, PlanVerificationError>;
```

It rejects noncanonical JSON, unknown/duplicate fields, wrong versions, bounds,
ID mismatches, and material over 1 MiB before allocation. Locally compiled plans
must pass through the same canonical encode-and-verify path as persisted plans.

Replace the stateful adapter with a stateless local adapter whose production
methods require authority explicitly:

```rust
pub struct LocalFileAdapter<F, W, M> { /* fs, wall clock, monotonic clock */ }

impl<F, W, M> LocalFileAdapter<F, W, M> {
    pub fn discover(
        &self,
        request: ExplicitLocalFileDiscovery,
        exclusions: &SourceExclusionSet,
    ) -> Result<LocalFileDiscoveryV1, DiscoveryError>;

    pub fn compile_plan(
        &self,
        binding: &ApprovedLocalFileBindingV1,
        intent: LocalFileIntentV1,
        exclusions: &SourceExclusionSet,
    ) -> Result<LocalFileQueryPlanMaterialV1, PlanningError>;

    pub fn execute(
        &self,
        plan: &VerifiedExecutableLocalFilePlanV1,
        sink: &mut dyn EnvelopeSink,
        cancellation: &dyn Cancellation,
        internal_paths: &dyn InternalPathRegistry,
    ) -> Result<FetchCompletion, ExecuteRejected>;
}
```

`ExecutionContext` becomes a crate-private view derived from the verified plan;
its public constructor is removed. `ApprovedRoot`, `SnapshotLimits`, and
`FileSnapshotAdapter::new` are removed from the production API, not wrapped by a
compatibility shim. Tests that exercise the byte framer call a private framing
harness.

`ExecuteRejected` is limited to failures established before a source byte is
read: invalid/expired plan, revoked binding/policy, unsupported platform,
identity change, excluded source, or unavailable target. After the first read,
every path returns a checked `FetchCompletion` preserving acknowledged counts.

## Canonical identities

`evidentrail-wire` uses RFC 8785 canonical JSON and one length-framed hash primitive:

```text
H(domain, body) = SHA-256(
  u64_le(len(domain)) || domain || u64_le(len(body)) || body
)
```

The exact domain strings are frozen in golden fixtures:

```text
evidentrail/local-file-source-identity/v1
evidentrail/local-file-query-plan-digest/v1
evidentrail/local-file-query-plan-id/v1
```

The source-identity body contains no payload. It contains contract and adapter
versions, Unix platform/proof kind, canonical root/member path bytes, root and
file device/inode, regular-file type/mode/link count, size, mtime seconds/nanos,
ctime seconds/nanos, start offset, and high-water mark. The resulting
`SourceIdentityDigest` is placed in `SourceIdentityV1`; proof observation/expiry
times and the binding reference remain separately typed.

The canonical plan body is the complete extended
`LocalFileQueryPlanMaterialV1`; it excludes only `PlanId`, `PlanDigest`, and the
sanitized display label. `PlanDigest` and `PlanId` are independent
domain-separated hashes of those same canonical bytes. Therefore changing any
retrieval, binding, source identity, member, snapshot fact, policy, cap,
ordering, continuation, internal-path policy, or execution time boundary changes
both. Verification recomputes both and compares the declared typed values before
execution.

Canonical plan/binding bytes are C2 local metadata and may contain the approved
path. Hashing is integrity, not anonymization: path-bearing bytes and their
digests never enter diagnostics or telemetry. These types have manual redacted
formatters; errors expose stable codes, fixed stages, counts, and cap values
only. Product UI path rendering is a separate explicit boundary and is excluded
from identity.

## Internal-path exclusion

The application owns one initialized `InternalPathRegistry`. Snapshot store,
key-envelope, diagnostic, telemetry-queue, and support-bundle components register
canonical roots, active aliases, and every existing Unix file identity, including
temporary, recovery, expired-but-not-yet-removed, and cleanup-pending objects.
Store initialization and recovery must complete registration before discovery is
available.

```rust
pub trait InternalPathRegistry {
    fn read_lease(&self) -> Result<InternalPathLease<'_>, InternalPathError>;
}

impl InternalPathLease<'_> {
    pub fn policy_digest(&self) -> InternalPathPolicyDigest;
    pub fn rejects_canonical(&self, path: &CanonicalUnixPath) -> bool;
    pub fn rejects_opened(&self, id: UnixFileObjectIdV1) -> bool;
}
```

The policy digest changes when configured roots/aliases relocate or are removed;
dynamic files below an already reserved root do not churn it. Providers register
a file identity immediately after safe creation/open and before publishing or
using it, and unregister only after unlink. A read lease makes the canonical
check, open, `fstat`, and opened-identity check atomic with respect to registry
updates. Registry failure is fail-closed.

Discovery and planning reject canonical targets within a reserved root. Execution
repeats that check using the current lease, then rejects an opened device/inode
matching any active internal file. This second check closes a hard-link alias
outside the reserved path. It applies to all internal components, not only the
snapshot store. An intentional diagnostic artifact must first be copied outside
every reserved root and separately approved.

`SnapshotStore::reserved_roots()` contributes store facts to this application
registry without creating an ingest/store dependency cycle. Shared opaque path
bytes, Unix object IDs, and exclusion-set value types belong in
`evidentrail-schema`; the mutable registry and synchronization stay in the application
composition layer.

## Pre-first-byte and completion algorithm

Execution performs these steps in order, with zero content reads before step 9:

1. Verify canonical plan bytes, IDs, schema/adapter version, hard bounds, and
   certified platform/filesystem.
2. Require wall-clock `now < execute_before`, unexpired source proof, exact live
   binding ID/version/digest, current policy digest, and matching repository.
3. Acquire an internal-path read lease and require its policy digest to equal the
   plan's value.
4. Recanonicalize the root/member, enforce component containment, and reject
   reserved canonical paths.
5. Open the root directory and compare its device/inode with the plan.
6. Walk member components descriptor-relatively with no-follow directory opens;
   open the final member read-only with `O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK`
   (plus `O_NOCTTY` where available).
7. `fstat` the handle; require a regular file and exact planned device, inode,
   mode/type, link count, size, mtime, ctime, offset, and high-water facts. Rebuild
   the source-identity body from the observed root, locator, and handle facts;
   recompute its `SourceIdentityDigest` through `evidentrail-wire` and require an exact
   match. Reject the opened identity if the registry marks it internal.
8. Resolve/re-stat the selected path again, require it to identify the same
   opened object and planned snapshot, and recheck root identity and exclusions.
9. Stream exactly `[0, high_water_exclusive)` with cap checks before each read;
   require a durable, valid sink acknowledgement before the next read.
10. Re-`fstat` the handle and revalidate root/path/registry. Any identity, size,
    mtime, ctime, link-count, path, or exclusion change is `Partial(SourceChanged)`.

V1 is intentionally conservative: append, rename, or metadata change after open
returns partial even when the originally opened prefix might be recoverable. Do
not claim append-safe or rename-safe completeness until an additional proof and
fixture suite is admitted.

Emit `CompletenessProof::PlannedUnixFileSnapshotVerifiedV1` (stable code
`planned_unix_file_snapshot_verified_v1`) only when all ten steps pass, every
planned byte and record is acknowledged, and no cap, cancellation, deadline,
read, sink, framing, or registry condition terminated execution. Stop emitting
the ambiguous `FixedSnapshotVerified` proof from the file adapter.

## Safe syscall boundary

The first macOS implementation should use a pinned `rustix` release with its
`fs` feature for the descriptor operations. Its public safe APIs cover
[`openat`](https://docs.rs/rustix/latest/rustix/fs/fn.openat.html), `fstat`, and
`fstatfs`, and use owned/borrowed descriptor types rather than raw integer file
descriptors. Product crates keep `unsafe_code = "forbid"`; any dependency
upgrade still requires license, advisory, provenance, and behavior review.

Walk every relative component with `openat` from the already verified parent
descriptor. Intermediate components use directory + no-follow + close-on-exec
flags; the final component uses read-only + no-follow + nonblocking +
close-on-exec flags and is then checked with `fstat`. `fstatfs` on the opened
root and file must match the admitted runtime/certification profile. Reads use
the same owned final descriptor. No raw descriptor may escape this module.

[`cap-std`](https://github.com/bytecodealliance/cap-std/blob/main/README.md) is
not the V1 path walker: it intentionally supports symlinks that remain inside
its sandbox, while this release contract rejects every symlink component and
revalidates exact planned object identity. This is a semantic choice, not a
general safety claim about either library.

The safe wrapper is necessary but not sufficient evidence. The race suite must
still exercise component replacement, nested/final symlinks, root rename,
hard-link aliases, file rotation, append/truncate, filesystem mismatch, and
registry changes around every preflight/read boundary on the certified matrix.

## Deadline and synchronous-I/O boundary

The plan carries two distinct limits:

- `execute_before` is an exclusive wall-clock validity boundary checked before
  content; and
- `wall_time_millis` is the effective minimum of request, binding, policy,
  adapter, and product limits.

At `execute` entry, capture `Instant::now()` and checked-add the wall-time budget.
Check the monotonic deadline and cancellation before every source read, and check
again after every read and every `sink.accept`. Cancellation or wall-time expiry
during preflight returns a zero-record partial completion; an identity, binding,
or policy rejection remains a pre-content `ExecuteRejected`. Once elapsed,
perform no new read, retain prior acknowledgements, and return
`Partial(WallTimeCap)` with `CapKind::WallTimeMillis`. Cancellation similarly
returns `Partial(Cancelled)`. A final acknowledgement arriving after the deadline
cannot become `Complete`.

This is cooperative, not preemptive. A synchronous regular-file `read` can block
inside the kernel, and `O_NONBLOCK` normally does not make regular-file I/O
interruptible. A synchronous sink can block in encryption, Keychain, or `fsync`.
The adapter observes cancellation/deadline only when such a call returns; it
cannot safely kill the call, abandon a mutating sink, or promise a fixed grace
latency. V1 therefore advertises `cooperative_deadline_between_io_calls_v1`, not
hard real-time cancellation. Network, FUSE, and unapproved filesystem types are
outside the certified capability. A future hard deadline requires a separately
reviewed cancellable I/O/process-isolation design.

## Advertised capability surface

After certification, adapter metadata may advertise only:

| Kind | Stable code |
|---|---|
| Source | `explicit_single_regular_file_v1` |
| Range | `whole_file_fixed_high_water_v1` |
| Identity | `unix_opened_handle_snapshot_v1` |
| Ordering | `single_file_byte_order_v1` |
| Framing | `byte_exact_newline_framing_v1` |
| Backpressure | `synchronous_ack_before_next_read_v1` |
| Cancellation | `cooperative_cancel_between_io_calls_v1` |
| Deadline | `cooperative_deadline_between_io_calls_v1` |
| Complete proof | `planned_unix_file_snapshot_verified_v1` |

Everything else is explicitly unsupported, not `Unknown`. Certification metadata
names the exact adapter version, OS version, filesystem type, fixture revision,
and test revision. A Darwin pass makes no Linux or generic-Unix claim.

## Required release matrix

| Gate | Minimum automated cases | Required result |
|---|---|---|
| Discovery | read-trap filesystem, unreadable content with readable metadata, literal file, no crawl/glob | zero content operations |
| Binding/plan | repository mismatch, cap widening, expiry/revocation, adapter/policy change, non-`None` continuation | reject before content |
| Canonical wire | RFC 8785 vectors; duplicate/unknown fields; oversize; declared ID/digest mismatch; mutate every semantic field | fail closed; stable goldens |
| Pre-read identity | append, truncate, replace, chmod/touch, root replace, member change between plan and execute | no sink mutation; identity error |
| Containment | absolute/`..`, inside and escaping symlink, nested/final swap, root swap, case alias, FIFO/socket/device | outside/special canary never reaches sink |
| Internal roots | direct path, parent selection, alias, relocation, check/open race, hard links to store/diagnostic/telemetry/support files | reject canonical or opened identity |
| In-read races | append, truncate, in-place write, rename, replacement, disappearance, registry change | preserve acks; never `Complete` |
| Framing/bounds | LF, CRLF, lone CR, blank, NUL, invalid UTF-8, missing terminator, duplicate, 8 MiB boundary, all cap coincidences | byte-exact; no read-ahead; honest fragment/partial |
| Acknowledgement | wrong retrieval/sequence/source-record ID/outcome/count, sink error, delayed acknowledgement | no inflated count or false complete |
| Cancellation/time | before first byte, mid-record, after ack, exact deadline, delayed read return, delayed sink return, wall-clock jump | exact ack prefix; partial; no later read |
| Completion | empty file, exact high-water/cap equality, every single proof predicate removed in turn | proof only when every predicate holds |
| Diagnostics | path/source/query/credential/error canaries through all errors, `Debug`, panic harness, diagnostics and CI artifacts | zero canary outside expected UI/evidence |
| Platform | real APFS plus injected FS faults; non-Unix compile/API gate | only certified target enabled |

Property tests cover binding monotonicity, canonical identity sensitivity, cap
ordering, and the invariant `Complete => acknowledged_source_bytes ==
high_water_exclusive && no terminating condition`. Fault tests record whether a
source byte was read, so a rejected preflight cannot pass merely because the sink
stayed empty.

## Dependency order and exit gate

1. **`evidentrail-schema`:** extend the current local plan/caps with retrieval,
   sensitive locator, Unix snapshot, wall time, ordering/snapshot mode, and
   internal-path policy facts; add the specific completeness proof. No second
   local-plan type is created.
2. **`evidentrail-wire`:** implement only the strict local binding/plan DTOs,
   canonicalization, domain hashes, private verified wrapper, bounds, and golden
   fixtures required above. This is the narrow local-plan slice already ordered
   by `WIRE_CONTRACT_PLAN`; it does not freeze unrelated G3 records.
3. **Registry providers:** implement the application-owned registry and
   diagnostic/telemetry/support contributors. Use synthetic store exclusions in
   adapter tests.
4. **`evidentrail-ingest`:** land metadata-only discovery and binding-intersected
   planning, change execution to the verified plan, preserve the tested framer,
   add Unix descriptor-relative open/revalidation, deadline checks, and delete
   the public legacy constructors.
5. **`evidentrail-store`:** implement the ADR's live reserved-root/file-identity
   contributor and durable sink. Wire it into the registry before enabling any
   product file acquisition.
6. **Certification:** run the full matrix on real APFS and fault adapters, freeze
   local plan/proof goldens, and publish the exact capability record.

Adapter implementation may proceed before the full wire/product record set is
frozen, but release remains blocked until the local binding/plan wire schema is
frozen, store exclusions and the durable sink are integrated, every required
matrix row passes, and the old caller-constructed execution path is absent from
the product build.
