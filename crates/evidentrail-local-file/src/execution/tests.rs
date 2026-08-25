use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::fs::{self as std_fs, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use evidentrail_authority::{
    CanonicalUnixPathV1, InternalPathPolicyV1, InternalPathRegistryV1,
    LiveApprovedBindingRegistryV1, authorize_local_file_plan_with_registries_v1,
};
use evidentrail_core::{DeterministicPolicy, LedgerBuildError, LedgerBuilder, PolicyAuthorization};
use evidentrail_ingest::{Cancellation, CancellationToken};
use evidentrail_schema::{
    AdapterIdentity, ApprovedLocalFileBindingMaterialV1, ApprovedLocalFileLocatorAuthorityV1,
    BindingId, CapKind, CompletenessProof, FetchCompleteness, FetchPartialReason,
    IdentityProofKindV1, LOCAL_FILE_ADAPTER_KIND_V1, LOCAL_FILE_ADAPTER_VERSION_V1,
    LocalFileArchitectureV1, LocalFileCertificationProfileDigest, LocalFileDeadlineModelV1,
    LocalFileFilesystemV1, LocalFileOperatingSystemV1, LocalFileOrderingV1, LocalFilePlanCapsV1,
    LocalFileQueryPlanMaterialV1, LocalFileRuntimeProfileV1, LocalFileSnapshotModeV1, PolicyDigest,
    RawEnvelopeV1, RecordFragmentReason, RecordState, RepositoryIdentityDigest, RetrievalId,
    SourceIdentityV1, UnixFileObjectIdV1, UnixFileSnapshotV1, UnixFileTypeV1,
    UnixLocalFileLocatorV1, UnixTimestampNanos,
};
use evidentrail_wire::{
    ApprovedLocalFileBindingV1, VerifiedLocalFilePlanV1,
    derive_local_file_source_identity_digest_v1, derive_local_file_source_member_v1,
    encode_approved_local_file_binding_v1, encode_local_file_plan_v1,
};

use super::*;
use crate::preflight::preflight_with_test_certification_v1;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const NANOS_PER_SECOND: i128 = 1_000_000_000;

struct Fixture {
    container: PathBuf,
    root: PathBuf,
    internal: PathBuf,
    file: PathBuf,
}

impl Fixture {
    fn new(bytes: &[u8]) -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let requested = std::env::temp_dir().join(format!(
            "evidentrail-local-execution-{}-{sequence}",
            std::process::id()
        ));
        std_fs::create_dir(&requested).unwrap();
        let container = std_fs::canonicalize(requested).unwrap();
        let root = container.join("approved");
        let internal = container.join("internal");
        std_fs::create_dir(&root).unwrap();
        std_fs::create_dir(&internal).unwrap();
        let file = root.join("service.log");
        std_fs::write(&file, bytes).unwrap();
        Self {
            container,
            root,
            internal,
            file,
        }
    }

    fn policy(&self) -> InternalPathPolicyV1 {
        InternalPathPolicyV1::new(
            [CanonicalUnixPathV1::new(path_bytes(&self.internal)).unwrap()],
            [],
        )
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std_fs::remove_dir_all(&self.container);
    }
}

struct Documents {
    binding: ApprovedLocalFileBindingV1,
    plan: VerifiedLocalFilePlanV1,
    checked_at: UnixTimestampNanos,
}

impl Documents {
    fn new(fixture: &Fixture, policy: &InternalPathPolicyV1, caps: LocalFilePlanCapsV1) -> Self {
        let checked_at = now_nanos();
        let valid_from = UnixTimestampNanos::new(checked_at.get() - 60 * NANOS_PER_SECOND);
        let created_at = UnixTimestampNanos::new(checked_at.get() - 30 * NANOS_PER_SECOND);
        let execute_before = UnixTimestampNanos::new(checked_at.get() + 300 * NANOS_PER_SECOND);
        let expires_at = UnixTimestampNanos::new(checked_at.get() + 600 * NANOS_PER_SECOND);
        let locator =
            UnixLocalFileLocatorV1::new(path_bytes(&fixture.root), [b"service.log".to_vec()])
                .unwrap();
        let snapshot = snapshot(&fixture.root, &fixture.file);
        let profile = runtime_profile();
        let maximum_caps = LocalFilePlanCapsV1::new(
            caps.source_bytes().max(4 * 1024 * 1024),
            caps.records().max(65_536),
            caps.per_record_bytes().max(1_048_576),
            caps.wall_time_millis().max(60_000),
        )
        .unwrap();
        let material = ApprovedLocalFileBindingMaterialV1::new(
            BindingId::from_bytes([0x61; 32]),
            1,
            RepositoryIdentityDigest::from_bytes([0x62; 32]),
            AdapterIdentity::new(LOCAL_FILE_ADAPTER_KIND_V1, LOCAL_FILE_ADAPTER_VERSION_V1)
                .unwrap(),
            ApprovedLocalFileLocatorAuthorityV1::new(locator.clone(), snapshot.root()),
            1,
            PolicyDigest::from_bytes([0x63; 32]),
            policy.digest(),
            profile,
            LocalFileSnapshotModeV1::WholeFileFixedHighWater,
            LocalFileOrderingV1::SingleFileByteOrder,
            maximum_caps,
            valid_from,
            expires_at,
        )
        .unwrap();
        let binding = encode_approved_local_file_binding_v1(&material).unwrap();
        let source_identity = SourceIdentityV1::new(
            binding.material().adapter().clone(),
            *binding.binding_ref(),
            derive_local_file_source_identity_digest_v1(&locator, snapshot, profile).unwrap(),
            IdentityProofKindV1::LocalFileMetadata,
            valid_from,
            Some(expires_at),
        )
        .unwrap();
        let plan = encode_local_file_plan_v1(
            &LocalFileQueryPlanMaterialV1::new(
                RetrievalId::from_bytes([0x64; 32]),
                binding.material().repository_identity(),
                source_identity,
                locator.clone(),
                profile,
                derive_local_file_source_member_v1(&locator).unwrap(),
                snapshot,
                LocalFileSnapshotModeV1::WholeFileFixedHighWater,
                LocalFileOrderingV1::SingleFileByteOrder,
                LocalFileOrderingV1::SingleFileByteOrder,
                policy.digest(),
                binding.material().policy_version().get(),
                binding.material().policy_digest(),
                caps,
                created_at,
                execute_before,
                None,
            )
            .unwrap(),
        )
        .unwrap();
        Self {
            binding,
            plan,
            checked_at,
        }
    }
}

fn path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

fn now_nanos() -> UnixTimestampNanos {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    UnixTimestampNanos::new(i128::try_from(elapsed.as_nanos()).unwrap())
}

fn runtime_profile() -> LocalFileRuntimeProfileV1 {
    let architecture = if cfg!(target_arch = "aarch64") {
        LocalFileArchitectureV1::Aarch64
    } else {
        LocalFileArchitectureV1::X86_64
    };
    LocalFileRuntimeProfileV1::new(
        LocalFileOperatingSystemV1::MacOs,
        LocalFileFilesystemV1::Apfs,
        architecture,
        LocalFileDeadlineModelV1::CooperativeBetweenIoCalls,
        LocalFileCertificationProfileDigest::from_bytes([0x65; 32]),
    )
    .unwrap()
}

fn snapshot(root: &Path, file: &Path) -> UnixFileSnapshotV1 {
    let root_metadata = std_fs::metadata(root).unwrap();
    let file_metadata = std_fs::metadata(file).unwrap();
    UnixFileSnapshotV1::new(
        UnixFileObjectIdV1::new(root_metadata.dev(), root_metadata.ino()),
        UnixFileObjectIdV1::new(file_metadata.dev(), file_metadata.ino()),
        UnixFileTypeV1::Regular,
        file_metadata.mode(),
        file_metadata.nlink(),
        file_metadata.size(),
        file_metadata.mtime(),
        file_metadata.mtime_nsec(),
        file_metadata.ctime(),
        file_metadata.ctime_nsec(),
        0,
        file_metadata.size(),
    )
    .unwrap()
}

fn caps(bytes: usize, records: u64, per_record: u64, wall: u64) -> LocalFilePlanCapsV1 {
    let source_bytes = u64::try_from(bytes).unwrap().max(1);
    LocalFilePlanCapsV1::new(source_bytes, records, per_record.min(source_bytes), wall).unwrap()
}

fn install_binding(docs: &Documents) -> LiveApprovedBindingRegistryV1 {
    let bindings = LiveApprovedBindingRegistryV1::new();
    bindings.install(docs.binding.clone()).unwrap();
    bindings
}

fn token<'binding, 'paths>(
    docs: &Documents,
    bindings: &'binding LiveApprovedBindingRegistryV1,
    paths: &'paths InternalPathRegistryV1,
) -> PreflightedLocalFileV1<'binding, 'paths> {
    let authority = authorize_local_file_plan_with_registries_v1(
        &docs.plan,
        &docs.binding,
        bindings,
        paths,
        docs.checked_at,
    )
    .unwrap();
    preflight_with_test_certification_v1(&docs.plan, authority).unwrap()
}

fn ledger_builder(docs: &Documents) -> LedgerBuilder<SourceExactPolicy> {
    let material = docs.plan.material();
    LedgerBuilder::new(
        evidentrail_schema::FetchIdentity::new(
            material.retrieval_id(),
            docs.plan.plan_id(),
            docs.plan.plan_digest(),
            material.source_identity().adapter().clone(),
        ),
        material.source_identity().digest(),
        SourceExactPolicy,
    )
}

#[derive(Clone, Copy)]
struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

struct FixedWallClockV1(UnixTimestampNanos);

impl ExecutionWallClockV1 for FixedWallClockV1 {
    fn now(&self) -> Result<UnixTimestampNanos, LocalFileExecutionError> {
        Ok(self.0)
    }
}

struct ScriptedWallClockV1 {
    values: RefCell<VecDeque<UnixTimestampNanos>>,
    last: Cell<UnixTimestampNanos>,
}

impl ScriptedWallClockV1 {
    fn new(values: impl IntoIterator<Item = UnixTimestampNanos>) -> Self {
        let values = values.into_iter().collect::<VecDeque<_>>();
        let first = values
            .front()
            .copied()
            .unwrap_or(UnixTimestampNanos::new(0));
        Self {
            values: RefCell::new(values),
            last: Cell::new(first),
        }
    }
}

impl ExecutionWallClockV1 for ScriptedWallClockV1 {
    fn now(&self) -> Result<UnixTimestampNanos, LocalFileExecutionError> {
        if let Some(value) = self.values.borrow_mut().pop_front() {
            self.last.set(value);
        }
        Ok(self.last.get())
    }
}

struct SteadyMonotonicClockV1;

impl ExecutionMonotonicClockV1 for SteadyMonotonicClockV1 {
    type Instant = u64;

    fn now(&self) -> Self::Instant {
        0
    }

    fn checked_add_millis(
        &self,
        instant: Self::Instant,
        wall_time_millis: u64,
    ) -> Option<Self::Instant> {
        instant.checked_add(wall_time_millis)
    }

    fn elapsed_millis(&self, started_at: Self::Instant, ended_at: Self::Instant) -> Option<u64> {
        ended_at.checked_sub(started_at)
    }
}

struct ScriptedMonotonicClockV1 {
    values: RefCell<VecDeque<u64>>,
    last: Cell<u64>,
}

impl ScriptedMonotonicClockV1 {
    fn new(values: impl IntoIterator<Item = u64>) -> Self {
        Self {
            values: RefCell::new(values.into_iter().collect()),
            last: Cell::new(0),
        }
    }
}

impl ExecutionMonotonicClockV1 for ScriptedMonotonicClockV1 {
    type Instant = u64;

    fn now(&self) -> Self::Instant {
        if let Some(value) = self.values.borrow_mut().pop_front() {
            self.last.set(value);
        }
        self.last.get()
    }

    fn checked_add_millis(
        &self,
        instant: Self::Instant,
        wall_time_millis: u64,
    ) -> Option<Self::Instant> {
        instant.checked_add(wall_time_millis)
    }

    fn elapsed_millis(&self, started_at: Self::Instant, ended_at: Self::Instant) -> Option<u64> {
        ended_at.checked_sub(started_at)
    }
}

struct FixedCancellationV1(bool);

impl Cancellation for FixedCancellationV1 {
    fn is_cancelled(&self) -> bool {
        self.0
    }
}

struct CancelOnCheckV1 {
    checks: Cell<usize>,
    cancel_on: usize,
}

impl Cancellation for CancelOnCheckV1 {
    fn is_cancelled(&self) -> bool {
        let check = self.checks.get() + 1;
        self.checks.set(check);
        check >= self.cancel_on
    }
}

fn execute_test<M, O>(
    preflight: PreflightedLocalFileV1<'_, '_>,
    sink: &mut dyn EnvelopeSink,
    cancellation: &dyn Cancellation,
    docs: &Documents,
    clock: &M,
    observer: &O,
) -> Result<FetchCompletion, LocalFileExecutionError>
where
    M: ExecutionMonotonicClockV1,
    O: ExecutionObserverV1,
{
    execute_with(
        preflight,
        sink,
        cancellation,
        &FixedWallClockV1(docs.checked_at),
        clock,
        observer,
    )
}

fn cap_usage(completion: &FetchCompletion, kind: CapKind) -> CapUsage {
    *completion
        .cap_usage()
        .iter()
        .find(|usage| usage.kind() == kind)
        .unwrap()
}

#[test]
fn lossless_binary_framing_seals_and_expands_the_exact_ledger() {
    let raw = b"dup\r\ndup\r\n\ninvalid:\xff\0\nfinal";
    let fixture = Fixture::new(raw);
    let policy = fixture.policy();
    let docs = Documents::new(
        &fixture,
        &policy,
        caps(raw.len(), 16, u64::try_from(raw.len()).unwrap(), 10_000),
    );
    let bindings = install_binding(&docs);
    let paths = InternalPathRegistryV1::new(policy);
    let mut builder = ledger_builder(&docs);
    let completion = execute_test(
        token(&docs, &bindings, &paths),
        &mut builder,
        &FixedCancellationV1(false),
        &docs,
        &SteadyMonotonicClockV1,
        &NoopExecutionObserverV1,
    )
    .unwrap();
    assert_eq!(
        completion.completeness(),
        &FetchCompleteness::complete(CompletenessProof::PlannedUnixFileSnapshotVerifiedV1)
    );
    assert_eq!(
        cap_usage(&completion, CapKind::SourceBytes).used(),
        completion.acknowledged().source_bytes()
    );
    let ledger = builder.seal(completion).unwrap();
    assert_eq!(ledger.events().len(), 5);
    assert_eq!(
        ledger.passthrough().flatten().copied().collect::<Vec<_>>(),
        raw
    );
    assert_eq!(ledger.events()[0].terminator(), Some(&b"\r\n"[..]));
    assert_eq!(ledger.events()[1].raw(), b"dup\r\n");
    assert_eq!(ledger.events()[2].payload(), b"");
    assert_eq!(ledger.events()[3].payload(), b"invalid:\xff\0");
    assert_eq!(ledger.events()[4].terminator(), Some(&b""[..]));
    let anchor = ledger.events()[2].id();
    let expansion = ledger.expand_same_lane(anchor, 1, 1).unwrap();
    assert_eq!(
        expansion.raw_events().collect::<Vec<_>>(),
        vec![&b"dup\r\n"[..], &b"\n"[..], &b"invalid:\xff\0\n"[..]]
    );
}

#[test]
fn empty_snapshot_is_complete_without_fabricating_a_record() {
    let fixture = Fixture::new(b"");
    let policy = fixture.policy();
    let docs = Documents::new(&fixture, &policy, caps(0, 1, 1, 10_000));
    let bindings = install_binding(&docs);
    let paths = InternalPathRegistryV1::new(policy);
    let mut builder = ledger_builder(&docs);
    let completion = execute_test(
        token(&docs, &bindings, &paths),
        &mut builder,
        &FixedCancellationV1(false),
        &docs,
        &SteadyMonotonicClockV1,
        &NoopExecutionObserverV1,
    )
    .unwrap();
    assert_eq!(completion.acknowledged().records(), 0);
    assert_eq!(completion.acknowledged().source_bytes(), 0);
    assert!(matches!(
        completion.completeness(),
        FetchCompleteness::Complete { .. }
    ));
    assert!(builder.seal(completion).unwrap().is_empty());
}

#[test]
fn exact_source_boundary_record_cap_and_per_record_cap_are_independent() {
    {
        let raw = b"one\r\n";
        let fixture = Fixture::new(raw);
        let policy = fixture.policy();
        let docs = Documents::new(&fixture, &policy, caps(raw.len(), 1, 5, 10_000));
        let bindings = install_binding(&docs);
        let paths = InternalPathRegistryV1::new(policy);
        let mut builder = ledger_builder(&docs);
        let completion = execute_test(
            token(&docs, &bindings, &paths),
            &mut builder,
            &FixedCancellationV1(false),
            &docs,
            &SteadyMonotonicClockV1,
            &NoopExecutionObserverV1,
        )
        .unwrap();
        assert!(matches!(
            completion.completeness(),
            FetchCompleteness::Complete { .. }
        ));
        assert!(!cap_usage(&completion, CapKind::SourceBytes).reached());
        assert!(!cap_usage(&completion, CapKind::Records).reached());
        assert!(!cap_usage(&completion, CapKind::PerRecordBytes).reached());
        assert_eq!(
            cap_usage(&completion, CapKind::SourceBytes).used(),
            completion.acknowledged().source_bytes()
        );
        builder.seal(completion).unwrap();
    }

    {
        let raw = b"one\n\nthree\n";
        let fixture = Fixture::new(raw);
        let policy = fixture.policy();
        let docs = Documents::new(&fixture, &policy, caps(raw.len(), 2, 16, 10_000));
        let bindings = install_binding(&docs);
        let paths = InternalPathRegistryV1::new(policy);
        let mut builder = ledger_builder(&docs);
        let completion = execute_test(
            token(&docs, &bindings, &paths),
            &mut builder,
            &FixedCancellationV1(false),
            &docs,
            &SteadyMonotonicClockV1,
            &NoopExecutionObserverV1,
        )
        .unwrap();
        assert!(cap_usage(&completion, CapKind::Records).reached());
        assert_eq!(completion.acknowledged().records(), 2);
        assert_eq!(
            cap_usage(&completion, CapKind::SourceBytes).used(),
            completion.acknowledged().source_bytes()
        );
        assert_eq!(builder.seal(completion).unwrap().events().len(), 2);
    }

    {
        let raw = b"abcdef\nnext\n";
        let fixture = Fixture::new(raw);
        let policy = fixture.policy();
        let docs = Documents::new(&fixture, &policy, caps(raw.len(), 16, 3, 10_000));
        let bindings = install_binding(&docs);
        let paths = InternalPathRegistryV1::new(policy);
        let mut builder = ledger_builder(&docs);
        let completion = execute_test(
            token(&docs, &bindings, &paths),
            &mut builder,
            &FixedCancellationV1(false),
            &docs,
            &SteadyMonotonicClockV1,
            &NoopExecutionObserverV1,
        )
        .unwrap();
        assert!(cap_usage(&completion, CapKind::PerRecordBytes).reached());
        assert_eq!(completion.acknowledged().source_bytes(), 3);
        assert_eq!(cap_usage(&completion, CapKind::SourceBytes).used(), 3);
        let ledger = builder.seal(completion).unwrap();
        assert_eq!(ledger.events()[0].raw(), b"abc");
        assert_eq!(
            ledger.events()[0].record_state(),
            RecordState::AdapterFragment {
                reason: RecordFragmentReason::PerRecordByteCap
            }
        );
    }
}

struct RejectingSinkV1 {
    calls: usize,
    offered_source_bytes: u64,
}

impl EnvelopeSink for RejectingSinkV1 {
    fn accept(
        &mut self,
        envelope: RawEnvelopeV1,
    ) -> Result<evidentrail_schema::SinkAck, LedgerBuildError> {
        self.calls += 1;
        self.offered_source_bytes = u64::try_from(envelope.record().source_len()).unwrap();
        Err(LedgerBuildError::EventCountOverflow)
    }
}

#[test]
fn sink_rejection_has_explicit_unacknowledged_divergence_and_zero_read_ahead() {
    let raw = b"one\nCANARY_MUST_NOT_BE_READ\n";
    let fixture = Fixture::new(raw);
    let policy = fixture.policy();
    let docs = Documents::new(&fixture, &policy, caps(raw.len(), 16, 64, 10_000));
    let bindings = install_binding(&docs);
    let paths = InternalPathRegistryV1::new(policy);
    let mut sink = RejectingSinkV1 {
        calls: 0,
        offered_source_bytes: 0,
    };
    let completion = execute_test(
        token(&docs, &bindings, &paths),
        &mut sink,
        &FixedCancellationV1(false),
        &docs,
        &SteadyMonotonicClockV1,
        &NoopExecutionObserverV1,
    )
    .unwrap();
    assert_eq!(sink.calls, 1);
    assert_eq!(sink.offered_source_bytes, 4);
    assert_eq!(completion.acknowledged().source_bytes(), 0);
    assert_eq!(cap_usage(&completion, CapKind::SourceBytes).used(), 4);
    assert_eq!(completion.error_codes(), &[FetchErrorCode::SinkFailure]);
}

struct CancelAfterAckSinkV1 {
    inner: LedgerBuilder<SourceExactPolicy>,
    cancellation: CancellationToken,
}

impl EnvelopeSink for CancelAfterAckSinkV1 {
    fn accept(
        &mut self,
        envelope: RawEnvelopeV1,
    ) -> Result<evidentrail_schema::SinkAck, LedgerBuildError> {
        let ack = self.inner.accept(envelope)?;
        self.cancellation.cancel();
        Ok(ack)
    }
}

#[test]
fn cancellation_boundaries_commit_acquired_bytes_but_never_read_ahead() {
    {
        let raw = b"one\ntwo\n";
        let fixture = Fixture::new(raw);
        let policy = fixture.policy();
        let docs = Documents::new(&fixture, &policy, caps(raw.len(), 16, 16, 10_000));
        let bindings = install_binding(&docs);
        let paths = InternalPathRegistryV1::new(policy);
        let mut builder = ledger_builder(&docs);
        let completion = execute_test(
            token(&docs, &bindings, &paths),
            &mut builder,
            &FixedCancellationV1(true),
            &docs,
            &SteadyMonotonicClockV1,
            &NoopExecutionObserverV1,
        )
        .unwrap();
        assert_eq!(cap_usage(&completion, CapKind::SourceBytes).used(), 0);
        assert_eq!(completion.acknowledged().source_bytes(), 0);
        builder.seal(completion).unwrap();
    }

    {
        let raw = b"abc\nnext\n";
        let fixture = Fixture::new(raw);
        let policy = fixture.policy();
        let docs = Documents::new(&fixture, &policy, caps(raw.len(), 16, 16, 10_000));
        let bindings = install_binding(&docs);
        let paths = InternalPathRegistryV1::new(policy);
        let cancellation = CancelOnCheckV1 {
            checks: Cell::new(0),
            cancel_on: 3,
        };
        let mut builder = ledger_builder(&docs);
        let completion = execute_test(
            token(&docs, &bindings, &paths),
            &mut builder,
            &cancellation,
            &docs,
            &SteadyMonotonicClockV1,
            &NoopExecutionObserverV1,
        )
        .unwrap();
        assert_eq!(cap_usage(&completion, CapKind::SourceBytes).used(), 1);
        assert_eq!(completion.acknowledged().source_bytes(), 1);
        let ledger = builder.seal(completion).unwrap();
        assert_eq!(ledger.events()[0].raw(), b"a");
        assert_eq!(
            ledger.events()[0].record_state(),
            RecordState::AdapterFragment {
                reason: RecordFragmentReason::OtherVersioned {
                    version: 1,
                    code: 2,
                },
            }
        );
    }

    {
        let raw = b"one\nnext\n";
        let fixture = Fixture::new(raw);
        let policy = fixture.policy();
        let docs = Documents::new(&fixture, &policy, caps(raw.len(), 16, 16, 10_000));
        let bindings = install_binding(&docs);
        let paths = InternalPathRegistryV1::new(policy);
        let cancellation = CancellationToken::new();
        let mut sink = CancelAfterAckSinkV1 {
            inner: ledger_builder(&docs),
            cancellation: cancellation.clone(),
        };
        let completion = execute_test(
            token(&docs, &bindings, &paths),
            &mut sink,
            &cancellation,
            &docs,
            &SteadyMonotonicClockV1,
            &NoopExecutionObserverV1,
        )
        .unwrap();
        assert_eq!(cap_usage(&completion, CapKind::SourceBytes).used(), 4);
        assert_eq!(completion.acknowledged().source_bytes(), 4);
        sink.inner.seal(completion).unwrap();
    }
}

#[test]
fn deadline_boundaries_commit_the_read_prefix_and_stop_future_reads() {
    for (timeline, raw, expected_bytes, expected_fragment_code) in [
        (vec![0, 0, 10], &b"a\nnext\n"[..], 0, None),
        (vec![0, 0, 0, 10], &b"a\nnext\n"[..], 1, Some(3)),
        (vec![0, 0, 0, 0, 0, 10], &b"\nnext\n"[..], 1, None),
        (vec![5, 4], &b"a\nnext\n"[..], 0, None),
    ] {
        let fixture = Fixture::new(raw);
        let policy = fixture.policy();
        let docs = Documents::new(&fixture, &policy, caps(raw.len(), 16, 16, 10));
        let bindings = install_binding(&docs);
        let paths = InternalPathRegistryV1::new(policy);
        let mut builder = ledger_builder(&docs);
        let clock = ScriptedMonotonicClockV1::new(timeline);
        let completion = execute_test(
            token(&docs, &bindings, &paths),
            &mut builder,
            &FixedCancellationV1(false),
            &docs,
            &clock,
            &NoopExecutionObserverV1,
        )
        .unwrap();
        assert_eq!(
            cap_usage(&completion, CapKind::SourceBytes).used(),
            expected_bytes
        );
        assert_eq!(completion.acknowledged().source_bytes(), expected_bytes);
        assert!(cap_usage(&completion, CapKind::WallTimeMillis).reached());
        let ledger = builder.seal(completion).unwrap();
        if let Some(code) = expected_fragment_code {
            assert_eq!(ledger.events().len(), 1);
            assert_eq!(ledger.events()[0].raw(), b"a");
            assert_eq!(
                ledger.events()[0].record_state(),
                RecordState::AdapterFragment {
                    reason: RecordFragmentReason::OtherVersioned { version: 1, code },
                }
            );
        }
    }
}

struct TruncateAfterReadV1 {
    file: PathBuf,
    after_bytes: u64,
    fired: Cell<bool>,
}

impl ExecutionObserverV1 for TruncateAfterReadV1 {
    fn after_pre_first_validation(&self) {}

    fn after_content_read(&self, bytes_read: u64) {
        if bytes_read == self.after_bytes && !self.fired.replace(true) {
            OpenOptions::new()
                .write(true)
                .open(&self.file)
                .unwrap()
                .set_len(0)
                .unwrap();
        }
    }

    fn after_sink_call(&self, _acknowledged_records: u64) {}
}

struct MutateBeforeFirstReadV1 {
    file: PathBuf,
}

#[derive(Default)]
struct ReadCountingObserverV1 {
    reads: Cell<u64>,
}

impl ExecutionObserverV1 for ReadCountingObserverV1 {
    fn after_pre_first_validation(&self) {}

    fn after_content_read(&self, _bytes_read: u64) {
        self.reads.set(self.reads.get().saturating_add(1));
    }

    fn after_sink_call(&self, _acknowledged_records: u64) {}
}

impl ExecutionObserverV1 for MutateBeforeFirstReadV1 {
    fn after_pre_first_validation(&self) {
        OpenOptions::new()
            .append(true)
            .open(&self.file)
            .unwrap()
            .write_all(b"mutation")
            .unwrap();
    }

    fn after_content_read(&self, _bytes_read: u64) {}

    fn after_sink_call(&self, _acknowledged_records: u64) {}
}

struct AppendAfterAckSinkV1 {
    inner: LedgerBuilder<SourceExactPolicy>,
    file: PathBuf,
    appended: bool,
}

impl EnvelopeSink for AppendAfterAckSinkV1 {
    fn accept(
        &mut self,
        envelope: RawEnvelopeV1,
    ) -> Result<evidentrail_schema::SinkAck, LedgerBuildError> {
        let ack = self.inner.accept(envelope)?;
        if !self.appended {
            OpenOptions::new()
                .append(true)
                .open(&self.file)
                .unwrap()
                .write_all(b"later")
                .unwrap();
            self.appended = true;
        }
        Ok(ack)
    }
}

#[test]
fn pre_first_mutation_reads_zero_and_post_first_mutations_return_checked_partial() {
    {
        let raw = b"alpha\n";
        let fixture = Fixture::new(raw);
        let policy = fixture.policy();
        let docs = Documents::new(&fixture, &policy, caps(raw.len(), 16, 16, 10_000));
        let bindings = install_binding(&docs);
        let paths = InternalPathRegistryV1::new(policy);
        let mut builder = ledger_builder(&docs);
        let error = execute_test(
            token(&docs, &bindings, &paths),
            &mut builder,
            &FixedCancellationV1(false),
            &docs,
            &SteadyMonotonicClockV1,
            &MutateBeforeFirstReadV1 {
                file: fixture.file.clone(),
            },
        )
        .unwrap_err();
        assert_eq!(error, LocalFileExecutionError::DescriptorValidationFailed);
    }

    {
        let raw = b"abcdef\n";
        let fixture = Fixture::new(raw);
        let policy = fixture.policy();
        let docs = Documents::new(&fixture, &policy, caps(raw.len(), 16, 16, 10_000));
        let bindings = install_binding(&docs);
        let paths = InternalPathRegistryV1::new(policy);
        let mut builder = ledger_builder(&docs);
        let completion = execute_test(
            token(&docs, &bindings, &paths),
            &mut builder,
            &FixedCancellationV1(false),
            &docs,
            &SteadyMonotonicClockV1,
            &TruncateAfterReadV1 {
                file: fixture.file.clone(),
                after_bytes: 1,
                fired: Cell::new(false),
            },
        )
        .unwrap();
        assert_eq!(completion.acknowledged().source_bytes(), 1);
        assert_eq!(cap_usage(&completion, CapKind::SourceBytes).used(), 1);
        let FetchCompleteness::Partial { reasons, .. } = completion.completeness() else {
            panic!("truncation must be partial");
        };
        assert!(
            reasons
                .iter()
                .any(|reason| reason == FetchPartialReason::SourceChanged)
        );
        assert!(
            reasons
                .iter()
                .any(|reason| reason == FetchPartialReason::SourceReadError)
        );
        builder.seal(completion).unwrap();
    }

    {
        let raw = b"one\n";
        let fixture = Fixture::new(raw);
        let policy = fixture.policy();
        let docs = Documents::new(&fixture, &policy, caps(raw.len(), 16, 16, 10_000));
        let bindings = install_binding(&docs);
        let paths = InternalPathRegistryV1::new(policy);
        let mut sink = AppendAfterAckSinkV1 {
            inner: ledger_builder(&docs),
            file: fixture.file.clone(),
            appended: false,
        };
        let completion = execute_test(
            token(&docs, &bindings, &paths),
            &mut sink,
            &FixedCancellationV1(false),
            &docs,
            &SteadyMonotonicClockV1,
            &NoopExecutionObserverV1,
        )
        .unwrap();
        assert_eq!(completion.acknowledged().source_bytes(), 4);
        assert_eq!(cap_usage(&completion, CapKind::SourceBytes).used(), 4);
        assert!(matches!(
            completion.completeness(),
            FetchCompleteness::Partial { .. }
        ));
        sink.inner.seal(completion).unwrap();
    }
}

#[test]
fn expiry_at_the_final_pre_first_byte_check_reads_zero_bytes() {
    let raw = b"must-not-be-read\n";
    let fixture = Fixture::new(raw);
    let policy = fixture.policy();
    let docs = Documents::new(&fixture, &policy, caps(raw.len(), 16, 16, 10_000));
    let bindings = install_binding(&docs);
    let paths = InternalPathRegistryV1::new(policy);
    let mut builder = ledger_builder(&docs);
    let observer = ReadCountingObserverV1::default();
    let wall_clock =
        ScriptedWallClockV1::new([docs.checked_at, docs.plan.material().execute_before()]);

    let error = execute_with(
        token(&docs, &bindings, &paths),
        &mut builder,
        &FixedCancellationV1(false),
        &wall_clock,
        &SteadyMonotonicClockV1,
        &observer,
    )
    .unwrap_err();

    assert_eq!(error, LocalFileExecutionError::AuthorityOutsideValidity);
    assert_eq!(observer.reads.get(), 0);
}

#[test]
fn execution_errors_and_debug_are_contentless() {
    let rendered = format!("{:?}", LocalFileExecutionError::DescriptorValidationFailed);
    assert_eq!(
        rendered,
        "LocalFileExecutionError { code: \"EVIDENTRAIL_LOCAL_EXECUTION_DESCRIPTOR_VALIDATION_FAILED\" }"
    );
    assert!(!rendered.contains("service.log"));
}
