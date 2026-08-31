use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use evidentrail_schema::{EventId, ExactnessBasis, ResultId};
use evidentrail_snapshot_format::{
    AuthenticatedEventIndexDirectoryV2, AuthenticatedEventIndexEntryV2, AuthenticatedEventIndexV2,
    BuildContextDigestsV1, DataManifestV2, DurableAcknowledgementV2, DurableBatchJournalV2,
    EventFrameLocatorV2, FinalManifestV2, FrameCommitmentV1, FrameHeaderV2, LifecycleDigestV1,
    LifecycleTransitionV1, MAX_AUTHENTICATED_EVENT_INDEX_SHARD_ENTRIES_V2,
    MAX_FRAME_PLAINTEXT_BYTES_V1, MAX_FRAMES_PER_SEGMENT_V1, NonceReservationV1, OperationIdV1,
    SEGMENT_HEADER_BYTES_V2, SealCommitmentsV1, SealedFrameV2, SegmentHeaderV2,
    SnapshotObjectKindV2, derive_lifecycle_digest_v1, open_frame_v2, seal_frame_v2,
};
use rustix::fs::{self as rfs, AtFlags, FlockOperation, Mode, OFlags, RenameFlags};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{AuthorityDestroyOutcomeV2, KeyAuthorityErrorV2, KeyAuthorityV2};

pub const MAX_DURABLE_BATCH_EVENTS_V2: usize = (MAX_FRAMES_PER_SEGMENT_V1 as usize) - 2;
pub const MAX_DURABLE_EXPANSION_EVENTS_V2: usize = 1_024;
pub const MAX_DURABLE_EXPANSION_BYTES_V2: usize = 64 * 1024 * 1024;
pub const CREATING_RECOVERY_GRACE_NANOS_V2: i64 = 300_000_000_000;

const ROOT_MODE_V2: u32 = 0o700;
const FILE_MODE_V2: u32 = 0o600;
const EVENT_PAYLOAD_HEADER_BYTES_V2: usize = 112;
const EVENT_PAYLOAD_MAGIC_V2: [u8; 8] = *b"EVREVT02";
const BATCH_META_BYTES_V2: usize = 80;
const BATCH_META_MAGIC_V2: [u8; 8] = *b"EVRBAT02";
const REPOSITORY_COMMITMENT_BYTES_V2: usize = 32;
const REPOSITORY_COMMITMENT_DOMAIN_V2: &[u8] = b"evidentrail.repository.commitment.v2";
const BATCH_DIGEST_DOMAIN_V2: &[u8] = b"evidentrail.repository.batch.v2";
const BEGIN_DIGEST_DOMAIN_V2: &[u8] = b"evidentrail.repository.begin.v2";
const DATA_OPERATION_DOMAIN_V2: &[u8] = b"evidentrail.repository.commit-data.v2";
const SEAL_OPERATION_DOMAIN_V2: &[u8] = b"evidentrail.repository.seal.v2";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableRepositoryFaultPointV2 {
    AfterAuthorityBegin,
    AfterBeginDurability,
    AfterBatchDurabilityBeforeAcknowledgement,
    AfterDataDurabilityBeforeAuthority,
    AfterSealDurabilityBeforeAuthority,
    AfterCommitmentDurabilityBeforeRename,
    AfterPublishRenameBeforeAuthority,
    AfterAuthorityDestroyBeforeCleanup,
}

/// Deterministic crash-boundary hook. Production uses the no-op default;
/// qualification tests may fail one named boundary and then reopen/retry.
pub trait DurableRepositoryFaultInjectorV2: Send + Sync {
    fn fail_at(&self, point: DurableRepositoryFaultPointV2) -> bool;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoDurableRepositoryFaultsV2;

impl DurableRepositoryFaultInjectorV2 for NoDurableRepositoryFaultsV2 {
    fn fail_at(&self, _point: DurableRepositoryFaultPointV2) -> bool {
        false
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DurableEventInputV2 {
    event_id: EventId,
    exactness_basis: ExactnessBasis,
    authorized_bytes: Vec<u8>,
}

impl DurableEventInputV2 {
    pub fn new(
        event_id: EventId,
        exactness_basis: ExactnessBasis,
        authorized_bytes: Vec<u8>,
    ) -> Result<Self, DurableRepositoryErrorV2> {
        let encoded = EVENT_PAYLOAD_HEADER_BYTES_V2
            .checked_add(authorized_bytes.len())
            .ok_or(DurableRepositoryErrorV2::CapacityExceeded)?;
        if encoded > MAX_FRAME_PLAINTEXT_BYTES_V1 {
            return Err(DurableRepositoryErrorV2::CapacityExceeded);
        }
        Ok(Self {
            event_id,
            exactness_basis,
            authorized_bytes,
        })
    }

    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn exactness_basis(&self) -> ExactnessBasis {
        self.exactness_basis
    }

    #[must_use]
    pub fn authorized_bytes(&self) -> &[u8] {
        &self.authorized_bytes
    }
}

impl fmt::Debug for DurableEventInputV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableEventInputV2")
            .field("exact_byte_count", &self.authorized_bytes.len())
            .finish_non_exhaustive()
    }
}

pub struct BatchCommitInputV2 {
    ordinal: u64,
    operation: OperationIdV1,
    events: Vec<DurableEventInputV2>,
    semantic_receipts: Vec<Vec<u8>>,
    operational_receipts: Vec<Vec<u8>>,
}

impl BatchCommitInputV2 {
    pub fn new(
        ordinal: u64,
        operation: OperationIdV1,
        events: Vec<DurableEventInputV2>,
        semantic_receipts: Vec<Vec<u8>>,
        operational_receipts: Vec<Vec<u8>>,
    ) -> Result<Self, DurableRepositoryErrorV2> {
        let frame_count = 2usize
            .checked_add(events.len())
            .and_then(|count| count.checked_add(semantic_receipts.len()))
            .and_then(|count| count.checked_add(operational_receipts.len()))
            .ok_or(DurableRepositoryErrorV2::CapacityExceeded)?;
        if operation.is_zero()
            || events.len() > MAX_DURABLE_BATCH_EVENTS_V2
            || frame_count > MAX_FRAMES_PER_SEGMENT_V1 as usize
            || semantic_receipts
                .iter()
                .chain(operational_receipts.iter())
                .any(|bytes| bytes.len() > MAX_FRAME_PLAINTEXT_BYTES_V1)
        {
            return Err(DurableRepositoryErrorV2::InvalidOperation);
        }
        Ok(Self {
            ordinal,
            operation,
            events,
            semantic_receipts,
            operational_receipts,
        })
    }

    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }
}

impl fmt::Debug for BatchCommitInputV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BatchCommitInputV2")
            .field("ordinal", &self.ordinal)
            .field("event_count", &self.events.len())
            .field("semantic_receipt_count", &self.semantic_receipts.len())
            .field(
                "operational_receipt_count",
                &self.operational_receipts.len(),
            )
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DurableEventAcknowledgementV2 {
    event_id: EventId,
    locator: EventFrameLocatorV2,
}

impl DurableEventAcknowledgementV2 {
    #[must_use]
    pub const fn event_id(self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn locator(self) -> EventFrameLocatorV2 {
        self.locator
    }
}

impl fmt::Debug for DurableEventAcknowledgementV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurableEventAcknowledgementV2(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DurableBatchCommitV2 {
    ordinal: u64,
    acknowledgements: Vec<DurableEventAcknowledgementV2>,
    transition: LifecycleTransitionV1,
}

impl DurableBatchCommitV2 {
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    #[must_use]
    pub fn acknowledgements(&self) -> &[DurableEventAcknowledgementV2] {
        &self.acknowledgements
    }

    #[must_use]
    pub const fn transition(&self) -> LifecycleTransitionV1 {
        self.transition
    }
}

impl fmt::Debug for DurableBatchCommitV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableBatchCommitV2")
            .field("ordinal", &self.ordinal)
            .field("acknowledgement_count", &self.acknowledgements.len())
            .field("transition", &self.transition)
            .finish()
    }
}

#[derive(Clone, Copy)]
pub struct DataCommitInputV2 {
    pub operation: OperationIdV1,
    pub question_configuration: LifecycleDigestV1,
    pub acquisition_receipt: LifecycleDigestV1,
    pub transformation_receipts: LifecycleDigestV1,
    pub fetch_completion: LifecycleDigestV1,
    pub source_identity: LifecycleDigestV1,
    pub build_context: BuildContextDigestsV1,
}

impl fmt::Debug for DataCommitInputV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DataCommitInputV2(<redacted>)")
    }
}

pub struct SealInputV2 {
    pub operation: OperationIdV1,
    pub log_brief: Vec<u8>,
    pub references: Vec<u8>,
    pub presentation_receipt: Vec<u8>,
    pub status: Vec<u8>,
    pub alias_manifest: Vec<u8>,
}

impl fmt::Debug for SealInputV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SealInputV2(<redacted>)")
    }
}

pub struct OpenedDurableEventV2 {
    event_id: EventId,
    exactness_basis: ExactnessBasis,
    authorized_bytes: Zeroizing<Vec<u8>>,
}

impl OpenedDurableEventV2 {
    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn exactness_basis(&self) -> ExactnessBasis {
        self.exactness_basis
    }

    #[must_use]
    pub fn authorized_bytes(&self) -> &[u8] {
        &self.authorized_bytes
    }
}

impl fmt::Debug for OpenedDurableEventV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenedDurableEventV2")
            .field("exact_byte_count", &self.authorized_bytes.len())
            .finish_non_exhaustive()
    }
}

pub struct DurableExpansionV2 {
    events: Vec<OpenedDurableEventV2>,
    returned_bytes: usize,
}

impl DurableExpansionV2 {
    #[must_use]
    pub fn events(&self) -> &[OpenedDurableEventV2] {
        &self.events
    }

    #[must_use]
    pub const fn returned_bytes(&self) -> usize {
        self.returned_bytes
    }
}

impl fmt::Debug for DurableExpansionV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableExpansionV2")
            .field("event_count", &self.events.len())
            .field("returned_bytes", &self.returned_bytes)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RecoveryDispositionV2 {
    Absent,
    ResumeOpen,
    ResumeCompilation,
    ReissueRequired,
    CompletedPublication,
    AlreadyVisible,
    Expired,
    Quarantined,
    RollbackOrCorruption,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RecoveryEntryV2 {
    result_id: ResultId,
    disposition: RecoveryDispositionV2,
}

impl RecoveryEntryV2 {
    #[must_use]
    pub const fn result_id(self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn disposition(self) -> RecoveryDispositionV2 {
        self.disposition
    }
}

impl fmt::Debug for RecoveryEntryV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryEntryV2")
            .field("disposition", &self.disposition)
            .finish_non_exhaustive()
    }
}

pub struct RecoveryReportV2 {
    entries: Vec<RecoveryEntryV2>,
}

impl RecoveryReportV2 {
    #[must_use]
    pub fn entries(&self) -> &[RecoveryEntryV2] {
        &self.entries
    }
}

impl fmt::Debug for RecoveryReportV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryReportV2")
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

impl fmt::Debug for RecoveryDispositionV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryDispositionV2")
            .field("code", &self.code())
            .finish()
    }
}

impl RecoveryDispositionV2 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Absent => "EVIDENTRAIL_RECOVERY_ABSENT",
            Self::ResumeOpen => "EVIDENTRAIL_RECOVERY_RESUME_OPEN",
            Self::ResumeCompilation => "EVIDENTRAIL_RECOVERY_RESUME_COMPILATION",
            Self::ReissueRequired => "EVIDENTRAIL_RECOVERY_REISSUE_REQUIRED",
            Self::CompletedPublication => "EVIDENTRAIL_RECOVERY_COMPLETED_PUBLICATION",
            Self::AlreadyVisible => "EVIDENTRAIL_RECOVERY_ALREADY_VISIBLE",
            Self::Expired => "EVIDENTRAIL_RECOVERY_EXPIRED",
            Self::Quarantined => "EVIDENTRAIL_RECOVERY_QUARANTINED",
            Self::RollbackOrCorruption => "EVIDENTRAIL_RECOVERY_ROLLBACK_OR_CORRUPTION",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableRepositoryErrorV2 {
    InvalidRoot,
    UnsafeFilesystemObject,
    RepositoryLocked,
    ResultLocked,
    AuthorityLocked,
    AuthorityUnavailable,
    InvalidOperation,
    OperationConflict,
    InvalidState,
    CapacityExceeded,
    ResultUnavailable,
    WriteFailed,
    FileSyncFailed,
    DirectorySyncFailed,
    ReadFailed,
    DecodeFailed,
    AuthenticationFailed,
    CommitmentMismatch,
    DuplicateEvent,
    BatchOrdinalMismatch,
    PublicationFailed,
    RollbackOrCorruption,
    ReissueRequired,
    CleanupFailed,
    FaultInjected,
}

impl DurableRepositoryErrorV2 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidRoot => "EVIDENTRAIL_DURABLE_REPOSITORY_INVALID_ROOT",
            Self::UnsafeFilesystemObject => "EVIDENTRAIL_DURABLE_REPOSITORY_UNSAFE_OBJECT",
            Self::RepositoryLocked => "EVIDENTRAIL_DURABLE_REPOSITORY_LOCKED",
            Self::ResultLocked => "EVIDENTRAIL_DURABLE_RESULT_LOCKED",
            Self::AuthorityLocked => "EVIDENTRAIL_DURABLE_AUTHORITY_LOCKED",
            Self::AuthorityUnavailable => "EVIDENTRAIL_DURABLE_AUTHORITY_UNAVAILABLE",
            Self::InvalidOperation => "EVIDENTRAIL_DURABLE_INVALID_OPERATION",
            Self::OperationConflict => "EVIDENTRAIL_DURABLE_OPERATION_CONFLICT",
            Self::InvalidState => "EVIDENTRAIL_DURABLE_INVALID_STATE",
            Self::CapacityExceeded => "EVIDENTRAIL_DURABLE_CAPACITY_EXCEEDED",
            Self::ResultUnavailable => "EVIDENTRAIL_DURABLE_RESULT_UNAVAILABLE",
            Self::WriteFailed => "EVIDENTRAIL_DURABLE_WRITE_FAILED",
            Self::FileSyncFailed => "EVIDENTRAIL_DURABLE_FILE_SYNC_FAILED",
            Self::DirectorySyncFailed => "EVIDENTRAIL_DURABLE_DIRECTORY_SYNC_FAILED",
            Self::ReadFailed => "EVIDENTRAIL_DURABLE_READ_FAILED",
            Self::DecodeFailed => "EVIDENTRAIL_DURABLE_DECODE_FAILED",
            Self::AuthenticationFailed => "EVIDENTRAIL_DURABLE_AUTHENTICATION_FAILED",
            Self::CommitmentMismatch => "EVIDENTRAIL_DURABLE_COMMITMENT_MISMATCH",
            Self::DuplicateEvent => "EVIDENTRAIL_DURABLE_DUPLICATE_EVENT",
            Self::BatchOrdinalMismatch => "EVIDENTRAIL_DURABLE_BATCH_ORDINAL_MISMATCH",
            Self::PublicationFailed => "EVIDENTRAIL_DURABLE_PUBLICATION_FAILED",
            Self::RollbackOrCorruption => "EVIDENTRAIL_DURABLE_ROLLBACK_OR_CORRUPTION",
            Self::ReissueRequired => "EVIDENTRAIL_DURABLE_REISSUE_REQUIRED",
            Self::CleanupFailed => "EVIDENTRAIL_DURABLE_CLEANUP_FAILED",
            Self::FaultInjected => "EVIDENTRAIL_DURABLE_FAULT_INJECTED",
        }
    }
}

impl fmt::Debug for DurableRepositoryErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableRepositoryErrorV2")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for DurableRepositoryErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for DurableRepositoryErrorV2 {}

impl From<KeyAuthorityErrorV2> for DurableRepositoryErrorV2 {
    fn from(error: KeyAuthorityErrorV2) -> Self {
        match error {
            KeyAuthorityErrorV2::Locked => Self::AuthorityLocked,
            KeyAuthorityErrorV2::NotFound => Self::ResultUnavailable,
            KeyAuthorityErrorV2::OperationConflict => Self::OperationConflict,
            KeyAuthorityErrorV2::InvalidTransition => Self::InvalidState,
            KeyAuthorityErrorV2::CapacityExceeded
            | KeyAuthorityErrorV2::NonceNamespaceExhausted => Self::CapacityExceeded,
            _ => Self::AuthorityUnavailable,
        }
    }
}

pub struct DurableResultRepositoryV2<A> {
    root: PathBuf,
    root_file: File,
    authority: A,
    fault_injector: Arc<dyn DurableRepositoryFaultInjectorV2>,
    repository_lock: Mutex<()>,
    result_locks: Mutex<BTreeMap<ResultId, Arc<RwLock<()>>>>,
}

impl<A: KeyAuthorityV2> DurableResultRepositoryV2<A> {
    pub fn open(root: &Path, authority: A) -> Result<Self, DurableRepositoryErrorV2> {
        Self::open_with_fault_injector(root, authority, NoDurableRepositoryFaultsV2)
    }

    pub fn open_with_fault_injector<I>(
        root: &Path,
        authority: A,
        fault_injector: I,
    ) -> Result<Self, DurableRepositoryErrorV2>
    where
        I: DurableRepositoryFaultInjectorV2 + 'static,
    {
        if !root.is_absolute() {
            return Err(DurableRepositoryErrorV2::InvalidRoot);
        }
        match fs::symlink_metadata(root) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(DurableRepositoryErrorV2::UnsafeFilesystemObject);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(root).map_err(|_| DurableRepositoryErrorV2::InvalidRoot)?;
                set_mode(root, ROOT_MODE_V2)?;
                sync_parent(root)?;
            }
            Err(_) => return Err(DurableRepositoryErrorV2::InvalidRoot),
        }
        let root_file =
            open_directory_nofollow(root).map_err(|_| DurableRepositoryErrorV2::InvalidRoot)?;
        validate_owned_directory(root)?;
        let repository = Self {
            root: root.to_path_buf(),
            root_file,
            authority,
            fault_injector: Arc::new(fault_injector),
            repository_lock: Mutex::new(()),
            result_locks: Mutex::new(BTreeMap::new()),
        };
        repository.ensure_lock_file(&repository.root.join(".repository.lock"))?;
        Ok(repository)
    }

    #[must_use]
    pub const fn authority(&self) -> &A {
        &self.authority
    }

    pub fn begin(
        &self,
        result_id: ResultId,
        created_unix_nanos: i64,
        expires_unix_nanos: i64,
        operation: OperationIdV1,
        request_and_question: &[u8],
    ) -> Result<LifecycleTransitionV1, DurableRepositoryErrorV2> {
        if request_and_question.len() > MAX_FRAME_PLAINTEXT_BYTES_V1 || operation.is_zero() {
            return Err(DurableRepositoryErrorV2::InvalidOperation);
        }
        let _process_guard = self.lock_repository()?;
        let _file_guard = FileLockV2::exclusive(&self.root.join(".repository.lock"))?;
        let digest = digest_begin(
            result_id,
            created_unix_nanos,
            expires_unix_nanos,
            request_and_question,
        );
        let (record, transition) = self.authority.begin(
            result_id,
            created_unix_nanos,
            expires_unix_nanos,
            operation,
            digest,
        )?;
        self.checkpoint(DurableRepositoryFaultPointV2::AfterAuthorityBegin)?;
        let staging = self.staging_path(result_id);
        if staging.exists() {
            if transition == LifecycleTransitionV1::AlreadyApplied {
                validate_owned_directory(&staging)?;
                self.ensure_lock_file(&staging.join(".result.lock"))?;
                let request_path = staging.join(segment_name(0));
                if request_path.exists() {
                    self.verify_request_frame(result_id, &staging, request_and_question)?;
                    let nonce_operation = derived_operation(operation, 0x01);
                    let _ = self.authority.complete_nonce_reservation(
                        result_id,
                        nonce_operation,
                        digest,
                    )?;
                    return Ok(transition);
                }
            } else {
                return Err(DurableRepositoryErrorV2::OperationConflict);
            }
        } else {
            let name = staging
                .file_name()
                .ok_or(DurableRepositoryErrorV2::WriteFailed)?;
            rfs::mkdirat(&self.root_file, name, Mode::RWXU)
                .map_err(|_| DurableRepositoryErrorV2::WriteFailed)?;
            let directory = rfs::openat(
                &self.root_file,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| DurableRepositoryErrorV2::WriteFailed)?;
            rfs::fchmod(&directory, Mode::RWXU)
                .map_err(|_| DurableRepositoryErrorV2::WriteFailed)?;
            self.ensure_lock_file(&staging.join(".result.lock"))?;
            sync_directory(&self.root)?;
        }

        let nonce_operation = derived_operation(operation, 0x01);
        let reservation =
            self.authority
                .reserve_nonce_range(result_id, nonce_operation, digest, 1)?;
        let segment = SegmentHeaderV2::new(result_id, 0, FrameCommitmentV1::ZERO)
            .map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
        let header = FrameHeaderV2::new(
            SnapshotObjectKindV2::Request,
            0,
            0,
            0,
            u32_len(request_and_question.len())?,
            reservation
                .nonce_at(0)
                .map_err(|_| DurableRepositoryErrorV2::CapacityExceeded)?,
            FrameCommitmentV1::ZERO,
        )
        .map_err(|_| DurableRepositoryErrorV2::InvalidOperation)?;
        let sealed = self.with_key(result_id, |dek| {
            seal_frame_v2(dek, segment, header, request_and_question)
                .map_err(|_| DurableRepositoryErrorV2::AuthenticationFailed)
        })?;
        write_segment(&staging.join(segment_name(0)), segment, &[sealed])?;
        sync_directory(&staging)?;
        let _ = self
            .authority
            .complete_nonce_reservation(result_id, nonce_operation, digest)?;
        self.checkpoint(DurableRepositoryFaultPointV2::AfterBeginDurability)?;
        let _ = record;
        Ok(transition)
    }

    pub fn commit_batch(
        &self,
        result_id: ResultId,
        input: &BatchCommitInputV2,
    ) -> Result<DurableBatchCommitV2, DurableRepositoryErrorV2> {
        let result_lock = self.result_lock(result_id)?;
        let _process_guard = result_lock
            .write()
            .map_err(|_| DurableRepositoryErrorV2::ResultLocked)?;
        let staging = self.staging_path(result_id);
        let _file_guard = FileLockV2::exclusive(&staging.join(".result.lock"))?;
        let record = self.authority.snapshot(result_id)?;
        if record.state() != evidentrail_snapshot_format::ResultLifecycleStateV1::Open {
            return Err(DurableRepositoryErrorV2::InvalidState);
        }
        let digest = digest_batch(input);
        let segment_ordinal = input
            .ordinal
            .checked_add(1)
            .ok_or(DurableRepositoryErrorV2::CapacityExceeded)?;
        let path = staging.join(segment_name(segment_ordinal));
        if path.exists() {
            let _ =
                self.authority
                    .complete_nonce_reservation(result_id, input.operation, digest)?;
            return self.reopen_committed_batch(result_id, input, digest, &path);
        }
        let existing_batches = contiguous_batch_count(&staging)?;
        if input.ordinal != existing_batches {
            return Err(DurableRepositoryErrorV2::BatchOrdinalMismatch);
        }
        let (prior_commitment, global_sequence) = self.last_chain_position(result_id, &staging)?;
        let frame_count = 2
            + input.events.len()
            + input.semantic_receipts.len()
            + input.operational_receipts.len();
        let reservation = self.authority.reserve_nonce_range(
            result_id,
            input.operation,
            digest,
            frame_count as u64,
        )?;
        let segment = SegmentHeaderV2::new(result_id, segment_ordinal, prior_commitment)
            .map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
        let meta = encode_batch_meta(
            input.ordinal,
            input.operation,
            digest,
            input.events.len() as u64,
        );
        let (frames, acknowledgements) = self.with_key(result_id, |dek| {
            let mut frames = Vec::with_capacity(frame_count);
            push_frame_with_key(
                dek,
                segment,
                &reservation,
                SnapshotObjectKindV2::OperationalReceipt,
                global_sequence,
                &meta,
                &mut frames,
            )?;
            let mut acknowledgements = Vec::with_capacity(input.events.len());
            let mut byte_offset = SEGMENT_HEADER_BYTES_V2 as u64 + frames[0].encoded_len() as u64;
            for event in &input.events {
                let payload = encode_event_payload(event)?;
                push_frame_with_key(
                    dek,
                    segment,
                    &reservation,
                    SnapshotObjectKindV2::AuthorizedEvent,
                    global_sequence,
                    &payload,
                    &mut frames,
                )?;
                let frame = frames.last().ok_or(DurableRepositoryErrorV2::WriteFailed)?;
                let locator = EventFrameLocatorV2::new(
                    segment_ordinal,
                    frame.header().frame_sequence(),
                    frame.header().global_sequence(),
                    byte_offset,
                    u32_len(frame.encoded_len())?,
                    u32_len(event.authorized_bytes.len())?,
                    frame.commitment(),
                )
                .map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
                acknowledgements.push(DurableEventAcknowledgementV2 {
                    event_id: event.event_id,
                    locator,
                });
                byte_offset = byte_offset
                    .checked_add(frame.encoded_len() as u64)
                    .ok_or(DurableRepositoryErrorV2::CapacityExceeded)?;
            }
            for receipt in &input.semantic_receipts {
                push_frame_with_key(
                    dek,
                    segment,
                    &reservation,
                    SnapshotObjectKindV2::SemanticReceipt,
                    global_sequence,
                    receipt,
                    &mut frames,
                )?;
            }
            for receipt in &input.operational_receipts {
                push_frame_with_key(
                    dek,
                    segment,
                    &reservation,
                    SnapshotObjectKindV2::OperationalReceipt,
                    global_sequence,
                    receipt,
                    &mut frames,
                )?;
            }
            let journal = DurableBatchJournalV2::new(
                input.ordinal,
                input.operation,
                digest,
                reservation,
                acknowledgements
                    .iter()
                    .map(|acknowledgement| {
                        DurableAcknowledgementV2::new(
                            acknowledgement.event_id,
                            acknowledgement.locator,
                        )
                    })
                    .collect(),
            )
            .map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
            push_frame_with_key(
                dek,
                segment,
                &reservation,
                SnapshotObjectKindV2::OperationalReceipt,
                global_sequence,
                &journal.encode(),
                &mut frames,
            )?;
            Ok((frames, acknowledgements))
        })?;
        write_segment(&path, segment, &frames)?;
        sync_directory(&staging)?;
        let _ = self
            .authority
            .complete_nonce_reservation(result_id, input.operation, digest)?;
        self.checkpoint(DurableRepositoryFaultPointV2::AfterBatchDurabilityBeforeAcknowledgement)?;
        Ok(DurableBatchCommitV2 {
            ordinal: input.ordinal,
            acknowledgements,
            transition: LifecycleTransitionV1::Applied,
        })
    }

    pub fn commit_data(
        &self,
        result_id: ResultId,
        input: DataCommitInputV2,
    ) -> Result<LifecycleTransitionV1, DurableRepositoryErrorV2> {
        if input.operation.is_zero() {
            return Err(DurableRepositoryErrorV2::InvalidOperation);
        }
        let result_lock = self.result_lock(result_id)?;
        let _process_guard = result_lock
            .write()
            .map_err(|_| DurableRepositoryErrorV2::ResultLocked)?;
        let staging = self.staging_path(result_id);
        let storage = if staging.exists() {
            staging.clone()
        } else {
            self.final_path(result_id)
        };
        let _file_guard = FileLockV2::exclusive(&storage.join(".result.lock"))?;
        let record = self.authority.snapshot(result_id)?;
        if record.state() >= evidentrail_snapshot_format::ResultLifecycleStateV1::DataCommitted {
            let existing = self.read_data_manifest(result_id, &storage)?;
            if existing.question_configuration() != input.question_configuration
                || existing.acquisition_receipt() != input.acquisition_receipt
                || existing.transformation_receipts() != input.transformation_receipts
                || existing.fetch_completion() != input.fetch_completion
                || existing.source_identity() != input.source_identity
                || existing.build_context() != input.build_context.aggregate()
            {
                return Err(DurableRepositoryErrorV2::OperationConflict);
            }
            let digest = existing.digest();
            return self
                .authority
                .commit_data(result_id, input.operation, digest, input.build_context)
                .map_err(Into::into);
        }
        if record.state() != evidentrail_snapshot_format::ResultLifecycleStateV1::Open {
            return Err(DurableRepositoryErrorV2::InvalidState);
        }
        let (mut entries, batch_chain, acquisition_chain) =
            self.reconstruct_event_entries(result_id, &staging)?;
        // Shard boundaries are part of the authenticated directory's
        // canonical EventId ordering. Sorting only inside each shard allows
        // ranges from acquisition-order chunks to overlap once a result spans
        // more than one shard, which the directory must reject.
        entries.sort_by_key(AuthenticatedEventIndexEntryV2::event_id);
        let shards = entries
            .chunks(MAX_AUTHENTICATED_EVENT_INDEX_SHARD_ENTRIES_V2)
            .map(|entries| AuthenticatedEventIndexV2::new(entries.to_vec(), acquisition_chain))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
        let index = AuthenticatedEventIndexDirectoryV2::from_shards(&shards, acquisition_chain)
            .map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
        let request_digest = self.request_plaintext_digest(result_id, &staging)?;
        let manifest = DataManifestV2::new(
            result_id,
            contiguous_batch_count(&staging)?,
            index.event_count(),
            request_digest,
            input.question_configuration,
            batch_chain,
            index.digest(),
            input.acquisition_receipt,
            input.transformation_receipts,
            input.fetch_completion,
            input.source_identity,
            input.build_context.aggregate(),
            acquisition_chain,
        )
        .map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
        let digest = manifest.digest();
        let nonce_operation = derived_operation(input.operation, 0x02);
        let nonce_digest = digest_with_domain(
            DATA_OPERATION_DOMAIN_V2,
            &[index.digest().as_bytes(), digest.as_bytes()],
        );
        if staging.join("data-commit.seg").exists() {
            let existing = self.read_data_manifest(result_id, &staging)?;
            if existing != manifest {
                return Err(DurableRepositoryErrorV2::OperationConflict);
            }
            let _ = self.authority.complete_nonce_reservation(
                result_id,
                nonce_operation,
                nonce_digest,
            )?;
            return self
                .authority
                .commit_data(result_id, input.operation, digest, input.build_context)
                .map_err(Into::into);
        }
        let ordinal = next_segment_ordinal(&staging)?;
        let (prior, global) = self.last_chain_position(result_id, &staging)?;
        let frame_count = u64::try_from(shards.len())
            .map_err(|_| DurableRepositoryErrorV2::CapacityExceeded)?
            .checked_add(2)
            .ok_or(DurableRepositoryErrorV2::CapacityExceeded)?;
        let reservation = self.authority.reserve_nonce_range(
            result_id,
            nonce_operation,
            nonce_digest,
            frame_count,
        )?;
        let segment = SegmentHeaderV2::new(result_id, ordinal, prior)
            .map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
        let mut frames = Vec::with_capacity(shards.len() + 2);
        for shard in &shards {
            self.push_frame(
                result_id,
                segment,
                &reservation,
                SnapshotObjectKindV2::EventIndex,
                global,
                &shard.encode(),
                &mut frames,
            )?;
        }
        self.push_frame(
            result_id,
            segment,
            &reservation,
            SnapshotObjectKindV2::EventIndexDirectory,
            global,
            &index.encode(),
            &mut frames,
        )?;
        self.push_frame(
            result_id,
            segment,
            &reservation,
            SnapshotObjectKindV2::DataManifest,
            global,
            &manifest.encode(),
            &mut frames,
        )?;
        write_segment(&staging.join("data-commit.seg"), segment, &frames)?;
        sync_directory(&staging)?;
        let _ =
            self.authority
                .complete_nonce_reservation(result_id, nonce_operation, nonce_digest)?;
        self.checkpoint(DurableRepositoryFaultPointV2::AfterDataDurabilityBeforeAuthority)?;
        self.authority
            .commit_data(result_id, input.operation, digest, input.build_context)
            .map_err(Into::into)
    }

    pub fn seal(
        &self,
        result_id: ResultId,
        input: &SealInputV2,
    ) -> Result<LifecycleTransitionV1, DurableRepositoryErrorV2> {
        if input.operation.is_zero() {
            return Err(DurableRepositoryErrorV2::InvalidOperation);
        }
        let result_lock = self.result_lock(result_id)?;
        let _process_guard = result_lock
            .write()
            .map_err(|_| DurableRepositoryErrorV2::ResultLocked)?;
        let staging = self.staging_path(result_id);
        let storage = if staging.exists() {
            staging.clone()
        } else {
            self.final_path(result_id)
        };
        let _file_guard = FileLockV2::exclusive(&storage.join(".result.lock"))?;
        let record = self.authority.snapshot(result_id)?;
        for bytes in [
            &input.log_brief,
            &input.references,
            &input.presentation_receipt,
            &input.status,
            &input.alias_manifest,
        ] {
            if bytes.len() > MAX_FRAME_PLAINTEXT_BYTES_V1 {
                return Err(DurableRepositoryErrorV2::CapacityExceeded);
            }
        }
        let product_digests = [
            derive_lifecycle_digest_v1(&input.log_brief),
            derive_lifecycle_digest_v1(&input.references),
            derive_lifecycle_digest_v1(&input.presentation_receipt),
            derive_lifecycle_digest_v1(&input.status),
            derive_lifecycle_digest_v1(&input.alias_manifest),
        ];
        if record.state() >= evidentrail_snapshot_format::ResultLifecycleStateV1::Sealed {
            let final_manifest = self.read_final_manifest(result_id, &storage)?;
            if final_manifest.product_digests() != product_digests {
                return Err(DurableRepositoryErrorV2::OperationConflict);
            }
            return self
                .authority
                .seal(
                    result_id,
                    input.operation,
                    self.seal_commitments(result_id, &storage, final_manifest)?,
                )
                .map_err(Into::into);
        }
        if record.state() != evidentrail_snapshot_format::ResultLifecycleStateV1::DataCommitted {
            return Err(DurableRepositoryErrorV2::InvalidState);
        }
        let data = self.read_data_manifest(result_id, &staging)?;
        let final_manifest = FinalManifestV2::new(
            result_id,
            data.digest(),
            data.event_index(),
            data.frame_chain(),
            product_digests[0],
            product_digests[1],
            product_digests[2],
            product_digests[3],
            product_digests[4],
            5,
            data.event_count(),
        )
        .map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
        let digest = digest_with_domain(
            SEAL_OPERATION_DOMAIN_V2,
            &[
                final_manifest.digest().as_bytes(),
                final_manifest.product_commitment().as_bytes(),
            ],
        );
        let nonce_operation = derived_operation(input.operation, 0x03);
        if staging.join("sealed-products.seg").exists() {
            let existing = self.read_final_manifest(result_id, &staging)?;
            if existing != final_manifest {
                return Err(DurableRepositoryErrorV2::OperationConflict);
            }
            let _ =
                self.authority
                    .complete_nonce_reservation(result_id, nonce_operation, digest)?;
            return self
                .authority
                .seal(
                    result_id,
                    input.operation,
                    self.seal_commitments(result_id, &staging, existing)?,
                )
                .map_err(Into::into);
        }
        let ordinal = next_segment_ordinal(&staging)?;
        let (prior, global) = self.last_chain_position(result_id, &staging)?;
        let reservation =
            self.authority
                .reserve_nonce_range(result_id, nonce_operation, digest, 6)?;
        let segment = SegmentHeaderV2::new(result_id, ordinal, prior)
            .map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
        let mut frames = Vec::with_capacity(6);
        let products = [
            (SnapshotObjectKindV2::Product, input.log_brief.as_slice()),
            (SnapshotObjectKindV2::Product, input.references.as_slice()),
            (
                SnapshotObjectKindV2::Product,
                input.presentation_receipt.as_slice(),
            ),
            (SnapshotObjectKindV2::Product, input.status.as_slice()),
            (
                SnapshotObjectKindV2::AliasManifest,
                input.alias_manifest.as_slice(),
            ),
        ];
        for (kind, bytes) in products {
            self.push_frame(
                result_id,
                segment,
                &reservation,
                kind,
                global,
                bytes,
                &mut frames,
            )?;
        }
        self.push_frame(
            result_id,
            segment,
            &reservation,
            SnapshotObjectKindV2::FinalManifest,
            global,
            &final_manifest.encode(),
            &mut frames,
        )?;
        write_segment(&staging.join("sealed-products.seg"), segment, &frames)?;
        sync_directory(&staging)?;
        let _ = self
            .authority
            .complete_nonce_reservation(result_id, nonce_operation, digest)?;
        self.checkpoint(DurableRepositoryFaultPointV2::AfterSealDurabilityBeforeAuthority)?;
        let commitments = SealCommitmentsV1::new(
            final_manifest.digest(),
            data.digest(),
            data.event_index(),
            LifecycleDigestV1::from_bytes(
                *frames
                    .last()
                    .ok_or(DurableRepositoryErrorV2::WriteFailed)?
                    .commitment()
                    .as_bytes(),
            ),
            final_manifest.product_commitment(),
        );
        self.authority
            .seal(result_id, input.operation, commitments)
            .map_err(Into::into)
    }

    pub fn publish(
        &self,
        result_id: ResultId,
        operation: OperationIdV1,
    ) -> Result<LifecycleTransitionV1, DurableRepositoryErrorV2> {
        if operation.is_zero() {
            return Err(DurableRepositoryErrorV2::InvalidOperation);
        }
        let _repo_process = self.lock_repository()?;
        let _repo_file = FileLockV2::exclusive(&self.root.join(".repository.lock"))?;
        let result_lock = self.result_lock(result_id)?;
        let _result_process = result_lock
            .write()
            .map_err(|_| DurableRepositoryErrorV2::ResultLocked)?;
        let staging = self.staging_path(result_id);
        let final_path = self.final_path(result_id);
        let lock_path = if staging.exists() {
            staging.join(".result.lock")
        } else {
            final_path.join(".result.lock")
        };
        let _result_file = FileLockV2::exclusive(&lock_path)?;
        let authority = self.authority.snapshot(result_id)?;
        if authority.state() == evidentrail_snapshot_format::ResultLifecycleStateV1::Published {
            self.verify_visible(result_id, &final_path, authority.repository_commitment())?;
            return self
                .authority
                .publish(
                    result_id,
                    operation,
                    authority.publication_generation(),
                    authority.repository_commitment(),
                )
                .map_err(Into::into);
        }
        if authority.state() != evidentrail_snapshot_format::ResultLifecycleStateV1::Sealed {
            return Err(DurableRepositoryErrorV2::InvalidState);
        }
        let sealed_storage = if staging.exists() {
            &staging
        } else if final_path.exists() {
            &final_path
        } else {
            return Err(DurableRepositoryErrorV2::RollbackOrCorruption);
        };
        let final_manifest = self.read_final_manifest(result_id, sealed_storage)?;
        if final_manifest.digest() != authority.seal_commitments().final_manifest() {
            return Err(DurableRepositoryErrorV2::CommitmentMismatch);
        }
        let repository_commitment = derive_repository_commitment(authority.seal_commitments());
        let generation = self.authority.reserve_publication_generation(
            result_id,
            operation,
            repository_commitment,
        )?;
        if !staging.exists() {
            if read_commitment(&final_path.join("repository.commitment"))? != repository_commitment
            {
                return Err(DurableRepositoryErrorV2::RollbackOrCorruption);
            }
            sync_directory(&final_path)?;
            sync_directory(&self.root)?;
            return self
                .authority
                .publish(result_id, operation, generation, repository_commitment)
                .map_err(Into::into);
        }
        ensure_commitment(
            &staging.join("repository.commitment"),
            repository_commitment,
        )?;
        sync_directory(&staging)?;
        self.checkpoint(DurableRepositoryFaultPointV2::AfterCommitmentDurabilityBeforeRename)?;
        rfs::renameat_with(
            &self.root_file,
            staging
                .file_name()
                .ok_or(DurableRepositoryErrorV2::PublicationFailed)?,
            &self.root_file,
            final_path
                .file_name()
                .ok_or(DurableRepositoryErrorV2::PublicationFailed)?,
            RenameFlags::NOREPLACE,
        )
        .map_err(|_| DurableRepositoryErrorV2::PublicationFailed)?;
        sync_directory(&final_path)?;
        sync_directory(&self.root)?;
        self.checkpoint(DurableRepositoryFaultPointV2::AfterPublishRenameBeforeAuthority)?;
        self.authority
            .publish(result_id, operation, generation, repository_commitment)
            .map_err(Into::into)
    }

    /// Reopen the authenticated displayed-alias capability for a published
    /// result after a process restart.
    ///
    /// The caller must already possess the result identity. This method does
    /// not enumerate products: it verifies the trusted authority record, final
    /// repository commitment, encrypted final manifest, alias-frame digest,
    /// and fixed expiry before returning the frozen exact-only aliases.
    pub fn reopen_published_alias_manifest(
        &self,
        result_id: ResultId,
        now_unix_nanos: i64,
    ) -> Result<crate::DisplayedAliasManifestV1, DurableRepositoryErrorV2> {
        let result_lock = self.result_lock(result_id)?;
        let _process_guard = result_lock
            .read()
            .map_err(|_| DurableRepositoryErrorV2::ResultLocked)?;
        let final_path = self.final_path(result_id);
        let _file_guard = FileLockV2::shared(&final_path.join(".result.lock"))?;
        let authority = self.authority.snapshot(result_id)?;
        if authority.state() != evidentrail_snapshot_format::ResultLifecycleStateV1::Published
            || now_unix_nanos < authority.created_unix_nanos()
            || now_unix_nanos >= authority.expires_unix_nanos()
        {
            return Err(DurableRepositoryErrorV2::ResultUnavailable);
        }
        self.verify_visible(result_id, &final_path, authority.repository_commitment())?;
        self.with_key(result_id, |dek| {
            let final_manifest = read_typed_manifest_frame(
                dek,
                result_id,
                &final_path.join("sealed-products.seg"),
                SnapshotObjectKindV2::FinalManifest,
            )?;
            let final_manifest = FinalManifestV2::decode(&final_manifest)
                .map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
            if final_manifest.digest() != authority.seal_commitments().final_manifest() {
                return Err(DurableRepositoryErrorV2::CommitmentMismatch);
            }
            let alias_bytes = read_typed_manifest_frame(
                dek,
                result_id,
                &final_path.join("sealed-products.seg"),
                SnapshotObjectKindV2::AliasManifest,
            )?;
            if derive_lifecycle_digest_v1(&alias_bytes) != final_manifest.product_digests()[4] {
                return Err(DurableRepositoryErrorV2::CommitmentMismatch);
            }
            let aliases = crate::DisplayedAliasManifestV1::decode(&alias_bytes)
                .map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
            if aliases.result_id() != result_id
                || aliases.expires_at().get() != i128::from(authority.expires_unix_nanos())
            {
                return Err(DurableRepositoryErrorV2::CommitmentMismatch);
            }
            Ok(aliases)
        })
    }

    pub fn expand(
        &self,
        result_id: ResultId,
        event_ids: &[EventId],
        max_events: usize,
        max_bytes: usize,
        now_unix_nanos: i64,
    ) -> Result<DurableExpansionV2, DurableRepositoryErrorV2> {
        if event_ids.is_empty()
            || max_events == 0
            || max_events > MAX_DURABLE_EXPANSION_EVENTS_V2
            || max_bytes == 0
            || max_bytes > MAX_DURABLE_EXPANSION_BYTES_V2
        {
            return Err(DurableRepositoryErrorV2::InvalidOperation);
        }
        let result_lock = self.result_lock(result_id)?;
        let _process_guard = result_lock
            .read()
            .map_err(|_| DurableRepositoryErrorV2::ResultLocked)?;
        let final_path = self.final_path(result_id);
        let _file_guard = FileLockV2::shared(&final_path.join(".result.lock"))?;
        let authority = self.authority.snapshot(result_id)?;
        if authority.state() != evidentrail_snapshot_format::ResultLifecycleStateV1::Published
            || now_unix_nanos < authority.created_unix_nanos()
            || now_unix_nanos >= authority.expires_unix_nanos()
        {
            return Err(DurableRepositoryErrorV2::ResultUnavailable);
        }
        self.verify_visible(result_id, &final_path, authority.repository_commitment())?;
        self.with_key(result_id, |dek| {
            let final_manifest = read_typed_manifest_frame(
                dek,
                result_id,
                &final_path.join("sealed-products.seg"),
                SnapshotObjectKindV2::FinalManifest,
            )?;
            let final_manifest = FinalManifestV2::decode(&final_manifest)
                .map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
            if final_manifest.digest() != authority.seal_commitments().final_manifest() {
                return Err(DurableRepositoryErrorV2::CommitmentMismatch);
            }
            let index_bytes = read_typed_manifest_frame(
                dek,
                result_id,
                &final_path.join("data-commit.seg"),
                SnapshotObjectKindV2::EventIndexDirectory,
            )?;
            let index = AuthenticatedEventIndexDirectoryV2::decode(&index_bytes)
                .map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
            if index.digest() != final_manifest.event_index()
                || index.digest() != authority.seal_commitments().event_index()
            {
                return Err(DurableRepositoryErrorV2::CommitmentMismatch);
            }
            let mut seen = BTreeSet::new();
            let mut opened_shards = BTreeMap::new();
            let mut events = Vec::new();
            let mut returned_bytes = 0usize;
            for event_id in event_ids {
                if !seen.insert(*event_id) {
                    continue;
                }
                if events.len() == max_events {
                    return Err(DurableRepositoryErrorV2::CapacityExceeded);
                }
                let descriptor = *index
                    .shard_for(*event_id)
                    .ok_or(DurableRepositoryErrorV2::ResultUnavailable)?;
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    opened_shards.entry(descriptor.ordinal())
                {
                    let bytes = read_typed_frame_sequence(
                        dek,
                        result_id,
                        &final_path.join("data-commit.seg"),
                        descriptor.ordinal(),
                        SnapshotObjectKindV2::EventIndex,
                    )?;
                    if bytes.len() != descriptor.encoded_length() as usize {
                        return Err(DurableRepositoryErrorV2::CommitmentMismatch);
                    }
                    let shard = AuthenticatedEventIndexV2::decode(&bytes)
                        .map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
                    index
                        .verify_shard(descriptor, &shard)
                        .map_err(|_| DurableRepositoryErrorV2::CommitmentMismatch)?;
                    entry.insert(shard);
                }
                let entry = opened_shards
                    .get(&descriptor.ordinal())
                    .and_then(|shard| shard.get(*event_id))
                    .ok_or(DurableRepositoryErrorV2::ResultUnavailable)?;
                let opened = read_indexed_event(dek, result_id, &final_path, entry)?;
                let next = returned_bytes
                    .checked_add(opened.authorized_bytes.len())
                    .ok_or(DurableRepositoryErrorV2::CapacityExceeded)?;
                if next > max_bytes {
                    return Err(DurableRepositoryErrorV2::CapacityExceeded);
                }
                returned_bytes = next;
                events.push(opened);
            }
            Ok(DurableExpansionV2 {
                events,
                returned_bytes,
            })
        })
    }

    pub fn recover(
        &self,
        result_id: ResultId,
        now_unix_nanos: i64,
        resume_context: Option<BuildContextDigestsV1>,
    ) -> Result<RecoveryDispositionV2, DurableRepositoryErrorV2> {
        let _repo_process = self.lock_repository()?;
        let _repo_file = FileLockV2::exclusive(&self.root.join(".repository.lock"))?;
        let result_lock = self.result_lock(result_id)?;
        let _result_process = result_lock
            .write()
            .map_err(|_| DurableRepositoryErrorV2::ResultLocked)?;
        let staging = self.staging_path(result_id);
        let final_path = self.final_path(result_id);
        let mut result_file_guards = Vec::with_capacity(2);
        let mut invalid_active_object = false;
        for path in [&staging, &final_path] {
            if path.exists() {
                validate_owned_directory(path)?;
                let lock = path.join(".result.lock");
                if lock.exists() {
                    result_file_guards.push(FileLockV2::exclusive(&lock)?);
                } else {
                    invalid_active_object = true;
                }
            }
        }
        let authority = match self.authority.snapshot(result_id) {
            Ok(record) => record,
            Err(KeyAuthorityErrorV2::NotFound) => {
                if staging.exists() || final_path.exists() {
                    self.quarantine_owned(result_id)?;
                    return Ok(RecoveryDispositionV2::Quarantined);
                }
                return Ok(RecoveryDispositionV2::Absent);
            }
            Err(error) => return Err(error.into()),
        };
        if invalid_active_object || (staging.exists() && final_path.exists()) {
            self.quarantine_owned(result_id)?;
            return Ok(RecoveryDispositionV2::Quarantined);
        }
        if now_unix_nanos >= authority.expires_unix_nanos() {
            let _ = self.authority.destroy(result_id)?;
            for path in [&staging, &final_path] {
                if path.exists() {
                    fs::remove_dir_all(path)
                        .map_err(|_| DurableRepositoryErrorV2::CleanupFailed)?;
                }
            }
            sync_directory(&self.root)?;
            return Ok(RecoveryDispositionV2::Expired);
        }
        match authority.state() {
            evidentrail_snapshot_format::ResultLifecycleStateV1::Open => {
                if !staging.exists() {
                    if now_unix_nanos.saturating_sub(authority.created_unix_nanos())
                        >= CREATING_RECOVERY_GRACE_NANOS_V2
                    {
                        let _ = self.authority.destroy(result_id)?;
                    }
                    return Ok(RecoveryDispositionV2::Absent);
                }
                Ok(RecoveryDispositionV2::ResumeOpen)
            }
            evidentrail_snapshot_format::ResultLifecycleStateV1::DataCommitted => {
                if !staging.exists() {
                    return Ok(RecoveryDispositionV2::RollbackOrCorruption);
                }
                let Some(context) = resume_context else {
                    return Ok(RecoveryDispositionV2::ReissueRequired);
                };
                if authority.validate_resume_context(context).is_err() {
                    return Ok(RecoveryDispositionV2::ReissueRequired);
                }
                let data = self.read_data_manifest(result_id, &staging)?;
                if data.digest() != authority.data_digest() {
                    return Ok(RecoveryDispositionV2::RollbackOrCorruption);
                }
                Ok(RecoveryDispositionV2::ResumeCompilation)
            }
            evidentrail_snapshot_format::ResultLifecycleStateV1::Sealed => {
                let path = if final_path.exists() {
                    &final_path
                } else {
                    &staging
                };
                if !path.exists() {
                    return Ok(RecoveryDispositionV2::RollbackOrCorruption);
                }
                let final_manifest = self.read_final_manifest(result_id, path)?;
                if final_manifest.digest() != authority.seal_commitments().final_manifest() {
                    return Ok(RecoveryDispositionV2::RollbackOrCorruption);
                }
                let repository_commitment =
                    derive_repository_commitment(authority.seal_commitments());
                if staging.exists() {
                    ensure_commitment(
                        &staging.join("repository.commitment"),
                        repository_commitment,
                    )?;
                    sync_directory(&staging)?;
                    rfs::renameat_with(
                        &self.root_file,
                        staging
                            .file_name()
                            .ok_or(DurableRepositoryErrorV2::PublicationFailed)?,
                        &self.root_file,
                        final_path
                            .file_name()
                            .ok_or(DurableRepositoryErrorV2::PublicationFailed)?,
                        RenameFlags::NOREPLACE,
                    )
                    .map_err(|_| DurableRepositoryErrorV2::PublicationFailed)?;
                    sync_directory(&final_path)?;
                    sync_directory(&self.root)?;
                }
                let operation = recovery_operation(authority.seal_commitments().final_manifest());
                let generation = self.authority.reserve_publication_generation(
                    result_id,
                    operation,
                    repository_commitment,
                )?;
                self.authority
                    .publish(result_id, operation, generation, repository_commitment)?;
                Ok(RecoveryDispositionV2::CompletedPublication)
            }
            evidentrail_snapshot_format::ResultLifecycleStateV1::Published => {
                if self
                    .verify_visible(result_id, &final_path, authority.repository_commitment())
                    .is_ok()
                {
                    Ok(RecoveryDispositionV2::AlreadyVisible)
                } else {
                    Ok(RecoveryDispositionV2::RollbackOrCorruption)
                }
            }
        }
    }

    /// Reconcile every result named by the trusted authority and every
    /// syntactically valid active filesystem object. The report deliberately
    /// redacts identifiers from `Debug`; callers must already be authorized to
    /// use the explicit getters.
    pub fn recover_all<F>(
        &self,
        now_unix_nanos: i64,
        mut resume_context: F,
    ) -> Result<RecoveryReportV2, DurableRepositoryErrorV2>
    where
        F: FnMut(ResultId) -> Option<BuildContextDigestsV1>,
    {
        let mut result_ids = BTreeSet::new();
        for record in self.authority.list()? {
            result_ids.insert(record.result_id());
        }
        for entry in fs::read_dir(&self.root).map_err(|_| DurableRepositoryErrorV2::ReadFailed)? {
            let entry = entry.map_err(|_| DurableRepositoryErrorV2::ReadFailed)?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if let Some(result_id) = parse_active_result_name(&name) {
                result_ids.insert(result_id);
            }
        }
        let mut entries = Vec::with_capacity(result_ids.len());
        for result_id in result_ids {
            entries.push(RecoveryEntryV2 {
                result_id,
                disposition: self.recover(result_id, now_unix_nanos, resume_context(result_id))?,
            });
        }
        Ok(RecoveryReportV2 { entries })
    }

    pub fn destroy(
        &self,
        result_id: ResultId,
    ) -> Result<AuthorityDestroyOutcomeV2, DurableRepositoryErrorV2> {
        let result_lock = self.result_lock(result_id)?;
        let _process_guard = result_lock
            .write()
            .map_err(|_| DurableRepositoryErrorV2::ResultLocked)?;
        let staging = self.staging_path(result_id);
        let final_path = self.final_path(result_id);
        let lock_path = if final_path.exists() {
            final_path.join(".result.lock")
        } else if staging.exists() {
            staging.join(".result.lock")
        } else {
            self.root.join(".repository.lock")
        };
        let _file_guard = FileLockV2::exclusive(&lock_path)?;
        let outcome = self.authority.destroy(result_id)?;
        self.checkpoint(DurableRepositoryFaultPointV2::AfterAuthorityDestroyBeforeCleanup)?;
        for path in [&staging, &final_path] {
            if path.exists() {
                validate_owned_directory(path)?;
                fs::remove_dir_all(path).map_err(|_| DurableRepositoryErrorV2::CleanupFailed)?;
            }
        }
        sync_directory(&self.root)?;
        Ok(outcome)
    }

    #[allow(clippy::too_many_arguments)]
    fn push_frame(
        &self,
        result_id: ResultId,
        segment: SegmentHeaderV2,
        reservation: &NonceReservationV1,
        object_kind: SnapshotObjectKindV2,
        first_global_sequence: u64,
        plaintext: &[u8],
        frames: &mut Vec<SealedFrameV2>,
    ) -> Result<(), DurableRepositoryErrorV2> {
        self.with_key(result_id, |dek| {
            push_frame_with_key(
                dek,
                segment,
                reservation,
                object_kind,
                first_global_sequence,
                plaintext,
                frames,
            )
        })
    }

    fn with_key<R>(
        &self,
        result_id: ResultId,
        operation: impl FnOnce(
            &evidentrail_snapshot_format::ResultDekV1,
        ) -> Result<R, DurableRepositoryErrorV2>,
    ) -> Result<R, DurableRepositoryErrorV2> {
        let mut repository_error = None;
        let value = self
            .authority
            .with_result_key(result_id, |_, key| match operation(key) {
                Ok(value) => Ok(Some(value)),
                Err(error) => {
                    repository_error = Some(error);
                    Ok(None)
                }
            })?;
        match value {
            Some(value) => Ok(value),
            None => Err(repository_error.unwrap_or(DurableRepositoryErrorV2::AuthorityUnavailable)),
        }
    }

    fn reconstruct_event_entries(
        &self,
        result_id: ResultId,
        directory: &Path,
    ) -> Result<
        (
            Vec<AuthenticatedEventIndexEntryV2>,
            LifecycleDigestV1,
            FrameCommitmentV1,
        ),
        DurableRepositoryErrorV2,
    > {
        self.with_key(result_id, |dek| {
            let mut entries = Vec::new();
            let mut seen = BTreeSet::new();
            let mut batch_hasher = Sha256::new();
            batch_hasher.update(BATCH_DIGEST_DOMAIN_V2);
            let request_segment = read_segment(&directory.join(segment_name(0)))?;
            if request_segment.header.result_id() != result_id
                || request_segment.header.segment_ordinal() != 0
            {
                return Err(DurableRepositoryErrorV2::CommitmentMismatch);
            }
            let mut final_commitment = request_segment
                .frames
                .last()
                .ok_or(DurableRepositoryErrorV2::DecodeFailed)?
                .commitment();
            let count = contiguous_batch_count(directory)?;
            for ordinal in 0..count {
                let segment_path = directory.join(segment_name(ordinal + 1));
                let decoded = read_segment(&segment_path)?;
                if decoded.header.result_id() != result_id
                    || decoded.header.segment_ordinal() != ordinal + 1
                {
                    return Err(DurableRepositoryErrorV2::CommitmentMismatch);
                }
                let meta_frame = decoded
                    .frames
                    .first()
                    .ok_or(DurableRepositoryErrorV2::DecodeFailed)?;
                let meta = open_frame_v2(dek, decoded.header, meta_frame)
                    .map_err(|_| DurableRepositoryErrorV2::AuthenticationFailed)?;
                let (_, _, batch_digest, _) = decode_batch_meta(meta.as_bytes())?;
                batch_hasher.update(batch_digest.as_bytes());
                let mut offset = SEGMENT_HEADER_BYTES_V2 as u64;
                for frame in &decoded.frames {
                    let encoded_length = u32_len(frame.encoded_len())?;
                    if frame.header().object_kind() == SnapshotObjectKindV2::AuthorizedEvent {
                        let opened = open_frame_v2(dek, decoded.header, frame)
                            .map_err(|_| DurableRepositoryErrorV2::AuthenticationFailed)?;
                        let (event_id, basis, authorized) =
                            decode_event_payload(opened.as_bytes())?;
                        if !seen.insert(event_id) {
                            return Err(DurableRepositoryErrorV2::DuplicateEvent);
                        }
                        entries.push(AuthenticatedEventIndexEntryV2::new(
                            event_id,
                            basis,
                            EventFrameLocatorV2::new(
                                decoded.header.segment_ordinal(),
                                frame.header().frame_sequence(),
                                frame.header().global_sequence(),
                                offset,
                                encoded_length,
                                u32_len(authorized.len())?,
                                frame.commitment(),
                            )
                            .map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?,
                        ));
                    }
                    offset = offset
                        .checked_add(u64::from(encoded_length))
                        .ok_or(DurableRepositoryErrorV2::CapacityExceeded)?;
                    final_commitment = frame.commitment();
                }
            }
            Ok((
                entries,
                LifecycleDigestV1::from_bytes(batch_hasher.finalize().into()),
                final_commitment,
            ))
        })
    }

    fn reopen_committed_batch(
        &self,
        result_id: ResultId,
        input: &BatchCommitInputV2,
        digest: LifecycleDigestV1,
        path: &Path,
    ) -> Result<DurableBatchCommitV2, DurableRepositoryErrorV2> {
        self.with_key(result_id, |dek| {
            let decoded = read_segment(path)?;
            let first = decoded
                .frames
                .first()
                .ok_or(DurableRepositoryErrorV2::DecodeFailed)?;
            let meta = open_frame_v2(dek, decoded.header, first)
                .map_err(|_| DurableRepositoryErrorV2::AuthenticationFailed)?;
            let (ordinal, operation, stored_digest, event_count) =
                decode_batch_meta(meta.as_bytes())?;
            if ordinal != input.ordinal
                || operation != input.operation
                || stored_digest != digest
                || event_count != input.events.len() as u64
            {
                return Err(DurableRepositoryErrorV2::OperationConflict);
            }
            let mut acknowledgements = Vec::with_capacity(input.events.len());
            let mut offset = SEGMENT_HEADER_BYTES_V2 as u64 + first.encoded_len() as u64;
            for frame in decoded.frames.iter().skip(1) {
                if frame.header().object_kind() == SnapshotObjectKindV2::AuthorizedEvent {
                    let opened = open_frame_v2(dek, decoded.header, frame)
                        .map_err(|_| DurableRepositoryErrorV2::AuthenticationFailed)?;
                    let (event_id, _, authorized) = decode_event_payload(opened.as_bytes())?;
                    acknowledgements.push(DurableEventAcknowledgementV2 {
                        event_id,
                        locator: EventFrameLocatorV2::new(
                            decoded.header.segment_ordinal(),
                            frame.header().frame_sequence(),
                            frame.header().global_sequence(),
                            offset,
                            u32_len(frame.encoded_len())?,
                            u32_len(authorized.len())?,
                            frame.commitment(),
                        )
                        .map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?,
                    });
                }
                offset = offset
                    .checked_add(frame.encoded_len() as u64)
                    .ok_or(DurableRepositoryErrorV2::CapacityExceeded)?;
            }
            let journal_frame = decoded
                .frames
                .last()
                .ok_or(DurableRepositoryErrorV2::DecodeFailed)?;
            let journal_bytes = open_frame_v2(dek, decoded.header, journal_frame)
                .map_err(|_| DurableRepositoryErrorV2::AuthenticationFailed)?;
            let journal = DurableBatchJournalV2::decode(journal_bytes.as_bytes())
                .map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
            let acknowledged = acknowledgements
                .iter()
                .map(|acknowledgement| {
                    DurableAcknowledgementV2::new(acknowledgement.event_id, acknowledgement.locator)
                })
                .collect::<Vec<_>>();
            if journal.batch_ordinal() != ordinal
                || journal.operation() != operation
                || journal.canonical_digest() != stored_digest
                || journal.acknowledgements() != acknowledged
            {
                return Err(DurableRepositoryErrorV2::CommitmentMismatch);
            }
            Ok(DurableBatchCommitV2 {
                ordinal,
                acknowledgements,
                transition: LifecycleTransitionV1::AlreadyApplied,
            })
        })
    }

    fn last_chain_position(
        &self,
        result_id: ResultId,
        directory: &Path,
    ) -> Result<(FrameCommitmentV1, u64), DurableRepositoryErrorV2> {
        let mut files = all_segment_files(directory)?;
        files.sort_by_key(|(ordinal, _)| *ordinal);
        let mut prior = FrameCommitmentV1::ZERO;
        let mut next_global = 0u64;
        for (ordinal, path) in files {
            let decoded = read_segment(&path)?;
            if decoded.header.result_id() != result_id
                || decoded.header.segment_ordinal() != ordinal
                || (ordinal > 0 && decoded.header.prior_segment_commitment() != prior)
            {
                return Err(DurableRepositoryErrorV2::CommitmentMismatch);
            }
            for frame in &decoded.frames {
                if frame.header().global_sequence() != next_global {
                    return Err(DurableRepositoryErrorV2::CommitmentMismatch);
                }
                prior = frame.commitment();
                next_global = next_global
                    .checked_add(1)
                    .ok_or(DurableRepositoryErrorV2::CapacityExceeded)?;
            }
        }
        Ok((prior, next_global))
    }

    fn read_data_manifest(
        &self,
        result_id: ResultId,
        directory: &Path,
    ) -> Result<DataManifestV2, DurableRepositoryErrorV2> {
        self.with_key(result_id, |dek| {
            let bytes = read_typed_manifest_frame(
                dek,
                result_id,
                &directory.join("data-commit.seg"),
                SnapshotObjectKindV2::DataManifest,
            )?;
            DataManifestV2::decode(&bytes).map_err(|_| DurableRepositoryErrorV2::DecodeFailed)
        })
    }

    fn read_final_manifest(
        &self,
        result_id: ResultId,
        directory: &Path,
    ) -> Result<FinalManifestV2, DurableRepositoryErrorV2> {
        self.with_key(result_id, |dek| {
            let bytes = read_typed_manifest_frame(
                dek,
                result_id,
                &directory.join("sealed-products.seg"),
                SnapshotObjectKindV2::FinalManifest,
            )?;
            FinalManifestV2::decode(&bytes).map_err(|_| DurableRepositoryErrorV2::DecodeFailed)
        })
    }

    fn seal_commitments(
        &self,
        result_id: ResultId,
        directory: &Path,
        final_manifest: FinalManifestV2,
    ) -> Result<SealCommitmentsV1, DurableRepositoryErrorV2> {
        let decoded = read_segment(&directory.join("sealed-products.seg"))?;
        if decoded.header.result_id() != result_id {
            return Err(DurableRepositoryErrorV2::CommitmentMismatch);
        }
        let final_frame = decoded
            .frames
            .last()
            .ok_or(DurableRepositoryErrorV2::DecodeFailed)?;
        Ok(SealCommitmentsV1::new(
            final_manifest.digest(),
            final_manifest.data_manifest(),
            final_manifest.event_index(),
            LifecycleDigestV1::from_bytes(*final_frame.commitment().as_bytes()),
            final_manifest.product_commitment(),
        ))
    }

    fn request_plaintext_digest(
        &self,
        result_id: ResultId,
        directory: &Path,
    ) -> Result<LifecycleDigestV1, DurableRepositoryErrorV2> {
        self.with_key(result_id, |dek| {
            let decoded = read_segment(&directory.join(segment_name(0)))?;
            let frame = decoded
                .frames
                .first()
                .ok_or(DurableRepositoryErrorV2::DecodeFailed)?;
            let opened = open_frame_v2(dek, decoded.header, frame)
                .map_err(|_| DurableRepositoryErrorV2::AuthenticationFailed)?;
            Ok(derive_lifecycle_digest_v1(opened.as_bytes()))
        })
    }

    fn verify_request_frame(
        &self,
        result_id: ResultId,
        directory: &Path,
        expected: &[u8],
    ) -> Result<(), DurableRepositoryErrorV2> {
        self.with_key(result_id, |dek| {
            let decoded = read_segment(&directory.join(segment_name(0)))?;
            let frame = decoded
                .frames
                .first()
                .ok_or(DurableRepositoryErrorV2::DecodeFailed)?;
            if frame.header().object_kind() != SnapshotObjectKindV2::Request {
                return Err(DurableRepositoryErrorV2::CommitmentMismatch);
            }
            let opened = open_frame_v2(dek, decoded.header, frame)
                .map_err(|_| DurableRepositoryErrorV2::AuthenticationFailed)?;
            if opened.as_bytes() != expected {
                return Err(DurableRepositoryErrorV2::OperationConflict);
            }
            Ok(())
        })
    }

    fn verify_visible(
        &self,
        result_id: ResultId,
        final_path: &Path,
        expected: LifecycleDigestV1,
    ) -> Result<(), DurableRepositoryErrorV2> {
        if !final_path.exists() || self.staging_path(result_id).exists() {
            return Err(DurableRepositoryErrorV2::RollbackOrCorruption);
        }
        validate_owned_directory(final_path)?;
        let stored = read_commitment(&final_path.join("repository.commitment"))?;
        if stored != expected {
            return Err(DurableRepositoryErrorV2::RollbackOrCorruption);
        }
        let manifest = self.read_final_manifest(result_id, final_path)?;
        let authority = self.authority.snapshot(result_id)?;
        if manifest.digest() != authority.seal_commitments().final_manifest()
            || derive_repository_commitment(authority.seal_commitments()) != expected
        {
            return Err(DurableRepositoryErrorV2::RollbackOrCorruption);
        }
        Ok(())
    }

    fn quarantine_owned(&self, result_id: ResultId) -> Result<(), DurableRepositoryErrorV2> {
        for (suffix, path) in [
            ("staging", self.staging_path(result_id)),
            ("final", self.final_path(result_id)),
        ] {
            if path.exists() {
                validate_owned_directory(&path)?;
                let quarantine =
                    self.root
                        .join(format!(".quarantine-{}-{}", result_hex(result_id), suffix));
                if quarantine.exists() {
                    return Err(DurableRepositoryErrorV2::CleanupFailed);
                }
                rfs::renameat_with(
                    &self.root_file,
                    path.file_name()
                        .ok_or(DurableRepositoryErrorV2::CleanupFailed)?,
                    &self.root_file,
                    quarantine
                        .file_name()
                        .ok_or(DurableRepositoryErrorV2::CleanupFailed)?,
                    RenameFlags::NOREPLACE,
                )
                .map_err(|_| DurableRepositoryErrorV2::CleanupFailed)?;
            }
        }
        sync_directory(&self.root)
    }

    fn staging_path(&self, result_id: ResultId) -> PathBuf {
        self.root.join(format!(".open-{}", result_hex(result_id)))
    }

    fn final_path(&self, result_id: ResultId) -> PathBuf {
        self.root.join(format!("r-{}", result_hex(result_id)))
    }

    fn result_lock(
        &self,
        result_id: ResultId,
    ) -> Result<Arc<RwLock<()>>, DurableRepositoryErrorV2> {
        let mut locks = self
            .result_locks
            .lock()
            .map_err(|_| DurableRepositoryErrorV2::ResultLocked)?;
        Ok(locks
            .entry(result_id)
            .or_insert_with(|| Arc::new(RwLock::new(())))
            .clone())
    }

    fn lock_repository(&self) -> Result<MutexGuard<'_, ()>, DurableRepositoryErrorV2> {
        self.repository_lock
            .lock()
            .map_err(|_| DurableRepositoryErrorV2::RepositoryLocked)
    }

    fn checkpoint(
        &self,
        point: DurableRepositoryFaultPointV2,
    ) -> Result<(), DurableRepositoryErrorV2> {
        if self.fault_injector.fail_at(point) {
            Err(DurableRepositoryErrorV2::FaultInjected)
        } else {
            Ok(())
        }
    }

    fn ensure_lock_file(&self, path: &Path) -> Result<(), DurableRepositoryErrorV2> {
        if !path.exists() {
            let (parent, name) = parent_directory_and_name(path)?;
            let file = rfs::openat(
                &parent,
                &name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| DurableRepositoryErrorV2::WriteFailed)?;
            sync_file(&File::from(file))?;
        }
        validate_regular_file(path)
    }
}

fn push_frame_with_key(
    dek: &evidentrail_snapshot_format::ResultDekV1,
    segment: SegmentHeaderV2,
    reservation: &NonceReservationV1,
    object_kind: SnapshotObjectKindV2,
    first_global_sequence: u64,
    plaintext: &[u8],
    frames: &mut Vec<SealedFrameV2>,
) -> Result<(), DurableRepositoryErrorV2> {
    let sequence = frames.len() as u32;
    let previous = frames
        .last()
        .map_or(FrameCommitmentV1::ZERO, SealedFrameV2::commitment);
    let header = FrameHeaderV2::new(
        object_kind,
        segment.segment_ordinal(),
        sequence,
        first_global_sequence
            .checked_add(u64::from(sequence))
            .ok_or(DurableRepositoryErrorV2::CapacityExceeded)?,
        u32_len(plaintext.len())?,
        reservation
            .nonce_at(u64::from(sequence))
            .map_err(|_| DurableRepositoryErrorV2::CapacityExceeded)?,
        previous,
    )
    .map_err(|_| DurableRepositoryErrorV2::InvalidOperation)?;
    let frame = seal_frame_v2(dek, segment, header, plaintext)
        .map_err(|_| DurableRepositoryErrorV2::AuthenticationFailed)?;
    frames.push(frame);
    Ok(())
}

impl<A> fmt::Debug for DurableResultRepositoryV2<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurableResultRepositoryV2(<redacted>)")
    }
}

struct FileLockV2 {
    file: File,
}

impl FileLockV2 {
    fn exclusive(path: &Path) -> Result<Self, DurableRepositoryErrorV2> {
        Self::open(path, FlockOperation::LockExclusive)
    }

    fn shared(path: &Path) -> Result<Self, DurableRepositoryErrorV2> {
        Self::open(path, FlockOperation::LockShared)
    }

    fn open(path: &Path, operation: FlockOperation) -> Result<Self, DurableRepositoryErrorV2> {
        validate_regular_file(path)?;
        let file = open_regular_file_nofollow(path, true)
            .map_err(|_| DurableRepositoryErrorV2::ResultLocked)?;
        rfs::flock(&file, operation).map_err(|_| DurableRepositoryErrorV2::ResultLocked)?;
        Ok(Self { file })
    }
}

impl Drop for FileLockV2 {
    fn drop(&mut self) {
        let _ = rfs::flock(&self.file, FlockOperation::Unlock);
    }
}

struct DecodedSegmentV2 {
    header: SegmentHeaderV2,
    frames: Vec<SealedFrameV2>,
}

fn write_segment(
    path: &Path,
    header: SegmentHeaderV2,
    frames: &[SealedFrameV2],
) -> Result<(), DurableRepositoryErrorV2> {
    if frames.is_empty() || frames.len() > MAX_FRAMES_PER_SEGMENT_V1 as usize {
        return Err(DurableRepositoryErrorV2::InvalidOperation);
    }
    let (parent, file_name) = parent_directory_and_name(path)?;
    let file_name = file_name
        .to_str()
        .ok_or(DurableRepositoryErrorV2::WriteFailed)?;
    let temporary = OsString::from(format!(".{file_name}.tmp"));
    if entry_exists_at(&parent, &temporary)? {
        drop(open_regular_file_nofollow(
            &path.with_file_name(&temporary),
            false,
        )?);
        rfs::unlinkat(&parent, &temporary, AtFlags::empty())
            .map_err(|_| DurableRepositoryErrorV2::CleanupFailed)?;
    }
    if entry_exists_at(&parent, std::ffi::OsStr::new(file_name))? {
        return Err(DurableRepositoryErrorV2::OperationConflict);
    }
    let mut file = File::from(
        rfs::openat(
            &parent,
            &temporary,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| DurableRepositoryErrorV2::WriteFailed)?,
    );
    file.write_all(&header.encode())
        .map_err(|_| DurableRepositoryErrorV2::WriteFailed)?;
    for frame in frames {
        file.write_all(&frame.encode())
            .map_err(|_| DurableRepositoryErrorV2::WriteFailed)?;
    }
    sync_file(&file)?;
    drop(file);
    rfs::renameat_with(
        &parent,
        &temporary,
        &parent,
        file_name,
        RenameFlags::NOREPLACE,
    )
    .map_err(|_| DurableRepositoryErrorV2::WriteFailed)
}

fn read_segment(path: &Path) -> Result<DecodedSegmentV2, DurableRepositoryErrorV2> {
    let mut file = open_regular_file_nofollow(path, false)?;
    let length = usize::try_from(
        file.metadata()
            .map_err(|_| DurableRepositoryErrorV2::ReadFailed)?
            .len(),
    )
    .map_err(|_| DurableRepositoryErrorV2::CapacityExceeded)?;
    if length < SEGMENT_HEADER_BYTES_V2 {
        return Err(DurableRepositoryErrorV2::DecodeFailed);
    }
    let mut header_bytes = [0u8; SEGMENT_HEADER_BYTES_V2];
    file.read_exact(&mut header_bytes)
        .map_err(|_| DurableRepositoryErrorV2::ReadFailed)?;
    let header = SegmentHeaderV2::decode(&header_bytes)
        .map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
    let mut frames = Vec::new();
    let mut offset = SEGMENT_HEADER_BYTES_V2;
    while offset < length {
        if frames.len() == MAX_FRAMES_PER_SEGMENT_V1 as usize {
            return Err(DurableRepositoryErrorV2::CapacityExceeded);
        }
        let mut header_bytes = [0u8; evidentrail_snapshot_format::FRAME_HEADER_BYTES_V2];
        file.read_exact(&mut header_bytes)
            .map_err(|_| DurableRepositoryErrorV2::ReadFailed)?;
        let frame_header = FrameHeaderV2::decode(&header_bytes)
            .map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
        let encoded_length = evidentrail_snapshot_format::FRAME_HEADER_BYTES_V2
            .checked_add(frame_header.plaintext_length() as usize)
            .and_then(|value| value.checked_add(evidentrail_snapshot_format::FRAME_TAG_BYTES_V1))
            .and_then(|value| {
                value.checked_add(evidentrail_snapshot_format::FRAME_COMMITMENT_BYTES_V1)
            })
            .ok_or(DurableRepositoryErrorV2::CapacityExceeded)?;
        let mut encoded = vec![0u8; encoded_length];
        encoded[..evidentrail_snapshot_format::FRAME_HEADER_BYTES_V2]
            .copy_from_slice(&header_bytes);
        file.read_exact(&mut encoded[evidentrail_snapshot_format::FRAME_HEADER_BYTES_V2..])
            .map_err(|_| DurableRepositoryErrorV2::ReadFailed)?;
        let frame =
            SealedFrameV2::decode(&encoded).map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
        if frame.header().segment_ordinal() != header.segment_ordinal()
            || frame.header().frame_sequence() != frames.len() as u32
            || frame.header().previous_frame_commitment()
                != frames
                    .last()
                    .map_or(FrameCommitmentV1::ZERO, SealedFrameV2::commitment)
        {
            return Err(DurableRepositoryErrorV2::CommitmentMismatch);
        }
        offset = offset
            .checked_add(encoded_length)
            .ok_or(DurableRepositoryErrorV2::CapacityExceeded)?;
        frames.push(frame);
    }
    if offset != length || frames.is_empty() {
        return Err(DurableRepositoryErrorV2::DecodeFailed);
    }
    Ok(DecodedSegmentV2 { header, frames })
}

fn read_typed_manifest_frame(
    dek: &evidentrail_snapshot_format::ResultDekV1,
    result_id: ResultId,
    path: &Path,
    kind: SnapshotObjectKindV2,
) -> Result<Vec<u8>, DurableRepositoryErrorV2> {
    let (segment, frames) = scan_segment_frames(path)?;
    if segment.result_id() != result_id {
        return Err(DurableRepositoryErrorV2::CommitmentMismatch);
    }
    let mut found = None;
    for frame in frames {
        if frame.header.object_kind() == kind {
            if found.is_some() {
                return Err(DurableRepositoryErrorV2::DecodeFailed);
            }
            found = Some(open_scanned_frame(dek, path, segment, frame)?);
        }
    }
    found.ok_or(DurableRepositoryErrorV2::DecodeFailed)
}

#[derive(Clone, Copy)]
struct ScannedFrameV2 {
    header: FrameHeaderV2,
    byte_offset: u64,
    encoded_length: usize,
}

/// Scans only fixed headers and commitments. Large, unrelated index shards are
/// skipped without allocating or decrypting their ciphertext.
fn scan_segment_frames(
    path: &Path,
) -> Result<(SegmentHeaderV2, Vec<ScannedFrameV2>), DurableRepositoryErrorV2> {
    let mut file = open_regular_file_nofollow(path, false)?;
    let length = file
        .metadata()
        .map_err(|_| DurableRepositoryErrorV2::ReadFailed)?
        .len();
    if length < SEGMENT_HEADER_BYTES_V2 as u64 {
        return Err(DurableRepositoryErrorV2::DecodeFailed);
    }
    let mut segment_bytes = [0u8; SEGMENT_HEADER_BYTES_V2];
    file.read_exact(&mut segment_bytes)
        .map_err(|_| DurableRepositoryErrorV2::ReadFailed)?;
    let segment = SegmentHeaderV2::decode(&segment_bytes)
        .map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
    let mut frames = Vec::new();
    let mut offset = SEGMENT_HEADER_BYTES_V2 as u64;
    let mut previous = FrameCommitmentV1::ZERO;
    while offset < length {
        if frames.len() == MAX_FRAMES_PER_SEGMENT_V1 as usize {
            return Err(DurableRepositoryErrorV2::CapacityExceeded);
        }
        file.seek(SeekFrom::Start(offset))
            .map_err(|_| DurableRepositoryErrorV2::ReadFailed)?;
        let mut header_bytes = [0u8; evidentrail_snapshot_format::FRAME_HEADER_BYTES_V2];
        file.read_exact(&mut header_bytes)
            .map_err(|_| DurableRepositoryErrorV2::ReadFailed)?;
        let header = FrameHeaderV2::decode(&header_bytes)
            .map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
        let encoded_length = evidentrail_snapshot_format::FRAME_HEADER_BYTES_V2
            .checked_add(header.plaintext_length() as usize)
            .and_then(|value| value.checked_add(evidentrail_snapshot_format::FRAME_TAG_BYTES_V1))
            .and_then(|value| {
                value.checked_add(evidentrail_snapshot_format::FRAME_COMMITMENT_BYTES_V1)
            })
            .ok_or(DurableRepositoryErrorV2::CapacityExceeded)?;
        let next = offset
            .checked_add(encoded_length as u64)
            .ok_or(DurableRepositoryErrorV2::CapacityExceeded)?;
        if next > length
            || header.segment_ordinal() != segment.segment_ordinal()
            || header.frame_sequence() != frames.len() as u32
            || header.previous_frame_commitment() != previous
        {
            return Err(DurableRepositoryErrorV2::CommitmentMismatch);
        }
        file.seek(SeekFrom::Start(
            next - evidentrail_snapshot_format::FRAME_COMMITMENT_BYTES_V1 as u64,
        ))
        .map_err(|_| DurableRepositoryErrorV2::ReadFailed)?;
        let mut commitment = [0u8; evidentrail_snapshot_format::FRAME_COMMITMENT_BYTES_V1];
        file.read_exact(&mut commitment)
            .map_err(|_| DurableRepositoryErrorV2::ReadFailed)?;
        previous = FrameCommitmentV1::from_bytes(commitment);
        frames.push(ScannedFrameV2 {
            header,
            byte_offset: offset,
            encoded_length,
        });
        offset = next;
    }
    if offset != length || frames.is_empty() {
        return Err(DurableRepositoryErrorV2::DecodeFailed);
    }
    Ok((segment, frames))
}

fn open_scanned_frame(
    dek: &evidentrail_snapshot_format::ResultDekV1,
    path: &Path,
    segment: SegmentHeaderV2,
    frame: ScannedFrameV2,
) -> Result<Vec<u8>, DurableRepositoryErrorV2> {
    let mut file = open_regular_file_nofollow(path, false)?;
    file.seek(SeekFrom::Start(frame.byte_offset))
        .map_err(|_| DurableRepositoryErrorV2::ReadFailed)?;
    let mut encoded = vec![0u8; frame.encoded_length];
    file.read_exact(&mut encoded)
        .map_err(|_| DurableRepositoryErrorV2::ReadFailed)?;
    let sealed =
        SealedFrameV2::decode(&encoded).map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
    if sealed.header() != frame.header {
        return Err(DurableRepositoryErrorV2::CommitmentMismatch);
    }
    let opened = open_frame_v2(dek, segment, &sealed)
        .map_err(|_| DurableRepositoryErrorV2::AuthenticationFailed)?;
    Ok(opened.as_bytes().to_vec())
}

fn read_typed_frame_sequence(
    dek: &evidentrail_snapshot_format::ResultDekV1,
    result_id: ResultId,
    path: &Path,
    frame_sequence: u32,
    kind: SnapshotObjectKindV2,
) -> Result<Vec<u8>, DurableRepositoryErrorV2> {
    let (segment, frames) = scan_segment_frames(path)?;
    if segment.result_id() != result_id {
        return Err(DurableRepositoryErrorV2::CommitmentMismatch);
    }
    let frame = frames
        .get(frame_sequence as usize)
        .copied()
        .ok_or(DurableRepositoryErrorV2::DecodeFailed)?;
    if frame.header.frame_sequence() != frame_sequence || frame.header.object_kind() != kind {
        return Err(DurableRepositoryErrorV2::CommitmentMismatch);
    }
    open_scanned_frame(dek, path, segment, frame)
}

fn read_indexed_event(
    dek: &evidentrail_snapshot_format::ResultDekV1,
    result_id: ResultId,
    directory: &Path,
    entry: &AuthenticatedEventIndexEntryV2,
) -> Result<OpenedDurableEventV2, DurableRepositoryErrorV2> {
    let locator = entry.locator();
    let path = directory.join(segment_name(locator.segment_ordinal()));
    let mut file = open_regular_file_nofollow(&path, false)?;
    let mut segment_bytes = [0u8; SEGMENT_HEADER_BYTES_V2];
    file.read_exact(&mut segment_bytes)
        .map_err(|_| DurableRepositoryErrorV2::ReadFailed)?;
    let segment = SegmentHeaderV2::decode(&segment_bytes)
        .map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
    if segment.result_id() != result_id || segment.segment_ordinal() != locator.segment_ordinal() {
        return Err(DurableRepositoryErrorV2::CommitmentMismatch);
    }
    file.seek(SeekFrom::Start(locator.byte_offset()))
        .map_err(|_| DurableRepositoryErrorV2::ReadFailed)?;
    let mut encoded = vec![0u8; locator.encoded_length() as usize];
    file.read_exact(&mut encoded)
        .map_err(|_| DurableRepositoryErrorV2::ReadFailed)?;
    let frame =
        SealedFrameV2::decode(&encoded).map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
    if frame.header().object_kind() != SnapshotObjectKindV2::AuthorizedEvent
        || frame.header().frame_sequence() != locator.frame_sequence()
        || frame.header().global_sequence() != locator.global_sequence()
        || frame.commitment() != locator.frame_commitment()
    {
        return Err(DurableRepositoryErrorV2::CommitmentMismatch);
    }
    let opened = open_frame_v2(dek, segment, &frame)
        .map_err(|_| DurableRepositoryErrorV2::AuthenticationFailed)?;
    let (event_id, exactness_basis, authorized) = decode_event_payload(opened.as_bytes())?;
    if event_id != entry.event_id()
        || exactness_basis != entry.exactness_basis()
        || authorized.len() != locator.plaintext_length() as usize
    {
        return Err(DurableRepositoryErrorV2::CommitmentMismatch);
    }
    Ok(OpenedDurableEventV2 {
        event_id,
        exactness_basis,
        authorized_bytes: Zeroizing::new(authorized.to_vec()),
    })
}

fn encode_event_payload(event: &DurableEventInputV2) -> Result<Vec<u8>, DurableRepositoryErrorV2> {
    let mut encoded = vec![0u8; EVENT_PAYLOAD_HEADER_BYTES_V2];
    encoded[0..8].copy_from_slice(&EVENT_PAYLOAD_MAGIC_V2);
    encoded[8..40].copy_from_slice(event.event_id.as_bytes());
    encoded[44..48].copy_from_slice(&u32_len(event.authorized_bytes.len())?.to_be_bytes());
    match event.exactness_basis {
        ExactnessBasis::SourceExact => encoded[40..42].copy_from_slice(&1u16.to_be_bytes()),
        ExactnessBasis::PostPolicy {
            policy_digest,
            transformation_receipt_id,
        } => {
            encoded[40..42].copy_from_slice(&2u16.to_be_bytes());
            encoded[48..80].copy_from_slice(policy_digest.as_bytes());
            encoded[80..112].copy_from_slice(transformation_receipt_id.as_bytes());
        }
    }
    encoded.extend_from_slice(&event.authorized_bytes);
    Ok(encoded)
}

fn decode_event_payload(
    encoded: &[u8],
) -> Result<(EventId, ExactnessBasis, &[u8]), DurableRepositoryErrorV2> {
    if encoded.len() < EVENT_PAYLOAD_HEADER_BYTES_V2
        || encoded[0..8] != EVENT_PAYLOAD_MAGIC_V2
        || encoded[42..44].iter().any(|byte| *byte != 0)
    {
        return Err(DurableRepositoryErrorV2::DecodeFailed);
    }
    let length = read_u32(encoded, 44) as usize;
    if encoded.len() != EVENT_PAYLOAD_HEADER_BYTES_V2 + length {
        return Err(DurableRepositoryErrorV2::DecodeFailed);
    }
    let policy = read_array(encoded, 48);
    let receipt = read_array(encoded, 80);
    let basis = match read_u16(encoded, 40) {
        1 if policy.iter().all(|byte| *byte == 0) && receipt.iter().all(|byte| *byte == 0) => {
            ExactnessBasis::SourceExact
        }
        2 if policy.iter().any(|byte| *byte != 0) && receipt.iter().any(|byte| *byte != 0) => {
            ExactnessBasis::PostPolicy {
                policy_digest: evidentrail_schema::PolicyDigest::from_bytes(policy),
                transformation_receipt_id: evidentrail_schema::TransformationReceiptId::from_bytes(
                    receipt,
                ),
            }
        }
        _ => return Err(DurableRepositoryErrorV2::DecodeFailed),
    };
    Ok((
        EventId::from_bytes(read_array(encoded, 8)),
        basis,
        &encoded[EVENT_PAYLOAD_HEADER_BYTES_V2..],
    ))
}

fn encode_batch_meta(
    ordinal: u64,
    operation: OperationIdV1,
    digest: LifecycleDigestV1,
    event_count: u64,
) -> [u8; BATCH_META_BYTES_V2] {
    let mut encoded = [0u8; BATCH_META_BYTES_V2];
    encoded[0..8].copy_from_slice(&BATCH_META_MAGIC_V2);
    encoded[8..16].copy_from_slice(&ordinal.to_be_bytes());
    encoded[16..32].copy_from_slice(operation.as_bytes());
    encoded[32..64].copy_from_slice(digest.as_bytes());
    encoded[64..72].copy_from_slice(&event_count.to_be_bytes());
    encoded
}

fn decode_batch_meta(
    encoded: &[u8],
) -> Result<(u64, OperationIdV1, LifecycleDigestV1, u64), DurableRepositoryErrorV2> {
    if encoded.len() != BATCH_META_BYTES_V2
        || encoded[0..8] != BATCH_META_MAGIC_V2
        || encoded[72..].iter().any(|byte| *byte != 0)
    {
        return Err(DurableRepositoryErrorV2::DecodeFailed);
    }
    Ok((
        read_u64(encoded, 8),
        OperationIdV1::from_bytes(read_array(encoded, 16)),
        LifecycleDigestV1::from_bytes(read_array(encoded, 32)),
        read_u64(encoded, 64),
    ))
}

fn digest_batch(input: &BatchCommitInputV2) -> LifecycleDigestV1 {
    let mut hasher = Sha256::new();
    hasher.update(BATCH_DIGEST_DOMAIN_V2);
    hasher.update(input.ordinal.to_be_bytes());
    hasher.update(input.operation.as_bytes());
    for event in &input.events {
        hasher.update(event.event_id.as_bytes());
        hasher.update(event.exactness_basis.code().as_bytes());
        hasher.update((event.authorized_bytes.len() as u64).to_be_bytes());
        hasher.update(&event.authorized_bytes);
    }
    for receipt in &input.semantic_receipts {
        hasher.update(b"semantic");
        hasher.update((receipt.len() as u64).to_be_bytes());
        hasher.update(receipt);
    }
    for receipt in &input.operational_receipts {
        hasher.update(b"operational");
        hasher.update((receipt.len() as u64).to_be_bytes());
        hasher.update(receipt);
    }
    LifecycleDigestV1::from_bytes(hasher.finalize().into())
}

fn digest_begin(
    result_id: ResultId,
    created: i64,
    expires: i64,
    request: &[u8],
) -> LifecycleDigestV1 {
    let mut hasher = Sha256::new();
    hasher.update(BEGIN_DIGEST_DOMAIN_V2);
    hasher.update(result_id.as_bytes());
    hasher.update(created.to_be_bytes());
    hasher.update(expires.to_be_bytes());
    hasher.update((request.len() as u64).to_be_bytes());
    hasher.update(request);
    LifecycleDigestV1::from_bytes(hasher.finalize().into())
}

fn digest_with_domain(domain: &[u8], parts: &[&[u8]]) -> LifecycleDigestV1 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    LifecycleDigestV1::from_bytes(hasher.finalize().into())
}

fn derive_repository_commitment(commitments: SealCommitmentsV1) -> LifecycleDigestV1 {
    digest_with_domain(
        REPOSITORY_COMMITMENT_DOMAIN_V2,
        &[
            commitments.final_manifest().as_bytes(),
            commitments.data_manifest().as_bytes(),
            commitments.event_index().as_bytes(),
            commitments.frame_chain().as_bytes(),
            commitments.products().as_bytes(),
        ],
    )
}

fn ensure_commitment(
    path: &Path,
    commitment: LifecycleDigestV1,
) -> Result<(), DurableRepositoryErrorV2> {
    if path.exists() {
        return if read_commitment(path)? == commitment {
            Ok(())
        } else {
            Err(DurableRepositoryErrorV2::OperationConflict)
        };
    }
    let (parent, name) = parent_directory_and_name(path)?;
    let mut file = File::from(
        rfs::openat(
            &parent,
            &name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| DurableRepositoryErrorV2::WriteFailed)?,
    );
    file.write_all(commitment.as_bytes())
        .map_err(|_| DurableRepositoryErrorV2::WriteFailed)?;
    sync_file(&file)
}

fn read_commitment(path: &Path) -> Result<LifecycleDigestV1, DurableRepositoryErrorV2> {
    let mut file = open_regular_file_nofollow(path, false)?;
    let mut bytes = [0u8; REPOSITORY_COMMITMENT_BYTES_V2];
    file.read_exact(&mut bytes)
        .map_err(|_| DurableRepositoryErrorV2::ReadFailed)?;
    let mut trailing = [0u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| DurableRepositoryErrorV2::ReadFailed)?
        != 0
    {
        return Err(DurableRepositoryErrorV2::DecodeFailed);
    }
    Ok(LifecycleDigestV1::from_bytes(bytes))
}

fn contiguous_batch_count(directory: &Path) -> Result<u64, DurableRepositoryErrorV2> {
    let files = segment_files(directory)?;
    let ordinals: BTreeSet<u64> = files
        .iter()
        .filter_map(|(ordinal, _)| {
            if *ordinal > 0 {
                Some(*ordinal - 1)
            } else {
                None
            }
        })
        .collect();
    let mut expected = 0u64;
    for ordinal in ordinals {
        if ordinal != expected {
            return Err(DurableRepositoryErrorV2::BatchOrdinalMismatch);
        }
        expected += 1;
    }
    Ok(expected)
}

fn next_segment_ordinal(directory: &Path) -> Result<u64, DurableRepositoryErrorV2> {
    all_segment_files(directory)?
        .into_iter()
        .map(|(ordinal, _)| ordinal)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(DurableRepositoryErrorV2::CapacityExceeded)
}

fn all_segment_files(directory: &Path) -> Result<Vec<(u64, PathBuf)>, DurableRepositoryErrorV2> {
    let mut files = segment_files(directory)?;
    for name in ["data-commit.seg", "sealed-products.seg"] {
        let path = directory.join(name);
        if path.exists() {
            let decoded = read_segment(&path)?;
            files.push((decoded.header.segment_ordinal(), path));
        }
    }
    let mut ordinals = BTreeSet::new();
    if files.iter().any(|(ordinal, _)| !ordinals.insert(*ordinal)) {
        return Err(DurableRepositoryErrorV2::CommitmentMismatch);
    }
    Ok(files)
}

fn segment_files(directory: &Path) -> Result<Vec<(u64, PathBuf)>, DurableRepositoryErrorV2> {
    validate_owned_directory(directory)?;
    let mut files = Vec::new();
    for entry in fs::read_dir(directory).map_err(|_| DurableRepositoryErrorV2::ReadFailed)? {
        let entry = entry.map_err(|_| DurableRepositoryErrorV2::ReadFailed)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(number) = name
            .strip_prefix("segment-")
            .and_then(|value| value.strip_suffix(".seg"))
        else {
            continue;
        };
        if number.len() != 20 || !number.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(DurableRepositoryErrorV2::UnsafeFilesystemObject);
        }
        let ordinal = number
            .parse::<u64>()
            .map_err(|_| DurableRepositoryErrorV2::DecodeFailed)?;
        files.push((ordinal, entry.path()));
    }
    Ok(files)
}

fn segment_name(ordinal: u64) -> String {
    format!("segment-{ordinal:020}.seg")
}

fn derived_operation(operation: OperationIdV1, discriminator: u8) -> OperationIdV1 {
    let mut hasher = Sha256::new();
    hasher.update(b"evidentrail.repository.derived-operation.v2");
    hasher.update(operation.as_bytes());
    hasher.update([discriminator]);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    OperationIdV1::from_bytes(bytes)
}

fn recovery_operation(digest: LifecycleDigestV1) -> OperationIdV1 {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[15] = 1;
    }
    OperationIdV1::from_bytes(bytes)
}

fn result_hex(result_id: ResultId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(64);
    for byte in result_id.as_bytes() {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}

fn parse_active_result_name(name: &str) -> Option<ResultId> {
    let encoded = name
        .strip_prefix(".open-")
        .or_else(|| name.strip_prefix("r-"))?;
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (decode_hex_nibble(pair[0])? << 4) | decode_hex_nibble(pair[1])?;
    }
    Some(ResultId::from_bytes(bytes))
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn validate_owned_directory(path: &Path) -> Result<(), DurableRepositoryErrorV2> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| DurableRepositoryErrorV2::ResultUnavailable)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != ROOT_MODE_V2
    {
        return Err(DurableRepositoryErrorV2::UnsafeFilesystemObject);
    }
    Ok(())
}

fn validate_regular_file(path: &Path) -> Result<(), DurableRepositoryErrorV2> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| DurableRepositoryErrorV2::ResultUnavailable)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != FILE_MODE_V2
        || metadata.nlink() != 1
    {
        return Err(DurableRepositoryErrorV2::UnsafeFilesystemObject);
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), DurableRepositoryErrorV2> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|_| DurableRepositoryErrorV2::WriteFailed)
}

fn sync_directory(path: &Path) -> Result<(), DurableRepositoryErrorV2> {
    let file =
        open_directory_nofollow(path).map_err(|_| DurableRepositoryErrorV2::DirectorySyncFailed)?;
    rfs::fsync(&file).map_err(|_| DurableRepositoryErrorV2::DirectorySyncFailed)
}

fn open_directory_nofollow(path: &Path) -> Result<File, DurableRepositoryErrorV2> {
    if !path.is_absolute() {
        return Err(DurableRepositoryErrorV2::UnsafeFilesystemObject);
    }
    let current = rfs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| DurableRepositoryErrorV2::UnsafeFilesystemObject)?;
    let file = File::from(current);
    let metadata = file
        .metadata()
        .map_err(|_| DurableRepositoryErrorV2::UnsafeFilesystemObject)?;
    if !metadata.is_dir() {
        return Err(DurableRepositoryErrorV2::UnsafeFilesystemObject);
    }
    Ok(file)
}

fn open_regular_file_nofollow(
    path: &Path,
    writable: bool,
) -> Result<File, DurableRepositoryErrorV2> {
    let (parent, name) = parent_directory_and_name(path)?;
    let access = if writable {
        OFlags::RDWR
    } else {
        OFlags::RDONLY
    };
    let file = File::from(
        rfs::openat(
            &parent,
            &name,
            access | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| DurableRepositoryErrorV2::ReadFailed)?,
    );
    let metadata = file
        .metadata()
        .map_err(|_| DurableRepositoryErrorV2::ReadFailed)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != FILE_MODE_V2
        || metadata.nlink() != 1
    {
        return Err(DurableRepositoryErrorV2::UnsafeFilesystemObject);
    }
    Ok(file)
}

fn parent_directory_and_name(path: &Path) -> Result<(File, OsString), DurableRepositoryErrorV2> {
    let parent = path
        .parent()
        .ok_or(DurableRepositoryErrorV2::UnsafeFilesystemObject)?;
    let name = path
        .file_name()
        .ok_or(DurableRepositoryErrorV2::UnsafeFilesystemObject)?
        .to_os_string();
    Ok((open_directory_nofollow(parent)?, name))
}

fn entry_exists_at(
    directory: &File,
    name: &std::ffi::OsStr,
) -> Result<bool, DurableRepositoryErrorV2> {
    match rfs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(_) => Err(DurableRepositoryErrorV2::ReadFailed),
    }
}

fn sync_file(file: &File) -> Result<(), DurableRepositoryErrorV2> {
    file.sync_all()
        .map_err(|_| DurableRepositoryErrorV2::FileSyncFailed)?;
    #[cfg(target_os = "macos")]
    rfs::fcntl_fullfsync(file).map_err(|_| DurableRepositoryErrorV2::FileSyncFailed)?;
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), DurableRepositoryErrorV2> {
    let parent = path.parent().ok_or(DurableRepositoryErrorV2::InvalidRoot)?;
    sync_directory(parent)
}

fn u32_len(value: usize) -> Result<u32, DurableRepositoryErrorV2> {
    u32::try_from(value).map_err(|_| DurableRepositoryErrorV2::CapacityExceeded)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(read_array(bytes, offset))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(read_array(bytes, offset))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(read_array(bytes, offset))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut result = [0u8; N];
    result.copy_from_slice(&bytes[offset..offset + N]);
    result
}
