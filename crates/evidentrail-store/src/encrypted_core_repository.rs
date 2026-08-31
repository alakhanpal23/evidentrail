use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;
use std::sync::{Mutex, MutexGuard};

use evidentrail_schema::{
    AcquisitionOutcome, AcquisitionReceiptId, EventId, ExactnessBasis, ResultId,
    SourceIdentityDigest,
};
use evidentrail_snapshot_format::{
    AuthorizedByteRangeV1, CORE_RESULT_FRAME_PAYLOAD_SCHEMA_V1, CoreResultFrameAuthorityV1,
    CoreResultManifestSealContextV1, CoreResultManifestV1, EventExpansionIndexEntryV1,
    EventExpansionIndexV1, EventFrameLocatorV1, ExpectedCoreResultManifestContextV1,
    FRAME_HEADER_BYTES_V1, FRAME_TAG_BYTES_V1, FrameCommitmentV1, FrameHeaderV1, FrameObjectKindV1,
    MAX_FRAME_PLAINTEXT_BYTES_V1, MAX_FRAMES_PER_SEGMENT_V1, ManifestCommitmentV1,
    OpenedCoreResultManifestV1, OpenedFrameV1, ResultKeyRecordStateV1, ResultKeySealTransitionV1,
    SEGMENT_HEADER_BYTES_V1, SealBindingV1, SealedCoreResultManifestV1, SealedFrameV1,
    SegmentCatalogEntryV1, SegmentCatalogV1, SegmentHeaderV1, derive_segment_digest_v1,
    open_core_result_frame_v1, open_core_result_manifest_v1, seal_core_result_frame_v1,
    seal_core_result_manifest_v1, segment_start_commitment_v1,
};

use crate::sealed_bundle::{SealedBundleSegmentV1, SealedEncryptedCoreResultBundleV1};
use crate::{
    CreatingKeyContextV1, DisplayedAliasManifestV1, ExpectedKeyContextV1, KeyDestroyOutcomeV1,
    KeyProviderErrorV1, KeyProviderV1, OpenedResultKeyV1,
};

/// Hard in-memory publication bound for the provisional encrypted repository.
pub const MAX_MEMORY_ENCRYPTED_CORE_RESULTS_V1: usize = 4_096;
/// Hard process-local count bound across staged and published encrypted frames.
pub const MAX_MEMORY_ENCRYPTED_CORE_FRAMES_V1: usize = 4_096;
/// Hard process-local segment bound across staged and published snapshots.
pub const MAX_MEMORY_ENCRYPTED_CORE_SEGMENTS_V1: usize = 64;
/// Hard process-local encoded segment/frame byte bound.
pub const MAX_MEMORY_ENCRYPTED_CORE_FRAME_BYTES_V1: usize = 64 * 1024 * 1024;

/// Stable, contentless repository failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EncryptedCoreResultRepositoryErrorV1 {
    InvalidCapacity,
    CapacityExceeded,
    DuplicateResult,
    AuthorityMismatch,
    KeyProviderFailed,
    NonceIssuanceFailed,
    ManifestSealFailed,
    SealBindingFailed,
    KeySealFailed,
    PublicationFailed,
    ResultNotFound,
    KeyNotCreating,
    KeyNotSealed,
    CiphertextDecodeFailed,
    SealBindingMismatch,
    ManifestOpenFailed,
    NoStagedResult,
    EmptySegment,
    FrameCountCap,
    SegmentCountCap,
    FrameByteCap,
    FrameNonceIssuanceFailed,
    FrameSealFailed,
    FrameVerificationFailed,
    FramePublicationFailed,
    AuthorizedOutcomeRequiresEvent,
    DuplicateEventId,
    EventIndexBuildFailed,
    EventIndexMismatch,
    CatalogBuildFailed,
    CatalogMismatch,
    FrameNotFound,
    EventNotFound,
    EventBindingMismatch,
    AliasManifestRequiresTypedStaging,
    AliasManifestAlreadyStaged,
    AliasManifestResultMismatch,
    AliasManifestMissing,
    AliasManifestDuplicate,
    AliasManifestDecodeFailed,
    AliasManifestEventMismatch,
    BundleEncodeFailed,
    BundleDecodeFailed,
    BundleMismatch,
    FrameIdentityMismatch,
    FrameDecodeFailed,
    FrameOpenFailed,
    CiphertextCleanupFailed,
    RepositoryUnavailable,
}

impl EncryptedCoreResultRepositoryErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidCapacity => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_INVALID_CAPACITY",
            Self::CapacityExceeded => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_CAPACITY_EXCEEDED",
            Self::DuplicateResult => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_DUPLICATE_RESULT",
            Self::AuthorityMismatch => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_AUTHORITY_MISMATCH",
            Self::KeyProviderFailed => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_KEY_PROVIDER_FAILED",
            Self::NonceIssuanceFailed => {
                "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_NONCE_ISSUANCE_FAILED"
            }
            Self::ManifestSealFailed => {
                "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_MANIFEST_SEAL_FAILED"
            }
            Self::SealBindingFailed => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_SEAL_BINDING_FAILED",
            Self::KeySealFailed => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_KEY_SEAL_FAILED",
            Self::PublicationFailed => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_PUBLICATION_FAILED",
            Self::ResultNotFound => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_RESULT_NOT_FOUND",
            Self::KeyNotCreating => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_KEY_NOT_CREATING",
            Self::KeyNotSealed => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_KEY_NOT_SEALED",
            Self::CiphertextDecodeFailed => {
                "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_CIPHERTEXT_DECODE_FAILED"
            }
            Self::SealBindingMismatch => {
                "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_SEAL_BINDING_MISMATCH"
            }
            Self::ManifestOpenFailed => {
                "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_MANIFEST_OPEN_FAILED"
            }
            Self::NoStagedResult => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_NO_STAGED_RESULT",
            Self::EmptySegment => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_EMPTY_SEGMENT",
            Self::FrameCountCap => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_FRAME_COUNT_CAP",
            Self::SegmentCountCap => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_SEGMENT_COUNT_CAP",
            Self::FrameByteCap => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_FRAME_BYTE_CAP",
            Self::FrameNonceIssuanceFailed => {
                "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_FRAME_NONCE_ISSUANCE_FAILED"
            }
            Self::FrameSealFailed => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_FRAME_SEAL_FAILED",
            Self::FrameVerificationFailed => {
                "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_FRAME_VERIFICATION_FAILED"
            }
            Self::FramePublicationFailed => {
                "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_FRAME_PUBLICATION_FAILED"
            }
            Self::AuthorizedOutcomeRequiresEvent => {
                "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_AUTHORIZED_OUTCOME_REQUIRES_EVENT"
            }
            Self::DuplicateEventId => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_DUPLICATE_EVENT_ID",
            Self::EventIndexBuildFailed => {
                "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_EVENT_INDEX_BUILD_FAILED"
            }
            Self::EventIndexMismatch => {
                "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_EVENT_INDEX_MISMATCH"
            }
            Self::CatalogBuildFailed => {
                "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_CATALOG_BUILD_FAILED"
            }
            Self::CatalogMismatch => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_CATALOG_MISMATCH",
            Self::FrameNotFound => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_FRAME_NOT_FOUND",
            Self::EventNotFound => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_EVENT_NOT_FOUND",
            Self::EventBindingMismatch => {
                "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_EVENT_BINDING_MISMATCH"
            }
            Self::AliasManifestRequiresTypedStaging => {
                "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_ALIAS_MANIFEST_REQUIRES_TYPED_STAGING"
            }
            Self::AliasManifestAlreadyStaged => {
                "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_ALIAS_MANIFEST_ALREADY_STAGED"
            }
            Self::AliasManifestResultMismatch => {
                "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_ALIAS_MANIFEST_RESULT_MISMATCH"
            }
            Self::AliasManifestMissing => {
                "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_ALIAS_MANIFEST_MISSING"
            }
            Self::AliasManifestDuplicate => {
                "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_ALIAS_MANIFEST_DUPLICATE"
            }
            Self::AliasManifestDecodeFailed => {
                "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_ALIAS_MANIFEST_DECODE_FAILED"
            }
            Self::AliasManifestEventMismatch => {
                "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_ALIAS_MANIFEST_EVENT_MISMATCH"
            }
            Self::BundleEncodeFailed => {
                "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_BUNDLE_ENCODE_FAILED"
            }
            Self::BundleDecodeFailed => {
                "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_BUNDLE_DECODE_FAILED"
            }
            Self::BundleMismatch => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_BUNDLE_MISMATCH",
            Self::FrameIdentityMismatch => {
                "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_FRAME_IDENTITY_MISMATCH"
            }
            Self::FrameDecodeFailed => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_FRAME_DECODE_FAILED",
            Self::FrameOpenFailed => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_FRAME_OPEN_FAILED",
            Self::CiphertextCleanupFailed => {
                "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_CIPHERTEXT_CLEANUP_FAILED"
            }
            Self::RepositoryUnavailable => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_UNAVAILABLE",
        }
    }
}

impl fmt::Debug for EncryptedCoreResultRepositoryErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedCoreResultRepositoryErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for EncryptedCoreResultRepositoryErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for EncryptedCoreResultRepositoryErrorV1 {}

/// Exact immutable location of one encrypted frame in a result snapshot.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EncryptedCoreResultFrameLocatorV1 {
    segment_sequence: u64,
    global_frame_sequence: u64,
    segment_frame_sequence: u32,
}

impl EncryptedCoreResultFrameLocatorV1 {
    #[must_use]
    pub const fn new(
        segment_sequence: u64,
        global_frame_sequence: u64,
        segment_frame_sequence: u32,
    ) -> Self {
        Self {
            segment_sequence,
            global_frame_sequence,
            segment_frame_sequence,
        }
    }

    #[must_use]
    pub const fn segment_sequence(self) -> u64 {
        self.segment_sequence
    }

    #[must_use]
    pub const fn global_frame_sequence(self) -> u64 {
        self.global_frame_sequence
    }

    #[must_use]
    pub const fn segment_frame_sequence(self) -> u32 {
        self.segment_frame_sequence
    }
}

impl fmt::Debug for EncryptedCoreResultFrameLocatorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncryptedCoreResultFrameLocatorV1(<redacted>)")
    }
}

/// Contentless metadata returned only after one ciphertext frame has been
/// encrypted, decoded, commitment-checked, and authenticated in memory.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EncryptedCoreResultFramePublicationV1 {
    locator: EncryptedCoreResultFrameLocatorV1,
    object_kind: FrameObjectKindV1,
    commitment: FrameCommitmentV1,
    encoded_byte_count: u32,
}

impl EncryptedCoreResultFramePublicationV1 {
    #[must_use]
    pub const fn locator(self) -> EncryptedCoreResultFrameLocatorV1 {
        self.locator
    }

    #[must_use]
    pub const fn object_kind(self) -> FrameObjectKindV1 {
        self.object_kind
    }

    #[must_use]
    pub const fn commitment(self) -> FrameCommitmentV1 {
        self.commitment
    }

    #[must_use]
    pub const fn encoded_byte_count(self) -> u32 {
        self.encoded_byte_count
    }
}

impl fmt::Debug for EncryptedCoreResultFramePublicationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncryptedCoreResultFramePublicationV1(<redacted>)")
    }
}

/// Authenticated exact frame plaintext. The owned plaintext allocation is
/// zeroized by the snapshot-format owner when this value is dropped.
pub struct OpenedEncryptedCoreResultFrameV1 {
    locator: EncryptedCoreResultFrameLocatorV1,
    object_kind: FrameObjectKindV1,
    commitment: FrameCommitmentV1,
    plaintext: OpenedFrameV1,
}

impl OpenedEncryptedCoreResultFrameV1 {
    #[must_use]
    pub const fn locator(&self) -> EncryptedCoreResultFrameLocatorV1 {
        self.locator
    }

    #[must_use]
    pub const fn object_kind(&self) -> FrameObjectKindV1 {
        self.object_kind
    }

    #[must_use]
    pub const fn commitment(&self) -> FrameCommitmentV1 {
        self.commitment
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.plaintext.as_bytes()
    }
}

impl fmt::Debug for OpenedEncryptedCoreResultFrameV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenedEncryptedCoreResultFrameV1(<redacted>)")
    }
}

/// Contentless metadata for a typed persisted event whose exact authorized
/// bytes occupy one complete `AuthorizedOutcome` frame.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EncryptedCoreResultEventPublicationV1 {
    event_id: EventId,
    exactness_basis: ExactnessBasis,
    frame: EncryptedCoreResultFramePublicationV1,
}

impl EncryptedCoreResultEventPublicationV1 {
    #[must_use]
    pub const fn event_id(self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn exactness_basis(self) -> ExactnessBasis {
        self.exactness_basis
    }

    #[must_use]
    pub const fn frame(self) -> EncryptedCoreResultFramePublicationV1 {
        self.frame
    }
}

impl fmt::Debug for EncryptedCoreResultEventPublicationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncryptedCoreResultEventPublicationV1(<redacted>)")
    }
}

/// Authenticated exact authorized bytes for one manifest-indexed event.
///
/// The owned allocation is zeroized by `OpenedFrameV1` on drop. V1 admits no
/// framing prefix or suffix in an event frame, so this owner exposes only the
/// complete authorized byte range and never a larger decrypted payload.
pub struct OpenedEncryptedCoreResultEventV1 {
    event_id: EventId,
    exactness_basis: ExactnessBasis,
    authorized_bytes: OpenedFrameV1,
}

impl OpenedEncryptedCoreResultEventV1 {
    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn exactness_basis(&self) -> ExactnessBasis {
        self.exactness_basis
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.authorized_bytes.as_bytes()
    }
}

impl fmt::Debug for OpenedEncryptedCoreResultEventV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenedEncryptedCoreResultEventV1(<redacted>)")
    }
}

/// Contentless publication metadata returned only after the key record is
/// authenticated in its Sealed state and ciphertext is installed in memory.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EncryptedCoreResultPublicationV1 {
    result_id: ResultId,
    manifest_commitment: ManifestCommitmentV1,
}

impl EncryptedCoreResultPublicationV1 {
    #[must_use]
    pub const fn result_id(self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn manifest_commitment(self) -> ManifestCommitmentV1 {
        self.manifest_commitment
    }
}

impl fmt::Debug for EncryptedCoreResultPublicationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncryptedCoreResultPublicationV1(<redacted>)")
    }
}

/// Idempotent memory-repository destruction outcome.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EncryptedCoreResultDestroyOutcomeV1 {
    Destroyed,
    AlreadyAbsent,
}

impl EncryptedCoreResultDestroyOutcomeV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Destroyed => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_DESTROYED",
            Self::AlreadyAbsent => "EVIDENTRAIL_ENCRYPTED_CORE_REPOSITORY_ALREADY_ABSENT",
        }
    }
}

impl fmt::Debug for EncryptedCoreResultDestroyOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedCoreResultDestroyOutcomeV1")
            .field("code", &self.code())
            .finish()
    }
}

struct StoredEncryptedCoreResultV1 {
    encoded_manifest: Vec<u8>,
    segments: Vec<StoredEncryptedSegmentV1>,
    frame_count: usize,
    encoded_frame_bytes: usize,
}

struct StoredEncryptedSegmentV1 {
    encoded_header: [u8; SEGMENT_HEADER_BYTES_V1],
    encoded_frames: Vec<Vec<u8>>,
}

struct StagedEncryptedCoreResultV1 {
    authority: CoreResultFrameAuthorityV1,
    key_context: CreatingKeyContextV1,
    segments: Vec<StoredEncryptedSegmentV1>,
    next_global_frame_sequence: u64,
    frame_count: usize,
    encoded_frame_bytes: usize,
    events: Vec<StagedEventIndexMaterialV1>,
    displayed_alias_manifest_staged: bool,
}

#[derive(Clone, Copy)]
struct StagedEventIndexMaterialV1 {
    event_id: EventId,
    exactness_basis: ExactnessBasis,
    frame_locator: EventFrameLocatorV1,
    authorized_bytes: AuthorizedByteRangeV1,
}

struct RepositoryStateV1 {
    entries: BTreeMap<ResultId, StoredEncryptedCoreResultV1>,
    staged: BTreeMap<ResultId, StagedEncryptedCoreResultV1>,
    total_frame_count: usize,
    total_segment_count: usize,
    total_encoded_frame_bytes: usize,
    capacity: usize,
    fail_next_publication: bool,
    fail_next_frame_publication: bool,
    fail_next_ciphertext_cleanup: bool,
}

/// Transactional, memory-only encrypted core-result repository.
///
/// This provisional repository serializes create/seal/publish, open, and
/// destroy in one process. Its staged lifecycle stores authority-bound frame
/// ciphertext plus the exact outer manifest ciphertext and relies on
/// `KeyProviderV1` for key authority. It makes no filesystem, durability,
/// recovery, rollback-prevention, cross-process locking, or external
/// publication claim.
pub struct MemoryEncryptedCoreResultRepositoryV1<P> {
    provider: P,
    state: Mutex<RepositoryStateV1>,
}

impl<P: KeyProviderV1> MemoryEncryptedCoreResultRepositoryV1<P> {
    pub fn new(provider: P, capacity: usize) -> Result<Self, EncryptedCoreResultRepositoryErrorV1> {
        if capacity == 0 || capacity > MAX_MEMORY_ENCRYPTED_CORE_RESULTS_V1 {
            return Err(EncryptedCoreResultRepositoryErrorV1::InvalidCapacity);
        }
        Ok(Self {
            provider,
            state: Mutex::new(RepositoryStateV1 {
                entries: BTreeMap::new(),
                staged: BTreeMap::new(),
                total_frame_count: 0,
                total_segment_count: 0,
                total_encoded_frame_bytes: 0,
                capacity,
                fail_next_publication: false,
                fail_next_frame_publication: false,
                fail_next_ciphertext_cleanup: false,
            }),
        })
    }

    /// Create key authority, seal the exact typed manifest, publish the exact
    /// seal binding, and only then install ciphertext as an openable result.
    ///
    /// One byte-identical provider seal retry is attempted only for the
    /// provider's explicit `UpdateFailed` state. Any other pre-publication
    /// failure destroys repository-owned key authority best-effort and leaves
    /// no ciphertext entry. Because provider identities are tombstoned, such a
    /// failed ResultId is not reused; callers must issue a fresh ResultId.
    ///
    /// This manifest-only entry point deliberately stores no frame ciphertext.
    /// It therefore cannot make frames referenced by the supplied catalog
    /// available through [`Self::open_stored_frame`]. Frame-backed snapshots
    /// must use the begin/stage/seal lifecycle below.
    pub fn create_sealed_result(
        &self,
        key_context: &CreatingKeyContextV1,
        manifest: &CoreResultManifestV1,
    ) -> Result<EncryptedCoreResultPublicationV1, EncryptedCoreResultRepositoryErrorV1> {
        if key_context.result_id() != manifest.result_id() {
            return Err(EncryptedCoreResultRepositoryErrorV1::AuthorityMismatch);
        }
        let mut state = self.lock_state()?;
        if state.entries.contains_key(&key_context.result_id())
            || state.staged.contains_key(&key_context.result_id())
        {
            return Err(EncryptedCoreResultRepositoryErrorV1::DuplicateResult);
        }
        if state.entries.len() + state.staged.len() >= state.capacity {
            return Err(EncryptedCoreResultRepositoryErrorV1::CapacityExceeded);
        }

        self.provider
            .ensure_root_key()
            .map_err(|_| EncryptedCoreResultRepositoryErrorV1::KeyProviderFailed)?;
        let opened_key = self
            .provider
            .create_result_key(key_context)
            .map_err(|_| EncryptedCoreResultRepositoryErrorV1::KeyProviderFailed)?;
        if opened_key.result_id() != key_context.result_id()
            || opened_key.state() != ResultKeyRecordStateV1::Creating
        {
            drop(opened_key);
            self.rollback_key(key_context.result_id());
            return Err(EncryptedCoreResultRepositoryErrorV1::KeyProviderFailed);
        }

        let nonce = match self
            .provider
            .issue_snapshot_manifest_nonce(&key_context.result_id())
        {
            Ok(nonce) => nonce,
            Err(_) => {
                drop(opened_key);
                self.rollback_key(key_context.result_id());
                return Err(EncryptedCoreResultRepositoryErrorV1::NonceIssuanceFailed);
            }
        };
        let seal_context = match CoreResultManifestSealContextV1::new(
            key_context.created_unix_nanos(),
            key_context.expires_unix_nanos(),
            nonce,
        ) {
            Ok(context) => context,
            Err(_) => {
                drop(opened_key);
                self.rollback_key(key_context.result_id());
                return Err(EncryptedCoreResultRepositoryErrorV1::ManifestSealFailed);
            }
        };
        let sealed = match seal_core_result_manifest_v1(
            &opened_key.result_dek().manifest_key(),
            seal_context,
            manifest,
        ) {
            Ok(sealed) => sealed,
            Err(_) => {
                drop(opened_key);
                self.rollback_key(key_context.result_id());
                return Err(EncryptedCoreResultRepositoryErrorV1::ManifestSealFailed);
            }
        };
        drop(opened_key);

        let catalog = manifest.components().catalog();
        let binding = match SealBindingV1::new(
            sealed.commitment(),
            catalog.final_chain_root(),
            catalog.total_frame_count(),
            catalog.segment_count(),
        ) {
            Ok(binding) => binding,
            Err(_) => {
                self.rollback_key(key_context.result_id());
                return Err(EncryptedCoreResultRepositoryErrorV1::SealBindingFailed);
            }
        };
        if self
            .publish_key_seal_with_one_exact_retry(key_context.result_id(), &binding)
            .is_err()
        {
            self.rollback_key(key_context.result_id());
            return Err(EncryptedCoreResultRepositoryErrorV1::KeySealFailed);
        }

        if state.fail_next_publication {
            state.fail_next_publication = false;
            self.rollback_key(key_context.result_id());
            return Err(EncryptedCoreResultRepositoryErrorV1::PublicationFailed);
        }
        let prior = state.entries.insert(
            key_context.result_id(),
            StoredEncryptedCoreResultV1 {
                encoded_manifest: sealed.encode(),
                segments: Vec::new(),
                frame_count: 0,
                encoded_frame_bytes: 0,
            },
        );
        debug_assert!(prior.is_none());
        Ok(EncryptedCoreResultPublicationV1 {
            result_id: key_context.result_id(),
            manifest_commitment: sealed.commitment(),
        })
    }

    /// Begin a private in-memory frame staging transaction.
    ///
    /// Staged results consume capacity and key authority but are deliberately
    /// absent from every open surface until [`Self::seal_staged_result`]
    /// authenticates an exact manifest/catalog and seals the provider record.
    pub fn begin_staged_result(
        &self,
        key_context: &CreatingKeyContextV1,
        source_identity_digest: SourceIdentityDigest,
        acquisition_receipt_id: AcquisitionReceiptId,
    ) -> Result<(), EncryptedCoreResultRepositoryErrorV1> {
        let authority = CoreResultFrameAuthorityV1::new(
            key_context.result_id(),
            source_identity_digest,
            acquisition_receipt_id,
        )
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::AuthorityMismatch)?;
        let first_header = SegmentHeaderV1::new(
            CORE_RESULT_FRAME_PAYLOAD_SCHEMA_V1,
            key_context.result_id(),
            0,
            key_context.created_unix_nanos(),
            key_context.expires_unix_nanos(),
            FrameCommitmentV1::ZERO,
        )
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::CatalogBuildFailed)?;

        let mut state = self.lock_state()?;
        if state.entries.contains_key(&key_context.result_id())
            || state.staged.contains_key(&key_context.result_id())
        {
            return Err(EncryptedCoreResultRepositoryErrorV1::DuplicateResult);
        }
        if state.entries.len() + state.staged.len() >= state.capacity {
            return Err(EncryptedCoreResultRepositoryErrorV1::CapacityExceeded);
        }
        if state.total_segment_count >= MAX_MEMORY_ENCRYPTED_CORE_SEGMENTS_V1 {
            return Err(EncryptedCoreResultRepositoryErrorV1::SegmentCountCap);
        }
        let next_total_bytes = state
            .total_encoded_frame_bytes
            .checked_add(SEGMENT_HEADER_BYTES_V1)
            .ok_or(EncryptedCoreResultRepositoryErrorV1::FrameByteCap)?;
        if next_total_bytes > MAX_MEMORY_ENCRYPTED_CORE_FRAME_BYTES_V1 {
            return Err(EncryptedCoreResultRepositoryErrorV1::FrameByteCap);
        }

        self.provider
            .ensure_root_key()
            .map_err(|_| EncryptedCoreResultRepositoryErrorV1::KeyProviderFailed)?;
        let opened_key = self
            .provider
            .create_result_key(key_context)
            .map_err(|_| EncryptedCoreResultRepositoryErrorV1::KeyProviderFailed)?;
        if opened_key.result_id() != key_context.result_id()
            || opened_key.state() != ResultKeyRecordStateV1::Creating
            || opened_key.created_unix_nanos() != key_context.created_unix_nanos()
            || opened_key.expires_unix_nanos() != key_context.expires_unix_nanos()
        {
            drop(opened_key);
            self.rollback_key(key_context.result_id());
            return Err(EncryptedCoreResultRepositoryErrorV1::KeyProviderFailed);
        }
        drop(opened_key);

        state.staged.insert(
            key_context.result_id(),
            StagedEncryptedCoreResultV1 {
                authority,
                key_context: *key_context,
                segments: vec![StoredEncryptedSegmentV1 {
                    encoded_header: first_header.encode(),
                    encoded_frames: Vec::new(),
                }],
                next_global_frame_sequence: 0,
                frame_count: 0,
                encoded_frame_bytes: SEGMENT_HEADER_BYTES_V1,
                events: Vec::new(),
                displayed_alias_manifest_staged: false,
            },
        );
        state.total_segment_count += 1;
        state.total_encoded_frame_bytes = next_total_bytes;
        Ok(())
    }

    /// Stage one non-event frame while preserving the generic whole-frame API.
    ///
    /// `AuthorizedOutcome` is deliberately rejected here: persisted events
    /// must use [`Self::stage_authorized_event`] so no event frame can escape
    /// the derived expansion index. No nonce parameter is accepted.
    pub fn stage_frame(
        &self,
        result_id: &ResultId,
        object_kind: FrameObjectKindV1,
        plaintext: &[u8],
    ) -> Result<EncryptedCoreResultFramePublicationV1, EncryptedCoreResultRepositoryErrorV1> {
        if object_kind == FrameObjectKindV1::AuthorizedOutcome {
            return Err(EncryptedCoreResultRepositoryErrorV1::AuthorizedOutcomeRequiresEvent);
        }
        if DisplayedAliasManifestV1::has_magic(plaintext) {
            return Err(EncryptedCoreResultRepositoryErrorV1::AliasManifestRequiresTypedStaging);
        }
        self.stage_frame_internal(result_id, object_kind, plaintext, None)
    }

    /// Stage the one canonical displayed-alias manifest for a finalized
    /// product result. It is carried as a domain-tagged `AcquisitionSeal`
    /// payload because the frozen snapshot V1 object-kind vocabulary has no
    /// generic product-metadata kind. Generic staging cannot admit this magic.
    pub fn stage_displayed_alias_manifest(
        &self,
        result_id: &ResultId,
        manifest: &DisplayedAliasManifestV1,
    ) -> Result<EncryptedCoreResultFramePublicationV1, EncryptedCoreResultRepositoryErrorV1> {
        if manifest.result_id() != *result_id {
            return Err(EncryptedCoreResultRepositoryErrorV1::AliasManifestResultMismatch);
        }
        let encoded = manifest.encode();
        {
            let mut state = self.lock_state()?;
            let staged = state
                .staged
                .get_mut(result_id)
                .ok_or(EncryptedCoreResultRepositoryErrorV1::NoStagedResult)?;
            if staged.displayed_alias_manifest_staged {
                return Err(EncryptedCoreResultRepositoryErrorV1::AliasManifestAlreadyStaged);
            }
            staged.displayed_alias_manifest_staged = true;
        }
        let publication = self.stage_frame_internal(
            result_id,
            FrameObjectKindV1::AcquisitionSeal,
            &encoded,
            None,
        );
        if publication.is_err() {
            let mut state = self.lock_state()?;
            if let Some(staged) = state.staged.get_mut(result_id) {
                staged.displayed_alias_manifest_staged = false;
            }
        }
        publication
    }

    /// Stage exactly one persisted event as one complete authorized-outcome
    /// frame. Event identity, exactness, locator, encoded length, and the exact
    /// `[0, authorized_bytes.len())` range are retained for the derived index.
    /// The provider is the sole nonce issuer.
    pub fn stage_authorized_event(
        &self,
        result_id: &ResultId,
        event_id: EventId,
        exactness_basis: ExactnessBasis,
        authorized_bytes: &[u8],
    ) -> Result<EncryptedCoreResultEventPublicationV1, EncryptedCoreResultRepositoryErrorV1> {
        let frame = self.stage_frame_internal(
            result_id,
            FrameObjectKindV1::AuthorizedOutcome,
            authorized_bytes,
            Some((event_id, exactness_basis)),
        )?;
        Ok(EncryptedCoreResultEventPublicationV1 {
            event_id,
            exactness_basis,
            frame,
        })
    }

    fn stage_frame_internal(
        &self,
        result_id: &ResultId,
        object_kind: FrameObjectKindV1,
        plaintext: &[u8],
        event: Option<(EventId, ExactnessBasis)>,
    ) -> Result<EncryptedCoreResultFramePublicationV1, EncryptedCoreResultRepositoryErrorV1> {
        debug_assert_eq!(
            object_kind == FrameObjectKindV1::AuthorizedOutcome,
            event.is_some()
        );
        if plaintext.len() > MAX_FRAME_PLAINTEXT_BYTES_V1 {
            return Err(EncryptedCoreResultRepositoryErrorV1::FrameByteCap);
        }
        let encoded_length = FRAME_HEADER_BYTES_V1
            .checked_add(plaintext.len())
            .and_then(|value| value.checked_add(FRAME_TAG_BYTES_V1))
            .ok_or(EncryptedCoreResultRepositoryErrorV1::FrameByteCap)?;
        let plaintext_length = u32::try_from(plaintext.len())
            .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameByteCap)?;
        let encoded_byte_count = u32::try_from(encoded_length)
            .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameByteCap)?;

        let mut state = self.lock_state()?;
        if state.total_frame_count >= MAX_MEMORY_ENCRYPTED_CORE_FRAMES_V1 {
            return Err(EncryptedCoreResultRepositoryErrorV1::FrameCountCap);
        }
        let next_total_bytes = state
            .total_encoded_frame_bytes
            .checked_add(encoded_length)
            .ok_or(EncryptedCoreResultRepositoryErrorV1::FrameByteCap)?;
        if next_total_bytes > MAX_MEMORY_ENCRYPTED_CORE_FRAME_BYTES_V1 {
            return Err(EncryptedCoreResultRepositoryErrorV1::FrameByteCap);
        }

        let (authority, key_context, segment_header, locator, frame_offset, previous_commitment) = {
            let staged = state
                .staged
                .get(result_id)
                .ok_or(EncryptedCoreResultRepositoryErrorV1::NoStagedResult)?;
            if let Some((event_id, _)) = event {
                if staged
                    .events
                    .iter()
                    .any(|material| material.event_id == event_id)
                {
                    return Err(EncryptedCoreResultRepositoryErrorV1::DuplicateEventId);
                }
            }
            if staged.frame_count >= MAX_MEMORY_ENCRYPTED_CORE_FRAMES_V1 {
                return Err(EncryptedCoreResultRepositoryErrorV1::FrameCountCap);
            }
            let segment = staged
                .segments
                .last()
                .ok_or(EncryptedCoreResultRepositoryErrorV1::CatalogBuildFailed)?;
            if segment.encoded_frames.len() >= MAX_FRAMES_PER_SEGMENT_V1 as usize {
                return Err(EncryptedCoreResultRepositoryErrorV1::FrameCountCap);
            }
            let segment_header = SegmentHeaderV1::decode(&segment.encoded_header)
                .map_err(|_| EncryptedCoreResultRepositoryErrorV1::CatalogBuildFailed)?;
            let segment_frame_sequence = u32::try_from(segment.encoded_frames.len())
                .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameCountCap)?;
            let frame_offset = segment
                .encoded_frames
                .iter()
                .try_fold(SEGMENT_HEADER_BYTES_V1 as u64, |offset, encoded_frame| {
                    offset.checked_add(u64::try_from(encoded_frame.len()).ok()?)
                })
                .ok_or(EncryptedCoreResultRepositoryErrorV1::FrameByteCap)?;
            let previous_commitment = match segment.encoded_frames.last() {
                Some(encoded) => SealedFrameV1::decode(&segment_header, encoded)
                    .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameDecodeFailed)?
                    .commitment(),
                None => segment_start_commitment_v1(&segment_header),
            };
            (
                staged.authority,
                staged.key_context,
                segment_header,
                EncryptedCoreResultFrameLocatorV1::new(
                    u64::try_from(staged.segments.len() - 1)
                        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::SegmentCountCap)?,
                    staged.next_global_frame_sequence,
                    segment_frame_sequence,
                ),
                frame_offset,
                previous_commitment,
            )
        };

        let opened_key = self
            .provider
            .open_result_key(result_id, &key_context.expected_context())
            .map_err(|_| EncryptedCoreResultRepositoryErrorV1::KeyProviderFailed)?;
        if opened_key.state() != ResultKeyRecordStateV1::Creating {
            return Err(EncryptedCoreResultRepositoryErrorV1::KeyNotCreating);
        }
        let nonce = self
            .provider
            .issue_snapshot_frame_nonce(result_id)
            .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameNonceIssuanceFailed)?;
        let header = FrameHeaderV1::new(
            object_kind,
            locator.global_frame_sequence(),
            locator.segment_frame_sequence(),
            plaintext_length,
            nonce,
            previous_commitment,
        )
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameSealFailed)?;
        let sealed = seal_core_result_frame_v1(
            &opened_key.result_dek().frame_key(),
            authority,
            &segment_header,
            header,
            plaintext,
        )
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameSealFailed)?;
        let encoded = sealed.encode();
        if encoded.len() != encoded_length {
            return Err(EncryptedCoreResultRepositoryErrorV1::FrameVerificationFailed);
        }
        let decoded = SealedFrameV1::decode(&segment_header, &encoded)
            .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameVerificationFailed)?;
        if decoded.header() != sealed.header() || decoded.commitment() != sealed.commitment() {
            return Err(EncryptedCoreResultRepositoryErrorV1::FrameVerificationFailed);
        }
        let reopened = open_core_result_frame_v1(
            &opened_key.result_dek().frame_key(),
            authority,
            &segment_header,
            &decoded,
        )
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameVerificationFailed)?;
        if reopened.as_bytes() != plaintext {
            return Err(EncryptedCoreResultRepositoryErrorV1::FrameVerificationFailed);
        }
        drop(reopened);
        drop(opened_key);

        if state.fail_next_frame_publication {
            state.fail_next_frame_publication = false;
            return Err(EncryptedCoreResultRepositoryErrorV1::FramePublicationFailed);
        }
        let staged = state
            .staged
            .get_mut(result_id)
            .ok_or(EncryptedCoreResultRepositoryErrorV1::NoStagedResult)?;
        let next_global_frame_sequence = staged
            .next_global_frame_sequence
            .checked_add(1)
            .ok_or(EncryptedCoreResultRepositoryErrorV1::FrameCountCap)?;
        let next_staged_frame_count = staged
            .frame_count
            .checked_add(1)
            .ok_or(EncryptedCoreResultRepositoryErrorV1::FrameCountCap)?;
        let next_staged_encoded_bytes = staged
            .encoded_frame_bytes
            .checked_add(encoded_length)
            .ok_or(EncryptedCoreResultRepositoryErrorV1::FrameByteCap)?;
        let event_material = event
            .map(|(event_id, exactness_basis)| {
                Ok::<_, EncryptedCoreResultRepositoryErrorV1>(StagedEventIndexMaterialV1 {
                    event_id,
                    exactness_basis,
                    frame_locator: EventFrameLocatorV1::new(
                        locator.segment_sequence(),
                        locator.global_frame_sequence(),
                        locator.segment_frame_sequence(),
                        frame_offset,
                        encoded_byte_count,
                    )
                    .map_err(|_| EncryptedCoreResultRepositoryErrorV1::EventIndexBuildFailed)?,
                    authorized_bytes: AuthorizedByteRangeV1::new(0, plaintext_length)
                        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::EventIndexBuildFailed)?,
                })
            })
            .transpose()?;
        staged
            .segments
            .last_mut()
            .ok_or(EncryptedCoreResultRepositoryErrorV1::CatalogBuildFailed)?
            .encoded_frames
            .push(encoded);
        if let Some(material) = event_material {
            staged.events.push(material);
        }
        staged.next_global_frame_sequence = next_global_frame_sequence;
        staged.frame_count = next_staged_frame_count;
        staged.encoded_frame_bytes = next_staged_encoded_bytes;
        state.total_frame_count += 1;
        state.total_encoded_frame_bytes = next_total_bytes;

        Ok(EncryptedCoreResultFramePublicationV1 {
            locator,
            object_kind,
            commitment: sealed.commitment(),
            encoded_byte_count,
        })
    }

    /// Close the nonempty current segment and start the next exact chain.
    pub fn rotate_staged_segment(
        &self,
        result_id: &ResultId,
    ) -> Result<u64, EncryptedCoreResultRepositoryErrorV1> {
        let mut state = self.lock_state()?;
        if state.total_segment_count >= MAX_MEMORY_ENCRYPTED_CORE_SEGMENTS_V1 {
            return Err(EncryptedCoreResultRepositoryErrorV1::SegmentCountCap);
        }
        let next_total_bytes = state
            .total_encoded_frame_bytes
            .checked_add(SEGMENT_HEADER_BYTES_V1)
            .ok_or(EncryptedCoreResultRepositoryErrorV1::FrameByteCap)?;
        if next_total_bytes > MAX_MEMORY_ENCRYPTED_CORE_FRAME_BYTES_V1 {
            return Err(EncryptedCoreResultRepositoryErrorV1::FrameByteCap);
        }
        let staged = state
            .staged
            .get_mut(result_id)
            .ok_or(EncryptedCoreResultRepositoryErrorV1::NoStagedResult)?;
        if staged.segments.len() >= MAX_MEMORY_ENCRYPTED_CORE_SEGMENTS_V1 {
            return Err(EncryptedCoreResultRepositoryErrorV1::SegmentCountCap);
        }
        let current = staged
            .segments
            .last()
            .ok_or(EncryptedCoreResultRepositoryErrorV1::CatalogBuildFailed)?;
        let current_header = SegmentHeaderV1::decode(&current.encoded_header)
            .map_err(|_| EncryptedCoreResultRepositoryErrorV1::CatalogBuildFailed)?;
        let final_encoded = current
            .encoded_frames
            .last()
            .ok_or(EncryptedCoreResultRepositoryErrorV1::EmptySegment)?;
        let final_commitment = SealedFrameV1::decode(&current_header, final_encoded)
            .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameDecodeFailed)?
            .commitment();
        let segment_sequence = u64::try_from(staged.segments.len())
            .map_err(|_| EncryptedCoreResultRepositoryErrorV1::SegmentCountCap)?;
        let next_header = SegmentHeaderV1::new(
            CORE_RESULT_FRAME_PAYLOAD_SCHEMA_V1,
            staged.authority.result_id(),
            segment_sequence,
            staged.key_context.created_unix_nanos(),
            staged.key_context.expires_unix_nanos(),
            final_commitment,
        )
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::CatalogBuildFailed)?;
        let next_staged_encoded_bytes = staged
            .encoded_frame_bytes
            .checked_add(SEGMENT_HEADER_BYTES_V1)
            .ok_or(EncryptedCoreResultRepositoryErrorV1::FrameByteCap)?;
        staged.segments.push(StoredEncryptedSegmentV1 {
            encoded_header: next_header.encode(),
            encoded_frames: Vec::new(),
        });
        staged.encoded_frame_bytes = next_staged_encoded_bytes;
        state.total_segment_count += 1;
        state.total_encoded_frame_bytes = next_total_bytes;
        Ok(segment_sequence)
    }

    /// Return only the derived structural catalog needed to construct the
    /// matching typed manifest. No staged ciphertext or plaintext is exposed.
    pub fn staged_segment_catalog(
        &self,
        result_id: &ResultId,
    ) -> Result<SegmentCatalogV1, EncryptedCoreResultRepositoryErrorV1> {
        let state = self.lock_state()?;
        let staged = state
            .staged
            .get(result_id)
            .ok_or(EncryptedCoreResultRepositoryErrorV1::NoStagedResult)?;
        build_segment_catalog(&staged.segments, staged.key_context)
    }

    /// Return the exact canonical index derived from repository-owned staged
    /// frame bytes and typed event assignments. This is structural input for
    /// the caller's reconciled manifest; it exposes no plaintext or nonce.
    pub fn staged_event_expansion_index(
        &self,
        result_id: &ResultId,
    ) -> Result<EventExpansionIndexV1, EncryptedCoreResultRepositoryErrorV1> {
        let state = self.lock_state()?;
        let staged = state
            .staged
            .get(result_id)
            .ok_or(EncryptedCoreResultRepositoryErrorV1::NoStagedResult)?;
        let catalog = build_segment_catalog(&staged.segments, staged.key_context)?;
        build_event_expansion_index(&catalog, &staged.events)
    }

    /// Seal a staged result only when the supplied typed manifest contains the
    /// exact derived catalog and the same result/source/receipt authority.
    pub fn seal_staged_result(
        &self,
        result_id: &ResultId,
        manifest: &CoreResultManifestV1,
    ) -> Result<EncryptedCoreResultPublicationV1, EncryptedCoreResultRepositoryErrorV1> {
        let mut state = self.lock_state()?;
        let (authority, key_context, catalog, event_index) = {
            let staged = state
                .staged
                .get(result_id)
                .ok_or(EncryptedCoreResultRepositoryErrorV1::NoStagedResult)?;
            let catalog = build_segment_catalog(&staged.segments, staged.key_context)?;
            let event_index = build_event_expansion_index(&catalog, &staged.events)?;
            (staged.authority, staged.key_context, catalog, event_index)
        };
        if manifest.result_id() != authority.result_id()
            || manifest.source_identity_digest() != authority.source_identity_digest()
            || manifest.acquisition_receipt_id() != authority.acquisition_receipt_id()
        {
            return Err(EncryptedCoreResultRepositoryErrorV1::AuthorityMismatch);
        }
        if manifest.components().catalog().encode() != catalog.encode() {
            return Err(EncryptedCoreResultRepositoryErrorV1::CatalogMismatch);
        }
        if manifest.components().event_index().encode() != event_index.encode() {
            return Err(EncryptedCoreResultRepositoryErrorV1::EventIndexMismatch);
        }

        let opened_key = self
            .provider
            .open_result_key(result_id, &key_context.expected_context())
            .map_err(|_| EncryptedCoreResultRepositoryErrorV1::KeyProviderFailed)?;
        if opened_key.state() != ResultKeyRecordStateV1::Creating {
            return Err(EncryptedCoreResultRepositoryErrorV1::KeyNotCreating);
        }
        let nonce = match self.provider.issue_snapshot_manifest_nonce(result_id) {
            Ok(nonce) => nonce,
            Err(_) => {
                drop(opened_key);
                self.abort_staged_locked(&mut state, *result_id)?;
                return Err(EncryptedCoreResultRepositoryErrorV1::NonceIssuanceFailed);
            }
        };
        let seal_context = CoreResultManifestSealContextV1::new(
            key_context.created_unix_nanos(),
            key_context.expires_unix_nanos(),
            nonce,
        )
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::ManifestSealFailed)?;
        let sealed = match seal_core_result_manifest_v1(
            &opened_key.result_dek().manifest_key(),
            seal_context,
            manifest,
        ) {
            Ok(sealed) => sealed,
            Err(_) => {
                drop(opened_key);
                self.abort_staged_locked(&mut state, *result_id)?;
                return Err(EncryptedCoreResultRepositoryErrorV1::ManifestSealFailed);
            }
        };
        drop(opened_key);
        let binding = SealBindingV1::new(
            sealed.commitment(),
            catalog.final_chain_root(),
            catalog.total_frame_count(),
            catalog.segment_count(),
        )
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::SealBindingFailed)?;
        if self
            .publish_key_seal_with_one_exact_retry(*result_id, &binding)
            .is_err()
        {
            self.abort_staged_locked(&mut state, *result_id)?;
            return Err(EncryptedCoreResultRepositoryErrorV1::KeySealFailed);
        }
        if state.fail_next_publication {
            state.fail_next_publication = false;
            self.abort_staged_locked(&mut state, *result_id)?;
            return Err(EncryptedCoreResultRepositoryErrorV1::PublicationFailed);
        }

        let staged = state
            .staged
            .remove(result_id)
            .ok_or(EncryptedCoreResultRepositoryErrorV1::NoStagedResult)?;
        let prior = state.entries.insert(
            *result_id,
            StoredEncryptedCoreResultV1 {
                encoded_manifest: sealed.encode(),
                segments: staged.segments,
                frame_count: staged.frame_count,
                encoded_frame_bytes: staged.encoded_frame_bytes,
            },
        );
        debug_assert!(prior.is_none());
        Ok(EncryptedCoreResultPublicationV1 {
            result_id: *result_id,
            manifest_commitment: sealed.commitment(),
        })
    }

    /// Export the exact canonical ciphertext objects of one authenticated,
    /// published, frame-backed result.
    ///
    /// Staged results and manifest-only compatibility entries are not
    /// exportable. The returned value contains no plaintext and makes no
    /// filesystem, durability, recovery, or write-order claim.
    pub fn export_sealed_bundle(
        &self,
        expected: ExpectedCoreResultManifestContextV1,
    ) -> Result<SealedEncryptedCoreResultBundleV1, EncryptedCoreResultRepositoryErrorV1> {
        let state = self.lock_state()?;
        let stored = state
            .entries
            .get(&expected.result_id())
            .ok_or(EncryptedCoreResultRepositoryErrorV1::ResultNotFound)?;
        let (opened_key, opened_manifest) = self.authenticate_stored_result(stored, expected)?;
        if stored.segments.is_empty()
            || opened_manifest
                .manifest()
                .components()
                .catalog()
                .segment_count()
                == 0
        {
            return Err(EncryptedCoreResultRepositoryErrorV1::BundleEncodeFailed);
        }
        drop(opened_key);
        let segments = stored
            .segments
            .iter()
            .map(|segment| SealedBundleSegmentV1 {
                encoded_header: segment.encoded_header,
                encoded_frames: segment.encoded_frames.clone(),
            })
            .collect();
        SealedEncryptedCoreResultBundleV1::from_encrypted_parts(
            expected.result_id(),
            stored.encoded_manifest.clone(),
            segments,
        )
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::BundleEncodeFailed)
    }

    /// Authenticate and atomically publish a canonical ciphertext bundle under
    /// an independently existing sealed provider key record.
    ///
    /// The bundle is canonicalized again before materialization. Provider
    /// sealed state, the full expected authority, outer-manifest AEAD, key seal
    /// binding, exact manifest catalog, segment digests, frame commitments,
    /// sequences, lengths, counts, capacity, and duplicate state are all
    /// checked before repository state changes. Import never creates or seals
    /// key authority and never exposes staged ciphertext.
    pub fn import_sealed_bundle(
        &self,
        expected: ExpectedCoreResultManifestContextV1,
        bundle: SealedEncryptedCoreResultBundleV1,
    ) -> Result<EncryptedCoreResultPublicationV1, EncryptedCoreResultRepositoryErrorV1> {
        if bundle.result_id() != expected.result_id() {
            return Err(EncryptedCoreResultRepositoryErrorV1::AuthorityMismatch);
        }
        let canonical = bundle.encode();
        let bundle = SealedEncryptedCoreResultBundleV1::decode(&canonical)
            .map_err(|_| EncryptedCoreResultRepositoryErrorV1::BundleDecodeFailed)?;
        if bundle.result_id() != expected.result_id() {
            return Err(EncryptedCoreResultRepositoryErrorV1::AuthorityMismatch);
        }
        let (result_id, encoded_manifest, bundle_segments, frame_count, encoded_frame_bytes) =
            bundle.into_encrypted_parts();
        let segments = bundle_segments
            .into_iter()
            .map(|segment| StoredEncryptedSegmentV1 {
                encoded_header: segment.encoded_header,
                encoded_frames: segment.encoded_frames,
            })
            .collect::<Vec<_>>();
        let candidate = StoredEncryptedCoreResultV1 {
            encoded_manifest,
            segments,
            frame_count,
            encoded_frame_bytes,
        };

        let mut state = self.lock_state()?;
        if state.entries.contains_key(&result_id) || state.staged.contains_key(&result_id) {
            return Err(EncryptedCoreResultRepositoryErrorV1::DuplicateResult);
        }
        if state.entries.len() + state.staged.len() >= state.capacity {
            return Err(EncryptedCoreResultRepositoryErrorV1::CapacityExceeded);
        }
        let next_frame_count = state
            .total_frame_count
            .checked_add(candidate.frame_count)
            .ok_or(EncryptedCoreResultRepositoryErrorV1::FrameCountCap)?;
        if next_frame_count > MAX_MEMORY_ENCRYPTED_CORE_FRAMES_V1 {
            return Err(EncryptedCoreResultRepositoryErrorV1::FrameCountCap);
        }
        let next_segment_count = state
            .total_segment_count
            .checked_add(candidate.segments.len())
            .ok_or(EncryptedCoreResultRepositoryErrorV1::SegmentCountCap)?;
        if next_segment_count > MAX_MEMORY_ENCRYPTED_CORE_SEGMENTS_V1 {
            return Err(EncryptedCoreResultRepositoryErrorV1::SegmentCountCap);
        }
        let next_encoded_frame_bytes = state
            .total_encoded_frame_bytes
            .checked_add(candidate.encoded_frame_bytes)
            .ok_or(EncryptedCoreResultRepositoryErrorV1::FrameByteCap)?;
        if next_encoded_frame_bytes > MAX_MEMORY_ENCRYPTED_CORE_FRAME_BYTES_V1 {
            return Err(EncryptedCoreResultRepositoryErrorV1::FrameByteCap);
        }

        let (opened_key, opened_manifest) =
            self.authenticate_stored_result(&candidate, expected)?;
        let binding = opened_key
            .seal_binding()
            .ok_or(EncryptedCoreResultRepositoryErrorV1::KeyNotSealed)?;
        let manifest_commitment = binding.manifest_commitment();
        let catalog = opened_manifest.manifest().components().catalog();
        if usize::try_from(catalog.segment_count()).ok() != Some(candidate.segments.len())
            || usize::try_from(catalog.total_frame_count()).ok() != Some(candidate.frame_count)
            || usize::try_from(catalog.total_encoded_byte_count()).ok()
                != Some(candidate.encoded_frame_bytes)
        {
            return Err(EncryptedCoreResultRepositoryErrorV1::BundleMismatch);
        }
        drop(opened_key);

        if state.fail_next_publication {
            state.fail_next_publication = false;
            return Err(EncryptedCoreResultRepositoryErrorV1::PublicationFailed);
        }
        let prior = state.entries.insert(result_id, candidate);
        debug_assert!(prior.is_none());
        state.total_frame_count = next_frame_count;
        state.total_segment_count = next_segment_count;
        state.total_encoded_frame_bytes = next_encoded_frame_bytes;
        Ok(EncryptedCoreResultPublicationV1 {
            result_id,
            manifest_commitment,
        })
    }

    /// Open only a published ciphertext whose authenticated provider seal
    /// agrees with the exact stored manifest commitment and catalog chain.
    pub fn open_sealed_result(
        &self,
        expected: ExpectedCoreResultManifestContextV1,
    ) -> Result<OpenedCoreResultManifestV1, EncryptedCoreResultRepositoryErrorV1> {
        let state = self.lock_state()?;
        let stored = state
            .entries
            .get(&expected.result_id())
            .ok_or(EncryptedCoreResultRepositoryErrorV1::ResultNotFound)?;
        let (opened_key, opened) = self.authenticate_stored_result(stored, expected)?;
        drop(opened_key);
        Ok(opened)
    }

    /// Authenticate the sealed manifest, exact stored catalog, requested frame
    /// identity, authority-bound AAD, and frame ciphertext before returning the
    /// complete zeroizing plaintext. A frame is never sliced.
    pub fn open_stored_frame(
        &self,
        expected: ExpectedCoreResultManifestContextV1,
        locator: EncryptedCoreResultFrameLocatorV1,
    ) -> Result<OpenedEncryptedCoreResultFrameV1, EncryptedCoreResultRepositoryErrorV1> {
        let state = self.lock_state()?;
        let stored = state
            .entries
            .get(&expected.result_id())
            .ok_or(EncryptedCoreResultRepositoryErrorV1::ResultNotFound)?;
        if stored.segments.is_empty() {
            return Err(EncryptedCoreResultRepositoryErrorV1::FrameNotFound);
        }
        let (opened_key, _) = self.authenticate_stored_result(stored, expected)?;
        let decoded = decode_stored_frame(stored, locator)?;
        let authority = CoreResultFrameAuthorityV1::new(
            expected.result_id(),
            expected.source_identity_digest(),
            expected.acquisition_receipt_id(),
        )
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::AuthorityMismatch)?;
        let plaintext = open_core_result_frame_v1(
            &opened_key.result_dek().frame_key(),
            authority,
            &decoded.segment_header,
            &decoded.frame,
        )
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameOpenFailed)?;
        Ok(OpenedEncryptedCoreResultFrameV1 {
            locator,
            object_kind: decoded.frame.header().object_kind(),
            commitment: decoded.frame.commitment(),
            plaintext,
        })
    }

    /// Authenticate the result authority and canonical event index, locate the
    /// exact indexed frame in repository-owned bytes, authenticate the complete
    /// frame, and return only the event's exact authorized bytes.
    pub fn open_stored_event(
        &self,
        expected: ExpectedCoreResultManifestContextV1,
        event_id: EventId,
    ) -> Result<OpenedEncryptedCoreResultEventV1, EncryptedCoreResultRepositoryErrorV1> {
        let state = self.lock_state()?;
        let stored = state
            .entries
            .get(&expected.result_id())
            .ok_or(EncryptedCoreResultRepositoryErrorV1::ResultNotFound)?;
        let (opened_key, opened_manifest) = self.authenticate_stored_result(stored, expected)?;
        let entries = opened_manifest
            .manifest()
            .components()
            .event_index()
            .entries();
        let entry_index = entries
            .binary_search_by_key(&event_id, EventExpansionIndexEntryV1::event_id)
            .map_err(|_| EncryptedCoreResultRepositoryErrorV1::EventNotFound)?;
        let entry = entries[entry_index];
        let receipt_binding_matches = opened_manifest
            .manifest()
            .components()
            .source_outcomes()
            .entries()
            .iter()
            .any(|source_outcome| {
                matches!(
                    source_outcome.outcome(),
                    AcquisitionOutcome::Persisted {
                        event_id: bound_event_id,
                        exactness_basis,
                    } if *bound_event_id == event_id
                        && *exactness_basis == entry.exactness_basis()
                )
            });
        let indexed_locator = entry.frame_locator();
        let locator = EncryptedCoreResultFrameLocatorV1::new(
            indexed_locator.segment_sequence(),
            indexed_locator.global_frame_sequence(),
            indexed_locator.segment_frame_sequence(),
        );
        let decoded = decode_stored_frame(stored, locator)?;
        if !receipt_binding_matches
            || entry.event_id() != event_id
            || entry.frame_object_kind() != FrameObjectKindV1::AuthorizedOutcome
            || decoded.frame.header().object_kind() != FrameObjectKindV1::AuthorizedOutcome
            || indexed_locator.frame_offset() != decoded.frame_offset
            || indexed_locator.frame_encoded_length() != decoded.encoded_length
            || entry.authorized_bytes().offset() != 0
            || entry.authorized_bytes().length() != decoded.frame.header().plaintext_length()
        {
            return Err(EncryptedCoreResultRepositoryErrorV1::EventBindingMismatch);
        }
        let authority = CoreResultFrameAuthorityV1::new(
            expected.result_id(),
            expected.source_identity_digest(),
            expected.acquisition_receipt_id(),
        )
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::AuthorityMismatch)?;
        let authorized_bytes = open_core_result_frame_v1(
            &opened_key.result_dek().frame_key(),
            authority,
            &decoded.segment_header,
            &decoded.frame,
        )
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameOpenFailed)?;
        if authorized_bytes.as_bytes().len()
            != usize::try_from(entry.authorized_bytes().length())
                .map_err(|_| EncryptedCoreResultRepositoryErrorV1::EventBindingMismatch)?
        {
            return Err(EncryptedCoreResultRepositoryErrorV1::EventBindingMismatch);
        }
        Ok(OpenedEncryptedCoreResultEventV1 {
            event_id,
            exactness_basis: entry.exactness_basis(),
            authorized_bytes,
        })
    }

    /// Authenticate and recover the one domain-tagged displayed-alias
    /// manifest without opening any authorized event payload.
    pub(crate) fn open_displayed_alias_manifest(
        &self,
        expected: ExpectedCoreResultManifestContextV1,
    ) -> Result<DisplayedAliasManifestV1, EncryptedCoreResultRepositoryErrorV1> {
        let state = self.lock_state()?;
        let stored = state
            .entries
            .get(&expected.result_id())
            .ok_or(EncryptedCoreResultRepositoryErrorV1::ResultNotFound)?;
        let (opened_key, opened_manifest) = self.authenticate_stored_result(stored, expected)?;
        let authority = CoreResultFrameAuthorityV1::new(
            expected.result_id(),
            expected.source_identity_digest(),
            expected.acquisition_receipt_id(),
        )
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::AuthorityMismatch)?;
        let mut found = None;
        for stored_segment in &stored.segments {
            let segment_header = SegmentHeaderV1::decode(&stored_segment.encoded_header)
                .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameDecodeFailed)?;
            for encoded_frame in &stored_segment.encoded_frames {
                let frame = SealedFrameV1::decode(&segment_header, encoded_frame)
                    .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameDecodeFailed)?;
                if frame.header().object_kind() != FrameObjectKindV1::AcquisitionSeal {
                    continue;
                }
                let plaintext = open_core_result_frame_v1(
                    &opened_key.result_dek().frame_key(),
                    authority,
                    &segment_header,
                    &frame,
                )
                .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameOpenFailed)?;
                if !DisplayedAliasManifestV1::has_magic(plaintext.as_bytes()) {
                    continue;
                }
                let decoded = DisplayedAliasManifestV1::decode(plaintext.as_bytes())
                    .map_err(|_| EncryptedCoreResultRepositoryErrorV1::AliasManifestDecodeFailed)?;
                if found.replace(decoded).is_some() {
                    return Err(EncryptedCoreResultRepositoryErrorV1::AliasManifestDuplicate);
                }
            }
        }
        let manifest = found.ok_or(EncryptedCoreResultRepositoryErrorV1::AliasManifestMissing)?;
        if manifest.result_id() != expected.result_id()
            || manifest.expires_at().get() != i128::from(expected.expires_unix_nanos())
        {
            return Err(EncryptedCoreResultRepositoryErrorV1::AliasManifestResultMismatch);
        }
        let indexed_events = opened_manifest
            .manifest()
            .components()
            .event_index()
            .entries()
            .iter()
            .map(EventExpansionIndexEntryV1::event_id)
            .collect::<BTreeSet<_>>();
        for entry in manifest.entries() {
            if entry.reference().issued_at().get() < i128::from(expected.created_unix_nanos())
                || entry.reference().expires_at() != manifest.expires_at()
                || entry
                    .ordered_event_ids()
                    .iter()
                    .any(|event_id| !indexed_events.contains(event_id))
            {
                return Err(EncryptedCoreResultRepositoryErrorV1::AliasManifestEventMismatch);
            }
        }
        Ok(manifest)
    }

    /// Destroy key authority first, then remove the in-memory ciphertext.
    /// Failure to remove ciphertext after key destruction remains fail-closed:
    /// subsequent open cannot recover the DEK.
    pub fn destroy(
        &self,
        result_id: &ResultId,
    ) -> Result<EncryptedCoreResultDestroyOutcomeV1, EncryptedCoreResultRepositoryErrorV1> {
        let mut state = self.lock_state()?;
        let key_outcome = self
            .provider
            .destroy_result_key(result_id)
            .map_err(|_| EncryptedCoreResultRepositoryErrorV1::KeyProviderFailed)?;
        let ciphertext_exists =
            state.entries.contains_key(result_id) || state.staged.contains_key(result_id);
        if ciphertext_exists && state.fail_next_ciphertext_cleanup {
            state.fail_next_ciphertext_cleanup = false;
            return Err(EncryptedCoreResultRepositoryErrorV1::CiphertextCleanupFailed);
        }
        let removed_entry = state.entries.remove(result_id);
        let removed_staged = state.staged.remove(result_id);
        if let Some(removed) = removed_entry.as_ref() {
            release_frame_accounting(
                &mut state,
                removed.frame_count,
                removed.segments.len(),
                removed.encoded_frame_bytes,
            )?;
        }
        if let Some(removed) = removed_staged.as_ref() {
            release_frame_accounting(
                &mut state,
                removed.frame_count,
                removed.segments.len(),
                removed.encoded_frame_bytes,
            )?;
        }
        let removed = removed_entry.is_some() || removed_staged.is_some();
        Ok(
            if removed || key_outcome == KeyDestroyOutcomeV1::Destroyed {
                EncryptedCoreResultDestroyOutcomeV1::Destroyed
            } else {
                EncryptedCoreResultDestroyOutcomeV1::AlreadyAbsent
            },
        )
    }

    pub fn len(&self) -> Result<usize, EncryptedCoreResultRepositoryErrorV1> {
        let state = self.lock_state()?;
        Ok(state.entries.len() + state.staged.len())
    }

    pub fn is_empty(&self) -> Result<bool, EncryptedCoreResultRepositoryErrorV1> {
        Ok(self.len()? == 0)
    }

    #[cfg(any(test, feature = "internal-test-provider"))]
    pub fn provider_for_test(&self) -> &P {
        &self.provider
    }

    #[cfg(any(test, feature = "internal-test-provider"))]
    pub fn fail_next_publication_for_test(
        &self,
    ) -> Result<(), EncryptedCoreResultRepositoryErrorV1> {
        self.lock_state()?.fail_next_publication = true;
        Ok(())
    }

    #[cfg(any(test, feature = "internal-test-provider"))]
    pub fn fail_next_frame_publication_for_test(
        &self,
    ) -> Result<(), EncryptedCoreResultRepositoryErrorV1> {
        self.lock_state()?.fail_next_frame_publication = true;
        Ok(())
    }

    #[cfg(any(test, feature = "internal-test-provider"))]
    pub fn staged_frame_count_for_test(
        &self,
        result_id: &ResultId,
    ) -> Result<usize, EncryptedCoreResultRepositoryErrorV1> {
        Ok(self
            .lock_state()?
            .staged
            .get(result_id)
            .ok_or(EncryptedCoreResultRepositoryErrorV1::NoStagedResult)?
            .frame_count)
    }

    #[cfg(any(test, feature = "internal-test-provider"))]
    pub fn fail_next_ciphertext_cleanup_for_test(
        &self,
    ) -> Result<(), EncryptedCoreResultRepositoryErrorV1> {
        self.lock_state()?.fail_next_ciphertext_cleanup = true;
        Ok(())
    }

    #[cfg(any(test, feature = "internal-test-provider"))]
    pub fn corrupt_ciphertext_byte_for_test(
        &self,
        result_id: ResultId,
        offset: usize,
    ) -> Result<(), EncryptedCoreResultRepositoryErrorV1> {
        let mut state = self.lock_state()?;
        let stored = state
            .entries
            .get_mut(&result_id)
            .ok_or(EncryptedCoreResultRepositoryErrorV1::ResultNotFound)?;
        let byte = stored
            .encoded_manifest
            .get_mut(offset)
            .ok_or(EncryptedCoreResultRepositoryErrorV1::CiphertextDecodeFailed)?;
        *byte ^= 0x80;
        Ok(())
    }

    #[cfg(any(test, feature = "internal-test-provider"))]
    pub fn swap_ciphertexts_for_test(
        &self,
        first: ResultId,
        second: ResultId,
    ) -> Result<(), EncryptedCoreResultRepositoryErrorV1> {
        let mut state = self.lock_state()?;
        let first_bytes = state
            .entries
            .get(&first)
            .ok_or(EncryptedCoreResultRepositoryErrorV1::ResultNotFound)?
            .encoded_manifest
            .clone();
        let second_bytes = state
            .entries
            .get(&second)
            .ok_or(EncryptedCoreResultRepositoryErrorV1::ResultNotFound)?
            .encoded_manifest
            .clone();
        state
            .entries
            .get_mut(&first)
            .expect("both entries were checked")
            .encoded_manifest = second_bytes;
        state
            .entries
            .get_mut(&second)
            .expect("both entries were checked")
            .encoded_manifest = first_bytes;
        Ok(())
    }

    #[cfg(any(test, feature = "internal-test-provider"))]
    pub fn corrupt_stored_frame_byte_for_test(
        &self,
        result_id: ResultId,
        locator: EncryptedCoreResultFrameLocatorV1,
        offset: usize,
    ) -> Result<(), EncryptedCoreResultRepositoryErrorV1> {
        let mut state = self.lock_state()?;
        let frame = stored_frame_mut(&mut state, result_id, locator)?;
        let byte = frame
            .get_mut(offset)
            .ok_or(EncryptedCoreResultRepositoryErrorV1::FrameDecodeFailed)?;
        *byte ^= 0x80;
        Ok(())
    }

    #[cfg(any(test, feature = "internal-test-provider"))]
    pub fn truncate_stored_frame_for_test(
        &self,
        result_id: ResultId,
        locator: EncryptedCoreResultFrameLocatorV1,
        new_length: usize,
    ) -> Result<(), EncryptedCoreResultRepositoryErrorV1> {
        let mut state = self.lock_state()?;
        let frame = stored_frame_mut(&mut state, result_id, locator)?;
        if new_length >= frame.len() {
            return Err(EncryptedCoreResultRepositoryErrorV1::FrameDecodeFailed);
        }
        frame.truncate(new_length);
        Ok(())
    }

    #[cfg(any(test, feature = "internal-test-provider"))]
    pub fn swap_stored_frames_for_test(
        &self,
        first_result_id: ResultId,
        first_locator: EncryptedCoreResultFrameLocatorV1,
        second_result_id: ResultId,
        second_locator: EncryptedCoreResultFrameLocatorV1,
    ) -> Result<(), EncryptedCoreResultRepositoryErrorV1> {
        let mut state = self.lock_state()?;
        let first = stored_frame(&state, first_result_id, first_locator)?.clone();
        let second = stored_frame(&state, second_result_id, second_locator)?.clone();
        *stored_frame_mut(&mut state, first_result_id, first_locator)? = second;
        *stored_frame_mut(&mut state, second_result_id, second_locator)? = first;
        Ok(())
    }

    fn lock_state(
        &self,
    ) -> Result<MutexGuard<'_, RepositoryStateV1>, EncryptedCoreResultRepositoryErrorV1> {
        self.state
            .lock()
            .map_err(|_| EncryptedCoreResultRepositoryErrorV1::RepositoryUnavailable)
    }

    fn authenticate_stored_result(
        &self,
        stored: &StoredEncryptedCoreResultV1,
        expected: ExpectedCoreResultManifestContextV1,
    ) -> Result<(OpenedResultKeyV1, OpenedCoreResultManifestV1), EncryptedCoreResultRepositoryErrorV1>
    {
        let expected_key_context =
            ExpectedKeyContextV1::new(expected.created_unix_nanos(), expected.expires_unix_nanos())
                .map_err(|_| EncryptedCoreResultRepositoryErrorV1::AuthorityMismatch)?;
        let opened_key = self
            .provider
            .open_result_key(&expected.result_id(), &expected_key_context)
            .map_err(|_| EncryptedCoreResultRepositoryErrorV1::KeyProviderFailed)?;
        if opened_key.state() != ResultKeyRecordStateV1::Sealed {
            return Err(EncryptedCoreResultRepositoryErrorV1::KeyNotSealed);
        }
        let binding = opened_key
            .seal_binding()
            .ok_or(EncryptedCoreResultRepositoryErrorV1::KeyNotSealed)?;
        let sealed =
            SealedCoreResultManifestV1::decode(expected.result_id(), &stored.encoded_manifest)
                .map_err(|_| EncryptedCoreResultRepositoryErrorV1::CiphertextDecodeFailed)?;
        if sealed.commitment() != binding.manifest_commitment() {
            return Err(EncryptedCoreResultRepositoryErrorV1::SealBindingMismatch);
        }
        let opened = open_core_result_manifest_v1(
            &opened_key.result_dek().manifest_key(),
            expected,
            &sealed,
        )
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::ManifestOpenFailed)?;
        let manifest_catalog = opened.manifest().components().catalog();
        if manifest_catalog.final_chain_root() != binding.final_frame_commitment()
            || manifest_catalog.total_frame_count() != binding.total_frame_count()
            || manifest_catalog.segment_count() != binding.segment_count()
        {
            return Err(EncryptedCoreResultRepositoryErrorV1::SealBindingMismatch);
        }
        if !stored.segments.is_empty() {
            let key_context = CreatingKeyContextV1::new(
                expected.result_id(),
                expected.created_unix_nanos(),
                expected.expires_unix_nanos(),
            )
            .map_err(|_| EncryptedCoreResultRepositoryErrorV1::AuthorityMismatch)?;
            let stored_catalog = build_segment_catalog(&stored.segments, key_context)?;
            if usize::try_from(stored_catalog.total_frame_count()).ok() != Some(stored.frame_count)
                || usize::try_from(stored_catalog.total_encoded_byte_count()).ok()
                    != Some(stored.encoded_frame_bytes)
                || stored_catalog.encode() != manifest_catalog.encode()
            {
                return Err(EncryptedCoreResultRepositoryErrorV1::CatalogMismatch);
            }
        }
        Ok((opened_key, opened))
    }

    fn publish_key_seal_with_one_exact_retry(
        &self,
        result_id: ResultId,
        binding: &SealBindingV1,
    ) -> Result<ResultKeySealTransitionV1, KeyProviderErrorV1> {
        match self.provider.seal_result_key(&result_id, binding) {
            Err(KeyProviderErrorV1::UpdateFailed) => {
                self.provider.seal_result_key(&result_id, binding)
            }
            outcome => outcome,
        }
    }

    fn rollback_key(&self, result_id: ResultId) {
        let _ = self.provider.destroy_result_key(&result_id);
    }

    fn abort_staged_locked(
        &self,
        state: &mut RepositoryStateV1,
        result_id: ResultId,
    ) -> Result<(), EncryptedCoreResultRepositoryErrorV1> {
        self.rollback_key(result_id);
        if let Some(staged) = state.staged.remove(&result_id) {
            release_frame_accounting(
                state,
                staged.frame_count,
                staged.segments.len(),
                staged.encoded_frame_bytes,
            )?;
        }
        Ok(())
    }
}

impl<P> fmt::Debug for MemoryEncryptedCoreResultRepositoryV1<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MemoryEncryptedCoreResultRepositoryV1(<redacted>)")
    }
}

struct DecodedStoredFrameV1 {
    segment_header: SegmentHeaderV1,
    frame: SealedFrameV1,
    frame_offset: u64,
    encoded_length: u32,
}

fn decode_stored_frame(
    stored: &StoredEncryptedCoreResultV1,
    locator: EncryptedCoreResultFrameLocatorV1,
) -> Result<DecodedStoredFrameV1, EncryptedCoreResultRepositoryErrorV1> {
    let segment_index = usize::try_from(locator.segment_sequence())
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameNotFound)?;
    let stored_segment = stored
        .segments
        .get(segment_index)
        .ok_or(EncryptedCoreResultRepositoryErrorV1::FrameNotFound)?;
    let segment_header = SegmentHeaderV1::decode(&stored_segment.encoded_header)
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameDecodeFailed)?;
    let frame_index = usize::try_from(locator.segment_frame_sequence())
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameNotFound)?;
    let encoded_frame = stored_segment
        .encoded_frames
        .get(frame_index)
        .ok_or(EncryptedCoreResultRepositoryErrorV1::FrameNotFound)?;
    let frame = SealedFrameV1::decode(&segment_header, encoded_frame)
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameDecodeFailed)?;
    if segment_header.segment_sequence() != locator.segment_sequence()
        || frame.header().segment_frame_sequence() != locator.segment_frame_sequence()
        || frame.header().global_sequence() != locator.global_frame_sequence()
    {
        return Err(EncryptedCoreResultRepositoryErrorV1::FrameIdentityMismatch);
    }
    let frame_offset = stored_segment.encoded_frames[..frame_index]
        .iter()
        .try_fold(SEGMENT_HEADER_BYTES_V1 as u64, |offset, encoded| {
            offset.checked_add(u64::try_from(encoded.len()).ok()?)
        })
        .ok_or(EncryptedCoreResultRepositoryErrorV1::FrameByteCap)?;
    let encoded_length = u32::try_from(encoded_frame.len())
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameByteCap)?;
    Ok(DecodedStoredFrameV1 {
        segment_header,
        frame,
        frame_offset,
        encoded_length,
    })
}

fn build_segment_catalog(
    segments: &[StoredEncryptedSegmentV1],
    key_context: CreatingKeyContextV1,
) -> Result<SegmentCatalogV1, EncryptedCoreResultRepositoryErrorV1> {
    if segments.is_empty() {
        return Err(EncryptedCoreResultRepositoryErrorV1::CatalogBuildFailed);
    }
    if segments.len() > MAX_MEMORY_ENCRYPTED_CORE_SEGMENTS_V1 {
        return Err(EncryptedCoreResultRepositoryErrorV1::SegmentCountCap);
    }

    let mut entries = Vec::with_capacity(segments.len());
    let mut expected_global_sequence = 0u64;
    let mut expected_prior_segment_commitment = FrameCommitmentV1::ZERO;
    let mut seen_nonces = BTreeSet::new();
    let mut total_frame_count = 0usize;

    for (segment_index, stored_segment) in segments.iter().enumerate() {
        if stored_segment.encoded_frames.is_empty() {
            return Err(EncryptedCoreResultRepositoryErrorV1::EmptySegment);
        }
        let segment_header = SegmentHeaderV1::decode(&stored_segment.encoded_header)
            .map_err(|_| EncryptedCoreResultRepositoryErrorV1::CatalogBuildFailed)?;
        let expected_segment_sequence = u64::try_from(segment_index)
            .map_err(|_| EncryptedCoreResultRepositoryErrorV1::SegmentCountCap)?;
        if segment_header.payload_schema() != CORE_RESULT_FRAME_PAYLOAD_SCHEMA_V1
            || segment_header.result_id() != key_context.result_id()
            || segment_header.segment_sequence() != expected_segment_sequence
            || segment_header.created_unix_nanos() != key_context.created_unix_nanos()
            || segment_header.expires_unix_nanos() != key_context.expires_unix_nanos()
            || segment_header.prior_segment_commitment() != expected_prior_segment_commitment
        {
            return Err(EncryptedCoreResultRepositoryErrorV1::CatalogBuildFailed);
        }

        let first_global_sequence = expected_global_sequence;
        let mut expected_previous_commitment = segment_start_commitment_v1(&segment_header);
        let mut ciphertext_byte_count = 0u64;
        let encoded_capacity = stored_segment
            .encoded_frames
            .iter()
            .try_fold(SEGMENT_HEADER_BYTES_V1, |total, frame| {
                total.checked_add(frame.len())
            })
            .ok_or(EncryptedCoreResultRepositoryErrorV1::FrameByteCap)?;
        let mut encoded_segment = Vec::with_capacity(encoded_capacity);
        encoded_segment.extend_from_slice(&stored_segment.encoded_header);

        for (frame_index, encoded_frame) in stored_segment.encoded_frames.iter().enumerate() {
            let frame = SealedFrameV1::decode(&segment_header, encoded_frame)
                .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameDecodeFailed)?;
            let expected_segment_frame_sequence = u32::try_from(frame_index)
                .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameCountCap)?;
            if frame.header().global_sequence() != expected_global_sequence
                || frame.header().segment_frame_sequence() != expected_segment_frame_sequence
                || frame.header().previous_frame_commitment() != expected_previous_commitment
            {
                return Err(EncryptedCoreResultRepositoryErrorV1::FrameIdentityMismatch);
            }
            if !seen_nonces.insert(frame.header().nonce()) {
                return Err(EncryptedCoreResultRepositoryErrorV1::FrameVerificationFailed);
            }
            ciphertext_byte_count = ciphertext_byte_count
                .checked_add(u64::from(frame.header().ciphertext_length()))
                .ok_or(EncryptedCoreResultRepositoryErrorV1::FrameByteCap)?;
            expected_previous_commitment = frame.commitment();
            expected_global_sequence = expected_global_sequence
                .checked_add(1)
                .ok_or(EncryptedCoreResultRepositoryErrorV1::FrameCountCap)?;
            total_frame_count = total_frame_count
                .checked_add(1)
                .ok_or(EncryptedCoreResultRepositoryErrorV1::FrameCountCap)?;
            if total_frame_count > MAX_MEMORY_ENCRYPTED_CORE_FRAMES_V1 {
                return Err(EncryptedCoreResultRepositoryErrorV1::FrameCountCap);
            }
            encoded_segment.extend_from_slice(encoded_frame);
        }

        let frame_count = u32::try_from(stored_segment.encoded_frames.len())
            .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameCountCap)?;
        entries.push(
            SegmentCatalogEntryV1::new(
                expected_segment_sequence,
                first_global_sequence,
                frame_count,
                u64::try_from(encoded_segment.len())
                    .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameByteCap)?,
                ciphertext_byte_count,
                derive_segment_digest_v1(&encoded_segment),
                expected_previous_commitment,
            )
            .map_err(|_| EncryptedCoreResultRepositoryErrorV1::CatalogBuildFailed)?,
        );
        expected_prior_segment_commitment = expected_previous_commitment;
    }

    SegmentCatalogV1::new(entries)
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::CatalogBuildFailed)
}

fn build_event_expansion_index(
    catalog: &SegmentCatalogV1,
    materials: &[StagedEventIndexMaterialV1],
) -> Result<EventExpansionIndexV1, EncryptedCoreResultRepositoryErrorV1> {
    let entries = materials
        .iter()
        .map(|material| {
            EventExpansionIndexEntryV1::new(
                catalog,
                material.event_id,
                material.frame_locator,
                material.authorized_bytes,
                material.exactness_basis,
            )
            .map_err(|_| EncryptedCoreResultRepositoryErrorV1::EventIndexBuildFailed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    EventExpansionIndexV1::new(catalog, entries)
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::EventIndexBuildFailed)
}

fn release_frame_accounting(
    state: &mut RepositoryStateV1,
    frame_count: usize,
    segment_count: usize,
    encoded_frame_bytes: usize,
) -> Result<(), EncryptedCoreResultRepositoryErrorV1> {
    let next_frame_count = state
        .total_frame_count
        .checked_sub(frame_count)
        .ok_or(EncryptedCoreResultRepositoryErrorV1::RepositoryUnavailable)?;
    let next_segment_count = state
        .total_segment_count
        .checked_sub(segment_count)
        .ok_or(EncryptedCoreResultRepositoryErrorV1::RepositoryUnavailable)?;
    let next_encoded_frame_bytes = state
        .total_encoded_frame_bytes
        .checked_sub(encoded_frame_bytes)
        .ok_or(EncryptedCoreResultRepositoryErrorV1::RepositoryUnavailable)?;
    state.total_frame_count = next_frame_count;
    state.total_segment_count = next_segment_count;
    state.total_encoded_frame_bytes = next_encoded_frame_bytes;
    Ok(())
}

#[cfg(any(test, feature = "internal-test-provider"))]
fn stored_frame(
    state: &RepositoryStateV1,
    result_id: ResultId,
    locator: EncryptedCoreResultFrameLocatorV1,
) -> Result<&Vec<u8>, EncryptedCoreResultRepositoryErrorV1> {
    let segment_index = usize::try_from(locator.segment_sequence())
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameNotFound)?;
    let frame_index = usize::try_from(locator.segment_frame_sequence())
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameNotFound)?;
    state
        .entries
        .get(&result_id)
        .and_then(|result| result.segments.get(segment_index))
        .and_then(|segment| segment.encoded_frames.get(frame_index))
        .ok_or(EncryptedCoreResultRepositoryErrorV1::FrameNotFound)
}

#[cfg(any(test, feature = "internal-test-provider"))]
fn stored_frame_mut(
    state: &mut RepositoryStateV1,
    result_id: ResultId,
    locator: EncryptedCoreResultFrameLocatorV1,
) -> Result<&mut Vec<u8>, EncryptedCoreResultRepositoryErrorV1> {
    let segment_index = usize::try_from(locator.segment_sequence())
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameNotFound)?;
    let frame_index = usize::try_from(locator.segment_frame_sequence())
        .map_err(|_| EncryptedCoreResultRepositoryErrorV1::FrameNotFound)?;
    state
        .entries
        .get_mut(&result_id)
        .and_then(|result| result.segments.get_mut(segment_index))
        .and_then(|segment| segment.encoded_frames.get_mut(frame_index))
        .ok_or(EncryptedCoreResultRepositoryErrorV1::FrameNotFound)
}
