//! Bounded result storage, read-only expansion, and the key-provider boundary
//! for Evidentrail.
//!
//! The primary result backend is explicitly memory-only: authorized evidence
//! remains plaintext in process memory and is never written to disk. A separate
//! transactional in-memory repository exercises authority-bound frame and
//! typed core-manifest encryption, repository-derived event indexing, exact
//! authenticated event expansion, key-provider seal binding, and a bounded
//! canonical sealed-ciphertext export/import substrate without making it a
//! complete filesystem backend. The V2 Unix durable repository implements the
//! four-state lifecycle, batch-level sync barriers, independently encrypted
//! event frames, authenticated indexes, create-only publication, shared read
//! leases, exclusive destruction, and authority/filesystem reconciliation. It
//! is generic over `KeyAuthorityV2`; production durable mode must inject a
//! Keychain-backed authority. `ProcessKeyAuthorityV2` is conformance-only and
//! is not a rollback anchor. The older V1 APIs remain readable for compatibility.
//! Separately, a ciphertext-only filesystem
//! substrate can issue ordered file/directory sync barriers, publish a
//! create-only canonical name, strictly read it back, and conservatively
//! quarantine synthetic crash states. That boundary does not claim
//! sudden-power-loss durability, rollback prevention, authenticated recovery,
//! or product publication.
//! The state-oriented key-provider contract and pure encrypted key-record
//! handling do not make a filesystem, Keychain, durability, recovery, or
//! durable-ack claim. The in-memory provider used to exercise that contract is
//! unavailable unless tests or the non-default `internal-test-provider` feature
//! explicitly compile it.
//! Rollback protection trusts the external authority. Rollback of the OS
//! Keychain itself is outside the V1/V2 threat model. Plaintext/key zeroization
//! is best-effort memory hygiene and cannot erase allocator copies, kernel
//! buffers, caches, or swap.
//! This layer enforces whole-event count and byte bounds. Canonical rendered
//! token bounds belong to the later evidence renderer and must pass before an
//! expansion is returned through the product API.

mod alias_manifest;
#[cfg(unix)]
mod authenticated_restart;
#[cfg(unix)]
mod durable_repository_v2;
mod encrypted_core_repository;
#[cfg(any(test, feature = "internal-test-provider"))]
mod ephemeral_key_provider;
#[cfg(unix)]
mod filesystem_bundle;
mod key_authority_v2;
mod key_provider;
mod memory;
mod sealed_bundle;

pub use alias_manifest::{
    DISPLAYED_ALIAS_MANIFEST_ENTRY_HEADER_BYTES_V1, DISPLAYED_ALIAS_MANIFEST_HEADER_BYTES_V1,
    DISPLAYED_ALIAS_MANIFEST_SCHEMA_V1, DISPLAYED_ALIAS_MANIFEST_VERSION_V1,
    DisplayedAliasManifestEntryV1, DisplayedAliasManifestErrorV1, DisplayedAliasManifestV1,
};
#[cfg(unix)]
pub use authenticated_restart::{
    AuthenticatedFilesystemRecoveryDispositionV1, AuthenticatedFilesystemRecoveryPublicationV1,
    AuthenticatedFilesystemRestartCoordinatorV1, AuthenticatedFilesystemRestartErrorV1,
    RecoveredExactAliasResultV1, RecoveredProductAliasExpansionV1,
};
#[cfg(unix)]
pub use durable_repository_v2::{
    BatchCommitInputV2, CREATING_RECOVERY_GRACE_NANOS_V2, DataCommitInputV2, DurableBatchCommitV2,
    DurableEventAcknowledgementV2, DurableEventInputV2, DurableExpansionV2,
    DurableRepositoryErrorV2, DurableRepositoryFaultInjectorV2, DurableRepositoryFaultPointV2,
    DurableResultRepositoryV2, MAX_DURABLE_BATCH_EVENTS_V2, MAX_DURABLE_EXPANSION_BYTES_V2,
    MAX_DURABLE_EXPANSION_EVENTS_V2, NoDurableRepositoryFaultsV2, OpenedDurableEventV2,
    RecoveryDispositionV2, RecoveryEntryV2, RecoveryReportV2, SealInputV2,
};
pub use encrypted_core_repository::{
    EncryptedCoreResultDestroyOutcomeV1, EncryptedCoreResultEventPublicationV1,
    EncryptedCoreResultFrameLocatorV1, EncryptedCoreResultFramePublicationV1,
    EncryptedCoreResultPublicationV1, EncryptedCoreResultRepositoryErrorV1,
    MAX_MEMORY_ENCRYPTED_CORE_FRAME_BYTES_V1, MAX_MEMORY_ENCRYPTED_CORE_FRAMES_V1,
    MAX_MEMORY_ENCRYPTED_CORE_RESULTS_V1, MAX_MEMORY_ENCRYPTED_CORE_SEGMENTS_V1,
    MemoryEncryptedCoreResultRepositoryV1, OpenedEncryptedCoreResultEventV1,
    OpenedEncryptedCoreResultFrameV1,
};
#[cfg(any(test, feature = "internal-test-provider"))]
pub use ephemeral_key_provider::{EphemeralKeyProviderV1, MAX_EPHEMERAL_KEY_RECORDS_V1};
#[cfg(all(unix, any(test, feature = "internal-test-provider")))]
pub use filesystem_bundle::{FilesystemBundleFaultPointV1, FilesystemBundleOperationV1};
#[cfg(unix)]
pub use filesystem_bundle::{
    FilesystemBundlePublicationV1, FilesystemBundleRecoveryClassificationV1,
    FilesystemBundleRecoveryEntryV1, FilesystemBundleRecoveryReportV1,
    FilesystemSealedBundleErrorV1, FilesystemSealedBundleStoreV1,
    MAX_FILESYSTEM_BUNDLE_DIRECTORY_ENTRIES_V1, sealed_bundle_filename_v1,
    sealed_bundle_temporary_filename_v1,
};
pub use key_authority_v2::{
    AuthorityDestroyOutcomeV2, KeyAuthorityErrorV2, KeyAuthorityV2, ProcessKeyAuthorityV2,
};
pub use key_provider::{
    CreatingKeyContextV1, ExpectedKeyContextV1, KeyContextErrorV1, KeyDestroyOutcomeV1,
    KeyProviderErrorV1, KeyProviderV1, KeyRecordListStateV1, KeyRecordMetadataV1,
    MAX_SNAPSHOT_OBJECT_NONCES_PER_RESULT_V1, OpenedResultKeyV1,
};
pub use memory::{
    AliasExpansionRequestV1, DEFAULT_RESULT_TTL_NANOS, EvidenceAliasV1, ExpandedEventV1,
    ExpansionLimitV1, ExpansionRequestV1, ExpansionResponseV1, MAX_EXPANSION_BYTES,
    MAX_EXPANSION_EVENTS, MemoryResultStore, PreparedPacketReferencesV1, RegisteredResultV1,
    ResultStoreError,
};
pub use sealed_bundle::{
    MAX_SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_BYTES_V1, SEALED_BUNDLE_ORIGIN_V1,
    SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_FRAME_DESCRIPTOR_BYTES_V1,
    SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_HEADER_BYTES_V1,
    SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_OBJECT_KIND_V1,
    SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_SEGMENT_DESCRIPTOR_BYTES_V1,
    SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_VERSION_V1, SealedEncryptedCoreResultBundleErrorV1,
    SealedEncryptedCoreResultBundleV1,
};
