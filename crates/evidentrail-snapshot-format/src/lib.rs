//! Internal authenticated snapshot-format and crypto-material primitives for ADR 0004.
//!
//! This crate performs no filesystem, durability, recovery, or Keychain I/O.
//! It does define the fixed V2 external-authority record and the pure
//! `OPEN -> DATA_COMMITTED -> SEALED -> PUBLISHED` transition rules used by a
//! provider, plus independently authenticated V2 frames, event indexes, and
//! data/final manifests. It also provides in-memory entropy-backed result material and
//! result-scoped key derivation plus pure DEK-wrap and seal-binding AEAD
//! envelopes, fixed outer key-record and public cleanup-hint codecs, the pure
//! segment-catalog, event-expansion-index, source-outcome-table, and acquisition
//! completion components of a future encrypted manifest, their canonical core
//! bundle, the pure result/source/receipt authority-binding record around that
//! bundle, its typed in-memory outer-manifest AEAD integration, the stronger
//! result/source/receipt-bound frame AEAD primitive used by the memory
//! repository, and in-memory transition rules. These primitives are not a
//! complete encrypted manifest, result-key seal, verified persisted frame
//! chain, or sealed-result representation.
//! It provides no provider implementation or durable acknowledgment. V2 nonce
//! ranges are pure values here; atomic reservation belongs to the external
//! authority implementation in `evidentrail-store`.

mod acquisition_completion;
mod core_components;
mod core_result_frame;
mod core_result_manifest;
mod core_result_payload;
mod crypto;
mod error;
mod event_index;
mod event_index_v2;
mod frame_v2;
mod journal_v2;
mod key_envelope;
mod key_hierarchy;
mod lifecycle;
mod manifest;
mod material;
mod public_hint;
mod repository_manifest;
mod result_key_record;
mod segment_catalog;
mod source_outcome;
mod types;

pub use acquisition_completion::{
    ACQUISITION_COMPLETION_CAP_ENTRY_BYTES_V1, ACQUISITION_COMPLETION_CODE_ENTRY_BYTES_V1,
    ACQUISITION_COMPLETION_HEADER_BYTES_V1, ACQUISITION_COMPLETION_HIGH_WATER_PREFIX_BYTES_V1,
    ACQUISITION_COMPLETION_OBJECT_KIND_V1, ACQUISITION_COMPLETION_SCHEMA_V1,
    ACQUISITION_COMPLETION_VERSION_V1, AcquisitionCompletionRecordErrorV1,
    AcquisitionCompletionRecordV1, MAX_ACQUISITION_ADAPTER_FIELD_BYTES_V1,
    MAX_ACQUISITION_CAP_USAGES_V1, MAX_ACQUISITION_CURSOR_BYTES_V1, MAX_ACQUISITION_ERROR_CODES_V1,
    MAX_ACQUISITION_HIGH_WATER_MARKS_V1, MAX_ACQUISITION_PARTIAL_REASONS_V1,
    MAX_ACQUISITION_SOURCE_MEMBER_BYTES_V1, MAX_ENCODED_ACQUISITION_COMPLETION_BYTES_V1,
};
pub use core_components::{
    CORE_MANIFEST_COMPONENT_COUNT_V1, CORE_MANIFEST_COMPONENT_DESCRIPTOR_BYTES_V1,
    CORE_MANIFEST_COMPONENT_DIGEST_BYTES_V1, CORE_MANIFEST_COMPONENTS_BASE_HEADER_BYTES_V1,
    CORE_MANIFEST_COMPONENTS_DIGEST_BYTES_V1, CORE_MANIFEST_COMPONENTS_DIGEST_DOMAIN_V1,
    CORE_MANIFEST_COMPONENTS_HEADER_BYTES_V1, CORE_MANIFEST_COMPONENTS_OBJECT_KIND_V1,
    CORE_MANIFEST_COMPONENTS_SCHEMA_V1, CORE_MANIFEST_COMPONENTS_VERSION_V1,
    CoreManifestComponentDigestV1, CoreManifestComponentKindV1, CoreManifestComponentsDigestV1,
    CoreManifestComponentsErrorV1, CoreManifestComponentsV1,
    MAX_ENCODED_CORE_MANIFEST_COMPONENTS_BYTES_V1, derive_core_manifest_components_digest_v1,
};
pub use core_result_frame::{
    CORE_RESULT_FRAME_AAD_BYTES_V1, CORE_RESULT_FRAME_AAD_DOMAIN_V1,
    CORE_RESULT_FRAME_PAYLOAD_SCHEMA_V1, CoreResultFrameAuthorityV1, CoreResultFrameErrorV1,
    canonical_core_result_frame_aad_v1, open_core_result_frame_v1, seal_core_result_frame_v1,
};
pub use core_result_manifest::{
    CORE_RESULT_MANIFEST_DIGEST_BYTES_V1, CORE_RESULT_MANIFEST_DIGEST_DOMAIN_V1,
    CORE_RESULT_MANIFEST_HEADER_BYTES_V1, CORE_RESULT_MANIFEST_OBJECT_KIND_V1,
    CORE_RESULT_MANIFEST_SCHEMA_V1, CORE_RESULT_MANIFEST_VERSION_V1, CoreResultManifestDigestV1,
    CoreResultManifestErrorV1, CoreResultManifestV1, MAX_CORE_RESULT_MANIFEST_COMPONENTS_BYTES_V1,
    MAX_ENCODED_CORE_RESULT_MANIFEST_BYTES_V1,
};
pub use core_result_payload::{
    CORE_RESULT_MANIFEST_PAYLOAD_SCHEMA_V1, CoreResultManifestSealContextV1,
    CoreResultPayloadErrorV1, ExpectedCoreResultManifestContextV1, OpenedCoreResultManifestV1,
    SealedCoreResultManifestV1, open_core_result_manifest_v1, seal_core_result_manifest_v1,
};
pub use crypto::{
    FRAME_AAD_BYTES_V1, FRAME_AAD_DOMAIN_V1, FrameChainV1, OpenedFrameV1, SealedFrameV1,
    canonical_frame_aad_v1, open_frame_v1, seal_frame_v1, segment_start_commitment_v1,
};
pub use error::SnapshotFormatErrorV1;
pub use event_index::{
    AuthorizedByteRangeV1, EVENT_EXPANSION_INDEX_ENTRY_BYTES_V1,
    EVENT_EXPANSION_INDEX_HEADER_BYTES_V1, EVENT_EXPANSION_INDEX_OBJECT_KIND_V1,
    EVENT_EXPANSION_INDEX_SCHEMA_V1, EVENT_EXPANSION_INDEX_VERSION_V1,
    EVENT_EXPANSION_POST_POLICY_KIND_V1, EVENT_EXPANSION_SOURCE_EXACT_KIND_V1,
    EventExpansionIndexEntryV1, EventExpansionIndexErrorV1, EventExpansionIndexV1,
    EventFrameLocatorV1, MAX_ENCODED_EVENT_EXPANSION_INDEX_BYTES_V1,
    MAX_EVENT_EXPANSION_INDEX_ENTRIES_V1, SEGMENT_CATALOG_DIGEST_BYTES_V1, SegmentCatalogDigestV1,
    derive_segment_catalog_digest_v1,
};
pub use event_index_v2::{
    AUTHENTICATED_EVENT_INDEX_DIRECTORY_HEADER_BYTES_V2, AUTHENTICATED_EVENT_INDEX_ENTRY_BYTES_V2,
    AUTHENTICATED_EVENT_INDEX_HEADER_BYTES_V2, AUTHENTICATED_EVENT_INDEX_SHARD_DESCRIPTOR_BYTES_V2,
    AUTHENTICATED_EVENT_INDEX_VERSION_V2, AuthenticatedEventIndexDirectoryV2,
    AuthenticatedEventIndexEntryV2, AuthenticatedEventIndexErrorV2,
    AuthenticatedEventIndexShardDescriptorV2, AuthenticatedEventIndexV2, EventFrameLocatorV2,
    MAX_AUTHENTICATED_EVENT_INDEX_ENTRIES_V2, MAX_AUTHENTICATED_EVENT_INDEX_SHARD_ENTRIES_V2,
    MAX_AUTHENTICATED_EVENT_INDEX_SHARDS_V2, derive_authenticated_event_index_digest_v2,
};
pub use frame_v2::{
    FRAME_HEADER_BYTES_V2, FrameHeaderV2, MAX_ENCODED_FRAME_BYTES_V2, OpenedFrameV2,
    SEGMENT_HEADER_BYTES_V2, SNAPSHOT_FORMAT_VERSION_V2, SealedFrameV2, SegmentHeaderV2,
    SnapshotFrameErrorV2, SnapshotObjectKindV2, canonical_frame_aad_v2, open_frame_v2,
    open_frame_v2_with_additional_aad, seal_frame_v2, seal_frame_v2_with_additional_aad,
};
pub use journal_v2::{
    DURABLE_ACKNOWLEDGEMENT_BYTES_V2, DURABLE_BATCH_JOURNAL_HEADER_BYTES_V2,
    DURABLE_BATCH_JOURNAL_VERSION_V2, DurableAcknowledgementV2, DurableBatchJournalErrorV2,
    DurableBatchJournalV2, MAX_DURABLE_ACKNOWLEDGEMENTS_V2,
};
pub use key_envelope::{
    DEK_WRAP_AAD_BYTES_V1, DEK_WRAP_AAD_DOMAIN_V1, DekWrapNonceV1, KEY_ENVELOPE_CONTEXT_BYTES_V1,
    KEY_ENVELOPE_NONCE_BYTES_V1, KEY_ENVELOPE_TAG_BYTES_V1, KEY_RECORD_VERSION_V1,
    KeyEnvelopeContextV1, KeyEnvelopeErrorV1, MAX_SEGMENTS_PER_RESULT_V1,
    MAX_TOTAL_FRAMES_PER_RESULT_V1, OpenedSealBindingV1, SEAL_BINDING_AAD_BYTES_V1,
    SEAL_BINDING_AAD_DOMAIN_V1, SEAL_BINDING_BYTES_V1, SEALED_SEAL_BINDING_BYTES_V1,
    SealBindingNonceV1, SealBindingV1, SealedSealBindingV1, WRAPPED_RESULT_DEK_BYTES_V1,
    WrappedResultDekV1, canonical_dek_wrap_aad_v1, canonical_seal_binding_aad_v1,
    open_seal_binding_v1, open_wrapped_result_dek_v1, seal_binding_v1, wrap_result_dek_v1,
};
pub use key_hierarchy::{
    DEK_WRAP_KEY_INFO_BYTES_V1, DEK_WRAP_KEY_INFO_DOMAIN_V1, DERIVED_KEY_BYTES_V1, DekWrapKeyV1,
    DekWrapKeyViewV1, DerivedResultKeysV1, KeyHierarchyErrorV1, ROOT_KEK_BYTES_V1,
    ROOT_KEY_VERSION_BYTES_V1, RootKekV1, RootKeyVersionV1, SEAL_KEY_INFO_BYTES_V1,
    SEAL_KEY_INFO_DOMAIN_V1, SealKeyV1, SealKeyViewV1, canonical_dek_wrap_key_info_v1,
    canonical_seal_key_info_v1,
};
pub use lifecycle::{
    BuildContextDigestsV1, LIFECYCLE_DIGEST_BYTES_V1, LifecycleDigestV1, LifecycleRecordErrorV1,
    LifecycleTransitionV1, NonceReservationV1, OPERATION_ID_BYTES_V1, OperationIdV1,
    RESULT_AUTHORITY_RECORD_BYTES_V2, RESULT_AUTHORITY_RECORD_VERSION_V2,
    RESULT_NONCE_PREFIX_BYTES_V1, ResultAuthorityRecordV2, ResultLifecycleStateV1,
    ResultNoncePrefixV1, SealCommitmentsV1, derive_lifecycle_digest_v1,
};
pub use manifest::{
    MANIFEST_AAD_BYTES_V1, MANIFEST_AAD_DOMAIN_V1, MANIFEST_COMMITMENT_BYTES_V1,
    MANIFEST_HEADER_BYTES_V1, MANIFEST_NONCE_BYTES_V1, MANIFEST_OBJECT_KIND_V1,
    MANIFEST_TAG_BYTES_V1, MAX_ENCODED_MANIFEST_BYTES_V1, MAX_MANIFEST_CIPHERTEXT_BYTES_V1,
    MAX_MANIFEST_PLAINTEXT_BYTES_V1, ManifestCommitmentV1, ManifestHeaderV1, ManifestNonceV1,
    OpenedManifestV1, SealedManifestV1, canonical_manifest_aad_v1, open_manifest_v1,
    seal_manifest_v1,
};
pub use material::{
    EntropySourceFailureV1, EntropySourceV1, FrameKeyViewV1, ManifestKeyViewV1, OsEntropyV1,
    RESULT_DEK_BYTES_V1, ResultCryptoMaterialV1, ResultDekV1,
};
pub use public_hint::{
    PUBLIC_CLEANUP_HINT_BYTES_V1, PUBLIC_CLEANUP_HINT_VERSION_V1, PublicCleanupHintErrorV1,
    PublicCleanupHintV1,
};
pub use repository_manifest::{
    DATA_MANIFEST_BYTES_V2, DataManifestV2, FINAL_MANIFEST_BYTES_V2, FinalManifestV2,
    REPOSITORY_MANIFEST_VERSION_V2, RepositoryManifestErrorV2,
};
pub use result_key_record::{
    RESULT_KEY_RECORD_BYTES_V1, RESULT_KEY_RECORD_CREATING_STATE_V1,
    RESULT_KEY_RECORD_SEALED_STATE_V1, ResultKeyRecordErrorV1, ResultKeyRecordStateV1,
    ResultKeyRecordV1, ResultKeySealTransitionV1,
};
pub use segment_catalog::{
    MAX_ENCODED_SEGMENT_CATALOG_BYTES_V1, MAX_SEGMENT_CIPHERTEXT_BYTES_V1,
    MAX_SEGMENT_ENCODED_BYTES_V1, MAX_TOTAL_SEGMENT_CIPHERTEXT_BYTES_V1,
    MAX_TOTAL_SEGMENT_ENCODED_BYTES_V1, SEGMENT_CATALOG_ENTRY_BYTES_V1,
    SEGMENT_CATALOG_HEADER_BYTES_V1, SEGMENT_CATALOG_SCHEMA_V1, SEGMENT_CATALOG_VERSION_V1,
    SEGMENT_DIGEST_BYTES_V1, SegmentCatalogEntryV1, SegmentCatalogErrorV1, SegmentCatalogV1,
    SegmentDigestV1, derive_segment_digest_v1,
};
pub use source_outcome::{
    EVENT_EXPANSION_INDEX_DIGEST_BYTES_V1, EventExpansionIndexDigestV1,
    MAX_ENCODED_SOURCE_OUTCOME_TABLE_BYTES_V1, MAX_SOURCE_OUTCOME_TABLE_ENTRIES_V1,
    SOURCE_OUTCOME_OMITTED_BY_POLICY_KIND_V1, SOURCE_OUTCOME_POST_POLICY_KIND_V1,
    SOURCE_OUTCOME_SOURCE_EXACT_KIND_V1, SOURCE_OUTCOME_TABLE_ENTRY_BYTES_V1,
    SOURCE_OUTCOME_TABLE_HEADER_BYTES_V1, SOURCE_OUTCOME_TABLE_OBJECT_KIND_V1,
    SOURCE_OUTCOME_TABLE_SCHEMA_V1, SOURCE_OUTCOME_TABLE_VERSION_V1, SourceOutcomeTableEntryV1,
    SourceOutcomeTableErrorV1, SourceOutcomeTableV1, derive_event_expansion_index_digest_v1,
};
pub use types::{
    FRAME_COMMITMENT_BYTES_V1, FRAME_HEADER_BYTES_V1, FRAME_HEADER_VERSION_V1,
    FRAME_NONCE_BYTES_V1, FRAME_TAG_BYTES_V1, FrameCommitmentV1, FrameHeaderV1, FrameNonceV1,
    FrameObjectKindV1, MAX_ENCODED_FRAME_BYTES_V1, MAX_FRAME_CIPHERTEXT_BYTES_V1,
    MAX_FRAME_PLAINTEXT_BYTES_V1, MAX_FRAMES_PER_SEGMENT_V1, OUTER_VERSION_V1,
    SEGMENT_HEADER_BYTES_V1, SegmentHeaderV1, XCHACHA20_POLY1305_SUITE_ID_V1,
};
