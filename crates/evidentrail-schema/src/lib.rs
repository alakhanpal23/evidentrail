//! Dependency-free shared contract types for Evidentrail.
//!
//! This crate contains stable data vocabulary, not behavior that can bless an
//! invalid evidence packet. `evidentrail-core` computes identities, owns byte-exact
//! events, and constructs coverage receipts only after reconciliation.

mod acquisition;
mod block;
pub mod bounds;
mod coverage;
mod fetch;
mod id;
mod local_file_binding;
mod provenance;
mod provider_attestation;
mod query_plan;
mod raw_envelope;
mod source_identity;

pub use acquisition::{
    AcquisitionCounts, AcquisitionOutcome, AcquisitionOutcomeAssignment, AcquisitionReceipt,
    AcquisitionReceiptEntry, AcquisitionReceiptError, ExactnessBasis,
};
pub use block::{BlockConfidence, BlockState, FramingPolicy};
pub use coverage::{PresentationCounts, PresentationDisposition};
pub use fetch::{
    AcknowledgedCounts, AdapterOutcome, AttemptCounts, CapKind, CapUsage, CompletenessProof,
    FetchBoundaries, FetchCompleteness, FetchCompletion, FetchConstructionError, FetchErrorCode,
    FetchIdentity, FetchPartialReason, FetchPartialReasons, FetchTiming, FetchUnknownReason,
    HighWaterMark,
};
pub use id::{
    AcquisitionReceiptId, ArtifactDigest, BindingDigest, BindingId, BlockId, ContentHash, EventId,
    EvidenceReferenceId, InternalPathPolicyDigest, LocalFileCertificationProfileDigest, PatternId,
    PlanDigest, PlanId, PolicyDigest, PresentationReceiptId, QuestionDigest,
    RepositoryIdentityDigest, ResultId, RetrievalId, SourceIdentityDigest, SourceRecordId,
    TransformationReceiptId,
};
pub use local_file_binding::{
    ApprovedLocalFileBindingConstructionError, ApprovedLocalFileBindingMaterialV1,
    ApprovedLocalFileLocatorAuthorityV1,
};
pub use provenance::{
    PartialReason, PartialReasons, ProviderCompleteness, UnknownCompletenessReason,
};
pub use provider_attestation::{
    ProviderAttestationConstructionError, ProviderAttestationOriginV1,
    ProviderAttestationScopeDigestV1, ProviderAttestationValueV1, ProviderAttestationsV1,
    ProviderAttestedCorrelationV1, ProviderAttestedRelationKindV1,
};
pub use query_plan::{
    LOCAL_FILE_ADAPTER_KIND_V1, LOCAL_FILE_ADAPTER_VERSION_V1, LocalFileArchitectureV1,
    LocalFileDeadlineModelV1, LocalFileFilesystemV1, LocalFileOperatingSystemV1,
    LocalFileOrderingV1, LocalFilePlanCapsConstructionError, LocalFilePlanCapsV1,
    LocalFileQueryPlanConstructionError, LocalFileQueryPlanMaterialV1,
    LocalFileRuntimeProfileConstructionError, LocalFileRuntimeProfileV1, LocalFileSnapshotModeV1,
    UnixFileObjectIdV1, UnixFileSnapshotConstructionError, UnixFileSnapshotV1, UnixFileTypeV1,
    UnixLocalFileLocatorConstructionError, UnixLocalFileLocatorV1,
};
pub use raw_envelope::{
    AcquisitionSequence, AdapterIdentity, EncodingHint, EnvelopeConstructionError,
    EnvelopeOrdering, EnvelopeTimestamps, LaneKey, LaneSequence, MonotonicTimestampNanos,
    NativeEventId, NativeMetadata, NativeMetadataField, NativeMetadataValue, RawEnvelopeIdentityV1,
    RawEnvelopeV1, RawTimestamp, RecordBytes, RecordFormatHint, RecordFragmentReason, RecordHints,
    RecordState, SinkAck, SourceCursor, SourceMember, SourceStream, SourceTimestamp,
    UnixTimestampNanos,
};
pub use source_identity::{
    BindingRefConstructionError, BindingRefV1, IdentityProofKindV1,
    SourceIdentityConstructionError, SourceIdentityV1,
};
