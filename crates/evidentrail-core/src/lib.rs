//! Model-independent evidence integrity primitives for Evidentrail.
//!
//! `LedgerBuilder` is the sole raw-envelope consumer. It applies an explicit
//! policy before hashing or persistence, seals an exhaustive acquisition
//! receipt, and exposes only authorized immutable events. Presentation and
//! atomic-block reconciliation remain separate downstream accounting layers.

mod ack;
mod block;
mod coverage;
mod expansion;
mod hash;
mod ledger;
mod passthrough;
mod reference;
mod result_status;
mod transformation;

pub use ack::{
    PreparedSinkAckExpectation, SinkAckVerificationError, expected_source_record_id,
    verify_sink_ack_binding,
};
pub use block::{
    BlockAssignment, BlockExpansion, BlockIndex, BlockLookupError, BlockReconciliationError,
    EventBlock,
};
pub use evidentrail_schema::{
    AcknowledgedCounts, AcquisitionCounts, AcquisitionOutcome, AcquisitionReceipt,
    AcquisitionReceiptId, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    BlockConfidence, BlockId, BlockState, CapKind, CapUsage, CompletenessProof, ContentHash,
    EncodingHint, EnvelopeConstructionError, EnvelopeOrdering, EnvelopeTimestamps, EventId,
    EvidenceReferenceId, ExactnessBasis, FetchBoundaries, FetchCompleteness, FetchCompletion,
    FetchConstructionError, FetchErrorCode, FetchIdentity, FetchPartialReason, FetchPartialReasons,
    FetchTiming, FetchUnknownReason, FramingPolicy, HighWaterMark, LaneKey, LaneSequence,
    MonotonicTimestampNanos, NativeEventId, NativeMetadata, NativeMetadataField,
    NativeMetadataValue, PartialReason, PartialReasons, PatternId, PlanDigest, PlanId,
    PolicyDigest, PresentationCounts, PresentationDisposition, PresentationReceiptId,
    ProviderAttestationConstructionError, ProviderAttestationOriginV1,
    ProviderAttestationScopeDigestV1, ProviderAttestationValueV1, ProviderAttestationsV1,
    ProviderAttestedCorrelationV1, ProviderAttestedRelationKindV1, ProviderCompleteness,
    QuestionDigest, RawEnvelopeIdentityV1, RawEnvelopeV1, RawTimestamp, RecordBytes,
    RecordFormatHint, RecordFragmentReason, RecordHints, RecordState, ResultId, RetrievalId,
    SinkAck, SourceCursor, SourceIdentityDigest, SourceMember, SourceRecordId, SourceStream,
    SourceTimestamp, TransformationReceiptId, UnixTimestampNanos, UnknownCompletenessReason,
};
pub use coverage::{
    PresentationAssignment, PresentationReceipt, PresentationReceiptEntry,
    PresentationReconciliationError,
};
pub use expansion::{
    ExpandedEventV1, ExpansionLimitV1, ExpansionRequestV1, ExpansionResponseV1,
    MAX_EXPANSION_BYTES, MAX_EXPANSION_EVENTS, ResultStoreError, expand_retained_result_v1,
};
pub use hash::{derive_question_digest_v1, derive_source_exact_event_id_v1};
pub use ledger::{
    CheckedSealedLedgerViewV1, DeterministicPolicy, EnvelopeSink, Event, EventLedger, Expansion,
    LaneExpansion, LedgerBuildError, LedgerBuilder, LedgerIntegrityErrorV1, LedgerLookupError,
    PolicyAuthorization, checked_sealed_ledger_import_v1,
};
pub use passthrough::{
    PassthroughDecision, PassthroughSelection, PassthroughSelectionError, WholeRenderAssessmentV1,
    select_whole_render_passthrough,
};
pub use reference::{
    EvidenceReferenceConstructionError, EvidenceReferenceUnavailable, EvidenceReferenceV1,
    EvidenceTargetRef, ExpansionRelationV1, MAX_EVIDENCE_REFERENCE_TARGETS,
};
pub use result_status::{
    NeedsMoreReasonV1, RESULT_STATUS_CONTRACT_VERSION_V1, ResultStatusConstructionError,
    ResultStatusV1, SelectionStateV1,
};
pub use transformation::{
    ByteRangeReplacementV1, PreparedTransformationReceiptV1, TransformationReceiptErrorV1,
    TransformationReceiptV1,
};
