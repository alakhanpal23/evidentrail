use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;

use evidentrail_schema::{
    AcquisitionOutcome, AcquisitionOutcomeAssignment, AcquisitionReceipt, AcquisitionReceiptError,
    AcquisitionReceiptId, AcquisitionSequence, AdapterIdentity, ContentHash, EnvelopeTimestamps,
    EventId, ExactnessBasis, FetchCompletion, FetchIdentity, LaneKey, LaneSequence, NativeEventId,
    NativeMetadata, PlanDigest, PlanId, PolicyDigest, ProviderAttestationsV1, RawEnvelopeV1,
    RecordBytes, RecordHints, RecordState, RetrievalId, SinkAck, SourceCursor,
    SourceIdentityDigest, SourceRecordId, TransformationReceiptId,
};

use crate::ack::expected_source_record_id;
use crate::hash::{acquisition_receipt_id, authorized_content_hash, event_id};
use crate::transformation::{PreparedTransformationReceiptV1, TransformationReceiptV1};

/// Explicit result of applying a deterministic local policy to one envelope.
#[derive(Clone, PartialEq, Eq)]
pub enum PolicyAuthorization {
    /// Retain the exact source payload and source-defined terminator.
    SourceExact,
    /// Retain only the supplied deterministic post-policy representation.
    PostPolicy {
        authorized_record: RecordBytes,
        policy_digest: PolicyDigest,
        transformation_receipt_id: TransformationReceiptId,
    },
    /// Constructor-verified replacement receipt. The sink binds it to the
    /// resulting event and retains the sealed record in the ledger.
    PostPolicyReceipt {
        authorized_record: RecordBytes,
        transformation_receipt: PreparedTransformationReceiptV1,
    },
    /// Retain no payload and make no content-derived commitment.
    OmittedByPolicy { policy_digest: PolicyDigest },
}

impl PolicyAuthorization {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::SourceExact => "source_exact",
            Self::PostPolicy { .. } | Self::PostPolicyReceipt { .. } => "post_policy",
            Self::OmittedByPolicy { .. } => "omitted_by_policy",
        }
    }
}

impl fmt::Debug for PolicyAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolicyAuthorization")
            .field("code", &self.code())
            .finish()
    }
}

/// Policy evaluation runs inside the sole raw-envelope sink.
///
/// Implementations must be deterministic for the same envelope and policy
/// identity. Post-policy output must contain only the bytes authorized for
/// persistence.
pub trait DeterministicPolicy {
    fn authorize(&self, envelope: &RawEnvelopeV1) -> PolicyAuthorization;
}

/// Streaming boundary that acknowledges only durable policy outcomes.
pub trait EnvelopeSink {
    fn accept(&mut self, envelope: RawEnvelopeV1) -> Result<SinkAck, LedgerBuildError>;
}

/// An immutable authorized event in persisted order.
#[derive(Clone, PartialEq, Eq)]
pub struct Event {
    id: EventId,
    source_record_id: SourceRecordId,
    content_hash: ContentHash,
    exactness_basis: ExactnessBasis,
    ordinal: u64,
    acquisition_sequence: AcquisitionSequence,
    lane: LaneKey,
    lane_sequence: LaneSequence,
    raw: Arc<[u8]>,
    payload_len: usize,
    terminator_len: Option<usize>,
    native_event_id: Option<NativeEventId>,
    cursor: Option<SourceCursor>,
    record_state: RecordState,
    timestamps: EnvelopeTimestamps,
    metadata: Option<NativeMetadata>,
    provider_attestations: ProviderAttestationsV1,
    hints: RecordHints,
}

impl fmt::Debug for Event {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Event")
            .field("ordinal", &self.ordinal)
            .field("acquisition_sequence", &self.acquisition_sequence)
            .field("lane_sequence", &self.lane_sequence)
            .field("raw_bytes", &self.raw.len())
            .field("payload_bytes", &self.payload_len)
            .field("terminator_present", &self.terminator_len.is_some())
            .field("native_event_id_present", &self.native_event_id.is_some())
            .field("cursor_present", &self.cursor.is_some())
            .field("record_state", &self.record_state)
            .field("exactness_code", &self.exactness_basis.code())
            .field("timestamps", &self.timestamps)
            .field("metadata_present", &self.metadata.is_some())
            .field(
                "provider_attestation_count",
                &self.provider_attestations.len(),
            )
            .field("hints", &self.hints)
            .finish()
    }
}

impl Event {
    #[must_use]
    pub const fn id(&self) -> EventId {
        self.id
    }

    #[must_use]
    pub const fn source_record_id(&self) -> SourceRecordId {
        self.source_record_id
    }

    #[must_use]
    pub const fn content_hash(&self) -> ContentHash {
        self.content_hash
    }

    #[must_use]
    pub const fn exactness_basis(&self) -> ExactnessBasis {
        self.exactness_basis
    }

    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    #[must_use]
    pub const fn acquisition_sequence(&self) -> AcquisitionSequence {
        self.acquisition_sequence
    }

    #[must_use]
    pub const fn lane(&self) -> &LaneKey {
        &self.lane
    }

    #[must_use]
    pub const fn lane_sequence(&self) -> LaneSequence {
        self.lane_sequence
    }

    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.raw[..self.payload_len]
    }

    #[must_use]
    pub fn terminator(&self) -> Option<&[u8]> {
        self.terminator_len
            .map(|length| &self.raw[self.payload_len..self.payload_len + length])
    }

    #[must_use]
    pub const fn native_event_id(&self) -> Option<&NativeEventId> {
        self.native_event_id.as_ref()
    }

    #[must_use]
    pub const fn cursor(&self) -> Option<&SourceCursor> {
        self.cursor.as_ref()
    }

    #[must_use]
    pub const fn record_state(&self) -> RecordState {
        self.record_state
    }

    #[must_use]
    pub const fn timestamps(&self) -> &EnvelopeTimestamps {
        &self.timestamps
    }

    #[must_use]
    pub const fn metadata(&self) -> Option<&NativeMetadata> {
        self.metadata.as_ref()
    }

    #[must_use]
    pub const fn provider_attestations(&self) -> &ProviderAttestationsV1 {
        &self.provider_attestations
    }

    #[must_use]
    pub const fn hints(&self) -> RecordHints {
        self.hints
    }

    /// Verify bytes against the authorized-basis hash, never a pre-policy hash.
    #[must_use]
    pub fn content_matches(&self, candidate: &[u8]) -> bool {
        authorized_content_hash(candidate) == self.content_hash
    }
}

#[derive(PartialEq, Eq)]
pub enum LedgerBuildError {
    RetrievalMismatch,
    PlanIdMismatch,
    PlanDigestMismatch,
    AdapterMismatch,
    SourceIdentityMismatch,
    UnexpectedAcquisitionSequence { expected: u64, actual: u64 },
    UnexpectedLaneSequence { expected: u64, actual: u64 },
    AcquisitionSequenceOverflow,
    LaneSequenceOverflow,
    EventCountOverflow,
    ByteCountOverflow,
    SourceRecordIdCollision(SourceRecordId),
    EventIdCollision(EventId),
    TransformationReceiptCollision,
    CompletionIdentityMismatch,
    CompletionRecordCountMismatch,
    CompletionPayloadByteCountMismatch,
    CompletionSourceByteCountMismatch,
    CompleteWithFragment,
    AcquisitionReceiptInvalid(AcquisitionReceiptError),
}

impl LedgerBuildError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::RetrievalMismatch => "EVIDENTRAIL_LEDGER_RETRIEVAL_MISMATCH",
            Self::PlanIdMismatch => "EVIDENTRAIL_LEDGER_PLAN_ID_MISMATCH",
            Self::PlanDigestMismatch => "EVIDENTRAIL_LEDGER_PLAN_DIGEST_MISMATCH",
            Self::AdapterMismatch => "EVIDENTRAIL_LEDGER_ADAPTER_MISMATCH",
            Self::SourceIdentityMismatch => "EVIDENTRAIL_LEDGER_SOURCE_IDENTITY_MISMATCH",
            Self::UnexpectedAcquisitionSequence { .. } => {
                "EVIDENTRAIL_LEDGER_UNEXPECTED_ACQUISITION_SEQUENCE"
            }
            Self::UnexpectedLaneSequence { .. } => "EVIDENTRAIL_LEDGER_UNEXPECTED_LANE_SEQUENCE",
            Self::AcquisitionSequenceOverflow => "EVIDENTRAIL_LEDGER_ACQUISITION_SEQUENCE_OVERFLOW",
            Self::LaneSequenceOverflow => "EVIDENTRAIL_LEDGER_LANE_SEQUENCE_OVERFLOW",
            Self::EventCountOverflow => "EVIDENTRAIL_LEDGER_EVENT_COUNT_OVERFLOW",
            Self::ByteCountOverflow => "EVIDENTRAIL_LEDGER_BYTE_COUNT_OVERFLOW",
            Self::SourceRecordIdCollision(_) => "EVIDENTRAIL_LEDGER_SOURCE_RECORD_ID_COLLISION",
            Self::EventIdCollision(_) => "EVIDENTRAIL_LEDGER_EVENT_ID_COLLISION",
            Self::TransformationReceiptCollision => "EVIDENTRAIL_LEDGER_TRANSFORMATION_RECEIPT_COLLISION",
            Self::CompletionIdentityMismatch => "EVIDENTRAIL_LEDGER_COMPLETION_IDENTITY_MISMATCH",
            Self::CompletionRecordCountMismatch => "EVIDENTRAIL_LEDGER_COMPLETION_RECORD_COUNT_MISMATCH",
            Self::CompletionPayloadByteCountMismatch => {
                "EVIDENTRAIL_LEDGER_COMPLETION_PAYLOAD_BYTE_COUNT_MISMATCH"
            }
            Self::CompletionSourceByteCountMismatch => {
                "EVIDENTRAIL_LEDGER_COMPLETION_SOURCE_BYTE_COUNT_MISMATCH"
            }
            Self::CompleteWithFragment => "EVIDENTRAIL_LEDGER_COMPLETE_WITH_FRAGMENT",
            Self::AcquisitionReceiptInvalid(_) => "EVIDENTRAIL_LEDGER_ACQUISITION_RECEIPT_INVALID",
        }
    }
}

impl fmt::Debug for LedgerBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut summary = formatter.debug_struct("LedgerBuildError");
        summary.field("code", &self.code());
        match self {
            Self::UnexpectedAcquisitionSequence { expected, actual }
            | Self::UnexpectedLaneSequence { expected, actual } => {
                summary.field("expected", expected).field("actual", actual);
            }
            _ => {}
        }
        summary.finish()
    }
}

impl fmt::Display for LedgerBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for LedgerBuildError {}

#[derive(PartialEq, Eq)]
pub enum LedgerLookupError {
    UnknownEvent(EventId),
}

impl LedgerLookupError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnknownEvent(_) => "EVIDENTRAIL_LEDGER_UNKNOWN_EVENT",
        }
    }
}

impl fmt::Debug for LedgerLookupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LedgerLookupError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for LedgerLookupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for LedgerLookupError {}

/// Read-only neighborhood expansion around an exact event reference.
#[derive(Clone, Copy)]
pub struct Expansion<'a> {
    anchor: EventId,
    anchor_offset: usize,
    events: &'a [Event],
}

impl fmt::Debug for Expansion<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Expansion")
            .field("anchor_offset", &self.anchor_offset)
            .field("event_count", &self.events.len())
            .finish()
    }
}

impl<'a> Expansion<'a> {
    #[must_use]
    pub const fn anchor(&self) -> EventId {
        self.anchor
    }

    #[must_use]
    pub const fn anchor_offset(&self) -> usize {
        self.anchor_offset
    }

    #[must_use]
    pub const fn events(&self) -> &'a [Event] {
        self.events
    }
}

/// Mutable policy boundary that becomes an immutable ledger only after its
/// terminal fetch completion and acquisition receipt reconcile.
pub struct LedgerBuilder<P> {
    identity: FetchIdentity,
    source_identity_digest: SourceIdentityDigest,
    policy: P,
    next_acquisition_sequence: u64,
    next_lane_sequences: BTreeMap<LaneKey, u64>,
    source_record_ids: BTreeSet<SourceRecordId>,
    expected_source_records: Vec<SourceRecordId>,
    acquisition_assignments: Vec<AcquisitionOutcomeAssignment>,
    transformation_receipts: BTreeMap<TransformationReceiptId, TransformationReceiptV1>,
    events: Vec<Event>,
    positions: BTreeMap<EventId, usize>,
    acknowledged_records: u64,
    acknowledged_payload_bytes: u64,
    acknowledged_source_bytes: u64,
    saw_fragment: bool,
}

impl<P> fmt::Debug for LedgerBuilder<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LedgerBuilder")
            .field("acknowledged_records", &self.acknowledged_records)
            .field("persisted_events", &self.events.len())
            .field("lane_count", &self.next_lane_sequences.len())
            .field("saw_fragment", &self.saw_fragment)
            .finish()
    }
}

impl<P> LedgerBuilder<P>
where
    P: DeterministicPolicy,
{
    #[must_use]
    pub fn new(
        identity: FetchIdentity,
        source_identity_digest: SourceIdentityDigest,
        policy: P,
    ) -> Self {
        Self {
            identity,
            source_identity_digest,
            policy,
            next_acquisition_sequence: 0,
            next_lane_sequences: BTreeMap::new(),
            source_record_ids: BTreeSet::new(),
            expected_source_records: Vec::new(),
            acquisition_assignments: Vec::new(),
            transformation_receipts: BTreeMap::new(),
            events: Vec::new(),
            positions: BTreeMap::new(),
            acknowledged_records: 0,
            acknowledged_payload_bytes: 0,
            acknowledged_source_bytes: 0,
            saw_fragment: false,
        }
    }

    #[must_use]
    pub const fn identity(&self) -> &FetchIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn source_identity_digest(&self) -> SourceIdentityDigest {
        self.source_identity_digest
    }

    pub fn seal(self, completion: FetchCompletion) -> Result<EventLedger, LedgerBuildError> {
        if completion.identity() != &self.identity {
            return Err(LedgerBuildError::CompletionIdentityMismatch);
        }
        let acknowledged = completion.acknowledged();
        if acknowledged.records() != self.acknowledged_records {
            return Err(LedgerBuildError::CompletionRecordCountMismatch);
        }
        if acknowledged.payload_bytes() != self.acknowledged_payload_bytes {
            return Err(LedgerBuildError::CompletionPayloadByteCountMismatch);
        }
        if acknowledged.source_bytes() != self.acknowledged_source_bytes {
            return Err(LedgerBuildError::CompletionSourceByteCountMismatch);
        }
        if completion.provider_completeness().is_complete() && self.saw_fragment {
            return Err(LedgerBuildError::CompleteWithFragment);
        }

        let acquisition_receipt = AcquisitionReceipt::reconcile(
            self.identity.retrieval_id(),
            self.expected_source_records,
            self.acquisition_assignments,
        )
        .map_err(LedgerBuildError::AcquisitionReceiptInvalid)?;
        let acquisition_receipt_id = acquisition_receipt_id(&acquisition_receipt);
        let mut lane_positions = BTreeMap::<LaneKey, Vec<usize>>::new();
        for (position, event) in self.events.iter().enumerate() {
            lane_positions
                .entry(event.lane().clone())
                .or_default()
                .push(position);
        }
        Ok(EventLedger {
            retrieval_id: self.identity.retrieval_id(),
            plan_id: self.identity.plan_id(),
            plan_digest: self.identity.plan_digest(),
            source_identity_digest: self.source_identity_digest,
            adapter: self.identity.adapter().clone(),
            completion,
            acquisition_receipt_id,
            acquisition_receipt,
            transformation_receipts: self.transformation_receipts,
            events: self.events,
            positions: self.positions,
            lane_positions,
        })
    }

    fn validate_identity(&self, envelope: &RawEnvelopeV1) -> Result<(), LedgerBuildError> {
        let identity = envelope.identity();
        if identity.retrieval_id() != self.identity.retrieval_id() {
            return Err(LedgerBuildError::RetrievalMismatch);
        }
        if identity.plan_id() != self.identity.plan_id() {
            return Err(LedgerBuildError::PlanIdMismatch);
        }
        if identity.plan_digest() != self.identity.plan_digest() {
            return Err(LedgerBuildError::PlanDigestMismatch);
        }
        if identity.adapter() != self.identity.adapter() {
            return Err(LedgerBuildError::AdapterMismatch);
        }
        if identity.source_identity_digest() != self.source_identity_digest {
            return Err(LedgerBuildError::SourceIdentityMismatch);
        }
        Ok(())
    }
}

impl<P> EnvelopeSink for LedgerBuilder<P>
where
    P: DeterministicPolicy,
{
    fn accept(&mut self, envelope: RawEnvelopeV1) -> Result<SinkAck, LedgerBuildError> {
        self.validate_identity(&envelope)?;

        let actual_acquisition = envelope.ordering().acquisition_sequence().get();
        if actual_acquisition != self.next_acquisition_sequence {
            return Err(LedgerBuildError::UnexpectedAcquisitionSequence {
                expected: self.next_acquisition_sequence,
                actual: actual_acquisition,
            });
        }
        let next_acquisition = actual_acquisition
            .checked_add(1)
            .ok_or(LedgerBuildError::AcquisitionSequenceOverflow)?;

        let lane = envelope.ordering().lane().clone();
        let expected_lane = self.next_lane_sequences.get(&lane).copied().unwrap_or(0);
        let actual_lane = envelope.ordering().lane_sequence().get();
        if actual_lane != expected_lane {
            return Err(LedgerBuildError::UnexpectedLaneSequence {
                expected: expected_lane,
                actual: actual_lane,
            });
        }
        let next_lane = actual_lane
            .checked_add(1)
            .ok_or(LedgerBuildError::LaneSequenceOverflow)?;

        let payload_bytes = u64::try_from(envelope.record().payload_len())
            .map_err(|_| LedgerBuildError::ByteCountOverflow)?;
        let source_bytes = u64::try_from(envelope.record().source_len())
            .map_err(|_| LedgerBuildError::ByteCountOverflow)?;
        let acknowledged_records = self
            .acknowledged_records
            .checked_add(1)
            .ok_or(LedgerBuildError::EventCountOverflow)?;
        let acknowledged_payload_bytes = self
            .acknowledged_payload_bytes
            .checked_add(payload_bytes)
            .ok_or(LedgerBuildError::ByteCountOverflow)?;
        let acknowledged_source_bytes = self
            .acknowledged_source_bytes
            .checked_add(source_bytes)
            .ok_or(LedgerBuildError::ByteCountOverflow)?;

        let source_record_id = expected_source_record_id(&envelope);
        if self.source_record_ids.contains(&source_record_id) {
            return Err(LedgerBuildError::SourceRecordIdCollision(source_record_id));
        }

        let authorization = self.policy.authorize(&envelope);
        let (outcome, authorized_byte_count, event, transformation_receipt) = match authorization {
            PolicyAuthorization::SourceExact => self
                .persist_authorized(
                    &envelope,
                    envelope.record().clone(),
                    ExactnessBasis::SourceExact,
                    source_record_id,
                )?
                .with_receipt(None),
            PolicyAuthorization::PostPolicy {
                authorized_record,
                policy_digest,
                transformation_receipt_id,
            } => self
                .persist_authorized(
                    &envelope,
                    authorized_record,
                    ExactnessBasis::PostPolicy {
                        policy_digest,
                        transformation_receipt_id,
                    },
                    source_record_id,
                )?
                .with_receipt(None),
            PolicyAuthorization::PostPolicyReceipt {
                authorized_record,
                transformation_receipt,
            } => {
                let exactness = ExactnessBasis::PostPolicy {
                    policy_digest: transformation_receipt.policy_digest(),
                    transformation_receipt_id: transformation_receipt.id(),
                };
                let persisted = self.persist_authorized(
                    &envelope,
                    authorized_record,
                    exactness,
                    source_record_id,
                )?;
                let event_id = persisted
                    .2
                    .as_ref()
                    .expect("authorized persistence returns an event")
                    .id();
                persisted.with_receipt(Some(transformation_receipt.bind(event_id)))
            }
            PolicyAuthorization::OmittedByPolicy { policy_digest } => (
                AcquisitionOutcome::OmittedByPolicy { policy_digest },
                0,
                None,
                None,
            ),
        };

        if let Some(receipt) = transformation_receipt {
            if self
                .transformation_receipts
                .insert(receipt.id(), receipt)
                .is_some()
            {
                return Err(LedgerBuildError::TransformationReceiptCollision);
            }
        }

        if let Some(event) = event {
            self.positions.insert(event.id, self.events.len());
            self.events.push(event);
        }
        self.next_acquisition_sequence = next_acquisition;
        self.next_lane_sequences.insert(lane, next_lane);
        self.source_record_ids.insert(source_record_id);
        self.expected_source_records.push(source_record_id);
        self.acquisition_assignments
            .push(AcquisitionOutcomeAssignment::new(
                source_record_id,
                outcome.clone(),
            ));
        self.acknowledged_records = acknowledged_records;
        self.acknowledged_payload_bytes = acknowledged_payload_bytes;
        self.acknowledged_source_bytes = acknowledged_source_bytes;
        self.saw_fragment |= !envelope.state().is_complete();

        Ok(SinkAck::new(
            self.identity.retrieval_id(),
            source_record_id,
            envelope.ordering().acquisition_sequence(),
            authorized_byte_count,
            outcome,
        ))
    }
}

trait WithTransformationReceipt {
    fn with_receipt(
        self,
        receipt: Option<TransformationReceiptV1>,
    ) -> (
        AcquisitionOutcome,
        u64,
        Option<Event>,
        Option<TransformationReceiptV1>,
    );
}

impl WithTransformationReceipt for (AcquisitionOutcome, u64, Option<Event>) {
    fn with_receipt(
        self,
        receipt: Option<TransformationReceiptV1>,
    ) -> (
        AcquisitionOutcome,
        u64,
        Option<Event>,
        Option<TransformationReceiptV1>,
    ) {
        (self.0, self.1, self.2, receipt)
    }
}

impl<P> LedgerBuilder<P>
where
    P: DeterministicPolicy,
{
    fn persist_authorized(
        &self,
        envelope: &RawEnvelopeV1,
        authorized_record: RecordBytes,
        exactness_basis: ExactnessBasis,
        source_record_id: SourceRecordId,
    ) -> Result<(AcquisitionOutcome, u64, Option<Event>), LedgerBuildError> {
        let ordinal =
            u64::try_from(self.events.len()).map_err(|_| LedgerBuildError::EventCountOverflow)?;
        let payload_len = authorized_record.payload_len();
        let terminator_len = authorized_record.terminator().map(<[u8]>::len);
        let raw = authorized_record.exact_bytes();
        let authorized_byte_count =
            u64::try_from(raw.len()).map_err(|_| LedgerBuildError::ByteCountOverflow)?;
        let content_hash = authorized_content_hash(&raw);
        let id = event_id(
            self.identity.retrieval_id(),
            source_record_id,
            content_hash,
            exactness_basis,
            envelope.provider_attestations(),
        );
        if self.positions.contains_key(&id) {
            return Err(LedgerBuildError::EventIdCollision(id));
        }
        let outcome = AcquisitionOutcome::Persisted {
            event_id: id,
            exactness_basis,
        };
        let event = Event {
            id,
            source_record_id,
            content_hash,
            exactness_basis,
            ordinal,
            acquisition_sequence: envelope.ordering().acquisition_sequence(),
            lane: envelope.ordering().lane().clone(),
            lane_sequence: envelope.ordering().lane_sequence(),
            raw: Arc::from(raw),
            payload_len,
            terminator_len,
            native_event_id: envelope.native_event_id().cloned(),
            cursor: envelope.cursor().cloned(),
            record_state: envelope.state(),
            timestamps: envelope.timestamps().clone(),
            metadata: envelope.metadata().cloned(),
            provider_attestations: envelope.provider_attestations().clone(),
            hints: envelope.hints(),
        };
        Ok((outcome, authorized_byte_count, Some(event)))
    }
}

/// Immutable authorized ledger for exactly one bounded retrieval.
#[derive(Clone)]
pub struct EventLedger {
    retrieval_id: RetrievalId,
    plan_id: PlanId,
    plan_digest: PlanDigest,
    source_identity_digest: SourceIdentityDigest,
    adapter: AdapterIdentity,
    completion: FetchCompletion,
    acquisition_receipt_id: AcquisitionReceiptId,
    acquisition_receipt: AcquisitionReceipt,
    transformation_receipts: BTreeMap<TransformationReceiptId, TransformationReceiptV1>,
    events: Vec<Event>,
    positions: BTreeMap<EventId, usize>,
    lane_positions: BTreeMap<LaneKey, Vec<usize>>,
}

impl fmt::Debug for EventLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventLedger")
            .field("event_count", &self.events.len())
            .field(
                "acknowledged_count",
                &self.acquisition_receipt.acknowledged_count(),
            )
            .field("provider_completeness", &self.completion.completeness())
            .finish()
    }
}

impl EventLedger {
    #[must_use]
    pub const fn retrieval_id(&self) -> RetrievalId {
        self.retrieval_id
    }

    #[must_use]
    pub const fn plan_id(&self) -> PlanId {
        self.plan_id
    }

    #[must_use]
    pub const fn plan_digest(&self) -> PlanDigest {
        self.plan_digest
    }

    #[must_use]
    pub const fn source_identity_digest(&self) -> SourceIdentityDigest {
        self.source_identity_digest
    }

    #[must_use]
    pub const fn adapter(&self) -> &AdapterIdentity {
        &self.adapter
    }

    #[must_use]
    pub const fn fetch_completion(&self) -> &FetchCompletion {
        &self.completion
    }

    #[must_use]
    pub const fn acquisition_receipt(&self) -> &AcquisitionReceipt {
        &self.acquisition_receipt
    }

    #[must_use]
    pub const fn acquisition_receipt_id(&self) -> AcquisitionReceiptId {
        self.acquisition_receipt_id
    }

    /// Sealed transformation records keyed by their recomputed identities.
    #[must_use]
    pub fn transformation_receipts(
        &self,
    ) -> impl ExactSizeIterator<Item = &TransformationReceiptV1> {
        self.transformation_receipts.values()
    }

    #[must_use]
    pub fn transformation_receipt(
        &self,
        id: TransformationReceiptId,
    ) -> Option<&TransformationReceiptV1> {
        self.transformation_receipts.get(&id)
    }

    #[must_use]
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    #[must_use]
    pub fn contains(&self, id: EventId) -> bool {
        self.positions.contains_key(&id)
    }

    pub(crate) fn position(&self, id: EventId) -> Option<usize> {
        self.positions.get(&id).copied()
    }

    pub fn event(&self, id: EventId) -> Result<&Event, LedgerLookupError> {
        let position = self
            .positions
            .get(&id)
            .copied()
            .ok_or(LedgerLookupError::UnknownEvent(id))?;
        Ok(&self.events[position])
    }

    /// Return authorized-basis bytes without decoding or normalization.
    pub fn exact_bytes(&self, id: EventId) -> Result<&[u8], LedgerLookupError> {
        self.event(id).map(Event::raw)
    }

    /// Return exact authorized payloads in persisted order without separators.
    pub fn passthrough(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.events.iter().map(Event::raw)
    }

    pub fn expand(
        &self,
        anchor: EventId,
        before: usize,
        after: usize,
    ) -> Result<Expansion<'_>, LedgerLookupError> {
        let position = self
            .positions
            .get(&anchor)
            .copied()
            .ok_or(LedgerLookupError::UnknownEvent(anchor))?;
        let start = position.saturating_sub(before);
        let end = position
            .saturating_add(after)
            .saturating_add(1)
            .min(self.events.len());
        Ok(Expansion {
            anchor,
            anchor_offset: position - start,
            events: &self.events[start..end],
        })
    }

    /// Expand bounded neighbors in the anchor's source-member/stream lane.
    ///
    /// Unlike [`EventLedger::expand`], globally interleaved events from other
    /// lanes are not returned and do not consume the before/after allowance.
    pub fn expand_same_lane(
        &self,
        anchor: EventId,
        before: usize,
        after: usize,
    ) -> Result<LaneExpansion<'_>, LedgerLookupError> {
        let position = self
            .positions
            .get(&anchor)
            .copied()
            .ok_or(LedgerLookupError::UnknownEvent(anchor))?;
        let lane = self.events[position].lane();
        let lane_positions = self
            .lane_positions
            .get(lane)
            .expect("sealed ledgers index every event lane");
        let lane_offset = lane_positions
            .binary_search(&position)
            .expect("sealed ledgers index every event position");
        let start = lane_offset.saturating_sub(before);
        let end = lane_offset
            .saturating_add(after)
            .saturating_add(1)
            .min(lane_positions.len());
        let events = lane_positions[start..end]
            .iter()
            .map(|event_position| &self.events[*event_position])
            .collect();
        Ok(LaneExpansion {
            anchor,
            anchor_offset: lane_offset - start,
            events,
        })
    }

    /// Validate every derived identity and join before exposing an export view.
    pub fn checked_export_v1(
        &self,
    ) -> Result<CheckedSealedLedgerViewV1<'_>, LedgerIntegrityErrorV1> {
        validate_sealed_ledger(self)?;
        Ok(CheckedSealedLedgerViewV1 { ledger: self })
    }
}

/// Read-only export authority available only after complete reconciliation.
pub struct CheckedSealedLedgerViewV1<'ledger> {
    ledger: &'ledger EventLedger,
}
impl<'ledger> CheckedSealedLedgerViewV1<'ledger> {
    #[must_use]
    pub const fn ledger(&self) -> &'ledger EventLedger {
        self.ledger
    }
}
impl fmt::Debug for CheckedSealedLedgerViewV1<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckedSealedLedgerViewV1")
            .field("event_count", &self.ledger.len())
            .field(
                "transformation_receipt_count",
                &self.ledger.transformation_receipts.len(),
            )
            .finish()
    }
}

/// Consume an already constructor-built ledger and recheck all derived state.
/// Importers must first reconstruct through `LedgerBuilder`; this function
/// never assigns a private event, receipt, or index field from decoded data.
pub fn checked_sealed_ledger_import_v1(
    ledger: EventLedger,
) -> Result<EventLedger, LedgerIntegrityErrorV1> {
    validate_sealed_ledger(&ledger)?;
    Ok(ledger)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LedgerIntegrityErrorV1 {
    OrderingMismatch,
    ContentHashMismatch,
    EventIdentityMismatch,
    AcquisitionReceiptMismatch,
    TransformationReceiptMissing,
    TransformationReceiptDuplicate,
    TransformationReceiptMismatch,
}
impl LedgerIntegrityErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::OrderingMismatch => "EVIDENTRAIL_LEDGER_INTEGRITY_ORDERING_MISMATCH",
            Self::ContentHashMismatch => "EVIDENTRAIL_LEDGER_INTEGRITY_CONTENT_HASH_MISMATCH",
            Self::EventIdentityMismatch => "EVIDENTRAIL_LEDGER_INTEGRITY_EVENT_IDENTITY_MISMATCH",
            Self::AcquisitionReceiptMismatch => {
                "EVIDENTRAIL_LEDGER_INTEGRITY_ACQUISITION_RECEIPT_MISMATCH"
            }
            Self::TransformationReceiptMissing => {
                "EVIDENTRAIL_LEDGER_INTEGRITY_TRANSFORMATION_RECEIPT_MISSING"
            }
            Self::TransformationReceiptDuplicate => {
                "EVIDENTRAIL_LEDGER_INTEGRITY_TRANSFORMATION_RECEIPT_DUPLICATE"
            }
            Self::TransformationReceiptMismatch => {
                "EVIDENTRAIL_LEDGER_INTEGRITY_TRANSFORMATION_RECEIPT_MISMATCH"
            }
        }
    }
}
impl fmt::Debug for LedgerIntegrityErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LedgerIntegrityErrorV1")
            .field("code", &self.code())
            .finish()
    }
}
impl fmt::Display for LedgerIntegrityErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl StdError for LedgerIntegrityErrorV1 {}

fn validate_sealed_ledger(ledger: &EventLedger) -> Result<(), LedgerIntegrityErrorV1> {
    let mut prior_acquisition = None;
    let mut seen_events = BTreeSet::new();
    for (position, event) in ledger.events.iter().enumerate() {
        if event.ordinal != position as u64
            || ledger.positions.get(&event.id) != Some(&position)
            || prior_acquisition.is_some_and(|prior| event.acquisition_sequence.get() <= prior)
        {
            return Err(LedgerIntegrityErrorV1::OrderingMismatch);
        }
        prior_acquisition = Some(event.acquisition_sequence.get());
        if authorized_content_hash(event.raw()) != event.content_hash {
            return Err(LedgerIntegrityErrorV1::ContentHashMismatch);
        }
        if event_id(
            ledger.retrieval_id,
            event.source_record_id,
            event.content_hash,
            event.exactness_basis,
            &event.provider_attestations,
        ) != event.id
        {
            return Err(LedgerIntegrityErrorV1::EventIdentityMismatch);
        }
        seen_events.insert(event.id);
    }
    if acquisition_receipt_id(&ledger.acquisition_receipt) != ledger.acquisition_receipt_id {
        return Err(LedgerIntegrityErrorV1::AcquisitionReceiptMismatch);
    }
    let mut receipt_events = BTreeSet::new();
    for entry in ledger.acquisition_receipt.entries() {
        if let AcquisitionOutcome::Persisted {
            event_id,
            exactness_basis,
        } = entry.outcome()
        {
            let event = ledger
                .event(*event_id)
                .map_err(|_| LedgerIntegrityErrorV1::AcquisitionReceiptMismatch)?;
            if event.source_record_id != entry.source_record_id()
                || event.exactness_basis != *exactness_basis
            {
                return Err(LedgerIntegrityErrorV1::AcquisitionReceiptMismatch);
            }
            seen_events.remove(event_id);
            if let ExactnessBasis::PostPolicy {
                policy_digest,
                transformation_receipt_id,
            } = exactness_basis
            {
                let receipt = ledger
                    .transformation_receipts
                    .get(transformation_receipt_id)
                    .ok_or(LedgerIntegrityErrorV1::TransformationReceiptMissing)?;
                if !receipt_events.insert(receipt.resulting_event_id()) {
                    return Err(LedgerIntegrityErrorV1::TransformationReceiptDuplicate);
                }
                if receipt.resulting_event_id() != *event_id
                    || receipt.policy_digest() != *policy_digest
                    || receipt.output_content_hash() != event.content_hash
                    || receipt.output_length() != event.raw.len() as u64
                    || receipt.output_payload_length() != event.payload_len as u64
                    || receipt.output_terminator_length()
                        != event.terminator_len.map(|value| value as u64)
                {
                    return Err(LedgerIntegrityErrorV1::TransformationReceiptMismatch);
                }
            }
        }
    }
    if !seen_events.is_empty() || receipt_events.len() != ledger.transformation_receipts.len() {
        return Err(LedgerIntegrityErrorV1::AcquisitionReceiptMismatch);
    }
    Ok(())
}

/// Exact, bounded neighborhood in one source-member/stream lane.
#[derive(Clone)]
pub struct LaneExpansion<'ledger> {
    anchor: EventId,
    anchor_offset: usize,
    events: Vec<&'ledger Event>,
}

impl fmt::Debug for LaneExpansion<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LaneExpansion")
            .field("anchor_offset", &self.anchor_offset)
            .field("event_count", &self.events.len())
            .finish()
    }
}

impl<'ledger> LaneExpansion<'ledger> {
    #[must_use]
    pub const fn anchor(&self) -> EventId {
        self.anchor
    }

    #[must_use]
    pub const fn anchor_offset(&self) -> usize {
        self.anchor_offset
    }

    #[must_use]
    pub fn events(&self) -> &[&'ledger Event] {
        &self.events
    }

    pub fn raw_events(&self) -> impl ExactSizeIterator<Item = &'ledger [u8]> + '_ {
        self.events.iter().map(|event| event.raw())
    }
}
