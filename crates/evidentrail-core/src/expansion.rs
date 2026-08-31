use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::bounds::{
    MAX_EXPANSION_BEFORE_AFTER, MAX_EXPANSION_BYTES as SCHEMA_MAX_EXPANSION_BYTES,
    MAX_EXPANSION_EVENTS as SCHEMA_MAX_EXPANSION_EVENTS,
};
use evidentrail_schema::{
    AcquisitionSequence, EventId, ExactnessBasis, LaneSequence, RecordState, ResultId,
    UnixTimestampNanos,
};

use crate::{
    Event, EventLedger, EvidenceReferenceId, EvidenceReferenceV1, EvidenceTargetRef,
    ExpansionRelationV1,
};

pub const MAX_EXPANSION_EVENTS: usize = SCHEMA_MAX_EXPANSION_EVENTS;
pub const MAX_EXPANSION_BYTES: usize = SCHEMA_MAX_EXPANSION_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpansionLimitV1 {
    max_events: usize,
    max_bytes: usize,
    before: usize,
    after: usize,
}

impl ExpansionLimitV1 {
    pub fn new(
        max_events: usize,
        max_bytes: usize,
        before: usize,
        after: usize,
    ) -> Result<Self, ResultStoreError> {
        if max_events == 0
            || max_events > MAX_EXPANSION_EVENTS
            || max_bytes == 0
            || max_bytes > MAX_EXPANSION_BYTES
            || before > MAX_EXPANSION_BEFORE_AFTER
            || after > MAX_EXPANSION_BEFORE_AFTER
        {
            return Err(ResultStoreError::InvalidExpansionLimit);
        }
        Ok(Self {
            max_events,
            max_bytes,
            before,
            after,
        })
    }
    #[must_use]
    pub const fn max_events(self) -> usize {
        self.max_events
    }
    #[must_use]
    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }
    #[must_use]
    pub const fn before(self) -> usize {
        self.before
    }
    #[must_use]
    pub const fn after(self) -> usize {
        self.after
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExpansionRequestV1 {
    result_id: ResultId,
    reference_id: EvidenceReferenceId,
    relation: ExpansionRelationV1,
    limit: ExpansionLimitV1,
}

impl ExpansionRequestV1 {
    #[must_use]
    pub const fn new(
        result_id: ResultId,
        reference_id: EvidenceReferenceId,
        relation: ExpansionRelationV1,
        limit: ExpansionLimitV1,
    ) -> Self {
        Self {
            result_id,
            reference_id,
            relation,
            limit,
        }
    }
    #[must_use]
    pub const fn result_id(self) -> ResultId {
        self.result_id
    }
    #[must_use]
    pub const fn reference_id(self) -> EvidenceReferenceId {
        self.reference_id
    }
    #[must_use]
    pub const fn relation(self) -> ExpansionRelationV1 {
        self.relation
    }
    #[must_use]
    pub const fn limit(self) -> ExpansionLimitV1 {
        self.limit
    }
}

impl fmt::Debug for ExpansionRequestV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExpansionRequestV1")
            .field("relation", &self.relation)
            .field("limit", &self.limit)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ExpandedEventV1 {
    event_id: EventId,
    exactness_basis: ExactnessBasis,
    acquisition_sequence: AcquisitionSequence,
    lane_sequence: LaneSequence,
    record_state: RecordState,
    exact_bytes: Vec<u8>,
}

impl ExpandedEventV1 {
    fn from_event(event: &Event) -> Self {
        Self {
            event_id: event.id(),
            exactness_basis: event.exactness_basis(),
            acquisition_sequence: event.acquisition_sequence(),
            lane_sequence: event.lane_sequence(),
            record_state: event.record_state(),
            exact_bytes: event.raw().to_vec(),
        }
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
    pub const fn acquisition_sequence(&self) -> AcquisitionSequence {
        self.acquisition_sequence
    }
    #[must_use]
    pub const fn lane_sequence(&self) -> LaneSequence {
        self.lane_sequence
    }
    #[must_use]
    pub const fn record_state(&self) -> RecordState {
        self.record_state
    }
    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }
}

impl fmt::Debug for ExpandedEventV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExpandedEventV1")
            .field("exactness_code", &self.exactness_basis.code())
            .field("exact_byte_count", &self.exact_bytes.len())
            .field("record_state", &self.record_state)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ExpansionResponseV1 {
    result_id: ResultId,
    reference_id: EvidenceReferenceId,
    relation: ExpansionRelationV1,
    events: Vec<ExpandedEventV1>,
    returned_bytes: usize,
    truncated: bool,
}

impl ExpansionResponseV1 {
    #[must_use]
    pub const fn result_id(&self) -> ResultId {
        self.result_id
    }
    #[must_use]
    pub const fn reference_id(&self) -> EvidenceReferenceId {
        self.reference_id
    }
    #[must_use]
    pub const fn relation(&self) -> ExpansionRelationV1 {
        self.relation
    }
    #[must_use]
    pub fn events(&self) -> &[ExpandedEventV1] {
        &self.events
    }
    #[must_use]
    pub const fn returned_bytes(&self) -> usize {
        self.returned_bytes
    }
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

impl fmt::Debug for ExpansionResponseV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExpansionResponseV1")
            .field("relation", &self.relation)
            .field("event_count", &self.events.len())
            .field("returned_bytes", &self.returned_bytes)
            .field("truncated", &self.truncated)
            .finish()
    }
}

/// Context-bound construction of a response; callers cannot manufacture a
/// verified response by assigning its private fields.
pub fn expand_retained_result_v1(
    ledger: &EventLedger,
    reference: &EvidenceReferenceV1,
    request: ExpansionRequestV1,
    now: UnixTimestampNanos,
) -> Result<ExpansionResponseV1, ResultStoreError> {
    if reference.id() != request.reference_id || reference.result_id() != request.result_id {
        return Err(ResultStoreError::ReferenceUnavailable);
    }
    reference
        .authorize(request.result_id, request.relation, now)
        .map_err(|_| ResultStoreError::ReferenceUnavailable)?;
    let candidates = expansion_candidates(ledger, reference, request)?;
    if request.relation == ExpansionRelationV1::Exact && candidates.len() > 1 {
        let required = candidates
            .iter()
            .try_fold(0_usize, |total, event| total.checked_add(event.raw().len()));
        if candidates.len() > request.limit.max_events
            || required.is_none_or(|bytes| bytes > request.limit.max_bytes)
        {
            return Err(ResultStoreError::InsufficientExpansionBudget);
        }
    }
    let mut seen = BTreeSet::new();
    let mut events = Vec::new();
    let mut returned_bytes = 0_usize;
    let mut truncated = false;
    for event in candidates {
        if !seen.insert(event.id()) {
            continue;
        }
        let Some(next_bytes) = returned_bytes.checked_add(event.raw().len()) else {
            truncated = true;
            break;
        };
        if events.len() == request.limit.max_events || next_bytes > request.limit.max_bytes {
            truncated = true;
            break;
        }
        returned_bytes = next_bytes;
        events.push(ExpandedEventV1::from_event(event));
    }
    Ok(ExpansionResponseV1 {
        result_id: request.result_id,
        reference_id: request.reference_id,
        relation: request.relation,
        events,
        returned_bytes,
        truncated,
    })
}

fn expansion_candidates<'a>(
    ledger: &'a EventLedger,
    reference: &EvidenceReferenceV1,
    request: ExpansionRequestV1,
) -> Result<Vec<&'a Event>, ResultStoreError> {
    match request.relation {
        ExpansionRelationV1::Exact => reference
            .targets()
            .iter()
            .map(|target| match target {
                EvidenceTargetRef::Event(id) => ledger
                    .event(*id)
                    .map_err(|_| ResultStoreError::ReferenceUnavailable),
                EvidenceTargetRef::Block(_) => Err(ResultStoreError::ReferenceUnavailable),
            })
            .collect(),
        ExpansionRelationV1::GlobalBeforeAfter => ledger
            .expand(
                single_event_target(reference)?,
                request.limit.before,
                request.limit.after,
            )
            .map(|value| value.events().iter().collect())
            .map_err(|_| ResultStoreError::ReferenceUnavailable),
        ExpansionRelationV1::SameLaneBeforeAfter => ledger
            .expand_same_lane(
                single_event_target(reference)?,
                request.limit.before,
                request.limit.after,
            )
            .map(|value| value.events().to_vec())
            .map_err(|_| ResultStoreError::ReferenceUnavailable),
        ExpansionRelationV1::PatternMembers
        | ExpansionRelationV1::SameAttestedTrace
        | ExpansionRelationV1::AroundOnset => Err(ResultStoreError::ReferenceUnavailable),
    }
}

fn single_event_target(reference: &EvidenceReferenceV1) -> Result<EventId, ResultStoreError> {
    match reference.targets() {
        [EvidenceTargetRef::Event(id)] => Ok(*id),
        _ => Err(ResultStoreError::ReferenceUnavailable),
    }
}

/// Compatibility error retained while store callers migrate to core expansion.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ResultStoreError {
    DuplicateResultId,
    TimestampOverflow,
    InvalidReferenceMaterial,
    InvalidExpansionLimit,
    InvalidEvidenceAlias,
    AliasManifestAlreadyPublished,
    InsufficientExpansionBudget,
    ReferenceUnavailable,
}
impl ResultStoreError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::DuplicateResultId => "EVIDENTRAIL_STORE_DUPLICATE_RESULT_ID",
            Self::TimestampOverflow => "EVIDENTRAIL_STORE_TIMESTAMP_OVERFLOW",
            Self::InvalidReferenceMaterial => "EVIDENTRAIL_STORE_INVALID_REFERENCE_MATERIAL",
            Self::InvalidExpansionLimit => "EVIDENTRAIL_STORE_INVALID_EXPANSION_LIMIT",
            Self::InvalidEvidenceAlias => "EVIDENTRAIL_STORE_INVALID_EVIDENCE_ALIAS",
            Self::AliasManifestAlreadyPublished => {
                "EVIDENTRAIL_STORE_ALIAS_MANIFEST_ALREADY_PUBLISHED"
            }
            Self::InsufficientExpansionBudget => "EVIDENTRAIL_STORE_INSUFFICIENT_EXPANSION_BUDGET",
            Self::ReferenceUnavailable => "EVIDENTRAIL_STORE_REFERENCE_UNAVAILABLE",
        }
    }
}
impl fmt::Debug for ResultStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResultStoreError")
            .field("code", &self.code())
            .finish()
    }
}
impl fmt::Display for ResultStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl StdError for ResultStoreError {}
