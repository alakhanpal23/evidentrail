use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;

use evidentrail_core::{
    AcquisitionSequence, Event, EventId, EventLedger, EvidenceReferenceId, EvidenceReferenceV1,
    EvidenceTargetRef, ExactnessBasis, ExpansionRelationV1, LaneSequence, RecordState, ResultId,
    UnixTimestampNanos,
};
use evidentrail_schema::bounds::{
    DEFAULT_RESULT_TTL_SECS, MAX_EXPANSION_BEFORE_AFTER,
    MAX_EXPANSION_BYTES as SCHEMA_MAX_EXPANSION_BYTES,
    MAX_EXPANSION_EVENTS as SCHEMA_MAX_EXPANSION_EVENTS, MAX_LOG_BRIEF_EVIDENCE_PACKETS,
};

pub const DEFAULT_RESULT_TTL_NANOS: i128 = DEFAULT_RESULT_TTL_SECS as i128 * 1_000_000_000;
pub const MAX_EXPANSION_EVENTS: usize = SCHEMA_MAX_EXPANSION_EVENTS;
pub const MAX_EXPANSION_BYTES: usize = SCHEMA_MAX_EXPANSION_BYTES;

/// One-based, result-scoped evidence alias rendered as `E1`, `E2`, and so on.
///
/// The ordinal has no authority by itself. It is resolved only against the
/// immutable reference manifest of a caller-supplied [`ResultId`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EvidenceAliasV1 {
    result_id: ResultId,
    one_based_ordinal: u16,
}

impl EvidenceAliasV1 {
    pub fn new(result_id: ResultId, one_based_ordinal: u16) -> Result<Self, ResultStoreError> {
        if one_based_ordinal == 0 || usize::from(one_based_ordinal) > MAX_LOG_BRIEF_EVIDENCE_PACKETS
        {
            return Err(ResultStoreError::InvalidEvidenceAlias);
        }
        Ok(Self {
            result_id,
            one_based_ordinal,
        })
    }

    #[must_use]
    pub const fn one_based_ordinal(self) -> u16 {
        self.one_based_ordinal
    }

    /// Return the result scope carried by this short alias.
    ///
    /// The identity is not authority by itself. Callers must still resolve it
    /// against the immutable alias manifest for the same result.
    #[must_use]
    pub const fn result_id(self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub fn canonical_token(self) -> String {
        format!("E{}", self.one_based_ordinal)
    }

    fn zero_based_index(self) -> usize {
        usize::from(self.one_based_ordinal - 1)
    }

    fn is_scoped_to(self, result_id: ResultId) -> bool {
        self.result_id == result_id
    }
}

impl fmt::Debug for EvidenceAliasV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceAliasV1")
            .field("one_based_ordinal", &self.one_based_ordinal)
            .finish()
    }
}

/// Explicit whole-event bounds for one read-only expansion.
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

/// Store-facing expansion request. It accepts no source path, query, refresh,
/// or scope-widening field.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExpansionRequestV1 {
    result_id: ResultId,
    reference_id: EvidenceReferenceId,
    relation: ExpansionRelationV1,
    limit: ExpansionLimitV1,
}

/// Expansion request using a short result-scoped evidence alias. Resolution
/// never consults a process-global alias table.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AliasExpansionRequestV1 {
    result_id: ResultId,
    alias: EvidenceAliasV1,
    relation: ExpansionRelationV1,
    limit: ExpansionLimitV1,
}

impl AliasExpansionRequestV1 {
    #[must_use]
    pub const fn new(
        result_id: ResultId,
        alias: EvidenceAliasV1,
        relation: ExpansionRelationV1,
        limit: ExpansionLimitV1,
    ) -> Self {
        Self {
            result_id,
            alias,
            relation,
            limit,
        }
    }

    #[must_use]
    pub const fn result_id(self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn alias(self) -> EvidenceAliasV1 {
        self.alias
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

impl fmt::Debug for AliasExpansionRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AliasExpansionRequestV1")
            .field("alias", &self.alias)
            .field("relation", &self.relation)
            .field("limit", &self.limit)
            .finish()
    }
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
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExpansionRequestV1")
            .field("relation", &self.relation)
            .field("limit", &self.limit)
            .finish()
    }
}

/// One copied authorized-basis event in an expansion response.
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
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExpandedEventV1")
            .field("exactness_code", &self.exactness_basis.code())
            .field("exact_byte_count", &self.exact_bytes.len())
            .field("record_state", &self.record_state)
            .finish()
    }
}

/// Bounded, whole-event expansion copied from an unexpired memory result.
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
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExpansionResponseV1")
            .field("relation", &self.relation)
            .field("event_count", &self.events.len())
            .field("returned_bytes", &self.returned_bytes)
            .field("truncated", &self.truncated)
            .finish()
    }
}

struct MemoryResult {
    ledger: EventLedger,
    created_at: UnixTimestampNanos,
    expires_at: UnixTimestampNanos,
    references: BTreeMap<EvidenceReferenceId, EvidenceReferenceV1>,
    /// Frozen mapping used by the published artifact's short aliases. `None`
    /// means no short alias has ever been made public for this result.
    evidence_alias_manifest: Option<Vec<EvidenceReferenceId>>,
    /// Event-order aliases prepared at insertion and published only if the
    /// canonical passthrough artifact actually fits.
    pending_event_alias_manifest: Vec<EvidenceReferenceId>,
}

/// Result of one atomic fixed-TTL insertion and per-event reference
/// registration. References are returned in sealed ledger order.
#[derive(Clone, PartialEq, Eq)]
pub struct RegisteredResultV1 {
    expires_at: UnixTimestampNanos,
    references: Vec<EvidenceReferenceV1>,
}

impl RegisteredResultV1 {
    #[must_use]
    pub const fn expires_at(&self) -> UnixTimestampNanos {
        self.expires_at
    }

    #[must_use]
    pub fn references(&self) -> &[EvidenceReferenceV1] {
        &self.references
    }
}

impl fmt::Debug for RegisteredResultV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegisteredResultV1")
            .field("reference_count", &self.references.len())
            .field("fixed_expiry_present", &true)
            .finish()
    }
}

/// Read-only prepared replacement for one result's reference/alias manifest.
/// Construction is store-bound; committing it is one atomic map replacement.
#[derive(Clone, PartialEq, Eq)]
pub struct PreparedPacketReferencesV1 {
    result_id: ResultId,
    result_created_at: UnixTimestampNanos,
    expires_at: UnixTimestampNanos,
    references: Vec<EvidenceReferenceV1>,
}

impl PreparedPacketReferencesV1 {
    #[must_use]
    pub const fn expires_at(&self) -> UnixTimestampNanos {
        self.expires_at
    }

    #[must_use]
    pub fn references(&self) -> &[EvidenceReferenceV1] {
        &self.references
    }
}

impl fmt::Debug for PreparedPacketReferencesV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedPacketReferencesV1")
            .field("reference_count", &self.references.len())
            .field("fixed_expiry_present", &true)
            .finish()
    }
}

/// Explicit memory-only result backend with fixed, non-sliding 30-minute TTL.
///
/// The caller supplies a cryptographically random `ResultId` at the product
/// boundary. This backend detects collisions but does not pretend deterministic
/// fixture bytes are production randomness.
#[derive(Default)]
pub struct MemoryResultStore {
    results: BTreeMap<ResultId, MemoryResult>,
}

impl MemoryResultStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        &mut self,
        result_id: ResultId,
        ledger: EventLedger,
        created_at: UnixTimestampNanos,
    ) -> Result<UnixTimestampNanos, ResultStoreError> {
        if self.results.contains_key(&result_id) {
            return Err(ResultStoreError::DuplicateResultId);
        }
        let expires_at = fixed_expiry(created_at)?;
        self.results.insert(
            result_id,
            MemoryResult {
                ledger,
                created_at,
                expires_at,
                references: BTreeMap::new(),
                evidence_alias_manifest: None,
                pending_event_alias_manifest: Vec::new(),
            },
        );
        Ok(expires_at)
    }

    /// Atomically insert one sealed ledger and issue one result-scoped
    /// event reference per event. Every reference allows exact, same-lane, and
    /// global-neighborhood expansion and shares the store's fixed expiry.
    /// Empty ledgers are valid and register no references.
    pub fn insert_with_event_references(
        &mut self,
        result_id: ResultId,
        ledger: EventLedger,
        created_at: UnixTimestampNanos,
    ) -> Result<RegisteredResultV1, ResultStoreError> {
        if self.results.contains_key(&result_id) {
            return Err(ResultStoreError::DuplicateResultId);
        }
        let expires_at = fixed_expiry(created_at)?;
        let mut references = Vec::with_capacity(ledger.len());
        let mut registered = BTreeMap::new();
        for event in ledger.events() {
            let reference = EvidenceReferenceV1::issue(
                result_id,
                [EvidenceTargetRef::Event(event.id())],
                [
                    ExpansionRelationV1::Exact,
                    ExpansionRelationV1::SameLaneBeforeAfter,
                    ExpansionRelationV1::GlobalBeforeAfter,
                ],
                created_at,
                expires_at,
            )
            .map_err(|_| ResultStoreError::InvalidReferenceMaterial)?;
            if registered
                .insert(reference.id(), reference.clone())
                .is_some()
            {
                return Err(ResultStoreError::InvalidReferenceMaterial);
            }
            references.push(reference);
        }

        self.results.insert(
            result_id,
            MemoryResult {
                ledger,
                created_at,
                expires_at,
                references: registered,
                evidence_alias_manifest: None,
                pending_event_alias_manifest: references
                    .iter()
                    .map(EvidenceReferenceV1::id)
                    .collect(),
            },
        );
        Ok(RegisteredResultV1 {
            expires_at,
            references,
        })
    }

    /// Publish the event-order short-alias manifest exactly once after the
    /// caller has produced a final passthrough artifact. Until this call, full
    /// references work but short aliases are unavailable.
    pub fn publish_event_aliases(
        &mut self,
        result_id: ResultId,
        now: UnixTimestampNanos,
    ) -> Result<(), ResultStoreError> {
        let result = self
            .results
            .get_mut(&result_id)
            .ok_or(ResultStoreError::ReferenceUnavailable)?;
        if now < result.created_at || now >= result.expires_at {
            return Err(ResultStoreError::ReferenceUnavailable);
        }
        if result.evidence_alias_manifest.is_some() {
            return Err(ResultStoreError::AliasManifestAlreadyPublished);
        }
        result.evidence_alias_manifest =
            Some(std::mem::take(&mut result.pending_event_alias_manifest));
        Ok(())
    }

    /// Prepare exact packet references against an existing retained result
    /// without changing its currently registered references or alias manifest.
    pub fn prepare_packet_references(
        &self,
        result_id: ResultId,
        packet_event_ids: impl IntoIterator<Item = Vec<EventId>>,
        now: UnixTimestampNanos,
    ) -> Result<PreparedPacketReferencesV1, ResultStoreError> {
        let result = self
            .results
            .get(&result_id)
            .ok_or(ResultStoreError::ReferenceUnavailable)?;
        if now < result.created_at || now >= result.expires_at {
            return Err(ResultStoreError::ReferenceUnavailable);
        }
        let references = build_packet_references(
            &result.ledger,
            result_id,
            packet_event_ids,
            now,
            result.expires_at,
        )?;
        Ok(PreparedPacketReferencesV1 {
            result_id,
            result_created_at: result.created_at,
            expires_at: result.expires_at,
            references,
        })
    }

    /// Atomically publish a frozen packet alias manifest and union its
    /// references with already-issued full capabilities. Every validation and
    /// merge completes before either stored map is changed.
    pub fn commit_packet_references(
        &mut self,
        prepared: PreparedPacketReferencesV1,
        now: UnixTimestampNanos,
    ) -> Result<RegisteredResultV1, ResultStoreError> {
        let registered = reference_map(&prepared.references)?;
        let result = self
            .results
            .get_mut(&prepared.result_id)
            .ok_or(ResultStoreError::ReferenceUnavailable)?;
        if result.created_at != prepared.result_created_at
            || result.expires_at != prepared.expires_at
            || now < result.created_at
            || now >= result.expires_at
        {
            return Err(ResultStoreError::ReferenceUnavailable);
        }
        if result.evidence_alias_manifest.is_some() {
            return Err(ResultStoreError::AliasManifestAlreadyPublished);
        }
        if registered
            .keys()
            .any(|reference_id| result.references.contains_key(reference_id))
        {
            return Err(ResultStoreError::InvalidReferenceMaterial);
        }
        let mut merged_references = result.references.clone();
        merged_references.extend(registered);
        result.evidence_alias_manifest = Some(
            prepared
                .references
                .iter()
                .map(EvidenceReferenceV1::id)
                .collect(),
        );
        result.pending_event_alias_manifest.clear();
        result.references = merged_references;
        Ok(RegisteredResultV1 {
            expires_at: prepared.expires_at,
            references: prepared.references,
        })
    }

    /// Borrow the sealed ledger for an existing unexpired result. Lookup and
    /// expiry failures are intentionally indistinguishable and no mutable
    /// ledger handle is exposed.
    pub fn ledger(
        &self,
        result_id: ResultId,
        now: UnixTimestampNanos,
    ) -> Result<&EventLedger, ResultStoreError> {
        let result = self
            .results
            .get(&result_id)
            .ok_or(ResultStoreError::ReferenceUnavailable)?;
        if now < result.created_at || now >= result.expires_at {
            return Err(ResultStoreError::ReferenceUnavailable);
        }
        Ok(&result.ledger)
    }

    /// Copy only immutable, contentless capability metadata registered for an
    /// unexpired result. This deliberately exposes neither the ledger nor an
    /// alias manifest and exists so a higher product layer can preserve
    /// already-issued full references while replacing plaintext retention.
    pub fn registered_reference_metadata(
        &self,
        result_id: ResultId,
        now: UnixTimestampNanos,
    ) -> Result<Vec<EvidenceReferenceV1>, ResultStoreError> {
        let result = self
            .results
            .get(&result_id)
            .ok_or(ResultStoreError::ReferenceUnavailable)?;
        if now < result.created_at || now >= result.expires_at {
            return Err(ResultStoreError::ReferenceUnavailable);
        }
        Ok(result.references.values().cloned().collect())
    }

    /// Issue and register an event-only reference against the sealed result.
    /// Unsupported relation families are unavailable until their trusted index
    /// exists; they are not simulated from payload text.
    pub fn issue_event_reference(
        &mut self,
        result_id: ResultId,
        event_ids: impl IntoIterator<Item = EventId>,
        relations: impl IntoIterator<Item = ExpansionRelationV1>,
        now: UnixTimestampNanos,
    ) -> Result<EvidenceReferenceV1, ResultStoreError> {
        let result = self
            .results
            .get_mut(&result_id)
            .ok_or(ResultStoreError::ReferenceUnavailable)?;
        if now < result.created_at || now >= result.expires_at {
            return Err(ResultStoreError::ReferenceUnavailable);
        }

        let event_ids = event_ids.into_iter().collect::<Vec<_>>();
        if event_ids.is_empty()
            || event_ids
                .iter()
                .any(|event_id| !result.ledger.contains(*event_id))
        {
            return Err(ResultStoreError::InvalidReferenceMaterial);
        }
        let relations = relations.into_iter().collect::<Vec<_>>();
        if relations.iter().any(|relation| {
            !matches!(
                relation,
                ExpansionRelationV1::Exact
                    | ExpansionRelationV1::SameLaneBeforeAfter
                    | ExpansionRelationV1::GlobalBeforeAfter
            )
        }) || (event_ids.len() != 1
            && relations
                .iter()
                .any(|relation| *relation != ExpansionRelationV1::Exact))
        {
            return Err(ResultStoreError::InvalidReferenceMaterial);
        }

        let reference = EvidenceReferenceV1::issue(
            result_id,
            event_ids.into_iter().map(EvidenceTargetRef::Event),
            relations,
            now,
            result.expires_at,
        )
        .map_err(|_| ResultStoreError::InvalidReferenceMaterial)?;
        if result.references.contains_key(&reference.id()) {
            return Err(ResultStoreError::InvalidReferenceMaterial);
        }
        result.references.insert(reference.id(), reference.clone());
        Ok(reference)
    }

    pub fn expand(
        &self,
        request: ExpansionRequestV1,
        now: UnixTimestampNanos,
    ) -> Result<ExpansionResponseV1, ResultStoreError> {
        let result = self
            .results
            .get(&request.result_id)
            .ok_or(ResultStoreError::ReferenceUnavailable)?;
        if now < result.created_at || now >= result.expires_at {
            return Err(ResultStoreError::ReferenceUnavailable);
        }
        let reference = result
            .references
            .get(&request.reference_id)
            .ok_or(ResultStoreError::ReferenceUnavailable)?;
        reference
            .authorize(request.result_id, request.relation, now)
            .map_err(|_| ResultStoreError::ReferenceUnavailable)?;

        let candidates = expansion_candidates(&result.ledger, reference, request)?;
        if request.relation == ExpansionRelationV1::Exact && candidates.len() > 1 {
            let required_bytes = candidates
                .iter()
                .try_fold(0_usize, |total, event| total.checked_add(event.raw().len()));
            if candidates.len() > request.limit.max_events
                || required_bytes.is_none_or(|bytes| bytes > request.limit.max_bytes)
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

    /// Resolve a short alias only inside the supplied result's immutable
    /// evidence manifest, then perform the normal authorized expansion.
    pub fn expand_alias(
        &self,
        request: AliasExpansionRequestV1,
        now: UnixTimestampNanos,
    ) -> Result<ExpansionResponseV1, ResultStoreError> {
        let result = self
            .results
            .get(&request.result_id)
            .ok_or(ResultStoreError::ReferenceUnavailable)?;
        if !request.alias.is_scoped_to(request.result_id) {
            return Err(ResultStoreError::ReferenceUnavailable);
        }
        if now < result.created_at || now >= result.expires_at {
            return Err(ResultStoreError::ReferenceUnavailable);
        }
        let reference_id = *result
            .evidence_alias_manifest
            .as_ref()
            .ok_or(ResultStoreError::ReferenceUnavailable)?
            .get(request.alias.zero_based_index())
            .ok_or(ResultStoreError::ReferenceUnavailable)?;
        self.expand(
            ExpansionRequestV1::new(
                request.result_id,
                reference_id,
                request.relation,
                request.limit,
            ),
            now,
        )
    }

    /// Idempotently make a result and every reference unavailable.
    pub fn delete(&mut self, result_id: ResultId) {
        self.results.remove(&result_id);
    }

    /// Remove all results whose exclusive expiry has been reached.
    pub fn cleanup_expired(&mut self, now: UnixTimestampNanos) -> usize {
        let before = self.results.len();
        self.results.retain(|_, result| now < result.expires_at);
        before - self.results.len()
    }

    #[must_use]
    pub fn result_count(&self) -> usize {
        self.results.len()
    }
}

impl fmt::Debug for MemoryResultStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reference_count = self
            .results
            .values()
            .map(|result| result.references.len())
            .sum::<usize>();
        formatter
            .debug_struct("MemoryResultStore")
            .field("backend", &"memory_only")
            .field("result_count", &self.results.len())
            .field("reference_count", &reference_count)
            .finish()
    }
}

fn expansion_candidates<'ledger>(
    ledger: &'ledger EventLedger,
    reference: &EvidenceReferenceV1,
    request: ExpansionRequestV1,
) -> Result<Vec<&'ledger Event>, ResultStoreError> {
    match request.relation {
        ExpansionRelationV1::Exact => reference
            .targets()
            .iter()
            .map(|target| match target {
                EvidenceTargetRef::Event(event_id) => ledger
                    .event(*event_id)
                    .map_err(|_| ResultStoreError::ReferenceUnavailable),
                EvidenceTargetRef::Block(_) => Err(ResultStoreError::ReferenceUnavailable),
            })
            .collect(),
        ExpansionRelationV1::GlobalBeforeAfter => {
            let anchor = single_event_target(reference)?;
            ledger
                .expand(anchor, request.limit.before, request.limit.after)
                .map(|expansion| expansion.events().iter().collect())
                .map_err(|_| ResultStoreError::ReferenceUnavailable)
        }
        ExpansionRelationV1::SameLaneBeforeAfter => {
            let anchor = single_event_target(reference)?;
            ledger
                .expand_same_lane(anchor, request.limit.before, request.limit.after)
                .map(|expansion| expansion.events().to_vec())
                .map_err(|_| ResultStoreError::ReferenceUnavailable)
        }
        ExpansionRelationV1::PatternMembers
        | ExpansionRelationV1::SameAttestedTrace
        | ExpansionRelationV1::AroundOnset => Err(ResultStoreError::ReferenceUnavailable),
    }
}

fn single_event_target(reference: &EvidenceReferenceV1) -> Result<EventId, ResultStoreError> {
    match reference.targets() {
        [EvidenceTargetRef::Event(event_id)] => Ok(*event_id),
        _ => Err(ResultStoreError::ReferenceUnavailable),
    }
}

/// Stable contentless store failure. All lookup, expiry, cross-result, and
/// relation denials intentionally share `ReferenceUnavailable`.
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
            Self::AliasManifestAlreadyPublished => "EVIDENTRAIL_STORE_ALIAS_MANIFEST_ALREADY_PUBLISHED",
            Self::InsufficientExpansionBudget => "EVIDENTRAIL_STORE_INSUFFICIENT_EXPANSION_BUDGET",
            Self::ReferenceUnavailable => "EVIDENTRAIL_STORE_REFERENCE_UNAVAILABLE",
        }
    }
}

impl fmt::Debug for ResultStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResultStoreError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for ResultStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ResultStoreError {}

fn fixed_expiry(created_at: UnixTimestampNanos) -> Result<UnixTimestampNanos, ResultStoreError> {
    created_at
        .get()
        .checked_add(DEFAULT_RESULT_TTL_NANOS)
        .map(UnixTimestampNanos::new)
        .ok_or(ResultStoreError::TimestampOverflow)
}

fn build_packet_references(
    ledger: &EventLedger,
    result_id: ResultId,
    packet_event_ids: impl IntoIterator<Item = Vec<EventId>>,
    issued_at: UnixTimestampNanos,
    expires_at: UnixTimestampNanos,
) -> Result<Vec<EvidenceReferenceV1>, ResultStoreError> {
    let packet_event_ids = packet_event_ids.into_iter().collect::<Vec<_>>();
    if packet_event_ids.len() > MAX_LOG_BRIEF_EVIDENCE_PACKETS {
        return Err(ResultStoreError::InvalidReferenceMaterial);
    }
    let mut assigned_events = BTreeSet::new();
    let mut references = Vec::with_capacity(packet_event_ids.len());
    for packet in packet_event_ids {
        if packet.is_empty() {
            return Err(ResultStoreError::InvalidReferenceMaterial);
        }
        let packet_len = packet.len();
        let packet_set = packet.into_iter().collect::<BTreeSet<_>>();
        if packet_set.len() != packet_len
            || packet_set
                .iter()
                .any(|event_id| !ledger.contains(*event_id))
            || packet_set
                .iter()
                .any(|event_id| !assigned_events.insert(*event_id))
        {
            return Err(ResultStoreError::InvalidReferenceMaterial);
        }
        let targets = ledger
            .events()
            .iter()
            .filter(|event| packet_set.contains(&event.id()))
            .map(|event| EvidenceTargetRef::Event(event.id()))
            .collect::<Vec<_>>();
        if targets.len() != packet_set.len() {
            return Err(ResultStoreError::InvalidReferenceMaterial);
        }
        references.push(
            EvidenceReferenceV1::issue(
                result_id,
                targets,
                [ExpansionRelationV1::Exact],
                issued_at,
                expires_at,
            )
            .map_err(|_| ResultStoreError::InvalidReferenceMaterial)?,
        );
    }
    reference_map(&references)?;
    Ok(references)
}

fn reference_map(
    references: &[EvidenceReferenceV1],
) -> Result<BTreeMap<EvidenceReferenceId, EvidenceReferenceV1>, ResultStoreError> {
    let mut registered = BTreeMap::new();
    for reference in references {
        if registered
            .insert(reference.id(), reference.clone())
            .is_some()
        {
            return Err(ResultStoreError::InvalidReferenceMaterial);
        }
    }
    Ok(registered)
}
