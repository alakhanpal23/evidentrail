use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;

use evidentrail_core::{
    EventId, EventLedger, PresentationAssignment, PresentationDisposition, RetrievalId,
};

/// Exact source-payload byte budget for one benchmark artifact.
///
/// Event separators are not invented and therefore do not contribute to this
/// cost. Each event already owns its exact source bytes, including any source
/// terminator captured as part of the event.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ByteBudget(usize);

impl ByteBudget {
    #[must_use]
    pub const fn new(bytes: usize) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn bytes(self) -> usize {
        self.0
    }
}

/// Stable identity for a deterministic benchmark method implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MethodDescriptor {
    name: &'static str,
    version: &'static str,
}

impl MethodDescriptor {
    #[must_use]
    pub const fn new(name: &'static str, version: &'static str) -> Self {
        Self { name, version }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    #[must_use]
    pub const fn version(self) -> &'static str {
        self.version
    }
}

/// Why a baseline made an event a selection candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SelectionReason {
    Chronological,
    FullQueryMatch,
    IdentifierMatch,
    QueryTermMatch,
    HeadSentinel,
    TailSentinel,
    CoverageSentinel,
}

impl SelectionReason {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Chronological => "chronological",
            Self::FullQueryMatch => "full_query_match",
            Self::IdentifierMatch => "identifier_match",
            Self::QueryTermMatch => "query_term_match",
            Self::HeadSentinel => "head_sentinel",
            Self::TailSentinel => "tail_sentinel",
            Self::CoverageSentinel => "coverage_sentinel",
        }
    }
}

/// Immutable benchmark request.
///
/// The question is bytes so baselines never need lossy decoding. Grep uses
/// ASCII case folding and otherwise compares bytes literally.
#[derive(Clone, Copy)]
pub struct MethodInput<'a> {
    ledger: &'a EventLedger,
    query: &'a [u8],
    budget: ByteBudget,
}

impl fmt::Debug for MethodInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MethodInput")
            .field("event_count", &self.ledger.len())
            .field("query_bytes", &self.query.len())
            .field("budget", &self.budget)
            .finish()
    }
}

impl<'a> MethodInput<'a> {
    #[must_use]
    pub const fn new(ledger: &'a EventLedger, query: &'a [u8], budget: ByteBudget) -> Self {
        Self {
            ledger,
            query,
            budget,
        }
    }

    #[must_use]
    pub const fn ledger(self) -> &'a EventLedger {
        self.ledger
    }

    #[must_use]
    pub const fn query(self) -> &'a [u8] {
        self.query
    }

    #[must_use]
    pub const fn budget(self) -> ByteBudget {
        self.budget
    }
}

/// One selected whole event. Bytes remain in the ledger and are addressed by
/// exact event identity; the result records their source-byte cost.
#[derive(Clone, PartialEq, Eq)]
pub struct SelectedEvent {
    event_id: EventId,
    ordinal: u64,
    source_byte_cost: usize,
    reasons: Vec<SelectionReason>,
}

impl fmt::Debug for SelectedEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedEvent")
            .field("event_id", &self.event_id)
            .field("ordinal", &self.ordinal)
            .field("source_byte_cost", &self.source_byte_cost)
            .field("reasons", &self.reasons)
            .finish()
    }
}

impl SelectedEvent {
    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    #[must_use]
    pub const fn source_byte_cost(&self) -> usize {
        self.source_byte_cost
    }

    #[must_use]
    pub fn reasons(&self) -> &[SelectionReason] {
        &self.reasons
    }
}

/// Cost of a candidate set after deduplicating underlying events.
///
/// An event proposed by multiple retrieval views contributes once to both
/// fields. Events with identical payloads but distinct event identities remain
/// distinct candidates because they are distinct source occurrences.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CandidateCost {
    event_count: usize,
    unique_source_bytes: usize,
}

impl CandidateCost {
    #[must_use]
    pub(crate) const fn new(event_count: usize, unique_source_bytes: usize) -> Self {
        Self {
            event_count,
            unique_source_bytes,
        }
    }

    #[must_use]
    pub const fn event_count(self) -> usize {
        self.event_count
    }

    #[must_use]
    pub const fn unique_source_bytes(self) -> usize {
        self.unique_source_bytes
    }
}

/// Accounting summary for one method output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountingSummary {
    received_event_count: usize,
    candidate_cost: CandidateCost,
    selected_event_count: usize,
    retained_raw_event_count: usize,
    budget_excluded_candidate_count: usize,
    selected_source_bytes: usize,
    budget: ByteBudget,
}

impl AccountingSummary {
    #[must_use]
    pub const fn received_event_count(self) -> usize {
        self.received_event_count
    }

    #[must_use]
    pub const fn candidate_event_count(self) -> usize {
        self.candidate_cost.event_count()
    }

    #[must_use]
    pub const fn candidate_cost(self) -> CandidateCost {
        self.candidate_cost
    }

    #[must_use]
    pub const fn selected_event_count(self) -> usize {
        self.selected_event_count
    }

    #[must_use]
    pub const fn retained_raw_event_count(self) -> usize {
        self.retained_raw_event_count
    }

    #[must_use]
    pub const fn budget_excluded_candidate_count(self) -> usize {
        self.budget_excluded_candidate_count
    }

    #[must_use]
    pub const fn selected_source_bytes(self) -> usize {
        self.selected_source_bytes
    }

    #[must_use]
    pub const fn budget(self) -> ByteBudget {
        self.budget
    }
}

/// Deterministic selection output in original ledger order.
///
/// The exact candidate identities are retained for governed accounting replay
/// but are deliberately omitted from diagnostic formatting and the public
/// accessor surface.
#[derive(Clone, PartialEq, Eq)]
pub struct MethodResult {
    method: MethodDescriptor,
    retrieval_id: RetrievalId,
    candidate_event_ids: Vec<EventId>,
    selected: Vec<SelectedEvent>,
    accounting: AccountingSummary,
}

impl fmt::Debug for MethodResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MethodResult")
            .field("method", &self.method)
            .field("retrieval_id", &self.retrieval_id)
            .field("accounting", &self.accounting)
            .finish()
    }
}

impl MethodResult {
    #[must_use]
    pub const fn method(&self) -> MethodDescriptor {
        self.method
    }

    #[must_use]
    pub const fn retrieval_id(&self) -> RetrievalId {
        self.retrieval_id
    }

    #[must_use]
    pub fn selected(&self) -> &[SelectedEvent] {
        &self.selected
    }

    #[must_use]
    pub(crate) fn candidate_event_ids(&self) -> &[EventId] {
        &self.candidate_event_ids
    }

    #[must_use]
    pub const fn accounting(&self) -> AccountingSummary {
        self.accounting
    }

    #[must_use]
    pub fn contains(&self, event_id: EventId) -> bool {
        self.selected
            .iter()
            .any(|selected| selected.event_id() == event_id)
    }

    /// Produce one presentation disposition for every persisted ledger event.
    ///
    /// Baselines show selected events verbatim and leave every unselected event
    /// byte-exact and addressable in the ledger as `RetainedRaw`.
    pub fn presentation_assignments(
        &self,
        ledger: &EventLedger,
    ) -> Result<Vec<PresentationAssignment>, MethodError> {
        if ledger.retrieval_id() != self.retrieval_id
            || ledger.len() != self.accounting.received_event_count
        {
            return Err(MethodError::RetrievalMismatch);
        }

        let selected = self
            .selected
            .iter()
            .map(SelectedEvent::event_id)
            .collect::<BTreeSet<_>>();
        if selected.iter().any(|event_id| !ledger.contains(*event_id)) {
            return Err(MethodError::RetrievalMismatch);
        }

        Ok(ledger
            .events()
            .iter()
            .map(|event| {
                let disposition = if selected.contains(&event.id()) {
                    PresentationDisposition::ShownVerbatim
                } else {
                    PresentationDisposition::RetainedRaw
                };
                PresentationAssignment::new(event.id(), disposition)
            })
            .collect())
    }
}

/// Stable failures that contain no source content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MethodError {
    SourceByteCostOverflow,
    RetrievalMismatch,
    ReservedQuotaExceedsBudget,
    LexicalScoringFailure,
}

impl MethodError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SourceByteCostOverflow => "EVIDENTRAIL_BENCH_SOURCE_BYTE_COST_OVERFLOW",
            Self::RetrievalMismatch => "EVIDENTRAIL_BENCH_RETRIEVAL_MISMATCH",
            Self::ReservedQuotaExceedsBudget => "EVIDENTRAIL_BENCH_RESERVED_QUOTA_EXCEEDS_BUDGET",
            Self::LexicalScoringFailure => "EVIDENTRAIL_BENCH_LEXICAL_SCORING_FAILURE",
        }
    }
}

impl fmt::Display for MethodError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for MethodError {}

/// Common interface for deterministic benchmark arms.
pub trait BenchmarkMethod {
    fn descriptor(&self) -> MethodDescriptor;

    fn run(&self, input: MethodInput<'_>) -> Result<MethodResult, MethodError>;
}

pub(crate) fn build_result(
    method: MethodDescriptor,
    ledger: &EventLedger,
    budget: ByteBudget,
    candidate_ordinals: &BTreeSet<usize>,
    budget_excluded_candidate_count: usize,
    selected_ordinals: BTreeMap<usize, Vec<SelectionReason>>,
) -> Result<MethodResult, MethodError> {
    let candidate_cost = candidate_cost_for_ordinals(ledger, candidate_ordinals)?;
    let candidate_event_ids = candidate_ordinals
        .iter()
        .map(|ordinal| ledger.events()[*ordinal].id())
        .collect::<Vec<_>>();
    let mut selected = Vec::with_capacity(selected_ordinals.len());
    let mut selected_source_bytes = 0usize;

    for (ordinal, mut reasons) in selected_ordinals {
        let event = &ledger.events()[ordinal];
        selected_source_bytes = selected_source_bytes
            .checked_add(event.raw().len())
            .ok_or(MethodError::SourceByteCostOverflow)?;
        reasons.sort_unstable();
        reasons.dedup();
        selected.push(SelectedEvent {
            event_id: event.id(),
            ordinal: event.ordinal(),
            source_byte_cost: event.raw().len(),
            reasons,
        });
    }

    debug_assert!(selected_source_bytes <= budget.bytes());
    let selected_event_count = selected.len();
    let accounting = AccountingSummary {
        received_event_count: ledger.len(),
        candidate_cost,
        selected_event_count,
        retained_raw_event_count: ledger.len() - selected_event_count,
        budget_excluded_candidate_count,
        selected_source_bytes,
        budget,
    };

    Ok(MethodResult {
        method,
        retrieval_id: ledger.retrieval_id(),
        candidate_event_ids,
        selected,
        accounting,
    })
}

pub(crate) fn candidate_cost_for_ordinals(
    ledger: &EventLedger,
    candidate_ordinals: &BTreeSet<usize>,
) -> Result<CandidateCost, MethodError> {
    let mut unique_source_bytes = 0usize;
    for ordinal in candidate_ordinals {
        unique_source_bytes = unique_source_bytes
            .checked_add(ledger.events()[*ordinal].raw().len())
            .ok_or(MethodError::SourceByteCostOverflow)?;
    }
    Ok(CandidateCost::new(
        candidate_ordinals.len(),
        unique_source_bytes,
    ))
}

pub(crate) fn checked_cost_within_budget(
    current: usize,
    event_bytes: usize,
    budget: ByteBudget,
) -> Result<Option<usize>, MethodError> {
    let total = current
        .checked_add(event_bytes)
        .ok_or(MethodError::SourceByteCostOverflow)?;
    Ok((total <= budget.bytes()).then_some(total))
}
