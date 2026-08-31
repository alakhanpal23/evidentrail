use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_core::{EventId, EventLedger};

use crate::method::{CandidateCost, MethodResult};

/// Exact required-evidence recall counts.
///
/// Empty required sets are reported as not applicable rather than receiving a
/// misleading perfect or zero floating-point score.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequiredEvidenceRecall {
    required_event_count: usize,
    selected_required_event_count: usize,
}

impl RequiredEvidenceRecall {
    #[must_use]
    pub const fn required_event_count(self) -> usize {
        self.required_event_count
    }

    #[must_use]
    pub const fn selected_required_event_count(self) -> usize {
        self.selected_required_event_count
    }

    #[must_use]
    pub const fn missed_required_event_count(self) -> usize {
        self.required_event_count - self.selected_required_event_count
    }

    #[must_use]
    pub fn ratio(self) -> Option<f64> {
        (self.required_event_count != 0)
            .then(|| self.selected_required_event_count as f64 / self.required_event_count as f64)
    }
}

/// Contentless metric failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetricError {
    RetrievalMismatch,
    UnknownRequiredEvidence { count: usize },
    UnknownCandidateEvent { count: usize },
    EmptyRequirement,
    EmptyRequirementAlternative,
    InvalidRequirementWeight,
    RequirementWeightSumNotFinite,
    CandidateByteCostOverflow,
}

impl MetricError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::RetrievalMismatch => "EVIDENTRAIL_BENCH_METRIC_RETRIEVAL_MISMATCH",
            Self::UnknownRequiredEvidence { .. } => {
                "EVIDENTRAIL_BENCH_METRIC_UNKNOWN_REQUIRED_EVIDENCE"
            }
            Self::UnknownCandidateEvent { .. } => {
                "EVIDENTRAIL_BENCH_METRIC_UNKNOWN_CANDIDATE_EVENT"
            }
            Self::EmptyRequirement => "EVIDENTRAIL_BENCH_METRIC_EMPTY_REQUIREMENT",
            Self::EmptyRequirementAlternative => {
                "EVIDENTRAIL_BENCH_METRIC_EMPTY_REQUIREMENT_ALTERNATIVE"
            }
            Self::InvalidRequirementWeight => "EVIDENTRAIL_BENCH_METRIC_INVALID_REQUIREMENT_WEIGHT",
            Self::RequirementWeightSumNotFinite => {
                "EVIDENTRAIL_BENCH_METRIC_REQUIREMENT_WEIGHT_SUM_NOT_FINITE"
            }
            Self::CandidateByteCostOverflow => {
                "EVIDENTRAIL_BENCH_METRIC_CANDIDATE_BYTE_COST_OVERFLOW"
            }
        }
    }
}

/// One weighted diagnostic fact and its jointly sufficient evidence choices.
///
/// Every inner vector is one alternative: all events in that vector must be
/// selected to satisfy the requirement. Satisfying any alternative satisfies
/// the requirement. Construction canonicalizes and deduplicates event IDs and
/// duplicate alternatives.
#[derive(Clone, PartialEq)]
pub struct DiagnosticRequirement {
    weight: f64,
    alternatives: Vec<Vec<EventId>>,
}

impl fmt::Debug for DiagnosticRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let unique_event_reference_count = self
            .alternatives
            .iter()
            .flatten()
            .copied()
            .collect::<BTreeSet<_>>()
            .len();
        formatter
            .debug_struct("DiagnosticRequirement")
            .field("weight", &self.weight)
            .field("alternative_count", &self.alternatives.len())
            .field(
                "unique_event_reference_count",
                &unique_event_reference_count,
            )
            .finish()
    }
}

impl DiagnosticRequirement {
    pub fn new<A, I>(weight: f64, alternatives: A) -> Result<Self, MetricError>
    where
        A: IntoIterator<Item = I>,
        I: IntoIterator<Item = EventId>,
    {
        if !weight.is_finite() || weight <= 0.0 {
            return Err(MetricError::InvalidRequirementWeight);
        }

        let mut canonical = BTreeSet::new();
        let mut saw_alternative = false;
        for alternative in alternatives {
            saw_alternative = true;
            let event_ids = alternative.into_iter().collect::<BTreeSet<_>>();
            if event_ids.is_empty() {
                return Err(MetricError::EmptyRequirementAlternative);
            }
            canonical.insert(event_ids.into_iter().collect::<Vec<_>>());
        }
        if !saw_alternative {
            return Err(MetricError::EmptyRequirement);
        }

        Ok(Self {
            weight,
            alternatives: canonical.into_iter().collect(),
        })
    }

    #[must_use]
    pub const fn weight(&self) -> f64 {
        self.weight
    }

    #[must_use]
    pub fn alternatives(&self) -> &[Vec<EventId>] {
        &self.alternatives
    }

    #[must_use]
    pub fn is_satisfied_by(&self, selected: &BTreeSet<EventId>) -> bool {
        self.alternatives.iter().any(|alternative| {
            alternative
                .iter()
                .all(|event_id| selected.contains(event_id))
        })
    }
}

/// Weighted requirement recall for one benchmark case.
///
/// `weighted_recall` is not applicable only when the case has no diagnostic
/// requirements. Every non-empty valid case has positive finite total weight.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CaseDiagnosticRecall {
    requirement_count: usize,
    satisfied_requirement_count: usize,
    total_weight: f64,
    satisfied_weight: f64,
}

impl CaseDiagnosticRecall {
    #[must_use]
    pub const fn requirement_count(self) -> usize {
        self.requirement_count
    }

    #[must_use]
    pub const fn satisfied_requirement_count(self) -> usize {
        self.satisfied_requirement_count
    }

    #[must_use]
    pub const fn missed_requirement_count(self) -> usize {
        self.requirement_count - self.satisfied_requirement_count
    }

    #[must_use]
    pub const fn total_weight(self) -> f64 {
        self.total_weight
    }

    #[must_use]
    pub const fn satisfied_weight(self) -> f64 {
        self.satisfied_weight
    }

    #[must_use]
    pub fn weighted_recall(self) -> Option<f64> {
        (self.requirement_count != 0).then(|| self.satisfied_weight / self.total_weight)
    }
}

/// Evaluate weighted diagnostic requirements against selected evidence.
pub fn diagnostic_requirement_coverage(
    ledger: &EventLedger,
    result: &MethodResult,
    requirements: &[DiagnosticRequirement],
) -> Result<CaseDiagnosticRecall, MetricError> {
    if ledger.retrieval_id() != result.retrieval_id() {
        return Err(MetricError::RetrievalMismatch);
    }

    let referenced = requirements
        .iter()
        .flat_map(|requirement| requirement.alternatives.iter().flatten().copied())
        .collect::<BTreeSet<_>>();
    let unknown_count = referenced
        .iter()
        .filter(|event_id| !ledger.contains(**event_id))
        .count();
    if unknown_count != 0 {
        return Err(MetricError::UnknownRequiredEvidence {
            count: unknown_count,
        });
    }

    let selected = result
        .selected()
        .iter()
        .map(|event| event.event_id())
        .collect::<BTreeSet<_>>();
    let mut total_weight = 0.0;
    let mut satisfied_weight = 0.0;
    let mut satisfied_requirement_count = 0usize;
    for requirement in requirements {
        total_weight += requirement.weight;
        if !total_weight.is_finite() {
            return Err(MetricError::RequirementWeightSumNotFinite);
        }
        if requirement.is_satisfied_by(&selected) {
            satisfied_requirement_count += 1;
            satisfied_weight += requirement.weight;
            if !satisfied_weight.is_finite() {
                return Err(MetricError::RequirementWeightSumNotFinite);
            }
        }
    }

    Ok(CaseDiagnosticRecall {
        requirement_count: requirements.len(),
        satisfied_requirement_count,
        total_weight,
        satisfied_weight,
    })
}

/// Cost an arbitrary candidate set by unique event identity.
///
/// Repeated references do not add candidates or bytes. Distinct source events
/// with identical payload bytes remain distinct and are both charged.
pub fn candidate_cost(
    ledger: &EventLedger,
    candidate_event_ids: &[EventId],
) -> Result<CandidateCost, MetricError> {
    let candidates = candidate_event_ids.iter().copied().collect::<BTreeSet<_>>();
    let unknown_count = candidates
        .iter()
        .filter(|event_id| !ledger.contains(**event_id))
        .count();
    if unknown_count != 0 {
        return Err(MetricError::UnknownCandidateEvent {
            count: unknown_count,
        });
    }

    let mut unique_source_bytes = 0usize;
    for event in ledger.events() {
        if candidates.contains(&event.id()) {
            unique_source_bytes = unique_source_bytes
                .checked_add(event.raw().len())
                .ok_or(MetricError::CandidateByteCostOverflow)?;
        }
    }
    Ok(CandidateCost::new(candidates.len(), unique_source_bytes))
}

impl fmt::Display for MetricError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for MetricError {}

/// Score the unique required event IDs retained by a method result.
pub fn required_evidence_recall(
    ledger: &EventLedger,
    result: &MethodResult,
    required_event_ids: &[EventId],
) -> Result<RequiredEvidenceRecall, MetricError> {
    if ledger.retrieval_id() != result.retrieval_id() {
        return Err(MetricError::RetrievalMismatch);
    }

    let required = required_event_ids.iter().copied().collect::<BTreeSet<_>>();
    let unknown_count = required
        .iter()
        .filter(|event_id| !ledger.contains(**event_id))
        .count();
    if unknown_count != 0 {
        return Err(MetricError::UnknownRequiredEvidence {
            count: unknown_count,
        });
    }

    let selected = result
        .selected()
        .iter()
        .map(|event| event.event_id())
        .collect::<BTreeSet<_>>();
    let selected_required_event_count = required.intersection(&selected).count();

    Ok(RequiredEvidenceRecall {
        required_event_count: required.len(),
        selected_required_event_count,
    })
}
