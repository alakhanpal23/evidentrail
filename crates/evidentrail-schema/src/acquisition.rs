use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;

use crate::{EventId, PolicyDigest, RetrievalId, SourceRecordId, TransformationReceiptId};

/// The immutable byte basis against which a persisted event may claim exact
/// expansion.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ExactnessBasis {
    /// Persisted payload and source-defined terminator are byte-for-byte source
    /// evidence.
    SourceExact,
    /// Persisted bytes are exact only relative to a declared deterministic
    /// policy transformation.
    PostPolicy {
        policy_digest: PolicyDigest,
        transformation_receipt_id: TransformationReceiptId,
    },
}

impl ExactnessBasis {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SourceExact => "source_exact",
            Self::PostPolicy { .. } => "post_policy",
        }
    }

    #[must_use]
    pub const fn is_source_exact(self) -> bool {
        matches!(self, Self::SourceExact)
    }
}

impl fmt::Debug for ExactnessBasis {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactnessBasis")
            .field("code", &self.code())
            .finish()
    }
}

/// Exactly one authorization outcome for an acknowledged source envelope.
///
/// Policy omission belongs here, before persistence. It is intentionally not
/// a presentation disposition because no event exists to present.
#[derive(Clone, PartialEq, Eq)]
pub enum AcquisitionOutcome {
    Persisted {
        event_id: EventId,
        exactness_basis: ExactnessBasis,
    },
    OmittedByPolicy {
        policy_digest: PolicyDigest,
    },
}

impl AcquisitionOutcome {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Persisted {
                exactness_basis: ExactnessBasis::SourceExact,
                ..
            } => "source_exact",
            Self::Persisted {
                exactness_basis: ExactnessBasis::PostPolicy { .. },
                ..
            } => "post_policy",
            Self::OmittedByPolicy { .. } => "omitted_by_policy",
        }
    }

    #[must_use]
    pub const fn persisted_event_id(&self) -> Option<EventId> {
        match self {
            Self::Persisted { event_id, .. } => Some(*event_id),
            Self::OmittedByPolicy { .. } => None,
        }
    }

    #[must_use]
    pub const fn exactness_basis(&self) -> Option<ExactnessBasis> {
        match self {
            Self::Persisted {
                exactness_basis, ..
            } => Some(*exactness_basis),
            Self::OmittedByPolicy { .. } => None,
        }
    }
}

impl fmt::Debug for AcquisitionOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcquisitionOutcome")
            .field("code", &self.code())
            .finish()
    }
}

/// A proposed authorization outcome for one expected source record.
///
/// Assignments become receipt entries only after exhaustive reconciliation.
#[derive(Clone, PartialEq, Eq)]
pub struct AcquisitionOutcomeAssignment {
    source_record_id: SourceRecordId,
    outcome: AcquisitionOutcome,
}

impl AcquisitionOutcomeAssignment {
    #[must_use]
    pub const fn new(source_record_id: SourceRecordId, outcome: AcquisitionOutcome) -> Self {
        Self {
            source_record_id,
            outcome,
        }
    }

    #[must_use]
    pub const fn source_record_id(&self) -> SourceRecordId {
        self.source_record_id
    }

    #[must_use]
    pub const fn outcome(&self) -> &AcquisitionOutcome {
        &self.outcome
    }
}

impl fmt::Debug for AcquisitionOutcomeAssignment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcquisitionOutcomeAssignment")
            .field("outcome_code", &self.outcome.code())
            .finish()
    }
}

/// One expected source record and its reconciled authorization outcome.
///
/// Only `AcquisitionReceipt::reconcile` can construct this type, so its
/// presence in a receipt proves that the source record was expected and was
/// assigned exactly once.
#[derive(Clone, PartialEq, Eq)]
pub struct AcquisitionReceiptEntry {
    source_record_id: SourceRecordId,
    outcome: AcquisitionOutcome,
}

impl AcquisitionReceiptEntry {
    #[must_use]
    pub const fn source_record_id(&self) -> SourceRecordId {
        self.source_record_id
    }

    #[must_use]
    pub const fn outcome(&self) -> &AcquisitionOutcome {
        &self.outcome
    }
}

impl fmt::Debug for AcquisitionReceiptEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcquisitionReceiptEntry")
            .field("outcome_code", &self.outcome.code())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AcquisitionCounts {
    pub source_exact: usize,
    pub post_policy: usize,
    pub omitted_by_policy: usize,
}

impl AcquisitionCounts {
    #[must_use]
    pub const fn acknowledged(self) -> usize {
        self.source_exact + self.post_policy + self.omitted_by_policy
    }

    fn observe(&mut self, outcome: &AcquisitionOutcome) {
        match outcome {
            AcquisitionOutcome::Persisted {
                exactness_basis: ExactnessBasis::SourceExact,
                ..
            } => self.source_exact += 1,
            AcquisitionOutcome::Persisted {
                exactness_basis: ExactnessBasis::PostPolicy { .. },
                ..
            } => self.post_policy += 1,
            AcquisitionOutcome::OmittedByPolicy { .. } => self.omitted_by_policy += 1,
        }
    }
}

/// An internally reconciled accounting of every acknowledged source record.
///
/// Expected source records define the canonical receipt order. Construction
/// rejects duplicate expected identities, unknown/duplicate/missing outcome
/// assignments, and reuse of one persisted event for multiple source records.
/// Counts are derived from reconciled entries, so the acknowledgement equation
/// cannot drift internally.
#[derive(Clone, PartialEq, Eq)]
pub struct AcquisitionReceipt {
    retrieval_id: RetrievalId,
    entries: Vec<AcquisitionReceiptEntry>,
    counts: AcquisitionCounts,
}

impl AcquisitionReceipt {
    pub fn reconcile(
        retrieval_id: RetrievalId,
        expected_source_records: impl IntoIterator<Item = SourceRecordId>,
        assignments: impl IntoIterator<Item = AcquisitionOutcomeAssignment>,
    ) -> Result<Self, AcquisitionReceiptError> {
        let mut expected_set = BTreeSet::new();
        let mut expected_order = Vec::new();
        for source_record_id in expected_source_records {
            if !expected_set.insert(source_record_id) {
                return Err(AcquisitionReceiptError::DuplicateExpectedSourceRecord(
                    source_record_id,
                ));
            }
            expected_order.push(source_record_id);
        }

        let mut outcomes_by_source = BTreeMap::new();
        let mut persisted_events = BTreeSet::new();
        for assignment in assignments {
            let source_record_id = assignment.source_record_id;
            if !expected_set.contains(&source_record_id) {
                return Err(AcquisitionReceiptError::UnknownSourceRecord(
                    source_record_id,
                ));
            }
            if outcomes_by_source.contains_key(&source_record_id) {
                return Err(AcquisitionReceiptError::DuplicateOutcomeAssignment(
                    source_record_id,
                ));
            }
            if let Some(event_id) = assignment.outcome.persisted_event_id() {
                if !persisted_events.insert(event_id) {
                    return Err(AcquisitionReceiptError::DuplicatePersistedEvent(event_id));
                }
            }
            outcomes_by_source.insert(source_record_id, assignment.outcome);
        }

        let missing = expected_order
            .iter()
            .copied()
            .filter(|source_record_id| !outcomes_by_source.contains_key(source_record_id))
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(AcquisitionReceiptError::MissingOutcomeAssignments(missing));
        }

        let mut counts = AcquisitionCounts::default();
        let mut entries = Vec::with_capacity(expected_order.len());
        for source_record_id in expected_order {
            let outcome = outcomes_by_source
                .remove(&source_record_id)
                .expect("missing assignments were rejected above");
            counts.observe(&outcome);
            entries.push(AcquisitionReceiptEntry {
                source_record_id,
                outcome,
            });
        }
        Ok(Self {
            retrieval_id,
            entries,
            counts,
        })
    }

    #[must_use]
    pub const fn retrieval_id(&self) -> RetrievalId {
        self.retrieval_id
    }

    #[must_use]
    pub fn entries(&self) -> &[AcquisitionReceiptEntry] {
        &self.entries
    }

    #[must_use]
    pub const fn counts(&self) -> AcquisitionCounts {
        self.counts
    }

    #[must_use]
    pub fn acknowledged_count(&self) -> usize {
        self.entries.len()
    }
}

impl fmt::Debug for AcquisitionReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcquisitionReceipt")
            .field("acknowledged_count", &self.entries.len())
            .field("counts", &self.counts)
            .finish()
    }
}

#[derive(PartialEq, Eq)]
pub enum AcquisitionReceiptError {
    DuplicateExpectedSourceRecord(SourceRecordId),
    UnknownSourceRecord(SourceRecordId),
    DuplicateOutcomeAssignment(SourceRecordId),
    MissingOutcomeAssignments(Vec<SourceRecordId>),
    DuplicatePersistedEvent(EventId),
}

impl AcquisitionReceiptError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::DuplicateExpectedSourceRecord(_) => {
                "EVIDENTRAIL_ACQUISITION_DUPLICATE_EXPECTED_SOURCE_RECORD"
            }
            Self::UnknownSourceRecord(_) => "EVIDENTRAIL_ACQUISITION_UNKNOWN_SOURCE_RECORD",
            Self::DuplicateOutcomeAssignment(_) => "EVIDENTRAIL_ACQUISITION_DUPLICATE_OUTCOME_ASSIGNMENT",
            Self::MissingOutcomeAssignments(_) => "EVIDENTRAIL_ACQUISITION_MISSING_OUTCOME_ASSIGNMENTS",
            Self::DuplicatePersistedEvent(_) => "EVIDENTRAIL_ACQUISITION_DUPLICATE_PERSISTED_EVENT",
        }
    }

    /// Number of records or events implicated, without revealing identities.
    #[must_use]
    pub fn affected_count(&self) -> usize {
        match self {
            Self::MissingOutcomeAssignments(source_record_ids) => source_record_ids.len(),
            Self::DuplicateExpectedSourceRecord(_)
            | Self::UnknownSourceRecord(_)
            | Self::DuplicateOutcomeAssignment(_)
            | Self::DuplicatePersistedEvent(_) => 1,
        }
    }
}

impl fmt::Debug for AcquisitionReceiptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcquisitionReceiptError")
            .field("code", &self.code())
            .field("affected_count", &self.affected_count())
            .finish()
    }
}

impl fmt::Display for AcquisitionReceiptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} (affected_count={})",
            self.code(),
            self.affected_count()
        )
    }
}

impl StdError for AcquisitionReceiptError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_record_id(seed: u8) -> SourceRecordId {
        SourceRecordId::from_bytes([seed; 32])
    }

    fn event_id(seed: u8) -> EventId {
        EventId::from_bytes([seed; 32])
    }

    fn source_exact(source_seed: u8, event_seed: u8) -> AcquisitionOutcomeAssignment {
        AcquisitionOutcomeAssignment::new(
            source_record_id(source_seed),
            AcquisitionOutcome::Persisted {
                event_id: event_id(event_seed),
                exactness_basis: ExactnessBasis::SourceExact,
            },
        )
    }

    fn omitted(source_seed: u8, policy_seed: u8) -> AcquisitionOutcomeAssignment {
        AcquisitionOutcomeAssignment::new(
            source_record_id(source_seed),
            AcquisitionOutcome::OmittedByPolicy {
                policy_digest: PolicyDigest::from_bytes([policy_seed; 32]),
            },
        )
    }

    #[test]
    fn receipt_is_exhaustive_counted_and_ordered_by_expected_records() {
        let post_policy = ExactnessBasis::PostPolicy {
            policy_digest: PolicyDigest::from_bytes([7; 32]),
            transformation_receipt_id: TransformationReceiptId::from_bytes([8; 32]),
        };
        let expected = [
            source_record_id(1),
            source_record_id(2),
            source_record_id(3),
        ];
        let receipt = AcquisitionReceipt::reconcile(
            RetrievalId::from_bytes([1; 32]),
            expected,
            [
                omitted(3, 9),
                AcquisitionOutcomeAssignment::new(
                    source_record_id(2),
                    AcquisitionOutcome::Persisted {
                        event_id: event_id(2),
                        exactness_basis: post_policy,
                    },
                ),
                source_exact(1, 1),
            ],
        )
        .unwrap();

        assert_eq!(
            receipt
                .entries()
                .iter()
                .map(AcquisitionReceiptEntry::source_record_id)
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(receipt.acknowledged_count(), 3);
        assert_eq!(receipt.counts().source_exact, 1);
        assert_eq!(receipt.counts().post_policy, 1);
        assert_eq!(receipt.counts().omitted_by_policy, 1);
        assert_eq!(receipt.counts().acknowledged(), 3);
    }

    #[test]
    fn empty_expected_set_reconciles_to_an_empty_receipt() {
        let receipt =
            AcquisitionReceipt::reconcile(RetrievalId::from_bytes([2; 32]), [], std::iter::empty())
                .unwrap();

        assert!(receipt.entries().is_empty());
        assert_eq!(receipt.counts().acknowledged(), 0);
    }

    #[test]
    fn duplicate_expected_source_record_is_rejected() {
        let duplicate = source_record_id(4);
        let error = AcquisitionReceipt::reconcile(
            RetrievalId::from_bytes([3; 32]),
            [duplicate, duplicate],
            [],
        )
        .unwrap_err();

        assert_eq!(
            error,
            AcquisitionReceiptError::DuplicateExpectedSourceRecord(duplicate)
        );
        assert_eq!(
            error.to_string(),
            "EVIDENTRAIL_ACQUISITION_DUPLICATE_EXPECTED_SOURCE_RECORD (affected_count=1)"
        );
    }

    #[test]
    fn unknown_outcome_assignment_is_rejected() {
        let unknown = source_record_id(5);
        let error = AcquisitionReceipt::reconcile(
            RetrievalId::from_bytes([4; 32]),
            [source_record_id(4)],
            [omitted(5, 1)],
        )
        .unwrap_err();

        assert_eq!(error, AcquisitionReceiptError::UnknownSourceRecord(unknown));
    }

    #[test]
    fn duplicate_outcome_assignment_is_rejected() {
        let duplicate = source_record_id(6);
        let error = AcquisitionReceipt::reconcile(
            RetrievalId::from_bytes([5; 32]),
            [duplicate],
            [omitted(6, 1), omitted(6, 2)],
        )
        .unwrap_err();

        assert_eq!(
            error,
            AcquisitionReceiptError::DuplicateOutcomeAssignment(duplicate)
        );
    }

    #[test]
    fn all_missing_outcomes_are_reported_in_expected_order() {
        let expected = [
            source_record_id(9),
            source_record_id(7),
            source_record_id(8),
        ];
        let error = AcquisitionReceipt::reconcile(
            RetrievalId::from_bytes([6; 32]),
            expected,
            [omitted(9, 1)],
        )
        .unwrap_err();

        assert_eq!(
            error,
            AcquisitionReceiptError::MissingOutcomeAssignments(vec![
                source_record_id(7),
                source_record_id(8),
            ])
        );
        assert_eq!(error.affected_count(), 2);
    }

    #[test]
    fn one_persisted_event_cannot_satisfy_two_source_records() {
        let duplicate_event = event_id(10);
        let error = AcquisitionReceipt::reconcile(
            RetrievalId::from_bytes([7; 32]),
            [source_record_id(10), source_record_id(11)],
            [source_exact(10, 10), source_exact(11, 10)],
        )
        .unwrap_err();

        assert_eq!(
            error,
            AcquisitionReceiptError::DuplicatePersistedEvent(duplicate_event)
        );
    }

    #[test]
    fn sensitive_acquisition_debug_and_errors_are_contentless() {
        let canary_source_record_id = source_record_id(12);
        let canary_event_id = event_id(12);
        let canary_policy_digest = PolicyDigest::from_bytes([0x55; 32]);
        let canary_transformation_receipt_id = TransformationReceiptId::from_bytes([0x66; 32]);
        let basis = ExactnessBasis::PostPolicy {
            policy_digest: canary_policy_digest,
            transformation_receipt_id: canary_transformation_receipt_id,
        };
        let assignment = AcquisitionOutcomeAssignment::new(
            canary_source_record_id,
            AcquisitionOutcome::Persisted {
                event_id: canary_event_id,
                exactness_basis: basis,
            },
        );
        let receipt = AcquisitionReceipt::reconcile(
            RetrievalId::from_bytes([8; 32]),
            [canary_source_record_id],
            [assignment.clone()],
        )
        .unwrap();
        let error = AcquisitionReceipt::reconcile(
            RetrievalId::from_bytes([9; 32]),
            [canary_source_record_id],
            [assignment.clone(), assignment.clone()],
        )
        .unwrap_err();

        let canaries = [
            canary_source_record_id.to_string(),
            canary_event_id.to_string(),
            canary_policy_digest.to_string(),
            canary_transformation_receipt_id.to_string(),
        ];
        let rendered = [
            format!("{canary_source_record_id:?}"),
            format!("{canary_policy_digest:?}"),
            format!("{canary_transformation_receipt_id:?}"),
            format!("{basis:?}"),
            format!("{assignment:?}"),
            format!("{:?}", assignment.outcome()),
            format!("{:?}", receipt.entries()[0]),
            format!("{receipt:?}"),
            format!("{error:?}"),
            error.to_string(),
        ];
        for output in rendered {
            for canary in &canaries {
                assert!(!output.contains(canary));
            }
        }
        assert_eq!(
            format!("{canary_source_record_id:?}"),
            "SourceRecordId(<redacted>)"
        );
        assert_eq!(
            format!("{basis:?}"),
            "ExactnessBasis { code: \"post_policy\" }"
        );
        assert_eq!(
            format!("{error:?}"),
            "AcquisitionReceiptError { code: \"EVIDENTRAIL_ACQUISITION_DUPLICATE_OUTCOME_ASSIGNMENT\", affected_count: 1 }"
        );
    }
}
