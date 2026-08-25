use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::{
    EventId, PresentationCounts, PresentationDisposition, PresentationReceiptId, RetrievalId,
};

use crate::hash::{finish_presentation_receipt, presentation_receipt_hasher, update_field};
use crate::ledger::EventLedger;

/// Proposed presentation outcome for one persisted event.
#[derive(Clone, PartialEq, Eq)]
pub struct PresentationAssignment {
    event_id: EventId,
    disposition: PresentationDisposition,
}

impl PresentationAssignment {
    #[must_use]
    pub const fn new(event_id: EventId, disposition: PresentationDisposition) -> Self {
        Self {
            event_id,
            disposition,
        }
    }

    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn disposition(&self) -> &PresentationDisposition {
        &self.disposition
    }
}

impl fmt::Debug for PresentationAssignment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PresentationAssignment")
            .field("disposition_code", &self.disposition.code())
            .finish()
    }
}

/// Reconciled presentation entry. Only `PresentationReceipt::reconcile` can
/// construct one.
#[derive(Clone, PartialEq, Eq)]
pub struct PresentationReceiptEntry {
    event_id: EventId,
    disposition: PresentationDisposition,
}

impl PresentationReceiptEntry {
    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn disposition(&self) -> &PresentationDisposition {
        &self.disposition
    }
}

impl fmt::Debug for PresentationReceiptEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PresentationReceiptEntry")
            .field("disposition_code", &self.disposition.code())
            .finish()
    }
}

#[derive(PartialEq, Eq)]
pub enum PresentationReconciliationError {
    UnknownEvent(EventId),
    DuplicateAssignment(EventId),
    MissingAssignments(Vec<EventId>),
}

impl PresentationReconciliationError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnknownEvent(_) => "EVIDENTRAIL_PRESENTATION_UNKNOWN_EVENT",
            Self::DuplicateAssignment(_) => "EVIDENTRAIL_PRESENTATION_DUPLICATE_ASSIGNMENT",
            Self::MissingAssignments(_) => "EVIDENTRAIL_PRESENTATION_MISSING_ASSIGNMENTS",
        }
    }

    #[must_use]
    pub fn affected_event_count(&self) -> usize {
        match self {
            Self::UnknownEvent(_) | Self::DuplicateAssignment(_) => 1,
            Self::MissingAssignments(events) => events.len(),
        }
    }
}

impl fmt::Debug for PresentationReconciliationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PresentationReconciliationError")
            .field("code", &self.code())
            .field("affected_event_count", &self.affected_event_count())
            .finish()
    }
}

impl fmt::Display for PresentationReconciliationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} (affected_event_count={})",
            self.code(),
            self.affected_event_count()
        )
    }
}

impl StdError for PresentationReconciliationError {}

/// Exhaustive presentation accounting over persisted authorized events only.
/// Policy omissions exist exclusively in the acquisition receipt.
#[derive(Clone, PartialEq, Eq)]
pub struct PresentationReceipt {
    id: PresentationReceiptId,
    retrieval_id: RetrievalId,
    entries: Vec<PresentationReceiptEntry>,
    counts: PresentationCounts,
}

impl PresentationReceipt {
    pub fn reconcile<I>(
        ledger: &EventLedger,
        assignments: I,
    ) -> Result<Self, PresentationReconciliationError>
    where
        I: IntoIterator<Item = PresentationAssignment>,
    {
        let mut by_id = BTreeMap::new();
        for assignment in assignments {
            if !ledger.contains(assignment.event_id) {
                return Err(PresentationReconciliationError::UnknownEvent(
                    assignment.event_id,
                ));
            }
            if by_id
                .insert(assignment.event_id, assignment.disposition)
                .is_some()
            {
                return Err(PresentationReconciliationError::DuplicateAssignment(
                    assignment.event_id,
                ));
            }
        }

        let missing = ledger
            .events()
            .iter()
            .map(|event| event.id())
            .filter(|id| !by_id.contains_key(id))
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(PresentationReconciliationError::MissingAssignments(missing));
        }

        let mut counts = PresentationCounts::default();
        let entries = ledger
            .events()
            .iter()
            .map(|event| {
                let event_id = event.id();
                let disposition = by_id
                    .remove(&event_id)
                    .expect("all ledger event IDs were checked above");
                match &disposition {
                    PresentationDisposition::ShownVerbatim => counts.shown_verbatim += 1,
                    PresentationDisposition::PatternRepresented { .. } => {
                        counts.pattern_represented += 1;
                    }
                    PresentationDisposition::RetainedRaw => counts.retained_raw += 1,
                }
                PresentationReceiptEntry {
                    event_id,
                    disposition,
                }
            })
            .collect::<Vec<_>>();

        debug_assert_eq!(counts.persisted(), ledger.len());
        let id = presentation_receipt_id(ledger.retrieval_id(), &entries);
        Ok(Self {
            id,
            retrieval_id: ledger.retrieval_id(),
            entries,
            counts,
        })
    }

    #[must_use]
    pub const fn id(&self) -> PresentationReceiptId {
        self.id
    }

    #[must_use]
    pub const fn retrieval_id(&self) -> RetrievalId {
        self.retrieval_id
    }

    #[must_use]
    pub fn persisted_count(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub const fn unaccounted_count(&self) -> usize {
        0
    }

    #[must_use]
    pub const fn counts(&self) -> PresentationCounts {
        self.counts
    }

    #[must_use]
    pub fn entries(&self) -> &[PresentationReceiptEntry] {
        &self.entries
    }
}

impl fmt::Debug for PresentationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PresentationReceipt")
            .field("persisted_count", &self.entries.len())
            .field("counts", &self.counts)
            .finish()
    }
}

fn presentation_receipt_id(
    retrieval_id: RetrievalId,
    entries: &[PresentationReceiptEntry],
) -> PresentationReceiptId {
    let mut hasher = presentation_receipt_hasher(retrieval_id);
    for entry in entries {
        update_field(&mut hasher, entry.event_id.as_bytes());
        match &entry.disposition {
            PresentationDisposition::ShownVerbatim => {
                update_field(&mut hasher, b"shown-verbatim");
            }
            PresentationDisposition::PatternRepresented { pattern_id } => {
                update_field(&mut hasher, b"pattern-represented");
                update_field(&mut hasher, pattern_id.as_bytes());
            }
            PresentationDisposition::RetainedRaw => {
                update_field(&mut hasher, b"retained-raw");
            }
        }
    }
    finish_presentation_receipt(hasher)
}
