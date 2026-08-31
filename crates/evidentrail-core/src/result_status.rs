use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::{FetchCompleteness, PresentationDisposition};

use crate::coverage::{PresentationAssignment, PresentationReceipt};
use crate::ledger::EventLedger;
use crate::passthrough::PassthroughSelection;

/// Semantic contract version for [`ResultStatusV1`].
pub const RESULT_STATUS_CONTRACT_VERSION_V1: u16 = 1;

/// Typed reason that Evidentrail cannot honestly produce a selected evidence result.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NeedsMoreReasonV1 {
    FixedOverheadExceedsBudget,
    MandatoryEvidenceExceedsBudget,
    CandidateConfidenceBelowSupportedEnvelope,
    QuestionUnsupported,
    ScopeUnsupported,
    OtherVersioned { version: u16, code: u16 },
}

impl NeedsMoreReasonV1 {
    /// Stable contentless reason code suitable for diagnostics and wire maps.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::FixedOverheadExceedsBudget => "fixed_overhead_exceeds_budget",
            Self::MandatoryEvidenceExceedsBudget => "mandatory_evidence_exceeds_budget",
            Self::CandidateConfidenceBelowSupportedEnvelope => {
                "candidate_confidence_below_supported_envelope"
            }
            Self::QuestionUnsupported => "question_unsupported",
            Self::ScopeUnsupported => "scope_unsupported",
            Self::OtherVersioned { .. } => "other_versioned",
        }
    }
}

impl fmt::Debug for NeedsMoreReasonV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NeedsMoreReasonV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
enum SelectionStateKindV1 {
    Passthrough(PassthroughSelection),
    Compiled(PresentationReceipt),
    NeedsMore {
        reason: NeedsMoreReasonV1,
        presentation_receipt: PresentationReceipt,
    },
}

/// Checked downstream selection state, independent from acquisition state.
///
/// Its inner variants are private so callers cannot construct a compiled or
/// needs-more claim without the corresponding exhaustive receipt checks.
#[derive(Clone, PartialEq, Eq)]
pub struct SelectionStateV1 {
    kind: SelectionStateKindV1,
}

impl SelectionStateV1 {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match &self.kind {
            SelectionStateKindV1::Passthrough(_) => "passthrough",
            SelectionStateKindV1::Compiled(_) => "compiled",
            SelectionStateKindV1::NeedsMore { .. } => "needs_more",
        }
    }

    #[must_use]
    pub const fn presentation_receipt(&self) -> &PresentationReceipt {
        match &self.kind {
            SelectionStateKindV1::Passthrough(selection) => selection.presentation_receipt(),
            SelectionStateKindV1::Compiled(receipt)
            | SelectionStateKindV1::NeedsMore {
                presentation_receipt: receipt,
                ..
            } => receipt,
        }
    }

    #[must_use]
    pub const fn passthrough_selection(&self) -> Option<&PassthroughSelection> {
        match &self.kind {
            SelectionStateKindV1::Passthrough(selection) => Some(selection),
            SelectionStateKindV1::Compiled(_) | SelectionStateKindV1::NeedsMore { .. } => None,
        }
    }

    #[must_use]
    pub const fn needs_more_reason(&self) -> Option<NeedsMoreReasonV1> {
        match &self.kind {
            SelectionStateKindV1::NeedsMore { reason, .. } => Some(*reason),
            SelectionStateKindV1::Passthrough(_) | SelectionStateKindV1::Compiled(_) => None,
        }
    }
}

impl fmt::Debug for SelectionStateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut summary = formatter.debug_struct("SelectionStateV1");
        summary.field("code", &self.code()).field(
            "persisted_event_count",
            &self.presentation_receipt().persisted_count(),
        );
        if let Some(reason) = self.needs_more_reason() {
            summary.field("reason_code", &reason.code());
        }
        summary.finish()
    }
}

/// Independent acquisition and checked selection state for one sealed result.
#[derive(Clone, PartialEq, Eq)]
pub struct ResultStatusV1 {
    acquisition: FetchCompleteness,
    selection: SelectionStateV1,
}

impl ResultStatusV1 {
    /// Consume a selector-produced exact passthrough and bind it to its sealed
    /// ledger. Partial or unknown acquisition remains unchanged.
    pub fn passthrough(
        ledger: &EventLedger,
        selection: PassthroughSelection,
    ) -> Result<Self, ResultStatusConstructionError> {
        let receipt = selection.presentation_receipt();
        validate_receipt_binding(ledger, receipt)?;
        let counts = receipt.counts();
        if counts.shown_verbatim != ledger.len()
            || counts.pattern_represented != 0
            || counts.retained_raw != 0
            || receipt
                .entries()
                .iter()
                .any(|entry| entry.disposition() != &PresentationDisposition::ShownVerbatim)
        {
            return Err(ResultStatusConstructionError::InvalidPassthroughAccounting);
        }

        Ok(Self {
            acquisition: ledger.fetch_completion().completeness().clone(),
            selection: SelectionStateV1 {
                kind: SelectionStateKindV1::Passthrough(selection),
            },
        })
    }

    /// Construct compiled selection from an exhaustive ledger-bound receipt.
    /// At least one event must not be shown verbatim, and at least one event
    /// must be shown or pattern-represented; otherwise the honest state is
    /// passthrough or needs-more respectively.
    pub fn compiled(
        ledger: &EventLedger,
        presentation_receipt: PresentationReceipt,
    ) -> Result<Self, ResultStatusConstructionError> {
        validate_receipt_binding(ledger, &presentation_receipt)?;
        let counts = presentation_receipt.counts();
        if counts.shown_verbatim == ledger.len() {
            return Err(ResultStatusConstructionError::CompiledMasqueradesAsPassthrough);
        }
        if counts.shown_verbatim == 0 && counts.pattern_represented == 0 {
            return Err(ResultStatusConstructionError::CompiledHasNoPresentedEvidence);
        }

        Ok(Self {
            acquisition: ledger.fetch_completion().completeness().clone(),
            selection: SelectionStateV1 {
                kind: SelectionStateKindV1::Compiled(presentation_receipt),
            },
        })
    }

    /// Construct an honest needs-more state and account for every persisted
    /// event as retained raw. The reason is typed and cannot contain content.
    pub fn needs_more(
        ledger: &EventLedger,
        reason: NeedsMoreReasonV1,
    ) -> Result<Self, ResultStatusConstructionError> {
        let presentation_receipt = PresentationReceipt::reconcile(
            ledger,
            ledger.events().iter().map(|event| {
                PresentationAssignment::new(event.id(), PresentationDisposition::RetainedRaw)
            }),
        )
        .map_err(|_| ResultStatusConstructionError::NeedsMoreAccountingInvariantViolation)?;
        validate_receipt_binding(ledger, &presentation_receipt)?;

        Ok(Self {
            acquisition: ledger.fetch_completion().completeness().clone(),
            selection: SelectionStateV1 {
                kind: SelectionStateKindV1::NeedsMore {
                    reason,
                    presentation_receipt,
                },
            },
        })
    }

    #[must_use]
    pub const fn contract_version(&self) -> u16 {
        RESULT_STATUS_CONTRACT_VERSION_V1
    }

    #[must_use]
    pub const fn acquisition(&self) -> &FetchCompleteness {
        &self.acquisition
    }

    #[must_use]
    pub const fn selection(&self) -> &SelectionStateV1 {
        &self.selection
    }
}

impl fmt::Debug for ResultStatusV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResultStatusV1")
            .field("contract_version", &RESULT_STATUS_CONTRACT_VERSION_V1)
            .field("acquisition_code", &self.acquisition.code())
            .field("selection_code", &self.selection.code())
            .finish()
    }
}

/// Invalid cross-record state claim for one result.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ResultStatusConstructionError {
    PresentationRetrievalMismatch,
    PresentationEventCountMismatch,
    PresentationEventOrderMismatch,
    PresentationCountMismatch,
    InvalidPassthroughAccounting,
    CompiledMasqueradesAsPassthrough,
    CompiledHasNoPresentedEvidence,
    NeedsMoreAccountingInvariantViolation,
}

impl ResultStatusConstructionError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PresentationRetrievalMismatch => {
                "EVIDENTRAIL_RESULT_STATUS_PRESENTATION_RETRIEVAL_MISMATCH"
            }
            Self::PresentationEventCountMismatch => {
                "EVIDENTRAIL_RESULT_STATUS_PRESENTATION_EVENT_COUNT_MISMATCH"
            }
            Self::PresentationEventOrderMismatch => {
                "EVIDENTRAIL_RESULT_STATUS_PRESENTATION_EVENT_ORDER_MISMATCH"
            }
            Self::PresentationCountMismatch => {
                "EVIDENTRAIL_RESULT_STATUS_PRESENTATION_COUNT_MISMATCH"
            }
            Self::InvalidPassthroughAccounting => {
                "EVIDENTRAIL_RESULT_STATUS_INVALID_PASSTHROUGH_ACCOUNTING"
            }
            Self::CompiledMasqueradesAsPassthrough => {
                "EVIDENTRAIL_RESULT_STATUS_COMPILED_MASQUERADES_AS_PASSTHROUGH"
            }
            Self::CompiledHasNoPresentedEvidence => {
                "EVIDENTRAIL_RESULT_STATUS_COMPILED_HAS_NO_PRESENTED_EVIDENCE"
            }
            Self::NeedsMoreAccountingInvariantViolation => {
                "EVIDENTRAIL_RESULT_STATUS_NEEDS_MORE_ACCOUNTING_INVARIANT_VIOLATION"
            }
        }
    }
}

impl fmt::Debug for ResultStatusConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResultStatusConstructionError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for ResultStatusConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ResultStatusConstructionError {}

fn validate_receipt_binding(
    ledger: &EventLedger,
    receipt: &PresentationReceipt,
) -> Result<(), ResultStatusConstructionError> {
    if receipt.retrieval_id() != ledger.retrieval_id() {
        return Err(ResultStatusConstructionError::PresentationRetrievalMismatch);
    }
    if receipt.persisted_count() != ledger.len() {
        return Err(ResultStatusConstructionError::PresentationEventCountMismatch);
    }
    if receipt
        .entries()
        .iter()
        .zip(ledger.events())
        .any(|(entry, event)| entry.event_id() != event.id())
    {
        return Err(ResultStatusConstructionError::PresentationEventOrderMismatch);
    }
    if receipt.counts().persisted() != ledger.len() || receipt.unaccounted_count() != 0 {
        return Err(ResultStatusConstructionError::PresentationCountMismatch);
    }
    Ok(())
}
