use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::PresentationDisposition;

use crate::coverage::{PresentationAssignment, PresentationReceipt};
use crate::ledger::EventLedger;

/// Exact assessment of one already-rendered complete candidate artifact.
///
/// The token count is intentionally not decomposed into event or fixed-cost
/// fragments: pinned BPE tokenization can merge across every such boundary.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WholeRenderAssessmentV1 {
    total_rendered_tokens: u64,
    total_token_limit: u64,
}

impl WholeRenderAssessmentV1 {
    #[must_use]
    pub const fn new(total_rendered_tokens: u64, total_token_limit: u64) -> Self {
        Self {
            total_rendered_tokens,
            total_token_limit,
        }
    }

    #[must_use]
    pub const fn total_rendered_tokens(self) -> u64 {
        self.total_rendered_tokens
    }

    #[must_use]
    pub const fn total_token_limit(self) -> u64 {
        self.total_token_limit
    }

    #[must_use]
    pub const fn fits(self) -> bool {
        self.total_rendered_tokens <= self.total_token_limit
    }
}

impl fmt::Debug for WholeRenderAssessmentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WholeRenderAssessmentV1")
            .field("total_rendered_tokens", &self.total_rendered_tokens)
            .field("total_token_limit", &self.total_token_limit)
            .field("fits", &self.fits())
            .finish()
    }
}

/// Selected exact passthrough with exhaustive shown-verbatim accounting.
#[derive(Clone, PartialEq, Eq)]
pub struct PassthroughSelection {
    assessment: WholeRenderAssessmentV1,
    presentation_receipt: PresentationReceipt,
}

impl PassthroughSelection {
    #[must_use]
    pub const fn assessment(&self) -> WholeRenderAssessmentV1 {
        self.assessment
    }

    #[must_use]
    pub const fn presentation_receipt(&self) -> &PresentationReceipt {
        &self.presentation_receipt
    }
}

impl fmt::Debug for PassthroughSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PassthroughSelection")
            .field("assessment", &self.assessment)
            .field(
                "shown_event_count",
                &self.presentation_receipt.persisted_count(),
            )
            .finish()
    }
}

/// Honest result of the final whole-render passthrough assessment.
#[derive(Clone, PartialEq, Eq)]
pub enum PassthroughDecision {
    Selected(PassthroughSelection),
    CompilationRequired(WholeRenderAssessmentV1),
}

impl PassthroughDecision {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Selected(_) => "selected",
            Self::CompilationRequired(_) => "compilation_required",
        }
    }

    #[must_use]
    pub const fn assessment(&self) -> WholeRenderAssessmentV1 {
        match self {
            Self::Selected(selection) => selection.assessment,
            Self::CompilationRequired(assessment) => *assessment,
        }
    }
}

impl fmt::Debug for PassthroughDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PassthroughDecision")
            .field("code", &self.code())
            .field("assessment", &self.assessment())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PassthroughSelectionError {
    PresentationInvariantViolation,
}

impl PassthroughSelectionError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PresentationInvariantViolation => {
                "EVIDENTRAIL_PASSTHROUGH_PRESENTATION_INVARIANT_VIOLATION"
            }
        }
    }
}

impl fmt::Debug for PassthroughSelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PassthroughSelectionError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for PassthroughSelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for PassthroughSelectionError {}

/// Apply the mandatory passthrough-first rule to an exact complete-render
/// token count. A status and receipt are constructed only after the artifact
/// fits; an over-budget candidate cannot masquerade as passthrough.
pub fn select_whole_render_passthrough(
    ledger: &EventLedger,
    assessment: WholeRenderAssessmentV1,
) -> Result<PassthroughDecision, PassthroughSelectionError> {
    if !assessment.fits() {
        return Ok(PassthroughDecision::CompilationRequired(assessment));
    }

    let presentation_receipt = PresentationReceipt::reconcile(
        ledger,
        ledger.events().iter().map(|event| {
            PresentationAssignment::new(event.id(), PresentationDisposition::ShownVerbatim)
        }),
    )
    .map_err(|_| PassthroughSelectionError::PresentationInvariantViolation)?;

    Ok(PassthroughDecision::Selected(PassthroughSelection {
        assessment,
        presentation_receipt,
    }))
}
