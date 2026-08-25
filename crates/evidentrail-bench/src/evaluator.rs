use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_core::{
    BlockIndex, EventId, EventLedger, FetchCompleteness, PresentationCounts,
    PresentationDisposition, PresentationReceipt, PresentationReceiptId, RetrievalId,
};
use evidentrail_schema::ArtifactDigest;

use crate::{
    EvidentrailBenchAnnotationSpecV1, EvidentrailBenchCaseSpecV1, EvidenceTargetV1, ExpectedAcquisitionClassV1,
    GovernedCaseArtifactBindingV1, GovernedCaseArtifactJoinV1, MethodDescriptor, MethodResult,
};

/// Exact, label-free method and presentation accounting safe for a public run
/// result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicCaseAccountingV1 {
    received_event_count: u64,
    candidate_event_count: u64,
    candidate_source_bytes: u64,
    selected_event_count: u64,
    selected_source_bytes: u64,
    retained_raw_event_count: u64,
    budget_excluded_candidate_count: u64,
    source_byte_budget: u64,
    shown_verbatim_event_count: u64,
    pattern_represented_event_count: u64,
    presentation_retained_raw_event_count: u64,
}

impl PublicCaseAccountingV1 {
    #[must_use]
    pub const fn received_event_count(self) -> u64 {
        self.received_event_count
    }

    #[must_use]
    pub const fn candidate_event_count(self) -> u64 {
        self.candidate_event_count
    }

    #[must_use]
    pub const fn candidate_source_bytes(self) -> u64 {
        self.candidate_source_bytes
    }

    #[must_use]
    pub const fn selected_event_count(self) -> u64 {
        self.selected_event_count
    }

    #[must_use]
    pub const fn selected_source_bytes(self) -> u64 {
        self.selected_source_bytes
    }

    #[must_use]
    pub const fn retained_raw_event_count(self) -> u64 {
        self.retained_raw_event_count
    }

    #[must_use]
    pub const fn budget_excluded_candidate_count(self) -> u64 {
        self.budget_excluded_candidate_count
    }

    #[must_use]
    pub const fn source_byte_budget(self) -> u64 {
        self.source_byte_budget
    }

    #[must_use]
    pub const fn shown_verbatim_event_count(self) -> u64 {
        self.shown_verbatim_event_count
    }

    #[must_use]
    pub const fn pattern_represented_event_count(self) -> u64 {
        self.pattern_represented_event_count
    }

    #[must_use]
    pub const fn presentation_retained_raw_event_count(self) -> u64 {
        self.presentation_retained_raw_event_count
    }

    #[must_use]
    pub const fn presented_event_count(self) -> u64 {
        self.shown_verbatim_event_count
            + self.pattern_represented_event_count
            + self.presentation_retained_raw_event_count
    }
}

/// Label-free case result suitable for public run artifacts.
///
/// It contains no requirements, target identities, evidence roles, satisfied
/// labels, or recall values. Those remain solely in
/// [`GovernedCaseEvaluationV1`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicCaseEvaluationResultV1 {
    public_case_artifact_digest: ArtifactDigest,
    method: MethodDescriptor,
    retrieval_id: RetrievalId,
    acquisition_class: ExpectedAcquisitionClassV1,
    presentation_receipt_id: PresentationReceiptId,
    accounting: PublicCaseAccountingV1,
}

impl PublicCaseEvaluationResultV1 {
    #[must_use]
    pub const fn public_case_artifact_digest(self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn method(self) -> MethodDescriptor {
        self.method
    }

    #[must_use]
    pub const fn retrieval_id(self) -> RetrievalId {
        self.retrieval_id
    }

    #[must_use]
    pub const fn acquisition_class(self) -> ExpectedAcquisitionClassV1 {
        self.acquisition_class
    }

    #[must_use]
    pub const fn presentation_receipt_id(self) -> PresentationReceiptId {
        self.presentation_receipt_id
    }

    #[must_use]
    pub const fn accounting(self) -> PublicCaseAccountingV1 {
        self.accounting
    }
}

impl fmt::Debug for PublicCaseEvaluationResultV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicCaseEvaluationResultV1")
            .field("public_case_artifact_present", &true)
            .field("method", &self.method)
            .field("retrieval_identity_present", &true)
            .field("acquisition_class", &self.acquisition_class)
            .field("presentation_receipt_present", &true)
            .field("accounting", &self.accounting)
            .finish()
    }
}

/// Exact governed weighted-recall counts.
///
/// The ratio is represented by the two integer weight totals; no float or
/// rounded scalar is persisted by this evaluator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GovernedRequirementRecallV1 {
    requirement_count: u64,
    satisfied_requirement_count: u64,
    total_weight_micros: u64,
    satisfied_weight_micros: u64,
}

impl GovernedRequirementRecallV1 {
    #[must_use]
    pub const fn requirement_count(self) -> u64 {
        self.requirement_count
    }

    #[must_use]
    pub const fn satisfied_requirement_count(self) -> u64 {
        self.satisfied_requirement_count
    }

    #[must_use]
    pub const fn missed_requirement_count(self) -> u64 {
        self.requirement_count - self.satisfied_requirement_count
    }

    #[must_use]
    pub const fn total_weight_micros(self) -> u64 {
        self.total_weight_micros
    }

    #[must_use]
    pub const fn satisfied_weight_micros(self) -> u64 {
        self.satisfied_weight_micros
    }

    /// Exact weighted-recall numerator and denominator.
    #[must_use]
    pub const fn exact_weight_ratio(self) -> (u64, u64) {
        (self.satisfied_weight_micros, self.total_weight_micros)
    }

    #[must_use]
    pub const fn is_perfect(self) -> bool {
        self.satisfied_weight_micros == self.total_weight_micros
    }
}

/// Governed evaluation output. Only its label-free projection belongs in a
/// public result artifact.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GovernedCaseEvaluationV1 {
    artifact_binding: GovernedCaseArtifactBindingV1,
    public_result: PublicCaseEvaluationResultV1,
    diagnostic_recall: GovernedRequirementRecallV1,
}

impl GovernedCaseEvaluationV1 {
    #[must_use]
    pub const fn artifact_binding(self) -> GovernedCaseArtifactBindingV1 {
        self.artifact_binding
    }

    #[must_use]
    pub const fn public_result(self) -> PublicCaseEvaluationResultV1 {
        self.public_result
    }

    #[must_use]
    pub const fn diagnostic_recall(self) -> GovernedRequirementRecallV1 {
        self.diagnostic_recall
    }
}

impl fmt::Debug for GovernedCaseEvaluationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedCaseEvaluationV1")
            .field("governed_artifact_binding", &self.artifact_binding)
            .field("public_result", &self.public_result)
            .field("diagnostic_recall", &self.diagnostic_recall)
            .finish()
    }
}

/// One exact method-accounting invariant checked by the evaluator.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CaseAccountingDimensionV1 {
    ReceivedEventCount,
    CandidateSet,
    CandidateEventCount,
    CandidateSourceBytes,
    SelectedSet,
    SelectedEventCount,
    SelectedSourceBytes,
    SelectedEventMetadata,
    SelectedEventOrder,
    SelectedCandidateSubset,
    RetainedRawEventCount,
    BudgetExcludedCandidateCount,
    SourceByteBudget,
    PresentationCounts,
}

impl CaseAccountingDimensionV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ReceivedEventCount => "received_event_count",
            Self::CandidateSet => "candidate_set",
            Self::CandidateEventCount => "candidate_event_count",
            Self::CandidateSourceBytes => "candidate_source_bytes",
            Self::SelectedSet => "selected_set",
            Self::SelectedEventCount => "selected_event_count",
            Self::SelectedSourceBytes => "selected_source_bytes",
            Self::SelectedEventMetadata => "selected_event_metadata",
            Self::SelectedEventOrder => "selected_event_order",
            Self::SelectedCandidateSubset => "selected_candidate_subset",
            Self::RetainedRawEventCount => "retained_raw_event_count",
            Self::BudgetExcludedCandidateCount => "budget_excluded_candidate_count",
            Self::SourceByteBudget => "source_byte_budget",
            Self::PresentationCounts => "presentation_counts",
        }
    }
}

impl fmt::Debug for CaseAccountingDimensionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CaseAccountingDimensionV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Contentless governed-evaluation failures.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CaseEvaluationError {
    PublicCaseArtifactBindingMismatch,
    PlanDigestMismatch,
    AcquisitionClassMismatch,
    RetrievalMismatch,
    BlockIndexRetrievalMismatch,
    BlockIndexRequired,
    UnknownEvidenceEvent {
        count: usize,
    },
    UnknownEvidenceBlock {
        count: usize,
    },
    MethodAccountingMismatch {
        dimension: CaseAccountingDimensionV1,
    },
    PresentationReconciliationFailed,
    PresentationReceiptMismatch,
    AccountingValueOverflow,
    RequirementWeightOverflow,
}

impl CaseEvaluationError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PublicCaseArtifactBindingMismatch => {
                "EVIDENTRAIL_BENCH_EVAL_PUBLIC_CASE_ARTIFACT_BINDING_MISMATCH"
            }
            Self::PlanDigestMismatch => "EVIDENTRAIL_BENCH_EVAL_PLAN_DIGEST_MISMATCH",
            Self::AcquisitionClassMismatch => "EVIDENTRAIL_BENCH_EVAL_ACQUISITION_CLASS_MISMATCH",
            Self::RetrievalMismatch => "EVIDENTRAIL_BENCH_EVAL_RETRIEVAL_MISMATCH",
            Self::BlockIndexRetrievalMismatch => "EVIDENTRAIL_BENCH_EVAL_BLOCK_INDEX_RETRIEVAL_MISMATCH",
            Self::BlockIndexRequired => "EVIDENTRAIL_BENCH_EVAL_BLOCK_INDEX_REQUIRED",
            Self::UnknownEvidenceEvent { .. } => "EVIDENTRAIL_BENCH_EVAL_UNKNOWN_EVIDENCE_EVENT",
            Self::UnknownEvidenceBlock { .. } => "EVIDENTRAIL_BENCH_EVAL_UNKNOWN_EVIDENCE_BLOCK",
            Self::MethodAccountingMismatch { .. } => "EVIDENTRAIL_BENCH_EVAL_METHOD_ACCOUNTING_MISMATCH",
            Self::PresentationReconciliationFailed => {
                "EVIDENTRAIL_BENCH_EVAL_PRESENTATION_RECONCILIATION_FAILED"
            }
            Self::PresentationReceiptMismatch => "EVIDENTRAIL_BENCH_EVAL_PRESENTATION_RECEIPT_MISMATCH",
            Self::AccountingValueOverflow => "EVIDENTRAIL_BENCH_EVAL_ACCOUNTING_VALUE_OVERFLOW",
            Self::RequirementWeightOverflow => "EVIDENTRAIL_BENCH_EVAL_REQUIREMENT_WEIGHT_OVERFLOW",
        }
    }
}

impl fmt::Debug for CaseEvaluationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("CaseEvaluationError");
        debug.field("code", &self.code());
        match self {
            Self::UnknownEvidenceEvent { count } | Self::UnknownEvidenceBlock { count } => {
                debug.field("count", count);
            }
            Self::MethodAccountingMismatch { dimension } => {
                debug.field("dimension", &dimension.code());
            }
            _ => {}
        }
        debug.finish()
    }
}

impl fmt::Display for CaseEvaluationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for CaseEvaluationError {}

/// Join and evaluate one public case, governed annotation, sealed ledger, and
/// deterministic method result.
///
/// A reconciled block index is optional for event-only annotations and required
/// as soon as any diagnostic or role target references a block. A block target
/// is selected only when every one of its member events is selected, so partial
/// block retention cannot satisfy an intact-block requirement.
pub fn evaluate_governed_case_v1(
    artifact_join: GovernedCaseArtifactJoinV1,
    public_case: &EvidentrailBenchCaseSpecV1,
    annotation: &EvidentrailBenchAnnotationSpecV1,
    ledger: &EventLedger,
    method_result: &MethodResult,
    block_index: Option<&BlockIndex<'_>>,
) -> Result<GovernedCaseEvaluationV1, CaseEvaluationError> {
    evaluate_governed_case_impl_v1(
        artifact_join,
        public_case,
        annotation,
        ledger,
        method_result,
        None,
        block_index,
    )
}

/// Evaluate a case using an already frozen, exhaustively reconciled
/// presentation receipt.
///
/// This is the governed-runner entrypoint: the deterministic method result is
/// produced first, the public presentation is reconciled second, and only then
/// can hidden annotations enter evaluation. The supplied receipt is checked
/// event-by-event against the frozen result; matching aggregate counts alone
/// are insufficient.
pub fn evaluate_governed_case_with_presentation_v1(
    artifact_join: GovernedCaseArtifactJoinV1,
    public_case: &EvidentrailBenchCaseSpecV1,
    annotation: &EvidentrailBenchAnnotationSpecV1,
    ledger: &EventLedger,
    method_result: &MethodResult,
    presentation: &PresentationReceipt,
    block_index: Option<&BlockIndex<'_>>,
) -> Result<GovernedCaseEvaluationV1, CaseEvaluationError> {
    evaluate_governed_case_impl_v1(
        artifact_join,
        public_case,
        annotation,
        ledger,
        method_result,
        Some(presentation),
        block_index,
    )
}

fn evaluate_governed_case_impl_v1(
    artifact_join: GovernedCaseArtifactJoinV1,
    public_case: &EvidentrailBenchCaseSpecV1,
    annotation: &EvidentrailBenchAnnotationSpecV1,
    ledger: &EventLedger,
    method_result: &MethodResult,
    supplied_presentation: Option<&PresentationReceipt>,
    block_index: Option<&BlockIndex<'_>>,
) -> Result<GovernedCaseEvaluationV1, CaseEvaluationError> {
    let artifact_binding = validate_governed_case_inputs_v1(
        artifact_join,
        public_case,
        annotation,
        ledger,
        block_index,
    )?;
    let acquisition_class = acquisition_class(ledger.fetch_completion().completeness());

    let validated = validate_method_result(ledger, method_result)?;
    validate_governed_annotation_targets_v1(annotation, ledger, block_index)?;
    let selected_targets = selected_targets_v1(block_index, &validated.selected_event_ids);
    let diagnostic_recall = evaluate_requirements_v1(annotation, &selected_targets)?;

    let generated_presentation;
    let presentation = if let Some(presentation) = supplied_presentation {
        presentation
    } else {
        let assignments = method_result
            .presentation_assignments(ledger)
            .map_err(|_| CaseEvaluationError::RetrievalMismatch)?;
        generated_presentation = PresentationReceipt::reconcile(ledger, assignments)
            .map_err(|_| CaseEvaluationError::PresentationReconciliationFailed)?;
        &generated_presentation
    };
    validate_presentation_receipt(ledger, presentation, &validated.selected_event_ids)?;
    validate_presentation_accounting(
        ledger,
        method_result,
        presentation.counts(),
        validated.selected_event_ids.len(),
    )?;

    let accounting = PublicCaseAccountingV1 {
        received_event_count: to_u64(ledger.len())?,
        candidate_event_count: to_u64(validated.candidate_event_count)?,
        candidate_source_bytes: to_u64(validated.candidate_source_bytes)?,
        selected_event_count: to_u64(validated.selected_event_ids.len())?,
        selected_source_bytes: to_u64(validated.selected_source_bytes)?,
        retained_raw_event_count: to_u64(
            ledger
                .len()
                .checked_sub(validated.selected_event_ids.len())
                .ok_or(CaseEvaluationError::MethodAccountingMismatch {
                    dimension: CaseAccountingDimensionV1::RetainedRawEventCount,
                })?,
        )?,
        budget_excluded_candidate_count: to_u64(
            method_result.accounting().budget_excluded_candidate_count(),
        )?,
        source_byte_budget: to_u64(method_result.accounting().budget().bytes())?,
        shown_verbatim_event_count: to_u64(presentation.counts().shown_verbatim)?,
        pattern_represented_event_count: to_u64(presentation.counts().pattern_represented)?,
        presentation_retained_raw_event_count: to_u64(presentation.counts().retained_raw)?,
    };
    let public_result = PublicCaseEvaluationResultV1 {
        public_case_artifact_digest: artifact_binding.public_case_artifact_digest(),
        method: method_result.method(),
        retrieval_id: ledger.retrieval_id(),
        acquisition_class,
        presentation_receipt_id: presentation.id(),
        accounting,
    };

    Ok(GovernedCaseEvaluationV1 {
        artifact_binding,
        public_result,
        diagnostic_recall,
    })
}

pub(crate) fn validate_governed_case_inputs_v1(
    artifact_join: GovernedCaseArtifactJoinV1,
    public_case: &EvidentrailBenchCaseSpecV1,
    annotation: &EvidentrailBenchAnnotationSpecV1,
    ledger: &EventLedger,
    block_index: Option<&BlockIndex<'_>>,
) -> Result<GovernedCaseArtifactBindingV1, CaseEvaluationError> {
    let artifact_binding = artifact_join.artifact_binding();
    if annotation.public_case_artifact_digest() != artifact_binding.public_case_artifact_digest() {
        return Err(CaseEvaluationError::PublicCaseArtifactBindingMismatch);
    }
    if public_case.plan_digest() != ledger.plan_digest() {
        return Err(CaseEvaluationError::PlanDigestMismatch);
    }
    if acquisition_class(ledger.fetch_completion().completeness())
        != public_case.expected_acquisition_class()
    {
        return Err(CaseEvaluationError::AcquisitionClassMismatch);
    }
    if block_index.is_some_and(|index| index.retrieval_id() != ledger.retrieval_id()) {
        return Err(CaseEvaluationError::BlockIndexRetrievalMismatch);
    }
    Ok(artifact_binding)
}

fn validate_presentation_receipt(
    ledger: &EventLedger,
    presentation: &PresentationReceipt,
    selected_event_ids: &BTreeSet<EventId>,
) -> Result<(), CaseEvaluationError> {
    if presentation.retrieval_id() != ledger.retrieval_id()
        || presentation.persisted_count() != ledger.len()
        || presentation.entries().len() != ledger.len()
    {
        return Err(CaseEvaluationError::PresentationReceiptMismatch);
    }

    for (entry, event) in presentation.entries().iter().zip(ledger.events()) {
        let expected = if selected_event_ids.contains(&event.id()) {
            PresentationDisposition::ShownVerbatim
        } else {
            PresentationDisposition::RetainedRaw
        };
        if entry.event_id() != event.id() || entry.disposition() != &expected {
            return Err(CaseEvaluationError::PresentationReceiptMismatch);
        }
    }
    Ok(())
}

struct ValidatedMethodResult {
    candidate_event_count: usize,
    candidate_source_bytes: usize,
    selected_event_ids: BTreeSet<EventId>,
    selected_source_bytes: usize,
}

fn validate_method_result(
    ledger: &EventLedger,
    method_result: &MethodResult,
) -> Result<ValidatedMethodResult, CaseEvaluationError> {
    if method_result.retrieval_id() != ledger.retrieval_id() {
        return Err(CaseEvaluationError::RetrievalMismatch);
    }
    let accounting = method_result.accounting();
    if accounting.received_event_count() != ledger.len() {
        return accounting_mismatch(CaseAccountingDimensionV1::ReceivedEventCount);
    }

    let candidate_event_ids = method_result.candidate_event_ids();
    let candidate_set = candidate_event_ids.iter().copied().collect::<BTreeSet<_>>();
    if candidate_set.len() != candidate_event_ids.len()
        || candidate_set
            .iter()
            .any(|event_id| !ledger.contains(*event_id))
    {
        return accounting_mismatch(CaseAccountingDimensionV1::CandidateSet);
    }
    let mut candidate_source_bytes = 0usize;
    for event in ledger.events() {
        if candidate_set.contains(&event.id()) {
            candidate_source_bytes = candidate_source_bytes
                .checked_add(event.raw().len())
                .ok_or(CaseEvaluationError::AccountingValueOverflow)?;
        }
    }
    if accounting.candidate_event_count() != candidate_set.len() {
        return accounting_mismatch(CaseAccountingDimensionV1::CandidateEventCount);
    }
    if accounting.candidate_cost().unique_source_bytes() != candidate_source_bytes {
        return accounting_mismatch(CaseAccountingDimensionV1::CandidateSourceBytes);
    }

    let mut selected_event_ids = BTreeSet::new();
    let mut selected_source_bytes = 0usize;
    let mut previous_ordinal = None;
    for selected in method_result.selected() {
        if !selected_event_ids.insert(selected.event_id()) {
            return accounting_mismatch(CaseAccountingDimensionV1::SelectedSet);
        }
        let event = ledger.event(selected.event_id()).map_err(|_| {
            CaseEvaluationError::MethodAccountingMismatch {
                dimension: CaseAccountingDimensionV1::SelectedSet,
            }
        })?;
        if selected.ordinal() != event.ordinal() || selected.source_byte_cost() != event.raw().len()
        {
            return accounting_mismatch(CaseAccountingDimensionV1::SelectedEventMetadata);
        }
        if previous_ordinal.is_some_and(|ordinal| selected.ordinal() <= ordinal) {
            return accounting_mismatch(CaseAccountingDimensionV1::SelectedEventOrder);
        }
        previous_ordinal = Some(selected.ordinal());
        selected_source_bytes = selected_source_bytes
            .checked_add(event.raw().len())
            .ok_or(CaseEvaluationError::AccountingValueOverflow)?;
    }
    if !selected_event_ids.is_subset(&candidate_set) {
        return accounting_mismatch(CaseAccountingDimensionV1::SelectedCandidateSubset);
    }
    if accounting.selected_event_count() != selected_event_ids.len() {
        return accounting_mismatch(CaseAccountingDimensionV1::SelectedEventCount);
    }
    if accounting.selected_source_bytes() != selected_source_bytes {
        return accounting_mismatch(CaseAccountingDimensionV1::SelectedSourceBytes);
    }
    let retained_raw = ledger.len().checked_sub(selected_event_ids.len()).ok_or(
        CaseEvaluationError::MethodAccountingMismatch {
            dimension: CaseAccountingDimensionV1::RetainedRawEventCount,
        },
    )?;
    if accounting.retained_raw_event_count() != retained_raw {
        return accounting_mismatch(CaseAccountingDimensionV1::RetainedRawEventCount);
    }
    let budget_excluded = candidate_set
        .len()
        .checked_sub(selected_event_ids.len())
        .ok_or(CaseEvaluationError::MethodAccountingMismatch {
            dimension: CaseAccountingDimensionV1::BudgetExcludedCandidateCount,
        })?;
    if accounting.budget_excluded_candidate_count() != budget_excluded {
        return accounting_mismatch(CaseAccountingDimensionV1::BudgetExcludedCandidateCount);
    }
    if selected_source_bytes > accounting.budget().bytes() {
        return accounting_mismatch(CaseAccountingDimensionV1::SourceByteBudget);
    }

    Ok(ValidatedMethodResult {
        candidate_event_count: candidate_set.len(),
        candidate_source_bytes,
        selected_event_ids,
        selected_source_bytes,
    })
}

fn validate_presentation_accounting(
    ledger: &EventLedger,
    method_result: &MethodResult,
    counts: PresentationCounts,
    selected_event_count: usize,
) -> Result<(), CaseEvaluationError> {
    let retained_raw = ledger.len().checked_sub(selected_event_count).ok_or(
        CaseEvaluationError::MethodAccountingMismatch {
            dimension: CaseAccountingDimensionV1::PresentationCounts,
        },
    )?;
    if counts.persisted() != ledger.len()
        || counts.shown_verbatim != selected_event_count
        || counts.pattern_represented != 0
        || counts.retained_raw != retained_raw
        || method_result.accounting().retained_raw_event_count() != counts.retained_raw
    {
        return accounting_mismatch(CaseAccountingDimensionV1::PresentationCounts);
    }
    Ok(())
}

fn collect_annotation_targets(
    annotation: &EvidentrailBenchAnnotationSpecV1,
) -> BTreeSet<EvidenceTargetV1> {
    let mut targets = annotation
        .diagnostic_requirements()
        .iter()
        .flat_map(|requirement| requirement.alternatives().iter().flatten().copied())
        .collect::<BTreeSet<_>>();
    for role_targets in [
        annotation.precursor_targets(),
        annotation.symptom_targets(),
        annotation.supporting_targets(),
        annotation.distractor_targets(),
        annotation.unsafe_targets(),
    ]
    .into_iter()
    .flatten()
    {
        targets.extend(role_targets.iter().copied());
    }
    targets
}

pub(crate) fn validate_governed_annotation_targets_v1(
    annotation: &EvidentrailBenchAnnotationSpecV1,
    ledger: &EventLedger,
    block_index: Option<&BlockIndex<'_>>,
) -> Result<(), CaseEvaluationError> {
    let targets = collect_annotation_targets(annotation);
    validate_annotation_targets(ledger, block_index, &targets)
}

fn validate_annotation_targets(
    ledger: &EventLedger,
    block_index: Option<&BlockIndex<'_>>,
    targets: &BTreeSet<EvidenceTargetV1>,
) -> Result<(), CaseEvaluationError> {
    let block_target_count = targets
        .iter()
        .filter(|target| matches!(target, EvidenceTargetV1::Block(_)))
        .count();
    if block_target_count != 0 && block_index.is_none() {
        return Err(CaseEvaluationError::BlockIndexRequired);
    }

    let unknown_event_count = targets
        .iter()
        .filter(|target| match target {
            EvidenceTargetV1::Event(event_id) => !ledger.contains(*event_id),
            EvidenceTargetV1::Block(_) => false,
        })
        .count();
    if unknown_event_count != 0 {
        return Err(CaseEvaluationError::UnknownEvidenceEvent {
            count: unknown_event_count,
        });
    }

    let unknown_block_count = block_index.map_or(0, |block_index| {
        targets
            .iter()
            .filter(|target| match target {
                EvidenceTargetV1::Event(_) => false,
                EvidenceTargetV1::Block(block_id) => block_index.block(*block_id).is_err(),
            })
            .count()
    });
    if unknown_block_count != 0 {
        return Err(CaseEvaluationError::UnknownEvidenceBlock {
            count: unknown_block_count,
        });
    }
    Ok(())
}

pub(crate) fn selected_targets_v1(
    block_index: Option<&BlockIndex<'_>>,
    selected_event_ids: &BTreeSet<EventId>,
) -> BTreeSet<EvidenceTargetV1> {
    let mut selected_targets = selected_event_ids
        .iter()
        .copied()
        .map(EvidenceTargetV1::Event)
        .collect::<BTreeSet<_>>();
    if let Some(block_index) = block_index {
        selected_targets.extend(
            block_index
                .blocks()
                .iter()
                .filter(|block| {
                    block
                        .member_ids()
                        .iter()
                        .all(|event_id| selected_event_ids.contains(event_id))
                })
                .map(|block| EvidenceTargetV1::Block(block.id())),
        );
    }
    selected_targets
}

pub(crate) fn evaluate_requirements_v1(
    annotation: &EvidentrailBenchAnnotationSpecV1,
    selected_targets: &BTreeSet<EvidenceTargetV1>,
) -> Result<GovernedRequirementRecallV1, CaseEvaluationError> {
    let mut total_weight_micros = 0u64;
    let mut satisfied_weight_micros = 0u64;
    let mut satisfied_requirement_count = 0usize;
    for requirement in annotation.diagnostic_requirements() {
        total_weight_micros = total_weight_micros
            .checked_add(requirement.weight_micros())
            .ok_or(CaseEvaluationError::RequirementWeightOverflow)?;
        if requirement.is_satisfied_by(selected_targets) {
            satisfied_requirement_count = satisfied_requirement_count
                .checked_add(1)
                .ok_or(CaseEvaluationError::AccountingValueOverflow)?;
            satisfied_weight_micros = satisfied_weight_micros
                .checked_add(requirement.weight_micros())
                .ok_or(CaseEvaluationError::RequirementWeightOverflow)?;
        }
    }

    Ok(GovernedRequirementRecallV1 {
        requirement_count: to_u64(annotation.diagnostic_requirements().len())?,
        satisfied_requirement_count: to_u64(satisfied_requirement_count)?,
        total_weight_micros,
        satisfied_weight_micros,
    })
}

pub(crate) const fn acquisition_class(
    completeness: &FetchCompleteness,
) -> ExpectedAcquisitionClassV1 {
    match completeness {
        FetchCompleteness::Complete { .. } => ExpectedAcquisitionClassV1::Complete,
        FetchCompleteness::Partial { .. } => ExpectedAcquisitionClassV1::Partial,
        FetchCompleteness::Unknown { .. } => ExpectedAcquisitionClassV1::Unknown,
    }
}

fn accounting_mismatch<T>(dimension: CaseAccountingDimensionV1) -> Result<T, CaseEvaluationError> {
    Err(CaseEvaluationError::MethodAccountingMismatch { dimension })
}

fn to_u64(value: usize) -> Result<u64, CaseEvaluationError> {
    u64::try_from(value).map_err(|_| CaseEvaluationError::AccountingValueOverflow)
}
