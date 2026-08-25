use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;

use evidentrail_core::{BlockIndex, EventLedger, PresentationReceipt, derive_question_digest_v1};
use evidentrail_schema::ArtifactDigest;

use crate::{
    BenchmarkMethod, BenchmarkRunIdentityV1, ByteBudget, CandidateCapViolations,
    CandidateResourceEnvelope, CandidateResourceError, CaseEvaluationError,
    EvidentrailBenchAnnotationSpecV1, EvidentrailBenchCaseSpecV1, EvidentrailBenchHiddenEvaluationManifestV1,
    EvidentrailBenchRunManifestV1, FrozenCandidateRenderingV1, FrozenCandidateSelectionDigestV1,
    GovernedCaseArtifactBindingV1, GovernedRunAggregateV1, GovernedRunCaseInputV1,
    MeasurementEnvironmentV1, MeasurementProvenanceError, MeasurementProvenanceReceiptV1,
    MethodDescriptor, MethodError, MethodInput, MethodResult, RunAggregationError,
    aggregate_governed_run_v1, candidate_resource_envelope,
    derive_frozen_candidate_selection_digest_v1, evaluate_governed_case_with_presentation_v1,
};

/// Public-only input for one hermetic method invocation.
///
/// The exact query bytes are domain-separated and hashed inside the runner
/// before any method invocation. Measurement receipts are deliberately absent
/// from this type and enter only after method output is frozen.
#[derive(Clone, Copy)]
pub struct HermeticPublicCaseInputV1<'case> {
    public_case_artifact_digest: ArtifactDigest,
    public_case: &'case EvidentrailBenchCaseSpecV1,
    ledger: &'case EventLedger,
    query: &'case [u8],
}

impl<'case> HermeticPublicCaseInputV1<'case> {
    #[must_use]
    pub const fn new(
        public_case_artifact_digest: ArtifactDigest,
        public_case: &'case EvidentrailBenchCaseSpecV1,
        ledger: &'case EventLedger,
        query: &'case [u8],
    ) -> Self {
        Self {
            public_case_artifact_digest,
            public_case,
            ledger,
            query,
        }
    }

    #[must_use]
    pub const fn public_case_artifact_digest(self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }
}

impl fmt::Debug for HermeticPublicCaseInputV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HermeticPublicCaseInputV1")
            .field("public_case_link_present", &true)
            .field("event_count", &self.ledger.len())
            .field("query_byte_count", &self.query.len())
            .finish()
    }
}

/// Hidden annotation input admitted only after public method results and
/// presentation receipts have been frozen.
#[derive(Clone, Copy)]
pub struct HermeticGovernedCaseInputV1<'annotation, 'ledger> {
    artifact_binding: GovernedCaseArtifactBindingV1,
    annotation: &'annotation EvidentrailBenchAnnotationSpecV1,
    block_index: Option<&'annotation BlockIndex<'ledger>>,
}

impl<'annotation, 'ledger> HermeticGovernedCaseInputV1<'annotation, 'ledger> {
    #[must_use]
    pub const fn new(
        artifact_binding: GovernedCaseArtifactBindingV1,
        annotation: &'annotation EvidentrailBenchAnnotationSpecV1,
        block_index: Option<&'annotation BlockIndex<'ledger>>,
    ) -> Self {
        Self {
            artifact_binding,
            annotation,
            block_index,
        }
    }

    #[must_use]
    pub const fn artifact_binding(self) -> GovernedCaseArtifactBindingV1 {
        self.artifact_binding
    }
}

impl fmt::Debug for HermeticGovernedCaseInputV1<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HermeticGovernedCaseInputV1")
            .field("artifact_binding", &self.artifact_binding)
            .field("annotation_present", &true)
            .field("block_index_present", &self.block_index.is_some())
            .finish()
    }
}

/// Immutable, annotation-free internal state after method execution and
/// exhaustive presentation reconciliation, but before external measurement
/// provenance is admitted.
///
/// This borrows the sealed ledger and is not itself a shareable public result
/// artifact. Use the later governed aggregate's public projection for that.
pub struct FrozenPublicCaseRunV1<'case> {
    public_case_artifact_digest: ArtifactDigest,
    public_case: &'case EvidentrailBenchCaseSpecV1,
    ledger: &'case EventLedger,
    method_result: MethodResult,
    presentation_receipt: PresentationReceipt,
    candidate_selection_digest: FrozenCandidateSelectionDigestV1,
}

impl<'case> FrozenPublicCaseRunV1<'case> {
    #[must_use]
    pub const fn public_case_artifact_digest(&self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn public_case(&self) -> &'case EvidentrailBenchCaseSpecV1 {
        self.public_case
    }

    #[must_use]
    pub const fn ledger(&self) -> &'case EventLedger {
        self.ledger
    }

    #[must_use]
    pub const fn method_result(&self) -> &MethodResult {
        &self.method_result
    }

    #[must_use]
    pub const fn presentation_receipt(&self) -> &PresentationReceipt {
        &self.presentation_receipt
    }

    #[must_use]
    pub const fn candidate_selection_digest(&self) -> FrozenCandidateSelectionDigestV1 {
        self.candidate_selection_digest
    }
}

impl fmt::Debug for FrozenPublicCaseRunV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenPublicCaseRunV1")
            .field("public_case_link_present", &true)
            .field("event_count", &self.ledger.len())
            .field("method_result", &self.method_result)
            .field("presentation_receipt", &self.presentation_receipt)
            .field("candidate_selection_binding_present", &true)
            .finish()
    }
}

/// Canonically ordered, annotation-free internal run frozen before governed
/// evaluation.
pub struct FrozenPublicRunV1<'case> {
    run_manifest_artifact_digest: ArtifactDigest,
    run_manifest: EvidentrailBenchRunManifestV1,
    method: MethodDescriptor,
    cases: Vec<FrozenPublicCaseRunV1<'case>>,
}

impl<'case> FrozenPublicRunV1<'case> {
    #[must_use]
    pub const fn run_manifest_artifact_digest(&self) -> ArtifactDigest {
        self.run_manifest_artifact_digest
    }

    #[must_use]
    pub const fn run_identity(&self) -> BenchmarkRunIdentityV1 {
        self.run_manifest.identity()
    }

    #[must_use]
    pub const fn method(&self) -> MethodDescriptor {
        self.method
    }

    #[must_use]
    pub fn cases(&self) -> &[FrozenPublicCaseRunV1<'case>] {
        &self.cases
    }
}

impl fmt::Debug for FrozenPublicRunV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenPublicRunV1")
            .field("run_manifest_link_present", &true)
            .field("run_identity", &self.run_manifest.identity())
            .field("method", &self.method)
            .field("case_count", &self.cases.len())
            .finish()
    }
}

/// One externally measured case whose self-asserted receipt has been checked
/// against an exact frozen public case.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MeasurementValidatedCaseV1 {
    receipt: MeasurementProvenanceReceiptV1,
    candidate_resources: CandidateResourceEnvelope,
}

impl MeasurementValidatedCaseV1 {
    #[must_use]
    pub const fn public_case_artifact_digest(self) -> ArtifactDigest {
        self.receipt.public_case_artifact_digest()
    }

    #[must_use]
    pub const fn receipt(self) -> MeasurementProvenanceReceiptV1 {
        self.receipt
    }

    #[must_use]
    pub const fn candidate_resources(self) -> CandidateResourceEnvelope {
        self.candidate_resources
    }
}

impl fmt::Debug for MeasurementValidatedCaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MeasurementValidatedCaseV1")
            .field("public_case_link_present", &true)
            .field("measurement_receipt", &self.receipt)
            .field("candidate_resources", &self.candidate_resources)
            .finish()
    }
}

/// Annotation-free frozen run after every self-asserted measurement receipt
/// has been bound and checked against the declared resource cap.
pub struct MeasurementValidatedPublicRunV1<'case> {
    frozen_run: FrozenPublicRunV1<'case>,
    measurement_environment: MeasurementEnvironmentV1,
    cases: Vec<MeasurementValidatedCaseV1>,
}

impl<'case> MeasurementValidatedPublicRunV1<'case> {
    #[must_use]
    pub const fn frozen_run(&self) -> &FrozenPublicRunV1<'case> {
        &self.frozen_run
    }

    #[must_use]
    pub const fn measurement_environment(&self) -> MeasurementEnvironmentV1 {
        self.measurement_environment
    }

    #[must_use]
    pub fn cases(&self) -> &[MeasurementValidatedCaseV1] {
        &self.cases
    }
}

impl fmt::Debug for MeasurementValidatedPublicRunV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MeasurementValidatedPublicRunV1")
            .field("frozen_public_run", &self.frozen_run)
            .field("measurement_environment", &self.measurement_environment)
            .field("case_count", &self.cases.len())
            .field("trust_boundary", &"self_asserted_reproducibility_input")
            .finish()
    }
}

/// Stable, contentless failures from public execution and governed joining.
#[derive(Clone, PartialEq, Eq)]
pub enum HermeticRunnerError {
    MissingPublicCaseInputs { count: usize },
    DuplicatePublicCaseInput,
    ExtraPublicCaseInputs { count: usize },
    QuestionDigestMismatch,
    PlanDigestMismatch,
    BudgetPointNotDeclared,
    MethodByteBudgetNotRepresentable,
    MethodExecutionFailed { error: MethodError },
    MethodIdentityMismatch,
    CandidateSelectionBindingFailed { error: MeasurementProvenanceError },
    MissingCandidateRenderings { count: usize },
    DuplicateCandidateRendering,
    ExtraCandidateRenderings { count: usize },
    CandidateRenderingSelectionMismatch,
    CandidateRenderingPresentationMismatch,
    CandidateRenderingRendererIdentityMismatch,
    CandidateRenderingRendererVersionMismatch,
    MissingMeasurementReceipts { count: usize },
    DuplicateMeasurementReceipt,
    ExtraMeasurementReceipts { count: usize },
    MeasurementRunManifestArtifactMismatch,
    MeasurementRunIdentityMismatch,
    MeasurementMethodMismatch,
    MeasurementCandidateSelectionMismatch,
    MeasurementPresentationReceiptMismatch,
    MeasurementTokenizerIdentityMismatch,
    MeasurementRendererIdentityMismatch,
    MeasurementRendererVersionMismatch,
    MeasurementHarnessIdentityMismatch,
    MeasurementHarnessVersionMismatch,
    MeasurementRenderedCandidateArtifactMismatch,
    MeasurementRenderedCandidateByteCountMismatch,
    CandidateResourceAccountingFailed { error: CandidateResourceError },
    CandidateResourceCapExceeded { violations: CandidateCapViolations },
    PresentationAssignmentFailed,
    PresentationReconciliationFailed,
    GovernedHiddenManifestRunMismatch,
    GovernedHiddenCaseCohortMismatch,
    GovernedArtifactBindingMismatch,
    MissingGovernedCaseInputs { count: usize },
    DuplicateGovernedCaseInput,
    ExtraGovernedCaseInputs { count: usize },
    CaseEvaluationFailed { error: CaseEvaluationError },
    RunAggregationFailed { error: RunAggregationError },
}

impl HermeticRunnerError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::MissingPublicCaseInputs { .. } => "EVIDENTRAIL_BENCH_RUNNER_MISSING_PUBLIC_CASE_INPUTS",
            Self::DuplicatePublicCaseInput => "EVIDENTRAIL_BENCH_RUNNER_DUPLICATE_PUBLIC_CASE_INPUT",
            Self::ExtraPublicCaseInputs { .. } => "EVIDENTRAIL_BENCH_RUNNER_EXTRA_PUBLIC_CASE_INPUTS",
            Self::QuestionDigestMismatch => "EVIDENTRAIL_BENCH_RUNNER_QUESTION_DIGEST_MISMATCH",
            Self::PlanDigestMismatch => "EVIDENTRAIL_BENCH_RUNNER_PLAN_DIGEST_MISMATCH",
            Self::BudgetPointNotDeclared => "EVIDENTRAIL_BENCH_RUNNER_BUDGET_POINT_NOT_DECLARED",
            Self::MethodByteBudgetNotRepresentable => {
                "EVIDENTRAIL_BENCH_RUNNER_METHOD_BYTE_BUDGET_NOT_REPRESENTABLE"
            }
            Self::MethodExecutionFailed { .. } => "EVIDENTRAIL_BENCH_RUNNER_METHOD_EXECUTION_FAILED",
            Self::MethodIdentityMismatch => "EVIDENTRAIL_BENCH_RUNNER_METHOD_IDENTITY_MISMATCH",
            Self::CandidateSelectionBindingFailed { .. } => {
                "EVIDENTRAIL_BENCH_RUNNER_CANDIDATE_SELECTION_BINDING_FAILED"
            }
            Self::MissingCandidateRenderings { .. } => {
                "EVIDENTRAIL_BENCH_RUNNER_MISSING_CANDIDATE_RENDERINGS"
            }
            Self::DuplicateCandidateRendering => "EVIDENTRAIL_BENCH_RUNNER_DUPLICATE_CANDIDATE_RENDERING",
            Self::ExtraCandidateRenderings { .. } => {
                "EVIDENTRAIL_BENCH_RUNNER_EXTRA_CANDIDATE_RENDERINGS"
            }
            Self::CandidateRenderingSelectionMismatch => {
                "EVIDENTRAIL_BENCH_RUNNER_CANDIDATE_RENDERING_SELECTION_MISMATCH"
            }
            Self::CandidateRenderingPresentationMismatch => {
                "EVIDENTRAIL_BENCH_RUNNER_CANDIDATE_RENDERING_PRESENTATION_MISMATCH"
            }
            Self::CandidateRenderingRendererIdentityMismatch => {
                "EVIDENTRAIL_BENCH_RUNNER_CANDIDATE_RENDERING_RENDERER_IDENTITY_MISMATCH"
            }
            Self::CandidateRenderingRendererVersionMismatch => {
                "EVIDENTRAIL_BENCH_RUNNER_CANDIDATE_RENDERING_RENDERER_VERSION_MISMATCH"
            }
            Self::MissingMeasurementReceipts { .. } => {
                "EVIDENTRAIL_BENCH_RUNNER_MISSING_MEASUREMENT_RECEIPTS"
            }
            Self::DuplicateMeasurementReceipt => "EVIDENTRAIL_BENCH_RUNNER_DUPLICATE_MEASUREMENT_RECEIPT",
            Self::ExtraMeasurementReceipts { .. } => {
                "EVIDENTRAIL_BENCH_RUNNER_EXTRA_MEASUREMENT_RECEIPTS"
            }
            Self::MeasurementRunManifestArtifactMismatch => {
                "EVIDENTRAIL_BENCH_RUNNER_MEASUREMENT_RUN_MANIFEST_ARTIFACT_MISMATCH"
            }
            Self::MeasurementRunIdentityMismatch => {
                "EVIDENTRAIL_BENCH_RUNNER_MEASUREMENT_RUN_IDENTITY_MISMATCH"
            }
            Self::MeasurementMethodMismatch => "EVIDENTRAIL_BENCH_RUNNER_MEASUREMENT_METHOD_MISMATCH",
            Self::MeasurementCandidateSelectionMismatch => {
                "EVIDENTRAIL_BENCH_RUNNER_MEASUREMENT_CANDIDATE_SELECTION_MISMATCH"
            }
            Self::MeasurementPresentationReceiptMismatch => {
                "EVIDENTRAIL_BENCH_RUNNER_MEASUREMENT_PRESENTATION_RECEIPT_MISMATCH"
            }
            Self::MeasurementTokenizerIdentityMismatch => {
                "EVIDENTRAIL_BENCH_RUNNER_MEASUREMENT_TOKENIZER_IDENTITY_MISMATCH"
            }
            Self::MeasurementRendererIdentityMismatch => {
                "EVIDENTRAIL_BENCH_RUNNER_MEASUREMENT_RENDERER_IDENTITY_MISMATCH"
            }
            Self::MeasurementRendererVersionMismatch => {
                "EVIDENTRAIL_BENCH_RUNNER_MEASUREMENT_RENDERER_VERSION_MISMATCH"
            }
            Self::MeasurementHarnessIdentityMismatch => {
                "EVIDENTRAIL_BENCH_RUNNER_MEASUREMENT_HARNESS_IDENTITY_MISMATCH"
            }
            Self::MeasurementHarnessVersionMismatch => {
                "EVIDENTRAIL_BENCH_RUNNER_MEASUREMENT_HARNESS_VERSION_MISMATCH"
            }
            Self::MeasurementRenderedCandidateArtifactMismatch => {
                "EVIDENTRAIL_BENCH_RUNNER_MEASUREMENT_RENDERED_CANDIDATE_ARTIFACT_MISMATCH"
            }
            Self::MeasurementRenderedCandidateByteCountMismatch => {
                "EVIDENTRAIL_BENCH_RUNNER_MEASUREMENT_RENDERED_CANDIDATE_BYTE_COUNT_MISMATCH"
            }
            Self::CandidateResourceAccountingFailed { .. } => {
                "EVIDENTRAIL_BENCH_RUNNER_CANDIDATE_RESOURCE_ACCOUNTING_FAILED"
            }
            Self::CandidateResourceCapExceeded { .. } => {
                "EVIDENTRAIL_BENCH_RUNNER_CANDIDATE_RESOURCE_CAP_EXCEEDED"
            }
            Self::PresentationAssignmentFailed => {
                "EVIDENTRAIL_BENCH_RUNNER_PRESENTATION_ASSIGNMENT_FAILED"
            }
            Self::PresentationReconciliationFailed => {
                "EVIDENTRAIL_BENCH_RUNNER_PRESENTATION_RECONCILIATION_FAILED"
            }
            Self::GovernedHiddenManifestRunMismatch => {
                "EVIDENTRAIL_BENCH_RUNNER_GOVERNED_HIDDEN_MANIFEST_RUN_MISMATCH"
            }
            Self::GovernedHiddenCaseCohortMismatch => {
                "EVIDENTRAIL_BENCH_RUNNER_GOVERNED_HIDDEN_CASE_COHORT_MISMATCH"
            }
            Self::GovernedArtifactBindingMismatch => {
                "EVIDENTRAIL_BENCH_RUNNER_GOVERNED_ARTIFACT_BINDING_MISMATCH"
            }
            Self::MissingGovernedCaseInputs { .. } => {
                "EVIDENTRAIL_BENCH_RUNNER_MISSING_GOVERNED_CASE_INPUTS"
            }
            Self::DuplicateGovernedCaseInput => "EVIDENTRAIL_BENCH_RUNNER_DUPLICATE_GOVERNED_CASE_INPUT",
            Self::ExtraGovernedCaseInputs { .. } => "EVIDENTRAIL_BENCH_RUNNER_EXTRA_GOVERNED_CASE_INPUTS",
            Self::CaseEvaluationFailed { .. } => "EVIDENTRAIL_BENCH_RUNNER_CASE_EVALUATION_FAILED",
            Self::RunAggregationFailed { .. } => "EVIDENTRAIL_BENCH_RUNNER_RUN_AGGREGATION_FAILED",
        }
    }

    #[must_use]
    pub const fn candidate_cap_violations(&self) -> Option<&CandidateCapViolations> {
        match self {
            Self::CandidateResourceCapExceeded { violations } => Some(violations),
            _ => None,
        }
    }
}

impl fmt::Debug for HermeticRunnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("HermeticRunnerError");
        debug.field("code", &self.code());
        match self {
            Self::MissingPublicCaseInputs { count }
            | Self::ExtraPublicCaseInputs { count }
            | Self::MissingCandidateRenderings { count }
            | Self::ExtraCandidateRenderings { count }
            | Self::MissingMeasurementReceipts { count }
            | Self::ExtraMeasurementReceipts { count }
            | Self::MissingGovernedCaseInputs { count }
            | Self::ExtraGovernedCaseInputs { count } => {
                debug.field("count", count);
            }
            Self::MethodExecutionFailed { error } => {
                debug.field("cause_code", &error.code());
            }
            Self::CandidateSelectionBindingFailed { error } => {
                debug.field("cause_code", &error.code());
            }
            Self::CandidateResourceAccountingFailed { error } => {
                debug.field("cause_code", &error.code());
            }
            Self::CandidateResourceCapExceeded { violations } => {
                debug.field("violations", violations);
            }
            Self::CaseEvaluationFailed { error } => {
                debug.field("cause_code", &error.code());
            }
            Self::RunAggregationFailed { error } => {
                debug.field("cause_code", &error.code());
            }
            _ => {}
        }
        debug.finish()
    }
}

impl fmt::Display for HermeticRunnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for HermeticRunnerError {}

/// Execute one deterministic method over an exact public case cohort.
///
/// All cohort, question, plan, and budget bindings are checked before the
/// first method invocation. Cases then execute in canonical manifest order.
/// The method receives only ledger, query, and the exact declared
/// unique-candidate-source-byte cap as its whole-event [`ByteBudget`]. Because
/// every selected event must belong to the later validated candidate set, this
/// is a conservative selection bound; v1 has no separate output-byte
/// dimension. This phase freezes a candidate-selection digest and presentation
/// receipt but accepts no measurements or annotations.
pub fn execute_hermetic_public_run_v1<'case, Method, Inputs>(
    run_manifest_artifact_digest: ArtifactDigest,
    run_manifest: &EvidentrailBenchRunManifestV1,
    method: &Method,
    inputs: Inputs,
) -> Result<FrozenPublicRunV1<'case>, HermeticRunnerError>
where
    Method: BenchmarkMethod + ?Sized,
    Inputs: IntoIterator<Item = HermeticPublicCaseInputV1<'case>>,
{
    let expected_cases = run_manifest
        .public_case_artifact_digests()
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut by_case = BTreeMap::new();
    for input in inputs {
        let case_digest = input.public_case_artifact_digest;
        if by_case.insert(case_digest, input).is_some() {
            return Err(HermeticRunnerError::DuplicatePublicCaseInput);
        }
    }
    let extra_case_count = by_case
        .keys()
        .filter(|case| !expected_cases.contains(case))
        .count();
    if extra_case_count != 0 {
        return Err(HermeticRunnerError::ExtraPublicCaseInputs {
            count: extra_case_count,
        });
    }
    let missing_case_count = run_manifest
        .public_case_artifact_digests()
        .iter()
        .filter(|case| !by_case.contains_key(case))
        .count();
    if missing_case_count != 0 {
        return Err(HermeticRunnerError::MissingPublicCaseInputs {
            count: missing_case_count,
        });
    }

    let budget_cap = run_manifest.identity().budget().cap();
    let method_byte_budget = ByteBudget::new(
        usize::try_from(budget_cap.unique_candidate_source_bytes())
            .map_err(|_| HermeticRunnerError::MethodByteBudgetNotRepresentable)?,
    );
    for case_digest in run_manifest.public_case_artifact_digests() {
        let input = by_case
            .get(case_digest)
            .expect("missing public cases were rejected above");
        if input.public_case.question_digest() != derive_question_digest_v1(input.query) {
            return Err(HermeticRunnerError::QuestionDigestMismatch);
        }
        if input.public_case.plan_digest() != input.ledger.plan_digest() {
            return Err(HermeticRunnerError::PlanDigestMismatch);
        }
        if !input.public_case.budget_points().contains(&budget_cap) {
            return Err(HermeticRunnerError::BudgetPointNotDeclared);
        }
    }

    let expected_method = method.descriptor();
    let mut frozen_cases = Vec::with_capacity(by_case.len());
    for case_digest in run_manifest.public_case_artifact_digests() {
        let input = by_case
            .remove(case_digest)
            .expect("missing public cases were rejected above");
        let method_result = method
            .run(MethodInput::new(
                input.ledger,
                input.query,
                method_byte_budget,
            ))
            .map_err(|error| HermeticRunnerError::MethodExecutionFailed { error })?;
        if method_result.method() != expected_method {
            return Err(HermeticRunnerError::MethodIdentityMismatch);
        }

        let assignments = method_result
            .presentation_assignments(input.ledger)
            .map_err(|_| HermeticRunnerError::PresentationAssignmentFailed)?;
        let presentation_receipt = PresentationReceipt::reconcile(input.ledger, assignments)
            .map_err(|_| HermeticRunnerError::PresentationReconciliationFailed)?;
        let candidate_selection_digest =
            derive_frozen_candidate_selection_digest_v1(input.ledger, &method_result)
                .map_err(|error| HermeticRunnerError::CandidateSelectionBindingFailed { error })?;
        frozen_cases.push(FrozenPublicCaseRunV1 {
            public_case_artifact_digest: *case_digest,
            public_case: input.public_case,
            ledger: input.ledger,
            method_result,
            presentation_receipt,
            candidate_selection_digest,
        });
    }
    debug_assert!(by_case.is_empty());

    Ok(FrozenPublicRunV1 {
        run_manifest_artifact_digest,
        run_manifest: run_manifest.clone(),
        method: expected_method,
        cases: frozen_cases,
    })
}

/// Bind exactly one self-asserted measurement receipt to every frozen case.
///
/// The rendering and receipt cohorts plus every execution, selection,
/// presentation, renderer, rendered-artifact, tokenizer, and harness binding
/// are validated before a type eligible for governed evaluation can be
/// constructed. Candidate count and unique bytes are derived from the ledger;
/// only token count, wall time, and peak RSS come from the external
/// self-asserted receipt. Rendering bindings and receipts are reproducibility
/// inputs, not independent attestations.
pub fn bind_hermetic_measurement_receipts_v1<'case, Renderings, Receipts>(
    frozen_run: FrozenPublicRunV1<'case>,
    expected_environment: MeasurementEnvironmentV1,
    renderings: Renderings,
    receipts: Receipts,
) -> Result<MeasurementValidatedPublicRunV1<'case>, HermeticRunnerError>
where
    Renderings: IntoIterator<Item = FrozenCandidateRenderingV1>,
    Receipts: IntoIterator<Item = MeasurementProvenanceReceiptV1>,
{
    let expected_cases = frozen_run
        .run_manifest
        .public_case_artifact_digests()
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut renderings_by_case = BTreeMap::new();
    for rendering in renderings {
        let case_digest = rendering.public_case_artifact_digest();
        if renderings_by_case.insert(case_digest, rendering).is_some() {
            return Err(HermeticRunnerError::DuplicateCandidateRendering);
        }
    }
    let extra_rendering_count = renderings_by_case
        .keys()
        .filter(|case| !expected_cases.contains(case))
        .count();
    if extra_rendering_count != 0 {
        return Err(HermeticRunnerError::ExtraCandidateRenderings {
            count: extra_rendering_count,
        });
    }
    let missing_rendering_count = frozen_run
        .run_manifest
        .public_case_artifact_digests()
        .iter()
        .filter(|case| !renderings_by_case.contains_key(case))
        .count();
    if missing_rendering_count != 0 {
        return Err(HermeticRunnerError::MissingCandidateRenderings {
            count: missing_rendering_count,
        });
    }

    let mut receipts_by_case = BTreeMap::new();
    for receipt in receipts {
        let case_digest = receipt.public_case_artifact_digest();
        if receipts_by_case.insert(case_digest, receipt).is_some() {
            return Err(HermeticRunnerError::DuplicateMeasurementReceipt);
        }
    }
    let extra_case_count = receipts_by_case
        .keys()
        .filter(|case| !expected_cases.contains(case))
        .count();
    if extra_case_count != 0 {
        return Err(HermeticRunnerError::ExtraMeasurementReceipts {
            count: extra_case_count,
        });
    }
    let missing_case_count = frozen_run
        .run_manifest
        .public_case_artifact_digests()
        .iter()
        .filter(|case| !receipts_by_case.contains_key(case))
        .count();
    if missing_case_count != 0 {
        return Err(HermeticRunnerError::MissingMeasurementReceipts {
            count: missing_case_count,
        });
    }

    let budget_cap = frozen_run.run_manifest.identity().budget().cap();
    let mut validated_cases = Vec::with_capacity(frozen_run.cases.len());
    for frozen_case in &frozen_run.cases {
        let rendering = renderings_by_case
            .remove(&frozen_case.public_case_artifact_digest)
            .expect("missing candidate renderings were rejected above");
        if rendering.candidate_selection_digest() != frozen_case.candidate_selection_digest {
            return Err(HermeticRunnerError::CandidateRenderingSelectionMismatch);
        }
        if rendering.presentation_receipt_id() != frozen_case.presentation_receipt.id() {
            return Err(HermeticRunnerError::CandidateRenderingPresentationMismatch);
        }
        if rendering.renderer().artifact_digest()
            != expected_environment.renderer().artifact_digest()
        {
            return Err(HermeticRunnerError::CandidateRenderingRendererIdentityMismatch);
        }
        if rendering.renderer().contract_version()
            != expected_environment.renderer().contract_version()
        {
            return Err(HermeticRunnerError::CandidateRenderingRendererVersionMismatch);
        }

        let receipt = receipts_by_case
            .remove(&frozen_case.public_case_artifact_digest)
            .expect("missing measurement receipts were rejected above");
        if receipt.run_manifest_artifact_digest() != frozen_run.run_manifest_artifact_digest {
            return Err(HermeticRunnerError::MeasurementRunManifestArtifactMismatch);
        }
        if receipt.run_identity() != frozen_run.run_manifest.identity() {
            return Err(HermeticRunnerError::MeasurementRunIdentityMismatch);
        }
        if receipt.method() != frozen_run.method {
            return Err(HermeticRunnerError::MeasurementMethodMismatch);
        }
        if receipt.candidate_selection_digest() != frozen_case.candidate_selection_digest {
            return Err(HermeticRunnerError::MeasurementCandidateSelectionMismatch);
        }
        if receipt.presentation_receipt_id() != frozen_case.presentation_receipt.id() {
            return Err(HermeticRunnerError::MeasurementPresentationReceiptMismatch);
        }
        if receipt.environment().tokenizer() != expected_environment.tokenizer() {
            return Err(HermeticRunnerError::MeasurementTokenizerIdentityMismatch);
        }
        if receipt.environment().renderer().artifact_digest()
            != expected_environment.renderer().artifact_digest()
        {
            return Err(HermeticRunnerError::MeasurementRendererIdentityMismatch);
        }
        if receipt.environment().renderer().contract_version()
            != expected_environment.renderer().contract_version()
        {
            return Err(HermeticRunnerError::MeasurementRendererVersionMismatch);
        }
        if receipt.environment().harness().artifact_digest()
            != expected_environment.harness().artifact_digest()
        {
            return Err(HermeticRunnerError::MeasurementHarnessIdentityMismatch);
        }
        if receipt.environment().harness().contract_version()
            != expected_environment.harness().contract_version()
        {
            return Err(HermeticRunnerError::MeasurementHarnessVersionMismatch);
        }
        if receipt.rendered_candidate().artifact_digest()
            != rendering.rendered_candidate().artifact_digest()
        {
            return Err(HermeticRunnerError::MeasurementRenderedCandidateArtifactMismatch);
        }
        if receipt.rendered_candidate().byte_count() != rendering.rendered_candidate().byte_count()
        {
            return Err(HermeticRunnerError::MeasurementRenderedCandidateByteCountMismatch);
        }

        let candidate_resources = candidate_resource_envelope(
            frozen_case.ledger,
            frozen_case.method_result.candidate_event_ids(),
            receipt.externally_observed(),
        )
        .map_err(|error| HermeticRunnerError::CandidateResourceAccountingFailed { error })?;
        budget_cap
            .check(candidate_resources)
            .map_err(
                |violations| HermeticRunnerError::CandidateResourceCapExceeded { violations },
            )?;
        validated_cases.push(MeasurementValidatedCaseV1 {
            receipt,
            candidate_resources,
        });
    }
    debug_assert!(renderings_by_case.is_empty());
    debug_assert!(receipts_by_case.is_empty());

    Ok(MeasurementValidatedPublicRunV1 {
        frozen_run,
        measurement_environment: expected_environment,
        cases: validated_cases,
    })
}

/// Join a measurement-validated public run to exactly one governed annotation
/// per case, evaluate each case, and aggregate through the governed runner.
///
/// The type boundary makes it impossible to call this entrypoint with a merely
/// frozen but unmeasured run. Hidden labels enter only after all self-asserted
/// provenance bindings and resource caps have passed.
pub fn evaluate_measurement_validated_hermetic_run_v1<'case, 'annotation, 'ledger, Inputs>(
    validated_run: &MeasurementValidatedPublicRunV1<'case>,
    hidden_evaluation_manifest: &EvidentrailBenchHiddenEvaluationManifestV1,
    inputs: Inputs,
) -> Result<GovernedRunAggregateV1, HermeticRunnerError>
where
    'ledger: 'annotation,
    Inputs: IntoIterator<Item = HermeticGovernedCaseInputV1<'annotation, 'ledger>>,
{
    let frozen_run = &validated_run.frozen_run;
    if hidden_evaluation_manifest.public_run_manifest_artifact_digest()
        != frozen_run.run_manifest_artifact_digest
    {
        return Err(HermeticRunnerError::GovernedHiddenManifestRunMismatch);
    }
    if hidden_evaluation_manifest
        .case_bindings()
        .iter()
        .map(|binding| binding.public_case_artifact_digest())
        .ne(frozen_run
            .run_manifest
            .public_case_artifact_digests()
            .iter()
            .copied())
    {
        return Err(HermeticRunnerError::GovernedHiddenCaseCohortMismatch);
    }
    let expected_cases = frozen_run
        .run_manifest
        .public_case_artifact_digests()
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut by_case = BTreeMap::new();
    for input in inputs {
        let case_digest = input.artifact_binding.public_case_artifact_digest();
        if by_case.insert(case_digest, input).is_some() {
            return Err(HermeticRunnerError::DuplicateGovernedCaseInput);
        }
    }
    let extra_case_count = by_case
        .keys()
        .filter(|case| !expected_cases.contains(case))
        .count();
    if extra_case_count != 0 {
        return Err(HermeticRunnerError::ExtraGovernedCaseInputs {
            count: extra_case_count,
        });
    }
    let missing_case_count = frozen_run
        .run_manifest
        .public_case_artifact_digests()
        .iter()
        .filter(|case| !by_case.contains_key(case))
        .count();
    if missing_case_count != 0 {
        return Err(HermeticRunnerError::MissingGovernedCaseInputs {
            count: missing_case_count,
        });
    }
    if by_case.iter().any(|(case_digest, input)| {
        hidden_evaluation_manifest.binding_for_public_case(*case_digest)
            != Some(input.artifact_binding)
    }) {
        return Err(HermeticRunnerError::GovernedArtifactBindingMismatch);
    }

    let mut governed_results = Vec::with_capacity(frozen_run.cases.len());
    for frozen_case in &frozen_run.cases {
        let governed_input = by_case
            .remove(&frozen_case.public_case_artifact_digest)
            .expect("missing governed cases were rejected above");
        let artifact_join = hidden_evaluation_manifest
            .resolve_case_binding(governed_input.artifact_binding)
            .map_err(|_| HermeticRunnerError::GovernedArtifactBindingMismatch)?;
        let evaluation = evaluate_governed_case_with_presentation_v1(
            artifact_join,
            frozen_case.public_case,
            governed_input.annotation,
            frozen_case.ledger,
            &frozen_case.method_result,
            &frozen_case.presentation_receipt,
            governed_input.block_index,
        )
        .map_err(|error| HermeticRunnerError::CaseEvaluationFailed { error })?;
        governed_results.push(GovernedRunCaseInputV1::new(
            frozen_run.run_manifest_artifact_digest,
            frozen_run.run_manifest.identity(),
            evaluation,
        ));
    }
    debug_assert!(by_case.is_empty());

    aggregate_governed_run_v1(
        frozen_run.run_manifest_artifact_digest,
        &frozen_run.run_manifest,
        hidden_evaluation_manifest,
        frozen_run.method,
        governed_results,
    )
    .map_err(|error| HermeticRunnerError::RunAggregationFailed { error })
}
