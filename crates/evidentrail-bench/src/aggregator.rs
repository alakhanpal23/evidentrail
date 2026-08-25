use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::ArtifactDigest;

use crate::{
    BenchmarkBudgetV1, BenchmarkRunIdentityV1, EvidentrailBenchHiddenEvaluationManifestV1,
    EvidentrailBenchRunManifestV1, ExpectedAcquisitionClassV1, GovernedCaseEvaluationV1,
    MethodDescriptor, PublicCaseAccountingV1, PublicCaseEvaluationResultV1,
};

/// One governed case evaluation attributed to a resolved run manifest.
///
/// The redundant run identity is intentional: aggregation rejects an entry
/// produced under another system, build, dataset, seed, or budget instead of
/// trusting the destination manifest chosen by the caller.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GovernedRunCaseInputV1 {
    run_manifest_artifact_digest: ArtifactDigest,
    run_identity: BenchmarkRunIdentityV1,
    evaluation: GovernedCaseEvaluationV1,
}

impl GovernedRunCaseInputV1 {
    #[must_use]
    pub const fn new(
        run_manifest_artifact_digest: ArtifactDigest,
        run_identity: BenchmarkRunIdentityV1,
        evaluation: GovernedCaseEvaluationV1,
    ) -> Self {
        Self {
            run_manifest_artifact_digest,
            run_identity,
            evaluation,
        }
    }

    #[must_use]
    pub const fn run_manifest_artifact_digest(self) -> ArtifactDigest {
        self.run_manifest_artifact_digest
    }

    #[must_use]
    pub const fn run_identity(self) -> BenchmarkRunIdentityV1 {
        self.run_identity
    }

    #[must_use]
    pub const fn evaluation(self) -> GovernedCaseEvaluationV1 {
        self.evaluation
    }
}

impl fmt::Debug for GovernedRunCaseInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedRunCaseInputV1")
            .field("run_manifest_link_present", &true)
            .field("run_identity", &self.run_identity)
            .field("public_case_evaluation_present", &true)
            .field("governed_case_evaluation_present", &true)
            .finish()
    }
}

/// Exact public sums across every case in one run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PublicRunAccountingV1 {
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

impl PublicRunAccountingV1 {
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

/// Label-free aggregate suitable for public run artifacts.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicRunAggregateV1 {
    run_manifest_artifact_digest: ArtifactDigest,
    run_identity: BenchmarkRunIdentityV1,
    method: MethodDescriptor,
    case_count: u64,
    complete_case_count: u64,
    partial_case_count: u64,
    unknown_case_count: u64,
    accounting: PublicRunAccountingV1,
}

impl PublicRunAggregateV1 {
    #[must_use]
    pub const fn run_manifest_artifact_digest(self) -> ArtifactDigest {
        self.run_manifest_artifact_digest
    }

    #[must_use]
    pub const fn run_identity(self) -> BenchmarkRunIdentityV1 {
        self.run_identity
    }

    #[must_use]
    pub const fn method(self) -> MethodDescriptor {
        self.method
    }

    #[must_use]
    pub const fn case_count(self) -> u64 {
        self.case_count
    }

    #[must_use]
    pub const fn complete_case_count(self) -> u64 {
        self.complete_case_count
    }

    #[must_use]
    pub const fn partial_case_count(self) -> u64 {
        self.partial_case_count
    }

    #[must_use]
    pub const fn unknown_case_count(self) -> u64 {
        self.unknown_case_count
    }

    #[must_use]
    pub const fn accounting(self) -> PublicRunAccountingV1 {
        self.accounting
    }
}

impl fmt::Debug for PublicRunAggregateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicRunAggregateV1")
            .field("run_manifest_link_present", &true)
            .field("run_identity", &self.run_identity)
            .field("method", &self.method)
            .field("case_count", &self.case_count)
            .field("complete_case_count", &self.complete_case_count)
            .field("partial_case_count", &self.partial_case_count)
            .field("unknown_case_count", &self.unknown_case_count)
            .field("accounting", &self.accounting)
            .finish()
    }
}

/// Exact hidden sums across governed case requirements.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GovernedRunRecallV1 {
    requirement_count: u64,
    satisfied_requirement_count: u64,
    total_weight_micros: u64,
    satisfied_weight_micros: u64,
}

impl GovernedRunRecallV1 {
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

    #[must_use]
    pub const fn exact_weight_ratio(self) -> (u64, u64) {
        (self.satisfied_weight_micros, self.total_weight_micros)
    }
}

/// Public, score-free per-case material in canonical manifest order.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicRunComparisonInputV1 {
    run_manifest_artifact_digest: ArtifactDigest,
    run_identity: BenchmarkRunIdentityV1,
    method: MethodDescriptor,
    case_results: Vec<PublicCaseEvaluationResultV1>,
}

impl PublicRunComparisonInputV1 {
    #[must_use]
    pub const fn run_manifest_artifact_digest(&self) -> ArtifactDigest {
        self.run_manifest_artifact_digest
    }

    #[must_use]
    pub const fn run_identity(&self) -> BenchmarkRunIdentityV1 {
        self.run_identity
    }

    #[must_use]
    pub const fn method(&self) -> MethodDescriptor {
        self.method
    }

    #[must_use]
    pub fn case_results(&self) -> &[PublicCaseEvaluationResultV1] {
        &self.case_results
    }
}

impl fmt::Debug for PublicRunComparisonInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicRunComparisonInputV1")
            .field("run_manifest_link_present", &true)
            .field("run_identity", &self.run_identity)
            .field("method", &self.method)
            .field("case_count", &self.case_results.len())
            .finish()
    }
}

/// Governed aggregate and its deliberately label-free public projections.
#[derive(Clone, PartialEq, Eq)]
pub struct GovernedRunAggregateV1 {
    public_aggregate: PublicRunAggregateV1,
    governed_recall: GovernedRunRecallV1,
    public_comparison_input: PublicRunComparisonInputV1,
}

impl GovernedRunAggregateV1 {
    #[must_use]
    pub const fn public_aggregate(&self) -> PublicRunAggregateV1 {
        self.public_aggregate
    }

    #[must_use]
    pub const fn governed_recall(&self) -> GovernedRunRecallV1 {
        self.governed_recall
    }

    #[must_use]
    pub const fn public_comparison_input(&self) -> &PublicRunComparisonInputV1 {
        &self.public_comparison_input
    }
}

impl fmt::Debug for GovernedRunAggregateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedRunAggregateV1")
            .field("public_aggregate", &self.public_aggregate)
            .field("governed_recall", &self.governed_recall)
            .field("public_comparison_input_present", &true)
            .finish()
    }
}

/// One exactly aligned public case pair. It carries accounting and provenance,
/// not a score or winner declaration.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PairedPublicCaseInputV1 {
    public_case_artifact_digest: ArtifactDigest,
    left: PublicCaseEvaluationResultV1,
    right: PublicCaseEvaluationResultV1,
}

impl PairedPublicCaseInputV1 {
    #[must_use]
    pub const fn public_case_artifact_digest(self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn left(self) -> PublicCaseEvaluationResultV1 {
        self.left
    }

    #[must_use]
    pub const fn right(self) -> PublicCaseEvaluationResultV1 {
        self.right
    }
}

impl fmt::Debug for PairedPublicCaseInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairedPublicCaseInputV1")
            .field("public_case_link_present", &true)
            .field("left_public_result_present", &true)
            .field("right_public_result_present", &true)
            .finish()
    }
}

/// Exact matched public input for a later paired evaluator.
#[derive(Clone, PartialEq, Eq)]
pub struct ExactPairedRunComparisonInputV1 {
    left_run_manifest_artifact_digest: ArtifactDigest,
    right_run_manifest_artifact_digest: ArtifactDigest,
    left_run_identity: BenchmarkRunIdentityV1,
    right_run_identity: BenchmarkRunIdentityV1,
    left_method: MethodDescriptor,
    right_method: MethodDescriptor,
    case_pairs: Vec<PairedPublicCaseInputV1>,
}

impl ExactPairedRunComparisonInputV1 {
    pub fn new(
        left: &PublicRunComparisonInputV1,
        right: &PublicRunComparisonInputV1,
    ) -> Result<Self, RunAggregationError> {
        if left.run_identity.dataset_artifact_digest()
            != right.run_identity.dataset_artifact_digest()
        {
            return Err(RunAggregationError::DatasetIdentityMismatch);
        }
        if left.run_identity.seed() != right.run_identity.seed() {
            return Err(RunAggregationError::SeedMismatch);
        }
        validate_exact_budget_match(left.run_identity.budget(), right.run_identity.budget())?;
        if left.case_results.len() != right.case_results.len()
            || left
                .case_results
                .iter()
                .zip(&right.case_results)
                .any(|(left, right)| {
                    left.public_case_artifact_digest() != right.public_case_artifact_digest()
                })
        {
            return Err(RunAggregationError::PublicCaseCohortMismatch);
        }

        let case_pairs = left
            .case_results
            .iter()
            .copied()
            .zip(right.case_results.iter().copied())
            .map(|(left, right)| PairedPublicCaseInputV1 {
                public_case_artifact_digest: left.public_case_artifact_digest(),
                left,
                right,
            })
            .collect();
        Ok(Self {
            left_run_manifest_artifact_digest: left.run_manifest_artifact_digest,
            right_run_manifest_artifact_digest: right.run_manifest_artifact_digest,
            left_run_identity: left.run_identity,
            right_run_identity: right.run_identity,
            left_method: left.method,
            right_method: right.method,
            case_pairs,
        })
    }

    #[must_use]
    pub const fn left_run_manifest_artifact_digest(&self) -> ArtifactDigest {
        self.left_run_manifest_artifact_digest
    }

    #[must_use]
    pub const fn right_run_manifest_artifact_digest(&self) -> ArtifactDigest {
        self.right_run_manifest_artifact_digest
    }

    #[must_use]
    pub const fn left_run_identity(&self) -> BenchmarkRunIdentityV1 {
        self.left_run_identity
    }

    #[must_use]
    pub const fn right_run_identity(&self) -> BenchmarkRunIdentityV1 {
        self.right_run_identity
    }

    #[must_use]
    pub const fn left_method(&self) -> MethodDescriptor {
        self.left_method
    }

    #[must_use]
    pub const fn right_method(&self) -> MethodDescriptor {
        self.right_method
    }

    #[must_use]
    pub fn case_pairs(&self) -> &[PairedPublicCaseInputV1] {
        &self.case_pairs
    }
}

impl fmt::Debug for ExactPairedRunComparisonInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactPairedRunComparisonInputV1")
            .field("left_run_manifest_link_present", &true)
            .field("right_run_manifest_link_present", &true)
            .field("left_run_identity", &self.left_run_identity)
            .field("right_run_identity", &self.right_run_identity)
            .field("left_method", &self.left_method)
            .field("right_method", &self.right_method)
            .field("case_count", &self.case_pairs.len())
            .finish()
    }
}

/// One checked aggregate dimension, used only in contentless diagnostics.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RunAggregateDimensionV1 {
    CaseCount,
    CompleteCaseCount,
    PartialCaseCount,
    UnknownCaseCount,
    ReceivedEventCount,
    CandidateEventCount,
    CandidateSourceBytes,
    SelectedEventCount,
    SelectedSourceBytes,
    RetainedRawEventCount,
    BudgetExcludedCandidateCount,
    SourceByteBudget,
    ShownVerbatimEventCount,
    PatternRepresentedEventCount,
    PresentationRetainedRawEventCount,
    RequirementCount,
    SatisfiedRequirementCount,
    TotalWeightMicros,
    SatisfiedWeightMicros,
}

impl RunAggregateDimensionV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::CaseCount => "case_count",
            Self::CompleteCaseCount => "complete_case_count",
            Self::PartialCaseCount => "partial_case_count",
            Self::UnknownCaseCount => "unknown_case_count",
            Self::ReceivedEventCount => "received_event_count",
            Self::CandidateEventCount => "candidate_event_count",
            Self::CandidateSourceBytes => "candidate_source_bytes",
            Self::SelectedEventCount => "selected_event_count",
            Self::SelectedSourceBytes => "selected_source_bytes",
            Self::RetainedRawEventCount => "retained_raw_event_count",
            Self::BudgetExcludedCandidateCount => "budget_excluded_candidate_count",
            Self::SourceByteBudget => "source_byte_budget",
            Self::ShownVerbatimEventCount => "shown_verbatim_event_count",
            Self::PatternRepresentedEventCount => "pattern_represented_event_count",
            Self::PresentationRetainedRawEventCount => "presentation_retained_raw_event_count",
            Self::RequirementCount => "requirement_count",
            Self::SatisfiedRequirementCount => "satisfied_requirement_count",
            Self::TotalWeightMicros => "total_weight_micros",
            Self::SatisfiedWeightMicros => "satisfied_weight_micros",
        }
    }
}

impl fmt::Debug for RunAggregateDimensionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunAggregateDimensionV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Contentless aggregation and exact-pairing failures.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RunAggregationError {
    RunManifestArtifactMismatch,
    HiddenEvaluationManifestRunMismatch,
    GovernedCaseArtifactBindingMismatch,
    RunIdentityMismatch,
    MethodMismatch,
    MissingCaseEvaluations { count: usize },
    DuplicateCaseEvaluation,
    ExtraCaseEvaluations { count: usize },
    AggregateOverflow { dimension: RunAggregateDimensionV1 },
    DatasetIdentityMismatch,
    PublicCaseCohortMismatch,
    SeedMismatch,
    BudgetMismatch,
    IncomparableBudgets,
}

impl RunAggregationError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::RunManifestArtifactMismatch => {
                "EVIDENTRAIL_BENCH_RUN_AGGREGATE_MANIFEST_ARTIFACT_MISMATCH"
            }
            Self::HiddenEvaluationManifestRunMismatch => {
                "EVIDENTRAIL_BENCH_RUN_AGGREGATE_HIDDEN_MANIFEST_RUN_MISMATCH"
            }
            Self::GovernedCaseArtifactBindingMismatch => {
                "EVIDENTRAIL_BENCH_RUN_AGGREGATE_GOVERNED_CASE_ARTIFACT_BINDING_MISMATCH"
            }
            Self::RunIdentityMismatch => "EVIDENTRAIL_BENCH_RUN_AGGREGATE_IDENTITY_MISMATCH",
            Self::MethodMismatch => "EVIDENTRAIL_BENCH_RUN_AGGREGATE_METHOD_MISMATCH",
            Self::MissingCaseEvaluations { .. } => {
                "EVIDENTRAIL_BENCH_RUN_AGGREGATE_MISSING_CASE_EVALUATIONS"
            }
            Self::DuplicateCaseEvaluation => "EVIDENTRAIL_BENCH_RUN_AGGREGATE_DUPLICATE_CASE_EVALUATION",
            Self::ExtraCaseEvaluations { .. } => "EVIDENTRAIL_BENCH_RUN_AGGREGATE_EXTRA_CASE_EVALUATIONS",
            Self::AggregateOverflow { .. } => "EVIDENTRAIL_BENCH_RUN_AGGREGATE_OVERFLOW",
            Self::DatasetIdentityMismatch => "EVIDENTRAIL_BENCH_RUN_COMPARISON_DATASET_IDENTITY_MISMATCH",
            Self::PublicCaseCohortMismatch => {
                "EVIDENTRAIL_BENCH_RUN_COMPARISON_PUBLIC_CASE_COHORT_MISMATCH"
            }
            Self::SeedMismatch => "EVIDENTRAIL_BENCH_RUN_COMPARISON_SEED_MISMATCH",
            Self::BudgetMismatch => "EVIDENTRAIL_BENCH_RUN_COMPARISON_BUDGET_MISMATCH",
            Self::IncomparableBudgets => "EVIDENTRAIL_BENCH_RUN_COMPARISON_INCOMPARABLE_BUDGETS",
        }
    }
}

impl fmt::Debug for RunAggregationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("RunAggregationError");
        debug.field("code", &self.code());
        match self {
            Self::MissingCaseEvaluations { count } | Self::ExtraCaseEvaluations { count } => {
                debug.field("count", count);
            }
            Self::AggregateOverflow { dimension } => {
                debug.field("dimension", &dimension.code());
            }
            _ => {}
        }
        debug.finish()
    }
}

impl fmt::Display for RunAggregationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for RunAggregationError {}

/// Aggregate exactly one governed case evaluation for every manifest case.
///
/// Input order has no effect: output case results are restored to the run
/// manifest's canonical case order. The expected method is supplied by the
/// governed runner after resolving the manifest's opaque system/build
/// artifacts; this domain layer does not pretend to hash or execute a method.
pub fn aggregate_governed_run_v1<Inputs>(
    run_manifest_artifact_digest: ArtifactDigest,
    run_manifest: &EvidentrailBenchRunManifestV1,
    hidden_evaluation_manifest: &EvidentrailBenchHiddenEvaluationManifestV1,
    expected_method: MethodDescriptor,
    inputs: Inputs,
) -> Result<GovernedRunAggregateV1, RunAggregationError>
where
    Inputs: IntoIterator<Item = GovernedRunCaseInputV1>,
{
    if hidden_evaluation_manifest.public_run_manifest_artifact_digest()
        != run_manifest_artifact_digest
    {
        return Err(RunAggregationError::HiddenEvaluationManifestRunMismatch);
    }
    let expected_cases = run_manifest
        .public_case_artifact_digests()
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut by_case = BTreeMap::new();
    let mut extra_case_count = 0usize;
    for input in inputs {
        if input.run_manifest_artifact_digest != run_manifest_artifact_digest {
            return Err(RunAggregationError::RunManifestArtifactMismatch);
        }
        if input.run_identity != run_manifest.identity() {
            return Err(RunAggregationError::RunIdentityMismatch);
        }
        let public_result = input.evaluation.public_result();
        if public_result.method() != expected_method {
            return Err(RunAggregationError::MethodMismatch);
        }
        let public_case_artifact_digest = public_result.public_case_artifact_digest();
        if by_case
            .insert(public_case_artifact_digest, input.evaluation)
            .is_some()
        {
            return Err(RunAggregationError::DuplicateCaseEvaluation);
        }
        if !expected_cases.contains(&public_case_artifact_digest) {
            extra_case_count =
                extra_case_count
                    .checked_add(1)
                    .ok_or(RunAggregationError::AggregateOverflow {
                        dimension: RunAggregateDimensionV1::CaseCount,
                    })?;
        }
    }
    if extra_case_count != 0 {
        return Err(RunAggregationError::ExtraCaseEvaluations {
            count: extra_case_count,
        });
    }
    let missing_case_count = run_manifest
        .public_case_artifact_digests()
        .iter()
        .filter(|case| !by_case.contains_key(case))
        .count();
    if missing_case_count != 0 {
        return Err(RunAggregationError::MissingCaseEvaluations {
            count: missing_case_count,
        });
    }
    if by_case.iter().any(|(case_digest, evaluation)| {
        let artifact_binding = evaluation.artifact_binding();
        artifact_binding.public_case_artifact_digest() != *case_digest
            || hidden_evaluation_manifest.binding_for_public_case(*case_digest)
                != Some(artifact_binding)
    }) {
        return Err(RunAggregationError::GovernedCaseArtifactBindingMismatch);
    }

    let mut totals = CheckedRunTotals::default();
    let mut ordered_public_results = Vec::with_capacity(by_case.len());
    for public_case_artifact_digest in run_manifest.public_case_artifact_digests() {
        let evaluation = by_case
            .remove(public_case_artifact_digest)
            .expect("missing manifest cases were rejected above");
        totals.add_case(evaluation)?;
        ordered_public_results.push(evaluation.public_result());
    }
    debug_assert!(by_case.is_empty());

    let public_aggregate = PublicRunAggregateV1 {
        run_manifest_artifact_digest,
        run_identity: run_manifest.identity(),
        method: expected_method,
        case_count: totals.case_count,
        complete_case_count: totals.complete_case_count,
        partial_case_count: totals.partial_case_count,
        unknown_case_count: totals.unknown_case_count,
        accounting: totals.public_accounting,
    };
    let public_comparison_input = PublicRunComparisonInputV1 {
        run_manifest_artifact_digest,
        run_identity: run_manifest.identity(),
        method: expected_method,
        case_results: ordered_public_results,
    };
    Ok(GovernedRunAggregateV1 {
        public_aggregate,
        governed_recall: totals.governed_recall,
        public_comparison_input,
    })
}

#[derive(Default)]
struct CheckedRunTotals {
    case_count: u64,
    complete_case_count: u64,
    partial_case_count: u64,
    unknown_case_count: u64,
    public_accounting: PublicRunAccountingV1,
    governed_recall: GovernedRunRecallV1,
}

impl CheckedRunTotals {
    fn add_case(
        &mut self,
        evaluation: GovernedCaseEvaluationV1,
    ) -> Result<(), RunAggregationError> {
        checked_add(&mut self.case_count, 1, RunAggregateDimensionV1::CaseCount)?;
        match evaluation.public_result().acquisition_class() {
            ExpectedAcquisitionClassV1::Complete => checked_add(
                &mut self.complete_case_count,
                1,
                RunAggregateDimensionV1::CompleteCaseCount,
            )?,
            ExpectedAcquisitionClassV1::Partial => checked_add(
                &mut self.partial_case_count,
                1,
                RunAggregateDimensionV1::PartialCaseCount,
            )?,
            ExpectedAcquisitionClassV1::Unknown => checked_add(
                &mut self.unknown_case_count,
                1,
                RunAggregateDimensionV1::UnknownCaseCount,
            )?,
        }

        self.add_public_accounting(evaluation.public_result().accounting())?;
        let recall = evaluation.diagnostic_recall();
        checked_add(
            &mut self.governed_recall.requirement_count,
            recall.requirement_count(),
            RunAggregateDimensionV1::RequirementCount,
        )?;
        checked_add(
            &mut self.governed_recall.satisfied_requirement_count,
            recall.satisfied_requirement_count(),
            RunAggregateDimensionV1::SatisfiedRequirementCount,
        )?;
        checked_add(
            &mut self.governed_recall.total_weight_micros,
            recall.total_weight_micros(),
            RunAggregateDimensionV1::TotalWeightMicros,
        )?;
        checked_add(
            &mut self.governed_recall.satisfied_weight_micros,
            recall.satisfied_weight_micros(),
            RunAggregateDimensionV1::SatisfiedWeightMicros,
        )?;
        Ok(())
    }

    fn add_public_accounting(
        &mut self,
        accounting: PublicCaseAccountingV1,
    ) -> Result<(), RunAggregationError> {
        checked_add(
            &mut self.public_accounting.received_event_count,
            accounting.received_event_count(),
            RunAggregateDimensionV1::ReceivedEventCount,
        )?;
        checked_add(
            &mut self.public_accounting.candidate_event_count,
            accounting.candidate_event_count(),
            RunAggregateDimensionV1::CandidateEventCount,
        )?;
        checked_add(
            &mut self.public_accounting.candidate_source_bytes,
            accounting.candidate_source_bytes(),
            RunAggregateDimensionV1::CandidateSourceBytes,
        )?;
        checked_add(
            &mut self.public_accounting.selected_event_count,
            accounting.selected_event_count(),
            RunAggregateDimensionV1::SelectedEventCount,
        )?;
        checked_add(
            &mut self.public_accounting.selected_source_bytes,
            accounting.selected_source_bytes(),
            RunAggregateDimensionV1::SelectedSourceBytes,
        )?;
        checked_add(
            &mut self.public_accounting.retained_raw_event_count,
            accounting.retained_raw_event_count(),
            RunAggregateDimensionV1::RetainedRawEventCount,
        )?;
        checked_add(
            &mut self.public_accounting.budget_excluded_candidate_count,
            accounting.budget_excluded_candidate_count(),
            RunAggregateDimensionV1::BudgetExcludedCandidateCount,
        )?;
        checked_add(
            &mut self.public_accounting.source_byte_budget,
            accounting.source_byte_budget(),
            RunAggregateDimensionV1::SourceByteBudget,
        )?;
        checked_add(
            &mut self.public_accounting.shown_verbatim_event_count,
            accounting.shown_verbatim_event_count(),
            RunAggregateDimensionV1::ShownVerbatimEventCount,
        )?;
        checked_add(
            &mut self.public_accounting.pattern_represented_event_count,
            accounting.pattern_represented_event_count(),
            RunAggregateDimensionV1::PatternRepresentedEventCount,
        )?;
        checked_add(
            &mut self.public_accounting.presentation_retained_raw_event_count,
            accounting.presentation_retained_raw_event_count(),
            RunAggregateDimensionV1::PresentationRetainedRawEventCount,
        )?;
        Ok(())
    }
}

fn checked_add(
    total: &mut u64,
    value: u64,
    dimension: RunAggregateDimensionV1,
) -> Result<(), RunAggregationError> {
    *total = total
        .checked_add(value)
        .ok_or(RunAggregationError::AggregateOverflow { dimension })?;
    Ok(())
}

fn validate_exact_budget_match(
    left: BenchmarkBudgetV1,
    right: BenchmarkBudgetV1,
) -> Result<(), RunAggregationError> {
    if left == right {
        return Ok(());
    }
    let left_no_greater = budget_is_no_greater(left, right);
    let right_no_greater = budget_is_no_greater(right, left);
    if !left_no_greater && !right_no_greater {
        return Err(RunAggregationError::IncomparableBudgets);
    }
    Err(RunAggregationError::BudgetMismatch)
}

const fn budget_is_no_greater(left: BenchmarkBudgetV1, right: BenchmarkBudgetV1) -> bool {
    left.unique_candidate_event_count() <= right.unique_candidate_event_count()
        && left.unique_candidate_source_bytes() <= right.unique_candidate_source_bytes()
        && left.canonical_candidate_tokens() <= right.canonical_candidate_tokens()
        && left.wall_time_nanos() <= right.wall_time_nanos()
        && left.peak_memory_bytes() <= right.peak_memory_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_integer_aggregate_uses_checked_addition() {
        let dimensions = [
            RunAggregateDimensionV1::CaseCount,
            RunAggregateDimensionV1::CompleteCaseCount,
            RunAggregateDimensionV1::PartialCaseCount,
            RunAggregateDimensionV1::UnknownCaseCount,
            RunAggregateDimensionV1::ReceivedEventCount,
            RunAggregateDimensionV1::CandidateEventCount,
            RunAggregateDimensionV1::CandidateSourceBytes,
            RunAggregateDimensionV1::SelectedEventCount,
            RunAggregateDimensionV1::SelectedSourceBytes,
            RunAggregateDimensionV1::RetainedRawEventCount,
            RunAggregateDimensionV1::BudgetExcludedCandidateCount,
            RunAggregateDimensionV1::SourceByteBudget,
            RunAggregateDimensionV1::ShownVerbatimEventCount,
            RunAggregateDimensionV1::PatternRepresentedEventCount,
            RunAggregateDimensionV1::PresentationRetainedRawEventCount,
            RunAggregateDimensionV1::RequirementCount,
            RunAggregateDimensionV1::SatisfiedRequirementCount,
            RunAggregateDimensionV1::TotalWeightMicros,
            RunAggregateDimensionV1::SatisfiedWeightMicros,
        ];

        for dimension in dimensions {
            let mut total = u64::MAX;
            assert_eq!(
                checked_add(&mut total, 1, dimension),
                Err(RunAggregationError::AggregateOverflow { dimension })
            );
            assert_eq!(total, u64::MAX);
        }
    }
}
