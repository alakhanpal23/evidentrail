//! Frozen public and governed comparison for the bounded selector challenger.
//!
//! The public artifact joins every case from the six-case Full oracle corpus
//! and every selector perturbation before governed recall enters. The governed
//! projection checks the already-frozen six-case recall facts and emits an
//! explicit admission decision. It does not modify production selection.

use std::cmp::Ordering;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::ArtifactDigest;
use sha2::{Digest as _, Sha256};

use crate::bounded_selector_challenger::{
    BoundedSelectorChallengerErrorV1, BoundedSelectorCostRelationV1, BoundedSelectorNeedsMoreV1,
    BoundedSelectorObjectiveRelationV1, BoundedSelectorPacketIdV1, FrozenBoundedSelectorPairV1,
    FrozenExactPairFactsV1, FrozenSelectorOutcomeFactsV1, bounded_selector_challenger_identity_v1,
    evaluate_bounded_selector_challenger_v1, freeze_exact_pair_from_facts_v1,
};
use crate::{
    FrozenPublicSyntheticThreeLaneSelectionCorpusV1, FrozenSelectorPerturbationCorpusDigestV1,
    FrozenSelectorPerturbationCorpusV1, FrozenSyntheticFullSelectionOracleDecisionV1,
    FrozenSyntheticThreeLaneSelectionCorpusDigestV1, GovernedRequirementRecallV1,
    GovernedSelectorPerturbationReportV1, GovernedSyntheticFullSelectionOracleReportV1,
    SelectorPerturbationCaseV1, SyntheticThreeLaneAblationCaseV1,
};

const PUBLIC_COMPARISON_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/public-bounded-selector-challenger-comparison/v1\0";
const GOVERNED_COMPARISON_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/governed-bounded-selector-challenger-comparison/v1\0";

pub const BOUNDED_SELECTOR_CHALLENGER_COMPARISON_CASE_COUNT_V1: usize = 19;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SelectorChallengerComparisonCaseV1 {
    SyntheticFull(SyntheticThreeLaneAblationCaseV1),
    Perturbation(SelectorPerturbationCaseV1),
}

impl SelectorChallengerComparisonCaseV1 {
    #[must_use]
    pub fn identity_digest(self) -> ArtifactDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"evidentrail/bench/selector-challenger-comparison-case/v1\0");
        match self {
            Self::SyntheticFull(case) => {
                hasher.update([0]);
                hasher.update(case.identity_digest().as_bytes());
            }
            Self::Perturbation(case) => {
                hasher.update([1]);
                hasher.update(case.identity_digest().as_bytes());
            }
        }
        ArtifactDigest::from_bytes(hasher.finalize().into())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct FrozenSelectorChallengerComparisonCaseV1 {
    case: SelectorChallengerComparisonCaseV1,
    source_artifact_digest: ArtifactDigest,
    pair: FrozenBoundedSelectorPairV1,
    fixes_positive_production_regret: bool,
}

impl FrozenSelectorChallengerComparisonCaseV1 {
    #[must_use]
    pub const fn case(&self) -> SelectorChallengerComparisonCaseV1 {
        self.case
    }

    #[must_use]
    pub const fn source_artifact_digest(&self) -> ArtifactDigest {
        self.source_artifact_digest
    }

    #[must_use]
    pub const fn pair(&self) -> &FrozenBoundedSelectorPairV1 {
        &self.pair
    }

    #[must_use]
    pub const fn fixes_positive_production_regret(&self) -> bool {
        self.fixes_positive_production_regret
    }
}

impl fmt::Debug for FrozenSelectorChallengerComparisonCaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenSelectorChallengerComparisonCaseV1")
            .field("case", &self.case)
            .field("source_binding_present", &true)
            .field("pair", &self.pair)
            .field(
                "fixes_positive_production_regret",
                &self.fixes_positive_production_regret,
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct FrozenSelectorChallengerComparisonV1 {
    digest: ArtifactDigest,
    perturbation_corpus_digest: FrozenSelectorPerturbationCorpusDigestV1,
    synthetic_selection_corpus_digest: FrozenSyntheticThreeLaneSelectionCorpusDigestV1,
    cases: [FrozenSelectorChallengerComparisonCaseV1;
        BOUNDED_SELECTOR_CHALLENGER_COMPARISON_CASE_COUNT_V1],
    objective_better_count: u64,
    objective_equal_count: u64,
    matched_terminal_count: u64,
    objective_regression_count: u64,
    selected_cost_increase_count: u64,
    positive_regret_fix_count: u64,
    exact_mode_count: u64,
    beam_mode_count: u64,
    transition_cap_reached_count: u64,
}

impl FrozenSelectorChallengerComparisonV1 {
    #[must_use]
    pub const fn digest(&self) -> ArtifactDigest {
        self.digest
    }

    #[must_use]
    pub const fn perturbation_corpus_digest(&self) -> FrozenSelectorPerturbationCorpusDigestV1 {
        self.perturbation_corpus_digest
    }

    #[must_use]
    pub const fn synthetic_selection_corpus_digest(
        &self,
    ) -> FrozenSyntheticThreeLaneSelectionCorpusDigestV1 {
        self.synthetic_selection_corpus_digest
    }

    #[must_use]
    pub fn cases(
        &self,
    ) -> &[FrozenSelectorChallengerComparisonCaseV1;
         BOUNDED_SELECTOR_CHALLENGER_COMPARISON_CASE_COUNT_V1] {
        &self.cases
    }

    #[must_use]
    pub fn case(
        &self,
        case: SelectorChallengerComparisonCaseV1,
    ) -> &FrozenSelectorChallengerComparisonCaseV1 {
        self.cases
            .iter()
            .find(|entry| entry.case == case)
            .expect("closed comparison contains every case exactly once")
    }

    #[must_use]
    pub const fn objective_better_count(&self) -> u64 {
        self.objective_better_count
    }

    #[must_use]
    pub const fn objective_equal_count(&self) -> u64 {
        self.objective_equal_count
    }

    #[must_use]
    pub const fn matched_terminal_count(&self) -> u64 {
        self.matched_terminal_count
    }

    #[must_use]
    pub const fn objective_regression_count(&self) -> u64 {
        self.objective_regression_count
    }

    #[must_use]
    pub const fn selected_cost_increase_count(&self) -> u64 {
        self.selected_cost_increase_count
    }

    #[must_use]
    pub const fn positive_regret_fix_count(&self) -> u64 {
        self.positive_regret_fix_count
    }

    #[must_use]
    pub const fn exact_mode_count(&self) -> u64 {
        self.exact_mode_count
    }

    #[must_use]
    pub const fn beam_mode_count(&self) -> u64 {
        self.beam_mode_count
    }

    #[must_use]
    pub const fn transition_cap_reached_count(&self) -> u64 {
        self.transition_cap_reached_count
    }

    #[must_use]
    pub const fn contains_annotations(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn claims_wall_time_or_peak_rss(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn changes_production_selector(&self) -> bool {
        false
    }
}

impl fmt::Debug for FrozenSelectorChallengerComparisonV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenSelectorChallengerComparisonV1")
            .field("comparison_identity_present", &true)
            .field("source_bindings_present", &true)
            .field("case_count", &self.cases.len())
            .field("objective_better_count", &self.objective_better_count)
            .field("objective_equal_count", &self.objective_equal_count)
            .field("matched_terminal_count", &self.matched_terminal_count)
            .field(
                "objective_regression_count",
                &self.objective_regression_count,
            )
            .field(
                "selected_cost_increase_count",
                &self.selected_cost_increase_count,
            )
            .field("positive_regret_fix_count", &self.positive_regret_fix_count)
            .field("exact_mode_count", &self.exact_mode_count)
            .field("beam_mode_count", &self.beam_mode_count)
            .field(
                "transition_cap_reached_count",
                &self.transition_cap_reached_count,
            )
            .field("contains_annotations", &false)
            .field("claims_wall_time_or_peak_rss", &false)
            .field("changes_production_selector", &false)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectorChallengerRecallRelationV1 {
    ChallengerBetter,
    Equal,
    ChallengerWorse,
    NotEvaluated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SelectorChallengerAdmissionBlockerV1 {
    ObjectiveRegression,
    GovernedRecallRegression,
    HardConstraintViolation,
    TransitionCapReached,
    SelectedCostTradeoff,
    NoGovernedLargeUniverseQualityCase,
    NoMeasuredWallTimeOrPeakRss,
}

impl SelectorChallengerAdmissionBlockerV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ObjectiveRegression => "objective_regression",
            Self::GovernedRecallRegression => "governed_recall_regression",
            Self::HardConstraintViolation => "hard_constraint_violation",
            Self::TransitionCapReached => "transition_cap_reached",
            Self::SelectedCostTradeoff => "selected_cost_tradeoff",
            Self::NoGovernedLargeUniverseQualityCase => "no_governed_large_universe_quality_case",
            Self::NoMeasuredWallTimeOrPeakRss => "no_measured_wall_time_or_peak_rss",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GovernedSelectorChallengerRecallCaseV1 {
    case: SyntheticThreeLaneAblationCaseV1,
    production: GovernedRequirementRecallV1,
    challenger: Option<GovernedRequirementRecallV1>,
    relation: SelectorChallengerRecallRelationV1,
}

impl GovernedSelectorChallengerRecallCaseV1 {
    #[must_use]
    pub const fn case(self) -> SyntheticThreeLaneAblationCaseV1 {
        self.case
    }

    #[must_use]
    pub const fn production(self) -> GovernedRequirementRecallV1 {
        self.production
    }

    #[must_use]
    pub const fn challenger(self) -> Option<GovernedRequirementRecallV1> {
        self.challenger
    }

    #[must_use]
    pub const fn relation(self) -> SelectorChallengerRecallRelationV1 {
        self.relation
    }
}

impl fmt::Debug for GovernedSelectorChallengerRecallCaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedSelectorChallengerRecallCaseV1")
            .field("case", &self.case)
            .field("production", &self.production)
            .field("challenger", &self.challenger)
            .field("relation", &self.relation)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct GovernedSelectorChallengerComparisonV1 {
    digest: ArtifactDigest,
    public_comparison_digest: ArtifactDigest,
    recall_cases: [GovernedSelectorChallengerRecallCaseV1; 6],
    recall_better_count: u64,
    recall_equal_count: u64,
    recall_regression_count: u64,
    recall_not_evaluated_count: u64,
    blockers: Vec<SelectorChallengerAdmissionBlockerV1>,
}

impl GovernedSelectorChallengerComparisonV1 {
    #[must_use]
    pub const fn digest(&self) -> ArtifactDigest {
        self.digest
    }

    #[must_use]
    pub const fn public_comparison_digest(&self) -> ArtifactDigest {
        self.public_comparison_digest
    }

    #[must_use]
    pub fn recall_cases(&self) -> &[GovernedSelectorChallengerRecallCaseV1; 6] {
        &self.recall_cases
    }

    #[must_use]
    pub const fn recall_better_count(&self) -> u64 {
        self.recall_better_count
    }

    #[must_use]
    pub const fn recall_equal_count(&self) -> u64 {
        self.recall_equal_count
    }

    #[must_use]
    pub const fn recall_regression_count(&self) -> u64 {
        self.recall_regression_count
    }

    #[must_use]
    pub const fn recall_not_evaluated_count(&self) -> u64 {
        self.recall_not_evaluated_count
    }

    #[must_use]
    pub fn blockers(&self) -> &[SelectorChallengerAdmissionBlockerV1] {
        &self.blockers
    }

    #[must_use]
    pub fn production_promotion_eligible(&self) -> bool {
        self.blockers.is_empty()
    }

    #[must_use]
    pub fn remains_evaluation_only(&self) -> bool {
        !self.blockers.is_empty()
    }

    #[must_use]
    pub const fn contains_scalar_composite(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn claims_population_quality(&self) -> bool {
        false
    }
}

impl fmt::Debug for GovernedSelectorChallengerComparisonV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedSelectorChallengerComparisonV1")
            .field("comparison_identity_present", &true)
            .field("public_binding_present", &true)
            .field("recall_case_count", &self.recall_cases.len())
            .field("recall_better_count", &self.recall_better_count)
            .field("recall_equal_count", &self.recall_equal_count)
            .field("recall_regression_count", &self.recall_regression_count)
            .field(
                "recall_not_evaluated_count",
                &self.recall_not_evaluated_count,
            )
            .field("blockers", &self.blockers)
            .field("contains_scalar_composite", &false)
            .field("claims_population_quality", &false)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SelectorChallengerComparisonErrorV1 {
    Challenger(BoundedSelectorChallengerErrorV1),
    SourceBindingMismatch,
    UnsupportedSourceDecision,
    ArithmeticOverflow,
    DigestLengthOverflow,
    MissingCase,
}

impl SelectorChallengerComparisonErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Challenger(_) => "EVIDENTRAIL_BENCH_SELECTOR_CHALLENGER_COMPARISON_CHALLENGER",
            Self::SourceBindingMismatch => {
                "EVIDENTRAIL_BENCH_SELECTOR_CHALLENGER_COMPARISON_SOURCE_BINDING"
            }
            Self::UnsupportedSourceDecision => {
                "EVIDENTRAIL_BENCH_SELECTOR_CHALLENGER_COMPARISON_SOURCE_DECISION"
            }
            Self::ArithmeticOverflow => {
                "EVIDENTRAIL_BENCH_SELECTOR_CHALLENGER_COMPARISON_ARITHMETIC"
            }
            Self::DigestLengthOverflow => {
                "EVIDENTRAIL_BENCH_SELECTOR_CHALLENGER_COMPARISON_DIGEST_LENGTH"
            }
            Self::MissingCase => "EVIDENTRAIL_BENCH_SELECTOR_CHALLENGER_COMPARISON_MISSING_CASE",
        }
    }
}

impl fmt::Debug for SelectorChallengerComparisonErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectorChallengerComparisonErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for SelectorChallengerComparisonErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for SelectorChallengerComparisonErrorV1 {}

pub fn freeze_selector_challenger_comparison_v1(
    perturbations: &FrozenSelectorPerturbationCorpusV1,
    synthetic: &FrozenPublicSyntheticThreeLaneSelectionCorpusV1,
) -> Result<FrozenSelectorChallengerComparisonV1, SelectorChallengerComparisonErrorV1> {
    let mut cases = Vec::with_capacity(BOUNDED_SELECTOR_CHALLENGER_COMPARISON_CASE_COUNT_V1);
    for case in SyntheticThreeLaneAblationCaseV1::ALL {
        let oracle = synthetic.case(case).full_selection_oracle();
        let pair = pair_from_synthetic_oracle(oracle)?;
        cases.push(FrozenSelectorChallengerComparisonCaseV1 {
            case: SelectorChallengerComparisonCaseV1::SyntheticFull(case),
            source_artifact_digest: ArtifactDigest::from_bytes(*oracle.digest().as_bytes()),
            fixes_positive_production_regret: matches!(
                pair.objective_relation(),
                BoundedSelectorObjectiveRelationV1::ChallengerBetter
            ),
            pair,
        });
    }
    for case in SelectorPerturbationCaseV1::ALL {
        let source = perturbations.case(case);
        let problem =
            crate::selector_perturbation_corpus::build_selector_perturbation_problem_v1(case)
                .map_err(|_| SelectorChallengerComparisonErrorV1::SourceBindingMismatch)?;
        let pair = evaluate_bounded_selector_challenger_v1(&problem)
            .map_err(SelectorChallengerComparisonErrorV1::Challenger)?;
        if pair.problem_digest() != source.problem_digest() {
            return Err(SelectorChallengerComparisonErrorV1::SourceBindingMismatch);
        }
        let production_regret = source
            .outcome()
            .exact_evaluated()
            .map(|evaluated| evaluated.regret_numerator())
            .unwrap_or(0);
        let fixes_positive_production_regret = production_regret > 0
            && matches!(
                pair.objective_relation(),
                BoundedSelectorObjectiveRelationV1::ChallengerBetter
            );
        cases.push(FrozenSelectorChallengerComparisonCaseV1 {
            case: SelectorChallengerComparisonCaseV1::Perturbation(case),
            source_artifact_digest: ArtifactDigest::from_bytes(*source.digest().as_bytes()),
            pair,
            fixes_positive_production_regret,
        });
    }
    let cases: [FrozenSelectorChallengerComparisonCaseV1;
        BOUNDED_SELECTOR_CHALLENGER_COMPARISON_CASE_COUNT_V1] = cases
        .try_into()
        .map_err(|_| SelectorChallengerComparisonErrorV1::MissingCase)?;
    let counts = comparison_counts(&cases)?;
    let digest = derive_public_digest(perturbations.digest(), synthetic.digest(), &cases, counts)?;
    Ok(FrozenSelectorChallengerComparisonV1 {
        digest,
        perturbation_corpus_digest: perturbations.digest(),
        synthetic_selection_corpus_digest: synthetic.digest(),
        cases,
        objective_better_count: counts.0,
        objective_equal_count: counts.1,
        matched_terminal_count: counts.2,
        objective_regression_count: counts.3,
        selected_cost_increase_count: counts.4,
        positive_regret_fix_count: counts.5,
        exact_mode_count: counts.6,
        beam_mode_count: counts.7,
        transition_cap_reached_count: counts.8,
    })
}

pub fn evaluate_governed_selector_challenger_comparison_v1(
    public: &FrozenSelectorChallengerComparisonV1,
    perturbations: &GovernedSelectorPerturbationReportV1,
    synthetic: &GovernedSyntheticFullSelectionOracleReportV1,
) -> Result<GovernedSelectorChallengerComparisonV1, SelectorChallengerComparisonErrorV1> {
    if perturbations.public_corpus_digest() != public.perturbation_corpus_digest
        || synthetic.public_selection_corpus_digest() != public.synthetic_selection_corpus_digest
    {
        return Err(SelectorChallengerComparisonErrorV1::SourceBindingMismatch);
    }
    if perturbations.cases().iter().any(|case| !case.conforms()) {
        return Err(SelectorChallengerComparisonErrorV1::SourceBindingMismatch);
    }
    let recall_cases = SyntheticThreeLaneAblationCaseV1::ALL.map(|case| {
        let governed = synthetic.case(case);
        let production = governed.production_required_event_recall();
        let challenger = governed.optimum_required_event_recall();
        let relation = recall_relation(production, challenger);
        GovernedSelectorChallengerRecallCaseV1 {
            case,
            production,
            challenger,
            relation,
        }
    });
    let mut recall_better_count = 0_u64;
    let mut recall_equal_count = 0_u64;
    let mut recall_regression_count = 0_u64;
    let mut recall_not_evaluated_count = 0_u64;
    for case in &recall_cases {
        match case.relation {
            SelectorChallengerRecallRelationV1::ChallengerBetter => {
                recall_better_count = checked_add(recall_better_count, 1)?;
            }
            SelectorChallengerRecallRelationV1::Equal => {
                recall_equal_count = checked_add(recall_equal_count, 1)?;
            }
            SelectorChallengerRecallRelationV1::ChallengerWorse => {
                recall_regression_count = checked_add(recall_regression_count, 1)?;
            }
            SelectorChallengerRecallRelationV1::NotEvaluated => {
                recall_not_evaluated_count = checked_add(recall_not_evaluated_count, 1)?;
            }
        }
    }
    let mut blockers = Vec::new();
    if public.objective_regression_count > 0 {
        blockers.push(SelectorChallengerAdmissionBlockerV1::ObjectiveRegression);
    }
    if recall_regression_count > 0 {
        blockers.push(SelectorChallengerAdmissionBlockerV1::GovernedRecallRegression);
    }
    if public
        .cases
        .iter()
        .any(|case| !case.pair.hard_constraints_preserved())
    {
        blockers.push(SelectorChallengerAdmissionBlockerV1::HardConstraintViolation);
    }
    if public.transition_cap_reached_count > 0 {
        blockers.push(SelectorChallengerAdmissionBlockerV1::TransitionCapReached);
    }
    if public.selected_cost_increase_count > 0 {
        blockers.push(SelectorChallengerAdmissionBlockerV1::SelectedCostTradeoff);
    }
    // The only >12 case is a label-free perturbation. It cannot establish
    // governed quality behavior for the beam arm.
    blockers.push(SelectorChallengerAdmissionBlockerV1::NoGovernedLargeUniverseQualityCase);
    // This artifact enforces deterministic work caps but deliberately does not
    // claim measured latency or memory use.
    blockers.push(SelectorChallengerAdmissionBlockerV1::NoMeasuredWallTimeOrPeakRss);
    blockers.sort_unstable();
    blockers.dedup();
    let digest = derive_governed_digest(
        public.digest,
        perturbations.digest(),
        synthetic.digest(),
        &recall_cases,
        &blockers,
    )?;
    Ok(GovernedSelectorChallengerComparisonV1 {
        digest,
        public_comparison_digest: public.digest,
        recall_cases,
        recall_better_count,
        recall_equal_count,
        recall_regression_count,
        recall_not_evaluated_count,
        blockers,
    })
}

fn pair_from_synthetic_oracle(
    oracle: &crate::FrozenSyntheticFullSelectionOracleV1,
) -> Result<FrozenBoundedSelectorPairV1, SelectorChallengerComparisonErrorV1> {
    let problem_digest = oracle
        .selection_problem_digest()
        .ok_or(SelectorChallengerComparisonErrorV1::UnsupportedSourceDecision)?;
    match oracle.decision() {
        FrozenSyntheticFullSelectionOracleDecisionV1::ExactEvaluated(evaluated) => {
            freeze_exact_pair_from_facts_v1(FrozenExactPairFactsV1 {
                problem_digest,
                optional_packet_count: evaluated.optional_packet_count(),
                total_token_budget: oracle.total_token_budget(),
                mandatory_packet_ids: convert_proposal_ids(
                    evaluated.optimum_mandatory_packet_ids(),
                ),
                reachable_subset_count: evaluated.reachable_subset_count(),
                production: FrozenSelectorOutcomeFactsV1::Selected {
                    objective_gain_numerator: evaluated.production_gain().numerator(),
                    selected_packet_ids: convert_proposal_ids(evaluated.production_packet_ids()),
                    optional_acceptance_order: Vec::new(),
                    selected_packet_cost: evaluated.production_selected_packet_cost(),
                    accounted_token_upper_bound: evaluated.production_accounted_token_upper_bound(),
                    coverage_only_token_cost: evaluated.production_coverage_only_token_cost(),
                    coverage_only_token_limit: evaluated.production_coverage_only_token_limit(),
                },
                optimum: FrozenSelectorOutcomeFactsV1::Selected {
                    objective_gain_numerator: evaluated.optimum_gain().numerator(),
                    selected_packet_ids: convert_proposal_ids(evaluated.optimum_packet_ids()),
                    optional_acceptance_order: convert_proposal_ids(
                        evaluated.optimum_optional_acceptance_order(),
                    ),
                    selected_packet_cost: evaluated.optimum_selected_packet_cost(),
                    accounted_token_upper_bound: evaluated.optimum_accounted_token_upper_bound(),
                    coverage_only_token_cost: evaluated.optimum_coverage_only_token_cost(),
                    coverage_only_token_limit: evaluated.optimum_coverage_only_token_limit(),
                },
            })
            .map_err(SelectorChallengerComparisonErrorV1::Challenger)
        }
        FrozenSyntheticFullSelectionOracleDecisionV1::ProductionNeedsMore(needs_more) => {
            let reason = needs_more
                .selection_reason()
                .ok_or(SelectorChallengerComparisonErrorV1::UnsupportedSourceDecision)?;
            let fixed = needs_more
                .fixed_overhead_tokens()
                .ok_or(SelectorChallengerComparisonErrorV1::UnsupportedSourceDecision)?;
            let terminal = BoundedSelectorNeedsMoreV1 {
                reason,
                total_token_budget: oracle.total_token_budget(),
                reserved_fixed_overhead: fixed,
                mandatory_packet_cost: needs_more.mandatory_packet_cost(),
                mandatory_packet_count: needs_more.mandatory_packet_count(),
            };
            freeze_exact_pair_from_facts_v1(FrozenExactPairFactsV1 {
                problem_digest,
                optional_packet_count: needs_more.optional_packet_count(),
                total_token_budget: oracle.total_token_budget(),
                mandatory_packet_ids: Vec::new(),
                reachable_subset_count: 1,
                production: FrozenSelectorOutcomeFactsV1::NeedsMore(terminal),
                optimum: FrozenSelectorOutcomeFactsV1::NeedsMore(terminal),
            })
            .map_err(SelectorChallengerComparisonErrorV1::Challenger)
        }
        FrozenSyntheticFullSelectionOracleDecisionV1::OptionalPacketCapIneligible(_) => {
            Err(SelectorChallengerComparisonErrorV1::UnsupportedSourceDecision)
        }
    }
}

fn convert_proposal_ids(ids: &[crate::ProducerProposalIdV1]) -> Vec<BoundedSelectorPacketIdV1> {
    ids.iter()
        .map(|id| BoundedSelectorPacketIdV1::from_bytes(*id.as_bytes()))
        .collect()
}

#[allow(clippy::type_complexity)]
fn comparison_counts(
    cases: &[FrozenSelectorChallengerComparisonCaseV1;
         BOUNDED_SELECTOR_CHALLENGER_COMPARISON_CASE_COUNT_V1],
) -> Result<(u64, u64, u64, u64, u64, u64, u64, u64, u64), SelectorChallengerComparisonErrorV1> {
    let mut counts = (
        0_u64, 0_u64, 0_u64, 0_u64, 0_u64, 0_u64, 0_u64, 0_u64, 0_u64,
    );
    for case in cases {
        match case.pair.objective_relation() {
            BoundedSelectorObjectiveRelationV1::ChallengerBetter => {
                counts.0 = checked_add(counts.0, 1)?
            }
            BoundedSelectorObjectiveRelationV1::Equal => counts.1 = checked_add(counts.1, 1)?,
            BoundedSelectorObjectiveRelationV1::MatchedTerminal => {
                counts.2 = checked_add(counts.2, 1)?
            }
            BoundedSelectorObjectiveRelationV1::ChallengerWorse
            | BoundedSelectorObjectiveRelationV1::TerminalMismatch => {
                counts.3 = checked_add(counts.3, 1)?
            }
        }
        if case.pair.selected_cost_relation() == BoundedSelectorCostRelationV1::ChallengerHigher {
            counts.4 = checked_add(counts.4, 1)?;
        }
        if case.fixes_positive_production_regret {
            counts.5 = checked_add(counts.5, 1)?;
        }
        match case.pair.mode() {
            crate::BoundedSelectorChallengerModeV1::ExactSubsets => {
                counts.6 = checked_add(counts.6, 1)?
            }
            crate::BoundedSelectorChallengerModeV1::OrderAwareBeam => {
                counts.7 = checked_add(counts.7, 1)?
            }
        }
        if case.pair.observation().transition_cap_reached() {
            counts.8 = checked_add(counts.8, 1)?;
        }
    }
    Ok(counts)
}

fn recall_relation(
    production: GovernedRequirementRecallV1,
    challenger: Option<GovernedRequirementRecallV1>,
) -> SelectorChallengerRecallRelationV1 {
    let Some(challenger) = challenger else {
        return SelectorChallengerRecallRelationV1::NotEvaluated;
    };
    if production.total_weight_micros() != challenger.total_weight_micros() {
        return SelectorChallengerRecallRelationV1::ChallengerWorse;
    }
    match challenger
        .satisfied_weight_micros()
        .cmp(&production.satisfied_weight_micros())
    {
        Ordering::Greater => SelectorChallengerRecallRelationV1::ChallengerBetter,
        Ordering::Equal => SelectorChallengerRecallRelationV1::Equal,
        Ordering::Less => SelectorChallengerRecallRelationV1::ChallengerWorse,
    }
}

type ComparisonCounts = (u64, u64, u64, u64, u64, u64, u64, u64, u64);

fn derive_public_digest(
    perturbation_digest: FrozenSelectorPerturbationCorpusDigestV1,
    synthetic_digest: FrozenSyntheticThreeLaneSelectionCorpusDigestV1,
    cases: &[FrozenSelectorChallengerComparisonCaseV1;
         BOUNDED_SELECTOR_CHALLENGER_COMPARISON_CASE_COUNT_V1],
    counts: ComparisonCounts,
) -> Result<ArtifactDigest, SelectorChallengerComparisonErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, PUBLIC_COMPARISON_DOMAIN_V1)?;
    update_field(
        &mut hasher,
        bounded_selector_challenger_identity_v1()
            .digest()
            .as_bytes(),
    )?;
    update_field(&mut hasher, perturbation_digest.as_bytes())?;
    update_field(&mut hasher, synthetic_digest.as_bytes())?;
    update_u64(&mut hasher, checked_u64(cases.len())?);
    for case in cases {
        update_field(&mut hasher, case.case.identity_digest().as_bytes())?;
        update_field(&mut hasher, case.source_artifact_digest.as_bytes())?;
        update_field(&mut hasher, case.pair.digest().as_bytes())?;
        hasher.update([u8::from(case.fixes_positive_production_regret)]);
    }
    for count in [
        counts.0, counts.1, counts.2, counts.3, counts.4, counts.5, counts.6, counts.7, counts.8,
    ] {
        update_u64(&mut hasher, count);
    }
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

fn derive_governed_digest(
    public_digest: ArtifactDigest,
    perturbation_report_digest: ArtifactDigest,
    synthetic_report_digest: ArtifactDigest,
    recall_cases: &[GovernedSelectorChallengerRecallCaseV1; 6],
    blockers: &[SelectorChallengerAdmissionBlockerV1],
) -> Result<ArtifactDigest, SelectorChallengerComparisonErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, GOVERNED_COMPARISON_DOMAIN_V1)?;
    update_field(&mut hasher, public_digest.as_bytes())?;
    update_field(&mut hasher, perturbation_report_digest.as_bytes())?;
    update_field(&mut hasher, synthetic_report_digest.as_bytes())?;
    for case in recall_cases {
        update_field(&mut hasher, case.case.identity_digest().as_bytes())?;
        hash_recall(&mut hasher, case.production);
        match case.challenger {
            Some(recall) => {
                hasher.update([1]);
                hash_recall(&mut hasher, recall);
            }
            None => hasher.update([0]),
        }
        update_field(&mut hasher, recall_relation_code(case.relation).as_bytes())?;
    }
    update_u64(&mut hasher, checked_u64(blockers.len())?);
    for blocker in blockers {
        update_field(&mut hasher, blocker.code().as_bytes())?;
    }
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

fn hash_recall(hasher: &mut Sha256, recall: GovernedRequirementRecallV1) {
    for value in [
        recall.requirement_count(),
        recall.satisfied_requirement_count(),
        recall.total_weight_micros(),
        recall.satisfied_weight_micros(),
    ] {
        update_u64(hasher, value);
    }
}

const fn recall_relation_code(relation: SelectorChallengerRecallRelationV1) -> &'static str {
    match relation {
        SelectorChallengerRecallRelationV1::ChallengerBetter => "challenger_better",
        SelectorChallengerRecallRelationV1::Equal => "equal",
        SelectorChallengerRecallRelationV1::ChallengerWorse => "challenger_worse",
        SelectorChallengerRecallRelationV1::NotEvaluated => "not_evaluated",
    }
}

fn update_field(
    hasher: &mut Sha256,
    bytes: &[u8],
) -> Result<(), SelectorChallengerComparisonErrorV1> {
    update_u64(hasher, checked_u64(bytes.len())?);
    hasher.update(bytes);
    Ok(())
}

fn update_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

fn checked_add(left: u64, right: u64) -> Result<u64, SelectorChallengerComparisonErrorV1> {
    left.checked_add(right)
        .ok_or(SelectorChallengerComparisonErrorV1::ArithmeticOverflow)
}

fn checked_u64(value: usize) -> Result<u64, SelectorChallengerComparisonErrorV1> {
    u64::try_from(value).map_err(|_| SelectorChallengerComparisonErrorV1::DigestLengthOverflow)
}
