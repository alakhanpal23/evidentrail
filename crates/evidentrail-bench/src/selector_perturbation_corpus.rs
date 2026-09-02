//! Deterministic, hand-authored selector conformance perturbations.
//!
//! The public freeze evaluates production selection and the bounded exact
//! oracle without accepting annotations. The later governed join attaches
//! case-bound expected outcomes. That type staging is a label-free data
//! boundary, not external temporal/process attestation. Results describe only
//! these synthetic cases: they do not estimate population quality, establish
//! an approximation factor, or show that learned ranking is necessary.

use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::{ArtifactDigest, EventId};
use evidentrail_select::{
    AffinityV1, COVERAGE_ONLY_OPTIONAL_BUDGET_DENOMINATOR_V1, ComposableCostModelV1,
    ComposablePacketCostV1, FacetAffinityV1, FacetWeightV1, IntactPacketV1, MandatoryPacketV1,
    NeedsMoreReasonV1, PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1, PacketIdV1,
    ProductionFacetKindV1, ProductionFacetV1, ReservedFixedOverheadV1,
    SELECTION_OBJECTIVE_POLICY_NAME_V1, SELECTION_OBJECTIVE_POLICY_VERSION_V1, SelectionProblemV1,
    SelectionStrategyV1, TotalTokenBudgetV1,
};
use sha2::{Digest as _, Sha256};

use crate::{
    EXACT_SELECTION_ORACLE_POLICY_NAME_V1, EXACT_SELECTION_ORACLE_POLICY_VERSION_V1,
    ExactSelectionOracleErrorV1, ExactSmallSelectionNeedsMoreV1,
    ExactSmallSelectionRegretDecisionV1, ExactSmallSelectionRegretV1,
    MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1, evaluate_exact_small_selection_regret_v1,
};

const PUBLIC_CORPUS_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/public-selector-perturbation-corpus/v1\0";
const PUBLIC_CASE_DOMAIN_V1: &[u8] = b"evidentrail/bench/public-selector-perturbation-case/v1\0";
const GOVERNED_REPORT_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/governed-selector-perturbation-report/v1\0";

pub const SYNTHETIC_SELECTOR_PERTURBATION_CASE_COUNT_V1: usize = 13;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SelectorPerturbationFamilyV1 {
    BudgetBoundary,
    CostDensity,
    AffinityTie,
    ProviderCardinality,
    BreadthSlice,
    TerminalBudget,
    OracleCapacity,
}

impl SelectorPerturbationFamilyV1 {
    pub const ALL: [Self; 7] = [
        Self::BudgetBoundary,
        Self::CostDensity,
        Self::AffinityTie,
        Self::ProviderCardinality,
        Self::BreadthSlice,
        Self::TerminalBudget,
        Self::OracleCapacity,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::BudgetBoundary => "budget_boundary_v1",
            Self::CostDensity => "cost_density_v1",
            Self::AffinityTie => "affinity_tie_v1",
            Self::ProviderCardinality => "provider_cardinality_v1",
            Self::BreadthSlice => "breadth_slice_v1",
            Self::TerminalBudget => "terminal_budget_v1",
            Self::OracleCapacity => "oracle_capacity_v1",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SelectorPerturbationCaseV1 {
    BudgetExactFit,
    BudgetOneBelow,
    DensityTrap,
    EqualDensityTie,
    ProviderTopTwo,
    ProviderThirdEndpointZero,
    ProviderMandatoryComplement,
    BreadthSliceBlocked,
    BreadthMixedAdmissionOrder,
    FixedOverheadTerminal,
    MandatoryOverBudgetTerminal,
    OracleCapTwelveExact,
    OracleCapThirteenIneligible,
}

impl SelectorPerturbationCaseV1 {
    pub const ALL: [Self; SYNTHETIC_SELECTOR_PERTURBATION_CASE_COUNT_V1] = [
        Self::BudgetExactFit,
        Self::BudgetOneBelow,
        Self::DensityTrap,
        Self::EqualDensityTie,
        Self::ProviderTopTwo,
        Self::ProviderThirdEndpointZero,
        Self::ProviderMandatoryComplement,
        Self::BreadthSliceBlocked,
        Self::BreadthMixedAdmissionOrder,
        Self::FixedOverheadTerminal,
        Self::MandatoryOverBudgetTerminal,
        Self::OracleCapTwelveExact,
        Self::OracleCapThirteenIneligible,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::BudgetExactFit => "budget_exact_fit_v1",
            Self::BudgetOneBelow => "budget_one_below_v1",
            Self::DensityTrap => "density_trap_v1",
            Self::EqualDensityTie => "equal_density_tie_v1",
            Self::ProviderTopTwo => "provider_top_two_v1",
            Self::ProviderThirdEndpointZero => "provider_third_endpoint_zero_v1",
            Self::ProviderMandatoryComplement => "provider_mandatory_complement_v1",
            Self::BreadthSliceBlocked => "breadth_slice_blocked_v1",
            Self::BreadthMixedAdmissionOrder => "breadth_mixed_admission_order_v1",
            Self::FixedOverheadTerminal => "fixed_overhead_terminal_v1",
            Self::MandatoryOverBudgetTerminal => "mandatory_over_budget_terminal_v1",
            Self::OracleCapTwelveExact => "oracle_cap_twelve_exact_v1",
            Self::OracleCapThirteenIneligible => "oracle_cap_thirteen_ineligible_v1",
        }
    }

    #[must_use]
    pub const fn family(self) -> SelectorPerturbationFamilyV1 {
        match self {
            Self::BudgetExactFit | Self::BudgetOneBelow => {
                SelectorPerturbationFamilyV1::BudgetBoundary
            }
            Self::DensityTrap => SelectorPerturbationFamilyV1::CostDensity,
            Self::EqualDensityTie => SelectorPerturbationFamilyV1::AffinityTie,
            Self::ProviderTopTwo
            | Self::ProviderThirdEndpointZero
            | Self::ProviderMandatoryComplement => {
                SelectorPerturbationFamilyV1::ProviderCardinality
            }
            Self::BreadthSliceBlocked | Self::BreadthMixedAdmissionOrder => {
                SelectorPerturbationFamilyV1::BreadthSlice
            }
            Self::FixedOverheadTerminal | Self::MandatoryOverBudgetTerminal => {
                SelectorPerturbationFamilyV1::TerminalBudget
            }
            Self::OracleCapTwelveExact | Self::OracleCapThirteenIneligible => {
                SelectorPerturbationFamilyV1::OracleCapacity
            }
        }
    }

    #[must_use]
    pub fn identity_digest(self) -> ArtifactDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"evidentrail/bench/selector-perturbation-case-identity/v1\0");
        hasher.update(self.code().as_bytes());
        hasher.update([0]);
        hasher.update(self.family().code().as_bytes());
        ArtifactDigest::from_bytes(hasher.finalize().into())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrozenSelectorPerturbationCaseDigestV1([u8; 32]);

impl FrozenSelectorPerturbationCaseDigestV1 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for FrozenSelectorPerturbationCaseDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenSelectorPerturbationCaseDigestV1(<redacted>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrozenSelectorPerturbationCorpusDigestV1([u8; 32]);

impl FrozenSelectorPerturbationCorpusDigestV1 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for FrozenSelectorPerturbationCorpusDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenSelectorPerturbationCorpusDigestV1(<redacted>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SelectorPerturbationCapIneligibleV1 {
    optional_packet_count: u64,
    optional_packet_cap: u64,
}

impl SelectorPerturbationCapIneligibleV1 {
    #[must_use]
    pub const fn optional_packet_count(self) -> u64 {
        self.optional_packet_count
    }

    #[must_use]
    pub const fn optional_packet_cap(self) -> u64 {
        self.optional_packet_cap
    }
}

impl fmt::Debug for SelectorPerturbationCapIneligibleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectorPerturbationCapIneligibleV1")
            .field("optional_packet_count", &self.optional_packet_count)
            .field("optional_packet_cap", &self.optional_packet_cap)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum FrozenSelectorPerturbationOutcomeV1 {
    ExactEvaluated(Box<ExactSmallSelectionRegretV1>),
    ProductionNeedsMore(ExactSmallSelectionNeedsMoreV1),
    OptionalPacketCapIneligible(SelectorPerturbationCapIneligibleV1),
}

impl FrozenSelectorPerturbationOutcomeV1 {
    #[must_use]
    pub const fn exact_evaluated(&self) -> Option<&ExactSmallSelectionRegretV1> {
        match self {
            Self::ExactEvaluated(evaluated) => Some(evaluated),
            Self::ProductionNeedsMore(_) | Self::OptionalPacketCapIneligible(_) => None,
        }
    }

    #[must_use]
    pub const fn production_needs_more(&self) -> Option<ExactSmallSelectionNeedsMoreV1> {
        match self {
            Self::ProductionNeedsMore(needs_more) => Some(*needs_more),
            Self::ExactEvaluated(_) | Self::OptionalPacketCapIneligible(_) => None,
        }
    }

    #[must_use]
    pub const fn optional_packet_cap_ineligible(
        &self,
    ) -> Option<SelectorPerturbationCapIneligibleV1> {
        match self {
            Self::OptionalPacketCapIneligible(ineligible) => Some(*ineligible),
            Self::ExactEvaluated(_) | Self::ProductionNeedsMore(_) => None,
        }
    }
}

impl fmt::Debug for FrozenSelectorPerturbationOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExactEvaluated(evaluated) => formatter
                .debug_tuple("FrozenSelectorPerturbationOutcomeV1::ExactEvaluated")
                .field(evaluated)
                .finish(),
            Self::ProductionNeedsMore(needs_more) => formatter
                .debug_tuple("FrozenSelectorPerturbationOutcomeV1::ProductionNeedsMore")
                .field(needs_more)
                .finish(),
            Self::OptionalPacketCapIneligible(ineligible) => formatter
                .debug_tuple("FrozenSelectorPerturbationOutcomeV1::OptionalPacketCapIneligible")
                .field(ineligible)
                .finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct FrozenSelectorPerturbationCaseV1 {
    digest: FrozenSelectorPerturbationCaseDigestV1,
    case: SelectorPerturbationCaseV1,
    problem_digest: ArtifactDigest,
    optional_packet_count: u64,
    total_token_budget: u64,
    fixed_overhead_tokens: u64,
    outcome: FrozenSelectorPerturbationOutcomeV1,
}

impl FrozenSelectorPerturbationCaseV1 {
    #[must_use]
    pub const fn digest(&self) -> FrozenSelectorPerturbationCaseDigestV1 {
        self.digest
    }

    #[must_use]
    pub const fn case(&self) -> SelectorPerturbationCaseV1 {
        self.case
    }

    #[must_use]
    pub const fn family(&self) -> SelectorPerturbationFamilyV1 {
        self.case.family()
    }

    #[must_use]
    pub const fn problem_digest(&self) -> ArtifactDigest {
        self.problem_digest
    }

    #[must_use]
    pub const fn optional_packet_count(&self) -> u64 {
        self.optional_packet_count
    }

    #[must_use]
    pub const fn total_token_budget(&self) -> u64 {
        self.total_token_budget
    }

    #[must_use]
    pub const fn fixed_overhead_tokens(&self) -> u64 {
        self.fixed_overhead_tokens
    }

    #[must_use]
    pub const fn outcome(&self) -> &FrozenSelectorPerturbationOutcomeV1 {
        &self.outcome
    }
}

impl fmt::Debug for FrozenSelectorPerturbationCaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenSelectorPerturbationCaseV1")
            .field("case", &self.case)
            .field("problem_identity_present", &true)
            .field("optional_packet_count", &self.optional_packet_count)
            .field("total_token_budget", &self.total_token_budget)
            .field("fixed_overhead_tokens", &self.fixed_overhead_tokens)
            .field("outcome", &self.outcome)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct FrozenSelectorPerturbationCorpusV1 {
    digest: FrozenSelectorPerturbationCorpusDigestV1,
    cases: [FrozenSelectorPerturbationCaseV1; SYNTHETIC_SELECTOR_PERTURBATION_CASE_COUNT_V1],
}

impl FrozenSelectorPerturbationCorpusV1 {
    #[must_use]
    pub const fn digest(&self) -> FrozenSelectorPerturbationCorpusDigestV1 {
        self.digest
    }

    #[must_use]
    pub fn cases(
        &self,
    ) -> &[FrozenSelectorPerturbationCaseV1; SYNTHETIC_SELECTOR_PERTURBATION_CASE_COUNT_V1] {
        &self.cases
    }

    #[must_use]
    pub fn case(&self, case: SelectorPerturbationCaseV1) -> &FrozenSelectorPerturbationCaseV1 {
        &self.cases[case_index(case)]
    }

    #[must_use]
    pub const fn contains_governed_annotations(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn claims_population_quality(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn oracle_policy_name(&self) -> &'static [u8] {
        EXACT_SELECTION_ORACLE_POLICY_NAME_V1
    }

    #[must_use]
    pub const fn oracle_policy_version(&self) -> &'static [u8] {
        EXACT_SELECTION_ORACLE_POLICY_VERSION_V1
    }

    #[must_use]
    pub const fn oracle_optional_packet_cap(&self) -> usize {
        MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1
    }

    #[must_use]
    pub const fn production_objective_policy_name(&self) -> &'static [u8] {
        SELECTION_OBJECTIVE_POLICY_NAME_V1
    }

    #[must_use]
    pub const fn production_objective_policy_version(&self) -> &'static [u8] {
        SELECTION_OBJECTIVE_POLICY_VERSION_V1
    }

    #[must_use]
    pub const fn staging_trust_boundary_code(&self) -> &'static str {
        "label_free_data_boundary_not_external_temporal_attestation"
    }
}

impl fmt::Debug for FrozenSelectorPerturbationCorpusV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenSelectorPerturbationCorpusV1")
            .field("corpus_identity_present", &true)
            .field("case_count", &self.cases.len())
            .field("contains_governed_annotations", &false)
            .field("claims_population_quality", &false)
            .field(
                "oracle_optional_packet_cap",
                &self.oracle_optional_packet_cap(),
            )
            .field(
                "staging_trust_boundary",
                &self.staging_trust_boundary_code(),
            )
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SelectorPerturbationExpectedOutcomeV1 {
    ExactRegret { numerator: u64 },
    ProductionNeedsMore { reason: NeedsMoreReasonV1 },
    OptionalPacketCapIneligible { packet_count: u64, cap: u64 },
}

impl fmt::Debug for SelectorPerturbationExpectedOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::ExactRegret { .. } => "exact_regret",
            Self::ProductionNeedsMore { .. } => "production_needs_more",
            Self::OptionalPacketCapIneligible { .. } => "optional_packet_cap_ineligible",
        };
        formatter
            .debug_struct("SelectorPerturbationExpectedOutcomeV1")
            .field("kind", &kind)
            .field("details", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SelectorPerturbationGovernedAnnotationV1 {
    public_corpus_digest: FrozenSelectorPerturbationCorpusDigestV1,
    case: SelectorPerturbationCaseV1,
    public_case_digest: FrozenSelectorPerturbationCaseDigestV1,
    expected: SelectorPerturbationExpectedOutcomeV1,
}

impl SelectorPerturbationGovernedAnnotationV1 {
    #[must_use]
    pub const fn new(
        public_corpus_digest: FrozenSelectorPerturbationCorpusDigestV1,
        case: SelectorPerturbationCaseV1,
        public_case_digest: FrozenSelectorPerturbationCaseDigestV1,
        expected: SelectorPerturbationExpectedOutcomeV1,
    ) -> Self {
        Self {
            public_corpus_digest,
            case,
            public_case_digest,
            expected,
        }
    }
}

impl fmt::Debug for SelectorPerturbationGovernedAnnotationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectorPerturbationGovernedAnnotationV1")
            .field("public_bindings_present", &true)
            .field("case", &self.case)
            .field("expected_present", &true)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct GovernedSelectorPerturbationCaseV1 {
    public_case: FrozenSelectorPerturbationCaseV1,
    expected: SelectorPerturbationExpectedOutcomeV1,
    conforms: bool,
}

impl GovernedSelectorPerturbationCaseV1 {
    #[must_use]
    pub const fn public_case(&self) -> &FrozenSelectorPerturbationCaseV1 {
        &self.public_case
    }

    #[must_use]
    pub const fn expected(&self) -> SelectorPerturbationExpectedOutcomeV1 {
        self.expected
    }

    #[must_use]
    pub const fn conforms(&self) -> bool {
        self.conforms
    }
}

impl fmt::Debug for GovernedSelectorPerturbationCaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedSelectorPerturbationCaseV1")
            .field("public_case", &self.public_case)
            .field("expected_present", &true)
            .field("conforms", &self.conforms)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectorPerturbationFamilyDistributionV1 {
    family: SelectorPerturbationFamilyV1,
    case_count: u64,
    exact_zero_regret_count: u64,
    exact_positive_regret_count: u64,
    production_needs_more_count: u64,
    cap_ineligible_count: u64,
    conformance_mismatch_count: u64,
}

impl SelectorPerturbationFamilyDistributionV1 {
    #[must_use]
    pub const fn family(self) -> SelectorPerturbationFamilyV1 {
        self.family
    }

    #[must_use]
    pub const fn case_count(self) -> u64 {
        self.case_count
    }

    #[must_use]
    pub const fn exact_zero_regret_count(self) -> u64 {
        self.exact_zero_regret_count
    }

    #[must_use]
    pub const fn exact_positive_regret_count(self) -> u64 {
        self.exact_positive_regret_count
    }

    #[must_use]
    pub const fn production_needs_more_count(self) -> u64 {
        self.production_needs_more_count
    }

    #[must_use]
    pub const fn cap_ineligible_count(self) -> u64 {
        self.cap_ineligible_count
    }

    #[must_use]
    pub const fn conformance_mismatch_count(self) -> u64 {
        self.conformance_mismatch_count
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct GovernedSelectorPerturbationReportV1 {
    digest: ArtifactDigest,
    public_corpus_digest: FrozenSelectorPerturbationCorpusDigestV1,
    cases: [GovernedSelectorPerturbationCaseV1; SYNTHETIC_SELECTOR_PERTURBATION_CASE_COUNT_V1],
    family_distributions: [SelectorPerturbationFamilyDistributionV1; 7],
}

impl GovernedSelectorPerturbationReportV1 {
    #[must_use]
    pub const fn digest(&self) -> ArtifactDigest {
        self.digest
    }

    #[must_use]
    pub const fn public_corpus_digest(&self) -> FrozenSelectorPerturbationCorpusDigestV1 {
        self.public_corpus_digest
    }

    #[must_use]
    pub fn cases(
        &self,
    ) -> &[GovernedSelectorPerturbationCaseV1; SYNTHETIC_SELECTOR_PERTURBATION_CASE_COUNT_V1] {
        &self.cases
    }

    #[must_use]
    pub fn case(&self, case: SelectorPerturbationCaseV1) -> &GovernedSelectorPerturbationCaseV1 {
        &self.cases[case_index(case)]
    }

    #[must_use]
    pub fn family_distributions(&self) -> &[SelectorPerturbationFamilyDistributionV1; 7] {
        &self.family_distributions
    }

    #[must_use]
    pub const fn contains_scalar_composite(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn claims_population_quality(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn claims_approximation_factor(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn claims_learned_ranking_necessity(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn contains_winner(&self) -> bool {
        false
    }
}

impl fmt::Debug for GovernedSelectorPerturbationReportV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedSelectorPerturbationReportV1")
            .field("report_identity_present", &true)
            .field("public_corpus_binding_present", &true)
            .field("case_count", &self.cases.len())
            .field(
                "family_distribution_count",
                &self.family_distributions.len(),
            )
            .field("contains_scalar_composite", &false)
            .field("claims_population_quality", &false)
            .field("claims_approximation_factor", &false)
            .field("claims_learned_ranking_necessity", &false)
            .field("contains_winner", &false)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SelectorPerturbationCorpusErrorV1 {
    FixtureInvariant,
    Oracle(ExactSelectionOracleErrorV1),
    ArithmeticOverflow,
    DigestLengthOverflow,
    DuplicateAnnotation,
    MissingAnnotations { count: usize },
    ForeignCorpus,
    ForeignCase,
}

impl SelectorPerturbationCorpusErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::FixtureInvariant => "EVIDENTRAIL_BENCH_SELECTOR_PERTURBATION_FIXTURE",
            Self::Oracle(_) => "EVIDENTRAIL_BENCH_SELECTOR_PERTURBATION_ORACLE",
            Self::ArithmeticOverflow => "EVIDENTRAIL_BENCH_SELECTOR_PERTURBATION_ARITHMETIC",
            Self::DigestLengthOverflow => "EVIDENTRAIL_BENCH_SELECTOR_PERTURBATION_DIGEST_LENGTH",
            Self::DuplicateAnnotation => {
                "EVIDENTRAIL_BENCH_SELECTOR_PERTURBATION_DUPLICATE_ANNOTATION"
            }
            Self::MissingAnnotations { .. } => {
                "EVIDENTRAIL_BENCH_SELECTOR_PERTURBATION_MISSING_ANNOTATIONS"
            }
            Self::ForeignCorpus => "EVIDENTRAIL_BENCH_SELECTOR_PERTURBATION_FOREIGN_CORPUS",
            Self::ForeignCase => "EVIDENTRAIL_BENCH_SELECTOR_PERTURBATION_FOREIGN_CASE",
        }
    }
}

impl fmt::Debug for SelectorPerturbationCorpusErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("SelectorPerturbationCorpusErrorV1");
        debug.field("code", &self.code());
        if let Self::MissingAnnotations { count } = self {
            debug.field("count", count);
        }
        debug.finish()
    }
}

impl fmt::Display for SelectorPerturbationCorpusErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for SelectorPerturbationCorpusErrorV1 {}

/// Freeze every deterministic selector perturbation before governed expected
/// outcome annotations exist. No benchmark labels, logs, or model outputs are
/// inputs to this function.
pub fn freeze_selector_perturbation_corpus_v1()
-> Result<FrozenSelectorPerturbationCorpusV1, SelectorPerturbationCorpusErrorV1> {
    let cases = SelectorPerturbationCaseV1::ALL
        .into_iter()
        .map(freeze_case)
        .collect::<Result<Vec<_>, _>>()?;
    let cases: [FrozenSelectorPerturbationCaseV1; SYNTHETIC_SELECTOR_PERTURBATION_CASE_COUNT_V1] =
        cases
            .try_into()
            .map_err(|_| SelectorPerturbationCorpusErrorV1::FixtureInvariant)?;
    let mut hasher = Sha256::new();
    update_field(&mut hasher, PUBLIC_CORPUS_DOMAIN_V1)?;
    update_field(&mut hasher, EXACT_SELECTION_ORACLE_POLICY_NAME_V1)?;
    update_field(&mut hasher, EXACT_SELECTION_ORACLE_POLICY_VERSION_V1)?;
    update_field(&mut hasher, SELECTION_OBJECTIVE_POLICY_NAME_V1)?;
    update_field(&mut hasher, SELECTION_OBJECTIVE_POLICY_VERSION_V1)?;
    update_u64(
        &mut hasher,
        checked_u64(MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1)?,
    );
    update_u64(&mut hasher, COVERAGE_ONLY_OPTIONAL_BUDGET_DENOMINATOR_V1);
    update_u32(&mut hasher, PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1);
    for case in &cases {
        update_field(&mut hasher, case.digest.as_bytes())?;
    }
    Ok(FrozenSelectorPerturbationCorpusV1 {
        digest: FrozenSelectorPerturbationCorpusDigestV1(hasher.finalize().into()),
        cases,
    })
}

pub fn evaluate_governed_selector_perturbation_corpus_v1<Annotations>(
    public: &FrozenSelectorPerturbationCorpusV1,
    annotations: Annotations,
) -> Result<GovernedSelectorPerturbationReportV1, SelectorPerturbationCorpusErrorV1>
where
    Annotations: IntoIterator<Item = SelectorPerturbationGovernedAnnotationV1>,
{
    let mut by_case =
        std::array::from_fn::<_, SYNTHETIC_SELECTOR_PERTURBATION_CASE_COUNT_V1, _>(|_| None);
    for annotation in annotations {
        if annotation.public_corpus_digest != public.digest {
            return Err(SelectorPerturbationCorpusErrorV1::ForeignCorpus);
        }
        let index = case_index(annotation.case);
        if by_case[index].replace(annotation).is_some() {
            return Err(SelectorPerturbationCorpusErrorV1::DuplicateAnnotation);
        }
    }
    if by_case.iter().any(Option::is_none) {
        return Err(SelectorPerturbationCorpusErrorV1::MissingAnnotations {
            count: by_case.iter().filter(|entry| entry.is_none()).count(),
        });
    }
    let cases = by_case
        .into_iter()
        .zip(SelectorPerturbationCaseV1::ALL)
        .map(|(annotation, case)| {
            let annotation = annotation
                .ok_or(SelectorPerturbationCorpusErrorV1::MissingAnnotations { count: 1 })?;
            let public_case = public.case(case);
            if annotation.case != case || annotation.public_case_digest != public_case.digest {
                return Err(SelectorPerturbationCorpusErrorV1::ForeignCase);
            }
            Ok(GovernedSelectorPerturbationCaseV1 {
                public_case: public_case.clone(),
                expected: annotation.expected,
                conforms: expected_matches(public_case.outcome(), annotation.expected),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let cases: [GovernedSelectorPerturbationCaseV1; SYNTHETIC_SELECTOR_PERTURBATION_CASE_COUNT_V1] =
        cases
            .try_into()
            .map_err(|_| SelectorPerturbationCorpusErrorV1::FixtureInvariant)?;
    let family_distributions = SelectorPerturbationFamilyV1::ALL
        .map(|family| build_family_distribution(family, &cases))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| SelectorPerturbationCorpusErrorV1::FixtureInvariant)?;
    let digest = derive_governed_digest(public.digest, &cases, &family_distributions)?;
    Ok(GovernedSelectorPerturbationReportV1 {
        digest,
        public_corpus_digest: public.digest,
        cases,
        family_distributions,
    })
}

fn freeze_case(
    case: SelectorPerturbationCaseV1,
) -> Result<FrozenSelectorPerturbationCaseV1, SelectorPerturbationCorpusErrorV1> {
    let problem = build_selector_perturbation_problem_v1(case)?;
    let problem_digest =
        crate::bounded_selector_challenger::derive_selection_problem_digest_v1(&problem)
            .map_err(|_| SelectorPerturbationCorpusErrorV1::FixtureInvariant)?;
    let mandatory_ids = problem
        .mandatory()
        .iter()
        .map(|entry| entry.packet_id())
        .collect::<BTreeSet<_>>();
    let optional_packet_count = problem
        .packets()
        .iter()
        .filter(|packet| !mandatory_ids.contains(&packet.id()))
        .count();
    let outcome = match evaluate_exact_small_selection_regret_v1(&problem) {
        Ok(ExactSmallSelectionRegretDecisionV1::Evaluated(evaluated)) => {
            FrozenSelectorPerturbationOutcomeV1::ExactEvaluated(Box::new(evaluated))
        }
        Ok(ExactSmallSelectionRegretDecisionV1::NeedsMore(needs_more)) => {
            FrozenSelectorPerturbationOutcomeV1::ProductionNeedsMore(needs_more)
        }
        Err(ExactSelectionOracleErrorV1::TooManyOptionalPackets)
            if optional_packet_count > MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1 =>
        {
            FrozenSelectorPerturbationOutcomeV1::OptionalPacketCapIneligible(
                SelectorPerturbationCapIneligibleV1 {
                    optional_packet_count: checked_u64(optional_packet_count)?,
                    optional_packet_cap: checked_u64(
                        MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1,
                    )?,
                },
            )
        }
        Err(error) => return Err(SelectorPerturbationCorpusErrorV1::Oracle(error)),
    };
    let digest = derive_case_digest(
        case,
        problem_digest,
        &problem,
        optional_packet_count,
        &outcome,
    )?;
    Ok(FrozenSelectorPerturbationCaseV1 {
        digest,
        case,
        problem_digest,
        optional_packet_count: checked_u64(optional_packet_count)?,
        total_token_budget: problem.total_token_budget().tokens(),
        fixed_overhead_tokens: problem.reserved_fixed_overhead().upper_bound_tokens(),
        outcome,
    })
}

pub(crate) fn build_selector_perturbation_problem_v1(
    case: SelectorPerturbationCaseV1,
) -> Result<SelectionProblemV1, SelectorPerturbationCorpusErrorV1> {
    match case {
        SelectorPerturbationCaseV1::BudgetExactFit => {
            independent_problem(case, &[(5, 500_000), (5, 500_000)], 10)
        }
        SelectorPerturbationCaseV1::BudgetOneBelow => {
            independent_problem(case, &[(5, 500_000), (5, 500_000)], 9)
        }
        SelectorPerturbationCaseV1::DensityTrap => {
            independent_problem(case, &[(6, 600_000), (5, 500_000), (5, 500_000)], 10)
        }
        SelectorPerturbationCaseV1::EqualDensityTie => {
            independent_problem(case, &[(2, 400_000), (2, 400_000)], 2)
        }
        SelectorPerturbationCaseV1::ProviderTopTwo => provider_problem(case, 2, false),
        SelectorPerturbationCaseV1::ProviderThirdEndpointZero => provider_problem(case, 3, false),
        SelectorPerturbationCaseV1::ProviderMandatoryComplement => provider_problem(case, 3, true),
        SelectorPerturbationCaseV1::BreadthSliceBlocked => breadth_blocked_problem(case),
        SelectorPerturbationCaseV1::BreadthMixedAdmissionOrder => breadth_mixed_problem(case),
        SelectorPerturbationCaseV1::FixedOverheadTerminal => fixed_overhead_problem(case),
        SelectorPerturbationCaseV1::MandatoryOverBudgetTerminal => {
            mandatory_over_budget_problem(case)
        }
        SelectorPerturbationCaseV1::OracleCapTwelveExact => capacity_problem(case, 12),
        SelectorPerturbationCaseV1::OracleCapThirteenIneligible => capacity_problem(case, 13),
    }
}

fn independent_problem(
    case: SelectorPerturbationCaseV1,
    specifications: &[(u64, u32)],
    budget: u64,
) -> Result<SelectionProblemV1, SelectorPerturbationCorpusErrorV1> {
    let mut facets = Vec::new();
    let mut packets = Vec::new();
    for (index, (cost, affinity)) in specifications.iter().copied().enumerate() {
        let facet = fixture_facet(case, index, ProductionFacetKindV1::QueryTerm, 1)?;
        packets.push(fixture_packet(case, index, cost, [(facet.id(), affinity)])?);
        facets.push(facet);
    }
    fixture_problem(facets, packets, [], budget, 0)
}

fn provider_problem(
    case: SelectorPerturbationCaseV1,
    budget: u64,
    mandatory_baseline: bool,
) -> Result<SelectionProblemV1, SelectorPerturbationCorpusErrorV1> {
    let provider = fixture_facet(
        case,
        0,
        ProductionFacetKindV1::ProviderAttestedGraphRelation,
        evidentrail_select::PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1,
    )?;
    if mandatory_baseline {
        let identifier =
            fixture_facet(case, 1, ProductionFacetKindV1::ValidatedQueryIdentifier, 1)?;
        let forced = fixture_packet(
            case,
            0,
            2,
            [(identifier.id(), 1_000_000), (provider.id(), 1_000_000)],
        )?;
        let expensive = fixture_packet(case, 1, 2, [(provider.id(), 1_000_000)])?;
        let cheap = fixture_packet(case, 2, 1, [(provider.id(), 800_000)])?;
        let mandatory = MandatoryPacketV1::validated_identifier(forced.id(), identifier.id());
        fixture_problem(
            [identifier, provider],
            [forced, expensive, cheap],
            [mandatory],
            budget,
            0,
        )
    } else {
        let packets = [1_000_000, 800_000, 300_000]
            .into_iter()
            .enumerate()
            .map(|(index, affinity)| fixture_packet(case, index, 1, [(provider.id(), affinity)]))
            .collect::<Result<Vec<_>, _>>()?;
        fixture_problem([provider], packets, [], budget, 0)
    }
}

fn breadth_blocked_problem(
    case: SelectorPerturbationCaseV1,
) -> Result<SelectionProblemV1, SelectorPerturbationCorpusErrorV1> {
    let breadth = fixture_facet(case, 0, ProductionFacetKindV1::SourceCoverageStratum, 1)?;
    let packet = fixture_packet(case, 0, 2, [(breadth.id(), 1_000_000)])?;
    fixture_problem([breadth], [packet], [], 8, 0)
}

fn breadth_mixed_problem(
    case: SelectorPerturbationCaseV1,
) -> Result<SelectionProblemV1, SelectorPerturbationCorpusErrorV1> {
    let diagnostic = fixture_facet(case, 0, ProductionFacetKindV1::QueryTerm, 1)?;
    let breadth = fixture_facet(case, 1, ProductionFacetKindV1::SourceCoverageStratum, 1)?;
    let mixed = fixture_packet(
        case,
        0,
        2,
        [(diagnostic.id(), 500_000), (breadth.id(), 1_000_000)],
    )?;
    let saturator = fixture_packet(case, 1, 1, [(diagnostic.id(), 1_000_000)])?;
    fixture_problem([diagnostic, breadth], [mixed, saturator], [], 3, 0)
}

fn fixed_overhead_problem(
    case: SelectorPerturbationCaseV1,
) -> Result<SelectionProblemV1, SelectorPerturbationCorpusErrorV1> {
    let facet = fixture_facet(case, 0, ProductionFacetKindV1::QueryTerm, 1)?;
    let packet = fixture_packet(case, 0, 1, [(facet.id(), 1_000_000)])?;
    fixture_problem([facet], [packet], [], 0, 1)
}

fn mandatory_over_budget_problem(
    case: SelectorPerturbationCaseV1,
) -> Result<SelectionProblemV1, SelectorPerturbationCorpusErrorV1> {
    let identifier = fixture_facet(case, 0, ProductionFacetKindV1::ValidatedQueryIdentifier, 1)?;
    let packet = fixture_packet(case, 0, 2, [(identifier.id(), 1_000_000)])?;
    let mandatory = MandatoryPacketV1::validated_identifier(packet.id(), identifier.id());
    fixture_problem([identifier], [packet], [mandatory], 1, 0)
}

fn capacity_problem(
    case: SelectorPerturbationCaseV1,
    count: usize,
) -> Result<SelectionProblemV1, SelectorPerturbationCorpusErrorV1> {
    let mut facets = Vec::with_capacity(count);
    let mut packets = Vec::with_capacity(count);
    for index in 0..count {
        let facet = fixture_facet(case, index, ProductionFacetKindV1::QueryTerm, 1)?;
        packets.push(fixture_packet(case, index, 1, [(facet.id(), 1)])?);
        facets.push(facet);
    }
    fixture_problem(facets, packets, [], checked_u64(count)?, 0)
}

fn fixture_problem(
    facets: impl IntoIterator<Item = ProductionFacetV1>,
    packets: impl IntoIterator<Item = IntactPacketV1>,
    mandatory: impl IntoIterator<Item = MandatoryPacketV1>,
    total_budget: u64,
    fixed_overhead: u64,
) -> Result<SelectionProblemV1, SelectorPerturbationCorpusErrorV1> {
    SelectionProblemV1::new(
        facets,
        packets,
        mandatory,
        TotalTokenBudgetV1::new(total_budget)
            .map_err(|_| SelectorPerturbationCorpusErrorV1::FixtureInvariant)?,
        ReservedFixedOverheadV1::new(fixture_cost_model(), fixed_overhead)
            .map_err(|_| SelectorPerturbationCorpusErrorV1::FixtureInvariant)?,
    )
    .map_err(|_| SelectorPerturbationCorpusErrorV1::FixtureInvariant)
}

fn fixture_facet(
    case: SelectorPerturbationCaseV1,
    index: usize,
    kind: ProductionFacetKindV1,
    weight: u32,
) -> Result<ProductionFacetV1, SelectorPerturbationCorpusErrorV1> {
    let mut key = Vec::new();
    key.extend_from_slice(case.code().as_bytes());
    key.extend_from_slice(&checked_u64(index)?.to_le_bytes());
    ProductionFacetV1::new(
        kind,
        &key,
        FacetWeightV1::new(weight)
            .map_err(|_| SelectorPerturbationCorpusErrorV1::FixtureInvariant)?,
    )
    .map_err(|_| SelectorPerturbationCorpusErrorV1::FixtureInvariant)
}

fn fixture_packet<const N: usize>(
    case: SelectorPerturbationCaseV1,
    index: usize,
    cost: u64,
    affinities: [(evidentrail_select::FacetIdV1, u32); N],
) -> Result<IntactPacketV1, SelectorPerturbationCorpusErrorV1> {
    let seed = u64::try_from(case_index(case))
        .ok()
        .and_then(|case_index| case_index.checked_mul(100))
        .and_then(|base| base.checked_add(checked_u64(index).ok()?))
        .and_then(|value| value.checked_add(1))
        .ok_or(SelectorPerturbationCorpusErrorV1::ArithmeticOverflow)?;
    let affinities = affinities
        .into_iter()
        .map(|(facet_id, affinity)| {
            Ok(FacetAffinityV1::new(
                facet_id,
                AffinityV1::new(affinity)
                    .map_err(|_| SelectorPerturbationCorpusErrorV1::FixtureInvariant)?,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    IntactPacketV1::new(
        PacketIdV1::from_bytes(id_bytes(seed)),
        [EventId::from_bytes(id_bytes(seed + 10_000))],
        ComposablePacketCostV1::new(fixture_cost_model(), cost)
            .map_err(|_| SelectorPerturbationCorpusErrorV1::FixtureInvariant)?,
        affinities,
    )
    .map_err(|_| SelectorPerturbationCorpusErrorV1::FixtureInvariant)
}

fn fixture_cost_model() -> ComposableCostModelV1 {
    ComposableCostModelV1::new(ArtifactDigest::from_bytes([0x9d; 32]))
}

fn id_bytes(seed: u64) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_be_bytes());
    bytes
}

fn derive_case_digest(
    case: SelectorPerturbationCaseV1,
    problem_digest: ArtifactDigest,
    problem: &SelectionProblemV1,
    optional_packet_count: usize,
    outcome: &FrozenSelectorPerturbationOutcomeV1,
) -> Result<FrozenSelectorPerturbationCaseDigestV1, SelectorPerturbationCorpusErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, PUBLIC_CASE_DOMAIN_V1)?;
    update_field(&mut hasher, case.identity_digest().as_bytes())?;
    update_field(&mut hasher, problem_digest.as_bytes())?;
    update_u64(&mut hasher, checked_u64(optional_packet_count)?);
    update_u64(&mut hasher, problem.total_token_budget().tokens());
    update_u64(
        &mut hasher,
        problem.reserved_fixed_overhead().upper_bound_tokens(),
    );
    hash_outcome(&mut hasher, outcome)?;
    Ok(FrozenSelectorPerturbationCaseDigestV1(
        hasher.finalize().into(),
    ))
}

fn hash_outcome(
    hasher: &mut Sha256,
    outcome: &FrozenSelectorPerturbationOutcomeV1,
) -> Result<(), SelectorPerturbationCorpusErrorV1> {
    match outcome {
        FrozenSelectorPerturbationOutcomeV1::ExactEvaluated(evaluated) => {
            hasher.update([0]);
            update_field(
                hasher,
                selection_strategy_code(evaluated.production_strategy()),
            )?;
            update_u64(hasher, evaluated.production_objective_gain().numerator());
            update_u64(hasher, evaluated.production_selected_packet_cost());
            update_u64(hasher, evaluated.production_accounted_token_upper_bound());
            update_u64(hasher, evaluated.production_coverage_only_token_cost());
            update_u64(hasher, evaluated.production_coverage_only_token_limit());
            hash_packet_ids(hasher, evaluated.production_packet_ids())?;
            update_u64(hasher, evaluated.optimum().objective_gain().numerator());
            hash_packet_ids(hasher, evaluated.optimum().mandatory_packet_ids())?;
            hash_packet_ids(hasher, evaluated.optimum().optional_acceptance_order())?;
            hash_packet_ids(hasher, evaluated.optimum().selected_packet_ids())?;
            update_u64(hasher, evaluated.optimum().mandatory_packet_cost());
            update_u64(hasher, evaluated.optimum().optional_packet_cost());
            update_u64(hasher, evaluated.optimum().selected_packet_cost());
            update_u64(hasher, evaluated.optimum().accounted_token_upper_bound());
            update_u64(hasher, evaluated.optimum().coverage_only_token_cost());
            update_u64(hasher, evaluated.optimum().coverage_only_token_limit());
            update_u64(hasher, evaluated.optimum().reachable_subset_count());
            update_u64(hasher, evaluated.regret_numerator());
        }
        FrozenSelectorPerturbationOutcomeV1::ProductionNeedsMore(needs_more) => {
            hasher.update([1]);
            update_field(hasher, needs_more_reason_code(needs_more.reason()))?;
            update_u64(hasher, needs_more.total_token_budget());
            update_u64(hasher, needs_more.reserved_fixed_overhead());
            update_u64(hasher, needs_more.mandatory_packet_cost());
            update_u64(hasher, needs_more.mandatory_packet_count());
        }
        FrozenSelectorPerturbationOutcomeV1::OptionalPacketCapIneligible(ineligible) => {
            hasher.update([2]);
            update_u64(hasher, ineligible.optional_packet_count());
            update_u64(hasher, ineligible.optional_packet_cap());
        }
    }
    Ok(())
}

fn expected_matches(
    outcome: &FrozenSelectorPerturbationOutcomeV1,
    expected: SelectorPerturbationExpectedOutcomeV1,
) -> bool {
    match (outcome, expected) {
        (
            FrozenSelectorPerturbationOutcomeV1::ExactEvaluated(evaluated),
            SelectorPerturbationExpectedOutcomeV1::ExactRegret { numerator },
        ) => evaluated.regret_numerator() == numerator,
        (
            FrozenSelectorPerturbationOutcomeV1::ProductionNeedsMore(needs_more),
            SelectorPerturbationExpectedOutcomeV1::ProductionNeedsMore { reason },
        ) => needs_more.reason() == reason,
        (
            FrozenSelectorPerturbationOutcomeV1::OptionalPacketCapIneligible(ineligible),
            SelectorPerturbationExpectedOutcomeV1::OptionalPacketCapIneligible {
                packet_count,
                cap,
            },
        ) => {
            ineligible.optional_packet_count() == packet_count
                && ineligible.optional_packet_cap() == cap
        }
        _ => false,
    }
}

fn build_family_distribution(
    family: SelectorPerturbationFamilyV1,
    cases: &[GovernedSelectorPerturbationCaseV1; SYNTHETIC_SELECTOR_PERTURBATION_CASE_COUNT_V1],
) -> Result<SelectorPerturbationFamilyDistributionV1, SelectorPerturbationCorpusErrorV1> {
    let mut distribution = SelectorPerturbationFamilyDistributionV1 {
        family,
        case_count: 0,
        exact_zero_regret_count: 0,
        exact_positive_regret_count: 0,
        production_needs_more_count: 0,
        cap_ineligible_count: 0,
        conformance_mismatch_count: 0,
    };
    for case in cases
        .iter()
        .filter(|case| case.public_case.family() == family)
    {
        distribution.case_count = distribution
            .case_count
            .checked_add(1)
            .ok_or(SelectorPerturbationCorpusErrorV1::ArithmeticOverflow)?;
        match case.public_case.outcome() {
            FrozenSelectorPerturbationOutcomeV1::ExactEvaluated(evaluated)
                if evaluated.regret_numerator() == 0 =>
            {
                distribution.exact_zero_regret_count = distribution
                    .exact_zero_regret_count
                    .checked_add(1)
                    .ok_or(SelectorPerturbationCorpusErrorV1::ArithmeticOverflow)?;
            }
            FrozenSelectorPerturbationOutcomeV1::ExactEvaluated(_) => {
                distribution.exact_positive_regret_count = distribution
                    .exact_positive_regret_count
                    .checked_add(1)
                    .ok_or(SelectorPerturbationCorpusErrorV1::ArithmeticOverflow)?;
            }
            FrozenSelectorPerturbationOutcomeV1::ProductionNeedsMore(_) => {
                distribution.production_needs_more_count = distribution
                    .production_needs_more_count
                    .checked_add(1)
                    .ok_or(SelectorPerturbationCorpusErrorV1::ArithmeticOverflow)?;
            }
            FrozenSelectorPerturbationOutcomeV1::OptionalPacketCapIneligible(_) => {
                distribution.cap_ineligible_count = distribution
                    .cap_ineligible_count
                    .checked_add(1)
                    .ok_or(SelectorPerturbationCorpusErrorV1::ArithmeticOverflow)?;
            }
        }
        if !case.conforms {
            distribution.conformance_mismatch_count = distribution
                .conformance_mismatch_count
                .checked_add(1)
                .ok_or(SelectorPerturbationCorpusErrorV1::ArithmeticOverflow)?;
        }
    }
    Ok(distribution)
}

fn derive_governed_digest(
    public_corpus_digest: FrozenSelectorPerturbationCorpusDigestV1,
    cases: &[GovernedSelectorPerturbationCaseV1; SYNTHETIC_SELECTOR_PERTURBATION_CASE_COUNT_V1],
    distributions: &[SelectorPerturbationFamilyDistributionV1; 7],
) -> Result<ArtifactDigest, SelectorPerturbationCorpusErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, GOVERNED_REPORT_DOMAIN_V1)?;
    update_field(&mut hasher, public_corpus_digest.as_bytes())?;
    for case in cases {
        update_field(&mut hasher, case.public_case.digest().as_bytes())?;
        hash_expected(&mut hasher, case.expected)?;
        hasher.update([u8::from(case.conforms)]);
    }
    for distribution in distributions {
        update_field(&mut hasher, distribution.family.code().as_bytes())?;
        for value in [
            distribution.case_count,
            distribution.exact_zero_regret_count,
            distribution.exact_positive_regret_count,
            distribution.production_needs_more_count,
            distribution.cap_ineligible_count,
            distribution.conformance_mismatch_count,
        ] {
            update_u64(&mut hasher, value);
        }
    }
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

fn hash_expected(
    hasher: &mut Sha256,
    expected: SelectorPerturbationExpectedOutcomeV1,
) -> Result<(), SelectorPerturbationCorpusErrorV1> {
    match expected {
        SelectorPerturbationExpectedOutcomeV1::ExactRegret { numerator } => {
            hasher.update([0]);
            update_u64(hasher, numerator);
        }
        SelectorPerturbationExpectedOutcomeV1::ProductionNeedsMore { reason } => {
            hasher.update([1]);
            update_field(hasher, needs_more_reason_code(reason))?;
        }
        SelectorPerturbationExpectedOutcomeV1::OptionalPacketCapIneligible {
            packet_count,
            cap,
        } => {
            hasher.update([2]);
            update_u64(hasher, packet_count);
            update_u64(hasher, cap);
        }
    }
    Ok(())
}

fn hash_packet_ids(
    hasher: &mut Sha256,
    packet_ids: &[PacketIdV1],
) -> Result<(), SelectorPerturbationCorpusErrorV1> {
    update_u64(hasher, checked_u64(packet_ids.len())?);
    for packet_id in packet_ids {
        update_field(hasher, packet_id.as_bytes())?;
    }
    Ok(())
}

const fn needs_more_reason_code(reason: NeedsMoreReasonV1) -> &'static [u8] {
    match reason {
        NeedsMoreReasonV1::FixedOverheadExceedsTotalBudget => {
            b"fixed_overhead_exceeds_total_budget"
        }
        NeedsMoreReasonV1::MandatoryCostExceedsAvailablePacketBudget => {
            b"mandatory_cost_exceeds_available_packet_budget"
        }
    }
}

const fn selection_strategy_code(strategy: SelectionStrategyV1) -> &'static [u8] {
    match strategy {
        SelectionStrategyV1::MandatoryOnly => b"mandatory_only",
        SelectionStrategyV1::DensityGreedy => b"density_greedy",
        SelectionStrategyV1::BestSingle => b"best_single",
        SelectionStrategyV1::ExternalOrderBudgetPack => b"external_order_budget_pack",
    }
}

fn update_field(
    hasher: &mut Sha256,
    bytes: &[u8],
) -> Result<(), SelectorPerturbationCorpusErrorV1> {
    update_u64(hasher, checked_u64(bytes.len())?);
    hasher.update(bytes);
    Ok(())
}

fn update_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

fn update_u32(hasher: &mut Sha256, value: u32) {
    hasher.update(value.to_le_bytes());
}

fn checked_u64(value: usize) -> Result<u64, SelectorPerturbationCorpusErrorV1> {
    u64::try_from(value).map_err(|_| SelectorPerturbationCorpusErrorV1::DigestLengthOverflow)
}

const fn case_index(case: SelectorPerturbationCaseV1) -> usize {
    match case {
        SelectorPerturbationCaseV1::BudgetExactFit => 0,
        SelectorPerturbationCaseV1::BudgetOneBelow => 1,
        SelectorPerturbationCaseV1::DensityTrap => 2,
        SelectorPerturbationCaseV1::EqualDensityTie => 3,
        SelectorPerturbationCaseV1::ProviderTopTwo => 4,
        SelectorPerturbationCaseV1::ProviderThirdEndpointZero => 5,
        SelectorPerturbationCaseV1::ProviderMandatoryComplement => 6,
        SelectorPerturbationCaseV1::BreadthSliceBlocked => 7,
        SelectorPerturbationCaseV1::BreadthMixedAdmissionOrder => 8,
        SelectorPerturbationCaseV1::FixedOverheadTerminal => 9,
        SelectorPerturbationCaseV1::MandatoryOverBudgetTerminal => 10,
        SelectorPerturbationCaseV1::OracleCapTwelveExact => 11,
        SelectorPerturbationCaseV1::OracleCapThirteenIneligible => 12,
    }
}
