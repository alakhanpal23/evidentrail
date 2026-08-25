use std::collections::BTreeSet;
use std::fmt;

use evidentrail_compile::{
    PreparedThreeLaneAblationV1, ThreeLaneAblationMaskV1, ThreeLaneNeedsMoreV1,
    benchmark_selection_problem_for_prepared_three_lane_ablation_v1,
    proposal_candidate_config_digest_v1, proposal_compiler_config_digest_v1,
    three_lane_ablation_config_digest_v1,
};
use evidentrail_core::EventId;
use evidentrail_evidence::Utf8ByteTokenizerV1;
use evidentrail_schema::ArtifactDigest;
use evidentrail_select::{NeedsMoreReasonV1, ObjectiveGainV1, PacketIdV1, SelectionStrategyV1};
use sha2::{Digest as _, Sha256};

use crate::evaluator::{evaluate_requirements_v1, selected_targets_v1};
use crate::small_selection_oracle::{
    EXACT_SELECTION_ORACLE_POLICY_NAME_V1, EXACT_SELECTION_ORACLE_POLICY_VERSION_V1,
    ExactSmallSelectionRegretDecisionV1, MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1,
    evaluate_exact_small_selection_regret_v1,
};
use crate::three_lane_ablation_selection_corpus::{
    FrozenSyntheticThreeLaneSelectionDecisionV1, FrozenSyntheticThreeLaneSelectionOutcomeV1,
    GovernedSyntheticThreeLaneSelectionCaseInputV1, ThreeLaneSelectionCorpusErrorV1,
};
use crate::{
    FrozenPublicThreeLaneAblationBatchDigestV1, FrozenSyntheticThreeLaneSelectionCorpusDigestV1,
    GovernedRequirementRecallV1, ProducerProposalIdV1, SyntheticThreeLaneAblationCaseV1,
};

const FROZEN_FULL_ORACLE_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/frozen-synthetic-full-selection-oracle/v1\0";
const GOVERNED_FULL_ORACLE_REPORT_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/governed-synthetic-full-selection-oracle-report/v1\0";

/// Domain-separated identity for one pre-annotation exact Full-arm oracle.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrozenSyntheticFullSelectionOracleDigestV1([u8; 32]);

impl FrozenSyntheticFullSelectionOracleDigestV1 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for FrozenSyntheticFullSelectionOracleDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenSyntheticFullSelectionOracleDigestV1(<redacted>)")
    }
}

/// Exact bounded optimum and the production Greedy+Max result on the same
/// `SelectionProblemV1`. Every integer is an objective or certified cost fact;
/// this carries no approximation-factor or population claim.
#[derive(Clone, PartialEq, Eq)]
pub struct FrozenSyntheticFullSelectionOracleEvaluatedV1 {
    proposal_packet_count: u64,
    optional_packet_count: u64,
    production_strategy: SelectionStrategyV1,
    production_gain: ObjectiveGainV1,
    production_packet_ids: Vec<ProducerProposalIdV1>,
    production_selected_packet_cost: u64,
    production_accounted_token_upper_bound: u64,
    production_coverage_only_token_cost: u64,
    production_coverage_only_token_limit: u64,
    optimum_gain: ObjectiveGainV1,
    optimum_packet_ids: Vec<ProducerProposalIdV1>,
    optimum_mandatory_packet_ids: Vec<ProducerProposalIdV1>,
    optimum_optional_acceptance_order: Vec<ProducerProposalIdV1>,
    optimum_mandatory_packet_cost: u64,
    optimum_optional_packet_cost: u64,
    optimum_selected_packet_cost: u64,
    optimum_accounted_token_upper_bound: u64,
    optimum_coverage_only_token_cost: u64,
    optimum_coverage_only_token_limit: u64,
    reachable_subset_count: u64,
    regret_numerator: u64,
}

impl FrozenSyntheticFullSelectionOracleEvaluatedV1 {
    #[must_use]
    pub const fn proposal_packet_count(&self) -> u64 {
        self.proposal_packet_count
    }

    #[must_use]
    pub const fn optional_packet_count(&self) -> u64 {
        self.optional_packet_count
    }

    #[must_use]
    pub const fn production_strategy(&self) -> SelectionStrategyV1 {
        self.production_strategy
    }

    #[must_use]
    pub const fn production_gain(&self) -> ObjectiveGainV1 {
        self.production_gain
    }

    #[must_use]
    pub fn production_packet_ids(&self) -> &[ProducerProposalIdV1] {
        &self.production_packet_ids
    }

    #[must_use]
    pub const fn production_selected_packet_cost(&self) -> u64 {
        self.production_selected_packet_cost
    }

    #[must_use]
    pub const fn production_accounted_token_upper_bound(&self) -> u64 {
        self.production_accounted_token_upper_bound
    }

    #[must_use]
    pub const fn production_coverage_only_token_cost(&self) -> u64 {
        self.production_coverage_only_token_cost
    }

    #[must_use]
    pub const fn production_coverage_only_token_limit(&self) -> u64 {
        self.production_coverage_only_token_limit
    }

    #[must_use]
    pub const fn optimum_gain(&self) -> ObjectiveGainV1 {
        self.optimum_gain
    }

    #[must_use]
    pub fn optimum_packet_ids(&self) -> &[ProducerProposalIdV1] {
        &self.optimum_packet_ids
    }

    #[must_use]
    pub fn optimum_mandatory_packet_ids(&self) -> &[ProducerProposalIdV1] {
        &self.optimum_mandatory_packet_ids
    }

    #[must_use]
    pub fn optimum_optional_acceptance_order(&self) -> &[ProducerProposalIdV1] {
        &self.optimum_optional_acceptance_order
    }

    #[must_use]
    pub const fn optimum_mandatory_packet_cost(&self) -> u64 {
        self.optimum_mandatory_packet_cost
    }

    #[must_use]
    pub const fn optimum_optional_packet_cost(&self) -> u64 {
        self.optimum_optional_packet_cost
    }

    #[must_use]
    pub const fn optimum_selected_packet_cost(&self) -> u64 {
        self.optimum_selected_packet_cost
    }

    #[must_use]
    pub const fn optimum_accounted_token_upper_bound(&self) -> u64 {
        self.optimum_accounted_token_upper_bound
    }

    #[must_use]
    pub const fn optimum_coverage_only_token_cost(&self) -> u64 {
        self.optimum_coverage_only_token_cost
    }

    #[must_use]
    pub const fn optimum_coverage_only_token_limit(&self) -> u64 {
        self.optimum_coverage_only_token_limit
    }

    #[must_use]
    pub const fn reachable_subset_count(&self) -> u64 {
        self.reachable_subset_count
    }

    #[must_use]
    pub const fn regret_numerator(&self) -> u64 {
        self.regret_numerator
    }

    #[must_use]
    pub const fn claims_approximation_factor(&self) -> bool {
        false
    }
}

impl fmt::Debug for FrozenSyntheticFullSelectionOracleEvaluatedV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenSyntheticFullSelectionOracleEvaluatedV1")
            .field("proposal_packet_count", &self.proposal_packet_count)
            .field("optional_packet_count", &self.optional_packet_count)
            .field("production_strategy", &self.production_strategy)
            .field("production_gain", &self.production_gain)
            .field("production_packet_count", &self.production_packet_ids.len())
            .field(
                "production_selected_packet_cost",
                &self.production_selected_packet_cost,
            )
            .field("optimum_gain", &self.optimum_gain)
            .field("optimum_packet_count", &self.optimum_packet_ids.len())
            .field(
                "optimum_selected_packet_cost",
                &self.optimum_selected_packet_cost,
            )
            .field("reachable_subset_count", &self.reachable_subset_count)
            .field("regret_numerator", &self.regret_numerator)
            .field("claims_approximation_factor", &false)
            .finish()
    }
}

/// Honest production terminal state. `selection_reason` is present for the
/// two selector-level budget terminals and absent for compiler-level empty or
/// no-positive-fit terminals.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FrozenSyntheticFullSelectionOracleNeedsMoreV1 {
    compiler_reason: ThreeLaneNeedsMoreV1,
    selection_reason: Option<NeedsMoreReasonV1>,
    fixed_overhead_tokens: Option<u64>,
    mandatory_packet_cost: u64,
    mandatory_packet_count: u64,
    proposal_packet_count: u64,
    optional_packet_count: u64,
}

impl FrozenSyntheticFullSelectionOracleNeedsMoreV1 {
    #[must_use]
    pub const fn compiler_reason(self) -> ThreeLaneNeedsMoreV1 {
        self.compiler_reason
    }

    #[must_use]
    pub const fn selection_reason(self) -> Option<NeedsMoreReasonV1> {
        self.selection_reason
    }

    #[must_use]
    pub const fn fixed_overhead_tokens(self) -> Option<u64> {
        self.fixed_overhead_tokens
    }

    #[must_use]
    pub const fn mandatory_packet_cost(self) -> u64 {
        self.mandatory_packet_cost
    }

    #[must_use]
    pub const fn mandatory_packet_count(self) -> u64 {
        self.mandatory_packet_count
    }

    #[must_use]
    pub const fn proposal_packet_count(self) -> u64 {
        self.proposal_packet_count
    }

    #[must_use]
    pub const fn optional_packet_count(self) -> u64 {
        self.optional_packet_count
    }
}

impl fmt::Debug for FrozenSyntheticFullSelectionOracleNeedsMoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenSyntheticFullSelectionOracleNeedsMoreV1")
            .field("compiler_reason", &self.compiler_reason)
            .field("selection_reason", &self.selection_reason)
            .field("fixed_overhead_tokens", &self.fixed_overhead_tokens)
            .field("mandatory_packet_cost", &self.mandatory_packet_cost)
            .field("mandatory_packet_count", &self.mandatory_packet_count)
            .field("proposal_packet_count", &self.proposal_packet_count)
            .field("optional_packet_count", &self.optional_packet_count)
            .finish()
    }
}

/// Explicit bounded-oracle ineligibility; production selection remains frozen
/// in the ordinary Full outcome and is not reclassified as an oracle result.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FrozenSyntheticFullSelectionOracleIneligibleV1 {
    optional_packet_count: u64,
    optional_packet_cap: u64,
}

impl FrozenSyntheticFullSelectionOracleIneligibleV1 {
    #[must_use]
    pub const fn optional_packet_count(self) -> u64 {
        self.optional_packet_count
    }

    #[must_use]
    pub const fn optional_packet_cap(self) -> u64 {
        self.optional_packet_cap
    }
}

impl fmt::Debug for FrozenSyntheticFullSelectionOracleIneligibleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenSyntheticFullSelectionOracleIneligibleV1")
            .field("optional_packet_count", &self.optional_packet_count)
            .field("optional_packet_cap", &self.optional_packet_cap)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum FrozenSyntheticFullSelectionOracleDecisionV1 {
    ExactEvaluated(Box<FrozenSyntheticFullSelectionOracleEvaluatedV1>),
    ProductionNeedsMore(FrozenSyntheticFullSelectionOracleNeedsMoreV1),
    OptionalPacketCapIneligible(FrozenSyntheticFullSelectionOracleIneligibleV1),
}

impl FrozenSyntheticFullSelectionOracleDecisionV1 {
    #[must_use]
    pub const fn exact_evaluated(&self) -> Option<&FrozenSyntheticFullSelectionOracleEvaluatedV1> {
        match self {
            Self::ExactEvaluated(evaluated) => Some(evaluated),
            Self::ProductionNeedsMore(_) | Self::OptionalPacketCapIneligible(_) => None,
        }
    }

    #[must_use]
    pub const fn production_needs_more(
        &self,
    ) -> Option<FrozenSyntheticFullSelectionOracleNeedsMoreV1> {
        match self {
            Self::ProductionNeedsMore(needs_more) => Some(*needs_more),
            Self::ExactEvaluated(_) | Self::OptionalPacketCapIneligible(_) => None,
        }
    }

    #[must_use]
    pub const fn optional_packet_cap_ineligible(
        &self,
    ) -> Option<FrozenSyntheticFullSelectionOracleIneligibleV1> {
        match self {
            Self::OptionalPacketCapIneligible(ineligible) => Some(*ineligible),
            Self::ExactEvaluated(_) | Self::ProductionNeedsMore(_) => None,
        }
    }
}

impl fmt::Debug for FrozenSyntheticFullSelectionOracleDecisionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExactEvaluated(evaluated) => formatter
                .debug_tuple("FrozenSyntheticFullSelectionOracleDecisionV1::ExactEvaluated")
                .field(evaluated)
                .finish(),
            Self::ProductionNeedsMore(needs_more) => formatter
                .debug_tuple("FrozenSyntheticFullSelectionOracleDecisionV1::ProductionNeedsMore")
                .field(needs_more)
                .finish(),
            Self::OptionalPacketCapIneligible(ineligible) => formatter
                .debug_tuple(
                    "FrozenSyntheticFullSelectionOracleDecisionV1::OptionalPacketCapIneligible",
                )
                .field(ineligible)
                .finish(),
        }
    }
}

/// Label-free oracle artifact bound to one exact Full producer receipt,
/// configured compiler, public case/batch, production outcome, and budget.
#[derive(Clone, PartialEq, Eq)]
pub struct FrozenSyntheticFullSelectionOracleV1 {
    digest: FrozenSyntheticFullSelectionOracleDigestV1,
    case: SyntheticThreeLaneAblationCaseV1,
    source_public_batch_digest: FrozenPublicThreeLaneAblationBatchDigestV1,
    production_outcome_digest: crate::FrozenSyntheticThreeLaneSelectionOutcomeDigestV1,
    proposal_receipt_digest: ArtifactDigest,
    full_configuration_digest: ArtifactDigest,
    candidate_config_digest: ArtifactDigest,
    compiler_config_digest: ArtifactDigest,
    total_token_budget: u64,
    selection_problem_digest: Option<ArtifactDigest>,
    decision: FrozenSyntheticFullSelectionOracleDecisionV1,
}

impl FrozenSyntheticFullSelectionOracleV1 {
    #[must_use]
    pub const fn digest(&self) -> FrozenSyntheticFullSelectionOracleDigestV1 {
        self.digest
    }

    #[must_use]
    pub const fn case(&self) -> SyntheticThreeLaneAblationCaseV1 {
        self.case
    }

    #[must_use]
    pub const fn source_public_batch_digest(&self) -> FrozenPublicThreeLaneAblationBatchDigestV1 {
        self.source_public_batch_digest
    }

    #[must_use]
    pub const fn production_outcome_digest(
        &self,
    ) -> crate::FrozenSyntheticThreeLaneSelectionOutcomeDigestV1 {
        self.production_outcome_digest
    }

    #[must_use]
    pub const fn proposal_receipt_digest(&self) -> ArtifactDigest {
        self.proposal_receipt_digest
    }

    #[must_use]
    pub const fn full_configuration_digest(&self) -> ArtifactDigest {
        self.full_configuration_digest
    }

    #[must_use]
    pub const fn candidate_config_digest(&self) -> ArtifactDigest {
        self.candidate_config_digest
    }

    #[must_use]
    pub const fn compiler_config_digest(&self) -> ArtifactDigest {
        self.compiler_config_digest
    }

    #[must_use]
    pub const fn total_token_budget(&self) -> u64 {
        self.total_token_budget
    }

    #[must_use]
    pub const fn selection_problem_digest(&self) -> Option<ArtifactDigest> {
        self.selection_problem_digest
    }

    #[must_use]
    pub const fn decision(&self) -> &FrozenSyntheticFullSelectionOracleDecisionV1 {
        &self.decision
    }

    #[must_use]
    pub const fn contains_annotations(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn claims_approximation_factor(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn claims_population_quality(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn oracle_optional_packet_cap(&self) -> usize {
        MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1
    }

    #[must_use]
    pub const fn oracle_policy_version(&self) -> &'static [u8] {
        EXACT_SELECTION_ORACLE_POLICY_VERSION_V1
    }
}

impl fmt::Debug for FrozenSyntheticFullSelectionOracleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenSyntheticFullSelectionOracleV1")
            .field("oracle_identity_present", &true)
            .field("case", &self.case)
            .field("public_batch_binding_present", &true)
            .field("production_outcome_binding_present", &true)
            .field("producer_receipt_binding_present", &true)
            .field("configuration_binding_present", &true)
            .field(
                "selection_problem_binding_present",
                &self.selection_problem_digest.is_some(),
            )
            .field("total_token_budget", &self.total_token_budget)
            .field("decision", &self.decision)
            .field("contains_annotations", &false)
            .field("claims_approximation_factor", &false)
            .field("claims_population_quality", &false)
            .field(
                "oracle_optional_packet_cap",
                &MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1,
            )
            .finish()
    }
}

/// Post-annotation exact-recall projection for one already-frozen oracle case.
/// The oracle objective and packet universe are never regenerated here.
#[derive(Clone, PartialEq, Eq)]
pub struct GovernedSyntheticFullSelectionOracleCaseV1 {
    case: SyntheticThreeLaneAblationCaseV1,
    frozen_oracle: FrozenSyntheticFullSelectionOracleV1,
    production_required_event_recall: GovernedRequirementRecallV1,
    optimum_required_event_recall: Option<GovernedRequirementRecallV1>,
}

impl GovernedSyntheticFullSelectionOracleCaseV1 {
    #[must_use]
    pub const fn case(&self) -> SyntheticThreeLaneAblationCaseV1 {
        self.case
    }

    #[must_use]
    pub const fn frozen_oracle(&self) -> &FrozenSyntheticFullSelectionOracleV1 {
        &self.frozen_oracle
    }

    #[must_use]
    pub const fn production_required_event_recall(&self) -> GovernedRequirementRecallV1 {
        self.production_required_event_recall
    }

    #[must_use]
    pub const fn optimum_required_event_recall(&self) -> Option<GovernedRequirementRecallV1> {
        self.optimum_required_event_recall
    }
}

impl fmt::Debug for GovernedSyntheticFullSelectionOracleCaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedSyntheticFullSelectionOracleCaseV1")
            .field("case", &self.case)
            .field("frozen_oracle", &self.frozen_oracle)
            .field(
                "production_required_event_recall",
                &self.production_required_event_recall,
            )
            .field(
                "optimum_required_event_recall",
                &self.optimum_required_event_recall,
            )
            .finish()
    }
}

/// Six-case conformance report. Counts describe only this frozen synthetic
/// corpus and deliberately make no population, approximation, winner, or
/// statistical claim.
#[derive(Clone, PartialEq, Eq)]
pub struct GovernedSyntheticFullSelectionOracleReportV1 {
    digest: ArtifactDigest,
    public_selection_corpus_digest: FrozenSyntheticThreeLaneSelectionCorpusDigestV1,
    cases: [GovernedSyntheticFullSelectionOracleCaseV1; 6],
    exact_evaluated_count: u64,
    zero_regret_count: u64,
    nonzero_regret_count: u64,
    production_needs_more_count: u64,
    optional_packet_cap_ineligible_count: u64,
}

impl GovernedSyntheticFullSelectionOracleReportV1 {
    #[must_use]
    pub const fn digest(&self) -> ArtifactDigest {
        self.digest
    }

    #[must_use]
    pub const fn public_selection_corpus_digest(
        &self,
    ) -> FrozenSyntheticThreeLaneSelectionCorpusDigestV1 {
        self.public_selection_corpus_digest
    }

    #[must_use]
    pub fn cases(&self) -> &[GovernedSyntheticFullSelectionOracleCaseV1; 6] {
        &self.cases
    }

    #[must_use]
    pub fn case(
        &self,
        case: SyntheticThreeLaneAblationCaseV1,
    ) -> &GovernedSyntheticFullSelectionOracleCaseV1 {
        &self.cases[case_index(case)]
    }

    #[must_use]
    pub const fn exact_evaluated_count(&self) -> u64 {
        self.exact_evaluated_count
    }

    #[must_use]
    pub const fn zero_regret_count(&self) -> u64 {
        self.zero_regret_count
    }

    #[must_use]
    pub const fn nonzero_regret_count(&self) -> u64 {
        self.nonzero_regret_count
    }

    #[must_use]
    pub const fn production_needs_more_count(&self) -> u64 {
        self.production_needs_more_count
    }

    #[must_use]
    pub const fn optional_packet_cap_ineligible_count(&self) -> u64 {
        self.optional_packet_cap_ineligible_count
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
    pub const fn contains_scalar_composite(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn oracle_optional_packet_cap(&self) -> usize {
        MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1
    }

    #[must_use]
    pub const fn oracle_policy_version(&self) -> &'static [u8] {
        EXACT_SELECTION_ORACLE_POLICY_VERSION_V1
    }
}

impl fmt::Debug for GovernedSyntheticFullSelectionOracleReportV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedSyntheticFullSelectionOracleReportV1")
            .field("report_identity_present", &true)
            .field("public_selection_binding_present", &true)
            .field("case_count", &self.cases.len())
            .field("exact_evaluated_count", &self.exact_evaluated_count)
            .field("zero_regret_count", &self.zero_regret_count)
            .field("nonzero_regret_count", &self.nonzero_regret_count)
            .field(
                "production_needs_more_count",
                &self.production_needs_more_count,
            )
            .field(
                "optional_packet_cap_ineligible_count",
                &self.optional_packet_cap_ineligible_count,
            )
            .field("claims_population_quality", &false)
            .field("claims_approximation_factor", &false)
            .field("contains_scalar_composite", &false)
            .field(
                "oracle_optional_packet_cap",
                &MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1,
            )
            .finish()
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn freeze_synthetic_full_selection_oracle_v1(
    case: SyntheticThreeLaneAblationCaseV1,
    source_public_batch_digest: FrozenPublicThreeLaneAblationBatchDigestV1,
    ledger: &evidentrail_core::EventLedger,
    configured: &PreparedThreeLaneAblationV1,
    total_token_budget: evidentrail_select::TotalTokenBudgetV1,
    tokenizer: &Utf8ByteTokenizerV1,
    production_outcome: &FrozenSyntheticThreeLaneSelectionOutcomeV1,
) -> Result<FrozenSyntheticFullSelectionOracleV1, ThreeLaneSelectionCorpusErrorV1> {
    if configured.mask() != ThreeLaneAblationMaskV1::Full {
        return Err(ThreeLaneSelectionCorpusErrorV1::ExactOracleBindingMismatch);
    }
    let prepared = configured.prepared();
    let input_receipt = prepared.receipt().input();
    let proposal_receipt_digest = prepared.receipt().digest();
    if configured.config_digest()
        != three_lane_ablation_config_digest_v1(ThreeLaneAblationMaskV1::Full)
        || input_receipt.candidate_config_digest() != proposal_candidate_config_digest_v1()
        || input_receipt.compiler_config_digest() != proposal_compiler_config_digest_v1()
        || production_outcome.mask() != ThreeLaneAblationMaskV1::Full
        || production_outcome.budget() != total_token_budget
        || production_receipt_digest(production_outcome) != proposal_receipt_digest
    {
        return Err(ThreeLaneSelectionCorpusErrorV1::ExactOracleBindingMismatch);
    }

    let proposal_packet_count = checked_u64(prepared.proposal_packets().len())?;
    let mandatory_packet_count = checked_u64(prepared.mandatory().len())?;
    let mandatory_packet_cost = production_outcome.mandatory_packet_tokens();
    let mut selection_problem_digest = None;
    let decision = if prepared.proposal_packets().is_empty() {
        require_compiler_needs_more(production_outcome, ThreeLaneNeedsMoreV1::NoProposalPackets)?;
        FrozenSyntheticFullSelectionOracleDecisionV1::ProductionNeedsMore(
            FrozenSyntheticFullSelectionOracleNeedsMoreV1 {
                compiler_reason: ThreeLaneNeedsMoreV1::NoProposalPackets,
                selection_reason: None,
                fixed_overhead_tokens: production_outcome.fixed_overhead_tokens(),
                mandatory_packet_cost,
                mandatory_packet_count,
                proposal_packet_count,
                optional_packet_count: 0,
            },
        )
    } else {
        let problem = benchmark_selection_problem_for_prepared_three_lane_ablation_v1(
            ledger,
            configured,
            total_token_budget,
            tokenizer,
        )
        .map_err(ThreeLaneSelectionCorpusErrorV1::Compiler)?;
        selection_problem_digest = Some(
            crate::bounded_selector_challenger::derive_selection_problem_digest_v1(&problem)
                .map_err(|_| ThreeLaneSelectionCorpusErrorV1::ExactOracleBindingMismatch)?,
        );
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
        if let Some(ineligible) = optional_packet_cap_ineligibility(optional_packet_count)? {
            FrozenSyntheticFullSelectionOracleDecisionV1::OptionalPacketCapIneligible(ineligible)
        } else {
            match evaluate_exact_small_selection_regret_v1(&problem)
                .map_err(ThreeLaneSelectionCorpusErrorV1::ExactOracle)?
            {
                ExactSmallSelectionRegretDecisionV1::NeedsMore(needs_more) => {
                    let compiler_reason = compiler_reason(needs_more.reason());
                    require_compiler_needs_more(production_outcome, compiler_reason)?;
                    FrozenSyntheticFullSelectionOracleDecisionV1::ProductionNeedsMore(
                        FrozenSyntheticFullSelectionOracleNeedsMoreV1 {
                            compiler_reason,
                            selection_reason: Some(needs_more.reason()),
                            fixed_overhead_tokens: Some(needs_more.reserved_fixed_overhead()),
                            mandatory_packet_cost: needs_more.mandatory_packet_cost(),
                            mandatory_packet_count: needs_more.mandatory_packet_count(),
                            proposal_packet_count,
                            optional_packet_count: checked_u64(optional_packet_count)?,
                        },
                    )
                }
                ExactSmallSelectionRegretDecisionV1::Evaluated(regret)
                    if regret.production_packet_ids().is_empty() =>
                {
                    if regret.production_objective_gain().numerator() != 0
                        || regret.optimum().objective_gain().numerator() != 0
                    {
                        return Err(ThreeLaneSelectionCorpusErrorV1::ExactOracleDecisionMismatch);
                    }
                    require_compiler_needs_more(
                        production_outcome,
                        ThreeLaneNeedsMoreV1::NoSelectedPacketFits,
                    )?;
                    FrozenSyntheticFullSelectionOracleDecisionV1::ProductionNeedsMore(
                        FrozenSyntheticFullSelectionOracleNeedsMoreV1 {
                            compiler_reason: ThreeLaneNeedsMoreV1::NoSelectedPacketFits,
                            selection_reason: None,
                            fixed_overhead_tokens: production_outcome.fixed_overhead_tokens(),
                            mandatory_packet_cost,
                            mandatory_packet_count,
                            proposal_packet_count,
                            optional_packet_count: checked_u64(optional_packet_count)?,
                        },
                    )
                }
                ExactSmallSelectionRegretDecisionV1::Evaluated(regret) => {
                    verify_production_evaluated(production_outcome, &regret)?;
                    let optimum = regret.optimum();
                    FrozenSyntheticFullSelectionOracleDecisionV1::ExactEvaluated(Box::new(
                        FrozenSyntheticFullSelectionOracleEvaluatedV1 {
                            proposal_packet_count,
                            optional_packet_count: checked_u64(optional_packet_count)?,
                            production_strategy: regret.production_strategy(),
                            production_gain: regret.production_objective_gain(),
                            production_packet_ids: convert_packet_ids(
                                regret.production_packet_ids(),
                            ),
                            production_selected_packet_cost: regret
                                .production_selected_packet_cost(),
                            production_accounted_token_upper_bound: regret
                                .production_accounted_token_upper_bound(),
                            production_coverage_only_token_cost: regret
                                .production_coverage_only_token_cost(),
                            production_coverage_only_token_limit: regret
                                .production_coverage_only_token_limit(),
                            optimum_gain: optimum.objective_gain(),
                            optimum_packet_ids: convert_packet_ids(optimum.selected_packet_ids()),
                            optimum_mandatory_packet_ids: convert_packet_ids(
                                optimum.mandatory_packet_ids(),
                            ),
                            optimum_optional_acceptance_order: convert_packet_ids(
                                optimum.optional_acceptance_order(),
                            ),
                            optimum_mandatory_packet_cost: optimum.mandatory_packet_cost(),
                            optimum_optional_packet_cost: optimum.optional_packet_cost(),
                            optimum_selected_packet_cost: optimum.selected_packet_cost(),
                            optimum_accounted_token_upper_bound: optimum
                                .accounted_token_upper_bound(),
                            optimum_coverage_only_token_cost: optimum.coverage_only_token_cost(),
                            optimum_coverage_only_token_limit: optimum.coverage_only_token_limit(),
                            reachable_subset_count: optimum.reachable_subset_count(),
                            regret_numerator: regret.regret_numerator(),
                        },
                    ))
                }
            }
        }
    };

    let digest = derive_frozen_oracle_digest(
        case,
        source_public_batch_digest,
        production_outcome.digest(),
        proposal_receipt_digest,
        configured.config_digest(),
        input_receipt.candidate_config_digest(),
        input_receipt.compiler_config_digest(),
        total_token_budget.tokens(),
        selection_problem_digest,
        &decision,
    )?;
    Ok(FrozenSyntheticFullSelectionOracleV1 {
        digest,
        case,
        source_public_batch_digest,
        production_outcome_digest: production_outcome.digest(),
        proposal_receipt_digest,
        full_configuration_digest: configured.config_digest(),
        candidate_config_digest: input_receipt.candidate_config_digest(),
        compiler_config_digest: input_receipt.compiler_config_digest(),
        total_token_budget: total_token_budget.tokens(),
        selection_problem_digest,
        decision,
    })
}

pub(crate) fn build_governed_full_selection_oracle_report_v1(
    public_selection_corpus_digest: FrozenSyntheticThreeLaneSelectionCorpusDigestV1,
    public_cases: &[crate::FrozenSyntheticThreeLaneSelectionCaseV1; 6],
    inputs: &[GovernedSyntheticThreeLaneSelectionCaseInputV1<'_, '_>],
) -> Result<GovernedSyntheticFullSelectionOracleReportV1, ThreeLaneSelectionCorpusErrorV1> {
    if inputs.len() != public_cases.len() {
        return Err(ThreeLaneSelectionCorpusErrorV1::MissingCases {
            count: public_cases.len().saturating_sub(inputs.len()),
        });
    }
    let mut cases = Vec::with_capacity(public_cases.len());
    for (public_case, input) in public_cases.iter().zip(inputs) {
        if public_case.case() != input.oracle_case()
            || public_case.full_selection_oracle().case() != input.oracle_case()
            || public_case
                .full_selection_oracle()
                .source_public_batch_digest()
                != input.oracle_source_public_batch_digest()
        {
            return Err(ThreeLaneSelectionCorpusErrorV1::ExactOracleBindingMismatch);
        }
        let full_outcome = public_case.outcome(ThreeLaneAblationMaskV1::Full);
        let production_event_ids = full_outcome
            .decision()
            .selected_event_ids()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let production_targets = selected_targets_v1(None, &production_event_ids);
        let production_required_event_recall =
            evaluate_requirements_v1(input.oracle_annotation(), &production_targets)
                .map_err(ThreeLaneSelectionCorpusErrorV1::CaseEvaluation)?;
        let optimum_required_event_recall = public_case
            .full_selection_oracle()
            .decision()
            .exact_evaluated()
            .map(|evaluated| {
                let optimum_event_ids =
                    resolve_packet_events(full_outcome, evaluated.optimum_packet_ids())?;
                let optimum_targets = selected_targets_v1(None, &optimum_event_ids);
                evaluate_requirements_v1(input.oracle_annotation(), &optimum_targets)
                    .map_err(ThreeLaneSelectionCorpusErrorV1::CaseEvaluation)
            })
            .transpose()?;
        cases.push(GovernedSyntheticFullSelectionOracleCaseV1 {
            case: input.oracle_case(),
            frozen_oracle: public_case.full_selection_oracle().clone(),
            production_required_event_recall,
            optimum_required_event_recall,
        });
    }
    let cases: [GovernedSyntheticFullSelectionOracleCaseV1; 6] = cases
        .try_into()
        .map_err(|_| ThreeLaneSelectionCorpusErrorV1::MissingCases { count: 1 })?;
    let mut exact_evaluated_count = 0_u64;
    let mut zero_regret_count = 0_u64;
    let mut nonzero_regret_count = 0_u64;
    let mut production_needs_more_count = 0_u64;
    let mut optional_packet_cap_ineligible_count = 0_u64;
    for case in &cases {
        match case.frozen_oracle.decision() {
            FrozenSyntheticFullSelectionOracleDecisionV1::ExactEvaluated(evaluated) => {
                exact_evaluated_count = checked_add(exact_evaluated_count, 1)?;
                if evaluated.regret_numerator() == 0 {
                    zero_regret_count = checked_add(zero_regret_count, 1)?;
                } else {
                    nonzero_regret_count = checked_add(nonzero_regret_count, 1)?;
                }
            }
            FrozenSyntheticFullSelectionOracleDecisionV1::ProductionNeedsMore(_) => {
                production_needs_more_count = checked_add(production_needs_more_count, 1)?;
            }
            FrozenSyntheticFullSelectionOracleDecisionV1::OptionalPacketCapIneligible(_) => {
                optional_packet_cap_ineligible_count =
                    checked_add(optional_packet_cap_ineligible_count, 1)?;
            }
        }
    }
    let digest = derive_governed_report_digest(public_selection_corpus_digest, &cases)?;
    Ok(GovernedSyntheticFullSelectionOracleReportV1 {
        digest,
        public_selection_corpus_digest,
        cases,
        exact_evaluated_count,
        zero_regret_count,
        nonzero_regret_count,
        production_needs_more_count,
        optional_packet_cap_ineligible_count,
    })
}

fn verify_production_evaluated(
    production_outcome: &FrozenSyntheticThreeLaneSelectionOutcomeV1,
    regret: &crate::ExactSmallSelectionRegretV1,
) -> Result<(), ThreeLaneSelectionCorpusErrorV1> {
    let selected = production_outcome
        .decision()
        .selected()
        .ok_or(ThreeLaneSelectionCorpusErrorV1::ExactOracleDecisionMismatch)?;
    let production_packet_ids = convert_packet_ids(regret.production_packet_ids());
    let selected_cost = production_outcome
        .proposal_audits()
        .iter()
        .filter(|packet| packet.is_selected())
        .try_fold(0_u64, |sum, packet| {
            checked_add(sum, packet.token_cost_upper_bound())
        })?;
    let selected_gain = production_outcome
        .proposal_audits()
        .iter()
        .filter(|packet| packet.is_selected())
        .try_fold(0_u64, |sum, packet| {
            checked_add(sum, packet.selected_marginal_gain_numerator().unwrap_or(0))
        })?;
    let fixed_overhead = production_outcome
        .fixed_overhead_tokens()
        .ok_or(ThreeLaneSelectionCorpusErrorV1::ExactOracleDecisionMismatch)?;
    if selected.selected_packet_ids() != production_packet_ids
        || selected_cost != regret.production_selected_packet_cost()
        || selected_gain != regret.production_objective_gain().numerator()
        || selected.coverage_only_token_charge() != regret.production_coverage_only_token_cost()
        || selected.coverage_only_token_limit() != regret.production_coverage_only_token_limit()
        || fixed_overhead
            .checked_add(selected_cost)
            .ok_or(ThreeLaneSelectionCorpusErrorV1::ArithmeticOverflow)?
            != regret.production_accounted_token_upper_bound()
    {
        return Err(ThreeLaneSelectionCorpusErrorV1::ExactOracleDecisionMismatch);
    }
    Ok(())
}

fn require_compiler_needs_more(
    outcome: &FrozenSyntheticThreeLaneSelectionOutcomeV1,
    expected: ThreeLaneNeedsMoreV1,
) -> Result<(), ThreeLaneSelectionCorpusErrorV1> {
    if outcome
        .decision()
        .needs_more()
        .is_none_or(|needs_more| needs_more.reason() != expected)
    {
        return Err(ThreeLaneSelectionCorpusErrorV1::ExactOracleDecisionMismatch);
    }
    Ok(())
}

fn production_receipt_digest(
    outcome: &FrozenSyntheticThreeLaneSelectionOutcomeV1,
) -> ArtifactDigest {
    match outcome.decision() {
        FrozenSyntheticThreeLaneSelectionDecisionV1::Selected(selected) => {
            selected.proposal_receipt_digest()
        }
        FrozenSyntheticThreeLaneSelectionDecisionV1::NeedsMore(needs_more) => {
            needs_more.proposal_receipt_digest()
        }
    }
}

const fn compiler_reason(reason: NeedsMoreReasonV1) -> ThreeLaneNeedsMoreV1 {
    match reason {
        NeedsMoreReasonV1::FixedOverheadExceedsTotalBudget => {
            ThreeLaneNeedsMoreV1::FixedOverheadExceedsTotalBudget
        }
        NeedsMoreReasonV1::MandatoryCostExceedsAvailablePacketBudget => {
            ThreeLaneNeedsMoreV1::MandatoryCostExceedsAvailablePacketBudget
        }
    }
}

fn resolve_packet_events(
    outcome: &FrozenSyntheticThreeLaneSelectionOutcomeV1,
    packet_ids: &[ProducerProposalIdV1],
) -> Result<BTreeSet<EventId>, ThreeLaneSelectionCorpusErrorV1> {
    let mut events = BTreeSet::new();
    for packet_id in packet_ids {
        let packet = outcome
            .proposal_audits()
            .iter()
            .find(|packet| packet.packet_id() == *packet_id)
            .ok_or(ThreeLaneSelectionCorpusErrorV1::ExactOracleBindingMismatch)?;
        events.extend(packet.member_event_ids().iter().copied());
    }
    Ok(events)
}

fn convert_packet_ids(packet_ids: &[PacketIdV1]) -> Vec<ProducerProposalIdV1> {
    packet_ids
        .iter()
        .map(|packet_id| ProducerProposalIdV1::from_bytes(*packet_id.as_bytes()))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn derive_frozen_oracle_digest(
    case: SyntheticThreeLaneAblationCaseV1,
    source_public_batch_digest: FrozenPublicThreeLaneAblationBatchDigestV1,
    production_outcome_digest: crate::FrozenSyntheticThreeLaneSelectionOutcomeDigestV1,
    proposal_receipt_digest: ArtifactDigest,
    full_configuration_digest: ArtifactDigest,
    candidate_config_digest: ArtifactDigest,
    compiler_config_digest: ArtifactDigest,
    total_token_budget: u64,
    selection_problem_digest: Option<ArtifactDigest>,
    decision: &FrozenSyntheticFullSelectionOracleDecisionV1,
) -> Result<FrozenSyntheticFullSelectionOracleDigestV1, ThreeLaneSelectionCorpusErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, FROZEN_FULL_ORACLE_DOMAIN_V1)?;
    update_field(&mut hasher, EXACT_SELECTION_ORACLE_POLICY_NAME_V1)?;
    update_field(&mut hasher, EXACT_SELECTION_ORACLE_POLICY_VERSION_V1)?;
    update_u64(
        &mut hasher,
        checked_u64(MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1)?,
    );
    update_field(&mut hasher, case.identity_digest().as_bytes())?;
    update_field(&mut hasher, source_public_batch_digest.as_bytes())?;
    update_field(&mut hasher, production_outcome_digest.as_bytes())?;
    update_field(&mut hasher, proposal_receipt_digest.as_bytes())?;
    update_field(&mut hasher, full_configuration_digest.as_bytes())?;
    update_field(&mut hasher, candidate_config_digest.as_bytes())?;
    update_field(&mut hasher, compiler_config_digest.as_bytes())?;
    update_u64(&mut hasher, total_token_budget);
    match selection_problem_digest {
        Some(digest) => {
            hasher.update([1]);
            update_field(&mut hasher, digest.as_bytes())?;
        }
        None => hasher.update([0]),
    }
    hash_oracle_decision(&mut hasher, decision)?;
    Ok(FrozenSyntheticFullSelectionOracleDigestV1(
        hasher.finalize().into(),
    ))
}

fn hash_oracle_decision(
    hasher: &mut Sha256,
    decision: &FrozenSyntheticFullSelectionOracleDecisionV1,
) -> Result<(), ThreeLaneSelectionCorpusErrorV1> {
    match decision {
        FrozenSyntheticFullSelectionOracleDecisionV1::ExactEvaluated(evaluated) => {
            hasher.update([0]);
            update_u64(hasher, evaluated.proposal_packet_count());
            update_u64(hasher, evaluated.optional_packet_count());
            update_field(
                hasher,
                selection_strategy_code(evaluated.production_strategy()),
            )?;
            update_u64(hasher, evaluated.production_gain().numerator());
            hash_packet_ids(hasher, evaluated.production_packet_ids())?;
            update_u64(hasher, evaluated.production_selected_packet_cost());
            update_u64(hasher, evaluated.production_accounted_token_upper_bound());
            update_u64(hasher, evaluated.production_coverage_only_token_cost());
            update_u64(hasher, evaluated.production_coverage_only_token_limit());
            update_u64(hasher, evaluated.optimum_gain().numerator());
            hash_packet_ids(hasher, evaluated.optimum_packet_ids())?;
            hash_packet_ids(hasher, evaluated.optimum_mandatory_packet_ids())?;
            hash_packet_ids(hasher, evaluated.optimum_optional_acceptance_order())?;
            update_u64(hasher, evaluated.optimum_mandatory_packet_cost());
            update_u64(hasher, evaluated.optimum_optional_packet_cost());
            update_u64(hasher, evaluated.optimum_selected_packet_cost());
            update_u64(hasher, evaluated.optimum_accounted_token_upper_bound());
            update_u64(hasher, evaluated.optimum_coverage_only_token_cost());
            update_u64(hasher, evaluated.optimum_coverage_only_token_limit());
            update_u64(hasher, evaluated.reachable_subset_count());
            update_u64(hasher, evaluated.regret_numerator());
        }
        FrozenSyntheticFullSelectionOracleDecisionV1::ProductionNeedsMore(needs_more) => {
            hasher.update([1]);
            update_field(hasher, needs_more.compiler_reason().code().as_bytes())?;
            match needs_more.selection_reason() {
                Some(reason) => {
                    hasher.update([1]);
                    update_field(hasher, selection_reason_code(reason))?;
                }
                None => hasher.update([0]),
            }
            hash_optional_u64(hasher, needs_more.fixed_overhead_tokens());
            update_u64(hasher, needs_more.mandatory_packet_cost());
            update_u64(hasher, needs_more.mandatory_packet_count());
            update_u64(hasher, needs_more.proposal_packet_count());
            update_u64(hasher, needs_more.optional_packet_count());
        }
        FrozenSyntheticFullSelectionOracleDecisionV1::OptionalPacketCapIneligible(ineligible) => {
            hasher.update([2]);
            update_u64(hasher, ineligible.optional_packet_count());
            update_u64(hasher, ineligible.optional_packet_cap());
        }
    }
    Ok(())
}

fn derive_governed_report_digest(
    public_selection_corpus_digest: FrozenSyntheticThreeLaneSelectionCorpusDigestV1,
    cases: &[GovernedSyntheticFullSelectionOracleCaseV1; 6],
) -> Result<ArtifactDigest, ThreeLaneSelectionCorpusErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, GOVERNED_FULL_ORACLE_REPORT_DOMAIN_V1)?;
    update_field(&mut hasher, EXACT_SELECTION_ORACLE_POLICY_NAME_V1)?;
    update_field(&mut hasher, EXACT_SELECTION_ORACLE_POLICY_VERSION_V1)?;
    update_u64(
        &mut hasher,
        checked_u64(MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1)?,
    );
    update_field(&mut hasher, public_selection_corpus_digest.as_bytes())?;
    for case in cases {
        update_field(&mut hasher, case.case.identity_digest().as_bytes())?;
        update_field(&mut hasher, case.frozen_oracle.digest().as_bytes())?;
        hash_recall(&mut hasher, case.production_required_event_recall);
        match case.optimum_required_event_recall {
            Some(recall) => {
                hasher.update([1]);
                hash_recall(&mut hasher, recall);
            }
            None => hasher.update([0]),
        }
    }
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

fn hash_recall(hasher: &mut Sha256, recall: GovernedRequirementRecallV1) {
    update_u64(hasher, recall.requirement_count());
    update_u64(hasher, recall.satisfied_requirement_count());
    update_u64(hasher, recall.total_weight_micros());
    update_u64(hasher, recall.satisfied_weight_micros());
}

fn hash_packet_ids(
    hasher: &mut Sha256,
    packet_ids: &[ProducerProposalIdV1],
) -> Result<(), ThreeLaneSelectionCorpusErrorV1> {
    update_u64(hasher, checked_u64(packet_ids.len())?);
    for packet_id in packet_ids {
        update_field(hasher, packet_id.as_bytes())?;
    }
    Ok(())
}

fn selection_reason_code(reason: NeedsMoreReasonV1) -> &'static [u8] {
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
    }
}

fn update_field(hasher: &mut Sha256, bytes: &[u8]) -> Result<(), ThreeLaneSelectionCorpusErrorV1> {
    update_u64(hasher, checked_u64(bytes.len())?);
    hasher.update(bytes);
    Ok(())
}

fn update_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

fn hash_optional_u64(hasher: &mut Sha256, value: Option<u64>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            update_u64(hasher, value);
        }
        None => hasher.update([0]),
    }
}

fn checked_u64(value: usize) -> Result<u64, ThreeLaneSelectionCorpusErrorV1> {
    u64::try_from(value).map_err(|_| ThreeLaneSelectionCorpusErrorV1::DigestLengthOverflow)
}

fn checked_add(left: u64, right: u64) -> Result<u64, ThreeLaneSelectionCorpusErrorV1> {
    left.checked_add(right)
        .ok_or(ThreeLaneSelectionCorpusErrorV1::ArithmeticOverflow)
}

fn optional_packet_cap_ineligibility(
    optional_packet_count: usize,
) -> Result<Option<FrozenSyntheticFullSelectionOracleIneligibleV1>, ThreeLaneSelectionCorpusErrorV1>
{
    if optional_packet_count <= MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1 {
        return Ok(None);
    }
    Ok(Some(FrozenSyntheticFullSelectionOracleIneligibleV1 {
        optional_packet_count: checked_u64(optional_packet_count)?,
        optional_packet_cap: checked_u64(MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1)?,
    }))
}

const fn case_index(case: SyntheticThreeLaneAblationCaseV1) -> usize {
    match case {
        SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead => 0,
        SyntheticThreeLaneAblationCaseV1::FailureOnsetMiddle => 1,
        SyntheticThreeLaneAblationCaseV1::ProviderCorrelationNearTail => 2,
        SyntheticThreeLaneAblationCaseV1::MixedJointInterleaved => 3,
        SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors => 4,
        SyntheticThreeLaneAblationCaseV1::UnknownArbitraryStructuralBytes => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_twelve_is_eligible_and_thirteen_is_explicitly_ineligible() {
        assert!(optional_packet_cap_ineligibility(12).unwrap().is_none());
        let ineligible = optional_packet_cap_ineligibility(13).unwrap().unwrap();
        assert_eq!(ineligible.optional_packet_count(), 13);
        assert_eq!(ineligible.optional_packet_cap(), 12);
    }
}
