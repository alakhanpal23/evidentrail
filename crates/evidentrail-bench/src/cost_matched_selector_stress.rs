//! Evaluation-only, deterministic selector stress corpus above the bounded
//! subset-oracle cap.
//!
//! Every case freezes the production selection first. The challenger and the
//! structured exact DP are then restricted to no more than that production
//! plan's selected packet cost and no more than its actual coverage-only
//! charge. Hidden evidence requirements enter only in the governed join.
//! These synthetic conformance cases make no population, approximation,
//! latency, RSS, or production-promotion claim.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::{ArtifactDigest, EventId};
use evidentrail_select::{
    AffinityV1, ComposableCostModelV1, ComposablePacketCostV1, FacetAffinityV1, FacetWeightV1,
    IntactPacketV1, MandatoryPacketV1, PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1, PacketIdV1,
    ProductionFacetKindV1, ProductionFacetV1, ReservedFixedOverheadV1,
    SELECTION_OBJECTIVE_POLICY_NAME_V1, SELECTION_OBJECTIVE_POLICY_VERSION_V1, SelectionDecisionV1,
    SelectionProblemV1, TotalTokenBudgetV1,
};
use sha2::{Digest as _, Sha256};

use crate::bounded_selector_challenger::{
    CostMatchedBeamFactsV1, derive_selection_problem_digest_v1,
    evaluate_cost_matched_order_aware_beam_v1,
};
use crate::{
    BOUNDED_SELECTOR_CHALLENGER_BEAM_WIDTH_V1, BOUNDED_SELECTOR_CHALLENGER_MAX_DEPTH_V1,
    BOUNDED_SELECTOR_CHALLENGER_TRANSITION_CAP_V1, BoundedSelectorSearchBoundsV1,
    BoundedSelectorSearchObservationV1,
};

const PUBLIC_CORPUS_DOMAIN_V1: &[u8] = b"evidentrail/bench/cost-matched-selector-stress-corpus/v1\0";
const PUBLIC_CASE_DOMAIN_V1: &[u8] = b"evidentrail/bench/cost-matched-selector-stress-case/v1\0";
const PUBLIC_PLAN_DOMAIN_V1: &[u8] = b"evidentrail/bench/cost-matched-selector-stress-plan/v1\0";
const GOVERNED_CORPUS_DOMAIN_V1: &[u8] = b"evidentrail/bench/governed-cost-matched-selector-stress/v1\0";
pub const STRUCTURED_DP_POLICY_NAME_V1: &[u8] = b"evidentrail/bench/additive-dual-resource-exact-dp";
pub const STRUCTURED_DP_POLICY_VERSION_V1: &[u8] = b"1";

pub const COST_MATCHED_CHALLENGER_POLICY_NAME_V1: &[u8] =
    b"evidentrail/bench/cost-matched-order-aware-beam-production-fallback";
pub const COST_MATCHED_CHALLENGER_POLICY_VERSION_V1: &[u8] = b"1";

pub const COST_MATCHED_STRESS_CASE_COUNT_V1: usize = 8;
pub const COST_MATCHED_STRESS_MIN_OPTIONAL_PACKETS_V1: usize = 13;
pub const STRUCTURED_DP_MAX_OPTIONAL_PACKETS_V1: usize = 48;
pub const STRUCTURED_DP_STATE_SLOT_CAP_V1: u64 = 65_536;
pub const STRUCTURED_DP_TRANSITION_CAP_V1: u64 = 1_000_000;
pub const MAX_COST_MATCHED_STRESS_REQUIREMENTS_V1: usize = 8;
pub const MAX_COST_MATCHED_STRESS_ALTERNATIVES_V1: usize = 4;
pub const MAX_COST_MATCHED_STRESS_EVENTS_PER_ALTERNATIVE_V1: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CostMatchedStressFamilyV1 {
    PrimaryKnapsack,
    CoverageKnapsack,
    MixedDualResource,
    ProviderCardinality,
    MandatoryBaseline,
    NonAdditiveSaturation,
    ExactCapacity,
}

impl CostMatchedStressFamilyV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PrimaryKnapsack => "primary_knapsack_v1",
            Self::CoverageKnapsack => "coverage_knapsack_v1",
            Self::MixedDualResource => "mixed_dual_resource_v1",
            Self::ProviderCardinality => "provider_cardinality_v1",
            Self::MandatoryBaseline => "mandatory_baseline_v1",
            Self::NonAdditiveSaturation => "non_additive_saturation_v1",
            Self::ExactCapacity => "exact_capacity_v1",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CostMatchedStressCaseV1 {
    PrimaryDensityTrap15,
    PrimaryBalanced16,
    CoverageDensityTrap15,
    MixedDualResource16,
    ProviderPairs14,
    MandatoryBaseline14,
    ProviderThirdEndpoint15,
    ExactPacketCap65,
}

impl CostMatchedStressCaseV1 {
    pub const ALL: [Self; COST_MATCHED_STRESS_CASE_COUNT_V1] = [
        Self::PrimaryDensityTrap15,
        Self::PrimaryBalanced16,
        Self::CoverageDensityTrap15,
        Self::MixedDualResource16,
        Self::ProviderPairs14,
        Self::MandatoryBaseline14,
        Self::ProviderThirdEndpoint15,
        Self::ExactPacketCap65,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PrimaryDensityTrap15 => "primary_density_trap_15_v1",
            Self::PrimaryBalanced16 => "primary_balanced_16_v1",
            Self::CoverageDensityTrap15 => "coverage_density_trap_15_v1",
            Self::MixedDualResource16 => "mixed_dual_resource_16_v1",
            Self::ProviderPairs14 => "provider_pairs_14_v1",
            Self::MandatoryBaseline14 => "mandatory_baseline_14_v1",
            Self::ProviderThirdEndpoint15 => "provider_third_endpoint_15_v1",
            Self::ExactPacketCap65 => "exact_packet_cap_65_v1",
        }
    }

    #[must_use]
    pub const fn family(self) -> CostMatchedStressFamilyV1 {
        match self {
            Self::PrimaryDensityTrap15 | Self::PrimaryBalanced16 => {
                CostMatchedStressFamilyV1::PrimaryKnapsack
            }
            Self::CoverageDensityTrap15 => CostMatchedStressFamilyV1::CoverageKnapsack,
            Self::MixedDualResource16 => CostMatchedStressFamilyV1::MixedDualResource,
            Self::ProviderPairs14 => CostMatchedStressFamilyV1::ProviderCardinality,
            Self::MandatoryBaseline14 => CostMatchedStressFamilyV1::MandatoryBaseline,
            Self::ProviderThirdEndpoint15 => CostMatchedStressFamilyV1::NonAdditiveSaturation,
            Self::ExactPacketCap65 => CostMatchedStressFamilyV1::ExactCapacity,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrozenCostMatchedStressDigestV1([u8; 32]);

impl FrozenCostMatchedStressDigestV1 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for FrozenCostMatchedStressDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenCostMatchedStressDigestV1(<redacted>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CostMatchedResourceEnvelopeV1 {
    selected_packet_cost_cap: u64,
    coverage_only_token_cost_cap: u64,
    mandatory_packet_cost: u64,
    reserved_fixed_overhead: u64,
}

impl CostMatchedResourceEnvelopeV1 {
    #[must_use]
    pub const fn selected_packet_cost_cap(self) -> u64 {
        self.selected_packet_cost_cap
    }

    #[must_use]
    pub const fn coverage_only_token_cost_cap(self) -> u64 {
        self.coverage_only_token_cost_cap
    }

    #[must_use]
    pub const fn mandatory_packet_cost(self) -> u64 {
        self.mandatory_packet_cost
    }

    #[must_use]
    pub const fn reserved_fixed_overhead(self) -> u64 {
        self.reserved_fixed_overhead
    }
}

impl fmt::Debug for CostMatchedResourceEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CostMatchedResourceEnvelopeV1")
            .field("selected_packet_cost_cap", &self.selected_packet_cost_cap)
            .field(
                "coverage_only_token_cost_cap",
                &self.coverage_only_token_cost_cap,
            )
            .field("mandatory_packet_cost", &self.mandatory_packet_cost)
            .field("reserved_fixed_overhead", &self.reserved_fixed_overhead)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CostMatchedPlanSourceV1 {
    Production,
    OrderAwareBeam,
    ProductionFallback,
    StructuredExactDp,
}

#[derive(Clone, PartialEq, Eq)]
pub struct FrozenCostMatchedPlanV1 {
    digest: ArtifactDigest,
    source: CostMatchedPlanSourceV1,
    objective_gain_numerator: u64,
    selected_packet_ids: Vec<PacketIdV1>,
    selected_event_ids: Vec<EventId>,
    selected_packet_cost: u64,
    coverage_only_token_cost: u64,
}

impl FrozenCostMatchedPlanV1 {
    #[must_use]
    pub const fn digest(&self) -> ArtifactDigest {
        self.digest
    }

    #[must_use]
    pub const fn source(&self) -> CostMatchedPlanSourceV1 {
        self.source
    }

    #[must_use]
    pub const fn objective_gain_numerator(&self) -> u64 {
        self.objective_gain_numerator
    }

    #[must_use]
    pub fn selected_packet_ids(&self) -> &[PacketIdV1] {
        &self.selected_packet_ids
    }

    #[must_use]
    pub fn selected_event_ids(&self) -> &[EventId] {
        &self.selected_event_ids
    }

    #[must_use]
    pub const fn selected_packet_cost(&self) -> u64 {
        self.selected_packet_cost
    }

    #[must_use]
    pub const fn coverage_only_token_cost(&self) -> u64 {
        self.coverage_only_token_cost
    }
}

impl fmt::Debug for FrozenCostMatchedPlanV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenCostMatchedPlanV1")
            .field("plan_identity_present", &true)
            .field("source", &self.source)
            .field("objective_gain_numerator", &self.objective_gain_numerator)
            .field("selected_packet_count", &self.selected_packet_ids.len())
            .field("selected_event_count", &self.selected_event_ids.len())
            .field("selected_packet_cost", &self.selected_packet_cost)
            .field("coverage_only_token_cost", &self.coverage_only_token_cost)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StructuredDpIneligibleReasonV1 {
    OptionalPacketCap,
    NonAdditiveSaturation,
    StateSlotCap,
    TransitionCap,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StructuredDpWorkReceiptV1 {
    optional_packet_cap: u64,
    state_slot_cap: u64,
    transition_attempt_cap: u64,
    retained_state_high_water: u64,
    transition_attempts: u64,
}

impl StructuredDpWorkReceiptV1 {
    #[must_use]
    pub const fn optional_packet_cap(self) -> u64 {
        self.optional_packet_cap
    }

    #[must_use]
    pub const fn state_slot_cap(self) -> u64 {
        self.state_slot_cap
    }

    #[must_use]
    pub const fn transition_attempt_cap(self) -> u64 {
        self.transition_attempt_cap
    }

    #[must_use]
    pub const fn retained_state_high_water(self) -> u64 {
        self.retained_state_high_water
    }

    #[must_use]
    pub const fn transition_attempts(self) -> u64 {
        self.transition_attempts
    }
}

impl fmt::Debug for StructuredDpWorkReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StructuredDpWorkReceiptV1")
            .field("optional_packet_cap", &self.optional_packet_cap)
            .field("state_slot_cap", &self.state_slot_cap)
            .field("transition_attempt_cap", &self.transition_attempt_cap)
            .field("retained_state_high_water", &self.retained_state_high_water)
            .field("transition_attempts", &self.transition_attempts)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum StructuredDpOutcomeV1 {
    Exact {
        optimum: FrozenCostMatchedPlanV1,
        work: StructuredDpWorkReceiptV1,
    },
    Ineligible {
        reason: StructuredDpIneligibleReasonV1,
        work: StructuredDpWorkReceiptV1,
    },
}

impl StructuredDpOutcomeV1 {
    #[must_use]
    pub const fn optimum(&self) -> Option<&FrozenCostMatchedPlanV1> {
        match self {
            Self::Exact { optimum, .. } => Some(optimum),
            Self::Ineligible { .. } => None,
        }
    }

    #[must_use]
    pub const fn ineligible_reason(&self) -> Option<StructuredDpIneligibleReasonV1> {
        match self {
            Self::Ineligible { reason, .. } => Some(*reason),
            Self::Exact { .. } => None,
        }
    }

    #[must_use]
    pub const fn work(&self) -> StructuredDpWorkReceiptV1 {
        match self {
            Self::Exact { work, .. } | Self::Ineligible { work, .. } => *work,
        }
    }
}

impl fmt::Debug for StructuredDpOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact { optimum, work } => formatter
                .debug_struct("StructuredDpOutcomeV1::Exact")
                .field("optimum", optimum)
                .field("work", work)
                .finish(),
            Self::Ineligible { reason, work } => formatter
                .debug_struct("StructuredDpOutcomeV1::Ineligible")
                .field("reason", reason)
                .field("work", work)
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CostMatchedObjectiveRelationV1 {
    ChallengerBetter,
    Equal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CostMatchedCostRelationV1 {
    ChallengerLower,
    Equal,
}

#[derive(Clone, PartialEq, Eq)]
pub struct FrozenCostMatchedStressCaseV1 {
    digest: FrozenCostMatchedStressDigestV1,
    case: CostMatchedStressCaseV1,
    problem_digest: ArtifactDigest,
    optional_packet_count: u64,
    event_universe: Vec<EventId>,
    envelope: CostMatchedResourceEnvelopeV1,
    production: FrozenCostMatchedPlanV1,
    challenger: FrozenCostMatchedPlanV1,
    beam_bounds: BoundedSelectorSearchBoundsV1,
    beam_observation: BoundedSelectorSearchObservationV1,
    structured_dp: StructuredDpOutcomeV1,
    objective_relation: CostMatchedObjectiveRelationV1,
    selected_cost_relation: CostMatchedCostRelationV1,
    coverage_cost_relation: CostMatchedCostRelationV1,
}

impl FrozenCostMatchedStressCaseV1 {
    #[must_use]
    pub const fn digest(&self) -> FrozenCostMatchedStressDigestV1 {
        self.digest
    }

    #[must_use]
    pub const fn case(&self) -> CostMatchedStressCaseV1 {
        self.case
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
    pub const fn envelope(&self) -> CostMatchedResourceEnvelopeV1 {
        self.envelope
    }

    #[must_use]
    pub const fn production(&self) -> &FrozenCostMatchedPlanV1 {
        &self.production
    }

    #[must_use]
    pub const fn challenger(&self) -> &FrozenCostMatchedPlanV1 {
        &self.challenger
    }

    #[must_use]
    pub const fn beam_bounds(&self) -> BoundedSelectorSearchBoundsV1 {
        self.beam_bounds
    }

    #[must_use]
    pub const fn beam_observation(&self) -> BoundedSelectorSearchObservationV1 {
        self.beam_observation
    }

    #[must_use]
    pub const fn structured_dp(&self) -> &StructuredDpOutcomeV1 {
        &self.structured_dp
    }

    #[must_use]
    pub const fn objective_relation(&self) -> CostMatchedObjectiveRelationV1 {
        self.objective_relation
    }

    #[must_use]
    pub const fn selected_cost_relation(&self) -> CostMatchedCostRelationV1 {
        self.selected_cost_relation
    }

    #[must_use]
    pub const fn coverage_cost_relation(&self) -> CostMatchedCostRelationV1 {
        self.coverage_cost_relation
    }

    #[must_use]
    pub const fn deterministic_axes_weakly_dominate(&self) -> bool {
        true
    }
}

impl fmt::Debug for FrozenCostMatchedStressCaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenCostMatchedStressCaseV1")
            .field("case_identity_present", &true)
            .field("case", &self.case)
            .field("problem_identity_present", &true)
            .field("optional_packet_count", &self.optional_packet_count)
            .field("event_universe_count", &self.event_universe.len())
            .field("envelope", &self.envelope)
            .field("production", &self.production)
            .field("challenger", &self.challenger)
            .field("beam_bounds", &self.beam_bounds)
            .field("beam_observation", &self.beam_observation)
            .field("structured_dp", &self.structured_dp)
            .field("objective_relation", &self.objective_relation)
            .field("selected_cost_relation", &self.selected_cost_relation)
            .field("coverage_cost_relation", &self.coverage_cost_relation)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct FrozenCostMatchedStressCorpusV1 {
    digest: FrozenCostMatchedStressDigestV1,
    cases: [FrozenCostMatchedStressCaseV1; COST_MATCHED_STRESS_CASE_COUNT_V1],
    challenger_better_count: u64,
    exact_dp_count: u64,
    ineligible_count: u64,
}

impl FrozenCostMatchedStressCorpusV1 {
    #[must_use]
    pub const fn digest(&self) -> FrozenCostMatchedStressDigestV1 {
        self.digest
    }

    #[must_use]
    pub fn cases(&self) -> &[FrozenCostMatchedStressCaseV1] {
        &self.cases
    }

    #[must_use]
    pub fn case(&self, case: CostMatchedStressCaseV1) -> &FrozenCostMatchedStressCaseV1 {
        self.cases
            .iter()
            .find(|entry| entry.case == case)
            .expect("closed corpus contains every case")
    }

    #[must_use]
    pub const fn challenger_better_count(&self) -> u64 {
        self.challenger_better_count
    }

    #[must_use]
    pub const fn exact_dp_count(&self) -> u64 {
        self.exact_dp_count
    }

    #[must_use]
    pub const fn ineligible_count(&self) -> u64 {
        self.ineligible_count
    }

    #[must_use]
    pub const fn contains_annotations(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn claims_population_quality(&self) -> bool {
        false
    }
}

impl fmt::Debug for FrozenCostMatchedStressCorpusV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenCostMatchedStressCorpusV1")
            .field("corpus_identity_present", &true)
            .field("case_count", &self.cases.len())
            .field("challenger_better_count", &self.challenger_better_count)
            .field("exact_dp_count", &self.exact_dp_count)
            .field("ineligible_count", &self.ineligible_count)
            .field("contains_annotations", &false)
            .field("claims_population_quality", &false)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CostMatchedStressErrorV1 {
    FixtureInvariant,
    ProductionSelection,
    ProductionTerminal,
    BeamEvaluation,
    ObjectiveContract,
    ResourceEnvelopeViolation,
    ArithmeticOverflow,
    DigestLengthOverflow,
    CaseSetMismatch,
    CaseBindingMismatch,
    RequirementBounds,
    RequirementUnknownEvent,
    RequirementDuplicate,
}

impl CostMatchedStressErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::FixtureInvariant => "EVIDENTRAIL_BENCH_COST_MATCHED_FIXTURE",
            Self::ProductionSelection => "EVIDENTRAIL_BENCH_COST_MATCHED_PRODUCTION",
            Self::ProductionTerminal => "EVIDENTRAIL_BENCH_COST_MATCHED_PRODUCTION_TERMINAL",
            Self::BeamEvaluation => "EVIDENTRAIL_BENCH_COST_MATCHED_BEAM",
            Self::ObjectiveContract => "EVIDENTRAIL_BENCH_COST_MATCHED_OBJECTIVE",
            Self::ResourceEnvelopeViolation => "EVIDENTRAIL_BENCH_COST_MATCHED_ENVELOPE",
            Self::ArithmeticOverflow => "EVIDENTRAIL_BENCH_COST_MATCHED_ARITHMETIC",
            Self::DigestLengthOverflow => "EVIDENTRAIL_BENCH_COST_MATCHED_DIGEST_LENGTH",
            Self::CaseSetMismatch => "EVIDENTRAIL_BENCH_COST_MATCHED_CASE_SET",
            Self::CaseBindingMismatch => "EVIDENTRAIL_BENCH_COST_MATCHED_CASE_BINDING",
            Self::RequirementBounds => "EVIDENTRAIL_BENCH_COST_MATCHED_REQUIREMENT_BOUNDS",
            Self::RequirementUnknownEvent => "EVIDENTRAIL_BENCH_COST_MATCHED_REQUIREMENT_EVENT",
            Self::RequirementDuplicate => "EVIDENTRAIL_BENCH_COST_MATCHED_REQUIREMENT_DUPLICATE",
        }
    }
}

impl fmt::Debug for CostMatchedStressErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CostMatchedStressErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for CostMatchedStressErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for CostMatchedStressErrorV1 {}

#[derive(Clone)]
struct DpItemV1 {
    packet_id: PacketIdV1,
    cost: u64,
    gain: u64,
    coverage_only: bool,
}

#[derive(Clone)]
struct DpStateV1 {
    gain: u64,
    selected_item_indices: Vec<usize>,
}

fn structured_dp_work(
    retained_state_high_water: u64,
    transition_attempts: u64,
) -> Result<StructuredDpWorkReceiptV1, CostMatchedStressErrorV1> {
    Ok(StructuredDpWorkReceiptV1 {
        optional_packet_cap: checked_u64(STRUCTURED_DP_MAX_OPTIONAL_PACKETS_V1)?,
        state_slot_cap: STRUCTURED_DP_STATE_SLOT_CAP_V1,
        transition_attempt_cap: STRUCTURED_DP_TRANSITION_CAP_V1,
        retained_state_high_water,
        transition_attempts,
    })
}

fn structured_dp_ineligible(
    reason: StructuredDpIneligibleReasonV1,
    retained_state_high_water: u64,
    transition_attempts: u64,
) -> Result<StructuredDpOutcomeV1, CostMatchedStressErrorV1> {
    Ok(StructuredDpOutcomeV1::Ineligible {
        reason,
        work: structured_dp_work(retained_state_high_water, transition_attempts)?,
    })
}

fn evaluate_structured_exact_dp_v1(
    problem: &SelectionProblemV1,
    envelope: CostMatchedResourceEnvelopeV1,
) -> Result<StructuredDpOutcomeV1, CostMatchedStressErrorV1> {
    let mandatory_ids = problem
        .mandatory()
        .iter()
        .map(|entry| entry.packet_id())
        .collect::<BTreeSet<_>>();
    let optional_packets = problem
        .packets()
        .iter()
        .enumerate()
        .filter(|(_, packet)| !mandatory_ids.contains(&packet.id()))
        .collect::<Vec<_>>();
    if optional_packets.len() > STRUCTURED_DP_MAX_OPTIONAL_PACKETS_V1 {
        return structured_dp_ineligible(StructuredDpIneligibleReasonV1::OptionalPacketCap, 0, 0);
    }

    // The exact DP is admitted only when saturation cannot couple optional
    // decisions. Counting every positive packet affinity (including the fixed
    // mandatory baseline) against the closed facet cardinality is a simple,
    // independently checkable sufficient condition for additivity.
    for facet in problem.facets() {
        let positive_packet_count = problem
            .packets()
            .iter()
            .filter(|packet| {
                packet
                    .affinities()
                    .iter()
                    .any(|affinity| affinity.facet_id() == facet.id())
            })
            .count();
        if positive_packet_count > usize::from(facet.kind().saturation_cardinality().count()) {
            return structured_dp_ineligible(
                StructuredDpIneligibleReasonV1::NonAdditiveSaturation,
                0,
                0,
            );
        }
    }

    let facet_by_id = problem
        .facets()
        .iter()
        .map(|facet| (facet.id(), facet))
        .collect::<BTreeMap<_, _>>();
    let mut items = Vec::with_capacity(optional_packets.len());
    let mut additive_gain = 0_u64;
    for (_, packet) in optional_packets {
        let gain = problem
            .normalized_gain([packet.id()])
            .map_err(|_| CostMatchedStressErrorV1::ObjectiveContract)?
            .numerator();
        additive_gain = additive_gain
            .checked_add(gain)
            .ok_or(CostMatchedStressErrorV1::ArithmeticOverflow)?;
        let has_primary_affinity = packet.affinities().iter().any(|affinity| {
            facet_by_id
                .get(&affinity.facet_id())
                .is_some_and(|facet| !facet.kind().is_coverage_only())
        });
        items.push(DpItemV1 {
            packet_id: packet.id(),
            cost: packet.composable_token_upper_bound().upper_bound_tokens(),
            gain,
            coverage_only: gain > 0 && !has_primary_affinity,
        });
    }
    let all_gain = problem
        .normalized_gain(items.iter().map(|item| item.packet_id))
        .map_err(|_| CostMatchedStressErrorV1::ObjectiveContract)?
        .numerator();
    if additive_gain != all_gain {
        return structured_dp_ineligible(
            StructuredDpIneligibleReasonV1::NonAdditiveSaturation,
            0,
            0,
        );
    }

    let optional_cost_cap = envelope
        .selected_packet_cost_cap
        .checked_sub(envelope.mandatory_packet_cost)
        .ok_or(CostMatchedStressErrorV1::ResourceEnvelopeViolation)?;
    let mut states = BTreeMap::new();
    states.insert(
        (0_u64, 0_u64),
        DpStateV1 {
            gain: 0,
            selected_item_indices: Vec::new(),
        },
    );
    let mut retained_state_high_water = 1_u64;
    let mut transition_attempts = 0_u64;
    for (item_index, item) in items.iter().enumerate() {
        let snapshot = states
            .iter()
            .map(|(key, state)| (*key, state.clone()))
            .collect::<Vec<_>>();
        for ((cost, coverage_cost), state) in snapshot {
            if transition_attempts == STRUCTURED_DP_TRANSITION_CAP_V1 {
                return structured_dp_ineligible(
                    StructuredDpIneligibleReasonV1::TransitionCap,
                    retained_state_high_water,
                    transition_attempts,
                );
            }
            transition_attempts = transition_attempts
                .checked_add(1)
                .ok_or(CostMatchedStressErrorV1::ArithmeticOverflow)?;
            let next_cost = cost
                .checked_add(item.cost)
                .ok_or(CostMatchedStressErrorV1::ArithmeticOverflow)?;
            if next_cost > optional_cost_cap {
                continue;
            }
            let next_coverage_cost = if item.coverage_only {
                coverage_cost
                    .checked_add(item.cost)
                    .ok_or(CostMatchedStressErrorV1::ArithmeticOverflow)?
            } else {
                coverage_cost
            };
            if next_coverage_cost > envelope.coverage_only_token_cost_cap {
                continue;
            }
            let mut candidate = state.clone();
            candidate.gain = candidate
                .gain
                .checked_add(item.gain)
                .ok_or(CostMatchedStressErrorV1::ArithmeticOverflow)?;
            candidate.selected_item_indices.push(item_index);
            let key = (next_cost, next_coverage_cost);
            let replaces = states
                .get(&key)
                .is_none_or(|current| dp_same_resource_state_is_better(&candidate, current));
            if replaces {
                if !states.contains_key(&key)
                    && checked_u64(states.len())? == STRUCTURED_DP_STATE_SLOT_CAP_V1
                {
                    return structured_dp_ineligible(
                        StructuredDpIneligibleReasonV1::StateSlotCap,
                        retained_state_high_water,
                        transition_attempts,
                    );
                }
                states.insert(key, candidate);
                retained_state_high_water =
                    retained_state_high_water.max(checked_u64(states.len())?);
            }
        }
    }

    let ((optional_cost, coverage_cost), best) = states
        .iter()
        .min_by(dp_final_state_ordering)
        .ok_or(CostMatchedStressErrorV1::ObjectiveContract)?;
    let optional_packet_ids = best
        .selected_item_indices
        .iter()
        .map(|index| items[*index].packet_id)
        .collect::<Vec<_>>();
    let verified_gain = problem
        .normalized_gain(optional_packet_ids.iter().copied())
        .map_err(|_| CostMatchedStressErrorV1::ObjectiveContract)?;
    if verified_gain.numerator() != best.gain {
        return Err(CostMatchedStressErrorV1::ObjectiveContract);
    }
    let mut selected_packet_ids = problem
        .mandatory()
        .iter()
        .map(|entry| entry.packet_id())
        .collect::<Vec<_>>();
    selected_packet_ids.extend(optional_packet_ids);
    let selected_packet_cost = problem
        .mandatory_cost()
        .checked_add(*optional_cost)
        .ok_or(CostMatchedStressErrorV1::ArithmeticOverflow)?;
    let optimum = freeze_plan(
        problem,
        CostMatchedPlanSourceV1::StructuredExactDp,
        best.gain,
        selected_packet_ids,
        selected_packet_cost,
        *coverage_cost,
    )?;
    Ok(StructuredDpOutcomeV1::Exact {
        optimum,
        work: structured_dp_work(retained_state_high_water, transition_attempts)?,
    })
}

fn dp_same_resource_state_is_better(candidate: &DpStateV1, current: &DpStateV1) -> bool {
    candidate
        .gain
        .cmp(&current.gain)
        .then_with(|| {
            current
                .selected_item_indices
                .len()
                .cmp(&candidate.selected_item_indices.len())
        })
        .then_with(|| {
            current
                .selected_item_indices
                .cmp(&candidate.selected_item_indices)
        })
        == Ordering::Greater
}

fn dp_final_state_ordering(
    left: &(&(u64, u64), &DpStateV1),
    right: &(&(u64, u64), &DpStateV1),
) -> Ordering {
    right
        .1
        .gain
        .cmp(&left.1.gain)
        .then_with(|| left.0.0.cmp(&right.0.0))
        .then_with(|| left.0.1.cmp(&right.0.1))
        .then_with(|| {
            left.1
                .selected_item_indices
                .len()
                .cmp(&right.1.selected_item_indices.len())
        })
        .then_with(|| {
            left.1
                .selected_item_indices
                .cmp(&right.1.selected_item_indices)
        })
}

/// Freeze every public problem, production decision, cost-matched challenger,
/// beam work receipt, and structured-DP decision without accepting hidden
/// requirements.
pub fn freeze_cost_matched_selector_stress_corpus_v1()
-> Result<FrozenCostMatchedStressCorpusV1, CostMatchedStressErrorV1> {
    let mut cases = Vec::with_capacity(COST_MATCHED_STRESS_CASE_COUNT_V1);
    for case in CostMatchedStressCaseV1::ALL {
        cases.push(freeze_case(case, false)?);
    }
    let cases: [FrozenCostMatchedStressCaseV1; COST_MATCHED_STRESS_CASE_COUNT_V1] = cases
        .try_into()
        .map_err(|_| CostMatchedStressErrorV1::CaseSetMismatch)?;
    let challenger_better_count = checked_u64(
        cases
            .iter()
            .filter(|case| {
                case.objective_relation == CostMatchedObjectiveRelationV1::ChallengerBetter
            })
            .count(),
    )?;
    let exact_dp_count = checked_u64(
        cases
            .iter()
            .filter(|case| matches!(case.structured_dp, StructuredDpOutcomeV1::Exact { .. }))
            .count(),
    )?;
    let ineligible_count = checked_u64(cases.len())?
        .checked_sub(exact_dp_count)
        .ok_or(CostMatchedStressErrorV1::ArithmeticOverflow)?;
    let mut hasher = Sha256::new();
    update_field(&mut hasher, PUBLIC_CORPUS_DOMAIN_V1)?;
    update_field(&mut hasher, SELECTION_OBJECTIVE_POLICY_NAME_V1)?;
    update_field(&mut hasher, SELECTION_OBJECTIVE_POLICY_VERSION_V1)?;
    update_field(&mut hasher, STRUCTURED_DP_POLICY_NAME_V1)?;
    update_field(&mut hasher, STRUCTURED_DP_POLICY_VERSION_V1)?;
    update_field(&mut hasher, COST_MATCHED_CHALLENGER_POLICY_NAME_V1)?;
    update_field(&mut hasher, COST_MATCHED_CHALLENGER_POLICY_VERSION_V1)?;
    update_u64(
        &mut hasher,
        checked_u64(BOUNDED_SELECTOR_CHALLENGER_BEAM_WIDTH_V1)?,
    );
    update_u64(
        &mut hasher,
        checked_u64(BOUNDED_SELECTOR_CHALLENGER_MAX_DEPTH_V1)?,
    );
    update_u64(&mut hasher, BOUNDED_SELECTOR_CHALLENGER_TRANSITION_CAP_V1);
    update_u64(&mut hasher, checked_u64(cases.len())?);
    for case in &cases {
        update_field(&mut hasher, case.digest.as_bytes())?;
    }
    update_u64(&mut hasher, challenger_better_count);
    update_u64(&mut hasher, exact_dp_count);
    update_u64(&mut hasher, ineligible_count);
    Ok(FrozenCostMatchedStressCorpusV1 {
        digest: FrozenCostMatchedStressDigestV1(hasher.finalize().into()),
        cases,
        challenger_better_count,
        exact_dp_count,
        ineligible_count,
    })
}

fn freeze_case(
    case: CostMatchedStressCaseV1,
    reverse_fixture_input: bool,
) -> Result<FrozenCostMatchedStressCaseV1, CostMatchedStressErrorV1> {
    let problem = build_stress_problem(case, reverse_fixture_input)?;
    let optional_packet_count = problem
        .packets()
        .len()
        .checked_sub(problem.mandatory().len())
        .ok_or(CostMatchedStressErrorV1::FixtureInvariant)?;
    if optional_packet_count < COST_MATCHED_STRESS_MIN_OPTIONAL_PACKETS_V1 {
        return Err(CostMatchedStressErrorV1::FixtureInvariant);
    }
    let decision = problem
        .select()
        .map_err(|_| CostMatchedStressErrorV1::ProductionSelection)?;
    let selection = match decision {
        SelectionDecisionV1::Selected(selection) => selection,
        SelectionDecisionV1::NeedsMore(_) => {
            return Err(CostMatchedStressErrorV1::ProductionTerminal);
        }
    };
    let production_packet_ids = selection
        .packets()
        .iter()
        .map(|packet| packet.packet().id())
        .collect::<Vec<_>>();
    let production = freeze_plan(
        &problem,
        CostMatchedPlanSourceV1::Production,
        selection.normalized_gain().numerator(),
        production_packet_ids,
        selection.selected_packet_cost(),
        selection.coverage_only_token_cost(),
    )?;
    let envelope = CostMatchedResourceEnvelopeV1 {
        selected_packet_cost_cap: production.selected_packet_cost,
        coverage_only_token_cost_cap: production.coverage_only_token_cost,
        mandatory_packet_cost: problem.mandatory_cost(),
        reserved_fixed_overhead: problem.reserved_fixed_overhead().upper_bound_tokens(),
    };
    let beam = evaluate_cost_matched_order_aware_beam_v1(
        &problem,
        envelope.selected_packet_cost_cap,
        envelope.coverage_only_token_cost_cap,
    )
    .map_err(|_| CostMatchedStressErrorV1::BeamEvaluation)?;
    let beam_plan = freeze_plan(
        &problem,
        CostMatchedPlanSourceV1::OrderAwareBeam,
        beam.objective_gain_numerator,
        beam.selected_packet_ids.clone(),
        beam.selected_packet_cost,
        beam.coverage_only_token_cost,
    )?;
    let challenger = if plan_is_better(&beam_plan, &production) {
        beam_plan
    } else {
        freeze_plan(
            &problem,
            CostMatchedPlanSourceV1::ProductionFallback,
            production.objective_gain_numerator,
            production.selected_packet_ids.clone(),
            production.selected_packet_cost,
            production.coverage_only_token_cost,
        )?
    };
    validate_envelope(&production, envelope)?;
    validate_envelope(&challenger, envelope)?;
    if challenger.objective_gain_numerator < production.objective_gain_numerator {
        return Err(CostMatchedStressErrorV1::ObjectiveContract);
    }
    let structured_dp = evaluate_structured_exact_dp_v1(&problem, envelope)?;
    if let Some(optimum) = structured_dp.optimum() {
        validate_envelope(optimum, envelope)?;
        if optimum.objective_gain_numerator < challenger.objective_gain_numerator {
            return Err(CostMatchedStressErrorV1::ObjectiveContract);
        }
    }
    let objective_relation =
        if challenger.objective_gain_numerator > production.objective_gain_numerator {
            CostMatchedObjectiveRelationV1::ChallengerBetter
        } else {
            CostMatchedObjectiveRelationV1::Equal
        };
    let selected_cost_relation = cost_relation(
        production.selected_packet_cost,
        challenger.selected_packet_cost,
    )?;
    let coverage_cost_relation = cost_relation(
        production.coverage_only_token_cost,
        challenger.coverage_only_token_cost,
    )?;
    let problem_digest = derive_selection_problem_digest_v1(&problem)
        .map_err(|_| CostMatchedStressErrorV1::ObjectiveContract)?;
    let event_universe = problem
        .packets()
        .iter()
        .flat_map(|packet| packet.event_ids().iter().copied())
        .collect::<Vec<_>>();
    let digest = derive_case_digest(CaseDigestMaterialV1 {
        case,
        problem_digest,
        optional_packet_count: checked_u64(optional_packet_count)?,
        event_universe: &event_universe,
        envelope,
        production: &production,
        challenger: &challenger,
        beam: &beam,
        structured_dp: &structured_dp,
        objective_relation,
        selected_cost_relation,
        coverage_cost_relation,
    })?;
    Ok(FrozenCostMatchedStressCaseV1 {
        digest,
        case,
        problem_digest,
        optional_packet_count: checked_u64(optional_packet_count)?,
        event_universe,
        envelope,
        production,
        challenger,
        beam_bounds: beam.bounds,
        beam_observation: beam.observation,
        structured_dp,
        objective_relation,
        selected_cost_relation,
        coverage_cost_relation,
    })
}

fn freeze_plan(
    problem: &SelectionProblemV1,
    source: CostMatchedPlanSourceV1,
    objective_gain_numerator: u64,
    mut selected_packet_ids: Vec<PacketIdV1>,
    selected_packet_cost: u64,
    coverage_only_token_cost: u64,
) -> Result<FrozenCostMatchedPlanV1, CostMatchedStressErrorV1> {
    selected_packet_ids.sort_unstable();
    if selected_packet_ids
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(CostMatchedStressErrorV1::ObjectiveContract);
    }
    let packet_by_id = problem
        .packets()
        .iter()
        .map(|packet| (packet.id(), packet))
        .collect::<BTreeMap<_, _>>();
    let mut selected_event_ids = Vec::new();
    for packet_id in &selected_packet_ids {
        let packet = packet_by_id
            .get(packet_id)
            .ok_or(CostMatchedStressErrorV1::ObjectiveContract)?;
        selected_event_ids.extend(packet.event_ids().iter().copied());
    }
    selected_event_ids.sort_unstable();
    if selected_event_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(CostMatchedStressErrorV1::ObjectiveContract);
    }
    let selected_set = selected_packet_ids.iter().copied().collect::<BTreeSet<_>>();
    if problem
        .mandatory()
        .iter()
        .any(|entry| !selected_set.contains(&entry.packet_id()))
    {
        return Err(CostMatchedStressErrorV1::ResourceEnvelopeViolation);
    }
    let mandatory_ids = problem
        .mandatory()
        .iter()
        .map(|entry| entry.packet_id())
        .collect::<BTreeSet<_>>();
    let verified_gain = problem
        .normalized_gain(
            selected_packet_ids
                .iter()
                .copied()
                .filter(|packet_id| !mandatory_ids.contains(packet_id)),
        )
        .map_err(|_| CostMatchedStressErrorV1::ObjectiveContract)?;
    if verified_gain.numerator() != objective_gain_numerator {
        return Err(CostMatchedStressErrorV1::ObjectiveContract);
    }
    let mut hasher = Sha256::new();
    update_field(&mut hasher, PUBLIC_PLAN_DOMAIN_V1)?;
    hasher.update([plan_source_code(source)]);
    update_u64(&mut hasher, objective_gain_numerator);
    update_u64(&mut hasher, checked_u64(selected_packet_ids.len())?);
    for packet_id in &selected_packet_ids {
        update_field(&mut hasher, packet_id.as_bytes())?;
    }
    update_u64(&mut hasher, checked_u64(selected_event_ids.len())?);
    for event_id in &selected_event_ids {
        update_field(&mut hasher, event_id.as_bytes())?;
    }
    update_u64(&mut hasher, selected_packet_cost);
    update_u64(&mut hasher, coverage_only_token_cost);
    Ok(FrozenCostMatchedPlanV1 {
        digest: ArtifactDigest::from_bytes(hasher.finalize().into()),
        source,
        objective_gain_numerator,
        selected_packet_ids,
        selected_event_ids,
        selected_packet_cost,
        coverage_only_token_cost,
    })
}

fn validate_envelope(
    plan: &FrozenCostMatchedPlanV1,
    envelope: CostMatchedResourceEnvelopeV1,
) -> Result<(), CostMatchedStressErrorV1> {
    if plan.selected_packet_cost > envelope.selected_packet_cost_cap
        || plan.coverage_only_token_cost > envelope.coverage_only_token_cost_cap
    {
        return Err(CostMatchedStressErrorV1::ResourceEnvelopeViolation);
    }
    Ok(())
}

fn plan_is_better(candidate: &FrozenCostMatchedPlanV1, current: &FrozenCostMatchedPlanV1) -> bool {
    candidate
        .objective_gain_numerator
        .cmp(&current.objective_gain_numerator)
        .then_with(|| {
            current
                .selected_packet_cost
                .cmp(&candidate.selected_packet_cost)
        })
        .then_with(|| {
            current
                .coverage_only_token_cost
                .cmp(&candidate.coverage_only_token_cost)
        })
        .then_with(|| {
            current
                .selected_packet_ids
                .len()
                .cmp(&candidate.selected_packet_ids.len())
        })
        .then_with(|| {
            current
                .selected_packet_ids
                .cmp(&candidate.selected_packet_ids)
        })
        == Ordering::Greater
}

fn cost_relation(
    production: u64,
    challenger: u64,
) -> Result<CostMatchedCostRelationV1, CostMatchedStressErrorV1> {
    match challenger.cmp(&production) {
        Ordering::Less => Ok(CostMatchedCostRelationV1::ChallengerLower),
        Ordering::Equal => Ok(CostMatchedCostRelationV1::Equal),
        Ordering::Greater => Err(CostMatchedStressErrorV1::ResourceEnvelopeViolation),
    }
}

struct CaseDigestMaterialV1<'a> {
    case: CostMatchedStressCaseV1,
    problem_digest: ArtifactDigest,
    optional_packet_count: u64,
    event_universe: &'a [EventId],
    envelope: CostMatchedResourceEnvelopeV1,
    production: &'a FrozenCostMatchedPlanV1,
    challenger: &'a FrozenCostMatchedPlanV1,
    beam: &'a CostMatchedBeamFactsV1,
    structured_dp: &'a StructuredDpOutcomeV1,
    objective_relation: CostMatchedObjectiveRelationV1,
    selected_cost_relation: CostMatchedCostRelationV1,
    coverage_cost_relation: CostMatchedCostRelationV1,
}

fn derive_case_digest(
    material: CaseDigestMaterialV1<'_>,
) -> Result<FrozenCostMatchedStressDigestV1, CostMatchedStressErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, PUBLIC_CASE_DOMAIN_V1)?;
    update_field(&mut hasher, material.case.code().as_bytes())?;
    update_field(&mut hasher, material.case.family().code().as_bytes())?;
    update_field(&mut hasher, material.problem_digest.as_bytes())?;
    update_u64(&mut hasher, material.optional_packet_count);
    update_u64(&mut hasher, checked_u64(material.event_universe.len())?);
    for event_id in material.event_universe {
        update_field(&mut hasher, event_id.as_bytes())?;
    }
    hash_envelope(&mut hasher, material.envelope);
    update_field(&mut hasher, material.production.digest.as_bytes())?;
    update_field(&mut hasher, material.challenger.digest.as_bytes())?;
    hash_beam_work(&mut hasher, material.beam.bounds, material.beam.observation);
    hash_dp_outcome(&mut hasher, material.structured_dp)?;
    hasher.update([objective_relation_code(material.objective_relation)]);
    hasher.update([cost_relation_code(material.selected_cost_relation)]);
    hasher.update([cost_relation_code(material.coverage_cost_relation)]);
    Ok(FrozenCostMatchedStressDigestV1(hasher.finalize().into()))
}

fn build_stress_problem(
    case: CostMatchedStressCaseV1,
    reverse_fixture_input: bool,
) -> Result<SelectionProblemV1, CostMatchedStressErrorV1> {
    let (mut facets, mut packets, mandatory, budget) = match case {
        CostMatchedStressCaseV1::PrimaryDensityTrap15 => {
            build_independent_problem(case, ProductionFacetKindV1::QueryTerm, &trap_specs(), 10)?
        }
        CostMatchedStressCaseV1::PrimaryBalanced16 => build_independent_problem(
            case,
            ProductionFacetKindV1::FailureRole,
            &(0_u32..16)
                .map(|index| (1, 200_000 + index * 20_000))
                .collect::<Vec<_>>(),
            8,
        )?,
        CostMatchedStressCaseV1::CoverageDensityTrap15 => build_independent_problem(
            case,
            ProductionFacetKindV1::SourceCoverageStratum,
            &trap_specs(),
            80,
        )?,
        CostMatchedStressCaseV1::MixedDualResource16 => build_mixed_problem(case)?,
        CostMatchedStressCaseV1::ProviderPairs14 => build_provider_pairs_problem(case)?,
        CostMatchedStressCaseV1::MandatoryBaseline14 => build_mandatory_problem(case)?,
        CostMatchedStressCaseV1::ProviderThirdEndpoint15 => {
            build_provider_third_endpoint_problem(case)?
        }
        CostMatchedStressCaseV1::ExactPacketCap65 => build_independent_problem(
            case,
            ProductionFacetKindV1::OnsetRole,
            &(0_u32..65)
                .map(|index| (1, 100_000 + index * 5_000))
                .collect::<Vec<_>>(),
            10,
        )?,
    };
    if reverse_fixture_input {
        facets.reverse();
        packets.reverse();
    }
    SelectionProblemV1::new(
        facets,
        packets,
        mandatory,
        TotalTokenBudgetV1::new(budget).map_err(|_| CostMatchedStressErrorV1::FixtureInvariant)?,
        ReservedFixedOverheadV1::new(fixture_cost_model(), 0)
            .map_err(|_| CostMatchedStressErrorV1::FixtureInvariant)?,
    )
    .map_err(|_| CostMatchedStressErrorV1::FixtureInvariant)
}

type FixturePartsV1 = (
    Vec<ProductionFacetV1>,
    Vec<IntactPacketV1>,
    Vec<MandatoryPacketV1>,
    u64,
);

fn trap_specs() -> Vec<(u64, u32)> {
    let mut specs = vec![(6, 750_000), (5, 600_000), (5, 600_000), (4, 100_000)];
    specs.extend((0..11).map(|index| (11, 500_000 + index * 10_000)));
    specs
}

fn build_independent_problem(
    case: CostMatchedStressCaseV1,
    kind: ProductionFacetKindV1,
    specs: &[(u64, u32)],
    budget: u64,
) -> Result<FixturePartsV1, CostMatchedStressErrorV1> {
    let mut facets = Vec::with_capacity(specs.len());
    let mut packets = Vec::with_capacity(specs.len());
    for (index, (cost, affinity)) in specs.iter().copied().enumerate() {
        let facet = fixture_facet(case, index, kind)?;
        packets.push(fixture_packet(case, index, cost, [(facet.id(), affinity)])?);
        facets.push(facet);
    }
    Ok((facets, packets, Vec::new(), budget))
}

fn build_mixed_problem(
    case: CostMatchedStressCaseV1,
) -> Result<FixturePartsV1, CostMatchedStressErrorV1> {
    let specs = [
        (10, 1_000_000, ProductionFacetKindV1::QueryTerm),
        (8, 790_000, ProductionFacetKindV1::QueryTerm),
        (8, 790_000, ProductionFacetKindV1::QueryTerm),
        (6, 100_000, ProductionFacetKindV1::QueryTerm),
        (2, 300_000, ProductionFacetKindV1::TimeCoverageStratum),
    ];
    let mut facets = Vec::with_capacity(16);
    let mut packets = Vec::with_capacity(16);
    for (index, (cost, affinity, kind)) in specs.into_iter().enumerate() {
        let facet = fixture_facet(case, index, kind)?;
        packets.push(fixture_packet(case, index, cost, [(facet.id(), affinity)])?);
        facets.push(facet);
    }
    for index in 5..16 {
        let facet = fixture_facet(case, index, ProductionFacetKindV1::QueryTerm)?;
        packets.push(fixture_packet(case, index, 19, [(facet.id(), 500_000)])?);
        facets.push(facet);
    }
    Ok((facets, packets, Vec::new(), 18))
}

fn build_provider_pairs_problem(
    case: CostMatchedStressCaseV1,
) -> Result<FixturePartsV1, CostMatchedStressErrorV1> {
    let mut facets = Vec::with_capacity(7);
    let mut packets = Vec::with_capacity(14);
    for pair_index in 0..7 {
        let facet = fixture_facet(
            case,
            pair_index,
            ProductionFacetKindV1::ProviderAttestedGraphRelation,
        )?;
        for endpoint in 0..2 {
            let packet_index = pair_index * 2 + endpoint;
            packets.push(fixture_packet(
                case,
                packet_index,
                1,
                [(facet.id(), 1_000_000)],
            )?);
        }
        facets.push(facet);
    }
    Ok((facets, packets, Vec::new(), 7))
}

fn build_mandatory_problem(
    case: CostMatchedStressCaseV1,
) -> Result<FixturePartsV1, CostMatchedStressErrorV1> {
    let mandatory_facet = fixture_facet(case, 0, ProductionFacetKindV1::ValidatedQueryIdentifier)?;
    let mandatory_packet = fixture_packet(case, 0, 1, [(mandatory_facet.id(), 1_000_000)])?;
    let mandatory = vec![MandatoryPacketV1::validated_identifier(
        mandatory_packet.id(),
        mandatory_facet.id(),
    )];
    let mut facets = vec![mandatory_facet];
    let mut packets = vec![mandatory_packet];
    for index in 1..=14 {
        let facet = fixture_facet(case, index, ProductionFacetKindV1::QueryTerm)?;
        packets.push(fixture_packet(
            case,
            index,
            1,
            [(
                facet.id(),
                150_000 + u32::try_from(index).unwrap_or(0) * 20_000,
            )],
        )?);
        facets.push(facet);
    }
    Ok((facets, packets, mandatory, 8))
}

fn build_provider_third_endpoint_problem(
    case: CostMatchedStressCaseV1,
) -> Result<FixturePartsV1, CostMatchedStressErrorV1> {
    let facet = fixture_facet(
        case,
        0,
        ProductionFacetKindV1::ProviderAttestedGraphRelation,
    )?;
    let packets = (0..15)
        .map(|index| fixture_packet(case, index, 1, [(facet.id(), 1_000_000)]))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((vec![facet], packets, Vec::new(), 2))
}

fn fixture_facet(
    case: CostMatchedStressCaseV1,
    index: usize,
    kind: ProductionFacetKindV1,
) -> Result<ProductionFacetV1, CostMatchedStressErrorV1> {
    let weight = if kind == ProductionFacetKindV1::ProviderAttestedGraphRelation {
        PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1
    } else {
        1
    };
    let mut semantic_key = Vec::new();
    semantic_key.extend_from_slice(case.code().as_bytes());
    semantic_key.push(0);
    semantic_key.extend_from_slice(&checked_u64(index)?.to_le_bytes());
    ProductionFacetV1::new(
        kind,
        &semantic_key,
        FacetWeightV1::new(weight).map_err(|_| CostMatchedStressErrorV1::FixtureInvariant)?,
    )
    .map_err(|_| CostMatchedStressErrorV1::FixtureInvariant)
}

fn fixture_packet<const N: usize>(
    case: CostMatchedStressCaseV1,
    index: usize,
    cost: u64,
    affinities: [(evidentrail_select::FacetIdV1, u32); N],
) -> Result<IntactPacketV1, CostMatchedStressErrorV1> {
    let packet_id = PacketIdV1::from_bytes(fixture_id_bytes(case, index, 10_000)?);
    let event_id = EventId::from_bytes(fixture_id_bytes(case, index, 20_000)?);
    let affinities = affinities
        .into_iter()
        .map(|(facet_id, affinity)| {
            Ok(FacetAffinityV1::new(
                facet_id,
                AffinityV1::new(affinity)
                    .map_err(|_| CostMatchedStressErrorV1::FixtureInvariant)?,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    IntactPacketV1::new(
        packet_id,
        [event_id],
        ComposablePacketCostV1::new(fixture_cost_model(), cost)
            .map_err(|_| CostMatchedStressErrorV1::FixtureInvariant)?,
        affinities,
    )
    .map_err(|_| CostMatchedStressErrorV1::FixtureInvariant)
}

fn fixture_cost_model() -> ComposableCostModelV1 {
    ComposableCostModelV1::new(ArtifactDigest::from_bytes([0xc7; 32]))
}

fn fixture_id_bytes(
    case: CostMatchedStressCaseV1,
    index: usize,
    namespace: u64,
) -> Result<[u8; 32], CostMatchedStressErrorV1> {
    let case_index = CostMatchedStressCaseV1::ALL
        .iter()
        .position(|candidate| *candidate == case)
        .ok_or(CostMatchedStressErrorV1::FixtureInvariant)?;
    let seed = checked_u64(case_index)?
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(checked_u64(index).ok()?))
        .and_then(|value| value.checked_add(namespace))
        .ok_or(CostMatchedStressErrorV1::ArithmeticOverflow)?;
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_be_bytes());
    Ok(bytes)
}

fn hash_envelope(hasher: &mut Sha256, envelope: CostMatchedResourceEnvelopeV1) {
    update_u64(hasher, envelope.selected_packet_cost_cap);
    update_u64(hasher, envelope.coverage_only_token_cost_cap);
    update_u64(hasher, envelope.mandatory_packet_cost);
    update_u64(hasher, envelope.reserved_fixed_overhead);
}

fn hash_beam_work(
    hasher: &mut Sha256,
    bounds: BoundedSelectorSearchBoundsV1,
    observation: BoundedSelectorSearchObservationV1,
) {
    update_u64(hasher, bounds.state_slot_cap());
    update_u64(hasher, bounds.transition_attempt_cap());
    update_u64(hasher, bounds.depth_cap());
    match observation.transition_attempts() {
        Some(value) => {
            hasher.update([1]);
            update_u64(hasher, value);
        }
        None => hasher.update([0]),
    }
    update_u64(hasher, observation.retained_state_high_water());
    hasher.update([u8::from(observation.transition_cap_reached())]);
}

fn hash_dp_outcome(
    hasher: &mut Sha256,
    outcome: &StructuredDpOutcomeV1,
) -> Result<(), CostMatchedStressErrorV1> {
    match outcome {
        StructuredDpOutcomeV1::Exact { optimum, work } => {
            hasher.update([0]);
            update_field(hasher, optimum.digest.as_bytes())?;
            hash_dp_work(hasher, *work);
        }
        StructuredDpOutcomeV1::Ineligible { reason, work } => {
            hasher.update([1, dp_ineligible_code(*reason)]);
            hash_dp_work(hasher, *work);
        }
    }
    Ok(())
}

fn hash_dp_work(hasher: &mut Sha256, work: StructuredDpWorkReceiptV1) {
    update_u64(hasher, work.optional_packet_cap);
    update_u64(hasher, work.state_slot_cap);
    update_u64(hasher, work.transition_attempt_cap);
    update_u64(hasher, work.retained_state_high_water);
    update_u64(hasher, work.transition_attempts);
}

const fn plan_source_code(source: CostMatchedPlanSourceV1) -> u8 {
    match source {
        CostMatchedPlanSourceV1::Production => 0,
        CostMatchedPlanSourceV1::OrderAwareBeam => 1,
        CostMatchedPlanSourceV1::ProductionFallback => 2,
        CostMatchedPlanSourceV1::StructuredExactDp => 3,
    }
}

const fn objective_relation_code(relation: CostMatchedObjectiveRelationV1) -> u8 {
    match relation {
        CostMatchedObjectiveRelationV1::ChallengerBetter => 0,
        CostMatchedObjectiveRelationV1::Equal => 1,
    }
}

const fn cost_relation_code(relation: CostMatchedCostRelationV1) -> u8 {
    match relation {
        CostMatchedCostRelationV1::ChallengerLower => 0,
        CostMatchedCostRelationV1::Equal => 1,
    }
}

const fn dp_ineligible_code(reason: StructuredDpIneligibleReasonV1) -> u8 {
    match reason {
        StructuredDpIneligibleReasonV1::OptionalPacketCap => 0,
        StructuredDpIneligibleReasonV1::NonAdditiveSaturation => 1,
        StructuredDpIneligibleReasonV1::StateSlotCap => 2,
        StructuredDpIneligibleReasonV1::TransitionCap => 3,
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CostMatchedStressRequirementV1 {
    weight: u32,
    alternatives: Vec<Vec<EventId>>,
}

impl CostMatchedStressRequirementV1 {
    pub fn new(
        weight: u32,
        alternatives: impl IntoIterator<Item = Vec<EventId>>,
    ) -> Result<Self, CostMatchedStressErrorV1> {
        if weight == 0 {
            return Err(CostMatchedStressErrorV1::RequirementBounds);
        }
        let mut alternatives = alternatives.into_iter().collect::<Vec<_>>();
        if alternatives.is_empty() || alternatives.len() > MAX_COST_MATCHED_STRESS_ALTERNATIVES_V1 {
            return Err(CostMatchedStressErrorV1::RequirementBounds);
        }
        for alternative in &mut alternatives {
            if alternative.is_empty()
                || alternative.len() > MAX_COST_MATCHED_STRESS_EVENTS_PER_ALTERNATIVE_V1
            {
                return Err(CostMatchedStressErrorV1::RequirementBounds);
            }
            alternative.sort_unstable();
            if alternative.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(CostMatchedStressErrorV1::RequirementDuplicate);
            }
        }
        alternatives.sort_unstable();
        if alternatives.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CostMatchedStressErrorV1::RequirementDuplicate);
        }
        Ok(Self {
            weight,
            alternatives,
        })
    }

    #[must_use]
    pub const fn weight(&self) -> u32 {
        self.weight
    }

    #[must_use]
    pub fn alternatives(&self) -> &[Vec<EventId>] {
        &self.alternatives
    }
}

impl fmt::Debug for CostMatchedStressRequirementV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CostMatchedStressRequirementV1")
            .field("weight", &self.weight)
            .field("alternative_count", &self.alternatives.len())
            .field(
                "required_event_reference_count",
                &self.alternatives.iter().map(Vec::len).sum::<usize>(),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CostMatchedStressGovernedAnnotationV1 {
    public_corpus_digest: FrozenCostMatchedStressDigestV1,
    case: CostMatchedStressCaseV1,
    public_case_digest: FrozenCostMatchedStressDigestV1,
    requirements: Vec<CostMatchedStressRequirementV1>,
}

impl CostMatchedStressGovernedAnnotationV1 {
    pub fn new(
        public_corpus_digest: FrozenCostMatchedStressDigestV1,
        case: CostMatchedStressCaseV1,
        public_case_digest: FrozenCostMatchedStressDigestV1,
        requirements: impl IntoIterator<Item = CostMatchedStressRequirementV1>,
    ) -> Result<Self, CostMatchedStressErrorV1> {
        let mut requirements = requirements.into_iter().collect::<Vec<_>>();
        if requirements.is_empty() || requirements.len() > MAX_COST_MATCHED_STRESS_REQUIREMENTS_V1 {
            return Err(CostMatchedStressErrorV1::RequirementBounds);
        }
        requirements.sort_unstable();
        if requirements.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CostMatchedStressErrorV1::RequirementDuplicate);
        }
        Ok(Self {
            public_corpus_digest,
            case,
            public_case_digest,
            requirements,
        })
    }

    #[must_use]
    pub const fn case(&self) -> CostMatchedStressCaseV1 {
        self.case
    }
}

impl fmt::Debug for CostMatchedStressGovernedAnnotationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CostMatchedStressGovernedAnnotationV1")
            .field("binding_present", &true)
            .field("case", &self.case)
            .field("requirement_count", &self.requirements.len())
            .finish()
    }
}

/// Fixed hand-authored conformance labels for the synthetic corpus. Requiring
/// the already-frozen public corpus prevents this helper from entering the
/// public generation signature. Type staging is not temporal attestation.
pub fn synthetic_cost_matched_stress_annotations_v1(
    public: &FrozenCostMatchedStressCorpusV1,
) -> Result<
    [CostMatchedStressGovernedAnnotationV1; COST_MATCHED_STRESS_CASE_COUNT_V1],
    CostMatchedStressErrorV1,
> {
    let mut annotations = Vec::with_capacity(COST_MATCHED_STRESS_CASE_COUNT_V1);
    for case in CostMatchedStressCaseV1::ALL {
        let required_indices: &[usize] = match case {
            CostMatchedStressCaseV1::PrimaryDensityTrap15
            | CostMatchedStressCaseV1::CoverageDensityTrap15 => &[1, 2],
            CostMatchedStressCaseV1::PrimaryBalanced16 => &[14, 15],
            CostMatchedStressCaseV1::MixedDualResource16 => &[1, 2, 4],
            CostMatchedStressCaseV1::ProviderPairs14 => &[0, 1],
            CostMatchedStressCaseV1::MandatoryBaseline14 => &[0, 14],
            CostMatchedStressCaseV1::ProviderThirdEndpoint15 => &[0, 1],
            CostMatchedStressCaseV1::ExactPacketCap65 => &[63, 64],
        };
        let alternative = required_indices
            .iter()
            .map(|index| Ok(EventId::from_bytes(fixture_id_bytes(case, *index, 20_000)?)))
            .collect::<Result<Vec<_>, CostMatchedStressErrorV1>>()?;
        let requirement = CostMatchedStressRequirementV1::new(1, [alternative])?;
        let public_case = public.case(case);
        annotations.push(CostMatchedStressGovernedAnnotationV1::new(
            public.digest,
            case,
            public_case.digest,
            [requirement],
        )?);
    }
    annotations
        .try_into()
        .map_err(|_| CostMatchedStressErrorV1::CaseSetMismatch)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CostMatchedStressRecallV1 {
    numerator: u64,
    denominator: u64,
    satisfied_requirement_count: u64,
    requirement_count: u64,
}

impl CostMatchedStressRecallV1 {
    #[must_use]
    pub const fn numerator(self) -> u64 {
        self.numerator
    }

    #[must_use]
    pub const fn denominator(self) -> u64 {
        self.denominator
    }

    #[must_use]
    pub const fn satisfied_requirement_count(self) -> u64 {
        self.satisfied_requirement_count
    }

    #[must_use]
    pub const fn requirement_count(self) -> u64 {
        self.requirement_count
    }
}

impl fmt::Debug for CostMatchedStressRecallV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CostMatchedStressRecallV1")
            .field("numerator", &self.numerator)
            .field("denominator", &self.denominator)
            .field(
                "satisfied_requirement_count",
                &self.satisfied_requirement_count,
            )
            .field("requirement_count", &self.requirement_count)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CostMatchedRecallRelationV1 {
    ChallengerBetter,
    Equal,
    ChallengerWorse,
}

#[derive(Clone, PartialEq, Eq)]
pub struct GovernedCostMatchedStressCaseV1 {
    case: CostMatchedStressCaseV1,
    public_case_digest: FrozenCostMatchedStressDigestV1,
    production_recall: CostMatchedStressRecallV1,
    challenger_recall: CostMatchedStressRecallV1,
    exact_dp_recall: Option<CostMatchedStressRecallV1>,
    recall_relation: CostMatchedRecallRelationV1,
    deterministic_weak_dominance: bool,
}

impl GovernedCostMatchedStressCaseV1 {
    #[must_use]
    pub const fn case(&self) -> CostMatchedStressCaseV1 {
        self.case
    }

    #[must_use]
    pub const fn production_recall(&self) -> CostMatchedStressRecallV1 {
        self.production_recall
    }

    #[must_use]
    pub const fn challenger_recall(&self) -> CostMatchedStressRecallV1 {
        self.challenger_recall
    }

    #[must_use]
    pub const fn exact_dp_recall(&self) -> Option<CostMatchedStressRecallV1> {
        self.exact_dp_recall
    }

    #[must_use]
    pub const fn recall_relation(&self) -> CostMatchedRecallRelationV1 {
        self.recall_relation
    }

    #[must_use]
    pub const fn deterministic_weak_dominance(&self) -> bool {
        self.deterministic_weak_dominance
    }
}

impl fmt::Debug for GovernedCostMatchedStressCaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedCostMatchedStressCaseV1")
            .field("case", &self.case)
            .field("public_case_binding_present", &true)
            .field("production_recall", &self.production_recall)
            .field("challenger_recall", &self.challenger_recall)
            .field("exact_dp_recall", &self.exact_dp_recall)
            .field("recall_relation", &self.recall_relation)
            .field(
                "deterministic_weak_dominance",
                &self.deterministic_weak_dominance,
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct GovernedCostMatchedStressCorpusV1 {
    digest: FrozenCostMatchedStressDigestV1,
    public_corpus_digest: FrozenCostMatchedStressDigestV1,
    cases: [GovernedCostMatchedStressCaseV1; COST_MATCHED_STRESS_CASE_COUNT_V1],
    recall_better_count: u64,
    recall_equal_count: u64,
    recall_worse_count: u64,
    deterministic_weak_dominance_count: u64,
}

impl GovernedCostMatchedStressCorpusV1 {
    #[must_use]
    pub const fn digest(&self) -> FrozenCostMatchedStressDigestV1 {
        self.digest
    }

    #[must_use]
    pub const fn public_corpus_digest(&self) -> FrozenCostMatchedStressDigestV1 {
        self.public_corpus_digest
    }

    #[must_use]
    pub fn cases(&self) -> &[GovernedCostMatchedStressCaseV1] {
        &self.cases
    }

    #[must_use]
    pub fn case(&self, case: CostMatchedStressCaseV1) -> &GovernedCostMatchedStressCaseV1 {
        self.cases
            .iter()
            .find(|entry| entry.case == case)
            .expect("closed governed corpus contains every case")
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
    pub const fn recall_worse_count(&self) -> u64 {
        self.recall_worse_count
    }

    #[must_use]
    pub const fn deterministic_weak_dominance_count(&self) -> u64 {
        self.deterministic_weak_dominance_count
    }

    #[must_use]
    pub const fn production_promotion_eligible(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn claims_measured_wall_time_or_peak_rss(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn claims_population_quality(&self) -> bool {
        false
    }
}

impl fmt::Debug for GovernedCostMatchedStressCorpusV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedCostMatchedStressCorpusV1")
            .field("governed_identity_present", &true)
            .field("public_binding_present", &true)
            .field("case_count", &self.cases.len())
            .field("recall_better_count", &self.recall_better_count)
            .field("recall_equal_count", &self.recall_equal_count)
            .field("recall_worse_count", &self.recall_worse_count)
            .field(
                "deterministic_weak_dominance_count",
                &self.deterministic_weak_dominance_count,
            )
            .field("production_promotion_eligible", &false)
            .field("claims_measured_wall_time_or_peak_rss", &false)
            .field("claims_population_quality", &false)
            .finish()
    }
}

pub fn evaluate_governed_cost_matched_selector_stress_v1(
    public: &FrozenCostMatchedStressCorpusV1,
    annotations: [CostMatchedStressGovernedAnnotationV1; COST_MATCHED_STRESS_CASE_COUNT_V1],
) -> Result<GovernedCostMatchedStressCorpusV1, CostMatchedStressErrorV1> {
    let mut seen = BTreeSet::new();
    let mut cases = Vec::with_capacity(COST_MATCHED_STRESS_CASE_COUNT_V1);
    for annotation in annotations {
        if annotation.public_corpus_digest != public.digest || !seen.insert(annotation.case) {
            return Err(CostMatchedStressErrorV1::CaseSetMismatch);
        }
        let public_case = public.case(annotation.case);
        if annotation.public_case_digest != public_case.digest {
            return Err(CostMatchedStressErrorV1::CaseBindingMismatch);
        }
        validate_requirement_events(public_case, &annotation.requirements)?;
        let production_recall = evaluate_recall(
            &annotation.requirements,
            public_case.production.selected_event_ids(),
        )?;
        let challenger_recall = evaluate_recall(
            &annotation.requirements,
            public_case.challenger.selected_event_ids(),
        )?;
        let exact_dp_recall = public_case
            .structured_dp
            .optimum()
            .map(|optimum| evaluate_recall(&annotation.requirements, optimum.selected_event_ids()))
            .transpose()?;
        let recall_relation = compare_recall(challenger_recall, production_recall)?;
        let deterministic_weak_dominance = public_case.deterministic_axes_weakly_dominate()
            && recall_relation != CostMatchedRecallRelationV1::ChallengerWorse;
        cases.push(GovernedCostMatchedStressCaseV1 {
            case: annotation.case,
            public_case_digest: public_case.digest,
            production_recall,
            challenger_recall,
            exact_dp_recall,
            recall_relation,
            deterministic_weak_dominance,
        });
    }
    if seen.len() != COST_MATCHED_STRESS_CASE_COUNT_V1 {
        return Err(CostMatchedStressErrorV1::CaseSetMismatch);
    }
    cases.sort_unstable_by_key(|case| case.case);
    let cases: [GovernedCostMatchedStressCaseV1; COST_MATCHED_STRESS_CASE_COUNT_V1] = cases
        .try_into()
        .map_err(|_| CostMatchedStressErrorV1::CaseSetMismatch)?;
    let recall_better_count = checked_u64(
        cases
            .iter()
            .filter(|case| case.recall_relation == CostMatchedRecallRelationV1::ChallengerBetter)
            .count(),
    )?;
    let recall_equal_count = checked_u64(
        cases
            .iter()
            .filter(|case| case.recall_relation == CostMatchedRecallRelationV1::Equal)
            .count(),
    )?;
    let recall_worse_count = checked_u64(cases.len())?
        .checked_sub(recall_better_count)
        .and_then(|value| value.checked_sub(recall_equal_count))
        .ok_or(CostMatchedStressErrorV1::ArithmeticOverflow)?;
    let deterministic_weak_dominance_count = checked_u64(
        cases
            .iter()
            .filter(|case| case.deterministic_weak_dominance)
            .count(),
    )?;
    let mut hasher = Sha256::new();
    update_field(&mut hasher, GOVERNED_CORPUS_DOMAIN_V1)?;
    update_field(&mut hasher, public.digest.as_bytes())?;
    update_u64(&mut hasher, checked_u64(cases.len())?);
    for case in &cases {
        update_field(&mut hasher, case.public_case_digest.as_bytes())?;
        update_field(&mut hasher, case.case.code().as_bytes())?;
        hash_recall(&mut hasher, case.production_recall);
        hash_recall(&mut hasher, case.challenger_recall);
        match case.exact_dp_recall {
            Some(recall) => {
                hasher.update([1]);
                hash_recall(&mut hasher, recall);
            }
            None => hasher.update([0]),
        }
        hasher.update([recall_relation_code(case.recall_relation)]);
        hasher.update([u8::from(case.deterministic_weak_dominance)]);
    }
    update_u64(&mut hasher, recall_better_count);
    update_u64(&mut hasher, recall_equal_count);
    update_u64(&mut hasher, recall_worse_count);
    update_u64(&mut hasher, deterministic_weak_dominance_count);
    Ok(GovernedCostMatchedStressCorpusV1 {
        digest: FrozenCostMatchedStressDigestV1(hasher.finalize().into()),
        public_corpus_digest: public.digest,
        cases,
        recall_better_count,
        recall_equal_count,
        recall_worse_count,
        deterministic_weak_dominance_count,
    })
}

fn validate_requirement_events(
    public_case: &FrozenCostMatchedStressCaseV1,
    requirements: &[CostMatchedStressRequirementV1],
) -> Result<(), CostMatchedStressErrorV1> {
    let universe = public_case.event_universe.iter().collect::<BTreeSet<_>>();
    if requirements.iter().any(|requirement| {
        requirement
            .alternatives
            .iter()
            .flatten()
            .any(|event_id| !universe.contains(event_id))
    }) {
        return Err(CostMatchedStressErrorV1::RequirementUnknownEvent);
    }
    Ok(())
}

fn evaluate_recall(
    requirements: &[CostMatchedStressRequirementV1],
    selected_event_ids: &[EventId],
) -> Result<CostMatchedStressRecallV1, CostMatchedStressErrorV1> {
    let selected = selected_event_ids.iter().collect::<BTreeSet<_>>();
    let mut numerator = 0_u64;
    let mut denominator = 0_u64;
    let mut satisfied_requirement_count = 0_u64;
    for requirement in requirements {
        let weight = u64::from(requirement.weight);
        denominator = denominator
            .checked_add(weight)
            .ok_or(CostMatchedStressErrorV1::ArithmeticOverflow)?;
        let satisfied = requirement.alternatives.iter().any(|alternative| {
            alternative
                .iter()
                .all(|event_id| selected.contains(event_id))
        });
        if satisfied {
            numerator = numerator
                .checked_add(weight)
                .ok_or(CostMatchedStressErrorV1::ArithmeticOverflow)?;
            satisfied_requirement_count = satisfied_requirement_count
                .checked_add(1)
                .ok_or(CostMatchedStressErrorV1::ArithmeticOverflow)?;
        }
    }
    Ok(CostMatchedStressRecallV1 {
        numerator,
        denominator,
        satisfied_requirement_count,
        requirement_count: checked_u64(requirements.len())?,
    })
}

fn compare_recall(
    challenger: CostMatchedStressRecallV1,
    production: CostMatchedStressRecallV1,
) -> Result<CostMatchedRecallRelationV1, CostMatchedStressErrorV1> {
    let left = u128::from(challenger.numerator)
        .checked_mul(u128::from(production.denominator))
        .ok_or(CostMatchedStressErrorV1::ArithmeticOverflow)?;
    let right = u128::from(production.numerator)
        .checked_mul(u128::from(challenger.denominator))
        .ok_or(CostMatchedStressErrorV1::ArithmeticOverflow)?;
    Ok(match left.cmp(&right) {
        Ordering::Greater => CostMatchedRecallRelationV1::ChallengerBetter,
        Ordering::Equal => CostMatchedRecallRelationV1::Equal,
        Ordering::Less => CostMatchedRecallRelationV1::ChallengerWorse,
    })
}

fn hash_recall(hasher: &mut Sha256, recall: CostMatchedStressRecallV1) {
    update_u64(hasher, recall.numerator);
    update_u64(hasher, recall.denominator);
    update_u64(hasher, recall.satisfied_requirement_count);
    update_u64(hasher, recall.requirement_count);
}

const fn recall_relation_code(relation: CostMatchedRecallRelationV1) -> u8 {
    match relation {
        CostMatchedRecallRelationV1::ChallengerBetter => 0,
        CostMatchedRecallRelationV1::Equal => 1,
        CostMatchedRecallRelationV1::ChallengerWorse => 2,
    }
}

fn checked_u64(value: usize) -> Result<u64, CostMatchedStressErrorV1> {
    u64::try_from(value).map_err(|_| CostMatchedStressErrorV1::ArithmeticOverflow)
}

fn update_field(hasher: &mut Sha256, bytes: &[u8]) -> Result<(), CostMatchedStressErrorV1> {
    update_u64(hasher, checked_u64(bytes.len())?);
    hasher.update(bytes);
    Ok(())
}

fn update_u64(hasher: &mut Sha256, value: u64) {
    // Frozen V1 integer encoding is little-endian.
    hasher.update(value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_input_permutation_cannot_change_any_frozen_case() {
        for case in CostMatchedStressCaseV1::ALL {
            let canonical = freeze_case(case, false).unwrap();
            let reversed = freeze_case(case, true).unwrap();
            assert_eq!(canonical, reversed);
            assert_eq!(canonical.digest(), reversed.digest());
        }
    }
}
