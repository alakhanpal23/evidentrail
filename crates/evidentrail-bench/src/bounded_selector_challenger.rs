//! Evaluation-only deterministic challenger for the production Greedy+Max
//! selector.
//!
//! Universes with at most 12 optional packets use the existing exact subset
//! oracle. Larger universes use an order-aware beam with closed work and state
//! caps, then compare against the production result as a fallback. This module
//! does not alter the runtime selector and makes no wall-time or RSS claim.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::ArtifactDigest;
use evidentrail_select::{
    COVERAGE_ONLY_OPTIONAL_BUDGET_DENOMINATOR_V1, FacetIdV1, FacetSaturationCardinalityV1,
    IntactPacketV1, NeedsMoreReasonV1, PacketIdV1, SELECTION_OBJECTIVE_POLICY_NAME_V1,
    SELECTION_OBJECTIVE_POLICY_VERSION_V1, SelectionDecisionV1, SelectionProblemV1,
};
use sha2::{Digest as _, Sha256};

use crate::{
    EXACT_SELECTION_ORACLE_POLICY_NAME_V1, EXACT_SELECTION_ORACLE_POLICY_VERSION_V1,
    ExactSelectionOracleErrorV1, ExactSmallSelectionOracleDecisionV1,
    MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1, evaluate_exact_small_selection_oracle_v1,
};

const CHALLENGER_DOMAIN_V1: &[u8] = b"evidentrail/bench/bounded-selector-challenger/v1\0";
const PROBLEM_DOMAIN_V1: &[u8] = b"evidentrail/bench/bounded-selector-challenger-problem/v1\0";

pub const BOUNDED_SELECTOR_CHALLENGER_POLICY_NAME_V1: &[u8] =
    b"evidentrail/bench/exact12-order-aware-beam-production-fallback";
pub const BOUNDED_SELECTOR_CHALLENGER_POLICY_VERSION_V1: &[u8] = b"1";
pub const BOUNDED_SELECTOR_CHALLENGER_BEAM_WIDTH_V1: usize = 64;
pub const BOUNDED_SELECTOR_CHALLENGER_MAX_DEPTH_V1: usize = 64;
pub const BOUNDED_SELECTOR_CHALLENGER_TRANSITION_CAP_V1: u64 = 131_072;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundedSelectorChallengerModeV1 {
    ExactSubsets,
    OrderAwareBeam,
}

impl BoundedSelectorChallengerModeV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ExactSubsets => "exact_subsets_optional_le_12",
            Self::OrderAwareBeam => "order_aware_beam_with_production_fallback",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundedSelectorPlanSourceV1 {
    ExactSubset,
    OrderAwareBeam,
    ProductionFallback,
}

impl BoundedSelectorPlanSourceV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ExactSubset => "exact_subset",
            Self::OrderAwareBeam => "order_aware_beam",
            Self::ProductionFallback => "production_greedy_max_fallback",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundedSelectorObjectiveRelationV1 {
    ChallengerBetter,
    Equal,
    ChallengerWorse,
    MatchedTerminal,
    TerminalMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundedSelectorCostRelationV1 {
    ChallengerLower,
    Equal,
    ChallengerHigher,
    NotApplicable,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BoundedSelectorPacketIdV1([u8; 32]);

impl BoundedSelectorPacketIdV1 {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<PacketIdV1> for BoundedSelectorPacketIdV1 {
    fn from(value: PacketIdV1) -> Self {
        Self(*value.as_bytes())
    }
}

impl fmt::Debug for BoundedSelectorPacketIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BoundedSelectorPacketIdV1(<redacted>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BoundedSelectorChallengerIdentityV1 {
    digest: ArtifactDigest,
}

impl BoundedSelectorChallengerIdentityV1 {
    #[must_use]
    pub const fn digest(self) -> ArtifactDigest {
        self.digest
    }

    #[must_use]
    pub const fn policy_name(self) -> &'static [u8] {
        BOUNDED_SELECTOR_CHALLENGER_POLICY_NAME_V1
    }

    #[must_use]
    pub const fn policy_version(self) -> &'static [u8] {
        BOUNDED_SELECTOR_CHALLENGER_POLICY_VERSION_V1
    }
}

impl fmt::Debug for BoundedSelectorChallengerIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedSelectorChallengerIdentityV1")
            .field("identity_present", &true)
            .field("policy_version", &"1")
            .finish()
    }
}

#[must_use]
pub fn bounded_selector_challenger_identity_v1() -> BoundedSelectorChallengerIdentityV1 {
    let mut hasher = Sha256::new();
    hash_static_field(&mut hasher, CHALLENGER_DOMAIN_V1);
    hash_static_field(&mut hasher, BOUNDED_SELECTOR_CHALLENGER_POLICY_NAME_V1);
    hash_static_field(&mut hasher, BOUNDED_SELECTOR_CHALLENGER_POLICY_VERSION_V1);
    hash_static_field(&mut hasher, EXACT_SELECTION_ORACLE_POLICY_NAME_V1);
    hash_static_field(&mut hasher, EXACT_SELECTION_ORACLE_POLICY_VERSION_V1);
    hash_static_field(&mut hasher, SELECTION_OBJECTIVE_POLICY_NAME_V1);
    hash_static_field(&mut hasher, SELECTION_OBJECTIVE_POLICY_VERSION_V1);
    hasher.update(
        u64::try_from(MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1)
            .expect("closed exact cap fits u64")
            .to_le_bytes(),
    );
    hasher.update(
        u64::try_from(BOUNDED_SELECTOR_CHALLENGER_BEAM_WIDTH_V1)
            .expect("closed beam width fits u64")
            .to_le_bytes(),
    );
    hasher.update(
        u64::try_from(BOUNDED_SELECTOR_CHALLENGER_MAX_DEPTH_V1)
            .expect("closed depth cap fits u64")
            .to_le_bytes(),
    );
    hasher.update(BOUNDED_SELECTOR_CHALLENGER_TRANSITION_CAP_V1.to_le_bytes());
    BoundedSelectorChallengerIdentityV1 {
        digest: ArtifactDigest::from_bytes(hasher.finalize().into()),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BoundedSelectorSearchBoundsV1 {
    state_slot_cap: u64,
    transition_attempt_cap: u64,
    depth_cap: u64,
}

impl BoundedSelectorSearchBoundsV1 {
    #[must_use]
    pub const fn state_slot_cap(self) -> u64 {
        self.state_slot_cap
    }

    #[must_use]
    pub const fn transition_attempt_cap(self) -> u64 {
        self.transition_attempt_cap
    }

    #[must_use]
    pub const fn depth_cap(self) -> u64 {
        self.depth_cap
    }
}

impl fmt::Debug for BoundedSelectorSearchBoundsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedSelectorSearchBoundsV1")
            .field("state_slot_cap", &self.state_slot_cap)
            .field("transition_attempt_cap", &self.transition_attempt_cap)
            .field("depth_cap", &self.depth_cap)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BoundedSelectorSearchObservationV1 {
    transition_attempts: Option<u64>,
    retained_state_high_water: u64,
    transition_cap_reached: bool,
}

impl BoundedSelectorSearchObservationV1 {
    #[must_use]
    pub const fn transition_attempts(self) -> Option<u64> {
        self.transition_attempts
    }

    #[must_use]
    pub const fn retained_state_high_water(self) -> u64 {
        self.retained_state_high_water
    }

    #[must_use]
    pub const fn transition_cap_reached(self) -> bool {
        self.transition_cap_reached
    }
}

impl fmt::Debug for BoundedSelectorSearchObservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedSelectorSearchObservationV1")
            .field("transition_attempts", &self.transition_attempts)
            .field("retained_state_high_water", &self.retained_state_high_water)
            .field("transition_cap_reached", &self.transition_cap_reached)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct BoundedSelectorSelectedPlanV1 {
    source: BoundedSelectorPlanSourceV1,
    objective_gain_numerator: u64,
    selected_packet_ids: Vec<BoundedSelectorPacketIdV1>,
    optional_acceptance_order: Vec<BoundedSelectorPacketIdV1>,
    selected_packet_cost: u64,
    accounted_token_upper_bound: u64,
    coverage_only_token_cost: u64,
    coverage_only_token_limit: u64,
}

impl BoundedSelectorSelectedPlanV1 {
    #[must_use]
    pub const fn source(&self) -> BoundedSelectorPlanSourceV1 {
        self.source
    }

    #[must_use]
    pub const fn objective_gain_numerator(&self) -> u64 {
        self.objective_gain_numerator
    }

    #[must_use]
    pub fn selected_packet_ids(&self) -> &[BoundedSelectorPacketIdV1] {
        &self.selected_packet_ids
    }

    #[must_use]
    pub fn optional_acceptance_order(&self) -> &[BoundedSelectorPacketIdV1] {
        &self.optional_acceptance_order
    }

    #[must_use]
    pub const fn selected_packet_cost(&self) -> u64 {
        self.selected_packet_cost
    }

    #[must_use]
    pub const fn accounted_token_upper_bound(&self) -> u64 {
        self.accounted_token_upper_bound
    }

    #[must_use]
    pub const fn coverage_only_token_cost(&self) -> u64 {
        self.coverage_only_token_cost
    }

    #[must_use]
    pub const fn coverage_only_token_limit(&self) -> u64 {
        self.coverage_only_token_limit
    }
}

impl fmt::Debug for BoundedSelectorSelectedPlanV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedSelectorSelectedPlanV1")
            .field("source", &self.source)
            .field("objective_gain_numerator", &self.objective_gain_numerator)
            .field("selected_packet_count", &self.selected_packet_ids.len())
            .field(
                "optional_acceptance_count",
                &self.optional_acceptance_order.len(),
            )
            .field("selected_packet_cost", &self.selected_packet_cost)
            .field(
                "accounted_token_upper_bound",
                &self.accounted_token_upper_bound,
            )
            .field("coverage_only_token_cost", &self.coverage_only_token_cost)
            .field("coverage_only_token_limit", &self.coverage_only_token_limit)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BoundedSelectorNeedsMoreV1 {
    pub(crate) reason: NeedsMoreReasonV1,
    pub(crate) total_token_budget: u64,
    pub(crate) reserved_fixed_overhead: u64,
    pub(crate) mandatory_packet_cost: u64,
    pub(crate) mandatory_packet_count: u64,
}

impl BoundedSelectorNeedsMoreV1 {
    #[must_use]
    pub const fn reason(self) -> NeedsMoreReasonV1 {
        self.reason
    }

    #[must_use]
    pub const fn total_token_budget(self) -> u64 {
        self.total_token_budget
    }

    #[must_use]
    pub const fn reserved_fixed_overhead(self) -> u64 {
        self.reserved_fixed_overhead
    }

    #[must_use]
    pub const fn mandatory_packet_cost(self) -> u64 {
        self.mandatory_packet_cost
    }

    #[must_use]
    pub const fn mandatory_packet_count(self) -> u64 {
        self.mandatory_packet_count
    }
}

impl fmt::Debug for BoundedSelectorNeedsMoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedSelectorNeedsMoreV1")
            .field("reason", &self.reason)
            .field("total_token_budget", &self.total_token_budget)
            .field("reserved_fixed_overhead", &self.reserved_fixed_overhead)
            .field("mandatory_packet_cost", &self.mandatory_packet_cost)
            .field("mandatory_packet_count", &self.mandatory_packet_count)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum BoundedSelectorOutcomeV1 {
    Selected(BoundedSelectorSelectedPlanV1),
    NeedsMore(BoundedSelectorNeedsMoreV1),
}

impl BoundedSelectorOutcomeV1 {
    #[must_use]
    pub const fn selected(&self) -> Option<&BoundedSelectorSelectedPlanV1> {
        match self {
            Self::Selected(selected) => Some(selected),
            Self::NeedsMore(_) => None,
        }
    }

    #[must_use]
    pub const fn needs_more(&self) -> Option<BoundedSelectorNeedsMoreV1> {
        match self {
            Self::NeedsMore(needs_more) => Some(*needs_more),
            Self::Selected(_) => None,
        }
    }
}

impl fmt::Debug for BoundedSelectorOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selected(selected) => formatter
                .debug_tuple("BoundedSelectorOutcomeV1::Selected")
                .field(selected)
                .finish(),
            Self::NeedsMore(needs_more) => formatter
                .debug_tuple("BoundedSelectorOutcomeV1::NeedsMore")
                .field(needs_more)
                .finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct FrozenBoundedSelectorPairV1 {
    digest: ArtifactDigest,
    problem_digest: ArtifactDigest,
    challenger_identity: BoundedSelectorChallengerIdentityV1,
    mode: BoundedSelectorChallengerModeV1,
    optional_packet_count: u64,
    bounds: BoundedSelectorSearchBoundsV1,
    observation: BoundedSelectorSearchObservationV1,
    production: BoundedSelectorOutcomeV1,
    challenger: BoundedSelectorOutcomeV1,
    objective_relation: BoundedSelectorObjectiveRelationV1,
    selected_cost_relation: BoundedSelectorCostRelationV1,
    hard_constraints_preserved: bool,
}

impl FrozenBoundedSelectorPairV1 {
    #[must_use]
    pub const fn digest(&self) -> ArtifactDigest {
        self.digest
    }

    #[must_use]
    pub const fn problem_digest(&self) -> ArtifactDigest {
        self.problem_digest
    }

    #[must_use]
    pub const fn challenger_identity(&self) -> BoundedSelectorChallengerIdentityV1 {
        self.challenger_identity
    }

    #[must_use]
    pub const fn mode(&self) -> BoundedSelectorChallengerModeV1 {
        self.mode
    }

    #[must_use]
    pub const fn optional_packet_count(&self) -> u64 {
        self.optional_packet_count
    }

    #[must_use]
    pub const fn bounds(&self) -> BoundedSelectorSearchBoundsV1 {
        self.bounds
    }

    #[must_use]
    pub const fn observation(&self) -> BoundedSelectorSearchObservationV1 {
        self.observation
    }

    #[must_use]
    pub const fn production(&self) -> &BoundedSelectorOutcomeV1 {
        &self.production
    }

    #[must_use]
    pub const fn challenger(&self) -> &BoundedSelectorOutcomeV1 {
        &self.challenger
    }

    #[must_use]
    pub const fn objective_relation(&self) -> BoundedSelectorObjectiveRelationV1 {
        self.objective_relation
    }

    #[must_use]
    pub const fn selected_cost_relation(&self) -> BoundedSelectorCostRelationV1 {
        self.selected_cost_relation
    }

    #[must_use]
    pub const fn hard_constraints_preserved(&self) -> bool {
        self.hard_constraints_preserved
    }

    #[must_use]
    pub const fn contains_labels(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn claims_wall_time_or_rss(&self) -> bool {
        false
    }
}

impl fmt::Debug for FrozenBoundedSelectorPairV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenBoundedSelectorPairV1")
            .field("pair_identity_present", &true)
            .field("problem_identity_present", &true)
            .field("challenger_identity", &self.challenger_identity)
            .field("mode", &self.mode)
            .field("optional_packet_count", &self.optional_packet_count)
            .field("bounds", &self.bounds)
            .field("observation", &self.observation)
            .field("production", &self.production)
            .field("challenger", &self.challenger)
            .field("objective_relation", &self.objective_relation)
            .field("selected_cost_relation", &self.selected_cost_relation)
            .field(
                "hard_constraints_preserved",
                &self.hard_constraints_preserved,
            )
            .field("contains_labels", &false)
            .field("claims_wall_time_or_rss", &false)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BoundedSelectorChallengerErrorV1 {
    ExactOracle(ExactSelectionOracleErrorV1),
    ProductionSelection,
    ObjectiveContract,
    ArithmeticOverflow,
    ConstraintViolation,
    DigestLengthOverflow,
}

impl BoundedSelectorChallengerErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ExactOracle(_) => "EVIDENTRAIL_BENCH_BOUNDED_CHALLENGER_EXACT_ORACLE",
            Self::ProductionSelection => "EVIDENTRAIL_BENCH_BOUNDED_CHALLENGER_PRODUCTION",
            Self::ObjectiveContract => "EVIDENTRAIL_BENCH_BOUNDED_CHALLENGER_OBJECTIVE",
            Self::ArithmeticOverflow => "EVIDENTRAIL_BENCH_BOUNDED_CHALLENGER_ARITHMETIC",
            Self::ConstraintViolation => "EVIDENTRAIL_BENCH_BOUNDED_CHALLENGER_CONSTRAINT",
            Self::DigestLengthOverflow => "EVIDENTRAIL_BENCH_BOUNDED_CHALLENGER_DIGEST_LENGTH",
        }
    }
}

impl fmt::Debug for BoundedSelectorChallengerErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedSelectorChallengerErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for BoundedSelectorChallengerErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for BoundedSelectorChallengerErrorV1 {}

pub(crate) enum FrozenSelectorOutcomeFactsV1 {
    Selected {
        objective_gain_numerator: u64,
        selected_packet_ids: Vec<BoundedSelectorPacketIdV1>,
        optional_acceptance_order: Vec<BoundedSelectorPacketIdV1>,
        selected_packet_cost: u64,
        accounted_token_upper_bound: u64,
        coverage_only_token_cost: u64,
        coverage_only_token_limit: u64,
    },
    NeedsMore(BoundedSelectorNeedsMoreV1),
}

pub(crate) struct FrozenExactPairFactsV1 {
    pub(crate) problem_digest: ArtifactDigest,
    pub(crate) optional_packet_count: u64,
    pub(crate) total_token_budget: u64,
    pub(crate) mandatory_packet_ids: Vec<BoundedSelectorPacketIdV1>,
    pub(crate) reachable_subset_count: u64,
    pub(crate) production: FrozenSelectorOutcomeFactsV1,
    pub(crate) optimum: FrozenSelectorOutcomeFactsV1,
}

pub(crate) fn freeze_exact_pair_from_facts_v1(
    facts: FrozenExactPairFactsV1,
) -> Result<FrozenBoundedSelectorPairV1, BoundedSelectorChallengerErrorV1> {
    if facts.optional_packet_count
        > u64::try_from(MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1)
            .map_err(|_| BoundedSelectorChallengerErrorV1::ArithmeticOverflow)?
    {
        return Err(BoundedSelectorChallengerErrorV1::ConstraintViolation);
    }
    let production = outcome_from_frozen_facts(
        facts.production,
        BoundedSelectorPlanSourceV1::ProductionFallback,
    );
    let challenger =
        outcome_from_frozen_facts(facts.optimum, BoundedSelectorPlanSourceV1::ExactSubset);
    let state_slots = 1_u64
        .checked_shl(
            u32::try_from(facts.optional_packet_count)
                .map_err(|_| BoundedSelectorChallengerErrorV1::ArithmeticOverflow)?,
        )
        .ok_or(BoundedSelectorChallengerErrorV1::ArithmeticOverflow)?;
    let bounds = BoundedSelectorSearchBoundsV1 {
        state_slot_cap: state_slots,
        transition_attempt_cap: state_slots
            .checked_mul(facts.optional_packet_count)
            .ok_or(BoundedSelectorChallengerErrorV1::ArithmeticOverflow)?,
        depth_cap: facts.optional_packet_count,
    };
    let observation = BoundedSelectorSearchObservationV1 {
        transition_attempts: None,
        retained_state_high_water: facts.reachable_subset_count,
        transition_cap_reached: false,
    };
    let objective_relation = objective_relation(&production, &challenger);
    let selected_cost_relation = selected_cost_relation(&production, &challenger);
    let hard_constraints_preserved = validate_frozen_outcome(
        facts.total_token_budget,
        &facts.mandatory_packet_ids,
        &challenger,
    );
    if !hard_constraints_preserved
        || matches!(
            objective_relation,
            BoundedSelectorObjectiveRelationV1::ChallengerWorse
                | BoundedSelectorObjectiveRelationV1::TerminalMismatch
        )
    {
        return Err(BoundedSelectorChallengerErrorV1::ConstraintViolation);
    }
    let challenger_identity = bounded_selector_challenger_identity_v1();
    let mode = BoundedSelectorChallengerModeV1::ExactSubsets;
    let digest = derive_pair_digest(
        facts.problem_digest,
        challenger_identity,
        mode,
        facts.optional_packet_count,
        bounds,
        observation,
        &production,
        &challenger,
        objective_relation,
        selected_cost_relation,
        hard_constraints_preserved,
    )?;
    Ok(FrozenBoundedSelectorPairV1 {
        digest,
        problem_digest: facts.problem_digest,
        challenger_identity,
        mode,
        optional_packet_count: facts.optional_packet_count,
        bounds,
        observation,
        production,
        challenger,
        objective_relation,
        selected_cost_relation,
        hard_constraints_preserved,
    })
}

fn outcome_from_frozen_facts(
    facts: FrozenSelectorOutcomeFactsV1,
    source: BoundedSelectorPlanSourceV1,
) -> BoundedSelectorOutcomeV1 {
    match facts {
        FrozenSelectorOutcomeFactsV1::Selected {
            objective_gain_numerator,
            selected_packet_ids,
            optional_acceptance_order,
            selected_packet_cost,
            accounted_token_upper_bound,
            coverage_only_token_cost,
            coverage_only_token_limit,
        } => BoundedSelectorOutcomeV1::Selected(BoundedSelectorSelectedPlanV1 {
            source,
            objective_gain_numerator,
            selected_packet_ids,
            optional_acceptance_order,
            selected_packet_cost,
            accounted_token_upper_bound,
            coverage_only_token_cost,
            coverage_only_token_limit,
        }),
        FrozenSelectorOutcomeFactsV1::NeedsMore(needs_more) => {
            BoundedSelectorOutcomeV1::NeedsMore(needs_more)
        }
    }
}

fn validate_frozen_outcome(
    total_token_budget: u64,
    mandatory_packet_ids: &[BoundedSelectorPacketIdV1],
    outcome: &BoundedSelectorOutcomeV1,
) -> bool {
    match outcome {
        BoundedSelectorOutcomeV1::Selected(selected) => {
            let selected_ids = selected
                .selected_packet_ids()
                .iter()
                .collect::<BTreeSet<_>>();
            selected.accounted_token_upper_bound() <= total_token_budget
                && selected.coverage_only_token_cost() <= selected.coverage_only_token_limit()
                && mandatory_packet_ids
                    .iter()
                    .all(|packet_id| selected_ids.contains(packet_id))
        }
        BoundedSelectorOutcomeV1::NeedsMore(needs_more) => match needs_more.reason() {
            NeedsMoreReasonV1::FixedOverheadExceedsTotalBudget => {
                needs_more.reserved_fixed_overhead() > needs_more.total_token_budget()
            }
            NeedsMoreReasonV1::MandatoryCostExceedsAvailablePacketBudget => {
                needs_more.reserved_fixed_overhead() <= needs_more.total_token_budget()
                    && needs_more.mandatory_packet_cost()
                        > needs_more.total_token_budget() - needs_more.reserved_fixed_overhead()
            }
        },
    }
}

#[derive(Clone, Copy, Default)]
struct FacetCoverageV1 {
    largest: u32,
    second_largest: u32,
}

impl FacetCoverageV1 {
    fn apply(&mut self, affinity: u32) {
        if affinity >= self.largest {
            self.second_largest = self.largest;
            self.largest = affinity;
        } else if affinity > self.second_largest {
            self.second_largest = affinity;
        }
    }

    const fn threshold(self, cardinality: FacetSaturationCardinalityV1) -> u32 {
        match cardinality {
            FacetSaturationCardinalityV1::One => self.largest,
            FacetSaturationCardinalityV1::Two => self.second_largest,
        }
    }
}

#[derive(Clone)]
struct BeamStateV1 {
    selected: Vec<bool>,
    acceptance_order: Vec<usize>,
    coverage: Vec<FacetCoverageV1>,
    objective_gain: u64,
    optional_cost: u64,
    coverage_only_cost: u64,
}

struct BeamResultV1 {
    best: BeamStateV1,
    transition_attempts: u64,
    retained_state_high_water: u64,
    transition_cap_reached: bool,
}

/// Crate-internal bridge for benchmark protocols that hold the challenger to
/// an already-frozen production resource envelope. This is deliberately not
/// a runtime selector API.
pub(crate) struct CostMatchedBeamFactsV1 {
    pub(crate) bounds: BoundedSelectorSearchBoundsV1,
    pub(crate) observation: BoundedSelectorSearchObservationV1,
    pub(crate) objective_gain_numerator: u64,
    pub(crate) selected_packet_ids: Vec<PacketIdV1>,
    pub(crate) selected_packet_cost: u64,
    pub(crate) coverage_only_token_cost: u64,
}

/// Evaluate the same closed order-aware beam under a caller-independent
/// resource envelope derived from an already-frozen production selection.
/// The caller supplies only those frozen numeric caps; this helper neither
/// accepts annotations nor changes the production selector.
pub(crate) fn evaluate_cost_matched_order_aware_beam_v1(
    problem: &SelectionProblemV1,
    selected_packet_cost_cap: u64,
    coverage_only_token_cost_cap: u64,
) -> Result<CostMatchedBeamFactsV1, BoundedSelectorChallengerErrorV1> {
    if selected_packet_cost_cap < problem.mandatory_cost() {
        return Err(BoundedSelectorChallengerErrorV1::ConstraintViolation);
    }
    let mandatory_ids = problem
        .mandatory()
        .iter()
        .map(|entry| entry.packet_id())
        .collect::<BTreeSet<_>>();
    let optional_packets = problem
        .packets()
        .iter()
        .filter(|packet| !mandatory_ids.contains(&packet.id()))
        .collect::<Vec<_>>();
    let optional_budget = selected_packet_cost_cap - problem.mandatory_cost();
    let beam = evaluate_order_aware_beam_with_limits(
        problem,
        &optional_packets,
        optional_budget,
        coverage_only_token_cost_cap,
    )?;
    let optional_acceptance_order = beam
        .best
        .acceptance_order
        .iter()
        .map(|index| optional_packets[*index].id())
        .collect::<Vec<_>>();
    let objective_gain = problem
        .normalized_gain(optional_acceptance_order.iter().copied())
        .map_err(|_| BoundedSelectorChallengerErrorV1::ObjectiveContract)?;
    if objective_gain.numerator() != beam.best.objective_gain {
        return Err(BoundedSelectorChallengerErrorV1::ObjectiveContract);
    }
    let selected_packet_cost = problem
        .mandatory_cost()
        .checked_add(beam.best.optional_cost)
        .ok_or(BoundedSelectorChallengerErrorV1::ArithmeticOverflow)?;
    if selected_packet_cost > selected_packet_cost_cap
        || beam.best.coverage_only_cost > coverage_only_token_cost_cap
    {
        return Err(BoundedSelectorChallengerErrorV1::ConstraintViolation);
    }
    let mut selected_packet_ids = problem
        .mandatory()
        .iter()
        .map(|entry| entry.packet_id())
        .collect::<Vec<_>>();
    selected_packet_ids.extend(optional_acceptance_order.iter().copied());
    let depth_cap = optional_packets
        .len()
        .min(BOUNDED_SELECTOR_CHALLENGER_MAX_DEPTH_V1);
    Ok(CostMatchedBeamFactsV1 {
        bounds: BoundedSelectorSearchBoundsV1 {
            state_slot_cap: checked_u64(
                BOUNDED_SELECTOR_CHALLENGER_BEAM_WIDTH_V1
                    .checked_mul(2)
                    .and_then(|value| value.checked_add(1))
                    .ok_or(BoundedSelectorChallengerErrorV1::ArithmeticOverflow)?,
            )?,
            transition_attempt_cap: BOUNDED_SELECTOR_CHALLENGER_TRANSITION_CAP_V1,
            depth_cap: checked_u64(depth_cap)?,
        },
        observation: BoundedSelectorSearchObservationV1 {
            transition_attempts: Some(beam.transition_attempts),
            retained_state_high_water: beam.retained_state_high_water,
            transition_cap_reached: beam.transition_cap_reached,
        },
        objective_gain_numerator: beam.best.objective_gain,
        selected_packet_ids,
        selected_packet_cost,
        coverage_only_token_cost: beam.best.coverage_only_cost,
    })
}

pub fn evaluate_bounded_selector_challenger_v1(
    problem: &SelectionProblemV1,
) -> Result<FrozenBoundedSelectorPairV1, BoundedSelectorChallengerErrorV1> {
    let production_decision = problem
        .select()
        .map_err(|_| BoundedSelectorChallengerErrorV1::ProductionSelection)?;
    let production = production_outcome(&production_decision)?;
    let mandatory_ids = problem
        .mandatory()
        .iter()
        .map(|entry| entry.packet_id())
        .collect::<BTreeSet<_>>();
    let optional_packets = problem
        .packets()
        .iter()
        .filter(|packet| !mandatory_ids.contains(&packet.id()))
        .collect::<Vec<_>>();
    let optional_packet_count = checked_u64(optional_packets.len())?;

    let (mode, bounds, observation, challenger) = if optional_packets.len()
        <= MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1
    {
        let state_slots = 1_u64
            .checked_shl(
                u32::try_from(optional_packets.len())
                    .map_err(|_| BoundedSelectorChallengerErrorV1::ArithmeticOverflow)?,
            )
            .ok_or(BoundedSelectorChallengerErrorV1::ArithmeticOverflow)?;
        let transition_bound = state_slots
            .checked_mul(optional_packet_count)
            .ok_or(BoundedSelectorChallengerErrorV1::ArithmeticOverflow)?;
        let exact = evaluate_exact_small_selection_oracle_v1(problem)
            .map_err(BoundedSelectorChallengerErrorV1::ExactOracle)?;
        let (outcome, retained_state_high_water) = exact_outcome(exact)?;
        (
            BoundedSelectorChallengerModeV1::ExactSubsets,
            BoundedSelectorSearchBoundsV1 {
                state_slot_cap: state_slots,
                transition_attempt_cap: transition_bound,
                depth_cap: optional_packet_count,
            },
            BoundedSelectorSearchObservationV1 {
                transition_attempts: None,
                retained_state_high_water,
                transition_cap_reached: false,
            },
            outcome,
        )
    } else {
        let depth_cap = optional_packets
            .len()
            .min(BOUNDED_SELECTOR_CHALLENGER_MAX_DEPTH_V1);
        let beam = evaluate_order_aware_beam(problem, &optional_packets)?;
        let beam_outcome = beam_outcome(problem, &optional_packets, &mandatory_ids, &beam.best)?;
        let challenger = choose_beam_or_production(beam_outcome, production.clone());
        (
            BoundedSelectorChallengerModeV1::OrderAwareBeam,
            BoundedSelectorSearchBoundsV1 {
                state_slot_cap: checked_u64(
                    BOUNDED_SELECTOR_CHALLENGER_BEAM_WIDTH_V1
                        .checked_mul(2)
                        .and_then(|value| value.checked_add(1))
                        .ok_or(BoundedSelectorChallengerErrorV1::ArithmeticOverflow)?,
                )?,
                transition_attempt_cap: BOUNDED_SELECTOR_CHALLENGER_TRANSITION_CAP_V1,
                depth_cap: checked_u64(depth_cap)?,
            },
            BoundedSelectorSearchObservationV1 {
                transition_attempts: Some(beam.transition_attempts),
                retained_state_high_water: beam.retained_state_high_water,
                transition_cap_reached: beam.transition_cap_reached,
            },
            challenger,
        )
    };

    let objective_relation = objective_relation(&production, &challenger);
    let selected_cost_relation = selected_cost_relation(&production, &challenger);
    let hard_constraints_preserved = validate_outcome(problem, &challenger).is_ok();
    if !hard_constraints_preserved
        || matches!(
            objective_relation,
            BoundedSelectorObjectiveRelationV1::ChallengerWorse
                | BoundedSelectorObjectiveRelationV1::TerminalMismatch
        )
    {
        return Err(BoundedSelectorChallengerErrorV1::ConstraintViolation);
    }
    let problem_digest = derive_selection_problem_digest_v1(problem)?;
    let challenger_identity = bounded_selector_challenger_identity_v1();
    let digest = derive_pair_digest(
        problem_digest,
        challenger_identity,
        mode,
        optional_packet_count,
        bounds,
        observation,
        &production,
        &challenger,
        objective_relation,
        selected_cost_relation,
        hard_constraints_preserved,
    )?;
    Ok(FrozenBoundedSelectorPairV1 {
        digest,
        problem_digest,
        challenger_identity,
        mode,
        optional_packet_count,
        bounds,
        observation,
        production,
        challenger,
        objective_relation,
        selected_cost_relation,
        hard_constraints_preserved,
    })
}

fn exact_outcome(
    exact: ExactSmallSelectionOracleDecisionV1,
) -> Result<(BoundedSelectorOutcomeV1, u64), BoundedSelectorChallengerErrorV1> {
    match exact {
        ExactSmallSelectionOracleDecisionV1::Optimal(plan) => {
            let selected = BoundedSelectorSelectedPlanV1 {
                source: BoundedSelectorPlanSourceV1::ExactSubset,
                objective_gain_numerator: plan.objective_gain().numerator(),
                selected_packet_ids: plan
                    .selected_packet_ids()
                    .iter()
                    .copied()
                    .map(Into::into)
                    .collect(),
                optional_acceptance_order: plan
                    .optional_acceptance_order()
                    .iter()
                    .copied()
                    .map(Into::into)
                    .collect(),
                selected_packet_cost: plan.selected_packet_cost(),
                accounted_token_upper_bound: plan.accounted_token_upper_bound(),
                coverage_only_token_cost: plan.coverage_only_token_cost(),
                coverage_only_token_limit: plan.coverage_only_token_limit(),
            };
            Ok((
                BoundedSelectorOutcomeV1::Selected(selected),
                plan.reachable_subset_count(),
            ))
        }
        ExactSmallSelectionOracleDecisionV1::NeedsMore(needs_more) => Ok((
            BoundedSelectorOutcomeV1::NeedsMore(BoundedSelectorNeedsMoreV1 {
                reason: needs_more.reason(),
                total_token_budget: needs_more.total_token_budget(),
                reserved_fixed_overhead: needs_more.reserved_fixed_overhead(),
                mandatory_packet_cost: needs_more.mandatory_packet_cost(),
                mandatory_packet_count: needs_more.mandatory_packet_count(),
            }),
            1,
        )),
    }
}

fn production_outcome(
    decision: &SelectionDecisionV1,
) -> Result<BoundedSelectorOutcomeV1, BoundedSelectorChallengerErrorV1> {
    match decision {
        SelectionDecisionV1::Selected(selection) => Ok(BoundedSelectorOutcomeV1::Selected(
            BoundedSelectorSelectedPlanV1 {
                source: BoundedSelectorPlanSourceV1::ProductionFallback,
                objective_gain_numerator: selection.normalized_gain().numerator(),
                selected_packet_ids: selection
                    .packets()
                    .iter()
                    .map(|packet| packet.packet().id().into())
                    .collect(),
                // Production V1 exposes presentation order, not the internal
                // greedy acceptance order. Do not relabel it as acceptance.
                optional_acceptance_order: Vec::new(),
                selected_packet_cost: selection.selected_packet_cost(),
                accounted_token_upper_bound: selection.accounted_token_upper_bound(),
                coverage_only_token_cost: selection.coverage_only_token_cost(),
                coverage_only_token_limit: selection.coverage_only_token_limit(),
            },
        )),
        SelectionDecisionV1::NeedsMore(needs_more) => Ok(BoundedSelectorOutcomeV1::NeedsMore(
            BoundedSelectorNeedsMoreV1 {
                reason: needs_more.reason(),
                total_token_budget: needs_more.total_token_budget().tokens(),
                reserved_fixed_overhead: needs_more.reserved_fixed_overhead(),
                mandatory_packet_cost: needs_more.mandatory_cost(),
                mandatory_packet_count: checked_u64(needs_more.mandatory_packet_count())?,
            },
        )),
    }
}

fn evaluate_order_aware_beam(
    problem: &SelectionProblemV1,
    optional_packets: &[&IntactPacketV1],
) -> Result<BeamResultV1, BoundedSelectorChallengerErrorV1> {
    let fixed = problem.reserved_fixed_overhead().upper_bound_tokens();
    let total = problem.total_token_budget().tokens();
    if fixed > total || problem.mandatory_cost() > total - fixed {
        let facet_positions = problem
            .facets()
            .iter()
            .enumerate()
            .map(|(index, facet)| (facet.id(), index))
            .collect::<BTreeMap<_, _>>();
        let packet_by_id = problem
            .packets()
            .iter()
            .map(|packet| (packet.id(), packet))
            .collect::<BTreeMap<_, _>>();
        let mut baseline_coverage = vec![FacetCoverageV1::default(); problem.facets().len()];
        for mandatory in problem.mandatory() {
            let packet = packet_by_id
                .get(&mandatory.packet_id())
                .copied()
                .ok_or(BoundedSelectorChallengerErrorV1::ObjectiveContract)?;
            apply_packet(&mut baseline_coverage, packet, &facet_positions)?;
        }
        return Ok(BeamResultV1 {
            best: BeamStateV1 {
                selected: vec![false; optional_packets.len()],
                acceptance_order: Vec::new(),
                coverage: baseline_coverage,
                objective_gain: 0,
                optional_cost: 0,
                coverage_only_cost: 0,
            },
            transition_attempts: 0,
            retained_state_high_water: 1,
            transition_cap_reached: false,
        });
    }
    let optional_budget = total - fixed - problem.mandatory_cost();
    let coverage_limit = optional_budget / COVERAGE_ONLY_OPTIONAL_BUDGET_DENOMINATOR_V1;
    evaluate_order_aware_beam_with_limits(
        problem,
        optional_packets,
        optional_budget,
        coverage_limit,
    )
}

fn evaluate_order_aware_beam_with_limits(
    problem: &SelectionProblemV1,
    optional_packets: &[&IntactPacketV1],
    optional_budget: u64,
    coverage_limit: u64,
) -> Result<BeamResultV1, BoundedSelectorChallengerErrorV1> {
    let facet_positions = problem
        .facets()
        .iter()
        .enumerate()
        .map(|(index, facet)| (facet.id(), index))
        .collect::<BTreeMap<_, _>>();
    let packet_by_id = problem
        .packets()
        .iter()
        .map(|packet| (packet.id(), packet))
        .collect::<BTreeMap<_, _>>();
    let mut baseline_coverage = vec![FacetCoverageV1::default(); problem.facets().len()];
    for mandatory in problem.mandatory() {
        let packet = packet_by_id
            .get(&mandatory.packet_id())
            .copied()
            .ok_or(BoundedSelectorChallengerErrorV1::ObjectiveContract)?;
        apply_packet(&mut baseline_coverage, packet, &facet_positions)?;
    }
    let initial = BeamStateV1 {
        selected: vec![false; optional_packets.len()],
        acceptance_order: Vec::new(),
        coverage: baseline_coverage,
        objective_gain: 0,
        optional_cost: 0,
        coverage_only_cost: 0,
    };
    let mut best = initial.clone();
    let mut frontier = vec![initial];
    let mut transition_attempts = 0_u64;
    let mut retained_state_high_water = 1_u64;
    let mut transition_cap_reached = false;
    let depth_cap = optional_packets
        .len()
        .min(BOUNDED_SELECTOR_CHALLENGER_MAX_DEPTH_V1);

    'depths: for _ in 0..depth_cap {
        let mut next = Vec::new();
        for state in &frontier {
            for (optional_index, packet) in optional_packets.iter().enumerate() {
                if state.selected[optional_index] {
                    continue;
                }
                if transition_attempts == BOUNDED_SELECTOR_CHALLENGER_TRANSITION_CAP_V1 {
                    transition_cap_reached = true;
                    break 'depths;
                }
                transition_attempts = transition_attempts
                    .checked_add(1)
                    .ok_or(BoundedSelectorChallengerErrorV1::ArithmeticOverflow)?;
                let packet_cost = packet.composable_token_upper_bound().upper_bound_tokens();
                let Some(next_cost) = state.optional_cost.checked_add(packet_cost) else {
                    return Err(BoundedSelectorChallengerErrorV1::ArithmeticOverflow);
                };
                if next_cost > optional_budget {
                    continue;
                }
                let (gain, coverage_only) =
                    marginal_score(problem, &facet_positions, &state.coverage, packet)?;
                if gain == 0 {
                    continue;
                }
                let next_coverage_cost = if coverage_only {
                    state
                        .coverage_only_cost
                        .checked_add(packet_cost)
                        .ok_or(BoundedSelectorChallengerErrorV1::ArithmeticOverflow)?
                } else {
                    state.coverage_only_cost
                };
                if next_coverage_cost > coverage_limit {
                    continue;
                }
                let mut candidate = state.clone();
                candidate.selected[optional_index] = true;
                candidate.acceptance_order.push(optional_index);
                candidate.optional_cost = next_cost;
                candidate.coverage_only_cost = next_coverage_cost;
                candidate.objective_gain = candidate
                    .objective_gain
                    .checked_add(gain)
                    .ok_or(BoundedSelectorChallengerErrorV1::ArithmeticOverflow)?;
                apply_packet(&mut candidate.coverage, packet, &facet_positions)?;
                if beam_state_is_better(&candidate, &best) {
                    best = candidate.clone();
                }
                insert_bounded_beam_state(&mut next, candidate);
                retained_state_high_water = retained_state_high_water.max(checked_u64(
                    frontier
                        .len()
                        .checked_add(next.len())
                        .ok_or(BoundedSelectorChallengerErrorV1::ArithmeticOverflow)?,
                )?);
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    Ok(BeamResultV1 {
        best,
        transition_attempts,
        retained_state_high_water,
        transition_cap_reached,
    })
}

fn insert_bounded_beam_state(states: &mut Vec<BeamStateV1>, candidate: BeamStateV1) {
    if let Some(position) = states
        .iter()
        .position(|current| current.selected == candidate.selected)
    {
        if canonical_same_set_state_is_better(&candidate, &states[position]) {
            states[position] = candidate;
        }
    } else {
        states.push(candidate);
    }
    states.sort_by(beam_state_ordering);
    states.truncate(BOUNDED_SELECTOR_CHALLENGER_BEAM_WIDTH_V1);
}

fn canonical_same_set_state_is_better(candidate: &BeamStateV1, current: &BeamStateV1) -> bool {
    candidate
        .coverage_only_cost
        .cmp(&current.coverage_only_cost)
        .then_with(|| candidate.acceptance_order.cmp(&current.acceptance_order))
        == Ordering::Less
}

fn beam_state_ordering(left: &BeamStateV1, right: &BeamStateV1) -> Ordering {
    right
        .objective_gain
        .cmp(&left.objective_gain)
        .then_with(|| left.optional_cost.cmp(&right.optional_cost))
        .then_with(|| left.coverage_only_cost.cmp(&right.coverage_only_cost))
        .then_with(|| {
            left.acceptance_order
                .len()
                .cmp(&right.acceptance_order.len())
        })
        .then_with(|| left.acceptance_order.cmp(&right.acceptance_order))
}

fn beam_state_is_better(candidate: &BeamStateV1, current: &BeamStateV1) -> bool {
    beam_state_ordering(candidate, current) == Ordering::Less
}

fn beam_outcome(
    problem: &SelectionProblemV1,
    optional_packets: &[&IntactPacketV1],
    mandatory_ids: &BTreeSet<PacketIdV1>,
    state: &BeamStateV1,
) -> Result<BoundedSelectorOutcomeV1, BoundedSelectorChallengerErrorV1> {
    let fixed = problem.reserved_fixed_overhead().upper_bound_tokens();
    let total = problem.total_token_budget().tokens();
    if fixed > total {
        return Ok(BoundedSelectorOutcomeV1::NeedsMore(
            BoundedSelectorNeedsMoreV1 {
                reason: NeedsMoreReasonV1::FixedOverheadExceedsTotalBudget,
                total_token_budget: total,
                reserved_fixed_overhead: fixed,
                mandatory_packet_cost: problem.mandatory_cost(),
                mandatory_packet_count: checked_u64(mandatory_ids.len())?,
            },
        ));
    }
    if problem.mandatory_cost() > total - fixed {
        return Ok(BoundedSelectorOutcomeV1::NeedsMore(
            BoundedSelectorNeedsMoreV1 {
                reason: NeedsMoreReasonV1::MandatoryCostExceedsAvailablePacketBudget,
                total_token_budget: total,
                reserved_fixed_overhead: fixed,
                mandatory_packet_cost: problem.mandatory_cost(),
                mandatory_packet_count: checked_u64(mandatory_ids.len())?,
            },
        ));
    }
    let mut selected_packet_ids = problem
        .mandatory()
        .iter()
        .map(|entry| entry.packet_id().into())
        .collect::<Vec<_>>();
    let optional_acceptance_order = state
        .acceptance_order
        .iter()
        .map(|index| BoundedSelectorPacketIdV1::from(optional_packets[*index].id()))
        .collect::<Vec<_>>();
    let verified_gain = problem
        .normalized_gain(
            state
                .acceptance_order
                .iter()
                .map(|index| optional_packets[*index].id()),
        )
        .map_err(|_| BoundedSelectorChallengerErrorV1::ObjectiveContract)?;
    if verified_gain.numerator() != state.objective_gain {
        return Err(BoundedSelectorChallengerErrorV1::ObjectiveContract);
    }
    selected_packet_ids.extend(optional_acceptance_order.iter().copied());
    let selected_packet_cost = problem
        .mandatory_cost()
        .checked_add(state.optional_cost)
        .ok_or(BoundedSelectorChallengerErrorV1::ArithmeticOverflow)?;
    let accounted_token_upper_bound = fixed
        .checked_add(selected_packet_cost)
        .ok_or(BoundedSelectorChallengerErrorV1::ArithmeticOverflow)?;
    Ok(BoundedSelectorOutcomeV1::Selected(
        BoundedSelectorSelectedPlanV1 {
            source: BoundedSelectorPlanSourceV1::OrderAwareBeam,
            objective_gain_numerator: state.objective_gain,
            selected_packet_ids,
            optional_acceptance_order,
            selected_packet_cost,
            accounted_token_upper_bound,
            coverage_only_token_cost: state.coverage_only_cost,
            coverage_only_token_limit: (total - fixed - problem.mandatory_cost())
                / COVERAGE_ONLY_OPTIONAL_BUDGET_DENOMINATOR_V1,
        },
    ))
}

fn choose_beam_or_production(
    beam: BoundedSelectorOutcomeV1,
    production: BoundedSelectorOutcomeV1,
) -> BoundedSelectorOutcomeV1 {
    match (&beam, &production) {
        (
            BoundedSelectorOutcomeV1::Selected(beam_plan),
            BoundedSelectorOutcomeV1::Selected(production_plan),
        ) if selected_plan_is_better(beam_plan, production_plan) => beam,
        (BoundedSelectorOutcomeV1::Selected(_), BoundedSelectorOutcomeV1::Selected(_)) => {
            production
        }
        (BoundedSelectorOutcomeV1::NeedsMore(_), BoundedSelectorOutcomeV1::NeedsMore(_)) => {
            production
        }
        _ => production,
    }
}

fn selected_plan_is_better(
    candidate: &BoundedSelectorSelectedPlanV1,
    current: &BoundedSelectorSelectedPlanV1,
) -> bool {
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

fn objective_relation(
    production: &BoundedSelectorOutcomeV1,
    challenger: &BoundedSelectorOutcomeV1,
) -> BoundedSelectorObjectiveRelationV1 {
    match (production, challenger) {
        (BoundedSelectorOutcomeV1::Selected(left), BoundedSelectorOutcomeV1::Selected(right)) => {
            match right
                .objective_gain_numerator()
                .cmp(&left.objective_gain_numerator())
            {
                Ordering::Greater => BoundedSelectorObjectiveRelationV1::ChallengerBetter,
                Ordering::Equal => BoundedSelectorObjectiveRelationV1::Equal,
                Ordering::Less => BoundedSelectorObjectiveRelationV1::ChallengerWorse,
            }
        }
        (BoundedSelectorOutcomeV1::NeedsMore(left), BoundedSelectorOutcomeV1::NeedsMore(right))
            if left.reason() == right.reason() =>
        {
            BoundedSelectorObjectiveRelationV1::MatchedTerminal
        }
        _ => BoundedSelectorObjectiveRelationV1::TerminalMismatch,
    }
}

fn selected_cost_relation(
    production: &BoundedSelectorOutcomeV1,
    challenger: &BoundedSelectorOutcomeV1,
) -> BoundedSelectorCostRelationV1 {
    match (production, challenger) {
        (BoundedSelectorOutcomeV1::Selected(left), BoundedSelectorOutcomeV1::Selected(right)) => {
            match right
                .selected_packet_cost()
                .cmp(&left.selected_packet_cost())
            {
                Ordering::Less => BoundedSelectorCostRelationV1::ChallengerLower,
                Ordering::Equal => BoundedSelectorCostRelationV1::Equal,
                Ordering::Greater => BoundedSelectorCostRelationV1::ChallengerHigher,
            }
        }
        _ => BoundedSelectorCostRelationV1::NotApplicable,
    }
}

fn validate_outcome(
    problem: &SelectionProblemV1,
    outcome: &BoundedSelectorOutcomeV1,
) -> Result<(), BoundedSelectorChallengerErrorV1> {
    match outcome {
        BoundedSelectorOutcomeV1::Selected(selected) => {
            if selected.accounted_token_upper_bound() > problem.total_token_budget().tokens()
                || selected.coverage_only_token_cost() > selected.coverage_only_token_limit()
            {
                return Err(BoundedSelectorChallengerErrorV1::ConstraintViolation);
            }
            let selected_ids = selected
                .selected_packet_ids()
                .iter()
                .map(BoundedSelectorPacketIdV1::as_bytes)
                .collect::<BTreeSet<_>>();
            if problem
                .mandatory()
                .iter()
                .any(|entry| !selected_ids.contains(entry.packet_id().as_bytes()))
            {
                return Err(BoundedSelectorChallengerErrorV1::ConstraintViolation);
            }
        }
        BoundedSelectorOutcomeV1::NeedsMore(needs_more) => match needs_more.reason() {
            NeedsMoreReasonV1::FixedOverheadExceedsTotalBudget
                if needs_more.reserved_fixed_overhead() <= needs_more.total_token_budget() =>
            {
                return Err(BoundedSelectorChallengerErrorV1::ConstraintViolation);
            }
            NeedsMoreReasonV1::MandatoryCostExceedsAvailablePacketBudget
                if needs_more.reserved_fixed_overhead() > needs_more.total_token_budget()
                    || needs_more.mandatory_packet_cost()
                        <= needs_more.total_token_budget()
                            - needs_more.reserved_fixed_overhead() =>
            {
                return Err(BoundedSelectorChallengerErrorV1::ConstraintViolation);
            }
            _ => {}
        },
    }
    Ok(())
}

fn apply_packet(
    coverage: &mut [FacetCoverageV1],
    packet: &IntactPacketV1,
    facet_positions: &BTreeMap<FacetIdV1, usize>,
) -> Result<(), BoundedSelectorChallengerErrorV1> {
    for affinity in packet.affinities() {
        let position = facet_positions
            .get(&affinity.facet_id())
            .copied()
            .ok_or(BoundedSelectorChallengerErrorV1::ObjectiveContract)?;
        coverage[position].apply(affinity.affinity().micros());
    }
    Ok(())
}

fn marginal_score(
    problem: &SelectionProblemV1,
    facet_positions: &BTreeMap<FacetIdV1, usize>,
    coverage: &[FacetCoverageV1],
    packet: &IntactPacketV1,
) -> Result<(u64, bool), BoundedSelectorChallengerErrorV1> {
    let mut gain = 0_u64;
    let mut has_primary_gain = false;
    for affinity in packet.affinities() {
        let position = facet_positions
            .get(&affinity.facet_id())
            .copied()
            .ok_or(BoundedSelectorChallengerErrorV1::ObjectiveContract)?;
        let facet = problem
            .facets()
            .get(position)
            .ok_or(BoundedSelectorChallengerErrorV1::ObjectiveContract)?;
        let threshold = coverage[position].threshold(facet.kind().saturation_cardinality());
        let delta = affinity.affinity().micros().saturating_sub(threshold);
        let contribution = u64::from(facet.weight().micros())
            .checked_mul(u64::from(delta))
            .ok_or(BoundedSelectorChallengerErrorV1::ArithmeticOverflow)?;
        gain = gain
            .checked_add(contribution)
            .ok_or(BoundedSelectorChallengerErrorV1::ArithmeticOverflow)?;
        if contribution > 0 && !facet.kind().is_coverage_only() {
            has_primary_gain = true;
        }
    }
    Ok((gain, gain > 0 && !has_primary_gain))
}

pub(crate) fn derive_selection_problem_digest_v1(
    problem: &SelectionProblemV1,
) -> Result<ArtifactDigest, BoundedSelectorChallengerErrorV1> {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, PROBLEM_DOMAIN_V1)?;
    hash_field(&mut hasher, SELECTION_OBJECTIVE_POLICY_NAME_V1)?;
    hash_field(&mut hasher, SELECTION_OBJECTIVE_POLICY_VERSION_V1)?;
    hash_u64(&mut hasher, COVERAGE_ONLY_OPTIONAL_BUDGET_DENOMINATOR_V1);
    hash_u64(&mut hasher, problem.total_token_budget().tokens());
    hash_field(
        &mut hasher,
        problem
            .reserved_fixed_overhead()
            .cost_model()
            .artifact_digest()
            .as_bytes(),
    )?;
    hash_u64(
        &mut hasher,
        problem.reserved_fixed_overhead().upper_bound_tokens(),
    );
    hash_u64(&mut hasher, checked_u64(problem.facets().len())?);
    for facet in problem.facets() {
        hash_field(&mut hasher, facet.id().as_bytes())?;
        hash_field(&mut hasher, facet.kind().code().as_bytes())?;
        hash_u32(&mut hasher, facet.weight().micros());
        hash_field(
            &mut hasher,
            facet.kind().saturation_cardinality().code().as_bytes(),
        )?;
    }
    hash_u64(&mut hasher, checked_u64(problem.packets().len())?);
    for packet in problem.packets() {
        hash_field(&mut hasher, packet.id().as_bytes())?;
        hash_u64(&mut hasher, checked_u64(packet.event_ids().len())?);
        for event_id in packet.event_ids() {
            hash_field(&mut hasher, event_id.as_bytes())?;
        }
        hash_field(
            &mut hasher,
            packet
                .composable_token_upper_bound()
                .cost_model()
                .artifact_digest()
                .as_bytes(),
        )?;
        hash_u64(
            &mut hasher,
            packet.composable_token_upper_bound().upper_bound_tokens(),
        );
        hash_u64(&mut hasher, checked_u64(packet.affinities().len())?);
        for affinity in packet.affinities() {
            hash_field(&mut hasher, affinity.facet_id().as_bytes())?;
            hash_u32(&mut hasher, affinity.affinity().micros());
        }
    }
    hash_u64(&mut hasher, checked_u64(problem.mandatory().len())?);
    for mandatory in problem.mandatory() {
        hash_field(&mut hasher, mandatory.packet_id().as_bytes())?;
        hash_field(
            &mut hasher,
            mandatory.validated_identifier_facet_id().as_bytes(),
        )?;
    }
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

#[allow(clippy::too_many_arguments)]
fn derive_pair_digest(
    problem_digest: ArtifactDigest,
    identity: BoundedSelectorChallengerIdentityV1,
    mode: BoundedSelectorChallengerModeV1,
    optional_packet_count: u64,
    bounds: BoundedSelectorSearchBoundsV1,
    observation: BoundedSelectorSearchObservationV1,
    production: &BoundedSelectorOutcomeV1,
    challenger: &BoundedSelectorOutcomeV1,
    objective_relation: BoundedSelectorObjectiveRelationV1,
    cost_relation: BoundedSelectorCostRelationV1,
    hard_constraints_preserved: bool,
) -> Result<ArtifactDigest, BoundedSelectorChallengerErrorV1> {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, CHALLENGER_DOMAIN_V1)?;
    hash_field(&mut hasher, problem_digest.as_bytes())?;
    hash_field(&mut hasher, identity.digest().as_bytes())?;
    hash_field(&mut hasher, mode.code().as_bytes())?;
    hash_u64(&mut hasher, optional_packet_count);
    for value in [
        bounds.state_slot_cap(),
        bounds.transition_attempt_cap(),
        bounds.depth_cap(),
    ] {
        hash_u64(&mut hasher, value);
    }
    match observation.transition_attempts() {
        Some(value) => {
            hasher.update([1]);
            hash_u64(&mut hasher, value);
        }
        None => hasher.update([0]),
    }
    hash_u64(&mut hasher, observation.retained_state_high_water());
    hasher.update([u8::from(observation.transition_cap_reached())]);
    hash_outcome(&mut hasher, production)?;
    hash_outcome(&mut hasher, challenger)?;
    hash_field(
        &mut hasher,
        objective_relation_code(objective_relation).as_bytes(),
    )?;
    hash_field(&mut hasher, cost_relation_code(cost_relation).as_bytes())?;
    hasher.update([u8::from(hard_constraints_preserved)]);
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

fn hash_outcome(
    hasher: &mut Sha256,
    outcome: &BoundedSelectorOutcomeV1,
) -> Result<(), BoundedSelectorChallengerErrorV1> {
    match outcome {
        BoundedSelectorOutcomeV1::Selected(selected) => {
            hasher.update([0]);
            hash_field(hasher, selected.source().code().as_bytes())?;
            hash_u64(hasher, selected.objective_gain_numerator());
            hash_packet_ids(hasher, selected.selected_packet_ids())?;
            hash_packet_ids(hasher, selected.optional_acceptance_order())?;
            hash_u64(hasher, selected.selected_packet_cost());
            hash_u64(hasher, selected.accounted_token_upper_bound());
            hash_u64(hasher, selected.coverage_only_token_cost());
            hash_u64(hasher, selected.coverage_only_token_limit());
        }
        BoundedSelectorOutcomeV1::NeedsMore(needs_more) => {
            hasher.update([1]);
            hash_field(hasher, needs_more.reason().code().as_bytes())?;
            hash_u64(hasher, needs_more.total_token_budget());
            hash_u64(hasher, needs_more.reserved_fixed_overhead());
            hash_u64(hasher, needs_more.mandatory_packet_cost());
            hash_u64(hasher, needs_more.mandatory_packet_count());
        }
    }
    Ok(())
}

fn hash_packet_ids(
    hasher: &mut Sha256,
    packet_ids: &[BoundedSelectorPacketIdV1],
) -> Result<(), BoundedSelectorChallengerErrorV1> {
    hash_u64(hasher, checked_u64(packet_ids.len())?);
    for packet_id in packet_ids {
        hash_field(hasher, packet_id.as_bytes())?;
    }
    Ok(())
}

const fn objective_relation_code(relation: BoundedSelectorObjectiveRelationV1) -> &'static str {
    match relation {
        BoundedSelectorObjectiveRelationV1::ChallengerBetter => "challenger_better",
        BoundedSelectorObjectiveRelationV1::Equal => "equal",
        BoundedSelectorObjectiveRelationV1::ChallengerWorse => "challenger_worse",
        BoundedSelectorObjectiveRelationV1::MatchedTerminal => "matched_terminal",
        BoundedSelectorObjectiveRelationV1::TerminalMismatch => "terminal_mismatch",
    }
}

const fn cost_relation_code(relation: BoundedSelectorCostRelationV1) -> &'static str {
    match relation {
        BoundedSelectorCostRelationV1::ChallengerLower => "challenger_lower",
        BoundedSelectorCostRelationV1::Equal => "equal",
        BoundedSelectorCostRelationV1::ChallengerHigher => "challenger_higher",
        BoundedSelectorCostRelationV1::NotApplicable => "not_applicable",
    }
}

fn hash_static_field(hasher: &mut Sha256, bytes: &'static [u8]) {
    hasher.update(
        u64::try_from(bytes.len())
            .expect("closed static identity length fits u64")
            .to_le_bytes(),
    );
    hasher.update(bytes);
}

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) -> Result<(), BoundedSelectorChallengerErrorV1> {
    hash_u64(hasher, checked_u64(bytes.len())?);
    hasher.update(bytes);
    Ok(())
}

fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

fn hash_u32(hasher: &mut Sha256, value: u32) {
    hasher.update(value.to_le_bytes());
}

fn checked_u64(value: usize) -> Result<u64, BoundedSelectorChallengerErrorV1> {
    u64::try_from(value).map_err(|_| BoundedSelectorChallengerErrorV1::DigestLengthOverflow)
}
