use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;

use evidentrail_select::{
    COVERAGE_ONLY_OPTIONAL_BUDGET_DENOMINATOR_V1, FacetIdV1, FacetSaturationCardinalityV1,
    IntactPacketV1, NeedsMoreReasonV1, ObjectiveGainV1, PacketIdV1,
    SELECTION_OBJECTIVE_POLICY_NAME_V1, SELECTION_OBJECTIVE_POLICY_VERSION_V1, SelectionDecisionV1,
    SelectionProblemV1, SelectionStrategyV1,
};

/// Exact-search bound for the optional packet universe. Mandatory packets do
/// not count toward this cap because they are fixed before optimization.
pub const MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1: usize = 12;
/// Benchmark-only oracle identity. This is not a production selector policy.
pub const EXACT_SELECTION_ORACLE_POLICY_NAME_V1: &[u8] =
    b"evidentrail/bench/exact-small-production-selection-oracle";
/// V1 uses subset dynamic programming with canonical minimum-charge orders.
pub const EXACT_SELECTION_ORACLE_POLICY_VERSION_V1: &[u8] = b"2";
/// Frozen deterministic optimum tie order.
pub const EXACT_SELECTION_ORACLE_TIE_BREAK_V1: &str = "gain_desc,total_packet_cost_asc,coverage_charge_asc,optional_count_asc,canonical_acceptance_order_asc";

/// Stable, contentless failure from bounded exact evaluation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ExactSelectionOracleErrorV1 {
    TooManyOptionalPackets,
    ObjectiveEvaluationFailure,
    ObjectiveContractMismatch,
    ArithmeticOverflow,
    ProductionSelectionFailure,
    ProductionDecisionMismatch,
    ProductionGainExceedsOptimum,
}

impl ExactSelectionOracleErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TooManyOptionalPackets => "EVIDENTRAIL_BENCH_EXACT_ORACLE_OPTIONAL_PACKET_CAP",
            Self::ObjectiveEvaluationFailure => {
                "EVIDENTRAIL_BENCH_EXACT_ORACLE_OBJECTIVE_EVALUATION"
            }
            Self::ObjectiveContractMismatch => "EVIDENTRAIL_BENCH_EXACT_ORACLE_OBJECTIVE_MISMATCH",
            Self::ArithmeticOverflow => "EVIDENTRAIL_BENCH_EXACT_ORACLE_ARITHMETIC_OVERFLOW",
            Self::ProductionSelectionFailure => "EVIDENTRAIL_BENCH_EXACT_ORACLE_PRODUCTION_FAILURE",
            Self::ProductionDecisionMismatch => "EVIDENTRAIL_BENCH_EXACT_ORACLE_DECISION_MISMATCH",
            Self::ProductionGainExceedsOptimum => {
                "EVIDENTRAIL_BENCH_EXACT_ORACLE_PRODUCTION_EXCEEDS_OPTIMUM"
            }
        }
    }
}

impl fmt::Debug for ExactSelectionOracleErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactSelectionOracleErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for ExactSelectionOracleErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ExactSelectionOracleErrorV1 {}

/// Production terminal state mirrored without attempting optional search.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExactSmallSelectionNeedsMoreV1 {
    reason: NeedsMoreReasonV1,
    total_token_budget: u64,
    reserved_fixed_overhead: u64,
    mandatory_packet_cost: u64,
    mandatory_packet_count: u64,
}

impl ExactSmallSelectionNeedsMoreV1 {
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

impl fmt::Debug for ExactSmallSelectionNeedsMoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactSmallSelectionNeedsMoreV1")
            .field("reason", &self.reason)
            .field("total_token_budget", &self.total_token_budget)
            .field("reserved_fixed_overhead", &self.reserved_fixed_overhead)
            .field("mandatory_packet_cost", &self.mandatory_packet_cost)
            .field("mandatory_packet_count", &self.mandatory_packet_count)
            .finish()
    }
}

/// Exact policy-feasible optimum for one bounded production selection problem.
///
/// `optional_acceptance_order` is semantically material: the same set can have
/// different coverage-only charges under different acceptance orders. For a
/// fixed set, the oracle retains the minimum-charge order and then the
/// lexicographically first order in the problem's intrinsic packet order.
#[derive(Clone, PartialEq, Eq)]
pub struct ExactSmallSelectionPlanV1 {
    objective_gain: ObjectiveGainV1,
    mandatory_packet_ids: Vec<PacketIdV1>,
    optional_acceptance_order: Vec<PacketIdV1>,
    selected_packet_ids: Vec<PacketIdV1>,
    mandatory_packet_cost: u64,
    optional_packet_cost: u64,
    selected_packet_cost: u64,
    accounted_token_upper_bound: u64,
    coverage_only_token_cost: u64,
    coverage_only_token_limit: u64,
    reachable_subset_count: u64,
}

impl ExactSmallSelectionPlanV1 {
    #[must_use]
    pub const fn objective_gain(&self) -> ObjectiveGainV1 {
        self.objective_gain
    }

    #[must_use]
    pub fn mandatory_packet_ids(&self) -> &[PacketIdV1] {
        &self.mandatory_packet_ids
    }

    #[must_use]
    pub fn optional_acceptance_order(&self) -> &[PacketIdV1] {
        &self.optional_acceptance_order
    }

    #[must_use]
    pub fn selected_packet_ids(&self) -> &[PacketIdV1] {
        &self.selected_packet_ids
    }

    #[must_use]
    pub const fn mandatory_packet_cost(&self) -> u64 {
        self.mandatory_packet_cost
    }

    #[must_use]
    pub const fn optional_packet_cost(&self) -> u64 {
        self.optional_packet_cost
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

    #[must_use]
    pub const fn reachable_subset_count(&self) -> u64 {
        self.reachable_subset_count
    }

    #[must_use]
    pub const fn tie_break_code(&self) -> &'static str {
        EXACT_SELECTION_ORACLE_TIE_BREAK_V1
    }

    #[must_use]
    pub const fn production_objective_policy_name(&self) -> &'static [u8] {
        SELECTION_OBJECTIVE_POLICY_NAME_V1
    }

    #[must_use]
    pub const fn production_objective_policy_version(&self) -> &'static [u8] {
        SELECTION_OBJECTIVE_POLICY_VERSION_V1
    }
}

impl fmt::Debug for ExactSmallSelectionPlanV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactSmallSelectionPlanV1")
            .field("objective_gain", &self.objective_gain)
            .field("mandatory_packet_count", &self.mandatory_packet_ids.len())
            .field(
                "optional_packet_count",
                &self.optional_acceptance_order.len(),
            )
            .field("selected_packet_cost", &self.selected_packet_cost)
            .field(
                "accounted_token_upper_bound",
                &self.accounted_token_upper_bound,
            )
            .field("coverage_only_token_cost", &self.coverage_only_token_cost)
            .field("coverage_only_token_limit", &self.coverage_only_token_limit)
            .field("reachable_subset_count", &self.reachable_subset_count)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ExactSmallSelectionOracleDecisionV1 {
    Optimal(ExactSmallSelectionPlanV1),
    NeedsMore(ExactSmallSelectionNeedsMoreV1),
}

impl fmt::Debug for ExactSmallSelectionOracleDecisionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Optimal(plan) => formatter
                .debug_tuple("ExactSmallSelectionOracleDecisionV1::Optimal")
                .field(plan)
                .finish(),
            Self::NeedsMore(needs_more) => formatter
                .debug_tuple("ExactSmallSelectionOracleDecisionV1::NeedsMore")
                .field(needs_more)
                .finish(),
        }
    }
}

/// Exact regret record for the current deterministic Greedy+Max selector.
/// It stores an integer objective difference and makes no approximation-factor
/// or population-quality claim.
#[derive(Clone, PartialEq, Eq)]
pub struct ExactSmallSelectionRegretV1 {
    optimum: ExactSmallSelectionPlanV1,
    production_strategy: SelectionStrategyV1,
    production_objective_gain: ObjectiveGainV1,
    production_selected_packet_cost: u64,
    production_accounted_token_upper_bound: u64,
    production_coverage_only_token_cost: u64,
    production_coverage_only_token_limit: u64,
    production_packet_ids: Vec<PacketIdV1>,
    regret_numerator: u64,
}

impl ExactSmallSelectionRegretV1 {
    #[must_use]
    pub const fn optimum(&self) -> &ExactSmallSelectionPlanV1 {
        &self.optimum
    }

    #[must_use]
    pub const fn production_strategy(&self) -> SelectionStrategyV1 {
        self.production_strategy
    }

    #[must_use]
    pub const fn production_objective_gain(&self) -> ObjectiveGainV1 {
        self.production_objective_gain
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
    pub fn production_packet_ids(&self) -> &[PacketIdV1] {
        &self.production_packet_ids
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

impl fmt::Debug for ExactSmallSelectionRegretV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactSmallSelectionRegretV1")
            .field("optimum", &self.optimum)
            .field("production_strategy", &self.production_strategy)
            .field("production_objective_gain", &self.production_objective_gain)
            .field(
                "production_selected_packet_cost",
                &self.production_selected_packet_cost,
            )
            .field(
                "production_accounted_token_upper_bound",
                &self.production_accounted_token_upper_bound,
            )
            .field(
                "production_coverage_only_token_cost",
                &self.production_coverage_only_token_cost,
            )
            .field(
                "production_coverage_only_token_limit",
                &self.production_coverage_only_token_limit,
            )
            .field("production_packet_count", &self.production_packet_ids.len())
            .field("regret_numerator", &self.regret_numerator)
            .field("claims_approximation_factor", &false)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ExactSmallSelectionRegretDecisionV1 {
    Evaluated(ExactSmallSelectionRegretV1),
    NeedsMore(ExactSmallSelectionNeedsMoreV1),
}

impl fmt::Debug for ExactSmallSelectionRegretDecisionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Evaluated(regret) => formatter
                .debug_tuple("ExactSmallSelectionRegretDecisionV1::Evaluated")
                .field(regret)
                .finish(),
            Self::NeedsMore(needs_more) => formatter
                .debug_tuple("ExactSmallSelectionRegretDecisionV1::NeedsMore")
                .field(needs_more)
                .finish(),
        }
    }
}

#[derive(Clone)]
struct ReachableSubsetV1 {
    coverage_only_token_cost: u64,
    optional_acceptance_order: Vec<usize>,
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

    fn threshold(self, cardinality: FacetSaturationCardinalityV1) -> u32 {
        match cardinality {
            FacetSaturationCardinalityV1::One => self.largest,
            FacetSaturationCardinalityV1::Two => self.second_largest,
        }
    }
}

struct OracleMaterial<'a> {
    optional_packets: Vec<&'a IntactPacketV1>,
    mandatory_packet_ids: Vec<PacketIdV1>,
    baseline_coverage: Vec<FacetCoverageV1>,
    facet_positions: BTreeMap<FacetIdV1, usize>,
    optional_cost_by_mask: Vec<u64>,
    objective_gain_by_mask: Vec<ObjectiveGainV1>,
}

/// Compute the exact current-policy optimum for a tightly bounded optional
/// packet universe. Hidden annotations and evaluation labels are not inputs.
pub fn evaluate_exact_small_selection_oracle_v1(
    problem: &SelectionProblemV1,
) -> Result<ExactSmallSelectionOracleDecisionV1, ExactSelectionOracleErrorV1> {
    let material = build_material(problem)?;
    let total_budget = problem.total_token_budget().tokens();
    let fixed_overhead = problem.reserved_fixed_overhead().upper_bound_tokens();
    let mandatory_count = u64::try_from(material.mandatory_packet_ids.len())
        .map_err(|_| ExactSelectionOracleErrorV1::ArithmeticOverflow)?;
    if fixed_overhead > total_budget {
        return Ok(ExactSmallSelectionOracleDecisionV1::NeedsMore(
            ExactSmallSelectionNeedsMoreV1 {
                reason: NeedsMoreReasonV1::FixedOverheadExceedsTotalBudget,
                total_token_budget: total_budget,
                reserved_fixed_overhead: fixed_overhead,
                mandatory_packet_cost: problem.mandatory_cost(),
                mandatory_packet_count: mandatory_count,
            },
        ));
    }
    let available_packet_budget = total_budget - fixed_overhead;
    if problem.mandatory_cost() > available_packet_budget {
        return Ok(ExactSmallSelectionOracleDecisionV1::NeedsMore(
            ExactSmallSelectionNeedsMoreV1 {
                reason: NeedsMoreReasonV1::MandatoryCostExceedsAvailablePacketBudget,
                total_token_budget: total_budget,
                reserved_fixed_overhead: fixed_overhead,
                mandatory_packet_cost: problem.mandatory_cost(),
                mandatory_packet_count: mandatory_count,
            },
        ));
    }

    let optional_budget = available_packet_budget - problem.mandatory_cost();
    let coverage_only_token_limit = optional_budget / COVERAGE_ONLY_OPTIONAL_BUDGET_DENOMINATOR_V1;
    let state_count = material.optional_cost_by_mask.len();
    let mut reachable = vec![None; state_count];
    reachable[0] = Some(ReachableSubsetV1 {
        coverage_only_token_cost: 0,
        optional_acceptance_order: Vec::new(),
    });

    for mask in 0..state_count {
        let Some(state) = reachable[mask].clone() else {
            continue;
        };
        let coverage = coverage_for_mask(&material, mask)?;
        for optional_index in 0..material.optional_packets.len() {
            let bit = 1_usize << optional_index;
            if mask & bit != 0 {
                continue;
            }
            let next_mask = mask | bit;
            if material.optional_cost_by_mask[next_mask] > optional_budget {
                continue;
            }
            let objective_delta = material.objective_gain_by_mask[next_mask]
                .numerator()
                .checked_sub(material.objective_gain_by_mask[mask].numerator())
                .ok_or(ExactSelectionOracleErrorV1::ObjectiveContractMismatch)?;
            let (reconstructed_delta, coverage_only) = marginal_score(
                problem,
                &material,
                &coverage,
                material.optional_packets[optional_index],
            )?;
            if objective_delta != reconstructed_delta {
                return Err(ExactSelectionOracleErrorV1::ObjectiveContractMismatch);
            }
            if objective_delta == 0 {
                continue;
            }
            let packet_cost = material.optional_packets[optional_index]
                .composable_token_upper_bound()
                .upper_bound_tokens();
            let next_coverage_cost = if coverage_only {
                state
                    .coverage_only_token_cost
                    .checked_add(packet_cost)
                    .ok_or(ExactSelectionOracleErrorV1::ArithmeticOverflow)?
            } else {
                state.coverage_only_token_cost
            };
            if next_coverage_cost > coverage_only_token_limit {
                continue;
            }
            let mut next_order = state.optional_acceptance_order.clone();
            next_order.push(optional_index);
            let candidate = ReachableSubsetV1 {
                coverage_only_token_cost: next_coverage_cost,
                optional_acceptance_order: next_order,
            };
            if reachable[next_mask]
                .as_ref()
                .is_none_or(|current| canonical_state_is_better(&candidate, current))
            {
                reachable[next_mask] = Some(candidate);
            }
        }
    }

    let reachable_subset_count = u64::try_from(reachable.iter().flatten().count())
        .map_err(|_| ExactSelectionOracleErrorV1::ArithmeticOverflow)?;
    let mut best_mask = 0_usize;
    for mask in 1..state_count {
        let Some(candidate) = reachable[mask].as_ref() else {
            continue;
        };
        let current = reachable[best_mask]
            .as_ref()
            .ok_or(ExactSelectionOracleErrorV1::ObjectiveContractMismatch)?;
        if optimum_state_is_better(mask, candidate, best_mask, current, &material) {
            best_mask = mask;
        }
    }
    let best = reachable[best_mask]
        .as_ref()
        .ok_or(ExactSelectionOracleErrorV1::ObjectiveContractMismatch)?;
    let optional_packet_cost = material.optional_cost_by_mask[best_mask];
    let selected_packet_cost = problem
        .mandatory_cost()
        .checked_add(optional_packet_cost)
        .ok_or(ExactSelectionOracleErrorV1::ArithmeticOverflow)?;
    let accounted_token_upper_bound = fixed_overhead
        .checked_add(selected_packet_cost)
        .ok_or(ExactSelectionOracleErrorV1::ArithmeticOverflow)?;
    if accounted_token_upper_bound > total_budget {
        return Err(ExactSelectionOracleErrorV1::ObjectiveContractMismatch);
    }
    let optional_acceptance_order = best
        .optional_acceptance_order
        .iter()
        .map(|index| material.optional_packets[*index].id())
        .collect::<Vec<_>>();
    let mut selected_packet_ids = material.mandatory_packet_ids.clone();
    selected_packet_ids.extend(optional_acceptance_order.iter().copied());
    Ok(ExactSmallSelectionOracleDecisionV1::Optimal(
        ExactSmallSelectionPlanV1 {
            objective_gain: material.objective_gain_by_mask[best_mask],
            mandatory_packet_ids: material.mandatory_packet_ids,
            optional_acceptance_order,
            selected_packet_ids,
            mandatory_packet_cost: problem.mandatory_cost(),
            optional_packet_cost,
            selected_packet_cost,
            accounted_token_upper_bound,
            coverage_only_token_cost: best.coverage_only_token_cost,
            coverage_only_token_limit,
            reachable_subset_count,
        },
    ))
}

/// Compare the production Greedy+Max decision with the exact bounded optimum.
pub fn evaluate_exact_small_selection_regret_v1(
    problem: &SelectionProblemV1,
) -> Result<ExactSmallSelectionRegretDecisionV1, ExactSelectionOracleErrorV1> {
    let oracle = evaluate_exact_small_selection_oracle_v1(problem)?;
    let production = problem
        .select()
        .map_err(|_| ExactSelectionOracleErrorV1::ProductionSelectionFailure)?;
    match (oracle, production) {
        (
            ExactSmallSelectionOracleDecisionV1::NeedsMore(oracle_needs_more),
            SelectionDecisionV1::NeedsMore(production_needs_more),
        ) if oracle_needs_more.reason() == production_needs_more.reason()
            && oracle_needs_more.reserved_fixed_overhead()
                == production_needs_more.reserved_fixed_overhead()
            && oracle_needs_more.mandatory_packet_cost()
                == production_needs_more.mandatory_cost() =>
        {
            Ok(ExactSmallSelectionRegretDecisionV1::NeedsMore(
                oracle_needs_more,
            ))
        }
        (
            ExactSmallSelectionOracleDecisionV1::Optimal(optimum),
            SelectionDecisionV1::Selected(production),
        ) => {
            let production_gain = production.normalized_gain();
            let regret_numerator = optimum
                .objective_gain()
                .numerator()
                .checked_sub(production_gain.numerator())
                .ok_or(ExactSelectionOracleErrorV1::ProductionGainExceedsOptimum)?;
            Ok(ExactSmallSelectionRegretDecisionV1::Evaluated(
                ExactSmallSelectionRegretV1 {
                    optimum,
                    production_strategy: production.strategy(),
                    production_objective_gain: production_gain,
                    production_selected_packet_cost: production.selected_packet_cost(),
                    production_accounted_token_upper_bound: production
                        .accounted_token_upper_bound(),
                    production_coverage_only_token_cost: production.coverage_only_token_cost(),
                    production_coverage_only_token_limit: production.coverage_only_token_limit(),
                    production_packet_ids: production
                        .packets()
                        .iter()
                        .map(|packet| packet.packet().id())
                        .collect(),
                    regret_numerator,
                },
            ))
        }
        _ => Err(ExactSelectionOracleErrorV1::ProductionDecisionMismatch),
    }
}

fn build_material(
    problem: &SelectionProblemV1,
) -> Result<OracleMaterial<'_>, ExactSelectionOracleErrorV1> {
    let mandatory_packet_ids = problem
        .mandatory()
        .iter()
        .map(|entry| entry.packet_id())
        .collect::<Vec<_>>();
    let mandatory = mandatory_packet_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let optional_packets = problem
        .packets()
        .iter()
        .filter(|packet| !mandatory.contains(&packet.id()))
        .collect::<Vec<_>>();
    if optional_packets.len() > MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1 {
        return Err(ExactSelectionOracleErrorV1::TooManyOptionalPackets);
    }
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
    for packet_id in &mandatory_packet_ids {
        let packet = packet_by_id
            .get(packet_id)
            .copied()
            .ok_or(ExactSelectionOracleErrorV1::ObjectiveContractMismatch)?;
        apply_packet(&mut baseline_coverage, packet, &facet_positions)?;
    }

    let state_count = 1_usize
        .checked_shl(
            u32::try_from(optional_packets.len())
                .map_err(|_| ExactSelectionOracleErrorV1::ArithmeticOverflow)?,
        )
        .ok_or(ExactSelectionOracleErrorV1::ArithmeticOverflow)?;
    let mut optional_cost_by_mask = vec![0_u64; state_count];
    let mut objective_gain_by_mask = Vec::with_capacity(state_count);
    for mask in 0..state_count {
        if mask != 0 {
            let bit = mask.trailing_zeros();
            let previous = mask & !(1_usize << bit);
            optional_cost_by_mask[mask] = optional_cost_by_mask[previous]
                .checked_add(
                    optional_packets[usize::try_from(bit)
                        .map_err(|_| ExactSelectionOracleErrorV1::ArithmeticOverflow)?]
                    .composable_token_upper_bound()
                    .upper_bound_tokens(),
                )
                .ok_or(ExactSelectionOracleErrorV1::ArithmeticOverflow)?;
        }
        let selected_ids = optional_packets
            .iter()
            .enumerate()
            .filter(|(index, _)| mask & (1_usize << index) != 0)
            .map(|(_, packet)| packet.id());
        objective_gain_by_mask.push(
            problem
                .normalized_gain(selected_ids)
                .map_err(|_| ExactSelectionOracleErrorV1::ObjectiveEvaluationFailure)?,
        );
    }
    Ok(OracleMaterial {
        optional_packets,
        mandatory_packet_ids,
        baseline_coverage,
        facet_positions,
        optional_cost_by_mask,
        objective_gain_by_mask,
    })
}

fn coverage_for_mask(
    material: &OracleMaterial<'_>,
    mask: usize,
) -> Result<Vec<FacetCoverageV1>, ExactSelectionOracleErrorV1> {
    let mut coverage = material.baseline_coverage.clone();
    for (index, packet) in material.optional_packets.iter().enumerate() {
        if mask & (1_usize << index) != 0 {
            apply_packet(&mut coverage, packet, &material.facet_positions)?;
        }
    }
    Ok(coverage)
}

fn apply_packet(
    coverage: &mut [FacetCoverageV1],
    packet: &IntactPacketV1,
    facet_positions: &BTreeMap<FacetIdV1, usize>,
) -> Result<(), ExactSelectionOracleErrorV1> {
    for affinity in packet.affinities() {
        let index = facet_positions
            .get(&affinity.facet_id())
            .copied()
            .ok_or(ExactSelectionOracleErrorV1::ObjectiveContractMismatch)?;
        coverage[index].apply(affinity.affinity().micros());
    }
    Ok(())
}

fn marginal_score(
    problem: &SelectionProblemV1,
    material: &OracleMaterial<'_>,
    coverage: &[FacetCoverageV1],
    packet: &IntactPacketV1,
) -> Result<(u64, bool), ExactSelectionOracleErrorV1> {
    let mut gain = 0_u64;
    let mut has_primary_gain = false;
    for affinity in packet.affinities() {
        let facet_index = material
            .facet_positions
            .get(&affinity.facet_id())
            .copied()
            .ok_or(ExactSelectionOracleErrorV1::ObjectiveContractMismatch)?;
        let facet = problem
            .facets()
            .get(facet_index)
            .ok_or(ExactSelectionOracleErrorV1::ObjectiveContractMismatch)?;
        let threshold = coverage[facet_index].threshold(facet.kind().saturation_cardinality());
        let delta = affinity.affinity().micros().saturating_sub(threshold);
        if delta == 0 {
            continue;
        }
        let contribution = u64::from(facet.weight().micros())
            .checked_mul(u64::from(delta))
            .ok_or(ExactSelectionOracleErrorV1::ArithmeticOverflow)?;
        gain = gain
            .checked_add(contribution)
            .ok_or(ExactSelectionOracleErrorV1::ArithmeticOverflow)?;
        if contribution > 0 && !facet.kind().is_coverage_only() {
            has_primary_gain = true;
        }
    }
    Ok((gain, gain > 0 && !has_primary_gain))
}

fn canonical_state_is_better(candidate: &ReachableSubsetV1, current: &ReachableSubsetV1) -> bool {
    candidate
        .coverage_only_token_cost
        .cmp(&current.coverage_only_token_cost)
        .then_with(|| {
            candidate
                .optional_acceptance_order
                .cmp(&current.optional_acceptance_order)
        })
        == Ordering::Less
}

fn optimum_state_is_better(
    candidate_mask: usize,
    candidate: &ReachableSubsetV1,
    current_mask: usize,
    current: &ReachableSubsetV1,
    material: &OracleMaterial<'_>,
) -> bool {
    material.objective_gain_by_mask[candidate_mask]
        .numerator()
        .cmp(&material.objective_gain_by_mask[current_mask].numerator())
        .then_with(|| {
            material.optional_cost_by_mask[current_mask]
                .cmp(&material.optional_cost_by_mask[candidate_mask])
        })
        .then_with(|| {
            current
                .coverage_only_token_cost
                .cmp(&candidate.coverage_only_token_cost)
        })
        .then_with(|| current_mask.count_ones().cmp(&candidate_mask.count_ones()))
        .then_with(|| {
            current
                .optional_acceptance_order
                .cmp(&candidate.optional_acceptance_order)
        })
        == Ordering::Greater
}
