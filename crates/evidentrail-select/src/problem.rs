use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;

use crate::types::{
    AFFINITY_SCALE_V1, COVERAGE_ONLY_OPTIONAL_BUDGET_DENOMINATOR_V1, ComposablePacketCostV1,
    FacetAffinityV1, FacetIdV1, FacetSaturationCardinalityV1, IntactPacketV1,
    MAX_MANDATORY_PACKETS_V1, MAX_SELECTION_EVENTS_V1, MAX_SELECTION_FACETS_V1,
    MAX_SELECTION_PACKETS_V1, MandatoryPacketV1, ObjectiveGainV1, PacketIdV1,
    ProductionFacetKindV1, ProductionFacetV1, ReservedFixedOverheadV1, TotalTokenBudgetV1,
};

/// Stable construction failure for a canonical selection universe.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SelectionProblemConstructionError {
    TooManyPackets,
    TooManyFacets,
    TooManyEvents,
    TooManyMandatoryPackets,
    DuplicatePacketId,
    DuplicateFacetId,
    OverlappingEvent,
    UnknownAffinityFacet,
    CostModelMismatch,
    DuplicateMandatoryPacket,
    UnknownMandatoryPacket,
    UnknownMandatoryFacet,
    MandatoryFacetNotValidatedIdentifier,
    MandatoryPacketLacksIdentifierAffinity,
    UniverseTokenCostOverflow,
    ObjectiveBoundOverflow,
}

impl SelectionProblemConstructionError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TooManyPackets => "EVIDENTRAIL_SELECT_TOO_MANY_PACKETS",
            Self::TooManyFacets => "EVIDENTRAIL_SELECT_TOO_MANY_FACETS",
            Self::TooManyEvents => "EVIDENTRAIL_SELECT_TOO_MANY_EVENTS",
            Self::TooManyMandatoryPackets => "EVIDENTRAIL_SELECT_TOO_MANY_MANDATORY_PACKETS",
            Self::DuplicatePacketId => "EVIDENTRAIL_SELECT_DUPLICATE_PACKET_ID",
            Self::DuplicateFacetId => "EVIDENTRAIL_SELECT_DUPLICATE_FACET_ID",
            Self::OverlappingEvent => "EVIDENTRAIL_SELECT_OVERLAPPING_EVENT",
            Self::UnknownAffinityFacet => "EVIDENTRAIL_SELECT_UNKNOWN_AFFINITY_FACET",
            Self::CostModelMismatch => "EVIDENTRAIL_SELECT_COST_MODEL_MISMATCH",
            Self::DuplicateMandatoryPacket => "EVIDENTRAIL_SELECT_DUPLICATE_MANDATORY_PACKET",
            Self::UnknownMandatoryPacket => "EVIDENTRAIL_SELECT_UNKNOWN_MANDATORY_PACKET",
            Self::UnknownMandatoryFacet => "EVIDENTRAIL_SELECT_UNKNOWN_MANDATORY_FACET",
            Self::MandatoryFacetNotValidatedIdentifier => {
                "EVIDENTRAIL_SELECT_MANDATORY_FACET_NOT_VALIDATED_IDENTIFIER"
            }
            Self::MandatoryPacketLacksIdentifierAffinity => {
                "EVIDENTRAIL_SELECT_MANDATORY_PACKET_LACKS_IDENTIFIER_AFFINITY"
            }
            Self::UniverseTokenCostOverflow => "EVIDENTRAIL_SELECT_UNIVERSE_TOKEN_COST_OVERFLOW",
            Self::ObjectiveBoundOverflow => "EVIDENTRAIL_SELECT_OBJECTIVE_BOUND_OVERFLOW",
        }
    }
}

impl fmt::Debug for SelectionProblemConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectionProblemConstructionError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for SelectionProblemConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for SelectionProblemConstructionError {}

/// Failure while evaluating a caller-provided optional packet set.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ObjectiveEvaluationError {
    UnknownPacket,
    DuplicatePacket,
    MandatoryPacketIncluded,
    ArithmeticInvariantViolation,
}

impl ObjectiveEvaluationError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnknownPacket => "EVIDENTRAIL_SELECT_OBJECTIVE_UNKNOWN_PACKET",
            Self::DuplicatePacket => "EVIDENTRAIL_SELECT_OBJECTIVE_DUPLICATE_PACKET",
            Self::MandatoryPacketIncluded => "EVIDENTRAIL_SELECT_OBJECTIVE_MANDATORY_PACKET_INCLUDED",
            Self::ArithmeticInvariantViolation => {
                "EVIDENTRAIL_SELECT_OBJECTIVE_ARITHMETIC_INVARIANT_VIOLATION"
            }
        }
    }
}

impl fmt::Debug for ObjectiveEvaluationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectiveEvaluationError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for ObjectiveEvaluationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ObjectiveEvaluationError {}

/// Defensive failure for arithmetic that construction proved bounded.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SelectionInvariantError {
    ArithmeticInvariantViolation,
}

impl SelectionInvariantError {
    pub const CODE: &'static str = "EVIDENTRAIL_SELECT_ARITHMETIC_INVARIANT_VIOLATION";
}

impl fmt::Debug for SelectionInvariantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectionInvariantError")
            .field("code", &Self::CODE)
            .finish()
    }
}

impl fmt::Display for SelectionInvariantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(Self::CODE)
    }
}

impl StdError for SelectionInvariantError {}

/// Canonical, validated V1 packet universe and strict token budget.
pub struct SelectionProblemV1 {
    facets: Vec<ProductionFacetV1>,
    packets: Vec<IntactPacketV1>,
    mandatory: Vec<MandatoryPacketV1>,
    total_token_budget: TotalTokenBudgetV1,
    reserved_fixed_overhead: ReservedFixedOverheadV1,
    mandatory_cost: u64,
}

impl SelectionProblemV1 {
    pub fn new(
        facets: impl IntoIterator<Item = ProductionFacetV1>,
        packets: impl IntoIterator<Item = IntactPacketV1>,
        mandatory: impl IntoIterator<Item = MandatoryPacketV1>,
        total_token_budget: TotalTokenBudgetV1,
        reserved_fixed_overhead: ReservedFixedOverheadV1,
    ) -> Result<Self, SelectionProblemConstructionError> {
        let mut facets = facets.into_iter().collect::<Vec<_>>();
        if facets.len() > MAX_SELECTION_FACETS_V1 {
            return Err(SelectionProblemConstructionError::TooManyFacets);
        }
        facets.sort_unstable_by_key(ProductionFacetV1::id);
        if facets.windows(2).any(|pair| pair[0].id() == pair[1].id()) {
            return Err(SelectionProblemConstructionError::DuplicateFacetId);
        }

        let mut objective_bound = 0_u64;
        for facet in &facets {
            let maximum_contribution = u64::from(facet.weight().micros())
                .checked_mul(u64::from(AFFINITY_SCALE_V1))
                .and_then(|value| {
                    value.checked_mul(u64::from(facet.kind().saturation_cardinality().count()))
                })
                .ok_or(SelectionProblemConstructionError::ObjectiveBoundOverflow)?;
            objective_bound = objective_bound
                .checked_add(maximum_contribution)
                .ok_or(SelectionProblemConstructionError::ObjectiveBoundOverflow)?;
        }

        let mut packets = packets.into_iter().collect::<Vec<_>>();
        if packets.len() > MAX_SELECTION_PACKETS_V1 {
            return Err(SelectionProblemConstructionError::TooManyPackets);
        }
        let mut packet_ids = BTreeSet::new();
        for packet in &packets {
            if !packet_ids.insert(packet.id()) {
                return Err(SelectionProblemConstructionError::DuplicatePacketId);
            }
        }
        // Intrinsic event membership, not the opaque caller label, controls
        // canonical order and every downstream tie.
        packets.sort_unstable_by(|left, right| left.event_ids().cmp(right.event_ids()));
        let packet_positions = packets
            .iter()
            .enumerate()
            .map(|(position, packet)| (packet.id(), position))
            .collect::<BTreeMap<_, _>>();

        let mut all_events = BTreeSet::new();
        let mut universe_token_cost = 0_u64;
        for packet in &packets {
            if packet.composable_token_upper_bound().cost_model()
                != reserved_fixed_overhead.cost_model()
            {
                return Err(SelectionProblemConstructionError::CostModelMismatch);
            }
            universe_token_cost = universe_token_cost
                .checked_add(packet.composable_token_upper_bound().upper_bound_tokens())
                .ok_or(SelectionProblemConstructionError::UniverseTokenCostOverflow)?;
            for event_id in packet.event_ids() {
                if !all_events.insert(*event_id) {
                    return Err(SelectionProblemConstructionError::OverlappingEvent);
                }
                if all_events.len() > MAX_SELECTION_EVENTS_V1 {
                    return Err(SelectionProblemConstructionError::TooManyEvents);
                }
            }
            for affinity in packet.affinities() {
                if facets
                    .binary_search_by_key(&affinity.facet_id(), ProductionFacetV1::id)
                    .is_err()
                {
                    return Err(SelectionProblemConstructionError::UnknownAffinityFacet);
                }
            }
        }

        let mut mandatory = mandatory.into_iter().collect::<Vec<_>>();
        if mandatory.len() > MAX_MANDATORY_PACKETS_V1 {
            return Err(SelectionProblemConstructionError::TooManyMandatoryPackets);
        }
        let mut mandatory_cost = 0_u64;
        let mut mandatory_packet_ids = BTreeSet::new();
        for entry in &mandatory {
            if !mandatory_packet_ids.insert(entry.packet_id()) {
                return Err(SelectionProblemConstructionError::DuplicateMandatoryPacket);
            }
            let packet_index = packet_positions
                .get(&entry.packet_id())
                .copied()
                .ok_or(SelectionProblemConstructionError::UnknownMandatoryPacket)?;
            let facet_index = facets
                .binary_search_by_key(
                    &entry.validated_identifier_facet_id(),
                    ProductionFacetV1::id,
                )
                .map_err(|_| SelectionProblemConstructionError::UnknownMandatoryFacet)?;
            if facets[facet_index].kind() != ProductionFacetKindV1::ValidatedQueryIdentifier {
                return Err(
                    SelectionProblemConstructionError::MandatoryFacetNotValidatedIdentifier,
                );
            }
            if packets[packet_index]
                .affinity_for(entry.validated_identifier_facet_id())
                .is_none()
            {
                return Err(
                    SelectionProblemConstructionError::MandatoryPacketLacksIdentifierAffinity,
                );
            }
            mandatory_cost = mandatory_cost
                .checked_add(
                    packets[packet_index]
                        .composable_token_upper_bound()
                        .upper_bound_tokens(),
                )
                .ok_or(SelectionProblemConstructionError::UniverseTokenCostOverflow)?;
        }
        mandatory.sort_unstable_by_key(|entry| {
            packet_positions
                .get(&entry.packet_id())
                .copied()
                .unwrap_or(usize::MAX)
        });

        Ok(Self {
            facets,
            packets,
            mandatory,
            total_token_budget,
            reserved_fixed_overhead,
            mandatory_cost,
        })
    }

    #[must_use]
    pub fn facets(&self) -> &[ProductionFacetV1] {
        &self.facets
    }

    #[must_use]
    pub fn packets(&self) -> &[IntactPacketV1] {
        &self.packets
    }

    #[must_use]
    pub fn mandatory(&self) -> &[MandatoryPacketV1] {
        &self.mandatory
    }

    #[must_use]
    pub const fn total_token_budget(&self) -> TotalTokenBudgetV1 {
        self.total_token_budget
    }

    #[must_use]
    pub const fn reserved_fixed_overhead(&self) -> ReservedFixedOverheadV1 {
        self.reserved_fixed_overhead
    }

    #[must_use]
    pub const fn available_packet_budget(&self) -> u64 {
        self.total_token_budget
            .tokens()
            .saturating_sub(self.reserved_fixed_overhead.upper_bound_tokens())
    }

    #[must_use]
    pub const fn mandatory_cost(&self) -> u64 {
        self.mandatory_cost
    }

    /// Evaluate normalized facility coverage for an optional packet set.
    /// Mandatory packets are already the baseline and therefore rejected from
    /// this argument rather than silently double-counted.
    pub fn normalized_gain(
        &self,
        optional_packet_ids: impl IntoIterator<Item = PacketIdV1>,
    ) -> Result<ObjectiveGainV1, ObjectiveEvaluationError> {
        let mut seen = BTreeSet::new();
        let mut optional_packet_indices = Vec::new();
        for packet_id in optional_packet_ids {
            if !seen.insert(packet_id) {
                return Err(ObjectiveEvaluationError::DuplicatePacket);
            }
            if self.is_mandatory(packet_id) {
                return Err(ObjectiveEvaluationError::MandatoryPacketIncluded);
            }
            optional_packet_indices.push(
                self.packet_index(packet_id)
                    .ok_or(ObjectiveEvaluationError::UnknownPacket)?,
            );
        }
        optional_packet_indices.sort_unstable();

        let mut coverage = self.mandatory_coverage();
        let mut total_gain = 0_u64;
        for packet_index in optional_packet_indices {
            let gain = self
                .marginal_gain(&coverage, &self.packets[packet_index])
                .ok_or(ObjectiveEvaluationError::ArithmeticInvariantViolation)?;
            total_gain = total_gain
                .checked_add(gain)
                .ok_or(ObjectiveEvaluationError::ArithmeticInvariantViolation)?;
            self.apply_packet(&mut coverage, &self.packets[packet_index]);
        }
        Ok(ObjectiveGainV1::from_numerator(total_gain))
    }

    /// Run deterministic density greedy and compare it with the best single
    /// fitting optional packet. No approximation factor beyond this exact
    /// implemented comparison is claimed.
    pub fn select(&self) -> Result<SelectionDecisionV1, SelectionInvariantError> {
        let fixed_overhead = self.reserved_fixed_overhead.upper_bound_tokens();
        if fixed_overhead > self.total_token_budget.tokens() {
            return Ok(SelectionDecisionV1::NeedsMore(NeedsMoreSelectionV1 {
                reason: NeedsMoreReasonV1::FixedOverheadExceedsTotalBudget,
                reserved_fixed_overhead: fixed_overhead,
                mandatory_cost: self.mandatory_cost,
                total_token_budget: self.total_token_budget,
                mandatory_packet_count: self.mandatory.len(),
            }));
        }
        let available_packet_budget = self.total_token_budget.tokens() - fixed_overhead;
        if self.mandatory_cost > available_packet_budget {
            return Ok(SelectionDecisionV1::NeedsMore(NeedsMoreSelectionV1 {
                reason: NeedsMoreReasonV1::MandatoryCostExceedsAvailablePacketBudget,
                reserved_fixed_overhead: fixed_overhead,
                mandatory_cost: self.mandatory_cost,
                total_token_budget: self.total_token_budget,
                mandatory_packet_count: self.mandatory.len(),
            }));
        }

        let optional_budget = available_packet_budget - self.mandatory_cost;
        let coverage_only_token_limit =
            optional_budget / COVERAGE_ONLY_OPTIONAL_BUDGET_DENOMINATOR_V1;
        let baseline = self.mandatory_coverage();
        let greedy = self.density_greedy(&baseline, optional_budget, coverage_only_token_limit)?;
        let best_single =
            self.best_single(&baseline, optional_budget, coverage_only_token_limit)?;
        let chosen = match best_single {
            Some(single) if plan_is_better(&single, &greedy) => single,
            _ => greedy,
        };

        let mut selected_packets = Vec::with_capacity(self.mandatory.len() + chosen.items.len());
        for entry in &self.mandatory {
            let packet_index = self
                .packet_index(entry.packet_id())
                .ok_or(SelectionInvariantError::ArithmeticInvariantViolation)?;
            selected_packets.push(SelectedPacketV1 {
                packet: self.packets[packet_index].clone(),
                facet_kinds: self
                    .packet_facet_kinds(&self.packets[packet_index])
                    .ok_or(SelectionInvariantError::ArithmeticInvariantViolation)?,
                marginal_gain: ObjectiveGainV1::from_numerator(0),
                forcing_constraint: SelectionConstraintV1::MandatoryValidatedIdentifier {
                    facet_id: entry.validated_identifier_facet_id(),
                },
            });
        }
        let mut presentation_items = chosen.items.iter().enumerate().collect::<Vec<_>>();
        presentation_items.sort_by_key(|(selection_rank, item)| {
            (
                self.packet_presentation_priority(&self.packets[item.packet_index]),
                *selection_rank,
            )
        });
        let mut presentation_coverage = baseline;
        let mut presentation_total_gain = 0_u64;
        for (_, item) in presentation_items {
            let forcing_constraint = match chosen.strategy {
                SelectionStrategyV1::DensityGreedy => SelectionConstraintV1::DensityGreedy,
                SelectionStrategyV1::BestSingle => SelectionConstraintV1::BestSingle,
                SelectionStrategyV1::MandatoryOnly => {
                    return Err(SelectionInvariantError::ArithmeticInvariantViolation);
                }
            };
            let packet = &self.packets[item.packet_index];
            let marginal_gain = self
                .marginal_gain(&presentation_coverage, packet)
                .ok_or(SelectionInvariantError::ArithmeticInvariantViolation)?;
            presentation_total_gain = presentation_total_gain
                .checked_add(marginal_gain)
                .ok_or(SelectionInvariantError::ArithmeticInvariantViolation)?;
            self.apply_packet(&mut presentation_coverage, packet);
            selected_packets.push(SelectedPacketV1 {
                packet: packet.clone(),
                facet_kinds: self
                    .packet_facet_kinds(packet)
                    .ok_or(SelectionInvariantError::ArithmeticInvariantViolation)?,
                marginal_gain: ObjectiveGainV1::from_numerator(marginal_gain),
                forcing_constraint,
            });
        }
        if presentation_total_gain != chosen.total_gain {
            return Err(SelectionInvariantError::ArithmeticInvariantViolation);
        }

        let selected_packet_cost = self
            .mandatory_cost
            .checked_add(chosen.token_cost)
            .ok_or(SelectionInvariantError::ArithmeticInvariantViolation)?;
        let accounted_token_upper_bound = fixed_overhead
            .checked_add(selected_packet_cost)
            .ok_or(SelectionInvariantError::ArithmeticInvariantViolation)?;
        if accounted_token_upper_bound > self.total_token_budget.tokens() {
            return Err(SelectionInvariantError::ArithmeticInvariantViolation);
        }

        Ok(SelectionDecisionV1::Selected(SelectionV1 {
            strategy: chosen.strategy,
            total_token_budget: self.total_token_budget,
            reserved_fixed_overhead: self.reserved_fixed_overhead,
            mandatory_token_cost: self.mandatory_cost,
            selected_packet_cost,
            accounted_token_upper_bound,
            coverage_only_token_limit,
            coverage_only_token_cost: chosen.coverage_only_token_cost,
            normalized_gain: ObjectiveGainV1::from_numerator(chosen.total_gain),
            packets: selected_packets,
        }))
    }

    fn density_greedy(
        &self,
        baseline: &[FacetCoverageV1],
        optional_budget: u64,
        coverage_only_token_limit: u64,
    ) -> Result<CandidatePlan, SelectionInvariantError> {
        let mut coverage = baseline.to_vec();
        let mut chosen = vec![false; self.packets.len()];
        for entry in &self.mandatory {
            let index = self
                .packet_index(entry.packet_id())
                .ok_or(SelectionInvariantError::ArithmeticInvariantViolation)?;
            chosen[index] = true;
        }
        let mut remaining = optional_budget;
        let mut remaining_coverage_only = coverage_only_token_limit;
        let mut items = Vec::new();
        let mut total_gain = 0_u64;
        let mut token_cost = 0_u64;
        let mut coverage_only_token_cost = 0_u64;

        loop {
            let mut best: Option<ScoredCandidate> = None;
            for (packet_index, packet) in self.packets.iter().enumerate() {
                let cost = packet.composable_token_upper_bound().upper_bound_tokens();
                if chosen[packet_index] || cost > remaining {
                    continue;
                }
                let marginal = self
                    .marginal_score(&coverage, packet)
                    .ok_or(SelectionInvariantError::ArithmeticInvariantViolation)?;
                if marginal.gain == 0 || (marginal.coverage_only && cost > remaining_coverage_only)
                {
                    continue;
                }
                let candidate = ScoredCandidate {
                    packet_index,
                    gain: marginal.gain,
                    coverage_only: marginal.coverage_only,
                };
                if best.as_ref().is_none_or(|current| {
                    density_candidate_is_better(&candidate, current, &self.packets)
                }) {
                    best = Some(candidate);
                }
            }

            let Some(best) = best else {
                break;
            };
            let packet = &self.packets[best.packet_index];
            let cost = packet.composable_token_upper_bound().upper_bound_tokens();
            chosen[best.packet_index] = true;
            remaining -= cost;
            if best.coverage_only {
                remaining_coverage_only -= cost;
                coverage_only_token_cost = coverage_only_token_cost
                    .checked_add(cost)
                    .ok_or(SelectionInvariantError::ArithmeticInvariantViolation)?;
            }
            token_cost = token_cost
                .checked_add(cost)
                .ok_or(SelectionInvariantError::ArithmeticInvariantViolation)?;
            total_gain = total_gain
                .checked_add(best.gain)
                .ok_or(SelectionInvariantError::ArithmeticInvariantViolation)?;
            self.apply_packet(&mut coverage, packet);
            items.push(PlanItem {
                packet_index: best.packet_index,
            });
        }

        let strategy = if items.is_empty() {
            SelectionStrategyV1::MandatoryOnly
        } else {
            SelectionStrategyV1::DensityGreedy
        };
        Ok(CandidatePlan {
            strategy,
            items,
            total_gain,
            token_cost,
            coverage_only_token_cost,
        })
    }

    fn best_single(
        &self,
        baseline: &[FacetCoverageV1],
        optional_budget: u64,
        coverage_only_token_limit: u64,
    ) -> Result<Option<CandidatePlan>, SelectionInvariantError> {
        let mut best: Option<ScoredCandidate> = None;
        for (packet_index, packet) in self.packets.iter().enumerate() {
            if self.is_mandatory(packet.id())
                || packet.composable_token_upper_bound().upper_bound_tokens() > optional_budget
            {
                continue;
            }
            let marginal = self
                .marginal_score(baseline, packet)
                .ok_or(SelectionInvariantError::ArithmeticInvariantViolation)?;
            if marginal.gain == 0
                || (marginal.coverage_only
                    && packet.composable_token_upper_bound().upper_bound_tokens()
                        > coverage_only_token_limit)
            {
                continue;
            }
            let candidate = ScoredCandidate {
                packet_index,
                gain: marginal.gain,
                coverage_only: marginal.coverage_only,
            };
            if best.as_ref().is_none_or(|current| {
                single_candidate_is_better(&candidate, current, &self.packets)
            }) {
                best = Some(candidate);
            }
        }
        Ok(best.map(|best| CandidatePlan {
            strategy: SelectionStrategyV1::BestSingle,
            items: vec![PlanItem {
                packet_index: best.packet_index,
            }],
            total_gain: best.gain,
            token_cost: self.packets[best.packet_index]
                .composable_token_upper_bound()
                .upper_bound_tokens(),
            coverage_only_token_cost: if best.coverage_only {
                self.packets[best.packet_index]
                    .composable_token_upper_bound()
                    .upper_bound_tokens()
            } else {
                0
            },
        }))
    }

    fn mandatory_coverage(&self) -> Vec<FacetCoverageV1> {
        let mut coverage = vec![FacetCoverageV1::default(); self.facets.len()];
        for entry in &self.mandatory {
            if let Some(packet_index) = self.packet_index(entry.packet_id()) {
                self.apply_packet(&mut coverage, &self.packets[packet_index]);
            }
        }
        coverage
    }

    fn marginal_gain(&self, coverage: &[FacetCoverageV1], packet: &IntactPacketV1) -> Option<u64> {
        self.marginal_score(coverage, packet)
            .map(|marginal| marginal.gain)
    }

    fn marginal_score(
        &self,
        coverage: &[FacetCoverageV1],
        packet: &IntactPacketV1,
    ) -> Option<MarginalScore> {
        let mut gain = 0_u64;
        let mut has_primary_gain = false;
        for affinity in packet.affinities() {
            let facet_index = self.facet_index(affinity.facet_id())?;
            let facet = &self.facets[facet_index];
            let affinity = affinity.affinity().micros();
            let delta = coverage[facet_index]
                .marginal_affinity(affinity, facet.kind().saturation_cardinality());
            if delta == 0 {
                continue;
            }
            let contribution = u64::from(facet.weight().micros()).checked_mul(delta)?;
            gain = gain.checked_add(contribution)?;
            if contribution > 0 && !facet.kind().is_coverage_only() {
                has_primary_gain = true;
            }
        }
        Some(MarginalScore {
            gain,
            coverage_only: gain > 0 && !has_primary_gain,
        })
    }

    fn apply_packet(&self, coverage: &mut [FacetCoverageV1], packet: &IntactPacketV1) {
        for affinity in packet.affinities() {
            if let Some(facet_index) = self.facet_index(affinity.facet_id()) {
                coverage[facet_index].apply_affinity(
                    affinity.affinity().micros(),
                    self.facets[facet_index].kind().saturation_cardinality(),
                );
            }
        }
    }

    fn packet_facet_kinds(&self, packet: &IntactPacketV1) -> Option<Vec<ProductionFacetKindV1>> {
        let mut kinds = packet
            .affinities()
            .iter()
            .map(|affinity| {
                self.facet_index(affinity.facet_id())
                    .map(|index| self.facets[index].kind())
            })
            .collect::<Option<Vec<_>>>()?;
        kinds.sort_unstable();
        kinds.dedup();
        Some(kinds)
    }

    fn packet_presentation_priority(&self, packet: &IntactPacketV1) -> u8 {
        packet
            .affinities()
            .iter()
            .filter_map(|affinity| self.facet_index(affinity.facet_id()))
            .map(|index| facet_presentation_priority(self.facets[index].kind()))
            .min()
            .unwrap_or(u8::MAX)
    }

    fn facet_index(&self, facet_id: FacetIdV1) -> Option<usize> {
        self.facets
            .binary_search_by_key(&facet_id, ProductionFacetV1::id)
            .ok()
    }

    fn packet_index(&self, packet_id: PacketIdV1) -> Option<usize> {
        self.packets
            .iter()
            .position(|packet| packet.id() == packet_id)
    }

    fn is_mandatory(&self, packet_id: PacketIdV1) -> bool {
        self.mandatory
            .iter()
            .any(|entry| entry.packet_id() == packet_id)
    }
}

impl fmt::Debug for SelectionProblemV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectionProblemV1")
            .field("facet_count", &self.facets.len())
            .field("packet_count", &self.packets.len())
            .field("mandatory_packet_count", &self.mandatory.len())
            .field("total_token_budget", &self.total_token_budget)
            .field("reserved_fixed_overhead", &self.reserved_fixed_overhead)
            .field("mandatory_cost", &self.mandatory_cost)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NeedsMoreReasonV1 {
    FixedOverheadExceedsTotalBudget,
    MandatoryCostExceedsAvailablePacketBudget,
}

impl NeedsMoreReasonV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::FixedOverheadExceedsTotalBudget => "fixed_overhead_exceeds_total_budget",
            Self::MandatoryCostExceedsAvailablePacketBudget => {
                "mandatory_cost_exceeds_available_packet_budget"
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct NeedsMoreSelectionV1 {
    reason: NeedsMoreReasonV1,
    reserved_fixed_overhead: u64,
    mandatory_cost: u64,
    total_token_budget: TotalTokenBudgetV1,
    mandatory_packet_count: usize,
}

impl NeedsMoreSelectionV1 {
    #[must_use]
    pub const fn reason(&self) -> NeedsMoreReasonV1 {
        self.reason
    }

    #[must_use]
    pub const fn mandatory_cost(&self) -> u64 {
        self.mandatory_cost
    }

    #[must_use]
    pub const fn reserved_fixed_overhead(&self) -> u64 {
        self.reserved_fixed_overhead
    }

    #[must_use]
    pub const fn total_token_budget(&self) -> TotalTokenBudgetV1 {
        self.total_token_budget
    }

    #[must_use]
    pub const fn mandatory_packet_count(&self) -> usize {
        self.mandatory_packet_count
    }
}

impl fmt::Debug for NeedsMoreSelectionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NeedsMoreSelectionV1")
            .field("reason", &self.reason)
            .field("reserved_fixed_overhead", &self.reserved_fixed_overhead)
            .field("mandatory_cost", &self.mandatory_cost)
            .field("total_token_budget", &self.total_token_budget)
            .field("mandatory_packet_count", &self.mandatory_packet_count)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionStrategyV1 {
    MandatoryOnly,
    DensityGreedy,
    BestSingle,
}

/// Why one packet appears in the chosen set.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SelectionConstraintV1 {
    MandatoryValidatedIdentifier { facet_id: FacetIdV1 },
    DensityGreedy,
    BestSingle,
}

impl SelectionConstraintV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::MandatoryValidatedIdentifier { .. } => "mandatory_validated_identifier",
            Self::DensityGreedy => "density_greedy",
            Self::BestSingle => "best_single",
        }
    }

    #[must_use]
    pub const fn mandatory_facet_id(self) -> Option<FacetIdV1> {
        match self {
            Self::MandatoryValidatedIdentifier { facet_id } => Some(facet_id),
            Self::DensityGreedy | Self::BestSingle => None,
        }
    }
}

impl fmt::Debug for SelectionConstraintV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectionConstraintV1")
            .field("code", &self.code())
            .finish()
    }
}

/// One intact selected packet with its full sparse affinity report.
#[derive(Clone, PartialEq, Eq)]
pub struct SelectedPacketV1 {
    packet: IntactPacketV1,
    facet_kinds: Vec<ProductionFacetKindV1>,
    marginal_gain: ObjectiveGainV1,
    forcing_constraint: SelectionConstraintV1,
}

impl SelectedPacketV1 {
    #[must_use]
    pub const fn packet(&self) -> &IntactPacketV1 {
        &self.packet
    }

    #[must_use]
    pub fn affinities(&self) -> &[FacetAffinityV1] {
        self.packet.affinities()
    }

    /// Canonical unique semantic role families attached to this packet.
    #[must_use]
    pub fn facet_kinds(&self) -> &[ProductionFacetKindV1] {
        &self.facet_kinds
    }

    #[must_use]
    pub const fn composable_token_upper_bound(&self) -> ComposablePacketCostV1 {
        self.packet.composable_token_upper_bound()
    }

    #[must_use]
    pub const fn marginal_gain(&self) -> ObjectiveGainV1 {
        self.marginal_gain
    }

    #[must_use]
    pub const fn forcing_constraint(&self) -> SelectionConstraintV1 {
        self.forcing_constraint
    }
}

impl fmt::Debug for SelectedPacketV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedPacketV1")
            .field("event_count", &self.packet.event_ids().len())
            .field("affinity_count", &self.packet.affinities().len())
            .field("facet_kind_count", &self.facet_kinds.len())
            .field(
                "composable_token_upper_bound",
                &self.composable_token_upper_bound(),
            )
            .field("marginal_gain", &self.marginal_gain)
            .field("forcing_constraint", &self.forcing_constraint)
            .finish()
    }
}

/// Successful strict-budget candidate selection.
///
/// The accounted value is an additive bound only when a downstream
/// ledger-aware compiler has verified the input cost objects. This selector
/// performs arithmetic over caller declarations; it does not certify them. A
/// later renderer must whole-render and retokenize before issuing `compiled`.
#[derive(Clone, PartialEq, Eq)]
pub struct SelectionV1 {
    strategy: SelectionStrategyV1,
    total_token_budget: TotalTokenBudgetV1,
    reserved_fixed_overhead: ReservedFixedOverheadV1,
    mandatory_token_cost: u64,
    selected_packet_cost: u64,
    accounted_token_upper_bound: u64,
    coverage_only_token_limit: u64,
    coverage_only_token_cost: u64,
    normalized_gain: ObjectiveGainV1,
    packets: Vec<SelectedPacketV1>,
}

impl SelectionV1 {
    #[must_use]
    pub const fn strategy(&self) -> SelectionStrategyV1 {
        self.strategy
    }

    #[must_use]
    pub const fn total_token_budget(&self) -> TotalTokenBudgetV1 {
        self.total_token_budget
    }

    #[must_use]
    pub const fn reserved_fixed_overhead(&self) -> ReservedFixedOverheadV1 {
        self.reserved_fixed_overhead
    }

    #[must_use]
    pub const fn mandatory_token_cost(&self) -> u64 {
        self.mandatory_token_cost
    }

    #[must_use]
    pub const fn selected_packet_cost(&self) -> u64 {
        self.selected_packet_cost
    }

    #[must_use]
    pub const fn accounted_token_upper_bound(&self) -> u64 {
        self.accounted_token_upper_bound
    }

    /// Maximum optional cost that may be spent on packets whose positive
    /// marginal contribution was exclusively source/service/time coverage.
    #[must_use]
    pub const fn coverage_only_token_limit(&self) -> u64 {
        self.coverage_only_token_limit
    }

    /// Actual selected cost charged to the coverage-only slice.
    #[must_use]
    pub const fn coverage_only_token_cost(&self) -> u64 {
        self.coverage_only_token_cost
    }

    #[must_use]
    pub const fn normalized_gain(&self) -> ObjectiveGainV1 {
        self.normalized_gain
    }

    #[must_use]
    pub fn packets(&self) -> &[SelectedPacketV1] {
        &self.packets
    }
}

impl fmt::Debug for SelectionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectionV1")
            .field("strategy", &self.strategy)
            .field("total_token_budget", &self.total_token_budget)
            .field("reserved_fixed_overhead", &self.reserved_fixed_overhead)
            .field("mandatory_token_cost", &self.mandatory_token_cost)
            .field("selected_packet_cost", &self.selected_packet_cost)
            .field(
                "accounted_token_upper_bound",
                &self.accounted_token_upper_bound,
            )
            .field("coverage_only_token_limit", &self.coverage_only_token_limit)
            .field("coverage_only_token_cost", &self.coverage_only_token_cost)
            .field("normalized_gain", &self.normalized_gain)
            .field("packet_count", &self.packets.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum SelectionDecisionV1 {
    Selected(SelectionV1),
    NeedsMore(NeedsMoreSelectionV1),
}

impl SelectionDecisionV1 {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Selected(_) => "selected",
            Self::NeedsMore(_) => "needs_more",
        }
    }
}

impl fmt::Debug for SelectionDecisionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectionDecisionV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, Copy)]
struct ScoredCandidate {
    packet_index: usize,
    gain: u64,
    coverage_only: bool,
}

#[derive(Clone, Copy)]
struct MarginalScore {
    gain: u64,
    coverage_only: bool,
}

/// Private objective state. Each call to `apply_affinity` corresponds to one
/// already-distinct selected packet: problem construction rejects overlapping
/// packet events, selection rejects duplicate packet choice, and arbitrary-set
/// evaluation rejects duplicate packet IDs.
#[derive(Clone, Copy, Default)]
struct FacetCoverageV1 {
    largest_affinity: u32,
    second_largest_affinity: u32,
}

impl FacetCoverageV1 {
    fn marginal_affinity(self, affinity: u32, cardinality: FacetSaturationCardinalityV1) -> u64 {
        let before = self.total_affinity(cardinality);
        let mut after = self;
        after.apply_affinity(affinity, cardinality);
        after.total_affinity(cardinality) - before
    }

    fn apply_affinity(&mut self, affinity: u32, cardinality: FacetSaturationCardinalityV1) {
        match cardinality {
            FacetSaturationCardinalityV1::One => {
                self.largest_affinity = self.largest_affinity.max(affinity);
            }
            FacetSaturationCardinalityV1::Two => {
                if affinity >= self.largest_affinity {
                    self.second_largest_affinity = self.largest_affinity;
                    self.largest_affinity = affinity;
                } else if affinity > self.second_largest_affinity {
                    self.second_largest_affinity = affinity;
                }
            }
        }
    }

    fn total_affinity(self, cardinality: FacetSaturationCardinalityV1) -> u64 {
        let largest = u64::from(self.largest_affinity);
        match cardinality {
            FacetSaturationCardinalityV1::One => largest,
            FacetSaturationCardinalityV1::Two => largest + u64::from(self.second_largest_affinity),
        }
    }
}

struct PlanItem {
    packet_index: usize,
}

struct CandidatePlan {
    strategy: SelectionStrategyV1,
    items: Vec<PlanItem>,
    total_gain: u64,
    token_cost: u64,
    coverage_only_token_cost: u64,
}

fn density_candidate_is_better(
    candidate: &ScoredCandidate,
    current: &ScoredCandidate,
    packets: &[IntactPacketV1],
) -> bool {
    let candidate_cost = packets[candidate.packet_index]
        .composable_token_upper_bound()
        .upper_bound_tokens();
    let current_cost = packets[current.packet_index]
        .composable_token_upper_bound()
        .upper_bound_tokens();
    let left = u128::from(candidate.gain) * u128::from(current_cost);
    let right = u128::from(current.gain) * u128::from(candidate_cost);
    match left.cmp(&right) {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => {
            candidate
                .gain
                .cmp(&current.gain)
                .then_with(|| current_cost.cmp(&candidate_cost))
                .then_with(|| current.packet_index.cmp(&candidate.packet_index))
                == Ordering::Greater
        }
    }
}

fn single_candidate_is_better(
    candidate: &ScoredCandidate,
    current: &ScoredCandidate,
    packets: &[IntactPacketV1],
) -> bool {
    let candidate_packet = &packets[candidate.packet_index];
    let current_packet = &packets[current.packet_index];
    candidate
        .gain
        .cmp(&current.gain)
        .then_with(|| {
            current_packet
                .composable_token_upper_bound()
                .upper_bound_tokens()
                .cmp(
                    &candidate_packet
                        .composable_token_upper_bound()
                        .upper_bound_tokens(),
                )
        })
        .then_with(|| current.packet_index.cmp(&candidate.packet_index))
        == Ordering::Greater
}

fn plan_is_better(candidate: &CandidatePlan, current: &CandidatePlan) -> bool {
    match candidate.total_gain.cmp(&current.total_gain) {
        Ordering::Greater => return true,
        Ordering::Less => return false,
        Ordering::Equal => {}
    }
    match current.token_cost.cmp(&candidate.token_cost) {
        Ordering::Greater => return true,
        Ordering::Less => return false,
        Ordering::Equal => {}
    }

    let mut candidate_intrinsic_indices = candidate
        .items
        .iter()
        .map(|item| item.packet_index)
        .collect::<Vec<_>>();
    let mut current_intrinsic_indices = current
        .items
        .iter()
        .map(|item| item.packet_index)
        .collect::<Vec<_>>();
    candidate_intrinsic_indices.sort_unstable();
    current_intrinsic_indices.sort_unstable();
    candidate_intrinsic_indices < current_intrinsic_indices
}

const fn facet_presentation_priority(kind: ProductionFacetKindV1) -> u8 {
    match kind {
        ProductionFacetKindV1::ValidatedQueryIdentifier
        | ProductionFacetKindV1::QueryTerm
        | ProductionFacetKindV1::FailureRole
        | ProductionFacetKindV1::OnsetRole
        | ProductionFacetKindV1::ValidatedTypedChange
        | ProductionFacetKindV1::ProviderAttestedGraphRelation => 0,
        ProductionFacetKindV1::ReconstructionRiskCoverage => 1,
        ProductionFacetKindV1::SourceCoverageStratum
        | ProductionFacetKindV1::ServiceCoverageStratum
        | ProductionFacetKindV1::TimeCoverageStratum => 2,
    }
}
