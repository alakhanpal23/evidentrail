use evidentrail_bench::{
    EXACT_SELECTION_ORACLE_POLICY_NAME_V1, EXACT_SELECTION_ORACLE_POLICY_VERSION_V1,
    EXACT_SELECTION_ORACLE_TIE_BREAK_V1, ExactSelectionOracleErrorV1,
    ExactSmallSelectionOracleDecisionV1, ExactSmallSelectionRegretDecisionV1,
    MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1, evaluate_exact_small_selection_oracle_v1,
    evaluate_exact_small_selection_regret_v1,
};
use evidentrail_schema::{ArtifactDigest, EventId};
use evidentrail_select::{
    AffinityV1, ComposableCostModelV1, ComposablePacketCostV1, FacetAffinityV1, FacetIdV1,
    FacetWeightV1, IntactPacketV1, MandatoryPacketV1, NeedsMoreReasonV1,
    PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1, PacketIdV1, ProductionFacetKindV1,
    ProductionFacetV1, ReservedFixedOverheadV1, SelectionProblemV1, SelectionStrategyV1,
    TotalTokenBudgetV1,
};

fn bytes(seed: u64) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_be_bytes());
    bytes
}

fn packet_id(seed: u64) -> PacketIdV1 {
    PacketIdV1::from_bytes(bytes(seed))
}

fn event_id(seed: u64) -> EventId {
    EventId::from_bytes(bytes(seed))
}

fn model() -> ComposableCostModelV1 {
    ComposableCostModelV1::new(ArtifactDigest::from_bytes([0x41; 32]))
}

fn facet(seed: u64, kind: ProductionFacetKindV1, weight: u32) -> ProductionFacetV1 {
    ProductionFacetV1::new(kind, &bytes(seed), FacetWeightV1::new(weight).unwrap()).unwrap()
}

fn packet(seed: u64, cost: u64, affinities: &[(FacetIdV1, u32)]) -> IntactPacketV1 {
    IntactPacketV1::new(
        packet_id(seed),
        [event_id(seed)],
        ComposablePacketCostV1::new(model(), cost).unwrap(),
        affinities.iter().map(|(facet_id, affinity)| {
            FacetAffinityV1::new(*facet_id, AffinityV1::new(*affinity).unwrap())
        }),
    )
    .unwrap()
}

fn problem(
    facets: impl IntoIterator<Item = ProductionFacetV1>,
    packets: impl IntoIterator<Item = IntactPacketV1>,
    mandatory: impl IntoIterator<Item = MandatoryPacketV1>,
    budget: u64,
    overhead: u64,
) -> SelectionProblemV1 {
    SelectionProblemV1::new(
        facets,
        packets,
        mandatory,
        TotalTokenBudgetV1::new(budget).unwrap(),
        ReservedFixedOverheadV1::new(model(), overhead).unwrap(),
    )
    .unwrap()
}

fn optimal(
    decision: ExactSmallSelectionOracleDecisionV1,
) -> evidentrail_bench::ExactSmallSelectionPlanV1 {
    let ExactSmallSelectionOracleDecisionV1::Optimal(plan) = decision else {
        panic!("fixture must have a policy-feasible optimum");
    };
    plan
}

fn better_independent_plan(
    candidate_gain: u64,
    candidate_cost: u64,
    candidate_indices: &[usize],
    current_gain: u64,
    current_cost: u64,
    current_indices: &[usize],
) -> bool {
    candidate_gain > current_gain
        || (candidate_gain == current_gain
            && (candidate_cost < current_cost
                || (candidate_cost == current_cost
                    && (candidate_indices.len() < current_indices.len()
                        || (candidate_indices.len() == current_indices.len()
                            && candidate_indices < current_indices)))))
}

fn independent_modular_optimum(
    values: &[u64],
    costs: &[u64],
    budget: u64,
) -> (u64, u64, Vec<usize>) {
    let mut best = (0_u64, 0_u64, Vec::new());
    for mask in 0..(1_usize << values.len()) {
        let mut gain = 0_u64;
        let mut cost = 0_u64;
        let mut indices = Vec::new();
        for index in 0..values.len() {
            if mask & (1_usize << index) != 0 {
                gain += values[index];
                cost += costs[index];
                indices.push(index);
            }
        }
        if cost <= budget && better_independent_plan(gain, cost, &indices, best.0, best.1, &best.2)
        {
            best = (gain, cost, indices);
        }
    }
    best
}

fn independent_provider_top_two_optimum(
    affinities: &[u32],
    costs: &[u64],
    budget: u64,
) -> (u64, u64, Vec<usize>) {
    let mut best = (0_u64, 0_u64, Vec::new());
    for mask in 0..(1_usize << affinities.len()) {
        let mut selected_affinities = Vec::new();
        let mut cost = 0_u64;
        let mut indices = Vec::new();
        for index in 0..affinities.len() {
            if mask & (1_usize << index) != 0 {
                selected_affinities.push(affinities[index]);
                cost += costs[index];
                indices.push(index);
            }
        }
        selected_affinities.sort_unstable_by(|left, right| right.cmp(left));
        let gain = selected_affinities
            .iter()
            .take(2)
            .map(|affinity| {
                u64::from(*affinity) * u64::from(PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1)
            })
            .sum();
        if cost <= budget && better_independent_plan(gain, cost, &indices, best.0, best.1, &best.2)
        {
            best = (gain, cost, indices);
        }
    }
    best
}

#[test]
fn generated_top_one_knapsacks_match_independent_exhaustive_subsets() {
    for seed in 0_u64..64 {
        let mut facets = Vec::new();
        let mut packets = Vec::new();
        let mut values = Vec::new();
        let mut costs = Vec::new();
        for index in 0..4_usize {
            let value = 100_000
                * (1 + u32::try_from((seed >> (index * 2)) & 0x3)
                    .expect("generated value fits u32"));
            let cost = 1 + ((seed + u64::try_from(index).unwrap() * 3) % 4);
            let production_facet = facet(
                1_000 + u64::try_from(index).unwrap(),
                ProductionFacetKindV1::QueryTerm,
                1,
            );
            packets.push(packet(
                2_000 + u64::try_from(index).unwrap(),
                cost,
                &[(production_facet.id(), value)],
            ));
            facets.push(production_facet);
            values.push(u64::from(value));
            costs.push(cost);
        }
        let budget = 1 + seed % 8;
        let expected = independent_modular_optimum(&values, &costs, budget);
        let exact = optimal(
            evaluate_exact_small_selection_oracle_v1(&problem(facets, packets, [], budget, 0))
                .unwrap(),
        );
        assert_eq!(exact.objective_gain().numerator(), expected.0);
        assert_eq!(exact.optional_packet_cost(), expected.1);
        assert_eq!(
            exact.optional_acceptance_order(),
            expected
                .2
                .iter()
                .map(|index| packet_id(2_000 + u64::try_from(*index).unwrap()))
                .collect::<Vec<_>>()
        );
        assert_eq!(exact.coverage_only_token_cost(), 0);
    }
}

#[test]
fn generated_provider_top_two_matches_independent_exhaustive_subsets() {
    let affinities = [1_000_000, 800_000, 300_000, 100_000];
    for seed in 0_u64..24 {
        let costs = (0..affinities.len())
            .map(|index| 1 + (seed + u64::try_from(index).unwrap() * 5) % 4)
            .collect::<Vec<_>>();
        let budget = 1 + seed % 7;
        let provider = facet(
            3_000,
            ProductionFacetKindV1::ProviderAttestedGraphRelation,
            PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1,
        );
        let packets = affinities
            .iter()
            .enumerate()
            .map(|(index, affinity)| {
                packet(
                    3_100 + u64::try_from(index).unwrap(),
                    costs[index],
                    &[(provider.id(), *affinity)],
                )
            })
            .collect::<Vec<_>>();
        let expected = independent_provider_top_two_optimum(&affinities, &costs, budget);
        let exact = optimal(
            evaluate_exact_small_selection_oracle_v1(&problem([provider], packets, [], budget, 0))
                .unwrap(),
        );
        assert_eq!(exact.objective_gain().numerator(), expected.0);
        assert_eq!(exact.optional_packet_cost(), expected.1);
        assert_eq!(
            exact.optional_acceptance_order(),
            expected
                .2
                .iter()
                .map(|index| packet_id(3_100 + u64::try_from(*index).unwrap()))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn mandatory_provider_baseline_leaves_one_exact_complement_slot() {
    let identifier = facet(4_000, ProductionFacetKindV1::ValidatedQueryIdentifier, 1);
    let provider = facet(
        4_001,
        ProductionFacetKindV1::ProviderAttestedGraphRelation,
        PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1,
    );
    let mandatory_packet = packet(
        4_100,
        2,
        &[(identifier.id(), 1), (provider.id(), 1_000_000)],
    );
    let expensive = packet(4_101, 3, &[(provider.id(), 1_000_000)]);
    let cheap = packet(4_102, 1, &[(provider.id(), 1_000_000)]);
    let exact = optimal(
        evaluate_exact_small_selection_oracle_v1(&problem(
            [identifier.clone(), provider],
            [mandatory_packet.clone(), expensive, cheap],
            [MandatoryPacketV1::validated_identifier(
                mandatory_packet.id(),
                identifier.id(),
            )],
            4,
            1,
        ))
        .unwrap(),
    );
    assert_eq!(exact.mandatory_packet_ids(), &[packet_id(4_100)]);
    assert_eq!(exact.optional_acceptance_order(), &[packet_id(4_102)]);
    assert_eq!(exact.objective_gain().numerator(), 500_000_000_000);
    assert_eq!(exact.mandatory_packet_cost(), 2);
    assert_eq!(exact.optional_packet_cost(), 1);
    assert_eq!(exact.accounted_token_upper_bound(), 4);
}

#[test]
fn dynamic_coverage_only_feasibility_preserves_the_exact_acceptance_order() {
    let diagnostic = facet(5_000, ProductionFacetKindV1::QueryTerm, 1);
    let breadth = facet(5_001, ProductionFacetKindV1::SourceCoverageStratum, 1);
    let mixed = packet(
        5_100,
        2,
        &[(diagnostic.id(), 500_000), (breadth.id(), 1_000_000)],
    );
    let diagnostic_saturator = packet(5_101, 1, &[(diagnostic.id(), 1_000_000)]);
    let exact = optimal(
        evaluate_exact_small_selection_oracle_v1(&problem(
            [diagnostic, breadth],
            [diagnostic_saturator, mixed],
            [],
            3,
            0,
        ))
        .unwrap(),
    );
    assert_eq!(exact.coverage_only_token_limit(), 0);
    assert_eq!(exact.coverage_only_token_cost(), 0);
    assert_eq!(
        exact.optional_acceptance_order(),
        &[packet_id(5_100), packet_id(5_101)],
        "the mixed packet must enter while it still has diagnostic marginal gain",
    );
    assert_eq!(exact.objective_gain().numerator(), 2_000_000);
    assert_eq!(exact.reachable_subset_count(), 4);
}

#[test]
fn mixed_primary_and_coverage_only_paths_charge_the_closed_slice_exactly() {
    let diagnostic = facet(6_000, ProductionFacetKindV1::QueryTerm, 1);
    let breadth_a = facet(6_001, ProductionFacetKindV1::SourceCoverageStratum, 1);
    let breadth_b = facet(6_002, ProductionFacetKindV1::TimeCoverageStratum, 1);
    let mixed = packet(
        6_100,
        2,
        &[(diagnostic.id(), 500_000), (breadth_a.id(), 1_000_000)],
    );
    let diagnostic_saturator = packet(6_101, 1, &[(diagnostic.id(), 1_000_000)]);
    let coverage_only = packet(6_102, 1, &[(breadth_b.id(), 1_000_000)]);
    let exact = optimal(
        evaluate_exact_small_selection_oracle_v1(&problem(
            [breadth_b, diagnostic, breadth_a],
            [coverage_only, diagnostic_saturator, mixed],
            [],
            8,
            0,
        ))
        .unwrap(),
    );
    assert_eq!(exact.coverage_only_token_limit(), 1);
    assert_eq!(exact.coverage_only_token_cost(), 1);
    assert_eq!(
        exact.optional_acceptance_order(),
        &[packet_id(6_100), packet_id(6_101), packet_id(6_102)]
    );
    assert_eq!(exact.objective_gain().numerator(), 3_000_000);
}

#[test]
fn canonical_problem_order_makes_oracle_output_permutation_invariant() {
    let diagnostic = facet(7_000, ProductionFacetKindV1::FailureRole, 1);
    let provider = facet(
        7_001,
        ProductionFacetKindV1::ProviderAttestedGraphRelation,
        PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1,
    );
    let packets = [
        packet(7_100, 2, &[(diagnostic.id(), 1_000_000)]),
        packet(7_101, 1, &[(provider.id(), 1_000_000)]),
        packet(7_102, 1, &[(provider.id(), 800_000)]),
    ];
    let first = evaluate_exact_small_selection_oracle_v1(&problem(
        [diagnostic.clone(), provider.clone()],
        packets.clone(),
        [],
        4,
        0,
    ))
    .unwrap();
    let second = evaluate_exact_small_selection_oracle_v1(&problem(
        [provider, diagnostic],
        packets.into_iter().rev(),
        [],
        4,
        0,
    ))
    .unwrap();
    assert_eq!(first, second);
}

#[test]
fn frozen_modular_witness_has_nonzero_greedy_max_regret() {
    let facets = [
        facet(8_000, ProductionFacetKindV1::QueryTerm, 1),
        facet(8_001, ProductionFacetKindV1::QueryTerm, 1),
        facet(8_002, ProductionFacetKindV1::QueryTerm, 1),
    ];
    let packets = [
        packet(8_100, 6, &[(facets[0].id(), 600_000)]),
        packet(8_101, 5, &[(facets[1].id(), 500_000)]),
        packet(8_102, 5, &[(facets[2].id(), 500_000)]),
    ];
    let decision =
        evaluate_exact_small_selection_regret_v1(&problem(facets, packets, [], 10, 0)).unwrap();
    let ExactSmallSelectionRegretDecisionV1::Evaluated(regret) = decision else {
        panic!("witness must be evaluated");
    };
    assert_eq!(
        regret.production_strategy(),
        SelectionStrategyV1::DensityGreedy
    );
    assert_eq!(regret.production_objective_gain().numerator(), 600_000);
    assert_eq!(regret.production_packet_ids(), &[packet_id(8_100)]);
    assert_eq!(regret.optimum().objective_gain().numerator(), 1_000_000);
    assert_eq!(
        regret.optimum().optional_acceptance_order(),
        &[packet_id(8_101), packet_id(8_102)]
    );
    assert_eq!(regret.regret_numerator(), 400_000);
    assert!(!regret.claims_approximation_factor());
}

#[test]
fn bounds_terminal_decisions_and_debug_surfaces_are_explicit_and_contentless() {
    assert_eq!(
        EXACT_SELECTION_ORACLE_POLICY_NAME_V1,
        b"evidentrail/bench/exact-small-production-selection-oracle"
    );
    assert_eq!(EXACT_SELECTION_ORACLE_POLICY_VERSION_V1, b"2");
    assert_eq!(
        EXACT_SELECTION_ORACLE_TIE_BREAK_V1,
        "gain_desc,total_packet_cost_asc,coverage_charge_asc,optional_count_asc,canonical_acceptance_order_asc"
    );

    let too_many_facets = (0..=MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1)
        .map(|index| {
            facet(
                9_000 + u64::try_from(index).unwrap(),
                ProductionFacetKindV1::QueryTerm,
                1,
            )
        })
        .collect::<Vec<_>>();
    let too_many_packets = too_many_facets
        .iter()
        .enumerate()
        .map(|(index, facet)| packet(9_100 + u64::try_from(index).unwrap(), 1, &[(facet.id(), 1)]))
        .collect::<Vec<_>>();
    let error = evaluate_exact_small_selection_oracle_v1(&problem(
        too_many_facets,
        too_many_packets,
        [],
        100,
        0,
    ))
    .unwrap_err();
    assert_eq!(error, ExactSelectionOracleErrorV1::TooManyOptionalPackets);
    assert_eq!(
        format!("{error:?}"),
        "ExactSelectionOracleErrorV1 { code: \"EVIDENTRAIL_BENCH_EXACT_ORACLE_OPTIONAL_PACKET_CAP\" }"
    );

    let fixed = evaluate_exact_small_selection_regret_v1(&problem([], [], [], 0, 1)).unwrap();
    let ExactSmallSelectionRegretDecisionV1::NeedsMore(fixed) = fixed else {
        panic!("fixed overhead must be terminal");
    };
    assert_eq!(
        fixed.reason(),
        NeedsMoreReasonV1::FixedOverheadExceedsTotalBudget
    );

    let identifier = facet(9_500, ProductionFacetKindV1::ValidatedQueryIdentifier, 1);
    let forced = packet(9_501, 2, &[(identifier.id(), 1)]);
    let mandatory = evaluate_exact_small_selection_oracle_v1(&problem(
        [identifier.clone()],
        [forced.clone()],
        [MandatoryPacketV1::validated_identifier(
            forced.id(),
            identifier.id(),
        )],
        1,
        0,
    ))
    .unwrap();
    let ExactSmallSelectionOracleDecisionV1::NeedsMore(mandatory) = mandatory else {
        panic!("mandatory over-budget must be terminal");
    };
    assert_eq!(
        mandatory.reason(),
        NeedsMoreReasonV1::MandatoryCostExceedsAvailablePacketBudget
    );
    let debug = format!("{mandatory:?}");
    assert!(!debug.contains("9500"));
    assert!(!debug.contains("9501"));
}
