use evidentrail_bench::{
    BOUNDED_SELECTOR_CHALLENGER_BEAM_WIDTH_V1, BOUNDED_SELECTOR_CHALLENGER_TRANSITION_CAP_V1,
    BoundedSelectorChallengerModeV1, BoundedSelectorCostRelationV1,
    BoundedSelectorObjectiveRelationV1, BoundedSelectorPlanSourceV1,
    evaluate_bounded_selector_challenger_v1,
};
use evidentrail_schema::{ArtifactDigest, EventId};
use evidentrail_select::{
    AffinityV1, ComposableCostModelV1, ComposablePacketCostV1, FacetAffinityV1, FacetWeightV1,
    IntactPacketV1, PacketIdV1, ProductionFacetKindV1, ProductionFacetV1, ReservedFixedOverheadV1,
    SelectionProblemV1, TotalTokenBudgetV1,
};

fn bytes(seed: u64) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_be_bytes());
    bytes
}

fn model() -> ComposableCostModelV1 {
    ComposableCostModelV1::new(ArtifactDigest::from_bytes([0x74; 32]))
}

fn independent_problem(specifications: &[(u64, u32)], budget: u64) -> SelectionProblemV1 {
    independent_problem_with_order(specifications, budget, false)
}

fn independent_problem_with_order(
    specifications: &[(u64, u32)],
    budget: u64,
    reverse_input_order: bool,
) -> SelectionProblemV1 {
    let mut facets = Vec::new();
    let mut packets = Vec::new();
    for (index, (cost, affinity)) in specifications.iter().copied().enumerate() {
        let seed = u64::try_from(index).unwrap() + 1;
        let facet = ProductionFacetV1::new(
            ProductionFacetKindV1::QueryTerm,
            &bytes(seed),
            FacetWeightV1::new(1).unwrap(),
        )
        .unwrap();
        packets.push(
            IntactPacketV1::new(
                PacketIdV1::from_bytes(bytes(seed + 10_000)),
                [EventId::from_bytes(bytes(seed + 20_000))],
                ComposablePacketCostV1::new(model(), cost).unwrap(),
                [FacetAffinityV1::new(
                    facet.id(),
                    AffinityV1::new(affinity).unwrap(),
                )],
            )
            .unwrap(),
        );
        facets.push(facet);
    }
    if reverse_input_order {
        facets.reverse();
        packets.reverse();
    }
    SelectionProblemV1::new(
        facets,
        packets,
        [],
        TotalTokenBudgetV1::new(budget).unwrap(),
        ReservedFixedOverheadV1::new(model(), 0).unwrap(),
    )
    .unwrap()
}

#[test]
fn exact_arm_fixes_the_frozen_density_witness_with_closed_work_bounds() {
    let problem = independent_problem(&[(6, 600_000), (5, 500_000), (5, 500_000)], 10);
    let pair = evaluate_bounded_selector_challenger_v1(&problem).unwrap();

    assert_eq!(pair.mode(), BoundedSelectorChallengerModeV1::ExactSubsets);
    assert_eq!(pair.optional_packet_count(), 3);
    assert_eq!(pair.bounds().state_slot_cap(), 8);
    assert_eq!(pair.bounds().transition_attempt_cap(), 24);
    assert_eq!(pair.bounds().depth_cap(), 3);
    assert_eq!(pair.observation().transition_attempts(), None);
    assert!(!pair.observation().transition_cap_reached());
    assert_eq!(
        pair.objective_relation(),
        BoundedSelectorObjectiveRelationV1::ChallengerBetter
    );
    assert_eq!(
        pair.selected_cost_relation(),
        BoundedSelectorCostRelationV1::ChallengerHigher
    );
    assert_eq!(
        pair.production()
            .selected()
            .unwrap()
            .objective_gain_numerator(),
        600_000
    );
    assert_eq!(
        pair.challenger()
            .selected()
            .unwrap()
            .objective_gain_numerator(),
        1_000_000
    );
    assert_eq!(
        pair.challenger().selected().unwrap().source(),
        BoundedSelectorPlanSourceV1::ExactSubset
    );
    assert!(pair.hard_constraints_preserved());
    assert!(!pair.contains_labels());
    assert!(!pair.claims_wall_time_or_rss());
}

#[test]
fn large_beam_enforces_transition_and_state_caps_then_falls_back_without_regression() {
    let specifications = (0..80).map(|_| (1, 1)).collect::<Vec<_>>();
    let problem = independent_problem(&specifications, 80);
    let replay_problem = independent_problem_with_order(&specifications, 80, true);
    let pair = evaluate_bounded_selector_challenger_v1(&problem).unwrap();
    let replay = evaluate_bounded_selector_challenger_v1(&replay_problem).unwrap();

    assert_eq!(pair, replay);
    assert_eq!(pair.digest(), replay.digest());
    assert_eq!(pair.mode(), BoundedSelectorChallengerModeV1::OrderAwareBeam);
    assert_eq!(pair.optional_packet_count(), 80);
    assert_eq!(
        pair.bounds().state_slot_cap(),
        u64::try_from(BOUNDED_SELECTOR_CHALLENGER_BEAM_WIDTH_V1 * 2 + 1).unwrap()
    );
    assert_eq!(
        pair.bounds().transition_attempt_cap(),
        BOUNDED_SELECTOR_CHALLENGER_TRANSITION_CAP_V1
    );
    assert_eq!(
        pair.observation().transition_attempts(),
        Some(BOUNDED_SELECTOR_CHALLENGER_TRANSITION_CAP_V1)
    );
    assert!(pair.observation().transition_cap_reached());
    assert!(pair.observation().retained_state_high_water() <= pair.bounds().state_slot_cap());
    assert_eq!(
        pair.objective_relation(),
        BoundedSelectorObjectiveRelationV1::Equal
    );
    assert_eq!(
        pair.challenger().selected().unwrap().source(),
        BoundedSelectorPlanSourceV1::ProductionFallback
    );
    assert_eq!(
        pair.challenger()
            .selected()
            .unwrap()
            .objective_gain_numerator(),
        pair.production()
            .selected()
            .unwrap()
            .objective_gain_numerator()
    );
    assert!(pair.hard_constraints_preserved());
}
