use evidentrail_schema::{ArtifactDigest, EventId, bounds::JSON_SAFE_INTEGER_MAX};
use evidentrail_select::{
    AffinityV1, COVERAGE_ONLY_OPTIONAL_BUDGET_DENOMINATOR_V1, ComposableCostModelV1,
    ComposablePacketCostV1, FacetAffinityV1, FacetConstructionError, FacetIdV1,
    FacetSaturationCardinalityV1, FacetWeightV1, FixedPointConstructionError, IntactPacketV1,
    MandatoryPacketV1, NeedsMoreReasonV1, ObjectiveEvaluationError,
    PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1, PacketConstructionError, PacketIdV1,
    ProductionFacetKindV1, ProductionFacetV1, ReservedFixedOverheadV1,
    SELECTION_OBJECTIVE_POLICY_VERSION_V1, SelectionConstraintV1, SelectionDecisionV1,
    SelectionProblemConstructionError, SelectionProblemV1, SelectionStrategyV1,
    TokenValueConstructionError, TotalTokenBudgetV1,
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

fn model(seed: u8) -> ComposableCostModelV1 {
    ComposableCostModelV1::new(ArtifactDigest::from_bytes([seed; 32]))
}

fn weight(micros: u32) -> FacetWeightV1 {
    FacetWeightV1::new(micros).unwrap()
}

fn affinity(micros: u32) -> AffinityV1 {
    AffinityV1::new(micros).unwrap()
}

fn facet(seed: u64, kind: ProductionFacetKindV1, micros: u32) -> ProductionFacetV1 {
    ProductionFacetV1::new(kind, &bytes(seed), weight(micros)).unwrap()
}

fn packet_with_model(
    seed: u64,
    events: &[u64],
    token_upper_bound: u64,
    affinities: &[(FacetIdV1, u32)],
    cost_model: ComposableCostModelV1,
) -> IntactPacketV1 {
    IntactPacketV1::new(
        packet_id(seed),
        events.iter().copied().map(event_id),
        ComposablePacketCostV1::new(cost_model, token_upper_bound).unwrap(),
        affinities
            .iter()
            .map(|(facet_id, micros)| FacetAffinityV1::new(*facet_id, affinity(*micros))),
    )
    .unwrap()
}

fn packet(
    seed: u64,
    events: &[u64],
    token_upper_bound: u64,
    affinities: &[(FacetIdV1, u32)],
) -> IntactPacketV1 {
    packet_with_model(seed, events, token_upper_bound, affinities, model(1))
}

fn overhead(tokens: u64) -> ReservedFixedOverheadV1 {
    ReservedFixedOverheadV1::new(model(1), tokens).unwrap()
}

fn budget(tokens: u64) -> TotalTokenBudgetV1 {
    TotalTokenBudgetV1::new(tokens).unwrap()
}

fn selected(decision: SelectionDecisionV1) -> evidentrail_select::SelectionV1 {
    let SelectionDecisionV1::Selected(selection) = decision else {
        panic!("fixture must select");
    };
    selection
}

#[test]
fn fixed_point_cost_facet_and_packet_construction_reject_noncanonical_values() {
    assert_eq!(
        FacetWeightV1::new(0),
        Err(FixedPointConstructionError::Zero)
    );
    assert_eq!(
        AffinityV1::new(evidentrail_select::AFFINITY_SCALE_V1 + 1),
        Err(FixedPointConstructionError::AboveUnitScale)
    );
    assert_eq!(
        ComposablePacketCostV1::new(model(1), 0),
        Err(TokenValueConstructionError::ZeroCost)
    );
    assert_eq!(
        ComposablePacketCostV1::new(model(1), JSON_SAFE_INTEGER_MAX + 1),
        Err(TokenValueConstructionError::AboveJsonSafeInteger)
    );
    assert_eq!(
        TotalTokenBudgetV1::new(JSON_SAFE_INTEGER_MAX + 1),
        Err(TokenValueConstructionError::AboveJsonSafeInteger)
    );
    assert_eq!(budget(0).tokens(), 0);
    assert_eq!(overhead(0).upper_bound_tokens(), 0);

    assert_eq!(
        ProductionFacetV1::new(ProductionFacetKindV1::QueryTerm, b"", weight(1)),
        Err(FacetConstructionError::EmptySemanticKey)
    );
    let too_large_key = vec![0_u8; evidentrail_select::MAX_FACET_SEMANTIC_KEY_BYTES_V1 + 1];
    assert_eq!(
        ProductionFacetV1::new(ProductionFacetKindV1::QueryTerm, &too_large_key, weight(1),),
        Err(FacetConstructionError::SemanticKeyTooLarge)
    );
    let same_a =
        ProductionFacetV1::new(ProductionFacetKindV1::QueryTerm, b"typed-key", weight(1)).unwrap();
    let same_b =
        ProductionFacetV1::new(ProductionFacetKindV1::QueryTerm, b"typed-key", weight(9)).unwrap();
    let other_kind = ProductionFacetV1::new(
        ProductionFacetKindV1::ValidatedQueryIdentifier,
        b"typed-key",
        weight(1),
    )
    .unwrap();
    assert_eq!(same_a.id(), same_b.id());
    assert_ne!(same_a.id(), other_kind.id());
    assert_eq!(SELECTION_OBJECTIVE_POLICY_VERSION_V1, b"2");
    assert_eq!(PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1, 500_000);
    assert_eq!(
        ProductionFacetKindV1::ProviderAttestedGraphRelation.saturation_cardinality(),
        FacetSaturationCardinalityV1::Two
    );
    assert!(
        ProductionFacetKindV1::ALL_V1
            .into_iter()
            .filter(|kind| *kind != ProductionFacetKindV1::ProviderAttestedGraphRelation)
            .all(|kind| kind.saturation_cardinality() == FacetSaturationCardinalityV1::One)
    );
    assert_eq!(
        ProductionFacetV1::new(
            ProductionFacetKindV1::ProviderAttestedGraphRelation,
            b"relation",
            weight(evidentrail_select::AFFINITY_SCALE_V1),
        ),
        Err(FacetConstructionError::InvalidProviderRelationWeight)
    );

    assert_eq!(
        IntactPacketV1::new(
            packet_id(1),
            [],
            ComposablePacketCostV1::new(model(1), 1).unwrap(),
            [],
        ),
        Err(PacketConstructionError::EmptyEventSet)
    );
    assert_eq!(
        IntactPacketV1::new(
            packet_id(1),
            [event_id(1), event_id(1)],
            ComposablePacketCostV1::new(model(1), 1).unwrap(),
            [],
        ),
        Err(PacketConstructionError::DuplicateEvent)
    );
    assert_eq!(
        IntactPacketV1::new(
            packet_id(1),
            [event_id(1)],
            ComposablePacketCostV1::new(model(1), 1).unwrap(),
            [],
        ),
        Err(PacketConstructionError::EmptyAffinitySet)
    );
    let duplicate_affinity = FacetAffinityV1::new(same_a.id(), affinity(1));
    assert_eq!(
        IntactPacketV1::new(
            packet_id(1),
            [event_id(1)],
            ComposablePacketCostV1::new(model(1), 1).unwrap(),
            [duplicate_affinity, duplicate_affinity],
        ),
        Err(PacketConstructionError::DuplicateFacetAffinity)
    );

    let f1 = facet(1, ProductionFacetKindV1::QueryTerm, 1);
    let f2 = facet(2, ProductionFacetKindV1::FailureRole, 1);
    let f3 = facet(3, ProductionFacetKindV1::OnsetRole, 1);
    let canonical = IntactPacketV1::new(
        packet_id(7),
        [event_id(3), event_id(1), event_id(2)],
        ComposablePacketCostV1::new(model(1), 3).unwrap(),
        [
            FacetAffinityV1::new(f3.id(), affinity(3)),
            FacetAffinityV1::new(f1.id(), affinity(1)),
            FacetAffinityV1::new(f2.id(), affinity(2)),
        ],
    )
    .unwrap();
    assert_eq!(
        canonical.event_ids(),
        &[event_id(1), event_id(2), event_id(3)]
    );
    assert!(
        canonical
            .affinities()
            .windows(2)
            .all(|pair| pair[0].facet_id() < pair[1].facet_id())
    );
}

#[test]
fn problem_rejects_cloned_semantics_duplicates_overlap_unknowns_and_bad_authority() {
    let identifier = facet(1, ProductionFacetKindV1::ValidatedQueryIdentifier, 10);
    let identifier_clone = ProductionFacetV1::new(
        ProductionFacetKindV1::ValidatedQueryIdentifier,
        &bytes(1),
        weight(99),
    )
    .unwrap();
    let term = facet(2, ProductionFacetKindV1::QueryTerm, 10);
    let unregistered = facet(3, ProductionFacetKindV1::FailureRole, 10);
    let p1 = packet(1, &[1], 2, &[(identifier.id(), 5)]);
    let p2 = packet(2, &[2], 2, &[(term.id(), 5)]);

    assert_eq!(
        SelectionProblemV1::new(
            [identifier.clone(), identifier_clone],
            [p1.clone()],
            [],
            budget(10),
            overhead(0),
        )
        .unwrap_err(),
        SelectionProblemConstructionError::DuplicateFacetId
    );
    assert_eq!(
        SelectionProblemV1::new(
            [identifier.clone()],
            [p1.clone(), packet(1, &[2], 2, &[(identifier.id(), 5)]),],
            [],
            budget(10),
            overhead(0),
        )
        .unwrap_err(),
        SelectionProblemConstructionError::DuplicatePacketId
    );
    assert_eq!(
        SelectionProblemV1::new(
            [identifier.clone()],
            [p1.clone(), packet(2, &[1], 2, &[(identifier.id(), 5)]),],
            [],
            budget(10),
            overhead(0),
        )
        .unwrap_err(),
        SelectionProblemConstructionError::OverlappingEvent
    );
    assert_eq!(
        SelectionProblemV1::new(
            [identifier.clone()],
            [packet(3, &[3], 1, &[(unregistered.id(), 1)])],
            [],
            budget(10),
            overhead(0),
        )
        .unwrap_err(),
        SelectionProblemConstructionError::UnknownAffinityFacet
    );
    assert_eq!(
        SelectionProblemV1::new(
            [identifier.clone()],
            [packet_with_model(
                4,
                &[4],
                1,
                &[(identifier.id(), 1)],
                model(2),
            )],
            [],
            budget(10),
            overhead(0),
        )
        .unwrap_err(),
        SelectionProblemConstructionError::CostModelMismatch
    );

    let unknown_packet = MandatoryPacketV1::validated_identifier(packet_id(99), identifier.id());
    assert_eq!(
        SelectionProblemV1::new(
            [identifier.clone()],
            [p1.clone()],
            [unknown_packet],
            budget(10),
            overhead(0),
        )
        .unwrap_err(),
        SelectionProblemConstructionError::UnknownMandatoryPacket
    );
    let mandatory = MandatoryPacketV1::validated_identifier(packet_id(1), identifier.id());
    assert_eq!(
        SelectionProblemV1::new(
            [identifier.clone()],
            [p1.clone()],
            [mandatory, mandatory],
            budget(10),
            overhead(0),
        )
        .unwrap_err(),
        SelectionProblemConstructionError::DuplicateMandatoryPacket
    );
    assert_eq!(
        SelectionProblemV1::new(
            [identifier.clone(), term.clone()],
            [p1.clone()],
            [MandatoryPacketV1::validated_identifier(
                packet_id(1),
                term.id(),
            )],
            budget(10),
            overhead(0),
        )
        .unwrap_err(),
        SelectionProblemConstructionError::MandatoryFacetNotValidatedIdentifier
    );
    assert_eq!(
        SelectionProblemV1::new(
            [identifier.clone(), term],
            [p2],
            [MandatoryPacketV1::validated_identifier(
                packet_id(2),
                identifier.id(),
            )],
            budget(10),
            overhead(0),
        )
        .unwrap_err(),
        SelectionProblemConstructionError::MandatoryPacketLacksIdentifierAffinity
    );
}

#[test]
fn universe_cost_overflow_is_rejected_before_selection() {
    let term = facet(1, ProductionFacetKindV1::QueryTerm, 1);
    let packets = (0_u64..2_049)
        .map(|index| {
            packet(
                index + 1,
                &[index + 1],
                JSON_SAFE_INTEGER_MAX,
                &[(term.id(), 1)],
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        SelectionProblemV1::new([term], packets, [], budget(0), overhead(0)).unwrap_err(),
        SelectionProblemConstructionError::UniverseTokenCostOverflow
    );
}

#[test]
fn normalized_facility_coverage_is_exhaustively_monotone_and_submodular() {
    let identifier = facet(1, ProductionFacetKindV1::ValidatedQueryIdentifier, 2);
    let failure = facet(2, ProductionFacetKindV1::FailureRole, 3);
    let time = facet(3, ProductionFacetKindV1::TimeCoverageStratum, 5);
    let packets = [
        packet(1, &[1], 2, &[(identifier.id(), 7), (failure.id(), 3)]),
        packet(2, &[2], 3, &[(identifier.id(), 4), (time.id(), 9)]),
        packet(3, &[3], 4, &[(failure.id(), 8), (time.id(), 2)]),
        packet(
            4,
            &[4],
            1,
            &[(identifier.id(), 1), (failure.id(), 1), (time.id(), 1)],
        ),
    ];
    let problem = SelectionProblemV1::new(
        [identifier.clone(), failure, time],
        packets,
        [MandatoryPacketV1::validated_identifier(
            packet_id(1),
            identifier.id(),
        )],
        budget(20),
        overhead(0),
    )
    .unwrap();
    let optional = [packet_id(2), packet_id(3), packet_id(4)];
    let gain = |mask: u8| {
        problem
            .normalized_gain(
                optional
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| mask & (1 << index) != 0)
                    .map(|(_, packet_id)| *packet_id),
            )
            .unwrap()
            .numerator()
    };

    assert_eq!(gain(0), 0);
    for smaller in 0_u8..8 {
        for larger in 0_u8..8 {
            if smaller & !larger != 0 {
                continue;
            }
            assert!(gain(smaller) <= gain(larger));
            for element in 0..3 {
                let bit = 1 << element;
                if larger & bit != 0 {
                    continue;
                }
                let marginal_smaller = gain(smaller | bit) - gain(smaller);
                let marginal_larger = gain(larger | bit) - gain(larger);
                assert!(marginal_smaller >= marginal_larger);
            }
        }
    }
    assert_eq!(
        problem.normalized_gain([packet_id(2), packet_id(2)]),
        Err(ObjectiveEvaluationError::DuplicatePacket)
    );
    assert_eq!(
        problem.normalized_gain([packet_id(1)]),
        Err(ObjectiveEvaluationError::MandatoryPacketIncluded)
    );
    assert_eq!(
        problem.normalized_gain([packet_id(99)]),
        Err(ObjectiveEvaluationError::UnknownPacket)
    );
}

#[test]
fn provider_top_two_is_exhaustively_monotone_submodular_and_third_is_zero() {
    let provider = facet(
        40,
        ProductionFacetKindV1::ProviderAttestedGraphRelation,
        PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1,
    );
    let packets = [
        packet(40, &[40], 1, &[(provider.id(), 1_000_000)]),
        packet(41, &[41], 1, &[(provider.id(), 800_000)]),
        packet(42, &[42], 1, &[(provider.id(), 300_000)]),
    ];
    let problem = SelectionProblemV1::new([provider], packets, [], budget(3), overhead(0)).unwrap();
    let optional = [packet_id(40), packet_id(41), packet_id(42)];
    let gain = |mask: u8| {
        problem
            .normalized_gain(
                optional
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| mask & (1 << index) != 0)
                    .map(|(_, packet_id)| *packet_id),
            )
            .unwrap()
            .numerator()
    };

    for smaller in 0_u8..8 {
        for larger in 0_u8..8 {
            if smaller & !larger != 0 {
                continue;
            }
            assert!(gain(smaller) <= gain(larger));
            for element in 0..3 {
                let bit = 1 << element;
                if larger & bit != 0 {
                    continue;
                }
                assert!(gain(smaller | bit) - gain(smaller) >= gain(larger | bit) - gain(larger));
            }
        }
    }
    assert_eq!(gain(0b001), 500_000_000_000);
    assert_eq!(gain(0b011), 900_000_000_000);
    assert_eq!(gain(0b111), 900_000_000_000);
    assert_eq!(gain(0b111) - gain(0b011), 0);
    assert_eq!(
        problem.normalized_gain([packet_id(40), packet_id(40)]),
        Err(ObjectiveEvaluationError::DuplicatePacket),
        "one packet can never occupy both saturation slots",
    );
}

#[test]
fn mandatory_provider_endpoint_leaves_one_complement_slot_and_budget_is_exact() {
    let identifier = facet(50, ProductionFacetKindV1::ValidatedQueryIdentifier, 1);
    let provider = facet(
        51,
        ProductionFacetKindV1::ProviderAttestedGraphRelation,
        PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1,
    );
    let packets = [
        packet(
            50,
            &[50],
            2,
            &[(identifier.id(), 1), (provider.id(), 1_000_000)],
        ),
        packet(51, &[51], 3, &[(provider.id(), 1_000_000)]),
        packet(52, &[52], 1, &[(provider.id(), 1_000_000)]),
    ];
    let mandatory = [MandatoryPacketV1::validated_identifier(
        packet_id(50),
        identifier.id(),
    )];
    let build = |tokens| {
        SelectionProblemV1::new(
            [identifier.clone(), provider.clone()],
            packets.clone(),
            mandatory,
            budget(tokens),
            overhead(1),
        )
        .unwrap()
    };
    let below = selected(build(3).select().unwrap());
    assert_eq!(below.packets().len(), 1);
    assert_eq!(below.normalized_gain().numerator(), 0);

    let exact = selected(build(4).select().unwrap());
    assert_eq!(exact.accounted_token_upper_bound(), 4);
    assert_eq!(exact.coverage_only_token_cost(), 0);
    assert_eq!(exact.packets().len(), 2);
    assert_eq!(exact.packets()[0].packet().id(), packet_id(50));
    assert_eq!(exact.packets()[1].packet().id(), packet_id(52));
    assert_eq!(
        exact.packets()[1].marginal_gain().numerator(),
        500_000_000_000
    );
    assert_eq!(
        build(6)
            .normalized_gain([packet_id(51), packet_id(52)])
            .unwrap()
            .numerator(),
        500_000_000_000,
        "the third distinct endpoint contributes zero after mandatory + complement",
    );
}

#[test]
fn best_single_respects_provider_top_two_baseline_and_beats_density_prefix() {
    let identifier = facet(60, ProductionFacetKindV1::ValidatedQueryIdentifier, 1);
    let provider = facet(
        61,
        ProductionFacetKindV1::ProviderAttestedGraphRelation,
        PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1,
    );
    let packets = [
        packet(
            60,
            &[60],
            1,
            &[(identifier.id(), 1), (provider.id(), 1_000_000)],
        ),
        packet(61, &[61], 5, &[(provider.id(), 1_000_000)]),
        packet(62, &[62], 2, &[(provider.id(), 500_000)]),
    ];
    let selection = selected(
        SelectionProblemV1::new(
            [identifier.clone(), provider],
            packets,
            [MandatoryPacketV1::validated_identifier(
                packet_id(60),
                identifier.id(),
            )],
            budget(6),
            overhead(0),
        )
        .unwrap()
        .select()
        .unwrap(),
    );
    assert_eq!(selection.strategy(), SelectionStrategyV1::BestSingle);
    assert_eq!(selection.packets().len(), 2);
    assert_eq!(selection.packets()[1].packet().id(), packet_id(61));
    assert_eq!(selection.normalized_gain().numerator(), 500_000_000_000);
    assert_eq!(
        selection.packets()[1].forcing_constraint(),
        SelectionConstraintV1::BestSingle
    );
}

#[test]
fn provider_top_two_selection_is_permutation_stable_and_presentation_exact() {
    let provider = facet(
        70,
        ProductionFacetKindV1::ProviderAttestedGraphRelation,
        PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1,
    );
    let risk = facet(71, ProductionFacetKindV1::ReconstructionRiskCoverage, 1);
    let facets = [provider.clone(), risk.clone()];
    let packets = [
        packet(70, &[70], 2, &[(provider.id(), 1_000_000)]),
        packet(71, &[71], 2, &[(provider.id(), 1_000_000)]),
        packet(72, &[72], 1, &[(risk.id(), 1_000_000)]),
        packet(73, &[73], 1, &[(provider.id(), 1_000_000)]),
    ];
    let expected =
        SelectionProblemV1::new(facets.clone(), packets.clone(), [], budget(5), overhead(0))
            .unwrap()
            .select()
            .unwrap();
    for facet_order in permutations(&facets) {
        for packet_order in permutations(&packets) {
            assert_eq!(
                SelectionProblemV1::new(
                    facet_order.clone(),
                    packet_order,
                    [],
                    budget(5),
                    overhead(0),
                )
                .unwrap()
                .select()
                .unwrap(),
                expected
            );
        }
    }
    let selection = selected(expected);
    let provider_packets = selection
        .packets()
        .iter()
        .filter(|packet| {
            packet
                .facet_kinds()
                .contains(&ProductionFacetKindV1::ProviderAttestedGraphRelation)
        })
        .collect::<Vec<_>>();
    assert_eq!(provider_packets.len(), 2);
    assert_eq!(
        provider_packets
            .iter()
            .map(|packet| packet.marginal_gain().numerator())
            .collect::<Vec<_>>(),
        [500_000_000_000, 500_000_000_000]
    );
    assert_eq!(
        selection
            .packets()
            .iter()
            .map(|packet| packet.marginal_gain().numerator())
            .sum::<u64>(),
        selection.normalized_gain().numerator()
    );
}

#[test]
fn fixed_overhead_and_mandatory_cost_are_reserved_before_strict_packet_budget() {
    let identifier = facet(1, ProductionFacetKindV1::ValidatedQueryIdentifier, 1);
    let failure = facet(2, ProductionFacetKindV1::FailureRole, 1);
    let onset = facet(3, ProductionFacetKindV1::OnsetRole, 1);
    let packets = [
        packet(1, &[1], 3, &[(identifier.id(), 10)]),
        packet(2, &[2], 4, &[(failure.id(), 10)]),
        packet(3, &[3], 6, &[(onset.id(), 10)]),
    ];
    let mandatory = [MandatoryPacketV1::validated_identifier(
        packet_id(1),
        identifier.id(),
    )];

    for raw_budget in 0_u64..=17 {
        let problem = SelectionProblemV1::new(
            [identifier.clone(), failure.clone(), onset.clone()],
            packets.clone(),
            mandatory,
            budget(raw_budget),
            overhead(2),
        )
        .unwrap();
        match problem.select().unwrap() {
            SelectionDecisionV1::NeedsMore(needs_more) => {
                assert!(raw_budget < 5);
                let expected_reason = if raw_budget < 2 {
                    NeedsMoreReasonV1::FixedOverheadExceedsTotalBudget
                } else {
                    NeedsMoreReasonV1::MandatoryCostExceedsAvailablePacketBudget
                };
                assert_eq!(needs_more.reason(), expected_reason);
                assert_eq!(needs_more.reserved_fixed_overhead(), 2);
                assert_eq!(needs_more.mandatory_cost(), 3);
                assert_eq!(needs_more.total_token_budget().tokens(), raw_budget);
            }
            SelectionDecisionV1::Selected(selection) => {
                assert!(raw_budget >= 5);
                assert!(selection.accounted_token_upper_bound() <= raw_budget);
                assert_eq!(selection.reserved_fixed_overhead().upper_bound_tokens(), 2);
                assert_eq!(selection.mandatory_token_cost(), 3);
                assert_eq!(selection.packets()[0].packet().id(), packet_id(1));
                assert!(matches!(
                    selection.packets()[0].forcing_constraint(),
                    SelectionConstraintV1::MandatoryValidatedIdentifier { .. }
                ));
                assert_eq!(
                    selection.selected_packet_cost(),
                    selection
                        .packets()
                        .iter()
                        .map(|packet| {
                            packet.composable_token_upper_bound().upper_bound_tokens()
                        })
                        .sum::<u64>()
                );
                assert_eq!(
                    selection.accounted_token_upper_bound(),
                    2 + selection.selected_packet_cost()
                );
                assert_eq!(
                    selection.coverage_only_token_limit(),
                    (raw_budget - 5) / COVERAGE_ONLY_OPTIONAL_BUDGET_DENOMINATOR_V1
                );
                assert_eq!(selection.coverage_only_token_cost(), 0);
            }
        }
    }
}

#[test]
fn packets_are_never_split_at_the_budget_boundary() {
    let failure = facet(1, ProductionFacetKindV1::FailureRole, 1);
    let intact = packet(1, &[1, 2, 3], 5, &[(failure.id(), 1)]);
    let too_small = SelectionProblemV1::new(
        [failure.clone()],
        [intact.clone()],
        [],
        budget(6),
        overhead(2),
    )
    .unwrap();
    assert!(selected(too_small.select().unwrap()).packets().is_empty());

    let exact =
        SelectionProblemV1::new([failure], [intact.clone()], [], budget(7), overhead(2)).unwrap();
    let exact = selected(exact.select().unwrap());
    assert_eq!(exact.packets().len(), 1);
    assert_eq!(exact.packets()[0].packet().event_ids(), intact.event_ids());
}

#[test]
fn coverage_only_packets_share_a_strict_optional_token_slice() {
    let coverage = (1_u64..=3)
        .map(|seed| facet(seed, ProductionFacetKindV1::TimeCoverageStratum, 1))
        .collect::<Vec<_>>();
    let packets = coverage
        .iter()
        .enumerate()
        .map(|(index, facet)| {
            let seed = u64::try_from(index).unwrap() + 1;
            packet(seed, &[seed], 6, &[(facet.id(), 1)])
        })
        .collect::<Vec<_>>();
    let selection = selected(
        SelectionProblemV1::new(coverage, packets, [], budget(80), overhead(0))
            .unwrap()
            .select()
            .unwrap(),
    );

    assert_eq!(selection.coverage_only_token_limit(), 10);
    assert_eq!(selection.coverage_only_token_cost(), 6);
    assert_eq!(selection.selected_packet_cost(), 6);
    assert_eq!(selection.packets().len(), 1);
}

#[test]
fn best_single_cannot_bypass_the_coverage_only_slice() {
    let coverage = facet(1, ProductionFacetKindV1::SourceCoverageStratum, 1);
    let selection = selected(
        SelectionProblemV1::new(
            [coverage.clone()],
            [packet(1, &[1], 11, &[(coverage.id(), 1)])],
            [],
            budget(80),
            overhead(0),
        )
        .unwrap()
        .select()
        .unwrap(),
    );

    assert_eq!(selection.coverage_only_token_limit(), 10);
    assert_eq!(selection.coverage_only_token_cost(), 0);
    assert_eq!(selection.strategy(), SelectionStrategyV1::MandatoryOnly);
    assert!(selection.packets().is_empty());
}

#[test]
fn marginal_classification_becomes_coverage_only_after_primary_gain_is_covered() {
    let failure = facet(1, ProductionFacetKindV1::FailureRole, 10);
    let onset = facet(2, ProductionFacetKindV1::OnsetRole, 9);
    let first_coverage = facet(3, ProductionFacetKindV1::TimeCoverageStratum, 1);
    let second_coverage = facet(4, ProductionFacetKindV1::TimeCoverageStratum, 1);
    let facets = [
        failure.clone(),
        onset.clone(),
        first_coverage.clone(),
        second_coverage.clone(),
    ];
    let packets = [
        packet(1, &[1], 8, &[(failure.id(), 10), (first_coverage.id(), 10)]),
        packet(
            2,
            &[2],
            8,
            &[(failure.id(), 10), (second_coverage.id(), 10)],
        ),
        packet(3, &[3], 20, &[(onset.id(), 10)]),
    ];
    let expected =
        SelectionProblemV1::new(facets.clone(), packets.clone(), [], budget(40), overhead(0))
            .unwrap()
            .select()
            .unwrap();

    for facet_order in permutations(&facets) {
        for packet_order in permutations(&packets) {
            let actual = SelectionProblemV1::new(
                facet_order.clone(),
                packet_order,
                [],
                budget(40),
                overhead(0),
            )
            .unwrap()
            .select()
            .unwrap();
            assert_eq!(actual, expected);
        }
    }

    let selection = selected(expected);
    assert_eq!(selection.coverage_only_token_limit(), 5);
    assert_eq!(selection.coverage_only_token_cost(), 0);
    assert_eq!(selection.selected_packet_cost(), 28);
    assert_eq!(
        selection
            .packets()
            .iter()
            .flat_map(|packet| packet.packet().event_ids().iter().copied())
            .collect::<Vec<_>>(),
        [event_id(1), event_id(3)]
    );
}

#[test]
fn presentation_orders_diagnostics_before_risk_and_recomputes_exact_marginals() {
    let failure = facet(1, ProductionFacetKindV1::FailureRole, 10);
    let risk = facet(2, ProductionFacetKindV1::ReconstructionRiskCoverage, 10);
    let breadth = facet(3, ProductionFacetKindV1::TimeCoverageStratum, 10);
    let facets = [failure.clone(), risk.clone(), breadth.clone()];
    let packets = [
        packet(1, &[1], 1, &[(risk.id(), 10), (breadth.id(), 10)]),
        packet(2, &[2], 10, &[(failure.id(), 10)]),
    ];
    let expected =
        SelectionProblemV1::new(facets.clone(), packets.clone(), [], budget(11), overhead(0))
            .unwrap()
            .select()
            .unwrap();

    for facet_order in permutations(&facets) {
        for packet_order in permutations(&packets) {
            assert_eq!(
                SelectionProblemV1::new(
                    facet_order.clone(),
                    packet_order,
                    [],
                    budget(11),
                    overhead(0),
                )
                .unwrap()
                .select()
                .unwrap(),
                expected
            );
        }
    }

    let selection = selected(expected);
    assert_eq!(
        selection
            .packets()
            .iter()
            .flat_map(|packet| packet.packet().event_ids().iter().copied())
            .collect::<Vec<_>>(),
        [event_id(2), event_id(1)]
    );
    assert_eq!(
        selection.packets()[0].facet_kinds(),
        [ProductionFacetKindV1::FailureRole]
    );
    assert_eq!(
        selection.packets()[1].facet_kinds(),
        [
            ProductionFacetKindV1::TimeCoverageStratum,
            ProductionFacetKindV1::ReconstructionRiskCoverage,
        ]
    );
    assert_eq!(
        selection
            .packets()
            .iter()
            .map(|packet| packet.marginal_gain().numerator())
            .sum::<u64>(),
        selection.normalized_gain().numerator()
    );
}

#[test]
fn greedy_plus_max_chooses_the_better_complete_plan() {
    let facets = (1_u64..=10)
        .map(|seed| facet(seed, ProductionFacetKindV1::QueryTerm, 1))
        .collect::<Vec<_>>();
    let all = facets
        .iter()
        .map(|facet| (facet.id(), 1))
        .collect::<Vec<_>>();
    let first_six = facets
        .iter()
        .take(6)
        .map(|facet| (facet.id(), 1))
        .collect::<Vec<_>>();
    let packets = [
        packet(1, &[1], 6, &all),
        packet(2, &[2], 3, &first_six),
        packet(3, &[3], 3, &first_six),
    ];
    let problem = SelectionProblemV1::new(facets, packets, [], budget(6), overhead(0)).unwrap();
    let selection = selected(problem.select().unwrap());
    assert_eq!(selection.strategy(), SelectionStrategyV1::BestSingle);
    assert_eq!(selection.packets().len(), 1);
    assert_eq!(selection.packets()[0].packet().event_ids(), &[event_id(1)]);
    assert_eq!(selection.normalized_gain().numerator(), 10);
    assert_eq!(
        selection.packets()[0].forcing_constraint(),
        SelectionConstraintV1::BestSingle
    );

    let complementary_facets = (20_u64..=23)
        .map(|seed| facet(seed, ProductionFacetKindV1::QueryTerm, 1))
        .collect::<Vec<_>>();
    let complementary_packets = [
        packet(
            10,
            &[10],
            2,
            &[
                (complementary_facets[0].id(), 1),
                (complementary_facets[1].id(), 1),
            ],
        ),
        packet(
            11,
            &[11],
            2,
            &[
                (complementary_facets[2].id(), 1),
                (complementary_facets[3].id(), 1),
            ],
        ),
        packet(
            12,
            &[12],
            4,
            &[
                (complementary_facets[0].id(), 1),
                (complementary_facets[1].id(), 1),
                (complementary_facets[2].id(), 1),
            ],
        ),
    ];
    let complementary = SelectionProblemV1::new(
        complementary_facets,
        complementary_packets,
        [],
        budget(4),
        overhead(0),
    )
    .unwrap();
    let selection = selected(complementary.select().unwrap());
    assert_eq!(selection.strategy(), SelectionStrategyV1::DensityGreedy);
    assert_eq!(selection.normalized_gain().numerator(), 4);
    assert_eq!(
        selection
            .packets()
            .iter()
            .flat_map(|packet| packet.packet().event_ids().iter().copied())
            .collect::<Vec<_>>(),
        [event_id(10), event_id(11)]
    );
}

fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    fn visit<T: Clone>(prefix: &mut Vec<T>, rest: &mut Vec<T>, output: &mut Vec<Vec<T>>) {
        if rest.is_empty() {
            output.push(prefix.clone());
            return;
        }
        for index in 0..rest.len() {
            let item = rest.remove(index);
            prefix.push(item.clone());
            visit(prefix, rest, output);
            prefix.pop();
            rest.insert(index, item);
        }
    }

    let mut output = Vec::new();
    visit(&mut Vec::new(), &mut items.to_vec(), &mut output);
    output
}

#[test]
fn canonicalization_makes_selection_permutation_invariant_with_intrinsic_ties() {
    let identifier = facet(1, ProductionFacetKindV1::ValidatedQueryIdentifier, 1);
    let failure = facet(2, ProductionFacetKindV1::FailureRole, 1);
    let onset = facet(3, ProductionFacetKindV1::OnsetRole, 1);
    let facets = [identifier.clone(), failure.clone(), onset];
    let packets = [
        packet(1, &[1], 1, &[(identifier.id(), 1)]),
        packet(2, &[2], 2, &[(failure.id(), 1)]),
        packet(3, &[3], 2, &[(failure.id(), 1)]),
    ];
    let mandatory = [MandatoryPacketV1::validated_identifier(
        packet_id(1),
        identifier.id(),
    )];
    let expected = SelectionProblemV1::new(
        facets.clone(),
        packets.clone(),
        mandatory,
        budget(3),
        overhead(0),
    )
    .unwrap()
    .select()
    .unwrap();

    for facet_order in permutations(&facets) {
        for packet_order in permutations(&packets) {
            let actual = SelectionProblemV1::new(
                facet_order.clone(),
                packet_order,
                mandatory,
                budget(3),
                overhead(0),
            )
            .unwrap()
            .select()
            .unwrap();
            assert_eq!(actual, expected);
        }
    }
    let selection = selected(expected);
    assert_eq!(selection.packets()[1].packet().event_ids(), &[event_id(2)]);
}

#[test]
fn relabeling_opaque_packet_ids_cannot_change_selected_event_membership() {
    let failure = facet(1, ProductionFacetKindV1::FailureRole, 1);
    let build = |first_label: u64, second_label: u64| {
        SelectionProblemV1::new(
            [failure.clone()],
            [
                packet(first_label, &[10], 2, &[(failure.id(), 1)]),
                packet(second_label, &[20], 2, &[(failure.id(), 1)]),
            ],
            [],
            budget(2),
            overhead(0),
        )
        .unwrap()
    };
    let event_members = |problem: SelectionProblemV1| {
        selected(problem.select().unwrap())
            .packets()
            .iter()
            .flat_map(|selected| selected.packet().event_ids().iter().copied())
            .collect::<Vec<_>>()
    };
    assert_eq!(event_members(build(1, 2)), [event_id(10)]);
    assert_eq!(event_members(build(200, 100)), [event_id(10)]);
}

#[test]
fn debug_and_error_formatting_are_contentless() {
    let secret_event = EventId::from_bytes([0xef; 32]);
    let secret_event_token = secret_event.to_string();
    let secret_facet = ProductionFacetV1::new(
        ProductionFacetKindV1::FailureRole,
        b"CANARY_SECRET_FACET_KEY",
        weight(1),
    )
    .unwrap();
    let packet = IntactPacketV1::new(
        PacketIdV1::from_bytes([0xab; 32]),
        [secret_event],
        ComposablePacketCostV1::new(model(0xcd), 1).unwrap(),
        [FacetAffinityV1::new(secret_facet.id(), affinity(1))],
    )
    .unwrap();
    let problem = SelectionProblemV1::new(
        [secret_facet],
        [packet],
        [],
        budget(1),
        ReservedFixedOverheadV1::new(model(0xcd), 0).unwrap(),
    )
    .unwrap();
    let decision = problem.select().unwrap();
    let selection = selected(decision.clone());
    let outputs = [
        format!("{problem:?}"),
        format!("{:?}", problem.facets()[0]),
        format!("{:?}", problem.packets()[0]),
        format!("{:?}", selection.packets()[0]),
        format!("{decision:?}"),
        format!("{:?}", SelectionProblemConstructionError::OverlappingEvent),
        SelectionProblemConstructionError::OverlappingEvent.to_string(),
    ];
    for output in outputs {
        for canary in [
            "CANARY_SECRET_FACET_KEY",
            "abab",
            "cdcd",
            "efef",
            secret_event_token.as_str(),
        ] {
            assert!(!output.contains(canary));
        }
    }
}
