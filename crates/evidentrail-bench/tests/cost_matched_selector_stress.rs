use std::collections::BTreeSet;

use evidentrail_bench::{
    BOUNDED_SELECTOR_CHALLENGER_TRANSITION_CAP_V1, COST_MATCHED_STRESS_CASE_COUNT_V1,
    COST_MATCHED_STRESS_MIN_OPTIONAL_PACKETS_V1, CostMatchedCostRelationV1,
    CostMatchedObjectiveRelationV1, CostMatchedPlanSourceV1, CostMatchedRecallRelationV1,
    CostMatchedStressCaseV1, CostMatchedStressErrorV1, CostMatchedStressGovernedAnnotationV1,
    CostMatchedStressRequirementV1, STRUCTURED_DP_MAX_OPTIONAL_PACKETS_V1,
    StructuredDpIneligibleReasonV1, evaluate_governed_cost_matched_selector_stress_v1,
    freeze_cost_matched_selector_stress_corpus_v1, synthetic_cost_matched_stress_annotations_v1,
};
use evidentrail_schema::EventId;

#[test]
fn public_cost_matched_stress_freezes_exact_resources_and_closed_work() {
    let public = freeze_cost_matched_selector_stress_corpus_v1().unwrap();
    let replay = freeze_cost_matched_selector_stress_corpus_v1().unwrap();

    assert_eq!(public, replay);
    assert_eq!(public.digest(), replay.digest());
    assert_eq!(public.cases().len(), COST_MATCHED_STRESS_CASE_COUNT_V1);
    assert_eq!(public.challenger_better_count(), 3);
    assert_eq!(public.exact_dp_count(), 6);
    assert_eq!(public.ineligible_count(), 2);
    let expected = [
        (
            CostMatchedStressCaseV1::PrimaryDensityTrap15,
            850_000,
            1_200_000,
            10,
            0,
        ),
        (
            CostMatchedStressCaseV1::PrimaryBalanced16,
            3_440_000,
            3_440_000,
            8,
            0,
        ),
        (
            CostMatchedStressCaseV1::CoverageDensityTrap15,
            850_000,
            1_200_000,
            10,
            10,
        ),
        (
            CostMatchedStressCaseV1::MixedDualResource16,
            1_400_000,
            1_880_000,
            18,
            2,
        ),
        (
            CostMatchedStressCaseV1::ProviderPairs14,
            3_500_000_000_000,
            3_500_000_000_000,
            7,
            0,
        ),
        (
            CostMatchedStressCaseV1::MandatoryBaseline14,
            2_590_000,
            2_590_000,
            8,
            0,
        ),
        (
            CostMatchedStressCaseV1::ProviderThirdEndpoint15,
            1_000_000_000_000,
            1_000_000_000_000,
            2,
            0,
        ),
        (
            CostMatchedStressCaseV1::ExactPacketCap65,
            3_975_000,
            3_975_000,
            10,
            0,
        ),
    ];
    for (case, production_gain, challenger_gain, cost, coverage_charge) in expected {
        let frozen = public.case(case);
        assert_eq!(
            frozen.production().objective_gain_numerator(),
            production_gain
        );
        assert_eq!(
            frozen.challenger().objective_gain_numerator(),
            challenger_gain
        );
        assert_eq!(frozen.production().selected_packet_cost(), cost);
        assert_eq!(frozen.challenger().selected_packet_cost(), cost);
        assert_eq!(
            frozen.production().coverage_only_token_cost(),
            coverage_charge
        );
        assert_eq!(
            frozen.challenger().coverage_only_token_cost(),
            coverage_charge
        );
    }
    assert_eq!(
        public
            .cases()
            .iter()
            .map(|case| case.digest())
            .collect::<BTreeSet<_>>()
            .len(),
        COST_MATCHED_STRESS_CASE_COUNT_V1
    );
    assert!(
        public
            .cases()
            .iter()
            .all(|case| case.optional_packet_count()
                >= u64::try_from(COST_MATCHED_STRESS_MIN_OPTIONAL_PACKETS_V1).unwrap())
    );
    for case in public.cases() {
        assert!(case.deterministic_axes_weakly_dominate());
        assert_eq!(
            case.selected_cost_relation(),
            CostMatchedCostRelationV1::Equal
        );
        assert_eq!(
            case.coverage_cost_relation(),
            CostMatchedCostRelationV1::Equal
        );
        assert!(
            case.challenger().selected_packet_cost() <= case.envelope().selected_packet_cost_cap()
        );
        assert!(
            case.challenger().coverage_only_token_cost()
                <= case.envelope().coverage_only_token_cost_cap()
        );
        assert_eq!(
            case.beam_bounds().transition_attempt_cap(),
            BOUNDED_SELECTOR_CHALLENGER_TRANSITION_CAP_V1
        );
        assert!(
            case.beam_observation().retained_state_high_water()
                <= case.beam_bounds().state_slot_cap()
        );
        assert!(
            case.beam_observation().transition_attempts().unwrap()
                <= case.beam_bounds().transition_attempt_cap()
        );
        if let Some(optimum) = case.structured_dp().optimum() {
            assert_eq!(
                optimum.objective_gain_numerator(),
                case.challenger().objective_gain_numerator()
            );
            assert_eq!(
                optimum.selected_packet_cost(),
                case.challenger().selected_packet_cost()
            );
            let work = case.structured_dp().work();
            assert!(work.retained_state_high_water() <= work.state_slot_cap());
            assert!(work.transition_attempts() <= work.transition_attempt_cap());
        }
    }
    assert!(!public.contains_annotations());
    assert!(!public.claims_population_quality());
}

#[test]
fn governed_join_is_bijective_exact_and_never_promotes_production() {
    let public = freeze_cost_matched_selector_stress_corpus_v1().unwrap();
    let annotations = synthetic_cost_matched_stress_annotations_v1(&public).unwrap();
    let governed =
        evaluate_governed_cost_matched_selector_stress_v1(&public, annotations.clone()).unwrap();
    let mut permuted = annotations;
    permuted.reverse();
    let replay = evaluate_governed_cost_matched_selector_stress_v1(&public, permuted).unwrap();

    assert_eq!(governed, replay);
    assert_eq!(governed.digest(), replay.digest());
    assert_eq!(governed.cases().len(), COST_MATCHED_STRESS_CASE_COUNT_V1);
    assert_eq!(governed.recall_better_count(), 3);
    assert_eq!(governed.recall_equal_count(), 5);
    assert_eq!(governed.recall_worse_count(), 0);
    assert_eq!(
        governed.deterministic_weak_dominance_count(),
        u64::try_from(COST_MATCHED_STRESS_CASE_COUNT_V1).unwrap()
    );
    assert!(!governed.production_promotion_eligible());
    assert!(!governed.claims_measured_wall_time_or_peak_rss());
    assert!(!governed.claims_population_quality());
    for case in governed.cases() {
        let expected_relation = match case.case() {
            CostMatchedStressCaseV1::PrimaryDensityTrap15
            | CostMatchedStressCaseV1::CoverageDensityTrap15
            | CostMatchedStressCaseV1::MixedDualResource16 => {
                CostMatchedRecallRelationV1::ChallengerBetter
            }
            CostMatchedStressCaseV1::PrimaryBalanced16
            | CostMatchedStressCaseV1::ProviderPairs14
            | CostMatchedStressCaseV1::MandatoryBaseline14
            | CostMatchedStressCaseV1::ProviderThirdEndpoint15
            | CostMatchedStressCaseV1::ExactPacketCap65 => CostMatchedRecallRelationV1::Equal,
        };
        assert_eq!(case.recall_relation(), expected_relation);
        if expected_relation == CostMatchedRecallRelationV1::ChallengerBetter {
            assert_eq!(
                (
                    case.production_recall().numerator(),
                    case.production_recall().denominator()
                ),
                (0, 1)
            );
            assert_eq!(
                (
                    case.challenger_recall().numerator(),
                    case.challenger_recall().denominator()
                ),
                (1, 1)
            );
        } else {
            assert_eq!(case.production_recall(), case.challenger_recall());
        }
        if let Some(exact_recall) = case.exact_dp_recall() {
            assert_eq!(exact_recall, case.challenger_recall());
        }
    }

    let mut duplicate = synthetic_cost_matched_stress_annotations_v1(&public).unwrap();
    duplicate[1] = duplicate[0].clone();
    assert_eq!(
        evaluate_governed_cost_matched_selector_stress_v1(&public, duplicate).unwrap_err(),
        CostMatchedStressErrorV1::CaseSetMismatch
    );

    let invalid_requirement =
        CostMatchedStressRequirementV1::new(1, [vec![EventId::from_bytes([0xff; 32])]]).unwrap();
    let wrong_binding = CostMatchedStressGovernedAnnotationV1::new(
        public.digest(),
        CostMatchedStressCaseV1::PrimaryDensityTrap15,
        public
            .case(CostMatchedStressCaseV1::PrimaryBalanced16)
            .digest(),
        [invalid_requirement],
    )
    .unwrap();
    let mut mismatched = synthetic_cost_matched_stress_annotations_v1(&public).unwrap();
    mismatched[0] = wrong_binding;
    assert_eq!(
        evaluate_governed_cost_matched_selector_stress_v1(&public, mismatched).unwrap_err(),
        CostMatchedStressErrorV1::CaseBindingMismatch
    );

    let unknown_event = CostMatchedStressGovernedAnnotationV1::new(
        public.digest(),
        CostMatchedStressCaseV1::PrimaryDensityTrap15,
        public
            .case(CostMatchedStressCaseV1::PrimaryDensityTrap15)
            .digest(),
        [
            CostMatchedStressRequirementV1::new(1, [vec![EventId::from_bytes([0xfe; 32])]])
                .unwrap(),
        ],
    )
    .unwrap();
    let mut unknown = synthetic_cost_matched_stress_annotations_v1(&public).unwrap();
    unknown[0] = unknown_event;
    assert_eq!(
        evaluate_governed_cost_matched_selector_stress_v1(&public, unknown).unwrap_err(),
        CostMatchedStressErrorV1::RequirementUnknownEvent
    );
}

#[test]
fn structured_dp_and_beam_terminals_are_explicit_and_contentless() {
    let public = freeze_cost_matched_selector_stress_corpus_v1().unwrap();
    let non_additive = public.case(CostMatchedStressCaseV1::ProviderThirdEndpoint15);
    assert_eq!(
        non_additive.structured_dp().ineligible_reason(),
        Some(StructuredDpIneligibleReasonV1::NonAdditiveSaturation)
    );
    let capacity = public.case(CostMatchedStressCaseV1::ExactPacketCap65);
    assert_eq!(
        capacity.structured_dp().ineligible_reason(),
        Some(StructuredDpIneligibleReasonV1::OptionalPacketCap)
    );
    assert_eq!(
        capacity.structured_dp().work().optional_packet_cap(),
        u64::try_from(STRUCTURED_DP_MAX_OPTIONAL_PACKETS_V1).unwrap()
    );

    let debug = format!(
        "{public:?} {:?} {:?}",
        CostMatchedStressErrorV1::CaseBindingMismatch,
        capacity.structured_dp()
    );
    for canary in ["fatal crash", "secret-query", "EventId", "PacketId"] {
        assert!(!debug.contains(canary));
    }
    assert!(matches!(
        non_additive.objective_relation(),
        CostMatchedObjectiveRelationV1::Equal | CostMatchedObjectiveRelationV1::ChallengerBetter
    ));
    assert!(matches!(
        capacity.challenger().source(),
        CostMatchedPlanSourceV1::OrderAwareBeam | CostMatchedPlanSourceV1::ProductionFallback
    ));
    assert!(matches!(
        synthetic_cost_matched_stress_annotations_v1(&public)
            .unwrap()
            .first()
            .unwrap()
            .case(),
        CostMatchedStressCaseV1::PrimaryDensityTrap15
    ));
    assert!(matches!(
        evaluate_governed_cost_matched_selector_stress_v1(
            &public,
            synthetic_cost_matched_stress_annotations_v1(&public).unwrap()
        )
        .unwrap()
        .cases()[0]
            .recall_relation(),
        CostMatchedRecallRelationV1::Equal | CostMatchedRecallRelationV1::ChallengerBetter
    ));
}
