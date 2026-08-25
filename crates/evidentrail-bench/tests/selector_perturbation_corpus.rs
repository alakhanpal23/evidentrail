use std::collections::BTreeSet;

use evidentrail_bench::{
    EXACT_SELECTION_ORACLE_POLICY_NAME_V1, EXACT_SELECTION_ORACLE_POLICY_VERSION_V1,
    FrozenSelectorPerturbationCorpusV1, FrozenSelectorPerturbationOutcomeV1,
    GovernedSelectorPerturbationReportV1, MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1,
    SelectorPerturbationCaseV1, SelectorPerturbationCorpusErrorV1,
    SelectorPerturbationExpectedOutcomeV1, SelectorPerturbationFamilyV1,
    SelectorPerturbationGovernedAnnotationV1, evaluate_governed_selector_perturbation_corpus_v1,
    freeze_selector_perturbation_corpus_v1,
};
use evidentrail_select::{
    NeedsMoreReasonV1, SELECTION_OBJECTIVE_POLICY_NAME_V1, SELECTION_OBJECTIVE_POLICY_VERSION_V1,
    SelectionStrategyV1,
};

fn expected(case: SelectorPerturbationCaseV1) -> SelectorPerturbationExpectedOutcomeV1 {
    match case {
        SelectorPerturbationCaseV1::DensityTrap => {
            SelectorPerturbationExpectedOutcomeV1::ExactRegret { numerator: 400_000 }
        }
        SelectorPerturbationCaseV1::BreadthMixedAdmissionOrder => {
            SelectorPerturbationExpectedOutcomeV1::ExactRegret { numerator: 500_000 }
        }
        SelectorPerturbationCaseV1::FixedOverheadTerminal => {
            SelectorPerturbationExpectedOutcomeV1::ProductionNeedsMore {
                reason: NeedsMoreReasonV1::FixedOverheadExceedsTotalBudget,
            }
        }
        SelectorPerturbationCaseV1::MandatoryOverBudgetTerminal => {
            SelectorPerturbationExpectedOutcomeV1::ProductionNeedsMore {
                reason: NeedsMoreReasonV1::MandatoryCostExceedsAvailablePacketBudget,
            }
        }
        SelectorPerturbationCaseV1::OracleCapThirteenIneligible => {
            SelectorPerturbationExpectedOutcomeV1::OptionalPacketCapIneligible {
                packet_count: 13,
                cap: 12,
            }
        }
        SelectorPerturbationCaseV1::BudgetExactFit
        | SelectorPerturbationCaseV1::BudgetOneBelow
        | SelectorPerturbationCaseV1::EqualDensityTie
        | SelectorPerturbationCaseV1::ProviderTopTwo
        | SelectorPerturbationCaseV1::ProviderThirdEndpointZero
        | SelectorPerturbationCaseV1::ProviderMandatoryComplement
        | SelectorPerturbationCaseV1::BreadthSliceBlocked
        | SelectorPerturbationCaseV1::OracleCapTwelveExact => {
            SelectorPerturbationExpectedOutcomeV1::ExactRegret { numerator: 0 }
        }
    }
}

fn annotations(
    public: &FrozenSelectorPerturbationCorpusV1,
) -> Vec<SelectorPerturbationGovernedAnnotationV1> {
    SelectorPerturbationCaseV1::ALL
        .into_iter()
        .map(|case| {
            SelectorPerturbationGovernedAnnotationV1::new(
                public.digest(),
                case,
                public.case(case).digest(),
                expected(case),
            )
        })
        .collect()
}

fn evaluated(
    public: &FrozenSelectorPerturbationCorpusV1,
    case: SelectorPerturbationCaseV1,
) -> &evidentrail_bench::ExactSmallSelectionRegretV1 {
    public
        .case(case)
        .outcome()
        .exact_evaluated()
        .expect("case is exact-oracle eligible")
}

fn distribution(
    report: &GovernedSelectorPerturbationReportV1,
    family: SelectorPerturbationFamilyV1,
) -> evidentrail_bench::SelectorPerturbationFamilyDistributionV1 {
    report
        .family_distributions()
        .iter()
        .copied()
        .find(|distribution| distribution.family() == family)
        .expect("every closed family is retained")
}

#[test]
fn public_freeze_is_deterministic_bounded_and_label_blind() {
    let first = freeze_selector_perturbation_corpus_v1().unwrap();
    let second = freeze_selector_perturbation_corpus_v1().unwrap();

    assert_eq!(first, second);
    assert_eq!(first.digest(), second.digest());
    assert_eq!(first.cases().len(), 13);
    assert!(!first.contains_governed_annotations());
    assert!(!first.claims_population_quality());
    assert_eq!(
        first.oracle_policy_name(),
        EXACT_SELECTION_ORACLE_POLICY_NAME_V1
    );
    assert_eq!(
        first.oracle_policy_version(),
        EXACT_SELECTION_ORACLE_POLICY_VERSION_V1
    );
    assert_eq!(
        first.oracle_optional_packet_cap(),
        MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1
    );
    assert_eq!(
        first.production_objective_policy_name(),
        SELECTION_OBJECTIVE_POLICY_NAME_V1
    );
    assert_eq!(
        first.production_objective_policy_version(),
        SELECTION_OBJECTIVE_POLICY_VERSION_V1
    );
    assert_eq!(
        first.staging_trust_boundary_code(),
        "label_free_data_boundary_not_external_temporal_attestation"
    );

    let case_digests = first
        .cases()
        .iter()
        .map(|case| case.digest())
        .collect::<BTreeSet<_>>();
    let problem_digests = first
        .cases()
        .iter()
        .map(|case| case.problem_digest())
        .collect::<BTreeSet<_>>();
    assert_eq!(case_digests.len(), 13);
    assert_eq!(problem_digests.len(), 13);
    for case in first.cases() {
        if case.case() != SelectorPerturbationCaseV1::OracleCapThirteenIneligible {
            assert!(
                case.optional_packet_count()
                    <= u64::try_from(MAX_EXACT_SELECTION_ORACLE_OPTIONAL_PACKETS_V1).unwrap()
            );
        }
    }

    let debug = format!("{first:?}");
    assert!(!debug.contains("ArtifactDigest"));
    assert!(!debug.contains("EventId"));
    assert!(!debug.contains("PacketId"));
    assert!(!debug.contains("SelectorPerturbationGovernedAnnotationV1"));
}

#[test]
fn exact_fault_matrix_preserves_two_nonzero_regret_witnesses() {
    let public = freeze_selector_perturbation_corpus_v1().unwrap();

    let density = evaluated(&public, SelectorPerturbationCaseV1::DensityTrap);
    assert_eq!(density.regret_numerator(), 400_000);
    assert_eq!(density.production_objective_gain().numerator(), 600_000);
    assert_eq!(density.optimum().objective_gain().numerator(), 1_000_000);
    assert_eq!(density.production_selected_packet_cost(), 6);
    assert_eq!(density.optimum().selected_packet_cost(), 10);
    assert_eq!(
        density.production_strategy(),
        SelectionStrategyV1::DensityGreedy
    );
    assert_eq!(density.production_packet_ids().len(), 1);
    assert_eq!(density.optimum().selected_packet_ids().len(), 2);

    let breadth = evaluated(
        &public,
        SelectorPerturbationCaseV1::BreadthMixedAdmissionOrder,
    );
    assert_eq!(breadth.regret_numerator(), 500_000);
    assert_eq!(breadth.production_objective_gain().numerator(), 1_500_000);
    assert_eq!(breadth.optimum().objective_gain().numerator(), 2_000_000);
    assert_eq!(breadth.production_selected_packet_cost(), 2);
    assert_eq!(breadth.optimum().selected_packet_cost(), 3);
    assert_eq!(
        breadth.production_strategy(),
        SelectionStrategyV1::BestSingle
    );
    assert_eq!(breadth.production_packet_ids().len(), 1);
    assert_eq!(breadth.optimum().optional_acceptance_order().len(), 2);
    assert_eq!(breadth.production_coverage_only_token_cost(), 0);
    assert_eq!(breadth.optimum().coverage_only_token_cost(), 0);

    let exact_zero_count = public
        .cases()
        .iter()
        .filter_map(|case| case.outcome().exact_evaluated())
        .filter(|evaluated| evaluated.regret_numerator() == 0)
        .count();
    let exact_positive_count = public
        .cases()
        .iter()
        .filter_map(|case| case.outcome().exact_evaluated())
        .filter(|evaluated| evaluated.regret_numerator() > 0)
        .count();
    assert_eq!(exact_zero_count, 8);
    assert_eq!(exact_positive_count, 2);
}

#[test]
fn provider_breadth_terminal_and_capacity_edges_are_exactly_retained() {
    let public = freeze_selector_perturbation_corpus_v1().unwrap();

    let provider_top_two = evaluated(&public, SelectorPerturbationCaseV1::ProviderTopTwo);
    assert_eq!(provider_top_two.regret_numerator(), 0);
    assert_eq!(
        provider_top_two.production_objective_gain().numerator(),
        900_000_000_000
    );
    assert_eq!(provider_top_two.production_packet_ids().len(), 2);

    let provider_third = evaluated(
        &public,
        SelectorPerturbationCaseV1::ProviderThirdEndpointZero,
    );
    assert_eq!(provider_third.regret_numerator(), 0);
    assert_eq!(
        provider_third.production_objective_gain().numerator(),
        900_000_000_000
    );
    assert_eq!(provider_third.production_packet_ids().len(), 2);

    let provider_mandatory = evaluated(
        &public,
        SelectorPerturbationCaseV1::ProviderMandatoryComplement,
    );
    assert_eq!(provider_mandatory.regret_numerator(), 0);
    assert_eq!(
        provider_mandatory.production_objective_gain().numerator(),
        400_000_000_000
    );
    assert_eq!(provider_mandatory.optimum().mandatory_packet_ids().len(), 1);
    assert_eq!(
        provider_mandatory
            .optimum()
            .optional_acceptance_order()
            .len(),
        1
    );

    let breadth_blocked = evaluated(&public, SelectorPerturbationCaseV1::BreadthSliceBlocked);
    assert_eq!(breadth_blocked.regret_numerator(), 0);
    assert_eq!(breadth_blocked.production_objective_gain().numerator(), 0);
    assert!(breadth_blocked.production_packet_ids().is_empty());
    assert!(breadth_blocked.optimum().selected_packet_ids().is_empty());
    assert_eq!(breadth_blocked.production_coverage_only_token_limit(), 1);

    let fixed = public.case(SelectorPerturbationCaseV1::FixedOverheadTerminal);
    assert_eq!(fixed.total_token_budget(), 0);
    assert_eq!(fixed.fixed_overhead_tokens(), 1);
    assert_eq!(
        fixed.outcome().production_needs_more().unwrap().reason(),
        NeedsMoreReasonV1::FixedOverheadExceedsTotalBudget
    );

    let mandatory = public.case(SelectorPerturbationCaseV1::MandatoryOverBudgetTerminal);
    let mandatory_needs_more = mandatory.outcome().production_needs_more().unwrap();
    assert_eq!(mandatory_needs_more.mandatory_packet_cost(), 2);
    assert_eq!(mandatory_needs_more.total_token_budget(), 1);
    assert_eq!(
        mandatory_needs_more.reason(),
        NeedsMoreReasonV1::MandatoryCostExceedsAvailablePacketBudget
    );

    let cap_twelve = evaluated(&public, SelectorPerturbationCaseV1::OracleCapTwelveExact);
    assert_eq!(cap_twelve.regret_numerator(), 0);
    assert_eq!(cap_twelve.optimum().optional_acceptance_order().len(), 12);
    let cap_thirteen = public.case(SelectorPerturbationCaseV1::OracleCapThirteenIneligible);
    let ineligible = cap_thirteen
        .outcome()
        .optional_packet_cap_ineligible()
        .unwrap();
    assert_eq!(ineligible.optional_packet_count(), 13);
    assert_eq!(ineligible.optional_packet_cap(), 12);
}

#[test]
fn governed_join_reports_only_per_family_counts_and_retains_every_residual() {
    let public = freeze_selector_perturbation_corpus_v1().unwrap();
    let report =
        evaluate_governed_selector_perturbation_corpus_v1(&public, annotations(&public)).unwrap();

    assert!(report.cases().iter().all(|case| case.conforms()));
    assert!(!report.contains_scalar_composite());
    assert!(!report.claims_population_quality());
    assert!(!report.claims_approximation_factor());
    assert!(!report.claims_learned_ranking_necessity());
    assert!(!report.contains_winner());

    let budget = distribution(&report, SelectorPerturbationFamilyV1::BudgetBoundary);
    assert_eq!(budget.case_count(), 2);
    assert_eq!(budget.exact_zero_regret_count(), 2);

    let density = distribution(&report, SelectorPerturbationFamilyV1::CostDensity);
    assert_eq!(density.case_count(), 1);
    assert_eq!(density.exact_positive_regret_count(), 1);

    let breadth = distribution(&report, SelectorPerturbationFamilyV1::BreadthSlice);
    assert_eq!(breadth.case_count(), 2);
    assert_eq!(breadth.exact_zero_regret_count(), 1);
    assert_eq!(breadth.exact_positive_regret_count(), 1);

    let terminal = distribution(&report, SelectorPerturbationFamilyV1::TerminalBudget);
    assert_eq!(terminal.production_needs_more_count(), 2);

    let capacity = distribution(&report, SelectorPerturbationFamilyV1::OracleCapacity);
    assert_eq!(capacity.exact_zero_regret_count(), 1);
    assert_eq!(capacity.cap_ineligible_count(), 1);

    assert_eq!(
        report
            .family_distributions()
            .iter()
            .map(|distribution| distribution.case_count())
            .sum::<u64>(),
        13
    );
    assert_eq!(
        report
            .family_distributions()
            .iter()
            .map(|distribution| distribution.conformance_mismatch_count())
            .sum::<u64>(),
        0
    );
}

#[test]
fn governed_join_is_bijective_permutation_stable_and_preserves_mismatches() {
    let public = freeze_selector_perturbation_corpus_v1().unwrap();
    let canonical = annotations(&public);
    let mut reversed = canonical.clone();
    reversed.reverse();
    let first =
        evaluate_governed_selector_perturbation_corpus_v1(&public, canonical.clone()).unwrap();
    let second = evaluate_governed_selector_perturbation_corpus_v1(&public, reversed).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.digest(), second.digest());

    let missing = evaluate_governed_selector_perturbation_corpus_v1(
        &public,
        canonical.iter().copied().take(12),
    )
    .unwrap_err();
    assert_eq!(
        missing,
        SelectorPerturbationCorpusErrorV1::MissingAnnotations { count: 1 }
    );

    let duplicate = evaluate_governed_selector_perturbation_corpus_v1(
        &public,
        canonical
            .iter()
            .copied()
            .chain(std::iter::once(canonical[0])),
    )
    .unwrap_err();
    assert_eq!(
        duplicate,
        SelectorPerturbationCorpusErrorV1::DuplicateAnnotation
    );

    let mut foreign_case = canonical.clone();
    foreign_case[0] = SelectorPerturbationGovernedAnnotationV1::new(
        public.digest(),
        SelectorPerturbationCaseV1::BudgetExactFit,
        public
            .case(SelectorPerturbationCaseV1::BudgetOneBelow)
            .digest(),
        expected(SelectorPerturbationCaseV1::BudgetExactFit),
    );
    assert_eq!(
        evaluate_governed_selector_perturbation_corpus_v1(&public, foreign_case).unwrap_err(),
        SelectorPerturbationCorpusErrorV1::ForeignCase
    );

    let mut mismatch = annotations(&public);
    mismatch[2] = SelectorPerturbationGovernedAnnotationV1::new(
        public.digest(),
        SelectorPerturbationCaseV1::DensityTrap,
        public
            .case(SelectorPerturbationCaseV1::DensityTrap)
            .digest(),
        SelectorPerturbationExpectedOutcomeV1::ExactRegret { numerator: 0 },
    );
    let mismatch_report =
        evaluate_governed_selector_perturbation_corpus_v1(&public, mismatch).unwrap();
    assert!(
        !mismatch_report
            .case(SelectorPerturbationCaseV1::DensityTrap)
            .conforms()
    );
    assert_eq!(
        distribution(&mismatch_report, SelectorPerturbationFamilyV1::CostDensity)
            .conformance_mismatch_count(),
        1
    );
}

#[test]
fn public_and_error_debug_surfaces_are_contentless() {
    let public = freeze_selector_perturbation_corpus_v1().unwrap();
    let case_debug = format!("{:?}", public.case(SelectorPerturbationCaseV1::DensityTrap));
    assert!(!case_debug.contains("PacketId"));
    assert!(!case_debug.contains("EventId"));
    assert!(!case_debug.contains("problem_digest"));

    let error = SelectorPerturbationCorpusErrorV1::MissingAnnotations { count: 7 };
    assert_eq!(error.to_string(), error.code());
    let error_debug = format!("{error:?}");
    assert!(error_debug.contains(error.code()));
    assert!(!error_debug.contains("trace=request-canary"));

    let governed_debug = format!(
        "{:?}",
        SelectorPerturbationGovernedAnnotationV1::new(
            public.digest(),
            SelectorPerturbationCaseV1::DensityTrap,
            public
                .case(SelectorPerturbationCaseV1::DensityTrap)
                .digest(),
            SelectorPerturbationExpectedOutcomeV1::ExactRegret {
                numerator: 91_827_364,
            },
        )
    );
    assert!(!governed_debug.contains("91827364"));

    let outcome = public
        .case(SelectorPerturbationCaseV1::DensityTrap)
        .outcome();
    assert!(matches!(
        outcome,
        FrozenSelectorPerturbationOutcomeV1::ExactEvaluated(_)
    ));
}
