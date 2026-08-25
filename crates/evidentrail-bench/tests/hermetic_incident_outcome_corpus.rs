use std::collections::BTreeSet;

use evidentrail_bench::{
    Bm25fConfigV1, ExactHermeticIncidentRecallV1, FrozenHermeticIncidentPublicCorpusV1,
    HERMETIC_INCIDENT_CASE_COUNT_V1, HERMETIC_INCIDENT_RECORD_COUNT_V1,
    HermeticIncidentAbstentionAuthorityV1, HermeticIncidentArmV1, HermeticIncidentCaseV1,
    HermeticIncidentClaimV1, HermeticIncidentCorpusErrorV1, HermeticIncidentExpectedOutcomeV1,
    HermeticIncidentGovernedAnnotationV1, HermeticIncidentRootAlternativeV1,
    build_governed_hermetic_incident_outcome_corpus_v1, freeze_hermetic_incident_public_corpus_v1,
    govern_hermetic_incident_outcome_corpus_v1, synthetic_hermetic_incident_annotations_v1,
};
use evidentrail_core::SourceStream;

fn public() -> FrozenHermeticIncidentPublicCorpusV1 {
    freeze_hermetic_incident_public_corpus_v1().unwrap()
}

#[test]
fn public_freeze_is_eight_case_label_free_and_deterministic() {
    let first = public();
    let second = public();
    assert_eq!(first.digest(), second.digest());
    assert_eq!(first, second);
    assert_eq!(first.cases().len(), HERMETIC_INCIDENT_CASE_COUNT_V1);
    assert_eq!(first.complete_count(), 6);
    assert_eq!(first.partial_count(), 1);
    assert_eq!(first.unknown_count(), 1);
    assert!(!first.contains_governed_labels());
    assert!(!first.claims_hosted_quality());
    assert_eq!(first.scope_code(), "synthetic_hermetic_conformance_only_v1");
    assert_eq!(
        first
            .cases()
            .iter()
            .map(|case| case.runtime())
            .collect::<BTreeSet<_>>()
            .len(),
        8
    );
    assert_eq!(
        first
            .cases()
            .iter()
            .map(|case| case.digest())
            .collect::<BTreeSet<_>>()
            .len(),
        8
    );
    for case in first.cases() {
        assert_eq!(case.ledger().len(), HERMETIC_INCIDENT_RECORD_COUNT_V1);
        assert_eq!(case.outcomes().len(), 5);
        assert!(!case.contains_governed_labels());
        assert_eq!(
            case.outcome(HermeticIncidentArmV1::FullThreeLane)
                .selected_unique_source_bytes(),
            case.matched_source_byte_budget()
        );
        assert!(
            case.outcome(HermeticIncidentArmV1::FullThreeLane)
                .producer_receipt_digest()
                .is_some()
        );
        for arm in [
            HermeticIncidentArmV1::RawChronological,
            HermeticIncidentArmV1::GrepHeadTail,
            HermeticIncidentArmV1::QuotaHybrid,
            HermeticIncidentArmV1::Bm25fWholeEvent,
        ] {
            let outcome = case.outcome(arm);
            assert!(outcome.producer_receipt_digest().is_none());
            assert!(outcome.selected_unique_source_bytes() <= case.matched_source_byte_budget());
        }
        assert_eq!(
            case.outcome(HermeticIncidentArmV1::Bm25fWholeEvent)
                .method_config_digest(),
            Some(Bm25fConfigV1.digest())
        );
        for arm in [
            HermeticIncidentArmV1::FullThreeLane,
            HermeticIncidentArmV1::RawChronological,
            HermeticIncidentArmV1::GrepHeadTail,
            HermeticIncidentArmV1::QuotaHybrid,
        ] {
            assert!(case.outcome(arm).method_config_digest().is_none());
        }
        assert!(case.exact_oracle().reachable_subset_count() > 0);
        assert_eq!(case.exact_oracle().optional_packet_cap(), 12);
        assert_eq!(case.exact_oracle().oracle_policy_version(), b"2");
        assert!(
            case.exact_oracle().objective_gain()
                >= case
                    .outcome(HermeticIncidentArmV1::FullThreeLane)
                    .objective_gain()
                    .unwrap()
        );
    }
}

#[test]
fn public_records_cover_binary_framing_interleaving_and_acquisition_limits() {
    let corpus = public();
    let binary = corpus.case(HermeticIncidentCaseV1::Case05);
    assert!(binary.ledger().events()[2].raw().contains(&0));
    assert!(std::str::from_utf8(binary.ledger().events()[2].raw()).is_err());
    assert!(
        binary
            .ledger()
            .events()
            .iter()
            .any(|event| event.terminator() == Some(b"\r\n"))
    );
    assert_eq!(
        binary.ledger().events().last().unwrap().terminator(),
        Some(&[][..])
    );

    let partial = corpus.case(HermeticIncidentCaseV1::Case07);
    assert_eq!(partial.expected_acquisition_class().code(), "partial");
    assert!(
        partial
            .scope_components()
            .iter()
            .any(|component| component == b"node-agent")
    );
    assert!(partial.ledger().events().iter().all(|event| {
        event.lane().member().as_bytes() != b"node-agent"
            && *event.lane().stream() == SourceStream::Container
    }));

    let unknown = corpus.case(HermeticIncidentCaseV1::Case08);
    assert_eq!(unknown.expected_acquisition_class().code(), "unknown");
    assert!(
        unknown
            .ledger()
            .events()
            .iter()
            .filter(|event| !event.provider_attestations().is_empty())
            .count()
            >= 2
    );
    assert!(
        unknown
            .ledger()
            .events()
            .windows(2)
            .any(|pair| pair[0].lane().member() != pair[1].lane().member())
    );
}

#[test]
fn public_surface_and_debug_do_not_contain_gold() {
    let corpus = public();
    let canary = b"gold-only:";
    for case in corpus.cases() {
        assert!(
            !case
                .question()
                .windows(canary.len())
                .any(|window| window == canary)
        );
        for event in case.ledger().events() {
            assert!(
                !event
                    .raw()
                    .windows(canary.len())
                    .any(|window| window == canary)
            );
        }
    }
    let debug = format!("{corpus:?}");
    assert!(!debug.contains("gold-only"));
    assert!(!debug.contains("orders-secret"));
    assert!(!debug.contains("auth-client-certificate"));
}

#[test]
fn governed_join_is_bijective_and_abstention_never_becomes_diagnosis_success() {
    let public = public();
    let annotations = synthetic_hermetic_incident_annotations_v1(&public).unwrap();
    assert_eq!(annotations.len(), 8);
    assert_eq!(
        annotations
            .iter()
            .map(|annotation| annotation.fault_family())
            .collect::<BTreeSet<_>>()
            .len(),
        8
    );
    let governed = govern_hermetic_incident_outcome_corpus_v1(&public, annotations).unwrap();
    assert_eq!(governed.diagnosis_expected_count(), 6);
    assert_eq!(governed.abstention_expected_count(), 2);
    assert_eq!(governed.exact_oracle_evaluated_count(), 8);
    assert!(!governed.contains_diagnosis_success_score());
    assert!(!governed.contains_scalar_composite());
    assert!(!governed.claims_hosted_quality());
    for case in HermeticIncidentCaseV1::ALL {
        let governed_case = governed.case(case);
        let should_diagnose = !matches!(
            case,
            HermeticIncidentCaseV1::Case07 | HermeticIncidentCaseV1::Case08
        );
        assert_eq!(governed_case.diagnosis_scoring_eligible(), should_diagnose);
        for outcome in governed_case.outcomes() {
            assert_eq!(outcome.recall().exact_ratio().1, 1_000_000);
        }
        assert_eq!(
            governed_case.exact_oracle_recall().exact_ratio().1,
            1_000_000
        );
    }
    assert!(matches!(
        governed
            .case(HermeticIncidentCaseV1::Case07)
            .expected_outcome(),
        HermeticIncidentExpectedOutcomeV1::Abstain(
            HermeticIncidentAbstentionAuthorityV1::MissingAuthorizedScopedComponent(_)
        )
    ));
    assert!(matches!(
        governed
            .case(HermeticIncidentCaseV1::Case08)
            .expected_outcome(),
        HermeticIncidentExpectedOutcomeV1::Abstain(
            HermeticIncidentAbstentionAuthorityV1::PredecessorOrderingUnobservable
        )
    ));
}

#[test]
fn governed_results_are_order_independent_and_report_exact_non_scalar_components() {
    let public = public();
    let forward = synthetic_hermetic_incident_annotations_v1(&public).unwrap();
    let mut reversed = forward.clone();
    reversed.reverse();
    let first = govern_hermetic_incident_outcome_corpus_v1(&public, forward).unwrap();
    let second = govern_hermetic_incident_outcome_corpus_v1(&public, reversed).unwrap();
    assert_eq!(first.digest(), second.digest());
    for arm in HermeticIncidentArmV1::ALL {
        let summary = first.arm_summary(arm);
        assert_eq!(summary.exact_ratio().1, 8_000_000);
        assert!(summary.exact_ratio().0 <= summary.exact_ratio().1);
        eprintln!(
            "{} recall={}/{} perfect_cases={}",
            arm.code(),
            summary.exact_ratio().0,
            summary.exact_ratio().1,
            summary.perfect_case_count()
        );
    }
    let bm25f = first.arm_summary(HermeticIncidentArmV1::Bm25fWholeEvent);
    assert_eq!(bm25f.exact_ratio(), (1_900_000, 8_000_000));
    assert_eq!(bm25f.perfect_case_count(), 1);
    for case in first.cases() {
        assert_eq!(
            case.outcome(HermeticIncidentArmV1::Bm25fWholeEvent)
                .method_config_digest(),
            Some(Bm25fConfigV1.digest())
        );
    }
    for case in first.cases() {
        eprintln!(
            "{} full={:?} raw={:?} grep={:?} quota={:?} bm25f={:?} bm25f_bytes={} bm25f_events={} oracle={:?}",
            case.case().code(),
            case.outcome(HermeticIncidentArmV1::FullThreeLane)
                .recall()
                .exact_ratio(),
            case.outcome(HermeticIncidentArmV1::RawChronological)
                .recall()
                .exact_ratio(),
            case.outcome(HermeticIncidentArmV1::GrepHeadTail)
                .recall()
                .exact_ratio(),
            case.outcome(HermeticIncidentArmV1::QuotaHybrid)
                .recall()
                .exact_ratio(),
            case.outcome(HermeticIncidentArmV1::Bm25fWholeEvent)
                .recall()
                .exact_ratio(),
            case.outcome(HermeticIncidentArmV1::Bm25fWholeEvent)
                .selected_unique_source_bytes(),
            case.outcome(HermeticIncidentArmV1::Bm25fWholeEvent)
                .selected_packet_count(),
            case.exact_oracle_recall().exact_ratio(),
        );
    }
}

#[test]
fn missing_duplicate_and_foreign_hidden_cases_fail_closed() {
    let public = public();
    let annotations = synthetic_hermetic_incident_annotations_v1(&public).unwrap();

    let mut missing = annotations.clone();
    missing.pop();
    assert_eq!(
        govern_hermetic_incident_outcome_corpus_v1(&public, missing).unwrap_err(),
        HermeticIncidentCorpusErrorV1::MissingCase
    );

    let mut duplicate = annotations.clone();
    duplicate.push(annotations[0].clone());
    assert_eq!(
        govern_hermetic_incident_outcome_corpus_v1(&public, duplicate).unwrap_err(),
        HermeticIncidentCorpusErrorV1::DuplicateCase
    );

    let first = &annotations[0];
    let foreign = HermeticIncidentGovernedAnnotationV1::try_new(
        HermeticIncidentCaseV1::Case02,
        first.public_case_digest(),
        first.fault_family(),
        first.expected_outcome().clone(),
        first.acceptable_roots().iter().cloned(),
        first.forbidden_claims().iter().cloned(),
        first.unsupported_claims().iter().cloned(),
        first.evidence().clone(),
    )
    .unwrap();
    let mut foreign_join = annotations;
    foreign_join[1] = foreign;
    assert_eq!(
        govern_hermetic_incident_outcome_corpus_v1(&public, foreign_join).unwrap_err(),
        HermeticIncidentCorpusErrorV1::ForeignCase
    );
}

#[test]
fn hidden_claim_bounds_and_diagnostics_are_contentless() {
    assert_eq!(
        HermeticIncidentClaimV1::new(vec![b'x'; 257]).unwrap_err(),
        HermeticIncidentCorpusErrorV1::AnnotationBounds
    );
    let claim = HermeticIncidentClaimV1::new(b"gold-only:canary-sensitive-root".to_vec()).unwrap();
    assert_eq!(
        HermeticIncidentRootAlternativeV1::new([claim.clone(), claim]).unwrap_err(),
        HermeticIncidentCorpusErrorV1::AnnotationBounds
    );
    let debug = format!(
        "{:?}",
        HermeticIncidentCorpusErrorV1::AbstentionAuthorityMismatch
    );
    assert!(!debug.contains("canary"));
    assert!(
        !format!(
            "{:?}",
            build_governed_hermetic_incident_outcome_corpus_v1().unwrap()
        )
        .contains("gold-only")
    );
}

#[test]
fn exact_recall_type_exposes_integer_components_only() {
    let governed = build_governed_hermetic_incident_outcome_corpus_v1().unwrap();
    let recall: ExactHermeticIncidentRecallV1 = governed
        .case(HermeticIncidentCaseV1::Case01)
        .outcome(HermeticIncidentArmV1::FullThreeLane)
        .recall();
    let (numerator, denominator) = recall.exact_ratio();
    assert!(numerator <= denominator);
    assert_eq!(recall.requirement_count(), 2);
    assert!(recall.satisfied_requirement_count() <= recall.requirement_count());
}
