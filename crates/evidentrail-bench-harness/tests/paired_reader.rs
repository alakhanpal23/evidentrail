#![cfg(target_os = "macos")]

use std::collections::BTreeSet;
use std::path::PathBuf;

use evidentrail_bench::{EvidentrailBenchAnnotationSpecV1, WeightedDiagnosticRequirementV1};
use evidentrail_bench_harness::{
    CONSTRAINED_MATCHED_IDENTIFIER_V1, CONSTRAINED_MATCHED_QUESTION_V1,
    ConstrainedReaderPairErrorV1, ConstrainedReaderPairRepeatabilityV1,
    DeterministicFixtureReaderModeV1, DeterministicFixtureReaderV1,
    FirstPartyConstrainedSubprocessTargetV1, FrozenConstrainedReaderPairV1, GovernedReaderTruthV1,
    HarnessLimitsV1, MacOsTimePeakRssObserverV1, PinnedLegacyDrainExecutionTargetV1,
    ReaderCauseGranularityV1, ReaderErrorV1, ReaderResourceCapsV1, artifact_digest_for_bytes_v1,
    evaluate_governed_constrained_reader_pair_v1, execute_constrained_reader_pair_v1,
    legacy_drain_full_membership_method_descriptor_v1, log_brief_compiled_method_descriptor_v1,
    prepare_constrained_pinned_drain_matched_case_v1, prepare_constrained_reader_input_pair_v1,
};
use evidentrail_schema::ArtifactDigest;

fn helper_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_evidentrail-bench-harness-helper"))
}

fn reader(mode: DeterministicFixtureReaderModeV1) -> DeterministicFixtureReaderV1 {
    DeterministicFixtureReaderV1::try_new(
        helper_path(),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        mode,
    )
    .unwrap()
}

fn caps() -> ReaderResourceCapsV1 {
    ReaderResourceCapsV1::try_new(
        HarnessLimitsV1::try_new(8 * 1024 * 1024, 1024 * 1024, 64 * 1024, 10_000_000_000).unwrap(),
        8 * 1024 * 1024,
        1024 * 1024,
        2 * 1024 * 1024 * 1024,
        1,
    )
    .unwrap()
}

fn truth_for_pair(
    inputs: &evidentrail_bench_harness::ConstrainedReaderInputPairV1,
) -> GovernedReaderTruthV1 {
    let handles = inputs.first_party().method_artifact().citation_handles();
    assert!(handles.len() >= 2);
    let first =
        WeightedDiagnosticRequirementV1::new(1_000_000, [handles[0].targets().to_vec()]).unwrap();
    let mut jointly_sufficient = handles[0].targets().to_vec();
    jointly_sufficient.extend_from_slice(handles[1].targets());
    let second = WeightedDiagnosticRequirementV1::new(2_000_000, [jointly_sufficient]).unwrap();
    let annotation = EvidentrailBenchAnnotationSpecV1::new(
        inputs.public_case_artifact_digest(),
        [first, second],
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    GovernedReaderTruthV1::try_new(
        inputs.public_case_artifact_digest(),
        annotation,
        true,
        vec!["db_pool_exhaustion".to_owned()],
        vec![ReaderCauseGranularityV1::RootCause],
        vec![
            "connection_pressure".to_owned(),
            "requests_blocked".to_owned(),
        ],
        vec!["network_fault".to_owned()],
    )
    .unwrap()
}

fn foreign_truth(
    inputs: &evidentrail_bench_harness::ConstrainedReaderInputPairV1,
) -> GovernedReaderTruthV1 {
    let foreign_case = ArtifactDigest::from_bytes([0xA7; 32]);
    let requirement = WeightedDiagnosticRequirementV1::new(
        1_000_000,
        [inputs.first_party().method_artifact().citation_handles()[0]
            .targets()
            .to_vec()],
    )
    .unwrap();
    let annotation = EvidentrailBenchAnnotationSpecV1::new(
        foreign_case,
        [requirement],
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    GovernedReaderTruthV1::try_new(
        foreign_case,
        annotation,
        true,
        vec!["db_pool_exhaustion".to_owned()],
        vec![ReaderCauseGranularityV1::RootCause],
        vec![
            "connection_pressure".to_owned(),
            "requests_blocked".to_owned(),
        ],
        Vec::new(),
    )
    .unwrap()
}

#[test]
fn same_case_methods_freeze_under_equal_reader_contract_and_govern_only_after_output() {
    let first_party = FirstPartyConstrainedSubprocessTargetV1::try_new(
        helper_path(),
        std::env::current_dir().unwrap(),
    )
    .unwrap();
    let drain = PinnedLegacyDrainExecutionTargetV1::try_new_hermetic_contract_fixture(
        helper_path(),
        std::env::current_dir().unwrap(),
    )
    .unwrap();
    let prepared = prepare_constrained_pinned_drain_matched_case_v1(first_party, drain).unwrap();
    let finalized = prepared.try_finalize().unwrap();
    let inputs = prepare_constrained_reader_input_pair_v1(&prepared).unwrap();

    assert_eq!(
        inputs.first_party().question(),
        CONSTRAINED_MATCHED_QUESTION_V1
    );
    assert_eq!(inputs.drain().question(), CONSTRAINED_MATCHED_QUESTION_V1);
    assert_eq!(inputs.first_party().context(), inputs.drain().context());
    assert_eq!(
        inputs.first_party().method_artifact().method(),
        log_brief_compiled_method_descriptor_v1()
    );
    assert_eq!(
        inputs.drain().method_artifact().method(),
        legacy_drain_full_membership_method_descriptor_v1()
    );
    assert_eq!(
        inputs
            .first_party()
            .method_artifact()
            .source_provenance_artifact_digest(),
        finalized
            .first_party_receipt()
            .submission()
            .artifact_digest()
    );
    assert_eq!(
        inputs
            .drain()
            .method_artifact()
            .source_provenance_artifact_digest(),
        prepared.drain_full_membership().artifact_digest()
    );
    assert_eq!(
        inputs.first_party().method_artifact().bytes(),
        prepared
            .first_party_subprocess_receipt()
            .execution()
            .stdout()
            .bytes()
    );
    assert_eq!(
        inputs.drain().method_artifact().bytes(),
        prepared.drain_execution().stdout().bytes()
    );

    let first_handles = inputs.first_party().method_artifact().citation_handles();
    assert!(!first_handles.is_empty());
    let cited_events = first_handles
        .iter()
        .flat_map(|handle| handle.targets().iter().copied())
        .collect::<BTreeSet<_>>();
    let exact_claim_events = finalized
        .first_party_receipt()
        .submission()
        .claims()
        .iter()
        .map(|claim| evidentrail_bench::EvidenceTargetV1::Event(claim.event_id()))
        .collect::<BTreeSet<_>>();
    assert_eq!(cited_events, exact_claim_events);
    for handle in first_handles {
        let start = usize::try_from(handle.marker_start()).unwrap();
        let end = usize::try_from(handle.marker_end()).unwrap();
        assert_eq!(
            &inputs.first_party().method_artifact().bytes()[start..end],
            format!("[E{}]", handle.handle()).as_bytes()
        );
    }
    assert!(
        inputs
            .drain()
            .method_artifact()
            .citation_handles()
            .is_empty()
    );
    assert_eq!(inputs.drain_source_exact_citation_handle_count(), 0);
    assert!(!inputs.drain_pattern_membership_promoted_to_source_exact_citations());
    assert!(!inputs.contains_hidden_labels());

    let observer = MacOsTimePeakRssObserverV1::try_system_v1().unwrap();
    let target = reader(DeterministicFixtureReaderModeV1::Correct);
    let pair =
        execute_constrained_reader_pair_v1(&observer, &target, inputs.clone(), caps()).unwrap();
    let second_pair =
        execute_constrained_reader_pair_v1(&observer, &target, inputs.clone(), caps()).unwrap();
    let repeatability =
        ConstrainedReaderPairRepeatabilityV1::try_new(&[pair.clone(), second_pair]).unwrap();
    assert_eq!(repeatability.trial_count(), 2);
    assert_eq!(
        repeatability.first_party().answer_artifact_digest(),
        pair.first_party().answer_artifact_digest()
    );
    assert_eq!(
        repeatability.drain().answer_artifact_digest(),
        pair.drain().answer_artifact_digest()
    );
    assert_eq!(repeatability.paired_trial_artifact_digests().len(), 2);
    assert!(!repeatability.contains_hidden_labels());
    assert!(!repeatability.contains_scalar_score_or_winner());
    assert_eq!(pair.first_party().caps(), pair.drain().caps());
    assert_eq!(
        pair.first_party().target().configuration_artifact_digest(),
        pair.drain().target().configuration_artifact_digest()
    );
    assert_eq!(
        pair.first_party().prompt().template_artifact_digest(),
        pair.drain().prompt().template_artifact_digest()
    );
    assert!(!pair.contains_hidden_labels());
    assert!(!pair.contains_scalar_score_or_winner());

    assert_eq!(
        FrozenConstrainedReaderPairV1::try_new(
            inputs.clone(),
            pair.drain().clone(),
            pair.first_party().clone(),
        ),
        Err(ConstrainedReaderPairErrorV1::ReaderArmBindingMismatch)
    );
    let alternate = reader(DeterministicFixtureReaderModeV1::AlternateValid);
    let alternate_pair =
        execute_constrained_reader_pair_v1(&observer, &alternate, inputs.clone(), caps()).unwrap();
    assert_eq!(
        FrozenConstrainedReaderPairV1::try_new(
            inputs.clone(),
            pair.first_party().clone(),
            alternate_pair.drain().clone(),
        ),
        Err(ConstrainedReaderPairErrorV1::ReaderConfigurationMismatch)
    );
    assert_eq!(
        ConstrainedReaderPairRepeatabilityV1::try_new(&[pair.clone(), alternate_pair]),
        Err(ConstrainedReaderPairErrorV1::PairRepeatabilityBindingMismatch)
    );

    assert_eq!(
        evaluate_governed_constrained_reader_pair_v1(&pair, &foreign_truth(&inputs)),
        Err(ConstrainedReaderPairErrorV1::Reader(
            ReaderErrorV1::GovernedCaseBindingMismatch,
        ))
    );
    let governed =
        evaluate_governed_constrained_reader_pair_v1(&pair, &truth_for_pair(&inputs)).unwrap();
    assert_eq!(
        governed.first_party().method(),
        log_brief_compiled_method_descriptor_v1()
    );
    assert_eq!(
        governed.drain().method(),
        legacy_drain_full_membership_method_descriptor_v1()
    );
    assert!(governed.first_party().score().cause_code_verified());
    assert!(governed.drain().score().cause_code_verified());
    assert_eq!(governed.first_party().score().valid_citation_count(), 2);
    assert_eq!(governed.first_party().score().invalid_citation_count(), 0);
    assert_eq!(governed.drain().score().valid_citation_count(), 0);
    assert_eq!(governed.drain().score().invalid_citation_count(), 2);
    assert_eq!(
        governed.first_party().score().total_requirement_count(),
        governed.drain().score().total_requirement_count()
    );
    assert_ne!(governed.first_party().resources().wall_time_nanos(), 0);
    assert_ne!(governed.drain().resources().wall_time_nanos(), 0);
    assert_ne!(
        governed
            .first_party()
            .resources()
            .direct_process_peak_rss_bytes(),
        0
    );
    assert_ne!(
        governed.drain().resources().direct_process_peak_rss_bytes(),
        0
    );
    assert!(!governed.scalar_score_available());
    assert!(!governed.winner_available());
    assert!(!governed.hosted_reader_used());
    assert!(!governed.comparative_quality_or_fairness_claim());

    let debug = format!("{inputs:?} {pair:?} {governed:?}");
    assert!(!debug.contains(std::str::from_utf8(CONSTRAINED_MATCHED_QUESTION_V1).unwrap()));
    assert!(!debug.contains(std::str::from_utf8(CONSTRAINED_MATCHED_IDENTIFIER_V1).unwrap()));
    assert!(!debug.contains("db_pool_exhaustion"));
    let error_debug = format!(
        "{:?}",
        ConstrainedReaderPairErrorV1::SourceArtifactBindingMismatch
    );
    assert_eq!(
        error_debug,
        "ConstrainedReaderPairErrorV1 { code: \"EVIDENTRAIL_BENCH_CONSTRAINED_READER_SOURCE_ARTIFACT_BINDING_MISMATCH\" }"
    );
    assert!(!error_debug.contains("artifact_digest"));
    assert_ne!(
        inputs.first_party_source_receipt_artifact_digest(),
        artifact_digest_for_bytes_v1(b"foreign-source-receipt")
    );
}
