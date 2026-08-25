#![cfg(target_os = "macos")]

use std::path::PathBuf;

use evidentrail_bench_harness::{
    CONSTRAINED_MATCHED_IDENTIFIER_V1, CONSTRAINED_PAIRED_TRIAL_COUNT_V1,
    ConstrainedPairedTrialErrorV1, ConstrainedPairedTrialOrderV1,
    FirstPartyConstrainedSubprocessTargetV1, PinnedLegacyDrainExecutionTargetV1,
    artifact_digest_for_bytes_v1, current_constrained_first_party_policy_identity_v1,
    run_constrained_paired_trials_for_expected_policy_v1, run_constrained_paired_trials_v1,
};

fn helper_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_evidentrail-bench-harness-helper"))
}

#[test]
fn fixed_alternating_trials_retain_raw_dimensions_and_never_claim_quality() {
    let helper = helper_path();
    let cwd = std::env::current_dir().unwrap();
    let first_party =
        FirstPartyConstrainedSubprocessTargetV1::try_new(helper.clone(), cwd.clone()).unwrap();
    let pinned_drain =
        PinnedLegacyDrainExecutionTargetV1::try_new_hermetic_contract_fixture(helper, cwd).unwrap();
    let run = run_constrained_paired_trials_v1(first_party, pinned_drain).unwrap();
    let prepared = run.prepared();
    let receipt = run.receipt();

    assert_eq!(receipt.trial_count(), CONSTRAINED_PAIRED_TRIAL_COUNT_V1);
    assert_eq!(receipt.trials().len(), CONSTRAINED_PAIRED_TRIAL_COUNT_V1);
    assert_eq!(
        receipt.finalized_case_artifact_digest(),
        run.finalized().artifact_digest()
    );
    assert_eq!(
        receipt.public_case_artifact_digest(),
        prepared.public_case_artifact_digest()
    );
    assert_eq!(
        receipt.first_party_invocation_digest(),
        prepared
            .first_party_subprocess_receipt()
            .invocation()
            .digest()
    );
    assert_eq!(
        receipt.pinned_drain_invocation_digest(),
        prepared.drain_invocation().digest()
    );
    assert_eq!(
        receipt.first_party_executable_build_artifact_digest(),
        prepared
            .first_party_subprocess_receipt()
            .executable_build_artifact_digest()
    );
    assert_eq!(
        receipt.pinned_drain_executable_build_artifact_digest(),
        prepared
            .drain_invocation()
            .program()
            .executable_build_artifact_digest()
    );
    assert_eq!(
        receipt.proposal_audit_artifact_digest(),
        prepared.proposal_audit().artifact_digest()
    );
    let policy_identity = receipt.first_party_policy_identity();
    assert_eq!(
        policy_identity,
        current_constrained_first_party_policy_identity_v1().unwrap()
    );
    let proposal_input = prepared.proposal_audit().audit().input();
    assert_eq!(
        policy_identity.candidate_config_digest(),
        proposal_input.candidate_config_digest()
    );
    assert_eq!(
        policy_identity.compiler_config_digest(),
        proposal_input.compiler_config_digest()
    );

    let first_output = prepared
        .first_party_subprocess_receipt()
        .execution()
        .stdout();
    let drain_output = prepared.drain_execution().stdout();
    let mut first_wall = Vec::new();
    let mut first_rss = Vec::new();
    let mut drain_wall = Vec::new();
    let mut drain_rss = Vec::new();
    for (index, trial) in receipt.trials().iter().enumerate() {
        assert_eq!(usize::from(trial.index()), index);
        assert_eq!(
            trial.order(),
            ConstrainedPairedTrialOrderV1::preregistered_for_index(index)
        );
        assert_eq!(
            trial.first_party().execution().stdout().bytes(),
            first_output.bytes()
        );
        assert_eq!(
            trial.pinned_drain().execution().stdout().bytes(),
            drain_output.bytes()
        );
        for observation in [trial.first_party(), trial.pinned_drain()] {
            assert_ne!(observation.wall_time_nanos(), 0);
            assert_ne!(observation.peak_rss_bytes(), 0);
            assert_ne!(observation.peak_rss_receipt().raw_report_byte_count(), 0);
            assert!(observation.direct_process_rss_only());
            assert!(!observation.child_tree_rss_claimed());
            assert!(!observation.independently_attested());
        }
        assert_eq!(
            trial
                .first_party()
                .peak_rss_receipt()
                .measurement_mechanism_artifact_digest(),
            receipt.observer_measurement_mechanism_artifact_digest()
        );
        assert_eq!(
            trial
                .pinned_drain()
                .peak_rss_receipt()
                .observer_executable_build_artifact_digest(),
            receipt.observer_executable_build_artifact_digest()
        );
        first_wall.push(trial.first_party().wall_time_nanos());
        first_rss.push(trial.first_party().peak_rss_bytes());
        drain_wall.push(trial.pinned_drain().wall_time_nanos());
        drain_rss.push(trial.pinned_drain().peak_rss_bytes());
    }

    assert_summary(receipt.first_party().wall_time_nanos(), &first_wall);
    assert_summary(receipt.first_party().peak_rss_bytes(), &first_rss);
    assert_summary(receipt.pinned_drain().wall_time_nanos(), &drain_wall);
    assert_summary(receipt.pinned_drain().peak_rss_bytes(), &drain_rss);
    assert_eq!(
        receipt.first_party().stdout_artifact_digest(),
        first_output.artifact_digest()
    );
    assert_eq!(
        receipt.pinned_drain().stdout_artifact_digest(),
        drain_output.artifact_digest()
    );

    assert!(!receipt.contains_hidden_annotations());
    assert!(!receipt.contains_scalar_outcome());
    assert!(!receipt.contains_quality_claim());
    assert!(!receipt.child_tree_rss_claimed());
    assert!(!receipt.independently_attested());
    assert_eq!(
        receipt.verify_finalized_case_artifact_v1(artifact_digest_for_bytes_v1(b"foreign")),
        Err(ConstrainedPairedTrialErrorV1::FinalizedCaseBindingMismatch)
    );
    let debug = format!("{run:?}");
    assert!(!debug.contains(std::str::from_utf8(CONSTRAINED_MATCHED_IDENTIFIER_V1).unwrap()));
    assert!(!debug.contains("Traceback"));
    assert!(!debug.contains("winner"));
}

#[test]
fn preregistered_policy_mismatch_fails_before_any_trial_execution() {
    let helper = helper_path();
    let cwd = std::env::current_dir().unwrap();
    let first_party =
        FirstPartyConstrainedSubprocessTargetV1::try_new(helper.clone(), cwd.clone()).unwrap();
    let pinned_drain =
        PinnedLegacyDrainExecutionTargetV1::try_new_hermetic_contract_fixture(helper, cwd).unwrap();
    let foreign = artifact_digest_for_bytes_v1(b"foreign-preregistered-policy");
    assert_ne!(
        foreign,
        current_constrained_first_party_policy_identity_v1()
            .unwrap()
            .artifact_digest()
    );
    assert!(matches!(
        run_constrained_paired_trials_for_expected_policy_v1(foreign, first_party, pinned_drain,),
        Err(ConstrainedPairedTrialErrorV1::ExpectedPolicyMismatch)
    ));
}

fn assert_summary(summary: evidentrail_bench_harness::IntegerSpreadV1, values: &[u64]) {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let median = sorted[sorted.len() / 2];
    let mut deviations = values
        .iter()
        .map(|value| value.abs_diff(median))
        .collect::<Vec<_>>();
    deviations.sort_unstable();
    assert_eq!(summary.count(), u64::try_from(values.len()).unwrap());
    assert_eq!(summary.minimum(), sorted[0]);
    assert_eq!(summary.median(), median);
    assert_eq!(summary.maximum(), sorted[sorted.len() - 1]);
    assert_eq!(
        summary.median_absolute_deviation(),
        deviations[deviations.len() / 2]
    );
}
