use std::path::PathBuf;

use evidentrail_bench_harness::{
    LEGACY_DRAIN_PINNED_COMMIT_V1, FirstPartyInProcessBuildV1, PINNED_LEGACY_DRAIN_MATCHED_INPUT_V1,
    PINNED_LEGACY_DRAIN_MATCHED_QUESTION_V1, PeakRssMeasurementUnitV1, PeakRssObservationBindingV1,
    PinnedLegacyDrainExecutionTargetV1, PinnedLegacyDrainTargetClassV1, PinnedDrainMatchedArmV1,
    PreparedPinnedDrainMatchedCaseErrorV1, PreparedPinnedDrainMatchedCaseV1,
    artifact_digest_for_bytes_v1, prepare_pinned_drain_matched_case_v1,
};
use evidentrail_core::derive_question_digest_v1;

const HERMETIC_FIRST_PARTY_PEAK_RSS_BYTES: u64 = 4_096;
const HERMETIC_DRAIN_PEAK_RSS_BYTES: u64 = 8_192;

fn helper_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_evidentrail-bench-harness-helper"))
}

fn prepare() -> PreparedPinnedDrainMatchedCaseV1 {
    let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
    let first_party =
        FirstPartyInProcessBuildV1::try_new(std::env::current_exe().unwrap()).unwrap();
    let drain =
        PinnedLegacyDrainExecutionTargetV1::try_new_hermetic_contract_fixture(helper_path(), cwd)
            .unwrap();
    prepare_pinned_drain_matched_case_v1(first_party, drain).unwrap()
}

#[test]
fn preparation_is_exact_score_free_deterministic_and_peak_rss_blocked() {
    let first = prepare();
    let second = prepare();

    first
        .first_party_manifest()
        .ensure_paired_comparable_with(first.drain_manifest())
        .unwrap();
    assert_eq!(
        first.public_case().question_digest(),
        derive_question_digest_v1(PINNED_LEGACY_DRAIN_MATCHED_QUESTION_V1)
    );
    assert_eq!(
        first.first_party_case_input().stdin().bytes(),
        PINNED_LEGACY_DRAIN_MATCHED_INPUT_V1
    );
    assert_eq!(first.ledger().len(), 6);
    assert_eq!(first.drain_full_membership().pattern_memberships().len(), 5);
    assert_eq!(
        first.drain_target_class(),
        PinnedLegacyDrainTargetClassV1::HermeticAdapterContractFixture
    );
    assert_ne!(
        first.drain_manifest().identity().system_artifact_digest(),
        artifact_digest_for_bytes_v1(LEGACY_DRAIN_PINNED_COMMIT_V1.as_bytes())
    );
    assert_ne!(
        first.drain_invocation().program().adapter_revision(),
        Some(LEGACY_DRAIN_PINNED_COMMIT_V1)
    );
    assert!(
        first
            .first_party_token_provenance()
            .is_whole_render_measured()
    );
    assert!(first.drain_token_provenance().is_whole_render_measured());
    assert_ne!(first.first_party_wall_time_nanos(), 0);
    assert_ne!(first.drain_execution().wall_time_nanos(), 0);
    assert!(!first.contains_hidden_annotations());
    assert!(!first.contains_scalar_outcome());
    assert!(!first.candidate_proposal_union_available());
    assert!(!first.cost_comparison_eligibility().cost_ordering_eligible());
    assert_ne!(
        first.cost_comparison_eligibility().first_party_scope(),
        first.cost_comparison_eligibility().drain_scope()
    );
    assert!(matches!(
        first.try_finalize(&[]),
        Err(
            PreparedPinnedDrainMatchedCaseErrorV1::MissingPeakRssObservation {
                arm: PinnedDrainMatchedArmV1::FirstParty,
            }
        )
    ));

    assert_eq!(
        first.preparation_contract_artifact_digest(),
        second.preparation_contract_artifact_digest()
    );
    assert_eq!(
        first.public_case_artifact_digest(),
        second.public_case_artifact_digest()
    );
    assert_eq!(
        first.first_party_manifest().identity(),
        second.first_party_manifest().identity()
    );
    assert_eq!(
        first.drain_manifest().identity(),
        second.drain_manifest().identity()
    );
    assert_eq!(
        first.first_party_rendered_artifact_digest(),
        second.first_party_rendered_artifact_digest()
    );
    assert_eq!(
        first.drain_full_membership().artifact_digest(),
        second.drain_full_membership().artifact_digest()
    );
    assert_eq!(
        first.drain_token_provenance().tokens(),
        u64::try_from(first.drain_execution().stdout().bytes().len()).unwrap()
    );

    let debug = format!("{first:?}");
    for forbidden in [
        "api request id=alpha",
        "database timeout",
        "what caused",
        "annotation_artifact",
        "root_cause",
    ] {
        assert!(!debug.contains(forbidden), "leaked {forbidden}: {debug}");
    }
}

#[test]
fn peak_rss_bindings_reject_mutation_and_fixture_finalization_stays_score_free() {
    let prepared = prepare();
    let mechanism = artifact_digest_for_bytes_v1(
        b"evidentrail/bench-harness/test-only-synthetic-peak-rss-observer/v1",
    );
    let first_binding = prepared
        .peak_rss_observation_binding(PinnedDrainMatchedArmV1::FirstParty)
        .unwrap();
    let drain_binding = prepared
        .peak_rss_observation_binding(PinnedDrainMatchedArmV1::PinnedDrainFullMembership)
        .unwrap();
    assert_eq!(
        first_binding.observe(mechanism, PeakRssMeasurementUnitV1::Bytes, 0),
        Err(PreparedPinnedDrainMatchedCaseErrorV1::InvalidPeakRssObservation)
    );

    let first = first_binding
        .observe(
            mechanism,
            PeakRssMeasurementUnitV1::Bytes,
            HERMETIC_FIRST_PARTY_PEAK_RSS_BYTES,
        )
        .unwrap();
    let drain = drain_binding
        .observe(
            mechanism,
            PeakRssMeasurementUnitV1::Bytes,
            HERMETIC_DRAIN_PEAK_RSS_BYTES,
        )
        .unwrap();
    assert!(matches!(
        prepared.try_finalize(&[first]),
        Err(
            PreparedPinnedDrainMatchedCaseErrorV1::MissingPeakRssObservation {
                arm: PinnedDrainMatchedArmV1::PinnedDrainFullMembership,
            }
        )
    ));
    assert!(matches!(
        prepared.try_finalize(&[first, first]),
        Err(
            PreparedPinnedDrainMatchedCaseErrorV1::DuplicatePeakRssObservation {
                arm: PinnedDrainMatchedArmV1::FirstParty,
            }
        )
    ));

    let wrong_drain_bindings = [
        PeakRssObservationBindingV1::new(
            PinnedDrainMatchedArmV1::PinnedDrainFullMembership,
            artifact_digest_for_bytes_v1(b"wrong-system"),
            drain_binding.executable_build_artifact_digest(),
            drain_binding.public_run_manifest_artifact_digest(),
            drain_binding.public_case_artifact_digest(),
        ),
        PeakRssObservationBindingV1::new(
            PinnedDrainMatchedArmV1::PinnedDrainFullMembership,
            drain_binding.system_artifact_digest(),
            artifact_digest_for_bytes_v1(b"wrong-executable-build"),
            drain_binding.public_run_manifest_artifact_digest(),
            drain_binding.public_case_artifact_digest(),
        ),
        PeakRssObservationBindingV1::new(
            PinnedDrainMatchedArmV1::PinnedDrainFullMembership,
            drain_binding.system_artifact_digest(),
            drain_binding.executable_build_artifact_digest(),
            artifact_digest_for_bytes_v1(b"wrong-run"),
            drain_binding.public_case_artifact_digest(),
        ),
        PeakRssObservationBindingV1::new(
            PinnedDrainMatchedArmV1::PinnedDrainFullMembership,
            drain_binding.system_artifact_digest(),
            drain_binding.executable_build_artifact_digest(),
            drain_binding.public_run_manifest_artifact_digest(),
            artifact_digest_for_bytes_v1(b"wrong-case"),
        ),
    ];
    for wrong_binding in wrong_drain_bindings {
        let wrong_drain = wrong_binding
            .observe(
                mechanism,
                PeakRssMeasurementUnitV1::Bytes,
                HERMETIC_DRAIN_PEAK_RSS_BYTES,
            )
            .unwrap();
        assert!(matches!(
            prepared.try_finalize(&[first, wrong_drain]),
            Err(
                PreparedPinnedDrainMatchedCaseErrorV1::PeakRssBindingMismatch {
                    arm: PinnedDrainMatchedArmV1::PinnedDrainFullMembership,
                }
            )
        ));
    }

    let changed_mechanism = drain_binding
        .observe(
            artifact_digest_for_bytes_v1(b"different-test-only-observer"),
            PeakRssMeasurementUnitV1::Bytes,
            HERMETIC_DRAIN_PEAK_RSS_BYTES,
        )
        .unwrap();
    assert_ne!(drain.artifact_digest(), changed_mechanism.artifact_digest());

    let finalized = prepared.try_finalize(&[first, drain]).unwrap();
    let changed_finalized = prepared.try_finalize(&[first, changed_mechanism]).unwrap();
    assert_ne!(
        finalized.artifact_digest(),
        changed_finalized.artifact_digest()
    );
    finalized
        .first_party_manifest()
        .ensure_paired_comparable_with(finalized.drain_manifest())
        .unwrap();
    assert_eq!(
        finalized
            .first_party_receipt()
            .submission()
            .resources()
            .peak_memory_bytes(),
        HERMETIC_FIRST_PARTY_PEAK_RSS_BYTES
    );
    assert_eq!(
        finalized
            .drain_receipt()
            .submission()
            .resources()
            .peak_memory_bytes(),
        HERMETIC_DRAIN_PEAK_RSS_BYTES
    );
    assert!(!finalized.first_party_peak_rss().is_independently_attested());
    assert!(!finalized.drain_peak_rss().is_independently_attested());
    assert!(!finalized.contains_hidden_annotations());
    assert!(!finalized.contains_scalar_outcome());
    assert!(!finalized.candidate_proposal_union_available());
    assert!(
        !finalized
            .cost_comparison_eligibility()
            .cost_ordering_eligible()
    );
    assert_ne!(
        finalized.artifact_digest(),
        finalized.first_party_peak_rss().artifact_digest()
    );

    let canary = "CANARY_PRIVATE_LOG_OR_LABEL";
    let debug = format!("{finalized:?}");
    assert!(!debug.contains(canary));
    let error = PreparedPinnedDrainMatchedCaseErrorV1::PeakRssBindingMismatch {
        arm: PinnedDrainMatchedArmV1::FirstParty,
    };
    assert!(!format!("{error:?}").contains(canary));
}
