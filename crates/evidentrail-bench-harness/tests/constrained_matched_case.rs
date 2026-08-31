#![cfg(target_os = "macos")]

use std::collections::BTreeSet;
use std::path::PathBuf;

use evidentrail_bench_harness::{
    CONSTRAINED_MATCHED_GENERATOR_SEED_V1, CONSTRAINED_MATCHED_GENERATOR_VERSION_V1,
    CONSTRAINED_MATCHED_IDENTIFIER_V1, CONSTRAINED_MATCHED_INPUT_ARTIFACT_DIGEST_V1,
    CONSTRAINED_MATCHED_QUESTION_V1, ClosedEnvironmentV1, ConstrainedMatchedCaseErrorV1,
    ExecutableBuildV1, ExternalOutputContractV1, FirstPartyConstrainedSubprocessErrorV1,
    FirstPartyConstrainedSubprocessTargetV1, FirstPartyOracleTrustV1,
    FirstPartySubprocessPeakRssStateV1, HarnessError, HarnessLimitsV1, HarnessTerminationCauseV1,
    InvocationInputContractV1, LEGACY_DRAIN_PINNED_COMMIT_V1, MatchedExecutionScopeV1,
    PinnedLegacyDrainExecutionTargetV1, PinnedLegacyDrainTargetClassV1,
    PreparedConstrainedPinnedDrainMatchedCaseV1, PublicSubprocessInvocationV1,
    artifact_digest_for_bytes_v1, artifact_digest_for_file_v1,
    constrained_pinned_drain_public_input_v1, execute_constrained_first_party_fixture_v1,
    execute_public_subprocess_v1, log_brief_compiled_method_descriptor_v1,
    prepare_constrained_pinned_drain_matched_case_v1,
};
use evidentrail_core::derive_question_digest_v1;

const EXPECTED_INPUT_BYTES_V1: usize = 152_248;
const EXPECTED_RECORDS_V1: usize = 200;
const EXPECTED_PRIMARY_BLOCKS_V1: u64 = 197;
const EXPECTED_PROPOSAL_PACKETS_V1: u64 = 14;
const EXPECTED_SELECTED_PACKETS_V1: u64 = 13;
const EXPECTED_TOKEN_BUDGET_V1: u64 = 180_000;

fn helper_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_evidentrail-bench-harness-helper"))
}

fn prepare() -> PreparedConstrainedPinnedDrainMatchedCaseV1 {
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
    prepare_constrained_pinned_drain_matched_case_v1(first_party, drain).unwrap()
}

#[test]
fn constrained_case_identity_is_frozen_compiled_deterministic_and_score_free() {
    let input = constrained_pinned_drain_public_input_v1().unwrap();
    assert_eq!(input.len(), EXPECTED_INPUT_BYTES_V1);
    assert_eq!(
        artifact_digest_for_bytes_v1(&input),
        CONSTRAINED_MATCHED_INPUT_ARTIFACT_DIGEST_V1
    );

    let first = prepare();
    let second = prepare();
    let generator = first.generator();
    assert_eq!(
        generator.generator_version(),
        CONSTRAINED_MATCHED_GENERATOR_VERSION_V1
    );
    assert_eq!(generator.seed(), CONSTRAINED_MATCHED_GENERATOR_SEED_V1);
    assert_eq!(
        generator.input_artifact_digest(),
        CONSTRAINED_MATCHED_INPUT_ARTIFACT_DIGEST_V1
    );
    assert_eq!(generator.input_byte_count(), EXPECTED_INPUT_BYTES_V1 as u64);
    assert_eq!(generator.record_count(), EXPECTED_RECORDS_V1 as u64);
    assert_eq!(generator.runtime_count(), 4);
    assert_eq!(generator.stream_count(), 3);
    assert_eq!(generator.validated_identifier_count(), 1);
    assert_eq!(generator.intact_failure_block_member_count(), 4);

    assert_eq!(
        first.first_party_method(),
        log_brief_compiled_method_descriptor_v1()
    );
    assert_eq!(first.public_case().budget_points().len(), 1);
    assert_eq!(
        first.public_case().budget_points()[0].canonical_candidate_tokens(),
        EXPECTED_TOKEN_BUDGET_V1
    );
    assert_eq!(
        first.public_case().question_digest(),
        derive_question_digest_v1(CONSTRAINED_MATCHED_QUESTION_V1)
    );
    assert_eq!(
        first.public_case().source_artifact_digests(),
        [CONSTRAINED_MATCHED_INPUT_ARTIFACT_DIGEST_V1]
    );
    assert_eq!(first.first_party_case_input().stdin().bytes(), input);
    assert_eq!(first.ledger().len(), EXPECTED_RECORDS_V1);
    assert_eq!(
        first
            .first_party_case_input()
            .source_record_map()
            .records()
            .len(),
        first.ledger().len()
    );
    for (record, event) in first
        .first_party_case_input()
        .source_record_map()
        .records()
        .iter()
        .zip(first.ledger().events())
    {
        assert_eq!(record.event_id(), event.id());
        assert_eq!(record.source_record_id(), event.source_record_id());
    }
    let runtime_lanes = first
        .ledger()
        .events()
        .iter()
        .map(|event| event.lane().member().as_bytes().to_vec())
        .collect::<BTreeSet<_>>();
    let stream_kinds = first
        .ledger()
        .events()
        .iter()
        .map(|event| event.lane().stream().code())
        .collect::<BTreeSet<_>>();
    assert_eq!(runtime_lanes.len(), 4);
    assert_eq!(stream_kinds.len(), 3);

    first
        .first_party_manifest()
        .ensure_paired_comparable_with(first.drain_manifest())
        .unwrap();
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

    let first_subprocess = first.first_party_subprocess_receipt();
    assert_eq!(
        first_subprocess.invocation().stdin().bytes(),
        input.as_slice()
    );
    assert_eq!(
        first_subprocess.system_artifact_digest(),
        first
            .first_party_manifest()
            .identity()
            .system_artifact_digest()
    );
    assert_eq!(
        first_subprocess.executable_build_artifact_digest(),
        first
            .first_party_manifest()
            .identity()
            .build_artifact_digest()
    );
    assert_eq!(
        first_subprocess.run_manifest_artifact_digest(),
        first_subprocess.invocation().run_manifest_artifact_digest()
    );
    assert_eq!(
        first_subprocess.public_case_artifact_digest(),
        first.public_case_artifact_digest()
    );
    assert_eq!(
        first_subprocess.stdin_artifact_digest(),
        CONSTRAINED_MATCHED_INPUT_ARTIFACT_DIGEST_V1
    );
    assert_eq!(
        first_subprocess.execution().stdout().artifact_digest(),
        first.first_party_rendered_artifact_digest()
    );
    assert_eq!(
        first_subprocess.captured_stdout_artifact_digest(),
        first.first_party_rendered_artifact_digest()
    );
    assert_eq!(
        first_subprocess.oracle_render_artifact_digest(),
        first.first_party_rendered_artifact_digest()
    );
    assert_eq!(
        first.first_party_wall_time_nanos(),
        first_subprocess.execution().wall_time_nanos()
    );
    assert!(first_subprocess.execution().stderr().bytes().is_empty());
    assert_eq!(
        first_subprocess.peak_rss_state(),
        FirstPartySubprocessPeakRssStateV1::ObservedMacOsTimeLDirectProcess
    );
    let first_peak = first.first_party_peak_rss_observer_receipt();
    let drain_peak = first.drain_peak_rss_observer_receipt().unwrap();
    assert_ne!(first_peak.peak_rss_bytes(), 0);
    assert_ne!(drain_peak.peak_rss_bytes(), 0);
    assert_eq!(
        first_peak.measurement_mechanism_artifact_digest(),
        drain_peak.measurement_mechanism_artifact_digest()
    );
    assert_eq!(
        first_peak.observer_executable_build_artifact_digest(),
        drain_peak.observer_executable_build_artifact_digest()
    );
    assert_eq!(
        first_peak.report_format_artifact_digest(),
        drain_peak.report_format_artifact_digest()
    );
    assert!(first_peak.observer_digest_verified_before_spawn());
    assert!(first_peak.observer_digest_verified_after_reap());
    assert_eq!(
        first_peak.observer_digest_before_spawn(),
        first_peak.observer_executable_build_artifact_digest()
    );
    assert_eq!(
        first_peak.observer_digest_after_reap(),
        first_peak.observer_executable_build_artifact_digest()
    );
    assert_eq!(first_peak.observer_canonical_path(), "/usr/bin/time");
    assert_eq!(first_peak.observer_contract_version(), 1);
    assert_eq!(first_peak.report_format_version(), 1);
    assert_eq!(
        first_subprocess.invocation().program().environment(),
        first.drain_invocation().program().environment()
    );
    assert_eq!(
        first_subprocess.invocation().limits().wall_nanos(),
        first.drain_invocation().limits().wall_nanos()
    );
    assert_eq!(
        first_subprocess.invocation().case_resolution_trust(),
        first.drain_invocation().case_resolution_trust()
    );
    assert!(first_peak.directly_timed_process_only());
    assert!(!first_peak.child_tree_peak_rss_claimed());
    assert!(!first_peak.independently_attested());
    assert_eq!(
        first_subprocess.oracle_trust(),
        FirstPartyOracleTrustV1::ParentExecutablePathHashBoundNotAttested
    );
    assert_ne!(
        first_subprocess.parent_oracle_build_artifact_digest(),
        first_subprocess.executable_build_artifact_digest()
    );
    assert!(first_subprocess.frozen_case_specific_reconstruction());
    assert!(!first_subprocess.contains_hidden_annotations());
    assert!(!first_subprocess.contains_scalar_outcome());

    let drain_membership = first.drain_full_membership();
    assert_eq!(
        drain_membership.charged_candidate_event_count(),
        EXPECTED_RECORDS_V1
    );
    assert_eq!(
        drain_membership.charged_candidate_source_bytes(),
        EXPECTED_INPUT_BYTES_V1 as u64
    );
    assert!(drain_membership.occurrence_membership_proven());
    assert!(drain_membership.resource_and_compression_accounting_available());
    assert!(!drain_membership.diagnostic_evidence_recall_scoreable());
    assert!(!drain_membership.source_exact_or_shown_verbatim());
    assert!(drain_membership.full_execution_measurement_required());

    assert!(first.first_party_proposal_audit_available());
    assert!(!first.drain_proposal_audit_available());
    assert!(!first.contains_hidden_annotations());
    assert!(!first.contains_scalar_outcome());
    assert!(!first.contains_downstream_vds_outcome());
    assert!(!first.representation_quality_scoreable());
    assert!(first.cost_comparison_eligibility().cost_ordering_eligible());
    assert_eq!(
        first.cost_comparison_eligibility().first_party_scope(),
        first.cost_comparison_eligibility().drain_scope()
    );
    assert!(first.cost_comparison_eligibility().wall_scope_comparable());
    assert!(first.cost_comparison_eligibility().peak_rss_comparable());
    assert_eq!(
        first.cost_comparison_eligibility().code(),
        "eligible_common_process_scope_and_peak_rss_observer"
    );
    let finalized = first.try_finalize().unwrap();
    assert_eq!(
        finalized.first_party_peak_rss().bytes(),
        first_peak.peak_rss_bytes()
    );
    assert_eq!(
        finalized.drain_peak_rss().bytes(),
        drain_peak.peak_rss_bytes()
    );
    assert!(
        finalized
            .cost_comparison_eligibility()
            .cost_ordering_eligible()
    );
    assert!(!finalized.contains_hidden_annotations());
    assert!(!finalized.contains_scalar_outcome());
    assert!(!finalized.representation_quality_scoreable());

    assert_eq!(generator, second.generator());
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
        first.first_party_subprocess_receipt().invocation().digest(),
        second
            .first_party_subprocess_receipt()
            .invocation()
            .digest()
    );
    assert_eq!(
        first
            .first_party_subprocess_receipt()
            .execution()
            .stdout()
            .artifact_digest(),
        second
            .first_party_subprocess_receipt()
            .execution()
            .stdout()
            .artifact_digest()
    );
    assert_eq!(
        first_peak.measurement_mechanism_artifact_digest(),
        second
            .first_party_peak_rss_observer_receipt()
            .measurement_mechanism_artifact_digest()
    );
    assert_eq!(
        first.proposal_audit().artifact_digest(),
        second.proposal_audit().artifact_digest()
    );
    assert_eq!(
        first.drain_full_membership().artifact_digest(),
        second.drain_full_membership().artifact_digest()
    );
}

#[test]
fn first_party_helper_rejects_foreign_input_and_receipt_mutations_contentlessly() {
    let _: fn(&[u8]) -> Result<Vec<u8>, ConstrainedMatchedCaseErrorV1> =
        execute_constrained_first_party_fixture_v1;
    let prepared = prepare();
    let receipt = prepared.first_party_subprocess_receipt();
    let mut foreign = constrained_pinned_drain_public_input_v1().unwrap();
    foreign[0] ^= 1;
    let foreign_error = execute_constrained_first_party_fixture_v1(&foreign).unwrap_err();
    assert_eq!(
        foreign_error,
        ConstrainedMatchedCaseErrorV1::InputArtifactMismatch
    );

    assert_eq!(
        receipt.verify_expected_render_v1(b"mutated-output"),
        Err(FirstPartyConstrainedSubprocessErrorV1::OutputMismatch)
    );
    assert_eq!(
        receipt.verify_execution_scope_v1(
            MatchedExecutionScopeV1::FirstPartyPreacquiredLedgerToOwnedRender
        ),
        Err(FirstPartyConstrainedSubprocessErrorV1::ExecutionScopeMismatch)
    );
    assert_eq!(
        receipt.verify_adapter_contract_v1(artifact_digest_for_bytes_v1(b"foreign-contract")),
        Err(FirstPartyConstrainedSubprocessErrorV1::AdapterContractMismatch)
    );

    let debug = format!("{receipt:?} {foreign_error:?}");
    for forbidden in [
        std::str::from_utf8(CONSTRAINED_MATCHED_IDENTIFIER_V1).unwrap(),
        std::str::from_utf8(CONSTRAINED_MATCHED_QUESTION_V1).unwrap(),
        "Traceback (most recent call last)",
        "mutated-output",
    ] {
        assert!(!debug.contains(forbidden));
    }
}

#[test]
fn first_party_subprocess_harness_enforces_build_output_and_wall_bounds() {
    let prepared = prepare();
    let manifest = prepared.first_party_manifest();
    let identity = manifest.identity();
    let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
    let input_len = u64::try_from(prepared.first_party_case_input().stdin().bytes().len()).unwrap();

    let wrong_executable = std::env::current_exe().unwrap().canonicalize().unwrap();
    let wrong_program = ExecutableBuildV1::try_new(
        identity.system_artifact_digest(),
        artifact_digest_for_file_v1(&wrong_executable).unwrap(),
        wrong_executable,
        vec!["ignored".to_owned()],
        cwd.clone(),
        ClosedEnvironmentV1::empty(),
        ExternalOutputContractV1::ExactIdentityNormalizer,
        Some("foreign-build-v1".to_owned()),
    )
    .unwrap();
    let normal_limits = HarnessLimitsV1::try_new(input_len, 1_000_000, 0, 5_000_000_000).unwrap();
    assert_eq!(
        PublicSubprocessInvocationV1::try_new(
            manifest,
            prepared.first_party_case_input().clone(),
            wrong_program,
            normal_limits,
            InvocationInputContractV1::ByteExact,
        ),
        Err(HarnessError::BuildArtifactMismatch)
    );

    let helper = helper_path().canonicalize().unwrap();
    let capped_program = ExecutableBuildV1::try_new(
        identity.system_artifact_digest(),
        identity.build_artifact_digest(),
        helper.clone(),
        vec!["--evidentrail-bench-first-party-constrained-v1".to_owned()],
        cwd.clone(),
        ClosedEnvironmentV1::empty(),
        ExternalOutputContractV1::ExactIdentityNormalizer,
        Some("evidentrail-first-party-constrained-subprocess-v2".to_owned()),
    )
    .unwrap();
    let capped = PublicSubprocessInvocationV1::try_new(
        manifest,
        prepared.first_party_case_input().clone(),
        capped_program,
        HarnessLimitsV1::try_new(input_len, 1, 0, 5_000_000_000).unwrap(),
        InvocationInputContractV1::ByteExact,
    )
    .unwrap();
    let capped_execution = execute_public_subprocess_v1(&capped).unwrap();
    assert!(
        capped_execution
            .termination_causes()
            .contains(&HarnessTerminationCauseV1::StdoutByteCap)
    );

    let sleeping_program = ExecutableBuildV1::try_new(
        identity.system_artifact_digest(),
        identity.build_artifact_digest(),
        helper,
        vec!["sleep-ms".to_owned(), "10000".to_owned()],
        cwd,
        ClosedEnvironmentV1::empty(),
        ExternalOutputContractV1::ExactIdentityNormalizer,
        Some("timeout-contract-probe-v1".to_owned()),
    )
    .unwrap();
    let sleeping = PublicSubprocessInvocationV1::try_new(
        manifest,
        prepared.first_party_case_input().clone(),
        sleeping_program,
        HarnessLimitsV1::try_new(input_len, 1, 0, 30_000_000).unwrap(),
        InvocationInputContractV1::ByteExact,
    )
    .unwrap();
    let timed_out = execute_public_subprocess_v1(&sleeping).unwrap();
    assert!(
        timed_out
            .termination_causes()
            .contains(&HarnessTerminationCauseV1::WallDeadline),
        "{timed_out:?}"
    );
    assert!(timed_out.child_reaped());
}

#[test]
fn production_audit_reconciles_exhaustive_selected_and_retained_partitions() {
    let prepared = prepare();
    let audit = prepared.proposal_audit();
    let production = audit.audit();
    let producer_receipt = production.receipt().unwrap();
    let producer_accounting = producer_receipt.accounting();

    assert_eq!(production.code(), "selected");
    assert!(production.reason().is_none());
    assert_eq!(
        audit.exhaustive_primary_block_count(),
        EXPECTED_PRIMARY_BLOCKS_V1
    );
    assert_eq!(
        audit.exhaustive_unique_member_event_count(),
        EXPECTED_RECORDS_V1 as u64
    );
    assert_eq!(
        audit.exhaustive_member_source_bytes(),
        EXPECTED_INPUT_BYTES_V1 as u64
    );
    assert_eq!(audit.proposal_packet_count(), EXPECTED_PROPOSAL_PACKETS_V1);
    assert_eq!(audit.selected_packet_count(), EXPECTED_SELECTED_PACKETS_V1);
    assert_eq!(
        audit.certification_packet_count(),
        audit.proposal_packet_count()
    );
    assert_eq!(
        audit.exhaustive_primary_block_count(),
        audit.proposal_packet_count() + audit.retained_raw_nonproposal_block_count()
    );
    assert_eq!(
        audit.exhaustive_unique_member_event_count(),
        audit.proposal_unique_member_event_count()
            + audit.retained_raw_nonproposal_unique_member_event_count()
    );
    assert_eq!(
        audit.exhaustive_member_source_bytes(),
        audit.proposal_member_source_bytes() + audit.retained_raw_nonproposal_source_bytes()
    );
    assert_eq!(
        audit.proposal_packet_count(),
        producer_accounting.proposal_packet_count()
    );
    assert_eq!(
        audit.proposal_unique_member_event_count(),
        producer_accounting.proposal_unique_member_event_count()
    );
    assert_eq!(
        audit.proposal_member_source_bytes(),
        producer_accounting.proposal_member_source_bytes()
    );
    assert_eq!(
        audit.proposal_affinity_count(),
        producer_accounting.proposal_affinity_count()
    );
    assert_eq!(
        audit.mandatory_proposal_count(),
        producer_accounting.mandatory_proposal_count()
    );
    assert_eq!(audit.facet_count(), producer_accounting.facet_count());
    assert_eq!(
        audit.validated_identifier_mandatory_reason_count(),
        audit.mandatory_proposal_count()
    );
    assert!(audit.validated_identifier_failure_block_selected());
    assert!(audit.selected_unique_member_event_count() > 0);
    assert!(
        audit.selected_unique_member_event_count() < audit.exhaustive_unique_member_event_count()
    );
    assert!(!production.selected_packet_ids().unwrap().is_empty());
    assert!(!production.prepared().unwrap().proposal_packets().is_empty());

    let debug = format!("{prepared:?}");
    for forbidden in [
        std::str::from_utf8(CONSTRAINED_MATCHED_IDENTIFIER_V1).unwrap(),
        std::str::from_utf8(CONSTRAINED_MATCHED_QUESTION_V1).unwrap(),
        "Traceback (most recent call last)",
        "request_id=",
        "annotation_artifact",
        "root_cause",
    ] {
        assert!(!debug.contains(forbidden), "redaction failure");
    }
    let canary = "CANARY_PRIVATE_LOG_OR_LABEL";
    for error in [
        ConstrainedMatchedCaseErrorV1::ProposalAccountingMismatch,
        ConstrainedMatchedCaseErrorV1::ValidatedIdentifierFailureBlockNotSelected,
        ConstrainedMatchedCaseErrorV1::ProductArtifactBindingMismatch,
    ] {
        assert!(!format!("{error:?}").contains(canary));
        assert!(!error.to_string().contains(canary));
    }
}
