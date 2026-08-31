#![cfg(target_os = "macos")]

use std::collections::BTreeSet;
use std::path::PathBuf;

use evidentrail_bench_harness::{
    CONSTRAINED_MATCHED_IDENTIFIER_V1, CONSTRAINED_MATCHED_QUESTION_V1,
    ConstrainedProducerUniverseBridgeErrorV1, FirstPartyConstrainedSubprocessTargetV1,
    PinnedLegacyDrainExecutionTargetV1, PreparedConstrainedPinnedDrainMatchedCaseV1,
    ProducerUniverseBasisV1, freeze_constrained_producer_universes_v1,
    prepare_constrained_pinned_drain_matched_case_v1,
};

const EXPECTED_FIRST_PARTY_PROPOSAL_PACKETS_V1: u64 = 14;
const EXPECTED_LEDGER_EVENTS_V1: u64 = 200;
const EXPECTED_LEDGER_SOURCE_BYTES_V1: u64 = 152_248;
const EXPECTED_HERMETIC_DRAIN_GROUPS_V1: u64 = 1;

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
fn constrained_bridge_freezes_exact_production_packets_and_full_drain_partition() {
    let prepared = prepare();
    let bridge = freeze_constrained_producer_universes_v1(&prepared).unwrap();
    let first_party = bridge.first_party();
    let drain = bridge.drain();
    let first_accounting = first_party.universe().accounting();
    let drain_accounting = drain.universe().accounting();

    assert_eq!(
        first_party.basis(),
        ProducerUniverseBasisV1::FirstPartyProductionPreSelection
    );
    assert_eq!(
        drain.basis(),
        ProducerUniverseBasisV1::DrainPostHocCompleteOccurrenceUpperBound
    );
    assert_eq!(
        first_accounting.proposal_packet_count(),
        EXPECTED_FIRST_PARTY_PROPOSAL_PACKETS_V1
    );
    assert_eq!(
        first_accounting.proposal_packet_count(),
        prepared.proposal_audit().proposal_packet_count()
    );
    assert_eq!(
        first_accounting.unique_member_event_count(),
        prepared
            .proposal_audit()
            .proposal_unique_member_event_count()
    );
    assert_eq!(
        first_accounting.unique_member_source_bytes(),
        prepared.proposal_audit().proposal_member_source_bytes()
    );
    assert!(first_accounting.unique_member_event_count() < EXPECTED_LEDGER_EVENTS_V1);
    assert!(first_party.original_preselection_producer_api());
    assert!(!first_party.posthoc_complete_occurrence_upper_bound());
    assert!(!first_party.complete_ledger_partition());
    assert!(first_party.nonexhaustive_ledger_proposal_union());
    assert_eq!(
        first_party.source_receipt_artifact_digest(),
        prepared.proposal_audit().artifact_digest()
    );
    assert_eq!(
        first_party
            .universe()
            .producer()
            .producer_receipt_artifact_digest(),
        prepared
            .proposal_audit()
            .audit()
            .receipt()
            .unwrap()
            .digest()
    );

    let production_memberships = prepared
        .proposal_audit()
        .audit()
        .prepared()
        .unwrap()
        .proposal_packets()
        .iter()
        .map(|packet| packet.event_ids().to_vec())
        .collect::<BTreeSet<_>>();
    let frozen_memberships = first_party
        .universe()
        .proposals()
        .iter()
        .map(|packet| packet.member_event_ids().to_vec())
        .collect::<BTreeSet<_>>();
    assert_eq!(frozen_memberships, production_memberships);

    assert_eq!(
        drain_accounting.proposal_packet_count(),
        EXPECTED_HERMETIC_DRAIN_GROUPS_V1
    );
    assert_eq!(
        drain_accounting.unique_member_event_count(),
        EXPECTED_LEDGER_EVENTS_V1
    );
    assert_eq!(
        drain_accounting.unique_member_source_bytes(),
        EXPECTED_LEDGER_SOURCE_BYTES_V1
    );
    assert!(drain.complete_ledger_partition());
    assert!(!drain.nonexhaustive_ledger_proposal_union());
    assert!(drain.posthoc_complete_occurrence_upper_bound());
    assert!(!drain.original_preselection_producer_api());
    assert_eq!(
        drain.source_receipt_artifact_digest(),
        prepared.drain_full_membership().artifact_digest()
    );
    let drain_members = drain
        .universe()
        .proposals()
        .iter()
        .flat_map(|packet| packet.member_event_ids().iter().copied())
        .collect::<BTreeSet<_>>();
    let ledger_members = prepared
        .ledger()
        .events()
        .iter()
        .map(|event| event.id())
        .collect::<BTreeSet<_>>();
    let drain_member_references = drain
        .universe()
        .proposals()
        .iter()
        .map(|packet| packet.member_event_ids().len())
        .sum::<usize>();
    assert_eq!(drain_members, ledger_members);
    assert_eq!(drain_member_references, prepared.ledger().len());

    assert_eq!(
        first_party.universe().acquisition_binding(),
        drain.universe().acquisition_binding()
    );
    assert_eq!(
        bridge.acquisition_binding(),
        first_party.universe().acquisition_binding()
    );
    assert_eq!(
        bridge.public_case_artifact_digest(),
        prepared.public_case_artifact_digest()
    );
    for arm in [first_party, drain] {
        assert!(!arm.source_exact_representation_claim());
        assert!(!arm.representation_recall_scoreable());
        assert!(!arm.contains_hidden_annotations());
        assert!(!arm.contains_measurements_or_caps());
        assert!(!arm.contains_score_or_winner());
        assert!(!arm.contains_downstream_vds_outcome());
    }
    assert!(!bridge.contains_hidden_annotations());
    assert!(!bridge.contains_measurements_or_caps());
    assert!(!bridge.contains_score_or_winner());
    assert!(!bridge.contains_downstream_vds_outcome());
    assert!(!bridge.hosted_evidentrail_behavior_claim());
    assert!(!bridge.drain_original_preselection_api_claim());
}

#[test]
fn constrained_bridge_is_deterministic_and_debug_and_errors_are_contentless() {
    let first = freeze_constrained_producer_universes_v1(&prepare()).unwrap();
    let second = freeze_constrained_producer_universes_v1(&prepare()).unwrap();
    assert_eq!(first.artifact_digest(), second.artifact_digest());
    assert_eq!(
        first.first_party().universe().digest(),
        second.first_party().universe().digest()
    );
    assert_eq!(
        first.drain().universe().digest(),
        second.drain().universe().digest()
    );

    let debug = format!("{first:?}");
    for forbidden in [
        std::str::from_utf8(CONSTRAINED_MATCHED_IDENTIFIER_V1).unwrap(),
        std::str::from_utf8(CONSTRAINED_MATCHED_QUESTION_V1).unwrap(),
        "Traceback (most recent call last)",
        "request_id=",
        "annotation_artifact",
        "root_cause",
        "diagnostic_requirement",
    ] {
        assert!(!debug.contains(forbidden), "redaction failure");
    }
    let canary = "CANARY_PRIVATE_LABEL_OR_LOG";
    for error in [
        ConstrainedProducerUniverseBridgeErrorV1::FirstPartyAuditBindingMismatch,
        ConstrainedProducerUniverseBridgeErrorV1::DrainGroupPatternMismatch,
        ConstrainedProducerUniverseBridgeErrorV1::DrainLedgerPartitionMismatch,
    ] {
        assert!(!format!("{error:?}").contains(canary));
        assert!(!error.to_string().contains(canary));
    }
}
