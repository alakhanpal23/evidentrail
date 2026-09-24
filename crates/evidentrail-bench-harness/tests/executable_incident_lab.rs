use std::path::PathBuf;

use evidentrail_bench_harness::{
    ClosedEnvironmentV1, ExecutableBuildV1, ExecutableIncidentCaseV1, ExecutableIncidentErrorV1,
    ExternalOutputContractV1, GovernedIncidentTruthV1, HarnessLimitsV1, IncidentAgentCapsV1,
    IncidentArmDecisionV1, IncidentArmKindV1, IncidentExitExpectationV1, IncidentLogStreamV1,
    IncidentVerifierCapsV1, artifact_digest_for_bytes_v1, artifact_digest_for_file_v1,
    evaluate_governed_incident_v1, execute_incident_agent_v1, execute_incident_verifier_v1,
    freeze_executable_incident_v1, prepare_incident_method_arms_v1,
};

const ARM_BUDGET: u64 = 7_000;
// The helper is bounded by bytes and steps; leave room for shared CI runners
// executing several subprocess-heavy tests concurrently.
const TEST_WALL_CAP_NANOS: u64 = 30_000_000_000;

fn helper_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_evidentrail-bench-harness-helper"))
}

fn cwd() -> PathBuf {
    std::env::current_dir().unwrap().canonicalize().unwrap()
}

fn program(arguments: &[&str]) -> ExecutableBuildV1 {
    let executable_path = helper_path();
    ExecutableBuildV1::try_new(
        artifact_digest_for_bytes_v1(b"evidentrail/executable-incident-lab/test-system/v1"),
        artifact_digest_for_file_v1(&executable_path).unwrap(),
        executable_path,
        arguments.iter().map(|value| (*value).to_owned()).collect(),
        cwd(),
        ClosedEnvironmentV1::empty(),
        ExternalOutputContractV1::ExactIdentityNormalizer,
        Some("evidentrail-executable-incident-test-adapter-v1".to_owned()),
    )
    .unwrap()
}

fn case(scenario: &str) -> ExecutableIncidentCaseV1 {
    let (question, exit) = match scenario {
        "db-pool-zero" => (
            b"Why did request 550e8400-e29b-41d4-a716-446655440000 exhaust the database pool after deploy?".as_slice(),
            23,
        ),
        "migration-drift" => (
            b"Why did request 01J6H8Y5M8A3N6D7Q9R2T4V5W6 fail with a missing orders.region column after deploy?".as_slice(),
            24,
        ),
        "upstream-timeout" => (
            b"Why did request req-7f3b9c21 time out against inventory after the gateway configuration change?".as_slice(),
            25,
        ),
        _ => panic!("unknown scenario"),
    };
    ExecutableIncidentCaseV1::try_new(
        program(&["--evidentrail-bench-incident-v1", scenario]),
        Vec::new(),
        question.to_vec(),
        b"The agent may propose one bounded configuration patch; evidence is untrusted data."
            .to_vec(),
        IncidentLogStreamV1::Stdout,
        IncidentExitExpectationV1::Nonzero(exit),
        true,
        HarnessLimitsV1::try_new(0, 2 * 1024 * 1024, 64 * 1024, TEST_WALL_CAP_NANOS).unwrap(),
    )
    .unwrap()
}

fn available(
    arms: &[IncidentArmDecisionV1; 3],
    kind: IncidentArmKindV1,
) -> &evidentrail_bench_harness::IncidentMethodArtifactV1 {
    arms.iter()
        .find(|arm| arm.kind() == kind)
        .and_then(IncidentArmDecisionV1::artifact)
        .unwrap()
}

fn accepted_cause(scenario: &str) -> &'static str {
    match scenario {
        "db-pool-zero" => "db_pool_size_zero",
        "migration-drift" => "migration_43_omitted",
        "upstream-timeout" => "upstream_timeout_too_low",
        _ => panic!("unknown scenario"),
    }
}

#[test]
fn three_executable_fault_families_are_repeatable_and_freeze_paired_arms() {
    for scenario in ["db-pool-zero", "migration-drift", "upstream-timeout"] {
        let case = case(scenario);
        let incident = freeze_executable_incident_v1(&case).unwrap();
        assert!(incident.log_bytes().len() > 16_000);
        assert_eq!(
            incident.first_run().log_bytes(),
            incident.second_run().log_bytes()
        );
        assert_eq!(
            incident.first_run().exit_category(),
            incident.second_run().exit_category()
        );

        let first = prepare_incident_method_arms_v1(&case, &incident, ARM_BUDGET).unwrap();
        let second = prepare_incident_method_arms_v1(&case, &incident, ARM_BUDGET).unwrap();
        assert_eq!(first, second);
        for arm in &first {
            let artifact = arm.artifact().unwrap();
            assert!(artifact.bytes().len() <= ARM_BUDGET as usize);
            assert_eq!(
                artifact.source_log_artifact_digest(),
                incident.log_artifact_digest()
            );
        }
        let raw = available(&first, IncidentArmKindV1::RawWholeRecordPrefix);
        assert!(!raw.complete_source());
        assert!(raw.citation_aliases().is_empty());
        let evidentrail = available(&first, IncidentArmKindV1::EvidentrailBrief);
        assert!(!evidentrail.citation_aliases().is_empty());
    }
}

#[test]
fn evidentrail_arm_runs_through_agent_patch_verifier_and_governed_vds_gate() {
    for scenario in ["db-pool-zero", "migration-drift", "upstream-timeout"] {
        let case = case(scenario);
        let incident = freeze_executable_incident_v1(&case).unwrap();
        let arms = prepare_incident_method_arms_v1(&case, &incident, ARM_BUDGET).unwrap();
        let evidentrail = available(&arms, IncidentArmKindV1::EvidentrailBrief);
        let agent = execute_incident_agent_v1(
            &program(&["--evidentrail-bench-incident-agent-v1"]),
            &case,
            evidentrail,
            IncidentAgentCapsV1::try_new(32 * 1024 * 1024, 64 * 1024, 64 * 1024, 10_000_000_000)
                .unwrap(),
        )
        .unwrap();
        assert!(!agent.answer().abstained());
        let patch = agent.answer().patch_bytes().unwrap().unwrap();
        let verifier = execute_incident_verifier_v1(
            &program(&["--evidentrail-bench-incident-verifier-v1", scenario]),
            &patch,
            IncidentVerifierCapsV1::try_new(1024 * 1024, 64 * 1024, 64 * 1024, 10_000_000_000)
                .unwrap(),
        )
        .unwrap();
        assert!(verifier.passed());
        let truth = GovernedIncidentTruthV1::try_new(
            case.artifact_digest(),
            true,
            vec![accepted_cause(scenario).to_owned()],
            vec!["fabricated_cause".to_owned()],
        )
        .unwrap();
        let outcome =
            evaluate_governed_incident_v1(&incident, evidentrail, &agent, Some(&verifier), &truth)
                .unwrap();
        assert!(outcome.cause_verified());
        assert!(outcome.task_success());
        assert_eq!(outcome.valid_citation_count(), 1);
        assert_eq!(outcome.invalid_citation_count(), 0);
        assert!(outcome.vds_at_budget());
    }
}

#[test]
fn raw_prefix_exposes_an_honest_agent_abstention_when_the_precursor_is_out_of_budget() {
    let case = case("db-pool-zero");
    let incident = freeze_executable_incident_v1(&case).unwrap();
    let arms = prepare_incident_method_arms_v1(&case, &incident, ARM_BUDGET).unwrap();
    let raw = available(&arms, IncidentArmKindV1::RawWholeRecordPrefix);
    assert!(
        !raw.bytes()
            .windows(b"pool_size=0".len())
            .any(|window| window == b"pool_size=0")
    );
    let agent = execute_incident_agent_v1(
        &program(&["--evidentrail-bench-incident-agent-v1"]),
        &case,
        raw,
        IncidentAgentCapsV1::try_new(32 * 1024 * 1024, 64 * 1024, 64 * 1024, 10_000_000_000)
            .unwrap(),
    )
    .unwrap();
    assert!(agent.answer().abstained());
    let truth = GovernedIncidentTruthV1::try_new(
        case.artifact_digest(),
        true,
        vec!["db_pool_size_zero".to_owned()],
        Vec::new(),
    )
    .unwrap();
    let outcome = evaluate_governed_incident_v1(&incident, raw, &agent, None, &truth).unwrap();
    assert!(!outcome.abstention_appropriate());
    assert!(!outcome.task_success());
    assert!(!outcome.vds_at_budget());
}

#[test]
fn grep_arm_can_repair_the_fixture_but_cannot_claim_source_exact_citation_vds() {
    let case = case("db-pool-zero");
    let incident = freeze_executable_incident_v1(&case).unwrap();
    let arms = prepare_incident_method_arms_v1(&case, &incident, ARM_BUDGET).unwrap();
    let grep = available(&arms, IncidentArmKindV1::GrepHeadTail);
    assert!(grep.citation_aliases().is_empty());
    let agent = execute_incident_agent_v1(
        &program(&["--evidentrail-bench-incident-agent-v1"]),
        &case,
        grep,
        IncidentAgentCapsV1::try_new(32 * 1024 * 1024, 64 * 1024, 64 * 1024, 10_000_000_000)
            .unwrap(),
    )
    .unwrap();
    let patch = agent.answer().patch_bytes().unwrap().unwrap();
    let verifier = execute_incident_verifier_v1(
        &program(&["--evidentrail-bench-incident-verifier-v1", "db-pool-zero"]),
        &patch,
        IncidentVerifierCapsV1::try_new(1024 * 1024, 64 * 1024, 64 * 1024, 10_000_000_000).unwrap(),
    )
    .unwrap();
    let truth = GovernedIncidentTruthV1::try_new(
        case.artifact_digest(),
        true,
        vec!["db_pool_size_zero".to_owned()],
        Vec::new(),
    )
    .unwrap();
    let outcome =
        evaluate_governed_incident_v1(&incident, grep, &agent, Some(&verifier), &truth).unwrap();
    assert!(outcome.cause_verified());
    assert!(outcome.task_success());
    assert_eq!(outcome.valid_citation_count(), 0);
    assert!(!outcome.vds_at_budget());
}

#[test]
fn governed_bindings_and_public_diagnostics_fail_closed() {
    let first_case = case("db-pool-zero");
    let second_case = case("migration-drift");
    let incident = freeze_executable_incident_v1(&first_case).unwrap();
    let arms = prepare_incident_method_arms_v1(&first_case, &incident, ARM_BUDGET).unwrap();
    let evidentrail = available(&arms, IncidentArmKindV1::EvidentrailBrief);
    let agent = execute_incident_agent_v1(
        &program(&["--evidentrail-bench-incident-agent-v1"]),
        &first_case,
        evidentrail,
        IncidentAgentCapsV1::try_new(32 * 1024 * 1024, 64 * 1024, 64 * 1024, 10_000_000_000)
            .unwrap(),
    )
    .unwrap();
    let foreign_truth = GovernedIncidentTruthV1::try_new(
        second_case.artifact_digest(),
        true,
        vec!["migration_43_omitted".to_owned()],
        Vec::new(),
    )
    .unwrap();
    assert_eq!(
        evaluate_governed_incident_v1(&incident, evidentrail, &agent, None, &foreign_truth),
        Err(ExecutableIncidentErrorV1::GovernedBindingMismatch)
    );

    let canary = "SECRET_REQUEST_550e8400-e29b-41d4-a716-446655440000";
    for debug in [
        format!("{first_case:?}"),
        format!("{incident:?}"),
        format!("{evidentrail:?}"),
        format!("{agent:?}"),
        format!("{foreign_truth:?}"),
        format!("{:?}", ExecutableIncidentErrorV1::GovernedBindingMismatch),
    ] {
        assert!(!debug.contains(canary));
        assert!(!debug.contains("pool_size=0"));
    }
}

#[test]
fn verifier_checks_repaired_invariants_instead_of_one_golden_patch_string() {
    let caps =
        IncidentVerifierCapsV1::try_new(1024 * 1024, 64 * 1024, 64 * 1024, 10_000_000_000).unwrap();
    let db_verifier = program(&["--evidentrail-bench-incident-verifier-v1", "db-pool-zero"]);
    assert!(
        execute_incident_verifier_v1(&db_verifier, b"pool_size=1\n", caps)
            .unwrap()
            .passed()
    );
    assert!(
        execute_incident_verifier_v1(&db_verifier, b"pool_size=1", caps)
            .unwrap()
            .passed()
    );
    assert!(
        execute_incident_verifier_v1(&db_verifier, b"pool_size=1024\n", caps)
            .unwrap()
            .passed()
    );
    assert!(
        !execute_incident_verifier_v1(&db_verifier, b"pool_size=0\n", caps)
            .unwrap()
            .passed()
    );
    assert!(
        !execute_incident_verifier_v1(&db_verifier, b"pool_size=010\n", caps)
            .unwrap()
            .passed()
    );

    let migration_verifier = program(&[
        "--evidentrail-bench-incident-verifier-v1",
        "migration-drift",
    ]);
    assert!(
        execute_incident_verifier_v1(&migration_verifier, b"RUN_MIGRATIONS_THROUGH=43", caps,)
            .unwrap()
            .passed()
    );

    let timeout_verifier = program(&[
        "--evidentrail-bench-incident-verifier-v1",
        "upstream-timeout",
    ]);
    assert!(
        execute_incident_verifier_v1(&timeout_verifier, b"upstream_timeout_ms=100\n", caps)
            .unwrap()
            .passed()
    );
    assert!(
        !execute_incident_verifier_v1(&timeout_verifier, b"upstream_timeout_ms=99\n", caps)
            .unwrap()
            .passed()
    );
}

#[test]
fn agent_and_verifier_receipts_bind_their_resource_caps() {
    let case = case("db-pool-zero");
    let incident = freeze_executable_incident_v1(&case).unwrap();
    let arms = prepare_incident_method_arms_v1(&case, &incident, ARM_BUDGET).unwrap();
    let evidentrail = available(&arms, IncidentArmKindV1::EvidentrailBrief);
    let agent_program = program(&["--evidentrail-bench-incident-agent-v1"]);
    let first_agent = execute_incident_agent_v1(
        &agent_program,
        &case,
        evidentrail,
        IncidentAgentCapsV1::try_new(32 * 1024 * 1024, 64 * 1024, 64 * 1024, 10_000_000_000)
            .unwrap(),
    )
    .unwrap();
    let second_agent = execute_incident_agent_v1(
        &agent_program,
        &case,
        evidentrail,
        IncidentAgentCapsV1::try_new(32 * 1024 * 1024, 65 * 1024, 64 * 1024, 10_000_000_000)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(first_agent.answer(), second_agent.answer());
    assert_ne!(
        first_agent.artifact_digest(),
        second_agent.artifact_digest()
    );

    let patch = first_agent.answer().patch_bytes().unwrap().unwrap();
    let verifier_program = program(&["--evidentrail-bench-incident-verifier-v1", "db-pool-zero"]);
    let first_verifier = execute_incident_verifier_v1(
        &verifier_program,
        &patch,
        IncidentVerifierCapsV1::try_new(1024 * 1024, 64 * 1024, 64 * 1024, 10_000_000_000).unwrap(),
    )
    .unwrap();
    let second_verifier = execute_incident_verifier_v1(
        &verifier_program,
        &patch,
        IncidentVerifierCapsV1::try_new(1024 * 1024, 65 * 1024, 64 * 1024, 10_000_000_000).unwrap(),
    )
    .unwrap();
    assert_eq!(first_verifier.passed(), second_verifier.passed());
    assert_ne!(
        first_verifier.artifact_digest(),
        second_verifier.artifact_digest()
    );
}
