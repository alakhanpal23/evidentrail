use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn production_shadow_emits_only_contentless_metrics() {
    let root = format!(
        "{}/../../fixtures/production-shadow-example",
        env!("CARGO_MANIFEST_DIR")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_evidentrail-production-shadow"))
        .args([&root, "manifest.json"])
        .env_remove("OPENAI_API_KEY")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 2);
    assert_eq!(report["mode"], "deterministic_memory_only_no_egress_v1");
    assert_eq!(report["attempt_count"], 3);
    assert_eq!(report["hosted_egress_attempted"], false);
    assert_eq!(report["hosted_provider_call_count"], 0);
    assert_eq!(report["hosted_execution_gate_passed"], true);
    assert_eq!(report["content_fields_emitted"], false);
    assert_eq!(report["required_evidence_recall_micros"], 1_000_000);
    assert_eq!(report["all_integrity_checks_passed"], true);
    assert_eq!(report["pilot_passed"], true);

    let serialized = String::from_utf8(output.stdout).unwrap();
    for forbidden in [
        "req-synthetic-7",
        "pool_exhausted",
        "synthetic-incident.log",
        "question.txt",
        "required-timeout.txt",
        "Why did",
        "ERROR service",
    ] {
        assert!(!serialized.contains(forbidden));
    }
}

#[test]
fn hosted_shadow_routes_through_ranker_and_fails_closed_without_credential() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "evidentrail-hosted-shadow-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir(&root).unwrap();
    let mut log = String::new();
    for index in 0..300 {
        log.push_str(&format!("INFO synthetic event {index}\n"));
    }
    log.push_str("ERROR synthetic timeout\n");
    fs::write(root.join("incident.log"), log).unwrap();
    fs::write(root.join("question.txt"), "Why did the timeout occur?\n").unwrap();
    fs::write(root.join("required.txt"), "ERROR synthetic timeout\n").unwrap();
    fs::write(
        root.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": 2,
            "data_classification": "synthetic_c0",
            "local_processing_only": false,
            "ranking_mode": "hosted",
            "hosted_egress": true,
            "hosted_egress_authorization": "operator_approved_openai_responses_v1",
            "content_telemetry": false,
            "retention": "memory_only",
            "repetitions": 3,
            "cases": [{
                "log_file": "incident.log",
                "question_file": "question.txt",
                "required_evidence_files": ["required.txt"],
                "token_budget": 4000,
                "protected_slice": false,
                "hosted_egress_approved": true
            }]
        }))
        .unwrap(),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_evidentrail-production-shadow"))
        .args([root.as_os_str(), "manifest.json".as_ref()])
        .env_remove("OPENAI_API_KEY")
        .env_remove("EVIDENTRAIL_HOSTED_RANKING_DISABLED")
        .output()
        .unwrap();
    fs::remove_dir_all(&root).unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ranking_mode"], "hosted");
    assert_eq!(report["hosted_ranking_diagnostic_count"], 3);
    assert_eq!(report["hosted_provider_call_count"], 0);
    assert_eq!(report["hosted_accepted_response_count"], 0);
    assert_eq!(report["hosted_fallback_count"], 3);
    assert_eq!(report["hosted_egress_attempted"], false);
    assert_eq!(report["hosted_execution_gate_passed"], false);
    assert_eq!(report["pilot_passed"], false);
    assert!(
        report["hosted_ranking_diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .all(|diagnostic| diagnostic["fallback_reason"] == "missing_credential")
    );
}
