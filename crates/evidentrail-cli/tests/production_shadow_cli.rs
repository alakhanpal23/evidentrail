use std::process::Command;

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
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["mode"], "deterministic_memory_only_no_egress_v1");
    assert_eq!(report["attempt_count"], 3);
    assert_eq!(report["hosted_egress_attempted"], false);
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
