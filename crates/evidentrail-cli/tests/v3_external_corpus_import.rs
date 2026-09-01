use std::sync::atomic::{AtomicU64, Ordering};

use evidentrail_cli::import_external_adjudicated_corpus_v3;
use sha2::{Digest, Sha256};

static NEXT: AtomicU64 = AtomicU64::new(1);

fn hex(bytes: &[u8]) -> String {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(LOWER_HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[test]
fn importer_verifies_external_artifact_and_citation_bytes_but_does_not_overclaim() {
    let root = std::env::temp_dir().join(format!(
        "evidentrail-v3-external-corpus-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&root).unwrap();
    let artifact = b"before\nERROR database pool exhausted request=req-7\nafter\n";
    std::fs::write(root.join("incident.log"), artifact).unwrap();
    let start = 7usize;
    let end = artifact.len() - 6;
    let line = serde_json::json!({
        "schema_version": 3,
        "case_id": "incident-7",
        "organization_id": "independent-org",
        "project_id": "service-a",
        "family_id": "pool-exhaustion",
        "split": "hidden-test",
        "question": "why did req-7 fail?",
        "artifact": {
            "relative_path": "incident.log",
            "sha256": hex(&Sha256::digest(artifact)),
        },
        "adjudication": {
            "annotator_ids": ["reviewer-a", "reviewer-b"],
            "adjudicator_id": "reviewer-c",
            "independently_adjudicated": true,
            "consent_or_license_id": "consent-7"
        },
        "requirements": [{
            "requirement_id": "root-cause",
            "alternatives": [[{
                "start_byte": start,
                "end_byte": end,
                "sha256": hex(&Sha256::digest(&artifact[start..end]))
            }]]
        }]
    });
    let manifest = format!("{}\n", serde_json::to_string(&line).unwrap());
    let report = import_external_adjudicated_corpus_v3(manifest.as_bytes(), &root).unwrap();
    assert_eq!(report.case_count, 1);
    assert_eq!(report.citation_count, 1);
    assert!(!report.certification_eligible);
    assert_eq!(report.qualification_blockers.len(), 2);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn importer_rejects_a_false_citation_digest() {
    let root = std::env::temp_dir().join(format!(
        "evidentrail-v3-external-corpus-bad-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("incident.log"), b"ERROR\n").unwrap();
    let manifest = format!(
        "{{\"schema_version\":3,\"case_id\":\"c\",\"organization_id\":\"o\",\"project_id\":\"p\",\"family_id\":\"f\",\"split\":\"test\",\"question\":\"q\",\"artifact\":{{\"relative_path\":\"incident.log\",\"sha256\":\"{}\"}},\"adjudication\":{{\"annotator_ids\":[\"a\",\"b\"],\"adjudicator_id\":\"c\",\"independently_adjudicated\":true,\"consent_or_license_id\":\"license\"}},\"requirements\":[{{\"requirement_id\":\"r\",\"alternatives\":[[{{\"start_byte\":0,\"end_byte\":5,\"sha256\":\"{}\"}}]]}}]}}\n",
        hex(&Sha256::digest(b"ERROR\n")),
        "00".repeat(32),
    );
    let error = import_external_adjudicated_corpus_v3(manifest.as_bytes(), &root).unwrap_err();
    assert_eq!(error.code(), "EVIDENTRAIL_CORPUS_V3_CITATION_DIGEST");
    std::fs::remove_dir_all(root).unwrap();
}
