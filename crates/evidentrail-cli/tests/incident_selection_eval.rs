//! Frozen synthetic selection regression, not a diagnosis-accuracy claim.

use evidentrail_cli::{AnalysisError, IncidentReasoner, ModelAssessment, analyze_with_reasoner};
use serde_json::Value;

#[derive(Default)]
struct AbstainingReasoner {
    request: Option<Value>,
}

impl IncidentReasoner for AbstainingReasoner {
    fn assess(&mut self, request: &Value) -> Result<ModelAssessment, AnalysisError> {
        self.request = Some(request.clone());
        Ok(ModelAssessment {
            schema_version: 1,
            hypotheses: Vec::new(),
            needs_more_evidence: true,
        })
    }
}

fn noisy_case(root_position: usize, role: &str) -> String {
    let mut lines = Vec::new();
    for index in 0..3_000 {
        if index == root_position {
            lines.push(format!(
                "service=db level={role} ROOT-CAUSE-CANARY storage exhausted"
            ));
        } else {
            lines.push(format!(
                "2026-09-22T12:{:02}:{:02}Z service=api level=warn retry pending",
                (index / 60) % 60,
                index % 60
            ));
        }
    }
    lines.join("\n")
}

#[test]
fn rare_failure_survives_high_volume_noise_at_three_positions() {
    let mut selected = 0;
    let mut raw_tail = 0;
    for root_position in [0, 1500, 2999] {
        let logs = noisy_case(root_position, "error");
        let mut reasoner = AbstainingReasoner::default();
        let report =
            analyze_with_reasoner(logs.as_bytes(), "Why is API failing?", None, &mut reasoner)
                .unwrap();
        let root_id = format!("L{}", root_position + 1);
        selected += usize::from(report.evidence.iter().any(|event| event.id == root_id));
        let tail = &logs[logs.len().saturating_sub(32 * 1024)..];
        raw_tail += usize::from(tail.contains("ROOT-CAUSE-CANARY"));
        assert_eq!(report.alert_group_count, 2);
        assert_eq!(reasoner.request.unwrap()["omitted_group_count"], 0);
    }
    assert_eq!(selected, 3);
    assert_eq!(raw_tail, 1);
}

#[test]
fn precursor_context_remains_citable_without_becoming_an_alert() {
    let mut logs = String::from(
        "service=db level=info pool_size=0 ROOT-CONTEXT-CANARY\nservice=db level=error connection refused\n",
    );
    for index in 0..3_000 {
        logs.push_str(&format!(
            "service=api level=warn retry pending timestamp={index}\n"
        ));
    }
    let mut reasoner = AbstainingReasoner::default();
    let report = analyze_with_reasoner(
        logs.as_bytes(),
        "Why is the API failing?",
        None,
        &mut reasoner,
    )
    .unwrap();
    assert!(
        report
            .evidence
            .iter()
            .any(|event| event.id == "L1" && event.sample.contains("ROOT-CONTEXT-CANARY"))
    );
    assert!(!logs[logs.len() - 32 * 1024..].contains("ROOT-CONTEXT-CANARY"));
}
