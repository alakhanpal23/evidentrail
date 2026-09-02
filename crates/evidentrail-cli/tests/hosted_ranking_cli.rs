use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn disabled_hosted_cli_emits_only_contentless_diagnostics_and_exact_fallback() {
    let mut input = b"ERROR hosted-cli-canary alpha ".to_vec();
    input.resize(7_000, b'a');
    input.push(b'\n');
    input.extend_from_slice(b"ERROR hosted-cli-canary beta ");
    input.resize(14_001, b'b');

    let mut child = Command::new(env!("CARGO_BIN_EXE_evidentrail"))
        .args([
            "brief",
            "--question",
            "why hosted-cli-question-canary?",
            "--token-budget",
            "10000",
            "--llm-rank",
        ])
        .env("EVIDENTRAIL_HOSTED_RANKING_DISABLED", "1")
        .env_remove("OPENAI_API_KEY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(!output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    let encoded = stderr
        .strip_prefix("EVIDENTRAIL_HOSTED_RANKING ")
        .unwrap()
        .trim_end();
    let diagnostics: serde_json::Value = serde_json::from_str(encoded).unwrap();
    assert_eq!(diagnostics["application_code"], "apply");
    assert_eq!(diagnostics["validation_code"], "not_received");
    assert_eq!(diagnostics["fallback_reason"], "disabled");
    assert!(!stderr.contains("hosted-cli-canary"));
    assert!(!stderr.contains("hosted-cli-question-canary"));
}

#[test]
fn contention_gated_cli_is_explicit_and_reports_its_policy_contentlessly() {
    let mut input = b"ERROR contention-cli-canary alpha ".to_vec();
    input.resize(7_000, b'a');
    input.push(b'\n');
    input.extend_from_slice(b"ERROR contention-cli-canary beta ");
    input.resize(14_001, b'b');

    let mut child = Command::new(env!("CARGO_BIN_EXE_evidentrail"))
        .args([
            "brief",
            "--question",
            "why contention-cli-question-canary?",
            "--token-budget",
            "10000",
            "--llm-rank-if-contended",
        ])
        .env("EVIDENTRAIL_HOSTED_RANKING_DISABLED", "1")
        .env_remove("OPENAI_API_KEY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    let encoded = stderr
        .strip_prefix("EVIDENTRAIL_HOSTED_RANKING ")
        .unwrap()
        .trim_end();
    let diagnostics: serde_json::Value = serde_json::from_str(encoded).unwrap();
    assert_eq!(diagnostics["application_code"], "apply_if_contended");
    assert_eq!(diagnostics["fallback_reason"], "disabled");
    assert!(!stderr.contains("contention-cli-canary"));
    assert!(!stderr.contains("contention-cli-question-canary"));
}
