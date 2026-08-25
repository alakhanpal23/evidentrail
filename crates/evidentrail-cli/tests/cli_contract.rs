use std::io::{BufReader, Read as _, Write as _};
use std::process::{Command, Stdio};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_evidentrail"))
}

fn exchange_json(
    input: &mut impl std::io::Write,
    output: &mut impl std::io::BufRead,
    request: &Value,
) -> Value {
    serde_json::to_writer(&mut *input, request).unwrap();
    input.write_all(b"\n").unwrap();
    input.flush().unwrap();
    let mut line = String::new();
    assert_ne!(output.read_line(&mut line).unwrap(), 0);
    serde_json::from_str(&line).unwrap()
}

fn modern_meta() -> Value {
    json!({
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {"name": "black-box-test", "version": "1"},
        "io.modelcontextprotocol/protocolVersion": "2026-07-28"
    })
}

#[test]
fn help_states_the_narrow_explicit_input_contract() {
    let output = command().arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("reads only explicit standard input"));
    assert!(stdout.contains("not discover files"));
    assert!(stdout.contains("model-token count"));
    assert!(output.stderr.is_empty());
}

#[test]
fn piped_input_produces_only_the_canonical_brief_on_stdout() {
    let mut child = command()
        .args(["brief", "--question", "why did REQ-7 fail?"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"boot\nrequest_id=REQ-7 database timeout\ndone\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("STATUS\n"));
    assert_eq!(stdout.matches("\nEVIDENCE\n").count(), 1);
    assert_eq!(stdout.matches("\nCOVERAGE\n").count(), 1);
}

#[test]
fn tiny_budget_exits_three_without_publishing_a_fake_brief() {
    let mut child = command()
        .args([
            "brief",
            "--question",
            "why did REQ-7 fail?",
            "--token-budget",
            "1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"request_id=REQ-7 database timeout\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.starts_with("EVIDENTRAIL_CLI_NEEDS_MORE reason="));
    assert!(stderr.contains("retained=false"));
    assert!(!stderr.contains("database timeout"));
}

#[test]
fn mcp_process_discovers_compiles_and_expands_exact_supplied_bytes() {
    let mut child = command()
        .arg("serve-mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());

    let discover = exchange_json(
        &mut input,
        &mut output,
        &json!({
            "id": 1,
            "jsonrpc": "2.0",
            "method": "server/discover",
            "params": {"_meta": modern_meta()}
        }),
    );
    assert_eq!(discover["result"]["resultType"], "complete");
    assert_eq!(discover["result"]["supportedVersions"][0], "2026-07-28");

    let listed = exchange_json(
        &mut input,
        &mut output,
        &json!({
            "id": 2,
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {"_meta": modern_meta()}
        }),
    );
    assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 2);

    let logs = b"request_id=REQ-10 timeout\0\xff\n";
    let compiled = exchange_json(
        &mut input,
        &mut output,
        &json!({
            "id": 3,
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "_meta": modern_meta(),
                "arguments": {
                    "logs_base64": STANDARD.encode(logs),
                    "question": "why did REQ-10 fail?",
                    "token_budget": 20_000
                },
                "name": "evidentrail_logs"
            }
        }),
    );
    assert_eq!(compiled["result"]["isError"], false);
    let result_id = compiled["result"]["structuredContent"]["result_id"]
        .as_str()
        .unwrap();

    let expanded = exchange_json(
        &mut input,
        &mut output,
        &json!({
            "id": 4,
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "_meta": modern_meta(),
                "arguments": {
                    "alias": "E1",
                    "max_bytes": 1024,
                    "max_events": 1,
                    "relation": "exact",
                    "result_id": result_id
                },
                "name": "evidentrail_expand"
            }
        }),
    );
    assert_eq!(expanded["result"]["isError"], false);
    let encoded = expanded["result"]["structuredContent"]["events"][0]["bytes_base64"]
        .as_str()
        .unwrap();
    assert_eq!(STANDARD.decode(encoded).unwrap(), logs);

    drop(input);
    drop(output);
    let status = child.wait().unwrap();
    assert!(status.success());
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(stderr.is_empty());
}

#[test]
fn mcp_process_supports_the_legacy_initialize_fallback() {
    let mut child = command()
        .arg("serve-mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());

    let initialized = exchange_json(
        &mut input,
        &mut output,
        &json!({
            "id": 1,
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "capabilities": {},
                "clientInfo": {"name": "legacy-black-box-test", "version": "1"},
                "protocolVersion": "2025-11-25"
            }
        }),
    );
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");

    serde_json::to_writer(
        &mut input,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }),
    )
    .unwrap();
    input.write_all(b"\n").unwrap();
    input.flush().unwrap();

    let listed = exchange_json(
        &mut input,
        &mut output,
        &json!({
            "id": 2,
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 2);
    assert!(listed["result"].get("resultType").is_none());

    drop(input);
    drop(output);
    let status = child.wait().unwrap();
    assert!(status.success());
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(stderr.is_empty());
}
