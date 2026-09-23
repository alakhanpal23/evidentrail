use std::io::{BufReader, Read as _, Write as _};
use std::process::{Command, Stdio};

#[cfg(target_os = "macos")]
use std::fs;
#[cfg(target_os = "macos")]
use std::os::unix::fs::{PermissionsExt as _, symlink};
#[cfg(target_os = "macos")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::sync::atomic::{AtomicU64, Ordering};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_evidentrail"))
}

#[cfg(target_os = "macos")]
static DOCTOR_FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "macos")]
struct DoctorFixture {
    root: PathBuf,
    home: PathBuf,
}

#[cfg(target_os = "macos")]
impl DoctorFixture {
    fn new() -> Self {
        let sequence = DOCTOR_FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "evidentrail-cli-doctor-contract-{}-{sequence}",
                std::process::id()
            ));
        fs::create_dir(&root).unwrap();
        let home = root.join("home");
        fs::create_dir(&home).unwrap();
        Self { root, home }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn doctor_command(&self, path: &Path) -> Command {
        let mut command = command();
        command
            .args(["doctor", "--file"])
            .arg(path)
            .env("HOME", &self.home);
        for variable in ["XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"] {
            command.env_remove(variable);
        }
        command
    }

    fn doctor(&self, path: &Path) -> std::process::Output {
        self.doctor_command(path).output().unwrap()
    }
}

#[cfg(target_os = "macos")]
impl Drop for DoctorFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(target_os = "macos")]
fn assert_doctor_failure(
    fixture: &DoctorFixture,
    path: &Path,
    expected_code: &str,
    canaries: &[&str],
) {
    let output = fixture.doctor(path);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(stderr, format!("{expected_code}\n"));
    assert!(!stderr.contains(path.to_str().unwrap()));
    for canary in canaries {
        assert!(!stderr.contains(canary));
    }
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
fn selection_preview_runs_without_a_hosted_credential() {
    let mut child = command()
        .args([
            "analyze",
            "--question",
            "Why did db fail?",
            "--selection-only",
        ])
        .env_remove("OPENAI_API_KEY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            b"service=db level=info pool_size=0\nservice=db level=error connection refused\n",
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["focus_services"], json!(["db"]));
    assert_eq!(report["hypotheses"], json!([]));
    assert_eq!(report["evidence"][0]["id"], "L1");
}

#[test]
fn selection_preview_reads_explicit_metric_file() {
    let path = std::env::temp_dir().join(format!(
        "evidentrail-metric-contract-{}-{}.ndjson",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut metrics = String::new();
    for index in 0..10 {
        metrics.push_str(&format!(
            "{{\"timestamp\":{},\"service\":\"db\",\"metric\":\"cpu\",\"value\":{}}}\n",
            if index < 5 { 700 + index } else { 995 + index },
            if index < 5 { 1 } else { 100 }
        ));
    }
    std::fs::write(&path, metrics).unwrap();
    let mut child = command()
        .args([
            "analyze",
            "--question",
            "Why did db fail?",
            "--selection-only",
            "--metrics",
        ])
        .arg(&path)
        .args(["--incident-time", "1000"])
        .env_remove("OPENAI_API_KEY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"service=db level=info healthy\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let _ = std::fs::remove_file(&path);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["metric_signal_count"], 1);
    assert_eq!(report["metric_signals"][0]["baseline_median"], 1.0);
    assert_eq!(report["metric_signals"][0]["incident_median"], 100.0);
    assert!(
        report["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["id"] == "M8")
    );
}

#[test]
fn durable_mcp_selection_fails_closed_without_platform_authority() {
    let output = command()
        .args(["serve-mcp", "--retention", "durable"])
        .env("HOME", "/tmp/evidentrail-durable-authority-test-home")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let expected = if cfg!(target_os = "macos") {
        "EVIDENTRAIL_CLI_DURABLE_AUTHORITY_UNAVAILABLE\n"
    } else {
        "EVIDENTRAIL_CLI_DURABLE_UNSUPPORTED_PLATFORM\n"
    };
    assert_eq!(String::from_utf8(output.stderr).unwrap(), expected);
}

#[cfg(target_os = "macos")]
#[test]
fn doctor_observes_an_unreadable_file_without_leaking_or_granting_authority() {
    let fixture = DoctorFixture::new();
    let candidate = fixture.path("PATH_CANARY_METADATA_ONLY.log");
    fs::write(&candidate, b"CONTENT_CANARY_MUST_NEVER_BE_READ\0\xff\n").unwrap();
    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o000)).unwrap();

    let output = fixture.doctor(&candidate);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let fields = stdout.trim_end().split(' ').collect::<Vec<_>>();
    assert_eq!(fields.len(), 10);
    assert_eq!(fields[0], "EVIDENTRAIL_CLI_DOCTOR_FILE_METADATA_OK");
    assert_eq!(
        fields[1],
        "capability=EVIDENTRAIL_LOCAL_DISCOVERY_EXPLICIT_SINGLE_REGULAR_FILE_METADATA_ONLY_V1"
    );
    assert_eq!(
        fields[2],
        "content=EVIDENTRAIL_LOCAL_DISCOVERY_CONTENT_NOT_READ"
    );
    assert_eq!(
        fields[3],
        "authorization=EVIDENTRAIL_LOCAL_DISCOVERY_AUTHORIZATION_NOT_GRANTED"
    );
    assert_eq!(
        fields[4],
        "certification=EVIDENTRAIL_LOCAL_DISCOVERY_CERTIFICATION_NOT_GRANTED"
    );
    assert_eq!(
        fields[5],
        "matrix_status=EVIDENTRAIL_LOCAL_HOST_MATRIX_ALL_CELLS_PASSED"
    );
    assert_eq!(fields[6], "matrix_version=1");
    assert_eq!(fields[7], "matrix_cells=13");
    let receipt = fields[8]
        .strip_prefix("matrix_receipt=local_file_host_matrix_receipt_sha256_")
        .unwrap();
    assert_eq!(receipt.len(), 64);
    assert!(
        receipt
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert_eq!(
        fields[9],
        "preflight_admission=EVIDENTRAIL_LOCAL_HOST_MATRIX_EVIDENCE_ONLY_PREFLIGHT_NOT_ADMITTED"
    );
    let repeated = fixture.doctor(&candidate);
    assert!(repeated.status.success());
    assert_eq!(repeated.stdout, output.stdout);
    assert!(repeated.stderr.is_empty());
    assert!(!stdout.contains(candidate.to_str().unwrap()));
    assert!(!stdout.contains("PATH_CANARY_METADATA_ONLY"));
    assert!(!stdout.contains("CONTENT_CANARY_MUST_NEVER_BE_READ"));
}

#[cfg(target_os = "macos")]
#[test]
fn doctor_matrix_failure_precedes_target_discovery_and_remains_contentless() {
    let fixture = DoctorFixture::new();
    let candidate = fixture.path("MATRIX_FAILURE_PATH_CANARY.log");
    fs::write(&candidate, b"MATRIX_FAILURE_CONTENT_CANARY").unwrap();
    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o000)).unwrap();
    let unavailable_temp = fixture.path("MATRIX_TEMP_PATH_CANARY_DOES_NOT_EXIST");

    let output = fixture
        .doctor_command(&candidate)
        .env("TMPDIR", &unavailable_temp)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        stderr,
        "EVIDENTRAIL_LOCAL_HOST_MATRIX_FIXTURE_UNAVAILABLE\n"
    );
    for canary in [
        "MATRIX_FAILURE_PATH_CANARY",
        "MATRIX_FAILURE_CONTENT_CANARY",
        "MATRIX_TEMP_PATH_CANARY",
    ] {
        assert!(!stderr.contains(canary));
    }
    assert!(!stderr.contains(candidate.to_str().unwrap()));
    assert!(!stderr.contains(unavailable_temp.to_str().unwrap()));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn doctor_unsupported_platform_fails_before_target_discovery() {
    let raw_path = "/PATH_CANARY_MUST_NOT_BE_ACCESSED";
    let output = command()
        .args(["doctor", "--file", raw_path])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "EVIDENTRAIL_LOCAL_HOST_MATRIX_UNSUPPORTED_OS\n"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn doctor_rejects_symlinks_nonregular_and_internal_paths_without_leaking() {
    let fixture = DoctorFixture::new();
    let target = fixture.path("TARGET_PATH_CANARY.log");
    fs::write(&target, b"TARGET_CONTENT_CANARY").unwrap();

    let final_alias = fixture.path("FINAL_SYMLINK_CANARY.log");
    symlink(&target, &final_alias).unwrap();
    assert_doctor_failure(
        &fixture,
        &final_alias,
        "EVIDENTRAIL_LOCAL_DISCOVERY_SYMLINK_REJECTED",
        &["TARGET_CONTENT_CANARY", "FINAL_SYMLINK_CANARY"],
    );

    let real_directory = fixture.path("REAL_DIRECTORY_CANARY");
    fs::create_dir(&real_directory).unwrap();
    fs::write(real_directory.join("nested.log"), b"NESTED_CONTENT_CANARY").unwrap();
    let ancestor_alias = fixture.path("ANCESTOR_SYMLINK_CANARY");
    symlink(&real_directory, &ancestor_alias).unwrap();
    assert_doctor_failure(
        &fixture,
        &ancestor_alias.join("nested.log"),
        "EVIDENTRAIL_LOCAL_DISCOVERY_SYMLINK_REJECTED",
        &["NESTED_CONTENT_CANARY", "ANCESTOR_SYMLINK_CANARY"],
    );
    assert_doctor_failure(
        &fixture,
        &real_directory,
        "EVIDENTRAIL_LOCAL_DISCOVERY_FINAL_NOT_REGULAR",
        &["NESTED_CONTENT_CANARY", "REAL_DIRECTORY_CANARY"],
    );

    let internal_root = fixture.home.join(".evidentrail");
    fs::create_dir(&internal_root).unwrap();
    let internal_file = internal_root.join("INTERNAL_PATH_CANARY.snapshot");
    fs::write(&internal_file, b"INTERNAL_CONTENT_CANARY").unwrap();
    assert_doctor_failure(
        &fixture,
        &internal_file,
        "EVIDENTRAIL_LOCAL_DISCOVERY_INTERNAL_PATH_RESERVED",
        &["INTERNAL_PATH_CANARY", "INTERNAL_CONTENT_CANARY"],
    );

    let default_snapshot_root = fixture
        .home
        .join("Library")
        .join("Caches")
        .join("ai.evidentrail")
        .join("snapshots-v1");
    fs::create_dir_all(&default_snapshot_root).unwrap();
    let default_snapshot = default_snapshot_root.join("DEFAULT_STORE_CANARY.snapshot");
    fs::write(&default_snapshot, b"DEFAULT_STORE_CONTENT_CANARY").unwrap();
    assert_doctor_failure(
        &fixture,
        &default_snapshot,
        "EVIDENTRAIL_LOCAL_DISCOVERY_INTERNAL_PATH_RESERVED",
        &["DEFAULT_STORE_CANARY", "DEFAULT_STORE_CONTENT_CANARY"],
    );

    let external_internal_root = fixture.path("RESOLVED_INTERNAL_ALIAS_CANARY");
    fs::create_dir(&external_internal_root).unwrap();
    let external_internal_file = external_internal_root.join("aliased.snapshot");
    fs::write(&external_internal_file, b"ALIASED_INTERNAL_CONTENT_CANARY").unwrap();
    let config_root = fixture.home.join(".config");
    fs::create_dir(&config_root).unwrap();
    symlink(&external_internal_root, config_root.join("evidentrail")).unwrap();
    assert_doctor_failure(
        &fixture,
        &external_internal_file,
        "EVIDENTRAIL_LOCAL_DISCOVERY_INTERNAL_PATH_RESERVED",
        &[
            "RESOLVED_INTERNAL_ALIAS_CANARY",
            "ALIASED_INTERNAL_CONTENT_CANARY",
        ],
    );
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
    assert_eq!(
        listed["result"]["tools"].as_array().unwrap().len(),
        if cfg!(target_os = "macos") { 4 } else { 2 }
    );

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
    assert_eq!(
        listed["result"]["tools"].as_array().unwrap().len(),
        if cfg!(target_os = "macos") { 4 } else { 2 }
    );
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
