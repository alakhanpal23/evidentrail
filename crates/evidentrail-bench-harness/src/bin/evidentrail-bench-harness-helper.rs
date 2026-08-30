use std::env;
use std::io::{self, Read, Write};
use std::thread;
use std::time::Duration;

fn main() {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let Some(mode) = arguments.first().map(String::as_str) else {
        std::process::exit(64);
    };
    match mode {
        "echo" => echo_stdin(),
        "echo-with-stderr" => {
            echo_stdin();
            io::stderr().write_all(b"synthetic-stderr\0\xff").unwrap();
        }
        "probe-env" => {
            let name = arguments.get(1).map_or("", String::as_str);
            match env::var_os(name) {
                Some(value) => io::stdout()
                    .write_all(value.to_string_lossy().as_bytes())
                    .unwrap(),
                None => io::stdout().write_all(b"<missing>").unwrap(),
            }
        }
        "probe-cwd" => io::stdout()
            .write_all(env::current_dir().unwrap().to_string_lossy().as_bytes())
            .unwrap(),
        "probe-arg" => io::stdout()
            .write_all(arguments.get(1).map_or(b"", String::as_bytes))
            .unwrap(),
        "emit-stdout" => emit(&mut io::stdout(), count_argument(&arguments)),
        "emit-stderr" => emit(&mut io::stderr(), count_argument(&arguments)),
        "sleep-ms" => thread::sleep(Duration::from_millis(count_argument(&arguments))),
        "exit" => {
            let code = i32::try_from(count_argument(&arguments)).unwrap_or(70);
            std::process::exit(code);
        }
        "--evidentrail-bench-first-party-constrained-v1" => {
            if !emit_first_party_constrained_product() {
                std::process::exit(65);
            }
        }
        "--evidentrail-bench-reader-fixture-v1" => {
            let reader_mode = arguments.get(1).map_or("", String::as_str);
            if !emit_reader_fixture_v1(reader_mode) {
                std::process::exit(65);
            }
        }
        "--evidentrail-bench-incident-v1" => {
            let incident = arguments.get(1).map_or("", String::as_str);
            emit_executable_incident_v1(incident);
        }
        "--evidentrail-bench-incident-agent-v1" => {
            if !emit_incident_agent_answer_v1() {
                std::process::exit(65);
            }
        }
        "--evidentrail-bench-incident-verifier-v1" => {
            let incident = arguments.get(1).map_or("", String::as_str);
            verify_incident_patch_v1(incident);
        }
        "--grouper" => emit_legacy_drain_fixture(),
        _ => std::process::exit(64),
    }
}

fn emit_executable_incident_v1(incident: &str) -> ! {
    let (cause_record, request_id, failure_records, exit_code) = match incident {
        "db-pool-zero" => (
            "2026-08-29T10:00:02Z CONFIG api pool_size=0 source=deploy-184\n",
            "550e8400-e29b-41d4-a716-446655440000",
            [
                "2026-08-29T10:00:08Z ERROR api request=550e8400-e29b-41d4-a716-446655440000 database pool exhausted\n",
                "thread 'request-worker' panicked at src/db.rs:84: connection pool has zero capacity\n",
                "stack backtrace:\n",
                "   0: api::db::acquire\n",
                "   1: api::orders::create\n",
            ],
            23,
        ),
        "migration-drift" => (
            "2026-08-29T10:00:02Z DEPLOY worker schema_expected=43 schema_actual=42\n",
            "01J6H8Y5M8A3N6D7Q9R2T4V5W6",
            [
                "2026-08-29T10:00:08Z ERROR worker request=01J6H8Y5M8A3N6D7Q9R2T4V5W6 column orders.region does not exist\n",
                "DatabaseError: undefined column orders.region\n",
                "    at migrateOrder (worker.js:119:17)\n",
                "    at processBatch (worker.js:74:9)\n",
                "Caused by: deployment omitted migration 43\n",
            ],
            24,
        ),
        "upstream-timeout" => (
            "2026-08-29T10:00:02Z CONFIG gateway upstream_timeout_ms=5 retry_limit=9\n",
            "req-7f3b9c21",
            [
                "2026-08-29T10:00:08Z ERROR gateway request=req-7f3b9c21 upstream inventory timed out after 5ms\n",
                "Traceback (most recent call last):\n",
                "  File \"gateway.py\", line 88, in fetch_inventory\n",
                "    raise UpstreamTimeout(\"inventory\")\n",
                "UpstreamTimeout: inventory\n",
            ],
            25,
        ),
        _ => std::process::exit(64),
    };

    let mut stdout = io::stdout().lock();
    writeln!(
        stdout,
        "2026-08-29T10:00:00Z INFO incident-lab scenario={incident} request={request_id}"
    )
    .unwrap();
    for ordinal in 0..96 {
        writeln!(
            stdout,
            "2026-08-29T10:00:01Z INFO heartbeat ordinal={ordinal:03} shard={} healthy=true queue_depth={} padding=abcdefghijklmnopqrstuv",
            ordinal % 8,
            (ordinal * 17) % 101
        )
        .unwrap();
    }
    stdout.write_all(cause_record.as_bytes()).unwrap();
    for ordinal in 96..176 {
        writeln!(
            stdout,
            "2026-08-29T10:00:05Z INFO heartbeat ordinal={ordinal:03} shard={} healthy=true queue_depth={} padding=zyxwvutsrqponmlkjihgfe",
            ordinal % 8,
            (ordinal * 19) % 101
        )
        .unwrap();
    }
    for record in failure_records {
        stdout.write_all(record.as_bytes()).unwrap();
    }
    stdout.flush().unwrap();
    std::process::exit(exit_code);
}

fn emit_incident_agent_answer_v1() -> bool {
    const MAX_PROMPT_BYTES: u64 = 40 * 1024 * 1024;
    let mut prompt = Vec::new();
    if io::stdin()
        .take(MAX_PROMPT_BYTES + 1)
        .read_to_end(&mut prompt)
        .is_err()
        || u64::try_from(prompt.len()).map_or(true, |length| length > MAX_PROMPT_BYTES)
        || !prompt.starts_with(b"EVIDENTRAIL_EXECUTABLE_INCIDENT_AGENT_V1\n")
    {
        return false;
    }
    let Some(method) = decode_prompt_hex_field_v1(&prompt, b"method_artifact=") else {
        return false;
    };
    let aliases = prompt
        .split(|byte| *byte == b'\n')
        .find_map(|line| line.strip_prefix(b"citation_aliases="))
        .unwrap_or_default();
    let first_alias = aliases
        .split(|byte| *byte == b',')
        .find(|value| !value.is_empty())
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|value| value.parse::<u32>().ok());

    let diagnosis = if contains_bytes(&method, b"pool_size=0") {
        Some(("db_pool_size_zero", "pool_size=8\n"))
    } else if contains_bytes(&method, b"schema_expected=43 schema_actual=42") {
        Some(("migration_43_omitted", "apply_migration=43\n"))
    } else if contains_bytes(&method, b"upstream_timeout_ms=5 retry_limit=9") {
        Some(("upstream_timeout_too_low", "upstream_timeout_ms=500\n"))
    } else {
        None
    };
    let answer = match diagnosis {
        Some((cause, patch)) => {
            let patch_hex = lowercase_hex(patch.as_bytes());
            let citations = first_alias.map_or_else(|| "[]".to_owned(), |alias| format!("[{alias}]"));
            format!(
                "{{\"schema_version\":1,\"abstained\":false,\"cause_code\":\"{cause}\",\"patch_hex\":\"{patch_hex}\",\"cited_aliases\":{citations},\"claim_codes\":[\"configuration_regression\"],\"uncertainty_micros\":100000}}"
            )
        }
        None => "{\"schema_version\":1,\"abstained\":true,\"cause_code\":null,\"patch_hex\":null,\"cited_aliases\":[],\"claim_codes\":[],\"uncertainty_micros\":900000}".to_owned(),
    };
    write_reader_answer(answer.as_bytes())
}

fn verify_incident_patch_v1(incident: &str) -> ! {
    let mut patch = Vec::new();
    if io::stdin()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut patch)
        .is_err()
    {
        std::process::exit(1);
    }
    let valid = match incident {
        "db-pool-zero" => parse_bounded_assignment_v1(&patch, b"pool_size=", 1, 1024),
        "migration-drift" => migration_patch_reaches_schema_v43(&patch),
        "upstream-timeout" => {
            parse_bounded_assignment_v1(&patch, b"upstream_timeout_ms=", 100, 60_000)
        }
        _ => std::process::exit(64),
    };
    if !valid {
        std::process::exit(1);
    }
    io::stdout().write_all(b"verification=passed\n").unwrap();
    std::process::exit(0);
}

fn parse_bounded_assignment_v1(patch: &[u8], prefix: &[u8], minimum: u64, maximum: u64) -> bool {
    let Some(value) = patch.strip_prefix(prefix) else {
        return false;
    };
    let value = value.strip_suffix(b"\n").unwrap_or(value);
    if value.is_empty() || (value.len() > 1 && value[0] == b'0') {
        return false;
    }
    std::str::from_utf8(value)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|value| (minimum..=maximum).contains(&value))
}

fn migration_patch_reaches_schema_v43(patch: &[u8]) -> bool {
    let patch = patch.strip_suffix(b"\n").unwrap_or(patch);
    [
        b"apply_migration=43".as_slice(),
        b"schema_actual=43".as_slice(),
        b"RUN_MIGRATIONS_THROUGH=43".as_slice(),
    ]
    .contains(&patch)
}

fn decode_prompt_hex_field_v1(prompt: &[u8], prefix: &[u8]) -> Option<Vec<u8>> {
    let encoded = prompt
        .split(|byte| *byte == b'\n')
        .find_map(|line| line.strip_prefix(prefix))?;
    if encoded.len() % 2 != 0 {
        return None;
    }
    encoded
        .chunks_exact(2)
        .map(|pair| Some((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn emit_reader_fixture_v1(mode: &str) -> bool {
    const MAX_PROMPT_BYTES: u64 = 40 * 1024 * 1024;
    let mut prompt = Vec::new();
    if io::stdin()
        .take(MAX_PROMPT_BYTES + 1)
        .read_to_end(&mut prompt)
        .is_err()
        || u64::try_from(prompt.len()).map_or(true, |length| length > MAX_PROMPT_BYTES)
        || !prompt.starts_with(b"EVIDENTRAIL_BENCH_READER_PROMPT_V1\n")
        || !prompt
            .windows(b"tool_actions=forbidden\n".len())
            .any(|window| window == b"tool_actions=forbidden\n")
    {
        return false;
    }
    match mode {
        "timeout" => {
            thread::sleep(Duration::from_millis(250));
            true
        }
        "oversize" => {
            emit(&mut io::stdout(), 5 * 1024 * 1024);
            true
        }
        "malformed" => write_reader_answer(
            br#"{"schema_version":1,"unknown_field":"rejected"}"#,
        ),
        "tool-action" => write_reader_answer(
            br#"{"schema_version":1,"abstained":false,"abstention_reason":null,"cause_code":"db_pool_exhaustion","cause_granularity":"root_cause","diagnosis":"Database connections are exhausted.","citation_handles":[1,2],"claim_codes":["connection_pressure","requests_blocked"],"uncertainty_micros":125000,"tool_actions":["restart_database"]}"#,
        ),
        "abstain" => write_reader_answer(
            br#"{"schema_version":1,"abstained":true,"abstention_reason":"insufficient_public_evidence","cause_code":null,"cause_granularity":"unspecified","diagnosis":null,"citation_handles":[],"claim_codes":[],"uncertainty_micros":900000,"tool_actions":[]}"#,
        ),
        "alternate-valid" => write_reader_answer(
            br#"{"schema_version":1,"abstained":false,"abstention_reason":null,"cause_code":"network_partition","cause_granularity":"contributing_cause","diagnosis":"A network partition interrupted requests.","citation_handles":[1],"claim_codes":["network_fault"],"uncertainty_micros":400000,"tool_actions":[]}"#,
        ),
        "invalid-citation" => write_reader_answer(
            br#"{"schema_version":1,"abstained":false,"abstention_reason":null,"cause_code":"db_pool_exhaustion","cause_granularity":"root_cause","diagnosis":"Database connections are exhausted.","citation_handles":[1,999],"claim_codes":["connection_pressure","requests_blocked"],"uncertainty_micros":125000,"tool_actions":[]}"#,
        ),
        "adversarial-nondeterministic" => {
            let answer = format!(
                "{{\"schema_version\":1,\"abstained\":false,\"abstention_reason\":null,\"cause_code\":\"db_pool_exhaustion\",\"cause_granularity\":\"root_cause\",\"diagnosis\":\"process_{}\",\"citation_handles\":[1,2],\"claim_codes\":[\"connection_pressure\",\"requests_blocked\"],\"uncertainty_micros\":125000,\"tool_actions\":[]}}",
                std::process::id()
            );
            write_reader_answer(answer.as_bytes())
        }
        "correct" => write_reader_answer(
            br#"{"schema_version":1,"abstained":false,"abstention_reason":null,"cause_code":"db_pool_exhaustion","cause_granularity":"root_cause","diagnosis":"Database connections are exhausted.","citation_handles":[1,2],"claim_codes":["connection_pressure","requests_blocked"],"uncertainty_micros":125000,"tool_actions":[]}"#,
        ),
        _ => false,
    }
}

fn write_reader_answer(bytes: &[u8]) -> bool {
    let mut stdout = io::stdout().lock();
    stdout.write_all(bytes).is_ok() && stdout.flush().is_ok()
}

fn emit_first_party_constrained_product() -> bool {
    let Ok(expected_input) = evidentrail_bench_harness::constrained_pinned_drain_public_input_v1() else {
        return false;
    };
    let Ok(expected_length) = u64::try_from(expected_input.len()) else {
        return false;
    };
    let Some(read_cap) = expected_length.checked_add(1) else {
        return false;
    };
    let mut input = Vec::new();
    if io::stdin().take(read_cap).read_to_end(&mut input).is_err() {
        return false;
    }
    if input != expected_input {
        return false;
    }
    let Ok(output) = evidentrail_bench_harness::execute_constrained_first_party_fixture_v1(&input) else {
        return false;
    };
    let mut stdout = io::stdout().lock();
    stdout.write_all(&output).is_ok() && stdout.flush().is_ok()
}

fn emit_legacy_drain_fixture() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let output = if input
        == "2026-08-24T12:00:00Z INFO item id=alpha\n2026-08-24T12:00:01Z INFO item id=beta\n"
    {
        r#"{
  "groups": [{
    "id": 0,
    "first_index": 0,
    "count": 2,
    "template": "item id=<*>",
    "samples": [
      {"index": 0, "text": "item id=alpha", "level": "info", "timestamp": "2026-08-24T12:00:00Z"},
      {"index": 1, "text": "item id=beta", "level": "info", "timestamp": "2026-08-24T12:00:01Z"}
    ],
    "slots": []
  }],
  "original_count": 2,
  "template_count": 1,
  "line_compression": 2.0
}"#
    } else if input
        == "2026-08-24T12:00:00Z INFO api request id=alpha\n\n2026-08-24T12:00:01Z INFO api request id=beta\r\n2026-08-24T12:00:01.500Z INFO api request id=gamma\n2026-08-24T12:00:02Z ERROR database timeout host=db-1\n2026-08-24T12:00:03Z ERROR database timeout host=db-2"
    {
        r#"{
  "groups": [
    {
      "id": 0,
      "first_index": 0,
      "count": 1,
      "template": "api request id=alpha",
      "samples": [{"index": 0, "text": "api request id=alpha", "level": "info", "timestamp": "2026-08-24T12:00:00Z"}],
      "slots": []
    },
    {
      "id": 1,
      "first_index": 1,
      "count": 1,
      "template": "api request id=beta",
      "samples": [{"index": 1, "text": "api request id=beta", "level": "info", "timestamp": "2026-08-24T12:00:01Z"}],
      "slots": []
    },
    {
      "id": 2,
      "first_index": 2,
      "count": 1,
      "template": "api request id=gamma",
      "samples": [{"index": 2, "text": "api request id=gamma", "level": "info", "timestamp": "2026-08-24T12:00:01.500Z"}],
      "slots": []
    },
    {
      "id": 3,
      "first_index": 3,
      "count": 1,
      "template": "database timeout host=db-1",
      "samples": [{"index": 3, "text": "database timeout host=db-1", "level": "error", "timestamp": "2026-08-24T12:00:02Z"}],
      "slots": []
    },
    {
      "id": 4,
      "first_index": 4,
      "count": 1,
      "template": "database timeout host=db-2",
      "samples": [{"index": 4, "text": "database timeout host=db-2", "level": "error", "timestamp": "2026-08-24T12:00:03Z"}],
      "slots": []
    }
  ],
  "original_count": 5,
  "template_count": 5,
  "line_compression": 1.0
}"#
    } else if input.contains("evidentrail-bench constrained-generator-v1") {
        let output = evidentrail_bench_harness::hermetic_legacy_drain_full_membership_fixture_json_v1(
            input.as_bytes(),
        )
        .unwrap();
        io::stdout().write_all(&output).unwrap();
        return;
    } else if input == "2026-08-24T12:00:00Z INFO tamper\n" {
        r#"{
  "groups": [{
    "id": 0,
    "first_index": 0,
    "count": 1,
    "template": "tamper",
    "samples": [
      {"index": 0, "text": "wrong", "level": "info", "timestamp": "2026-08-24T12:00:00Z"}
    ],
    "slots": []
  }],
  "original_count": 1,
  "template_count": 1,
  "line_compression": 1.0
}"#
    } else {
        r#"{"groups":[],"original_count":0,"template_count":0,"line_compression":0.0}"#
    };
    let mut stdout = io::stdout().lock();
    stdout.write_all(output.as_bytes()).unwrap();
    stdout.write_all(b"\n").unwrap();
}

fn echo_stdin() {
    let mut bytes = Vec::new();
    io::stdin().read_to_end(&mut bytes).unwrap();
    io::stdout().write_all(&bytes).unwrap();
}

fn count_argument(arguments: &[String]) -> u64 {
    arguments
        .get(1)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}

fn emit(writer: &mut impl Write, count: u64) {
    let chunk = [b'x'; 1024];
    let mut remaining = count;
    while remaining > 0 {
        let write = remaining.min(chunk.len() as u64) as usize;
        if writer.write_all(&chunk[..write]).is_err() {
            break;
        }
        remaining -= write as u64;
    }
}
