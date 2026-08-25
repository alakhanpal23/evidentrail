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
        "--grouper" => emit_legacy_drain_fixture(),
        _ => std::process::exit(64),
    }
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
