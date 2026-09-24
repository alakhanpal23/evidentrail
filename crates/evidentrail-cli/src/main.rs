#[cfg(unix)]
use std::collections::BTreeSet;
use std::env;
#[cfg(unix)]
use std::fs;
use std::fs::File;
use std::io::{self, IsTerminal as _, Read, Write as _};
#[cfg(target_os = "macos")]
use std::os::unix::fs::PermissionsExt as _;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;
#[cfg(target_os = "macos")]
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use evidentrail_authority::{CanonicalUnixPathV1, InternalPathPolicyV1, InternalPathRegistryV1};
use evidentrail_cli::{
    CliFailure, CompactionError, DEFAULT_TOKEN_BUDGET_V1, HostedRankingDiagnosticRecordV1,
    MAX_QUESTION_BYTES_V1, MAX_STDIN_BYTES_V1, OpenAiEvidenceRankerV1, OpenAiIncidentReasoner,
    StdinBriefOutcomeV1, analyze_with_reasoner_and_metrics_and_traces_and_precedents, compact_logs,
    compile_explicit_stdin_retained_with_contended_ranker_v1,
    compile_explicit_stdin_retained_with_contended_shadow_ranker_v1,
    compile_explicit_stdin_retained_with_ranker_v1,
    compile_explicit_stdin_retained_with_shadow_ranker_v1, compile_explicit_stdin_v1,
    compile_explicit_stream_v3, run_mcp_stdio_v1,
};
#[cfg(target_os = "macos")]
use evidentrail_cli::{
    DurablePublishingMcpRetentionBackendV2, McpRetentionBackendErrorV1, run_connected_logs_cli,
    run_mcp_stdio_with_backend_v1, run_sources_cli,
};
use evidentrail_core::UnixTimestampNanos;
use evidentrail_local_file::{
    discover_local_file_metadata_v1, run_local_file_host_certification_matrix_v1,
};
#[cfg(target_os = "macos")]
use evidentrail_product::DurableProductV2;
use evidentrail_schema::InternalPathPolicyDigest;
#[cfg(target_os = "macos")]
use evidentrail_store::DurableRetainedEventStoreV3;
use evidentrail_store::PackedMemoryEventStoreV3;
#[cfg(target_os = "macos")]
use evidentrail_store::{
    DurableRepositoryErrorV2, DurableResultRepositoryV2, MacOsKeychainAuthorityV2,
};

const HELP: &str = "Evidentrail diagnostic evidence compiler\n\nUSAGE:\n  evidentrail sources connect-cloudwatch --account ID --region REGION --log-group GROUP [--profile PROFILE]\n  evidentrail sources connect-sentry --organization ORG --project PROJECT [--region global|us|de --token-env NAME]\n  evidentrail sources connect-datadog --site SITE [--api-key-env NAME --application-key-env NAME]\n  evidentrail sources rotate-datadog --connection-id ID [--api-key-env NAME --application-key-env NAME]\n  evidentrail sources recover-datadog --connection-id ID [--api-key-env NAME --application-key-env NAME]\n  evidentrail sources list\n  evidentrail sources setup\n  evidentrail sources feedback evaluate|promote|rollback --source-id SOURCE_ID --task TEXT\n  evidentrail sources sync\n  evidentrail sources watch [--interval-seconds N]\n  evidentrail sources service install|status|uninstall\n  evidentrail sources disconnect --source-id SOURCE_ID\n  evidentrail logs (--task TEXT | --task-file PATH) [--max-raw-bytes N]\n  evidentrail compact [--task TEXT | --task-file PATH] < utf8-logs\n  evidentrail brief (--question TEXT | --question-file PATH) [--token-budget N] [--retention memory|durable] [--llm-rank | --llm-rank-if-contended] < logs\n  evidentrail analyze (--question TEXT | --question-file PATH) [--topology PATH] [--metrics PATH --incident-time UNIX] [--traces PATH] [--confirmed-incidents PATH] [--selection-only] < utf8-logs\n  evidentrail doctor --file PATH\n  evidentrail serve-mcp [--retention memory|durable]\n\nSources and connected logs are macOS-only. Logs catches up authorized sources before global selection, prints original source records on stdout and provisional coverage metadata on stderr. Sentry connects project error events with SENTRY_AUTH_TOKEN (project:read); structured Sentry logs are not exported. Datadog registration uses DD_API_KEY and DD_APP_KEY from the environment by default, but Datadog sync and cached reads are blocked until Data Access Control scope can be verified. Sources watch repeatedly synchronizes with backoff; sources service install registers it as a per-user macOS LaunchAgent. The memory-only MCP server supports bounded connected expansion.\nCompact selects log groups with EVIDENTRAIL_COMPACT_LOCAL_MODEL on Ollama or hosted GPT-6 Sol (OPENAI_API_KEY) and emits only original log lines with repeat counts.\nThe explicit stdin prototype is bounded to 16 MiB; connected full-history indexing remains incomplete.\nAnalyze requires OPENAI_API_KEY for hosted inference, or set\nEVIDENTRAIL_ANALYZE_LOCAL_MODEL to use an Ollama model on 127.0.0.1:11434.\nOllama must load at least 16K for metric-only analysis or 32K when alert groups are present.\n--selection-only previews the exact local evidence selection without a model call.\nAnalyze groups repeated alerts, computes optional metric changes, derives observed\nservice relationships from explicit NDJSON parent-child spans, optionally compares\noperator-confirmed incident patterns, and checks model citations. Hypotheses and dependency edges do not establish causality. Brief\nreads only explicit standard input and retention defaults to memory. --llm-rank is an\nexplicit memory-mode beta opt-in to one hosted evidence-ordering call.\n--llm-rank-if-contended calls only when deterministic packing excluded a\nmodel-visible optional block. Deterministic compression remains the fallback\nand default. Streaming V3 is behind EVIDENTRAIL_STREAMING_V3=1; durable brief\nretention is explicit and requires external authority. Doctor inspects metadata\nfor one explicit file. Explicit stdin commands do not discover files or crawl a workspace. Connected commands read only registered logging sources. Use --question-file to keep a question out of the process\nargument list. The pinned tokenizer conservatively counts one rendered UTF-8 byte\nas one budget unit; this is not a model-token count.\n";

const DOCTOR_SUCCESS_CODE_V1: &str = "EVIDENTRAIL_CLI_DOCTOR_FILE_METADATA_OK";
const DOCTOR_INTERNAL_POLICY_FAILURE_V1: &str =
    "EVIDENTRAIL_CLI_DOCTOR_INTERNAL_PATH_POLICY_UNAVAILABLE";

struct BriefOptions {
    question: Vec<u8>,
    token_budget: u64,
    retention: McpRetentionSelectionV1,
    ranking_mode: CliRankingModeV1,
}

struct AnalyzeOptions {
    question: Vec<u8>,
    topology_path: Option<PathBuf>,
    metrics_path: Option<PathBuf>,
    traces_path: Option<PathBuf>,
    precedents_path: Option<PathBuf>,
    incident_time: Option<i64>,
    selection_only: bool,
}

struct CompactOptions {
    task: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum CliRankingModeV1 {
    #[default]
    Deterministic,
    Hosted,
    HostedIfContended,
}

struct DoctorOptions {
    path: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum McpRetentionSelectionV1 {
    Memory,
    Durable,
}

struct ServeMcpOptions {
    retention: McpRetentionSelectionV1,
}

enum ParseDecision {
    Run(BriefOptions),
    Analyze(AnalyzeOptions),
    Compact(CompactOptions),
    Doctor(DoctorOptions),
    ServeMcp(ServeMcpOptions),
    Sources(Vec<std::ffi::OsString>),
    ConnectedLogs(Vec<std::ffi::OsString>),
    Help,
    Version,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BoundedReadFailure {
    Io,
    LimitExceeded,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(failure) => {
            let _ = writeln!(io::stderr().lock(), "{}", failure.code);
            ExitCode::from(failure.exit_code)
        }
    }
}

fn run() -> Result<ExitCode, CliFailure> {
    match parse_args(env::args_os().skip(1))? {
        ParseDecision::Help => {
            io::stdout()
                .lock()
                .write_all(HELP.as_bytes())
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_STDOUT_WRITE_FAILURE"))?;
            Ok(ExitCode::SUCCESS)
        }
        ParseDecision::Version => {
            writeln!(
                io::stdout().lock(),
                "evidentrail {}",
                env!("CARGO_PKG_VERSION")
            )
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_STDOUT_WRITE_FAILURE"))?;
            Ok(ExitCode::SUCCESS)
        }
        ParseDecision::Run(options) => run_brief(options),
        ParseDecision::Analyze(options) => run_analyze(options),
        ParseDecision::Compact(options) => run_compact(options),
        ParseDecision::Doctor(options) => run_doctor(options),
        ParseDecision::ServeMcp(options) => run_mcp(options),
        ParseDecision::Sources(args) => {
            #[cfg(target_os = "macos")]
            {
                run_sources_cli(args)
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = args;
                Err(CliFailure::runtime("EVIDENTRAIL_SOURCES_UNSUPPORTED_HOST"))
            }
        }
        ParseDecision::ConnectedLogs(args) => {
            #[cfg(target_os = "macos")]
            {
                run_connected_logs_cli(args)
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = args;
                Err(CliFailure::runtime("EVIDENTRAIL_LOGS_UNSUPPORTED_HOST"))
            }
        }
    }
}

fn parse_args(
    args: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<ParseDecision, CliFailure> {
    let mut args = args.into_iter();
    let Some(command) = args.next() else {
        return Ok(ParseDecision::Help);
    };
    if command == "--help" || command == "-h" {
        return Ok(ParseDecision::Help);
    }
    if command == "--version" || command == "-V" {
        return Ok(ParseDecision::Version);
    }
    if command == "sources" {
        return Ok(ParseDecision::Sources(args.collect()));
    }
    if command == "logs" {
        return Ok(ParseDecision::ConnectedLogs(args.collect()));
    }
    if command == "serve-mcp" {
        let mut retention = McpRetentionSelectionV1::Memory;
        let mut saw_retention = false;
        while let Some(argument) = args.next() {
            if argument == "--retention" {
                if saw_retention {
                    return Err(CliFailure::usage("EVIDENTRAIL_CLI_DUPLICATE_OPTION"));
                }
                saw_retention = true;
                let value = args
                    .next()
                    .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_CLI_MISSING_OPTION_VALUE"))?;
                retention = if value == "memory" {
                    McpRetentionSelectionV1::Memory
                } else if value == "durable" {
                    McpRetentionSelectionV1::Durable
                } else {
                    return Err(CliFailure::usage("EVIDENTRAIL_CLI_INVALID_RETENTION"));
                };
            } else if argument == "--help" || argument == "-h" {
                return Ok(ParseDecision::Help);
            } else {
                return Err(CliFailure::usage("EVIDENTRAIL_CLI_UNKNOWN_OPTION"));
            }
        }
        return Ok(ParseDecision::ServeMcp(ServeMcpOptions { retention }));
    }
    if command == "doctor" {
        let mut file = None;
        while let Some(argument) = args.next() {
            if argument == "--file" {
                let value = args
                    .next()
                    .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_CLI_MISSING_OPTION_VALUE"))?;
                if file.replace(PathBuf::from(value)).is_some() {
                    return Err(CliFailure::usage("EVIDENTRAIL_CLI_DUPLICATE_OPTION"));
                }
            } else if argument == "--help" || argument == "-h" {
                return Ok(ParseDecision::Help);
            } else {
                return Err(CliFailure::usage("EVIDENTRAIL_CLI_UNKNOWN_OPTION"));
            }
        }
        let path = file.ok_or_else(|| CliFailure::usage("EVIDENTRAIL_CLI_DOCTOR_FILE_REQUIRED"))?;
        return Ok(ParseDecision::Doctor(DoctorOptions { path }));
    }
    if command == "analyze" {
        return parse_analyze_args(args);
    }
    if command == "compact" {
        return parse_compact_args(args);
    }
    if command != "brief" {
        return Err(CliFailure::usage("EVIDENTRAIL_CLI_UNKNOWN_COMMAND"));
    }

    let mut inline_question = None;
    let mut question_file = None;
    let mut token_budget = DEFAULT_TOKEN_BUDGET_V1;
    let mut saw_token_budget = false;
    let mut retention = McpRetentionSelectionV1::Memory;
    let mut saw_retention = false;
    let mut ranking_mode = CliRankingModeV1::Deterministic;
    while let Some(argument) = args.next() {
        if argument == "--question" {
            let value = args
                .next()
                .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_CLI_MISSING_OPTION_VALUE"))?;
            if inline_question.replace(value).is_some() {
                return Err(CliFailure::usage("EVIDENTRAIL_CLI_DUPLICATE_OPTION"));
            }
        } else if argument == "--question-file" {
            let value = args
                .next()
                .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_CLI_MISSING_OPTION_VALUE"))?;
            if question_file.replace(value).is_some() {
                return Err(CliFailure::usage("EVIDENTRAIL_CLI_DUPLICATE_OPTION"));
            }
        } else if argument == "--token-budget" {
            if saw_token_budget {
                return Err(CliFailure::usage("EVIDENTRAIL_CLI_DUPLICATE_OPTION"));
            }
            saw_token_budget = true;
            let value = args
                .next()
                .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_CLI_MISSING_OPTION_VALUE"))?;
            let value = value
                .to_str()
                .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_CLI_INVALID_TOKEN_BUDGET"))?;
            token_budget = value
                .parse::<u64>()
                .map_err(|_| CliFailure::usage("EVIDENTRAIL_CLI_INVALID_TOKEN_BUDGET"))?;
        } else if argument == "--retention" {
            if saw_retention {
                return Err(CliFailure::usage("EVIDENTRAIL_CLI_DUPLICATE_OPTION"));
            }
            saw_retention = true;
            let value = args
                .next()
                .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_CLI_MISSING_OPTION_VALUE"))?;
            retention = if value == "memory" {
                McpRetentionSelectionV1::Memory
            } else if value == "durable" {
                McpRetentionSelectionV1::Durable
            } else {
                return Err(CliFailure::usage("EVIDENTRAIL_CLI_INVALID_RETENTION"));
            };
        } else if argument == "--llm-rank" {
            if ranking_mode != CliRankingModeV1::Deterministic {
                return Err(CliFailure::usage("EVIDENTRAIL_CLI_DUPLICATE_OPTION"));
            }
            ranking_mode = CliRankingModeV1::Hosted;
        } else if argument == "--llm-rank-if-contended" {
            if ranking_mode != CliRankingModeV1::Deterministic {
                return Err(CliFailure::usage("EVIDENTRAIL_CLI_DUPLICATE_OPTION"));
            }
            ranking_mode = CliRankingModeV1::HostedIfContended;
        } else if argument == "--help" || argument == "-h" {
            return Ok(ParseDecision::Help);
        } else {
            return Err(CliFailure::usage("EVIDENTRAIL_CLI_UNKNOWN_OPTION"));
        }
    }
    if inline_question.is_some() == question_file.is_some() {
        return Err(CliFailure::usage(
            "EVIDENTRAIL_CLI_QUESTION_SOURCE_REQUIRED",
        ));
    }
    let question = if let Some(question) = inline_question {
        question
            .into_string()
            .map_err(|_| CliFailure::usage("EVIDENTRAIL_CLI_QUESTION_NOT_UTF8"))?
            .into_bytes()
    } else {
        let question_file = question_file
            .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_CLI_QUESTION_SOURCE_REQUIRED"))?;
        let file = File::open(question_file)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_QUESTION_FILE_OPEN_FAILURE"))?;
        match read_bounded(file, MAX_QUESTION_BYTES_V1) {
            Ok(question) => question,
            Err(BoundedReadFailure::Io) => {
                return Err(CliFailure::runtime(
                    "EVIDENTRAIL_CLI_QUESTION_FILE_READ_FAILURE",
                ));
            }
            Err(BoundedReadFailure::LimitExceeded) => {
                return Err(CliFailure::usage("EVIDENTRAIL_CLI_QUESTION_TOO_LARGE"));
            }
        }
    };
    Ok(ParseDecision::Run(BriefOptions {
        question,
        token_budget,
        retention,
        ranking_mode,
    }))
}

fn parse_compact_args(
    mut args: impl Iterator<Item = std::ffi::OsString>,
) -> Result<ParseDecision, CliFailure> {
    let mut inline_task = None;
    let mut task_file = None;
    while let Some(argument) = args.next() {
        let slot = if argument == "--task" {
            &mut inline_task
        } else if argument == "--task-file" {
            &mut task_file
        } else if argument == "--help" || argument == "-h" {
            return Ok(ParseDecision::Help);
        } else {
            return Err(CliFailure::usage("EVIDENTRAIL_CLI_UNKNOWN_OPTION"));
        };
        let value = args
            .next()
            .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_CLI_MISSING_OPTION_VALUE"))?;
        if slot.replace(value).is_some() {
            return Err(CliFailure::usage("EVIDENTRAIL_CLI_DUPLICATE_OPTION"));
        }
    }
    if inline_task.is_some() && task_file.is_some() {
        return Err(CliFailure::usage("EVIDENTRAIL_CLI_TASK_SOURCE_CONFLICT"));
    }
    let task = if let Some(value) = inline_task {
        value
            .into_string()
            .map_err(|_| CliFailure::usage("EVIDENTRAIL_CLI_TASK_NOT_UTF8"))?
    } else if let Some(path) = task_file {
        let file = File::open(PathBuf::from(path))
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_TASK_FILE_OPEN_FAILURE"))?;
        let bytes = read_bounded(file, MAX_QUESTION_BYTES_V1).map_err(|error| match error {
            BoundedReadFailure::Io => CliFailure::runtime("EVIDENTRAIL_CLI_TASK_FILE_READ_FAILURE"),
            BoundedReadFailure::LimitExceeded => {
                CliFailure::usage("EVIDENTRAIL_CLI_TASK_TOO_LARGE")
            }
        })?;
        String::from_utf8(bytes).map_err(|_| CliFailure::usage("EVIDENTRAIL_CLI_TASK_NOT_UTF8"))?
    } else {
        "Select the log lines most useful for debugging abnormal behavior.".to_owned()
    };
    if task.trim().is_empty() || task.len() > MAX_QUESTION_BYTES_V1 {
        return Err(CliFailure::usage("EVIDENTRAIL_CLI_TASK_TOO_LARGE"));
    }
    Ok(ParseDecision::Compact(CompactOptions { task }))
}

fn parse_analyze_args(
    mut args: impl Iterator<Item = std::ffi::OsString>,
) -> Result<ParseDecision, CliFailure> {
    let mut inline_question = None;
    let mut question_file = None;
    let mut topology_path = None;
    let mut metrics_path = None;
    let mut traces_path = None;
    let mut precedents_path = None;
    let mut incident_time = None;
    let mut selection_only = false;
    while let Some(argument) = args.next() {
        if argument == "--selection-only" {
            if selection_only {
                return Err(CliFailure::usage("EVIDENTRAIL_CLI_DUPLICATE_OPTION"));
            }
            selection_only = true;
            continue;
        }
        let slot = if argument == "--question" {
            &mut inline_question
        } else if argument == "--question-file" {
            &mut question_file
        } else if argument == "--topology" {
            &mut topology_path
        } else if argument == "--metrics" {
            &mut metrics_path
        } else if argument == "--traces" {
            &mut traces_path
        } else if argument == "--confirmed-incidents" {
            &mut precedents_path
        } else if argument == "--incident-time" {
            &mut incident_time
        } else if argument == "--help" || argument == "-h" {
            return Ok(ParseDecision::Help);
        } else {
            return Err(CliFailure::usage("EVIDENTRAIL_CLI_UNKNOWN_OPTION"));
        };
        let value = args
            .next()
            .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_CLI_MISSING_OPTION_VALUE"))?;
        if slot.replace(value).is_some() {
            return Err(CliFailure::usage("EVIDENTRAIL_CLI_DUPLICATE_OPTION"));
        }
    }
    if inline_question.is_some() == question_file.is_some() {
        return Err(CliFailure::usage(
            "EVIDENTRAIL_CLI_QUESTION_SOURCE_REQUIRED",
        ));
    }
    if metrics_path.is_some() != incident_time.is_some() {
        return Err(CliFailure::usage(
            "EVIDENTRAIL_CLI_METRICS_TIME_PAIR_REQUIRED",
        ));
    }
    if precedents_path.is_some() && metrics_path.is_none() {
        return Err(CliFailure::usage(
            "EVIDENTRAIL_CLI_PRECEDENTS_REQUIRE_METRICS",
        ));
    }
    let incident_time = incident_time
        .map(|value| {
            value
                .to_str()
                .and_then(|text| text.parse::<i64>().ok())
                .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_CLI_INVALID_INCIDENT_TIME"))
        })
        .transpose()?;
    let question = if let Some(value) = inline_question {
        value
            .into_string()
            .map_err(|_| CliFailure::usage("EVIDENTRAIL_CLI_QUESTION_NOT_UTF8"))?
            .into_bytes()
    } else {
        let file = File::open(question_file.expect("one question source"))
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_QUESTION_FILE_OPEN_FAILURE"))?;
        read_bounded(file, MAX_QUESTION_BYTES_V1).map_err(|error| match error {
            BoundedReadFailure::Io => {
                CliFailure::runtime("EVIDENTRAIL_CLI_QUESTION_FILE_READ_FAILURE")
            }
            BoundedReadFailure::LimitExceeded => {
                CliFailure::usage("EVIDENTRAIL_CLI_QUESTION_TOO_LARGE")
            }
        })?
    };
    if question.is_empty() || question.len() > MAX_QUESTION_BYTES_V1 {
        return Err(CliFailure::usage("EVIDENTRAIL_CLI_QUESTION_TOO_LARGE"));
    }
    Ok(ParseDecision::Analyze(AnalyzeOptions {
        question,
        topology_path: topology_path.map(PathBuf::from),
        metrics_path: metrics_path.map(PathBuf::from),
        traces_path: traces_path.map(PathBuf::from),
        precedents_path: precedents_path.map(PathBuf::from),
        incident_time,
        selection_only,
    }))
}

fn run_compact(options: CompactOptions) -> Result<ExitCode, CliFailure> {
    if io::stdin().is_terminal() {
        return Err(CliFailure::usage("EVIDENTRAIL_CLI_EXPLICIT_STDIN_REQUIRED"));
    }
    let logs = read_bounded(io::stdin().lock(), 16 * 1024 * 1024).map_err(|error| match error {
        BoundedReadFailure::Io => CliFailure::runtime("EVIDENTRAIL_CLI_STDIN_READ_FAILURE"),
        BoundedReadFailure::LimitExceeded => CliFailure::usage("EVIDENTRAIL_CLI_INPUT_TOO_LARGE"),
    })?;
    let mut selector = OpenAiIncidentReasoner::from_compact_environment()
        .map_err(|error| CliFailure::runtime(error.code()))?;
    let pack = compact_logs(&logs, &options.task, &mut selector)
        .map_err(|error: CompactionError| CliFailure::runtime(error.code()))?;
    let mut stdout = io::stdout().lock();
    for entry in &pack.selected {
        writeln!(
            stdout,
            "[{} × {}] {}",
            entry.source_id,
            entry.repeat_count,
            serde_json::to_string(&entry.raw)
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_STDOUT_WRITE_FAILURE"))?,
        )
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_STDOUT_WRITE_FAILURE"))?;
        if let (Some(id), Some(raw)) = (&entry.last_source_id, &entry.last_raw) {
            writeln!(
                stdout,
                "[{id}] {}",
                serde_json::to_string(raw)
                    .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_STDOUT_WRITE_FAILURE"))?,
            )
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_STDOUT_WRITE_FAILURE"))?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn run_analyze(options: AnalyzeOptions) -> Result<ExitCode, CliFailure> {
    if io::stdin().is_terminal() {
        return Err(CliFailure::usage("EVIDENTRAIL_CLI_EXPLICIT_STDIN_REQUIRED"));
    }
    let logs = read_bounded(io::stdin().lock(), 16 * 1024 * 1024).map_err(|error| match error {
        BoundedReadFailure::Io => CliFailure::runtime("EVIDENTRAIL_CLI_STDIN_READ_FAILURE"),
        BoundedReadFailure::LimitExceeded => CliFailure::usage("EVIDENTRAIL_CLI_INPUT_TOO_LARGE"),
    })?;
    let topology = if let Some(path) = options.topology_path {
        let file = File::open(path)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_TOPOLOGY_FILE_OPEN_FAILURE"))?;
        Some(read_bounded(file, 64 * 1024).map_err(|error| match error {
            BoundedReadFailure::Io => {
                CliFailure::runtime("EVIDENTRAIL_CLI_TOPOLOGY_FILE_READ_FAILURE")
            }
            BoundedReadFailure::LimitExceeded => {
                CliFailure::usage("EVIDENTRAIL_CLI_TOPOLOGY_TOO_LARGE")
            }
        })?)
    } else {
        None
    };
    let metrics = if let Some(path) = options.metrics_path {
        let file = File::open(path)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_METRICS_FILE_OPEN_FAILURE"))?;
        Some(
            read_bounded(file, 16 * 1024 * 1024).map_err(|error| match error {
                BoundedReadFailure::Io => {
                    CliFailure::runtime("EVIDENTRAIL_CLI_METRICS_FILE_READ_FAILURE")
                }
                BoundedReadFailure::LimitExceeded => {
                    CliFailure::usage("EVIDENTRAIL_CLI_METRICS_TOO_LARGE")
                }
            })?,
        )
    } else {
        None
    };
    let traces = if let Some(path) = options.traces_path {
        let file = File::open(path)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_TRACES_FILE_OPEN_FAILURE"))?;
        Some(
            read_bounded(file, 64 * 1024 * 1024).map_err(|error| match error {
                BoundedReadFailure::Io => {
                    CliFailure::runtime("EVIDENTRAIL_CLI_TRACES_FILE_READ_FAILURE")
                }
                BoundedReadFailure::LimitExceeded => {
                    CliFailure::usage("EVIDENTRAIL_CLI_TRACES_TOO_LARGE")
                }
            })?,
        )
    } else {
        None
    };
    let precedents = if let Some(path) = options.precedents_path {
        let file = File::open(path)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_PRECEDENTS_FILE_OPEN_FAILURE"))?;
        Some(read_bounded(file, 64 * 1024).map_err(|error| match error {
            BoundedReadFailure::Io => {
                CliFailure::runtime("EVIDENTRAIL_CLI_PRECEDENTS_FILE_READ_FAILURE")
            }
            BoundedReadFailure::LimitExceeded => {
                CliFailure::usage("EVIDENTRAIL_CLI_PRECEDENTS_TOO_LARGE")
            }
        })?)
    } else {
        None
    };
    let metric_input = metrics
        .as_ref()
        .zip(options.incident_time)
        .map(|(bytes, time)| (bytes.as_slice(), time));
    let question = std::str::from_utf8(&options.question)
        .map_err(|_| CliFailure::usage("EVIDENTRAIL_CLI_QUESTION_NOT_UTF8"))?;
    let report = if options.selection_only {
        let mut reasoner = SelectionOnlyReasoner;
        analyze_with_reasoner_and_metrics_and_traces_and_precedents(
            &logs,
            question,
            topology.as_deref(),
            metric_input,
            traces.as_deref(),
            precedents.as_deref(),
            &mut reasoner,
        )
    } else {
        let mut reasoner = OpenAiIncidentReasoner::from_environment()
            .map_err(|error| CliFailure::runtime(error.code()))?;
        analyze_with_reasoner_and_metrics_and_traces_and_precedents(
            &logs,
            question,
            topology.as_deref(),
            metric_input,
            traces.as_deref(),
            precedents.as_deref(),
            &mut reasoner,
        )
    }
    .map_err(|error| CliFailure::runtime(error.code()))?;
    serde_json::to_writer_pretty(io::stdout().lock(), &report)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_STDOUT_WRITE_FAILURE"))?;
    writeln!(io::stdout().lock())
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_STDOUT_WRITE_FAILURE"))?;
    Ok(ExitCode::SUCCESS)
}

struct SelectionOnlyReasoner;

impl evidentrail_cli::IncidentReasoner for SelectionOnlyReasoner {
    fn assess(
        &mut self,
        _request: &serde_json::Value,
    ) -> Result<evidentrail_cli::ModelAssessment, evidentrail_cli::AnalysisError> {
        Ok(evidentrail_cli::ModelAssessment {
            schema_version: 1,
            hypotheses: Vec::new(),
            needs_more_evidence: true,
            highlight_event_ids: Vec::new(),
        })
    }
}

fn run_doctor(options: DoctorOptions) -> Result<ExitCode, CliFailure> {
    let matrix = run_local_file_host_certification_matrix_v1()
        .map_err(|error| CliFailure::runtime(error.code()))?;
    let (internal_paths, internal_policy_digest) = doctor_internal_paths_v1()?;
    let discovery =
        discover_local_file_metadata_v1(&options.path, &internal_paths, internal_policy_digest)
            .map_err(|error| CliFailure::runtime(error.code()))?;
    writeln!(
        io::stdout().lock(),
        concat!(
            "{} capability={} content={} authorization={} ",
            "certification={} matrix_status={} matrix_version={} matrix_cells={} ",
            "matrix_receipt={} preflight_admission={}"
        ),
        DOCTOR_SUCCESS_CODE_V1,
        discovery.capability_code(),
        discovery.content_access_code(),
        discovery.authorization_code(),
        discovery.certification_code(),
        matrix.status_code(),
        matrix.matrix_version(),
        matrix.passed_cells().len(),
        matrix.receipt_digest().canonical_token(),
        matrix.preflight_admission_code(),
    )
    .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_STDOUT_WRITE_FAILURE"))?;
    Ok(ExitCode::SUCCESS)
}

fn doctor_internal_paths_v1()
-> Result<(InternalPathRegistryV1, InternalPathPolicyDigest), CliFailure> {
    let policy = doctor_internal_path_policy_v1()?;
    let digest = policy.digest();
    Ok((InternalPathRegistryV1::new(policy), digest))
}

#[cfg(unix)]
fn doctor_internal_path_policy_v1() -> Result<InternalPathPolicyV1, CliFailure> {
    let configured_home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| CliFailure::runtime(DOCTOR_INTERNAL_POLICY_FAILURE_V1))?;
    if !configured_home.is_absolute() {
        return Err(CliFailure::runtime(DOCTOR_INTERNAL_POLICY_FAILURE_V1));
    }
    let home = fs::canonicalize(configured_home)
        .map_err(|_| CliFailure::runtime(DOCTOR_INTERNAL_POLICY_FAILURE_V1))?;
    let current = env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(|_| CliFailure::runtime(DOCTOR_INTERNAL_POLICY_FAILURE_V1))?;
    let mut candidates = vec![
        home.join(".evidentrail"),
        home.join(".Evidentrail"),
        home.join(".config").join("evidentrail"),
        home.join(".local").join("share").join("evidentrail"),
        home.join(".local").join("state").join("evidentrail"),
        home.join(".local").join("cache").join("evidentrail"),
        home.join("Library")
            .join("Application Support")
            .join("Evidentrail"),
        home.join("Library")
            .join("Application Support")
            .join("evidentrail"),
        home.join("Library").join("Caches").join("Evidentrail"),
        home.join("Library").join("Caches").join("evidentrail"),
        home.join("Library")
            .join("Caches")
            .join("ai.evidentrail")
            .join("snapshots-v1"),
        home.join("Library").join("Logs").join("Evidentrail"),
        home.join("Library").join("Logs").join("evidentrail"),
        current.join(".evidentrail"),
    ];
    for (variable, suffix) in [
        ("XDG_DATA_HOME", "evidentrail"),
        ("XDG_STATE_HOME", "evidentrail"),
        ("XDG_CACHE_HOME", "evidentrail"),
        ("XDG_CACHE_HOME", "ai.evidentrail/snapshots-v1"),
    ] {
        if let Some(value) = env::var_os(variable) {
            let root = PathBuf::from(value);
            if !root.is_absolute() {
                return Err(CliFailure::runtime(DOCTOR_INTERNAL_POLICY_FAILURE_V1));
            }
            candidates.push(root.join(suffix));
        }
    }

    let mut canonical_roots = BTreeSet::new();
    let mut canonical_aliases = BTreeSet::new();
    for candidate in candidates {
        let configured = canonical_policy_path_bytes_v1(&candidate)?;
        canonical_roots.insert(configured.clone());
        match fs::canonicalize(&candidate) {
            Ok(resolved) => {
                let resolved = canonical_policy_path_bytes_v1(&resolved)?;
                if resolved != configured {
                    canonical_aliases.insert(resolved);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(CliFailure::runtime(DOCTOR_INTERNAL_POLICY_FAILURE_V1)),
        }
    }
    canonical_aliases.retain(|alias| !canonical_roots.contains(alias));
    let roots = canonical_roots
        .into_iter()
        .map(|bytes| {
            CanonicalUnixPathV1::new(bytes)
                .map_err(|_| CliFailure::runtime(DOCTOR_INTERNAL_POLICY_FAILURE_V1))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let aliases = canonical_aliases
        .into_iter()
        .map(|bytes| {
            CanonicalUnixPathV1::new(bytes)
                .map_err(|_| CliFailure::runtime(DOCTOR_INTERNAL_POLICY_FAILURE_V1))
        })
        .collect::<Result<Vec<_>, _>>()?;
    InternalPathPolicyV1::new(roots, aliases)
        .map_err(|_| CliFailure::runtime(DOCTOR_INTERNAL_POLICY_FAILURE_V1))
}

#[cfg(unix)]
fn canonical_policy_path_bytes_v1(path: &Path) -> Result<Vec<u8>, CliFailure> {
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::Component;

    if !path.is_absolute() {
        return Err(CliFailure::runtime(DOCTOR_INTERNAL_POLICY_FAILURE_V1));
    }
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => components.clear(),
            Component::CurDir => {}
            Component::ParentDir => {
                if components.pop().is_none() {
                    return Err(CliFailure::runtime(DOCTOR_INTERNAL_POLICY_FAILURE_V1));
                }
            }
            Component::Normal(component) => components.push(component.as_bytes().to_vec()),
            Component::Prefix(_) => {
                return Err(CliFailure::runtime(DOCTOR_INTERNAL_POLICY_FAILURE_V1));
            }
        }
    }
    let mut bytes = Vec::from(b"/".as_slice());
    for (index, component) in components.iter().enumerate() {
        if index != 0 {
            bytes.push(b'/');
        }
        bytes.extend_from_slice(component);
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn doctor_internal_path_policy_v1() -> Result<InternalPathPolicyV1, CliFailure> {
    let placeholder = CanonicalUnixPathV1::new(b"/evidentrail-internal-unavailable".to_vec())
        .map_err(|_| CliFailure::runtime(DOCTOR_INTERNAL_POLICY_FAILURE_V1))?;
    InternalPathPolicyV1::new([placeholder], [])
        .map_err(|_| CliFailure::runtime(DOCTOR_INTERNAL_POLICY_FAILURE_V1))
}

fn run_mcp(options: ServeMcpOptions) -> Result<ExitCode, CliFailure> {
    match options.retention {
        McpRetentionSelectionV1::Memory => {
            run_mcp_stdio_v1(io::stdin().lock(), io::stdout().lock())
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_MCP_STDIO_FAILURE"))?;
            Ok(ExitCode::SUCCESS)
        }
        McpRetentionSelectionV1::Durable => run_durable_mcp_v2(),
    }
}

#[cfg(target_os = "macos")]
fn run_durable_mcp_v2() -> Result<ExitCode, CliFailure> {
    let repository_root = durable_cache_root_v2()?;
    let authority = MacOsKeychainAuthorityV2::production().map_err(|error| {
        if error == evidentrail_store::KeyAuthorityErrorV2::Locked {
            CliFailure::runtime("EVIDENTRAIL_CLI_DURABLE_AUTHORITY_LOCKED")
        } else {
            CliFailure::runtime("EVIDENTRAIL_CLI_DURABLE_AUTHORITY_UNAVAILABLE")
        }
    })?;
    authority.verify_access().map_err(|error| {
        if error == evidentrail_store::KeyAuthorityErrorV2::Locked {
            CliFailure::runtime("EVIDENTRAIL_CLI_DURABLE_AUTHORITY_LOCKED")
        } else {
            CliFailure::runtime("EVIDENTRAIL_CLI_DURABLE_AUTHORITY_UNAVAILABLE")
        }
    })?;
    let authority = Arc::new(authority);
    prepare_durable_cache_parent_v2(&repository_root)?;
    let repository = DurableResultRepositoryV2::open(&repository_root, authority)
        .map_err(map_durable_repository_failure_v2)?;
    let product = DurableProductV2::new(repository);
    let (backend, _) =
        DurablePublishingMcpRetentionBackendV2::new_with_startup_recovery(product, unix_now_v1()?)
            .map_err(map_durable_backend_failure_v2)?;
    run_mcp_stdio_with_backend_v1(io::stdin().lock(), io::stdout().lock(), backend)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_MCP_STDIO_FAILURE"))?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(target_os = "macos")]
fn prepare_durable_cache_parent_v2(repository_root: &Path) -> Result<(), CliFailure> {
    let parent = repository_root
        .parent()
        .ok_or_else(|| CliFailure::runtime("EVIDENTRAIL_CLI_DURABLE_CACHE_ROOT_UNAVAILABLE"))?;
    match fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(CliFailure::runtime(
                "EVIDENTRAIL_CLI_DURABLE_CACHE_ROOT_UNAVAILABLE",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(parent).map_err(|_| {
                CliFailure::runtime("EVIDENTRAIL_CLI_DURABLE_CACHE_ROOT_UNAVAILABLE")
            })?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|_| {
                CliFailure::runtime("EVIDENTRAIL_CLI_DURABLE_CACHE_ROOT_UNAVAILABLE")
            })?;
        }
        Err(_) => {
            return Err(CliFailure::runtime(
                "EVIDENTRAIL_CLI_DURABLE_CACHE_ROOT_UNAVAILABLE",
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn map_durable_repository_failure_v2(error: DurableRepositoryErrorV2) -> CliFailure {
    match error {
        DurableRepositoryErrorV2::AuthorityLocked => {
            CliFailure::runtime("EVIDENTRAIL_CLI_DURABLE_AUTHORITY_LOCKED")
        }
        DurableRepositoryErrorV2::AuthorityUnavailable => {
            CliFailure::runtime("EVIDENTRAIL_CLI_DURABLE_AUTHORITY_UNAVAILABLE")
        }
        _ => CliFailure::runtime("EVIDENTRAIL_CLI_DURABLE_REPOSITORY_UNAVAILABLE"),
    }
}

#[cfg(target_os = "macos")]
fn map_durable_backend_failure_v2(error: McpRetentionBackendErrorV1) -> CliFailure {
    match error {
        McpRetentionBackendErrorV1::AuthorityLocked => {
            CliFailure::runtime("EVIDENTRAIL_CLI_DURABLE_AUTHORITY_LOCKED")
        }
        McpRetentionBackendErrorV1::AuthorityUnavailable => {
            CliFailure::runtime("EVIDENTRAIL_CLI_DURABLE_AUTHORITY_UNAVAILABLE")
        }
        McpRetentionBackendErrorV1::RollbackOrCorruption => {
            CliFailure::runtime("EVIDENTRAIL_CLI_DURABLE_ROLLBACK_OR_CORRUPTION")
        }
        _ => CliFailure::runtime("EVIDENTRAIL_CLI_DURABLE_RECOVERY_FAILED"),
    }
}

#[cfg(not(target_os = "macos"))]
fn run_durable_mcp_v2() -> Result<ExitCode, CliFailure> {
    Err(CliFailure::runtime(
        "EVIDENTRAIL_CLI_DURABLE_UNSUPPORTED_PLATFORM",
    ))
}

#[cfg(target_os = "macos")]
fn durable_cache_root_v2() -> Result<PathBuf, CliFailure> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| CliFailure::runtime("EVIDENTRAIL_CLI_DURABLE_CACHE_ROOT_UNAVAILABLE"))?;
    durable_cache_root_for_home_v2(&home)
}

#[cfg(target_os = "macos")]
fn durable_cache_root_for_home_v2(home: &Path) -> Result<PathBuf, CliFailure> {
    if !home.is_absolute() {
        return Err(CliFailure::runtime(
            "EVIDENTRAIL_CLI_DURABLE_CACHE_ROOT_UNAVAILABLE",
        ));
    }
    Ok(home
        .join("Library")
        .join("Caches")
        .join("ai.evidentrail")
        .join("results-v2"))
}

#[cfg(target_os = "macos")]
fn durable_cache_root_v3() -> Result<PathBuf, CliFailure> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| CliFailure::runtime("EVIDENTRAIL_CLI_DURABLE_CACHE_ROOT_UNAVAILABLE"))?;
    if !home.is_absolute() {
        return Err(CliFailure::runtime(
            "EVIDENTRAIL_CLI_DURABLE_CACHE_ROOT_UNAVAILABLE",
        ));
    }
    Ok(home
        .join("Library")
        .join("Caches")
        .join("ai.evidentrail")
        .join("results-v3"))
}

fn run_brief(options: BriefOptions) -> Result<ExitCode, CliFailure> {
    if io::stdin().is_terminal() {
        return Err(CliFailure::usage("EVIDENTRAIL_CLI_EXPLICIT_STDIN_REQUIRED"));
    }
    let mut identity_seed = [0_u8; 32];
    getrandom::fill(&mut identity_seed)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_RANDOMNESS_FAILURE"))?;
    let now = unix_now_v1()?;
    if options.ranking_mode != CliRankingModeV1::Deterministic
        && options.retention == McpRetentionSelectionV1::Durable
    {
        return Err(CliFailure::usage(
            "EVIDENTRAIL_CLI_HOSTED_RANKING_REQUIRES_MEMORY_RETENTION",
        ));
    }
    let outcome = match options.retention {
        McpRetentionSelectionV1::Memory
            if options.ranking_mode != CliRankingModeV1::Deterministic =>
        {
            let input = match read_bounded(io::stdin().lock(), MAX_STDIN_BYTES_V1) {
                Ok(input) => input,
                Err(BoundedReadFailure::Io) => {
                    return Err(CliFailure::runtime("EVIDENTRAIL_CLI_STDIN_READ_FAILURE"));
                }
                Err(BoundedReadFailure::LimitExceeded) => {
                    return Err(CliFailure::runtime("EVIDENTRAIL_CLI_INPUT_TOO_LARGE"));
                }
            };
            let mut ranker = OpenAiEvidenceRankerV1::from_environment();
            let session = match (options.ranking_mode, hosted_ranking_shadow_enabled()) {
                (CliRankingModeV1::Hosted, true) => {
                    compile_explicit_stdin_retained_with_shadow_ranker_v1(
                        &input,
                        &options.question,
                        options.token_budget,
                        identity_seed,
                        now,
                        &mut ranker,
                    )
                }
                (CliRankingModeV1::Hosted, false) => {
                    compile_explicit_stdin_retained_with_ranker_v1(
                        &input,
                        &options.question,
                        options.token_budget,
                        identity_seed,
                        now,
                        &mut ranker,
                    )
                }
                (CliRankingModeV1::HostedIfContended, true) => {
                    compile_explicit_stdin_retained_with_contended_shadow_ranker_v1(
                        &input,
                        &options.question,
                        options.token_budget,
                        identity_seed,
                        now,
                        &mut ranker,
                    )
                }
                (CliRankingModeV1::HostedIfContended, false) => {
                    compile_explicit_stdin_retained_with_contended_ranker_v1(
                        &input,
                        &options.question,
                        options.token_budget,
                        identity_seed,
                        now,
                        &mut ranker,
                    )
                }
                (CliRankingModeV1::Deterministic, _) => unreachable!("guarded match arm"),
            }
            .map_err(|error| CliFailure::runtime(error.code()))?;
            if let Some(diagnostics) = session.hosted_ranking_diagnostics() {
                let record = HostedRankingDiagnosticRecordV1::from_diagnostics(diagnostics);
                let encoded = serde_json::to_string(&record).map_err(|_| {
                    CliFailure::runtime("EVIDENTRAIL_CLI_DIAGNOSTIC_SERIALIZATION_FAILURE")
                })?;
                writeln!(io::stderr().lock(), "EVIDENTRAIL_HOSTED_RANKING {encoded}")
                    .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_STDERR_WRITE_FAILURE"))?;
            }
            session.into_outcome()
        }
        McpRetentionSelectionV1::Memory if streaming_v3_enabled() => compile_explicit_stream_v3(
            io::stdin().lock(),
            &options.question,
            options.token_budget,
            identity_seed,
            now,
            PackedMemoryEventStoreV3::new(),
        )
        .map_err(|error| CliFailure::runtime(error.code()))?
        .into_outcome(),
        McpRetentionSelectionV1::Memory => {
            let input = match read_bounded(io::stdin().lock(), MAX_STDIN_BYTES_V1) {
                Ok(input) => input,
                Err(BoundedReadFailure::Io) => {
                    return Err(CliFailure::runtime("EVIDENTRAIL_CLI_STDIN_READ_FAILURE"));
                }
                Err(BoundedReadFailure::LimitExceeded) => {
                    return Err(CliFailure::runtime("EVIDENTRAIL_CLI_INPUT_TOO_LARGE"));
                }
            };
            compile_explicit_stdin_v1(
                &input,
                &options.question,
                options.token_budget,
                identity_seed,
                now,
            )
            .map_err(|error| CliFailure::runtime(error.code()))?
        }
        McpRetentionSelectionV1::Durable => {
            return run_durable_brief_v3(options, identity_seed, now);
        }
    };
    emit_brief_outcome(outcome)
}

fn streaming_v3_enabled() -> bool {
    env::var_os("EVIDENTRAIL_STREAMING_V3").is_some_and(|value| value == "1")
}

fn hosted_ranking_shadow_enabled() -> bool {
    env::var_os("EVIDENTRAIL_HOSTED_RANKING_SHADOW").is_some_and(|value| value == "1")
}

fn emit_brief_outcome(outcome: StdinBriefOutcomeV1) -> Result<ExitCode, CliFailure> {
    match outcome {
        StdinBriefOutcomeV1::Rendered(rendered) => {
            io::stdout()
                .lock()
                .write_all(rendered.text().as_bytes())
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_STDOUT_WRITE_FAILURE"))?;
            Ok(ExitCode::SUCCESS)
        }
        StdinBriefOutcomeV1::NeedsMore(needs_more) => {
            writeln!(
                io::stderr().lock(),
                "EVIDENTRAIL_CLI_NEEDS_MORE reason={} records={} source_bytes={} retained=false",
                needs_more.reason().code(),
                needs_more.source_record_count(),
                needs_more.source_byte_count(),
            )
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_STDERR_WRITE_FAILURE"))?;
            Ok(ExitCode::from(3))
        }
    }
}

#[cfg(target_os = "macos")]
fn run_durable_brief_v3(
    options: BriefOptions,
    identity_seed: [u8; 32],
    now: UnixTimestampNanos,
) -> Result<ExitCode, CliFailure> {
    let repository_root = durable_cache_root_v3()?;
    let authority = MacOsKeychainAuthorityV2::production().map_err(|error| {
        if error == evidentrail_store::KeyAuthorityErrorV2::Locked {
            CliFailure::runtime("EVIDENTRAIL_CLI_DURABLE_AUTHORITY_LOCKED")
        } else {
            CliFailure::runtime("EVIDENTRAIL_CLI_DURABLE_AUTHORITY_UNAVAILABLE")
        }
    })?;
    authority.verify_access().map_err(|error| {
        if error == evidentrail_store::KeyAuthorityErrorV2::Locked {
            CliFailure::runtime("EVIDENTRAIL_CLI_DURABLE_AUTHORITY_LOCKED")
        } else {
            CliFailure::runtime("EVIDENTRAIL_CLI_DURABLE_AUTHORITY_UNAVAILABLE")
        }
    })?;
    prepare_durable_cache_parent_v2(&repository_root)?;
    let backend = DurableRetainedEventStoreV3::open(&repository_root, Arc::new(authority))
        .map_err(|error| match error {
            evidentrail_store::RetainedEventStoreErrorV3::AuthorityLocked => {
                CliFailure::runtime("EVIDENTRAIL_CLI_DURABLE_AUTHORITY_LOCKED")
            }
            evidentrail_store::RetainedEventStoreErrorV3::AuthorityUnavailable => {
                CliFailure::runtime("EVIDENTRAIL_CLI_DURABLE_AUTHORITY_UNAVAILABLE")
            }
            _ => CliFailure::runtime("EVIDENTRAIL_CLI_DURABLE_REPOSITORY_UNAVAILABLE"),
        })?;
    let outcome = compile_explicit_stream_v3(
        io::stdin().lock(),
        &options.question,
        options.token_budget,
        identity_seed,
        now,
        backend,
    )
    .map_err(|error| CliFailure::runtime(error.code()))?
    .into_outcome();
    emit_brief_outcome(outcome)
}

#[cfg(not(target_os = "macos"))]
fn run_durable_brief_v3(
    _options: BriefOptions,
    _identity_seed: [u8; 32],
    _now: UnixTimestampNanos,
) -> Result<ExitCode, CliFailure> {
    Err(CliFailure::runtime(
        "EVIDENTRAIL_CLI_DURABLE_UNSUPPORTED_PLATFORM",
    ))
}

fn read_bounded(mut reader: impl Read, limit: usize) -> Result<Vec<u8>, BoundedReadFailure> {
    let read_limit = u64::try_from(limit)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(BoundedReadFailure::LimitExceeded)?;
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| BoundedReadFailure::Io)?;
    if bytes.len() > limit {
        return Err(BoundedReadFailure::LimitExceeded);
    }
    Ok(bytes)
}

fn unix_now_v1() -> Result<UnixTimestampNanos, CliFailure> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_SYSTEM_TIME_FAILURE"))?;
    let seconds = i128::from(elapsed.as_secs());
    let nanos = i128::from(elapsed.subsec_nanos());
    let value = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or_else(|| CliFailure::runtime("EVIDENTRAIL_CLI_SYSTEM_TIME_FAILURE"))?;
    Ok(UnixTimestampNanos::new(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_has_a_default_task_and_no_time_window_or_diagnosis_flags() {
        match parse_args(["compact".into()]) {
            Ok(ParseDecision::Compact(options)) => assert!(options.task.contains("log lines")),
            _ => panic!("expected compact command"),
        }
        assert_eq!(
            parse_args(["compact".into(), "--metrics".into()])
                .err()
                .unwrap()
                .code,
            "EVIDENTRAIL_CLI_UNKNOWN_OPTION",
        );
    }

    #[test]
    fn parser_requires_exactly_one_question_source() {
        assert!(matches!(
            parse_args(["brief".into(), "--question".into(), "why?".into()]),
            Ok(ParseDecision::Run(_))
        ));
        assert_eq!(
            parse_args(["brief".into()]).err().unwrap().code,
            "EVIDENTRAIL_CLI_QUESTION_SOURCE_REQUIRED"
        );
        assert_eq!(
            parse_args([
                "brief".into(),
                "--question".into(),
                "why?".into(),
                "--question-file".into(),
                "q.txt".into(),
            ])
            .err()
            .unwrap()
            .code,
            "EVIDENTRAIL_CLI_QUESTION_SOURCE_REQUIRED"
        );
    }

    #[test]
    fn parser_accepts_explicit_trace_file_for_analysis() {
        match parse_args([
            "analyze".into(),
            "--question".into(),
            "why?".into(),
            "--traces".into(),
            "spans.ndjson".into(),
        ]) {
            Ok(ParseDecision::Analyze(options)) => {
                assert_eq!(options.traces_path, Some(PathBuf::from("spans.ndjson")));
            }
            _ => panic!("expected analysis with trace input"),
        }
    }

    #[test]
    fn parser_accepts_explicit_confirmed_incident_history() {
        match parse_args([
            "analyze".into(),
            "--question".into(),
            "why?".into(),
            "--metrics".into(),
            "metrics.ndjson".into(),
            "--incident-time".into(),
            "1000".into(),
            "--confirmed-incidents".into(),
            "history.json".into(),
        ]) {
            Ok(ParseDecision::Analyze(options)) => {
                assert_eq!(options.precedents_path, Some(PathBuf::from("history.json")));
            }
            _ => panic!("expected analysis with confirmed incidents"),
        }
    }

    #[test]
    fn parser_accepts_explicit_mcp_retention_with_memory_default() {
        match parse_args(["serve-mcp".into()]) {
            Ok(ParseDecision::ServeMcp(options)) => {
                assert_eq!(options.retention, McpRetentionSelectionV1::Memory);
            }
            _ => panic!("expected MCP decision"),
        }
        match parse_args(["serve-mcp".into(), "--retention".into(), "durable".into()]) {
            Ok(ParseDecision::ServeMcp(options)) => {
                assert_eq!(options.retention, McpRetentionSelectionV1::Durable);
            }
            _ => panic!("expected durable MCP decision"),
        }
        assert!(matches!(
            parse_args(["serve-mcp".into(), "--help".into()]),
            Ok(ParseDecision::Help)
        ));
        assert_eq!(
            parse_args(["serve-mcp".into(), "--extra".into()])
                .err()
                .unwrap()
                .code,
            "EVIDENTRAIL_CLI_UNKNOWN_OPTION"
        );
        assert_eq!(
            parse_args(["serve-mcp".into(), "--retention".into(), "forever".into(),])
                .err()
                .unwrap()
                .code,
            "EVIDENTRAIL_CLI_INVALID_RETENTION"
        );
    }

    #[test]
    fn parser_accepts_brief_retention_with_memory_default() {
        match parse_args(["brief".into(), "--question".into(), "why?".into()]) {
            Ok(ParseDecision::Run(options)) => {
                assert_eq!(options.retention, McpRetentionSelectionV1::Memory);
                assert_eq!(options.ranking_mode, CliRankingModeV1::Deterministic);
            }
            _ => panic!("expected brief decision"),
        }
        match parse_args([
            "brief".into(),
            "--question".into(),
            "why?".into(),
            "--llm-rank".into(),
        ]) {
            Ok(ParseDecision::Run(options)) => {
                assert_eq!(options.ranking_mode, CliRankingModeV1::Hosted);
            }
            _ => panic!("expected hosted-ranking brief decision"),
        }
        match parse_args([
            "brief".into(),
            "--question".into(),
            "why?".into(),
            "--llm-rank-if-contended".into(),
        ]) {
            Ok(ParseDecision::Run(options)) => {
                assert_eq!(options.ranking_mode, CliRankingModeV1::HostedIfContended);
            }
            _ => panic!("expected contention-gated hosted-ranking brief decision"),
        }
        assert_eq!(
            parse_args([
                "brief".into(),
                "--question".into(),
                "why?".into(),
                "--llm-rank".into(),
                "--llm-rank-if-contended".into(),
            ])
            .err()
            .unwrap()
            .code,
            "EVIDENTRAIL_CLI_DUPLICATE_OPTION"
        );
        match parse_args([
            "brief".into(),
            "--question".into(),
            "why?".into(),
            "--retention".into(),
            "durable".into(),
        ]) {
            Ok(ParseDecision::Run(options)) => {
                assert_eq!(options.retention, McpRetentionSelectionV1::Durable);
            }
            _ => panic!("expected durable brief decision"),
        }
        assert_eq!(
            parse_args([
                "brief".into(),
                "--question".into(),
                "why?".into(),
                "--retention".into(),
                "invalid".into(),
            ])
            .err()
            .unwrap()
            .code,
            "EVIDENTRAIL_CLI_INVALID_RETENTION"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn durable_cache_root_is_platform_scoped_and_requires_absolute_home() {
        match durable_cache_root_for_home_v2(Path::new("/Users/tester")) {
            Ok(root) => assert_eq!(
                root,
                PathBuf::from("/Users/tester/Library/Caches/ai.evidentrail/results-v2")
            ),
            Err(_) => panic!("absolute home must produce the platform cache root"),
        }
        assert_eq!(
            durable_cache_root_for_home_v2(Path::new("relative"))
                .err()
                .unwrap()
                .code,
            "EVIDENTRAIL_CLI_DURABLE_CACHE_ROOT_UNAVAILABLE"
        );
    }

    #[test]
    fn parser_accepts_only_one_explicit_doctor_file() {
        match parse_args(["doctor".into(), "--file".into(), "candidate.log".into()]) {
            Ok(ParseDecision::Doctor(options)) => {
                assert_eq!(options.path, PathBuf::from("candidate.log"));
            }
            _ => panic!("expected doctor decision"),
        }
        assert_eq!(
            parse_args(["doctor".into()]).err().unwrap().code,
            "EVIDENTRAIL_CLI_DOCTOR_FILE_REQUIRED"
        );
        assert_eq!(
            parse_args(["doctor".into(), "--file".into()])
                .err()
                .unwrap()
                .code,
            "EVIDENTRAIL_CLI_MISSING_OPTION_VALUE"
        );
        assert_eq!(
            parse_args([
                "doctor".into(),
                "--file".into(),
                "one.log".into(),
                "--file".into(),
                "two.log".into(),
            ])
            .err()
            .unwrap()
            .code,
            "EVIDENTRAIL_CLI_DUPLICATE_OPTION"
        );
        assert_eq!(
            parse_args([
                "doctor".into(),
                "--file".into(),
                "candidate.log".into(),
                "--recursive".into(),
            ])
            .err()
            .unwrap()
            .code,
            "EVIDENTRAIL_CLI_UNKNOWN_OPTION"
        );
    }

    #[test]
    fn bounded_reader_rejects_one_byte_over_limit() {
        assert_eq!(read_bounded(&b"abc"[..], 3).unwrap(), b"abc");
        assert_eq!(
            read_bounded(&b"abcd"[..], 3),
            Err(BoundedReadFailure::LimitExceeded)
        );
    }
}
