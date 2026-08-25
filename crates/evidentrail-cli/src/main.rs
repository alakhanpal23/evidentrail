use std::env;
use std::fs::File;
use std::io::{self, IsTerminal as _, Read, Write as _};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use evidentrail_cli::{
    DEFAULT_TOKEN_BUDGET_V1, MAX_QUESTION_BYTES_V1, MAX_STDIN_BYTES_V1, StdinBriefOutcomeV1,
    compile_explicit_stdin_v1, run_mcp_stdio_v1,
};
use evidentrail_core::UnixTimestampNanos;

const HELP: &str = "Evidentrail diagnostic evidence compiler\n\nUSAGE:\n  evidentrail brief (--question TEXT | --question-file PATH) [--token-budget N] < logs\n  evidentrail serve-mcp\n\nThe V1 brief command reads only explicit standard input. The memory-only MCP service\naccepts log bytes only when supplied by its caller and retains successful results for\nbounded expansion until their fixed 30-minute expiry or process exit. The product does\nnot discover files, crawl a workspace, inspect ambient logs, persist results, or invoke\na model. Use --question-file when the question should not appear in the process argument\nlist. V1 conservatively counts one rendered UTF-8 byte as one budget unit; this is not a\nmodel-token count.\n";

struct BriefOptions {
    question: Vec<u8>,
    token_budget: u64,
}

enum ParseDecision {
    Run(BriefOptions),
    ServeMcp,
    Help,
    Version,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct CliFailure {
    code: &'static str,
    exit_code: u8,
}

impl CliFailure {
    const fn usage(code: &'static str) -> Self {
        Self { code, exit_code: 2 }
    }

    const fn runtime(code: &'static str) -> Self {
        Self { code, exit_code: 1 }
    }
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
            writeln!(io::stdout().lock(), "evidentrail {}", env!("CARGO_PKG_VERSION"))
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_STDOUT_WRITE_FAILURE"))?;
            Ok(ExitCode::SUCCESS)
        }
        ParseDecision::Run(options) => run_brief(options),
        ParseDecision::ServeMcp => run_mcp(),
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
    if command == "serve-mcp" {
        if let Some(argument) = args.next() {
            if (argument == "--help" || argument == "-h") && args.next().is_none() {
                return Ok(ParseDecision::Help);
            }
            return Err(CliFailure::usage("EVIDENTRAIL_CLI_UNKNOWN_OPTION"));
        }
        return Ok(ParseDecision::ServeMcp);
    }
    if command != "brief" {
        return Err(CliFailure::usage("EVIDENTRAIL_CLI_UNKNOWN_COMMAND"));
    }

    let mut inline_question = None;
    let mut question_file = None;
    let mut token_budget = DEFAULT_TOKEN_BUDGET_V1;
    let mut saw_token_budget = false;
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
        } else if argument == "--help" || argument == "-h" {
            return Ok(ParseDecision::Help);
        } else {
            return Err(CliFailure::usage("EVIDENTRAIL_CLI_UNKNOWN_OPTION"));
        }
    }
    if inline_question.is_some() == question_file.is_some() {
        return Err(CliFailure::usage("EVIDENTRAIL_CLI_QUESTION_SOURCE_REQUIRED"));
    }
    let question = if let Some(question) = inline_question {
        question
            .into_string()
            .map_err(|_| CliFailure::usage("EVIDENTRAIL_CLI_QUESTION_NOT_UTF8"))?
            .into_bytes()
    } else {
        let question_file =
            question_file.ok_or_else(|| CliFailure::usage("EVIDENTRAIL_CLI_QUESTION_SOURCE_REQUIRED"))?;
        let file = File::open(question_file)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_QUESTION_FILE_OPEN_FAILURE"))?;
        match read_bounded(file, MAX_QUESTION_BYTES_V1) {
            Ok(question) => question,
            Err(BoundedReadFailure::Io) => {
                return Err(CliFailure::runtime("EVIDENTRAIL_CLI_QUESTION_FILE_READ_FAILURE"));
            }
            Err(BoundedReadFailure::LimitExceeded) => {
                return Err(CliFailure::usage("EVIDENTRAIL_CLI_QUESTION_TOO_LARGE"));
            }
        }
    };
    Ok(ParseDecision::Run(BriefOptions {
        question,
        token_budget,
    }))
}

fn run_mcp() -> Result<ExitCode, CliFailure> {
    run_mcp_stdio_v1(io::stdin().lock(), io::stdout().lock())
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_MCP_STDIO_FAILURE"))?;
    Ok(ExitCode::SUCCESS)
}

fn run_brief(options: BriefOptions) -> Result<ExitCode, CliFailure> {
    if io::stdin().is_terminal() {
        return Err(CliFailure::usage("EVIDENTRAIL_CLI_EXPLICIT_STDIN_REQUIRED"));
    }
    let input = match read_bounded(io::stdin().lock(), MAX_STDIN_BYTES_V1) {
        Ok(input) => input,
        Err(BoundedReadFailure::Io) => {
            return Err(CliFailure::runtime("EVIDENTRAIL_CLI_STDIN_READ_FAILURE"));
        }
        Err(BoundedReadFailure::LimitExceeded) => {
            return Err(CliFailure::runtime("EVIDENTRAIL_CLI_INPUT_TOO_LARGE"));
        }
    };
    let mut identity_seed = [0_u8; 32];
    getrandom::fill(&mut identity_seed)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_CLI_RANDOMNESS_FAILURE"))?;
    let now = unix_now_v1()?;
    let outcome = compile_explicit_stdin_v1(
        &input,
        &options.question,
        options.token_budget,
        identity_seed,
        now,
    )
    .map_err(|error| CliFailure::runtime(error.code()))?;
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
    fn parser_accepts_only_bare_serve_mcp_command() {
        assert!(matches!(
            parse_args(["serve-mcp".into()]),
            Ok(ParseDecision::ServeMcp)
        ));
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
