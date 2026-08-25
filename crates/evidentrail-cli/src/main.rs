#[cfg(unix)]
use std::collections::BTreeSet;
use std::env;
#[cfg(unix)]
use std::fs;
use std::fs::File;
use std::io::{self, IsTerminal as _, Read, Write as _};
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use evidentrail_authority::{CanonicalUnixPathV1, InternalPathPolicyV1, InternalPathRegistryV1};
use evidentrail_cli::{
    DEFAULT_TOKEN_BUDGET_V1, MAX_QUESTION_BYTES_V1, MAX_STDIN_BYTES_V1, StdinBriefOutcomeV1,
    compile_explicit_stdin_v1, run_mcp_stdio_v1,
};
use evidentrail_core::UnixTimestampNanos;
use evidentrail_local_file::{
    discover_local_file_metadata_v1, run_local_file_host_certification_matrix_v1,
};
use evidentrail_schema::InternalPathPolicyDigest;

const HELP: &str = "Evidentrail diagnostic evidence compiler\n\nUSAGE:\n  evidentrail brief (--question TEXT | --question-file PATH) [--token-budget N] < logs\n  evidentrail doctor --file PATH\n  evidentrail serve-mcp\n\nThe V1 brief command reads only explicit standard input. The memory-only MCP service\naccepts log bytes only when supplied by its caller and retains successful results for\nbounded expansion until their fixed 30-minute expiry or process exit. Doctor inspects\nmetadata for exactly one explicit file; it never reads file contents, approves a source,\nor mints host certification. The product does not discover files beyond that exact\ndoctor path, crawl a workspace, inspect ambient logs, persist results, or invoke a model.\nUse --question-file when the question should not appear in the process argument list. V1\nconservatively counts one rendered UTF-8 byte as one budget unit; this is not a\nmodel-token count.\n";

const DOCTOR_SUCCESS_CODE_V1: &str = "EVIDENTRAIL_CLI_DOCTOR_FILE_METADATA_OK";
const DOCTOR_INTERNAL_POLICY_FAILURE_V1: &str = "EVIDENTRAIL_CLI_DOCTOR_INTERNAL_PATH_POLICY_UNAVAILABLE";

struct BriefOptions {
    question: Vec<u8>,
    token_budget: u64,
}

struct DoctorOptions {
    path: PathBuf,
}

enum ParseDecision {
    Run(BriefOptions),
    Doctor(DoctorOptions),
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
        ParseDecision::Doctor(options) => run_doctor(options),
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
