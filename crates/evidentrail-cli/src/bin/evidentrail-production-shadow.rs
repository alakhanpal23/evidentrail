//! Local-only, deterministic shadow runner for approved historical incidents.

use std::error::Error as StdError;
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use evidentrail_cli::{
    MAX_QUESTION_BYTES_V1, MAX_STDIN_BYTES_V1, StdinBriefOutcomeV1,
    compile_explicit_stdin_retained_v1,
};
use evidentrail_core::{ExpansionLimitV1, ExpansionRelationV1, UnixTimestampNanos};
use evidentrail_schema::ExactnessBasis;
use evidentrail_store::{
    AliasExpansionRequestV1, EvidenceAliasV1, MAX_EXPANSION_BYTES, MAX_EXPANSION_EVENTS,
};
use serde::{Deserialize, Serialize};

const MANIFEST_VERSION_V1: u16 = 1;
const REPORT_VERSION_V1: u16 = 1;
const MAX_MANIFEST_BYTES_V1: usize = 1024 * 1024;
const MAX_CASES_V1: usize = 100;
const MIN_REPETITIONS_V1: u16 = 3;
const MAX_REPETITIONS_V1: u16 = 10;
const MAX_REQUIREMENTS_PER_CASE_V1: usize = 64;
const MAX_REQUIREMENT_BYTES_V1: usize = 64 * 1024;

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DataClassificationV1 {
    SyntheticC0,
    GovernedEvaluationC4,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowManifestV1 {
    schema_version: u16,
    data_classification: DataClassificationV1,
    local_processing_only: bool,
    hosted_egress: bool,
    content_telemetry: bool,
    retention: RetentionV1,
    repetitions: u16,
    cases: Vec<ShadowCaseV1>,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RetentionV1 {
    MemoryOnly,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowCaseV1 {
    log_file: PathBuf,
    question_file: PathBuf,
    required_evidence_files: Vec<PathBuf>,
    token_budget: u64,
    protected_slice: bool,
}

#[derive(Serialize)]
struct ShadowReportV1 {
    schema_version: u16,
    qualification_eligible: bool,
    mode: &'static str,
    data_classification: DataClassificationV1,
    local_processing_only: bool,
    memory_only: bool,
    hosted_egress_attempted: bool,
    content_fields_emitted: bool,
    case_count: usize,
    repetitions: u16,
    attempt_count: u64,
    rendered_attempt_count: u64,
    needs_more_attempt_count: u64,
    product_failure_count: u64,
    source_byte_count: u64,
    rendered_byte_count: u64,
    expansion_attempt_count: u64,
    expansion_success_count: u64,
    required_evidence_count: u64,
    required_evidence_selected_count: u64,
    required_evidence_recall_micros: u64,
    p50_end_to_end_nanos: u64,
    p95_end_to_end_nanos: u64,
    all_integrity_checks_passed: bool,
    quality_gate_passed: bool,
    pilot_passed: bool,
    cases: Vec<CaseReportV1>,
}

#[derive(Serialize)]
struct CaseReportV1 {
    case_index: usize,
    protected_slice: bool,
    source_record_count: u64,
    source_byte_count: u64,
    token_budget: u64,
    attempt_count: u64,
    rendered_attempt_count: u64,
    needs_more_attempt_count: u64,
    product_failure_count: u64,
    rendered_byte_count: u64,
    evidence_alias_count: u64,
    expansion_attempt_count: u64,
    expansion_success_count: u64,
    required_evidence_count: u64,
    required_evidence_selected_count: u64,
    required_evidence_recall_micros: u64,
    p50_end_to_end_nanos: u64,
    p95_end_to_end_nanos: u64,
    all_integrity_checks_passed: bool,
}

struct CaseRunV1 {
    report: CaseReportV1,
    elapsed_nanos: Vec<u64>,
}

#[derive(Clone, Copy)]
enum ShadowErrorV1 {
    Usage,
    RootInvalid,
    ManifestInvalid,
    AuthorizationInvalid,
    PathInvalid,
    FilePermissionsInvalid,
    FileInvalid,
    FileChanged,
    InputInvalid,
    RandomnessUnavailable,
    ClockUnavailable,
    ReportWriteFailed,
}

impl ShadowErrorV1 {
    const fn code(self) -> &'static str {
        match self {
            Self::Usage => "EVIDENTRAIL_PRODUCTION_SHADOW_USAGE",
            Self::RootInvalid => "EVIDENTRAIL_PRODUCTION_SHADOW_ROOT_INVALID",
            Self::ManifestInvalid => "EVIDENTRAIL_PRODUCTION_SHADOW_MANIFEST_INVALID",
            Self::AuthorizationInvalid => "EVIDENTRAIL_PRODUCTION_SHADOW_AUTHORIZATION_INVALID",
            Self::PathInvalid => "EVIDENTRAIL_PRODUCTION_SHADOW_PATH_INVALID",
            Self::FilePermissionsInvalid => {
                "EVIDENTRAIL_PRODUCTION_SHADOW_FILE_PERMISSIONS_INVALID"
            }
            Self::FileInvalid => "EVIDENTRAIL_PRODUCTION_SHADOW_FILE_INVALID",
            Self::FileChanged => "EVIDENTRAIL_PRODUCTION_SHADOW_FILE_CHANGED",
            Self::InputInvalid => "EVIDENTRAIL_PRODUCTION_SHADOW_INPUT_INVALID",
            Self::RandomnessUnavailable => "EVIDENTRAIL_PRODUCTION_SHADOW_RANDOMNESS_UNAVAILABLE",
            Self::ClockUnavailable => "EVIDENTRAIL_PRODUCTION_SHADOW_CLOCK_UNAVAILABLE",
            Self::ReportWriteFailed => "EVIDENTRAIL_PRODUCTION_SHADOW_REPORT_WRITE_FAILED",
        }
    }
}

impl fmt::Debug for ShadowErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for ShadowErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ShadowErrorV1 {}

fn main() -> ExitCode {
    match run() {
        Ok(report) => {
            let passed = report.pilot_passed;
            let mut stdout = std::io::stdout().lock();
            if serde_json::to_writer(&mut stdout, &report).is_err()
                || stdout.write_all(b"\n").is_err()
            {
                eprintln!("{}", ShadowErrorV1::ReportWriteFailed.code());
                return ExitCode::from(2);
            }
            if passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        Err(error) => {
            eprintln!("{}", error.code());
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ShadowReportV1, ShadowErrorV1> {
    let mut arguments = std::env::args_os().skip(1);
    let root_argument = arguments.next().ok_or(ShadowErrorV1::Usage)?;
    let manifest_argument = arguments.next().ok_or(ShadowErrorV1::Usage)?;
    if arguments.next().is_some() {
        return Err(ShadowErrorV1::Usage);
    }
    let root_path = PathBuf::from(root_argument);
    if !root_path.is_absolute() {
        return Err(ShadowErrorV1::RootInvalid);
    }
    let root = root_path
        .canonicalize()
        .map_err(|_| ShadowErrorV1::RootInvalid)?;
    let root_metadata = fs::metadata(&root).map_err(|_| ShadowErrorV1::RootInvalid)?;
    if !root_metadata.is_dir() {
        return Err(ShadowErrorV1::RootInvalid);
    }

    let manifest_relative = PathBuf::from(manifest_argument);
    let manifest_bytes =
        read_bounded_file(&root, &manifest_relative, MAX_MANIFEST_BYTES_V1, false)?;
    let manifest: ShadowManifestV1 =
        serde_json::from_slice(&manifest_bytes).map_err(|_| ShadowErrorV1::ManifestInvalid)?;
    validate_manifest(&manifest)?;
    let private = manifest.data_classification == DataClassificationV1::GovernedEvaluationC4;
    if private {
        require_private_permissions(&root_metadata)?;
        let private_manifest_bytes =
            read_bounded_file(&root, &manifest_relative, MAX_MANIFEST_BYTES_V1, true)?;
        if private_manifest_bytes != manifest_bytes {
            return Err(ShadowErrorV1::FileChanged);
        }
    }

    let mut case_runs = Vec::with_capacity(manifest.cases.len());
    for (index, case) in manifest.cases.iter().enumerate() {
        case_runs.push(run_case(
            &root,
            index + 1,
            case,
            manifest.repetitions,
            private,
        )?);
    }
    Ok(aggregate_report(&manifest, case_runs))
}

fn validate_manifest(manifest: &ShadowManifestV1) -> Result<(), ShadowErrorV1> {
    if manifest.schema_version != MANIFEST_VERSION_V1
        || manifest.cases.is_empty()
        || manifest.cases.len() > MAX_CASES_V1
        || !(MIN_REPETITIONS_V1..=MAX_REPETITIONS_V1).contains(&manifest.repetitions)
    {
        return Err(ShadowErrorV1::ManifestInvalid);
    }
    if !manifest.local_processing_only
        || manifest.hosted_egress
        || manifest.content_telemetry
        || manifest.retention != RetentionV1::MemoryOnly
    {
        return Err(ShadowErrorV1::AuthorizationInvalid);
    }
    for case in &manifest.cases {
        if case.required_evidence_files.is_empty()
            || case.required_evidence_files.len() > MAX_REQUIREMENTS_PER_CASE_V1
            || case.token_budget == 0
        {
            return Err(ShadowErrorV1::ManifestInvalid);
        }
    }
    Ok(())
}

fn run_case(
    root: &Path,
    case_index: usize,
    case: &ShadowCaseV1,
    repetitions: u16,
    private: bool,
) -> Result<CaseRunV1, ShadowErrorV1> {
    let log = read_bounded_file(root, &case.log_file, MAX_STDIN_BYTES_V1, private)?;
    let question = read_bounded_file(root, &case.question_file, MAX_QUESTION_BYTES_V1, private)?;
    if log.is_empty() || question.is_empty() {
        return Err(ShadowErrorV1::InputInvalid);
    }
    let mut requirements = Vec::with_capacity(case.required_evidence_files.len());
    for path in &case.required_evidence_files {
        let requirement = read_bounded_file(root, path, MAX_REQUIREMENT_BYTES_V1, private)?;
        if requirement.is_empty() || !contains_bytes(&log, &requirement) {
            return Err(ShadowErrorV1::InputInvalid);
        }
        requirements.push(requirement);
    }

    let mut elapsed_nanos = Vec::with_capacity(usize::from(repetitions));
    let mut source_record_count = 0;
    let mut rendered_attempt_count = 0;
    let mut needs_more_attempt_count = 0;
    let mut product_failure_count = 0;
    let mut rendered_byte_count = 0;
    let mut evidence_alias_count = 0;
    let mut expansion_attempt_count = 0;
    let mut expansion_success_count = 0;
    let mut required_evidence_selected_count = 0;
    let mut integrity = true;

    for _ in 0..repetitions {
        let mut identity_seed = [0u8; 32];
        getrandom::fill(&mut identity_seed).map_err(|_| ShadowErrorV1::RandomnessUnavailable)?;
        let now = unix_now()?;
        let started = Instant::now();
        let session = match compile_explicit_stdin_retained_v1(
            &log,
            &question,
            case.token_budget,
            identity_seed,
            now,
        ) {
            Ok(session) => session,
            Err(_) => {
                product_failure_count += 1;
                integrity = false;
                elapsed_nanos.push(nanos(started.elapsed().as_nanos()));
                continue;
            }
        };
        elapsed_nanos.push(nanos(started.elapsed().as_nanos()));
        match session.outcome() {
            StdinBriefOutcomeV1::NeedsMore(needs_more) => {
                needs_more_attempt_count += 1;
                source_record_count = needs_more.source_record_count();
                integrity &= needs_more.source_byte_count() == log.len() as u64;
            }
            StdinBriefOutcomeV1::Rendered(rendered) => {
                rendered_attempt_count += 1;
                source_record_count = rendered.source_record_count();
                rendered_byte_count += rendered.text().len() as u64;
                evidence_alias_count += rendered.evidence_alias_count();
                integrity &= rendered.source_byte_count() == log.len() as u64;
                let mut matched = vec![false; requirements.len()];
                for ordinal in 1..=rendered.evidence_alias_count() {
                    expansion_attempt_count += 1;
                    let Ok(ordinal) = u16::try_from(ordinal) else {
                        integrity = false;
                        continue;
                    };
                    let Ok(alias) = EvidenceAliasV1::new(rendered.result_id(), ordinal) else {
                        integrity = false;
                        continue;
                    };
                    let Ok(limit) =
                        ExpansionLimitV1::new(MAX_EXPANSION_EVENTS, MAX_EXPANSION_BYTES, 0, 0)
                    else {
                        integrity = false;
                        continue;
                    };
                    let request = AliasExpansionRequestV1::new(
                        rendered.result_id(),
                        alias,
                        ExpansionRelationV1::Exact,
                        limit,
                    );
                    let Ok(response) = session.expand_alias(request, now) else {
                        integrity = false;
                        continue;
                    };
                    let returned_bytes = response
                        .events()
                        .iter()
                        .map(|event| event.exact_bytes().len())
                        .sum::<usize>();
                    let exact = response
                        .events()
                        .iter()
                        .all(|event| event.exactness_basis() == ExactnessBasis::SourceExact);
                    if response.result_id() != rendered.result_id()
                        || response.relation() != ExpansionRelationV1::Exact
                        || response.truncated()
                        || response.events().is_empty()
                        || returned_bytes != response.returned_bytes()
                        || !exact
                    {
                        integrity = false;
                        continue;
                    }
                    expansion_success_count += 1;
                    let mut expanded = Vec::with_capacity(returned_bytes);
                    for event in response.events() {
                        expanded.extend_from_slice(event.exact_bytes());
                    }
                    let contiguous = response.events().windows(2).all(|pair| {
                        let lane_contiguous = pair[0]
                            .lane_sequence()
                            .get()
                            .checked_add(1)
                            .is_some_and(|next| next == pair[1].lane_sequence().get());
                        let acquisition_contiguous = pair[0]
                            .acquisition_sequence()
                            .get()
                            .checked_add(1)
                            .is_some_and(|next| next == pair[1].acquisition_sequence().get());
                        lane_contiguous && acquisition_contiguous
                    });
                    for (matched, requirement) in matched.iter_mut().zip(&requirements) {
                        *matched |= if contiguous {
                            contains_bytes(&expanded, requirement)
                        } else {
                            response
                                .events()
                                .iter()
                                .any(|event| contains_bytes(event.exact_bytes(), requirement))
                        };
                    }
                }
                required_evidence_selected_count +=
                    matched.into_iter().filter(|selected| *selected).count() as u64;
            }
        }
    }

    let attempt_count = u64::from(repetitions);
    let required_evidence_count = requirements.len() as u64 * attempt_count;
    let recall = ratio_micros(required_evidence_selected_count, required_evidence_count);
    Ok(CaseRunV1 {
        report: CaseReportV1 {
            case_index,
            protected_slice: case.protected_slice,
            source_record_count,
            source_byte_count: log.len() as u64,
            token_budget: case.token_budget,
            attempt_count,
            rendered_attempt_count,
            needs_more_attempt_count,
            product_failure_count,
            rendered_byte_count,
            evidence_alias_count,
            expansion_attempt_count,
            expansion_success_count,
            required_evidence_count,
            required_evidence_selected_count,
            required_evidence_recall_micros: recall,
            p50_end_to_end_nanos: percentile(&elapsed_nanos, 50),
            p95_end_to_end_nanos: percentile(&elapsed_nanos, 95),
            all_integrity_checks_passed: integrity
                && expansion_attempt_count == expansion_success_count,
        },
        elapsed_nanos,
    })
}

fn aggregate_report(manifest: &ShadowManifestV1, case_runs: Vec<CaseRunV1>) -> ShadowReportV1 {
    let mut elapsed = Vec::new();
    let mut cases = Vec::with_capacity(case_runs.len());
    let mut rendered = 0;
    let mut needs_more = 0;
    let mut failures = 0;
    let mut source_bytes = 0;
    let mut rendered_bytes = 0;
    let mut expansion_attempts = 0;
    let mut expansion_successes = 0;
    let mut requirements = 0;
    let mut selected = 0;
    let mut integrity = true;
    for run in case_runs {
        let case = run.report;
        rendered += case.rendered_attempt_count;
        needs_more += case.needs_more_attempt_count;
        failures += case.product_failure_count;
        source_bytes += case.source_byte_count * case.attempt_count;
        rendered_bytes += case.rendered_byte_count;
        expansion_attempts += case.expansion_attempt_count;
        expansion_successes += case.expansion_success_count;
        requirements += case.required_evidence_count;
        selected += case.required_evidence_selected_count;
        integrity &= case.all_integrity_checks_passed;
        elapsed.extend(run.elapsed_nanos);
        cases.push(case);
    }
    let attempt_count = cases.iter().map(|case| case.attempt_count).sum();
    let recall = ratio_micros(selected, requirements);
    let quality = failures == 0 && needs_more == 0 && recall == 1_000_000;
    ShadowReportV1 {
        schema_version: REPORT_VERSION_V1,
        qualification_eligible: false,
        mode: "deterministic_memory_only_no_egress_v1",
        data_classification: manifest.data_classification,
        local_processing_only: true,
        memory_only: true,
        hosted_egress_attempted: false,
        content_fields_emitted: false,
        case_count: cases.len(),
        repetitions: manifest.repetitions,
        attempt_count,
        rendered_attempt_count: rendered,
        needs_more_attempt_count: needs_more,
        product_failure_count: failures,
        source_byte_count: source_bytes,
        rendered_byte_count: rendered_bytes,
        expansion_attempt_count: expansion_attempts,
        expansion_success_count: expansion_successes,
        required_evidence_count: requirements,
        required_evidence_selected_count: selected,
        required_evidence_recall_micros: recall,
        p50_end_to_end_nanos: percentile(&elapsed, 50),
        p95_end_to_end_nanos: percentile(&elapsed, 95),
        all_integrity_checks_passed: integrity,
        quality_gate_passed: quality,
        pilot_passed: integrity && quality,
        cases,
    }
}

fn read_bounded_file(
    root: &Path,
    relative: &Path,
    max_bytes: usize,
    private: bool,
) -> Result<Vec<u8>, ShadowErrorV1> {
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ShadowErrorV1::PathInvalid);
    }
    let joined = root.join(relative);
    let link_metadata = fs::symlink_metadata(&joined).map_err(|_| ShadowErrorV1::FileInvalid)?;
    if link_metadata.file_type().is_symlink() {
        return Err(ShadowErrorV1::PathInvalid);
    }
    let canonical = joined
        .canonicalize()
        .map_err(|_| ShadowErrorV1::PathInvalid)?;
    if !canonical.starts_with(root) {
        return Err(ShadowErrorV1::PathInvalid);
    }
    let mut file = File::open(&canonical).map_err(|_| ShadowErrorV1::FileInvalid)?;
    let before = file.metadata().map_err(|_| ShadowErrorV1::FileInvalid)?;
    if !before.is_file() || before.len() > max_bytes as u64 {
        return Err(ShadowErrorV1::FileInvalid);
    }
    if private {
        require_private_permissions(&before)?;
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ShadowErrorV1::FileInvalid)?;
    if bytes.len() > max_bytes {
        return Err(ShadowErrorV1::FileInvalid);
    }
    let after = file.metadata().map_err(|_| ShadowErrorV1::FileChanged)?;
    let path_after = fs::metadata(&canonical).map_err(|_| ShadowErrorV1::FileChanged)?;
    if !same_file_snapshot(&before, &after) || !same_file_snapshot(&before, &path_after) {
        return Err(ShadowErrorV1::FileChanged);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn require_private_permissions(metadata: &Metadata) -> Result<(), ShadowErrorV1> {
    use std::os::unix::fs::MetadataExt as _;
    if metadata.mode() & 0o077 != 0 {
        return Err(ShadowErrorV1::FilePermissionsInvalid);
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_private_permissions(_metadata: &Metadata) -> Result<(), ShadowErrorV1> {
    Err(ShadowErrorV1::FilePermissionsInvalid)
}

#[cfg(unix)]
fn same_file_snapshot(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}

#[cfg(not(unix))]
fn same_file_snapshot(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

fn unix_now() -> Result<UnixTimestampNanos, ShadowErrorV1> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ShadowErrorV1::ClockUnavailable)?
        .as_nanos();
    let nanos = i128::try_from(nanos).map_err(|_| ShadowErrorV1::ClockUnavailable)?;
    Ok(UnixTimestampNanos::new(nanos))
}

fn nanos(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn ratio_micros(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator.saturating_mul(1_000_000) / denominator
}

fn percentile(values: &[u64], percent: usize) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = percent.saturating_mul(sorted.len()).div_ceil(100).max(1);
    sorted[rank - 1]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_manifest() -> ShadowManifestV1 {
        ShadowManifestV1 {
            schema_version: MANIFEST_VERSION_V1,
            data_classification: DataClassificationV1::SyntheticC0,
            local_processing_only: true,
            hosted_egress: false,
            content_telemetry: false,
            retention: RetentionV1::MemoryOnly,
            repetitions: MIN_REPETITIONS_V1,
            cases: vec![ShadowCaseV1 {
                log_file: PathBuf::from("incident.log"),
                question_file: PathBuf::from("question.txt"),
                required_evidence_files: vec![PathBuf::from("required.txt")],
                token_budget: 4_000,
                protected_slice: false,
            }],
        }
    }

    #[test]
    fn percentile_uses_nearest_rank() {
        assert_eq!(percentile(&[4, 1, 3, 2], 50), 2);
        assert_eq!(percentile(&[4, 1, 3, 2], 95), 4);
        assert_eq!(percentile(&[], 95), 0);
    }

    #[test]
    fn byte_matching_is_exact_and_nonempty() {
        assert!(contains_bytes(b"alpha\0beta", b"\0b"));
        assert!(!contains_bytes(b"alpha", b""));
        assert!(!contains_bytes(b"alpha", b"beta"));
    }

    #[test]
    fn manifest_refuses_any_egress_or_content_telemetry() {
        let mut manifest = valid_manifest();
        assert!(validate_manifest(&manifest).is_ok());

        manifest.hosted_egress = true;
        assert!(matches!(
            validate_manifest(&manifest),
            Err(ShadowErrorV1::AuthorizationInvalid)
        ));

        manifest.hosted_egress = false;
        manifest.content_telemetry = true;
        assert!(matches!(
            validate_manifest(&manifest),
            Err(ShadowErrorV1::AuthorizationInvalid)
        ));
    }

    #[test]
    fn bounded_reader_refuses_path_escape_before_io() {
        let root = Path::new("/tmp");
        assert!(matches!(
            read_bounded_file(root, Path::new("../escape"), 1, false),
            Err(ShadowErrorV1::PathInvalid)
        ));
        assert!(matches!(
            read_bounded_file(root, Path::new("/tmp/escape"), 1, false),
            Err(ShadowErrorV1::PathInvalid)
        ));
    }
}
