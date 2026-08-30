use std::error::Error as StdError;
use std::ffi::OsString;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};

use evidentrail_schema::ArtifactDigest;

use crate::pinned_matched_case::{
    BoundPeakRssObservationV1, PeakRssMeasurementUnitV1, PeakRssObservationBindingV1,
};
use crate::process::{
    RawSubprocessExecutionV1, RawSubprocessSpecV1, SubprocessWrapperV1,
    execute_wrapped_raw_subprocess_v1, public_receipt_from_raw_v1,
};
use crate::{
    ExitCategoryV1, HarnessError, PublicSubprocessInvocationV1, SubprocessExecutionReceiptV1,
    artifact_digest_for_bytes_v1, artifact_digest_for_file_v1,
};

pub const MACOS_TIME_L_PEAK_RSS_OBSERVER_CONTRACT_VERSION_V1: u16 = 1;
pub const MACOS_TIME_L_PEAK_RSS_REPORT_FORMAT_VERSION_V1: u16 = 1;

const MACOS_TIME_PATH_V1: &str = "/usr/bin/time";
const MAX_REPORT_BYTES_V1: u64 = 64 * 1024;
const METRIC_LABEL_V1: &str = "maximum resident set size";
#[cfg(any(target_os = "macos", test))]
const OBSERVER_FORMAT_V1: &[u8] = b"evidentrail/bench-harness/macos-time-l-peak-rss-format/v1\0argv=-l,-o,<private-report>,--,<target-argv>\0metric=exactly-one-unsigned-decimal-maximum-resident-set-size\0unit=bytes\0scope=directly-timed-process\0child-tree-aggregate=not-claimed";
#[cfg(any(target_os = "macos", test))]
const OBSERVER_MECHANISM_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/macos-time-l-peak-rss-observer/v1";
const OBSERVATION_RECEIPT_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/macos-time-l-peak-rss-receipt/v1";
const TEMP_DIRECTORY_PREFIX_V1: &str = "evidentrail-bench-rss-v1";

static TEMP_SEQUENCE_V1: AtomicU64 = AtomicU64::new(0);

/// Pinned local identity for macOS `/usr/bin/time -l`.
///
/// Pre/post path hashing is self-asserted reproducibility evidence. It is not
/// immutable executable attestation and does not close a hostile path race.
#[derive(Clone, PartialEq, Eq)]
pub struct MacOsTimePeakRssObserverV1 {
    canonical_path: PathBuf,
    executable_build_artifact_digest: ArtifactDigest,
    report_format_artifact_digest: ArtifactDigest,
    measurement_mechanism_artifact_digest: ArtifactDigest,
}

impl MacOsTimePeakRssObserverV1 {
    pub fn try_system_v1() -> Result<Self, PeakRssObserverErrorV1> {
        #[cfg(not(target_os = "macos"))]
        {
            Err(PeakRssObserverErrorV1::UnsupportedPlatform)
        }
        #[cfg(target_os = "macos")]
        {
            let canonical_path = Path::new(MACOS_TIME_PATH_V1)
                .canonicalize()
                .map_err(|_| PeakRssObserverErrorV1::ObserverUnavailable)?;
            if canonical_path != Path::new(MACOS_TIME_PATH_V1) {
                return Err(PeakRssObserverErrorV1::ObserverCanonicalPathMismatch);
            }
            let metadata = std::fs::metadata(&canonical_path)
                .map_err(|_| PeakRssObserverErrorV1::ObserverUnavailable)?;
            if !metadata.is_file() {
                return Err(PeakRssObserverErrorV1::ObserverNotRegularFile);
            }
            let executable_build_artifact_digest = artifact_digest_for_file_v1(&canonical_path)?;
            let report_format_artifact_digest = artifact_digest_for_bytes_v1(OBSERVER_FORMAT_V1);
            let measurement_mechanism_artifact_digest = derive_mechanism_artifact_digest_v1(
                executable_build_artifact_digest,
                report_format_artifact_digest,
            )?;
            Ok(Self {
                canonical_path,
                executable_build_artifact_digest,
                report_format_artifact_digest,
                measurement_mechanism_artifact_digest,
            })
        }
    }

    #[must_use]
    pub const fn executable_build_artifact_digest(&self) -> ArtifactDigest {
        self.executable_build_artifact_digest
    }

    #[must_use]
    pub const fn report_format_artifact_digest(&self) -> ArtifactDigest {
        self.report_format_artifact_digest
    }

    #[must_use]
    pub const fn measurement_mechanism_artifact_digest(&self) -> ArtifactDigest {
        self.measurement_mechanism_artifact_digest
    }

    #[must_use]
    pub fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    #[must_use]
    pub const fn contract_version(&self) -> u16 {
        MACOS_TIME_L_PEAK_RSS_OBSERVER_CONTRACT_VERSION_V1
    }

    #[must_use]
    pub const fn report_format_version(&self) -> u16 {
        MACOS_TIME_L_PEAK_RSS_REPORT_FORMAT_VERSION_V1
    }

    #[must_use]
    pub const fn directly_timed_process_only(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn child_tree_peak_rss_claimed(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn independently_attested(&self) -> bool {
        false
    }

    fn reverify(&self) -> Result<ArtifactDigest, PeakRssObserverErrorV1> {
        if self.canonical_path != Path::new(MACOS_TIME_PATH_V1) {
            return Err(PeakRssObserverErrorV1::ObserverCanonicalPathMismatch);
        }
        let digest = artifact_digest_for_file_v1(&self.canonical_path)?;
        if digest != self.executable_build_artifact_digest {
            return Err(PeakRssObserverErrorV1::ObserverChanged);
        }
        Ok(digest)
    }
}

impl fmt::Debug for MacOsTimePeakRssObserverV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacOsTimePeakRssObserverV1")
            .field("canonical_path_bound", &true)
            .field("observer_build_bound", &true)
            .field("contract_version", &self.contract_version())
            .field("report_format_version", &self.report_format_version())
            .field("report_format_bound", &true)
            .field("directly_timed_process_only", &true)
            .field("child_tree_peak_rss_claimed", &false)
            .field("independently_attested", &false)
            .field("path_redacted", &true)
            .finish()
    }
}

/// One parsed, execution-bound macOS peak-RSS measurement. The exact target
/// executable and public invocation remain independently bound by the normal
/// subprocess receipt; this receipt additionally binds the observer and raw
/// report identities.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MacOsTimePeakRssReceiptV1 {
    artifact_digest: ArtifactDigest,
    observation: BoundPeakRssObservationV1,
    observer_executable_build_artifact_digest: ArtifactDigest,
    observer_digest_before_spawn: ArtifactDigest,
    observer_digest_after_reap: ArtifactDigest,
    report_format_artifact_digest: ArtifactDigest,
    measurement_mechanism_artifact_digest: ArtifactDigest,
    raw_report_artifact_digest: ArtifactDigest,
    raw_report_byte_count: u64,
    invocation_digest: crate::InvocationDigestV1,
    stdout_artifact_digest: ArtifactDigest,
    stderr_artifact_digest: ArtifactDigest,
    observer_digest_verified_before_spawn: bool,
    observer_digest_verified_after_reap: bool,
}

impl MacOsTimePeakRssReceiptV1 {
    #[must_use]
    pub const fn artifact_digest(self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn observation(self) -> BoundPeakRssObservationV1 {
        self.observation
    }

    #[must_use]
    pub const fn peak_rss_bytes(self) -> u64 {
        self.observation.bytes()
    }

    #[must_use]
    pub const fn observer_executable_build_artifact_digest(self) -> ArtifactDigest {
        self.observer_executable_build_artifact_digest
    }

    #[must_use]
    pub const fn observer_digest_before_spawn(self) -> ArtifactDigest {
        self.observer_digest_before_spawn
    }

    #[must_use]
    pub const fn observer_digest_after_reap(self) -> ArtifactDigest {
        self.observer_digest_after_reap
    }

    #[must_use]
    pub const fn observer_contract_version(self) -> u16 {
        MACOS_TIME_L_PEAK_RSS_OBSERVER_CONTRACT_VERSION_V1
    }

    #[must_use]
    pub const fn report_format_version(self) -> u16 {
        MACOS_TIME_L_PEAK_RSS_REPORT_FORMAT_VERSION_V1
    }

    #[must_use]
    pub const fn observer_canonical_path(self) -> &'static str {
        MACOS_TIME_PATH_V1
    }

    #[must_use]
    pub const fn report_format_artifact_digest(self) -> ArtifactDigest {
        self.report_format_artifact_digest
    }

    #[must_use]
    pub const fn measurement_mechanism_artifact_digest(self) -> ArtifactDigest {
        self.measurement_mechanism_artifact_digest
    }

    #[must_use]
    pub const fn raw_report_artifact_digest(self) -> ArtifactDigest {
        self.raw_report_artifact_digest
    }

    #[must_use]
    pub const fn raw_report_byte_count(self) -> u64 {
        self.raw_report_byte_count
    }

    #[must_use]
    pub const fn invocation_digest(self) -> crate::InvocationDigestV1 {
        self.invocation_digest
    }

    #[must_use]
    pub const fn stdout_artifact_digest(self) -> ArtifactDigest {
        self.stdout_artifact_digest
    }

    #[must_use]
    pub const fn stderr_artifact_digest(self) -> ArtifactDigest {
        self.stderr_artifact_digest
    }

    #[must_use]
    pub const fn observer_digest_verified_before_spawn(self) -> bool {
        self.observer_digest_verified_before_spawn
    }

    #[must_use]
    pub const fn observer_digest_verified_after_reap(self) -> bool {
        self.observer_digest_verified_after_reap
    }

    #[must_use]
    pub const fn unit(self) -> PeakRssMeasurementUnitV1 {
        PeakRssMeasurementUnitV1::Bytes
    }

    #[must_use]
    pub const fn directly_timed_process_only(self) -> bool {
        true
    }

    #[must_use]
    pub const fn child_tree_peak_rss_claimed(self) -> bool {
        false
    }

    #[must_use]
    pub const fn independently_attested(self) -> bool {
        false
    }
}

impl fmt::Debug for MacOsTimePeakRssReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacOsTimePeakRssReceiptV1")
            .field("receipt_artifact_bound", &true)
            .field("observation", &self.observation)
            .field("observer_build_bound", &true)
            .field("report_format_bound", &true)
            .field("raw_report_bound", &true)
            .field("invocation_bound", &true)
            .field("stdout_bound", &true)
            .field("stderr_bound", &true)
            .field("observer_digest_verified_before_spawn", &true)
            .field("observer_digest_verified_after_reap", &true)
            .field("directly_timed_process_only", &true)
            .field("child_tree_peak_rss_claimed", &false)
            .field("independently_attested", &false)
            .field("contains_hidden_annotations", &false)
            .finish()
    }
}

/// Crate-private observer result before a domain-specific receipt binds the
/// measured execution to its public case and method. The observer is
/// self-asserted reproducibility evidence for the directly timed process; it
/// is neither attestation nor a child-tree aggregate.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RawMacOsTimePeakRssV1 {
    pub(crate) observer_executable_build_artifact_digest: ArtifactDigest,
    pub(crate) observer_digest_before_spawn: ArtifactDigest,
    pub(crate) observer_digest_after_reap: ArtifactDigest,
    pub(crate) report_format_artifact_digest: ArtifactDigest,
    pub(crate) measurement_mechanism_artifact_digest: ArtifactDigest,
    pub(crate) raw_report_artifact_digest: ArtifactDigest,
    pub(crate) raw_report_byte_count: u64,
    pub(crate) peak_rss_bytes: u64,
}

pub(crate) struct RawObservedSubprocessV1 {
    pub(crate) execution: RawSubprocessExecutionV1,
    pub(crate) peak_rss: Result<RawMacOsTimePeakRssV1, PeakRssObserverErrorV1>,
}

pub(crate) fn execute_with_macos_time_peak_rss_v1(
    observer: &MacOsTimePeakRssObserverV1,
    invocation: &PublicSubprocessInvocationV1,
    binding: PeakRssObservationBindingV1,
) -> Result<(SubprocessExecutionReceiptV1, MacOsTimePeakRssReceiptV1), PeakRssObserverErrorV1> {
    validate_binding_v1(invocation, binding)?;
    let observed = execute_raw_with_macos_time_peak_rss_v1(
        observer,
        RawSubprocessSpecV1 {
            program: invocation.program(),
            stdin_bytes: invocation.stdin().bytes(),
            limits: invocation.limits(),
        },
    )?;
    let raw_observation = observed.peak_rss?;
    let execution = public_receipt_from_raw_v1(invocation, observed.execution);
    let observation = binding
        .observe(
            raw_observation.measurement_mechanism_artifact_digest,
            PeakRssMeasurementUnitV1::Bytes,
            raw_observation.peak_rss_bytes,
        )
        .map_err(|_| PeakRssObserverErrorV1::ObservationConstructionFailed)?;
    let artifact_digest = derive_receipt_artifact_digest_v1(
        observer,
        invocation,
        &execution,
        observation,
        raw_observation.raw_report_artifact_digest,
        raw_observation.raw_report_byte_count,
        raw_observation.observer_digest_before_spawn,
        raw_observation.observer_digest_after_reap,
    )?;
    let receipt = MacOsTimePeakRssReceiptV1 {
        artifact_digest,
        observation,
        observer_executable_build_artifact_digest: raw_observation
            .observer_executable_build_artifact_digest,
        observer_digest_before_spawn: raw_observation.observer_digest_before_spawn,
        observer_digest_after_reap: raw_observation.observer_digest_after_reap,
        report_format_artifact_digest: raw_observation.report_format_artifact_digest,
        measurement_mechanism_artifact_digest: raw_observation
            .measurement_mechanism_artifact_digest,
        raw_report_artifact_digest: raw_observation.raw_report_artifact_digest,
        raw_report_byte_count: raw_observation.raw_report_byte_count,
        invocation_digest: invocation.digest(),
        stdout_artifact_digest: execution.stdout().artifact_digest(),
        stderr_artifact_digest: execution.stderr().artifact_digest(),
        observer_digest_verified_before_spawn: true,
        observer_digest_verified_after_reap: true,
    };
    Ok((execution, receipt))
}

pub(crate) fn execute_raw_with_macos_time_peak_rss_v1(
    observer: &MacOsTimePeakRssObserverV1,
    spec: RawSubprocessSpecV1<'_>,
) -> Result<RawObservedSubprocessV1, PeakRssObserverErrorV1> {
    let before = observer.reverify()?;
    let report = SecureReportFileV1::create()?;
    let argv = vec![
        OsString::from("-l"),
        OsString::from("-o"),
        report.path().as_os_str().to_owned(),
        OsString::from("--"),
    ];
    let execution = execute_wrapped_raw_subprocess_v1(
        spec,
        SubprocessWrapperV1 {
            executable_path: &observer.canonical_path,
            argv: &argv,
        },
    );
    let after = observer.reverify();
    let report_bytes = report.read_and_cleanup();
    let peak_rss = (|| {
        let after = after?;
        if before != after {
            return Err(PeakRssObserverErrorV1::ObserverChanged);
        }
        let report_bytes = report_bytes?;
        let peak_rss_bytes = parse_macos_time_l_peak_rss_v1(&report_bytes)?;
        let raw_report_byte_count = u64::try_from(report_bytes.len())
            .map_err(|_| PeakRssObserverErrorV1::ArtifactLengthOverflow)?;
        let raw_report_artifact_digest = artifact_digest_for_bytes_v1(&report_bytes);
        Ok(RawMacOsTimePeakRssV1 {
            observer_executable_build_artifact_digest: before,
            observer_digest_before_spawn: before,
            observer_digest_after_reap: after,
            report_format_artifact_digest: observer.report_format_artifact_digest,
            measurement_mechanism_artifact_digest: observer.measurement_mechanism_artifact_digest,
            raw_report_artifact_digest,
            raw_report_byte_count,
            peak_rss_bytes,
        })
    })();
    match execution {
        Ok(execution) => Ok(RawObservedSubprocessV1 {
            execution,
            peak_rss,
        }),
        Err(error) => {
            // Preserve the established observer-error precedence while still
            // guaranteeing report cleanup and post-run observer reverification.
            peak_rss?;
            Err(error.into())
        }
    }
}

fn validate_binding_v1(
    invocation: &PublicSubprocessInvocationV1,
    binding: PeakRssObservationBindingV1,
) -> Result<(), PeakRssObserverErrorV1> {
    if binding.system_artifact_digest() != invocation.program().system_artifact_digest()
        || binding.executable_build_artifact_digest()
            != invocation.program().executable_build_artifact_digest()
        || binding.public_run_manifest_artifact_digest()
            != invocation.run_manifest_artifact_digest()
        || binding.public_case_artifact_digest() != invocation.public_case_artifact_digest()
    {
        return Err(PeakRssObserverErrorV1::ObservationBindingMismatch);
    }
    Ok(())
}

fn parse_macos_time_l_peak_rss_v1(report: &[u8]) -> Result<u64, PeakRssObserverErrorV1> {
    let report =
        std::str::from_utf8(report).map_err(|_| PeakRssObserverErrorV1::ReportEncodingInvalid)?;
    let mut value = None;
    for line in report.lines() {
        if !line.contains(METRIC_LABEL_V1) {
            continue;
        }
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 5
            || fields[1] != "maximum"
            || fields[2] != "resident"
            || fields[3] != "set"
            || fields[4] != "size"
            || fields[0].is_empty()
            || !fields[0].bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(PeakRssObserverErrorV1::MetricMalformed);
        }
        if value.is_some() {
            return Err(PeakRssObserverErrorV1::MetricDuplicate);
        }
        let parsed = fields[0]
            .parse::<u64>()
            .map_err(|_| PeakRssObserverErrorV1::MetricOverflow)?;
        if parsed == 0 {
            return Err(PeakRssObserverErrorV1::MetricZero);
        }
        value = Some(parsed);
    }
    value.ok_or(PeakRssObserverErrorV1::MetricMissing)
}

struct SecureReportFileV1 {
    directory: PathBuf,
    path: PathBuf,
    cleaned: bool,
}

impl SecureReportFileV1 {
    fn create() -> Result<Self, PeakRssObserverErrorV1> {
        #[cfg(not(unix))]
        {
            return Err(PeakRssObserverErrorV1::UnsupportedPlatform);
        }
        #[cfg(unix)]
        {
            let parent = std::env::temp_dir();
            if !parent.is_dir() {
                return Err(PeakRssObserverErrorV1::TemporaryDirectoryUnavailable);
            }
            for _ in 0..128 {
                let sequence = TEMP_SEQUENCE_V1.fetch_add(1, Ordering::Relaxed);
                let directory = parent.join(format!(
                    "{TEMP_DIRECTORY_PREFIX_V1}-{}-{sequence}",
                    std::process::id()
                ));
                let mut builder = std::fs::DirBuilder::new();
                builder.mode(0o700);
                match builder.create(&directory) {
                    Ok(()) => {
                        let path = directory.join("report");
                        let mut options = OpenOptions::new();
                        options.write(true).create_new(true).mode(0o600);
                        if options.open(&path).is_err() {
                            let _ = std::fs::remove_dir(&directory);
                            return Err(PeakRssObserverErrorV1::TemporaryReportCreateFailed);
                        }
                        return Ok(Self {
                            directory,
                            path,
                            cleaned: false,
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(_) => {
                        return Err(PeakRssObserverErrorV1::TemporaryDirectoryCreateFailed);
                    }
                }
            }
            Err(PeakRssObserverErrorV1::TemporaryDirectoryCreateFailed)
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn read_and_cleanup(mut self) -> Result<Vec<u8>, PeakRssObserverErrorV1> {
        let result = self.read_bounded();
        let cleanup = self.cleanup();
        match (result, cleanup) {
            (_, Err(error)) => Err(error),
            (result, Ok(())) => result,
        }
    }

    fn read_bounded(&self) -> Result<Vec<u8>, PeakRssObserverErrorV1> {
        #[cfg(not(unix))]
        {
            Err(PeakRssObserverErrorV1::UnsupportedPlatform)
        }
        #[cfg(unix)]
        {
            let metadata = std::fs::symlink_metadata(&self.path)
                .map_err(|_| PeakRssObserverErrorV1::TemporaryReportReadFailed)?;
            if !metadata.file_type().is_file() {
                return Err(PeakRssObserverErrorV1::TemporaryReportNotRegularFile);
            }
            if metadata.permissions().mode() & 0o777 != 0o600 {
                return Err(PeakRssObserverErrorV1::TemporaryReportPermissionsInvalid);
            }
            if metadata.len() > MAX_REPORT_BYTES_V1 {
                return Err(PeakRssObserverErrorV1::TemporaryReportTooLarge);
            }
            let mut file = OpenOptions::new()
                .read(true)
                .open(&self.path)
                .map_err(|_| PeakRssObserverErrorV1::TemporaryReportReadFailed)?;
            read_bounded_report_v1(&mut file)
        }
    }

    fn cleanup(&mut self) -> Result<(), PeakRssObserverErrorV1> {
        let file_result = remove_exact_file_if_present(&self.path);
        let directory_result = remove_exact_directory_if_present(&self.directory);
        self.cleaned = file_result.is_ok() && directory_result.is_ok();
        file_result.and(directory_result)
    }
}

impl Drop for SecureReportFileV1 {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.cleanup();
        }
    }
}

fn read_bounded_report_v1(file: &mut File) -> Result<Vec<u8>, PeakRssObserverErrorV1> {
    let mut bytes = Vec::new();
    file.take(MAX_REPORT_BYTES_V1 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| PeakRssObserverErrorV1::TemporaryReportReadFailed)?;
    if u64::try_from(bytes.len())
        .ok()
        .is_none_or(|length| length > MAX_REPORT_BYTES_V1)
    {
        return Err(PeakRssObserverErrorV1::TemporaryReportTooLarge);
    }
    Ok(bytes)
}

fn remove_exact_file_if_present(path: &Path) -> Result<(), PeakRssObserverErrorV1> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(PeakRssObserverErrorV1::TemporaryReportCleanupFailed),
    }
}

fn remove_exact_directory_if_present(path: &Path) -> Result<(), PeakRssObserverErrorV1> {
    match std::fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(PeakRssObserverErrorV1::TemporaryReportCleanupFailed),
    }
}

#[cfg(any(target_os = "macos", test))]
fn derive_mechanism_artifact_digest_v1(
    observer_build: ArtifactDigest,
    report_format: ArtifactDigest,
) -> Result<ArtifactDigest, PeakRssObserverErrorV1> {
    let mut bytes = Vec::new();
    append_field(&mut bytes, OBSERVER_MECHANISM_DOMAIN_V1)?;
    append_field(
        &mut bytes,
        &MACOS_TIME_L_PEAK_RSS_OBSERVER_CONTRACT_VERSION_V1.to_le_bytes(),
    )?;
    append_field(&mut bytes, MACOS_TIME_PATH_V1.as_bytes())?;
    append_field(&mut bytes, observer_build.as_bytes())?;
    append_field(
        &mut bytes,
        &MACOS_TIME_L_PEAK_RSS_REPORT_FORMAT_VERSION_V1.to_le_bytes(),
    )?;
    append_field(&mut bytes, report_format.as_bytes())?;
    Ok(artifact_digest_for_bytes_v1(&bytes))
}

#[allow(clippy::too_many_arguments)]
fn derive_receipt_artifact_digest_v1(
    observer: &MacOsTimePeakRssObserverV1,
    invocation: &PublicSubprocessInvocationV1,
    execution: &SubprocessExecutionReceiptV1,
    observation: BoundPeakRssObservationV1,
    raw_report_artifact_digest: ArtifactDigest,
    raw_report_byte_count: u64,
    before: ArtifactDigest,
    after: ArtifactDigest,
) -> Result<ArtifactDigest, PeakRssObserverErrorV1> {
    let mut bytes = Vec::new();
    append_field(&mut bytes, OBSERVATION_RECEIPT_DOMAIN_V1)?;
    append_field(
        &mut bytes,
        observer.measurement_mechanism_artifact_digest.as_bytes(),
    )?;
    append_field(&mut bytes, before.as_bytes())?;
    append_field(&mut bytes, after.as_bytes())?;
    append_field(&mut bytes, invocation.digest().as_bytes())?;
    append_field(
        &mut bytes,
        invocation.program().system_artifact_digest().as_bytes(),
    )?;
    append_field(
        &mut bytes,
        invocation
            .program()
            .executable_build_artifact_digest()
            .as_bytes(),
    )?;
    append_field(
        &mut bytes,
        invocation.run_manifest_artifact_digest().as_bytes(),
    )?;
    append_field(
        &mut bytes,
        invocation.public_case_artifact_digest().as_bytes(),
    )?;
    append_field(&mut bytes, invocation.stdin().artifact_digest().as_bytes())?;
    append_field(&mut bytes, execution.stdout().artifact_digest().as_bytes())?;
    append_field(&mut bytes, execution.stderr().artifact_digest().as_bytes())?;
    append_field(&mut bytes, execution.stdin_delivery().code().as_bytes())?;
    append_field(&mut bytes, execution.exit_category().code().as_bytes())?;
    match execution.exit_category() {
        ExitCategoryV1::Success | ExitCategoryV1::HarnessTerminated => {
            append_field(&mut bytes, &[])?;
        }
        ExitCategoryV1::Nonzero { code } => append_field(&mut bytes, &code.to_le_bytes())?,
        ExitCategoryV1::Signaled { signal } => {
            append_field(&mut bytes, &signal.unwrap_or_default().to_le_bytes())?;
        }
    }
    append_field(&mut bytes, execution.stdout().state().code().as_bytes())?;
    append_field(&mut bytes, execution.stderr().state().code().as_bytes())?;
    let termination_count = u64::try_from(execution.termination_causes().len())
        .map_err(|_| PeakRssObserverErrorV1::ArtifactLengthOverflow)?;
    append_field(&mut bytes, &termination_count.to_le_bytes())?;
    for cause in execution.termination_causes() {
        append_field(&mut bytes, cause.code().as_bytes())?;
    }
    append_field(&mut bytes, &execution.wall_time_nanos().to_le_bytes())?;
    append_field(&mut bytes, raw_report_artifact_digest.as_bytes())?;
    append_field(&mut bytes, &raw_report_byte_count.to_le_bytes())?;
    append_field(&mut bytes, observation.artifact_digest().as_bytes())?;
    append_field(&mut bytes, &observation.bytes().to_le_bytes())?;
    append_field(
        &mut bytes,
        PeakRssMeasurementUnitV1::Bytes.code().as_bytes(),
    )?;
    Ok(artifact_digest_for_bytes_v1(&bytes))
}

fn append_field(output: &mut Vec<u8>, field: &[u8]) -> Result<(), PeakRssObserverErrorV1> {
    let length =
        u64::try_from(field.len()).map_err(|_| PeakRssObserverErrorV1::ArtifactLengthOverflow)?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(field);
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PeakRssObserverErrorV1 {
    UnsupportedPlatform,
    ObserverUnavailable,
    ObserverCanonicalPathMismatch,
    ObserverNotRegularFile,
    ObserverChanged,
    ObservationBindingMismatch,
    TemporaryDirectoryUnavailable,
    TemporaryDirectoryCreateFailed,
    TemporaryReportCreateFailed,
    TemporaryReportNotRegularFile,
    TemporaryReportPermissionsInvalid,
    TemporaryReportTooLarge,
    TemporaryReportReadFailed,
    TemporaryReportCleanupFailed,
    ReportEncodingInvalid,
    MetricMissing,
    MetricDuplicate,
    MetricMalformed,
    MetricZero,
    MetricOverflow,
    ObservationConstructionFailed,
    ArtifactLengthOverflow,
    Harness(HarnessError),
}

impl PeakRssObserverErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "EVIDENTRAIL_BENCH_RSS_OBSERVER_UNSUPPORTED_PLATFORM",
            Self::ObserverUnavailable => "EVIDENTRAIL_BENCH_RSS_OBSERVER_UNAVAILABLE",
            Self::ObserverCanonicalPathMismatch => {
                "EVIDENTRAIL_BENCH_RSS_OBSERVER_CANONICAL_PATH_MISMATCH"
            }
            Self::ObserverNotRegularFile => "EVIDENTRAIL_BENCH_RSS_OBSERVER_NOT_REGULAR_FILE",
            Self::ObserverChanged => "EVIDENTRAIL_BENCH_RSS_OBSERVER_CHANGED",
            Self::ObservationBindingMismatch => "EVIDENTRAIL_BENCH_RSS_OBSERVER_BINDING_MISMATCH",
            Self::TemporaryDirectoryUnavailable => {
                "EVIDENTRAIL_BENCH_RSS_OBSERVER_TEMP_DIRECTORY_UNAVAILABLE"
            }
            Self::TemporaryDirectoryCreateFailed => {
                "EVIDENTRAIL_BENCH_RSS_OBSERVER_TEMP_DIRECTORY_CREATE_FAILED"
            }
            Self::TemporaryReportCreateFailed => {
                "EVIDENTRAIL_BENCH_RSS_OBSERVER_TEMP_REPORT_CREATE_FAILED"
            }
            Self::TemporaryReportNotRegularFile => {
                "EVIDENTRAIL_BENCH_RSS_OBSERVER_TEMP_REPORT_NOT_REGULAR_FILE"
            }
            Self::TemporaryReportPermissionsInvalid => {
                "EVIDENTRAIL_BENCH_RSS_OBSERVER_TEMP_REPORT_PERMISSIONS_INVALID"
            }
            Self::TemporaryReportTooLarge => "EVIDENTRAIL_BENCH_RSS_OBSERVER_TEMP_REPORT_TOO_LARGE",
            Self::TemporaryReportReadFailed => "EVIDENTRAIL_BENCH_RSS_OBSERVER_TEMP_REPORT_READ_FAILED",
            Self::TemporaryReportCleanupFailed => {
                "EVIDENTRAIL_BENCH_RSS_OBSERVER_TEMP_REPORT_CLEANUP_FAILED"
            }
            Self::ReportEncodingInvalid => "EVIDENTRAIL_BENCH_RSS_OBSERVER_REPORT_ENCODING_INVALID",
            Self::MetricMissing => "EVIDENTRAIL_BENCH_RSS_OBSERVER_METRIC_MISSING",
            Self::MetricDuplicate => "EVIDENTRAIL_BENCH_RSS_OBSERVER_METRIC_DUPLICATE",
            Self::MetricMalformed => "EVIDENTRAIL_BENCH_RSS_OBSERVER_METRIC_MALFORMED",
            Self::MetricZero => "EVIDENTRAIL_BENCH_RSS_OBSERVER_METRIC_ZERO",
            Self::MetricOverflow => "EVIDENTRAIL_BENCH_RSS_OBSERVER_METRIC_OVERFLOW",
            Self::ObservationConstructionFailed => {
                "EVIDENTRAIL_BENCH_RSS_OBSERVER_OBSERVATION_CONSTRUCTION_FAILED"
            }
            Self::ArtifactLengthOverflow => "EVIDENTRAIL_BENCH_RSS_OBSERVER_ARTIFACT_LENGTH_OVERFLOW",
            Self::Harness(error) => error.code(),
        }
    }
}

impl fmt::Debug for PeakRssObserverErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeakRssObserverErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for PeakRssObserverErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for PeakRssObserverErrorV1 {}

impl From<HarnessError> for PeakRssObserverErrorV1 {
    fn from(error: HarnessError) -> Self {
        Self::Harness(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn parser_accepts_exact_single_nonzero_metric_among_known_noise() {
        let report = b" 0.01 real 0.00 user 0.00 sys\n  1409024  maximum resident set size\n  3 voluntary context switches\n";
        assert_eq!(parse_macos_time_l_peak_rss_v1(report), Ok(1_409_024));
    }

    #[test]
    fn parser_rejects_missing_duplicate_and_ambiguous_metrics() {
        assert_eq!(
            parse_macos_time_l_peak_rss_v1(b"1 page reclaims\n"),
            Err(PeakRssObserverErrorV1::MetricMissing)
        );
        assert_eq!(
            parse_macos_time_l_peak_rss_v1(
                b"1 maximum resident set size\n2 maximum resident set size\n"
            ),
            Err(PeakRssObserverErrorV1::MetricDuplicate)
        );
        assert_eq!(
            parse_macos_time_l_peak_rss_v1(b"1 maximum resident set size unexpected\n"),
            Err(PeakRssObserverErrorV1::MetricMalformed)
        );
    }

    #[test]
    fn parser_rejects_negative_zero_malformed_overflow_and_invalid_utf8() {
        for report in [
            b"-1 maximum resident set size\n".as_slice(),
            b"+1 maximum resident set size\n",
            b"1.0 maximum resident set size\n",
        ] {
            assert_eq!(
                parse_macos_time_l_peak_rss_v1(report),
                Err(PeakRssObserverErrorV1::MetricMalformed)
            );
        }
        assert_eq!(
            parse_macos_time_l_peak_rss_v1(b"0 maximum resident set size\n"),
            Err(PeakRssObserverErrorV1::MetricZero)
        );
        assert_eq!(
            parse_macos_time_l_peak_rss_v1(b"18446744073709551616 maximum resident set size\n"),
            Err(PeakRssObserverErrorV1::MetricOverflow)
        );
        assert_eq!(
            parse_macos_time_l_peak_rss_v1(b"\xff maximum resident set size\n"),
            Err(PeakRssObserverErrorV1::ReportEncodingInvalid)
        );
    }

    #[cfg(unix)]
    #[test]
    fn secure_report_is_private_bounded_and_removed_exactly() {
        let report = SecureReportFileV1::create().unwrap();
        let directory = report.directory.clone();
        let path = report.path.clone();
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        report.read_and_cleanup().unwrap();
        assert!(!path.exists());
        assert!(!directory.exists());
    }

    #[cfg(unix)]
    #[test]
    fn secure_report_rejects_oversize_and_permission_mutation_then_cleans() {
        let report = SecureReportFileV1::create().unwrap();
        let directory = report.directory.clone();
        let path = report.path.clone();
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap()
            .write_all(&vec![
                b'x';
                usize::try_from(MAX_REPORT_BYTES_V1).unwrap() + 1
            ])
            .unwrap();
        assert_eq!(
            report.read_and_cleanup(),
            Err(PeakRssObserverErrorV1::TemporaryReportTooLarge)
        );
        assert!(!path.exists());
        assert!(!directory.exists());

        let report = SecureReportFileV1::create().unwrap();
        let directory = report.directory.clone();
        let path = report.path.clone();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            report.read_and_cleanup(),
            Err(PeakRssObserverErrorV1::TemporaryReportPermissionsInvalid)
        );
        assert!(!path.exists());
        assert!(!directory.exists());
    }

    #[test]
    fn mechanism_identity_binds_observer_build_and_format() {
        let build = ArtifactDigest::from_bytes([0x11; 32]);
        let format = ArtifactDigest::from_bytes([0x22; 32]);
        let baseline = derive_mechanism_artifact_digest_v1(build, format).unwrap();
        assert_eq!(
            baseline,
            derive_mechanism_artifact_digest_v1(build, format).unwrap()
        );
        assert_ne!(
            baseline,
            derive_mechanism_artifact_digest_v1(ArtifactDigest::from_bytes([0x12; 32]), format)
                .unwrap()
        );
        assert_ne!(
            baseline,
            derive_mechanism_artifact_digest_v1(build, ArtifactDigest::from_bytes([0x23; 32]))
                .unwrap()
        );
    }

    #[test]
    fn diagnostics_are_contentless() {
        let error = PeakRssObserverErrorV1::MetricMalformed;
        let debug = format!("{error:?}");
        assert_eq!(error.to_string(), error.code());
        assert!(!debug.contains(MACOS_TIME_PATH_V1));
        assert!(!debug.contains("maximum resident"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn system_observer_pins_exact_path_build_and_versioned_format() {
        let observer = MacOsTimePeakRssObserverV1::try_system_v1().unwrap();
        assert_eq!(observer.canonical_path(), Path::new(MACOS_TIME_PATH_V1));
        assert_eq!(
            observer.executable_build_artifact_digest(),
            artifact_digest_for_file_v1(Path::new(MACOS_TIME_PATH_V1)).unwrap()
        );
        assert_eq!(
            observer.contract_version(),
            MACOS_TIME_L_PEAK_RSS_OBSERVER_CONTRACT_VERSION_V1
        );
        assert_eq!(
            observer.report_format_version(),
            MACOS_TIME_L_PEAK_RSS_REPORT_FORMAT_VERSION_V1
        );
        assert!(observer.directly_timed_process_only());
        assert!(!observer.child_tree_peak_rss_claimed());
        assert!(!observer.independently_attested());
        let debug = format!("{observer:?}");
        assert!(!debug.contains(MACOS_TIME_PATH_V1));
    }
}
