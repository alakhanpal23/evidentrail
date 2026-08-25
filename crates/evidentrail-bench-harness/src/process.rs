use std::ffi::OsString;
use std::fmt;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt as _;

use evidentrail_bench::BenchmarkRunIdentityV1;
use evidentrail_schema::ArtifactDigest;

use crate::{
    ExecutableBuildV1, ExternalOutputContractV1, HarnessError, HarnessLimitsV1, InvocationDigestV1,
    PublicCaseResolutionTrustV1, PublicSubprocessInvocationV1, artifact_digest_for_bytes_v1,
    artifact_digest_for_file_v1,
};

const STREAM_ACTIVE: u8 = 0;
const STREAM_CAP_REACHED: u8 = 1;
const STREAM_READ_FAILED: u8 = 2;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StreamCaptureStateV1 {
    Complete,
    TruncatedAtCap,
    ReadFailed,
}

impl StreamCaptureStateV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::TruncatedAtCap => "truncated_at_cap",
            Self::ReadFailed => "read_failed",
        }
    }
}

impl fmt::Debug for StreamCaptureStateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StreamCaptureStateV1")
            .field("code", &self.code())
            .finish()
    }
}

/// A bounded byte-for-byte child stream capture.
///
/// `artifact_digest` always identifies exactly `bytes`. When the state is
/// truncated or failed, it identifies only the retained prefix and must not be
/// represented as the complete raw child stream.
#[derive(Clone, PartialEq, Eq)]
pub struct CapturedStreamV1 {
    bytes: Box<[u8]>,
    artifact_digest: ArtifactDigest,
    state: StreamCaptureStateV1,
}

impl CapturedStreamV1 {
    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn byte_count(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn state(&self) -> StreamCaptureStateV1 {
        self.state
    }

    #[must_use]
    pub const fn complete_artifact_digest(&self) -> Option<ArtifactDigest> {
        match self.state {
            StreamCaptureStateV1::Complete => Some(self.artifact_digest),
            StreamCaptureStateV1::TruncatedAtCap | StreamCaptureStateV1::ReadFailed => None,
        }
    }
}

impl fmt::Debug for CapturedStreamV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturedStreamV1")
            .field("byte_count", &self.bytes.len())
            .field("artifact_identity_present", &true)
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StdinDeliveryV1 {
    Complete,
    Incomplete,
}

impl StdinDeliveryV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Incomplete => "incomplete",
        }
    }
}

impl fmt::Debug for StdinDeliveryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StdinDeliveryV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HarnessTerminationCauseV1 {
    WallDeadline,
    StdoutByteCap,
    StderrByteCap,
    StdoutReadFailure,
    StderrReadFailure,
}

impl HarnessTerminationCauseV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::WallDeadline => "wall_deadline",
            Self::StdoutByteCap => "stdout_byte_cap",
            Self::StderrByteCap => "stderr_byte_cap",
            Self::StdoutReadFailure => "stdout_read_failure",
            Self::StderrReadFailure => "stderr_read_failure",
        }
    }
}

impl fmt::Debug for HarnessTerminationCauseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HarnessTerminationCauseV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ExitCategoryV1 {
    Success,
    Nonzero { code: i32 },
    Signaled { signal: Option<i32> },
    HarnessTerminated,
}

impl ExitCategoryV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Nonzero { .. } => "nonzero",
            Self::Signaled { .. } => "signaled",
            Self::HarnessTerminated => "harness_terminated",
        }
    }
}

impl fmt::Debug for ExitCategoryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("ExitCategoryV1");
        debug.field("code", &self.code());
        match self {
            Self::Nonzero { code } => {
                debug.field("exit_code", code);
            }
            Self::Signaled { signal } => {
                debug.field("signal", signal);
            }
            Self::Success | Self::HarnessTerminated => {}
        }
        debug.finish()
    }
}

/// Reaped child outcome plus exact bounded stream artifacts.
///
/// Executable verification is deliberately described as pre/post path hashing.
/// It is useful self-asserted reproducibility evidence, but is not attestation
/// and does not prove safety against a hostile path-replacement race.
#[derive(Clone, PartialEq, Eq)]
pub struct SubprocessExecutionReceiptV1 {
    invocation_digest: InvocationDigestV1,
    run_manifest_artifact_digest: ArtifactDigest,
    run_identity: BenchmarkRunIdentityV1,
    public_case_artifact_digest: ArtifactDigest,
    case_resolution_trust: PublicCaseResolutionTrustV1,
    stdin_artifact_digest: ArtifactDigest,
    output_contract: ExternalOutputContractV1,
    wall_time_nanos: u64,
    stdin_delivery: StdinDeliveryV1,
    exit_category: ExitCategoryV1,
    stdout: CapturedStreamV1,
    stderr: CapturedStreamV1,
    termination_causes: Vec<HarnessTerminationCauseV1>,
    child_reaped: bool,
    executable_path_digest_verified_before_spawn: bool,
    executable_path_digest_verified_after_spawn: bool,
}

impl SubprocessExecutionReceiptV1 {
    #[must_use]
    pub const fn invocation_digest(&self) -> InvocationDigestV1 {
        self.invocation_digest
    }

    #[must_use]
    pub const fn run_manifest_artifact_digest(&self) -> ArtifactDigest {
        self.run_manifest_artifact_digest
    }

    #[must_use]
    pub const fn run_identity(&self) -> BenchmarkRunIdentityV1 {
        self.run_identity
    }

    #[must_use]
    pub const fn public_case_artifact_digest(&self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn case_resolution_trust(&self) -> PublicCaseResolutionTrustV1 {
        self.case_resolution_trust
    }

    #[must_use]
    pub const fn stdin_artifact_digest(&self) -> ArtifactDigest {
        self.stdin_artifact_digest
    }

    #[must_use]
    pub const fn output_contract(&self) -> ExternalOutputContractV1 {
        self.output_contract
    }

    #[must_use]
    pub const fn wall_time_nanos(&self) -> u64 {
        self.wall_time_nanos
    }

    #[must_use]
    pub const fn stdin_delivery(&self) -> StdinDeliveryV1 {
        self.stdin_delivery
    }

    #[must_use]
    pub const fn exit_category(&self) -> ExitCategoryV1 {
        self.exit_category
    }

    #[must_use]
    pub const fn stdout(&self) -> &CapturedStreamV1 {
        &self.stdout
    }

    #[must_use]
    pub const fn stderr(&self) -> &CapturedStreamV1 {
        &self.stderr
    }

    #[must_use]
    pub fn termination_causes(&self) -> &[HarnessTerminationCauseV1] {
        &self.termination_causes
    }

    #[must_use]
    pub const fn child_reaped(&self) -> bool {
        self.child_reaped
    }

    #[must_use]
    pub const fn executable_path_digest_verified_before_spawn(&self) -> bool {
        self.executable_path_digest_verified_before_spawn
    }

    #[must_use]
    pub const fn executable_path_digest_verified_after_spawn(&self) -> bool {
        self.executable_path_digest_verified_after_spawn
    }
}

impl fmt::Debug for SubprocessExecutionReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubprocessExecutionReceiptV1")
            .field("invocation_binding_present", &true)
            .field("run_manifest_binding_present", &true)
            .field("run_identity", &self.run_identity)
            .field("public_case_binding_present", &true)
            .field("case_resolution_trust", &self.case_resolution_trust)
            .field("stdin_artifact_binding_present", &true)
            .field("output_contract", &self.output_contract)
            .field("wall_time_nanos", &self.wall_time_nanos)
            .field("stdin_delivery", &self.stdin_delivery)
            .field("exit_category", &self.exit_category)
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .field("termination_causes", &self.termination_causes)
            .field("child_reaped", &self.child_reaped)
            .field(
                "pre_spawn_path_digest_verified",
                &self.executable_path_digest_verified_before_spawn,
            )
            .field(
                "post_spawn_path_digest_verified",
                &self.executable_path_digest_verified_after_spawn,
            )
            .field("executable_identity_is_attestation", &false)
            .field("contains_governed_labels", &false)
            .finish()
    }
}

/// Crate-private process input shared by public benchmark arms and the
/// benchmark-only reader boundary. It carries no governed labels and performs
/// no case interpretation.
pub(crate) struct RawSubprocessSpecV1<'spec> {
    pub(crate) program: &'spec ExecutableBuildV1,
    pub(crate) stdin_bytes: &'spec [u8],
    pub(crate) limits: HarnessLimitsV1,
}

/// Crate-private byte-exact process outcome before a domain-specific receipt
/// adds case, method, or invocation bindings.
pub(crate) struct RawSubprocessExecutionV1 {
    pub(crate) wall_time_nanos: u64,
    pub(crate) stdin_delivery: StdinDeliveryV1,
    pub(crate) exit_category: ExitCategoryV1,
    pub(crate) stdout: CapturedStreamV1,
    pub(crate) stderr: CapturedStreamV1,
    pub(crate) termination_causes: Vec<HarnessTerminationCauseV1>,
    pub(crate) child_reaped: bool,
    pub(crate) executable_path_digest_verified_before_spawn: bool,
    pub(crate) executable_path_digest_verified_after_spawn: bool,
}

/// Execute one public invocation without a shell, ambient environment, or
/// unbounded child stream. Every spawned child is waited on, including timeout
/// and stream-cap termination paths.
pub fn execute_public_subprocess_v1(
    invocation: &PublicSubprocessInvocationV1,
) -> Result<SubprocessExecutionReceiptV1, HarnessError> {
    execute_public_subprocess_impl(invocation, None)
}

pub(crate) struct SubprocessWrapperV1<'wrapper> {
    pub(crate) executable_path: &'wrapper Path,
    pub(crate) argv: &'wrapper [OsString],
}

fn execute_public_subprocess_impl(
    invocation: &PublicSubprocessInvocationV1,
    wrapper: Option<SubprocessWrapperV1<'_>>,
) -> Result<SubprocessExecutionReceiptV1, HarnessError> {
    let raw = execute_raw_subprocess_impl(
        RawSubprocessSpecV1 {
            program: invocation.program(),
            stdin_bytes: invocation.stdin().bytes(),
            limits: invocation.limits(),
        },
        wrapper,
    )?;
    Ok(public_receipt_from_raw_v1(invocation, raw))
}

pub(crate) fn execute_wrapped_raw_subprocess_v1(
    spec: RawSubprocessSpecV1<'_>,
    wrapper: SubprocessWrapperV1<'_>,
) -> Result<RawSubprocessExecutionV1, HarnessError> {
    execute_raw_subprocess_impl(spec, Some(wrapper))
}

pub(crate) fn public_receipt_from_raw_v1(
    invocation: &PublicSubprocessInvocationV1,
    raw: RawSubprocessExecutionV1,
) -> SubprocessExecutionReceiptV1 {
    SubprocessExecutionReceiptV1 {
        invocation_digest: invocation.digest(),
        run_manifest_artifact_digest: invocation.run_manifest_artifact_digest(),
        run_identity: invocation.run_identity(),
        public_case_artifact_digest: invocation.public_case_artifact_digest(),
        case_resolution_trust: invocation.case_resolution_trust(),
        stdin_artifact_digest: invocation.stdin().artifact_digest(),
        output_contract: invocation.program().output_contract(),
        wall_time_nanos: raw.wall_time_nanos,
        stdin_delivery: raw.stdin_delivery,
        exit_category: raw.exit_category,
        stdout: raw.stdout,
        stderr: raw.stderr,
        termination_causes: raw.termination_causes,
        child_reaped: raw.child_reaped,
        executable_path_digest_verified_before_spawn: raw
            .executable_path_digest_verified_before_spawn,
        executable_path_digest_verified_after_spawn: raw
            .executable_path_digest_verified_after_spawn,
    }
}

fn execute_raw_subprocess_impl(
    spec: RawSubprocessSpecV1<'_>,
    wrapper: Option<SubprocessWrapperV1<'_>>,
) -> Result<RawSubprocessExecutionV1, HarnessError> {
    let stdout_cap = usize::try_from(spec.limits.stdout_bytes())
        .map_err(|_| HarnessError::ArtifactLengthOverflow)?;
    let stderr_cap = usize::try_from(spec.limits.stderr_bytes())
        .map_err(|_| HarnessError::ArtifactLengthOverflow)?;
    if !spec.program.cwd().is_dir() {
        return Err(HarnessError::WorkingDirectoryUnavailable);
    }
    let expected_build = spec.program.executable_build_artifact_digest();
    let before = artifact_digest_for_file_v1(spec.program.executable_path())?;
    if before != expected_build {
        return Err(HarnessError::ExecutableArtifactDigestMismatch);
    }

    let process_group = wrapper.is_some();
    let mut command = match wrapper {
        Some(wrapper) => {
            let mut command = Command::new(wrapper.executable_path);
            command
                .args(wrapper.argv)
                .arg(spec.program.executable_path())
                .args(spec.program.argv());
            #[cfg(unix)]
            command.process_group(0);
            command
        }
        None => {
            let mut command = Command::new(spec.program.executable_path());
            command.args(spec.program.argv());
            command
        }
    };
    command
        .current_dir(spec.program.cwd())
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for binding in spec.program.environment().bindings() {
        command.env(binding.name(), binding.value());
    }

    let started = Instant::now();
    let mut child = command.spawn().map_err(|_| HarnessError::SpawnFailed)?;
    let after = artifact_digest_for_file_v1(spec.program.executable_path());
    if after != Ok(expected_build) {
        force_kill_and_reap(&mut child, process_group)?;
        return Err(HarnessError::ExecutableChangedDuringSpawn);
    }

    let Some(child_stdin) = child.stdin.take() else {
        force_kill_and_reap(&mut child, process_group)?;
        return Err(HarnessError::MissingChildPipe);
    };
    let Some(child_stdout) = child.stdout.take() else {
        drop(child_stdin);
        force_kill_and_reap(&mut child, process_group)?;
        return Err(HarnessError::MissingChildPipe);
    };
    let Some(child_stderr) = child.stderr.take() else {
        drop(child_stdin);
        drop(child_stdout);
        force_kill_and_reap(&mut child, process_group)?;
        return Err(HarnessError::MissingChildPipe);
    };

    let stdin_bytes = spec.stdin_bytes.to_vec();
    let stdin_worker = thread::spawn(move || write_stdin(child_stdin, &stdin_bytes));

    let stdout_signal = Arc::new(AtomicU8::new(STREAM_ACTIVE));
    let stderr_signal = Arc::new(AtomicU8::new(STREAM_ACTIVE));
    let stdout_worker = spawn_capture_worker(child_stdout, stdout_cap, Arc::clone(&stdout_signal));
    let stderr_worker = spawn_capture_worker(child_stderr, stderr_cap, Arc::clone(&stderr_signal));

    let deadline = Duration::from_nanos(spec.limits.wall_nanos());
    let mut termination_causes = Vec::new();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(_) => {
                force_kill_and_reap(&mut child, process_group)?;
                join_workers_after_cleanup(stdin_worker, stdout_worker, stderr_worker)?;
                return Err(HarnessError::ChildStatusFailed);
            }
        }
        append_stream_cause(
            stdout_signal.load(Ordering::Acquire),
            HarnessTerminationCauseV1::StdoutByteCap,
            HarnessTerminationCauseV1::StdoutReadFailure,
            &mut termination_causes,
        );
        append_stream_cause(
            stderr_signal.load(Ordering::Acquire),
            HarnessTerminationCauseV1::StderrByteCap,
            HarnessTerminationCauseV1::StderrReadFailure,
            &mut termination_causes,
        );
        if started.elapsed() >= deadline {
            termination_causes.push(HarnessTerminationCauseV1::WallDeadline);
        }
        if !termination_causes.is_empty() {
            break force_kill_and_reap(&mut child, process_group)?;
        }
        thread::sleep(Duration::from_millis(1));
    };

    let stdin_delivery = stdin_worker
        .join()
        .map_err(|_| HarnessError::WorkerThreadFailed)?;
    let stdout = stdout_worker
        .join()
        .map_err(|_| HarnessError::WorkerThreadFailed)?;
    let stderr = stderr_worker
        .join()
        .map_err(|_| HarnessError::WorkerThreadFailed)?;

    append_capture_cause(
        stdout.state,
        HarnessTerminationCauseV1::StdoutByteCap,
        HarnessTerminationCauseV1::StdoutReadFailure,
        &mut termination_causes,
    );
    append_capture_cause(
        stderr.state,
        HarnessTerminationCauseV1::StderrByteCap,
        HarnessTerminationCauseV1::StderrReadFailure,
        &mut termination_causes,
    );
    termination_causes.sort_unstable();
    termination_causes.dedup();

    // A process may exit between the final poll and a cap signal. It has still
    // been reaped, and a bounded/truncated stream remains a harness-terminated
    // result even if no explicit kill was necessary.
    let exit_category = if termination_causes.is_empty() {
        classify_exit(status)
    } else {
        ExitCategoryV1::HarnessTerminated
    };
    let wall_time_nanos =
        u64::try_from(started.elapsed().as_nanos()).map_err(|_| HarnessError::WallTimeOverflow)?;

    Ok(RawSubprocessExecutionV1 {
        wall_time_nanos,
        stdin_delivery,
        exit_category,
        stdout,
        stderr,
        termination_causes,
        child_reaped: true,
        executable_path_digest_verified_before_spawn: true,
        executable_path_digest_verified_after_spawn: true,
    })
}

fn write_stdin(mut stdin: impl Write, bytes: &[u8]) -> StdinDeliveryV1 {
    if stdin.write_all(bytes).is_ok() && stdin.flush().is_ok() {
        StdinDeliveryV1::Complete
    } else {
        StdinDeliveryV1::Incomplete
    }
}

fn spawn_capture_worker<R>(
    reader: R,
    cap: usize,
    signal: Arc<AtomicU8>,
) -> thread::JoinHandle<CapturedStreamV1>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || capture_stream(reader, cap, &signal))
}

fn capture_stream(mut reader: impl Read, cap: usize, signal: &AtomicU8) -> CapturedStreamV1 {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8 * 1024];
    let state = loop {
        match reader.read(&mut buffer) {
            Ok(0) => break StreamCaptureStateV1::Complete,
            Ok(read) => {
                let remaining = cap.saturating_sub(bytes.len());
                let retained = read.min(remaining);
                bytes.extend_from_slice(&buffer[..retained]);
                if retained < read {
                    signal.store(STREAM_CAP_REACHED, Ordering::Release);
                    break StreamCaptureStateV1::TruncatedAtCap;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                signal.store(STREAM_READ_FAILED, Ordering::Release);
                break StreamCaptureStateV1::ReadFailed;
            }
        }
    };
    CapturedStreamV1 {
        artifact_digest: artifact_digest_for_bytes_v1(&bytes),
        bytes: bytes.into_boxed_slice(),
        state,
    }
}

fn append_stream_cause(
    state: u8,
    cap: HarnessTerminationCauseV1,
    read: HarnessTerminationCauseV1,
    causes: &mut Vec<HarnessTerminationCauseV1>,
) {
    match state {
        STREAM_CAP_REACHED => causes.push(cap),
        STREAM_READ_FAILED => causes.push(read),
        _ => {}
    }
}

fn append_capture_cause(
    state: StreamCaptureStateV1,
    cap: HarnessTerminationCauseV1,
    read: HarnessTerminationCauseV1,
    causes: &mut Vec<HarnessTerminationCauseV1>,
) {
    match state {
        StreamCaptureStateV1::Complete => {}
        StreamCaptureStateV1::TruncatedAtCap => causes.push(cap),
        StreamCaptureStateV1::ReadFailed => causes.push(read),
    }
}

fn force_kill_and_reap(
    child: &mut std::process::Child,
    process_group: bool,
) -> Result<ExitStatus, HarnessError> {
    // `kill` can legitimately race with a natural exit. The authoritative
    // cleanup result is the unconditional `wait`, which reaps either way.
    let process_group_termination_confirmed = request_termination(child, process_group);
    let status = child
        .wait()
        .map_err(|_| HarnessError::ChildTerminationFailed)?;
    if !process_group_termination_confirmed {
        return Err(HarnessError::ChildTerminationFailed);
    }
    Ok(status)
}

#[cfg(unix)]
fn request_termination(child: &mut std::process::Child, process_group: bool) -> bool {
    if process_group {
        // The wrapped process is placed in a fresh process group before spawn.
        // A safe syscall wrapper sends SIGKILL to the whole group so a timeout
        // cannot reap only `/usr/bin/time` while orphaning its timed target. A
        // natural-exit race is accepted; the unconditional wait below remains
        // the authoritative wrapper reap.
        let pid = rustix::process::Pid::from_child(child);
        match rustix::process::kill_process_group(pid, rustix::process::Signal::KILL) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => return true,
            Err(_) => {
                let _ = child.kill();
                return false;
            }
        }
    }
    let _ = child.kill();
    true
}

#[cfg(not(unix))]
fn request_termination(child: &mut std::process::Child, _process_group: bool) -> bool {
    let _ = child.kill();
    true
}

fn join_workers_after_cleanup(
    stdin_worker: thread::JoinHandle<StdinDeliveryV1>,
    stdout_worker: thread::JoinHandle<CapturedStreamV1>,
    stderr_worker: thread::JoinHandle<CapturedStreamV1>,
) -> Result<(), HarnessError> {
    stdin_worker
        .join()
        .map_err(|_| HarnessError::WorkerThreadFailed)?;
    stdout_worker
        .join()
        .map_err(|_| HarnessError::WorkerThreadFailed)?;
    stderr_worker
        .join()
        .map_err(|_| HarnessError::WorkerThreadFailed)?;
    Ok(())
}

fn classify_exit(status: ExitStatus) -> ExitCategoryV1 {
    if status.success() {
        return ExitCategoryV1::Success;
    }
    if let Some(code) = status.code() {
        return ExitCategoryV1::Nonzero { code };
    }
    ExitCategoryV1::Signaled {
        signal: platform_signal(&status),
    }
}

#[cfg(unix)]
fn platform_signal(status: &ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt as _;
    status.signal()
}

#[cfg(not(unix))]
fn platform_signal(_status: &ExitStatus) -> Option<i32> {
    None
}
