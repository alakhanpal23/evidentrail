use std::error::Error as StdError;
use std::fmt;
use std::path::{Path, PathBuf};

use evidentrail_bench::{EvidentrailBenchRunManifestV1, MeasurementTrustBoundaryV1};
use evidentrail_schema::ArtifactDigest;

use crate::constrained_matched_case::{
    CONSTRAINED_MATCHED_INPUT_ARTIFACT_DIGEST_V1, constrained_pinned_drain_public_input_v1,
};
use crate::peak_rss_observer::execute_with_macos_time_peak_rss_v1;
use crate::pinned_matched_case::{
    FirstPartyInProcessBuildV1, MatchedExecutionScopeV1, PeakRssObservationBindingV1,
    PreparedPinnedDrainMatchedCaseErrorV1,
};
use crate::{
    ClosedEnvironmentV1, ExecutableBuildV1, ExternalOutputContractV1, HarnessError,
    HarnessLimitsV1, InvocationInputContractV1, MacOsTimePeakRssObserverV1,
    MacOsTimePeakRssReceiptV1, PeakRssObserverErrorV1, PublicCaseInputBindingV1,
    PublicSubprocessInvocationV1, StrictNormalizedExternalOutputV1, SubprocessExecutionReceiptV1,
    artifact_digest_for_bytes_v1, artifact_digest_for_file_v1, strict_identity_normalize_v1,
};

pub const FIRST_PARTY_CONSTRAINED_SUBPROCESS_ADAPTER_CONTRACT_VERSION_V1: u16 = 2;

const HELPER_MODE_V1: &str = "--evidentrail-bench-first-party-constrained-v1";
const ADAPTER_REVISION_V1: &str = "evidentrail-first-party-constrained-subprocess-v2";
const ADAPTER_CONTRACT_V1: &[u8] = b"evidentrail/bench-harness/first-party-constrained-subprocess-adapter/v2\0argv=--evidentrail-bench-first-party-constrained-v1\0shell=false\0environment=cleared\0input=frozen-raw-public-stdin\0output=owned-canonical-product-render\0parent-oracle=byte-exact\0scope=raw-public-stdin-through-captured-process-output\0peak-rss=required-common-macos-time-l-observer";
const SYSTEM_MANIFEST_V1: &[u8] = b"evidentrail/bench-harness/first-party-constrained-subprocess-system/v2\0actual-memory-product=true\0adapter-contract=v2\0self-asserted-reproducibility=true";
const RECEIPT_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/first-party-constrained-subprocess-receipt/v2";

/// Peak-RSS state of the constrained first-party process envelope.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FirstPartySubprocessPeakRssStateV1 {
    UnavailableNeedsPinnedCommonObserver,
    ObservedMacOsTimeLDirectProcess,
}

impl FirstPartySubprocessPeakRssStateV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnavailableNeedsPinnedCommonObserver => {
                "unavailable_needs_pinned_common_observer"
            }
            Self::ObservedMacOsTimeLDirectProcess => "observed_macos_time_l_direct_process",
        }
    }
}

impl fmt::Debug for FirstPartySubprocessPeakRssStateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirstPartySubprocessPeakRssStateV1")
            .field("code", &self.code())
            .finish()
    }
}

/// The parent oracle is a second actual product call whose owned render was
/// validated before child admission. The helper build hash identifies only
/// the child; it does not attest the bytes executed by the parent process.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FirstPartyOracleTrustV1 {
    ParentExecutablePathHashBoundNotAttested,
}

impl FirstPartyOracleTrustV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ParentExecutablePathHashBoundNotAttested => {
                "parent_executable_path_hash_bound_not_attested"
            }
        }
    }
}

/// Pre/post path-hash binding for the caller process that independently owns
/// and validates the parent oracle render. This is exact local reproducibility
/// evidence for that executable file, not process or dependency attestation.
#[derive(Clone, PartialEq, Eq)]
pub struct FirstPartyParentOracleBuildV1 {
    executable_path: PathBuf,
    executable_build_artifact_digest: ArtifactDigest,
}

impl FirstPartyParentOracleBuildV1 {
    pub(crate) fn capture_current_process_v1()
    -> Result<Self, FirstPartyConstrainedSubprocessErrorV1> {
        let executable_path = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .map_err(|_| FirstPartyConstrainedSubprocessErrorV1::OracleExecutableUnavailable)?;
        let executable_build_artifact_digest = artifact_digest_for_file_v1(&executable_path)?;
        Ok(Self {
            executable_path,
            executable_build_artifact_digest,
        })
    }

    pub(crate) fn reverify(&self) -> Result<(), FirstPartyConstrainedSubprocessErrorV1> {
        if artifact_digest_for_file_v1(&self.executable_path)?
            != self.executable_build_artifact_digest
        {
            return Err(FirstPartyConstrainedSubprocessErrorV1::OracleExecutableChanged);
        }
        Ok(())
    }

    #[must_use]
    pub const fn executable_build_artifact_digest(&self) -> ArtifactDigest {
        self.executable_build_artifact_digest
    }
}

impl fmt::Debug for FirstPartyParentOracleBuildV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirstPartyParentOracleBuildV1")
            .field("executable_build_artifact_bound", &true)
            .field("path_redacted", &true)
            .field("independently_attested", &false)
            .finish()
    }
}

impl fmt::Debug for FirstPartyOracleTrustV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirstPartyOracleTrustV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Exact local helper build/cwd used for the first-party subprocess arm.
///
/// Path hashes are self-asserted reproducibility evidence. They are not
/// immutable-executable attestation and do not close a hostile replacement
/// race.
#[derive(Clone, PartialEq, Eq)]
pub struct FirstPartyConstrainedSubprocessTargetV1 {
    executable_path: PathBuf,
    cwd: PathBuf,
    system_artifact_digest: ArtifactDigest,
    executable_build_artifact_digest: ArtifactDigest,
    adapter_contract_artifact_digest: ArtifactDigest,
}

impl FirstPartyConstrainedSubprocessTargetV1 {
    pub fn try_new(
        executable_path: impl AsRef<Path>,
        cwd: impl AsRef<Path>,
    ) -> Result<Self, FirstPartyConstrainedSubprocessErrorV1> {
        let executable_path = executable_path
            .as_ref()
            .canonicalize()
            .map_err(|_| FirstPartyConstrainedSubprocessErrorV1::TargetUnavailable)?;
        let cwd = cwd
            .as_ref()
            .canonicalize()
            .map_err(|_| FirstPartyConstrainedSubprocessErrorV1::WorkingDirectoryUnavailable)?;
        if !cwd.is_dir() {
            return Err(FirstPartyConstrainedSubprocessErrorV1::WorkingDirectoryUnavailable);
        }
        let executable_build_artifact_digest = artifact_digest_for_file_v1(&executable_path)?;
        Ok(Self {
            executable_path,
            cwd,
            system_artifact_digest: artifact_digest_for_bytes_v1(SYSTEM_MANIFEST_V1),
            executable_build_artifact_digest,
            adapter_contract_artifact_digest: artifact_digest_for_bytes_v1(ADAPTER_CONTRACT_V1),
        })
    }

    #[must_use]
    pub const fn system_artifact_digest(&self) -> ArtifactDigest {
        self.system_artifact_digest
    }

    #[must_use]
    pub const fn executable_build_artifact_digest(&self) -> ArtifactDigest {
        self.executable_build_artifact_digest
    }

    #[must_use]
    pub const fn adapter_contract_artifact_digest(&self) -> ArtifactDigest {
        self.adapter_contract_artifact_digest
    }

    pub(crate) fn first_party_build(
        &self,
    ) -> Result<FirstPartyInProcessBuildV1, FirstPartyConstrainedSubprocessErrorV1> {
        FirstPartyInProcessBuildV1::try_new_with_system_artifact_digest(
            &self.executable_path,
            self.system_artifact_digest,
        )
        .map_err(Into::into)
    }

    fn reverify(&self) -> Result<(), FirstPartyConstrainedSubprocessErrorV1> {
        if artifact_digest_for_file_v1(&self.executable_path)?
            != self.executable_build_artifact_digest
        {
            return Err(FirstPartyConstrainedSubprocessErrorV1::ExecutableChanged);
        }
        Ok(())
    }

    fn exact_program(&self) -> Result<ExecutableBuildV1, FirstPartyConstrainedSubprocessErrorV1> {
        ExecutableBuildV1::try_new(
            self.system_artifact_digest,
            self.executable_build_artifact_digest,
            self.executable_path.clone(),
            vec![HELPER_MODE_V1.to_owned()],
            self.cwd.clone(),
            ClosedEnvironmentV1::empty(),
            ExternalOutputContractV1::ExactIdentityNormalizer,
            Some(ADAPTER_REVISION_V1.to_owned()),
        )
        .map_err(Into::into)
    }
}

impl fmt::Debug for FirstPartyConstrainedSubprocessTargetV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirstPartyConstrainedSubprocessTargetV1")
            .field("system_artifact_bound", &true)
            .field("executable_build_artifact_bound", &true)
            .field("adapter_contract_bound", &true)
            .field("paths_redacted", &true)
            .field("uses_shell", &false)
            .field("ambient_environment_cleared", &true)
            .field("independently_attested", &false)
            .finish()
    }
}

/// Frozen subprocess execution admitted only after the captured child stdout
/// exactly equals an independently produced and validated owned product render.
#[derive(Clone, PartialEq, Eq)]
pub struct FirstPartyConstrainedSubprocessReceiptV1 {
    artifact_digest: ArtifactDigest,
    adapter_contract_artifact_digest: ArtifactDigest,
    oracle_render_artifact_digest: ArtifactDigest,
    oracle_render_byte_count: u64,
    parent_oracle_build_artifact_digest: ArtifactDigest,
    invocation: PublicSubprocessInvocationV1,
    execution: SubprocessExecutionReceiptV1,
    peak_rss_observer_receipt: MacOsTimePeakRssReceiptV1,
    normalized: StrictNormalizedExternalOutputV1,
}

impl FirstPartyConstrainedSubprocessReceiptV1 {
    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn adapter_contract_artifact_digest(&self) -> ArtifactDigest {
        self.adapter_contract_artifact_digest
    }

    #[must_use]
    pub const fn oracle_render_artifact_digest(&self) -> ArtifactDigest {
        self.oracle_render_artifact_digest
    }

    #[must_use]
    pub const fn oracle_render_byte_count(&self) -> u64 {
        self.oracle_render_byte_count
    }

    #[must_use]
    pub const fn parent_oracle_build_artifact_digest(&self) -> ArtifactDigest {
        self.parent_oracle_build_artifact_digest
    }

    #[must_use]
    pub const fn invocation(&self) -> &PublicSubprocessInvocationV1 {
        &self.invocation
    }

    #[must_use]
    pub const fn execution(&self) -> &SubprocessExecutionReceiptV1 {
        &self.execution
    }

    #[must_use]
    pub const fn peak_rss_observer_receipt(&self) -> MacOsTimePeakRssReceiptV1 {
        self.peak_rss_observer_receipt
    }

    #[must_use]
    pub const fn normalized_output(&self) -> StrictNormalizedExternalOutputV1 {
        self.normalized
    }

    #[must_use]
    pub const fn system_artifact_digest(&self) -> ArtifactDigest {
        self.invocation.program().system_artifact_digest()
    }

    #[must_use]
    pub const fn executable_build_artifact_digest(&self) -> ArtifactDigest {
        self.invocation.program().executable_build_artifact_digest()
    }

    #[must_use]
    pub const fn run_manifest_artifact_digest(&self) -> ArtifactDigest {
        self.invocation.run_manifest_artifact_digest()
    }

    #[must_use]
    pub const fn public_case_artifact_digest(&self) -> ArtifactDigest {
        self.invocation.public_case_artifact_digest()
    }

    #[must_use]
    pub const fn stdin_artifact_digest(&self) -> ArtifactDigest {
        self.invocation.stdin().artifact_digest()
    }

    #[must_use]
    pub const fn captured_stdout_artifact_digest(&self) -> ArtifactDigest {
        self.execution.stdout().artifact_digest()
    }

    #[must_use]
    pub const fn execution_scope(&self) -> MatchedExecutionScopeV1 {
        MatchedExecutionScopeV1::RawPublicStdinToCapturedProcessOutput
    }

    #[must_use]
    pub const fn measurement_trust_boundary(&self) -> MeasurementTrustBoundaryV1 {
        MeasurementTrustBoundaryV1::SelfAssertedReproducibilityInput
    }

    #[must_use]
    pub const fn oracle_trust(&self) -> FirstPartyOracleTrustV1 {
        FirstPartyOracleTrustV1::ParentExecutablePathHashBoundNotAttested
    }

    #[must_use]
    pub const fn frozen_case_specific_reconstruction(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn peak_rss_state(&self) -> FirstPartySubprocessPeakRssStateV1 {
        FirstPartySubprocessPeakRssStateV1::ObservedMacOsTimeLDirectProcess
    }

    #[must_use]
    pub const fn contains_hidden_annotations(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn contains_scalar_outcome(&self) -> bool {
        false
    }

    pub fn verify_expected_render_v1(
        &self,
        expected: &[u8],
    ) -> Result<(), FirstPartyConstrainedSubprocessErrorV1> {
        if artifact_digest_for_bytes_v1(expected) != self.oracle_render_artifact_digest
            || u64::try_from(expected.len()).ok() != Some(self.oracle_render_byte_count)
            || self.execution.stdout().bytes() != expected
        {
            return Err(FirstPartyConstrainedSubprocessErrorV1::OutputMismatch);
        }
        Ok(())
    }

    pub fn verify_execution_scope_v1(
        &self,
        expected: MatchedExecutionScopeV1,
    ) -> Result<(), FirstPartyConstrainedSubprocessErrorV1> {
        if expected != self.execution_scope() {
            return Err(FirstPartyConstrainedSubprocessErrorV1::ExecutionScopeMismatch);
        }
        Ok(())
    }

    pub fn verify_adapter_contract_v1(
        &self,
        expected: ArtifactDigest,
    ) -> Result<(), FirstPartyConstrainedSubprocessErrorV1> {
        if expected != self.adapter_contract_artifact_digest {
            return Err(FirstPartyConstrainedSubprocessErrorV1::AdapterContractMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for FirstPartyConstrainedSubprocessReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirstPartyConstrainedSubprocessReceiptV1")
            .field("receipt_artifact_bound", &true)
            .field("adapter_contract_bound", &true)
            .field("helper_build_bound", &true)
            .field("run_case_input_bound", &true)
            .field("oracle_render_bound", &true)
            .field("parent_oracle_build_bound", &true)
            .field("captured_output_bound", &true)
            .field("execution_scope", &self.execution_scope())
            .field(
                "measurement_trust_boundary",
                &self.measurement_trust_boundary(),
            )
            .field("oracle_trust", &self.oracle_trust())
            .field("frozen_case_specific_reconstruction", &true)
            .field("peak_rss_state", &self.peak_rss_state())
            .field("peak_rss_observer", &self.peak_rss_observer_receipt)
            .field("contains_hidden_annotations", &false)
            .field("contains_scalar_outcome", &false)
            .finish()
    }
}

pub(crate) fn execute_and_freeze_constrained_first_party_subprocess_v1(
    manifest: &EvidentrailBenchRunManifestV1,
    case_input: PublicCaseInputBindingV1,
    target: &FirstPartyConstrainedSubprocessTargetV1,
    parent_oracle_build: &FirstPartyParentOracleBuildV1,
    independently_validated_owned_render: &[u8],
    peak_rss_observer: &MacOsTimePeakRssObserverV1,
    peak_rss_binding: PeakRssObservationBindingV1,
) -> Result<FirstPartyConstrainedSubprocessReceiptV1, FirstPartyConstrainedSubprocessErrorV1> {
    target.reverify()?;
    parent_oracle_build.reverify()?;
    validate_frozen_input(case_input.stdin().bytes())?;
    if case_input.stdin().artifact_digest() != CONSTRAINED_MATCHED_INPUT_ARTIFACT_DIGEST_V1 {
        return Err(FirstPartyConstrainedSubprocessErrorV1::ForeignInput);
    }
    let stdin_bytes = u64::try_from(case_input.stdin().bytes().len())
        .map_err(|_| FirstPartyConstrainedSubprocessErrorV1::ArtifactLengthOverflow)?;
    let stdout_bytes = u64::try_from(independently_validated_owned_render.len())
        .map_err(|_| FirstPartyConstrainedSubprocessErrorV1::ArtifactLengthOverflow)?;
    if stdout_bytes == 0 {
        return Err(FirstPartyConstrainedSubprocessErrorV1::OutputMismatch);
    }
    let limits = HarnessLimitsV1::try_new(
        stdin_bytes,
        stdout_bytes,
        0,
        manifest.identity().budget().wall_time_nanos(),
    )?;
    let invocation = PublicSubprocessInvocationV1::try_new(
        manifest,
        case_input,
        target.exact_program()?,
        limits,
        InvocationInputContractV1::ByteExact,
    )?;
    let (execution, peak_rss_observer_receipt) =
        execute_with_macos_time_peak_rss_v1(peak_rss_observer, &invocation, peak_rss_binding)?;
    target.reverify()?;
    freeze_execution_v1(
        target,
        parent_oracle_build,
        invocation,
        execution,
        peak_rss_observer_receipt,
        independently_validated_owned_render,
    )
}

fn freeze_execution_v1(
    target: &FirstPartyConstrainedSubprocessTargetV1,
    parent_oracle_build: &FirstPartyParentOracleBuildV1,
    invocation: PublicSubprocessInvocationV1,
    execution: SubprocessExecutionReceiptV1,
    peak_rss_observer_receipt: MacOsTimePeakRssReceiptV1,
    independently_validated_owned_render: &[u8],
) -> Result<FirstPartyConstrainedSubprocessReceiptV1, FirstPartyConstrainedSubprocessErrorV1> {
    if invocation.program() != &target.exact_program()?
        || invocation.input_contract() != InvocationInputContractV1::ByteExact
    {
        return Err(FirstPartyConstrainedSubprocessErrorV1::AdapterContractMismatch);
    }
    if execution.invocation_digest() != invocation.digest()
        || execution.run_manifest_artifact_digest() != invocation.run_manifest_artifact_digest()
        || execution.run_identity() != invocation.run_identity()
        || execution.public_case_artifact_digest() != invocation.public_case_artifact_digest()
        || execution.stdin_artifact_digest() != invocation.stdin().artifact_digest()
        || !execution.executable_path_digest_verified_before_spawn()
        || !execution.executable_path_digest_verified_after_spawn()
        || !execution.child_reaped()
        || peak_rss_observer_receipt.invocation_digest() != invocation.digest()
        || peak_rss_observer_receipt.stdout_artifact_digest()
            != execution.stdout().artifact_digest()
        || peak_rss_observer_receipt.stderr_artifact_digest()
            != execution.stderr().artifact_digest()
        || peak_rss_observer_receipt
            .observation()
            .binding()
            .system_artifact_digest()
            != invocation.program().system_artifact_digest()
        || peak_rss_observer_receipt
            .observation()
            .binding()
            .executable_build_artifact_digest()
            != invocation.program().executable_build_artifact_digest()
    {
        return Err(FirstPartyConstrainedSubprocessErrorV1::ExecutionBindingMismatch);
    }
    let normalized = strict_identity_normalize_v1(&execution)?;
    if !execution.stderr().bytes().is_empty() {
        return Err(FirstPartyConstrainedSubprocessErrorV1::UnexpectedStderr);
    }
    let oracle_render_artifact_digest =
        artifact_digest_for_bytes_v1(independently_validated_owned_render);
    let oracle_render_byte_count = u64::try_from(independently_validated_owned_render.len())
        .map_err(|_| FirstPartyConstrainedSubprocessErrorV1::ArtifactLengthOverflow)?;
    if execution.stdout().bytes() != independently_validated_owned_render
        || normalized.normalized_artifact_digest() != oracle_render_artifact_digest
        || normalized.normalized_byte_count() != oracle_render_byte_count
    {
        return Err(FirstPartyConstrainedSubprocessErrorV1::OutputMismatch);
    }
    let artifact_digest = derive_receipt_artifact_digest_v1(
        target,
        parent_oracle_build,
        &invocation,
        &execution,
        normalized,
        oracle_render_artifact_digest,
        oracle_render_byte_count,
        peak_rss_observer_receipt,
    )?;
    Ok(FirstPartyConstrainedSubprocessReceiptV1 {
        artifact_digest,
        adapter_contract_artifact_digest: target.adapter_contract_artifact_digest,
        oracle_render_artifact_digest,
        oracle_render_byte_count,
        parent_oracle_build_artifact_digest: parent_oracle_build.executable_build_artifact_digest,
        invocation,
        execution,
        peak_rss_observer_receipt,
        normalized,
    })
}

fn validate_frozen_input(input: &[u8]) -> Result<(), FirstPartyConstrainedSubprocessErrorV1> {
    if artifact_digest_for_bytes_v1(input) != CONSTRAINED_MATCHED_INPUT_ARTIFACT_DIGEST_V1 {
        return Err(FirstPartyConstrainedSubprocessErrorV1::ForeignInput);
    }
    let expected = constrained_pinned_drain_public_input_v1()
        .map_err(|_| FirstPartyConstrainedSubprocessErrorV1::InputShapeMismatch)?;
    if input != expected {
        return Err(FirstPartyConstrainedSubprocessErrorV1::InputShapeMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn derive_receipt_artifact_digest_v1(
    target: &FirstPartyConstrainedSubprocessTargetV1,
    parent_oracle_build: &FirstPartyParentOracleBuildV1,
    invocation: &PublicSubprocessInvocationV1,
    execution: &SubprocessExecutionReceiptV1,
    normalized: StrictNormalizedExternalOutputV1,
    oracle_render_artifact_digest: ArtifactDigest,
    oracle_render_byte_count: u64,
    peak_rss_observer_receipt: MacOsTimePeakRssReceiptV1,
) -> Result<ArtifactDigest, FirstPartyConstrainedSubprocessErrorV1> {
    let mut bytes = Vec::new();
    append_field(&mut bytes, RECEIPT_DOMAIN_V1)?;
    append_field(
        &mut bytes,
        &FIRST_PARTY_CONSTRAINED_SUBPROCESS_ADAPTER_CONTRACT_VERSION_V1.to_le_bytes(),
    )?;
    append_field(
        &mut bytes,
        target.adapter_contract_artifact_digest.as_bytes(),
    )?;
    append_field(&mut bytes, target.system_artifact_digest.as_bytes())?;
    append_field(
        &mut bytes,
        target.executable_build_artifact_digest.as_bytes(),
    )?;
    append_field(
        &mut bytes,
        parent_oracle_build
            .executable_build_artifact_digest
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
    append_field(&mut bytes, invocation.digest().as_bytes())?;
    append_field(&mut bytes, execution.stdout().artifact_digest().as_bytes())?;
    append_field(&mut bytes, execution.stderr().artifact_digest().as_bytes())?;
    append_field(
        &mut bytes,
        normalized.normalized_artifact_digest().as_bytes(),
    )?;
    append_field(&mut bytes, oracle_render_artifact_digest.as_bytes())?;
    append_field(&mut bytes, &oracle_render_byte_count.to_le_bytes())?;
    append_field(&mut bytes, &execution.wall_time_nanos().to_le_bytes())?;
    append_field(
        &mut bytes,
        peak_rss_observer_receipt.artifact_digest().as_bytes(),
    )?;
    append_field(
        &mut bytes,
        MatchedExecutionScopeV1::RawPublicStdinToCapturedProcessOutput
            .code()
            .as_bytes(),
    )?;
    Ok(artifact_digest_for_bytes_v1(&bytes))
}

fn append_field(
    output: &mut Vec<u8>,
    field: &[u8],
) -> Result<(), FirstPartyConstrainedSubprocessErrorV1> {
    let length = u64::try_from(field.len())
        .map_err(|_| FirstPartyConstrainedSubprocessErrorV1::ArtifactLengthOverflow)?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(field);
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FirstPartyConstrainedSubprocessErrorV1 {
    TargetUnavailable,
    OracleExecutableUnavailable,
    OracleExecutableChanged,
    WorkingDirectoryUnavailable,
    ExecutableChanged,
    ForeignInput,
    InputShapeMismatch,
    ArtifactLengthOverflow,
    AdapterContractMismatch,
    ExecutionBindingMismatch,
    OutputMismatch,
    UnexpectedStderr,
    ExecutionScopeMismatch,
    PeakRssObserver(PeakRssObserverErrorV1),
    Harness(HarnessError),
    Matched(PreparedPinnedDrainMatchedCaseErrorV1),
}

impl FirstPartyConstrainedSubprocessErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TargetUnavailable => "EVIDENTRAIL_BENCH_FIRST_PARTY_SUBPROCESS_TARGET_UNAVAILABLE",
            Self::OracleExecutableUnavailable => {
                "EVIDENTRAIL_BENCH_FIRST_PARTY_SUBPROCESS_ORACLE_EXECUTABLE_UNAVAILABLE"
            }
            Self::OracleExecutableChanged => {
                "EVIDENTRAIL_BENCH_FIRST_PARTY_SUBPROCESS_ORACLE_EXECUTABLE_CHANGED"
            }
            Self::WorkingDirectoryUnavailable => {
                "EVIDENTRAIL_BENCH_FIRST_PARTY_SUBPROCESS_WORKING_DIRECTORY_UNAVAILABLE"
            }
            Self::ExecutableChanged => "EVIDENTRAIL_BENCH_FIRST_PARTY_SUBPROCESS_EXECUTABLE_CHANGED",
            Self::ForeignInput => "EVIDENTRAIL_BENCH_FIRST_PARTY_SUBPROCESS_FOREIGN_INPUT",
            Self::InputShapeMismatch => "EVIDENTRAIL_BENCH_FIRST_PARTY_SUBPROCESS_INPUT_SHAPE_MISMATCH",
            Self::ArtifactLengthOverflow => {
                "EVIDENTRAIL_BENCH_FIRST_PARTY_SUBPROCESS_ARTIFACT_LENGTH_OVERFLOW"
            }
            Self::AdapterContractMismatch => {
                "EVIDENTRAIL_BENCH_FIRST_PARTY_SUBPROCESS_ADAPTER_CONTRACT_MISMATCH"
            }
            Self::ExecutionBindingMismatch => {
                "EVIDENTRAIL_BENCH_FIRST_PARTY_SUBPROCESS_EXECUTION_BINDING_MISMATCH"
            }
            Self::OutputMismatch => "EVIDENTRAIL_BENCH_FIRST_PARTY_SUBPROCESS_OUTPUT_MISMATCH",
            Self::UnexpectedStderr => "EVIDENTRAIL_BENCH_FIRST_PARTY_SUBPROCESS_UNEXPECTED_STDERR",
            Self::ExecutionScopeMismatch => {
                "EVIDENTRAIL_BENCH_FIRST_PARTY_SUBPROCESS_EXECUTION_SCOPE_MISMATCH"
            }
            Self::PeakRssObserver(error) => error.code(),
            Self::Harness(_) => "EVIDENTRAIL_BENCH_FIRST_PARTY_SUBPROCESS_HARNESS_FAILED",
            Self::Matched(_) => "EVIDENTRAIL_BENCH_FIRST_PARTY_SUBPROCESS_MATCHED_BUILD_FAILED",
        }
    }
}

impl fmt::Debug for FirstPartyConstrainedSubprocessErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirstPartyConstrainedSubprocessErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for FirstPartyConstrainedSubprocessErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for FirstPartyConstrainedSubprocessErrorV1 {}

impl From<HarnessError> for FirstPartyConstrainedSubprocessErrorV1 {
    fn from(error: HarnessError) -> Self {
        Self::Harness(error)
    }
}

impl From<PeakRssObserverErrorV1> for FirstPartyConstrainedSubprocessErrorV1 {
    fn from(error: PeakRssObserverErrorV1) -> Self {
        Self::PeakRssObserver(error)
    }
}

impl From<PreparedPinnedDrainMatchedCaseErrorV1> for FirstPartyConstrainedSubprocessErrorV1 {
    fn from(error: PreparedPinnedDrainMatchedCaseErrorV1) -> Self {
        Self::Matched(error)
    }
}
