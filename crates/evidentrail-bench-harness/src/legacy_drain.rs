use std::fmt;
use std::path::PathBuf;

use evidentrail_bench::EvidentrailBenchRunManifestV1;
use evidentrail_schema::bounds::JSON_SAFE_INTEGER_MAX;

use crate::{
    ClosedEnvironmentV1, ExecutableBuildV1, ExternalOutputContractV1, HarnessError,
    HarnessLimitsV1, InvocationInputContractV1, PublicCaseInputBindingV1,
    PublicSubprocessInvocationV1, artifact_digest_for_bytes_v1,
};
use evidentrail_schema::ArtifactDigest;

/// Pinned revision of the separate open-source `legacy-drain` CLI adapter.
///
/// This is not an identity for, or a claim about, the hosted Evidentrail product.
pub const LEGACY_DRAIN_PINNED_COMMIT_V1: &str = "5a84fb050e074b15474fdb264c9e97faaa66c9f5";
pub(crate) const LEGACY_DRAIN_HERMETIC_FIXTURE_REVISION_V1: &str =
    "legacy-drain-hermetic-adapter-contract-fixture-v1";
const LEGACY_DRAIN_HERMETIC_FIXTURE_SYSTEM_V1: &[u8] =
    b"evidentrail/bench-harness/legacy-drain-hermetic-adapter-contract-fixture/v1";
/// Frozen maximum retained occurrences admitted by the full-membership arm.
pub const MAX_LEGACY_DRAIN_FULL_MEMBERSHIP_RECORDS_V1: u64 = 4_096;
/// Frozen maximum public stdin size admitted by the full-membership arm.
pub const MAX_LEGACY_DRAIN_FULL_MEMBERSHIP_INPUT_BYTES_V1: u64 = 4 * 1024 * 1024;
/// Required stdout capture cap for the bounded full-membership arm.
pub const LEGACY_DRAIN_FULL_MEMBERSHIP_STDOUT_CAP_V1: u64 = 16 * 1024 * 1024;
const FULL_MEMBERSHIP_ADAPTER_IDENTITY_V1: &[u8] =
    b"evidentrail/bench-harness/legacy-drain-full-membership-adapter/v1";

#[must_use]
pub fn legacy_drain_full_membership_adapter_artifact_digest_v1() -> ArtifactDigest {
    artifact_digest_for_bytes_v1(FULL_MEMBERSHIP_ADAPTER_IDENTITY_V1)
}

pub(crate) fn legacy_drain_hermetic_fixture_system_artifact_digest_v1() -> ArtifactDigest {
    artifact_digest_for_bytes_v1(LEGACY_DRAIN_HERMETIC_FIXTURE_SYSTEM_V1)
}

/// Explicitly separates the ordinary compact sampling arm from the bounded
/// instrumentation arm used to prove complete occurrence membership.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LegacyDrainAdapterModeV1 {
    OpaqueSampled,
    FullMembershipAudit,
}

impl LegacyDrainAdapterModeV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::OpaqueSampled => "opaque_sampled",
            Self::FullMembershipAudit => "full_membership_audit",
        }
    }
}

impl fmt::Debug for LegacyDrainAdapterModeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyDrainAdapterModeV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Explicit cohort-coverage outcome for the narrower full-membership arm.
/// Unsupported cases remain members of the benchmark cohort and must be
/// reported as such; they cannot be silently omitted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LegacyDrainFullMembershipSupportV1 {
    Supported,
    UnsupportedInvalidUtf8,
    UnsupportedNonAsciiUtf8,
    UnsupportedNoRetainedRecords,
}

impl LegacyDrainFullMembershipSupportV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::UnsupportedInvalidUtf8 => "unsupported_invalid_utf8",
            Self::UnsupportedNonAsciiUtf8 => "unsupported_non_ascii_utf8",
            Self::UnsupportedNoRetainedRecords => "unsupported_no_retained_records",
        }
    }

    #[must_use]
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::Supported)
    }
}

impl fmt::Debug for LegacyDrainFullMembershipSupportV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyDrainFullMembershipSupportV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LegacyDrainUnsupportedInputV1 {
    InvalidUtf8,
}

impl LegacyDrainUnsupportedInputV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidUtf8 => "invalid_utf8",
        }
    }
}

impl fmt::Debug for LegacyDrainUnsupportedInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyDrainUnsupportedInputV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Known raw-text transformations in the pinned CLI's input path.
///
/// This records why a run is not byte/framing-parity with Evidentrail's event model.
/// It does not claim that the resulting output has any EventId or evidence
/// semantics.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LegacyDrainInputNormalizationV1 {
    input_byte_count: u64,
    logical_line_count: u64,
    retained_nonblank_line_count: u64,
    dropped_blank_line_count: u64,
    lf_terminator_count: u64,
    crlf_terminator_count: u64,
    final_lf_present: bool,
}

impl LegacyDrainInputNormalizationV1 {
    #[must_use]
    pub const fn input_byte_count(self) -> u64 {
        self.input_byte_count
    }

    #[must_use]
    pub const fn logical_line_count(self) -> u64 {
        self.logical_line_count
    }

    #[must_use]
    pub const fn retained_nonblank_line_count(self) -> u64 {
        self.retained_nonblank_line_count
    }

    #[must_use]
    pub const fn dropped_blank_line_count(self) -> u64 {
        self.dropped_blank_line_count
    }

    #[must_use]
    pub const fn lf_terminator_count(self) -> u64 {
        self.lf_terminator_count
    }

    #[must_use]
    pub const fn crlf_terminator_count(self) -> u64 {
        self.crlf_terminator_count
    }

    #[must_use]
    pub const fn final_lf_present(self) -> bool {
        self.final_lf_present
    }

    #[must_use]
    pub const fn blank_lines_are_dropped(self) -> bool {
        true
    }

    #[must_use]
    pub const fn line_terminators_are_discarded(self) -> bool {
        true
    }

    #[must_use]
    pub const fn whitespace_may_be_tokenized_and_rejoined(self) -> bool {
        true
    }

    #[must_use]
    pub const fn timestamp_and_level_may_be_extracted(self) -> bool {
        true
    }
}

impl fmt::Debug for LegacyDrainInputNormalizationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyDrainInputNormalizationV1")
            .field("input_byte_count", &self.input_byte_count)
            .field("logical_line_count", &self.logical_line_count)
            .field(
                "retained_nonblank_line_count",
                &self.retained_nonblank_line_count,
            )
            .field("dropped_blank_line_count", &self.dropped_blank_line_count)
            .field("lf_terminator_count", &self.lf_terminator_count)
            .field("crlf_terminator_count", &self.crlf_terminator_count)
            .field("final_lf_present", &self.final_lf_present)
            .field("blank_lines_are_dropped", &true)
            .field("line_terminators_are_discarded", &true)
            .field("whitespace_may_be_tokenized_and_rejoined", &true)
            .field("timestamp_and_level_may_be_extracted", &true)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LegacyDrainInputAssessmentV1 {
    Unsupported(LegacyDrainUnsupportedInputV1),
    SupportedWithNormalization(LegacyDrainInputNormalizationV1),
}

impl fmt::Debug for LegacyDrainInputAssessmentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(reason) => formatter
                .debug_struct("LegacyDrainInputAssessmentV1")
                .field("classification", &"unsupported")
                .field("reason", reason)
                .finish(),
            Self::SupportedWithNormalization(normalization) => formatter
                .debug_struct("LegacyDrainInputAssessmentV1")
                .field("classification", &"supported_with_normalization")
                .field("normalization", normalization)
                .finish(),
        }
    }
}

/// Configuration for the pinned open-source `legacy-drain` CLI arm.
///
/// The fixed arguments are always `--grouper drain --format json --samples N`.
/// The ordinary sampled arm keeps JSON stdout opaque. The distinct full-sample
/// instrumentation arm may produce a strictly validated occurrence-accounting
/// sidecar, but never source-exact evidence or diagnostic-recall credit.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LegacyDrainAdapterV1 {
    sample_cap: u64,
    mode: LegacyDrainAdapterModeV1,
}

impl LegacyDrainAdapterV1 {
    pub fn try_new(sample_cap: u64) -> Result<Self, HarnessError> {
        if sample_cap == 0
            || sample_cap > JSON_SAFE_INTEGER_MAX
            || usize::try_from(sample_cap).is_err()
        {
            return Err(HarnessError::InvalidSampleCap);
        }
        Ok(Self {
            sample_cap,
            mode: LegacyDrainAdapterModeV1::OpaqueSampled,
        })
    }

    /// Construct the distinct, bounded instrumentation arm. Its sample cap is
    /// derived from the canonical retained occurrence count; callers cannot
    /// supply a smaller cap and later claim complete membership. Every retained
    /// occurrence and exact source-record byte is charged against the declared
    /// candidate budget; this is not an uncharged helper run for the compact
    /// adapter.
    pub fn try_new_full_membership(
        run_manifest: &EvidentrailBenchRunManifestV1,
        case_input: &PublicCaseInputBindingV1,
        limits: HarnessLimitsV1,
    ) -> Result<Self, HarnessError> {
        let sample_cap = validate_full_membership_envelope(run_manifest, case_input, limits)?;
        Ok(Self {
            sample_cap,
            mode: LegacyDrainAdapterModeV1::FullMembershipAudit,
        })
    }

    pub fn assess_full_membership_case(
        case_input: &PublicCaseInputBindingV1,
    ) -> Result<LegacyDrainFullMembershipSupportV1, HarnessError> {
        if std::str::from_utf8(case_input.stdin().bytes()).is_err() {
            return Ok(LegacyDrainFullMembershipSupportV1::UnsupportedInvalidUtf8);
        }
        if !case_input.stdin().bytes().is_ascii() {
            return Ok(LegacyDrainFullMembershipSupportV1::UnsupportedNonAsciiUtf8);
        }
        let retained = case_input
            .source_record_map()
            .legacy_drain_retained_records(case_input.stdin())?;
        if retained.records().is_empty() {
            return Ok(LegacyDrainFullMembershipSupportV1::UnsupportedNoRetainedRecords);
        }
        Ok(LegacyDrainFullMembershipSupportV1::Supported)
    }

    pub(crate) fn try_new_full_membership_cap_for_validation(
        sample_cap: u64,
    ) -> Result<Self, HarnessError> {
        if sample_cap == 0
            || sample_cap > MAX_LEGACY_DRAIN_FULL_MEMBERSHIP_RECORDS_V1
            || usize::try_from(sample_cap).is_err()
        {
            return Err(HarnessError::InvalidSampleCap);
        }
        Ok(Self {
            sample_cap,
            mode: LegacyDrainAdapterModeV1::FullMembershipAudit,
        })
    }

    #[must_use]
    pub const fn sample_cap(self) -> u64 {
        self.sample_cap
    }

    #[must_use]
    pub const fn mode(self) -> LegacyDrainAdapterModeV1 {
        self.mode
    }

    #[must_use]
    pub fn fixed_argv(self) -> Vec<String> {
        vec![
            "--grouper".to_owned(),
            "drain".to_owned(),
            "--format".to_owned(),
            "json".to_owned(),
            "--samples".to_owned(),
            self.sample_cap.to_string(),
        ]
    }

    pub fn assess_input(self, input: &[u8]) -> Result<LegacyDrainInputAssessmentV1, HarnessError> {
        let Ok(text) = std::str::from_utf8(input) else {
            return Ok(LegacyDrainInputAssessmentV1::Unsupported(
                LegacyDrainUnsupportedInputV1::InvalidUtf8,
            ));
        };
        let input_byte_count =
            u64::try_from(input.len()).map_err(|_| HarnessError::InputAccountingOverflow)?;
        let logical_line_count = u64::try_from(text.lines().count())
            .map_err(|_| HarnessError::InputAccountingOverflow)?;
        let retained_nonblank_line_count =
            u64::try_from(text.lines().filter(|line| !line.trim().is_empty()).count())
                .map_err(|_| HarnessError::InputAccountingOverflow)?;
        let dropped_blank_line_count = logical_line_count
            .checked_sub(retained_nonblank_line_count)
            .ok_or(HarnessError::InputAccountingOverflow)?;
        let lf_terminator_count =
            u64::try_from(input.iter().filter(|byte| **byte == b'\n').count())
                .map_err(|_| HarnessError::InputAccountingOverflow)?;
        let crlf_terminator_count =
            u64::try_from(input.windows(2).filter(|window| *window == b"\r\n").count())
                .map_err(|_| HarnessError::InputAccountingOverflow)?;

        Ok(LegacyDrainInputAssessmentV1::SupportedWithNormalization(
            LegacyDrainInputNormalizationV1 {
                input_byte_count,
                logical_line_count,
                retained_nonblank_line_count,
                dropped_blank_line_count,
                lf_terminator_count,
                crlf_terminator_count,
                final_lf_present: input.last() == Some(&b'\n'),
            },
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_public_invocation(
        self,
        run_manifest: &EvidentrailBenchRunManifestV1,
        case_input: PublicCaseInputBindingV1,
        executable_path: PathBuf,
        cwd: PathBuf,
        environment: ClosedEnvironmentV1,
        limits: HarnessLimitsV1,
    ) -> Result<
        (
            PublicSubprocessInvocationV1,
            LegacyDrainInputNormalizationV1,
        ),
        HarnessError,
    > {
        self.build_public_invocation_with_revision(
            run_manifest,
            case_input,
            executable_path,
            cwd,
            environment,
            limits,
            LEGACY_DRAIN_PINNED_COMMIT_V1,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_hermetic_contract_fixture_invocation(
        self,
        run_manifest: &EvidentrailBenchRunManifestV1,
        case_input: PublicCaseInputBindingV1,
        executable_path: PathBuf,
        cwd: PathBuf,
        environment: ClosedEnvironmentV1,
        limits: HarnessLimitsV1,
    ) -> Result<
        (
            PublicSubprocessInvocationV1,
            LegacyDrainInputNormalizationV1,
        ),
        HarnessError,
    > {
        self.build_public_invocation_with_revision(
            run_manifest,
            case_input,
            executable_path,
            cwd,
            environment,
            limits,
            LEGACY_DRAIN_HERMETIC_FIXTURE_REVISION_V1,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_public_invocation_with_revision(
        self,
        run_manifest: &EvidentrailBenchRunManifestV1,
        case_input: PublicCaseInputBindingV1,
        executable_path: PathBuf,
        cwd: PathBuf,
        environment: ClosedEnvironmentV1,
        limits: HarnessLimitsV1,
        adapter_revision: &str,
    ) -> Result<
        (
            PublicSubprocessInvocationV1,
            LegacyDrainInputNormalizationV1,
        ),
        HarnessError,
    > {
        if self.mode == LegacyDrainAdapterModeV1::FullMembershipAudit
            && validate_full_membership_envelope(run_manifest, &case_input, limits)?
                != self.sample_cap
        {
            return Err(HarnessError::InvalidSampleCap);
        }
        let normalization = match self.assess_input(case_input.stdin().bytes())? {
            LegacyDrainInputAssessmentV1::Unsupported(_) => {
                return Err(HarnessError::UnsupportedExternalInput);
            }
            LegacyDrainInputAssessmentV1::SupportedWithNormalization(value) => value,
        };
        let identity = run_manifest.identity();
        let program = ExecutableBuildV1::try_new(
            identity.system_artifact_digest(),
            identity.build_artifact_digest(),
            executable_path,
            self.fixed_argv(),
            cwd,
            environment,
            ExternalOutputContractV1::OpaqueArtifactOnly,
            Some(adapter_revision.to_owned()),
        )?;
        let input_contract = match self.mode {
            LegacyDrainAdapterModeV1::OpaqueSampled => {
                InvocationInputContractV1::LegacyDrainRawTextKnownNormalization
            }
            LegacyDrainAdapterModeV1::FullMembershipAudit => {
                InvocationInputContractV1::LegacyDrainRawTextFullMembership
            }
        };
        let invocation = PublicSubprocessInvocationV1::try_new(
            run_manifest,
            case_input,
            program,
            limits,
            input_contract,
        )?;
        Ok((invocation, normalization))
    }
}

impl fmt::Debug for LegacyDrainAdapterV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyDrainAdapterV1")
            .field("adapter_scope", &"pinned_open_source_legacy_drain")
            .field("pinned_revision_present", &true)
            .field("mode", &self.mode)
            .field("sample_cap", &self.sample_cap)
            .field("raw_output_is_external_artifact", &true)
            .field("exact_evidence_credit", &false)
            .field("represents_hosted_evidentrail", &false)
            .finish()
    }
}

fn validate_full_membership_envelope(
    run_manifest: &EvidentrailBenchRunManifestV1,
    case_input: &PublicCaseInputBindingV1,
    limits: HarnessLimitsV1,
) -> Result<u64, HarnessError> {
    let stdin_byte_count = u64::try_from(case_input.stdin().bytes().len())
        .map_err(|_| HarnessError::InputAccountingOverflow)?;
    if stdin_byte_count > MAX_LEGACY_DRAIN_FULL_MEMBERSHIP_INPUT_BYTES_V1 {
        return Err(HarnessError::FullMembershipInputByteCapExceeded);
    }
    match LegacyDrainAdapterV1::assess_full_membership_case(case_input)? {
        LegacyDrainFullMembershipSupportV1::Supported => {}
        LegacyDrainFullMembershipSupportV1::UnsupportedNoRetainedRecords => {
            return Err(HarnessError::FullMembershipEmptyInput);
        }
        LegacyDrainFullMembershipSupportV1::UnsupportedInvalidUtf8
        | LegacyDrainFullMembershipSupportV1::UnsupportedNonAsciiUtf8 => {
            return Err(HarnessError::FullMembershipInputNormalizationUnsupported);
        }
    }
    if limits.stdout_bytes() < LEGACY_DRAIN_FULL_MEMBERSHIP_STDOUT_CAP_V1 {
        return Err(HarnessError::FullMembershipStdoutCapInsufficient);
    }
    let retained = case_input
        .source_record_map()
        .legacy_drain_retained_records(case_input.stdin())?;
    let retained_count = u64::try_from(retained.records().len())
        .map_err(|_| HarnessError::InputAccountingOverflow)?;
    if retained_count > MAX_LEGACY_DRAIN_FULL_MEMBERSHIP_RECORDS_V1 {
        return Err(HarnessError::FullMembershipRecordCapExceeded);
    }
    let retained_source_bytes = retained
        .records()
        .iter()
        .try_fold(0_u64, |total, retained| {
            let position = usize::try_from(retained.source_record_ordinal())
                .map_err(|_| HarnessError::InputAccountingOverflow)?;
            let source_record = case_input
                .source_record_map()
                .records()
                .get(position)
                .ok_or(HarnessError::SourceRecordMapInputMismatch)?;
            total
                .checked_add(
                    source_record
                        .source_byte_end()
                        .checked_sub(source_record.source_byte_start())
                        .ok_or(HarnessError::InputAccountingOverflow)?,
                )
                .ok_or(HarnessError::InputAccountingOverflow)
        })?;
    let budget = run_manifest.identity().budget();
    if budget.unique_candidate_event_count() < retained_count
        || budget.unique_candidate_source_bytes() < retained_source_bytes
    {
        return Err(HarnessError::FullMembershipCandidateBudgetInsufficient);
    }
    Ok(retained_count)
}
