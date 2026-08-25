use std::error::Error as StdError;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use evidentrail_bench::{
    BenchmarkBudgetV1, BenchmarkRunIdentityV1, CandidateRendererIdentityV1, EvidentrailBenchCaseSpecV1,
    EvidentrailBenchRunManifestV1, ExpectedAcquisitionClassV1, MeasuredCandidateResources,
    MeasurementEnvironmentV1, MeasurementHarnessIdentityV1, MethodDescriptor,
    RenderedCandidateArtifactV1, TokenizerIdentityV1,
};
use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    CompletenessProof, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, EventLedger,
    FetchBoundaries, FetchCompleteness, FetchCompletion, FetchIdentity, FetchTiming, LaneKey,
    LaneSequence, LedgerBuilder, PlanId, PolicyAuthorization, RawEnvelopeIdentityV1, RawEnvelopeV1,
    RecordBytes, RecordState, RetrievalId, SourceIdentityDigest, SourceMember, SourceStream,
    UnixTimestampNanos, derive_question_digest_v1,
};
use evidentrail_evidence::utf8_byte_tokenizer_digest_v1;
use evidentrail_product::{
    CompiledProductResultV1, DeterministicProductDecisionV1, MemoryProductV1,
    RenderedProductResultV1,
};
use evidentrail_schema::{ArtifactDigest, PlanDigest, ResultId};

use crate::fidelity_bridge::freeze_legacy_drain_full_membership_representation_with_method_v1;
use crate::peak_rss_observer::execute_with_macos_time_peak_rss_v1;
use crate::{
    LEGACY_DRAIN_FULL_MEMBERSHIP_STDOUT_CAP_V1, LEGACY_DRAIN_PINNED_COMMIT_V1,
    CanonicalTokenCountProvenanceV1, ClosedEnvironmentV1, LegacyDrainFidelityBridgeErrorV1,
    LegacyDrainFullMembershipArtifactV1, LegacyDrainJsonLimitsV1, LegacyDrainNormalizationErrorV1,
    FirstPartyLogBriefBridgeErrorV1, FirstPartyLogBriefRepresentationReceiptV1, HarnessError,
    HarnessLimitsV1, MacOsTimePeakRssObserverV1, MacOsTimePeakRssReceiptV1, PeakRssObserverErrorV1,
    PeakRssProvenanceV1, PublicCaseInputBindingV1, PublicSubprocessInvocationV1,
    StdinArtifactClassV1, StdinArtifactV1, SubprocessExecutionReceiptV1,
    artifact_digest_for_bytes_v1, artifact_digest_for_file_v1, canonical_public_case_artifact_v1,
    canonical_public_run_manifest_artifact_v1, execute_public_subprocess_v1,
    freeze_bound_owned_compiled_log_brief_representation_v1,
    freeze_bound_owned_passthrough_log_brief_representation_v1,
    measure_canonical_utf8_byte_tokens_v1, strict_normalize_pinned_legacy_drain_full_membership_v1,
};

/// One canonical public fixture shared by the pinned smoke and matched-case
/// preparation path. It contains no annotation or diagnostic label.
pub const PINNED_LEGACY_DRAIN_MATCHED_INPUT_V1: &[u8] =
    b"2026-08-24T12:00:00Z INFO api request id=alpha\n\
\n\
2026-08-24T12:00:01Z INFO api request id=beta\r\n\
2026-08-24T12:00:01.500Z INFO api request id=gamma\n\
2026-08-24T12:00:02Z ERROR database timeout host=db-1\n\
2026-08-24T12:00:03Z ERROR database timeout host=db-2";

/// Exact question bytes used by the first-party product arm.
pub const PINNED_LEGACY_DRAIN_MATCHED_QUESTION_V1: &[u8] = b"what caused the database timeout?";

const PINNED_MATCHED_CASE_MANIFEST_V1: &[u8] = b"evidentrail/bench-harness/pinned-drain-matched-case/v1\0public-fixture=true\0hidden-labels=none\0separate-executions=true\0peak-rss=required-bound-observation\0proposal-union=not-claimed";
const FIRST_PARTY_SYSTEM_MANIFEST_V1: &[u8] =
    b"evidentrail/bench-harness/first-party-memory-product-arm/v1";
const PEAK_RSS_OBSERVATION_DOMAIN_V1: &[u8] = b"evidentrail/bench-harness/bound-peak-rss-observation/v1";
const FIRST_PARTY_EXECUTION_MEASUREMENT_V1: &[u8] = b"evidentrail/bench-harness/first-party-memory-product-execution/v1\0clock=std-instant\0scope=create-deterministic-result-v1\0peak-rss=not-measured";
const DRAIN_EXECUTION_MEASUREMENT_V1: &[u8] = b"evidentrail/bench-harness/pinned-drain-full-membership-execution/v1\0clock=subprocess-harness\0scope=raw-public-stdin-through-captured-output\0peak-rss=not-measured";
const FINALIZED_MATCHED_CASE_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/finalized-pinned-drain-matched-case/v1";
const PINNED_MATCHED_PLAN_V1: &[u8] = b"evidentrail/bench-harness/pinned-drain-matched-plan/v1";
const PINNED_MATCHED_SPLIT_V1: &[u8] = b"evidentrail/bench-harness/pinned-drain-matched-split/v1";
const PINNED_MATCHED_LEAKAGE_V1: &[u8] =
    b"evidentrail/bench-harness/pinned-drain-matched-leakage-policy/v1";
const PINNED_MATCHED_RESULT_V1: &[u8] = b"evidentrail/bench-harness/pinned-drain-matched-result/v1";
const PINNED_MATCHED_SEED_V1: u64 = 1;
const PINNED_MATCHED_WALL_NANOS_V1: u64 = 10_000_000_000;
const PINNED_MATCHED_PEAK_BYTES_V1: u64 = 10_000_000_000;
const PINNED_MATCHED_TOKEN_CAP_V1: u64 = 10_000_000;
const PINNED_MATCHED_EVENT_CAP_V1: u64 = 1_000_000;
const PINNED_MATCHED_SOURCE_BYTE_CAP_V1: u64 = 64 * 1024 * 1024;
const PINNED_MATCHED_STDERR_CAP_V1: u64 = 1024 * 1024;

struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

/// Provenance class of the executable target used by a preparation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PinnedLegacyDrainTargetClassV1 {
    VerifiedCleanPinnedCheckout,
    HermeticAdapterContractFixture,
}

impl PinnedLegacyDrainTargetClassV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::VerifiedCleanPinnedCheckout => "verified_clean_pinned_checkout",
            Self::HermeticAdapterContractFixture => "hermetic_adapter_contract_fixture",
        }
    }
}

impl fmt::Debug for PinnedLegacyDrainTargetClassV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedLegacyDrainTargetClassV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Exact executable/cwd binding for the pinned subprocess arm.
///
/// Path hashing and clean-checkout verification are self-asserted local
/// reproducibility evidence, not immutable-executable attestation.
#[derive(Clone, PartialEq, Eq)]
pub struct PinnedLegacyDrainExecutionTargetV1 {
    class: PinnedLegacyDrainTargetClassV1,
    executable_path: PathBuf,
    cwd: PathBuf,
    git_executable: Option<PathBuf>,
    system_artifact_digest: ArtifactDigest,
    executable_build_artifact_digest: ArtifactDigest,
}

impl PinnedLegacyDrainExecutionTargetV1 {
    pub fn try_new_verified_local_checkout(
        checkout: impl AsRef<Path>,
        executable: impl AsRef<Path>,
        git_executable: impl AsRef<Path>,
    ) -> Result<Self, PreparedPinnedDrainMatchedCaseErrorV1> {
        let cwd = checkout
            .as_ref()
            .canonicalize()
            .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::TargetUnavailable)?;
        let executable_path = executable
            .as_ref()
            .canonicalize()
            .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::TargetUnavailable)?;
        let git_executable = git_executable
            .as_ref()
            .canonicalize()
            .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::GitUnavailable)?;
        if !executable_path.starts_with(&cwd) {
            return Err(PreparedPinnedDrainMatchedCaseErrorV1::TargetOutsideCheckout);
        }
        verify_checkout(&cwd, &git_executable)?;
        let executable_build_artifact_digest = artifact_digest_for_file_v1(&executable_path)?;
        Ok(Self {
            class: PinnedLegacyDrainTargetClassV1::VerifiedCleanPinnedCheckout,
            executable_path,
            cwd,
            git_executable: Some(git_executable),
            system_artifact_digest: artifact_digest_for_bytes_v1(
                LEGACY_DRAIN_PINNED_COMMIT_V1.as_bytes(),
            ),
            executable_build_artifact_digest,
        })
    }

    /// Construct an explicitly non-baseline target for default hermetic
    /// contract tests. Its system and method identities differ from the pinned
    /// checkout and cannot be reported as an observed `legacy-drain` build.
    pub fn try_new_hermetic_contract_fixture(
        executable: impl AsRef<Path>,
        cwd: impl AsRef<Path>,
    ) -> Result<Self, PreparedPinnedDrainMatchedCaseErrorV1> {
        let executable_path = executable
            .as_ref()
            .canonicalize()
            .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::TargetUnavailable)?;
        let cwd = cwd
            .as_ref()
            .canonicalize()
            .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::TargetUnavailable)?;
        let executable_build_artifact_digest = artifact_digest_for_file_v1(&executable_path)?;
        Ok(Self {
            class: PinnedLegacyDrainTargetClassV1::HermeticAdapterContractFixture,
            executable_path,
            cwd,
            git_executable: None,
            system_artifact_digest:
                crate::legacy_drain::legacy_drain_hermetic_fixture_system_artifact_digest_v1(),
            executable_build_artifact_digest,
        })
    }

    fn reverify(&self) -> Result<(), PreparedPinnedDrainMatchedCaseErrorV1> {
        if let Some(git_executable) = &self.git_executable {
            verify_checkout(&self.cwd, git_executable)?;
        }
        if artifact_digest_for_file_v1(&self.executable_path)?
            != self.executable_build_artifact_digest
        {
            return Err(PreparedPinnedDrainMatchedCaseErrorV1::ExecutableChanged);
        }
        Ok(())
    }

    #[must_use]
    pub const fn class(&self) -> PinnedLegacyDrainTargetClassV1 {
        self.class
    }

    #[must_use]
    pub const fn system_artifact_digest(&self) -> ArtifactDigest {
        self.system_artifact_digest
    }

    #[must_use]
    pub const fn executable_build_artifact_digest(&self) -> ArtifactDigest {
        self.executable_build_artifact_digest
    }

    fn method(&self) -> MethodDescriptor {
        match self.class {
            PinnedLegacyDrainTargetClassV1::VerifiedCleanPinnedCheckout => {
                crate::legacy_drain_full_membership_method_descriptor_v1()
            }
            PinnedLegacyDrainTargetClassV1::HermeticAdapterContractFixture => {
                MethodDescriptor::new("legacy-drain-full-membership-contract-fixture", "1")
            }
        }
    }
}

impl fmt::Debug for PinnedLegacyDrainExecutionTargetV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedLegacyDrainExecutionTargetV1")
            .field("class", &self.class)
            .field("executable_build_artifact_bound", &true)
            .field("system_artifact_bound", &true)
            .field("paths_redacted", &true)
            .field("independently_attested", &false)
            .finish()
    }
}

/// Self-asserted binding for the in-process executable that runs the actual
/// `MemoryProductV1` call.
///
/// The constrained subprocess wrapper derives an instance with the child
/// helper identity solely to build that arm's public run manifest. Its parent
/// byte oracle is separately typed as validated but not build-attested; the
/// helper hash must not be read as attesting the parent process.
#[derive(Clone, PartialEq, Eq)]
pub struct FirstPartyInProcessBuildV1 {
    executable_path: PathBuf,
    system_artifact_digest: ArtifactDigest,
    executable_build_artifact_digest: ArtifactDigest,
}

impl FirstPartyInProcessBuildV1 {
    pub fn try_new(
        executable_path: impl AsRef<Path>,
    ) -> Result<Self, PreparedPinnedDrainMatchedCaseErrorV1> {
        Self::try_new_with_system_artifact_digest(
            executable_path,
            artifact_digest_for_bytes_v1(FIRST_PARTY_SYSTEM_MANIFEST_V1),
        )
    }

    pub(crate) fn try_new_with_system_artifact_digest(
        executable_path: impl AsRef<Path>,
        system_artifact_digest: ArtifactDigest,
    ) -> Result<Self, PreparedPinnedDrainMatchedCaseErrorV1> {
        let executable_path = executable_path
            .as_ref()
            .canonicalize()
            .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::TargetUnavailable)?;
        let executable_build_artifact_digest = artifact_digest_for_file_v1(&executable_path)?;
        Ok(Self {
            executable_path,
            system_artifact_digest,
            executable_build_artifact_digest,
        })
    }

    fn reverify(&self) -> Result<(), PreparedPinnedDrainMatchedCaseErrorV1> {
        if artifact_digest_for_file_v1(&self.executable_path)?
            != self.executable_build_artifact_digest
        {
            return Err(PreparedPinnedDrainMatchedCaseErrorV1::ExecutableChanged);
        }
        Ok(())
    }

    #[must_use]
    pub const fn system_artifact_digest(&self) -> ArtifactDigest {
        self.system_artifact_digest
    }

    #[must_use]
    pub const fn executable_build_artifact_digest(&self) -> ArtifactDigest {
        self.executable_build_artifact_digest
    }
}

impl fmt::Debug for FirstPartyInProcessBuildV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirstPartyInProcessBuildV1")
            .field("system_artifact_bound", &true)
            .field("executable_build_artifact_bound", &true)
            .field("path_redacted", &true)
            .field("independently_attested", &false)
            .finish()
    }
}

/// Closed arm identity for an injected peak-RSS observation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PinnedDrainMatchedArmV1 {
    FirstParty,
    PinnedDrainFullMembership,
}

impl PinnedDrainMatchedArmV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::FirstParty => "first_party",
            Self::PinnedDrainFullMembership => "pinned_drain_full_membership",
        }
    }
}

impl fmt::Debug for PinnedDrainMatchedArmV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedDrainMatchedArmV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Exact wall/resource measurement scope for each prepared arm.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MatchedExecutionScopeV1 {
    FirstPartyPreacquiredLedgerToOwnedRender,
    DrainRawPublicStdinToCapturedFullMembershipOutput,
    /// Shell-free observer/child startup, exact raw public stdin delivery, the
    /// arm's case-specific work, bounded stdout/stderr capture, observer report
    /// write, and process reap. For the frozen constrained first-party case,
    /// the child validates the bytes then deterministically reconstructs the
    /// specified mixed-lane ledger; this scope does not claim a general
    /// production parser path or equivalent internal work between arms.
    RawPublicStdinToCapturedProcessOutput,
}

impl MatchedExecutionScopeV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::FirstPartyPreacquiredLedgerToOwnedRender => {
                "first_party_preacquired_ledger_to_owned_render"
            }
            Self::DrainRawPublicStdinToCapturedFullMembershipOutput => {
                "drain_raw_public_stdin_to_captured_full_membership_output"
            }
            Self::RawPublicStdinToCapturedProcessOutput => {
                "raw_public_stdin_to_captured_process_output"
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MatchedCostComparisonStatusV1 {
    UnequalExecutionScopes,
    EligibleCommonProcessScopeAndPeakRssObserver,
}

impl MatchedCostComparisonStatusV1 {
    const fn code(self) -> &'static str {
        match self {
            Self::UnequalExecutionScopes => "ineligible_unequal_execution_scopes",
            Self::EligibleCommonProcessScopeAndPeakRssObserver => {
                "eligible_common_process_scope_and_peak_rss_observer"
            }
        }
    }
}

impl fmt::Debug for MatchedExecutionScopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MatchedExecutionScopeV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Cost/Pareto ordering is admitted only for a common captured-process scope
/// with the same pinned peak-RSS observer. Generic preparations retain their
/// explicit unequal-scope or missing-observer blockers.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MatchedCostComparisonEligibilityV1 {
    first_party_scope: MatchedExecutionScopeV1,
    drain_scope: MatchedExecutionScopeV1,
    status: MatchedCostComparisonStatusV1,
}

impl MatchedCostComparisonEligibilityV1 {
    pub(crate) const fn unequal_v1() -> Self {
        Self {
            first_party_scope: MatchedExecutionScopeV1::FirstPartyPreacquiredLedgerToOwnedRender,
            drain_scope: MatchedExecutionScopeV1::DrainRawPublicStdinToCapturedFullMembershipOutput,
            status: MatchedCostComparisonStatusV1::UnequalExecutionScopes,
        }
    }

    pub(crate) const fn common_process_scope_and_peak_rss_observer_v1() -> Self {
        Self {
            first_party_scope: MatchedExecutionScopeV1::RawPublicStdinToCapturedProcessOutput,
            drain_scope: MatchedExecutionScopeV1::RawPublicStdinToCapturedProcessOutput,
            status: MatchedCostComparisonStatusV1::EligibleCommonProcessScopeAndPeakRssObserver,
        }
    }

    #[must_use]
    pub const fn first_party_scope(self) -> MatchedExecutionScopeV1 {
        self.first_party_scope
    }

    #[must_use]
    pub const fn drain_scope(self) -> MatchedExecutionScopeV1 {
        self.drain_scope
    }

    #[must_use]
    pub const fn cost_ordering_eligible(self) -> bool {
        matches!(
            self.status,
            MatchedCostComparisonStatusV1::EligibleCommonProcessScopeAndPeakRssObserver
        )
    }

    #[must_use]
    pub const fn wall_scope_comparable(self) -> bool {
        matches!(
            (self.first_party_scope, self.drain_scope),
            (
                MatchedExecutionScopeV1::RawPublicStdinToCapturedProcessOutput,
                MatchedExecutionScopeV1::RawPublicStdinToCapturedProcessOutput
            )
        )
    }

    #[must_use]
    pub const fn peak_rss_comparable(self) -> bool {
        matches!(
            self.status,
            MatchedCostComparisonStatusV1::EligibleCommonProcessScopeAndPeakRssObserver
        )
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        self.status.code()
    }
}

impl fmt::Debug for MatchedCostComparisonEligibilityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MatchedCostComparisonEligibilityV1")
            .field("code", &self.code())
            .field("first_party_scope", &self.first_party_scope)
            .field("drain_scope", &self.drain_scope)
            .field("wall_scope_comparable", &self.wall_scope_comparable())
            .field("peak_rss_comparable", &self.peak_rss_comparable())
            .field("cost_ordering_eligible", &self.cost_ordering_eligible())
            .finish()
    }
}

/// Frozen unit of a peak resident-set observation. V1 admits bytes only.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PeakRssMeasurementUnitV1 {
    Bytes,
}

impl PeakRssMeasurementUnitV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
        }
    }
}

impl fmt::Debug for PeakRssMeasurementUnitV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeakRssMeasurementUnitV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Exact identities an external peak-RSS observer must bind before its value
/// can finalize either arm.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PeakRssObservationBindingV1 {
    arm: PinnedDrainMatchedArmV1,
    system_artifact_digest: ArtifactDigest,
    executable_build_artifact_digest: ArtifactDigest,
    public_run_manifest_artifact_digest: ArtifactDigest,
    public_case_artifact_digest: ArtifactDigest,
}

impl PeakRssObservationBindingV1 {
    #[must_use]
    pub const fn new(
        arm: PinnedDrainMatchedArmV1,
        system_artifact_digest: ArtifactDigest,
        executable_build_artifact_digest: ArtifactDigest,
        public_run_manifest_artifact_digest: ArtifactDigest,
        public_case_artifact_digest: ArtifactDigest,
    ) -> Self {
        Self {
            arm,
            system_artifact_digest,
            executable_build_artifact_digest,
            public_run_manifest_artifact_digest,
            public_case_artifact_digest,
        }
    }

    #[must_use]
    pub const fn arm(self) -> PinnedDrainMatchedArmV1 {
        self.arm
    }

    #[must_use]
    pub const fn system_artifact_digest(self) -> ArtifactDigest {
        self.system_artifact_digest
    }

    #[must_use]
    pub const fn executable_build_artifact_digest(self) -> ArtifactDigest {
        self.executable_build_artifact_digest
    }

    #[must_use]
    pub const fn public_run_manifest_artifact_digest(self) -> ArtifactDigest {
        self.public_run_manifest_artifact_digest
    }

    #[must_use]
    pub const fn public_case_artifact_digest(self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    pub fn observe(
        self,
        measurement_mechanism_artifact_digest: ArtifactDigest,
        unit: PeakRssMeasurementUnitV1,
        value: u64,
    ) -> Result<BoundPeakRssObservationV1, PreparedPinnedDrainMatchedCaseErrorV1> {
        BoundPeakRssObservationV1::try_new(self, measurement_mechanism_artifact_digest, unit, value)
    }
}

impl fmt::Debug for PeakRssObservationBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeakRssObservationBindingV1")
            .field("arm", &self.arm)
            .field("system_artifact_bound", &true)
            .field("executable_build_artifact_bound", &true)
            .field("run_manifest_artifact_bound", &true)
            .field("public_case_artifact_bound", &true)
            .finish()
    }
}

/// Self-asserted, fully bound peak-RSS observation. It records provenance but
/// is not independent attestation of the measurement mechanism or value.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BoundPeakRssObservationV1 {
    binding: PeakRssObservationBindingV1,
    measurement_mechanism_artifact_digest: ArtifactDigest,
    unit: PeakRssMeasurementUnitV1,
    value: u64,
    artifact_digest: ArtifactDigest,
}

impl BoundPeakRssObservationV1 {
    pub fn try_new(
        binding: PeakRssObservationBindingV1,
        measurement_mechanism_artifact_digest: ArtifactDigest,
        unit: PeakRssMeasurementUnitV1,
        value: u64,
    ) -> Result<Self, PreparedPinnedDrainMatchedCaseErrorV1> {
        if value == 0 {
            return Err(PreparedPinnedDrainMatchedCaseErrorV1::InvalidPeakRssObservation);
        }
        let artifact_digest = derive_peak_rss_observation_artifact_digest(
            binding,
            measurement_mechanism_artifact_digest,
            unit,
            value,
        )?;
        Ok(Self {
            binding,
            measurement_mechanism_artifact_digest,
            unit,
            value,
            artifact_digest,
        })
    }

    #[must_use]
    pub const fn binding(self) -> PeakRssObservationBindingV1 {
        self.binding
    }

    #[must_use]
    pub const fn measurement_mechanism_artifact_digest(self) -> ArtifactDigest {
        self.measurement_mechanism_artifact_digest
    }

    #[must_use]
    pub const fn unit(self) -> PeakRssMeasurementUnitV1 {
        self.unit
    }

    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.value
    }

    #[must_use]
    pub const fn artifact_digest(self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn is_independently_attested(self) -> bool {
        false
    }
}

impl fmt::Debug for BoundPeakRssObservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundPeakRssObservationV1")
            .field("binding", &self.binding)
            .field("measurement_mechanism_artifact_bound", &true)
            .field("unit", &self.unit)
            .field("value", &self.value)
            .field("observation_artifact_bound", &true)
            .field("independently_attested", &false)
            .finish()
    }
}

enum PreparedFirstPartyProductOutputV1 {
    Passthrough(Box<RenderedProductResultV1>),
    Compiled(Box<CompiledProductResultV1>),
}

impl PreparedFirstPartyProductOutputV1 {
    fn rendered_bytes(&self) -> &[u8] {
        match self {
            Self::Passthrough(result) => result.artifact().text().as_bytes(),
            Self::Compiled(result) => result.artifact().text().as_bytes(),
        }
    }

    const fn method(&self) -> MethodDescriptor {
        match self {
            Self::Passthrough(_) => crate::log_brief_passthrough_method_descriptor_v1(),
            Self::Compiled(_) => crate::log_brief_compiled_method_descriptor_v1(),
        }
    }

    fn reported_token_count(&self) -> u64 {
        match self {
            Self::Passthrough(result) => result.artifact().brief().budget().total_rendered_tokens(),
            Self::Compiled(result) => result.artifact().brief().cost().total_rendered_tokens(),
        }
    }

    fn tokenizer_artifact_digest(&self) -> ArtifactDigest {
        match self {
            Self::Passthrough(result) => result.artifact().brief().budget().tokenizer_digest(),
            Self::Compiled(result) => result.artifact().brief().cost().tokenizer_digest(),
        }
    }

    const fn code(&self) -> &'static str {
        match self {
            Self::Passthrough(_) => "passthrough",
            Self::Compiled(_) => "compiled",
        }
    }
}

impl fmt::Debug for PreparedFirstPartyProductOutputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedFirstPartyProductOutputV1")
            .field("code", &self.code())
            .field("owned_product_artifact_present", &true)
            .finish()
    }
}

/// Public, label-free matched-case material frozen after both arms execute and
/// before governed annotations are admitted. The portable constructor leaves
/// peak RSS external; the constrained macOS constructor may retain its bound
/// Drain observer receipt while it obtains the matching first-party receipt.
pub struct PreparedPinnedDrainMatchedCaseV1 {
    preparation_contract_artifact_digest: ArtifactDigest,
    public_case: EvidentrailBenchCaseSpecV1,
    public_case_artifact_digest: ArtifactDigest,
    ledger: EventLedger,
    first_party_manifest: EvidentrailBenchRunManifestV1,
    drain_manifest: EvidentrailBenchRunManifestV1,
    first_party_case_input: PublicCaseInputBindingV1,
    drain_invocation: PublicSubprocessInvocationV1,
    first_party_build: FirstPartyInProcessBuildV1,
    drain_target: PinnedLegacyDrainExecutionTargetV1,
    _first_party_owner: MemoryProductV1,
    first_party_output: PreparedFirstPartyProductOutputV1,
    first_party_execution_measurement_artifact_digest: ArtifactDigest,
    first_party_wall_time_nanos: u64,
    first_party_tokens: CanonicalTokenCountProvenanceV1,
    drain_execution: SubprocessExecutionReceiptV1,
    drain_execution_measurement_artifact_digest: ArtifactDigest,
    drain_peak_rss_observer_receipt: Option<MacOsTimePeakRssReceiptV1>,
    drain_full_membership: LegacyDrainFullMembershipArtifactV1,
    drain_tokens: CanonicalTokenCountProvenanceV1,
}

impl PreparedPinnedDrainMatchedCaseV1 {
    #[must_use]
    pub const fn preparation_contract_artifact_digest(&self) -> ArtifactDigest {
        self.preparation_contract_artifact_digest
    }

    #[must_use]
    pub const fn public_case(&self) -> &EvidentrailBenchCaseSpecV1 {
        &self.public_case
    }

    #[must_use]
    pub const fn public_case_artifact_digest(&self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn ledger(&self) -> &EventLedger {
        &self.ledger
    }

    #[must_use]
    pub const fn first_party_manifest(&self) -> &EvidentrailBenchRunManifestV1 {
        &self.first_party_manifest
    }

    #[must_use]
    pub const fn drain_manifest(&self) -> &EvidentrailBenchRunManifestV1 {
        &self.drain_manifest
    }

    #[must_use]
    pub const fn first_party_case_input(&self) -> &PublicCaseInputBindingV1 {
        &self.first_party_case_input
    }

    #[must_use]
    pub const fn drain_invocation(&self) -> &PublicSubprocessInvocationV1 {
        &self.drain_invocation
    }

    #[must_use]
    pub const fn drain_execution(&self) -> &SubprocessExecutionReceiptV1 {
        &self.drain_execution
    }

    #[must_use]
    pub const fn drain_peak_rss_observer_receipt(&self) -> Option<MacOsTimePeakRssReceiptV1> {
        self.drain_peak_rss_observer_receipt
    }

    #[must_use]
    pub const fn drain_full_membership(&self) -> &LegacyDrainFullMembershipArtifactV1 {
        &self.drain_full_membership
    }

    #[must_use]
    pub const fn first_party_method(&self) -> MethodDescriptor {
        self.first_party_output.method()
    }

    pub(crate) const fn compiled_product_output(&self) -> Option<&CompiledProductResultV1> {
        match &self.first_party_output {
            PreparedFirstPartyProductOutputV1::Passthrough(_) => None,
            PreparedFirstPartyProductOutputV1::Compiled(result) => Some(result),
        }
    }

    pub(crate) fn bind_first_party_subprocess_measurement_v1(
        &mut self,
        execution_measurement_artifact_digest: ArtifactDigest,
        wall_time_nanos: u64,
    ) -> Result<(), PreparedPinnedDrainMatchedCaseErrorV1> {
        if wall_time_nanos == 0
            || wall_time_nanos
                > self
                    .first_party_manifest
                    .identity()
                    .budget()
                    .wall_time_nanos()
        {
            return Err(PreparedPinnedDrainMatchedCaseErrorV1::WallTimeUnavailable);
        }
        self.first_party_execution_measurement_artifact_digest =
            execution_measurement_artifact_digest;
        self.first_party_wall_time_nanos = wall_time_nanos;
        Ok(())
    }

    #[must_use]
    pub fn first_party_rendered_artifact_digest(&self) -> ArtifactDigest {
        artifact_digest_for_bytes_v1(self.first_party_output.rendered_bytes())
    }

    #[must_use]
    pub const fn first_party_wall_time_nanos(&self) -> u64 {
        self.first_party_wall_time_nanos
    }

    #[must_use]
    pub const fn first_party_execution_measurement_artifact_digest(&self) -> ArtifactDigest {
        self.first_party_execution_measurement_artifact_digest
    }

    #[must_use]
    pub const fn first_party_token_provenance(&self) -> CanonicalTokenCountProvenanceV1 {
        self.first_party_tokens
    }

    #[must_use]
    pub const fn drain_token_provenance(&self) -> CanonicalTokenCountProvenanceV1 {
        self.drain_tokens
    }

    #[must_use]
    pub const fn drain_target_class(&self) -> PinnedLegacyDrainTargetClassV1 {
        self.drain_target.class()
    }

    #[must_use]
    pub const fn contains_hidden_annotations(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn contains_scalar_outcome(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn candidate_proposal_union_available(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn cost_comparison_eligibility(&self) -> MatchedCostComparisonEligibilityV1 {
        MatchedCostComparisonEligibilityV1::unequal_v1()
    }

    pub fn peak_rss_observation_binding(
        &self,
        arm: PinnedDrainMatchedArmV1,
    ) -> Result<PeakRssObservationBindingV1, PreparedPinnedDrainMatchedCaseErrorV1> {
        let manifest = match arm {
            PinnedDrainMatchedArmV1::FirstParty => &self.first_party_manifest,
            PinnedDrainMatchedArmV1::PinnedDrainFullMembership => &self.drain_manifest,
        };
        peak_rss_observation_binding_v1(manifest, self.public_case_artifact_digest, arm)
    }

    /// Finalize both score-free public representation submissions only after
    /// receiving exactly one fully bound peak-RSS observation for each arm.
    /// This method has no annotation parameter and cannot emit a scalar score.
    pub fn try_finalize(
        &self,
        observations: &[BoundPeakRssObservationV1],
    ) -> Result<FinalizedPinnedDrainMatchedCaseV1, PreparedPinnedDrainMatchedCaseErrorV1> {
        self.first_party_build.reverify()?;
        self.drain_target.reverify()?;
        let first_party_peak = unique_observation(
            observations,
            PinnedDrainMatchedArmV1::FirstParty,
            self.peak_rss_observation_binding(PinnedDrainMatchedArmV1::FirstParty)?,
        )?;
        let drain_peak = unique_observation(
            observations,
            PinnedDrainMatchedArmV1::PinnedDrainFullMembership,
            self.peak_rss_observation_binding(PinnedDrainMatchedArmV1::PinnedDrainFullMembership)?,
        )?;
        if observations.len() != 2 {
            return Err(PreparedPinnedDrainMatchedCaseErrorV1::UnexpectedPeakRssObservation);
        }

        let first_party_measurement_harness = MeasurementHarnessIdentityV1::try_new(
            self.first_party_execution_measurement_artifact_digest,
            1,
        )
        .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::DomainConstructionFailed)?;
        let first_party_measurement = MeasuredCandidateResources::try_new(
            self.first_party_tokens.tokens(),
            self.first_party_wall_time_nanos,
            first_party_peak.bytes(),
        )
        .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::MeasurementBindingMismatch)?;
        let tokenizer = TokenizerIdentityV1::new(utf8_byte_tokenizer_digest_v1());
        let first_party_receipt = match &self.first_party_output {
            PreparedFirstPartyProductOutputV1::Passthrough(result) => {
                freeze_bound_owned_passthrough_log_brief_representation_v1(
                    &self.first_party_manifest,
                    &self.public_case,
                    &self.first_party_case_input,
                    &self.ledger,
                    result.artifact(),
                    tokenizer,
                    first_party_measurement_harness,
                    first_party_measurement,
                )?
            }
            PreparedFirstPartyProductOutputV1::Compiled(result) => {
                freeze_bound_owned_compiled_log_brief_representation_v1(
                    &self.first_party_manifest,
                    &self.public_case,
                    &self.first_party_case_input,
                    &self.ledger,
                    result.artifact(),
                    tokenizer,
                    first_party_measurement_harness,
                    first_party_measurement,
                )?
            }
        };

        let rendered_candidate = RenderedCandidateArtifactV1::try_new(
            self.drain_full_membership.raw_stdout_artifact_digest(),
            self.drain_full_membership.raw_stdout_byte_count(),
        )
        .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::MeasurementBindingMismatch)?;
        let drain_measurement_harness = MeasurementHarnessIdentityV1::try_new(
            self.drain_execution_measurement_artifact_digest,
            1,
        )
        .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::DomainConstructionFailed)?;
        let drain_environment = MeasurementEnvironmentV1::new(
            tokenizer,
            CandidateRendererIdentityV1::try_new(
                self.drain_full_membership.adapter_artifact_digest(),
                1,
            )
            .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::MeasurementBindingMismatch)?,
            drain_measurement_harness,
        );
        let drain_receipt = freeze_legacy_drain_full_membership_representation_with_method_v1(
            &self.drain_manifest,
            &self.ledger,
            &self.drain_execution,
            &self.drain_full_membership,
            self.drain_target.method(),
            drain_environment,
            rendered_candidate,
            self.drain_tokens,
            PeakRssProvenanceV1::ExternallySuppliedNotAttested {
                bytes: drain_peak.bytes(),
            },
        )?;

        let finalized_artifact_digest = derive_finalized_matched_case_artifact_digest(
            self.public_case_artifact_digest,
            &self.first_party_manifest,
            &self.drain_manifest,
            first_party_receipt.submission().artifact_digest(),
            drain_receipt.submission().artifact_digest(),
            first_party_peak.artifact_digest(),
            drain_peak.artifact_digest(),
            self.cost_comparison_eligibility(),
        )?;
        Ok(FinalizedPinnedDrainMatchedCaseV1 {
            artifact_digest: finalized_artifact_digest,
            public_case_artifact_digest: self.public_case_artifact_digest,
            first_party_manifest: self.first_party_manifest.clone(),
            drain_manifest: self.drain_manifest.clone(),
            first_party_receipt,
            drain_receipt,
            first_party_peak_rss: first_party_peak,
            drain_peak_rss: drain_peak,
        })
    }
}

impl fmt::Debug for PreparedPinnedDrainMatchedCaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedPinnedDrainMatchedCaseV1")
            .field("preparation_contract_bound", &true)
            .field("public_case_binding_present", &true)
            .field("pair_comparable_manifests_present", &true)
            .field("exact_case_input_binding_present", &true)
            .field("first_party_output", &self.first_party_output)
            .field("first_party_execution_charged", &true)
            .field("first_party_execution_measurement_bound", &true)
            .field("drain_target_class", &self.drain_target.class())
            .field("drain_execution_charged", &true)
            .field("full_membership_normalization_present", &true)
            .field("canonical_token_measurements_present", &true)
            .field(
                "peak_rss_observations_present",
                &self.drain_peak_rss_observer_receipt.is_some(),
            )
            .field("cost_comparison", &self.cost_comparison_eligibility())
            .field("contains_hidden_annotations", &false)
            .field("contains_scalar_outcome", &false)
            .field("candidate_proposal_union_available", &false)
            .finish()
    }
}

/// Finalized public submissions and bound measurement observations. This
/// remains score-free and contains no governed annotation or comparison result.
pub struct FinalizedPinnedDrainMatchedCaseV1 {
    artifact_digest: ArtifactDigest,
    public_case_artifact_digest: ArtifactDigest,
    first_party_manifest: EvidentrailBenchRunManifestV1,
    drain_manifest: EvidentrailBenchRunManifestV1,
    first_party_receipt: FirstPartyLogBriefRepresentationReceiptV1,
    drain_receipt: crate::LegacyDrainFullMembershipRepresentationReceiptV1,
    first_party_peak_rss: BoundPeakRssObservationV1,
    drain_peak_rss: BoundPeakRssObservationV1,
}

impl FinalizedPinnedDrainMatchedCaseV1 {
    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn public_case_artifact_digest(&self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn first_party_manifest(&self) -> &EvidentrailBenchRunManifestV1 {
        &self.first_party_manifest
    }

    #[must_use]
    pub const fn drain_manifest(&self) -> &EvidentrailBenchRunManifestV1 {
        &self.drain_manifest
    }

    #[must_use]
    pub const fn first_party_receipt(&self) -> &FirstPartyLogBriefRepresentationReceiptV1 {
        &self.first_party_receipt
    }

    #[must_use]
    pub const fn drain_receipt(&self) -> &crate::LegacyDrainFullMembershipRepresentationReceiptV1 {
        &self.drain_receipt
    }

    #[must_use]
    pub const fn first_party_peak_rss(&self) -> BoundPeakRssObservationV1 {
        self.first_party_peak_rss
    }

    #[must_use]
    pub const fn drain_peak_rss(&self) -> BoundPeakRssObservationV1 {
        self.drain_peak_rss
    }

    #[must_use]
    pub const fn contains_hidden_annotations(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn contains_scalar_outcome(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn candidate_proposal_union_available(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn cost_comparison_eligibility(&self) -> MatchedCostComparisonEligibilityV1 {
        MatchedCostComparisonEligibilityV1::unequal_v1()
    }
}

impl fmt::Debug for FinalizedPinnedDrainMatchedCaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalizedPinnedDrainMatchedCaseV1")
            .field("finalized_artifact_bound", &true)
            .field("public_case_binding_present", &true)
            .field("first_party_submission", &self.first_party_receipt)
            .field("drain_submission", &self.drain_receipt)
            .field("first_party_peak_rss", &self.first_party_peak_rss)
            .field("drain_peak_rss", &self.drain_peak_rss)
            .field("cost_comparison", &self.cost_comparison_eligibility())
            .field("contains_hidden_annotations", &false)
            .field("contains_scalar_outcome", &false)
            .field("candidate_proposal_union_available", &false)
            .finish()
    }
}

/// Execute and freeze the shared public fixture through the actual in-process
/// product owner and one separately charged full-membership subprocess arm.
///
/// This function never receives hidden annotations. It deliberately stops
/// before representation finalization because this portable harness does not
/// measure either arm's peak RSS.
pub fn prepare_pinned_drain_matched_case_v1(
    first_party_build: FirstPartyInProcessBuildV1,
    drain_target: PinnedLegacyDrainExecutionTargetV1,
) -> Result<PreparedPinnedDrainMatchedCaseV1, PreparedPinnedDrainMatchedCaseErrorV1> {
    let plan_digest = pinned_matched_plan_digest();
    let ledger = pinned_legacy_drain_matched_ledger_v1(plan_digest)?;
    prepare_matched_case_v1(
        MatchedCasePreparationV1 {
            preparation_contract_artifact_digest: artifact_digest_for_bytes_v1(
                PINNED_MATCHED_CASE_MANIFEST_V1,
            ),
            raw_input: PINNED_LEGACY_DRAIN_MATCHED_INPUT_V1,
            question: PINNED_LEGACY_DRAIN_MATCHED_QUESTION_V1,
            plan_digest,
            split_artifact_digest: artifact_digest_for_bytes_v1(PINNED_MATCHED_SPLIT_V1),
            leakage_artifact_digest: artifact_digest_for_bytes_v1(PINNED_MATCHED_LEAKAGE_V1),
            result_id: ResultId::from_bytes(
                *artifact_digest_for_bytes_v1(PINNED_MATCHED_RESULT_V1).as_bytes(),
            ),
            seed: PINNED_MATCHED_SEED_V1,
            budget: pinned_matched_budget()?,
            ledger,
        },
        first_party_build,
        drain_target,
        None,
    )
}

pub(crate) struct MatchedCasePreparationV1<'fixture> {
    pub(crate) preparation_contract_artifact_digest: ArtifactDigest,
    pub(crate) raw_input: &'fixture [u8],
    pub(crate) question: &'fixture [u8],
    pub(crate) plan_digest: PlanDigest,
    pub(crate) split_artifact_digest: ArtifactDigest,
    pub(crate) leakage_artifact_digest: ArtifactDigest,
    pub(crate) result_id: ResultId,
    pub(crate) seed: u64,
    pub(crate) budget: BenchmarkBudgetV1,
    pub(crate) ledger: EventLedger,
}

pub(crate) fn prepare_matched_case_v1(
    fixture: MatchedCasePreparationV1<'_>,
    first_party_build: FirstPartyInProcessBuildV1,
    drain_target: PinnedLegacyDrainExecutionTargetV1,
    drain_peak_rss_observer: Option<&MacOsTimePeakRssObserverV1>,
) -> Result<PreparedPinnedDrainMatchedCaseV1, PreparedPinnedDrainMatchedCaseErrorV1> {
    first_party_build.reverify()?;
    drain_target.reverify()?;

    let budget = fixture.budget;
    let source_digest = artifact_digest_for_bytes_v1(fixture.raw_input);
    let public_case = EvidentrailBenchCaseSpecV1::new(
        [source_digest],
        derive_question_digest_v1(fixture.question),
        fixture.plan_digest,
        [fixture.split_artifact_digest],
        [fixture.leakage_artifact_digest],
        [budget.cap()],
        ExpectedAcquisitionClassV1::Complete,
    )
    .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::DomainConstructionFailed)?;
    let public_case_artifact = canonical_public_case_artifact_v1(&public_case)?;
    let public_case_artifact_digest = public_case_artifact.artifact_digest();
    let first_party_manifest = matched_manifest(
        first_party_build.system_artifact_digest(),
        first_party_build.executable_build_artifact_digest(),
        source_digest,
        budget,
        public_case_artifact_digest,
        fixture.seed,
    )?;
    let drain_manifest = matched_manifest(
        drain_target.system_artifact_digest(),
        drain_target.executable_build_artifact_digest(),
        source_digest,
        budget,
        public_case_artifact_digest,
        fixture.seed,
    )?;
    first_party_manifest
        .ensure_paired_comparable_with(&drain_manifest)
        .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::RunManifestsNotPairComparable)?;

    let ledger = fixture.ledger;
    let first_party_case_input = matched_case_input(
        &first_party_manifest,
        &public_case,
        &ledger,
        source_digest,
        fixture.raw_input,
    )?;
    let drain_case_input = matched_case_input(
        &drain_manifest,
        &public_case,
        &ledger,
        source_digest,
        fixture.raw_input,
    )?;

    let mut first_party_owner = MemoryProductV1::new();
    let started = Instant::now();
    let decision = first_party_owner
        .create_deterministic_result_v1(
            fixture.result_id,
            fixture.question,
            ledger.clone(),
            UnixTimestampNanos::new(1),
            budget.canonical_candidate_tokens(),
        )
        .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::FirstPartyExecutionFailed)?;
    let first_party_wall_time_nanos = u64::try_from(started.elapsed().as_nanos())
        .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::WallTimeOverflow)?;
    if first_party_wall_time_nanos == 0 {
        return Err(PreparedPinnedDrainMatchedCaseErrorV1::WallTimeUnavailable);
    }
    first_party_build.reverify()?;
    let first_party_output = match decision {
        DeterministicProductDecisionV1::Passthrough(result) => {
            PreparedFirstPartyProductOutputV1::Passthrough(result)
        }
        DeterministicProductDecisionV1::Compiled(result) => {
            PreparedFirstPartyProductOutputV1::Compiled(result)
        }
        DeterministicProductDecisionV1::NeedsMore(_) => {
            return Err(PreparedPinnedDrainMatchedCaseErrorV1::FirstPartyNeedsMore);
        }
    };
    let first_party_tokens =
        measure_canonical_utf8_byte_tokens_v1(first_party_output.rendered_bytes())?;
    if !first_party_tokens.is_whole_render_measured()
        || first_party_tokens.tokens() != first_party_output.reported_token_count()
        || first_party_tokens.tokenizer_artifact_digest()
            != Some(first_party_output.tokenizer_artifact_digest())
        || first_party_tokens.tokens() > budget.canonical_candidate_tokens()
        || first_party_wall_time_nanos > budget.wall_time_nanos()
        || usize_exceeds_u64_cap(ledger.len(), budget.unique_candidate_event_count())
        || usize_exceeds_u64_cap(
            fixture.raw_input.len(),
            budget.unique_candidate_source_bytes(),
        )
    {
        return Err(PreparedPinnedDrainMatchedCaseErrorV1::CanonicalTokenBindingMismatch);
    }

    let limits = HarnessLimitsV1::try_new(
        u64::try_from(fixture.raw_input.len())
            .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::DomainConstructionFailed)?,
        LEGACY_DRAIN_FULL_MEMBERSHIP_STDOUT_CAP_V1,
        PINNED_MATCHED_STDERR_CAP_V1,
        budget.wall_time_nanos(),
    )?;
    let adapter = crate::LegacyDrainAdapterV1::try_new_full_membership(
        &drain_manifest,
        &drain_case_input,
        limits,
    )?;
    let (drain_invocation, _) = match drain_target.class {
        PinnedLegacyDrainTargetClassV1::VerifiedCleanPinnedCheckout => adapter
            .build_public_invocation(
                &drain_manifest,
                drain_case_input,
                drain_target.executable_path.clone(),
                drain_target.cwd.clone(),
                ClosedEnvironmentV1::empty(),
                limits,
            )?,
        PinnedLegacyDrainTargetClassV1::HermeticAdapterContractFixture => adapter
            .build_hermetic_contract_fixture_invocation(
                &drain_manifest,
                drain_case_input,
                drain_target.executable_path.clone(),
                drain_target.cwd.clone(),
                ClosedEnvironmentV1::empty(),
                limits,
            )?,
    };
    let (drain_execution, drain_peak_rss_observer_receipt) =
        if let Some(observer) = drain_peak_rss_observer {
            let binding = peak_rss_observation_binding_v1(
                &drain_manifest,
                public_case_artifact_digest,
                PinnedDrainMatchedArmV1::PinnedDrainFullMembership,
            )?;
            let (execution, receipt) =
                execute_with_macos_time_peak_rss_v1(observer, &drain_invocation, binding)?;
            (execution, Some(receipt))
        } else {
            (execute_public_subprocess_v1(&drain_invocation)?, None)
        };
    drain_target.reverify()?;
    let drain_full_membership = strict_normalize_pinned_legacy_drain_full_membership_v1(
        &drain_invocation,
        &drain_execution,
        LegacyDrainJsonLimitsV1::default(),
    )?;
    let drain_tokens = measure_canonical_utf8_byte_tokens_v1(drain_execution.stdout().bytes())?;
    if !drain_tokens.is_whole_render_measured()
        || drain_tokens.rendered_artifact_digest()
            != Some(drain_full_membership.raw_stdout_artifact_digest())
        || drain_tokens.rendered_byte_count() != Some(drain_full_membership.raw_stdout_byte_count())
        || drain_tokens.tokens() > budget.canonical_candidate_tokens()
        || drain_execution.wall_time_nanos() > budget.wall_time_nanos()
    {
        return Err(PreparedPinnedDrainMatchedCaseErrorV1::CanonicalTokenBindingMismatch);
    }

    Ok(PreparedPinnedDrainMatchedCaseV1 {
        preparation_contract_artifact_digest: fixture.preparation_contract_artifact_digest,
        public_case,
        public_case_artifact_digest,
        ledger,
        first_party_manifest,
        drain_manifest,
        first_party_case_input,
        drain_invocation,
        first_party_build,
        drain_target,
        _first_party_owner: first_party_owner,
        first_party_output,
        first_party_execution_measurement_artifact_digest: artifact_digest_for_bytes_v1(
            FIRST_PARTY_EXECUTION_MEASUREMENT_V1,
        ),
        first_party_wall_time_nanos,
        first_party_tokens,
        drain_execution,
        drain_execution_measurement_artifact_digest: drain_peak_rss_observer_receipt.map_or_else(
            || artifact_digest_for_bytes_v1(DRAIN_EXECUTION_MEASUREMENT_V1),
            MacOsTimePeakRssReceiptV1::artifact_digest,
        ),
        drain_peak_rss_observer_receipt,
        drain_full_membership,
        drain_tokens,
    })
}

/// Build the exact source-exact ledger shared by the legacy smoke and the new
/// matched preparation path.
pub fn pinned_legacy_drain_matched_ledger_v1(
    plan_digest: PlanDigest,
) -> Result<EventLedger, PreparedPinnedDrainMatchedCaseErrorV1> {
    let retrieval_id = RetrievalId::from_bytes([0x41; 32]);
    let plan_id = PlanId::from_bytes([0x42; 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([0x43; 32]);
    let adapter = AdapterIdentity::new("pinned-drain-matched-fixture", "1")
        .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::DomainConstructionFailed)?;
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let lane = LaneKey::new(
        SourceMember::new(b"pinned-drain-matched-source".to_vec())
            .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::DomainConstructionFailed)?,
        SourceStream::OtherVersioned {
            version: 1,
            code: 42,
        },
    );
    let records = canonical_records(PINNED_LEGACY_DRAIN_MATCHED_INPUT_V1);
    let mut builder = LedgerBuilder::new(
        fetch_identity.clone(),
        source_identity_digest,
        SourceExactPolicy,
    );
    for (sequence, (payload, terminator)) in records.iter().enumerate() {
        let sequence = u64::try_from(sequence)
            .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::DomainConstructionFailed)?;
        builder
            .accept(RawEnvelopeV1::new(
                envelope_identity.clone(),
                EnvelopeOrdering::new(
                    AcquisitionSequence::new(sequence),
                    lane.clone(),
                    LaneSequence::new(sequence),
                ),
                RecordBytes::framed(payload.clone(), terminator.clone()),
                RecordState::Complete,
            ))
            .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::DomainConstructionFailed)?;
    }
    let record_count = u64::try_from(records.len())
        .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::DomainConstructionFailed)?;
    let payload_byte_count = records.iter().try_fold(0_u64, |total, (payload, _)| {
        total
            .checked_add(
                u64::try_from(payload.len())
                    .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::DomainConstructionFailed)?,
            )
            .ok_or(PreparedPinnedDrainMatchedCaseErrorV1::DomainConstructionFailed)
    })?;
    let source_byte_count = u64::try_from(PINNED_LEGACY_DRAIN_MATCHED_INPUT_V1.len())
        .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::DomainConstructionFailed)?;
    let completion = FetchCompletion::new(
        fetch_identity,
        FetchTiming::new(UnixTimestampNanos::new(0), UnixTimestampNanos::new(1)),
        AcknowledgedCounts::new(record_count, payload_byte_count, source_byte_count),
        AttemptCounts::new(1, 1),
        AttemptCounts::default(),
        FetchBoundaries::default(),
        [],
        AdapterOutcome::Finished,
        [],
        FetchCompleteness::complete(CompletenessProof::OtherVersioned {
            version: 1,
            code: 42,
        }),
    )
    .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::DomainConstructionFailed)?;
    builder
        .seal(completion)
        .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::DomainConstructionFailed)
}

#[must_use]
pub fn pinned_legacy_drain_matched_plan_digest_v1() -> PlanDigest {
    pinned_matched_plan_digest()
}

fn pinned_matched_plan_digest() -> PlanDigest {
    PlanDigest::from_bytes(*artifact_digest_for_bytes_v1(PINNED_MATCHED_PLAN_V1).as_bytes())
}

fn pinned_matched_budget() -> Result<BenchmarkBudgetV1, PreparedPinnedDrainMatchedCaseErrorV1> {
    BenchmarkBudgetV1::try_new(
        Some(PINNED_MATCHED_EVENT_CAP_V1),
        Some(PINNED_MATCHED_SOURCE_BYTE_CAP_V1),
        Some(PINNED_MATCHED_TOKEN_CAP_V1),
        Some(PINNED_MATCHED_WALL_NANOS_V1),
        Some(PINNED_MATCHED_PEAK_BYTES_V1),
    )
    .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::DomainConstructionFailed)
}

fn matched_manifest(
    system_artifact_digest: ArtifactDigest,
    build_artifact_digest: ArtifactDigest,
    dataset_artifact_digest: ArtifactDigest,
    budget: BenchmarkBudgetV1,
    public_case_artifact_digest: ArtifactDigest,
    seed: u64,
) -> Result<EvidentrailBenchRunManifestV1, PreparedPinnedDrainMatchedCaseErrorV1> {
    let identity = BenchmarkRunIdentityV1::try_new(
        Some(system_artifact_digest),
        Some(build_artifact_digest),
        Some(dataset_artifact_digest),
        Some(seed),
        Some(budget),
    )
    .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::DomainConstructionFailed)?;
    EvidentrailBenchRunManifestV1::new(identity, [public_case_artifact_digest])
        .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::DomainConstructionFailed)
}

fn peak_rss_observation_binding_v1(
    manifest: &EvidentrailBenchRunManifestV1,
    public_case_artifact_digest: ArtifactDigest,
    arm: PinnedDrainMatchedArmV1,
) -> Result<PeakRssObservationBindingV1, PreparedPinnedDrainMatchedCaseErrorV1> {
    let canonical_run = canonical_public_run_manifest_artifact_v1(manifest)
        .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::DomainConstructionFailed)?;
    let identity = manifest.identity();
    Ok(PeakRssObservationBindingV1::new(
        arm,
        identity.system_artifact_digest(),
        identity.build_artifact_digest(),
        canonical_run.artifact_digest(),
        public_case_artifact_digest,
    ))
}

fn matched_case_input(
    manifest: &EvidentrailBenchRunManifestV1,
    public_case: &EvidentrailBenchCaseSpecV1,
    ledger: &EventLedger,
    source_digest: ArtifactDigest,
    raw_input: &[u8],
) -> Result<PublicCaseInputBindingV1, PreparedPinnedDrainMatchedCaseErrorV1> {
    let stdin = StdinArtifactV1::try_new(
        StdinArtifactClassV1::PublicCase,
        source_digest,
        raw_input.to_vec(),
    )?;
    PublicCaseInputBindingV1::try_new_canonical(manifest, public_case, stdin, ledger)
        .map_err(Into::into)
}

fn canonical_records(raw: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut records = Vec::new();
    let mut start = 0;
    for (position, byte) in raw.iter().copied().enumerate() {
        if byte != b'\n' {
            continue;
        }
        let payload_end = if position > start && raw[position - 1] == b'\r' {
            position - 1
        } else {
            position
        };
        records.push((
            raw[start..payload_end].to_vec(),
            raw[payload_end..=position].to_vec(),
        ));
        start = position + 1;
    }
    if start < raw.len() {
        records.push((raw[start..].to_vec(), Vec::new()));
    }
    records
}

fn unique_observation(
    observations: &[BoundPeakRssObservationV1],
    arm: PinnedDrainMatchedArmV1,
    expected_binding: PeakRssObservationBindingV1,
) -> Result<BoundPeakRssObservationV1, PreparedPinnedDrainMatchedCaseErrorV1> {
    let mut matching = observations
        .iter()
        .copied()
        .filter(|observation| observation.binding().arm() == arm);
    let observation = matching
        .next()
        .ok_or(PreparedPinnedDrainMatchedCaseErrorV1::MissingPeakRssObservation { arm })?;
    if matching.next().is_some() {
        return Err(PreparedPinnedDrainMatchedCaseErrorV1::DuplicatePeakRssObservation { arm });
    }
    if observation.binding() != expected_binding {
        return Err(PreparedPinnedDrainMatchedCaseErrorV1::PeakRssBindingMismatch { arm });
    }
    Ok(observation)
}

fn derive_peak_rss_observation_artifact_digest(
    binding: PeakRssObservationBindingV1,
    measurement_mechanism_artifact_digest: ArtifactDigest,
    unit: PeakRssMeasurementUnitV1,
    value: u64,
) -> Result<ArtifactDigest, PreparedPinnedDrainMatchedCaseErrorV1> {
    let mut bytes = Vec::new();
    append_artifact_field(&mut bytes, PEAK_RSS_OBSERVATION_DOMAIN_V1)?;
    append_artifact_field(&mut bytes, binding.arm().code().as_bytes())?;
    append_artifact_field(&mut bytes, binding.system_artifact_digest().as_bytes())?;
    append_artifact_field(
        &mut bytes,
        binding.executable_build_artifact_digest().as_bytes(),
    )?;
    append_artifact_field(
        &mut bytes,
        binding.public_run_manifest_artifact_digest().as_bytes(),
    )?;
    append_artifact_field(&mut bytes, binding.public_case_artifact_digest().as_bytes())?;
    append_artifact_field(&mut bytes, measurement_mechanism_artifact_digest.as_bytes())?;
    append_artifact_field(&mut bytes, unit.code().as_bytes())?;
    append_artifact_field(&mut bytes, &value.to_le_bytes())?;
    Ok(artifact_digest_for_bytes_v1(&bytes))
}

#[allow(clippy::too_many_arguments)]
fn derive_finalized_matched_case_artifact_digest(
    public_case_artifact_digest: ArtifactDigest,
    first_party_manifest: &EvidentrailBenchRunManifestV1,
    drain_manifest: &EvidentrailBenchRunManifestV1,
    first_party_submission_artifact_digest: ArtifactDigest,
    drain_submission_artifact_digest: ArtifactDigest,
    first_party_peak_rss_artifact_digest: ArtifactDigest,
    drain_peak_rss_artifact_digest: ArtifactDigest,
    cost_eligibility: MatchedCostComparisonEligibilityV1,
) -> Result<ArtifactDigest, PreparedPinnedDrainMatchedCaseErrorV1> {
    let first_run = canonical_public_run_manifest_artifact_v1(first_party_manifest)
        .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::DomainConstructionFailed)?;
    let drain_run = canonical_public_run_manifest_artifact_v1(drain_manifest)
        .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::DomainConstructionFailed)?;
    let mut bytes = Vec::new();
    append_artifact_field(&mut bytes, FINALIZED_MATCHED_CASE_DOMAIN_V1)?;
    append_artifact_field(&mut bytes, public_case_artifact_digest.as_bytes())?;
    append_artifact_field(&mut bytes, first_run.artifact_digest().as_bytes())?;
    append_artifact_field(&mut bytes, drain_run.artifact_digest().as_bytes())?;
    append_artifact_field(
        &mut bytes,
        first_party_submission_artifact_digest.as_bytes(),
    )?;
    append_artifact_field(&mut bytes, drain_submission_artifact_digest.as_bytes())?;
    append_artifact_field(&mut bytes, first_party_peak_rss_artifact_digest.as_bytes())?;
    append_artifact_field(&mut bytes, drain_peak_rss_artifact_digest.as_bytes())?;
    append_artifact_field(
        &mut bytes,
        cost_eligibility.first_party_scope().code().as_bytes(),
    )?;
    append_artifact_field(&mut bytes, cost_eligibility.drain_scope().code().as_bytes())?;
    Ok(artifact_digest_for_bytes_v1(&bytes))
}

fn append_artifact_field(
    output: &mut Vec<u8>,
    field: &[u8],
) -> Result<(), PreparedPinnedDrainMatchedCaseErrorV1> {
    let length = u64::try_from(field.len())
        .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::DomainConstructionFailed)?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(field);
    Ok(())
}

fn usize_exceeds_u64_cap(value: usize, cap: u64) -> bool {
    match u64::try_from(value) {
        Ok(value) => value > cap,
        Err(_) => true,
    }
}

fn verify_checkout(
    checkout: &Path,
    git_executable: &Path,
) -> Result<(), PreparedPinnedDrainMatchedCaseErrorV1> {
    let head = git_stdout(checkout, git_executable, &["rev-parse", "HEAD"])?;
    if trim_ascii(&head) != LEGACY_DRAIN_PINNED_COMMIT_V1.as_bytes() {
        return Err(PreparedPinnedDrainMatchedCaseErrorV1::RevisionMismatch);
    }
    let status = git_stdout(
        checkout,
        git_executable,
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?;
    if !status.is_empty() {
        return Err(PreparedPinnedDrainMatchedCaseErrorV1::WorktreeDirty);
    }
    Ok(())
}

fn git_stdout(
    checkout: &Path,
    git_executable: &Path,
    arguments: &[&str],
) -> Result<Vec<u8>, PreparedPinnedDrainMatchedCaseErrorV1> {
    let output = Command::new(git_executable)
        .env_clear()
        .arg("-C")
        .arg(checkout)
        .args(arguments)
        .output()
        .map_err(|_| PreparedPinnedDrainMatchedCaseErrorV1::GitUnavailable)?;
    if !output.status.success() {
        return Err(PreparedPinnedDrainMatchedCaseErrorV1::GitCommandFailed);
    }
    Ok(output.stdout)
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |position| position + 1);
    &bytes[start..end]
}

/// Contentless preparation/finalization failures.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PreparedPinnedDrainMatchedCaseErrorV1 {
    TargetUnavailable,
    TargetOutsideCheckout,
    GitUnavailable,
    GitCommandFailed,
    RevisionMismatch,
    WorktreeDirty,
    ExecutableChanged,
    DomainConstructionFailed,
    RunManifestsNotPairComparable,
    FirstPartyExecutionFailed,
    FirstPartyNeedsMore,
    WallTimeOverflow,
    WallTimeUnavailable,
    CanonicalTokenBindingMismatch,
    MeasurementBindingMismatch,
    InvalidPeakRssObservation,
    MissingPeakRssObservation { arm: PinnedDrainMatchedArmV1 },
    DuplicatePeakRssObservation { arm: PinnedDrainMatchedArmV1 },
    UnexpectedPeakRssObservation,
    PeakRssBindingMismatch { arm: PinnedDrainMatchedArmV1 },
    PeakRssObserver(PeakRssObserverErrorV1),
    Harness(HarnessError),
    Normalizer(LegacyDrainNormalizationErrorV1),
    DrainFidelity(LegacyDrainFidelityBridgeErrorV1),
    FirstPartyFidelity(FirstPartyLogBriefBridgeErrorV1),
}

impl PreparedPinnedDrainMatchedCaseErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TargetUnavailable => "EVIDENTRAIL_BENCH_MATCHED_TARGET_UNAVAILABLE",
            Self::TargetOutsideCheckout => "EVIDENTRAIL_BENCH_MATCHED_TARGET_OUTSIDE_CHECKOUT",
            Self::GitUnavailable => "EVIDENTRAIL_BENCH_MATCHED_GIT_UNAVAILABLE",
            Self::GitCommandFailed => "EVIDENTRAIL_BENCH_MATCHED_GIT_COMMAND_FAILED",
            Self::RevisionMismatch => "EVIDENTRAIL_BENCH_MATCHED_PINNED_REVISION_MISMATCH",
            Self::WorktreeDirty => "EVIDENTRAIL_BENCH_MATCHED_PINNED_WORKTREE_DIRTY",
            Self::ExecutableChanged => "EVIDENTRAIL_BENCH_MATCHED_EXECUTABLE_CHANGED",
            Self::DomainConstructionFailed => "EVIDENTRAIL_BENCH_MATCHED_DOMAIN_CONSTRUCTION_FAILED",
            Self::RunManifestsNotPairComparable => {
                "EVIDENTRAIL_BENCH_MATCHED_RUN_MANIFESTS_NOT_PAIR_COMPARABLE"
            }
            Self::FirstPartyExecutionFailed => "EVIDENTRAIL_BENCH_MATCHED_FIRST_PARTY_EXECUTION_FAILED",
            Self::FirstPartyNeedsMore => "EVIDENTRAIL_BENCH_MATCHED_FIRST_PARTY_NEEDS_MORE",
            Self::WallTimeOverflow => "EVIDENTRAIL_BENCH_MATCHED_WALL_TIME_OVERFLOW",
            Self::WallTimeUnavailable => "EVIDENTRAIL_BENCH_MATCHED_WALL_TIME_UNAVAILABLE",
            Self::CanonicalTokenBindingMismatch => {
                "EVIDENTRAIL_BENCH_MATCHED_CANONICAL_TOKEN_BINDING_MISMATCH"
            }
            Self::MeasurementBindingMismatch => "EVIDENTRAIL_BENCH_MATCHED_MEASUREMENT_BINDING_MISMATCH",
            Self::InvalidPeakRssObservation => "EVIDENTRAIL_BENCH_MATCHED_INVALID_PEAK_RSS_OBSERVATION",
            Self::MissingPeakRssObservation { .. } => {
                "EVIDENTRAIL_BENCH_MATCHED_PEAK_RSS_OBSERVATION_MISSING"
            }
            Self::DuplicatePeakRssObservation { .. } => {
                "EVIDENTRAIL_BENCH_MATCHED_PEAK_RSS_OBSERVATION_DUPLICATE"
            }
            Self::UnexpectedPeakRssObservation => {
                "EVIDENTRAIL_BENCH_MATCHED_PEAK_RSS_OBSERVATION_UNEXPECTED"
            }
            Self::PeakRssBindingMismatch { .. } => "EVIDENTRAIL_BENCH_MATCHED_PEAK_RSS_BINDING_MISMATCH",
            Self::PeakRssObserver(error) => error.code(),
            Self::Harness(error) => error.code(),
            Self::Normalizer(error) => error.code(),
            Self::DrainFidelity(error) => error.code(),
            Self::FirstPartyFidelity(error) => error.code(),
        }
    }
}

impl fmt::Debug for PreparedPinnedDrainMatchedCaseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("PreparedPinnedDrainMatchedCaseErrorV1");
        debug.field("code", &self.code());
        match self {
            Self::MissingPeakRssObservation { arm }
            | Self::DuplicatePeakRssObservation { arm }
            | Self::PeakRssBindingMismatch { arm } => {
                debug.field("arm", &arm.code());
            }
            _ => {}
        }
        debug.finish()
    }
}

impl fmt::Display for PreparedPinnedDrainMatchedCaseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for PreparedPinnedDrainMatchedCaseErrorV1 {}

impl From<HarnessError> for PreparedPinnedDrainMatchedCaseErrorV1 {
    fn from(error: HarnessError) -> Self {
        Self::Harness(error)
    }
}

impl From<PeakRssObserverErrorV1> for PreparedPinnedDrainMatchedCaseErrorV1 {
    fn from(error: PeakRssObserverErrorV1) -> Self {
        Self::PeakRssObserver(error)
    }
}

impl From<LegacyDrainNormalizationErrorV1> for PreparedPinnedDrainMatchedCaseErrorV1 {
    fn from(error: LegacyDrainNormalizationErrorV1) -> Self {
        Self::Normalizer(error)
    }
}

impl From<LegacyDrainFidelityBridgeErrorV1> for PreparedPinnedDrainMatchedCaseErrorV1 {
    fn from(error: LegacyDrainFidelityBridgeErrorV1) -> Self {
        Self::DrainFidelity(error)
    }
}

impl From<FirstPartyLogBriefBridgeErrorV1> for PreparedPinnedDrainMatchedCaseErrorV1 {
    fn from(error: FirstPartyLogBriefBridgeErrorV1) -> Self {
        Self::FirstPartyFidelity(error)
    }
}
