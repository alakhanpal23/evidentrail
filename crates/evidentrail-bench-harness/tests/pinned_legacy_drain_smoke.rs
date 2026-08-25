use std::fmt;
use std::path::PathBuf;
use std::process::Command;

use evidentrail_bench::{
    BenchmarkBudgetV1, BenchmarkRunIdentityV1, EvidentrailBenchCaseSpecV1, EvidentrailBenchRunManifestV1,
    ExpectedAcquisitionClassV1,
};
use evidentrail_bench_harness::{
    LEGACY_DRAIN_FULL_MEMBERSHIP_STDOUT_CAP_V1, LEGACY_DRAIN_PINNED_COMMIT_V1,
    CONSTRAINED_MATCHED_INPUT_ARTIFACT_DIGEST_V1, ClosedEnvironmentV1, LegacyDrainAdapterModeV1,
    LegacyDrainAdapterV1, LegacyDrainInputAssessmentV1, LegacyDrainJsonLimitsV1,
    LegacyDrainNormalizationErrorV1, LegacyDrainUnsupportedInputV1, ConstrainedMatchedCaseErrorV1,
    ConstrainedPairedTrialErrorV1, ConstrainedProducerUniverseBridgeErrorV1, ExitCategoryV1,
    FirstPartyConstrainedSubprocessErrorV1, FirstPartyConstrainedSubprocessTargetV1,
    FirstPartyInProcessBuildV1, HarnessError, HarnessLimitsV1,
    PINNED_LEGACY_DRAIN_MATCHED_INPUT_V1 as SYNTHETIC_INPUT, PinnedLegacyDrainExecutionTargetV1,
    PinnedLegacyDrainTargetClassV1, PinnedDrainMatchedArmV1, PreparedPinnedDrainMatchedCaseErrorV1,
    PublicCaseInputBindingV1, StdinArtifactClassV1, StdinArtifactV1, StdinDeliveryV1,
    StreamCaptureStateV1, artifact_digest_for_bytes_v1, artifact_digest_for_file_v1,
    canonical_public_case_artifact_v1, canonical_public_run_manifest_artifact_v1,
    current_constrained_first_party_policy_identity_v1, execute_public_subprocess_v1,
    freeze_constrained_producer_universes_v1, prepare_pinned_drain_matched_case_v1,
    run_constrained_paired_trials_for_expected_policy_v1, strict_identity_normalize_v1,
    strict_normalize_pinned_legacy_drain_full_membership_v1,
    strict_normalize_pinned_legacy_drain_output_v1,
};
use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    CompletenessProof, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, EventLedger,
    FetchBoundaries, FetchCompleteness, FetchCompletion, FetchIdentity, FetchTiming, LaneKey,
    LaneSequence, LedgerBuilder, PlanId, PolicyAuthorization, RawEnvelopeIdentityV1, RawEnvelopeV1,
    RecordBytes, RecordState, RetrievalId, SourceIdentityDigest, SourceMember, SourceStream,
    UnixTimestampNanos,
};
use evidentrail_schema::{ArtifactDigest, PlanDigest, QuestionDigest};

const CHECKOUT: &str = "/opt/evidentrail-bench/legacy-drain";
const EXECUTABLE: &str = "/opt/evidentrail-bench/legacy-drain/target/debug/legacy-drain";
const GIT_EXECUTABLE: &str = "/usr/bin/git";
const EXPECTED_FIRST_PARTY_POLICY_IDENTITY_V4: ArtifactDigest = ArtifactDigest::from_bytes([
    0x1a, 0xfb, 0xae, 0x0b, 0x9a, 0x60, 0x06, 0xc4, 0xbd, 0xc0, 0x93, 0x9d, 0x68, 0x31, 0x14, 0x40,
    0x4a, 0xcb, 0xff, 0xf6, 0xba, 0xab, 0xca, 0x7c, 0xde, 0xc2, 0x60, 0x55, 0x62, 0x02, 0x5a, 0x0c,
]);
const EXPECTED_BUILD_DIGEST: ArtifactDigest = ArtifactDigest::from_bytes([
    0x40, 0xa8, 0x3d, 0xb5, 0x9c, 0xf2, 0x02, 0x46, 0x38, 0x13, 0x63, 0xed, 0xdb, 0x2d, 0x27, 0xc5,
    0x6a, 0x38, 0x6d, 0x9e, 0x4d, 0xcf, 0x32, 0xac, 0x81, 0x15, 0xf5, 0x5b, 0x94, 0x45, 0xd2, 0x20,
]);
const EXPECTED_CONSTRAINED_DRAIN_POSTHOC_GROUPS: u64 = 8;
const EXPECTED_CONSTRAINED_FIRST_PRODUCER_UNIVERSE_DIGEST_V4: [u8; 32] = [
    0x99, 0x33, 0x2c, 0x0b, 0x3c, 0xa4, 0x3c, 0x71, 0xb0, 0x52, 0x2b, 0x8b, 0xda, 0x76, 0x3f, 0x3f,
    0x5a, 0xba, 0x2a, 0xa7, 0xbd, 0xa5, 0xa3, 0x00, 0x7d, 0x78, 0x6b, 0x9f, 0x7c, 0x84, 0x4c, 0x71,
];
const EXPECTED_CONSTRAINED_DRAIN_POSTHOC_UNIVERSE_DIGEST: [u8; 32] = [
    0xe9, 0xb5, 0xbe, 0x56, 0xb8, 0x06, 0x10, 0x11, 0xdf, 0x4f, 0x9b, 0x26, 0x01, 0x6e, 0x59, 0x84,
    0xad, 0x51, 0xb4, 0xea, 0x26, 0x62, 0xc1, 0x57, 0x85, 0xe4, 0x17, 0x94, 0xbf, 0x1a, 0xc8, 0xc0,
];
const EXPECTED_CONSTRAINED_PRODUCER_PAIR_DIGEST_V4: [u8; 32] = [
    0x0c, 0xbe, 0x95, 0xdd, 0x28, 0xf4, 0x2b, 0x14, 0x64, 0x63, 0x9b, 0xc5, 0x15, 0x91, 0x3c, 0x44,
    0x27, 0x26, 0x74, 0x6b, 0x5d, 0x7a, 0x95, 0x3f, 0xd9, 0xf0, 0x11, 0xfc, 0xeb, 0xef, 0xdd, 0xa5,
];
const EXPECTED_STDIN_DIGEST: ArtifactDigest = ArtifactDigest::from_bytes([
    0x88, 0xc0, 0xb9, 0x8f, 0x60, 0xe7, 0xa2, 0xf2, 0xe5, 0x89, 0xf1, 0x2f, 0xd8, 0xbe, 0x06, 0xcc,
    0x15, 0x58, 0xc0, 0x0c, 0x35, 0x0e, 0x40, 0x23, 0x50, 0x71, 0xc4, 0x34, 0xd1, 0xc9, 0x4c, 0xc5,
]);
const EXPECTED_RUN_MANIFEST_DIGEST: ArtifactDigest = ArtifactDigest::from_bytes([
    0x56, 0xd5, 0x64, 0xc6, 0x41, 0x6b, 0x96, 0x94, 0x49, 0x99, 0x19, 0x2c, 0xac, 0x0e, 0x46, 0x44,
    0xd4, 0x80, 0x10, 0x80, 0x08, 0x9a, 0xee, 0x0a, 0x0d, 0x69, 0xb3, 0x33, 0x42, 0xdd, 0xd7, 0xa2,
]);
const EXPECTED_PUBLIC_CASE_DIGEST: ArtifactDigest = ArtifactDigest::from_bytes([
    0x6c, 0xb9, 0x23, 0x3c, 0x12, 0x42, 0x18, 0x37, 0xbe, 0x94, 0xce, 0x0a, 0x60, 0x79, 0xf8, 0xdd,
    0x22, 0xd0, 0xd8, 0x9c, 0x45, 0x0d, 0x60, 0x4a, 0xf1, 0x4f, 0xf5, 0x78, 0x6a, 0xc7, 0x8f, 0x5c,
]);
const EXPECTED_SOURCE_RECORD_MAP_DIGEST: ArtifactDigest = ArtifactDigest::from_bytes([
    0x12, 0x63, 0xaa, 0x89, 0xbb, 0x9d, 0x83, 0x1b, 0x74, 0xb4, 0xad, 0xa5, 0xef, 0x22, 0x94, 0xf1,
    0x82, 0xdb, 0x40, 0xd0, 0xdb, 0xb6, 0xd1, 0xa9, 0xae, 0x0c, 0xac, 0x84, 0x68, 0xd1, 0x39, 0x2a,
]);
const EXPECTED_RETAINED_RECORD_MAP_DIGEST: ArtifactDigest = ArtifactDigest::from_bytes([
    0x7e, 0xab, 0xdf, 0xa3, 0x79, 0xbc, 0xa8, 0xa1, 0x01, 0x22, 0x95, 0x3f, 0xcd, 0x58, 0xf3, 0x3b,
    0xcd, 0xc3, 0x87, 0x24, 0x15, 0xe8, 0x4c, 0xa2, 0x1a, 0x47, 0xd7, 0xc4, 0xfd, 0xf2, 0x72, 0xf4,
]);
const EXPECTED_INVOCATION_DIGEST: [u8; 32] = [
    0x10, 0xa9, 0x22, 0xf8, 0x60, 0x77, 0x4c, 0x83, 0xbe, 0x65, 0xa9, 0x3c, 0x33, 0xc2, 0x4f, 0x8f,
    0x48, 0xa4, 0x8d, 0x6e, 0xe6, 0xc3, 0xff, 0xe7, 0xe7, 0x2e, 0xc6, 0xe3, 0x8c, 0x0a, 0x06, 0x9e,
];
const EXPECTED_STDOUT_DIGEST: ArtifactDigest = ArtifactDigest::from_bytes([
    0x00, 0x6b, 0x90, 0x81, 0x70, 0x1d, 0x69, 0x92, 0xf0, 0x89, 0x59, 0x73, 0xa9, 0x89, 0x4f, 0xa6,
    0x2e, 0xea, 0xa7, 0x8a, 0x7a, 0x54, 0xfe, 0x8c, 0x85, 0x3f, 0xa7, 0x58, 0x05, 0xb6, 0xa8, 0xd1,
]);
const EXPECTED_STDERR_DIGEST: ArtifactDigest = ArtifactDigest::from_bytes([
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
]);
const EXPECTED_NORMALIZER_DIGEST: ArtifactDigest = ArtifactDigest::from_bytes([
    0x24, 0x48, 0xca, 0xaf, 0x24, 0x25, 0xb3, 0x21, 0x1c, 0xec, 0xfa, 0xf0, 0x83, 0xdc, 0x71, 0x9f,
    0xa7, 0x5e, 0x30, 0xf9, 0x61, 0x2d, 0x4c, 0xe6, 0xcb, 0x42, 0x64, 0x76, 0x55, 0xc2, 0x70, 0x00,
]);
const EXPECTED_NORMALIZATION_RECEIPT_DIGEST: ArtifactDigest = ArtifactDigest::from_bytes([
    0x83, 0x0e, 0xb9, 0x51, 0x71, 0x09, 0x16, 0x0d, 0xa6, 0x33, 0xed, 0x54, 0x02, 0xd6, 0x54, 0x33,
    0x94, 0xc2, 0x7a, 0x73, 0x02, 0x78, 0x5a, 0x6e, 0x22, 0xf1, 0xcf, 0x8a, 0x03, 0xec, 0xd7, 0x7b,
]);
const EXPECTED_FULL_ADAPTER_DIGEST: ArtifactDigest = ArtifactDigest::from_bytes([
    0x0f, 0xcc, 0xb0, 0x8e, 0x86, 0x07, 0x77, 0x21, 0xaf, 0x2e, 0xf9, 0xb1, 0x1a, 0x37, 0x76, 0x9b,
    0xf0, 0x01, 0x1c, 0x64, 0x7f, 0x1a, 0xfb, 0x51, 0x24, 0x88, 0x8b, 0x21, 0xd4, 0x8d, 0x4f, 0x57,
]);
const EXPECTED_FULL_NORMALIZER_DIGEST: ArtifactDigest = ArtifactDigest::from_bytes([
    0x0a, 0x81, 0x4f, 0xad, 0x48, 0x2a, 0x88, 0x69, 0x9b, 0x2c, 0x53, 0xaa, 0x1d, 0x4a, 0x3a, 0x85,
    0x13, 0xf3, 0x7f, 0xc1, 0x83, 0x34, 0x01, 0x57, 0xd0, 0xf3, 0x6e, 0x5f, 0x0d, 0xa4, 0x4d, 0x6f,
]);
const EXPECTED_FULL_INVOCATION_DIGEST: [u8; 32] = [
    0xe8, 0xfb, 0x4e, 0xd0, 0xfc, 0xdb, 0x1a, 0xa4, 0xc5, 0x66, 0xac, 0x81, 0x51, 0x0f, 0x3a, 0xdc,
    0x4a, 0xbc, 0x70, 0xb7, 0xe7, 0x87, 0xa1, 0x66, 0x17, 0x51, 0xba, 0xab, 0x3e, 0xcf, 0xe2, 0x8c,
];
const EXPECTED_FULL_ARTIFACT_DIGEST: ArtifactDigest = ArtifactDigest::from_bytes([
    0x95, 0xc3, 0xb3, 0x69, 0x43, 0x11, 0x5e, 0x77, 0x0a, 0x23, 0x38, 0x82, 0xd8, 0xb0, 0x33, 0x0b,
    0xa9, 0x2d, 0x21, 0x21, 0xdd, 0x6d, 0xda, 0x9e, 0x29, 0x9a, 0x7e, 0xb5, 0x81, 0x7a, 0x27, 0xaf,
]);
const EXPECTED_FULL_STDOUT_DIGEST: ArtifactDigest = ArtifactDigest::from_bytes([
    0xdc, 0x7c, 0x13, 0xff, 0x6b, 0x66, 0x1f, 0x78, 0x04, 0x8f, 0x92, 0xdf, 0x91, 0x6e, 0x07, 0xd5,
    0x73, 0x62, 0x59, 0xc7, 0x45, 0xce, 0x1e, 0x06, 0x0d, 0x04, 0x60, 0xcf, 0x48, 0xbe, 0x37, 0xb8,
]);

struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SmokeBlocker {
    CheckoutUnavailable,
    GitUnavailable,
    GitCommandFailed,
    RevisionMismatch,
    WorktreeDirty,
    ExecutableUnavailable,
    BuildArtifactMismatch,
    DomainConstructionFailed,
    Harness(HarnessError),
    Normalizer(LegacyDrainNormalizationErrorV1),
    Matched(PreparedPinnedDrainMatchedCaseErrorV1),
    Constrained(ConstrainedMatchedCaseErrorV1),
    FirstPartySubprocess(FirstPartyConstrainedSubprocessErrorV1),
    PairedTrials(ConstrainedPairedTrialErrorV1),
    ProducerUniverse(ConstrainedProducerUniverseBridgeErrorV1),
    UnexpectedNormalization,
    UnexpectedInvocationContract,
    UnexpectedExecutionOutcome,
    OpaqueOutputWasNormalized,
    UnexpectedOpaqueNormalization,
    NondeterministicOpaqueOutput,
    RecordedArtifactMismatch,
}

impl SmokeBlocker {
    const fn code(self) -> &'static str {
        match self {
            Self::CheckoutUnavailable => "LEGACY_DRAIN_SMOKE_CHECKOUT_UNAVAILABLE",
            Self::GitUnavailable => "LEGACY_DRAIN_SMOKE_GIT_UNAVAILABLE",
            Self::GitCommandFailed => "LEGACY_DRAIN_SMOKE_GIT_COMMAND_FAILED",
            Self::RevisionMismatch => "LEGACY_DRAIN_SMOKE_REVISION_MISMATCH",
            Self::WorktreeDirty => "LEGACY_DRAIN_SMOKE_WORKTREE_DIRTY",
            Self::ExecutableUnavailable => "LEGACY_DRAIN_SMOKE_EXECUTABLE_UNAVAILABLE",
            Self::BuildArtifactMismatch => "LEGACY_DRAIN_SMOKE_BUILD_ARTIFACT_MISMATCH",
            Self::DomainConstructionFailed => "LEGACY_DRAIN_SMOKE_DOMAIN_CONSTRUCTION_FAILED",
            Self::Harness(error) => error.code(),
            Self::Normalizer(error) => error.code(),
            Self::Matched(error) => error.code(),
            Self::Constrained(error) => error.code(),
            Self::FirstPartySubprocess(error) => error.code(),
            Self::PairedTrials(error) => error.code(),
            Self::ProducerUniverse(error) => error.code(),
            Self::UnexpectedNormalization => "LEGACY_DRAIN_SMOKE_UNEXPECTED_NORMALIZATION",
            Self::UnexpectedInvocationContract => {
                "LEGACY_DRAIN_SMOKE_UNEXPECTED_INVOCATION_CONTRACT"
            }
            Self::UnexpectedExecutionOutcome => "LEGACY_DRAIN_SMOKE_UNEXPECTED_EXECUTION_OUTCOME",
            Self::OpaqueOutputWasNormalized => "LEGACY_DRAIN_SMOKE_OPAQUE_OUTPUT_WAS_NORMALIZED",
            Self::UnexpectedOpaqueNormalization => {
                "LEGACY_DRAIN_SMOKE_UNEXPECTED_OPAQUE_NORMALIZATION"
            }
            Self::NondeterministicOpaqueOutput => {
                "LEGACY_DRAIN_SMOKE_NONDETERMINISTIC_OPAQUE_OUTPUT"
            }
            Self::RecordedArtifactMismatch => "LEGACY_DRAIN_SMOKE_RECORDED_ARTIFACT_MISMATCH",
        }
    }
}

impl fmt::Debug for SmokeBlocker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SmokeBlocker")
            .field("code", &self.code())
            .finish()
    }
}

impl From<HarnessError> for SmokeBlocker {
    fn from(error: HarnessError) -> Self {
        Self::Harness(error)
    }
}

impl From<LegacyDrainNormalizationErrorV1> for SmokeBlocker {
    fn from(error: LegacyDrainNormalizationErrorV1) -> Self {
        Self::Normalizer(error)
    }
}

impl From<PreparedPinnedDrainMatchedCaseErrorV1> for SmokeBlocker {
    fn from(error: PreparedPinnedDrainMatchedCaseErrorV1) -> Self {
        Self::Matched(error)
    }
}

impl From<ConstrainedMatchedCaseErrorV1> for SmokeBlocker {
    fn from(error: ConstrainedMatchedCaseErrorV1) -> Self {
        Self::Constrained(error)
    }
}

impl From<FirstPartyConstrainedSubprocessErrorV1> for SmokeBlocker {
    fn from(error: FirstPartyConstrainedSubprocessErrorV1) -> Self {
        Self::FirstPartySubprocess(error)
    }
}

impl From<ConstrainedProducerUniverseBridgeErrorV1> for SmokeBlocker {
    fn from(error: ConstrainedProducerUniverseBridgeErrorV1) -> Self {
        Self::ProducerUniverse(error)
    }
}

impl From<ConstrainedPairedTrialErrorV1> for SmokeBlocker {
    fn from(error: ConstrainedPairedTrialErrorV1) -> Self {
        Self::PairedTrials(error)
    }
}

/// Explicitly opt-in because it depends on one pinned local checkout and
/// executable artifact. The compact arm remains opaque; the distinct, charged
/// full arm proves `PatternRepresented` occurrence membership. Neither arm
/// constructs exact evidence recall, a quality score, or a hosted Evidentrail result.
#[test]
#[ignore = "opt-in pinned local legacy-drain smoke; non-scoring reproducibility evidence only"]
fn pinned_local_legacy_drain_is_deterministic_and_non_scoring() -> Result<(), SmokeBlocker> {
    assert_checkout_state()?;

    let checkout = PathBuf::from(CHECKOUT)
        .canonicalize()
        .map_err(|_| SmokeBlocker::CheckoutUnavailable)?;
    let executable = PathBuf::from(EXECUTABLE)
        .canonicalize()
        .map_err(|_| SmokeBlocker::ExecutableUnavailable)?;
    let build_digest = artifact_digest_for_file_v1(&executable)
        .map_err(|_| SmokeBlocker::ExecutableUnavailable)?;
    if build_digest != EXPECTED_BUILD_DIGEST {
        return Err(SmokeBlocker::BuildArtifactMismatch);
    }

    let source_digest = artifact_digest_for_bytes_v1(SYNTHETIC_INPUT);
    if source_digest != EXPECTED_STDIN_DIGEST {
        return Err(SmokeBlocker::RecordedArtifactMismatch);
    }
    let budget = BenchmarkBudgetV1::try_new(
        Some(1_000_000),
        Some(64 * 1024 * 1024),
        Some(10_000_000),
        Some(10_000_000_000),
        Some(10_000_000_000),
    )
    .map_err(|_| SmokeBlocker::DomainConstructionFailed)?;
    let run_identity = BenchmarkRunIdentityV1::try_new(
        Some(artifact_digest_for_bytes_v1(
            LEGACY_DRAIN_PINNED_COMMIT_V1.as_bytes(),
        )),
        Some(build_digest),
        Some(source_digest),
        Some(1),
        Some(budget),
    )
    .map_err(|_| SmokeBlocker::DomainConstructionFailed)?;
    let public_case = EvidentrailBenchCaseSpecV1::new(
        [source_digest],
        QuestionDigest::from_bytes([0x31; 32]),
        PlanDigest::from_bytes([0x32; 32]),
        [artifact_digest_for_bytes_v1(b"pinned-drain-smoke-split-v1")],
        [artifact_digest_for_bytes_v1(
            b"pinned-drain-smoke-leakage-policy-v1",
        )],
        [budget.cap()],
        ExpectedAcquisitionClassV1::Complete,
    )
    .map_err(|_| SmokeBlocker::DomainConstructionFailed)?;
    let public_case_artifact = canonical_public_case_artifact_v1(&public_case)?;
    let public_case_artifact_digest = public_case_artifact.artifact_digest();
    let run_manifest = EvidentrailBenchRunManifestV1::new(run_identity, [public_case_artifact_digest])
        .map_err(|_| SmokeBlocker::DomainConstructionFailed)?;
    let stdin = StdinArtifactV1::try_new(
        StdinArtifactClassV1::HermeticSyntheticFixture,
        source_digest,
        SYNTHETIC_INPUT.to_vec(),
    )?;
    let ledger = source_exact_ledger(SYNTHETIC_INPUT, public_case.plan_digest())?;
    let case_input =
        PublicCaseInputBindingV1::try_new_canonical(&run_manifest, &public_case, stdin, &ledger)?;
    let adapter = LegacyDrainAdapterV1::try_new(2)?;
    let limits = HarnessLimitsV1::try_new(
        u64::try_from(SYNTHETIC_INPUT.len()).map_err(|_| SmokeBlocker::DomainConstructionFailed)?,
        1024 * 1024,
        1024 * 1024,
        10_000_000_000,
    )?;
    let (invocation, normalization) = adapter.build_public_invocation(
        &run_manifest,
        case_input,
        executable.clone(),
        checkout.clone(),
        ClosedEnvironmentV1::empty(),
        limits,
    )?;
    if invocation.program().executable_path() != executable
        || invocation.program().executable_build_artifact_digest() != EXPECTED_BUILD_DIGEST
        || invocation.run_manifest_artifact_digest() != EXPECTED_RUN_MANIFEST_DIGEST
        || invocation.public_case_artifact_digest() != EXPECTED_PUBLIC_CASE_DIGEST
        || invocation.source_record_map().map_artifact_digest() != EXPECTED_SOURCE_RECORD_MAP_DIGEST
        || invocation.digest().as_bytes() != &EXPECTED_INVOCATION_DIGEST
        || invocation.program().cwd() != checkout
        || invocation.program().argv() != adapter.fixed_argv()
        || invocation.program().adapter_revision() != Some(LEGACY_DRAIN_PINNED_COMMIT_V1)
        || !invocation
            .program()
            .environment()
            .allowed_names()
            .is_empty()
        || !invocation.program().environment().bindings().is_empty()
        || invocation.stdin().artifact_digest() != EXPECTED_STDIN_DIGEST
        || invocation.stdin().bytes() != SYNTHETIC_INPUT
    {
        return Err(SmokeBlocker::UnexpectedInvocationContract);
    }

    if normalization.input_byte_count() != SYNTHETIC_INPUT.len() as u64
        || normalization.logical_line_count() != 6
        || normalization.retained_nonblank_line_count() != 5
        || normalization.dropped_blank_line_count() != 1
        || normalization.lf_terminator_count() != 5
        || normalization.crlf_terminator_count() != 1
        || normalization.final_lf_present()
        || !normalization.blank_lines_are_dropped()
        || !normalization.line_terminators_are_discarded()
        || !normalization.whitespace_may_be_tokenized_and_rejoined()
        || !normalization.timestamp_and_level_may_be_extracted()
    {
        return Err(SmokeBlocker::UnexpectedNormalization);
    }
    if adapter.assess_input(b"valid\n\xff")?
        != LegacyDrainInputAssessmentV1::Unsupported(LegacyDrainUnsupportedInputV1::InvalidUtf8)
    {
        return Err(SmokeBlocker::UnexpectedNormalization);
    }

    let first = execute_public_subprocess_v1(&invocation)?;
    let second = execute_public_subprocess_v1(&invocation)?;
    for execution in [&first, &second] {
        if execution.exit_category() != ExitCategoryV1::Success
            || execution.stdin_delivery() != StdinDeliveryV1::Complete
            || execution.stdout().state() != StreamCaptureStateV1::Complete
            || execution.stderr().state() != StreamCaptureStateV1::Complete
            || !execution.termination_causes().is_empty()
            || !execution.executable_path_digest_verified_before_spawn()
            || !execution.executable_path_digest_verified_after_spawn()
        {
            return Err(SmokeBlocker::UnexpectedExecutionOutcome);
        }
        if strict_identity_normalize_v1(execution)
            != Err(HarnessError::OutputNormalizationUnsupported)
        {
            return Err(SmokeBlocker::OpaqueOutputWasNormalized);
        }
    }
    if first.stdout().bytes().is_empty()
        || first.stdout().artifact_digest() != second.stdout().artifact_digest()
        || first.stdout().bytes() != second.stdout().bytes()
        || first.stderr().artifact_digest() != second.stderr().artifact_digest()
        || first.stderr().bytes() != second.stderr().bytes()
    {
        return Err(SmokeBlocker::NondeterministicOpaqueOutput);
    }
    if first.stdout().artifact_digest() != EXPECTED_STDOUT_DIGEST
        || first.stderr().artifact_digest() != EXPECTED_STDERR_DIGEST
        || first.stdout().byte_count() != 1570
    {
        return Err(SmokeBlocker::RecordedArtifactMismatch);
    }

    let normalized_first = strict_normalize_pinned_legacy_drain_output_v1(
        &invocation,
        &first,
        LegacyDrainJsonLimitsV1::default(),
    )?;
    let normalized_second = strict_normalize_pinned_legacy_drain_output_v1(
        &invocation,
        &second,
        LegacyDrainJsonLimitsV1::default(),
    )?;
    println!(
        "pinned smoke build={} run_manifest={} public_case={} stdin={} source_record_map={} retained_record_map={} invocation={} stdout={} stdout_bytes={} stderr={} stderr_bytes={} normalizer={} normalization_receipt={}",
        hex(build_digest.as_bytes()),
        hex(invocation.run_manifest_artifact_digest().as_bytes()),
        hex(invocation.public_case_artifact_digest().as_bytes()),
        hex(source_digest.as_bytes()),
        hex(normalized_first
            .source_record_map_artifact_digest()
            .as_bytes()),
        hex(normalized_first
            .retained_record_map_artifact_digest()
            .as_bytes()),
        hex(invocation.digest().as_bytes()),
        hex(first.stdout().artifact_digest().as_bytes()),
        first.stdout().byte_count(),
        hex(first.stderr().artifact_digest().as_bytes()),
        first.stderr().byte_count(),
        hex(normalized_first.normalizer_artifact_digest().as_bytes()),
        hex(normalized_first.normalization_artifact_digest().as_bytes()),
    );
    let membership = normalized_first.membership_unprovable();
    if normalized_first != normalized_second
        || normalized_first.normalizer_artifact_digest() != EXPECTED_NORMALIZER_DIGEST
        || normalized_first.normalization_artifact_digest() != EXPECTED_NORMALIZATION_RECEIPT_DIGEST
        || normalized_first.executable_build_artifact_digest() != EXPECTED_BUILD_DIGEST
        || normalized_first.stdin_artifact_digest() != EXPECTED_STDIN_DIGEST
        || normalized_first.source_record_map_artifact_digest() != EXPECTED_SOURCE_RECORD_MAP_DIGEST
        || normalized_first.retained_record_map_artifact_digest()
            != EXPECTED_RETAINED_RECORD_MAP_DIGEST
        || normalized_first.raw_stdout_artifact_digest() != EXPECTED_STDOUT_DIGEST
        || normalized_first.raw_stderr_artifact_digest() != EXPECTED_STDERR_DIGEST
        || normalized_first.raw_stdout_byte_count() != 1570
        || normalized_first.raw_stderr_byte_count() != 0
        || normalized_first.original_count() != 5
        || normalized_first.template_count() != 2
        || normalized_first.group_count() != 2
        || normalized_first.sample_count() != 4
        || normalized_first.sample_count() >= normalized_first.original_count()
        || normalized_first.slot_count() != 2
        || normalized_first.slot_sample_count() != 5
        || normalized_first.candidate_membership_scoreable()
        || !normalized_first.raw_stdout_remains_opaque()
        || !membership.original_source_record_bytes_present()
        || !membership.sampled_position_indices_structurally_bounded()
        || membership.sampled_normalized_fields_verified_against_source()
        || membership.sampled_occurrence_evidence_joinable()
        || membership.complete_group_occurrence_positions_present()
        || !membership.source_framing_preserved_by_binding()
    {
        return Err(SmokeBlocker::UnexpectedOpaqueNormalization);
    }

    let full_stdin = StdinArtifactV1::try_new(
        StdinArtifactClassV1::HermeticSyntheticFixture,
        source_digest,
        SYNTHETIC_INPUT.to_vec(),
    )?;
    let full_case_input = PublicCaseInputBindingV1::try_new_canonical(
        &run_manifest,
        &public_case,
        full_stdin,
        &ledger,
    )?;
    let full_limits = HarnessLimitsV1::try_new(
        u64::try_from(SYNTHETIC_INPUT.len()).map_err(|_| SmokeBlocker::DomainConstructionFailed)?,
        LEGACY_DRAIN_FULL_MEMBERSHIP_STDOUT_CAP_V1,
        1024 * 1024,
        10_000_000_000,
    )?;
    let full_adapter =
        LegacyDrainAdapterV1::try_new_full_membership(&run_manifest, &full_case_input, full_limits)?;
    let (full_invocation, _) = full_adapter.build_public_invocation(
        &run_manifest,
        full_case_input,
        executable,
        checkout,
        ClosedEnvironmentV1::empty(),
        full_limits,
    )?;
    if full_adapter.mode() != LegacyDrainAdapterModeV1::FullMembershipAudit
        || full_adapter.sample_cap() != 5
        || full_invocation.digest() == invocation.digest()
        || full_invocation.digest().as_bytes() != &EXPECTED_FULL_INVOCATION_DIGEST
    {
        return Err(SmokeBlocker::UnexpectedInvocationContract);
    }
    let full_first_execution = execute_public_subprocess_v1(&full_invocation)?;
    let full_second_execution = execute_public_subprocess_v1(&full_invocation)?;
    let full_first = strict_normalize_pinned_legacy_drain_full_membership_v1(
        &full_invocation,
        &full_first_execution,
        LegacyDrainJsonLimitsV1::default(),
    )?;
    let full_second = strict_normalize_pinned_legacy_drain_full_membership_v1(
        &full_invocation,
        &full_second_execution,
        LegacyDrainJsonLimitsV1::default(),
    )?;
    if full_first != full_second
        || full_first.adapter_artifact_digest() != EXPECTED_FULL_ADAPTER_DIGEST
        || full_first.normalizer_artifact_digest() != EXPECTED_FULL_NORMALIZER_DIGEST
        || full_first.artifact_digest() != EXPECTED_FULL_ARTIFACT_DIGEST
        || full_first.raw_stdout_artifact_digest() != EXPECTED_FULL_STDOUT_DIGEST
        || full_first.raw_stdout_byte_count() != 1732
        || full_first.raw_stdout_artifact_digest() == normalized_first.raw_stdout_artifact_digest()
        || full_first.raw_stdout_byte_count() <= normalized_first.raw_stdout_byte_count()
        || full_first.pattern_memberships().len() != 5
        || full_first.transformed_samples().len() != 5
        || full_first.charged_candidate_event_count() != 5
        || full_first.charged_candidate_source_bytes()
            != u64::try_from(SYNTHETIC_INPUT.len())
                .map_err(|_| SmokeBlocker::DomainConstructionFailed)?
                - 1
        || !full_first.occurrence_membership_proven()
        || !full_first.resource_and_compression_accounting_available()
        || full_first.diagnostic_evidence_recall_scoreable()
        || full_first.source_exact_or_shown_verbatim()
        || !full_first.full_execution_measurement_required()
        || full_first
            .pattern_memberships()
            .iter()
            .zip(full_first.transformed_samples())
            .enumerate()
            .any(|(index, (pattern, sample))| {
                u64::try_from(index).ok() != Some(pattern.retained_index())
                    || pattern.retained_index() != sample.retained_index()
                    || pattern.event_id() != sample.event_id()
            })
    {
        return Err(SmokeBlocker::UnexpectedOpaqueNormalization);
    }
    println!(
        "pinned full-membership smoke adapter={} normalizer={} invocation={} artifact={} stdout={} stdout_bytes={} occurrence_count={} charged_source_bytes={} diagnostic_recall_scoreable=false shown_verbatim=false",
        hex(full_first.adapter_artifact_digest().as_bytes()),
        hex(full_first.normalizer_artifact_digest().as_bytes()),
        hex(full_invocation.digest().as_bytes()),
        hex(full_first.artifact_digest().as_bytes()),
        hex(full_first.raw_stdout_artifact_digest().as_bytes()),
        full_first.raw_stdout_byte_count(),
        full_first.pattern_memberships().len(),
        full_first.charged_candidate_source_bytes(),
    );

    assert_checkout_state()?;
    Ok(())
}

/// Opt-in same-case boundary using the actual in-process product owner and the
/// verified pinned local full-membership executable. It intentionally stops at
/// the typed peak-RSS blocker and emits no governed score.
#[test]
#[ignore = "opt-in actual first-party + pinned local legacy-drain preparation; score-free"]
fn pinned_local_legacy_drain_prepares_exact_matched_case_without_peak_rss_fabrication()
-> Result<(), SmokeBlocker> {
    assert_checkout_state()?;
    let first_party = FirstPartyInProcessBuildV1::try_new(
        std::env::current_exe().map_err(|_| SmokeBlocker::ExecutableUnavailable)?,
    )?;
    let drain = PinnedLegacyDrainExecutionTargetV1::try_new_verified_local_checkout(
        CHECKOUT,
        EXECUTABLE,
        GIT_EXECUTABLE,
    )?;
    if drain.executable_build_artifact_digest() != EXPECTED_BUILD_DIGEST {
        return Err(SmokeBlocker::BuildArtifactMismatch);
    }
    let prepared = prepare_pinned_drain_matched_case_v1(first_party, drain)?;
    prepared
        .first_party_manifest()
        .ensure_paired_comparable_with(prepared.drain_manifest())
        .map_err(|_| SmokeBlocker::DomainConstructionFailed)?;
    if prepared.drain_target_class() != PinnedLegacyDrainTargetClassV1::VerifiedCleanPinnedCheckout
        || prepared.drain_invocation().program().adapter_revision()
            != Some(LEGACY_DRAIN_PINNED_COMMIT_V1)
        || prepared.drain_full_membership().pattern_memberships().len() != 5
        || prepared.drain_full_membership().transformed_samples().len() != 5
        || prepared
            .drain_full_membership()
            .raw_stdout_artifact_digest()
            != EXPECTED_FULL_STDOUT_DIGEST
        || !prepared
            .first_party_token_provenance()
            .is_whole_render_measured()
        || !prepared.drain_token_provenance().is_whole_render_measured()
        || prepared.contains_hidden_annotations()
        || prepared.contains_scalar_outcome()
        || prepared.candidate_proposal_union_available()
        || prepared
            .cost_comparison_eligibility()
            .cost_ordering_eligible()
        || prepared.cost_comparison_eligibility().first_party_scope()
            == prepared.cost_comparison_eligibility().drain_scope()
    {
        return Err(SmokeBlocker::UnexpectedOpaqueNormalization);
    }
    if !matches!(
        prepared.try_finalize(&[]),
        Err(
            PreparedPinnedDrainMatchedCaseErrorV1::MissingPeakRssObservation {
                arm: PinnedDrainMatchedArmV1::FirstParty,
            }
        )
    ) {
        return Err(SmokeBlocker::UnexpectedExecutionOutcome);
    }

    let first_run = canonical_public_run_manifest_artifact_v1(prepared.first_party_manifest())?;
    let drain_run = canonical_public_run_manifest_artifact_v1(prepared.drain_manifest())?;
    println!(
        "pinned matched preparation case={} first_build={} first_run={} first_render={} first_tokens={} first_scope={} drain_build={} drain_run={} drain_invocation={} drain_full_artifact={} drain_stdout={} drain_tokens={} drain_scope={} peak_rss=missing_typed cost_ordering=ineligible_unequal_execution_scopes score=false proposal_union=false hosted=false",
        hex(prepared.public_case_artifact_digest().as_bytes()),
        hex(prepared
            .first_party_manifest()
            .identity()
            .build_artifact_digest()
            .as_bytes()),
        hex(first_run.artifact_digest().as_bytes()),
        hex(prepared.first_party_rendered_artifact_digest().as_bytes()),
        prepared.first_party_token_provenance().tokens(),
        prepared
            .cost_comparison_eligibility()
            .first_party_scope()
            .code(),
        hex(prepared
            .drain_manifest()
            .identity()
            .build_artifact_digest()
            .as_bytes()),
        hex(drain_run.artifact_digest().as_bytes()),
        hex(prepared.drain_invocation().digest().as_bytes()),
        hex(prepared
            .drain_full_membership()
            .artifact_digest()
            .as_bytes()),
        hex(prepared
            .drain_full_membership()
            .raw_stdout_artifact_digest()
            .as_bytes()),
        prepared.drain_token_provenance().tokens(),
        prepared.cost_comparison_eligibility().drain_scope().code(),
    );
    assert_checkout_state()?;
    Ok(())
}

/// Opt-in constrained compiled-path execution through the workspace helper
/// and the same verified pinned checkout. Both wall clocks cover the same
/// raw-stdin-through-captured-process-output envelope for this frozen case.
/// One pinned macOS observer supplies process peak RSS for both arms. Quality
/// remains representation-fidelity/VDS blocked and no scalar winner is emitted.
#[test]
#[ignore = "opt-in constrained compiled case + pinned local legacy-drain; score-free"]
fn pinned_local_legacy_drain_prepares_constrained_compiled_case() -> Result<(), SmokeBlocker> {
    current_constrained_first_party_policy_identity_v1()?
        .verify_expected_artifact_digest_v1(EXPECTED_FIRST_PARTY_POLICY_IDENTITY_V4)?;
    assert_checkout_state()?;
    let first_party = FirstPartyConstrainedSubprocessTargetV1::try_new(
        env!("CARGO_BIN_EXE_evidentrail-bench-harness-helper"),
        std::env::current_dir().map_err(|_| SmokeBlocker::ExecutableUnavailable)?,
    )?;
    let drain = PinnedLegacyDrainExecutionTargetV1::try_new_verified_local_checkout(
        CHECKOUT,
        EXECUTABLE,
        GIT_EXECUTABLE,
    )?;
    if drain.executable_build_artifact_digest() != EXPECTED_BUILD_DIGEST {
        return Err(SmokeBlocker::BuildArtifactMismatch);
    }
    let paired_run = run_constrained_paired_trials_for_expected_policy_v1(
        EXPECTED_FIRST_PARTY_POLICY_IDENTITY_V4,
        first_party,
        drain,
    )?;
    let prepared = paired_run.prepared();
    let repeatability = paired_run.receipt();
    let producer_universes = freeze_constrained_producer_universes_v1(prepared)?;
    println!(
        "constrained producer checkpoint first={} drain={} pair={} first_packets={} drain_groups={}",
        hex(producer_universes
            .first_party()
            .universe()
            .digest()
            .as_bytes()),
        hex(producer_universes.drain().universe().digest().as_bytes()),
        hex(producer_universes.artifact_digest().as_bytes()),
        producer_universes
            .first_party()
            .universe()
            .accounting()
            .proposal_packet_count(),
        producer_universes
            .drain()
            .universe()
            .accounting()
            .proposal_packet_count(),
    );
    prepared
        .first_party_manifest()
        .ensure_paired_comparable_with(prepared.drain_manifest())
        .map_err(|_| SmokeBlocker::DomainConstructionFailed)?;
    if prepared.generator().input_artifact_digest() != CONSTRAINED_MATCHED_INPUT_ARTIFACT_DIGEST_V1
        || prepared.first_party_method().name() != "evidentrail-log-brief-compiled"
        || prepared.proposal_audit().audit().code() != "selected"
        || prepared.proposal_audit().proposal_packet_count() == 0
        || prepared.proposal_audit().selected_packet_count() == 0
        || !prepared
            .proposal_audit()
            .validated_identifier_failure_block_selected()
        || prepared.drain_target_class()
            != PinnedLegacyDrainTargetClassV1::VerifiedCleanPinnedCheckout
        || prepared.drain_invocation().program().adapter_revision()
            != Some(LEGACY_DRAIN_PINNED_COMMIT_V1)
        || prepared
            .drain_full_membership()
            .charged_candidate_event_count()
            != prepared.ledger().len()
        || prepared.contains_hidden_annotations()
        || prepared.contains_scalar_outcome()
        || prepared.contains_downstream_vds_outcome()
        || prepared.representation_quality_scoreable()
        || prepared.drain_proposal_audit_available()
        || producer_universes
            .first_party()
            .universe()
            .accounting()
            .proposal_packet_count()
            != prepared.proposal_audit().proposal_packet_count()
        || producer_universes
            .drain()
            .universe()
            .accounting()
            .unique_member_event_count()
            != u64::try_from(prepared.ledger().len())
                .map_err(|_| SmokeBlocker::DomainConstructionFailed)?
        || producer_universes
            .drain()
            .universe()
            .accounting()
            .proposal_packet_count()
            != EXPECTED_CONSTRAINED_DRAIN_POSTHOC_GROUPS
        || producer_universes
            .first_party()
            .universe()
            .digest()
            .as_bytes()
            != &EXPECTED_CONSTRAINED_FIRST_PRODUCER_UNIVERSE_DIGEST_V4
        || producer_universes.drain().universe().digest().as_bytes()
            != &EXPECTED_CONSTRAINED_DRAIN_POSTHOC_UNIVERSE_DIGEST
        || producer_universes.artifact_digest().as_bytes()
            != &EXPECTED_CONSTRAINED_PRODUCER_PAIR_DIGEST_V4
        || !producer_universes.drain().complete_ledger_partition()
        || !producer_universes
            .drain()
            .posthoc_complete_occurrence_upper_bound()
        || producer_universes
            .drain()
            .original_preselection_producer_api()
        || producer_universes.drain().representation_recall_scoreable()
        || producer_universes.contains_hidden_annotations()
        || producer_universes.contains_measurements_or_caps()
        || producer_universes.contains_score_or_winner()
        || producer_universes.contains_downstream_vds_outcome()
        || producer_universes.hosted_evidentrail_behavior_claim()
        || !prepared
            .cost_comparison_eligibility()
            .cost_ordering_eligible()
        || !prepared
            .cost_comparison_eligibility()
            .wall_scope_comparable()
        || !prepared.cost_comparison_eligibility().peak_rss_comparable()
        || prepared.cost_comparison_eligibility().code()
            != "eligible_common_process_scope_and_peak_rss_observer"
        || repeatability.trial_count() != 3
        || repeatability.trials().len() != 3
        || repeatability.contains_hidden_annotations()
        || repeatability.contains_scalar_outcome()
        || repeatability.contains_quality_claim()
        || repeatability.child_tree_rss_claimed()
        || repeatability.independently_attested()
    {
        return Err(SmokeBlocker::UnexpectedOpaqueNormalization);
    }
    let first_peak = prepared.first_party_peak_rss_observer_receipt();
    let drain_peak = prepared
        .drain_peak_rss_observer_receipt()
        .ok_or(SmokeBlocker::UnexpectedExecutionOutcome)?;
    if first_peak.peak_rss_bytes() == 0
        || drain_peak.peak_rss_bytes() == 0
        || first_peak.measurement_mechanism_artifact_digest()
            != drain_peak.measurement_mechanism_artifact_digest()
        || first_peak.observer_executable_build_artifact_digest()
            != drain_peak.observer_executable_build_artifact_digest()
        || first_peak.report_format_artifact_digest() != drain_peak.report_format_artifact_digest()
        || first_peak.child_tree_peak_rss_claimed()
        || drain_peak.child_tree_peak_rss_claimed()
        || first_peak.independently_attested()
        || drain_peak.independently_attested()
    {
        return Err(SmokeBlocker::UnexpectedExecutionOutcome);
    }
    let finalized = paired_run.finalized();

    let first_run = canonical_public_run_manifest_artifact_v1(prepared.first_party_manifest())?;
    let drain_run = canonical_public_run_manifest_artifact_v1(prepared.drain_manifest())?;
    println!(
        "pinned constrained preparation generator={} input={} case={} first_run={} first_helper_build={} parent_oracle_build={} first_adapter={} first_render={} first_tokens={} first_subprocess_receipt={} first_subprocess_invocation={} proposal_receipt={} proposals={} proposal_unique_events={} proposal_unique_source_bytes={} selected={} first_producer_universe={} first_scope={} drain_run={} drain_invocation={} drain_full_artifact={} drain_stdout={} drain_tokens={} drain_posthoc_groups={} drain_occurrences={} drain_source_bytes={} drain_posthoc_universe={} producer_pair={} drain_scope={} observer_build={} observer_format={} observer_mechanism={} first_peak_rss_bytes={} first_peak_receipt={} drain_peak_rss_bytes={} drain_peak_receipt={} finalized={} peak_rss_semantics=direct_process_bytes_child_tree_not_claimed trust=self_asserted_non_attesting cost_ordering=eligible_common_process_scope_and_peak_rss_observer score=false vds=false first_party_production_proposal_union=true drain_posthoc_occurrence_upper_bound=true drain_original_preselection_api=false hosted=false",
        hex(prepared.generator().generator_artifact_digest().as_bytes()),
        hex(prepared.generator().input_artifact_digest().as_bytes()),
        hex(prepared.public_case_artifact_digest().as_bytes()),
        hex(first_run.artifact_digest().as_bytes()),
        hex(prepared
            .first_party_subprocess_receipt()
            .executable_build_artifact_digest()
            .as_bytes()),
        hex(prepared
            .first_party_subprocess_receipt()
            .parent_oracle_build_artifact_digest()
            .as_bytes()),
        hex(prepared
            .first_party_subprocess_receipt()
            .adapter_contract_artifact_digest()
            .as_bytes()),
        hex(prepared.first_party_rendered_artifact_digest().as_bytes()),
        prepared.first_party_token_provenance().tokens(),
        hex(prepared
            .first_party_subprocess_receipt()
            .artifact_digest()
            .as_bytes()),
        hex(prepared
            .first_party_subprocess_receipt()
            .invocation()
            .digest()
            .as_bytes()),
        hex(prepared.proposal_audit().artifact_digest().as_bytes()),
        prepared.proposal_audit().proposal_packet_count(),
        producer_universes
            .first_party()
            .universe()
            .accounting()
            .unique_member_event_count(),
        producer_universes
            .first_party()
            .universe()
            .accounting()
            .unique_member_source_bytes(),
        prepared.proposal_audit().selected_packet_count(),
        hex(producer_universes
            .first_party()
            .universe()
            .digest()
            .as_bytes()),
        prepared
            .cost_comparison_eligibility()
            .first_party_scope()
            .code(),
        hex(drain_run.artifact_digest().as_bytes()),
        hex(prepared.drain_invocation().digest().as_bytes()),
        hex(prepared
            .drain_full_membership()
            .artifact_digest()
            .as_bytes()),
        hex(prepared
            .drain_full_membership()
            .raw_stdout_artifact_digest()
            .as_bytes()),
        prepared.drain_token_provenance().tokens(),
        producer_universes
            .drain()
            .universe()
            .accounting()
            .proposal_packet_count(),
        producer_universes
            .drain()
            .universe()
            .accounting()
            .unique_member_event_count(),
        producer_universes
            .drain()
            .universe()
            .accounting()
            .unique_member_source_bytes(),
        hex(producer_universes.drain().universe().digest().as_bytes()),
        hex(producer_universes.artifact_digest().as_bytes()),
        prepared.cost_comparison_eligibility().drain_scope().code(),
        hex(first_peak
            .observer_executable_build_artifact_digest()
            .as_bytes()),
        hex(first_peak.report_format_artifact_digest().as_bytes()),
        hex(first_peak
            .measurement_mechanism_artifact_digest()
            .as_bytes()),
        first_peak.peak_rss_bytes(),
        hex(first_peak.artifact_digest().as_bytes()),
        drain_peak.peak_rss_bytes(),
        hex(drain_peak.artifact_digest().as_bytes()),
        hex(finalized.artifact_digest().as_bytes()),
    );
    for trial in repeatability.trials() {
        println!(
            "paired constrained trial index={} order={} first_wall_nanos={} first_peak_rss_bytes={} first_stdout={} drain_wall_nanos={} drain_peak_rss_bytes={} drain_stdout={}",
            trial.index(),
            trial.order().code(),
            trial.first_party().wall_time_nanos(),
            trial.first_party().peak_rss_bytes(),
            hex(trial.first_party().stdout_artifact_digest().as_bytes()),
            trial.pinned_drain().wall_time_nanos(),
            trial.pinned_drain().peak_rss_bytes(),
            hex(trial.pinned_drain().stdout_artifact_digest().as_bytes()),
        );
    }
    let first_wall = repeatability.first_party().wall_time_nanos();
    let first_rss = repeatability.first_party().peak_rss_bytes();
    let drain_wall = repeatability.pinned_drain().wall_time_nanos();
    let drain_rss = repeatability.pinned_drain().peak_rss_bytes();
    println!(
        "paired constrained repeatability receipt={} trials={} first_wall_min={} first_wall_median={} first_wall_max={} first_wall_mad={} first_rss_min={} first_rss_median={} first_rss_max={} first_rss_mad={} drain_wall_min={} drain_wall_median={} drain_wall_max={} drain_wall_mad={} drain_rss_min={} drain_rss_median={} drain_rss_max={} drain_rss_mad={} direct_process_rss=true child_tree_rss=false independently_attested=false scalar=false quality=false first_party_policy_identity={} compiler_policy_version_hex={}",
        hex(repeatability.artifact_digest().as_bytes()),
        repeatability.trial_count(),
        first_wall.minimum(),
        first_wall.median(),
        first_wall.maximum(),
        first_wall.median_absolute_deviation(),
        first_rss.minimum(),
        first_rss.median(),
        first_rss.maximum(),
        first_rss.median_absolute_deviation(),
        drain_wall.minimum(),
        drain_wall.median(),
        drain_wall.maximum(),
        drain_wall.median_absolute_deviation(),
        drain_rss.minimum(),
        drain_rss.median(),
        drain_rss.maximum(),
        drain_rss.median_absolute_deviation(),
        hex(repeatability
            .first_party_policy_identity()
            .artifact_digest()
            .as_bytes()),
        hex(repeatability
            .first_party_policy_identity()
            .compiler_policy_version()),
    );
    assert_checkout_state()?;
    Ok(())
}

fn source_exact_ledger(raw: &[u8], plan_digest: PlanDigest) -> Result<EventLedger, SmokeBlocker> {
    let retrieval_id = RetrievalId::from_bytes([0x41; 32]);
    let plan_id = PlanId::from_bytes([0x42; 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([0x43; 32]);
    let adapter = AdapterIdentity::new("pinned-drain-smoke", "1")
        .map_err(|_| SmokeBlocker::DomainConstructionFailed)?;
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let lane = LaneKey::new(
        SourceMember::new(b"pinned-drain-smoke-source".to_vec())
            .map_err(|_| SmokeBlocker::DomainConstructionFailed)?,
        SourceStream::OtherVersioned {
            version: 1,
            code: 42,
        },
    );
    let records = canonical_records(raw);
    let mut builder = LedgerBuilder::new(
        fetch_identity.clone(),
        source_identity_digest,
        SourceExactPolicy,
    );
    for (sequence, (payload, terminator)) in records.iter().enumerate() {
        let sequence =
            u64::try_from(sequence).map_err(|_| SmokeBlocker::DomainConstructionFailed)?;
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
            .map_err(|_| SmokeBlocker::DomainConstructionFailed)?;
    }
    let record_count =
        u64::try_from(records.len()).map_err(|_| SmokeBlocker::DomainConstructionFailed)?;
    let payload_byte_count = records.iter().try_fold(0_u64, |total, (payload, _)| {
        total
            .checked_add(
                u64::try_from(payload.len()).map_err(|_| SmokeBlocker::DomainConstructionFailed)?,
            )
            .ok_or(SmokeBlocker::DomainConstructionFailed)
    })?;
    let source_byte_count =
        u64::try_from(raw.len()).map_err(|_| SmokeBlocker::DomainConstructionFailed)?;
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
    .map_err(|_| SmokeBlocker::DomainConstructionFailed)?;
    builder
        .seal(completion)
        .map_err(|_| SmokeBlocker::DomainConstructionFailed)
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

fn assert_checkout_state() -> Result<(), SmokeBlocker> {
    if !PathBuf::from(CHECKOUT).is_dir() {
        return Err(SmokeBlocker::CheckoutUnavailable);
    }
    let head = git_stdout(&["rev-parse", "HEAD"])?;
    if trim_ascii(&head) != LEGACY_DRAIN_PINNED_COMMIT_V1.as_bytes() {
        return Err(SmokeBlocker::RevisionMismatch);
    }
    let status = git_stdout(&["status", "--porcelain=v1", "--untracked-files=all"])?;
    if !status.is_empty() {
        return Err(SmokeBlocker::WorktreeDirty);
    }
    Ok(())
}

fn git_stdout(arguments: &[&str]) -> Result<Vec<u8>, SmokeBlocker> {
    let output = Command::new(GIT_EXECUTABLE)
        .env_clear()
        .arg("-C")
        .arg(CHECKOUT)
        .args(arguments)
        .output()
        .map_err(|_| SmokeBlocker::GitUnavailable)?;
    if !output.status.success() {
        return Err(SmokeBlocker::GitCommandFailed);
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

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}
