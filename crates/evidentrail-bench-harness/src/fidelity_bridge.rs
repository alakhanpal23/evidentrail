use std::error::Error as StdError;
use std::fmt;

use evidentrail_bench::{
    EvidenceRepresentationClaimV1, EvidentrailBenchRunManifestV1,
    FrozenExternalRepresentationSubmissionV1, MeasuredCandidateResources, MeasurementEnvironmentV1,
    MethodDescriptor, RenderedCandidateArtifactV1,
};
use evidentrail_core::EventLedger;
use evidentrail_evidence::{PinnedTokenizer, Utf8ByteTokenizerV1, utf8_byte_tokenizer_digest_v1};
use evidentrail_schema::ArtifactDigest;

use crate::{
    InvocationDigestV1, LEGACY_DRAIN_PINNED_COMMIT_V1, LegacyDrainFullMembershipArtifactV1,
    PeakRssProvenanceV1, SubprocessExecutionReceiptV1, artifact_digest_for_bytes_v1,
    canonical_public_run_manifest_artifact_v1,
};

const CANONICAL_UTF8_BYTE_TOKEN_MEASUREMENT_CONTRACT_V1: &[u8] = b"evidentrail/bench-harness/canonical-token-measurement/utf8-byte-whole-render/v1\0exact-render-bytes=true\0one-call=true\0token-unit=utf8-byte\0self-asserted=true";

/// Fixed identity for the ordinary compact, opaque pinned CLI arm.
#[must_use]
pub const fn legacy_drain_compact_method_descriptor_v1() -> MethodDescriptor {
    MethodDescriptor::new(
        "legacy-drain-compact-adapter",
        LEGACY_DRAIN_PINNED_COMMIT_V1,
    )
}

/// Fixed identity for the separately executed and charged full-membership arm.
#[must_use]
pub const fn legacy_drain_full_membership_method_descriptor_v1() -> MethodDescriptor {
    MethodDescriptor::new(
        "legacy-drain-full-membership-adapter",
        LEGACY_DRAIN_PINNED_COMMIT_V1,
    )
}

/// Canonical token count supplied by an external observer.
///
/// The portable harness binds this value but does not attest that the named
/// tokenizer produced it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CanonicalTokenCountProvenanceV1 {
    ExternallySuppliedNotAttested {
        tokens: u64,
    },
    PinnedUtf8ByteTokenizerWholeRender {
        tokens: u64,
        rendered_artifact_digest: ArtifactDigest,
        rendered_byte_count: u64,
        measurement_contract_artifact_digest: ArtifactDigest,
    },
}

impl CanonicalTokenCountProvenanceV1 {
    #[must_use]
    pub const fn tokens(self) -> u64 {
        match self {
            Self::ExternallySuppliedNotAttested { tokens }
            | Self::PinnedUtf8ByteTokenizerWholeRender { tokens, .. } => tokens,
        }
    }

    #[must_use]
    pub fn tokenizer_artifact_digest(self) -> Option<ArtifactDigest> {
        match self {
            Self::ExternallySuppliedNotAttested { .. } => None,
            Self::PinnedUtf8ByteTokenizerWholeRender { .. } => {
                Some(utf8_byte_tokenizer_digest_v1())
            }
        }
    }

    #[must_use]
    pub const fn rendered_artifact_digest(self) -> Option<ArtifactDigest> {
        match self {
            Self::ExternallySuppliedNotAttested { .. } => None,
            Self::PinnedUtf8ByteTokenizerWholeRender {
                rendered_artifact_digest,
                ..
            } => Some(rendered_artifact_digest),
        }
    }

    #[must_use]
    pub const fn rendered_byte_count(self) -> Option<u64> {
        match self {
            Self::ExternallySuppliedNotAttested { .. } => None,
            Self::PinnedUtf8ByteTokenizerWholeRender {
                rendered_byte_count,
                ..
            } => Some(rendered_byte_count),
        }
    }

    #[must_use]
    pub const fn measurement_contract_artifact_digest(self) -> Option<ArtifactDigest> {
        match self {
            Self::ExternallySuppliedNotAttested { .. } => None,
            Self::PinnedUtf8ByteTokenizerWholeRender {
                measurement_contract_artifact_digest,
                ..
            } => Some(measurement_contract_artifact_digest),
        }
    }

    #[must_use]
    pub const fn is_whole_render_measured(self) -> bool {
        matches!(self, Self::PinnedUtf8ByteTokenizerWholeRender { .. })
    }

    #[must_use]
    pub const fn is_independently_attested(self) -> bool {
        false
    }
}

impl fmt::Debug for CanonicalTokenCountProvenanceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let classification = match self {
            Self::ExternallySuppliedNotAttested { .. } => "externally_supplied_not_attested",
            Self::PinnedUtf8ByteTokenizerWholeRender { .. } => {
                "pinned_utf8_byte_tokenizer_whole_render"
            }
        };
        formatter
            .debug_struct("CanonicalTokenCountProvenanceV1")
            .field("classification", &classification)
            .field("tokens", &self.tokens())
            .field("whole_render_measured", &self.is_whole_render_measured())
            .field("independently_attested", &false)
            .finish()
    }
}

/// Measure one exact complete UTF-8 render with the pinned byte tokenizer.
/// The receipt is reproducible process-local provenance, not attestation.
pub fn measure_canonical_utf8_byte_tokens_v1(
    rendered_bytes: &[u8],
) -> Result<CanonicalTokenCountProvenanceV1, LegacyDrainFidelityBridgeErrorV1> {
    let rendered = std::str::from_utf8(rendered_bytes)
        .map_err(|_| LegacyDrainFidelityBridgeErrorV1::CanonicalTokenizerMeasurementFailed)?;
    let tokenizer = Utf8ByteTokenizerV1::new();
    let tokens = tokenizer
        .count_tokens(rendered)
        .map_err(|_| LegacyDrainFidelityBridgeErrorV1::CanonicalTokenizerMeasurementFailed)?;
    if tokenizer.whole_render_calls() != 1 {
        return Err(LegacyDrainFidelityBridgeErrorV1::CanonicalTokenizerMeasurementFailed);
    }
    let rendered_byte_count = u64::try_from(rendered_bytes.len())
        .map_err(|_| LegacyDrainFidelityBridgeErrorV1::AccountingOverflow)?;
    Ok(
        CanonicalTokenCountProvenanceV1::PinnedUtf8ByteTokenizerWholeRender {
            tokens,
            rendered_artifact_digest: artifact_digest_for_bytes_v1(rendered_bytes),
            rendered_byte_count,
            measurement_contract_artifact_digest: artifact_digest_for_bytes_v1(
                CANONICAL_UTF8_BYTE_TOKEN_MEASUREMENT_CONTRACT_V1,
            ),
        },
    )
}

/// Public, score-free provenance for the full-membership representation.
///
/// Construction binds the separately executed full arm, strict normalizer
/// artifact, exact raw output, complete occurrence claims, and all five
/// candidate-resource dimensions. It contains no governed annotation or score.
#[derive(Clone, PartialEq, Eq)]
pub struct LegacyDrainFullMembershipRepresentationReceiptV1 {
    invocation_digest: InvocationDigestV1,
    full_membership_artifact_digest: ArtifactDigest,
    submission: FrozenExternalRepresentationSubmissionV1,
    canonical_tokens: CanonicalTokenCountProvenanceV1,
    peak_rss: PeakRssProvenanceV1,
}

impl LegacyDrainFullMembershipRepresentationReceiptV1 {
    #[must_use]
    pub const fn invocation_digest(&self) -> InvocationDigestV1 {
        self.invocation_digest
    }

    #[must_use]
    pub const fn full_membership_artifact_digest(&self) -> ArtifactDigest {
        self.full_membership_artifact_digest
    }

    #[must_use]
    pub const fn submission(&self) -> &FrozenExternalRepresentationSubmissionV1 {
        &self.submission
    }

    #[must_use]
    pub const fn canonical_token_provenance(&self) -> CanonicalTokenCountProvenanceV1 {
        self.canonical_tokens
    }

    #[must_use]
    pub const fn peak_rss_provenance(&self) -> PeakRssProvenanceV1 {
        self.peak_rss
    }
}

impl fmt::Debug for LegacyDrainFullMembershipRepresentationReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyDrainFullMembershipRepresentationReceiptV1")
            .field("invocation_binding_present", &true)
            .field("full_membership_artifact_binding_present", &true)
            .field("score_free_submission", &self.submission)
            .field("canonical_token_provenance", &self.canonical_tokens)
            .field("peak_rss_provenance", &self.peak_rss)
            .field("contains_governed_labels", &false)
            .field("contains_score", &false)
            .finish()
    }
}

/// Freeze the score-free full-membership arm before governed labels enter.
///
/// `rendered_candidate` must identify the exact full-arm stdout. Wall time is
/// taken from that same execution receipt. Token count and peak RSS are
/// required external observations and remain explicitly non-attested.
#[allow(clippy::too_many_arguments)]
pub fn freeze_legacy_drain_full_membership_representation_v1(
    run_manifest: &EvidentrailBenchRunManifestV1,
    ledger: &EventLedger,
    execution: &SubprocessExecutionReceiptV1,
    full_membership: &LegacyDrainFullMembershipArtifactV1,
    environment: MeasurementEnvironmentV1,
    rendered_candidate: RenderedCandidateArtifactV1,
    canonical_tokens: CanonicalTokenCountProvenanceV1,
    peak_rss: PeakRssProvenanceV1,
) -> Result<LegacyDrainFullMembershipRepresentationReceiptV1, LegacyDrainFidelityBridgeErrorV1> {
    freeze_legacy_drain_full_membership_representation_with_method_v1(
        run_manifest,
        ledger,
        execution,
        full_membership,
        legacy_drain_full_membership_method_descriptor_v1(),
        environment,
        rendered_candidate,
        canonical_tokens,
        peak_rss,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn freeze_legacy_drain_full_membership_representation_with_method_v1(
    run_manifest: &EvidentrailBenchRunManifestV1,
    ledger: &EventLedger,
    execution: &SubprocessExecutionReceiptV1,
    full_membership: &LegacyDrainFullMembershipArtifactV1,
    method: MethodDescriptor,
    environment: MeasurementEnvironmentV1,
    rendered_candidate: RenderedCandidateArtifactV1,
    canonical_tokens: CanonicalTokenCountProvenanceV1,
    peak_rss: PeakRssProvenanceV1,
) -> Result<LegacyDrainFullMembershipRepresentationReceiptV1, LegacyDrainFidelityBridgeErrorV1> {
    let canonical_run = canonical_public_run_manifest_artifact_v1(run_manifest)
        .map_err(|_| LegacyDrainFidelityBridgeErrorV1::RunManifestBindingMismatch)?;
    let stdout_digest = execution
        .stdout()
        .complete_artifact_digest()
        .ok_or(LegacyDrainFidelityBridgeErrorV1::ExecutionBindingMismatch)?;
    let stderr_digest = execution
        .stderr()
        .complete_artifact_digest()
        .ok_or(LegacyDrainFidelityBridgeErrorV1::ExecutionBindingMismatch)?;
    let stdout_byte_count = u64::try_from(execution.stdout().byte_count())
        .map_err(|_| LegacyDrainFidelityBridgeErrorV1::AccountingOverflow)?;
    let stderr_byte_count = u64::try_from(execution.stderr().byte_count())
        .map_err(|_| LegacyDrainFidelityBridgeErrorV1::AccountingOverflow)?;
    if canonical_run.artifact_digest() != full_membership.run_manifest_artifact_digest()
        || execution.run_manifest_artifact_digest()
            != full_membership.run_manifest_artifact_digest()
        || execution.public_case_artifact_digest() != full_membership.public_case_artifact_digest()
        || execution.invocation_digest() != full_membership.invocation_digest()
        || stdout_digest != full_membership.raw_stdout_artifact_digest()
        || stderr_digest != full_membership.raw_stderr_artifact_digest()
        || stdout_byte_count != full_membership.raw_stdout_byte_count()
        || stderr_byte_count != full_membership.raw_stderr_byte_count()
    {
        return Err(LegacyDrainFidelityBridgeErrorV1::ExecutionBindingMismatch);
    }
    if rendered_candidate.artifact_digest() != stdout_digest
        || rendered_candidate.byte_count() != stdout_byte_count
    {
        return Err(LegacyDrainFidelityBridgeErrorV1::MeasurementBindingMismatch);
    }
    if canonical_tokens.is_whole_render_measured()
        && (canonical_tokens.tokenizer_artifact_digest()
            != Some(environment.tokenizer().artifact_digest())
            || canonical_tokens.rendered_artifact_digest()
                != Some(rendered_candidate.artifact_digest())
            || canonical_tokens.rendered_byte_count() != Some(rendered_candidate.byte_count()))
    {
        return Err(LegacyDrainFidelityBridgeErrorV1::MeasurementBindingMismatch);
    }
    if full_membership.pattern_memberships().len() != full_membership.transformed_samples().len()
        || full_membership
            .pattern_memberships()
            .iter()
            .zip(full_membership.transformed_samples())
            .any(|(pattern, transformed)| {
                pattern.retained_index() != transformed.retained_index()
                    || pattern.source_record_ordinal() != transformed.source_record_ordinal()
                    || pattern.event_id() != transformed.event_id()
                    || pattern.group_id() != transformed.group_id()
            })
    {
        return Err(LegacyDrainFidelityBridgeErrorV1::MembershipBindingMismatch);
    }

    let claims = full_membership
        .pattern_memberships()
        .iter()
        .zip(full_membership.transformed_samples())
        .flat_map(|(pattern, transformed)| {
            [
                EvidenceRepresentationClaimV1::pattern_only(
                    pattern.event_id(),
                    pattern.group_pattern_artifact_digest(),
                ),
                EvidenceRepresentationClaimV1::source_validated_transformed_sample(
                    transformed.event_id(),
                    transformed.transformed_sample_artifact_digest(),
                ),
            ]
        })
        .collect::<Vec<_>>();
    let externally_observed = MeasuredCandidateResources::try_new(
        canonical_tokens.tokens(),
        execution.wall_time_nanos(),
        peak_rss.bytes(),
    )
    .map_err(|_| LegacyDrainFidelityBridgeErrorV1::MeasurementBindingMismatch)?;
    let submission = FrozenExternalRepresentationSubmissionV1::try_new_self_asserted(
        canonical_run.artifact_digest(),
        run_manifest,
        full_membership.public_case_artifact_digest(),
        method,
        ledger,
        full_membership.artifact_digest(),
        full_membership.normalizer_artifact_digest(),
        environment,
        rendered_candidate,
        execution.stdout().bytes(),
        externally_observed,
        claims,
    )
    .map_err(|_| LegacyDrainFidelityBridgeErrorV1::RepresentationConstructionFailed)?;
    if submission.resources().unique_candidate_event_count()
        != u64::try_from(full_membership.charged_candidate_event_count())
            .map_err(|_| LegacyDrainFidelityBridgeErrorV1::AccountingOverflow)?
        || submission.resources().unique_candidate_source_bytes()
            != full_membership.charged_candidate_source_bytes()
    {
        return Err(LegacyDrainFidelityBridgeErrorV1::MembershipBindingMismatch);
    }

    Ok(LegacyDrainFullMembershipRepresentationReceiptV1 {
        invocation_digest: execution.invocation_digest(),
        full_membership_artifact_digest: full_membership.artifact_digest(),
        submission,
        canonical_tokens,
        peak_rss,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LegacyDrainFidelityBridgeErrorV1 {
    RunManifestBindingMismatch,
    ExecutionBindingMismatch,
    MeasurementBindingMismatch,
    MembershipBindingMismatch,
    RepresentationConstructionFailed,
    CanonicalTokenizerMeasurementFailed,
    AccountingOverflow,
}

impl LegacyDrainFidelityBridgeErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::RunManifestBindingMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_FIDELITY_RUN_MANIFEST_BINDING_MISMATCH"
            }
            Self::ExecutionBindingMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_FIDELITY_EXECUTION_BINDING_MISMATCH"
            }
            Self::MeasurementBindingMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_FIDELITY_MEASUREMENT_BINDING_MISMATCH"
            }
            Self::MembershipBindingMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_FIDELITY_MEMBERSHIP_BINDING_MISMATCH"
            }
            Self::RepresentationConstructionFailed => {
                "EVIDENTRAIL_BENCH_HARNESS_FIDELITY_REPRESENTATION_CONSTRUCTION_FAILED"
            }
            Self::CanonicalTokenizerMeasurementFailed => {
                "EVIDENTRAIL_BENCH_HARNESS_FIDELITY_CANONICAL_TOKENIZER_MEASUREMENT_FAILED"
            }
            Self::AccountingOverflow => "EVIDENTRAIL_BENCH_HARNESS_FIDELITY_ACCOUNTING_OVERFLOW",
        }
    }
}

impl fmt::Debug for LegacyDrainFidelityBridgeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyDrainFidelityBridgeErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for LegacyDrainFidelityBridgeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for LegacyDrainFidelityBridgeErrorV1 {}
