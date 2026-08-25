use std::fmt;

use evidentrail_bench::{
    BenchmarkRunIdentityV1, CandidateResourceEnvelope, ExternalSystemResultEnvelopeV1,
    FrozenCandidateSelectionDigestV1, MeasurementEnvironmentV1, MeasurementTrustBoundaryV1,
    MethodDescriptor, RenderedCandidateArtifactV1,
};
use evidentrail_schema::{ArtifactDigest, PresentationReceiptId};

use crate::{
    ExitCategoryV1, ExternalOutputContractV1, HarnessError, InvocationDigestV1,
    PublicCaseResolutionTrustV1, StdinDeliveryV1, SubprocessExecutionReceiptV1,
};

/// Peak RSS is currently supplied by an external observer and is not attested
/// by this portable subprocess harness. It is mandatory and never guessed or
/// defaulted to zero.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PeakRssProvenanceV1 {
    ExternallySuppliedNotAttested { bytes: u64 },
}

impl PeakRssProvenanceV1 {
    #[must_use]
    pub const fn bytes(self) -> u64 {
        match self {
            Self::ExternallySuppliedNotAttested { bytes } => bytes,
        }
    }

    #[must_use]
    pub const fn is_independently_attested(self) -> bool {
        false
    }
}

impl fmt::Debug for PeakRssProvenanceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeakRssProvenanceV1")
            .field("classification", &"externally_supplied_not_attested")
            .field("bytes", &self.bytes())
            .field("independently_attested", &false)
            .finish()
    }
}

/// A strict normalized artifact bound to a successful complete execution.
///
/// Construction is intentionally private. The only current normalizer is the
/// byte-identity contract used by hermetic helpers. Pinned `legacy-drain` output
/// is opaque and cannot construct this token.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StrictNormalizedExternalOutputV1 {
    invocation_digest: InvocationDigestV1,
    raw_stdout_artifact_digest: ArtifactDigest,
    normalized_artifact_digest: ArtifactDigest,
    normalized_byte_count: u64,
}

impl StrictNormalizedExternalOutputV1 {
    #[must_use]
    pub const fn invocation_digest(self) -> InvocationDigestV1 {
        self.invocation_digest
    }

    #[must_use]
    pub const fn raw_stdout_artifact_digest(self) -> ArtifactDigest {
        self.raw_stdout_artifact_digest
    }

    #[must_use]
    pub const fn normalized_artifact_digest(self) -> ArtifactDigest {
        self.normalized_artifact_digest
    }

    #[must_use]
    pub const fn normalized_byte_count(self) -> u64 {
        self.normalized_byte_count
    }
}

impl fmt::Debug for StrictNormalizedExternalOutputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StrictNormalizedExternalOutputV1")
            .field("invocation_binding_present", &true)
            .field("raw_stdout_binding_present", &true)
            .field("normalized_artifact_binding_present", &true)
            .field("normalized_byte_count", &self.normalized_byte_count)
            .finish()
    }
}

/// Apply the only implemented strict normalizer: exact stdout byte identity.
/// Opaque external output, including pinned `legacy-drain` JSON, fails closed.
pub fn strict_identity_normalize_v1(
    execution: &SubprocessExecutionReceiptV1,
) -> Result<StrictNormalizedExternalOutputV1, HarnessError> {
    if execution.output_contract() != ExternalOutputContractV1::ExactIdentityNormalizer {
        return Err(HarnessError::OutputNormalizationUnsupported);
    }
    if execution.exit_category() != ExitCategoryV1::Success
        || execution.stdin_delivery() != StdinDeliveryV1::Complete
        || !execution.termination_causes().is_empty()
    {
        return Err(HarnessError::ProcessNotSuccessful);
    }
    let Some(raw_stdout_artifact_digest) = execution.stdout().complete_artifact_digest() else {
        return Err(HarnessError::OutputNotComplete);
    };
    if execution.stderr().complete_artifact_digest().is_none() {
        return Err(HarnessError::OutputNotComplete);
    }
    let normalized_byte_count = u64::try_from(execution.stdout().byte_count())
        .map_err(|_| HarnessError::ArtifactLengthOverflow)?;
    Ok(StrictNormalizedExternalOutputV1 {
        invocation_digest: execution.invocation_digest(),
        raw_stdout_artifact_digest,
        normalized_artifact_digest: raw_stdout_artifact_digest,
        normalized_byte_count,
    })
}

/// Self-asserted external measurement provenance for one frozen public result.
///
/// This binds reproducibility inputs and observations. It is not a signature,
/// trusted timestamp, executable attestation, tokenizer attestation, or peak
/// RSS attestation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SelfAssertedExternalMeasurementReceiptV1 {
    invocation_digest: InvocationDigestV1,
    run_manifest_artifact_digest: ArtifactDigest,
    run_identity: BenchmarkRunIdentityV1,
    public_case_artifact_digest: ArtifactDigest,
    case_resolution_trust: PublicCaseResolutionTrustV1,
    method: MethodDescriptor,
    candidate_selection_digest: FrozenCandidateSelectionDigestV1,
    presentation_receipt_id: PresentationReceiptId,
    environment: MeasurementEnvironmentV1,
    rendered_candidate: RenderedCandidateArtifactV1,
    raw_stdout_artifact_digest: ArtifactDigest,
    raw_stderr_artifact_digest: ArtifactDigest,
    candidate_resources: CandidateResourceEnvelope,
    peak_rss_provenance: PeakRssProvenanceV1,
}

impl SelfAssertedExternalMeasurementReceiptV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        execution: &SubprocessExecutionReceiptV1,
        normalized: StrictNormalizedExternalOutputV1,
        method: MethodDescriptor,
        candidate_selection_digest: FrozenCandidateSelectionDigestV1,
        presentation_receipt_id: PresentationReceiptId,
        environment: MeasurementEnvironmentV1,
        rendered_candidate: RenderedCandidateArtifactV1,
        candidate_resources: CandidateResourceEnvelope,
        peak_rss_provenance: PeakRssProvenanceV1,
    ) -> Result<Self, HarnessError> {
        if execution.exit_category() != ExitCategoryV1::Success
            || execution.stdin_delivery() != StdinDeliveryV1::Complete
            || !execution.termination_causes().is_empty()
        {
            return Err(HarnessError::ProcessNotSuccessful);
        }
        let Some(raw_stdout_artifact_digest) = execution.stdout().complete_artifact_digest() else {
            return Err(HarnessError::OutputNotComplete);
        };
        let Some(raw_stderr_artifact_digest) = execution.stderr().complete_artifact_digest() else {
            return Err(HarnessError::OutputNotComplete);
        };
        if normalized.invocation_digest != execution.invocation_digest()
            || normalized.raw_stdout_artifact_digest != raw_stdout_artifact_digest
            || rendered_candidate.artifact_digest() != normalized.normalized_artifact_digest
            || rendered_candidate.byte_count() != normalized.normalized_byte_count
            || candidate_resources.wall_time_nanos() != execution.wall_time_nanos()
            || candidate_resources.peak_memory_bytes() != peak_rss_provenance.bytes()
            || execution
                .run_identity()
                .budget()
                .cap()
                .check(candidate_resources)
                .is_err()
        {
            return Err(HarnessError::MeasurementBindingMismatch);
        }
        Ok(Self {
            invocation_digest: execution.invocation_digest(),
            run_manifest_artifact_digest: execution.run_manifest_artifact_digest(),
            run_identity: execution.run_identity(),
            public_case_artifact_digest: execution.public_case_artifact_digest(),
            case_resolution_trust: execution.case_resolution_trust(),
            method,
            candidate_selection_digest,
            presentation_receipt_id,
            environment,
            rendered_candidate,
            raw_stdout_artifact_digest,
            raw_stderr_artifact_digest,
            candidate_resources,
            peak_rss_provenance,
        })
    }

    #[must_use]
    pub const fn trust_boundary(self) -> MeasurementTrustBoundaryV1 {
        MeasurementTrustBoundaryV1::SelfAssertedReproducibilityInput
    }

    #[must_use]
    pub const fn invocation_digest(self) -> InvocationDigestV1 {
        self.invocation_digest
    }

    #[must_use]
    pub const fn run_manifest_artifact_digest(self) -> ArtifactDigest {
        self.run_manifest_artifact_digest
    }

    #[must_use]
    pub const fn run_identity(self) -> BenchmarkRunIdentityV1 {
        self.run_identity
    }

    #[must_use]
    pub const fn public_case_artifact_digest(self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn case_resolution_trust(self) -> PublicCaseResolutionTrustV1 {
        self.case_resolution_trust
    }

    #[must_use]
    pub const fn method(self) -> MethodDescriptor {
        self.method
    }

    #[must_use]
    pub const fn candidate_selection_digest(self) -> FrozenCandidateSelectionDigestV1 {
        self.candidate_selection_digest
    }

    #[must_use]
    pub const fn presentation_receipt_id(self) -> PresentationReceiptId {
        self.presentation_receipt_id
    }

    #[must_use]
    pub const fn environment(self) -> MeasurementEnvironmentV1 {
        self.environment
    }

    #[must_use]
    pub const fn rendered_candidate(self) -> RenderedCandidateArtifactV1 {
        self.rendered_candidate
    }

    #[must_use]
    pub const fn raw_stdout_artifact_digest(self) -> ArtifactDigest {
        self.raw_stdout_artifact_digest
    }

    #[must_use]
    pub const fn raw_stderr_artifact_digest(self) -> ArtifactDigest {
        self.raw_stderr_artifact_digest
    }

    #[must_use]
    pub const fn candidate_resources(self) -> CandidateResourceEnvelope {
        self.candidate_resources
    }

    #[must_use]
    pub const fn peak_rss_provenance(self) -> PeakRssProvenanceV1 {
        self.peak_rss_provenance
    }
}

impl fmt::Debug for SelfAssertedExternalMeasurementReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelfAssertedExternalMeasurementReceiptV1")
            .field("trust_boundary", &self.trust_boundary())
            .field("invocation_binding_present", &true)
            .field("run_manifest_binding_present", &true)
            .field("run_identity", &self.run_identity)
            .field("public_case_binding_present", &true)
            .field("case_resolution_trust", &self.case_resolution_trust)
            .field("method_binding_present", &true)
            .field("candidate_selection_binding_present", &true)
            .field("presentation_receipt_binding_present", &true)
            .field("measurement_environment", &self.environment)
            .field("rendered_candidate", &self.rendered_candidate)
            .field("raw_stdout_binding_present", &true)
            .field("raw_stderr_binding_present", &true)
            .field("candidate_resources_present", &true)
            .field("peak_rss_provenance", &self.peak_rss_provenance)
            .field("contains_governed_labels", &false)
            .finish()
    }
}

/// Public, score-free external result plus its self-asserted provenance.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicExternalResultSubmissionV1 {
    invocation_digest: InvocationDigestV1,
    result: ExternalSystemResultEnvelopeV1,
    measurement: SelfAssertedExternalMeasurementReceiptV1,
}

impl PublicExternalResultSubmissionV1 {
    pub fn try_new(
        execution: &SubprocessExecutionReceiptV1,
        normalized: StrictNormalizedExternalOutputV1,
        result: ExternalSystemResultEnvelopeV1,
        measurement: SelfAssertedExternalMeasurementReceiptV1,
    ) -> Result<Self, HarnessError> {
        if execution.exit_category() != ExitCategoryV1::Success
            || execution.stdin_delivery() != StdinDeliveryV1::Complete
            || !execution.termination_causes().is_empty()
        {
            return Err(HarnessError::ProcessNotSuccessful);
        }
        let Some(current_stdout_artifact_digest) = execution.stdout().complete_artifact_digest()
        else {
            return Err(HarnessError::OutputNotComplete);
        };
        let Some(current_stderr_artifact_digest) = execution.stderr().complete_artifact_digest()
        else {
            return Err(HarnessError::OutputNotComplete);
        };
        if normalized.invocation_digest != execution.invocation_digest()
            || normalized.raw_stdout_artifact_digest != current_stdout_artifact_digest
            || result.public_run_manifest_artifact_digest()
                != execution.run_manifest_artifact_digest()
            || result.run_identity() != execution.run_identity()
            || result.public_case_artifact_digest() != execution.public_case_artifact_digest()
            || result.raw_output_artifact_digest() != normalized.raw_stdout_artifact_digest
            || result.normalized_output_artifact_digest() != normalized.normalized_artifact_digest
            || result.candidate_resources() != measurement.candidate_resources
            || measurement.invocation_digest != execution.invocation_digest()
            || measurement.run_manifest_artifact_digest != execution.run_manifest_artifact_digest()
            || measurement.run_identity != execution.run_identity()
            || measurement.public_case_artifact_digest != execution.public_case_artifact_digest()
            || measurement.case_resolution_trust != execution.case_resolution_trust()
            || measurement.raw_stdout_artifact_digest != normalized.raw_stdout_artifact_digest
            || measurement.raw_stderr_artifact_digest != current_stderr_artifact_digest
            || measurement.candidate_resources.wall_time_nanos() != execution.wall_time_nanos()
            || measurement.rendered_candidate.artifact_digest()
                != normalized.normalized_artifact_digest
            || measurement.rendered_candidate.byte_count() != normalized.normalized_byte_count
        {
            return Err(HarnessError::PublicResultBindingMismatch);
        }
        Ok(Self {
            invocation_digest: execution.invocation_digest(),
            result,
            measurement,
        })
    }

    #[must_use]
    pub const fn invocation_digest(self) -> InvocationDigestV1 {
        self.invocation_digest
    }

    #[must_use]
    pub const fn result(self) -> ExternalSystemResultEnvelopeV1 {
        self.result
    }

    #[must_use]
    pub const fn measurement(self) -> SelfAssertedExternalMeasurementReceiptV1 {
        self.measurement
    }
}

impl fmt::Debug for PublicExternalResultSubmissionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicExternalResultSubmissionV1")
            .field("invocation_binding_present", &true)
            .field("score_free_public_result", &self.result)
            .field("self_asserted_measurement", &self.measurement)
            .field("contains_score", &false)
            .field("contains_governed_labels", &false)
            .finish()
    }
}
