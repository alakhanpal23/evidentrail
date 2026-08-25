use std::error::Error as StdError;
use std::fmt;

use evidentrail_core::{EventLedger, PresentationReceiptId};
use evidentrail_schema::ArtifactDigest;
use evidentrail_schema::bounds::JSON_SAFE_INTEGER_MAX;
use sha2::{Digest as _, Sha256};

use crate::{BenchmarkRunIdentityV1, MeasuredCandidateResources, MethodDescriptor, MethodResult};

const FROZEN_SELECTION_DOMAIN_V1: &[u8] = b"evidentrail/bench/frozen-candidate-selection/v1";

/// Opaque identity of the exact tokenizer implementation and configuration.
///
/// The artifact is resolved by the benchmark harness; this domain type does
/// not inspect or endorse the tokenizer it names.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TokenizerIdentityV1 {
    artifact_digest: ArtifactDigest,
}

/// Opaque identity of the exact canonical candidate renderer and its
/// serialization contract.
///
/// The artifact is resolved by the benchmark harness. A positive JSON-safe
/// contract version prevents an omitted/default version from being mistaken
/// for an identified serialization.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CandidateRendererIdentityV1 {
    artifact_digest: ArtifactDigest,
    contract_version: u64,
}

impl CandidateRendererIdentityV1 {
    pub fn try_new(
        artifact_digest: ArtifactDigest,
        contract_version: u64,
    ) -> Result<Self, MeasurementProvenanceError> {
        if contract_version == 0 {
            return Err(MeasurementProvenanceError::ZeroRendererContractVersion);
        }
        if contract_version > JSON_SAFE_INTEGER_MAX {
            return Err(MeasurementProvenanceError::RendererContractVersionExceedsJsonSafeInteger);
        }
        Ok(Self {
            artifact_digest,
            contract_version,
        })
    }

    #[must_use]
    pub const fn artifact_digest(self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn contract_version(self) -> u64 {
        self.contract_version
    }
}

impl fmt::Debug for CandidateRendererIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CandidateRendererIdentityV1")
            .field("artifact_identity_present", &true)
            .field("contract_version", &self.contract_version)
            .finish()
    }
}

/// Exact artifact produced by the canonical candidate renderer.
///
/// The byte count is part of the binding rather than inferred from source
/// events: canonical serialization may add framing or metadata. It may be zero
/// for a renderer-defined empty candidate artifact, but must remain JSON-safe.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RenderedCandidateArtifactV1 {
    artifact_digest: ArtifactDigest,
    byte_count: u64,
}

impl RenderedCandidateArtifactV1 {
    pub fn try_new(
        artifact_digest: ArtifactDigest,
        byte_count: u64,
    ) -> Result<Self, MeasurementProvenanceError> {
        if byte_count > JSON_SAFE_INTEGER_MAX {
            return Err(MeasurementProvenanceError::RenderedCandidateBytesExceedJsonSafeInteger);
        }
        Ok(Self {
            artifact_digest,
            byte_count,
        })
    }

    #[must_use]
    pub const fn artifact_digest(self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn byte_count(self) -> u64 {
        self.byte_count
    }
}

impl fmt::Debug for RenderedCandidateArtifactV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedCandidateArtifactV1")
            .field("artifact_identity_present", &true)
            .field("byte_count", &self.byte_count)
            .finish()
    }
}

impl TokenizerIdentityV1 {
    #[must_use]
    pub const fn new(artifact_digest: ArtifactDigest) -> Self {
        Self { artifact_digest }
    }

    #[must_use]
    pub const fn artifact_digest(self) -> ArtifactDigest {
        self.artifact_digest
    }
}

impl fmt::Debug for TokenizerIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenizerIdentityV1")
            .field("artifact_identity_present", &true)
            .finish()
    }
}

/// Opaque measurement-harness artifact plus a positive JSON-safe contract
/// version.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MeasurementHarnessIdentityV1 {
    artifact_digest: ArtifactDigest,
    contract_version: u64,
}

impl MeasurementHarnessIdentityV1 {
    pub fn try_new(
        artifact_digest: ArtifactDigest,
        contract_version: u64,
    ) -> Result<Self, MeasurementProvenanceError> {
        if contract_version == 0 {
            return Err(MeasurementProvenanceError::ZeroHarnessContractVersion);
        }
        if contract_version > JSON_SAFE_INTEGER_MAX {
            return Err(MeasurementProvenanceError::HarnessContractVersionExceedsJsonSafeInteger);
        }
        Ok(Self {
            artifact_digest,
            contract_version,
        })
    }

    #[must_use]
    pub const fn artifact_digest(self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn contract_version(self) -> u64 {
        self.contract_version
    }
}

impl fmt::Debug for MeasurementHarnessIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MeasurementHarnessIdentityV1")
            .field("artifact_identity_present", &true)
            .field("contract_version", &self.contract_version)
            .finish()
    }
}

/// Run-wide identities expected for every externally measured case.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MeasurementEnvironmentV1 {
    tokenizer: TokenizerIdentityV1,
    renderer: CandidateRendererIdentityV1,
    harness: MeasurementHarnessIdentityV1,
}

impl MeasurementEnvironmentV1 {
    #[must_use]
    pub const fn new(
        tokenizer: TokenizerIdentityV1,
        renderer: CandidateRendererIdentityV1,
        harness: MeasurementHarnessIdentityV1,
    ) -> Self {
        Self {
            tokenizer,
            renderer,
            harness,
        }
    }

    #[must_use]
    pub const fn tokenizer(self) -> TokenizerIdentityV1 {
        self.tokenizer
    }

    #[must_use]
    pub const fn renderer(self) -> CandidateRendererIdentityV1 {
        self.renderer
    }

    #[must_use]
    pub const fn harness(self) -> MeasurementHarnessIdentityV1 {
        self.harness
    }
}

impl fmt::Debug for MeasurementEnvironmentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MeasurementEnvironmentV1")
            .field("tokenizer", &self.tokenizer)
            .field("renderer", &self.renderer)
            .field("harness", &self.harness)
            .finish()
    }
}

/// Self-asserted pre-measurement binding for the exact rendered candidate
/// artifact.
///
/// This value lets the runner compare the later measurement receipt against a
/// rendering frozen before governed labels are admitted. It is reproducibility
/// provenance, not independent attestation that the named renderer ran.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FrozenCandidateRenderingV1 {
    public_case_artifact_digest: ArtifactDigest,
    candidate_selection_digest: FrozenCandidateSelectionDigestV1,
    presentation_receipt_id: PresentationReceiptId,
    renderer: CandidateRendererIdentityV1,
    rendered_candidate: RenderedCandidateArtifactV1,
}

impl FrozenCandidateRenderingV1 {
    #[must_use]
    pub const fn new_self_asserted(
        public_case_artifact_digest: ArtifactDigest,
        candidate_selection_digest: FrozenCandidateSelectionDigestV1,
        presentation_receipt_id: PresentationReceiptId,
        renderer: CandidateRendererIdentityV1,
        rendered_candidate: RenderedCandidateArtifactV1,
    ) -> Self {
        Self {
            public_case_artifact_digest,
            candidate_selection_digest,
            presentation_receipt_id,
            renderer,
            rendered_candidate,
        }
    }

    #[must_use]
    pub const fn public_case_artifact_digest(self) -> ArtifactDigest {
        self.public_case_artifact_digest
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
    pub const fn renderer(self) -> CandidateRendererIdentityV1 {
        self.renderer
    }

    #[must_use]
    pub const fn rendered_candidate(self) -> RenderedCandidateArtifactV1 {
        self.rendered_candidate
    }
}

impl fmt::Debug for FrozenCandidateRenderingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenCandidateRenderingV1")
            .field("public_case_binding_present", &true)
            .field("candidate_selection_binding_present", &true)
            .field("presentation_receipt_binding_present", &true)
            .field("renderer", &self.renderer)
            .field("rendered_candidate", &self.rendered_candidate)
            .field("trust_boundary", &"self_asserted_reproducibility_input")
            .finish()
    }
}

/// Domain-separated commitment to one exact frozen candidate set and
/// selection result.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrozenCandidateSelectionDigestV1([u8; 32]);

impl FrozenCandidateSelectionDigestV1 {
    /// Materialize a persisted self-asserted receipt value. Validation against
    /// a frozen run remains mandatory before governed evaluation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for FrozenCandidateSelectionDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenCandidateSelectionDigestV1(<redacted>)")
    }
}

/// The only trust class represented by the current receipt.
///
/// It records reproducibility inputs asserted by the harness. It is not an
/// independent signature, trusted timestamp, remote attestation, or audit.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MeasurementTrustBoundaryV1 {
    SelfAssertedReproducibilityInput,
}

impl MeasurementTrustBoundaryV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SelfAssertedReproducibilityInput => "self_asserted_reproducibility_input",
        }
    }
}

impl fmt::Debug for MeasurementTrustBoundaryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MeasurementTrustBoundaryV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Self-asserted provenance for externally observed candidate measurements.
///
/// Every execution identity and frozen-output binding is explicit. Successful
/// runner validation proves internal consistency with those asserted inputs;
/// it does not prove that the harness or observations were independently
/// trusted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MeasurementProvenanceReceiptV1 {
    run_manifest_artifact_digest: ArtifactDigest,
    run_identity: BenchmarkRunIdentityV1,
    public_case_artifact_digest: ArtifactDigest,
    method: MethodDescriptor,
    candidate_selection_digest: FrozenCandidateSelectionDigestV1,
    presentation_receipt_id: PresentationReceiptId,
    environment: MeasurementEnvironmentV1,
    rendered_candidate: RenderedCandidateArtifactV1,
    externally_observed: MeasuredCandidateResources,
}

impl MeasurementProvenanceReceiptV1 {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new_self_asserted(
        run_manifest_artifact_digest: ArtifactDigest,
        run_identity: BenchmarkRunIdentityV1,
        public_case_artifact_digest: ArtifactDigest,
        method: MethodDescriptor,
        candidate_selection_digest: FrozenCandidateSelectionDigestV1,
        presentation_receipt_id: PresentationReceiptId,
        environment: MeasurementEnvironmentV1,
        rendered_candidate: RenderedCandidateArtifactV1,
        externally_observed: MeasuredCandidateResources,
    ) -> Self {
        Self {
            run_manifest_artifact_digest,
            run_identity,
            public_case_artifact_digest,
            method,
            candidate_selection_digest,
            presentation_receipt_id,
            environment,
            rendered_candidate,
            externally_observed,
        }
    }

    #[must_use]
    pub const fn trust_boundary(self) -> MeasurementTrustBoundaryV1 {
        MeasurementTrustBoundaryV1::SelfAssertedReproducibilityInput
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
    pub const fn externally_observed(self) -> MeasuredCandidateResources {
        self.externally_observed
    }

    #[must_use]
    pub const fn canonical_candidate_tokens(self) -> u64 {
        self.externally_observed.canonical_candidate_tokens()
    }

    #[must_use]
    pub const fn wall_time_nanos(self) -> u64 {
        self.externally_observed.wall_time_nanos()
    }

    #[must_use]
    pub const fn peak_rss_bytes(self) -> u64 {
        self.externally_observed.peak_memory_bytes()
    }
}

impl fmt::Debug for MeasurementProvenanceReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MeasurementProvenanceReceiptV1")
            .field("trust_boundary", &self.trust_boundary())
            .field("run_manifest_binding_present", &true)
            .field("run_identity_binding_present", &true)
            .field("public_case_binding_present", &true)
            .field("method_binding_present", &true)
            .field("candidate_selection_binding_present", &true)
            .field("presentation_receipt_binding_present", &true)
            .field("measurement_environment", &self.environment)
            .field("rendered_candidate", &self.rendered_candidate)
            .field("external_observation_dimensions_present", &3)
            .finish()
    }
}

/// Stable construction failures with no identities or content.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MeasurementProvenanceError {
    ZeroRendererContractVersion,
    RendererContractVersionExceedsJsonSafeInteger,
    RenderedCandidateBytesExceedJsonSafeInteger,
    ZeroHarnessContractVersion,
    HarnessContractVersionExceedsJsonSafeInteger,
    SelectionBindingLengthOverflow,
    SelectionBindingValueOverflow,
}

impl MeasurementProvenanceError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ZeroRendererContractVersion => {
                "EVIDENTRAIL_BENCH_MEASUREMENT_ZERO_RENDERER_CONTRACT_VERSION"
            }
            Self::RendererContractVersionExceedsJsonSafeInteger => {
                "EVIDENTRAIL_BENCH_MEASUREMENT_RENDERER_VERSION_EXCEEDS_JSON_SAFE_INTEGER"
            }
            Self::RenderedCandidateBytesExceedJsonSafeInteger => {
                "EVIDENTRAIL_BENCH_MEASUREMENT_RENDERED_CANDIDATE_BYTES_EXCEED_JSON_SAFE_INTEGER"
            }
            Self::ZeroHarnessContractVersion => {
                "EVIDENTRAIL_BENCH_MEASUREMENT_ZERO_HARNESS_CONTRACT_VERSION"
            }
            Self::HarnessContractVersionExceedsJsonSafeInteger => {
                "EVIDENTRAIL_BENCH_MEASUREMENT_HARNESS_VERSION_EXCEEDS_JSON_SAFE_INTEGER"
            }
            Self::SelectionBindingLengthOverflow => {
                "EVIDENTRAIL_BENCH_MEASUREMENT_SELECTION_BINDING_LENGTH_OVERFLOW"
            }
            Self::SelectionBindingValueOverflow => {
                "EVIDENTRAIL_BENCH_MEASUREMENT_SELECTION_BINDING_VALUE_OVERFLOW"
            }
        }
    }
}

impl fmt::Debug for MeasurementProvenanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MeasurementProvenanceError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for MeasurementProvenanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for MeasurementProvenanceError {}

/// Derive the compact binding used by a measurement receipt.
///
/// Candidate identities remain ordered exactly as frozen by the method. The
/// selected sequence binds event identity, ordinal, source-byte cost, and every
/// canonical selection reason. Accounting is included explicitly so a receipt
/// cannot be replayed across a budget or accounting change.
pub fn derive_frozen_candidate_selection_digest_v1(
    ledger: &EventLedger,
    result: &MethodResult,
) -> Result<FrozenCandidateSelectionDigestV1, MeasurementProvenanceError> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, FROZEN_SELECTION_DOMAIN_V1)?;
    update_field(&mut hasher, ledger.retrieval_id().as_bytes())?;
    update_field(&mut hasher, result.method().name().as_bytes())?;
    update_field(&mut hasher, result.method().version().as_bytes())?;

    update_usize(&mut hasher, result.candidate_event_ids().len())?;
    for event_id in result.candidate_event_ids() {
        update_field(&mut hasher, event_id.as_bytes())?;
    }

    update_usize(&mut hasher, result.selected().len())?;
    for selected in result.selected() {
        update_field(&mut hasher, selected.event_id().as_bytes())?;
        update_u64(&mut hasher, selected.ordinal())?;
        update_usize(&mut hasher, selected.source_byte_cost())?;
        update_usize(&mut hasher, selected.reasons().len())?;
        for reason in selected.reasons() {
            update_field(&mut hasher, reason.code().as_bytes())?;
        }
    }

    let accounting = result.accounting();
    for value in [
        accounting.received_event_count(),
        accounting.candidate_event_count(),
        accounting.candidate_cost().unique_source_bytes(),
        accounting.selected_event_count(),
        accounting.retained_raw_event_count(),
        accounting.budget_excluded_candidate_count(),
        accounting.selected_source_bytes(),
        accounting.budget().bytes(),
    ] {
        update_usize(&mut hasher, value)?;
    }

    Ok(FrozenCandidateSelectionDigestV1(hasher.finalize().into()))
}

fn update_usize(hasher: &mut Sha256, value: usize) -> Result<(), MeasurementProvenanceError> {
    let value = u64::try_from(value)
        .map_err(|_| MeasurementProvenanceError::SelectionBindingValueOverflow)?;
    update_u64(hasher, value)
}

fn update_u64(hasher: &mut Sha256, value: u64) -> Result<(), MeasurementProvenanceError> {
    update_field(hasher, &value.to_le_bytes())
}

fn update_field(hasher: &mut Sha256, field: &[u8]) -> Result<(), MeasurementProvenanceError> {
    let length = u64::try_from(field.len())
        .map_err(|_| MeasurementProvenanceError::SelectionBindingLengthOverflow)?;
    hasher.update(length.to_le_bytes());
    hasher.update(field);
    Ok(())
}
