use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;

use evidentrail_core::{BlockIndex, EventLedger, RetrievalId};
use evidentrail_schema::{ArtifactDigest, EventId};
use sha2::{Digest as _, Sha256};

use crate::{
    BenchmarkRunIdentityV1, CandidateResourceEnvelope, EvidenceTargetV1,
    EvidentrailBenchAnnotationSpecV1, EvidentrailBenchRunManifestV1, GovernedCaseArtifactBindingV1,
    GovernedCaseArtifactJoinV1, MeasuredCandidateResources, MeasurementEnvironmentV1,
    MeasurementTrustBoundaryV1, MethodDescriptor, RenderedCandidateArtifactV1,
    WeightedDiagnosticRequirementV1, candidate_resource_envelope,
};

const SOURCE_EXACT_REPRESENTATION_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/source-exact-representation/v1";
const REVERSIBLE_ENCODED_REPRESENTATION_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/reversible-encoded-representation/v1";
const ASCII_BYTE_ESCAPE_V1_MANIFEST: &[u8] = b"evidentrail/bench/reversible-encoding/ascii-byte-escape/v1\0printable-ascii=literal-except-backslash\0backslash=double-backslash\0lf=backslash-n\0cr=backslash-r\0tab=backslash-t\0other=backslash-xhh-lowercase\0single-line=true";
const PASSTHROUGH_ASCII_BYTE_ESCAPE_FIELD_PREFIX_V1: &[u8] =
    b"\n    data_encoding: ascii_byte_escape_v1\n    data: ";
const COMPILED_ASCII_BYTE_ESCAPE_FIELD_PREFIX_V1: &[u8] =
    b"\n      data_encoding: ascii_byte_escape_v1\n      data: ";
const REPRESENTATION_SUBMISSION_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/external-representation-submission/v1";
const FIDELITY_POLICY_DOMAIN_V1: &[u8] = b"evidentrail/bench/governed-fidelity-policy/v1";
const FIDELITY_SCORE_DOMAIN_V1: &[u8] = b"evidentrail/bench/governed-fidelity-score/v1";
const NEEDS_VDS_DOMAIN_V1: &[u8] = b"evidentrail/bench/governed-fidelity-needs-vds/v1";

/// Hard V1 ceiling for occurrence/class claims in one frozen submission.
pub const MAX_REPRESENTATION_CLAIMS_V1: usize = 8_192;
/// Hard V1 ceiling for governed diagnostic requirements in one policy.
pub const MAX_FIDELITY_REQUIREMENTS_V1: usize = 4_096;
/// Hard V1 ceiling for pinned transformed artifacts in one requirement rule.
pub const MAX_PINNED_TRANSFORMS_PER_REQUIREMENT_V1: usize = 4_096;
/// Hard V1 ceiling for the exact rendered candidate artifact.
pub const MAX_FIDELITY_RENDERED_CANDIDATE_BYTES_V1: u64 = 16 * 1024 * 1024;
/// Hard V1 ceiling for each method identity component.
pub const MAX_FIDELITY_METHOD_IDENTITY_BYTES_V1: usize = 128;

/// Fidelity class asserted before governed annotations are admitted.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceRepresentationClassV1 {
    SourceExactShownVerbatim,
    SourceExactReversibleEncoding,
    SourceValidatedTransformedSample,
    PatternOnly,
}

impl EvidenceRepresentationClassV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SourceExactShownVerbatim => "source_exact_shown_verbatim",
            Self::SourceExactReversibleEncoding => "source_exact_reversible_encoding",
            Self::SourceValidatedTransformedSample => "source_validated_transformed_sample",
            Self::PatternOnly => "pattern_only",
        }
    }
}

/// Closed identity of a reversible evidence encoding admitted for static
/// fidelity. V1 admits only canonical `ascii_byte_escape_v1`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReversibleEncodingIdentityV1 {
    artifact_digest: ArtifactDigest,
    contract_version: u64,
}

impl ReversibleEncodingIdentityV1 {
    /// Resolve persisted identity material against the closed V1 registry.
    pub fn try_new(
        artifact_digest: ArtifactDigest,
        contract_version: u64,
    ) -> Result<Self, RepresentationFidelityErrorV1> {
        let expected = ascii_byte_escape_v1_identity();
        if artifact_digest != expected.artifact_digest
            || contract_version != expected.contract_version
        {
            return Err(RepresentationFidelityErrorV1::UnknownReversibleEncoding);
        }
        Ok(expected)
    }

    #[must_use]
    pub const fn artifact_digest(self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn contract_version(self) -> u64 {
        self.contract_version
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        "ascii_byte_escape_v1"
    }
}

impl fmt::Debug for ReversibleEncodingIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReversibleEncodingIdentityV1")
            .field("code", &self.code())
            .field("contract_version", &self.contract_version)
            .field("artifact_identity_present", &true)
            .finish()
    }
}

/// Identity of the independently specified canonical single-line byte escape.
#[must_use]
pub fn ascii_byte_escape_v1_identity() -> ReversibleEncodingIdentityV1 {
    ReversibleEncodingIdentityV1 {
        artifact_digest: raw_artifact_digest(ASCII_BYTE_ESCAPE_V1_MANIFEST),
        contract_version: 1,
    }
}

impl fmt::Debug for EvidenceRepresentationClassV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceRepresentationClassV1")
            .field("code", &self.code())
            .finish()
    }
}

/// One public, score-free occurrence representation claim.
///
/// The digest identifies the exact representation artifact for this
/// occurrence. It is not a hidden-label assertion and does not itself grant
/// recall credit.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EvidenceRepresentationClaimV1 {
    event_id: EventId,
    class: EvidenceRepresentationClassV1,
    representation_artifact_digest: ArtifactDigest,
    reversible_encoding: Option<ReversibleEncodingIdentityV1>,
    reversible_context_start: Option<u64>,
    rendered_byte_range: Option<(u64, u64)>,
}

impl EvidenceRepresentationClaimV1 {
    /// Claim one exact source occurrence at a unique half-open byte range in
    /// the frozen rendered candidate artifact.
    #[must_use]
    pub const fn source_exact_shown_verbatim(
        event_id: EventId,
        representation_artifact_digest: ArtifactDigest,
        rendered_byte_start: u64,
        rendered_byte_end: u64,
    ) -> Self {
        Self {
            event_id,
            class: EvidenceRepresentationClassV1::SourceExactShownVerbatim,
            representation_artifact_digest,
            reversible_encoding: None,
            reversible_context_start: None,
            rendered_byte_range: Some((rendered_byte_start, rendered_byte_end)),
        }
    }

    /// Claim one exact source occurrence represented by a closed reversible
    /// encoding in the frozen render.
    ///
    /// `rendered_context_start..rendered_byte_start` must be one admitted
    /// canonical field prefix. `rendered_byte_start..rendered_byte_end` is the
    /// encoded data and may be empty only for an empty source event. The full
    /// context-through-data range is occurrence-unique and non-overlapping.
    #[must_use]
    pub const fn source_exact_reversible_encoding(
        event_id: EventId,
        reversible_encoding: ReversibleEncodingIdentityV1,
        representation_artifact_digest: ArtifactDigest,
        rendered_context_start: u64,
        rendered_byte_start: u64,
        rendered_byte_end: u64,
    ) -> Self {
        Self {
            event_id,
            class: EvidenceRepresentationClassV1::SourceExactReversibleEncoding,
            representation_artifact_digest,
            reversible_encoding: Some(reversible_encoding),
            reversible_context_start: Some(rendered_context_start),
            rendered_byte_range: Some((rendered_byte_start, rendered_byte_end)),
        }
    }

    #[must_use]
    pub const fn source_validated_transformed_sample(
        event_id: EventId,
        representation_artifact_digest: ArtifactDigest,
    ) -> Self {
        Self {
            event_id,
            class: EvidenceRepresentationClassV1::SourceValidatedTransformedSample,
            representation_artifact_digest,
            reversible_encoding: None,
            reversible_context_start: None,
            rendered_byte_range: None,
        }
    }

    #[must_use]
    pub const fn pattern_only(
        event_id: EventId,
        representation_artifact_digest: ArtifactDigest,
    ) -> Self {
        Self {
            event_id,
            class: EvidenceRepresentationClassV1::PatternOnly,
            representation_artifact_digest,
            reversible_encoding: None,
            reversible_context_start: None,
            rendered_byte_range: None,
        }
    }

    #[must_use]
    pub const fn event_id(self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn class(self) -> EvidenceRepresentationClassV1 {
        self.class
    }

    #[must_use]
    pub const fn representation_artifact_digest(self) -> ArtifactDigest {
        self.representation_artifact_digest
    }

    #[must_use]
    pub const fn reversible_encoding(self) -> Option<ReversibleEncodingIdentityV1> {
        self.reversible_encoding
    }

    #[must_use]
    pub const fn reversible_context_start(self) -> Option<u64> {
        self.reversible_context_start
    }

    #[must_use]
    pub const fn rendered_byte_range(self) -> Option<(u64, u64)> {
        self.rendered_byte_range
    }
}

impl fmt::Debug for EvidenceRepresentationClaimV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceRepresentationClaimV1")
            .field("event_identity_present", &true)
            .field("class", &self.class)
            .field("representation_artifact_identity_present", &true)
            .field(
                "reversible_encoding_identity_present",
                &self.reversible_encoding.is_some(),
            )
            .field(
                "reversible_context_range_present",
                &self.reversible_context_start.is_some(),
            )
            .field(
                "rendered_byte_range_present",
                &self.rendered_byte_range.is_some(),
            )
            .finish()
    }
}

/// Derive the only V1 digest that may back a source-exact/verbatim claim.
///
/// Governed evaluation recomputes this digest from the sealed ledger. A
/// whitespace, terminator, NUL, or invalid-UTF-8 change therefore fails exact
/// fidelity without decoding or normalization.
pub fn derive_source_exact_representation_artifact_digest_v1(
    source_bytes: &[u8],
) -> Result<ArtifactDigest, RepresentationFidelityErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, SOURCE_EXACT_REPRESENTATION_DOMAIN_V1)?;
    update_field(&mut hasher, source_bytes)?;
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

/// Bind one exact canonical encoded slice to its closed codec identity.
pub fn derive_reversible_encoded_representation_artifact_digest_v1(
    reversible_encoding: ReversibleEncodingIdentityV1,
    encoded_bytes: &[u8],
) -> Result<ArtifactDigest, RepresentationFidelityErrorV1> {
    validate_reversible_encoding(reversible_encoding)?;
    let mut hasher = Sha256::new();
    update_field(&mut hasher, REVERSIBLE_ENCODED_REPRESENTATION_DOMAIN_V1)?;
    update_field(&mut hasher, reversible_encoding.artifact_digest.as_bytes())?;
    update_u64(&mut hasher, reversible_encoding.contract_version)?;
    update_field(&mut hasher, encoded_bytes)?;
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

/// Public representation/provenance material frozen before hidden labels.
///
/// The receipt is self-asserted reproducibility input, not attestation. Its
/// inherent event count and source bytes are recomputed from the sealed ledger;
/// token count, wall time, and peak memory remain explicit external
/// observations. No annotation or score can be stored here.
#[derive(Clone, PartialEq, Eq)]
pub struct FrozenExternalRepresentationSubmissionV1 {
    artifact_digest: ArtifactDigest,
    public_run_manifest_artifact_digest: ArtifactDigest,
    run_identity: BenchmarkRunIdentityV1,
    public_case_artifact_digest: ArtifactDigest,
    method: MethodDescriptor,
    retrieval_id: RetrievalId,
    representation_artifact_digest: ArtifactDigest,
    normalizer_artifact_digest: ArtifactDigest,
    environment: MeasurementEnvironmentV1,
    rendered_candidate: RenderedCandidateArtifactV1,
    resources: CandidateResourceEnvelope,
    claims: Vec<EvidenceRepresentationClaimV1>,
    candidate_event_ids: Vec<EventId>,
}

impl FrozenExternalRepresentationSubmissionV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new_self_asserted<Claims>(
        public_run_manifest_artifact_digest: ArtifactDigest,
        run_manifest: &EvidentrailBenchRunManifestV1,
        public_case_artifact_digest: ArtifactDigest,
        method: MethodDescriptor,
        ledger: &EventLedger,
        representation_artifact_digest: ArtifactDigest,
        normalizer_artifact_digest: ArtifactDigest,
        environment: MeasurementEnvironmentV1,
        rendered_candidate: RenderedCandidateArtifactV1,
        rendered_candidate_bytes: &[u8],
        externally_observed: MeasuredCandidateResources,
        claims: Claims,
    ) -> Result<Self, RepresentationFidelityErrorV1>
    where
        Claims: IntoIterator<Item = EvidenceRepresentationClaimV1>,
    {
        if run_manifest
            .public_case_artifact_digests()
            .binary_search(&public_case_artifact_digest)
            .is_err()
        {
            return Err(RepresentationFidelityErrorV1::UnknownPublicCaseArtifact);
        }
        validate_method_identity(method)?;
        if rendered_candidate.byte_count() > MAX_FIDELITY_RENDERED_CANDIDATE_BYTES_V1 {
            return Err(RepresentationFidelityErrorV1::RenderedCandidateTooLarge);
        }
        let rendered_byte_count = u64::try_from(rendered_candidate_bytes.len())
            .map_err(|_| RepresentationFidelityErrorV1::ArtifactLengthOverflow)?;
        if rendered_candidate.byte_count() != rendered_byte_count
            || raw_artifact_digest(rendered_candidate_bytes) != rendered_candidate.artifact_digest()
        {
            return Err(RepresentationFidelityErrorV1::RenderedCandidateArtifactMismatch);
        }

        let mut claims = claims
            .into_iter()
            .take(MAX_REPRESENTATION_CLAIMS_V1 + 1)
            .collect::<Vec<_>>();
        if claims.is_empty() {
            return Err(RepresentationFidelityErrorV1::EmptyRepresentationClaims);
        }
        if claims.len() > MAX_REPRESENTATION_CLAIMS_V1 {
            return Err(RepresentationFidelityErrorV1::TooManyRepresentationClaims);
        }
        claims.sort_unstable();
        let mut event_classes = BTreeSet::new();
        let mut proven_ranges = Vec::new();
        for claim in &claims {
            if !event_classes.insert((claim.event_id, claim.class)) {
                return Err(RepresentationFidelityErrorV1::DuplicateEventRepresentationClass);
            }
            match (
                claim.class,
                claim.reversible_encoding,
                claim.reversible_context_start,
                claim.rendered_byte_range,
            ) {
                (
                    EvidenceRepresentationClassV1::SourceExactShownVerbatim,
                    None,
                    None,
                    Some((start, end)),
                ) => {
                    let start = usize::try_from(start)
                        .map_err(|_| RepresentationFidelityErrorV1::InvalidRenderedByteRange)?;
                    let end = usize::try_from(end)
                        .map_err(|_| RepresentationFidelityErrorV1::InvalidRenderedByteRange)?;
                    if start >= end {
                        return Err(RepresentationFidelityErrorV1::InvalidRenderedByteRange);
                    }
                    let rendered_slice = rendered_candidate_bytes
                        .get(start..end)
                        .ok_or(RepresentationFidelityErrorV1::InvalidRenderedByteRange)?;
                    let event = ledger
                        .event(claim.event_id)
                        .map_err(|_| RepresentationFidelityErrorV1::UnknownClaimedEvent)?;
                    if rendered_slice != event.raw()
                        || derive_source_exact_representation_artifact_digest_v1(rendered_slice)?
                            != claim.representation_artifact_digest
                    {
                        return Err(RepresentationFidelityErrorV1::SourceExactDigestMismatch {
                            count: 1,
                        });
                    }
                    proven_ranges.push((start, end));
                }
                (
                    EvidenceRepresentationClassV1::SourceExactReversibleEncoding,
                    Some(reversible_encoding),
                    Some(context_start),
                    Some((start, end)),
                ) => {
                    validate_reversible_encoding(reversible_encoding)?;
                    let context_start = usize::try_from(context_start)
                        .map_err(|_| RepresentationFidelityErrorV1::InvalidRenderedByteRange)?;
                    let start = usize::try_from(start)
                        .map_err(|_| RepresentationFidelityErrorV1::InvalidRenderedByteRange)?;
                    let end = usize::try_from(end)
                        .map_err(|_| RepresentationFidelityErrorV1::InvalidRenderedByteRange)?;
                    if context_start >= start || start > end {
                        return Err(RepresentationFidelityErrorV1::InvalidRenderedByteRange);
                    }
                    let context = rendered_candidate_bytes
                        .get(context_start..start)
                        .ok_or(RepresentationFidelityErrorV1::InvalidRenderedByteRange)?;
                    if context != PASSTHROUGH_ASCII_BYTE_ESCAPE_FIELD_PREFIX_V1
                        && context != COMPILED_ASCII_BYTE_ESCAPE_FIELD_PREFIX_V1
                    {
                        return Err(
                            RepresentationFidelityErrorV1::MalformedReversibleEncodingContext,
                        );
                    }
                    let rendered_slice = rendered_candidate_bytes
                        .get(start..end)
                        .ok_or(RepresentationFidelityErrorV1::InvalidRenderedByteRange)?;
                    let event = ledger
                        .event(claim.event_id)
                        .map_err(|_| RepresentationFidelityErrorV1::UnknownClaimedEvent)?;
                    verify_ascii_byte_escape_v1(rendered_slice, event.raw())?;
                    if derive_reversible_encoded_representation_artifact_digest_v1(
                        reversible_encoding,
                        rendered_slice,
                    )? != claim.representation_artifact_digest
                    {
                        return Err(
                            RepresentationFidelityErrorV1::ReversibleEncodingDigestMismatch,
                        );
                    }
                    // The field prefix is part of the occurrence proof. This
                    // keeps even empty encoded data ranges non-empty and stops
                    // multiple empty events from aliasing one proof location.
                    proven_ranges.push((context_start, end));
                }
                (EvidenceRepresentationClassV1::SourceExactShownVerbatim, _, _, _)
                | (EvidenceRepresentationClassV1::SourceExactReversibleEncoding, _, _, _)
                | (
                    EvidenceRepresentationClassV1::SourceValidatedTransformedSample
                    | EvidenceRepresentationClassV1::PatternOnly,
                    Some(_),
                    _,
                    _,
                )
                | (
                    EvidenceRepresentationClassV1::SourceValidatedTransformedSample
                    | EvidenceRepresentationClassV1::PatternOnly,
                    _,
                    Some(_),
                    _,
                )
                | (
                    EvidenceRepresentationClassV1::SourceValidatedTransformedSample
                    | EvidenceRepresentationClassV1::PatternOnly,
                    _,
                    _,
                    Some(_),
                ) => {
                    return Err(RepresentationFidelityErrorV1::InvalidRenderedByteRange);
                }
                (
                    EvidenceRepresentationClassV1::SourceValidatedTransformedSample
                    | EvidenceRepresentationClassV1::PatternOnly,
                    None,
                    None,
                    None,
                ) => {}
            }
        }
        proven_ranges.sort_unstable();
        if proven_ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err(RepresentationFidelityErrorV1::OverlappingProvenRepresentationRanges);
        }
        let candidate_event_ids = claims
            .iter()
            .map(|claim| claim.event_id)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let resources =
            candidate_resource_envelope(ledger, &candidate_event_ids, externally_observed)
                .map_err(|_| RepresentationFidelityErrorV1::CandidateResourceInvariantViolation)?;
        run_manifest
            .identity()
            .budget()
            .cap()
            .check(resources)
            .map_err(|_| RepresentationFidelityErrorV1::CandidateResourceCapExceeded)?;

        let artifact_digest = derive_representation_submission_artifact_digest(
            public_run_manifest_artifact_digest,
            run_manifest.identity(),
            public_case_artifact_digest,
            method,
            ledger.retrieval_id(),
            representation_artifact_digest,
            normalizer_artifact_digest,
            environment,
            rendered_candidate,
            resources,
            &claims,
        )?;
        Ok(Self {
            artifact_digest,
            public_run_manifest_artifact_digest,
            run_identity: run_manifest.identity(),
            public_case_artifact_digest,
            method,
            retrieval_id: ledger.retrieval_id(),
            representation_artifact_digest,
            normalizer_artifact_digest,
            environment,
            rendered_candidate,
            resources,
            claims,
            candidate_event_ids,
        })
    }

    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn public_run_manifest_artifact_digest(&self) -> ArtifactDigest {
        self.public_run_manifest_artifact_digest
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
    pub const fn method(&self) -> MethodDescriptor {
        self.method
    }

    #[must_use]
    pub const fn retrieval_id(&self) -> RetrievalId {
        self.retrieval_id
    }

    #[must_use]
    pub const fn representation_artifact_digest(&self) -> ArtifactDigest {
        self.representation_artifact_digest
    }

    #[must_use]
    pub const fn normalizer_artifact_digest(&self) -> ArtifactDigest {
        self.normalizer_artifact_digest
    }

    #[must_use]
    pub const fn environment(&self) -> MeasurementEnvironmentV1 {
        self.environment
    }

    #[must_use]
    pub const fn rendered_candidate(&self) -> RenderedCandidateArtifactV1 {
        self.rendered_candidate
    }

    #[must_use]
    pub const fn resources(&self) -> CandidateResourceEnvelope {
        self.resources
    }

    #[must_use]
    pub fn claims(&self) -> &[EvidenceRepresentationClaimV1] {
        &self.claims
    }

    #[must_use]
    pub fn candidate_event_ids(&self) -> &[EventId] {
        &self.candidate_event_ids
    }

    #[must_use]
    pub const fn trust_boundary(&self) -> MeasurementTrustBoundaryV1 {
        MeasurementTrustBoundaryV1::SelfAssertedReproducibilityInput
    }
}

impl fmt::Debug for FrozenExternalRepresentationSubmissionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let exact_count = class_count(
            &self.claims,
            EvidenceRepresentationClassV1::SourceExactShownVerbatim,
        );
        let reversible_exact_count = class_count(
            &self.claims,
            EvidenceRepresentationClassV1::SourceExactReversibleEncoding,
        );
        let transformed_count = class_count(
            &self.claims,
            EvidenceRepresentationClassV1::SourceValidatedTransformedSample,
        );
        let pattern_count = class_count(&self.claims, EvidenceRepresentationClassV1::PatternOnly);
        formatter
            .debug_struct("FrozenExternalRepresentationSubmissionV1")
            .field("trust_boundary", &self.trust_boundary())
            .field("artifact_binding_present", &true)
            .field("public_run_binding_present", &true)
            .field("public_case_binding_present", &true)
            .field("method", &self.method)
            .field("retrieval_binding_present", &true)
            .field("representation_binding_present", &true)
            .field("normalizer_binding_present", &true)
            .field("measurement_environment", &self.environment)
            .field("rendered_candidate", &self.rendered_candidate)
            .field("resources", &self.resources)
            .field("candidate_event_count", &self.candidate_event_ids.len())
            .field("source_exact_claim_count", &exact_count)
            .field(
                "reversible_source_exact_claim_count",
                &reversible_exact_count,
            )
            .field("transformed_claim_count", &transformed_count)
            .field("pattern_claim_count", &pattern_count)
            .field("contains_governed_labels", &false)
            .field("contains_score", &false)
            .finish()
    }
}

/// Closed fallback for a non-exact representation.
///
/// There is deliberately no pattern-accepting variant. Pattern-only material
/// can be rejected or deferred to an external downstream diagnostic study.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NonExactFidelityDispositionV1 {
    Reject,
    NeedsDownstreamVds,
}

impl NonExactFidelityDispositionV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::NeedsDownstreamVds => "needs_downstream_vds",
        }
    }
}

impl fmt::Debug for NonExactFidelityDispositionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NonExactFidelityDispositionV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Hidden expectation for one transformed artifact at one event target.
///
/// Matching this tuple never grants static recall: the public submission does
/// not prove that the per-event transform is reader-visible in the frozen
/// rendered bytes. A matching expectation can only be rejected or routed to a
/// downstream VDS by its enclosing rule.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PinnedTransformedExpectationV1 {
    event_id: EventId,
    transformed_artifact_digest: ArtifactDigest,
}

impl PinnedTransformedExpectationV1 {
    #[must_use]
    pub const fn new(event_id: EventId, transformed_artifact_digest: ArtifactDigest) -> Self {
        Self {
            event_id,
            transformed_artifact_digest,
        }
    }

    #[must_use]
    pub const fn event_id(self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn transformed_artifact_digest(self) -> ArtifactDigest {
        self.transformed_artifact_digest
    }
}

impl fmt::Debug for PinnedTransformedExpectationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedTransformedExpectationV1")
            .field("event_identity_present", &true)
            .field("transformed_artifact_identity_present", &true)
            .finish()
    }
}

/// Governed policy for one diagnostic requirement.
///
/// Source-exact/verbatim evidence is always eligible after ledger verification.
/// A transformed sample can be distinguished as matching or not matching its
/// exact event+artifact expectation. Both paths remain closed non-exact
/// dispositions: reject or defer to downstream VDS. Pattern-only material has
/// the same closed choices and can never be directly accepted by this type.
#[derive(Clone, PartialEq, Eq)]
pub struct RequirementFidelityPolicyV1 {
    expected_transformed: Vec<PinnedTransformedExpectationV1>,
    expected_transformed_disposition: NonExactFidelityDispositionV1,
    unmatched_transformed: NonExactFidelityDispositionV1,
    pattern_only: NonExactFidelityDispositionV1,
}

impl RequirementFidelityPolicyV1 {
    #[must_use]
    pub const fn source_exact_only() -> Self {
        Self {
            expected_transformed: Vec::new(),
            expected_transformed_disposition: NonExactFidelityDispositionV1::Reject,
            unmatched_transformed: NonExactFidelityDispositionV1::Reject,
            pattern_only: NonExactFidelityDispositionV1::Reject,
        }
    }

    pub fn try_new<Expected>(
        expected_transformed: Expected,
        expected_transformed_disposition: NonExactFidelityDispositionV1,
        unmatched_transformed: NonExactFidelityDispositionV1,
        pattern_only: NonExactFidelityDispositionV1,
    ) -> Result<Self, RepresentationFidelityErrorV1>
    where
        Expected: IntoIterator<Item = PinnedTransformedExpectationV1>,
    {
        let mut expected_transformed = expected_transformed
            .into_iter()
            .take(MAX_PINNED_TRANSFORMS_PER_REQUIREMENT_V1 + 1)
            .collect::<Vec<_>>();
        if expected_transformed.len() > MAX_PINNED_TRANSFORMS_PER_REQUIREMENT_V1 {
            return Err(RepresentationFidelityErrorV1::TooManyPinnedTransforms);
        }
        expected_transformed.sort_unstable();
        if expected_transformed
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(RepresentationFidelityErrorV1::DuplicatePinnedTransform);
        }
        Ok(Self {
            expected_transformed,
            expected_transformed_disposition,
            unmatched_transformed,
            pattern_only,
        })
    }

    #[must_use]
    pub fn expected_transformed(&self) -> &[PinnedTransformedExpectationV1] {
        &self.expected_transformed
    }

    #[must_use]
    pub const fn expected_transformed_disposition(&self) -> NonExactFidelityDispositionV1 {
        self.expected_transformed_disposition
    }

    #[must_use]
    pub const fn unmatched_transformed(&self) -> NonExactFidelityDispositionV1 {
        self.unmatched_transformed
    }

    #[must_use]
    pub const fn pattern_only(&self) -> NonExactFidelityDispositionV1 {
        self.pattern_only
    }

    fn transform_disposition(
        &self,
        event_id: EventId,
        artifact_digest: ArtifactDigest,
    ) -> NonExactFidelityDispositionV1 {
        if self
            .expected_transformed
            .binary_search(&PinnedTransformedExpectationV1::new(
                event_id,
                artifact_digest,
            ))
            .is_ok()
        {
            self.expected_transformed_disposition
        } else {
            self.unmatched_transformed
        }
    }
}

impl Default for RequirementFidelityPolicyV1 {
    fn default() -> Self {
        Self::source_exact_only()
    }
}

impl fmt::Debug for RequirementFidelityPolicyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequirementFidelityPolicyV1")
            .field(
                "expected_transformed_count",
                &self.expected_transformed.len(),
            )
            .field(
                "expected_transformed_disposition",
                &self.expected_transformed_disposition,
            )
            .field("unmatched_transformed", &self.unmatched_transformed)
            .field("pattern_only", &self.pattern_only)
            .finish()
    }
}

/// Hidden, annotation-bound fidelity policy with exactly one rule per
/// diagnostic requirement.
#[derive(Clone, PartialEq, Eq)]
pub struct GovernedRepresentationFidelityPolicyV1 {
    artifact_digest: ArtifactDigest,
    artifact_binding: GovernedCaseArtifactBindingV1,
    rules: Vec<RequirementFidelityPolicyV1>,
}

impl GovernedRepresentationFidelityPolicyV1 {
    pub fn try_new<Rules>(
        artifact_binding: GovernedCaseArtifactBindingV1,
        annotation: &EvidentrailBenchAnnotationSpecV1,
        rules: Rules,
    ) -> Result<Self, RepresentationFidelityErrorV1>
    where
        Rules: IntoIterator<Item = RequirementFidelityPolicyV1>,
    {
        if annotation.public_case_artifact_digest()
            != artifact_binding.public_case_artifact_digest()
        {
            return Err(RepresentationFidelityErrorV1::GovernedArtifactBindingMismatch);
        }
        if annotation.diagnostic_requirements().len() > MAX_FIDELITY_REQUIREMENTS_V1 {
            return Err(RepresentationFidelityErrorV1::TooManyFidelityRequirements);
        }
        let expected_rule_count = annotation.diagnostic_requirements().len();
        let rules = rules
            .into_iter()
            .take(expected_rule_count.saturating_add(1))
            .collect::<Vec<_>>();
        if rules.len() != annotation.diagnostic_requirements().len() {
            return Err(RepresentationFidelityErrorV1::RequirementPolicyCountMismatch);
        }
        for (requirement, rule) in annotation.diagnostic_requirements().iter().zip(&rules) {
            let permitted_event_targets = requirement
                .alternatives()
                .iter()
                .flatten()
                .filter_map(|target| match target {
                    EvidenceTargetV1::Event(event_id) => Some(*event_id),
                    EvidenceTargetV1::Block(_) => None,
                })
                .collect::<BTreeSet<_>>();
            if rule
                .expected_transformed
                .iter()
                .any(|expectation| !permitted_event_targets.contains(&expectation.event_id))
            {
                return Err(RepresentationFidelityErrorV1::PinnedTransformOutsideRequirement);
            }
        }

        let artifact_digest = derive_fidelity_policy_artifact_digest(artifact_binding, &rules)?;
        Ok(Self {
            artifact_digest,
            artifact_binding,
            rules,
        })
    }

    pub fn source_exact_only(
        artifact_binding: GovernedCaseArtifactBindingV1,
        annotation: &EvidentrailBenchAnnotationSpecV1,
    ) -> Result<Self, RepresentationFidelityErrorV1> {
        if annotation.diagnostic_requirements().len() > MAX_FIDELITY_REQUIREMENTS_V1 {
            return Err(RepresentationFidelityErrorV1::TooManyFidelityRequirements);
        }
        Self::try_new(
            artifact_binding,
            annotation,
            (0..annotation.diagnostic_requirements().len())
                .map(|_| RequirementFidelityPolicyV1::source_exact_only()),
        )
    }

    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn artifact_binding(&self) -> GovernedCaseArtifactBindingV1 {
        self.artifact_binding
    }

    #[must_use]
    pub fn rules(&self) -> &[RequirementFidelityPolicyV1] {
        &self.rules
    }
}

impl fmt::Debug for GovernedRepresentationFidelityPolicyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pinned_transform_count = self
            .rules
            .iter()
            .map(|rule| rule.expected_transformed.len())
            .sum::<usize>();
        formatter
            .debug_struct("GovernedRepresentationFidelityPolicyV1")
            .field("artifact_binding_present", &true)
            .field("policy_artifact_identity_present", &true)
            .field("requirement_rule_count", &self.rules.len())
            .field("pinned_transform_count", &pinned_transform_count)
            .field("pattern_static_acceptance_available", &false)
            .finish()
    }
}

/// Exact governed score plus its frozen public and hidden-policy provenance.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GovernedRepresentationScoreSubmissionV1 {
    artifact_digest: ArtifactDigest,
    artifact_binding: GovernedCaseArtifactBindingV1,
    representation_submission_artifact_digest: ArtifactDigest,
    fidelity_policy_artifact_digest: ArtifactDigest,
    requirement_count: u64,
    satisfied_requirement_count: u64,
    total_weight_micros: u64,
    satisfied_weight_micros: u64,
}

impl GovernedRepresentationScoreSubmissionV1 {
    #[must_use]
    pub const fn artifact_digest(self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn artifact_binding(self) -> GovernedCaseArtifactBindingV1 {
        self.artifact_binding
    }

    #[must_use]
    pub const fn representation_submission_artifact_digest(self) -> ArtifactDigest {
        self.representation_submission_artifact_digest
    }

    #[must_use]
    pub const fn fidelity_policy_artifact_digest(self) -> ArtifactDigest {
        self.fidelity_policy_artifact_digest
    }

    #[must_use]
    pub const fn requirement_count(self) -> u64 {
        self.requirement_count
    }

    #[must_use]
    pub const fn satisfied_requirement_count(self) -> u64 {
        self.satisfied_requirement_count
    }

    #[must_use]
    pub const fn total_weight_micros(self) -> u64 {
        self.total_weight_micros
    }

    #[must_use]
    pub const fn satisfied_weight_micros(self) -> u64 {
        self.satisfied_weight_micros
    }

    #[must_use]
    pub const fn exact_weight_ratio(self) -> (u64, u64) {
        (self.satisfied_weight_micros, self.total_weight_micros)
    }
}

impl fmt::Debug for GovernedRepresentationScoreSubmissionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedRepresentationScoreSubmissionV1")
            .field("artifact_binding_present", &true)
            .field("score_artifact_identity_present", &true)
            .field("representation_submission_binding_present", &true)
            .field("fidelity_policy_binding_present", &true)
            .field("requirement_count", &self.requirement_count)
            .field(
                "satisfied_requirement_count",
                &self.satisfied_requirement_count,
            )
            .field("total_weight_micros", &self.total_weight_micros)
            .field("satisfied_weight_micros", &self.satisfied_weight_micros)
            .finish()
    }
}

/// Governed non-score result for requirements whose non-exact fidelity cannot
/// be decided by the closed static policy.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GovernedNeedsDownstreamVdsV1 {
    artifact_digest: ArtifactDigest,
    artifact_binding: GovernedCaseArtifactBindingV1,
    representation_submission_artifact_digest: ArtifactDigest,
    fidelity_policy_artifact_digest: ArtifactDigest,
    requirement_count: u64,
    unresolved_requirement_count: u64,
}

impl GovernedNeedsDownstreamVdsV1 {
    #[must_use]
    pub const fn artifact_digest(self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn artifact_binding(self) -> GovernedCaseArtifactBindingV1 {
        self.artifact_binding
    }

    #[must_use]
    pub const fn representation_submission_artifact_digest(self) -> ArtifactDigest {
        self.representation_submission_artifact_digest
    }

    #[must_use]
    pub const fn fidelity_policy_artifact_digest(self) -> ArtifactDigest {
        self.fidelity_policy_artifact_digest
    }

    #[must_use]
    pub const fn requirement_count(self) -> u64 {
        self.requirement_count
    }

    #[must_use]
    pub const fn unresolved_requirement_count(self) -> u64 {
        self.unresolved_requirement_count
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        "needs_downstream_vds"
    }
}

impl fmt::Debug for GovernedNeedsDownstreamVdsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedNeedsDownstreamVdsV1")
            .field("code", &self.code())
            .field("artifact_binding_present", &true)
            .field("decision_artifact_identity_present", &true)
            .field("representation_submission_binding_present", &true)
            .field("fidelity_policy_binding_present", &true)
            .field("requirement_count", &self.requirement_count)
            .field(
                "unresolved_requirement_count",
                &self.unresolved_requirement_count,
            )
            .field("contains_score", &false)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum GovernedRepresentationFidelityOutcomeV1 {
    Scored(GovernedRepresentationScoreSubmissionV1),
    NeedsDownstreamVds(GovernedNeedsDownstreamVdsV1),
}

impl GovernedRepresentationFidelityOutcomeV1 {
    pub fn score_submission(
        self,
    ) -> Result<GovernedRepresentationScoreSubmissionV1, RepresentationFidelityErrorV1> {
        match self {
            Self::Scored(score) => Ok(score),
            Self::NeedsDownstreamVds(_) => Err(RepresentationFidelityErrorV1::NeedsDownstreamVds),
        }
    }
}

impl fmt::Debug for GovernedRepresentationFidelityOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scored(score) => formatter
                .debug_struct("GovernedRepresentationFidelityOutcomeV1")
                .field("classification", &"scored")
                .field("score", score)
                .finish(),
            Self::NeedsDownstreamVds(needs_vds) => formatter
                .debug_struct("GovernedRepresentationFidelityOutcomeV1")
                .field("classification", &"needs_downstream_vds")
                .field("decision", needs_vds)
                .finish(),
        }
    }
}

/// Evaluate one frozen public representation only after its exact hidden
/// annotation join and fidelity policy are available.
///
/// Source-exact claims are byte-verified against both the rendered artifact and
/// sealed ledger. Transformed and pattern-only claims never directly satisfy a
/// target: a hidden rule may only reject them or route complete non-exact
/// coverage to downstream VDS. When a rule defers complete non-exact coverage,
/// the whole result is `NeedsDownstreamVds`; no partial/static scalar is
/// emitted.
pub fn evaluate_governed_representation_fidelity_v1(
    artifact_join: GovernedCaseArtifactJoinV1,
    annotation: &EvidentrailBenchAnnotationSpecV1,
    ledger: &EventLedger,
    block_index: Option<&BlockIndex<'_>>,
    submission: &FrozenExternalRepresentationSubmissionV1,
    policy: &GovernedRepresentationFidelityPolicyV1,
) -> Result<GovernedRepresentationFidelityOutcomeV1, RepresentationFidelityErrorV1> {
    let artifact_binding = artifact_join.artifact_binding();
    if submission.public_run_manifest_artifact_digest
        != artifact_join.public_run_manifest_artifact_digest()
    {
        return Err(RepresentationFidelityErrorV1::PublicRunManifestBindingMismatch);
    }
    if annotation.public_case_artifact_digest() != artifact_binding.public_case_artifact_digest()
        || policy.artifact_binding != artifact_binding
    {
        return Err(RepresentationFidelityErrorV1::GovernedArtifactBindingMismatch);
    }
    if submission.public_case_artifact_digest != artifact_binding.public_case_artifact_digest() {
        return Err(RepresentationFidelityErrorV1::PublicSubmissionBindingMismatch);
    }
    if submission.retrieval_id != ledger.retrieval_id() {
        return Err(RepresentationFidelityErrorV1::RetrievalMismatch);
    }
    if let Some(block_index) = block_index {
        if block_index.retrieval_id() != ledger.retrieval_id() {
            return Err(RepresentationFidelityErrorV1::BlockIndexRetrievalMismatch);
        }
    }
    validate_annotation_targets(annotation, ledger, block_index)?;
    validate_submission_accounting(submission, ledger)?;
    let claims = ClaimIndex::try_new(submission, ledger)?;

    let mut requirement_count = 0_u64;
    let mut satisfied_requirement_count = 0_u64;
    let mut unresolved_requirement_count = 0_u64;
    let mut total_weight_micros = 0_u64;
    let mut satisfied_weight_micros = 0_u64;
    for (requirement, rule) in annotation
        .diagnostic_requirements()
        .iter()
        .zip(&policy.rules)
    {
        requirement_count = requirement_count
            .checked_add(1)
            .ok_or(RepresentationFidelityErrorV1::AccountingOverflow)?;
        total_weight_micros = total_weight_micros
            .checked_add(requirement.weight_micros())
            .ok_or(RepresentationFidelityErrorV1::RequirementWeightOverflow)?;
        match requirement_status(requirement, rule, &claims, block_index)? {
            RequirementStatus::Satisfied => {
                satisfied_requirement_count = satisfied_requirement_count
                    .checked_add(1)
                    .ok_or(RepresentationFidelityErrorV1::AccountingOverflow)?;
                satisfied_weight_micros = satisfied_weight_micros
                    .checked_add(requirement.weight_micros())
                    .ok_or(RepresentationFidelityErrorV1::RequirementWeightOverflow)?;
            }
            RequirementStatus::Missed => {}
            RequirementStatus::NeedsDownstreamVds => {
                unresolved_requirement_count = unresolved_requirement_count
                    .checked_add(1)
                    .ok_or(RepresentationFidelityErrorV1::AccountingOverflow)?;
            }
        }
    }

    if unresolved_requirement_count != 0 {
        let artifact_digest = derive_needs_vds_artifact_digest(
            artifact_binding,
            submission.artifact_digest,
            policy.artifact_digest,
            requirement_count,
            unresolved_requirement_count,
        )?;
        return Ok(GovernedRepresentationFidelityOutcomeV1::NeedsDownstreamVds(
            GovernedNeedsDownstreamVdsV1 {
                artifact_digest,
                artifact_binding,
                representation_submission_artifact_digest: submission.artifact_digest,
                fidelity_policy_artifact_digest: policy.artifact_digest,
                requirement_count,
                unresolved_requirement_count,
            },
        ));
    }

    let artifact_digest = derive_score_artifact_digest(
        artifact_binding,
        submission.artifact_digest,
        policy.artifact_digest,
        requirement_count,
        satisfied_requirement_count,
        total_weight_micros,
        satisfied_weight_micros,
    )?;
    Ok(GovernedRepresentationFidelityOutcomeV1::Scored(
        GovernedRepresentationScoreSubmissionV1 {
            artifact_digest,
            artifact_binding,
            representation_submission_artifact_digest: submission.artifact_digest,
            fidelity_policy_artifact_digest: policy.artifact_digest,
            requirement_count,
            satisfied_requirement_count,
            total_weight_micros,
            satisfied_weight_micros,
        },
    ))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TargetStatus {
    Accepted,
    Deferred,
    Missing,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RequirementStatus {
    Satisfied,
    NeedsDownstreamVds,
    Missed,
}

struct ClaimIndex {
    exact: BTreeSet<EventId>,
    transformed: BTreeMap<EventId, ArtifactDigest>,
    patterns: BTreeSet<EventId>,
}

impl ClaimIndex {
    fn try_new(
        submission: &FrozenExternalRepresentationSubmissionV1,
        ledger: &EventLedger,
    ) -> Result<Self, RepresentationFidelityErrorV1> {
        let mut exact = BTreeSet::new();
        let mut transformed = BTreeMap::new();
        let mut patterns = BTreeSet::new();
        let mut bad_exact_count = 0_usize;
        for claim in &submission.claims {
            let event = ledger
                .event(claim.event_id)
                .map_err(|_| RepresentationFidelityErrorV1::UnknownClaimedEvent)?;
            match claim.class {
                EvidenceRepresentationClassV1::SourceExactShownVerbatim => {
                    if derive_source_exact_representation_artifact_digest_v1(event.raw())?
                        != claim.representation_artifact_digest
                    {
                        bad_exact_count = bad_exact_count
                            .checked_add(1)
                            .ok_or(RepresentationFidelityErrorV1::AccountingOverflow)?;
                    }
                    exact.insert(claim.event_id);
                }
                EvidenceRepresentationClassV1::SourceExactReversibleEncoding => {
                    let identity = claim
                        .reversible_encoding
                        .ok_or(RepresentationFidelityErrorV1::UnknownReversibleEncoding)?;
                    validate_reversible_encoding(identity)?;
                    exact.insert(claim.event_id);
                }
                EvidenceRepresentationClassV1::SourceValidatedTransformedSample => {
                    transformed.insert(claim.event_id, claim.representation_artifact_digest);
                }
                EvidenceRepresentationClassV1::PatternOnly => {
                    patterns.insert(claim.event_id);
                }
            }
        }
        if bad_exact_count != 0 {
            return Err(RepresentationFidelityErrorV1::SourceExactDigestMismatch {
                count: bad_exact_count,
            });
        }
        Ok(Self {
            exact,
            transformed,
            patterns,
        })
    }

    fn event_status(&self, event_id: EventId, rule: &RequirementFidelityPolicyV1) -> TargetStatus {
        if self.exact.contains(&event_id) {
            return TargetStatus::Accepted;
        }
        if let Some(artifact_digest) = self.transformed.get(&event_id) {
            if rule.transform_disposition(event_id, *artifact_digest)
                == NonExactFidelityDispositionV1::NeedsDownstreamVds
            {
                return TargetStatus::Deferred;
            }
        }
        if self.patterns.contains(&event_id)
            && rule.pattern_only == NonExactFidelityDispositionV1::NeedsDownstreamVds
        {
            return TargetStatus::Deferred;
        }
        TargetStatus::Missing
    }

    fn block_status(
        &self,
        member_ids: &[EventId],
        rule: &RequirementFidelityPolicyV1,
    ) -> TargetStatus {
        if member_ids
            .iter()
            .all(|event_id| self.exact.contains(event_id))
        {
            return TargetStatus::Accepted;
        }
        let completely_deferred = member_ids
            .iter()
            .all(|event_id| self.event_status(*event_id, rule) != TargetStatus::Missing);
        if completely_deferred {
            TargetStatus::Deferred
        } else {
            TargetStatus::Missing
        }
    }
}

fn requirement_status(
    requirement: &WeightedDiagnosticRequirementV1,
    rule: &RequirementFidelityPolicyV1,
    claims: &ClaimIndex,
    block_index: Option<&BlockIndex<'_>>,
) -> Result<RequirementStatus, RepresentationFidelityErrorV1> {
    let mut has_deferred_alternative = false;
    for alternative in requirement.alternatives() {
        let mut has_deferred_target = false;
        let mut missing = false;
        for target in alternative {
            let status = match target {
                EvidenceTargetV1::Event(event_id) => claims.event_status(*event_id, rule),
                EvidenceTargetV1::Block(block_id) => {
                    let block_index =
                        block_index.ok_or(RepresentationFidelityErrorV1::BlockIndexRequired)?;
                    let block = block_index
                        .block(*block_id)
                        .map_err(|_| RepresentationFidelityErrorV1::UnknownEvidenceBlock)?;
                    claims.block_status(block.member_ids(), rule)
                }
            };
            match status {
                TargetStatus::Accepted => {}
                TargetStatus::Deferred => has_deferred_target = true,
                TargetStatus::Missing => {
                    missing = true;
                    break;
                }
            }
        }
        if !missing && !has_deferred_target {
            return Ok(RequirementStatus::Satisfied);
        }
        if !missing && has_deferred_target {
            has_deferred_alternative = true;
        }
    }
    if has_deferred_alternative {
        Ok(RequirementStatus::NeedsDownstreamVds)
    } else {
        Ok(RequirementStatus::Missed)
    }
}

fn validate_annotation_targets(
    annotation: &EvidentrailBenchAnnotationSpecV1,
    ledger: &EventLedger,
    block_index: Option<&BlockIndex<'_>>,
) -> Result<(), RepresentationFidelityErrorV1> {
    let targets = annotation
        .diagnostic_requirements()
        .iter()
        .flat_map(|requirement| requirement.alternatives().iter().flatten().copied())
        .collect::<BTreeSet<_>>();
    if targets
        .iter()
        .any(|target| matches!(target, EvidenceTargetV1::Block(_)))
        && block_index.is_none()
    {
        return Err(RepresentationFidelityErrorV1::BlockIndexRequired);
    }
    if targets.iter().any(|target| match target {
        EvidenceTargetV1::Event(event_id) => !ledger.contains(*event_id),
        EvidenceTargetV1::Block(_) => false,
    }) {
        return Err(RepresentationFidelityErrorV1::UnknownEvidenceEvent);
    }
    if block_index.is_some_and(|index| {
        targets.iter().any(|target| match target {
            EvidenceTargetV1::Event(_) => false,
            EvidenceTargetV1::Block(block_id) => index.block(*block_id).is_err(),
        })
    }) {
        return Err(RepresentationFidelityErrorV1::UnknownEvidenceBlock);
    }
    Ok(())
}

fn validate_submission_accounting(
    submission: &FrozenExternalRepresentationSubmissionV1,
    ledger: &EventLedger,
) -> Result<(), RepresentationFidelityErrorV1> {
    let mut source_bytes = 0_u64;
    for event_id in &submission.candidate_event_ids {
        let event = ledger
            .event(*event_id)
            .map_err(|_| RepresentationFidelityErrorV1::UnknownClaimedEvent)?;
        source_bytes = source_bytes
            .checked_add(
                u64::try_from(event.raw().len())
                    .map_err(|_| RepresentationFidelityErrorV1::AccountingOverflow)?,
            )
            .ok_or(RepresentationFidelityErrorV1::AccountingOverflow)?;
    }
    let event_count = u64::try_from(submission.candidate_event_ids.len())
        .map_err(|_| RepresentationFidelityErrorV1::AccountingOverflow)?;
    if submission.resources.unique_candidate_event_count() != event_count
        || submission.resources.unique_candidate_source_bytes() != source_bytes
    {
        return Err(RepresentationFidelityErrorV1::CandidateResourceInvariantViolation);
    }
    Ok(())
}

/// Contentless construction and governed-evaluation failures.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RepresentationFidelityErrorV1 {
    UnknownPublicCaseArtifact,
    EmptyMethodIdentity,
    MethodIdentityTooLarge,
    RenderedCandidateTooLarge,
    RenderedCandidateArtifactMismatch,
    EmptyRepresentationClaims,
    TooManyRepresentationClaims,
    DuplicateEventRepresentationClass,
    InvalidRenderedByteRange,
    OverlappingProvenRepresentationRanges,
    UnknownReversibleEncoding,
    MalformedReversibleEncodingContext,
    MalformedReversibleEncoding,
    ReversibleDecodedBytesMismatch,
    ReversibleEncodingDigestMismatch,
    CandidateResourceInvariantViolation,
    CandidateResourceCapExceeded,
    GovernedArtifactBindingMismatch,
    PublicRunManifestBindingMismatch,
    PublicSubmissionBindingMismatch,
    RetrievalMismatch,
    BlockIndexRetrievalMismatch,
    BlockIndexRequired,
    UnknownClaimedEvent,
    UnknownEvidenceEvent,
    UnknownEvidenceBlock,
    SourceExactDigestMismatch { count: usize },
    TooManyPinnedTransforms,
    DuplicatePinnedTransform,
    TooManyFidelityRequirements,
    RequirementPolicyCountMismatch,
    PinnedTransformOutsideRequirement,
    AccountingOverflow,
    RequirementWeightOverflow,
    ArtifactLengthOverflow,
    NeedsDownstreamVds,
}

impl RepresentationFidelityErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnknownPublicCaseArtifact => "EVIDENTRAIL_BENCH_FIDELITY_UNKNOWN_PUBLIC_CASE",
            Self::EmptyMethodIdentity => "EVIDENTRAIL_BENCH_FIDELITY_EMPTY_METHOD_IDENTITY",
            Self::MethodIdentityTooLarge => "EVIDENTRAIL_BENCH_FIDELITY_METHOD_IDENTITY_TOO_LARGE",
            Self::RenderedCandidateTooLarge => {
                "EVIDENTRAIL_BENCH_FIDELITY_RENDERED_CANDIDATE_TOO_LARGE"
            }
            Self::RenderedCandidateArtifactMismatch => {
                "EVIDENTRAIL_BENCH_FIDELITY_RENDERED_CANDIDATE_ARTIFACT_MISMATCH"
            }
            Self::EmptyRepresentationClaims => "EVIDENTRAIL_BENCH_FIDELITY_EMPTY_CLAIMS",
            Self::TooManyRepresentationClaims => "EVIDENTRAIL_BENCH_FIDELITY_TOO_MANY_CLAIMS",
            Self::DuplicateEventRepresentationClass => {
                "EVIDENTRAIL_BENCH_FIDELITY_DUPLICATE_EVENT_REPRESENTATION_CLASS"
            }
            Self::InvalidRenderedByteRange => {
                "EVIDENTRAIL_BENCH_FIDELITY_INVALID_RENDERED_BYTE_RANGE"
            }
            Self::OverlappingProvenRepresentationRanges => {
                "EVIDENTRAIL_BENCH_FIDELITY_OVERLAPPING_PROVEN_REPRESENTATION_RANGES"
            }
            Self::UnknownReversibleEncoding => {
                "EVIDENTRAIL_BENCH_FIDELITY_UNKNOWN_REVERSIBLE_ENCODING"
            }
            Self::MalformedReversibleEncodingContext => {
                "EVIDENTRAIL_BENCH_FIDELITY_MALFORMED_REVERSIBLE_ENCODING_CONTEXT"
            }
            Self::MalformedReversibleEncoding => {
                "EVIDENTRAIL_BENCH_FIDELITY_MALFORMED_REVERSIBLE_ENCODING"
            }
            Self::ReversibleDecodedBytesMismatch => {
                "EVIDENTRAIL_BENCH_FIDELITY_REVERSIBLE_DECODED_BYTES_MISMATCH"
            }
            Self::ReversibleEncodingDigestMismatch => {
                "EVIDENTRAIL_BENCH_FIDELITY_REVERSIBLE_ENCODING_DIGEST_MISMATCH"
            }
            Self::CandidateResourceInvariantViolation => {
                "EVIDENTRAIL_BENCH_FIDELITY_CANDIDATE_RESOURCE_INVARIANT"
            }
            Self::CandidateResourceCapExceeded => {
                "EVIDENTRAIL_BENCH_FIDELITY_CANDIDATE_RESOURCE_CAP_EXCEEDED"
            }
            Self::GovernedArtifactBindingMismatch => {
                "EVIDENTRAIL_BENCH_FIDELITY_GOVERNED_BINDING_MISMATCH"
            }
            Self::PublicRunManifestBindingMismatch => {
                "EVIDENTRAIL_BENCH_FIDELITY_PUBLIC_RUN_MANIFEST_BINDING_MISMATCH"
            }
            Self::PublicSubmissionBindingMismatch => {
                "EVIDENTRAIL_BENCH_FIDELITY_PUBLIC_SUBMISSION_BINDING_MISMATCH"
            }
            Self::RetrievalMismatch => "EVIDENTRAIL_BENCH_FIDELITY_RETRIEVAL_MISMATCH",
            Self::BlockIndexRetrievalMismatch => {
                "EVIDENTRAIL_BENCH_FIDELITY_BLOCK_INDEX_RETRIEVAL_MISMATCH"
            }
            Self::BlockIndexRequired => "EVIDENTRAIL_BENCH_FIDELITY_BLOCK_INDEX_REQUIRED",
            Self::UnknownClaimedEvent => "EVIDENTRAIL_BENCH_FIDELITY_UNKNOWN_CLAIMED_EVENT",
            Self::UnknownEvidenceEvent => "EVIDENTRAIL_BENCH_FIDELITY_UNKNOWN_EVIDENCE_EVENT",
            Self::UnknownEvidenceBlock => "EVIDENTRAIL_BENCH_FIDELITY_UNKNOWN_EVIDENCE_BLOCK",
            Self::SourceExactDigestMismatch { .. } => {
                "EVIDENTRAIL_BENCH_FIDELITY_SOURCE_EXACT_DIGEST_MISMATCH"
            }
            Self::TooManyPinnedTransforms => {
                "EVIDENTRAIL_BENCH_FIDELITY_TOO_MANY_PINNED_TRANSFORMS"
            }
            Self::DuplicatePinnedTransform => {
                "EVIDENTRAIL_BENCH_FIDELITY_DUPLICATE_PINNED_TRANSFORM"
            }
            Self::TooManyFidelityRequirements => "EVIDENTRAIL_BENCH_FIDELITY_TOO_MANY_REQUIREMENTS",
            Self::RequirementPolicyCountMismatch => {
                "EVIDENTRAIL_BENCH_FIDELITY_REQUIREMENT_POLICY_COUNT_MISMATCH"
            }
            Self::PinnedTransformOutsideRequirement => {
                "EVIDENTRAIL_BENCH_FIDELITY_PINNED_TRANSFORM_OUTSIDE_REQUIREMENT"
            }
            Self::AccountingOverflow => "EVIDENTRAIL_BENCH_FIDELITY_ACCOUNTING_OVERFLOW",
            Self::RequirementWeightOverflow => "EVIDENTRAIL_BENCH_FIDELITY_WEIGHT_OVERFLOW",
            Self::ArtifactLengthOverflow => "EVIDENTRAIL_BENCH_FIDELITY_ARTIFACT_LENGTH_OVERFLOW",
            Self::NeedsDownstreamVds => "EVIDENTRAIL_BENCH_FIDELITY_NEEDS_DOWNSTREAM_VDS",
        }
    }
}

impl fmt::Debug for RepresentationFidelityErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("RepresentationFidelityErrorV1");
        debug.field("code", &self.code());
        if let Self::SourceExactDigestMismatch { count } = self {
            debug.field("count", count);
        }
        debug.finish()
    }
}

impl fmt::Display for RepresentationFidelityErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for RepresentationFidelityErrorV1 {}

fn validate_method_identity(method: MethodDescriptor) -> Result<(), RepresentationFidelityErrorV1> {
    if method.name().is_empty() || method.version().is_empty() {
        return Err(RepresentationFidelityErrorV1::EmptyMethodIdentity);
    }
    if method.name().len() > MAX_FIDELITY_METHOD_IDENTITY_BYTES_V1
        || method.version().len() > MAX_FIDELITY_METHOD_IDENTITY_BYTES_V1
    {
        return Err(RepresentationFidelityErrorV1::MethodIdentityTooLarge);
    }
    Ok(())
}

fn class_count(
    claims: &[EvidenceRepresentationClaimV1],
    class: EvidenceRepresentationClassV1,
) -> usize {
    claims.iter().filter(|claim| claim.class == class).count()
}

#[allow(clippy::too_many_arguments)]
fn derive_representation_submission_artifact_digest(
    public_run_manifest_artifact_digest: ArtifactDigest,
    run_identity: BenchmarkRunIdentityV1,
    public_case_artifact_digest: ArtifactDigest,
    method: MethodDescriptor,
    retrieval_id: RetrievalId,
    representation_artifact_digest: ArtifactDigest,
    normalizer_artifact_digest: ArtifactDigest,
    environment: MeasurementEnvironmentV1,
    rendered_candidate: RenderedCandidateArtifactV1,
    resources: CandidateResourceEnvelope,
    claims: &[EvidenceRepresentationClaimV1],
) -> Result<ArtifactDigest, RepresentationFidelityErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, REPRESENTATION_SUBMISSION_DOMAIN_V1)?;
    for digest in [
        public_run_manifest_artifact_digest,
        run_identity.system_artifact_digest(),
        run_identity.build_artifact_digest(),
        run_identity.dataset_artifact_digest(),
        public_case_artifact_digest,
    ] {
        update_field(&mut hasher, digest.as_bytes())?;
    }
    update_u64(&mut hasher, run_identity.seed())?;
    let budget = run_identity.budget();
    for value in [
        budget.unique_candidate_event_count(),
        budget.unique_candidate_source_bytes(),
        budget.canonical_candidate_tokens(),
        budget.wall_time_nanos(),
        budget.peak_memory_bytes(),
    ] {
        update_u64(&mut hasher, value)?;
    }
    update_field(&mut hasher, method.name().as_bytes())?;
    update_field(&mut hasher, method.version().as_bytes())?;
    update_field(&mut hasher, retrieval_id.as_bytes())?;
    update_field(&mut hasher, representation_artifact_digest.as_bytes())?;
    update_field(&mut hasher, normalizer_artifact_digest.as_bytes())?;
    let tokenizer = environment.tokenizer();
    update_field(&mut hasher, tokenizer.artifact_digest().as_bytes())?;
    let renderer = environment.renderer();
    update_field(&mut hasher, renderer.artifact_digest().as_bytes())?;
    update_u64(&mut hasher, renderer.contract_version())?;
    let harness = environment.harness();
    update_field(&mut hasher, harness.artifact_digest().as_bytes())?;
    update_u64(&mut hasher, harness.contract_version())?;
    update_field(&mut hasher, rendered_candidate.artifact_digest().as_bytes())?;
    update_u64(&mut hasher, rendered_candidate.byte_count())?;
    for value in [
        resources.unique_candidate_event_count(),
        resources.unique_candidate_source_bytes(),
        resources.canonical_candidate_tokens(),
        resources.wall_time_nanos(),
        resources.peak_memory_bytes(),
    ] {
        update_u64(&mut hasher, value)?;
    }
    update_usize(&mut hasher, claims.len())?;
    for claim in claims {
        update_field(&mut hasher, claim.event_id.as_bytes())?;
        update_field(&mut hasher, claim.class.code().as_bytes())?;
        update_field(&mut hasher, claim.representation_artifact_digest.as_bytes())?;
        match claim.reversible_encoding {
            Some(identity) => {
                update_u64(&mut hasher, 1)?;
                update_field(&mut hasher, identity.artifact_digest.as_bytes())?;
                update_u64(&mut hasher, identity.contract_version)?;
            }
            None => update_u64(&mut hasher, 0)?,
        }
        match claim.reversible_context_start {
            Some(context_start) => {
                update_u64(&mut hasher, 1)?;
                update_u64(&mut hasher, context_start)?;
            }
            None => update_u64(&mut hasher, 0)?,
        }
        match claim.rendered_byte_range {
            Some((start, end)) => {
                update_u64(&mut hasher, 1)?;
                update_u64(&mut hasher, start)?;
                update_u64(&mut hasher, end)?;
            }
            None => update_u64(&mut hasher, 0)?,
        }
    }
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

fn derive_fidelity_policy_artifact_digest(
    artifact_binding: GovernedCaseArtifactBindingV1,
    rules: &[RequirementFidelityPolicyV1],
) -> Result<ArtifactDigest, RepresentationFidelityErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, FIDELITY_POLICY_DOMAIN_V1)?;
    update_field(
        &mut hasher,
        artifact_binding.public_case_artifact_digest().as_bytes(),
    )?;
    update_field(
        &mut hasher,
        artifact_binding.annotation_artifact_digest().as_bytes(),
    )?;
    update_usize(&mut hasher, rules.len())?;
    for rule in rules {
        update_field(
            &mut hasher,
            rule.expected_transformed_disposition.code().as_bytes(),
        )?;
        update_field(&mut hasher, rule.unmatched_transformed.code().as_bytes())?;
        update_field(&mut hasher, rule.pattern_only.code().as_bytes())?;
        update_usize(&mut hasher, rule.expected_transformed.len())?;
        for expectation in &rule.expected_transformed {
            update_field(&mut hasher, expectation.event_id.as_bytes())?;
            update_field(
                &mut hasher,
                expectation.transformed_artifact_digest.as_bytes(),
            )?;
        }
    }
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

#[allow(clippy::too_many_arguments)]
fn derive_score_artifact_digest(
    artifact_binding: GovernedCaseArtifactBindingV1,
    representation_submission_artifact_digest: ArtifactDigest,
    fidelity_policy_artifact_digest: ArtifactDigest,
    requirement_count: u64,
    satisfied_requirement_count: u64,
    total_weight_micros: u64,
    satisfied_weight_micros: u64,
) -> Result<ArtifactDigest, RepresentationFidelityErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, FIDELITY_SCORE_DOMAIN_V1)?;
    update_field(
        &mut hasher,
        artifact_binding.public_case_artifact_digest().as_bytes(),
    )?;
    update_field(
        &mut hasher,
        artifact_binding.annotation_artifact_digest().as_bytes(),
    )?;
    update_field(
        &mut hasher,
        representation_submission_artifact_digest.as_bytes(),
    )?;
    update_field(&mut hasher, fidelity_policy_artifact_digest.as_bytes())?;
    for value in [
        requirement_count,
        satisfied_requirement_count,
        total_weight_micros,
        satisfied_weight_micros,
    ] {
        update_u64(&mut hasher, value)?;
    }
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

fn derive_needs_vds_artifact_digest(
    artifact_binding: GovernedCaseArtifactBindingV1,
    representation_submission_artifact_digest: ArtifactDigest,
    fidelity_policy_artifact_digest: ArtifactDigest,
    requirement_count: u64,
    unresolved_requirement_count: u64,
) -> Result<ArtifactDigest, RepresentationFidelityErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, NEEDS_VDS_DOMAIN_V1)?;
    update_field(
        &mut hasher,
        artifact_binding.public_case_artifact_digest().as_bytes(),
    )?;
    update_field(
        &mut hasher,
        artifact_binding.annotation_artifact_digest().as_bytes(),
    )?;
    update_field(
        &mut hasher,
        representation_submission_artifact_digest.as_bytes(),
    )?;
    update_field(&mut hasher, fidelity_policy_artifact_digest.as_bytes())?;
    update_u64(&mut hasher, requirement_count)?;
    update_u64(&mut hasher, unresolved_requirement_count)?;
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

fn update_usize(hasher: &mut Sha256, value: usize) -> Result<(), RepresentationFidelityErrorV1> {
    let value =
        u64::try_from(value).map_err(|_| RepresentationFidelityErrorV1::ArtifactLengthOverflow)?;
    update_u64(hasher, value)
}

fn update_u64(hasher: &mut Sha256, value: u64) -> Result<(), RepresentationFidelityErrorV1> {
    update_field(hasher, &value.to_le_bytes())
}

fn update_field(hasher: &mut Sha256, field: &[u8]) -> Result<(), RepresentationFidelityErrorV1> {
    let length = u64::try_from(field.len())
        .map_err(|_| RepresentationFidelityErrorV1::ArtifactLengthOverflow)?;
    hasher.update(length.to_le_bytes());
    hasher.update(field);
    Ok(())
}

fn validate_reversible_encoding(
    identity: ReversibleEncodingIdentityV1,
) -> Result<(), RepresentationFidelityErrorV1> {
    if identity == ascii_byte_escape_v1_identity() {
        Ok(())
    } else {
        Err(RepresentationFidelityErrorV1::UnknownReversibleEncoding)
    }
}

fn verify_ascii_byte_escape_v1(
    encoded: &[u8],
    expected: &[u8],
) -> Result<(), RepresentationFidelityErrorV1> {
    let mut encoded_offset = 0_usize;
    let mut decoded_offset = 0_usize;
    let mut mismatch = false;
    while encoded_offset < encoded.len() {
        let byte = encoded[encoded_offset];
        let (decoded, consumed) = if byte == b'\\' {
            let escape = *encoded
                .get(encoded_offset + 1)
                .ok_or(RepresentationFidelityErrorV1::MalformedReversibleEncoding)?;
            match escape {
                b'\\' => (b'\\', 2),
                b'n' => (b'\n', 2),
                b'r' => (b'\r', 2),
                b't' => (b'\t', 2),
                b'x' => {
                    let high = *encoded
                        .get(encoded_offset + 2)
                        .ok_or(RepresentationFidelityErrorV1::MalformedReversibleEncoding)?;
                    let low = *encoded
                        .get(encoded_offset + 3)
                        .ok_or(RepresentationFidelityErrorV1::MalformedReversibleEncoding)?;
                    let high = lowercase_hex_value(high)
                        .ok_or(RepresentationFidelityErrorV1::MalformedReversibleEncoding)?;
                    let low = lowercase_hex_value(low)
                        .ok_or(RepresentationFidelityErrorV1::MalformedReversibleEncoding)?;
                    let decoded = (high << 4) | low;
                    if matches!(decoded, b'\\' | b'\n' | b'\r' | b'\t' | 0x20..=0x7e) {
                        return Err(RepresentationFidelityErrorV1::MalformedReversibleEncoding);
                    }
                    (decoded, 4)
                }
                _ => return Err(RepresentationFidelityErrorV1::MalformedReversibleEncoding),
            }
        } else if (0x20..=0x7e).contains(&byte) {
            (byte, 1)
        } else {
            return Err(RepresentationFidelityErrorV1::MalformedReversibleEncoding);
        };
        if expected.get(decoded_offset) != Some(&decoded) {
            mismatch = true;
        }
        decoded_offset = decoded_offset
            .checked_add(1)
            .ok_or(RepresentationFidelityErrorV1::AccountingOverflow)?;
        encoded_offset = encoded_offset
            .checked_add(consumed)
            .ok_or(RepresentationFidelityErrorV1::AccountingOverflow)?;
    }
    if mismatch || decoded_offset != expected.len() {
        return Err(RepresentationFidelityErrorV1::ReversibleDecodedBytesMismatch);
    }
    Ok(())
}

const fn lowercase_hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn raw_artifact_digest(bytes: &[u8]) -> ArtifactDigest {
    ArtifactDigest::from_bytes(Sha256::digest(bytes).into())
}
