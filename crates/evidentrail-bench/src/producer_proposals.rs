use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_core::{
    AcquisitionReceiptId, BlockIndex, EventId, EventLedger, PlanDigest, PlanId, RetrievalId,
    SourceIdentityDigest,
};
use evidentrail_schema::ArtifactDigest;
use evidentrail_schema::bounds::JSON_SAFE_INTEGER_MAX;
use sha2::{Digest as _, Sha256};

use crate::producer_renderer::{
    CanonicalProducerProposalArtifactV1, ProducerProposalRendererIdentityV1,
    canonical_producer_proposal_renderer_v1_identity,
};
use crate::{
    CaseEvaluationError, EvidentrailBenchAnnotationSpecV1, EvidentrailBenchCaseSpecV1,
    ExpectedAcquisitionClassV1, GovernedCaseArtifactBindingV1, GovernedCaseArtifactJoinV1,
    GovernedRequirementRecallV1, MeasurementTrustBoundaryV1,
};

use crate::evaluator::{
    acquisition_class, evaluate_requirements_v1, selected_targets_v1,
    validate_governed_annotation_targets_v1, validate_governed_case_inputs_v1,
};

const FROZEN_PRODUCER_PROPOSAL_UNIVERSE_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/frozen-producer-proposal-universe/v1\0";
const PRODUCER_PROPOSAL_MEASUREMENT_RECEIPT_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/producer-proposal-measurement-receipt/v1\0";

/// Maximum packets in one frozen producer proposal universe.
pub const MAX_PRODUCER_PROPOSAL_PACKETS_V1: usize = 4_096;
/// Maximum exact event members in one producer proposal packet.
pub const MAX_PRODUCER_PROPOSAL_MEMBERS_PER_PACKET_V1: usize = 4_096;
/// Maximum packet-member references across one frozen proposal universe.
pub const MAX_PRODUCER_PROPOSAL_MEMBER_REFERENCES_V1: usize = 65_536;

/// Benchmark-neutral opaque identity for one producer proposal packet.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProducerProposalIdV1([u8; 32]);

impl ProducerProposalIdV1 {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ProducerProposalIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProducerProposalIdV1(<redacted>)")
    }
}

/// One exact, indivisible producer proposal and its non-empty member set.
///
/// Member order is canonicalized by event identity. This type has no label,
/// annotation, relevance, or scoring input.
#[derive(Clone, PartialEq, Eq)]
pub struct ProducerProposalPacketV1 {
    id: ProducerProposalIdV1,
    member_event_ids: Vec<EventId>,
}

impl ProducerProposalPacketV1 {
    pub fn try_new<Members>(
        id: ProducerProposalIdV1,
        member_event_ids: Members,
    ) -> Result<Self, ProducerProposalErrorV1>
    where
        Members: IntoIterator<Item = EventId>,
    {
        let mut members = Vec::new();
        for member in member_event_ids {
            if members.len() >= MAX_PRODUCER_PROPOSAL_MEMBERS_PER_PACKET_V1 {
                return Err(ProducerProposalErrorV1::TooManyMembersPerProposal);
            }
            members.push(member);
        }
        if members.is_empty() {
            return Err(ProducerProposalErrorV1::EmptyProposalMembership);
        }
        members.sort_unstable();
        if members.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ProducerProposalErrorV1::DuplicateProposalMember);
        }
        Ok(Self {
            id,
            member_event_ids: members,
        })
    }

    #[must_use]
    pub const fn id(&self) -> ProducerProposalIdV1 {
        self.id
    }

    #[must_use]
    pub fn member_event_ids(&self) -> &[EventId] {
        &self.member_event_ids
    }
}

impl fmt::Debug for ProducerProposalPacketV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProducerProposalPacketV1")
            .field("member_event_count", &self.member_event_ids.len())
            .finish()
    }
}

/// Exact producer method, configuration, and producer-receipt artifacts.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProducerProposalIdentityV1 {
    method_artifact_digest: ArtifactDigest,
    config_artifact_digest: ArtifactDigest,
    producer_receipt_artifact_digest: ArtifactDigest,
}

impl ProducerProposalIdentityV1 {
    #[must_use]
    pub const fn new(
        method_artifact_digest: ArtifactDigest,
        config_artifact_digest: ArtifactDigest,
        producer_receipt_artifact_digest: ArtifactDigest,
    ) -> Self {
        Self {
            method_artifact_digest,
            config_artifact_digest,
            producer_receipt_artifact_digest,
        }
    }

    #[must_use]
    pub const fn method_artifact_digest(self) -> ArtifactDigest {
        self.method_artifact_digest
    }

    #[must_use]
    pub const fn config_artifact_digest(self) -> ArtifactDigest {
        self.config_artifact_digest
    }

    #[must_use]
    pub const fn producer_receipt_artifact_digest(self) -> ArtifactDigest {
        self.producer_receipt_artifact_digest
    }
}

impl fmt::Debug for ProducerProposalIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProducerProposalIdentityV1")
            .field("method_artifact_present", &true)
            .field("config_artifact_present", &true)
            .field("producer_receipt_artifact_present", &true)
            .finish()
    }
}

/// Domain-separated commitment to the complete label-blind proposal universe.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrozenProducerProposalUniverseDigestV1([u8; 32]);

impl FrozenProducerProposalUniverseDigestV1 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for FrozenProducerProposalUniverseDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenProducerProposalUniverseDigestV1(<redacted>)")
    }
}

/// Inherent, label-free accounting over the exact proposal universe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProducerProposalAccountingV1 {
    proposal_packet_count: u64,
    unique_member_event_count: u64,
    unique_member_source_bytes: u64,
}

/// Exact source-acquisition authority shared by comparable producer results.
///
/// Proposal-universe digests are deliberately excluded because different
/// producer methods must be free to emit different proposal memberships.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProducerProposalAcquisitionBindingV1 {
    retrieval_id: RetrievalId,
    plan_id: PlanId,
    plan_digest: PlanDigest,
    acquisition_receipt_id: AcquisitionReceiptId,
    source_identity_digest: SourceIdentityDigest,
    acquisition_class: ExpectedAcquisitionClassV1,
}

impl ProducerProposalAcquisitionBindingV1 {
    pub(crate) fn from_ledger(ledger: &EventLedger) -> Self {
        Self {
            retrieval_id: ledger.retrieval_id(),
            plan_id: ledger.plan_id(),
            plan_digest: ledger.plan_digest(),
            acquisition_receipt_id: ledger.acquisition_receipt_id(),
            source_identity_digest: ledger.source_identity_digest(),
            acquisition_class: acquisition_class(ledger.fetch_completion().completeness()),
        }
    }

    #[must_use]
    pub const fn retrieval_id(self) -> RetrievalId {
        self.retrieval_id
    }

    #[must_use]
    pub const fn plan_id(self) -> PlanId {
        self.plan_id
    }

    #[must_use]
    pub const fn plan_digest(self) -> PlanDigest {
        self.plan_digest
    }

    #[must_use]
    pub const fn acquisition_receipt_id(self) -> AcquisitionReceiptId {
        self.acquisition_receipt_id
    }

    #[must_use]
    pub const fn source_identity_digest(self) -> SourceIdentityDigest {
        self.source_identity_digest
    }

    #[must_use]
    pub const fn acquisition_class(self) -> ExpectedAcquisitionClassV1 {
        self.acquisition_class
    }
}

impl fmt::Debug for ProducerProposalAcquisitionBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProducerProposalAcquisitionBindingV1")
            .field("retrieval_identity_present", &true)
            .field("plan_identity_present", &true)
            .field("acquisition_receipt_present", &true)
            .field("source_identity_present", &true)
            .field("acquisition_class", &self.acquisition_class)
            .finish()
    }
}

impl ProducerProposalAccountingV1 {
    #[must_use]
    pub const fn proposal_packet_count(self) -> u64 {
        self.proposal_packet_count
    }

    #[must_use]
    pub const fn unique_member_event_count(self) -> u64 {
        self.unique_member_event_count
    }

    #[must_use]
    pub const fn unique_member_source_bytes(self) -> u64 {
        self.unique_member_source_bytes
    }
}

/// Immutable public proposal universe with a label-free construction surface.
///
/// The type boundary accepts no annotation or hidden target. It cannot attest
/// that a caller did not inspect hidden labels before choosing memberships.
/// Governed execution must freeze the universe and producer receipt before it
/// grants annotation access.
#[derive(Clone, PartialEq, Eq)]
pub struct FrozenProducerProposalUniverseV1 {
    digest: FrozenProducerProposalUniverseDigestV1,
    public_case_artifact_digest: ArtifactDigest,
    retrieval_id: RetrievalId,
    plan_id: PlanId,
    plan_digest: PlanDigest,
    acquisition_receipt_id: AcquisitionReceiptId,
    source_identity_digest: SourceIdentityDigest,
    acquisition_class: ExpectedAcquisitionClassV1,
    producer: ProducerProposalIdentityV1,
    proposals: Vec<ProducerProposalPacketV1>,
    accounting: ProducerProposalAccountingV1,
}

impl FrozenProducerProposalUniverseV1 {
    /// Freeze a public, label-free proposal universe against one sealed ledger.
    ///
    /// The constructor deliberately accepts no governed annotation, target,
    /// score, or relevance input. This is a data boundary, not temporal or
    /// process attestation.
    pub fn try_new<Proposals>(
        public_case_artifact_digest: ArtifactDigest,
        public_case: &EvidentrailBenchCaseSpecV1,
        ledger: &EventLedger,
        producer: ProducerProposalIdentityV1,
        proposal_packets: Proposals,
    ) -> Result<Self, ProducerProposalErrorV1>
    where
        Proposals: IntoIterator<Item = ProducerProposalPacketV1>,
    {
        if public_case.plan_digest() != ledger.plan_digest() {
            return Err(ProducerProposalErrorV1::PublicCasePlanMismatch);
        }
        let acquisition_class = acquisition_class(ledger.fetch_completion().completeness());
        if public_case.expected_acquisition_class() != acquisition_class {
            return Err(ProducerProposalErrorV1::PublicCaseAcquisitionMismatch);
        }

        let mut proposals = Vec::new();
        let mut member_reference_count = 0usize;
        for proposal in proposal_packets {
            if proposals.len() >= MAX_PRODUCER_PROPOSAL_PACKETS_V1 {
                return Err(ProducerProposalErrorV1::TooManyProposalPackets);
            }
            member_reference_count = member_reference_count
                .checked_add(proposal.member_event_ids.len())
                .ok_or(ProducerProposalErrorV1::AccountingOverflow)?;
            if member_reference_count > MAX_PRODUCER_PROPOSAL_MEMBER_REFERENCES_V1 {
                return Err(ProducerProposalErrorV1::TooManyProposalMemberReferences);
            }
            proposals.push(proposal);
        }
        proposals.sort_unstable_by_key(ProducerProposalPacketV1::id);
        if proposals.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(ProducerProposalErrorV1::DuplicateProposalId);
        }

        let unique_members = proposal_member_union(&proposals);
        let unknown_member_count = unique_members
            .iter()
            .filter(|event_id| !ledger.contains(**event_id))
            .count();
        if unknown_member_count != 0 {
            return Err(ProducerProposalErrorV1::UnknownProposalMember {
                count: unknown_member_count,
            });
        }
        let accounting = derive_accounting(ledger, proposals.len(), &unique_members)?;
        let digest = derive_frozen_universe_digest(
            public_case_artifact_digest,
            ledger,
            acquisition_class,
            producer,
            &proposals,
            accounting,
        )?;

        Ok(Self {
            digest,
            public_case_artifact_digest,
            retrieval_id: ledger.retrieval_id(),
            plan_id: ledger.plan_id(),
            plan_digest: ledger.plan_digest(),
            acquisition_receipt_id: ledger.acquisition_receipt_id(),
            source_identity_digest: ledger.source_identity_digest(),
            acquisition_class,
            producer,
            proposals,
            accounting,
        })
    }

    #[must_use]
    pub const fn digest(&self) -> FrozenProducerProposalUniverseDigestV1 {
        self.digest
    }

    #[must_use]
    pub const fn public_case_artifact_digest(&self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn retrieval_id(&self) -> RetrievalId {
        self.retrieval_id
    }

    #[must_use]
    pub const fn plan_id(&self) -> PlanId {
        self.plan_id
    }

    #[must_use]
    pub const fn plan_digest(&self) -> PlanDigest {
        self.plan_digest
    }

    #[must_use]
    pub const fn acquisition_receipt_id(&self) -> AcquisitionReceiptId {
        self.acquisition_receipt_id
    }

    #[must_use]
    pub const fn source_identity_digest(&self) -> SourceIdentityDigest {
        self.source_identity_digest
    }

    #[must_use]
    pub const fn acquisition_class(&self) -> ExpectedAcquisitionClassV1 {
        self.acquisition_class
    }

    #[must_use]
    pub const fn producer(&self) -> ProducerProposalIdentityV1 {
        self.producer
    }

    #[must_use]
    pub fn proposals(&self) -> &[ProducerProposalPacketV1] {
        &self.proposals
    }

    #[must_use]
    pub const fn accounting(&self) -> ProducerProposalAccountingV1 {
        self.accounting
    }

    #[must_use]
    pub const fn acquisition_binding(&self) -> ProducerProposalAcquisitionBindingV1 {
        ProducerProposalAcquisitionBindingV1 {
            retrieval_id: self.retrieval_id,
            plan_id: self.plan_id,
            plan_digest: self.plan_digest,
            acquisition_receipt_id: self.acquisition_receipt_id,
            source_identity_digest: self.source_identity_digest,
            acquisition_class: self.acquisition_class,
        }
    }

    /// Explicitly states what this public type boundary does and does not prove.
    #[must_use]
    pub const fn construction_trust_boundary_code(&self) -> &'static str {
        "label_free_data_boundary_process_order_not_attested"
    }
}

impl fmt::Debug for FrozenProducerProposalUniverseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenProducerProposalUniverseV1")
            .field("authority_identities_present", &true)
            .field("producer_artifacts_present", &true)
            .field(
                "construction_trust_boundary",
                &self.construction_trust_boundary_code(),
            )
            .field("proposal_packet_count", &self.proposals.len())
            .field(
                "unique_member_event_count",
                &self.accounting.unique_member_event_count,
            )
            .field("acquisition_class", &self.acquisition_class)
            .finish()
    }
}

/// Versioned environment asserted for tokenization and resource observation.
///
/// The renderer identity is closed to the built-in canonical V1 renderer. The
/// tokenizer and harness artifact identities remain explicit governance inputs;
/// this type does not attest that either artifact ran.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProducerProposalMeasurementEnvironmentV1 {
    renderer: ProducerProposalRendererIdentityV1,
    tokenizer_artifact_digest: ArtifactDigest,
    tokenizer_contract_version: u64,
    measurement_harness_artifact_digest: ArtifactDigest,
    measurement_harness_contract_version: u64,
}

impl ProducerProposalMeasurementEnvironmentV1 {
    pub fn try_new(
        renderer_artifact_digest: ArtifactDigest,
        renderer_contract_version: u64,
        tokenizer_artifact_digest: ArtifactDigest,
        tokenizer_contract_version: u64,
        measurement_harness_artifact_digest: ArtifactDigest,
        measurement_harness_contract_version: u64,
    ) -> Result<Self, ProducerProposalErrorV1> {
        if renderer_contract_version == 0 {
            return Err(ProducerProposalErrorV1::ZeroRendererContractVersion);
        }
        if tokenizer_contract_version == 0 {
            return Err(ProducerProposalErrorV1::ZeroTokenizerContractVersion);
        }
        if measurement_harness_contract_version == 0 {
            return Err(ProducerProposalErrorV1::ZeroMeasurementHarnessContractVersion);
        }
        if [
            renderer_contract_version,
            tokenizer_contract_version,
            measurement_harness_contract_version,
        ]
        .into_iter()
        .any(|version| version > JSON_SAFE_INTEGER_MAX)
        {
            return Err(ProducerProposalErrorV1::MeasurementValueExceedsJsonSafeInteger);
        }
        let renderer = canonical_producer_proposal_renderer_v1_identity();
        if renderer_artifact_digest != renderer.artifact_digest()
            || renderer_contract_version != renderer.contract_version()
        {
            return Err(ProducerProposalErrorV1::UnsupportedCanonicalRenderer);
        }
        Ok(Self {
            renderer,
            tokenizer_artifact_digest,
            tokenizer_contract_version,
            measurement_harness_artifact_digest,
            measurement_harness_contract_version,
        })
    }

    #[must_use]
    pub const fn contract_version(self) -> u64 {
        1
    }

    #[must_use]
    pub const fn renderer(self) -> ProducerProposalRendererIdentityV1 {
        self.renderer
    }

    #[must_use]
    pub const fn tokenizer_artifact_digest(self) -> ArtifactDigest {
        self.tokenizer_artifact_digest
    }

    #[must_use]
    pub const fn tokenizer_contract_version(self) -> u64 {
        self.tokenizer_contract_version
    }

    #[must_use]
    pub const fn measurement_harness_artifact_digest(self) -> ArtifactDigest {
        self.measurement_harness_artifact_digest
    }

    #[must_use]
    pub const fn measurement_harness_contract_version(self) -> u64 {
        self.measurement_harness_contract_version
    }
}

impl fmt::Debug for ProducerProposalMeasurementEnvironmentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProducerProposalMeasurementEnvironmentV1")
            .field("contract_version", &self.contract_version())
            .field("renderer", &self.renderer)
            .field("tokenizer_artifact_present", &true)
            .field(
                "tokenizer_contract_version",
                &self.tokenizer_contract_version,
            )
            .field("measurement_harness_artifact_present", &true)
            .field(
                "measurement_harness_contract_version",
                &self.measurement_harness_contract_version,
            )
            .finish()
    }
}

/// Derived identity of the exact canonical artifact consumed by measurement.
///
/// No public arbitrary constructor exists: values can only be derived from the
/// closed canonical renderer's raw-content artifact.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RenderedProducerProposalArtifactV1 {
    artifact_digest: ArtifactDigest,
    byte_count: u64,
}

impl RenderedProducerProposalArtifactV1 {
    fn from_canonical(artifact: &CanonicalProducerProposalArtifactV1) -> Self {
        Self {
            artifact_digest: artifact.artifact_digest(),
            byte_count: artifact.byte_count(),
        }
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

impl fmt::Debug for RenderedProducerProposalArtifactV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedProducerProposalArtifactV1")
            .field("artifact_identity_present", &true)
            .field("byte_count", &self.byte_count)
            .finish()
    }
}

/// Externally observed proposal-render resources. Wall time and peak RSS are
/// mandatory and strictly positive; no absent observation becomes zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeasuredProducerProposalResourcesV1 {
    canonical_proposal_render_tokens: u64,
    wall_time_nanos: u64,
    peak_rss_bytes: u64,
}

impl MeasuredProducerProposalResourcesV1 {
    pub fn try_new(
        canonical_proposal_render_tokens: u64,
        wall_time_nanos: Option<u64>,
        peak_rss_bytes: Option<u64>,
    ) -> Result<Self, ProducerProposalErrorV1> {
        let wall_time_nanos =
            wall_time_nanos.ok_or(ProducerProposalErrorV1::MissingWallTimeMeasurement)?;
        let peak_rss_bytes =
            peak_rss_bytes.ok_or(ProducerProposalErrorV1::MissingPeakRssMeasurement)?;
        if wall_time_nanos == 0 {
            return Err(ProducerProposalErrorV1::ZeroWallTimeMeasurement);
        }
        if peak_rss_bytes == 0 {
            return Err(ProducerProposalErrorV1::ZeroPeakRssMeasurement);
        }
        if [
            canonical_proposal_render_tokens,
            wall_time_nanos,
            peak_rss_bytes,
        ]
        .into_iter()
        .any(|value| value > JSON_SAFE_INTEGER_MAX)
        {
            return Err(ProducerProposalErrorV1::MeasurementValueExceedsJsonSafeInteger);
        }
        Ok(Self {
            canonical_proposal_render_tokens,
            wall_time_nanos,
            peak_rss_bytes,
        })
    }

    #[must_use]
    pub const fn canonical_proposal_render_tokens(self) -> u64 {
        self.canonical_proposal_render_tokens
    }

    #[must_use]
    pub const fn wall_time_nanos(self) -> u64 {
        self.wall_time_nanos
    }

    #[must_use]
    pub const fn peak_rss_bytes(self) -> u64 {
        self.peak_rss_bytes
    }
}

/// Self-asserted measurement binding for one exact frozen proposal universe.
///
/// Equality and digest checks provide reproducibility binding only. They are
/// not remote attestation, a trusted timestamp, or proof that observations are
/// independently correct.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProducerProposalMeasurementReceiptV1 {
    digest: ArtifactDigest,
    universe_digest: FrozenProducerProposalUniverseDigestV1,
    public_case_artifact_digest: ArtifactDigest,
    retrieval_id: RetrievalId,
    plan_id: PlanId,
    plan_digest: PlanDigest,
    acquisition_receipt_id: AcquisitionReceiptId,
    producer: ProducerProposalIdentityV1,
    environment: ProducerProposalMeasurementEnvironmentV1,
    rendered_artifact: RenderedProducerProposalArtifactV1,
    measured: MeasuredProducerProposalResourcesV1,
}

impl ProducerProposalMeasurementReceiptV1 {
    pub fn try_new_self_asserted(
        universe: &FrozenProducerProposalUniverseV1,
        canonical_artifact: CanonicalProducerProposalArtifactV1,
        environment: ProducerProposalMeasurementEnvironmentV1,
        measured: MeasuredProducerProposalResourcesV1,
    ) -> Result<Self, ProducerProposalErrorV1> {
        Self::try_new_self_asserted_borrowed(universe, &canonical_artifact, environment, measured)
    }

    /// Construct a receipt without consuming the exact raw-content render.
    /// This supports immutable public benchmark packages that retain the
    /// canonical artifact alongside its self-asserted measurement receipt.
    pub fn try_new_self_asserted_borrowed(
        universe: &FrozenProducerProposalUniverseV1,
        canonical_artifact: &CanonicalProducerProposalArtifactV1,
        environment: ProducerProposalMeasurementEnvironmentV1,
        measured: MeasuredProducerProposalResourcesV1,
    ) -> Result<Self, ProducerProposalErrorV1> {
        if !canonical_artifact.has_valid_integrity() {
            return Err(ProducerProposalErrorV1::CanonicalRenderArtifactIntegrityMismatch);
        }
        if canonical_artifact.acquisition_binding() != universe.acquisition_binding() {
            return Err(ProducerProposalErrorV1::CanonicalRenderAcquisitionMismatch);
        }
        if canonical_artifact.universe_digest() != universe.digest {
            return Err(ProducerProposalErrorV1::CanonicalRenderUniverseMismatch);
        }
        if canonical_artifact.renderer() != environment.renderer {
            return Err(ProducerProposalErrorV1::UnsupportedCanonicalRenderer);
        }
        let rendered_artifact =
            RenderedProducerProposalArtifactV1::from_canonical(canonical_artifact);
        let digest =
            derive_measurement_receipt_digest(universe, environment, rendered_artifact, measured);
        Ok(Self {
            digest,
            universe_digest: universe.digest,
            public_case_artifact_digest: universe.public_case_artifact_digest,
            retrieval_id: universe.retrieval_id,
            plan_id: universe.plan_id,
            plan_digest: universe.plan_digest,
            acquisition_receipt_id: universe.acquisition_receipt_id,
            producer: universe.producer,
            environment,
            rendered_artifact,
            measured,
        })
    }

    #[must_use]
    pub const fn digest(self) -> ArtifactDigest {
        self.digest
    }

    #[must_use]
    pub const fn universe_digest(self) -> FrozenProducerProposalUniverseDigestV1 {
        self.universe_digest
    }

    #[must_use]
    pub const fn public_case_artifact_digest(self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn producer(self) -> ProducerProposalIdentityV1 {
        self.producer
    }

    #[must_use]
    pub const fn environment(self) -> ProducerProposalMeasurementEnvironmentV1 {
        self.environment
    }

    #[must_use]
    pub const fn rendered_artifact(self) -> RenderedProducerProposalArtifactV1 {
        self.rendered_artifact
    }

    #[must_use]
    pub const fn measured(self) -> MeasuredProducerProposalResourcesV1 {
        self.measured
    }

    #[must_use]
    pub const fn trust_boundary_code(self) -> &'static str {
        "self_asserted_reproducibility_input_not_attested"
    }

    pub(crate) fn matches(&self, universe: &FrozenProducerProposalUniverseV1) -> bool {
        self.universe_digest == universe.digest
            && self.public_case_artifact_digest == universe.public_case_artifact_digest
            && self.retrieval_id == universe.retrieval_id
            && self.plan_id == universe.plan_id
            && self.plan_digest == universe.plan_digest
            && self.acquisition_receipt_id == universe.acquisition_receipt_id
            && self.producer == universe.producer
            && self.digest
                == derive_measurement_receipt_digest(
                    universe,
                    self.environment,
                    self.rendered_artifact,
                    self.measured,
                )
    }
}

impl fmt::Debug for ProducerProposalMeasurementReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProducerProposalMeasurementReceiptV1")
            .field("universe_binding_present", &true)
            .field("case_plan_acquisition_bindings_present", &true)
            .field("producer_binding_present", &true)
            .field("measurement_environment", &self.environment)
            .field("rendered_artifact", &self.rendered_artifact)
            .field("measurement_dimension_count", &3)
            .field("trust_boundary", &self.trust_boundary_code())
            .finish()
    }
}

/// Exact producer-proposal resource surface. Unique member-event count is
/// explicit accounting; the remaining five values are Protocol K cap axes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProducerProposalResourceEnvelopeV1 {
    proposal_packet_count: u64,
    unique_member_event_count: u64,
    unique_member_source_bytes: u64,
    canonical_proposal_render_tokens: u64,
    wall_time_nanos: u64,
    peak_rss_bytes: u64,
}

impl ProducerProposalResourceEnvelopeV1 {
    #[must_use]
    pub const fn proposal_packet_count(self) -> u64 {
        self.proposal_packet_count
    }

    #[must_use]
    pub const fn unique_member_event_count(self) -> u64 {
        self.unique_member_event_count
    }

    #[must_use]
    pub const fn unique_member_source_bytes(self) -> u64 {
        self.unique_member_source_bytes
    }

    #[must_use]
    pub const fn canonical_proposal_render_tokens(self) -> u64 {
        self.canonical_proposal_render_tokens
    }

    #[must_use]
    pub const fn wall_time_nanos(self) -> u64 {
        self.wall_time_nanos
    }

    #[must_use]
    pub const fn peak_rss_bytes(self) -> u64 {
        self.peak_rss_bytes
    }
}

/// One explicit producer-proposal resource-cap dimension.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProducerProposalResourceDimensionV1 {
    ProposalPacketCount,
    UniqueMemberSourceBytes,
    CanonicalProposalRenderTokens,
    WallTimeNanos,
    PeakRssBytes,
}

impl ProducerProposalResourceDimensionV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ProposalPacketCount => "proposal_packet_count",
            Self::UniqueMemberSourceBytes => "unique_member_source_bytes",
            Self::CanonicalProposalRenderTokens => "canonical_proposal_render_tokens",
            Self::WallTimeNanos => "wall_time_nanos",
            Self::PeakRssBytes => "peak_rss_bytes",
        }
    }
}

impl fmt::Debug for ProducerProposalResourceDimensionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProducerProposalResourceDimensionV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Inclusive maxima for the five Protocol K producer-proposal dimensions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProducerProposalResourceCapV1 {
    proposal_packet_count: u64,
    unique_member_source_bytes: u64,
    canonical_proposal_render_tokens: u64,
    wall_time_nanos: u64,
    peak_rss_bytes: u64,
}

impl ProducerProposalResourceCapV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        proposal_packet_count: u64,
        unique_member_source_bytes: u64,
        canonical_proposal_render_tokens: u64,
        wall_time_nanos: u64,
        peak_rss_bytes: u64,
    ) -> Result<Self, ProducerProposalErrorV1> {
        if [
            proposal_packet_count,
            unique_member_source_bytes,
            canonical_proposal_render_tokens,
            wall_time_nanos,
            peak_rss_bytes,
        ]
        .into_iter()
        .any(|value| value > JSON_SAFE_INTEGER_MAX)
        {
            return Err(ProducerProposalErrorV1::ResourceCapExceedsJsonSafeInteger);
        }
        Ok(Self {
            proposal_packet_count,
            unique_member_source_bytes,
            canonical_proposal_render_tokens,
            wall_time_nanos,
            peak_rss_bytes,
        })
    }

    #[must_use]
    pub const fn proposal_packet_count(self) -> u64 {
        self.proposal_packet_count
    }

    #[must_use]
    pub const fn unique_member_source_bytes(self) -> u64 {
        self.unique_member_source_bytes
    }

    #[must_use]
    pub const fn canonical_proposal_render_tokens(self) -> u64 {
        self.canonical_proposal_render_tokens
    }

    #[must_use]
    pub const fn wall_time_nanos(self) -> u64 {
        self.wall_time_nanos
    }

    #[must_use]
    pub const fn peak_rss_bytes(self) -> u64 {
        self.peak_rss_bytes
    }

    /// Preserve every exceeded dimension in fixed resource-surface order.
    pub fn check(
        self,
        resources: ProducerProposalResourceEnvelopeV1,
    ) -> Result<(), ProducerProposalCapViolationsV1> {
        let mut dimensions = Vec::new();
        if resources.proposal_packet_count > self.proposal_packet_count {
            dimensions.push(ProducerProposalResourceDimensionV1::ProposalPacketCount);
        }
        if resources.unique_member_source_bytes > self.unique_member_source_bytes {
            dimensions.push(ProducerProposalResourceDimensionV1::UniqueMemberSourceBytes);
        }
        if resources.canonical_proposal_render_tokens > self.canonical_proposal_render_tokens {
            dimensions.push(ProducerProposalResourceDimensionV1::CanonicalProposalRenderTokens);
        }
        if resources.wall_time_nanos > self.wall_time_nanos {
            dimensions.push(ProducerProposalResourceDimensionV1::WallTimeNanos);
        }
        if resources.peak_rss_bytes > self.peak_rss_bytes {
            dimensions.push(ProducerProposalResourceDimensionV1::PeakRssBytes);
        }
        if dimensions.is_empty() {
            Ok(())
        } else {
            Err(ProducerProposalCapViolationsV1 { dimensions })
        }
    }
}

/// Non-empty, non-scalarized set of producer-proposal cap violations.
#[derive(Clone, PartialEq, Eq)]
pub struct ProducerProposalCapViolationsV1 {
    dimensions: Vec<ProducerProposalResourceDimensionV1>,
}

impl ProducerProposalCapViolationsV1 {
    #[must_use]
    pub fn dimensions(&self) -> &[ProducerProposalResourceDimensionV1] {
        &self.dimensions
    }

    #[must_use]
    pub fn contains(&self, dimension: ProducerProposalResourceDimensionV1) -> bool {
        self.dimensions.contains(&dimension)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.dimensions.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        "EVIDENTRAIL_BENCH_PRODUCER_PROPOSAL_RESOURCE_CAP_VIOLATED"
    }
}

impl fmt::Debug for ProducerProposalCapViolationsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dimensions = self
            .dimensions
            .iter()
            .map(|dimension| dimension.code())
            .collect::<Vec<_>>();
        formatter
            .debug_struct("ProducerProposalCapViolationsV1")
            .field("dimension_codes", &dimensions)
            .finish()
    }
}

impl fmt::Display for ProducerProposalCapViolationsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ProducerProposalCapViolationsV1 {}

/// Governed exact pre-ranking recall plus its unsquashed resource surface.
///
/// The proposal and recall joins are governed. The render/token/time/RSS
/// values remain self-asserted reproducibility inputs until a separate
/// governed rerun verifies them.
#[derive(Clone, PartialEq, Eq)]
pub struct GovernedProducerProposalEvaluationV1 {
    artifact_binding: GovernedCaseArtifactBindingV1,
    acquisition_binding: ProducerProposalAcquisitionBindingV1,
    universe_digest: FrozenProducerProposalUniverseDigestV1,
    producer: ProducerProposalIdentityV1,
    measurement_receipt_digest: ArtifactDigest,
    measurement_environment: ProducerProposalMeasurementEnvironmentV1,
    measurement_trust_boundary: MeasurementTrustBoundaryV1,
    resource_cap: ProducerProposalResourceCapV1,
    resources: ProducerProposalResourceEnvelopeV1,
    cap_violations: Option<ProducerProposalCapViolationsV1>,
    recall: GovernedRequirementRecallV1,
}

impl GovernedProducerProposalEvaluationV1 {
    #[must_use]
    pub const fn artifact_binding(&self) -> GovernedCaseArtifactBindingV1 {
        self.artifact_binding
    }

    #[must_use]
    pub const fn acquisition_binding(&self) -> ProducerProposalAcquisitionBindingV1 {
        self.acquisition_binding
    }

    #[must_use]
    pub const fn universe_digest(&self) -> FrozenProducerProposalUniverseDigestV1 {
        self.universe_digest
    }

    #[must_use]
    pub const fn producer(&self) -> ProducerProposalIdentityV1 {
        self.producer
    }

    #[must_use]
    pub const fn measurement_receipt_digest(&self) -> ArtifactDigest {
        self.measurement_receipt_digest
    }

    #[must_use]
    pub const fn measurement_environment(&self) -> ProducerProposalMeasurementEnvironmentV1 {
        self.measurement_environment
    }

    /// Trust class of every externally measured resource in this result.
    ///
    /// V1 never promotes a self-asserted receipt into a verified cost claim.
    #[must_use]
    pub const fn measurement_trust_boundary(&self) -> MeasurementTrustBoundaryV1 {
        self.measurement_trust_boundary
    }

    /// Exact five-axis Protocol K cap used to classify this evaluation.
    #[must_use]
    pub const fn resource_cap(&self) -> ProducerProposalResourceCapV1 {
        self.resource_cap
    }

    #[must_use]
    pub const fn resources(&self) -> ProducerProposalResourceEnvelopeV1 {
        self.resources
    }

    #[must_use]
    pub fn cap_violations(&self) -> Option<&ProducerProposalCapViolationsV1> {
        self.cap_violations.as_ref()
    }

    #[must_use]
    pub const fn recall(&self) -> GovernedRequirementRecallV1 {
        self.recall
    }
}

impl fmt::Debug for GovernedProducerProposalEvaluationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedProducerProposalEvaluationV1")
            .field("artifact_binding", &self.artifact_binding)
            .field("acquisition_binding", &self.acquisition_binding)
            .field("producer_identity_present", &true)
            .field("measurement_binding_present", &true)
            .field("measurement_environment", &self.measurement_environment)
            .field(
                "measurement_trust_boundary",
                &self.measurement_trust_boundary,
            )
            .field("resource_cap", &self.resource_cap)
            .field("resources", &self.resources)
            .field("cap_violations", &self.cap_violations)
            .field("recall", &self.recall)
            .finish()
    }
}

/// Join one frozen label-blind proposal universe to governed requirements.
///
/// The unique member union is the recall surface. A block target receives
/// credit only when every member of that reconciled block is in the union.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_governed_producer_proposals_v1(
    artifact_join: GovernedCaseArtifactJoinV1,
    public_case: &EvidentrailBenchCaseSpecV1,
    annotation: &EvidentrailBenchAnnotationSpecV1,
    ledger: &EventLedger,
    block_index: &BlockIndex<'_>,
    universe: &FrozenProducerProposalUniverseV1,
    measurement: ProducerProposalMeasurementReceiptV1,
    cap: ProducerProposalResourceCapV1,
) -> Result<GovernedProducerProposalEvaluationV1, ProducerProposalErrorV1> {
    let artifact_binding = validate_governed_case_inputs_v1(
        artifact_join,
        public_case,
        annotation,
        ledger,
        Some(block_index),
    )
    .map_err(map_case_evaluation_error)?;
    if artifact_binding.public_case_artifact_digest() != universe.public_case_artifact_digest {
        return Err(ProducerProposalErrorV1::PublicCaseArtifactBindingMismatch);
    }
    let ledger_acquisition_class = acquisition_class(ledger.fetch_completion().completeness());
    if universe.acquisition_class != ledger_acquisition_class {
        return Err(ProducerProposalErrorV1::PublicCaseAcquisitionMismatch);
    }
    if universe.retrieval_id != ledger.retrieval_id() {
        return Err(ProducerProposalErrorV1::RetrievalMismatch);
    }
    if universe.plan_id != ledger.plan_id() || universe.plan_digest != ledger.plan_digest() {
        return Err(ProducerProposalErrorV1::PlanIdentityMismatch);
    }
    if universe.source_identity_digest != ledger.source_identity_digest() {
        return Err(ProducerProposalErrorV1::SourceIdentityMismatch);
    }
    if universe.acquisition_receipt_id != ledger.acquisition_receipt_id() {
        return Err(ProducerProposalErrorV1::AcquisitionReceiptMismatch);
    }
    if !measurement.matches(universe) {
        return Err(ProducerProposalErrorV1::MeasurementBindingMismatch);
    }
    validate_block_universe(ledger, block_index)?;

    let unique_members = proposal_member_union(&universe.proposals);
    let accounting = derive_accounting(ledger, universe.proposals.len(), &unique_members)?;
    if accounting != universe.accounting {
        return Err(ProducerProposalErrorV1::ProposalAccountingMismatch);
    }
    validate_governed_annotation_targets_v1(annotation, ledger, Some(block_index))
        .map_err(map_case_evaluation_error)?;
    let covered_targets = selected_targets_v1(Some(block_index), &unique_members);
    let recall = evaluate_requirements_v1(annotation, &covered_targets)
        .map_err(map_case_evaluation_error)?;
    let measured = measurement.measured;
    let resources = ProducerProposalResourceEnvelopeV1 {
        proposal_packet_count: accounting.proposal_packet_count,
        unique_member_event_count: accounting.unique_member_event_count,
        unique_member_source_bytes: accounting.unique_member_source_bytes,
        canonical_proposal_render_tokens: measured.canonical_proposal_render_tokens,
        wall_time_nanos: measured.wall_time_nanos,
        peak_rss_bytes: measured.peak_rss_bytes,
    };
    let cap_violations = cap.check(resources).err();

    Ok(GovernedProducerProposalEvaluationV1 {
        artifact_binding,
        acquisition_binding: universe.acquisition_binding(),
        universe_digest: universe.digest,
        producer: universe.producer,
        measurement_receipt_digest: measurement.digest,
        measurement_environment: measurement.environment,
        measurement_trust_boundary: MeasurementTrustBoundaryV1::SelfAssertedReproducibilityInput,
        resource_cap: cap,
        resources,
        cap_violations,
        recall,
    })
}

/// Contentless construction, binding, and governed-evaluation failures.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProducerProposalErrorV1 {
    EmptyProposalMembership,
    TooManyMembersPerProposal,
    DuplicateProposalMember,
    TooManyProposalPackets,
    TooManyProposalMemberReferences,
    DuplicateProposalId,
    UnknownProposalMember { count: usize },
    AccountingOverflow,
    AccountingExceedsJsonSafeInteger,
    ProposalAccountingMismatch,
    PublicCaseArtifactBindingMismatch,
    PublicCasePlanMismatch,
    PublicCaseAcquisitionMismatch,
    RetrievalMismatch,
    PlanIdentityMismatch,
    AcquisitionReceiptMismatch,
    SourceIdentityMismatch,
    MeasurementBindingMismatch,
    ZeroRendererContractVersion,
    ZeroTokenizerContractVersion,
    ZeroMeasurementHarnessContractVersion,
    UnsupportedCanonicalRenderer,
    CanonicalRenderArtifactIntegrityMismatch,
    CanonicalRenderAcquisitionMismatch,
    CanonicalRenderUniverseMismatch,
    MissingWallTimeMeasurement,
    ZeroWallTimeMeasurement,
    MissingPeakRssMeasurement,
    ZeroPeakRssMeasurement,
    MeasurementValueExceedsJsonSafeInteger,
    ResourceCapExceedsJsonSafeInteger,
    BlockIndexRetrievalMismatch,
    BlockIndexUniverseMismatch,
    UnknownAnnotationEvent { count: usize },
    UnknownAnnotationBlock { count: usize },
    RequirementWeightOverflow,
    RequirementCountOverflow,
    GovernedCaseValidationInvariant,
}

impl ProducerProposalErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyProposalMembership => "EVIDENTRAIL_BENCH_PROPOSAL_EMPTY_MEMBERSHIP",
            Self::TooManyMembersPerProposal => "EVIDENTRAIL_BENCH_PROPOSAL_MEMBER_CAP",
            Self::DuplicateProposalMember => "EVIDENTRAIL_BENCH_PROPOSAL_DUPLICATE_MEMBER",
            Self::TooManyProposalPackets => "EVIDENTRAIL_BENCH_PROPOSAL_PACKET_CAP",
            Self::TooManyProposalMemberReferences => "EVIDENTRAIL_BENCH_PROPOSAL_MEMBER_REFERENCE_CAP",
            Self::DuplicateProposalId => "EVIDENTRAIL_BENCH_PROPOSAL_DUPLICATE_ID",
            Self::UnknownProposalMember { .. } => "EVIDENTRAIL_BENCH_PROPOSAL_UNKNOWN_MEMBER",
            Self::AccountingOverflow => "EVIDENTRAIL_BENCH_PROPOSAL_ACCOUNTING_OVERFLOW",
            Self::AccountingExceedsJsonSafeInteger => {
                "EVIDENTRAIL_BENCH_PROPOSAL_ACCOUNTING_EXCEEDS_JSON_SAFE_INTEGER"
            }
            Self::ProposalAccountingMismatch => "EVIDENTRAIL_BENCH_PROPOSAL_ACCOUNTING_MISMATCH",
            Self::PublicCaseArtifactBindingMismatch => {
                "EVIDENTRAIL_BENCH_PROPOSAL_PUBLIC_CASE_ARTIFACT_BINDING_MISMATCH"
            }
            Self::PublicCasePlanMismatch => "EVIDENTRAIL_BENCH_PROPOSAL_PUBLIC_CASE_PLAN_MISMATCH",
            Self::PublicCaseAcquisitionMismatch => {
                "EVIDENTRAIL_BENCH_PROPOSAL_PUBLIC_CASE_ACQUISITION_MISMATCH"
            }
            Self::RetrievalMismatch => "EVIDENTRAIL_BENCH_PROPOSAL_RETRIEVAL_MISMATCH",
            Self::PlanIdentityMismatch => "EVIDENTRAIL_BENCH_PROPOSAL_PLAN_IDENTITY_MISMATCH",
            Self::AcquisitionReceiptMismatch => "EVIDENTRAIL_BENCH_PROPOSAL_ACQUISITION_RECEIPT_MISMATCH",
            Self::SourceIdentityMismatch => "EVIDENTRAIL_BENCH_PROPOSAL_SOURCE_IDENTITY_MISMATCH",
            Self::MeasurementBindingMismatch => "EVIDENTRAIL_BENCH_PROPOSAL_MEASUREMENT_BINDING_MISMATCH",
            Self::ZeroRendererContractVersion => {
                "EVIDENTRAIL_BENCH_PROPOSAL_ZERO_RENDERER_CONTRACT_VERSION"
            }
            Self::ZeroTokenizerContractVersion => {
                "EVIDENTRAIL_BENCH_PROPOSAL_ZERO_TOKENIZER_CONTRACT_VERSION"
            }
            Self::ZeroMeasurementHarnessContractVersion => {
                "EVIDENTRAIL_BENCH_PROPOSAL_ZERO_MEASUREMENT_HARNESS_CONTRACT_VERSION"
            }
            Self::UnsupportedCanonicalRenderer => {
                "EVIDENTRAIL_BENCH_PROPOSAL_UNSUPPORTED_CANONICAL_RENDERER"
            }
            Self::CanonicalRenderArtifactIntegrityMismatch => {
                "EVIDENTRAIL_BENCH_PROPOSAL_CANONICAL_RENDER_ARTIFACT_INTEGRITY_MISMATCH"
            }
            Self::CanonicalRenderAcquisitionMismatch => {
                "EVIDENTRAIL_BENCH_PROPOSAL_CANONICAL_RENDER_ACQUISITION_MISMATCH"
            }
            Self::CanonicalRenderUniverseMismatch => {
                "EVIDENTRAIL_BENCH_PROPOSAL_CANONICAL_RENDER_UNIVERSE_MISMATCH"
            }
            Self::MissingWallTimeMeasurement => "EVIDENTRAIL_BENCH_PROPOSAL_MISSING_WALL_TIME",
            Self::ZeroWallTimeMeasurement => "EVIDENTRAIL_BENCH_PROPOSAL_ZERO_WALL_TIME",
            Self::MissingPeakRssMeasurement => "EVIDENTRAIL_BENCH_PROPOSAL_MISSING_PEAK_RSS",
            Self::ZeroPeakRssMeasurement => "EVIDENTRAIL_BENCH_PROPOSAL_ZERO_PEAK_RSS",
            Self::MeasurementValueExceedsJsonSafeInteger => {
                "EVIDENTRAIL_BENCH_PROPOSAL_MEASUREMENT_EXCEEDS_JSON_SAFE_INTEGER"
            }
            Self::ResourceCapExceedsJsonSafeInteger => {
                "EVIDENTRAIL_BENCH_PROPOSAL_RESOURCE_CAP_EXCEEDS_JSON_SAFE_INTEGER"
            }
            Self::BlockIndexRetrievalMismatch => {
                "EVIDENTRAIL_BENCH_PROPOSAL_BLOCK_INDEX_RETRIEVAL_MISMATCH"
            }
            Self::BlockIndexUniverseMismatch => {
                "EVIDENTRAIL_BENCH_PROPOSAL_BLOCK_INDEX_UNIVERSE_MISMATCH"
            }
            Self::UnknownAnnotationEvent { .. } => "EVIDENTRAIL_BENCH_PROPOSAL_UNKNOWN_ANNOTATION_EVENT",
            Self::UnknownAnnotationBlock { .. } => "EVIDENTRAIL_BENCH_PROPOSAL_UNKNOWN_ANNOTATION_BLOCK",
            Self::RequirementWeightOverflow => "EVIDENTRAIL_BENCH_PROPOSAL_REQUIREMENT_WEIGHT_OVERFLOW",
            Self::RequirementCountOverflow => "EVIDENTRAIL_BENCH_PROPOSAL_REQUIREMENT_COUNT_OVERFLOW",
            Self::GovernedCaseValidationInvariant => {
                "EVIDENTRAIL_BENCH_PROPOSAL_GOVERNED_CASE_VALIDATION_INVARIANT"
            }
        }
    }
}

impl fmt::Debug for ProducerProposalErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("ProducerProposalErrorV1");
        debug.field("code", &self.code());
        match self {
            Self::UnknownProposalMember { count }
            | Self::UnknownAnnotationEvent { count }
            | Self::UnknownAnnotationBlock { count } => {
                debug.field("count", count);
            }
            _ => {}
        }
        debug.finish()
    }
}

impl fmt::Display for ProducerProposalErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ProducerProposalErrorV1 {}

fn map_case_evaluation_error(error: CaseEvaluationError) -> ProducerProposalErrorV1 {
    match error {
        CaseEvaluationError::PublicCaseArtifactBindingMismatch => {
            ProducerProposalErrorV1::PublicCaseArtifactBindingMismatch
        }
        CaseEvaluationError::PlanDigestMismatch => ProducerProposalErrorV1::PublicCasePlanMismatch,
        CaseEvaluationError::AcquisitionClassMismatch => {
            ProducerProposalErrorV1::PublicCaseAcquisitionMismatch
        }
        CaseEvaluationError::RetrievalMismatch => ProducerProposalErrorV1::RetrievalMismatch,
        CaseEvaluationError::BlockIndexRetrievalMismatch => {
            ProducerProposalErrorV1::BlockIndexRetrievalMismatch
        }
        CaseEvaluationError::UnknownEvidenceEvent { count } => {
            ProducerProposalErrorV1::UnknownAnnotationEvent { count }
        }
        CaseEvaluationError::UnknownEvidenceBlock { count } => {
            ProducerProposalErrorV1::UnknownAnnotationBlock { count }
        }
        CaseEvaluationError::AccountingValueOverflow => {
            ProducerProposalErrorV1::RequirementCountOverflow
        }
        CaseEvaluationError::RequirementWeightOverflow => {
            ProducerProposalErrorV1::RequirementWeightOverflow
        }
        CaseEvaluationError::BlockIndexRequired
        | CaseEvaluationError::MethodAccountingMismatch { .. }
        | CaseEvaluationError::PresentationReconciliationFailed
        | CaseEvaluationError::PresentationReceiptMismatch => {
            ProducerProposalErrorV1::GovernedCaseValidationInvariant
        }
    }
}

fn proposal_member_union(proposals: &[ProducerProposalPacketV1]) -> BTreeSet<EventId> {
    proposals
        .iter()
        .flat_map(|proposal| proposal.member_event_ids.iter().copied())
        .collect()
}

fn derive_accounting(
    ledger: &EventLedger,
    proposal_count: usize,
    unique_members: &BTreeSet<EventId>,
) -> Result<ProducerProposalAccountingV1, ProducerProposalErrorV1> {
    let proposal_packet_count = checked_json_safe_count(proposal_count)?;
    let unique_member_event_count = checked_json_safe_count(unique_members.len())?;
    let mut unique_member_source_bytes = 0u64;
    for event_id in unique_members {
        let event = ledger
            .event(*event_id)
            .map_err(|_| ProducerProposalErrorV1::UnknownProposalMember { count: 1 })?;
        let event_bytes = u64::try_from(event.raw().len())
            .map_err(|_| ProducerProposalErrorV1::AccountingOverflow)?;
        unique_member_source_bytes = unique_member_source_bytes
            .checked_add(event_bytes)
            .ok_or(ProducerProposalErrorV1::AccountingOverflow)?;
    }
    if unique_member_source_bytes > JSON_SAFE_INTEGER_MAX {
        return Err(ProducerProposalErrorV1::AccountingExceedsJsonSafeInteger);
    }
    Ok(ProducerProposalAccountingV1 {
        proposal_packet_count,
        unique_member_event_count,
        unique_member_source_bytes,
    })
}

fn derive_frozen_universe_digest(
    public_case_artifact_digest: ArtifactDigest,
    ledger: &EventLedger,
    acquisition_class: ExpectedAcquisitionClassV1,
    producer: ProducerProposalIdentityV1,
    proposals: &[ProducerProposalPacketV1],
    accounting: ProducerProposalAccountingV1,
) -> Result<FrozenProducerProposalUniverseDigestV1, ProducerProposalErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, FROZEN_PRODUCER_PROPOSAL_UNIVERSE_DOMAIN_V1);
    update_field(&mut hasher, public_case_artifact_digest.as_bytes());
    update_field(&mut hasher, ledger.retrieval_id().as_bytes());
    update_field(&mut hasher, ledger.plan_id().as_bytes());
    update_field(&mut hasher, ledger.plan_digest().as_bytes());
    update_field(&mut hasher, ledger.acquisition_receipt_id().as_bytes());
    update_field(&mut hasher, ledger.source_identity_digest().as_bytes());
    update_field(&mut hasher, acquisition_class.code().as_bytes());
    update_field(&mut hasher, producer.method_artifact_digest.as_bytes());
    update_field(&mut hasher, producer.config_artifact_digest.as_bytes());
    update_field(
        &mut hasher,
        producer.producer_receipt_artifact_digest.as_bytes(),
    );
    update_u64(&mut hasher, accounting.proposal_packet_count);
    update_u64(&mut hasher, accounting.unique_member_event_count);
    update_u64(&mut hasher, accounting.unique_member_source_bytes);
    update_u64(&mut hasher, checked_json_safe_count(proposals.len())?);
    for proposal in proposals {
        update_field(&mut hasher, proposal.id.as_bytes());
        update_u64(
            &mut hasher,
            checked_json_safe_count(proposal.member_event_ids.len())?,
        );
        for event_id in &proposal.member_event_ids {
            update_field(&mut hasher, event_id.as_bytes());
        }
    }
    Ok(FrozenProducerProposalUniverseDigestV1(
        hasher.finalize().into(),
    ))
}

fn derive_measurement_receipt_digest(
    universe: &FrozenProducerProposalUniverseV1,
    environment: ProducerProposalMeasurementEnvironmentV1,
    rendered_artifact: RenderedProducerProposalArtifactV1,
    measured: MeasuredProducerProposalResourcesV1,
) -> ArtifactDigest {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, PRODUCER_PROPOSAL_MEASUREMENT_RECEIPT_DOMAIN_V1);
    update_field(&mut hasher, universe.digest.as_bytes());
    update_field(&mut hasher, universe.public_case_artifact_digest.as_bytes());
    update_field(&mut hasher, universe.retrieval_id.as_bytes());
    update_field(&mut hasher, universe.plan_id.as_bytes());
    update_field(&mut hasher, universe.plan_digest.as_bytes());
    update_field(&mut hasher, universe.acquisition_receipt_id.as_bytes());
    update_field(
        &mut hasher,
        universe.producer.method_artifact_digest.as_bytes(),
    );
    update_field(
        &mut hasher,
        universe.producer.config_artifact_digest.as_bytes(),
    );
    update_field(
        &mut hasher,
        universe
            .producer
            .producer_receipt_artifact_digest
            .as_bytes(),
    );
    update_u64(&mut hasher, environment.contract_version());
    update_field(
        &mut hasher,
        environment.renderer.artifact_digest().as_bytes(),
    );
    update_u64(&mut hasher, environment.renderer.contract_version());
    update_field(
        &mut hasher,
        environment.tokenizer_artifact_digest.as_bytes(),
    );
    update_u64(&mut hasher, environment.tokenizer_contract_version);
    update_field(
        &mut hasher,
        environment.measurement_harness_artifact_digest.as_bytes(),
    );
    update_u64(
        &mut hasher,
        environment.measurement_harness_contract_version,
    );
    update_field(&mut hasher, rendered_artifact.artifact_digest.as_bytes());
    update_u64(&mut hasher, rendered_artifact.byte_count);
    update_u64(&mut hasher, measured.canonical_proposal_render_tokens);
    update_u64(&mut hasher, measured.wall_time_nanos);
    update_u64(&mut hasher, measured.peak_rss_bytes);
    ArtifactDigest::from_bytes(hasher.finalize().into())
}

fn validate_block_universe(
    ledger: &EventLedger,
    block_index: &BlockIndex<'_>,
) -> Result<(), ProducerProposalErrorV1> {
    if block_index.retrieval_id() != ledger.retrieval_id() {
        return Err(ProducerProposalErrorV1::BlockIndexRetrievalMismatch);
    }
    let ledger_events = ledger
        .events()
        .iter()
        .map(|event| event.id())
        .collect::<BTreeSet<_>>();
    let mut block_events = BTreeSet::new();
    for event_id in block_index
        .blocks()
        .iter()
        .flat_map(|block| block.member_ids().iter().copied())
    {
        if !block_events.insert(event_id) {
            return Err(ProducerProposalErrorV1::BlockIndexUniverseMismatch);
        }
    }
    if block_events != ledger_events {
        return Err(ProducerProposalErrorV1::BlockIndexUniverseMismatch);
    }
    Ok(())
}

fn checked_json_safe_count(value: usize) -> Result<u64, ProducerProposalErrorV1> {
    let value = u64::try_from(value).map_err(|_| ProducerProposalErrorV1::AccountingOverflow)?;
    if value > JSON_SAFE_INTEGER_MAX {
        return Err(ProducerProposalErrorV1::AccountingExceedsJsonSafeInteger);
    }
    Ok(value)
}

fn update_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn update_u64(hasher: &mut Sha256, value: u64) {
    update_field(hasher, &value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_receipt_digest_mutation_fails_its_self_consistency_check() {
        let producer = ProducerProposalIdentityV1::new(
            ArtifactDigest::from_bytes([10; 32]),
            ArtifactDigest::from_bytes([11; 32]),
            ArtifactDigest::from_bytes([12; 32]),
        );
        let universe = FrozenProducerProposalUniverseV1 {
            digest: FrozenProducerProposalUniverseDigestV1([1; 32]),
            public_case_artifact_digest: ArtifactDigest::from_bytes([2; 32]),
            retrieval_id: RetrievalId::from_bytes([3; 32]),
            plan_id: PlanId::from_bytes([4; 32]),
            plan_digest: PlanDigest::from_bytes([5; 32]),
            acquisition_receipt_id: AcquisitionReceiptId::from_bytes([6; 32]),
            source_identity_digest: SourceIdentityDigest::from_bytes([7; 32]),
            acquisition_class: ExpectedAcquisitionClassV1::Complete,
            producer,
            proposals: Vec::new(),
            accounting: ProducerProposalAccountingV1 {
                proposal_packet_count: 0,
                unique_member_event_count: 0,
                unique_member_source_bytes: 0,
            },
        };
        let renderer = canonical_producer_proposal_renderer_v1_identity();
        let environment = ProducerProposalMeasurementEnvironmentV1::try_new(
            renderer.artifact_digest(),
            renderer.contract_version(),
            ArtifactDigest::from_bytes([8; 32]),
            1,
            ArtifactDigest::from_bytes([9; 32]),
            1,
        )
        .unwrap();
        let rendered_artifact = RenderedProducerProposalArtifactV1 {
            artifact_digest: ArtifactDigest::from_bytes([13; 32]),
            byte_count: 14,
        };
        let measured =
            MeasuredProducerProposalResourcesV1::try_new(15, Some(16), Some(17)).unwrap();
        let digest =
            derive_measurement_receipt_digest(&universe, environment, rendered_artifact, measured);
        let mut receipt = ProducerProposalMeasurementReceiptV1 {
            digest,
            universe_digest: universe.digest,
            public_case_artifact_digest: universe.public_case_artifact_digest,
            retrieval_id: universe.retrieval_id,
            plan_id: universe.plan_id,
            plan_digest: universe.plan_digest,
            acquisition_receipt_id: universe.acquisition_receipt_id,
            producer,
            environment,
            rendered_artifact,
            measured,
        };
        assert!(receipt.matches(&universe));
        receipt.digest = ArtifactDigest::from_bytes([0xff; 32]);
        assert!(!receipt.matches(&universe));
        assert!(!format!("{receipt:?}").contains("ffffffff"));
    }
}
