use std::error::Error as StdError;
use std::fmt;

use evidentrail_core::{BlockId, EventId, QuestionDigest, RetrievalId};
use evidentrail_select::{
    FacetAffinityV1, FacetIdV1, PacketIdV1, ProductionFacetKindV1, ProductionFacetV1,
};

use crate::query::ValidatedIdentifierKindV1;

pub const CANDIDATE_POLICY_NAME_V1: &[u8] = b"evidentrail/lexical-primary-block-candidates";
pub const CANDIDATE_POLICY_VERSION_V1: &[u8] = b"1";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CandidateNeedsMoreReasonV1 {
    QuestionBytesCap,
    QueryTokenCountCap,
    QueryTokenBytesCap,
    QueryTermCountCap,
    ValidatedIdentifierCountCap,
    PrimaryBlockCountCap,
    PrimaryBytesScannedCap,
    IdentifierBlockFanoutCap,
    MandatoryBlockCountCap,
    EmittedSignalCountCap,
    CoverageAnalysisTokenCap,
    CoverageSignalObservationCap,
    CoverageSourceLaneCap,
    CoverageFacetOutputCap,
    CoverageAffinityOutputCap,
    CoverageSentinelOutputCap,
    ProviderIdentityBytesScannedCap,
    ProviderAttestationBytesScannedCap,
    ProviderAttestationCountCap,
    ProviderCorrelationKeyCap,
    ProviderGraphNodeCap,
    ProviderGraphEdgeCap,
    ProviderRelationFanoutCap,
    ProviderGraphDegreeCap,
    ProviderFacetOutputCap,
    ProviderAffinityOutputCap,
    ArithmeticCapacity,
}

impl CandidateNeedsMoreReasonV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::QuestionBytesCap => "question_bytes_cap",
            Self::QueryTokenCountCap => "query_token_count_cap",
            Self::QueryTokenBytesCap => "query_token_bytes_cap",
            Self::QueryTermCountCap => "query_term_count_cap",
            Self::ValidatedIdentifierCountCap => "validated_identifier_count_cap",
            Self::PrimaryBlockCountCap => "primary_block_count_cap",
            Self::PrimaryBytesScannedCap => "primary_bytes_scanned_cap",
            Self::IdentifierBlockFanoutCap => "identifier_block_fanout_cap",
            Self::MandatoryBlockCountCap => "mandatory_block_count_cap",
            Self::EmittedSignalCountCap => "emitted_signal_count_cap",
            Self::CoverageAnalysisTokenCap => "coverage_analysis_token_cap",
            Self::CoverageSignalObservationCap => "coverage_signal_observation_cap",
            Self::CoverageSourceLaneCap => "coverage_source_lane_cap",
            Self::CoverageFacetOutputCap => "coverage_facet_output_cap",
            Self::CoverageAffinityOutputCap => "coverage_affinity_output_cap",
            Self::CoverageSentinelOutputCap => "coverage_sentinel_output_cap",
            Self::ProviderIdentityBytesScannedCap => "provider_identity_bytes_scanned_cap",
            Self::ProviderAttestationBytesScannedCap => "provider_attestation_bytes_scanned_cap",
            Self::ProviderAttestationCountCap => "provider_attestation_count_cap",
            Self::ProviderCorrelationKeyCap => "provider_correlation_key_cap",
            Self::ProviderGraphNodeCap => "provider_graph_node_cap",
            Self::ProviderGraphEdgeCap => "provider_graph_edge_cap",
            Self::ProviderRelationFanoutCap => "provider_relation_fanout_cap",
            Self::ProviderGraphDegreeCap => "provider_graph_degree_cap",
            Self::ProviderFacetOutputCap => "provider_facet_output_cap",
            Self::ProviderAffinityOutputCap => "provider_affinity_output_cap",
            Self::ArithmeticCapacity => "arithmetic_capacity",
        }
    }
}

impl fmt::Debug for CandidateNeedsMoreReasonV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CandidateNeedsMoreReasonV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CandidateNeedsMoreV1 {
    reason: CandidateNeedsMoreReasonV1,
}

impl CandidateNeedsMoreV1 {
    #[must_use]
    pub(crate) const fn new(reason: CandidateNeedsMoreReasonV1) -> Self {
        Self { reason }
    }

    #[must_use]
    pub const fn reason(self) -> CandidateNeedsMoreReasonV1 {
        self.reason
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        self.reason.code()
    }
}

impl fmt::Debug for CandidateNeedsMoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CandidateNeedsMoreV1")
            .field("reason", &self.reason)
            .finish()
    }
}

impl fmt::Display for CandidateNeedsMoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for CandidateNeedsMoreV1 {}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CandidateBuildErrorV1 {
    FacetContractViolation,
    FixedPointContractViolation,
    BlockIndexContractViolation,
}

impl CandidateBuildErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::FacetContractViolation => "EVIDENTRAIL_CANDIDATES_FACET_CONTRACT_VIOLATION",
            Self::FixedPointContractViolation => "EVIDENTRAIL_CANDIDATES_FIXED_POINT_CONTRACT_VIOLATION",
            Self::BlockIndexContractViolation => "EVIDENTRAIL_CANDIDATES_BLOCK_INDEX_CONTRACT_VIOLATION",
        }
    }
}

impl fmt::Debug for CandidateBuildErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CandidateBuildErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for CandidateBuildErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for CandidateBuildErrorV1 {}

#[derive(Clone, PartialEq, Eq)]
pub enum CandidateFacetV1 {
    QueryTerm(ProductionFacetV1),
    ValidatedQueryIdentifier {
        facet: ProductionFacetV1,
        identifier_kind: ValidatedIdentifierKindV1,
    },
}

impl CandidateFacetV1 {
    #[must_use]
    pub const fn facet(&self) -> &ProductionFacetV1 {
        match self {
            Self::QueryTerm(facet) | Self::ValidatedQueryIdentifier { facet, .. } => facet,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> ProductionFacetKindV1 {
        self.facet().kind()
    }

    #[must_use]
    pub const fn identifier_kind(&self) -> Option<ValidatedIdentifierKindV1> {
        match self {
            Self::QueryTerm(_) => None,
            Self::ValidatedQueryIdentifier {
                identifier_kind, ..
            } => Some(*identifier_kind),
        }
    }
}

impl fmt::Debug for CandidateFacetV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CandidateFacetV1")
            .field("kind", &self.kind())
            .field("identifier_kind", &self.identifier_kind())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MandatoryIdentifierReasonV1 {
    facet_id: FacetIdV1,
    identifier_kind: ValidatedIdentifierKindV1,
}

impl MandatoryIdentifierReasonV1 {
    #[must_use]
    pub(crate) const fn new(
        facet_id: FacetIdV1,
        identifier_kind: ValidatedIdentifierKindV1,
    ) -> Self {
        Self {
            facet_id,
            identifier_kind,
        }
    }

    #[must_use]
    pub const fn facet_id(self) -> FacetIdV1 {
        self.facet_id
    }

    #[must_use]
    pub const fn identifier_kind(self) -> ValidatedIdentifierKindV1 {
        self.identifier_kind
    }
}

impl fmt::Debug for MandatoryIdentifierReasonV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MandatoryIdentifierReasonV1")
            .field("identifier_kind", &self.identifier_kind)
            .finish()
    }
}

/// One occurrence-aware primary block ready for the later cost compiler.
/// Event membership is copied exactly from the reconciled `BlockIndex`; this
/// type cannot propose an alternate or overlapping packet.
#[derive(Clone, PartialEq, Eq)]
pub struct PrimaryBlockCandidateV1 {
    block_id: BlockId,
    packet_id: PacketIdV1,
    ordered_event_ids: Vec<EventId>,
    affinities: Vec<FacetAffinityV1>,
    mandatory_reasons: Vec<MandatoryIdentifierReasonV1>,
    exact_byte_count: u64,
    document_token_count: u64,
}

impl PrimaryBlockCandidateV1 {
    #[must_use]
    pub const fn block_id(&self) -> BlockId {
        self.block_id
    }

    #[must_use]
    pub const fn packet_id(&self) -> PacketIdV1 {
        self.packet_id
    }

    #[must_use]
    pub fn ordered_event_ids(&self) -> &[EventId] {
        &self.ordered_event_ids
    }

    #[must_use]
    pub fn affinities(&self) -> &[FacetAffinityV1] {
        &self.affinities
    }

    #[must_use]
    pub fn mandatory_reasons(&self) -> &[MandatoryIdentifierReasonV1] {
        &self.mandatory_reasons
    }

    #[must_use]
    pub const fn exact_byte_count(&self) -> u64 {
        self.exact_byte_count
    }

    #[must_use]
    pub const fn document_token_count(&self) -> u64 {
        self.document_token_count
    }

    pub(crate) fn new(
        block_id: BlockId,
        ordered_event_ids: Vec<EventId>,
        affinities: Vec<FacetAffinityV1>,
        mandatory_reasons: Vec<MandatoryIdentifierReasonV1>,
        exact_byte_count: u64,
        document_token_count: u64,
    ) -> Self {
        Self {
            packet_id: PacketIdV1::from_bytes(*block_id.as_bytes()),
            block_id,
            ordered_event_ids,
            affinities,
            mandatory_reasons,
            exact_byte_count,
            document_token_count,
        }
    }
}

impl fmt::Debug for PrimaryBlockCandidateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrimaryBlockCandidateV1")
            .field("event_count", &self.ordered_event_ids.len())
            .field("affinity_count", &self.affinities.len())
            .field("mandatory_reason_count", &self.mandatory_reasons.len())
            .field("exact_byte_count", &self.exact_byte_count)
            .field("document_token_count", &self.document_token_count)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct LexicalCandidateUniverseV1 {
    retrieval_id: RetrievalId,
    question_digest: QuestionDigest,
    facets: Vec<CandidateFacetV1>,
    primary_blocks: Vec<PrimaryBlockCandidateV1>,
    scanned_bytes: u64,
    scanned_tokens: u64,
    emitted_signal_count: usize,
    mandatory_block_count: usize,
}

pub(crate) struct UniverseAccountingV1 {
    pub(crate) scanned_bytes: u64,
    pub(crate) scanned_tokens: u64,
    pub(crate) emitted_signal_count: usize,
    pub(crate) mandatory_block_count: usize,
}

impl LexicalCandidateUniverseV1 {
    pub const CONTRACT_VERSION: u16 = 1;

    #[must_use]
    pub const fn contract_version(&self) -> u16 {
        Self::CONTRACT_VERSION
    }

    #[must_use]
    pub const fn policy_name(&self) -> &'static [u8] {
        CANDIDATE_POLICY_NAME_V1
    }

    #[must_use]
    pub const fn policy_version(&self) -> &'static [u8] {
        CANDIDATE_POLICY_VERSION_V1
    }

    #[must_use]
    pub const fn retrieval_id(&self) -> RetrievalId {
        self.retrieval_id
    }

    #[must_use]
    pub const fn question_digest(&self) -> QuestionDigest {
        self.question_digest
    }

    #[must_use]
    pub fn facets(&self) -> &[CandidateFacetV1] {
        &self.facets
    }

    #[must_use]
    pub fn primary_blocks(&self) -> &[PrimaryBlockCandidateV1] {
        &self.primary_blocks
    }

    #[must_use]
    pub const fn scanned_bytes(&self) -> u64 {
        self.scanned_bytes
    }

    #[must_use]
    pub const fn scanned_tokens(&self) -> u64 {
        self.scanned_tokens
    }

    #[must_use]
    pub const fn emitted_signal_count(&self) -> usize {
        self.emitted_signal_count
    }

    #[must_use]
    pub const fn mandatory_block_count(&self) -> usize {
        self.mandatory_block_count
    }

    pub(crate) fn new(
        retrieval_id: RetrievalId,
        question_digest: QuestionDigest,
        facets: Vec<CandidateFacetV1>,
        primary_blocks: Vec<PrimaryBlockCandidateV1>,
        accounting: UniverseAccountingV1,
    ) -> Self {
        Self {
            retrieval_id,
            question_digest,
            facets,
            primary_blocks,
            scanned_bytes: accounting.scanned_bytes,
            scanned_tokens: accounting.scanned_tokens,
            emitted_signal_count: accounting.emitted_signal_count,
            mandatory_block_count: accounting.mandatory_block_count,
        }
    }
}

impl fmt::Debug for LexicalCandidateUniverseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LexicalCandidateUniverseV1")
            .field("facet_count", &self.facets.len())
            .field("primary_block_count", &self.primary_blocks.len())
            .field("scanned_bytes", &self.scanned_bytes)
            .field("scanned_tokens", &self.scanned_tokens)
            .field("emitted_signal_count", &self.emitted_signal_count)
            .field("mandatory_block_count", &self.mandatory_block_count)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum CandidateGenerationDecisionV1 {
    Ready(LexicalCandidateUniverseV1),
    NeedsMore(CandidateNeedsMoreV1),
}

impl CandidateGenerationDecisionV1 {
    #[must_use]
    pub const fn ready(&self) -> Option<&LexicalCandidateUniverseV1> {
        match self {
            Self::Ready(universe) => Some(universe),
            Self::NeedsMore(_) => None,
        }
    }

    #[must_use]
    pub const fn needs_more(&self) -> Option<CandidateNeedsMoreV1> {
        match self {
            Self::Ready(_) => None,
            Self::NeedsMore(reason) => Some(*reason),
        }
    }
}

impl fmt::Debug for CandidateGenerationDecisionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready(universe) => formatter
                .debug_struct("CandidateGenerationDecisionV1")
                .field("state", &"ready")
                .field("summary", universe)
                .finish(),
            Self::NeedsMore(reason) => formatter
                .debug_struct("CandidateGenerationDecisionV1")
                .field("state", &"needs_more")
                .field("reason", reason)
                .finish(),
        }
    }
}
