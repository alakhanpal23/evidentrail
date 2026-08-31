use std::error::Error as StdError;
use std::fmt;

use evidentrail_candidates::{
    CandidateBuildErrorV1, CandidateNeedsMoreReasonV1, CoverageCandidateUniverseV1,
    LexicalCandidateUniverseV1, MandatoryIdentifierReasonV1, ProviderCorrelationUniverseV1,
};
use evidentrail_core::{BlockId, EventId, QuestionDigest, ResultId};
use evidentrail_evidence::{CompiledCostCertificationError, CompiledCostCertificationV1};
use evidentrail_select::{
    PacketConstructionError, PacketIdV1, ProductionFacetV1, SelectionInvariantError,
    SelectionProblemConstructionError, SelectionV1,
};

use crate::proposal::{ProposalUniverseAccountingErrorV1, ProposalUniverseReceiptV1};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CandidateLaneV1 {
    Lexical,
    Coverage,
    Provider,
}

impl CandidateLaneV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Lexical => "lexical",
            Self::Coverage => "coverage",
            Self::Provider => "provider",
        }
    }
}

impl fmt::Debug for CandidateLaneV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CandidateLaneV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LaneUniverseViolationV1 {
    RetrievalMismatch,
    DuplicateBlock,
    UnknownBlock,
    MissingBlock,
}

impl LaneUniverseViolationV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::RetrievalMismatch => "retrieval_mismatch",
            Self::DuplicateBlock => "duplicate_block",
            Self::UnknownBlock => "unknown_block",
            Self::MissingBlock => "missing_block",
        }
    }
}

impl fmt::Debug for LaneUniverseViolationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LaneUniverseViolationV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ThreeLaneCompileErrorV1 {
    CandidateBuild {
        lane: CandidateLaneV1,
        source: CandidateBuildErrorV1,
    },
    LedgerBlockRetrievalMismatch,
    LedgerBlockEventUniverseMismatch,
    LaneUniverse {
        lane: CandidateLaneV1,
        violation: LaneUniverseViolationV1,
    },
    LexicalPacketIdMismatch,
    LexicalMembershipMismatch,
    FacetMaterialCollision,
    UnknownAffinityFacet {
        lane: CandidateLaneV1,
    },
    MandatoryReasonMismatch,
    PacketConstruction(PacketConstructionError),
    ProposalAccounting(ProposalUniverseAccountingErrorV1),
    PreparedBindingMismatch,
    CostCertification(CompiledCostCertificationError),
    SelectionProblem(SelectionProblemConstructionError),
    SelectionInvariant(SelectionInvariantError),
    CertificateVerification(CompiledCostCertificationError),
}

impl ThreeLaneCompileErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::CandidateBuild { .. } => "EVIDENTRAIL_COMPILE_CANDIDATE_BUILD",
            Self::LedgerBlockRetrievalMismatch => {
                "EVIDENTRAIL_COMPILE_LEDGER_BLOCK_RETRIEVAL_MISMATCH"
            }
            Self::LedgerBlockEventUniverseMismatch => {
                "EVIDENTRAIL_COMPILE_LEDGER_BLOCK_EVENT_UNIVERSE_MISMATCH"
            }
            Self::LaneUniverse { .. } => "EVIDENTRAIL_COMPILE_LANE_UNIVERSE",
            Self::LexicalPacketIdMismatch => "EVIDENTRAIL_COMPILE_LEXICAL_PACKET_ID_MISMATCH",
            Self::LexicalMembershipMismatch => "EVIDENTRAIL_COMPILE_LEXICAL_MEMBERSHIP_MISMATCH",
            Self::FacetMaterialCollision => "EVIDENTRAIL_COMPILE_FACET_MATERIAL_COLLISION",
            Self::UnknownAffinityFacet { .. } => "EVIDENTRAIL_COMPILE_UNKNOWN_AFFINITY_FACET",
            Self::MandatoryReasonMismatch => "EVIDENTRAIL_COMPILE_MANDATORY_REASON_MISMATCH",
            Self::PacketConstruction(_) => "EVIDENTRAIL_COMPILE_PACKET_CONSTRUCTION",
            Self::ProposalAccounting(_) => "EVIDENTRAIL_COMPILE_PROPOSAL_ACCOUNTING",
            Self::PreparedBindingMismatch => "EVIDENTRAIL_COMPILE_PREPARED_BINDING_MISMATCH",
            Self::CostCertification(_) => "EVIDENTRAIL_COMPILE_COST_CERTIFICATION",
            Self::SelectionProblem(_) => "EVIDENTRAIL_COMPILE_SELECTION_PROBLEM",
            Self::SelectionInvariant(_) => "EVIDENTRAIL_COMPILE_SELECTION_INVARIANT",
            Self::CertificateVerification(_) => "EVIDENTRAIL_COMPILE_CERTIFICATE_VERIFICATION",
        }
    }

    #[must_use]
    pub const fn lane(self) -> Option<CandidateLaneV1> {
        match self {
            Self::CandidateBuild { lane, .. }
            | Self::LaneUniverse { lane, .. }
            | Self::UnknownAffinityFacet { lane } => Some(lane),
            _ => None,
        }
    }

    #[must_use]
    pub const fn universe_violation(self) -> Option<LaneUniverseViolationV1> {
        match self {
            Self::LaneUniverse { violation, .. } => Some(violation),
            _ => None,
        }
    }
}

impl fmt::Debug for ThreeLaneCompileErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ThreeLaneCompileErrorV1")
            .field("code", &self.code())
            .field("lane", &self.lane())
            .field("universe_violation", &self.universe_violation())
            .finish()
    }
}

impl fmt::Display for ThreeLaneCompileErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ThreeLaneCompileErrorV1 {}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ThreeLaneNeedsMoreV1 {
    CandidateLane {
        lane: CandidateLaneV1,
        reason: CandidateNeedsMoreReasonV1,
    },
    EmptyPrimaryUniverse,
    NoProposalPackets,
    FixedOverheadExceedsTotalBudget,
    MandatoryCostExceedsAvailablePacketBudget,
    NoSelectedPacketFits,
}

impl ThreeLaneNeedsMoreV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::CandidateLane { .. } => "candidate_lane_needs_more",
            Self::EmptyPrimaryUniverse => "empty_primary_universe",
            Self::NoProposalPackets => "no_proposal_packets",
            Self::FixedOverheadExceedsTotalBudget => "fixed_overhead_exceeds_total_budget",
            Self::MandatoryCostExceedsAvailablePacketBudget => {
                "mandatory_cost_exceeds_available_packet_budget"
            }
            Self::NoSelectedPacketFits => "no_selected_packet_fits",
        }
    }

    #[must_use]
    pub const fn lane(self) -> Option<CandidateLaneV1> {
        match self {
            Self::CandidateLane { lane, .. } => Some(lane),
            _ => None,
        }
    }

    #[must_use]
    pub const fn candidate_reason(self) -> Option<CandidateNeedsMoreReasonV1> {
        match self {
            Self::CandidateLane { reason, .. } => Some(reason),
            _ => None,
        }
    }
}

impl fmt::Debug for ThreeLaneNeedsMoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ThreeLaneNeedsMoreV1")
            .field("code", &self.code())
            .field("lane", &self.lane())
            .field("candidate_reason", &self.candidate_reason())
            .finish()
    }
}

/// Borrowed, already-ready lane outputs. Construction itself makes no trust
/// claim; the compiler reconciles every field against the supplied block index.
#[derive(Clone, Copy)]
pub struct ReadyCandidateLanesV1<'a> {
    lexical: &'a LexicalCandidateUniverseV1,
    coverage: &'a CoverageCandidateUniverseV1,
    provider: &'a ProviderCorrelationUniverseV1,
}

impl<'a> ReadyCandidateLanesV1<'a> {
    #[must_use]
    pub const fn new(
        lexical: &'a LexicalCandidateUniverseV1,
        coverage: &'a CoverageCandidateUniverseV1,
        provider: &'a ProviderCorrelationUniverseV1,
    ) -> Self {
        Self {
            lexical,
            coverage,
            provider,
        }
    }

    #[must_use]
    pub const fn lexical(self) -> &'a LexicalCandidateUniverseV1 {
        self.lexical
    }

    #[must_use]
    pub const fn coverage(self) -> &'a CoverageCandidateUniverseV1 {
        self.coverage
    }

    #[must_use]
    pub const fn provider(self) -> &'a ProviderCorrelationUniverseV1 {
        self.provider
    }
}

impl fmt::Debug for ReadyCandidateLanesV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadyCandidateLanesV1")
            .field("lexical", &self.lexical)
            .field("coverage", &self.coverage)
            .field("provider", &self.provider)
            .finish()
    }
}

/// Compiler-only metadata for one canonical primary packet. Exact source order
/// is retained here even though the selector canonicalizes its event set.
#[derive(Clone, PartialEq, Eq)]
pub struct CompiledPacketMetadataV1 {
    block_id: BlockId,
    packet_id: PacketIdV1,
    ordered_event_ids: Vec<EventId>,
    mandatory_reasons: Vec<MandatoryIdentifierReasonV1>,
}

pub(crate) fn find_packet_metadata_v1(
    metadata: &[CompiledPacketMetadataV1],
    packet_id: PacketIdV1,
) -> Option<&CompiledPacketMetadataV1> {
    metadata.iter().find(|entry| entry.packet_id() == packet_id)
}

impl CompiledPacketMetadataV1 {
    pub(crate) fn new(
        block_id: BlockId,
        packet_id: PacketIdV1,
        ordered_event_ids: Vec<EventId>,
        mandatory_reasons: Vec<MandatoryIdentifierReasonV1>,
    ) -> Self {
        Self {
            block_id,
            packet_id,
            ordered_event_ids,
            mandatory_reasons,
        }
    }

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
    pub fn mandatory_reasons(&self) -> &[MandatoryIdentifierReasonV1] {
        &self.mandatory_reasons
    }

    #[must_use]
    pub fn canonical_forcing_facet_id(&self) -> Option<evidentrail_select::FacetIdV1> {
        self.mandatory_reasons
            .first()
            .map(|reason| reason.facet_id())
    }
}

impl fmt::Debug for CompiledPacketMetadataV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledPacketMetadataV1")
            .field("event_count", &self.ordered_event_ids.len())
            .field("mandatory_reason_count", &self.mandatory_reasons.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CertifiedThreeLaneSelectionV1 {
    proposal_receipt: ProposalUniverseReceiptV1,
    result_id: ResultId,
    question_digest: QuestionDigest,
    facets: Vec<ProductionFacetV1>,
    packet_metadata: Vec<CompiledPacketMetadataV1>,
    proposal_packet_ids: Vec<PacketIdV1>,
    selection: SelectionV1,
    certification: CompiledCostCertificationV1,
}

impl CertifiedThreeLaneSelectionV1 {
    pub(crate) fn new(
        proposal_receipt: ProposalUniverseReceiptV1,
        facets: Vec<ProductionFacetV1>,
        packet_metadata: Vec<CompiledPacketMetadataV1>,
        proposal_packet_ids: Vec<PacketIdV1>,
        selection: SelectionV1,
        certification: CompiledCostCertificationV1,
    ) -> Self {
        let result_id = proposal_receipt.input().result_id();
        let question_digest = proposal_receipt.input().question_digest();
        Self {
            proposal_receipt,
            result_id,
            question_digest,
            facets,
            packet_metadata,
            proposal_packet_ids,
            selection,
            certification,
        }
    }

    #[must_use]
    pub const fn proposal_receipt(&self) -> ProposalUniverseReceiptV1 {
        self.proposal_receipt
    }

    #[must_use]
    pub const fn result_id(&self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn question_digest(&self) -> QuestionDigest {
        self.question_digest
    }

    #[must_use]
    pub fn facets(&self) -> &[ProductionFacetV1] {
        &self.facets
    }

    #[must_use]
    pub fn packet_metadata(&self) -> &[CompiledPacketMetadataV1] {
        &self.packet_metadata
    }

    /// Canonical primary packet IDs that received at least one explicit
    /// positive affinity and therefore entered the selector proposal set.
    /// The cost certificate covers exactly this proposal set;
    /// [`Self::packet_metadata`] and receipt accounting remain exhaustive over
    /// all primary blocks, including retained-raw nonproposals.
    #[must_use]
    pub fn proposal_packet_ids(&self) -> &[PacketIdV1] {
        &self.proposal_packet_ids
    }

    /// Resolve one exact positive-affinity proposal ID to its exhaustive
    /// canonical block metadata and member order.
    #[must_use]
    pub fn proposal_metadata(&self, packet_id: PacketIdV1) -> Option<&CompiledPacketMetadataV1> {
        if self.proposal_packet_ids.binary_search(&packet_id).is_err() {
            return None;
        }
        find_packet_metadata_v1(&self.packet_metadata, packet_id)
    }

    #[must_use]
    pub const fn selection(&self) -> &SelectionV1 {
        &self.selection
    }

    #[must_use]
    pub const fn certification(&self) -> &CompiledCostCertificationV1 {
        &self.certification
    }
}

impl fmt::Debug for CertifiedThreeLaneSelectionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertifiedThreeLaneSelectionV1")
            .field("proposal_receipt", &self.proposal_receipt)
            .field("facet_count", &self.facets.len())
            .field("packet_metadata_count", &self.packet_metadata.len())
            .field("proposal_packet_count", &self.proposal_packet_ids.len())
            .field("selection", &self.selection)
            .field("certification", &self.certification)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use evidentrail_core::BlockId;

    #[test]
    fn proposal_metadata_lookup_does_not_assume_packet_id_sort_order() {
        let lower_block_higher_packet = CompiledPacketMetadataV1::new(
            BlockId::from_bytes([0x10; 32]),
            PacketIdV1::from_bytes([0xf0; 32]),
            Vec::new(),
            Vec::new(),
        );
        let higher_block_lower_packet = CompiledPacketMetadataV1::new(
            BlockId::from_bytes([0x20; 32]),
            PacketIdV1::from_bytes([0x01; 32]),
            Vec::new(),
            Vec::new(),
        );
        let metadata = [lower_block_higher_packet, higher_block_lower_packet];

        assert!(metadata[0].block_id() < metadata[1].block_id());
        assert!(metadata[0].packet_id() > metadata[1].packet_id());
        for expected in &metadata {
            assert_eq!(
                find_packet_metadata_v1(&metadata, expected.packet_id()),
                Some(expected)
            );
        }
        assert_eq!(
            find_packet_metadata_v1(&metadata, PacketIdV1::from_bytes([0x77; 32])),
            None
        );
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ThreeLaneCompileDecisionV1 {
    Selected(Box<CertifiedThreeLaneSelectionV1>),
    NeedsMore(ThreeLaneNeedsMoreV1),
}

impl ThreeLaneCompileDecisionV1 {
    #[must_use]
    pub fn selected(&self) -> Option<&CertifiedThreeLaneSelectionV1> {
        match self {
            Self::Selected(selection) => Some(selection.as_ref()),
            Self::NeedsMore(_) => None,
        }
    }

    #[must_use]
    pub const fn needs_more(&self) -> Option<ThreeLaneNeedsMoreV1> {
        match self {
            Self::Selected(_) => None,
            Self::NeedsMore(reason) => Some(*reason),
        }
    }
}

impl fmt::Debug for ThreeLaneCompileDecisionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selected(selection) => formatter
                .debug_struct("ThreeLaneCompileDecisionV1")
                .field("state", &"selected")
                .field("summary", selection)
                .finish(),
            Self::NeedsMore(reason) => formatter
                .debug_struct("ThreeLaneCompileDecisionV1")
                .field("state", &"needs_more")
                .field("reason", reason)
                .finish(),
        }
    }
}
