use std::fmt;

use evidentrail_core::{BlockId, ProviderAttestedRelationKindV1, RetrievalId};
use evidentrail_select::{FacetAffinityV1, FacetIdV1, ProductionFacetKindV1, ProductionFacetV1};

use crate::types::CandidateNeedsMoreV1;

pub const PROVIDER_CORRELATION_POLICY_NAME_V1: &[u8] = b"evidentrail/provider-attested-correlation";
/// V2 declares half-weight relation endpoints for the selector's closed
/// two-distinct-packet saturation contract.
pub const PROVIDER_CORRELATION_POLICY_VERSION_V1: &[u8] = b"2";

/// Honest V1 schema capability. Generic `NativeMetadata` remains uninterpreted;
/// the only cross-lane vocabulary is the closed, adapter-attested schema.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProviderCorrelationCapabilityV1 {
    NativeEventIdentityAndScopedAdapterAttestations,
}

impl ProviderCorrelationCapabilityV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NativeEventIdentityAndScopedAdapterAttestations => {
                "native_event_identity_and_scoped_adapter_attestations"
            }
        }
    }
}

impl fmt::Debug for ProviderCorrelationCapabilityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderCorrelationCapabilityV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Opaque domain-separated digest of one canonical provider join key.
///
/// Native event identities commit retrieval + exact source lane + native ID;
/// adapter attestations commit exactly scope digest + relation kind + opaque
/// value. It has no display form and never exposes provider bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderCorrelationKeyV1([u8; 32]);

impl ProviderCorrelationKeyV1 {
    #[must_use]
    pub(crate) const fn from_derived_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ProviderCorrelationKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderCorrelationKeyV1(<redacted>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProviderRelationSourceV1 {
    NativeEventId,
    AdapterAttestation,
}

impl ProviderRelationSourceV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NativeEventId => "native_event_id",
            Self::AdapterAttestation => "adapter_attestation",
        }
    }
}

impl fmt::Debug for ProviderRelationSourceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderRelationSourceV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProviderRelationKindV1 {
    SharedNativeEventIdentity,
    SharedAdapterAttestedIdentity(ProviderAttestedRelationKindV1),
}

impl ProviderRelationKindV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SharedNativeEventIdentity => "shared_native_event_identity",
            Self::SharedAdapterAttestedIdentity(_) => "shared_adapter_attested_identity",
        }
    }

    #[must_use]
    pub const fn attested_kind(self) -> Option<ProviderAttestedRelationKindV1> {
        match self {
            Self::SharedNativeEventIdentity => None,
            Self::SharedAdapterAttestedIdentity(kind) => Some(kind),
        }
    }
}

impl fmt::Debug for ProviderRelationKindV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderRelationKindV1")
            .field("code", &self.code())
            .field(
                "attested_kind",
                &self
                    .attested_kind()
                    .map(ProviderAttestedRelationKindV1::code),
            )
            .finish()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ProviderRelationDescriptorV1 {
    pub(crate) source: ProviderRelationSourceV1,
    pub(crate) kind: ProviderRelationKindV1,
}

impl ProviderRelationDescriptorV1 {
    #[must_use]
    pub(crate) const fn new(
        source: ProviderRelationSourceV1,
        kind: ProviderRelationKindV1,
    ) -> Self {
        Self { source, kind }
    }
}

/// Ordering is a transparent observed fact. Neither variant means parenthood,
/// causality, responsibility, or root cause.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProviderOrderingBasisV1 {
    LaneSequence,
    LaneSequenceWithAdapterMonotonic,
}

impl ProviderOrderingBasisV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::LaneSequence => "lane_sequence",
            Self::LaneSequenceWithAdapterMonotonic => "lane_sequence_with_adapter_monotonic",
        }
    }
}

impl fmt::Debug for ProviderOrderingBasisV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderOrderingBasisV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ProviderCorrelationFacetV1 {
    facet: ProductionFacetV1,
    correlation_key: ProviderCorrelationKeyV1,
    source: ProviderRelationSourceV1,
    relation_kind: ProviderRelationKindV1,
}

impl ProviderCorrelationFacetV1 {
    #[must_use]
    pub(crate) const fn new(
        facet: ProductionFacetV1,
        correlation_key: ProviderCorrelationKeyV1,
        relation: ProviderRelationDescriptorV1,
    ) -> Self {
        Self {
            facet,
            correlation_key,
            source: relation.source,
            relation_kind: relation.kind,
        }
    }

    #[must_use]
    pub const fn facet(&self) -> &ProductionFacetV1 {
        &self.facet
    }

    #[must_use]
    pub const fn kind(&self) -> ProductionFacetKindV1 {
        self.facet.kind()
    }

    #[must_use]
    pub const fn correlation_key(&self) -> ProviderCorrelationKeyV1 {
        self.correlation_key
    }

    #[must_use]
    pub const fn source(&self) -> ProviderRelationSourceV1 {
        self.source
    }

    #[must_use]
    pub const fn relation_kind(&self) -> ProviderRelationKindV1 {
        self.relation_kind
    }
}

impl fmt::Debug for ProviderCorrelationFacetV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderCorrelationFacetV1")
            .field("kind", &self.kind())
            .field("source", &self.source)
            .field("relation_kind", &self.relation_kind)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProviderBlockRelationV1 {
    correlation_key: ProviderCorrelationKeyV1,
    facet_id: FacetIdV1,
    source: ProviderRelationSourceV1,
    relation_kind: ProviderRelationKindV1,
    group_block_count: u16,
}

impl ProviderBlockRelationV1 {
    #[must_use]
    pub(crate) const fn new(
        correlation_key: ProviderCorrelationKeyV1,
        facet_id: FacetIdV1,
        relation: ProviderRelationDescriptorV1,
        group_block_count: u16,
    ) -> Self {
        Self {
            correlation_key,
            facet_id,
            source: relation.source,
            relation_kind: relation.kind,
            group_block_count,
        }
    }

    #[must_use]
    pub const fn correlation_key(self) -> ProviderCorrelationKeyV1 {
        self.correlation_key
    }

    #[must_use]
    pub const fn facet_id(self) -> FacetIdV1 {
        self.facet_id
    }

    #[must_use]
    pub const fn source(self) -> ProviderRelationSourceV1 {
        self.source
    }

    #[must_use]
    pub const fn relation_kind(self) -> ProviderRelationKindV1 {
        self.relation_kind
    }

    #[must_use]
    pub const fn group_block_count(self) -> u16 {
        self.group_block_count
    }
}

impl fmt::Debug for ProviderBlockRelationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderBlockRelationV1")
            .field("source", &self.source)
            .field("relation_kind", &self.relation_kind)
            .field("group_block_count", &self.group_block_count)
            .finish()
    }
}

/// One direct observed-order edge between adjacent same-lane blocks sharing a
/// typed correlation. `earlier`/`later` are never causal or parent/child facts.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProviderGraphEdgeV1 {
    earlier_block_id: BlockId,
    later_block_id: BlockId,
    correlation_key: ProviderCorrelationKeyV1,
    facet_id: FacetIdV1,
    source: ProviderRelationSourceV1,
    relation_kind: ProviderRelationKindV1,
    ordering_basis: ProviderOrderingBasisV1,
    hop_depth: u8,
}

impl ProviderGraphEdgeV1 {
    #[must_use]
    pub(crate) const fn new(
        earlier_block_id: BlockId,
        later_block_id: BlockId,
        correlation_key: ProviderCorrelationKeyV1,
        facet_id: FacetIdV1,
        relation: ProviderRelationDescriptorV1,
        ordering_basis: ProviderOrderingBasisV1,
        hop_depth: u8,
    ) -> Self {
        Self {
            earlier_block_id,
            later_block_id,
            correlation_key,
            facet_id,
            source: relation.source,
            relation_kind: relation.kind,
            ordering_basis,
            hop_depth,
        }
    }

    #[must_use]
    pub const fn earlier_block_id(self) -> BlockId {
        self.earlier_block_id
    }

    #[must_use]
    pub const fn later_block_id(self) -> BlockId {
        self.later_block_id
    }

    #[must_use]
    pub const fn correlation_key(self) -> ProviderCorrelationKeyV1 {
        self.correlation_key
    }

    #[must_use]
    pub const fn facet_id(self) -> FacetIdV1 {
        self.facet_id
    }

    #[must_use]
    pub const fn source(self) -> ProviderRelationSourceV1 {
        self.source
    }

    #[must_use]
    pub const fn relation_kind(self) -> ProviderRelationKindV1 {
        self.relation_kind
    }

    #[must_use]
    pub const fn ordering_basis(self) -> ProviderOrderingBasisV1 {
        self.ordering_basis
    }

    #[must_use]
    pub const fn hop_depth(self) -> u8 {
        self.hop_depth
    }
}

impl fmt::Debug for ProviderGraphEdgeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderGraphEdgeV1")
            .field("source", &self.source)
            .field("relation_kind", &self.relation_kind)
            .field("ordering_basis", &self.ordering_basis)
            .field("hop_depth", &self.hop_depth)
            .finish()
    }
}

/// Independent lane-3 annotation keyed only by a reconciled primary BlockId.
/// It contains no alternate membership and no mandatory authority.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderBlockAnnotationV1 {
    block_id: BlockId,
    relations: Vec<ProviderBlockRelationV1>,
    affinities: Vec<FacetAffinityV1>,
}

impl ProviderBlockAnnotationV1 {
    #[must_use]
    pub(crate) const fn new(
        block_id: BlockId,
        relations: Vec<ProviderBlockRelationV1>,
        affinities: Vec<FacetAffinityV1>,
    ) -> Self {
        Self {
            block_id,
            relations,
            affinities,
        }
    }

    #[must_use]
    pub const fn block_id(&self) -> BlockId {
        self.block_id
    }

    #[must_use]
    pub fn relations(&self) -> &[ProviderBlockRelationV1] {
        &self.relations
    }

    #[must_use]
    pub fn affinities(&self) -> &[FacetAffinityV1] {
        &self.affinities
    }
}

impl fmt::Debug for ProviderBlockAnnotationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderBlockAnnotationV1")
            .field("relation_count", &self.relations.len())
            .field("affinity_count", &self.affinities.len())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProviderCorrelationAccountingV1 {
    identity_bytes_scanned: u64,
    native_identity_bytes_scanned: u64,
    attestation_bytes_scanned: u64,
    attestation_count_inspected: usize,
    correlation_key_count: usize,
    graph_node_count: usize,
    graph_edge_count: usize,
    emitted_facet_count: usize,
    emitted_affinity_count: usize,
    untyped_metadata_event_count_ignored: usize,
}

pub(crate) struct ProviderCorrelationAccountingPartsV1 {
    pub(crate) identity_bytes_scanned: u64,
    pub(crate) native_identity_bytes_scanned: u64,
    pub(crate) attestation_bytes_scanned: u64,
    pub(crate) attestation_count_inspected: usize,
    pub(crate) correlation_key_count: usize,
    pub(crate) graph_node_count: usize,
    pub(crate) graph_edge_count: usize,
    pub(crate) emitted_facet_count: usize,
    pub(crate) emitted_affinity_count: usize,
    pub(crate) untyped_metadata_event_count_ignored: usize,
}

impl ProviderCorrelationAccountingV1 {
    #[must_use]
    pub(crate) const fn new(parts: ProviderCorrelationAccountingPartsV1) -> Self {
        Self {
            identity_bytes_scanned: parts.identity_bytes_scanned,
            native_identity_bytes_scanned: parts.native_identity_bytes_scanned,
            attestation_bytes_scanned: parts.attestation_bytes_scanned,
            attestation_count_inspected: parts.attestation_count_inspected,
            correlation_key_count: parts.correlation_key_count,
            graph_node_count: parts.graph_node_count,
            graph_edge_count: parts.graph_edge_count,
            emitted_facet_count: parts.emitted_facet_count,
            emitted_affinity_count: parts.emitted_affinity_count,
            untyped_metadata_event_count_ignored: parts.untyped_metadata_event_count_ignored,
        }
    }

    #[must_use]
    /// Total native-identity plus attestation material bytes inspected.
    pub const fn identity_bytes_scanned(self) -> u64 {
        self.identity_bytes_scanned
    }

    #[must_use]
    /// Native-ID namespace material inspected under the native-only cap.
    pub const fn native_identity_bytes_scanned(self) -> u64 {
        self.native_identity_bytes_scanned
    }

    #[must_use]
    /// Scoped adapter-attestation material inspected under its separate cap.
    pub const fn attestation_bytes_scanned(self) -> u64 {
        self.attestation_bytes_scanned
    }

    #[must_use]
    pub const fn attestation_count_inspected(self) -> usize {
        self.attestation_count_inspected
    }

    #[must_use]
    pub const fn correlation_key_count(self) -> usize {
        self.correlation_key_count
    }

    #[must_use]
    pub const fn graph_node_count(self) -> usize {
        self.graph_node_count
    }

    #[must_use]
    pub const fn graph_edge_count(self) -> usize {
        self.graph_edge_count
    }

    #[must_use]
    pub const fn emitted_facet_count(self) -> usize {
        self.emitted_facet_count
    }

    #[must_use]
    pub const fn emitted_affinity_count(self) -> usize {
        self.emitted_affinity_count
    }

    #[must_use]
    pub const fn untyped_metadata_event_count_ignored(self) -> usize {
        self.untyped_metadata_event_count_ignored
    }
}

impl fmt::Debug for ProviderCorrelationAccountingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderCorrelationAccountingV1")
            .field("identity_bytes_scanned", &self.identity_bytes_scanned)
            .field(
                "native_identity_bytes_scanned",
                &self.native_identity_bytes_scanned,
            )
            .field("attestation_bytes_scanned", &self.attestation_bytes_scanned)
            .field(
                "attestation_count_inspected",
                &self.attestation_count_inspected,
            )
            .field("correlation_key_count", &self.correlation_key_count)
            .field("graph_node_count", &self.graph_node_count)
            .field("graph_edge_count", &self.graph_edge_count)
            .field("emitted_facet_count", &self.emitted_facet_count)
            .field("emitted_affinity_count", &self.emitted_affinity_count)
            .field(
                "untyped_metadata_event_count_ignored",
                &self.untyped_metadata_event_count_ignored,
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ProviderCorrelationUniverseV1 {
    retrieval_id: RetrievalId,
    capability: ProviderCorrelationCapabilityV1,
    facets: Vec<ProviderCorrelationFacetV1>,
    annotations: Vec<ProviderBlockAnnotationV1>,
    edges: Vec<ProviderGraphEdgeV1>,
    accounting: ProviderCorrelationAccountingV1,
}

impl ProviderCorrelationUniverseV1 {
    pub const CONTRACT_VERSION: u16 = 1;

    #[must_use]
    pub const fn contract_version(&self) -> u16 {
        Self::CONTRACT_VERSION
    }

    #[must_use]
    pub const fn policy_name(&self) -> &'static [u8] {
        PROVIDER_CORRELATION_POLICY_NAME_V1
    }

    #[must_use]
    pub const fn policy_version(&self) -> &'static [u8] {
        PROVIDER_CORRELATION_POLICY_VERSION_V1
    }

    #[must_use]
    pub const fn retrieval_id(&self) -> RetrievalId {
        self.retrieval_id
    }

    #[must_use]
    pub const fn capability(&self) -> ProviderCorrelationCapabilityV1 {
        self.capability
    }

    #[must_use]
    pub fn facets(&self) -> &[ProviderCorrelationFacetV1] {
        &self.facets
    }

    #[must_use]
    pub fn annotations(&self) -> &[ProviderBlockAnnotationV1] {
        &self.annotations
    }

    #[must_use]
    pub fn edges(&self) -> &[ProviderGraphEdgeV1] {
        &self.edges
    }

    #[must_use]
    pub const fn accounting(&self) -> ProviderCorrelationAccountingV1 {
        self.accounting
    }

    pub(crate) fn new(
        retrieval_id: RetrievalId,
        facets: Vec<ProviderCorrelationFacetV1>,
        annotations: Vec<ProviderBlockAnnotationV1>,
        edges: Vec<ProviderGraphEdgeV1>,
        accounting: ProviderCorrelationAccountingV1,
    ) -> Self {
        Self {
            retrieval_id,
            capability:
                ProviderCorrelationCapabilityV1::NativeEventIdentityAndScopedAdapterAttestations,
            facets,
            annotations,
            edges,
            accounting,
        }
    }
}

impl fmt::Debug for ProviderCorrelationUniverseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderCorrelationUniverseV1")
            .field("facet_count", &self.facets.len())
            .field("annotation_count", &self.annotations.len())
            .field("edge_count", &self.edges.len())
            .field("accounting", &self.accounting)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ProviderCorrelationGenerationDecisionV1 {
    Ready(ProviderCorrelationUniverseV1),
    NeedsMore(CandidateNeedsMoreV1),
}

impl ProviderCorrelationGenerationDecisionV1 {
    #[must_use]
    pub const fn ready(&self) -> Option<&ProviderCorrelationUniverseV1> {
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

impl fmt::Debug for ProviderCorrelationGenerationDecisionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready(universe) => formatter
                .debug_struct("ProviderCorrelationGenerationDecisionV1")
                .field("state", &"ready")
                .field("summary", universe)
                .finish(),
            Self::NeedsMore(reason) => formatter
                .debug_struct("ProviderCorrelationGenerationDecisionV1")
                .field("state", &"needs_more")
                .field("reason", reason)
                .finish(),
        }
    }
}
