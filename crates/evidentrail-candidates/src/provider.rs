use std::collections::{BTreeMap, btree_map::Entry};

use evidentrail_core::{
    BlockId, BlockIndex, Event, LaneKey, ProviderAttestedCorrelationV1, SourceStream,
};
use evidentrail_select::{
    AFFINITY_SCALE_V1, AffinityV1, FacetAffinityV1, FacetIdV1, FacetWeightV1,
    PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1, ProductionFacetKindV1, ProductionFacetV1,
};
use sha2::{Digest, Sha256};

use crate::bounds::{
    MAX_PRIMARY_BLOCKS_V1, MAX_PROVIDER_ATTESTATION_BYTES_SCANNED_V1,
    MAX_PROVIDER_ATTESTATIONS_INSPECTED_V1, MAX_PROVIDER_CORRELATION_KEYS_V1,
    MAX_PROVIDER_GRAPH_DEGREE_V1, MAX_PROVIDER_GRAPH_EDGES_V1, MAX_PROVIDER_GRAPH_HOP_DEPTH_V1,
    MAX_PROVIDER_GRAPH_NODES_V1, MAX_PROVIDER_IDENTITY_BYTES_SCANNED_V1,
    MAX_PROVIDER_OUTPUT_AFFINITIES_V1, MAX_PROVIDER_OUTPUT_FACETS_V1,
    MAX_PROVIDER_RELATION_FANOUT_V1,
};
use crate::provider_types::{
    ProviderBlockAnnotationV1, ProviderBlockRelationV1, ProviderCorrelationAccountingPartsV1,
    ProviderCorrelationAccountingV1, ProviderCorrelationFacetV1,
    ProviderCorrelationGenerationDecisionV1, ProviderCorrelationKeyV1,
    ProviderCorrelationUniverseV1, ProviderGraphEdgeV1, ProviderOrderingBasisV1,
    ProviderRelationDescriptorV1, ProviderRelationKindV1, ProviderRelationSourceV1,
};
use crate::types::{CandidateBuildErrorV1, CandidateNeedsMoreReasonV1, CandidateNeedsMoreV1};

const NATIVE_KEY_DOMAIN_V1: &[u8] = b"evidentrail/provider-correlation-key/native-event/v1\0";
const ATTESTED_KEY_DOMAIN_V1: &[u8] = b"evidentrail/provider-correlation-key/adapter-attestation/v1\0";

#[derive(Clone)]
struct NodeOccurrence {
    block_id: BlockId,
    lane: LaneKey,
    first_lane_sequence: u64,
    first_adapter_monotonic: Option<u64>,
}

struct CorrelationGroup {
    source: ProviderRelationSourceV1,
    relation_kind: ProviderRelationKindV1,
    nodes: BTreeMap<BlockId, NodeOccurrence>,
}

impl CorrelationGroup {
    fn new(source: ProviderRelationSourceV1, relation_kind: ProviderRelationKindV1) -> Self {
        Self {
            source,
            relation_kind,
            nodes: BTreeMap::new(),
        }
    }
}

struct WorkAnnotation {
    block_id: BlockId,
    relations: BTreeMap<(ProviderCorrelationKeyV1, FacetIdV1), ProviderBlockRelationV1>,
    affinities: BTreeMap<FacetIdV1, FacetAffinityV1>,
}

impl WorkAnnotation {
    fn new(block_id: BlockId) -> Self {
        Self {
            block_id,
            relations: BTreeMap::new(),
            affinities: BTreeMap::new(),
        }
    }
}

enum GenerationFailure {
    NeedsMore(CandidateNeedsMoreReasonV1),
    Build(CandidateBuildErrorV1),
}

impl From<CandidateNeedsMoreReasonV1> for GenerationFailure {
    fn from(reason: CandidateNeedsMoreReasonV1) -> Self {
        Self::NeedsMore(reason)
    }
}

impl From<CandidateBuildErrorV1> for GenerationFailure {
    fn from(error: CandidateBuildErrorV1) -> Self {
        Self::Build(error)
    }
}

/// Build V1 provider correlations from two disjoint trust namespaces.
///
/// `NativeEventId` equality remains scoped to retrieval + source member +
/// stream. Adapter attestations use exactly their opaque scope digest + closed
/// relation kind + opaque value, so they may share membership across lanes.
/// Generic metadata, payload bytes, source-record identity, and wall clocks are
/// never interpreted. Ordered edges are emitted only inside one exact lane and
/// mean observed lane order, never parenthood or causality.
pub fn generate_provider_correlations_v1(
    blocks: &BlockIndex<'_>,
) -> Result<ProviderCorrelationGenerationDecisionV1, CandidateBuildErrorV1> {
    match build_provider_correlations_v1(blocks) {
        Ok(universe) => Ok(ProviderCorrelationGenerationDecisionV1::Ready(universe)),
        Err(GenerationFailure::NeedsMore(reason)) => Ok(
            ProviderCorrelationGenerationDecisionV1::NeedsMore(CandidateNeedsMoreV1::new(reason)),
        ),
        Err(GenerationFailure::Build(error)) => Err(error),
    }
}

fn build_provider_correlations_v1(
    blocks: &BlockIndex<'_>,
) -> Result<ProviderCorrelationUniverseV1, GenerationFailure> {
    if blocks.len() > MAX_PRIMARY_BLOCKS_V1 {
        return Err(CandidateNeedsMoreReasonV1::PrimaryBlockCountCap.into());
    }
    let mut groups = BTreeMap::<ProviderCorrelationKeyV1, CorrelationGroup>::new();
    let mut work = blocks
        .blocks()
        .iter()
        .map(|block| (block.id(), WorkAnnotation::new(block.id())))
        .collect::<BTreeMap<_, _>>();
    let mut native_identity_bytes_scanned = 0u64;
    let mut attestation_bytes_scanned = 0u64;
    let mut attestation_count_inspected = 0usize;
    let mut graph_node_count = 0usize;
    let mut untyped_metadata_event_count_ignored = 0usize;

    for block in blocks.blocks() {
        let expansion = blocks
            .expand_block(block.id())
            .map_err(|_| CandidateBuildErrorV1::BlockIndexContractViolation)?;
        for event in expansion.events() {
            if event.metadata().is_some() {
                untyped_metadata_event_count_ignored = untyped_metadata_event_count_ignored
                    .checked_add(1)
                    .ok_or(CandidateNeedsMoreReasonV1::ArithmeticCapacity)?;
            }
            if event.native_event_id().is_some() {
                native_identity_bytes_scanned = checked_bounded_u64_add(
                    native_identity_bytes_scanned,
                    native_identity_material_bytes(event)?,
                    MAX_PROVIDER_IDENTITY_BYTES_SCANNED_V1,
                    CandidateNeedsMoreReasonV1::ProviderIdentityBytesScannedCap,
                )?;
                register_occurrence(
                    &mut groups,
                    native_correlation_key(blocks.retrieval_id().as_bytes(), event),
                    ProviderRelationSourceV1::NativeEventId,
                    ProviderRelationKindV1::SharedNativeEventIdentity,
                    block.id(),
                    event,
                    &mut graph_node_count,
                )?;
            }
            for attestation in event.provider_attestations().entries() {
                attestation_count_inspected = checked_bounded_increment(
                    attestation_count_inspected,
                    MAX_PROVIDER_ATTESTATIONS_INSPECTED_V1,
                    CandidateNeedsMoreReasonV1::ProviderAttestationCountCap,
                )?;
                attestation_bytes_scanned = checked_bounded_u64_add(
                    attestation_bytes_scanned,
                    attestation_material_bytes(attestation)?,
                    MAX_PROVIDER_ATTESTATION_BYTES_SCANNED_V1,
                    CandidateNeedsMoreReasonV1::ProviderAttestationBytesScannedCap,
                )?;
                register_occurrence(
                    &mut groups,
                    attested_correlation_key(attestation),
                    ProviderRelationSourceV1::AdapterAttestation,
                    ProviderRelationKindV1::SharedAdapterAttestedIdentity(
                        attestation.relation_kind(),
                    ),
                    block.id(),
                    event,
                    &mut graph_node_count,
                )?;
            }
        }
    }

    let endpoint_weight = FacetWeightV1::new(PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1)
        .map_err(|_| CandidateBuildErrorV1::FixedPointContractViolation)?;
    let full_affinity = AffinityV1::new(AFFINITY_SCALE_V1)
        .map_err(|_| CandidateBuildErrorV1::FixedPointContractViolation)?;
    let mut facets = BTreeMap::<FacetIdV1, ProviderCorrelationFacetV1>::new();
    let mut edges = Vec::new();
    let mut degrees = BTreeMap::<BlockId, usize>::new();
    let mut affinity_count = 0usize;

    for (key, group) in &groups {
        if group.nodes.len() < 2 {
            continue;
        }
        if group.nodes.len() > MAX_PROVIDER_RELATION_FANOUT_V1 {
            return Err(CandidateNeedsMoreReasonV1::ProviderRelationFanoutCap.into());
        }
        if facets.len() >= MAX_PROVIDER_OUTPUT_FACETS_V1 {
            return Err(CandidateNeedsMoreReasonV1::ProviderFacetOutputCap.into());
        }
        let facet = ProductionFacetV1::new(
            ProductionFacetKindV1::ProviderAttestedGraphRelation,
            key.as_bytes(),
            endpoint_weight,
        )
        .map_err(|_| CandidateBuildErrorV1::FacetContractViolation)?;
        let facet_id = facet.id();
        if facets
            .insert(
                facet_id,
                ProviderCorrelationFacetV1::new(
                    facet,
                    *key,
                    ProviderRelationDescriptorV1::new(group.source, group.relation_kind),
                ),
            )
            .is_some()
        {
            return Err(CandidateBuildErrorV1::FacetContractViolation.into());
        }

        let group_block_count = u16::try_from(group.nodes.len())
            .map_err(|_| CandidateNeedsMoreReasonV1::ArithmeticCapacity)?;
        let mut nodes_by_lane = BTreeMap::<LaneKey, Vec<NodeOccurrence>>::new();
        for node in group.nodes.values() {
            affinity_count = checked_bounded_increment(
                affinity_count,
                MAX_PROVIDER_OUTPUT_AFFINITIES_V1,
                CandidateNeedsMoreReasonV1::ProviderAffinityOutputCap,
            )?;
            let annotation = work
                .get_mut(&node.block_id)
                .ok_or(CandidateBuildErrorV1::BlockIndexContractViolation)?;
            annotation.relations.insert(
                (*key, facet_id),
                ProviderBlockRelationV1::new(
                    *key,
                    facet_id,
                    ProviderRelationDescriptorV1::new(group.source, group.relation_kind),
                    group_block_count,
                ),
            );
            annotation
                .affinities
                .insert(facet_id, FacetAffinityV1::new(facet_id, full_affinity));
            nodes_by_lane
                .entry(node.lane.clone())
                .or_default()
                .push(node.clone());
        }

        for lane_nodes in nodes_by_lane.values_mut() {
            lane_nodes.sort_unstable_by(|left, right| {
                left.first_lane_sequence
                    .cmp(&right.first_lane_sequence)
                    .then_with(|| left.block_id.cmp(&right.block_id))
            });
            for adjacent in lane_nodes.windows(2) {
                let [earlier, later] = adjacent else {
                    return Err(CandidateBuildErrorV1::BlockIndexContractViolation.into());
                };
                if edges.len() >= MAX_PROVIDER_GRAPH_EDGES_V1 {
                    return Err(CandidateNeedsMoreReasonV1::ProviderGraphEdgeCap.into());
                }
                increment_degree(&mut degrees, earlier.block_id)?;
                increment_degree(&mut degrees, later.block_id)?;
                edges.push(ProviderGraphEdgeV1::new(
                    earlier.block_id,
                    later.block_id,
                    *key,
                    facet_id,
                    ProviderRelationDescriptorV1::new(group.source, group.relation_kind),
                    ordering_basis(
                        earlier.first_adapter_monotonic,
                        later.first_adapter_monotonic,
                    ),
                    MAX_PROVIDER_GRAPH_HOP_DEPTH_V1,
                ));
            }
        }
    }

    edges.sort_unstable();
    let annotations = work
        .into_values()
        .map(|annotation| {
            ProviderBlockAnnotationV1::new(
                annotation.block_id,
                annotation.relations.into_values().collect(),
                annotation.affinities.into_values().collect(),
            )
        })
        .collect::<Vec<_>>();
    let identity_bytes_scanned = native_identity_bytes_scanned
        .checked_add(attestation_bytes_scanned)
        .ok_or(CandidateNeedsMoreReasonV1::ArithmeticCapacity)?;
    let graph_edge_count = edges.len();
    let emitted_facet_count = facets.len();

    Ok(ProviderCorrelationUniverseV1::new(
        blocks.retrieval_id(),
        facets.into_values().collect(),
        annotations,
        edges,
        ProviderCorrelationAccountingV1::new(ProviderCorrelationAccountingPartsV1 {
            identity_bytes_scanned,
            native_identity_bytes_scanned,
            attestation_bytes_scanned,
            attestation_count_inspected,
            correlation_key_count: groups.len(),
            graph_node_count,
            graph_edge_count,
            emitted_facet_count,
            emitted_affinity_count: affinity_count,
            untyped_metadata_event_count_ignored,
        }),
    ))
}

fn register_occurrence(
    groups: &mut BTreeMap<ProviderCorrelationKeyV1, CorrelationGroup>,
    key: ProviderCorrelationKeyV1,
    source: ProviderRelationSourceV1,
    relation_kind: ProviderRelationKindV1,
    block_id: BlockId,
    event: &Event,
    graph_node_count: &mut usize,
) -> Result<(), GenerationFailure> {
    if !groups.contains_key(&key) && groups.len() >= MAX_PROVIDER_CORRELATION_KEYS_V1 {
        return Err(CandidateNeedsMoreReasonV1::ProviderCorrelationKeyCap.into());
    }
    let group = match groups.entry(key) {
        Entry::Occupied(entry) => {
            if entry.get().source != source || entry.get().relation_kind != relation_kind {
                return Err(CandidateBuildErrorV1::FacetContractViolation.into());
            }
            entry.into_mut()
        }
        Entry::Vacant(entry) => entry.insert(CorrelationGroup::new(source, relation_kind)),
    };
    if let Some(existing) = group.nodes.get_mut(&block_id) {
        if event.lane_sequence().get() < existing.first_lane_sequence {
            existing.first_lane_sequence = event.lane_sequence().get();
            existing.first_adapter_monotonic = event
                .timestamps()
                .adapter_monotonic_time()
                .map(|timestamp| timestamp.get());
        }
        return Ok(());
    }
    *graph_node_count = checked_bounded_increment(
        *graph_node_count,
        MAX_PROVIDER_GRAPH_NODES_V1,
        CandidateNeedsMoreReasonV1::ProviderGraphNodeCap,
    )?;
    group.nodes.insert(
        block_id,
        NodeOccurrence {
            block_id,
            lane: event.lane().clone(),
            first_lane_sequence: event.lane_sequence().get(),
            first_adapter_monotonic: event
                .timestamps()
                .adapter_monotonic_time()
                .map(|timestamp| timestamp.get()),
        },
    );
    Ok(())
}

fn native_identity_material_bytes(event: &Event) -> Result<u64, CandidateNeedsMoreReasonV1> {
    let native = event
        .native_event_id()
        .ok_or(CandidateNeedsMoreReasonV1::ArithmeticCapacity)?;
    sum_material_bytes([
        32usize,
        event.lane().member().as_bytes().len(),
        stream_material_bytes(event.lane().stream()),
        native.as_bytes().len(),
    ])
}

fn attestation_material_bytes(
    attestation: &ProviderAttestedCorrelationV1,
) -> Result<u64, CandidateNeedsMoreReasonV1> {
    sum_material_bytes([
        attestation.scope_digest().as_bytes().len(),
        attestation.relation_kind().code().len(),
        attestation.value().as_bytes().len(),
    ])
}

fn sum_material_bytes<const N: usize>(
    lengths: [usize; N],
) -> Result<u64, CandidateNeedsMoreReasonV1> {
    lengths.into_iter().try_fold(0u64, |total, length| {
        total
            .checked_add(
                u64::try_from(length)
                    .map_err(|_| CandidateNeedsMoreReasonV1::ArithmeticCapacity)?,
            )
            .ok_or(CandidateNeedsMoreReasonV1::ArithmeticCapacity)
    })
}

fn stream_material_bytes(stream: &SourceStream) -> usize {
    stream.code().len()
        + match stream {
            SourceStream::OtherVersioned { .. } => 4,
            SourceStream::Stdout
            | SourceStream::Stderr
            | SourceStream::Container
            | SourceStream::Journal
            | SourceStream::LogStream
            | SourceStream::FileMember => 0,
        }
}

fn native_correlation_key(retrieval_id: &[u8; 32], event: &Event) -> ProviderCorrelationKeyV1 {
    let native_event_id = event
        .native_event_id()
        .expect("provider key derivation requires a native event identity");
    let mut hasher = Sha256::new();
    hasher.update(NATIVE_KEY_DOMAIN_V1);
    update_hash_field(&mut hasher, retrieval_id);
    update_hash_field(&mut hasher, event.lane().member().as_bytes());
    update_hash_field(&mut hasher, event.lane().stream().code().as_bytes());
    if let SourceStream::OtherVersioned { version, code } = event.lane().stream() {
        update_hash_field(&mut hasher, &version.to_be_bytes());
        update_hash_field(&mut hasher, &code.to_be_bytes());
    }
    update_hash_field(&mut hasher, native_event_id.as_bytes());
    ProviderCorrelationKeyV1::from_derived_bytes(hasher.finalize().into())
}

fn attested_correlation_key(
    attestation: &ProviderAttestedCorrelationV1,
) -> ProviderCorrelationKeyV1 {
    let mut hasher = Sha256::new();
    hasher.update(ATTESTED_KEY_DOMAIN_V1);
    update_hash_field(&mut hasher, attestation.scope_digest().as_bytes());
    update_hash_field(&mut hasher, attestation.relation_kind().code().as_bytes());
    update_hash_field(&mut hasher, attestation.value().as_bytes());
    ProviderCorrelationKeyV1::from_derived_bytes(hasher.finalize().into())
}

fn update_hash_field(hasher: &mut Sha256, field: &[u8]) {
    let length = u64::try_from(field.len()).expect("provider identity field length fits u64");
    hasher.update(length.to_be_bytes());
    hasher.update(field);
}

fn ordering_basis(
    earlier_monotonic: Option<u64>,
    later_monotonic: Option<u64>,
) -> ProviderOrderingBasisV1 {
    match (earlier_monotonic, later_monotonic) {
        (Some(earlier), Some(later)) if earlier <= later => {
            ProviderOrderingBasisV1::LaneSequenceWithAdapterMonotonic
        }
        _ => ProviderOrderingBasisV1::LaneSequence,
    }
}

fn increment_degree(
    degrees: &mut BTreeMap<BlockId, usize>,
    block_id: BlockId,
) -> Result<(), CandidateNeedsMoreReasonV1> {
    let degree = degrees.entry(block_id).or_default();
    *degree = checked_bounded_increment(
        *degree,
        MAX_PROVIDER_GRAPH_DEGREE_V1,
        CandidateNeedsMoreReasonV1::ProviderGraphDegreeCap,
    )?;
    Ok(())
}

fn checked_bounded_increment(
    current: usize,
    maximum: usize,
    cap_reason: CandidateNeedsMoreReasonV1,
) -> Result<usize, CandidateNeedsMoreReasonV1> {
    let next = current
        .checked_add(1)
        .ok_or(CandidateNeedsMoreReasonV1::ArithmeticCapacity)?;
    if next > maximum {
        return Err(cap_reason);
    }
    Ok(next)
}

fn checked_bounded_u64_add(
    current: u64,
    additional: u64,
    maximum: u64,
    cap_reason: CandidateNeedsMoreReasonV1,
) -> Result<u64, CandidateNeedsMoreReasonV1> {
    let next = current
        .checked_add(additional)
        .ok_or(CandidateNeedsMoreReasonV1::ArithmeticCapacity)?;
    if next > maximum {
        return Err(cap_reason);
    }
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use evidentrail_core::ProviderAttestedRelationKindV1;

    #[test]
    fn every_provider_counter_accepts_its_cap_and_rejects_the_next_value() {
        for (maximum, reason) in [
            (
                MAX_PROVIDER_ATTESTATIONS_INSPECTED_V1,
                CandidateNeedsMoreReasonV1::ProviderAttestationCountCap,
            ),
            (
                MAX_PROVIDER_CORRELATION_KEYS_V1,
                CandidateNeedsMoreReasonV1::ProviderCorrelationKeyCap,
            ),
            (
                MAX_PROVIDER_GRAPH_NODES_V1,
                CandidateNeedsMoreReasonV1::ProviderGraphNodeCap,
            ),
            (
                MAX_PROVIDER_GRAPH_EDGES_V1,
                CandidateNeedsMoreReasonV1::ProviderGraphEdgeCap,
            ),
            (
                MAX_PROVIDER_RELATION_FANOUT_V1,
                CandidateNeedsMoreReasonV1::ProviderRelationFanoutCap,
            ),
            (
                MAX_PROVIDER_GRAPH_DEGREE_V1,
                CandidateNeedsMoreReasonV1::ProviderGraphDegreeCap,
            ),
            (
                MAX_PROVIDER_OUTPUT_FACETS_V1,
                CandidateNeedsMoreReasonV1::ProviderFacetOutputCap,
            ),
            (
                MAX_PROVIDER_OUTPUT_AFFINITIES_V1,
                CandidateNeedsMoreReasonV1::ProviderAffinityOutputCap,
            ),
        ] {
            assert_eq!(
                checked_bounded_increment(maximum - 1, maximum, reason),
                Ok(maximum)
            );
            assert_eq!(
                checked_bounded_increment(maximum, maximum, reason),
                Err(reason)
            );
        }
        for (maximum, reason) in [
            (
                MAX_PROVIDER_IDENTITY_BYTES_SCANNED_V1,
                CandidateNeedsMoreReasonV1::ProviderIdentityBytesScannedCap,
            ),
            (
                MAX_PROVIDER_ATTESTATION_BYTES_SCANNED_V1,
                CandidateNeedsMoreReasonV1::ProviderAttestationBytesScannedCap,
            ),
        ] {
            assert_eq!(
                checked_bounded_u64_add(0, maximum, maximum, reason),
                Ok(maximum)
            );
            assert_eq!(
                checked_bounded_u64_add(maximum, 1, maximum, reason),
                Err(reason)
            );
        }
    }

    #[test]
    fn only_trustworthy_monotonic_order_can_corroborate_lane_sequence() {
        assert_eq!(
            ordering_basis(Some(10), Some(11)),
            ProviderOrderingBasisV1::LaneSequenceWithAdapterMonotonic
        );
        assert_eq!(
            ordering_basis(Some(11), Some(10)),
            ProviderOrderingBasisV1::LaneSequence
        );
        assert_eq!(
            ordering_basis(None, Some(10)),
            ProviderOrderingBasisV1::LaneSequence
        );
    }

    #[test]
    fn native_and_attested_key_domains_are_distinct() {
        assert_ne!(NATIVE_KEY_DOMAIN_V1, ATTESTED_KEY_DOMAIN_V1);
        assert_ne!(
            ProviderAttestedRelationKindV1::TraceIdentity.code(),
            ProviderAttestedRelationKindV1::RequestIdentity.code()
        );
    }
}
