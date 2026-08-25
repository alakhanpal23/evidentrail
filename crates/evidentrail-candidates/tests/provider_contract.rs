use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use evidentrail_candidates::{
    CandidateNeedsMoreReasonV1, PROVIDER_CORRELATION_POLICY_VERSION_V1, ProviderBlockAnnotationV1,
    ProviderCorrelationCapabilityV1, ProviderCorrelationGenerationDecisionV1,
    ProviderCorrelationUniverseV1, ProviderOrderingBasisV1, ProviderRelationKindV1,
    ProviderRelationSourceV1, generate_provider_correlations_v1,
};
use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    BlockAssignment, BlockConfidence, BlockIndex, BlockState, CompletenessProof,
    DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, EnvelopeTimestamps, EventLedger,
    FetchBoundaries, FetchCompleteness, FetchCompletion, FetchIdentity, FetchTiming, FramingPolicy,
    LaneKey, LaneSequence, LedgerBuilder, MonotonicTimestampNanos, NativeEventId, NativeMetadata,
    NativeMetadataField, NativeMetadataValue, PlanDigest, PlanId, PolicyAuthorization,
    ProviderAttestationScopeDigestV1, ProviderAttestationValueV1, ProviderAttestationsV1,
    ProviderAttestedCorrelationV1, ProviderAttestedRelationKindV1, RawEnvelopeIdentityV1,
    RawEnvelopeV1, RecordBytes, RecordState, RetrievalId, SourceIdentityDigest, SourceMember,
    SourceStream, UnixTimestampNanos,
};
use evidentrail_framing::frame_source_lanes_v1;
use evidentrail_select::{PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1, ProductionFacetKindV1};

struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FixtureStream {
    Stdout,
    Stderr,
}

#[derive(Clone)]
struct RecordSpec {
    member: u16,
    stream: FixtureStream,
    payload: Vec<u8>,
    native_event_id: Option<Vec<u8>>,
    provider_attestations: ProviderAttestationsV1,
    metadata: Option<NativeMetadata>,
    monotonic: Option<u64>,
}

impl RecordSpec {
    fn line(payload: impl Into<Vec<u8>>) -> Self {
        Self {
            member: 0,
            stream: FixtureStream::Stderr,
            payload: payload.into(),
            native_event_id: None,
            provider_attestations: ProviderAttestationsV1::default(),
            metadata: None,
            monotonic: None,
        }
    }

    fn with_native_id(mut self, native_event_id: impl Into<Vec<u8>>) -> Self {
        self.native_event_id = Some(native_event_id.into());
        self
    }

    fn with_metadata(mut self, metadata: NativeMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    fn with_attestations(
        mut self,
        attestations: impl IntoIterator<Item = ProviderAttestedCorrelationV1>,
    ) -> Self {
        self.provider_attestations = ProviderAttestationsV1::new(attestations).unwrap();
        self
    }

    fn on_member(mut self, member: u16) -> Self {
        self.member = member;
        self
    }

    fn on_stream(mut self, stream: FixtureStream) -> Self {
        self.stream = stream;
        self
    }

    fn at_monotonic(mut self, monotonic: u64) -> Self {
        self.monotonic = Some(monotonic);
        self
    }
}

fn ledger(seed: u8, records: &[RecordSpec]) -> EventLedger {
    let retrieval_id = RetrievalId::from_bytes([seed; 32]);
    let plan_id = PlanId::from_bytes([41; 32]);
    let plan_digest = PlanDigest::from_bytes([42; 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([43; 32]);
    let adapter = AdapterIdentity::new("provider-fixture", "1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let mut lane_sequences = BTreeMap::<(u16, FixtureStream), u64>::new();
    let mut builder = LedgerBuilder::new(
        fetch_identity.clone(),
        source_identity_digest,
        SourceExactPolicy,
    );
    let mut payload_bytes = 0u64;
    let mut source_bytes = 0u64;
    let mut members = BTreeSet::new();

    for (position, record) in records.iter().enumerate() {
        members.insert(record.member);
        let lane_identity = (record.member, record.stream);
        let lane_sequence = lane_sequences.entry(lane_identity).or_default();
        let mut member = b"provider-fixture-member".to_vec();
        member.extend_from_slice(&record.member.to_be_bytes());
        let stream = match record.stream {
            FixtureStream::Stdout => SourceStream::Stdout,
            FixtureStream::Stderr => SourceStream::Stderr,
        };
        let record_bytes = RecordBytes::framed(record.payload.clone(), b"\n".to_vec());
        payload_bytes = payload_bytes
            .checked_add(u64::try_from(record_bytes.payload_len()).unwrap())
            .unwrap();
        source_bytes = source_bytes
            .checked_add(u64::try_from(record_bytes.source_len()).unwrap())
            .unwrap();
        let mut envelope = RawEnvelopeV1::new(
            envelope_identity.clone(),
            EnvelopeOrdering::new(
                AcquisitionSequence::new(u64::try_from(position).unwrap()),
                LaneKey::new(SourceMember::new(member).unwrap(), stream),
                LaneSequence::new(*lane_sequence),
            ),
            record_bytes,
            RecordState::Complete,
        )
        .with_timestamps(EnvelopeTimestamps::new(
            None,
            None,
            None,
            record.monotonic.map(MonotonicTimestampNanos::new),
        ));
        if let Some(native_event_id) = &record.native_event_id {
            envelope =
                envelope.with_native_event_id(NativeEventId::new(native_event_id.clone()).unwrap());
        }
        if let Some(metadata) = &record.metadata {
            envelope = envelope.with_metadata(metadata.clone());
        }
        envelope = envelope.with_provider_attestations(record.provider_attestations.clone());
        builder.accept(envelope).unwrap();
        *lane_sequence = lane_sequence.checked_add(1).unwrap();
    }

    let record_count = u64::try_from(records.len()).unwrap();
    let member_count = u64::try_from(members.len()).unwrap();
    let completion = FetchCompletion::new(
        fetch_identity,
        FetchTiming::new(UnixTimestampNanos::new(0), UnixTimestampNanos::new(1)),
        AcknowledgedCounts::new(record_count, payload_bytes, source_bytes),
        AttemptCounts::new(member_count, member_count),
        AttemptCounts::default(),
        FetchBoundaries::default(),
        [],
        AdapterOutcome::Finished,
        [],
        FetchCompleteness::complete(CompletenessProof::OtherVersioned {
            version: 1,
            code: 151,
        }),
    )
    .unwrap();
    builder.seal(completion).unwrap()
}

fn ready(blocks: &BlockIndex<'_>) -> ProviderCorrelationUniverseV1 {
    match generate_provider_correlations_v1(blocks).unwrap() {
        ProviderCorrelationGenerationDecisionV1::Ready(universe) => universe,
        ProviderCorrelationGenerationDecisionV1::NeedsMore(reason) => {
            panic!("unexpected needs_more: {}", reason.code())
        }
    }
}

fn attestation(
    scope_seed: u8,
    kind: ProviderAttestedRelationKindV1,
    value: impl Into<Vec<u8>>,
) -> ProviderAttestedCorrelationV1 {
    ProviderAttestedCorrelationV1::new(
        ProviderAttestationScopeDigestV1::from_bytes([scope_seed; 32]),
        kind,
        ProviderAttestationValueV1::new(value).unwrap(),
    )
}

fn annotation(
    universe: &ProviderCorrelationUniverseV1,
    block_id: evidentrail_core::BlockId,
) -> &ProviderBlockAnnotationV1 {
    universe
        .annotations()
        .binary_search_by_key(&block_id, ProviderBlockAnnotationV1::block_id)
        .map(|position| &universe.annotations()[position])
        .unwrap()
}

fn manual_index<'ledger>(
    ledger: &'ledger EventLedger,
    ranges: &[Range<usize>],
    reverse_assignments: bool,
) -> BlockIndex<'ledger> {
    let mut assignments = ranges
        .iter()
        .map(|range| {
            let first = &ledger.events()[range.start];
            BlockAssignment::new_same_lane_v1(
                first.lane().clone(),
                ledger.events()[range.clone()]
                    .iter()
                    .map(|event| (event.id(), event.lane_sequence())),
                FramingPolicy::new(b"provider-test-primary-v1".to_vec(), b"1".to_vec()),
                BlockState::ProviderAtomic,
                BlockConfidence::Certain,
            )
        })
        .collect::<Vec<_>>();
    if reverse_assignments {
        assignments.reverse();
    }
    BlockIndex::reconcile(ledger, assignments).unwrap()
}

#[test]
fn exact_native_identity_emits_only_typed_noncausal_relations() {
    let records = [
        RecordSpec::line(b"first provider record".to_vec())
            .with_native_id(b"native-correlation-1".to_vec())
            .at_monotonic(10),
        RecordSpec::line(b"unrelated record".to_vec()),
        RecordSpec::line(b"second provider record".to_vec())
            .with_native_id(b"native-correlation-1".to_vec())
            .at_monotonic(11),
    ];
    let ledger = ledger(81, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(&blocks);
    let first = blocks.block_for_event(ledger.events()[0].id()).unwrap();
    let unrelated = blocks.block_for_event(ledger.events()[1].id()).unwrap();
    let second = blocks.block_for_event(ledger.events()[2].id()).unwrap();

    assert_eq!(
        universe.capability(),
        ProviderCorrelationCapabilityV1::NativeEventIdentityAndScopedAdapterAttestations
    );
    assert_eq!(universe.facets().len(), 1);
    assert_eq!(
        universe.policy_version(),
        PROVIDER_CORRELATION_POLICY_VERSION_V1
    );
    assert_eq!(
        universe.facets()[0].kind(),
        ProductionFacetKindV1::ProviderAttestedGraphRelation
    );
    assert_eq!(
        universe.facets()[0].facet().weight().micros(),
        PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1
    );
    assert_eq!(
        universe.facets()[0].source(),
        ProviderRelationSourceV1::NativeEventId
    );
    assert_eq!(
        universe.facets()[0].relation_kind(),
        ProviderRelationKindV1::SharedNativeEventIdentity
    );
    assert_eq!(annotation(&universe, first.id()).relations().len(), 1);
    assert!(annotation(&universe, unrelated.id()).relations().is_empty());
    assert_eq!(annotation(&universe, second.id()).affinities().len(), 1);
    assert_eq!(universe.edges().len(), 1);
    assert_eq!(universe.edges()[0].earlier_block_id(), first.id());
    assert_eq!(universe.edges()[0].later_block_id(), second.id());
    assert_eq!(
        universe.edges()[0].ordering_basis(),
        ProviderOrderingBasisV1::LaneSequenceWithAdapterMonotonic
    );
    assert_eq!(universe.edges()[0].hop_depth(), 1);
    assert_eq!(universe.annotations().len(), blocks.len());
}

#[test]
fn source_member_stream_and_retrieval_are_exact_namespace_boundaries() {
    let records = [
        RecordSpec::line(b"member-zero-a".to_vec()).with_native_id(b"same-id".to_vec()),
        RecordSpec::line(b"member-one-a".to_vec())
            .on_member(1)
            .with_native_id(b"same-id".to_vec()),
        RecordSpec::line(b"stdout-a".to_vec())
            .on_stream(FixtureStream::Stdout)
            .with_native_id(b"same-id".to_vec()),
        RecordSpec::line(b"member-zero-b".to_vec()).with_native_id(b"same-id".to_vec()),
        RecordSpec::line(b"member-one-b".to_vec())
            .on_member(1)
            .with_native_id(b"same-id".to_vec()),
        RecordSpec::line(b"stdout-b".to_vec())
            .on_stream(FixtureStream::Stdout)
            .with_native_id(b"same-id".to_vec()),
    ];
    let first_ledger = ledger(82, &records);
    let first_blocks = frame_source_lanes_v1(&first_ledger).unwrap();
    let first = ready(&first_blocks);
    let replay_elsewhere = ledger(83, &records);
    let replay_elsewhere_blocks = frame_source_lanes_v1(&replay_elsewhere).unwrap();
    let second = ready(&replay_elsewhere_blocks);

    assert_eq!(first.facets().len(), 3);
    assert_eq!(first.edges().len(), 3);
    assert!(
        first
            .annotations()
            .iter()
            .filter_map(|item| item.relations().first())
            .all(|relation| relation.group_block_count() == 2)
    );
    let first_keys = first
        .facets()
        .iter()
        .map(|facet| facet.correlation_key())
        .collect::<BTreeSet<_>>();
    let second_keys = second
        .facets()
        .iter()
        .map(|facet| facet.correlation_key())
        .collect::<BTreeSet<_>>();
    assert_eq!(first_keys.len(), 3);
    assert!(first_keys.is_disjoint(&second_keys));
}

#[test]
fn scoped_attestations_join_across_members_and_streams_without_fabricated_order() {
    let shared = attestation(
        7,
        ProviderAttestedRelationKindV1::TraceIdentity,
        b"shared-provider-trace".to_vec(),
    );
    let records = [
        RecordSpec::line(b"stderr member zero".to_vec())
            .with_attestations([shared.clone()])
            .at_monotonic(10),
        RecordSpec::line(b"stdout member nine".to_vec())
            .on_member(9)
            .on_stream(FixtureStream::Stdout)
            .with_attestations([shared])
            .at_monotonic(11),
    ];
    let ledger = ledger(94, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(&blocks);

    assert_eq!(universe.facets().len(), 1);
    assert_eq!(universe.edges().len(), 0);
    assert_eq!(universe.accounting().attestation_count_inspected(), 2);
    assert!(universe.accounting().attestation_bytes_scanned() > 0);
    assert!(universe.annotations().iter().all(|annotation| {
        annotation.relations().len() == 1
            && annotation.relations()[0].source() == ProviderRelationSourceV1::AdapterAttestation
            && annotation.relations()[0].relation_kind()
                == ProviderRelationKindV1::SharedAdapterAttestedIdentity(
                    ProviderAttestedRelationKindV1::TraceIdentity,
                )
    }));
}

#[test]
fn attestation_scope_and_relation_kind_are_exact_join_boundaries() {
    let records = [
        RecordSpec::line(b"scope one trace".to_vec()).with_attestations([attestation(
            1,
            ProviderAttestedRelationKindV1::TraceIdentity,
            b"same-value".to_vec(),
        )]),
        RecordSpec::line(b"scope two trace".to_vec()).with_attestations([attestation(
            2,
            ProviderAttestedRelationKindV1::TraceIdentity,
            b"same-value".to_vec(),
        )]),
        RecordSpec::line(b"scope one request".to_vec()).with_attestations([attestation(
            1,
            ProviderAttestedRelationKindV1::RequestIdentity,
            b"same-value".to_vec(),
        )]),
    ];
    let ledger = ledger(95, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(&blocks);

    assert!(universe.facets().is_empty());
    assert!(universe.edges().is_empty());
    assert_eq!(universe.accounting().correlation_key_count(), 3);
    assert_eq!(universe.accounting().graph_node_count(), 3);
}

#[test]
fn attested_key_is_the_exact_scoped_tuple_not_the_retrieval() {
    let shared = attestation(
        8,
        ProviderAttestedRelationKindV1::DeploymentIdentity,
        b"provider-deployment".to_vec(),
    );
    let records = [
        RecordSpec::line(b"one".to_vec()).with_attestations([shared.clone()]),
        RecordSpec::line(b"two".to_vec()).with_attestations([shared]),
    ];
    let first_ledger = ledger(98, &records);
    let second_ledger = ledger(99, &records);
    let first_blocks = frame_source_lanes_v1(&first_ledger).unwrap();
    let second_blocks = frame_source_lanes_v1(&second_ledger).unwrap();

    assert_eq!(
        ready(&first_blocks).facets()[0].correlation_key(),
        ready(&second_blocks).facets()[0].correlation_key()
    );
}

#[test]
fn native_and_attested_equal_bytes_remain_separate_namespaces() {
    let value = b"identical-opaque-value".to_vec();
    let scoped = attestation(
        3,
        ProviderAttestedRelationKindV1::SessionIdentity,
        value.clone(),
    );
    let records = [
        RecordSpec::line(b"first".to_vec())
            .with_native_id(value.clone())
            .with_attestations([scoped.clone()]),
        RecordSpec::line(b"second".to_vec())
            .with_native_id(value)
            .with_attestations([scoped]),
    ];
    let ledger = ledger(96, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(&blocks);
    let sources = universe
        .facets()
        .iter()
        .map(|facet| facet.source())
        .collect::<BTreeSet<_>>();

    assert_eq!(universe.facets().len(), 2);
    assert_eq!(sources.len(), 2);
    assert!(sources.contains(&ProviderRelationSourceV1::NativeEventId));
    assert!(sources.contains(&ProviderRelationSourceV1::AdapterAttestation));
    assert_ne!(
        universe.facets()[0].correlation_key(),
        universe.facets()[1].correlation_key()
    );
}

#[test]
fn arbitrary_attested_bytes_and_duplicate_block_occurrences_are_exact_and_bounded() {
    let shared = attestation(
        4,
        ProviderAttestedRelationKindV1::ContainerIdentity,
        vec![0, 0xff, b'\n', b'/', 0x80],
    );
    let records = [
        RecordSpec::line(b"Traceback (most recent call last):".to_vec())
            .with_attestations([shared.clone(), shared.clone()]),
        RecordSpec::line(b"  File \"x.py\", line 1".to_vec()).with_attestations([shared.clone()]),
        RecordSpec::line(b"ValueError: bad".to_vec()).with_attestations([shared.clone()]),
        RecordSpec::line(b"later".to_vec()).with_attestations([shared]),
    ];
    let ledger = ledger(97, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(&blocks);

    assert_eq!(blocks.len(), 2);
    assert_eq!(universe.facets().len(), 1);
    assert_eq!(universe.accounting().attestation_count_inspected(), 4);
    assert_eq!(universe.accounting().graph_node_count(), 2);
    assert_eq!(universe.accounting().emitted_affinity_count(), 2);
    assert_eq!(universe.edges().len(), 1);
}

#[test]
fn payload_lookalikes_generic_metadata_and_source_record_identity_create_no_graph() {
    let metadata = NativeMetadata::new([
        NativeMetadataField::new(
            b"trace_id_SECRET_FIELD".to_vec(),
            NativeMetadataValue::Text("SECRET_METADATA_VALUE".to_owned()),
        ),
        NativeMetadataField::new(
            b"service".to_vec(),
            NativeMetadataValue::Bytes(b"SECRET_SERVICE".to_vec()),
        ),
    ]);
    let records = [
        RecordSpec::line(b"trace.id=provider-lookalike\0SECRET_PAYLOAD\xff".to_vec())
            .with_metadata(metadata),
        RecordSpec::line(b"trace_id=provider-lookalike SECRET_PAYLOAD".to_vec()),
    ];
    let ledger = ledger(84, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(&blocks);

    assert!(universe.facets().is_empty());
    assert!(universe.edges().is_empty());
    assert!(
        universe
            .annotations()
            .iter()
            .all(|item| item.relations().is_empty() && item.affinities().is_empty())
    );
    assert_eq!(
        universe.accounting().untyped_metadata_event_count_ignored(),
        1
    );
    assert_eq!(universe.accounting().correlation_key_count(), 0);
    assert_ne!(
        ledger.events()[0].source_record_id(),
        ledger.events()[1].source_record_id()
    );
}

#[test]
fn duplicate_native_occurrences_inside_one_atomic_block_are_one_graph_node() {
    let native = b"provider-duplicate-native".to_vec();
    let records = [
        RecordSpec::line(b"Traceback (most recent call last):".to_vec())
            .with_native_id(native.clone()),
        RecordSpec::line(b"  File \"app.py\", line 7, in run".to_vec())
            .with_native_id(native.clone()),
        RecordSpec::line(b"ValueError: bad input".to_vec()).with_native_id(native.clone()),
        RecordSpec::line(b"later provider record".to_vec()).with_native_id(native),
    ];
    let ledger = ledger(85, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(&blocks);
    let trace = blocks.block_for_event(ledger.events()[0].id()).unwrap();

    assert_eq!(blocks.expand_block(trace.id()).unwrap().events().len(), 3);
    assert_eq!(universe.accounting().correlation_key_count(), 1);
    assert_eq!(universe.accounting().graph_node_count(), 2);
    assert_eq!(universe.accounting().emitted_affinity_count(), 2);
    assert_eq!(universe.edges().len(), 1);
    assert_eq!(annotation(&universe, trace.id()).relations().len(), 1);
}

#[test]
fn global_interleaving_does_not_join_or_reorder_distinct_lanes() {
    let records = [
        RecordSpec::line(b"stderr-before".to_vec())
            .with_native_id(b"stderr-native".to_vec())
            .at_monotonic(90),
        RecordSpec::line(b"stdout-between".to_vec())
            .on_stream(FixtureStream::Stdout)
            .with_native_id(b"stderr-native".to_vec())
            .at_monotonic(91),
        RecordSpec::line(b"stderr-after".to_vec())
            .with_native_id(b"stderr-native".to_vec())
            .at_monotonic(92),
    ];
    let ledger = ledger(86, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(&blocks);
    let stderr_before = blocks.block_for_event(ledger.events()[0].id()).unwrap();
    let stdout = blocks.block_for_event(ledger.events()[1].id()).unwrap();
    let stderr_after = blocks.block_for_event(ledger.events()[2].id()).unwrap();

    assert_eq!(universe.facets().len(), 1);
    assert_eq!(universe.edges().len(), 1);
    assert_eq!(universe.edges()[0].earlier_block_id(), stderr_before.id());
    assert_eq!(universe.edges()[0].later_block_id(), stderr_after.id());
    assert!(annotation(&universe, stdout.id()).relations().is_empty());
}

#[test]
fn relation_fanout_bomb_fails_closed_with_typed_needs_more() {
    let shared = attestation(
        21,
        ProviderAttestedRelationKindV1::HostIdentity,
        b"one-overwide-provider-attestation".to_vec(),
    );
    let records = (0..65)
        .map(|ordinal| {
            RecordSpec::line(format!("plain record {ordinal}").into_bytes())
                .with_attestations([shared.clone()])
        })
        .collect::<Vec<_>>();
    let ledger = ledger(87, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();

    let decision = generate_provider_correlations_v1(&blocks).unwrap();
    assert_eq!(
        decision.needs_more().unwrap().reason(),
        CandidateNeedsMoreReasonV1::ProviderRelationFanoutCap
    );
}

#[test]
fn high_degree_bomb_fails_closed_instead_of_truncating_relations() {
    let mut records = Vec::new();
    for ordinal in 0..65 {
        records.push(
            RecordSpec::line(format!("central member {ordinal}").into_bytes()).with_attestations([
                attestation(
                    22,
                    ProviderAttestedRelationKindV1::RequestIdentity,
                    format!("attested-{ordinal:03}").into_bytes(),
                ),
            ]),
        );
    }
    for ordinal in 0..65 {
        records.push(
            RecordSpec::line(format!("outer member {ordinal}").into_bytes()).with_attestations([
                attestation(
                    22,
                    ProviderAttestedRelationKindV1::RequestIdentity,
                    format!("attested-{ordinal:03}").into_bytes(),
                ),
            ]),
        );
    }
    let ledger = ledger(88, &records);
    let mut ranges = Vec::with_capacity(66);
    ranges.push(0..65);
    ranges.extend((65..130).map(|position| position..position + 1));
    let blocks = manual_index(&ledger, &ranges, false);

    let decision = generate_provider_correlations_v1(&blocks).unwrap();
    assert_eq!(
        decision.needs_more().unwrap().reason(),
        CandidateNeedsMoreReasonV1::ProviderGraphDegreeCap
    );
}

#[test]
fn bounded_cycles_are_preserved_as_observed_relations_without_graph_walks() {
    let records = [
        RecordSpec::line(b"a-x".to_vec()).with_native_id(b"x".to_vec()),
        RecordSpec::line(b"a-z".to_vec()).with_native_id(b"z".to_vec()),
        RecordSpec::line(b"b-x".to_vec()).with_native_id(b"x".to_vec()),
        RecordSpec::line(b"b-y".to_vec()).with_native_id(b"y".to_vec()),
        RecordSpec::line(b"c-y".to_vec()).with_native_id(b"y".to_vec()),
        RecordSpec::line(b"c-z".to_vec()).with_native_id(b"z".to_vec()),
    ];
    let ledger = ledger(89, &records);
    let blocks = manual_index(&ledger, &[0..2, 2..4, 4..6], false);
    let universe = ready(&blocks);

    assert_eq!(universe.facets().len(), 3);
    assert_eq!(universe.edges().len(), 3);
    assert_eq!(universe.annotations().len(), 3);
    assert!(
        universe
            .annotations()
            .iter()
            .all(|item| item.relations().len() == 2)
    );
    assert!(universe.edges().iter().all(|edge| edge.hop_depth() == 1));
}

#[test]
fn absent_native_identity_and_empty_input_remain_exhaustive_and_empty() {
    let populated_ledger = ledger(
        90,
        &[
            RecordSpec::line(b"plain one".to_vec()),
            RecordSpec::line(b"plain two".to_vec()),
        ],
    );
    let blocks = frame_source_lanes_v1(&populated_ledger).unwrap();
    let universe = ready(&blocks);
    assert_eq!(universe.annotations().len(), blocks.len());
    assert!(universe.facets().is_empty());
    assert!(universe.edges().is_empty());

    let empty_ledger = ledger(91, &[]);
    let empty_blocks = frame_source_lanes_v1(&empty_ledger).unwrap();
    let empty = ready(&empty_blocks);
    assert!(empty.annotations().is_empty());
    assert!(empty.facets().is_empty());
    assert!(empty.edges().is_empty());
}

#[test]
fn replay_and_assignment_permutation_are_canonical() {
    let shared = attestation(
        23,
        ProviderAttestedRelationKindV1::ServiceIdentity,
        b"shared-service".to_vec(),
    );
    let records = [
        RecordSpec::line(b"first".to_vec())
            .with_native_id(b"shared-a".to_vec())
            .with_attestations([shared.clone()]),
        RecordSpec::line(b"second".to_vec()).with_native_id(b"shared-b".to_vec()),
        RecordSpec::line(b"third".to_vec())
            .with_native_id(b"shared-a".to_vec())
            .with_attestations([shared]),
        RecordSpec::line(b"fourth".to_vec()).with_native_id(b"shared-b".to_vec()),
    ];
    let first_ledger = ledger(92, &records);
    let replay_ledger = ledger(92, &records);
    let ranges = [0..1, 1..2, 2..3, 3..4];
    let first_blocks = manual_index(&first_ledger, &ranges, false);
    let permuted_blocks = manual_index(&first_ledger, &ranges, true);
    let replay_blocks = manual_index(&replay_ledger, &ranges, false);

    assert_eq!(ready(&first_blocks), ready(&permuted_blocks));
    assert_eq!(ready(&first_blocks), ready(&replay_blocks));
}

#[test]
fn debug_and_error_formatting_never_exposes_provider_or_content_canaries() {
    const CANARY: &str = "SECRET_PROVIDER_NATIVE_MEMBER_PAYLOAD_METADATA";
    let metadata = NativeMetadata::new([NativeMetadataField::new(
        CANARY.as_bytes().to_vec(),
        NativeMetadataValue::Text(CANARY.to_owned()),
    )]);
    let records = [
        RecordSpec::line(CANARY.as_bytes().to_vec())
            .on_member(0x5345)
            .with_native_id(CANARY.as_bytes().to_vec())
            .with_attestations([attestation(
                0x53,
                ProviderAttestedRelationKindV1::TraceIdentity,
                CANARY.as_bytes().to_vec(),
            )])
            .with_metadata(metadata.clone()),
        RecordSpec::line(CANARY.as_bytes().to_vec())
            .on_member(0x5345)
            .with_native_id(CANARY.as_bytes().to_vec())
            .with_attestations([attestation(
                0x53,
                ProviderAttestedRelationKindV1::TraceIdentity,
                CANARY.as_bytes().to_vec(),
            )])
            .with_metadata(metadata),
    ];
    let ledger = ledger(93, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let decision = generate_provider_correlations_v1(&blocks).unwrap();
    let rendered = format!(
        "{decision:?} {:?} {:?}",
        CandidateNeedsMoreReasonV1::ProviderGraphDegreeCap,
        evidentrail_candidates::CandidateBuildErrorV1::BlockIndexContractViolation
    );

    assert!(!rendered.contains(CANARY));
    assert!(!rendered.contains("trace_id_SECRET_FIELD"));
    assert!(!rendered.contains("SECRET_METADATA_VALUE"));
}
