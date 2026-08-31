use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    CompletenessProof, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, FetchBoundaries,
    FetchCompleteness, FetchCompletion, FetchIdentity, FetchTiming, LaneKey, LaneSequence,
    LedgerBuilder, PlanDigest, PlanId, PolicyAuthorization, RawEnvelopeIdentityV1, RawEnvelopeV1,
    RecordBytes, RecordState, RetrievalId, SourceIdentityDigest, SourceMember, SourceStream,
    UnixTimestampNanos,
};
use evidentrail_product::{StreamingAnalysisContextV3, StreamingLaneContextV3, StreamingProductV3};
use evidentrail_schema::ResultId;
use evidentrail_store::{
    PackedMemoryEventStoreV3, RetainedAcquisitionFinishV3, RetainedEventInputV3,
    RetainedEventStoreV3, RetainedStoreBeginV3,
};

#[derive(Clone, Copy)]
struct SourceExact;

impl DeterministicPolicy for SourceExact {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

#[test]
fn multi_lane_partitions_end_at_v1_atomic_block_boundaries() {
    let retrieval_id = RetrievalId::from_bytes([1; 32]);
    let plan_id = PlanId::from_bytes([2; 32]);
    let plan_digest = PlanDigest::from_bytes([3; 32]);
    let source_digest = SourceIdentityDigest::from_bytes([4; 32]);
    let adapter = AdapterIdentity::new("streaming-v3-multi-lane", "v1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity =
        RawEnvelopeIdentityV1::new(retrieval_id, plan_id, plan_digest, adapter, source_digest);
    let lane_a = LaneKey::new(
        SourceMember::new(b"app".to_vec()).unwrap(),
        SourceStream::Stderr,
    );
    let lane_b = LaneKey::new(
        SourceMember::new(b"sidecar".to_vec()).unwrap(),
        SourceStream::LogStream,
    );
    let mut records = (0..4_095)
        .map(|ordinal| {
            (
                0u64,
                ordinal,
                format!("INFO ordinal={ordinal}\n").into_bytes(),
            )
        })
        .collect::<Vec<_>>();
    records.extend([
        (0, 4_095, b"Traceback (most recent call last):\n".to_vec()),
        (0, 4_096, b"  File \"main.py\", line 9\n".to_vec()),
        (0, 4_097, b"ValueError: request-id-atomic\n".to_vec()),
        (0, 4_098, b"INFO after atomic block\n".to_vec()),
        (0, 4_099, b"INFO final app line\n".to_vec()),
    ]);
    // Acquisition order deliberately interleaves the lanes; lane scans must
    // still reconstruct each source lane by its independent sequence.
    records.insert(100, (1, 0, b"sidecar ready\n".to_vec()));
    records.insert(2_000, (1, 1, b"sidecar healthy\n".to_vec()));

    let mut builder = LedgerBuilder::new(fetch_identity.clone(), source_digest, SourceExact);
    let mut payload_bytes = 0u64;
    let mut source_bytes = 0u64;
    for (acquisition, (lane, sequence, exact)) in records.iter().enumerate() {
        let payload_len = exact.len() - 1;
        payload_bytes += payload_len as u64;
        source_bytes += exact.len() as u64;
        builder
            .accept(RawEnvelopeV1::new(
                envelope_identity.clone(),
                EnvelopeOrdering::new(
                    AcquisitionSequence::new(acquisition as u64),
                    if *lane == 0 {
                        lane_a.clone()
                    } else {
                        lane_b.clone()
                    },
                    LaneSequence::new(*sequence),
                ),
                RecordBytes::framed(exact[..payload_len].to_vec(), b"\n".to_vec()),
                RecordState::Complete,
            ))
            .unwrap();
    }
    let completion = FetchCompletion::new(
        fetch_identity.clone(),
        FetchTiming::new(UnixTimestampNanos::new(1), UnixTimestampNanos::new(2)),
        AcknowledgedCounts::new(records.len() as u64, payload_bytes, source_bytes),
        AttemptCounts::new(2, 2),
        AttemptCounts::default(),
        FetchBoundaries::default(),
        [],
        AdapterOutcome::Finished,
        [],
        FetchCompleteness::complete(CompletenessProof::InMemoryFixtureExhausted),
    )
    .unwrap();
    let ledger = builder.seal(completion.clone()).unwrap();

    let result_id = ResultId::from_bytes([9; 32]);
    let mut store = PackedMemoryEventStoreV3::new();
    store
        .begin(RetainedStoreBeginV3 {
            result_id,
            namespace: [10; 32],
            created_unix_nanos: 1,
            expires_unix_nanos: 100,
        })
        .unwrap();
    for event in ledger.events() {
        let lane_ordinal = if event.lane() == &lane_a { 0 } else { 1 };
        store
            .append(RetainedEventInputV3 {
                event_id: event.id(),
                acquisition_ordinal: event.acquisition_sequence().get(),
                lane_ordinal,
                lane_sequence: event.lane_sequence().get(),
                payload_len: event.payload().len() as u32,
                terminator_len: event.terminator().map_or(0, |value| value.len() as u8),
                exact_bytes: event.raw(),
            })
            .unwrap();
    }
    let manifest = store
        .finish_acquisition(RetainedAcquisitionFinishV3 {
            record_count: records.len() as u64,
            payload_byte_count: payload_bytes,
            source_byte_count: source_bytes,
            input_digest: [11; 32],
            completion_digest: [12; 32],
        })
        .unwrap();
    let context = StreamingAnalysisContextV3::new_multi_lane(
        fetch_identity,
        source_digest,
        vec![
            StreamingLaneContextV3::new(lane_a, envelope_identity.clone()),
            StreamingLaneContextV3::new(lane_b, envelope_identity),
        ],
        completion,
    );
    let mut product = StreamingProductV3::new(store);
    product
        .compile_store(
            result_id,
            b"request-id-atomic ValueError",
            &context,
            manifest,
            UnixTimestampNanos::new(3),
            100_000,
        )
        .unwrap();
    let plan = product.last_analysis_plan().expect("analysis completed");
    assert_eq!(plan.partition_count(), 2);
    assert_eq!(plan.source_block_count(), records.len() - 2);
    assert!(plan.projected_event_count() >= 3);
}
