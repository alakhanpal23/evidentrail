use evidentrail_bench::{
    CandidateResourceCap, CandidateResourceDimension, CandidateResourceError,
    MeasuredCandidateResources, candidate_resource_envelope, cost_pareto_dominates,
};
use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    CompletenessProof, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, EventLedger,
    FetchBoundaries, FetchCompleteness, FetchCompletion, FetchIdentity, FetchTiming, LaneKey,
    LaneSequence, LedgerBuilder, PlanDigest, PlanId, PolicyAuthorization, RawEnvelopeIdentityV1,
    RawEnvelopeV1, RecordBytes, RecordState, RetrievalId, SourceIdentityDigest, SourceMember,
    SourceStream, UnixTimestampNanos,
};

struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

fn ledger(raw_events: &[&[u8]]) -> EventLedger {
    let retrieval_id = RetrievalId::from_bytes([81; 32]);
    let plan_id = PlanId::from_bytes([82; 32]);
    let plan_digest = PlanDigest::from_bytes([83; 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([84; 32]);
    let adapter = AdapterIdentity::new("candidate-resource-fixture", "1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let lane = LaneKey::new(
        SourceMember::new(b"candidate-resource-member".to_vec()).unwrap(),
        SourceStream::OtherVersioned {
            version: 1,
            code: 3,
        },
    );
    let mut builder = LedgerBuilder::new(
        fetch_identity.clone(),
        source_identity_digest,
        SourceExactPolicy,
    );
    let mut source_bytes = 0_u64;

    for (position, raw) in raw_events.iter().enumerate() {
        let sequence = u64::try_from(position).unwrap();
        source_bytes = source_bytes
            .checked_add(u64::try_from(raw.len()).unwrap())
            .unwrap();
        builder
            .accept(RawEnvelopeV1::new(
                envelope_identity.clone(),
                EnvelopeOrdering::new(
                    AcquisitionSequence::new(sequence),
                    lane.clone(),
                    LaneSequence::new(sequence),
                ),
                RecordBytes::whole(raw.to_vec()),
                RecordState::Complete,
            ))
            .unwrap();
    }

    let records = u64::try_from(raw_events.len()).unwrap();
    let completion = FetchCompletion::new(
        fetch_identity,
        FetchTiming::new(UnixTimestampNanos::new(0), UnixTimestampNanos::new(1)),
        AcknowledgedCounts::new(records, source_bytes, source_bytes),
        AttemptCounts::new(1, 1),
        AttemptCounts::default(),
        FetchBoundaries::default(),
        [],
        AdapterOutcome::Finished,
        [],
        FetchCompleteness::complete(CompletenessProof::OtherVersioned {
            version: 1,
            code: 3,
        }),
    )
    .unwrap();
    builder.seal(completion).unwrap()
}

fn measurements(tokens: u128, wall_time: u128, peak_memory: u128) -> MeasuredCandidateResources {
    MeasuredCandidateResources::try_new(tokens, wall_time, peak_memory).unwrap()
}

#[test]
fn duplicate_references_are_free_but_duplicate_payload_occurrences_are_charged() {
    let ledger = ledger(&[b"same", b"same", b"longer"]);
    let first = ledger.events()[0].id();
    let second = ledger.events()[1].id();
    let cost = candidate_resource_envelope(
        &ledger,
        &[first, first, second, second],
        measurements(7, 11, 13),
    )
    .unwrap();

    assert_eq!(cost.unique_candidate_event_count(), 2);
    assert_eq!(cost.unique_candidate_source_bytes(), 8);
    assert_eq!(cost.canonical_candidate_tokens(), 7);
    assert_eq!(cost.wall_time_nanos(), 11);
    assert_eq!(cost.peak_memory_bytes(), 13);
}

#[test]
fn every_cap_dimension_can_fail_independently() {
    let ledger = ledger(&[b"same", b"same"]);
    let ids = ledger
        .events()
        .iter()
        .map(|event| event.id())
        .collect::<Vec<_>>();
    let cost = candidate_resource_envelope(&ledger, &ids, measurements(7, 11, 13)).unwrap();
    let exact = CandidateResourceCap::try_new(2, 8, 7, 11, 13).unwrap();
    assert_eq!(exact.check(cost), Ok(()));

    let cases = [
        (
            CandidateResourceCap::try_new(1, 8, 7, 11, 13).unwrap(),
            CandidateResourceDimension::UniqueCandidateEventCount,
        ),
        (
            CandidateResourceCap::try_new(2, 7, 7, 11, 13).unwrap(),
            CandidateResourceDimension::UniqueCandidateSourceBytes,
        ),
        (
            CandidateResourceCap::try_new(2, 8, 6, 11, 13).unwrap(),
            CandidateResourceDimension::CanonicalCandidateTokens,
        ),
        (
            CandidateResourceCap::try_new(2, 8, 7, 10, 13).unwrap(),
            CandidateResourceDimension::WallTimeNanos,
        ),
        (
            CandidateResourceCap::try_new(2, 8, 7, 11, 12).unwrap(),
            CandidateResourceDimension::PeakMemoryBytes,
        ),
    ];

    for (cap, expected) in cases {
        let violations = cap.check(cost).unwrap_err();
        assert_eq!(violations.dimensions(), &[expected]);
        assert_eq!(violations.len(), 1);
        assert!(!violations.is_empty());
        assert!(violations.contains(expected));
        assert_eq!(
            violations.to_string(),
            "EVIDENTRAIL_BENCH_CANDIDATE_RESOURCE_CAP_VIOLATED"
        );
    }
}

#[test]
fn pareto_dominance_is_cost_only_strict_and_not_scalarized() {
    let ledger = ledger(&[b"candidate"]);
    let id = ledger.events()[0].id();
    let equal_left = candidate_resource_envelope(&ledger, &[id], measurements(7, 11, 13)).unwrap();
    let equal_right = candidate_resource_envelope(&ledger, &[id], measurements(7, 11, 13)).unwrap();
    assert!(!cost_pareto_dominates(equal_left, equal_right));
    assert!(!equal_left.pareto_dominates(equal_right));

    let cheaper = candidate_resource_envelope(&ledger, &[id], measurements(6, 11, 13)).unwrap();
    assert!(cost_pareto_dominates(cheaper, equal_right));
    assert!(!cost_pareto_dominates(equal_right, cheaper));

    let token_time_tradeoff =
        candidate_resource_envelope(&ledger, &[id], measurements(5, 12, 13)).unwrap();
    assert!(!cost_pareto_dominates(token_time_tradeoff, equal_right));
    assert!(!cost_pareto_dominates(equal_right, token_time_tradeoff));
}

#[test]
fn checked_construction_reports_typed_contentless_overflow() {
    let overflows = [
        (
            CandidateResourceCap::try_new(u128::MAX, 0, 0, 0, 0).unwrap_err(),
            CandidateResourceError::CandidateEventCountOverflow,
        ),
        (
            CandidateResourceCap::try_new(0, u128::MAX, 0, 0, 0).unwrap_err(),
            CandidateResourceError::UniqueCandidateSourceBytesOverflow,
        ),
        (
            CandidateResourceCap::try_new(0, 0, u128::MAX, 0, 0).unwrap_err(),
            CandidateResourceError::CanonicalTokenCountOverflow,
        ),
        (
            CandidateResourceCap::try_new(0, 0, 0, u128::MAX, 0).unwrap_err(),
            CandidateResourceError::WallTimeNanosOverflow,
        ),
        (
            CandidateResourceCap::try_new(0, 0, 0, 0, u128::MAX).unwrap_err(),
            CandidateResourceError::PeakMemoryBytesOverflow,
        ),
    ];
    for (actual, expected) in overflows {
        assert_eq!(actual, expected);
        assert!(!format!("{actual:?}").contains("CANARY_SECRET"));
        assert!(!actual.to_string().contains("CANARY_SECRET"));
    }

    assert_eq!(
        MeasuredCandidateResources::try_new(u128::MAX, 0, 0).unwrap_err(),
        CandidateResourceError::CanonicalTokenCountOverflow
    );
    assert_eq!(
        MeasuredCandidateResources::try_new(0, u128::MAX, 0).unwrap_err(),
        CandidateResourceError::WallTimeNanosOverflow
    );
    assert_eq!(
        MeasuredCandidateResources::try_new(0, 0, u128::MAX).unwrap_err(),
        CandidateResourceError::PeakMemoryBytesOverflow
    );
}

#[test]
fn unknown_candidate_and_cap_diagnostics_do_not_leak_payload() {
    let ledger = ledger(&[b"CANARY_SECRET_PAYLOAD"]);
    let unknown = evidentrail_core::EventId::from_bytes([99; 32]);
    let error =
        candidate_resource_envelope(&ledger, &[unknown], measurements(1, 1, 1)).unwrap_err();
    assert_eq!(
        error,
        CandidateResourceError::UnknownCandidateEvent { count: 1 }
    );
    assert_eq!(
        error.to_string(),
        "EVIDENTRAIL_BENCH_RESOURCE_UNKNOWN_CANDIDATE_EVENT"
    );
    assert!(!format!("{error:?}").contains("CANARY_SECRET_PAYLOAD"));

    let id = ledger.events()[0].id();
    let cost = candidate_resource_envelope(&ledger, &[id], measurements(1, 1, 1)).unwrap();
    let violations = CandidateResourceCap::try_new(0, 0, 0, 0, 0)
        .unwrap()
        .check(cost)
        .unwrap_err();
    assert_eq!(violations.dimensions().len(), 5);
    assert!(!format!("{violations:?}").contains("CANARY_SECRET_PAYLOAD"));
}
