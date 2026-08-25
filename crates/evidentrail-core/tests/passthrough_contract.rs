use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    CompletenessProof, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, FetchBoundaries,
    FetchCompleteness, FetchCompletion, FetchIdentity, FetchPartialReason, FetchPartialReasons,
    FetchTiming, LaneKey, LaneSequence, LedgerBuilder, PassthroughDecision,
    PassthroughSelectionError, PlanDigest, PlanId, PolicyAuthorization, PresentationDisposition,
    RawEnvelopeIdentityV1, RawEnvelopeV1, RecordBytes, RecordState, RetrievalId,
    SourceIdentityDigest, SourceMember, SourceStream, UnixTimestampNanos, WholeRenderAssessmentV1,
    select_whole_render_passthrough,
};

#[derive(Clone, Copy)]
struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

fn ledger(completeness: FetchCompleteness) -> evidentrail_core::EventLedger {
    let retrieval_id = RetrievalId::from_bytes([1; 32]);
    let plan_id = PlanId::from_bytes([2; 32]);
    let plan_digest = PlanDigest::from_bytes([3; 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([4; 32]);
    let adapter = AdapterIdentity::new("fixture", "1").unwrap();
    let identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let lane = LaneKey::new(
        SourceMember::new(b"approved-member".to_vec()).unwrap(),
        SourceStream::Stderr,
    );
    let mut builder =
        LedgerBuilder::new(identity.clone(), source_identity_digest, SourceExactPolicy);
    for sequence in 0..2 {
        builder
            .accept(RawEnvelopeV1::new(
                envelope_identity.clone(),
                EnvelopeOrdering::new(
                    AcquisitionSequence::new(sequence),
                    lane.clone(),
                    LaneSequence::new(sequence),
                ),
                RecordBytes::whole(vec![b'a' + u8::try_from(sequence).unwrap()]),
                RecordState::Complete,
            ))
            .unwrap();
    }
    let completion = FetchCompletion::new(
        identity,
        FetchTiming::new(UnixTimestampNanos::new(1), UnixTimestampNanos::new(2)),
        AcknowledgedCounts::new(2, 2, 2),
        AttemptCounts::new(1, 1),
        AttemptCounts::default(),
        FetchBoundaries::default(),
        [],
        AdapterOutcome::Finished,
        [],
        completeness,
    )
    .unwrap();
    builder.seal(completion).unwrap()
}

fn complete_ledger() -> evidentrail_core::EventLedger {
    ledger(FetchCompleteness::complete(
        CompletenessProof::InMemoryFixtureExhausted,
    ))
}

#[test]
fn exact_whole_render_at_budget_is_selected_and_exhaustively_shown() {
    let ledger = complete_ledger();
    let assessment = WholeRenderAssessmentV1::new(15, 15);
    let decision = select_whole_render_passthrough(&ledger, assessment).unwrap();
    let PassthroughDecision::Selected(selection) = decision else {
        panic!("complete fitting render must use exact passthrough");
    };

    assert_eq!(selection.assessment(), assessment);
    assert_eq!(selection.presentation_receipt().persisted_count(), 2);
    assert_eq!(selection.presentation_receipt().counts().shown_verbatim, 2);
    assert!(
        selection
            .presentation_receipt()
            .entries()
            .iter()
            .all(|entry| entry.disposition() == &PresentationDisposition::ShownVerbatim)
    );
}

#[test]
fn partial_acquisition_can_still_pass_through_every_persisted_event() {
    let ledger = ledger(FetchCompleteness::partial(
        FetchPartialReasons::new(FetchPartialReason::Cancelled),
        None,
    ));
    let decision =
        select_whole_render_passthrough(&ledger, WholeRenderAssessmentV1::new(9, 10)).unwrap();

    assert!(matches!(decision, PassthroughDecision::Selected(_)));
    assert!(matches!(
        ledger.fetch_completion().completeness(),
        FetchCompleteness::Partial { .. }
    ));
}

#[test]
fn one_token_over_routes_to_compilation_without_constructing_a_selection() {
    let ledger = complete_ledger();
    let assessment = WholeRenderAssessmentV1::new(15, 14);
    let decision = select_whole_render_passthrough(&ledger, assessment).unwrap();

    let PassthroughDecision::CompilationRequired(returned) = decision else {
        panic!("oversized whole render must route to compilation");
    };
    assert_eq!(returned, assessment);
    assert!(!returned.fits());
}

#[test]
fn zero_budget_is_compilation_not_a_false_fixed_overhead_claim() {
    let ledger = complete_ledger();
    let decision =
        select_whole_render_passthrough(&ledger, WholeRenderAssessmentV1::new(1, 0)).unwrap();

    assert!(matches!(
        decision,
        PassthroughDecision::CompilationRequired(_)
    ));
}

#[test]
fn whole_render_assessment_and_errors_are_contentless() {
    let ledger = complete_ledger();
    let event_token = ledger.events()[0].id().to_string();
    let decision =
        select_whole_render_passthrough(&ledger, WholeRenderAssessmentV1::new(10, 10)).unwrap();

    assert!(!format!("{decision:?}").contains(&event_token));
    assert_eq!(
        PassthroughSelectionError::PresentationInvariantViolation.to_string(),
        "EVIDENTRAIL_PASSTHROUGH_PRESENTATION_INVARIANT_VIOLATION"
    );
}
