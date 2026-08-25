use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    CompletenessProof, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, FetchBoundaries,
    FetchCompleteness, FetchCompletion, FetchIdentity, FetchPartialReason, FetchPartialReasons,
    FetchTiming, FetchUnknownReason, LaneKey, LaneSequence, LedgerBuilder, NeedsMoreReasonV1,
    PassthroughDecision, PatternId, PlanDigest, PlanId, PolicyAuthorization,
    PresentationAssignment, PresentationDisposition, PresentationReceipt, RawEnvelopeIdentityV1,
    RawEnvelopeV1, RecordBytes, RecordState, ResultStatusConstructionError, ResultStatusV1,
    RetrievalId, SourceCursor, SourceIdentityDigest, SourceMember, SourceStream,
    UnixTimestampNanos, WholeRenderAssessmentV1, select_whole_render_passthrough,
};

#[derive(Clone, Copy)]
struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

fn ledger(
    seed: u8,
    completeness: FetchCompleteness,
    payloads: &[&[u8]],
) -> evidentrail_core::EventLedger {
    let retrieval_id = RetrievalId::from_bytes([seed; 32]);
    let plan_id = PlanId::from_bytes([seed.wrapping_add(1); 32]);
    let plan_digest = PlanDigest::from_bytes([seed.wrapping_add(2); 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([seed.wrapping_add(3); 32]);
    let adapter = AdapterIdentity::new("CANARY_STATUS_ADAPTER", "CANARY_STATUS_VERSION").unwrap();
    let identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let lane = LaneKey::new(
        SourceMember::new(b"CANARY_STATUS_MEMBER_/private/log".to_vec()).unwrap(),
        SourceStream::Stderr,
    );
    let mut builder =
        LedgerBuilder::new(identity.clone(), source_identity_digest, SourceExactPolicy);
    let mut source_bytes = 0_u64;
    for (position, payload) in payloads.iter().enumerate() {
        let sequence = u64::try_from(position).unwrap();
        source_bytes += u64::try_from(payload.len()).unwrap();
        builder
            .accept(RawEnvelopeV1::new(
                envelope_identity.clone(),
                EnvelopeOrdering::new(
                    AcquisitionSequence::new(sequence),
                    lane.clone(),
                    LaneSequence::new(sequence),
                ),
                RecordBytes::whole(payload.to_vec()),
                RecordState::Complete,
            ))
            .unwrap();
    }
    let record_count = u64::try_from(payloads.len()).unwrap();
    let completion = FetchCompletion::new(
        identity,
        FetchTiming::new(UnixTimestampNanos::new(1), UnixTimestampNanos::new(2)),
        AcknowledgedCounts::new(record_count, source_bytes, source_bytes),
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

fn complete_ledger(seed: u8) -> evidentrail_core::EventLedger {
    ledger(
        seed,
        FetchCompleteness::complete(CompletenessProof::InMemoryFixtureExhausted),
        &[b"CANARY_STATUS_PAYLOAD_A", b"CANARY_STATUS_PAYLOAD_B"],
    )
}

fn passthrough_selection(ledger: &evidentrail_core::EventLedger) -> evidentrail_core::PassthroughSelection {
    let decision =
        select_whole_render_passthrough(ledger, WholeRenderAssessmentV1::new(42, 42)).unwrap();
    let PassthroughDecision::Selected(selection) = decision else {
        panic!("fixture must fit exact passthrough");
    };
    selection
}

#[test]
fn passthrough_preserves_partial_acquisition_without_upgrading_it() {
    let expected = FetchCompleteness::partial(
        FetchPartialReasons::new(FetchPartialReason::SourceByteCap),
        Some(SourceCursor::new(b"CANARY_STATUS_CURSOR".to_vec()).unwrap()),
    );
    let ledger = ledger(
        1,
        expected.clone(),
        &[b"CANARY_STATUS_PAYLOAD_A", b"CANARY_STATUS_PAYLOAD_B"],
    );

    let status = ResultStatusV1::passthrough(&ledger, passthrough_selection(&ledger)).unwrap();

    assert_eq!(status.contract_version(), 1);
    assert_eq!(status.acquisition(), &expected);
    assert_eq!(status.selection().code(), "passthrough");
    assert!(status.selection().passthrough_selection().is_some());
    assert_eq!(
        status
            .selection()
            .presentation_receipt()
            .counts()
            .shown_verbatim,
        ledger.len()
    );
}

#[test]
fn passthrough_preserves_unknown_acquisition_without_upgrading_it() {
    let expected = FetchCompleteness::unknown(FetchUnknownReason::RetentionUnobservable);
    let ledger = ledger(
        2,
        expected.clone(),
        &[b"CANARY_STATUS_PAYLOAD_A", b"CANARY_STATUS_PAYLOAD_B"],
    );

    let status = ResultStatusV1::passthrough(&ledger, passthrough_selection(&ledger)).unwrap();

    assert_eq!(status.acquisition(), &expected);
    assert_eq!(status.acquisition().code(), "unknown");
    assert_eq!(status.selection().code(), "passthrough");
}

#[test]
fn passthrough_selection_is_revalidated_against_the_target_ledger() {
    let first = complete_ledger(3);
    let other_retrieval = complete_ledger(4);
    let selection = passthrough_selection(&first);

    assert_eq!(
        ResultStatusV1::passthrough(&other_retrieval, selection).unwrap_err(),
        ResultStatusConstructionError::PresentationRetrievalMismatch
    );

    let same_retrieval_different_events = ledger(
        3,
        FetchCompleteness::complete(CompletenessProof::InMemoryFixtureExhausted),
        &[b"different-a", b"different-b"],
    );
    let selection = passthrough_selection(&first);
    assert_eq!(
        ResultStatusV1::passthrough(&same_retrieval_different_events, selection).unwrap_err(),
        ResultStatusConstructionError::PresentationEventOrderMismatch
    );
}

#[test]
fn compiled_requires_exhaustive_non_passthrough_presentation() {
    let ledger = complete_ledger(5);
    let first = ledger.events()[0].id();
    let second = ledger.events()[1].id();
    let compiled_receipt = PresentationReceipt::reconcile(
        &ledger,
        [
            PresentationAssignment::new(first, PresentationDisposition::ShownVerbatim),
            PresentationAssignment::new(second, PresentationDisposition::RetainedRaw),
        ],
    )
    .unwrap();

    let status = ResultStatusV1::compiled(&ledger, compiled_receipt).unwrap();
    assert_eq!(status.selection().code(), "compiled");
    assert_eq!(
        status.selection().presentation_receipt().persisted_count(),
        2
    );
    assert_eq!(
        status
            .selection()
            .presentation_receipt()
            .unaccounted_count(),
        0
    );

    let all_shown = PresentationReceipt::reconcile(
        &ledger,
        ledger.events().iter().map(|event| {
            PresentationAssignment::new(event.id(), PresentationDisposition::ShownVerbatim)
        }),
    )
    .unwrap();
    assert_eq!(
        ResultStatusV1::compiled(&ledger, all_shown).unwrap_err(),
        ResultStatusConstructionError::CompiledMasqueradesAsPassthrough
    );

    let all_retained = PresentationReceipt::reconcile(
        &ledger,
        ledger.events().iter().map(|event| {
            PresentationAssignment::new(event.id(), PresentationDisposition::RetainedRaw)
        }),
    )
    .unwrap();
    assert_eq!(
        ResultStatusV1::compiled(&ledger, all_retained).unwrap_err(),
        ResultStatusConstructionError::CompiledHasNoPresentedEvidence
    );
}

#[test]
fn pattern_representation_is_a_valid_non_passthrough_compilation() {
    let ledger = complete_ledger(6);
    let receipt = PresentationReceipt::reconcile(
        &ledger,
        [
            PresentationAssignment::new(
                ledger.events()[0].id(),
                PresentationDisposition::PatternRepresented {
                    pattern_id: PatternId::from_bytes([0x41; 32]),
                },
            ),
            PresentationAssignment::new(
                ledger.events()[1].id(),
                PresentationDisposition::RetainedRaw,
            ),
        ],
    )
    .unwrap();

    let status = ResultStatusV1::compiled(&ledger, receipt).unwrap();
    assert_eq!(status.selection().code(), "compiled");
    assert_eq!(
        status
            .selection()
            .presentation_receipt()
            .counts()
            .pattern_represented,
        1
    );
}

#[test]
fn needs_more_has_typed_reason_and_all_retained_raw_accounting() {
    let expected = FetchCompleteness::partial(
        FetchPartialReasons::new(FetchPartialReason::Cancelled),
        None,
    );
    let ledger = ledger(
        7,
        expected.clone(),
        &[b"CANARY_STATUS_PAYLOAD_A", b"CANARY_STATUS_PAYLOAD_B"],
    );
    let reason = NeedsMoreReasonV1::MandatoryEvidenceExceedsBudget;

    let status = ResultStatusV1::needs_more(&ledger, reason).unwrap();
    let receipt = status.selection().presentation_receipt();
    assert_eq!(status.acquisition(), &expected);
    assert_eq!(status.selection().code(), "needs_more");
    assert_eq!(status.selection().needs_more_reason(), Some(reason));
    assert_eq!(receipt.persisted_count(), ledger.len());
    assert_eq!(receipt.unaccounted_count(), 0);
    assert_eq!(receipt.counts().shown_verbatim, 0);
    assert_eq!(receipt.counts().pattern_represented, 0);
    assert_eq!(receipt.counts().retained_raw, ledger.len());
    assert!(
        receipt
            .entries()
            .iter()
            .all(|entry| entry.disposition() == &PresentationDisposition::RetainedRaw)
    );
}

#[test]
fn status_reason_and_errors_format_without_content_or_provenance() {
    let expected = FetchCompleteness::partial(
        FetchPartialReasons::new(FetchPartialReason::SourceReadError),
        Some(SourceCursor::new(b"CANARY_STATUS_CURSOR".to_vec()).unwrap()),
    );
    let ledger = ledger(
        8,
        expected,
        &[b"CANARY_STATUS_PAYLOAD_A", b"CANARY_STATUS_PAYLOAD_B"],
    );
    let reason = NeedsMoreReasonV1::OtherVersioned {
        version: 54_321,
        code: 12_345,
    };
    let status = ResultStatusV1::needs_more(&ledger, reason).unwrap();
    let outputs = [
        format!("{status:?}"),
        format!("{:?}", status.selection()),
        format!("{reason:?}"),
        format!(
            "{:?}",
            ResultStatusConstructionError::PresentationEventOrderMismatch
        ),
        ResultStatusConstructionError::PresentationEventOrderMismatch.to_string(),
    ];
    let event_token = ledger.events()[0].id().to_string();

    for output in outputs {
        for canary in [
            "CANARY_STATUS_PAYLOAD",
            "CANARY_STATUS_CURSOR",
            "CANARY_STATUS_MEMBER",
            "CANARY_STATUS_ADAPTER",
            "54321",
            "12345",
            event_token.as_str(),
        ] {
            assert!(!output.contains(canary));
        }
    }
    assert_eq!(reason.code(), "other_versioned");
    assert_eq!(
        ResultStatusConstructionError::PresentationEventOrderMismatch.code(),
        "EVIDENTRAIL_RESULT_STATUS_PRESENTATION_EVENT_ORDER_MISMATCH"
    );
}
