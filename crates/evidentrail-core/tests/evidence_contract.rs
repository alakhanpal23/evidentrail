use evidentrail_core::{
    AcknowledgedCounts, AcquisitionOutcome, AcquisitionSequence, AdapterIdentity, AdapterOutcome,
    AttemptCounts, CompletenessProof, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, EventId,
    ExactnessBasis, FetchBoundaries, FetchCompleteness, FetchCompletion, FetchIdentity,
    FetchPartialReason, FetchPartialReasons, FetchTiming, LaneKey, LaneSequence, LedgerBuildError,
    LedgerBuilder, LedgerLookupError, NativeEventId, PartialReason, PatternId, PlanDigest, PlanId,
    PolicyAuthorization, PolicyDigest, PresentationAssignment, PresentationDisposition,
    PresentationReceipt, PresentationReconciliationError, ProviderCompleteness,
    RawEnvelopeIdentityV1, RawEnvelopeV1, RecordBytes, RecordFragmentReason, RecordState,
    RetrievalId, SourceCursor, SourceIdentityDigest, SourceMember, SourceStream,
    TransformationReceiptId, UnixTimestampNanos,
};

fn retrieval_id(seed: u8) -> RetrievalId {
    RetrievalId::from_bytes([seed; 32])
}

fn source_digest(seed: u8) -> SourceIdentityDigest {
    SourceIdentityDigest::from_bytes([seed; 32])
}

fn adapter() -> AdapterIdentity {
    AdapterIdentity::new("replay", "1.0.0").unwrap()
}

fn fetch_identity(seed: u8) -> FetchIdentity {
    FetchIdentity::new(
        retrieval_id(seed),
        PlanId::from_bytes([seed.wrapping_add(1); 32]),
        PlanDigest::from_bytes([seed.wrapping_add(2); 32]),
        adapter(),
    )
}

#[allow(clippy::too_many_arguments)]
fn envelope(
    identity: &FetchIdentity,
    source_identity_digest: SourceIdentityDigest,
    acquisition_sequence: u64,
    member: &[u8],
    stream: SourceStream,
    lane_sequence: u64,
    record: RecordBytes,
    state: RecordState,
) -> RawEnvelopeV1 {
    RawEnvelopeV1::new(
        RawEnvelopeIdentityV1::new(
            identity.retrieval_id(),
            identity.plan_id(),
            identity.plan_digest(),
            identity.adapter().clone(),
            source_identity_digest,
        ),
        EnvelopeOrdering::new(
            AcquisitionSequence::new(acquisition_sequence),
            LaneKey::new(SourceMember::new(member.to_vec()).unwrap(), stream),
            LaneSequence::new(lane_sequence),
        ),
        record,
        state,
    )
}

fn completion(
    identity: FetchIdentity,
    counts: AcknowledgedCounts,
    completeness: FetchCompleteness,
) -> FetchCompletion {
    let attempted_members = u64::from(counts.records() > 0);
    FetchCompletion::new(
        identity,
        FetchTiming::new(UnixTimestampNanos::new(100), UnixTimestampNanos::new(200)),
        counts,
        AttemptCounts::new(attempted_members, attempted_members),
        AttemptCounts::default(),
        FetchBoundaries::default(),
        [],
        AdapterOutcome::Finished,
        [],
        completeness,
    )
    .unwrap()
}

fn complete(identity: FetchIdentity, records: u64, payload: u64, source: u64) -> FetchCompletion {
    completion(
        identity,
        AcknowledgedCounts::new(records, payload, source),
        FetchCompleteness::complete(CompletenessProof::ReplayManifestVerified),
    )
}

#[derive(Clone, Copy)]
struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

#[derive(Clone)]
struct ReplacePolicy {
    record: RecordBytes,
    policy_digest: PolicyDigest,
    transformation_receipt_id: TransformationReceiptId,
}

impl DeterministicPolicy for ReplacePolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::PostPolicy {
            authorized_record: self.record.clone(),
            policy_digest: self.policy_digest,
            transformation_receipt_id: self.transformation_receipt_id,
        }
    }
}

#[derive(Clone, Copy)]
struct OmitPolicy {
    policy_digest: PolicyDigest,
}

impl DeterministicPolicy for OmitPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::OmittedByPolicy {
            policy_digest: self.policy_digest,
        }
    }
}

#[test]
fn source_exact_invalid_utf8_and_framing_are_preserved_byte_for_byte() {
    let identity = fetch_identity(1);
    let source = source_digest(10);
    let payload = vec![0xff, 0xfe, 0x00, b'e', b'r', b'r'];
    let terminator = b"\r\n".to_vec();
    let mut builder = LedgerBuilder::new(identity.clone(), source, SourceExactPolicy);
    let ack = builder
        .accept(envelope(
            &identity,
            source,
            0,
            b"stderr",
            SourceStream::Stderr,
            0,
            RecordBytes::framed(payload.clone(), terminator.clone()),
            RecordState::Complete,
        ))
        .unwrap();
    let ledger = builder
        .seal(complete(
            identity,
            1,
            u64::try_from(payload.len()).unwrap(),
            u64::try_from(payload.len() + terminator.len()).unwrap(),
        ))
        .unwrap();
    let event = &ledger.events()[0];

    assert_eq!(ack.authorized_byte_count(), 8);
    assert_eq!(ack.outcome().persisted_event_id(), Some(event.id()));
    assert_eq!(event.payload(), payload);
    assert_eq!(event.terminator(), Some(terminator.as_slice()));
    assert_eq!(event.raw(), [payload, terminator].concat());
    assert_eq!(event.exactness_basis(), ExactnessBasis::SourceExact);
    assert!(event.content_matches(event.raw()));
    assert_eq!(ledger.exact_bytes(event.id()).unwrap(), event.raw());
}

#[test]
fn post_policy_hash_and_identity_commit_only_to_authorized_bytes() {
    const ORIGINAL: &[u8] = b"SECRET original token=abc";
    const AUTHORIZED: &[u8] = b"token=[redacted]";
    let identity = fetch_identity(2);
    let source = source_digest(11);
    let policy_digest = PolicyDigest::from_bytes([31; 32]);
    let transformation_receipt_id = TransformationReceiptId::from_bytes([32; 32]);
    let policy = ReplacePolicy {
        record: RecordBytes::whole(AUTHORIZED.to_vec()),
        policy_digest,
        transformation_receipt_id,
    };
    let mut builder = LedgerBuilder::new(identity.clone(), source, policy);
    let ack = builder
        .accept(envelope(
            &identity,
            source,
            0,
            b"api",
            SourceStream::LogStream,
            0,
            RecordBytes::whole(ORIGINAL.to_vec()),
            RecordState::Complete,
        ))
        .unwrap();
    let ledger = builder
        .seal(complete(
            identity,
            1,
            u64::try_from(ORIGINAL.len()).unwrap(),
            u64::try_from(ORIGINAL.len()).unwrap(),
        ))
        .unwrap();
    let event = &ledger.events()[0];

    assert_eq!(ack.authorized_byte_count(), 16);
    assert_eq!(event.raw(), AUTHORIZED);
    assert!(event.content_matches(AUTHORIZED));
    assert!(!event.content_matches(ORIGINAL));
    assert_eq!(
        event.exactness_basis(),
        ExactnessBasis::PostPolicy {
            policy_digest,
            transformation_receipt_id,
        }
    );
    assert!(!format!("{event:?}").contains(std::str::from_utf8(ORIGINAL).unwrap()));
}

#[test]
fn omitted_payload_is_neither_retained_nor_content_committed() {
    let identity = fetch_identity(3);
    let source = source_digest(12);
    let policy_digest = PolicyDigest::from_bytes([44; 32]);
    let build = |payload: &[u8]| {
        let mut builder =
            LedgerBuilder::new(identity.clone(), source, OmitPolicy { policy_digest });
        let ack = builder
            .accept(envelope(
                &identity,
                source,
                0,
                b"member",
                SourceStream::FileMember,
                0,
                RecordBytes::whole(payload.to_vec()),
                RecordState::Complete,
            ))
            .unwrap();
        let ledger = builder
            .seal(complete(
                identity.clone(),
                1,
                u64::try_from(payload.len()).unwrap(),
                u64::try_from(payload.len()).unwrap(),
            ))
            .unwrap();
        (ack, ledger)
    };

    let (first_ack, first) = build(b"secret payload one");
    let (second_ack, second) = build(b"completely different secret payload two");

    assert_eq!(first_ack.authorized_byte_count(), 0);
    assert!(matches!(
        first_ack.outcome(),
        AcquisitionOutcome::OmittedByPolicy { .. }
    ));
    assert_eq!(first_ack.source_record_id(), second_ack.source_record_id());
    assert!(first.events().is_empty());
    assert!(second.events().is_empty());
    assert_eq!(first.acquisition_receipt(), second.acquisition_receipt());
    assert_eq!(first.acquisition_receipt().counts().omitted_by_policy, 1);
}

#[test]
fn duplicate_payloads_share_authorized_hash_but_keep_distinct_source_and_event_ids() {
    let identity = fetch_identity(4);
    let source = source_digest(13);
    let mut builder = LedgerBuilder::new(identity.clone(), source, SourceExactPolicy);
    for sequence in 0..2 {
        builder
            .accept(envelope(
                &identity,
                source,
                sequence,
                b"member",
                SourceStream::Stdout,
                sequence,
                RecordBytes::whole(b"same payload".to_vec()),
                RecordState::Complete,
            ))
            .unwrap();
    }
    let ledger = builder.seal(complete(identity, 2, 24, 24)).unwrap();
    let first = &ledger.events()[0];
    let second = &ledger.events()[1];

    assert_eq!(first.content_hash(), second.content_hash());
    assert_ne!(first.source_record_id(), second.source_record_id());
    assert_ne!(first.id(), second.id());
    assert_eq!(first.ordinal(), 0);
    assert_eq!(second.ordinal(), 1);
}

#[test]
fn source_record_and_event_replay_are_deterministic_and_retrieval_local() {
    let build = |seed| {
        let identity = fetch_identity(seed);
        let source = source_digest(14);
        let mut builder = LedgerBuilder::new(identity.clone(), source, SourceExactPolicy);
        let envelope = envelope(
            &identity,
            source,
            0,
            b"member",
            SourceStream::Journal,
            0,
            RecordBytes::whole(b"same".to_vec()),
            RecordState::Complete,
        )
        .with_native_event_id(NativeEventId::new(b"native".to_vec()).unwrap())
        .with_cursor(SourceCursor::new(b"cursor".to_vec()).unwrap());
        let ack = builder.accept(envelope).unwrap();
        let ledger = builder.seal(complete(identity, 1, 4, 4)).unwrap();
        (ack, ledger)
    };

    let (first_ack, first) = build(5);
    let (replay_ack, replay) = build(5);
    let (other_ack, other) = build(6);

    assert_eq!(first_ack.source_record_id(), replay_ack.source_record_id());
    assert_eq!(first.events()[0].id(), replay.events()[0].id());
    assert_eq!(
        first.acquisition_receipt_id(),
        replay.acquisition_receipt_id()
    );
    assert_ne!(first_ack.source_record_id(), other_ack.source_record_id());
    assert_ne!(first.events()[0].id(), other.events()[0].id());
    assert_ne!(
        first.acquisition_receipt_id(),
        other.acquisition_receipt_id()
    );
}

#[test]
fn builder_rejects_retrieval_plan_adapter_and_source_mismatches_transactionally() {
    let identity = fetch_identity(7);
    let source = source_digest(15);
    let cases = [
        (
            RawEnvelopeIdentityV1::new(
                retrieval_id(99),
                identity.plan_id(),
                identity.plan_digest(),
                identity.adapter().clone(),
                source,
            ),
            LedgerBuildError::RetrievalMismatch,
        ),
        (
            RawEnvelopeIdentityV1::new(
                identity.retrieval_id(),
                PlanId::from_bytes([99; 32]),
                identity.plan_digest(),
                identity.adapter().clone(),
                source,
            ),
            LedgerBuildError::PlanIdMismatch,
        ),
        (
            RawEnvelopeIdentityV1::new(
                identity.retrieval_id(),
                identity.plan_id(),
                PlanDigest::from_bytes([99; 32]),
                identity.adapter().clone(),
                source,
            ),
            LedgerBuildError::PlanDigestMismatch,
        ),
        (
            RawEnvelopeIdentityV1::new(
                identity.retrieval_id(),
                identity.plan_id(),
                identity.plan_digest(),
                AdapterIdentity::new("other", "1").unwrap(),
                source,
            ),
            LedgerBuildError::AdapterMismatch,
        ),
        (
            RawEnvelopeIdentityV1::new(
                identity.retrieval_id(),
                identity.plan_id(),
                identity.plan_digest(),
                identity.adapter().clone(),
                source_digest(99),
            ),
            LedgerBuildError::SourceIdentityMismatch,
        ),
    ];

    for (raw_identity, expected) in cases {
        let mut builder = LedgerBuilder::new(identity.clone(), source, SourceExactPolicy);
        let invalid = RawEnvelopeV1::new(
            raw_identity,
            EnvelopeOrdering::new(
                AcquisitionSequence::new(0),
                LaneKey::new(
                    SourceMember::new(b"member".to_vec()).unwrap(),
                    SourceStream::Stdout,
                ),
                LaneSequence::new(0),
            ),
            RecordBytes::whole(b"payload".to_vec()),
            RecordState::Complete,
        );
        assert_eq!(builder.accept(invalid).unwrap_err(), expected);

        builder
            .accept(envelope(
                &identity,
                source,
                0,
                b"member",
                SourceStream::Stdout,
                0,
                RecordBytes::whole(b"payload".to_vec()),
                RecordState::Complete,
            ))
            .unwrap();
    }
}

#[test]
fn builder_rejects_global_and_lane_sequence_gaps_without_advancing() {
    let identity = fetch_identity(8);
    let source = source_digest(16);
    let mut builder = LedgerBuilder::new(identity.clone(), source, SourceExactPolicy);

    let global_error = builder
        .accept(envelope(
            &identity,
            source,
            1,
            b"member",
            SourceStream::Stdout,
            0,
            RecordBytes::whole(b"one".to_vec()),
            RecordState::Complete,
        ))
        .unwrap_err();
    assert_eq!(
        global_error,
        LedgerBuildError::UnexpectedAcquisitionSequence {
            expected: 0,
            actual: 1,
        }
    );

    builder
        .accept(envelope(
            &identity,
            source,
            0,
            b"member",
            SourceStream::Stdout,
            0,
            RecordBytes::whole(b"zero".to_vec()),
            RecordState::Complete,
        ))
        .unwrap();
    let lane_error = builder
        .accept(envelope(
            &identity,
            source,
            1,
            b"member",
            SourceStream::Stdout,
            2,
            RecordBytes::whole(b"one".to_vec()),
            RecordState::Complete,
        ))
        .unwrap_err();
    assert_eq!(
        lane_error,
        LedgerBuildError::UnexpectedLaneSequence {
            expected: 1,
            actual: 2,
        }
    );
    builder
        .accept(envelope(
            &identity,
            source,
            1,
            b"member",
            SourceStream::Stdout,
            1,
            RecordBytes::whole(b"one".to_vec()),
            RecordState::Complete,
        ))
        .unwrap();
}

fn builder_with_one(
    identity: &FetchIdentity,
    source: SourceIdentityDigest,
    state: RecordState,
) -> LedgerBuilder<SourceExactPolicy> {
    let mut builder = LedgerBuilder::new(identity.clone(), source, SourceExactPolicy);
    builder
        .accept(envelope(
            identity,
            source,
            0,
            b"member",
            SourceStream::Stdout,
            0,
            RecordBytes::whole(b"abc".to_vec()),
            state,
        ))
        .unwrap();
    builder
}

#[test]
fn sealing_rejects_completion_identity_counts_and_false_complete_fragment() {
    let identity = fetch_identity(9);
    let source = source_digest(17);

    let wrong_identity = fetch_identity(10);
    assert_eq!(
        builder_with_one(&identity, source, RecordState::Complete)
            .seal(complete(wrong_identity, 1, 3, 3))
            .unwrap_err(),
        LedgerBuildError::CompletionIdentityMismatch
    );
    assert_eq!(
        builder_with_one(&identity, source, RecordState::Complete)
            .seal(complete(identity.clone(), 2, 3, 3))
            .unwrap_err(),
        LedgerBuildError::CompletionRecordCountMismatch
    );
    assert_eq!(
        builder_with_one(&identity, source, RecordState::Complete)
            .seal(complete(identity.clone(), 1, 2, 3))
            .unwrap_err(),
        LedgerBuildError::CompletionPayloadByteCountMismatch
    );
    assert_eq!(
        builder_with_one(&identity, source, RecordState::Complete)
            .seal(complete(identity.clone(), 1, 3, 4))
            .unwrap_err(),
        LedgerBuildError::CompletionSourceByteCountMismatch
    );
    assert_eq!(
        builder_with_one(
            &identity,
            source,
            RecordState::AdapterFragment {
                reason: RecordFragmentReason::PerRecordByteCap,
            },
        )
        .seal(complete(identity, 1, 3, 3))
        .unwrap_err(),
        LedgerBuildError::CompleteWithFragment
    );
}

#[test]
fn acquisition_and_presentation_receipts_are_separate_and_exhaustive() {
    struct MixedPolicy;
    impl DeterministicPolicy for MixedPolicy {
        fn authorize(&self, envelope: &RawEnvelopeV1) -> PolicyAuthorization {
            match envelope.ordering().acquisition_sequence().get() {
                0 => PolicyAuthorization::SourceExact,
                1 => PolicyAuthorization::PostPolicy {
                    authorized_record: RecordBytes::whole(b"post".to_vec()),
                    policy_digest: PolicyDigest::from_bytes([61; 32]),
                    transformation_receipt_id: TransformationReceiptId::from_bytes([62; 32]),
                },
                _ => PolicyAuthorization::OmittedByPolicy {
                    policy_digest: PolicyDigest::from_bytes([63; 32]),
                },
            }
        }
    }

    let identity = fetch_identity(11);
    let source = source_digest(18);
    let mut builder = LedgerBuilder::new(identity.clone(), source, MixedPolicy);
    let mut acks = Vec::new();
    for sequence in 0..3 {
        acks.push(
            builder
                .accept(envelope(
                    &identity,
                    source,
                    sequence,
                    b"member",
                    SourceStream::Stdout,
                    sequence,
                    RecordBytes::whole(b"raw".to_vec()),
                    RecordState::Complete,
                ))
                .unwrap(),
        );
    }
    let ledger = builder.seal(complete(identity, 3, 9, 9)).unwrap();
    let acquisition = ledger.acquisition_receipt();

    assert!(
        ledger
            .acquisition_receipt_id()
            .to_string()
            .starts_with("acqrcpt_")
    );
    assert_eq!(acquisition.acknowledged_count(), 3);
    assert_eq!(acquisition.counts().source_exact, 1);
    assert_eq!(acquisition.counts().post_policy, 1);
    assert_eq!(acquisition.counts().omitted_by_policy, 1);
    assert_eq!(ledger.len(), 2);
    assert_eq!(acks[2].authorized_byte_count(), 0);

    let presentation = PresentationReceipt::reconcile(
        &ledger,
        [
            PresentationAssignment::new(
                ledger.events()[1].id(),
                PresentationDisposition::PatternRepresented {
                    pattern_id: PatternId::from_bytes([0xa1; 32]),
                },
            ),
            PresentationAssignment::new(
                ledger.events()[0].id(),
                PresentationDisposition::ShownVerbatim,
            ),
        ],
    )
    .unwrap();
    assert_eq!(presentation.persisted_count(), 2);
    assert_eq!(presentation.counts().shown_verbatim, 1);
    assert_eq!(presentation.counts().pattern_represented, 1);
    assert_eq!(presentation.counts().retained_raw, 0);
    assert_eq!(presentation.unaccounted_count(), 0);
    assert_eq!(
        presentation
            .entries()
            .iter()
            .map(|entry| entry.event_id())
            .collect::<Vec<_>>(),
        ledger
            .events()
            .iter()
            .map(|event| event.id())
            .collect::<Vec<_>>()
    );
}

#[test]
fn presentation_reconciliation_rejects_missing_unknown_and_duplicate_assignments() {
    let identity = fetch_identity(12);
    let source = source_digest(19);
    let mut builder = LedgerBuilder::new(identity.clone(), source, SourceExactPolicy);
    for sequence in 0..2 {
        builder
            .accept(envelope(
                &identity,
                source,
                sequence,
                b"member",
                SourceStream::Stdout,
                sequence,
                RecordBytes::whole(vec![u8::try_from(sequence).unwrap()]),
                RecordState::Complete,
            ))
            .unwrap();
    }
    let ledger = builder.seal(complete(identity, 2, 2, 2)).unwrap();
    let first = ledger.events()[0].id();
    let second = ledger.events()[1].id();

    assert_eq!(
        PresentationReceipt::reconcile(
            &ledger,
            [PresentationAssignment::new(
                first,
                PresentationDisposition::RetainedRaw,
            )],
        )
        .unwrap_err(),
        PresentationReconciliationError::MissingAssignments(vec![second])
    );
    let unknown = EventId::from_bytes([99; 32]);
    assert_eq!(
        PresentationReceipt::reconcile(
            &ledger,
            [PresentationAssignment::new(
                unknown,
                PresentationDisposition::RetainedRaw,
            )],
        )
        .unwrap_err(),
        PresentationReconciliationError::UnknownEvent(unknown)
    );
    assert_eq!(
        PresentationReceipt::reconcile(
            &ledger,
            [
                PresentationAssignment::new(first, PresentationDisposition::ShownVerbatim),
                PresentationAssignment::new(first, PresentationDisposition::RetainedRaw),
            ],
        )
        .unwrap_err(),
        PresentationReconciliationError::DuplicateAssignment(first)
    );
}

#[test]
fn partial_fetch_status_survives_ledger_and_presentation_reconciliation() {
    let identity = fetch_identity(13);
    let source = source_digest(20);
    let mut builder = LedgerBuilder::new(identity.clone(), source, SourceExactPolicy);
    builder
        .accept(envelope(
            &identity,
            source,
            0,
            b"member",
            SourceStream::Stdout,
            0,
            RecordBytes::whole(b"received".to_vec()),
            RecordState::Complete,
        ))
        .unwrap();
    let partial = FetchCompleteness::partial(
        FetchPartialReasons::with_additional(
            FetchPartialReason::ProviderCap,
            [FetchPartialReason::PaginationIncomplete],
        ),
        Some(SourceCursor::new(b"next".to_vec()).unwrap()),
    );
    let ledger = builder
        .seal(completion(
            identity,
            AcknowledgedCounts::new(1, 8, 8),
            partial,
        ))
        .unwrap();
    let presentation = PresentationReceipt::reconcile(
        &ledger,
        [PresentationAssignment::new(
            ledger.events()[0].id(),
            PresentationDisposition::RetainedRaw,
        )],
    )
    .unwrap();

    assert!(
        !ledger
            .fetch_completion()
            .provider_completeness()
            .is_complete()
    );
    let ProviderCompleteness::Partial { reasons, .. } =
        ledger.fetch_completion().provider_completeness()
    else {
        panic!("partial completion changed variant");
    };
    assert_eq!(
        reasons.iter().map(PartialReason::code).collect::<Vec<_>>(),
        vec!["provider_cap", "pagination_incomplete"]
    );
    assert_eq!(presentation.persisted_count(), 1);
}

#[test]
fn passthrough_and_expansion_preserve_authorized_event_boundaries() {
    let identity = fetch_identity(14);
    let source = source_digest(21);
    let records = [b"zero".as_slice(), b"one", b"two", b"three"];
    let mut builder = LedgerBuilder::new(identity.clone(), source, SourceExactPolicy);
    for (position, raw) in records.iter().enumerate() {
        let sequence = u64::try_from(position).unwrap();
        builder
            .accept(envelope(
                &identity,
                source,
                sequence,
                b"member",
                SourceStream::Stdout,
                sequence,
                RecordBytes::whole(raw.to_vec()),
                RecordState::Complete,
            ))
            .unwrap();
    }
    let ledger = builder.seal(complete(identity, 4, 15, 15)).unwrap();
    assert_eq!(ledger.passthrough().collect::<Vec<_>>(), records.to_vec());
    let anchor = ledger.events()[2].id();
    let expansion = ledger.expand(anchor, 1, 20).unwrap();
    assert_eq!(expansion.anchor_offset(), 1);
    assert_eq!(
        expansion
            .events()
            .iter()
            .map(|event| event.raw())
            .collect::<Vec<_>>(),
        vec![b"one".as_slice(), b"two".as_slice(), b"three".as_slice()]
    );
}

#[test]
fn same_lane_expansion_ignores_globally_interleaved_streams() {
    let identity = fetch_identity(17);
    let source = source_digest(23);
    let mut builder = LedgerBuilder::new(identity.clone(), source, SourceExactPolicy);
    let records = [
        (SourceStream::Stderr, 0, b"e0".as_slice()),
        (SourceStream::Stdout, 0, b"o0".as_slice()),
        (SourceStream::Stderr, 1, b"e1".as_slice()),
        (SourceStream::Stdout, 1, b"o1".as_slice()),
        (SourceStream::Stderr, 2, b"e2".as_slice()),
    ];
    for (acquisition, (stream, lane_sequence, raw)) in records.iter().enumerate() {
        builder
            .accept(envelope(
                &identity,
                source,
                u64::try_from(acquisition).unwrap(),
                b"process",
                stream.clone(),
                *lane_sequence,
                RecordBytes::whole(raw.to_vec()),
                RecordState::Complete,
            ))
            .unwrap();
    }
    let ledger = builder.seal(complete(identity, 5, 10, 10)).unwrap();
    let anchor = ledger.events()[2].id();

    let lane = ledger.expand_same_lane(anchor, 1, 1).unwrap();
    assert_eq!(lane.anchor(), anchor);
    assert_eq!(lane.anchor_offset(), 1);
    assert_eq!(
        lane.raw_events().collect::<Vec<_>>(),
        vec![b"e0".as_slice(), b"e1".as_slice(), b"e2".as_slice()]
    );
    assert_eq!(
        ledger
            .expand(anchor, 1, 1)
            .unwrap()
            .events()
            .iter()
            .map(|event| event.raw())
            .collect::<Vec<_>>(),
        vec![b"o0".as_slice(), b"e1".as_slice(), b"o1".as_slice()]
    );
    assert!(!format!("{lane:?}").contains(&anchor.to_string()));
}

#[test]
fn debug_and_error_formatting_never_expose_content_or_provenance() {
    const RAW: &str = "CANARY_RAW_PAYLOAD_47eb";
    const MEMBER: &str = "CANARY_MEMBER_86cd";
    const NATIVE: &str = "CANARY_NATIVE_ID_40aa";
    const CURSOR: &str = "CANARY_CURSOR_e1d2";
    const PATTERN_BYTE: u8 = 0xd1;
    let identity = fetch_identity(16);
    let source = source_digest(22);
    let mut builder = LedgerBuilder::new(identity.clone(), source, SourceExactPolicy);
    let raw = envelope(
        &identity,
        source,
        0,
        MEMBER.as_bytes(),
        SourceStream::Stderr,
        0,
        RecordBytes::whole(RAW.as_bytes().to_vec()),
        RecordState::Complete,
    )
    .with_native_event_id(NativeEventId::new(NATIVE.as_bytes().to_vec()).unwrap())
    .with_cursor(SourceCursor::new(CURSOR.as_bytes().to_vec()).unwrap());
    let raw_summary = format!("{raw:?}");
    let ack = builder.accept(raw).unwrap();
    let builder_summary = format!("{builder:?}");
    let ledger = builder.seal(complete(identity, 1, 23, 23)).unwrap();
    let event = &ledger.events()[0];
    let assignment = PresentationAssignment::new(
        event.id(),
        PresentationDisposition::PatternRepresented {
            pattern_id: PatternId::from_bytes([PATTERN_BYTE; 32]),
        },
    );
    let assignment_summary = format!("{assignment:?}");
    let receipt = PresentationReceipt::reconcile(&ledger, [assignment]).unwrap();
    let lookup_error = LedgerLookupError::UnknownEvent(event.id());
    let build_error = LedgerBuildError::EventIdCollision(event.id());
    let receipt_error = PresentationReconciliationError::MissingAssignments(vec![event.id()]);

    let rendered = [
        raw_summary,
        builder_summary,
        format!("{ack:?}"),
        format!("{event:?}"),
        format!("{ledger:?}"),
        format!("{:?}", ledger.acquisition_receipt_id()),
        assignment_summary,
        format!("{:?}", receipt.entries()[0]),
        format!("{receipt:?}"),
        format!("{:?}", event.id()),
        format!("{:?}", event.source_record_id()),
        format!("{:?}", event.content_hash()),
        format!("{:?}", receipt.id()),
        format!("{lookup_error}"),
        format!("{lookup_error:?}"),
        format!("{build_error}"),
        format!("{build_error:?}"),
        format!("{receipt_error}"),
        format!("{receipt_error:?}"),
    ];
    for output in rendered {
        for forbidden in [RAW, MEMBER, NATIVE, CURSOR] {
            assert!(!output.contains(forbidden), "leaked {forbidden}: {output}");
        }
        assert!(!output.contains(&format!("{PATTERN_BYTE:02x}").repeat(4)));
        assert!(!output.contains(&event.id().to_string()));
        assert!(!output.contains(&event.source_record_id().to_string()));
        assert!(!output.contains(&event.content_hash().to_string()));
        assert!(!output.contains(&ledger.acquisition_receipt_id().to_string()));
        assert!(!output.contains(&receipt.id().to_string()));
    }

    assert_eq!(format!("{lookup_error}"), "EVIDENTRAIL_LEDGER_UNKNOWN_EVENT");
    assert_eq!(
        format!("{receipt_error}"),
        "EVIDENTRAIL_PRESENTATION_MISSING_ASSIGNMENTS (affected_event_count=1)"
    );
}
