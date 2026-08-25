use evidentrail_core::{
    BlockAssignment, BlockConfidence, BlockId, BlockIndex, BlockLookupError,
    BlockReconciliationError, BlockState, DeterministicPolicy, EnvelopeSink, EventId, EventLedger,
    FramingPolicy, LedgerBuilder, PolicyAuthorization, RetrievalId,
};
use evidentrail_schema::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    CompletenessProof, EnvelopeOrdering, FetchBoundaries, FetchCompleteness, FetchCompletion,
    FetchIdentity, FetchTiming, LaneKey, LaneSequence, PlanDigest, PlanId, RawEnvelopeIdentityV1,
    RawEnvelopeV1, RecordBytes, RecordState, SourceIdentityDigest, SourceMember, SourceStream,
    UnixTimestampNanos,
};

struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

fn retrieval_id(seed: u8) -> RetrievalId {
    RetrievalId::from_bytes([seed; 32])
}

fn ledger(retrieval_id: RetrievalId, raw_events: &[&[u8]]) -> EventLedger {
    source_exact_ledger(retrieval_id, raw_events.iter().map(|raw| raw.to_vec()))
}

fn source_exact_ledger(
    retrieval_id: RetrievalId,
    raw_events: impl IntoIterator<Item = Vec<u8>>,
) -> EventLedger {
    let plan_id = PlanId::from_bytes([51; 32]);
    let plan_digest = PlanDigest::from_bytes([52; 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([53; 32]);
    let adapter = AdapterIdentity::new("block-fixture", "1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let lane = LaneKey::new(
        SourceMember::new(b"block-fixture-member".to_vec()).unwrap(),
        SourceStream::FileMember,
    );
    let mut builder = LedgerBuilder::new(
        fetch_identity.clone(),
        source_identity_digest,
        SourceExactPolicy,
    );
    let mut source_bytes = 0u64;
    let mut record_count = 0u64;

    for (position, raw) in raw_events.into_iter().enumerate() {
        let sequence = u64::try_from(position).unwrap();
        source_bytes = source_bytes
            .checked_add(u64::try_from(raw.len()).unwrap())
            .unwrap();
        record_count = record_count.checked_add(1).unwrap();
        builder
            .accept(RawEnvelopeV1::new(
                envelope_identity.clone(),
                EnvelopeOrdering::new(
                    AcquisitionSequence::new(sequence),
                    lane.clone(),
                    LaneSequence::new(sequence),
                ),
                RecordBytes::whole(raw),
                RecordState::Complete,
            ))
            .unwrap();
    }

    let completion = FetchCompletion::new(
        fetch_identity,
        FetchTiming::new(UnixTimestampNanos::new(0), UnixTimestampNanos::new(1)),
        AcknowledgedCounts::new(record_count, source_bytes, source_bytes),
        AttemptCounts::new(1, 1),
        AttemptCounts::default(),
        FetchBoundaries::default(),
        [],
        AdapterOutcome::Finished,
        [],
        FetchCompleteness::complete(CompletenessProof::OtherVersioned {
            version: 1,
            code: 1,
        }),
    )
    .unwrap();
    builder.seal(completion).unwrap()
}

fn policy() -> FramingPolicy {
    FramingPolicy::new(b"bounded-multiline-vocabulary".to_vec(), b"1".to_vec())
}

fn default_lane(ledger: &EventLedger) -> LaneKey {
    ledger.events()[0].lane().clone()
}

fn interleaved_stdout_stderr_ledger() -> EventLedger {
    let retrieval_id = retrieval_id(36);
    let plan_id = PlanId::from_bytes([61; 32]);
    let plan_digest = PlanDigest::from_bytes([62; 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([63; 32]);
    let adapter = AdapterIdentity::new("synthetic-process", "1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let member = SourceMember::new(b"synthetic-process-1".to_vec()).unwrap();
    let stdout = LaneKey::new(member.clone(), SourceStream::Stdout);
    let stderr = LaneKey::new(member, SourceStream::Stderr);
    let records = [
        (stdout.clone(), 0, b"out-0\n".as_slice()),
        (stderr.clone(), 0, b"err-0\n".as_slice()),
        (stdout, 1, b"out-1\n".as_slice()),
        (stderr, 1, b"err-1\n".as_slice()),
    ];
    let mut builder = LedgerBuilder::new(
        fetch_identity.clone(),
        source_identity_digest,
        SourceExactPolicy,
    );
    let mut source_bytes = 0u64;
    for (acquisition, (lane, lane_sequence, raw)) in records.into_iter().enumerate() {
        source_bytes += u64::try_from(raw.len()).unwrap();
        builder
            .accept(RawEnvelopeV1::new(
                envelope_identity.clone(),
                EnvelopeOrdering::new(
                    AcquisitionSequence::new(u64::try_from(acquisition).unwrap()),
                    lane,
                    LaneSequence::new(lane_sequence),
                ),
                RecordBytes::whole(raw.to_vec()),
                RecordState::Complete,
            ))
            .unwrap();
    }
    let completion = FetchCompletion::new(
        fetch_identity,
        FetchTiming::new(UnixTimestampNanos::new(0), UnixTimestampNanos::new(1)),
        AcknowledgedCounts::new(4, source_bytes, source_bytes),
        AttemptCounts::new(1, 1),
        AttemptCounts::default(),
        FetchBoundaries::default(),
        [],
        AdapterOutcome::Finished,
        [],
        FetchCompleteness::complete(CompletenessProof::OtherVersioned {
            version: 1,
            code: 1,
        }),
    )
    .unwrap();
    builder.seal(completion).unwrap()
}

fn assignment(
    ledger: &EventLedger,
    member_ids: impl IntoIterator<Item = EventId>,
) -> BlockAssignment {
    assignment_at(ledger, 0, member_ids)
}

fn assignment_at(
    ledger: &EventLedger,
    first_lane_sequence: u64,
    member_ids: impl IntoIterator<Item = EventId>,
) -> BlockAssignment {
    BlockAssignment::new_same_lane_v1(
        default_lane(ledger),
        member_ids
            .into_iter()
            .enumerate()
            .map(|(offset, event_id)| {
                (
                    event_id,
                    LaneSequence::new(first_lane_sequence + u64::try_from(offset).unwrap()),
                )
            }),
        policy(),
        BlockState::Reconstructed,
        BlockConfidence::High,
    )
}

fn reconcile_one_block<'ledger>(
    ledger: &'ledger EventLedger,
    framing_policy: FramingPolicy,
) -> BlockIndex<'ledger> {
    BlockIndex::reconcile(
        ledger,
        [BlockAssignment::new_same_lane_v1(
            default_lane(ledger),
            ledger
                .events()
                .iter()
                .map(|event| (event.id(), LaneSequence::new(event.ordinal()))),
            framing_policy,
            BlockState::Reconstructed,
            BlockConfidence::Certain,
        )],
    )
    .unwrap()
}

#[test]
fn singleton_assignments_reconcile_into_source_order() {
    let ledger = ledger(retrieval_id(20), &[b"zero\n", b"one\n", b"two\n"]);
    let ids = ledger
        .events()
        .iter()
        .map(|event| event.id())
        .collect::<Vec<_>>();
    let index = BlockIndex::reconcile(
        &ledger,
        [
            assignment_at(&ledger, 2, [ids[2]]),
            assignment_at(&ledger, 0, [ids[0]]),
            assignment_at(&ledger, 1, [ids[1]]),
        ],
    )
    .unwrap();

    assert_eq!(index.len(), ledger.len());
    for (position, block) in index.blocks().iter().enumerate() {
        assert_eq!(block.ordinal(), u64::try_from(position).unwrap());
        assert_eq!(block.member_ids(), &[ids[position]]);
        assert_eq!(index.block_for_event(ids[position]).unwrap(), block);
        assert_eq!(index.expand_block(block.id()).unwrap().events().len(), 1);
    }
}

#[test]
fn multiline_block_membership_and_event_expansion_are_exact() {
    let ledger = ledger(
        retrieval_id(21),
        &[
            b"error: checkout failed\n",
            b"  at charge\n",
            b"  caused by timeout\n",
            b"next\n",
        ],
    );
    let ids = ledger
        .events()
        .iter()
        .map(|event| event.id())
        .collect::<Vec<_>>();
    let index = BlockIndex::reconcile(
        &ledger,
        [
            assignment_at(&ledger, 0, ids[..3].iter().copied()),
            assignment_at(&ledger, 3, [ids[3]]),
        ],
    )
    .unwrap();

    let expanded = index.expand_event(ids[1]).unwrap();
    assert_eq!(expanded.block().member_ids(), &ids[..3]);
    assert_eq!(expanded.block().state(), BlockState::Reconstructed);
    assert_eq!(expanded.block().confidence(), BlockConfidence::High);
    assert_eq!(
        expanded
            .events()
            .iter()
            .map(|event| event.id())
            .collect::<Vec<_>>(),
        ids[..3]
    );
    assert_eq!(
        expanded.raw_events().collect::<Vec<_>>(),
        vec![
            b"error: checkout failed\n".as_slice(),
            b"  at charge\n".as_slice(),
            b"  caused by timeout\n".as_slice(),
        ]
    );
}

#[test]
fn exact_byte_reconstruction_inserts_nothing_and_preserves_invalid_utf8() {
    let raw = [
        vec![0xff, b'e', b'r', b'r', b'\n'],
        b"  continuation\n".to_vec(),
        vec![0x00, 0xfe],
    ];
    let ledger = source_exact_ledger(retrieval_id(22), raw.iter().cloned());
    let ids = ledger.events().iter().map(|event| event.id());
    let index = BlockIndex::reconcile(&ledger, [assignment(&ledger, ids)]).unwrap();

    let reconstructed = index
        .expand_block(index.blocks()[0].id())
        .unwrap()
        .exact_bytes();
    assert_eq!(
        reconstructed,
        raw.iter().flatten().copied().collect::<Vec<_>>()
    );
}

#[test]
fn block_identity_is_deterministic_retrieval_local_and_policy_versioned() {
    let build = |id| ledger(id, &[b"first\n", b"second\n"]);
    let first = build(retrieval_id(23));
    let replay = build(retrieval_id(23));
    let separate = build(retrieval_id(24));

    let first_index = reconcile_one_block(&first, policy());
    let replay_index = reconcile_one_block(&replay, policy());
    let separate_index = reconcile_one_block(&separate, policy());
    let versioned_index = reconcile_one_block(
        &first,
        FramingPolicy::new(b"bounded-multiline-vocabulary".to_vec(), b"2".to_vec()),
    );
    assert_eq!(first_index.blocks()[0].id(), replay_index.blocks()[0].id());
    assert_ne!(
        first_index.blocks()[0].id(),
        separate_index.blocks()[0].id()
    );
    assert_ne!(
        first_index.blocks()[0].id(),
        versioned_index.blocks()[0].id()
    );
}

#[test]
fn empty_assignment_is_rejected() {
    let ledger = ledger(retrieval_id(25), &[b"event"]);
    let error = BlockIndex::reconcile(&ledger, [assignment(&ledger, [])]).unwrap_err();

    assert_eq!(
        error,
        BlockReconciliationError::EmptyAssignment {
            assignment_index: 0
        }
    );
}

#[test]
fn foreign_member_is_rejected() {
    let local_ledger = ledger(retrieval_id(26), &[b"local"]);
    let foreign_ledger = ledger(retrieval_id(27), &[b"foreign"]);
    let foreign = foreign_ledger.events()[0].id();
    let error =
        BlockIndex::reconcile(&local_ledger, [assignment(&local_ledger, [foreign])]).unwrap_err();

    assert_eq!(
        error,
        BlockReconciliationError::ForeignMember {
            assignment_index: 0,
            member_index: 0,
            event_id: foreign,
        }
    );
}

#[test]
fn assignment_lane_must_match_persisted_event_lane() {
    let ledger = ledger(retrieval_id(38), &[b"event"]);
    let event = &ledger.events()[0];
    let wrong_lane = LaneKey::new(event.lane().member().clone(), SourceStream::Stderr);
    let error = BlockIndex::reconcile(
        &ledger,
        [BlockAssignment::new_same_lane_v1(
            wrong_lane,
            [(event.id(), event.lane_sequence())],
            policy(),
            BlockState::ProviderAtomic,
            BlockConfidence::Certain,
        )],
    )
    .unwrap_err();

    assert_eq!(
        error,
        BlockReconciliationError::MemberLaneMismatch {
            assignment_index: 0,
            member_index: 0,
        }
    );
}

#[test]
fn assignment_lane_sequence_must_match_persisted_event_position() {
    let ledger = ledger(retrieval_id(39), &[b"event"]);
    let event = &ledger.events()[0];
    let error = BlockIndex::reconcile(
        &ledger,
        [BlockAssignment::new_same_lane_v1(
            event.lane().clone(),
            [(
                event.id(),
                LaneSequence::new(event.lane_sequence().get() + 1),
            )],
            policy(),
            BlockState::ProviderAtomic,
            BlockConfidence::Certain,
        )],
    )
    .unwrap_err();

    assert_eq!(
        error,
        BlockReconciliationError::MemberLaneSequenceMismatch {
            assignment_index: 0,
            member_index: 0,
        }
    );
}

#[test]
fn repeated_member_inside_one_assignment_is_rejected() {
    let ledger = ledger(retrieval_id(28), &[b"one", b"two"]);
    let first = ledger.events()[0].id();
    let second = ledger.events()[1].id();
    let error = BlockIndex::reconcile(&ledger, [assignment(&ledger, [first, first])]).unwrap_err();

    assert_eq!(
        error,
        BlockReconciliationError::DuplicateMember {
            assignment_index: 0,
            member_index: 1,
            event_id: first,
        }
    );

    let nonadjacent =
        BlockIndex::reconcile(&ledger, [assignment(&ledger, [first, second, first])]).unwrap_err();
    assert_eq!(
        nonadjacent,
        BlockReconciliationError::DuplicateMember {
            assignment_index: 0,
            member_index: 2,
            event_id: first,
        }
    );
}

#[test]
fn duplicate_assignment_is_rejected_before_overlap() {
    let ledger = ledger(retrieval_id(29), &[b"one"]);
    let id = ledger.events()[0].id();
    let error = BlockIndex::reconcile(
        &ledger,
        [assignment(&ledger, [id]), assignment(&ledger, [id])],
    )
    .unwrap_err();

    assert!(matches!(
        error,
        BlockReconciliationError::DuplicateAssignment {
            first_assignment_index: 0,
            duplicate_assignment_index: 1,
            ..
        }
    ));
}

#[test]
fn overlapping_distinct_assignments_are_rejected() {
    let ledger = ledger(retrieval_id(30), &[b"zero", b"one", b"two"]);
    let ids = ledger
        .events()
        .iter()
        .map(|event| event.id())
        .collect::<Vec<_>>();
    let error = BlockIndex::reconcile(
        &ledger,
        [
            assignment(&ledger, [ids[0], ids[1]]),
            BlockAssignment::new_same_lane_v1(
                default_lane(&ledger),
                [
                    (ids[1], LaneSequence::new(1)),
                    (ids[2], LaneSequence::new(2)),
                ],
                FramingPolicy::new(b"different-policy".to_vec(), b"1".to_vec()),
                BlockState::Ambiguous,
                BlockConfidence::Low,
            ),
        ],
    )
    .unwrap_err();

    assert_eq!(
        error,
        BlockReconciliationError::OverlappingMember {
            first_assignment_index: 0,
            second_assignment_index: 1,
            event_id: ids[1],
        }
    );
}

#[test]
fn reversed_member_ids_are_rejected_by_lane_sequence() {
    let ledger = ledger(retrieval_id(31), &[b"zero", b"one"]);
    let ids = ledger
        .events()
        .iter()
        .map(|event| event.id())
        .collect::<Vec<_>>();
    let error = BlockIndex::reconcile(
        &ledger,
        [BlockAssignment::new_same_lane_v1(
            default_lane(&ledger),
            [
                (ids[1], LaneSequence::new(1)),
                (ids[0], LaneSequence::new(0)),
            ],
            policy(),
            BlockState::Reconstructed,
            BlockConfidence::High,
        )],
    )
    .unwrap_err();

    assert_eq!(
        error,
        BlockReconciliationError::ReversedLaneSequence {
            assignment_index: 0,
            previous_member_index: 0,
            member_index: 1,
        }
    );
}

#[test]
fn noncontiguous_lane_sequence_is_rejected() {
    let ledger = ledger(retrieval_id(32), &[b"zero", b"one"]);
    let ids = ledger
        .events()
        .iter()
        .map(|event| event.id())
        .collect::<Vec<_>>();
    let error = BlockIndex::reconcile(
        &ledger,
        [BlockAssignment::new_same_lane_v1(
            default_lane(&ledger),
            [
                (ids[0], LaneSequence::new(0)),
                (ids[1], LaneSequence::new(2)),
            ],
            policy(),
            BlockState::Reconstructed,
            BlockConfidence::High,
        )],
    )
    .unwrap_err();

    assert_eq!(
        error,
        BlockReconciliationError::NonContiguousLaneSequence {
            assignment_index: 0,
            previous_member_index: 0,
            member_index: 1,
        }
    );
}

#[test]
fn reversed_lane_sequence_is_rejected_even_when_acquisition_order_increases() {
    let ledger = ledger(retrieval_id(35), &[b"zero", b"one", b"two"]);
    let ids = ledger
        .events()
        .iter()
        .map(|event| event.id())
        .collect::<Vec<_>>();
    let error = BlockIndex::reconcile(
        &ledger,
        [BlockAssignment::new_same_lane_v1(
            default_lane(&ledger),
            [
                (ids[1], LaneSequence::new(1)),
                (ids[2], LaneSequence::new(0)),
            ],
            policy(),
            BlockState::Reconstructed,
            BlockConfidence::High,
        )],
    )
    .unwrap_err();

    assert_eq!(
        error,
        BlockReconciliationError::ReversedLaneSequence {
            assignment_index: 0,
            previous_member_index: 0,
            member_index: 1,
        }
    );
}

#[test]
fn stdout_stderr_interleaving_uses_lane_positions_not_global_slices() {
    let ledger = interleaved_stdout_stderr_ledger();
    let ids = ledger
        .events()
        .iter()
        .map(|event| event.id())
        .collect::<Vec<_>>();
    let stdout = ledger.events()[0].lane().clone();
    let stderr = ledger.events()[1].lane().clone();
    let index = BlockIndex::reconcile(
        &ledger,
        [
            BlockAssignment::new_same_lane_v1(
                stdout.clone(),
                [
                    (ids[0], LaneSequence::new(0)),
                    (ids[2], LaneSequence::new(1)),
                ],
                policy(),
                BlockState::Reconstructed,
                BlockConfidence::Certain,
            ),
            BlockAssignment::new_same_lane_v1(
                stderr.clone(),
                [
                    (ids[1], LaneSequence::new(0)),
                    (ids[3], LaneSequence::new(1)),
                ],
                policy(),
                BlockState::Reconstructed,
                BlockConfidence::Certain,
            ),
        ],
    )
    .unwrap();

    assert_eq!(index.blocks().len(), 2);
    assert_eq!(index.blocks()[0].lane(), &stdout);
    assert_eq!(index.blocks()[0].member_ids(), &[ids[0], ids[2]]);
    assert_eq!(index.blocks()[0].member_positions(), &[0, 2]);
    assert_eq!(
        index.blocks()[0].member_lane_sequences(),
        &[LaneSequence::new(0), LaneSequence::new(1)]
    );
    assert_eq!(index.blocks()[1].lane(), &stderr);
    assert_eq!(index.blocks()[1].member_ids(), &[ids[1], ids[3]]);
    assert_eq!(index.blocks()[1].member_positions(), &[1, 3]);

    let stdout_expansion = index.expand_event(ids[2]).unwrap();
    assert_eq!(
        stdout_expansion
            .events()
            .iter()
            .map(|event| event.id())
            .collect::<Vec<_>>(),
        vec![ids[0], ids[2]]
    );
    assert_eq!(stdout_expansion.exact_bytes(), b"out-0\nout-1\n");
    let stderr_expansion = index.expand_event(ids[3]).unwrap();
    assert_eq!(stderr_expansion.exact_bytes(), b"err-0\nerr-1\n");

    for event in ledger.events() {
        assert!(index.block_for_event(event.id()).is_ok());
    }
}

#[test]
fn missing_primary_membership_is_rejected() {
    let ledger = ledger(retrieval_id(33), &[b"zero", b"one"]);
    let ids = ledger
        .events()
        .iter()
        .map(|event| event.id())
        .collect::<Vec<_>>();
    let error = BlockIndex::reconcile(&ledger, [assignment(&ledger, [ids[0]])]).unwrap_err();

    assert_eq!(error, BlockReconciliationError::MissingEvents(vec![ids[1]]));
}

#[test]
fn block_debug_and_error_formatting_are_contentless() {
    const POLICY_CANARY: &str = "CANARY_FRAMING_POLICY_22d1";
    const VERSION_CANARY: &str = "CANARY_FRAMING_VERSION_a310";
    const PAYLOAD_CANARY: &str = "CANARY_BLOCK_PAYLOAD_9fc2";
    const LANE_CANARY: &str = "CANARY_BLOCK_LANE_201f";

    let ledger = ledger(retrieval_id(34), &[PAYLOAD_CANARY.as_bytes()]);
    let event_id = ledger.events()[0].id();
    let framing_policy = FramingPolicy::new(
        POLICY_CANARY.as_bytes().to_vec(),
        VERSION_CANARY.as_bytes().to_vec(),
    );
    let framing_debug = format!("{framing_policy:?}");
    let diagnostic_assignment = BlockAssignment::new_same_lane_v1(
        LaneKey::new(
            SourceMember::new(LANE_CANARY.as_bytes().to_vec()).unwrap(),
            SourceStream::Stderr,
        ),
        [(event_id, LaneSequence::new(0))],
        framing_policy.clone(),
        BlockState::FallbackSingleton,
        BlockConfidence::Unknown,
    );
    let assignment_debug = format!("{diagnostic_assignment:?}");
    let valid_assignment = BlockAssignment::new_same_lane_v1(
        ledger.events()[0].lane().clone(),
        [(event_id, ledger.events()[0].lane_sequence())],
        framing_policy,
        BlockState::FallbackSingleton,
        BlockConfidence::Unknown,
    );
    let index = BlockIndex::reconcile(&ledger, [valid_assignment]).unwrap();
    let block = &index.blocks()[0];
    let expansion = index.expand_block(block.id()).unwrap();
    let foreign_event = EventId::from_bytes([0x41; 32]);
    let foreign_block = BlockId::from_bytes([0x42; 32]);
    let reconcile_error = BlockReconciliationError::ForeignMember {
        assignment_index: 7,
        member_index: 2,
        event_id: foreign_event,
    };
    let lookup_errors = [
        BlockLookupError::UnknownEvent(foreign_event),
        BlockLookupError::UnknownBlock(foreign_block),
    ];

    let rendered = [
        framing_debug.clone(),
        assignment_debug,
        format!("{index:#?}"),
        format!("{block:?}"),
        format!("{index:?}"),
        format!("{expansion:?}"),
        format!("{:?}", block.id()),
        format!("{reconcile_error}"),
        format!("{reconcile_error:?}"),
        format!("{}", lookup_errors[0]),
        format!("{:?}", lookup_errors[0]),
        format!("{}", lookup_errors[1]),
        format!("{:?}", lookup_errors[1]),
    ];
    for output in rendered {
        for forbidden in [POLICY_CANARY, VERSION_CANARY, PAYLOAD_CANARY, LANE_CANARY] {
            assert!(
                !output.contains(forbidden),
                "block formatting leaked {forbidden}: {output}"
            );
        }
        assert!(!output.contains(&event_id.to_string()));
        assert!(!output.contains(&block.id().to_string()));
        assert!(!output.contains(&foreign_event.to_string()));
        assert!(!output.contains(&foreign_block.to_string()));
    }

    assert_eq!(format!("{:?}", block.id()), "BlockId(<redacted>)");
    assert_eq!(
        framing_debug,
        format!(
            "FramingPolicy {{ policy_bytes: {}, version_bytes: {} }}",
            POLICY_CANARY.len(),
            VERSION_CANARY.len()
        )
    );
    assert_eq!(
        format!("{reconcile_error}"),
        "EVIDENTRAIL_BLOCK_FOREIGN_MEMBER (affected_event_count=1)"
    );
}
