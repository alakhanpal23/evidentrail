use std::collections::{BTreeMap, BTreeSet};

use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    BlockConfidence, BlockIndex, BlockState, CompletenessProof, DeterministicPolicy,
    EnvelopeOrdering, EnvelopeSink, EnvelopeTimestamps, EventLedger, FetchBoundaries,
    FetchCompleteness, FetchCompletion, FetchIdentity, FetchPartialReason, FetchPartialReasons,
    FetchTiming, LaneKey, LaneSequence, LedgerBuilder, MonotonicTimestampNanos, PlanDigest, PlanId,
    PolicyAuthorization, RawEnvelopeIdentityV1, RawEnvelopeV1, RecordBytes, RecordFragmentReason,
    RecordState, RetrievalId, SourceIdentityDigest, SourceMember, SourceStream, UnixTimestampNanos,
};
use evidentrail_framing::{
    FRAMING_POLICY_NAME_V1, FRAMING_POLICY_VERSION_V1, MAX_CONTINUATION_GAP_NANOS_V1,
    MAX_RECONSTRUCTED_BLOCK_BYTES_V1, MAX_RECONSTRUCTED_BLOCK_LINES_V1,
    MAX_RECONSTRUCTED_STATE_DEPTH_V1, SourceLaneFramingError, frame_source_lanes_v1,
    source_lane_framing_policy_v1,
};

struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FixtureLane {
    Stdout,
    Stderr,
}

#[derive(Clone)]
struct RecordSpec {
    lane: FixtureLane,
    payload: Vec<u8>,
    terminator: Option<Vec<u8>>,
    state: RecordState,
    monotonic: Option<u64>,
}

impl RecordSpec {
    fn line(payload: impl Into<Vec<u8>>) -> Self {
        Self {
            lane: FixtureLane::Stderr,
            payload: payload.into(),
            terminator: Some(b"\n".to_vec()),
            state: RecordState::Complete,
            monotonic: Some(100),
        }
    }

    fn crlf(payload: impl Into<Vec<u8>>) -> Self {
        Self {
            terminator: Some(b"\r\n".to_vec()),
            ..Self::line(payload)
        }
    }

    fn unterminated(payload: impl Into<Vec<u8>>) -> Self {
        Self {
            terminator: Some(Vec::new()),
            ..Self::line(payload)
        }
    }

    fn delimited(payload: impl Into<Vec<u8>>, terminator: impl Into<Vec<u8>>) -> Self {
        Self {
            terminator: Some(terminator.into()),
            ..Self::line(payload)
        }
    }

    fn whole(payload: impl Into<Vec<u8>>) -> Self {
        Self {
            terminator: None,
            ..Self::line(payload)
        }
    }

    fn fragment(payload: impl Into<Vec<u8>>) -> Self {
        Self {
            state: RecordState::AdapterFragment {
                reason: RecordFragmentReason::MalformedProviderFraming,
            },
            ..Self::line(payload)
        }
    }

    fn on(mut self, lane: FixtureLane) -> Self {
        self.lane = lane;
        self
    }

    fn monotonic(mut self, value: Option<u64>) -> Self {
        self.monotonic = value;
        self
    }

    fn exact_bytes(&self) -> Vec<u8> {
        let mut bytes = self.payload.clone();
        if let Some(terminator) = &self.terminator {
            bytes.extend_from_slice(terminator);
        }
        bytes
    }
}

fn retrieval_id(seed: u8) -> RetrievalId {
    RetrievalId::from_bytes([seed; 32])
}

fn ledger(seed: u8, records: &[RecordSpec]) -> EventLedger {
    let retrieval_id = retrieval_id(seed);
    let plan_id = PlanId::from_bytes([21; 32]);
    let plan_digest = PlanDigest::from_bytes([22; 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([23; 32]);
    let adapter = AdapterIdentity::new("framing-fixture", "1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let member = SourceMember::new(b"fixture-process".to_vec()).unwrap();
    let lanes = BTreeMap::from([
        (
            FixtureLane::Stdout,
            LaneKey::new(member.clone(), SourceStream::Stdout),
        ),
        (
            FixtureLane::Stderr,
            LaneKey::new(member, SourceStream::Stderr),
        ),
    ]);
    let mut lane_sequences = BTreeMap::<FixtureLane, u64>::new();
    let mut builder = LedgerBuilder::new(
        fetch_identity.clone(),
        source_identity_digest,
        SourceExactPolicy,
    );
    let mut source_bytes = 0u64;
    let mut payload_bytes = 0u64;

    for (position, record) in records.iter().enumerate() {
        let lane_sequence = lane_sequences.entry(record.lane).or_default();
        let source_record = match &record.terminator {
            Some(terminator) => RecordBytes::framed(record.payload.clone(), terminator.clone()),
            None => RecordBytes::whole(record.payload.clone()),
        };
        source_bytes = source_bytes
            .checked_add(u64::try_from(source_record.source_len()).unwrap())
            .unwrap();
        payload_bytes = payload_bytes
            .checked_add(u64::try_from(source_record.payload_len()).unwrap())
            .unwrap();
        let timestamps = EnvelopeTimestamps::new(
            None,
            None,
            None,
            record.monotonic.map(MonotonicTimestampNanos::new),
        );
        let envelope = RawEnvelopeV1::new(
            envelope_identity.clone(),
            EnvelopeOrdering::new(
                AcquisitionSequence::new(u64::try_from(position).unwrap()),
                lanes[&record.lane].clone(),
                LaneSequence::new(*lane_sequence),
            ),
            source_record,
            record.state,
        )
        .with_timestamps(timestamps);
        builder.accept(envelope).unwrap();
        *lane_sequence = lane_sequence.checked_add(1).unwrap();
    }

    let record_count = u64::try_from(records.len()).unwrap();
    let completeness = if records.iter().any(|record| !record.state.is_complete()) {
        FetchCompleteness::partial(
            FetchPartialReasons::new(FetchPartialReason::MalformedProviderFraming),
            None,
        )
    } else {
        FetchCompleteness::complete(CompletenessProof::OtherVersioned {
            version: 1,
            code: 91,
        })
    };
    let completion = FetchCompletion::new(
        fetch_identity,
        FetchTiming::new(UnixTimestampNanos::new(0), UnixTimestampNanos::new(1)),
        AcknowledgedCounts::new(record_count, payload_bytes, source_bytes),
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

fn framed<'ledger>(ledger: &'ledger EventLedger) -> BlockIndex<'ledger> {
    let index = frame_source_lanes_v1(ledger).unwrap();
    assert_exact_primary_partition(ledger, &index);
    index
}

fn assert_exact_primary_partition(ledger: &EventLedger, index: &BlockIndex<'_>) {
    let mut members = BTreeSet::new();
    for block in index.blocks() {
        assert_eq!(block.framing_policy().policy(), FRAMING_POLICY_NAME_V1);
        assert_eq!(block.framing_policy().version(), FRAMING_POLICY_VERSION_V1);
        let expansion = index.expand_block(block.id()).unwrap();
        let mut expected = Vec::new();
        for event in expansion.events() {
            assert!(members.insert(event.id()));
            expected.extend_from_slice(event.raw());
            assert_eq!(index.block_for_event(event.id()).unwrap().id(), block.id());
        }
        assert_eq!(expansion.exact_bytes(), expected);
    }
    assert_eq!(members.len(), ledger.len());
    assert_eq!(
        members,
        ledger.events().iter().map(|event| event.id()).collect()
    );
}

fn exact_block_bytes(index: &BlockIndex<'_>) -> Vec<Vec<u8>> {
    index
        .blocks()
        .iter()
        .map(|block| index.expand_block(block.id()).unwrap().exact_bytes())
        .collect()
}

#[test]
fn frozen_policy_and_hard_caps_are_auditable() {
    let policy = source_lane_framing_policy_v1();
    assert_eq!(policy.policy(), b"evidentrail/source-lane-atomic-framer");
    assert_eq!(policy.version(), b"1");
    assert_eq!(MAX_RECONSTRUCTED_BLOCK_LINES_V1, 256);
    assert_eq!(MAX_RECONSTRUCTED_BLOCK_BYTES_V1, 1_048_576);
    assert_eq!(MAX_RECONSTRUCTED_STATE_DEPTH_V1, 32);
    assert_eq!(MAX_CONTINUATION_GAP_NANOS_V1, 30_000_000_000);
}

#[test]
fn unrecognized_records_are_exact_fallback_singletons() {
    let records = [
        RecordSpec::line(b"ordinary log".to_vec()),
        RecordSpec::line(Vec::new()),
        RecordSpec::line(b"at lunch".to_vec()),
        RecordSpec::line(b"Caused by gossip".to_vec()),
    ];
    let ledger = ledger(1, &records);
    let index = framed(&ledger);

    assert_eq!(index.len(), records.len());
    assert_eq!(
        exact_block_bytes(&index),
        records.map(|record| record.exact_bytes())
    );
    for (position, block) in index.blocks().iter().enumerate() {
        assert_eq!(
            block.state(),
            BlockState::FallbackSingleton,
            "unexpected singleton state at {position}"
        );
        assert_eq!(block.confidence(), BlockConfidence::Certain);
    }
}

#[test]
fn python_traceback_and_nested_exception_chain_are_one_exact_block() {
    let records = [
        RecordSpec::line(b"Traceback (most recent call last):".to_vec()),
        RecordSpec::line(b"  File \"worker.py\", line 7, in run".to_vec()),
        RecordSpec::line(b"    parse(value)".to_vec()),
        RecordSpec::line(b"ValueError: first".to_vec()),
        RecordSpec::line(Vec::new()),
        RecordSpec::line(
            b"The above exception was the direct cause of the following exception:".to_vec(),
        ),
        RecordSpec::line(Vec::new()),
        RecordSpec::line(b"Traceback (most recent call last):".to_vec()),
        RecordSpec::line(b"  File \"worker.py\", line 9, in run".to_vec()),
        RecordSpec::line(b"RuntimeError: second".to_vec()),
        RecordSpec::line(b"unrelated".to_vec()),
    ];
    let ledger = ledger(2, &records);
    let index = framed(&ledger);

    assert_eq!(index.len(), 2);
    assert_eq!(index.blocks()[0].len(), 10);
    assert_eq!(index.blocks()[0].state(), BlockState::Reconstructed);
    assert_eq!(index.blocks()[0].confidence(), BlockConfidence::High);
    let expected = records[..10]
        .iter()
        .flat_map(RecordSpec::exact_bytes)
        .collect::<Vec<_>>();
    assert_eq!(
        index
            .expand_block(index.blocks()[0].id())
            .unwrap()
            .exact_bytes(),
        expected
    );
}

#[test]
fn jvm_dotnet_and_javascript_stack_families_are_bounded_blocks() {
    let cases = [
        vec![
            RecordSpec::line(
                b"Exception in thread \"main\" java.lang.IllegalStateException: no".to_vec(),
            ),
            RecordSpec::line(b"\tat app.Main.run(Main.java:7)".to_vec()),
            RecordSpec::line(b"Caused by: java.io.IOException: disk".to_vec()),
            RecordSpec::line(b"\tat app.Store.read(Store.java:3)".to_vec()),
            RecordSpec::line(b"\t... 1 more".to_vec()),
        ],
        vec![
            RecordSpec::line(b"Unhandled exception. System.InvalidOperationException: no".to_vec()),
            RecordSpec::line(b"   at Example.Work() in /src/App.cs:line 9".to_vec()),
            RecordSpec::line(b" ---> System.ArgumentException: inner".to_vec()),
            RecordSpec::line(b"   at Example.Parse() in /src/App.cs:line 3".to_vec()),
            RecordSpec::line(b"--- End of inner exception stack trace ---".to_vec()),
        ],
        vec![
            RecordSpec::line(b"TypeError: value is not callable".to_vec()),
            RecordSpec::line(b"    at run (/srv/app.js:4:2)".to_vec()),
            RecordSpec::line(b"    at main (/srv/app.js:8:1)".to_vec()),
        ],
    ];

    for (offset, records) in cases.iter().enumerate() {
        let ledger = ledger(10 + u8::try_from(offset).unwrap(), records);
        let index = framed(&ledger);
        assert_eq!(index.len(), 1);
        assert_eq!(index.blocks()[0].len(), records.len());
        assert_eq!(index.blocks()[0].state(), BlockState::Reconstructed);
        assert_eq!(index.blocks()[0].confidence(), BlockConfidence::High);
    }
}

#[test]
fn rust_and_go_panics_preserve_complete_source_sequences() {
    let rust = [
        RecordSpec::line(b"thread 'main' panicked at 'boom', src/main.rs:3:5".to_vec()),
        RecordSpec::line(b"stack backtrace:".to_vec()),
        RecordSpec::line(b"   0: demo::main".to_vec()),
        RecordSpec::line(b"             at ./src/main.rs:3:5".to_vec()),
        RecordSpec::line(b"note: run with `RUST_BACKTRACE=full`".to_vec()),
    ];
    let go = [
        RecordSpec::line(b"panic: boom".to_vec()),
        RecordSpec::line(Vec::new()),
        RecordSpec::line(b"goroutine 1 [running]:".to_vec()),
        RecordSpec::line(b"main.main()".to_vec()),
        RecordSpec::line(b"\t/tmp/main.go:4 +0x20".to_vec()),
        RecordSpec::line(b"created by runtime.main".to_vec()),
    ];

    for (seed, records) in [(20, rust.as_slice()), (21, go.as_slice())] {
        let ledger = ledger(seed, records);
        let index = framed(&ledger);
        assert_eq!(index.len(), 1);
        assert_eq!(index.blocks()[0].len(), records.len());
        assert_eq!(index.blocks()[0].state(), BlockState::Reconstructed);
    }
}

#[test]
fn compiler_diagnostics_assertions_and_test_diffs_are_intact() {
    let compiler = [
        RecordSpec::line(b"error[E0425]: cannot find value `missing`".to_vec()),
        RecordSpec::line(b" --> src/main.rs:2:5".to_vec()),
        RecordSpec::line(b"  |".to_vec()),
        RecordSpec::line(b"2 |     missing();".to_vec()),
        RecordSpec::line(b"  |     ^^^^^^^ not found".to_vec()),
        RecordSpec::line(b"  = help: define it first".to_vec()),
    ];
    let assertion = [
        RecordSpec::line(b"assertion `left == right` failed".to_vec()),
        RecordSpec::line(b"  left: 1".to_vec()),
        RecordSpec::line(b" right: 2".to_vec()),
    ];
    let diff = [
        RecordSpec::line(b"--- expected".to_vec()),
        RecordSpec::line(b"+++ actual".to_vec()),
        RecordSpec::line(b"@@ -1 +1 @@".to_vec()),
        RecordSpec::line(b"- old".to_vec()),
        RecordSpec::line(b"+ new".to_vec()),
    ];

    for (seed, records) in [
        (30, compiler.as_slice()),
        (31, assertion.as_slice()),
        (32, diff.as_slice()),
    ] {
        let ledger = ledger(seed, records);
        let index = framed(&ledger);
        assert_eq!(index.len(), 1);
        assert_eq!(index.blocks()[0].len(), records.len());
        assert_eq!(index.blocks()[0].state(), BlockState::Reconstructed);
    }
}

#[test]
fn binary_blank_crlf_and_missing_terminator_records_remain_exact() {
    let records = [
        RecordSpec::line(vec![0xff, 0xfe, b'x']),
        RecordSpec::line(b"nul\0inside".to_vec()),
        RecordSpec::line(Vec::new()),
        RecordSpec::whole(b"provider\natomic\r\nrecord".to_vec()),
        RecordSpec::crlf(b"Traceback (most recent call last):".to_vec()),
        RecordSpec::crlf(b"  File \"x.py\", line 1, in f".to_vec()),
        RecordSpec::unterminated(b"ValueError: exact final line".to_vec()),
    ];
    let ledger = ledger(40, &records);
    let index = framed(&ledger);

    assert_eq!(index.len(), 5);
    assert_eq!(index.blocks()[0].state(), BlockState::FallbackSingleton);
    assert_eq!(index.blocks()[0].confidence(), BlockConfidence::Unknown);
    assert_eq!(index.blocks()[1].state(), BlockState::FallbackSingleton);
    assert_eq!(index.blocks()[1].confidence(), BlockConfidence::Unknown);
    assert_eq!(index.blocks()[2].state(), BlockState::FallbackSingleton);
    assert_eq!(index.blocks()[2].confidence(), BlockConfidence::Certain);
    assert_eq!(index.blocks()[3].state(), BlockState::ProviderAtomic);
    assert_eq!(index.blocks()[3].confidence(), BlockConfidence::Certain);
    assert_eq!(index.blocks()[4].state(), BlockState::Reconstructed);
    assert_eq!(index.blocks()[4].len(), 3);
    let reconstructed = records[4..]
        .iter()
        .flat_map(RecordSpec::exact_bytes)
        .collect::<Vec<_>>();
    assert_eq!(
        index
            .expand_block(index.blocks()[4].id())
            .unwrap()
            .exact_bytes(),
        reconstructed
    );
}

#[test]
fn provider_atomic_complete_record_is_never_joined_or_split() {
    let records = [
        RecordSpec::whole(
            b"Traceback (most recent call last):\n  File \"x.py\"\nValueError: x".to_vec(),
        ),
        RecordSpec::line(b"  File \"not-attached.py\", line 1".to_vec()),
    ];
    let ledger = ledger(41, &records);
    let index = framed(&ledger);

    assert_eq!(index.len(), 2);
    assert_eq!(index.blocks()[0].state(), BlockState::ProviderAtomic);
    assert_eq!(index.blocks()[0].len(), 1);
    assert_eq!(index.blocks()[1].state(), BlockState::Ambiguous);
    assert_eq!(index.blocks()[1].confidence(), BlockConfidence::Low);
}

#[test]
fn global_lane_interleaving_does_not_split_same_lane_trace() {
    let records = [
        RecordSpec::line(b"Traceback (most recent call last):".to_vec()),
        RecordSpec::line(b"stdout one".to_vec()).on(FixtureLane::Stdout),
        RecordSpec::line(b"  File \"worker.py\", line 2, in run".to_vec()),
        RecordSpec::line(b"stdout two".to_vec()).on(FixtureLane::Stdout),
        RecordSpec::line(b"RuntimeError: failed".to_vec()),
    ];
    let ledger = ledger(50, &records);
    let index = framed(&ledger);

    let trace = index.block_for_event(ledger.events()[0].id()).unwrap();
    assert_eq!(trace.member_positions(), &[0, 2, 4]);
    assert_eq!(
        trace.member_lane_sequences(),
        &[
            LaneSequence::new(0),
            LaneSequence::new(1),
            LaneSequence::new(2)
        ]
    );
    assert_eq!(trace.state(), BlockState::Reconstructed);
    assert_eq!(
        index.block_for_event(ledger.events()[2].id()).unwrap().id(),
        trace.id()
    );
    assert_eq!(
        index.block_for_event(ledger.events()[4].id()).unwrap().id(),
        trace.id()
    );
    assert_ne!(
        index.block_for_event(ledger.events()[1].id()).unwrap().id(),
        trace.id()
    );
}

#[test]
fn orphan_false_continuations_and_fragments_never_attach() {
    let records = [
        RecordSpec::line(b"ordinary".to_vec()),
        RecordSpec::line(b"    at forged.heading(Field.java:1)".to_vec()),
        RecordSpec::line(b"Caused by: standalone text".to_vec()),
        RecordSpec::line(b"Traceback (most recent call last):".to_vec()),
        RecordSpec::fragment(b"  File \"fragment.py\", line 1".to_vec()),
        RecordSpec::line(b"ValueError: detached".to_vec()),
    ];
    let ledger = ledger(51, &records);
    let index = framed(&ledger);

    assert_eq!(index.len(), records.len());
    assert_eq!(index.blocks()[1].state(), BlockState::Ambiguous);
    assert_eq!(index.blocks()[1].confidence(), BlockConfidence::Low);
    assert_eq!(index.blocks()[2].state(), BlockState::Ambiguous);
    assert_eq!(index.blocks()[2].confidence(), BlockConfidence::Low);
    assert_eq!(index.blocks()[3].state(), BlockState::Ambiguous);
    assert_eq!(index.blocks()[3].confidence(), BlockConfidence::Low);
    assert_eq!(index.blocks()[4].state(), BlockState::Ambiguous);
    assert_eq!(index.blocks()[4].confidence(), BlockConfidence::Unknown);
    assert_eq!(
        index
            .expand_event(ledger.events()[4].id())
            .unwrap()
            .exact_bytes(),
        records[4].exact_bytes()
    );
}

#[test]
fn line_cap_stops_before_the_next_continuation() {
    let mut records = vec![RecordSpec::line(
        b"Traceback (most recent call last):".to_vec(),
    )];
    for line in 0..MAX_RECONSTRUCTED_BLOCK_LINES_V1 {
        records.push(RecordSpec::line(
            format!("  File \"f{line}.py\", line 1, in x").into_bytes(),
        ));
    }
    records.push(RecordSpec::line(b"after cap".to_vec()));
    let ledger = ledger(60, &records);
    let index = framed(&ledger);

    assert_eq!(index.blocks()[0].len(), MAX_RECONSTRUCTED_BLOCK_LINES_V1);
    assert_eq!(index.blocks()[0].state(), BlockState::Reconstructed);
    assert_eq!(index.blocks()[0].confidence(), BlockConfidence::Medium);
    let first_after_cap = ledger.events()[MAX_RECONSTRUCTED_BLOCK_LINES_V1].id();
    let after_cap_block = index.block_for_event(first_after_cap).unwrap();
    assert_eq!(after_cap_block.len(), 1);
    assert_eq!(after_cap_block.state(), BlockState::Ambiguous);
    assert_eq!(
        index.expand_event(first_after_cap).unwrap().exact_bytes(),
        records[MAX_RECONSTRUCTED_BLOCK_LINES_V1].exact_bytes()
    );
}

#[test]
fn byte_cap_stops_before_an_oversized_continuation() {
    let records = [
        RecordSpec::line(b"Traceback (most recent call last):".to_vec()),
        RecordSpec::line({
            let mut bytes = b"    ".to_vec();
            bytes.resize(MAX_RECONSTRUCTED_BLOCK_BYTES_V1 + 1, b'x');
            bytes
        }),
        RecordSpec::line(b"after".to_vec()),
    ];
    let ledger = ledger(61, &records);
    let index = framed(&ledger);

    assert_eq!(index.len(), 3);
    assert_eq!(index.blocks()[0].state(), BlockState::Ambiguous);
    assert_eq!(index.blocks()[1].state(), BlockState::Ambiguous);
    assert_eq!(index.blocks()[1].len(), 1);
    assert_eq!(
        index
            .expand_block(index.blocks()[1].id())
            .unwrap()
            .exact_bytes(),
        records[1].exact_bytes()
    );
}

#[test]
fn state_depth_cap_stops_before_nested_cause() {
    let mut records = vec![
        RecordSpec::line(b"Exception in thread \"main\" java.lang.RuntimeException: root".to_vec()),
        RecordSpec::line(b"\tat app.Main.main(Main.java:1)".to_vec()),
    ];
    for depth in 0..MAX_RECONSTRUCTED_STATE_DEPTH_V1 {
        records.push(RecordSpec::line(
            format!("Caused by: java.lang.RuntimeException: {depth}").into_bytes(),
        ));
    }
    let ledger = ledger(62, &records);
    let index = framed(&ledger);

    let expected_first_len = 1 + usize::from(MAX_RECONSTRUCTED_STATE_DEPTH_V1);
    assert_eq!(index.blocks()[0].len(), expected_first_len);
    assert_eq!(index.blocks()[0].confidence(), BlockConfidence::Medium);
    let rejected_cause = ledger.events()[expected_first_len].id();
    assert_eq!(index.block_for_event(rejected_cause).unwrap().len(), 1);
    assert_eq!(
        index.block_for_event(rejected_cause).unwrap().state(),
        BlockState::Ambiguous
    );
}

#[test]
fn only_same_lane_monotonic_time_can_authorize_high_confidence_joining() {
    let within = [
        RecordSpec::line(b"TypeError: bad".to_vec()).monotonic(Some(10)),
        RecordSpec::line(b"    at one (/a.js:1:1)".to_vec())
            .monotonic(Some(10 + MAX_CONTINUATION_GAP_NANOS_V1)),
        RecordSpec::line(b"    at two (/a.js:2:1)".to_vec())
            .monotonic(Some(11 + 2 * MAX_CONTINUATION_GAP_NANOS_V1)),
    ];
    let within_ledger = ledger(70, &within);
    let within_index = framed(&within_ledger);
    assert_eq!(within_index.blocks()[0].len(), 2);
    assert_eq!(within_index.blocks()[0].confidence(), BlockConfidence::High);
    assert_eq!(
        within_index
            .block_for_event(within_ledger.events()[2].id())
            .unwrap()
            .len(),
        1
    );

    let missing = [
        RecordSpec::line(b"TypeError: bad".to_vec()).monotonic(None),
        RecordSpec::line(b"    at one (/a.js:1:1)".to_vec()).monotonic(Some(20)),
    ];
    let missing_ledger = ledger(71, &missing);
    let missing_index = framed(&missing_ledger);
    assert_eq!(missing_index.blocks()[0].len(), 2);
    assert_eq!(
        missing_index.blocks()[0].confidence(),
        BlockConfidence::Medium
    );

    let reversed = [
        RecordSpec::line(b"TypeError: bad".to_vec()).monotonic(Some(20)),
        RecordSpec::line(b"    at one (/a.js:1:1)".to_vec()).monotonic(Some(19)),
    ];
    let reversed_ledger = ledger(72, &reversed);
    let reversed_index = framed(&reversed_ledger);
    assert_eq!(reversed_index.len(), 2);
    assert_eq!(reversed_index.blocks()[0].state(), BlockState::Ambiguous);
    assert_eq!(reversed_index.blocks()[1].state(), BlockState::Ambiguous);
}

#[test]
fn ineligible_structural_lookahead_cannot_cause_blank_absorption() {
    let records = [
        RecordSpec::line(b"panic: bounded".to_vec()).monotonic(Some(0)),
        RecordSpec::line(Vec::new()).monotonic(Some(1)),
        RecordSpec::line(b"goroutine 1 [running]:".to_vec())
            .monotonic(Some(MAX_CONTINUATION_GAP_NANOS_V1 + 2)),
    ];
    let ledger = ledger(73, &records);
    let index = framed(&ledger);

    assert_eq!(index.len(), 3);
    assert_eq!(index.blocks()[0].state(), BlockState::Ambiguous);
    assert_eq!(index.blocks()[1].state(), BlockState::FallbackSingleton);
    assert_eq!(index.blocks()[2].state(), BlockState::Ambiguous);
    assert_eq!(
        index
            .expand_event(ledger.events()[1].id())
            .unwrap()
            .exact_bytes(),
        b"\n"
    );
}

#[test]
fn unknown_record_delimiter_is_never_treated_as_a_line_boundary() {
    let records = [
        RecordSpec::delimited(
            b"Traceback (most recent call last):".to_vec(),
            b"<record-end>".to_vec(),
        ),
        RecordSpec::line(b"  File \"must-not-join.py\", line 1".to_vec()),
    ];
    let ledger = ledger(74, &records);
    let index = framed(&ledger);

    assert_eq!(index.len(), 2);
    assert_eq!(index.blocks()[0].state(), BlockState::FallbackSingleton);
    assert_eq!(index.blocks()[0].confidence(), BlockConfidence::Unknown);
    assert_eq!(
        index
            .expand_event(ledger.events()[0].id())
            .unwrap()
            .exact_bytes(),
        records[0].exact_bytes()
    );
    assert_eq!(index.blocks()[1].state(), BlockState::Ambiguous);
}

#[test]
fn replay_is_deterministic_and_retrieval_identity_isolated() {
    let records = [
        RecordSpec::line(b"panic: exact".to_vec()),
        RecordSpec::line(b"goroutine 1 [running]:".to_vec()),
        RecordSpec::line(b"main.main()".to_vec()),
        RecordSpec::line(b"\t/tmp/main.go:1 +0x1".to_vec()),
    ];
    let first_ledger = ledger(80, &records);
    let replay_ledger = ledger(80, &records);
    let foreign_ledger = ledger(81, &records);
    let first = framed(&first_ledger);
    let replay = framed(&replay_ledger);
    let foreign = framed(&foreign_ledger);

    assert_eq!(
        first_ledger
            .events()
            .iter()
            .map(|event| event.id())
            .collect::<Vec<_>>(),
        replay_ledger
            .events()
            .iter()
            .map(|event| event.id())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        first
            .blocks()
            .iter()
            .map(|block| block.id())
            .collect::<Vec<_>>(),
        replay
            .blocks()
            .iter()
            .map(|block| block.id())
            .collect::<Vec<_>>()
    );
    assert_ne!(first.blocks()[0].id(), foreign.blocks()[0].id());
}

#[test]
fn cross_lane_permutation_does_not_change_lane_local_grouping() {
    let a = [
        RecordSpec::line(b"Traceback (most recent call last):".to_vec()),
        RecordSpec::line(b"out-a".to_vec()).on(FixtureLane::Stdout),
        RecordSpec::line(b"  File \"x.py\", line 1".to_vec()),
        RecordSpec::line(b"out-b".to_vec()).on(FixtureLane::Stdout),
        RecordSpec::line(b"ValueError: x".to_vec()),
    ];
    let b = [
        RecordSpec::line(b"out-a".to_vec()).on(FixtureLane::Stdout),
        RecordSpec::line(b"Traceback (most recent call last):".to_vec()),
        RecordSpec::line(b"out-b".to_vec()).on(FixtureLane::Stdout),
        RecordSpec::line(b"  File \"x.py\", line 1".to_vec()),
        RecordSpec::line(b"ValueError: x".to_vec()),
    ];
    let ledger_a = ledger(82, &a);
    let ledger_b = ledger(83, &b);
    let index_a = framed(&ledger_a);
    let index_b = framed(&ledger_b);

    let stderr_groups = |index: &BlockIndex<'_>| {
        index
            .blocks()
            .iter()
            .filter(|block| block.lane().stream() == &SourceStream::Stderr)
            .map(|block| index.expand_block(block.id()).unwrap().exact_bytes())
            .collect::<Vec<_>>()
    };
    assert_eq!(stderr_groups(&index_a), stderr_groups(&index_b));
}

#[test]
fn diagnostics_are_contentless() {
    let canary = "FRAMING_SECRET_CANARY";
    let records = [RecordSpec::line(canary.as_bytes().to_vec())];
    let ledger = ledger(90, &records);
    let index = framed(&ledger);
    let expansion = index.expand_block(index.blocks()[0].id()).unwrap();
    let error = SourceLaneFramingError::BlockByteCountOverflow;

    for diagnostic in [
        format!("{index:?}"),
        format!("{:?}", index.blocks()[0]),
        format!("{expansion:?}"),
        format!("{error:?}"),
        error.to_string(),
        format!("{:?}", source_lane_framing_policy_v1()),
    ] {
        assert!(!diagnostic.contains(canary));
    }
    assert_eq!(error.code(), "EVIDENTRAIL_FRAMING_BLOCK_BYTE_COUNT_OVERFLOW");
}
