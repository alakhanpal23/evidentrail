use std::cell::Cell;

use evidentrail_core::{
    DeterministicPolicy, EnvelopeSink, LedgerBuildError, LedgerBuilder, PolicyAuthorization,
    PolicyDigest, expected_source_record_id,
};
use evidentrail_ingest::{
    Cancellation, CancellationToken, ExecutionContext, InMemoryReplayAdapter, IngestError,
    MAX_AUTHORIZED_RECORD_BYTES, SourceAdapter,
};
use evidentrail_schema::bounds::{JSON_SAFE_INTEGER_MAX, MAX_RECORD_TERMINATOR_BYTES};
use evidentrail_schema::{
    AcquisitionSequence, AdapterIdentity, AdapterOutcome, CompletenessProof, FetchCompleteness,
    FetchErrorCode, FetchIdentity, FetchPartialReason, LaneKey, LaneSequence, PlanDigest, PlanId,
    RawEnvelopeV1, RecordBytes, RecordState, RetrievalId, SourceIdentityDigest, SourceMember,
    SourceStream,
};

fn context(seed: u8, adapter_kind: &str) -> ExecutionContext {
    ExecutionContext::new(
        FetchIdentity::new(
            RetrievalId::from_bytes([seed; 32]),
            PlanId::from_bytes([seed.wrapping_add(1); 32]),
            PlanDigest::from_bytes([seed.wrapping_add(2); 32]),
            AdapterIdentity::new(adapter_kind, "1.0.0").unwrap(),
        ),
        SourceIdentityDigest::from_bytes([seed.wrapping_add(3); 32]),
    )
}

#[derive(Clone, Copy)]
struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

#[derive(Clone, Copy)]
struct OmitPolicy;

impl DeterministicPolicy for OmitPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::OmittedByPolicy {
            policy_digest: PolicyDigest::from_bytes([77; 32]),
        }
    }
}

fn fixture_envelope(
    context: &ExecutionContext,
    sequence: u64,
    member: &SourceMember,
    record: RecordBytes,
) -> RawEnvelopeV1 {
    RawEnvelopeV1::new(
        context.envelope_identity(),
        evidentrail_schema::EnvelopeOrdering::new(
            AcquisitionSequence::new(sequence),
            LaneKey::new(member.clone(), SourceStream::FileMember),
            LaneSequence::new(sequence),
        ),
        record,
        RecordState::Complete,
    )
}

fn replay_fixture(envelopes: Vec<RawEnvelopeV1>) -> InMemoryReplayAdapter {
    let max_records = u64::try_from(envelopes.len()).unwrap().max(1);
    let max_source_bytes = envelopes
        .iter()
        .try_fold(0_u64, |total, envelope| {
            total.checked_add(u64::try_from(envelope.record().source_len()).unwrap())
        })
        .unwrap()
        .max(1);
    InMemoryReplayAdapter::new(envelopes, max_records, max_source_bytes).unwrap()
}

fn execute_replay<P>(
    replay: &InMemoryReplayAdapter,
    context: &ExecutionContext,
    policy: P,
) -> evidentrail_core::EventLedger
where
    P: DeterministicPolicy,
{
    let mut builder = LedgerBuilder::new(
        context.fetch_identity().clone(),
        context.source_identity_digest(),
        policy,
    );
    let completion = replay.execute(context, &mut builder).unwrap();
    builder.seal(completion).unwrap()
}

#[test]
fn replay_is_deterministic_lossless_and_uses_only_the_fixture_proof() {
    let context = context(7, "in-memory-fixture");
    let member = SourceMember::new(b"fixture:synthetic".to_vec()).unwrap();
    let replay = replay_fixture(vec![
        fixture_envelope(
            &context,
            0,
            &member,
            RecordBytes::framed(b"alpha".to_vec(), b"\r\n".to_vec()),
        ),
        fixture_envelope(
            &context,
            1,
            &member,
            RecordBytes::whole(vec![0xff, 0x00, b'Z']),
        ),
    ]);

    let first = execute_replay(&replay, &context, SourceExactPolicy);
    let second = execute_replay(&replay, &context, SourceExactPolicy);

    assert_eq!(
        first
            .events()
            .iter()
            .map(|event| (event.id(), event.raw().to_vec()))
            .collect::<Vec<_>>(),
        second
            .events()
            .iter()
            .map(|event| (event.id(), event.raw().to_vec()))
            .collect::<Vec<_>>()
    );
    assert_eq!(first.fetch_completion(), second.fetch_completion());
    assert_eq!(first.acquisition_receipt(), second.acquisition_receipt());
    assert_eq!(
        first.passthrough().flatten().copied().collect::<Vec<_>>(),
        b"alpha\r\n\xff\0Z"
    );
    assert_eq!(
        first.fetch_completion().completeness(),
        &FetchCompleteness::complete(CompletenessProof::InMemoryFixtureExhausted)
    );
}

#[test]
fn replay_policy_omission_is_a_durable_acknowledgement() {
    let context = context(8, "in-memory-fixture");
    let member = SourceMember::new(b"fixture:omission".to_vec()).unwrap();
    let replay = replay_fixture(vec![fixture_envelope(
        &context,
        0,
        &member,
        RecordBytes::whole(b"secret-payload".to_vec()),
    )]);

    let ledger = execute_replay(&replay, &context, OmitPolicy);
    assert!(ledger.events().is_empty());
    assert_eq!(ledger.fetch_completion().acknowledged().records(), 1);
    assert_eq!(ledger.acquisition_receipt().acknowledged_count(), 1);
    assert_eq!(ledger.acquisition_receipt().counts().omitted_by_policy, 1);
    assert!(matches!(
        ledger.fetch_completion().completeness(),
        FetchCompleteness::Complete { .. }
    ));
}

struct FailAfter<P> {
    inner: LedgerBuilder<P>,
    accepted: usize,
    limit: usize,
}

impl<P> EnvelopeSink for FailAfter<P>
where
    P: DeterministicPolicy,
{
    fn accept(
        &mut self,
        envelope: RawEnvelopeV1,
    ) -> Result<evidentrail_schema::SinkAck, LedgerBuildError> {
        if self.accepted == self.limit {
            return Err(LedgerBuildError::EventCountOverflow);
        }
        let acknowledgement = self.inner.accept(envelope)?;
        self.accepted += 1;
        Ok(acknowledgement)
    }
}

#[test]
fn replay_sink_failure_preserves_only_durable_acknowledgements() {
    let context = context(9, "in-memory-fixture");
    let member = SourceMember::new(b"fixture:sink-failure".to_vec()).unwrap();
    let replay = replay_fixture(
        (0_u64..3)
            .map(|sequence| {
                fixture_envelope(
                    &context,
                    sequence,
                    &member,
                    RecordBytes::whole(vec![b'a' + u8::try_from(sequence).unwrap()]),
                )
            })
            .collect(),
    );
    let mut sink = FailAfter {
        inner: LedgerBuilder::new(
            context.fetch_identity().clone(),
            context.source_identity_digest(),
            SourceExactPolicy,
        ),
        accepted: 0,
        limit: 1,
    };

    let completion = replay.execute(&context, &mut sink).unwrap();
    assert_eq!(completion.acknowledged().records(), 1);
    assert_eq!(completion.adapter_outcome(), AdapterOutcome::SinkStopped);
    assert_eq!(completion.error_codes(), &[FetchErrorCode::SinkFailure]);
    let FetchCompleteness::Partial { reasons, .. } = completion.completeness() else {
        panic!("sink failure must be partial");
    };
    assert_eq!(
        reasons.iter().collect::<Vec<_>>(),
        vec![FetchPartialReason::SinkFailure]
    );
    let ledger = sink.inner.seal(completion).unwrap();
    assert_eq!(ledger.events().len(), 1);
    assert_eq!(ledger.acquisition_receipt().acknowledged_count(), 1);
}

struct CancelAfter<P> {
    inner: LedgerBuilder<P>,
    accepted: usize,
    cancellation: CancellationToken,
}

impl<P> EnvelopeSink for CancelAfter<P>
where
    P: DeterministicPolicy,
{
    fn accept(
        &mut self,
        envelope: RawEnvelopeV1,
    ) -> Result<evidentrail_schema::SinkAck, LedgerBuildError> {
        let acknowledgement = self.inner.accept(envelope)?;
        self.accepted += 1;
        if self.accepted == 1 {
            self.cancellation.cancel();
        }
        Ok(acknowledgement)
    }
}

#[test]
fn replay_cancellation_preserves_the_acknowledged_prefix() {
    let context = context(12, "in-memory-fixture");
    let member = SourceMember::new(b"fixture:cancellation".to_vec()).unwrap();
    let replay = replay_fixture(
        (0_u64..3)
            .map(|sequence| {
                fixture_envelope(
                    &context,
                    sequence,
                    &member,
                    RecordBytes::whole(vec![b'a' + u8::try_from(sequence).unwrap()]),
                )
            })
            .collect(),
    );
    let cancellation = CancellationToken::new();
    let mut sink = CancelAfter {
        inner: LedgerBuilder::new(
            context.fetch_identity().clone(),
            context.source_identity_digest(),
            SourceExactPolicy,
        ),
        accepted: 0,
        cancellation: cancellation.clone(),
    };

    let completion = replay
        .execute_with_cancellation(&context, &mut sink, &cancellation)
        .unwrap();
    assert_eq!(completion.acknowledged().records(), 1);
    assert_eq!(completion.adapter_outcome(), AdapterOutcome::Cancelled);
    assert!(completion.error_codes().is_empty());
    let FetchCompleteness::Partial { reasons, .. } = completion.completeness() else {
        panic!("cancellation must be partial");
    };
    assert_eq!(
        reasons.iter().collect::<Vec<_>>(),
        vec![FetchPartialReason::Cancelled]
    );
    assert_eq!(sink.inner.seal(completion).unwrap().events().len(), 1);
}

struct CancelDuringPrevalidation {
    checks: Cell<usize>,
}

impl Cancellation for CancelDuringPrevalidation {
    fn is_cancelled(&self) -> bool {
        let check = self.checks.get() + 1;
        self.checks.set(check);
        check >= 2
    }
}

#[test]
fn replay_prevalidation_cancellation_mutates_no_sink_state() {
    let context = context(15, "in-memory-fixture");
    let member = SourceMember::new(b"fixture:prevalidation-cancellation".to_vec()).unwrap();
    let replay = replay_fixture(
        (0_u64..4)
            .map(|sequence| {
                fixture_envelope(
                    &context,
                    sequence,
                    &member,
                    RecordBytes::whole(vec![b'a' + u8::try_from(sequence).unwrap()]),
                )
            })
            .collect(),
    );
    let mut sink = FailAfter {
        inner: LedgerBuilder::new(
            context.fetch_identity().clone(),
            context.source_identity_digest(),
            SourceExactPolicy,
        ),
        accepted: 0,
        limit: usize::MAX,
    };
    let cancellation = CancelDuringPrevalidation {
        checks: Cell::new(0),
    };

    let completion = replay
        .execute_with_cancellation(&context, &mut sink, &cancellation)
        .unwrap();
    assert_eq!(cancellation.checks.get(), 2);
    assert_eq!(sink.accepted, 0);
    assert_eq!(completion.acknowledged().records(), 0);
    assert_eq!(completion.adapter_outcome(), AdapterOutcome::Cancelled);
}

#[derive(Clone, Copy)]
enum ForgedAcknowledgement {
    WrongSourceRecord,
    WrongSourceExactByteCount,
    NonzeroOmission,
    OversizedPostPolicy,
}

struct ForgedAcknowledgementSink {
    forged: ForgedAcknowledgement,
    accepted_envelopes: usize,
}

impl EnvelopeSink for ForgedAcknowledgementSink {
    fn accept(
        &mut self,
        envelope: RawEnvelopeV1,
    ) -> Result<evidentrail_schema::SinkAck, LedgerBuildError> {
        self.accepted_envelopes += 1;
        let retrieval_id = envelope.identity().retrieval_id();
        let sequence = envelope.ordering().acquisition_sequence();
        let expected_source_record = expected_source_record_id(&envelope);
        let source_bytes = u64::try_from(envelope.record().source_len()).unwrap();
        let source_exact = || evidentrail_schema::AcquisitionOutcome::Persisted {
            event_id: evidentrail_schema::EventId::from_bytes([0x31; 32]),
            exactness_basis: evidentrail_schema::ExactnessBasis::SourceExact,
        };
        let (source_record_id, authorized_byte_count, outcome) = match self.forged {
            ForgedAcknowledgement::WrongSourceRecord => (
                evidentrail_schema::SourceRecordId::from_bytes([0x32; 32]),
                source_bytes,
                source_exact(),
            ),
            ForgedAcknowledgement::WrongSourceExactByteCount => {
                (expected_source_record, source_bytes + 1, source_exact())
            }
            ForgedAcknowledgement::NonzeroOmission => (
                expected_source_record,
                1,
                evidentrail_schema::AcquisitionOutcome::OmittedByPolicy {
                    policy_digest: PolicyDigest::from_bytes([0x33; 32]),
                },
            ),
            ForgedAcknowledgement::OversizedPostPolicy => (
                expected_source_record,
                u64::try_from(MAX_AUTHORIZED_RECORD_BYTES).unwrap() + 1,
                evidentrail_schema::AcquisitionOutcome::Persisted {
                    event_id: evidentrail_schema::EventId::from_bytes([0x34; 32]),
                    exactness_basis: evidentrail_schema::ExactnessBasis::PostPolicy {
                        policy_digest: PolicyDigest::from_bytes([0x35; 32]),
                        transformation_receipt_id:
                            evidentrail_schema::TransformationReceiptId::from_bytes([0x36; 32]),
                    },
                },
            ),
        };
        Ok(evidentrail_schema::SinkAck::new(
            retrieval_id,
            source_record_id,
            sequence,
            authorized_byte_count,
            outcome,
        ))
    }
}

#[test]
fn replay_rejects_forged_acknowledgements_before_accounting() {
    for forged in [
        ForgedAcknowledgement::WrongSourceRecord,
        ForgedAcknowledgement::WrongSourceExactByteCount,
        ForgedAcknowledgement::NonzeroOmission,
        ForgedAcknowledgement::OversizedPostPolicy,
    ] {
        let context = context(19, "in-memory-fixture");
        let member = SourceMember::new(b"fixture:forged-ack".to_vec()).unwrap();
        let replay = replay_fixture(vec![fixture_envelope(
            &context,
            0,
            &member,
            RecordBytes::framed(b"secret".to_vec(), b"\n".to_vec()),
        )]);
        let mut sink = ForgedAcknowledgementSink {
            forged,
            accepted_envelopes: 0,
        };

        let completion = replay.execute(&context, &mut sink).unwrap();
        assert_eq!(sink.accepted_envelopes, 1);
        assert_eq!(completion.acknowledged().records(), 0);
        assert_eq!(completion.acknowledged().source_bytes(), 0);
        assert_eq!(completion.adapter_outcome(), AdapterOutcome::SinkStopped);
        assert_eq!(completion.error_codes(), &[FetchErrorCode::SinkFailure]);
    }
}

#[test]
fn replay_constructor_enforces_bounds_and_fixture_shape_before_execution() {
    let context = context(16, "in-memory-fixture");
    let member = SourceMember::new(b"fixture:construction-bounds".to_vec()).unwrap();
    let first = fixture_envelope(&context, 0, &member, RecordBytes::whole(b"a".to_vec()));
    let second = fixture_envelope(&context, 1, &member, RecordBytes::whole(b"b".to_vec()));

    for invalid in [
        InMemoryReplayAdapter::new(vec![first.clone()], 0, 1),
        InMemoryReplayAdapter::new(vec![first.clone()], 1, 0),
        InMemoryReplayAdapter::new(vec![first.clone()], JSON_SAFE_INTEGER_MAX + 1, 1),
        InMemoryReplayAdapter::new(vec![first.clone()], 1, JSON_SAFE_INTEGER_MAX + 1),
    ] {
        assert_eq!(invalid, Err(IngestError::InvalidLimit));
    }
    assert_eq!(
        InMemoryReplayAdapter::new(vec![first.clone(), second], 1, 2),
        Err(IngestError::InvalidReplayFixture)
    );
    assert_eq!(
        InMemoryReplayAdapter::new(
            vec![fixture_envelope(
                &context,
                0,
                &member,
                RecordBytes::whole(b"ab".to_vec()),
            )],
            1,
            1,
        ),
        Err(IngestError::InvalidReplayFixture)
    );
    let oversized_record = fixture_envelope(
        &context,
        0,
        &member,
        RecordBytes::whole(vec![0; MAX_AUTHORIZED_RECORD_BYTES + 1]),
    );
    assert_eq!(
        InMemoryReplayAdapter::new(
            vec![oversized_record],
            1,
            u64::try_from(MAX_AUTHORIZED_RECORD_BYTES).unwrap() + 1,
        ),
        Err(IngestError::InvalidReplayFixture)
    );
    let oversized_terminator = fixture_envelope(
        &context,
        0,
        &member,
        RecordBytes::framed(Vec::new(), vec![b'\n'; MAX_RECORD_TERMINATOR_BYTES + 1]),
    );
    assert_eq!(
        InMemoryReplayAdapter::new(
            vec![oversized_terminator],
            1,
            u64::try_from(MAX_RECORD_TERMINATOR_BYTES).unwrap() + 1,
        ),
        Err(IngestError::InvalidReplayFixture)
    );
    let accepted = InMemoryReplayAdapter::new(vec![first], 1, 1).unwrap();
    assert_eq!(accepted.max_records(), 1);
    assert_eq!(accepted.max_source_bytes(), 1);
    assert_eq!(accepted.fixture_source_bytes(), 1);
}

#[test]
fn invalid_replay_is_rejected_before_sink_mutation() {
    let context = context(10, "in-memory-fixture");
    let member = SourceMember::new(b"fixture:invalid".to_vec()).unwrap();
    let replay = replay_fixture(vec![fixture_envelope(
        &context,
        1,
        &member,
        RecordBytes::whole(b"payload".to_vec()),
    )]);
    let mut builder = LedgerBuilder::new(
        context.fetch_identity().clone(),
        context.source_identity_digest(),
        SourceExactPolicy,
    );
    assert_eq!(
        replay.execute(&context, &mut builder),
        Err(IngestError::InvalidReplayFixture)
    );
}

#[test]
fn replay_debug_and_errors_are_contentless() {
    const RAW: &[u8] = b"CANARY_RAW_CONTENT_9fa1";
    const MEMBER: &[u8] = b"CANARY_MEMBER_PATH_722c";
    const PATH: &[u8] = b"CANARY_SOURCE_PATH_2c4f";
    const QUERY: &[u8] = b"CANARY_QUERY_5a91";
    let context = ExecutionContext::new(
        FetchIdentity::new(
            RetrievalId::from_bytes([11; 32]),
            PlanId::from_bytes([12; 32]),
            PlanDigest::from_bytes(*b"CANARY_QUERY_5a91_______________"),
            AdapterIdentity::new("in-memory-fixture", "1").unwrap(),
        ),
        SourceIdentityDigest::from_bytes([13; 32]),
    );
    let member = SourceMember::new(MEMBER.to_vec()).unwrap();
    let envelope = fixture_envelope(&context, 0, &member, RecordBytes::whole(RAW.to_vec()));
    let replay = replay_fixture(vec![envelope.clone()]);
    for output in [
        format!("{envelope:?}"),
        format!("{replay:?}"),
        format!("{context:?}"),
        format!("{:?}", IngestError::InvalidReplayFixture),
        IngestError::InvalidReplayFixture.to_string(),
    ] {
        for canary in [RAW, MEMBER, PATH, QUERY] {
            assert!(
                !output
                    .as_bytes()
                    .windows(canary.len())
                    .any(|part| part == canary),
                "debug output leaked a canary"
            );
        }
    }
}
