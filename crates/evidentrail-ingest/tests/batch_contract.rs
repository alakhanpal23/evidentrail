use std::collections::BTreeMap;

use evidentrail_core::{DeterministicPolicy, LedgerBuilder, PolicyAuthorization};
use evidentrail_ingest::{
    BatchOperationIdV1, BatchSinkErrorV1, EnvelopeBatchAcknowledgementsV1, EnvelopeBatchSinkV1,
    EnvelopeBatchV1, ExecutionContext, SingleEnvelopeBatchSinkV1,
};
use evidentrail_schema::{
    AcquisitionSequence, AdapterIdentity, EnvelopeOrdering, FetchIdentity, LaneKey, LaneSequence,
    PlanDigest, PlanId, RawEnvelopeV1, RecordBytes, RecordState, RetrievalId, SinkAck,
    SourceIdentityDigest, SourceMember, SourceStream,
};

#[derive(Clone, Copy)]
struct SourceExact;

impl DeterministicPolicy for SourceExact {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

fn context(seed: u8) -> ExecutionContext {
    ExecutionContext::new(
        FetchIdentity::new(
            RetrievalId::from_bytes([seed; 32]),
            PlanId::from_bytes([seed.wrapping_add(1); 32]),
            PlanDigest::from_bytes([seed.wrapping_add(2); 32]),
            AdapterIdentity::new("batch-contract", "1").unwrap(),
        ),
        SourceIdentityDigest::from_bytes([seed.wrapping_add(3); 32]),
    )
}

fn envelope(context: &ExecutionContext, sequence: u64, bytes: &[u8]) -> RawEnvelopeV1 {
    RawEnvelopeV1::new(
        context.envelope_identity(),
        EnvelopeOrdering::new(
            AcquisitionSequence::new(sequence),
            LaneKey::new(
                SourceMember::new(b"MEMBER_CANARY".to_vec()).unwrap(),
                SourceStream::LogStream,
            ),
            LaneSequence::new(sequence),
        ),
        RecordBytes::whole(bytes.to_vec()),
        RecordState::Complete,
    )
}

struct IdempotentSink<P> {
    inner: LedgerBuilder<P>,
    committed: BTreeMap<BatchOperationIdV1, ([u8; 32], Vec<SinkAck>)>,
}

impl<P> EnvelopeBatchSinkV1 for IdempotentSink<P>
where
    P: DeterministicPolicy,
{
    fn commit_batch(
        &mut self,
        batch: &EnvelopeBatchV1,
    ) -> Result<EnvelopeBatchAcknowledgementsV1, BatchSinkErrorV1> {
        if let Some((digest, acknowledgements)) = self.committed.get(&batch.operation_id()) {
            if digest != batch.canonical_digest() {
                return Err(BatchSinkErrorV1::operation_conflict());
            }
            return EnvelopeBatchAcknowledgementsV1::verify(batch, acknowledgements.clone());
        }
        let mut compatibility = SingleEnvelopeBatchSinkV1::new(&mut self.inner);
        let committed = compatibility.commit_batch(batch)?;
        let acknowledgements = committed.as_slice().to_vec();
        self.committed.insert(
            batch.operation_id(),
            (*batch.canonical_digest(), acknowledgements.clone()),
        );
        EnvelopeBatchAcknowledgementsV1::verify(batch, acknowledgements)
    }
}

#[test]
fn operation_identity_is_stable_for_ordinal_while_digest_binds_changed_bytes() {
    let context = context(1);
    let first = EnvelopeBatchV1::new(&context, 7, [envelope(&context, 0, b"first")]).unwrap();
    let changed = EnvelopeBatchV1::new(&context, 7, [envelope(&context, 0, b"changed")]).unwrap();
    assert_eq!(first.operation_id(), changed.operation_id());
    assert_ne!(first.canonical_digest(), changed.canonical_digest());

    let mut sink = IdempotentSink {
        inner: LedgerBuilder::new(
            context.fetch_identity().clone(),
            context.source_identity_digest(),
            SourceExact,
        ),
        committed: BTreeMap::new(),
    };
    let first_ack = sink.commit_batch(&first).unwrap();
    let retry_ack = sink.commit_batch(&first).unwrap();
    assert_eq!(first_ack.as_slice(), retry_ack.as_slice());
    let error = sink.commit_batch(&changed).unwrap_err();
    assert_eq!(
        error.to_string(),
        "EVIDENTRAIL_BATCH_SINK_OPERATION_CONFLICT"
    );
}

#[test]
fn batch_rejects_cross_context_and_noncontiguous_order_before_sink_mutation() {
    let first_context = context(2);
    let other_context = context(3);
    let cross_context = EnvelopeBatchV1::new(
        &first_context,
        0,
        [envelope(&other_context, 0, b"CONTENT_CANARY")],
    )
    .unwrap_err();
    assert_eq!(
        cross_context.to_string(),
        "EVIDENTRAIL_BATCH_CROSS_CONTEXT_ENVELOPE"
    );

    let noncontiguous = EnvelopeBatchV1::new(
        &first_context,
        0,
        [
            envelope(&first_context, 0, b"a"),
            envelope(&first_context, 2, b"b"),
        ],
    )
    .unwrap_err();
    assert_eq!(
        noncontiguous.to_string(),
        "EVIDENTRAIL_BATCH_NONCONTIGUOUS_ORDERING"
    );
}

#[test]
fn batch_debug_and_errors_are_contentless() {
    let context = context(4);
    let batch = EnvelopeBatchV1::new(
        &context,
        0,
        [envelope(&context, 0, b"CONTENT_CANARY_SECRET")],
    )
    .unwrap();
    let text = format!("{batch:?} {:?}", batch.operation_id());
    assert!(!text.contains("CONTENT_CANARY_SECRET"));
    assert!(!text.contains("MEMBER_CANARY"));
}
