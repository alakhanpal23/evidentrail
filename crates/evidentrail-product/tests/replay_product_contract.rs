use std::cell::Cell;

use evidentrail_core::{
    AcquisitionSequence, AdapterIdentity, DeterministicPolicy, EnvelopeOrdering,
    ExpansionRelationV1, FetchIdentity, LaneKey, LaneSequence, LedgerBuilder, PlanDigest, PlanId,
    PolicyAuthorization, RawEnvelopeV1, RecordBytes, RecordState, RetrievalId,
    SourceIdentityDigest, SourceMember, SourceStream, UnixTimestampNanos,
};
use evidentrail_evidence::{PinnedTokenizer, TokenizerFailure};
use evidentrail_framing::frame_source_lanes_v1;
use evidentrail_ingest::{ExecutionContext, InMemoryReplayAdapter, SourceAdapter};
use evidentrail_product::{MemoryProductV1, ProductResultDecisionV1};
use evidentrail_schema::{ArtifactDigest, ResultId};
use evidentrail_store::{AliasExpansionRequestV1, EvidenceAliasV1, ExpansionLimitV1};

const TOKENIZER_DIGEST: ArtifactDigest = ArtifactDigest::from_bytes([0x71; 32]);

#[derive(Clone, Copy)]
struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

struct ByteTokenizer {
    calls: Cell<usize>,
}

impl ByteTokenizer {
    fn new() -> Self {
        Self {
            calls: Cell::new(0),
        }
    }
}

impl PinnedTokenizer for ByteTokenizer {
    fn digest(&self) -> ArtifactDigest {
        TOKENIZER_DIGEST
    }

    fn count_tokens(&self, complete_render: &str) -> Result<u64, TokenizerFailure> {
        self.calls.set(self.calls.get() + 1);
        u64::try_from(complete_render.len()).map_err(|_| TokenizerFailure)
    }
}

fn envelope(
    identity: &evidentrail_core::RawEnvelopeIdentityV1,
    lane: LaneKey,
    acquisition_sequence: u64,
    lane_sequence: u64,
    payload: Vec<u8>,
    terminator: Vec<u8>,
) -> RawEnvelopeV1 {
    RawEnvelopeV1::new(
        identity.clone(),
        EnvelopeOrdering::new(
            AcquisitionSequence::new(acquisition_sequence),
            lane,
            LaneSequence::new(lane_sequence),
        ),
        RecordBytes::framed(payload, terminator),
        RecordState::Complete,
    )
}

#[test]
fn replay_to_exact_brief_and_expansion_survives_fixture_drop() {
    let retrieval_id = RetrievalId::from_bytes([0x11; 32]);
    let plan_id = PlanId::from_bytes([0x12; 32]);
    let plan_digest = PlanDigest::from_bytes([0x13; 32]);
    let source_identity = SourceIdentityDigest::from_bytes([0x14; 32]);
    let adapter_identity = AdapterIdentity::new("replay", "1.0.0").unwrap();
    let fetch_identity =
        FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter_identity.clone());
    let context = ExecutionContext::new(fetch_identity.clone(), source_identity);
    let raw_identity = context.envelope_identity();
    let member = SourceMember::new(b"synthetic-process".to_vec()).unwrap();
    let stderr = LaneKey::new(member.clone(), SourceStream::Stderr);
    let stdout = LaneKey::new(member, SourceStream::Stdout);

    let exact_records = vec![
        b"Traceback (most recent call last):\n".to_vec(),
        b"health ok\n".to_vec(),
        b"  File \"worker.py\", line 7, in run\n".to_vec(),
        b"RuntimeError: database unavailable\n".to_vec(),
        b"opaque:\xff\x00\n".to_vec(),
    ];
    let envelopes = vec![
        envelope(
            &raw_identity,
            stderr.clone(),
            0,
            0,
            b"Traceback (most recent call last):".to_vec(),
            b"\n".to_vec(),
        ),
        envelope(
            &raw_identity,
            stdout.clone(),
            1,
            0,
            b"health ok".to_vec(),
            b"\n".to_vec(),
        ),
        envelope(
            &raw_identity,
            stderr.clone(),
            2,
            1,
            b"  File \"worker.py\", line 7, in run".to_vec(),
            b"\n".to_vec(),
        ),
        envelope(
            &raw_identity,
            stderr,
            3,
            2,
            b"RuntimeError: database unavailable".to_vec(),
            b"\n".to_vec(),
        ),
        envelope(
            &raw_identity,
            stdout,
            4,
            1,
            b"opaque:\xff\x00".to_vec(),
            b"\n".to_vec(),
        ),
    ];
    let source_bytes = exact_records.iter().map(Vec::len).sum::<usize>();
    let replay = InMemoryReplayAdapter::new(
        envelopes,
        u64::try_from(exact_records.len()).unwrap(),
        u64::try_from(source_bytes).unwrap(),
    )
    .unwrap();
    let mut builder = LedgerBuilder::new(fetch_identity, source_identity, SourceExactPolicy);
    let completion = replay.execute(&context, &mut builder).unwrap();
    drop(replay);
    let ledger = builder.seal(completion).unwrap();

    assert_eq!(
        ledger
            .events()
            .iter()
            .map(|event| event.raw().to_vec())
            .collect::<Vec<_>>(),
        exact_records
    );
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    assert_eq!(blocks.len(), 3);
    let traceback = blocks.block_for_event(ledger.events()[0].id()).unwrap();
    assert_eq!(traceback.member_positions(), &[0, 2, 3]);
    assert_eq!(
        blocks.expand_block(traceback.id()).unwrap().exact_bytes(),
        [
            exact_records[0].as_slice(),
            exact_records[2].as_slice(),
            exact_records[3].as_slice(),
        ]
        .concat()
    );

    let tokenizer = ByteTokenizer::new();
    let result_id = ResultId::from_bytes([0x21; 32]);
    let now = UnixTimestampNanos::new(1_000);
    let mut product = MemoryProductV1::new();
    let decision = product
        .create_result(
            result_id,
            b"why did the database request fail?",
            ledger,
            now,
            1_000_000,
            &tokenizer,
        )
        .unwrap();
    let ProductResultDecisionV1::Rendered(rendered) = decision else {
        panic!("the bounded fixture must take the exact passthrough path");
    };

    assert_eq!(tokenizer.calls.get(), 1);
    assert_eq!(rendered.result_id(), result_id);
    assert_eq!(rendered.artifact().brief().evidence().len(), 5);
    assert_eq!(
        rendered
            .artifact()
            .brief()
            .evidence()
            .iter()
            .map(|evidence| evidence.authorized_bytes().to_vec())
            .collect::<Vec<_>>(),
        exact_records
    );
    let presentation = rendered.artifact().brief().coverage().presentation_counts();
    assert_eq!(presentation.shown_verbatim, 5);
    assert_eq!(presentation.pattern_represented, 0);
    assert_eq!(presentation.retained_raw, 0);

    let exact = product
        .expand_alias(
            AliasExpansionRequestV1::new(
                result_id,
                EvidenceAliasV1::new(result_id, 1).unwrap(),
                ExpansionRelationV1::Exact,
                ExpansionLimitV1::new(1, 1024, 0, 0).unwrap(),
            ),
            now,
        )
        .unwrap();
    assert_eq!(exact.events().len(), 1);
    assert_eq!(exact.events()[0].exact_bytes(), exact_records[0]);

    let same_lane = product
        .expand_alias(
            AliasExpansionRequestV1::new(
                result_id,
                EvidenceAliasV1::new(result_id, 1).unwrap(),
                ExpansionRelationV1::SameLaneBeforeAfter,
                ExpansionLimitV1::new(3, 4096, 0, 2).unwrap(),
            ),
            now,
        )
        .unwrap();
    assert_eq!(
        same_lane
            .events()
            .iter()
            .map(|event| event.exact_bytes().to_vec())
            .collect::<Vec<_>>(),
        vec![
            exact_records[0].clone(),
            exact_records[2].clone(),
            exact_records[3].clone(),
        ]
    );
    assert!(!same_lane.truncated());
    assert_eq!(product.result_count(), 1);
}
