#![cfg(unix)]

use std::fs;

use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    CompletenessProof, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, FetchBoundaries,
    FetchCompleteness, FetchCompletion, FetchIdentity, FetchTiming, LaneKey, LaneSequence,
    LedgerBuilder, PlanDigest, PlanId, PolicyAuthorization, RawEnvelopeIdentityV1, RawEnvelopeV1,
    RecordBytes, RecordState, RetrievalId, SourceIdentityDigest, SourceMember, SourceStream,
    UnixTimestampNanos,
};
use evidentrail_product::{
    DeterministicProductDecisionV1, DurableProductErrorV2, DurableProductV2, MemoryProductV1,
    durable_product_build_context_v2,
};
use evidentrail_schema::ResultId;
use evidentrail_snapshot_format::{BuildContextDigestsV1, LifecycleDigestV1, OperationIdV1};
use evidentrail_store::{
    AliasExpansionRequestV1, DataCommitInputV2, DurableResultRepositoryV2, EvidenceAliasV1,
    ExpansionLimitV1, ProcessKeyAuthorityV2, RecoveryDispositionV2,
};

#[derive(Clone, Copy)]
struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

fn ledger(seed: u8, records: &[RecordBytes]) -> evidentrail_core::EventLedger {
    let retrieval_id = RetrievalId::from_bytes([seed; 32]);
    let plan_id = PlanId::from_bytes([seed.wrapping_add(1); 32]);
    let plan_digest = PlanDigest::from_bytes([seed.wrapping_add(2); 32]);
    let source_identity = SourceIdentityDigest::from_bytes([seed.wrapping_add(3); 32]);
    let adapter = AdapterIdentity::new("durable-product-test", "v2").unwrap();
    let identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity =
        RawEnvelopeIdentityV1::new(retrieval_id, plan_id, plan_digest, adapter, source_identity);
    let lane = LaneKey::new(
        SourceMember::new(b"durable-fixture".to_vec()).unwrap(),
        SourceStream::Stderr,
    );
    let mut builder = LedgerBuilder::new(identity.clone(), source_identity, SourceExactPolicy);
    let mut payload_bytes = 0u64;
    let mut source_bytes = 0u64;
    for (position, record) in records.iter().cloned().enumerate() {
        let sequence = u64::try_from(position).unwrap();
        payload_bytes += u64::try_from(record.payload_len()).unwrap();
        source_bytes += u64::try_from(record.source_len()).unwrap();
        builder
            .accept(RawEnvelopeV1::new(
                envelope_identity.clone(),
                EnvelopeOrdering::new(
                    AcquisitionSequence::new(sequence),
                    lane.clone(),
                    LaneSequence::new(sequence),
                ),
                record,
                RecordState::Complete,
            ))
            .unwrap();
    }
    let count = u64::try_from(records.len()).unwrap();
    let attempts = if records.is_empty() {
        AttemptCounts::default()
    } else {
        AttemptCounts::new(1, 1)
    };
    let completion = FetchCompletion::new(
        identity,
        FetchTiming::new(UnixTimestampNanos::new(1), UnixTimestampNanos::new(2)),
        AcknowledgedCounts::new(count, payload_bytes, source_bytes),
        attempts,
        AttemptCounts::default(),
        FetchBoundaries::default(),
        [],
        AdapterOutcome::Finished,
        [],
        FetchCompleteness::complete(CompletenessProof::InMemoryFixtureExhausted),
    )
    .unwrap();
    builder.seal(completion).unwrap()
}

fn unique_root(suffix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("evidentrail-product-v2-{}-{suffix}", std::process::id()))
}

#[test]
fn memory_and_durable_artifacts_match_and_source_deletion_does_not_break_expansion() {
    let root = unique_root("parity");
    let _ = fs::remove_dir_all(&root);
    let result_id = ResultId::from_bytes([0x81; 32]);
    let now = UnixTimestampNanos::new(1_000);
    let question = b"why did the durable request fail?";
    let records = vec![
        RecordBytes::whole(b"ERROR request=R1 timeout\0\xff".to_vec()),
        RecordBytes::framed(b"retry failed".to_vec(), b"\r\n".to_vec()),
    ];

    let mut memory = MemoryProductV1::new();
    let memory_decision = memory
        .create_deterministic_result_v1(result_id, question, ledger(1, &records), now, 100_000)
        .unwrap();
    let repository =
        DurableResultRepositoryV2::open(&root, ProcessKeyAuthorityV2::new(8).unwrap()).unwrap();
    let mut durable = DurableProductV2::new(repository);
    let durable_decision = durable
        .create_deterministic_result_v2(result_id, question, ledger(1, &records), now, 100_000)
        .unwrap();
    let memory_text = match &memory_decision {
        DeterministicProductDecisionV1::Passthrough(result) => result.artifact().text(),
        DeterministicProductDecisionV1::Compiled(result) => result.artifact().text(),
        DeterministicProductDecisionV1::NeedsMore(_) => panic!("fixture must render"),
    };
    let durable_text = match &durable_decision {
        DeterministicProductDecisionV1::Passthrough(result) => result.artifact().text(),
        DeterministicProductDecisionV1::Compiled(result) => result.artifact().text(),
        DeterministicProductDecisionV1::NeedsMore(_) => panic!("fixture must render"),
    };
    assert_eq!(durable_text.as_bytes(), memory_text.as_bytes());
    drop(records);
    drop(memory);

    let expansion = durable
        .expand_alias(
            AliasExpansionRequestV1::new(
                result_id,
                EvidenceAliasV1::new(result_id, 1).unwrap(),
                evidentrail_core::ExpansionRelationV1::Exact,
                ExpansionLimitV1::new(8, 4096, 0, 0).unwrap(),
            ),
            UnixTimestampNanos::new(now.get() + 1),
        )
        .unwrap();
    assert!(!expansion.events().is_empty());
    assert!(
        expansion.events()[0]
            .authorized_bytes()
            .starts_with(b"ERROR")
    );
    assert_eq!(durable.published_result_count(), 1);
    durable.repository().destroy(result_id).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn unpublished_and_cross_result_aliases_fail_closed_and_cleanup_is_exclusive() {
    let root = unique_root("authorization");
    let _ = fs::remove_dir_all(&root);
    let result_id = ResultId::from_bytes([0x82; 32]);
    let other = ResultId::from_bytes([0x83; 32]);
    let now = UnixTimestampNanos::new(2_000);
    let repository =
        DurableResultRepositoryV2::open(&root, ProcessKeyAuthorityV2::new(8).unwrap()).unwrap();
    let mut durable = DurableProductV2::new(repository);
    durable
        .create_deterministic_result_v2(
            result_id,
            b"why?",
            ledger(2, &[RecordBytes::whole(b"one".to_vec())]),
            now,
            100_000,
        )
        .unwrap();
    let wrong = AliasExpansionRequestV1::new(
        result_id,
        EvidenceAliasV1::new(other, 1).unwrap(),
        evidentrail_core::ExpansionRelationV1::Exact,
        ExpansionLimitV1::new(1, 1024, 0, 0).unwrap(),
    );
    assert_eq!(
        durable.expand_alias(wrong, now).err(),
        Some(DurableProductErrorV2::ReferenceUnavailable)
    );
    assert_eq!(
        durable
            .recover_presented_result(result_id, UnixTimestampNanos::new(now.get() + 1))
            .unwrap(),
        RecoveryDispositionV2::AlreadyVisible
    );
    let startup = durable
        .reconcile_startup(UnixTimestampNanos::new(now.get() + 1))
        .unwrap();
    assert_eq!(startup.visible(), 1);
    assert_eq!(startup.resumable(), 0);
    assert_eq!(startup.reissue_required(), 0);
    assert_eq!(startup.unavailable(), 0);
    let expiry = UnixTimestampNanos::new(now.get() + evidentrail_store::DEFAULT_RESULT_TTL_NANOS);
    assert_eq!(durable.cleanup_expired(expiry), 1);
    assert_eq!(durable.published_result_count(), 0);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn build_context_is_stable_and_mismatch_is_typed_reissue() {
    let root = unique_root("build-mismatch");
    let _ = fs::remove_dir_all(&root);
    let result_id = ResultId::from_bytes([0x84; 32]);
    let context = durable_product_build_context_v2();
    assert_eq!(context, durable_product_build_context_v2());
    let mismatched = BuildContextDigestsV1::new(
        LifecycleDigestV1::from_bytes([0xff; 32]),
        LifecycleDigestV1::from_bytes([2; 32]),
        LifecycleDigestV1::from_bytes([3; 32]),
        LifecycleDigestV1::from_bytes([4; 32]),
        LifecycleDigestV1::from_bytes([5; 32]),
    );
    assert_ne!(context.aggregate(), mismatched.aggregate());

    let repository =
        DurableResultRepositoryV2::open(&root, ProcessKeyAuthorityV2::new(4).unwrap()).unwrap();
    repository
        .begin(
            result_id,
            3_000,
            4_000,
            OperationIdV1::from_bytes([1; 16]),
            b"request",
        )
        .unwrap();
    repository
        .commit_data(
            result_id,
            DataCommitInputV2 {
                operation: OperationIdV1::from_bytes([2; 16]),
                question_configuration: LifecycleDigestV1::from_bytes([1; 32]),
                acquisition_receipt: LifecycleDigestV1::from_bytes([2; 32]),
                transformation_receipts: LifecycleDigestV1::from_bytes([3; 32]),
                fetch_completion: LifecycleDigestV1::from_bytes([4; 32]),
                source_identity: LifecycleDigestV1::from_bytes([5; 32]),
                build_context: context,
            },
        )
        .unwrap();
    assert_eq!(
        repository
            .recover(result_id, 3_001, Some(mismatched))
            .unwrap(),
        RecoveryDispositionV2::ReissueRequired
    );
    repository.destroy(result_id).unwrap();
    fs::remove_dir_all(root).unwrap();
}
