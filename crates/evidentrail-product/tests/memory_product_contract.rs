use evidentrail_core::ExpansionRelationV1;
use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    CompletenessProof, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, FetchBoundaries,
    FetchCompleteness, FetchCompletion, FetchIdentity, FetchPartialReason, FetchPartialReasons,
    FetchTiming, FetchUnknownReason, LaneKey, LaneSequence, LedgerBuilder, PlanDigest, PlanId,
    PolicyAuthorization, RawEnvelopeIdentityV1, RawEnvelopeV1, RecordBytes, RecordState,
    RetrievalId, SourceCursor, SourceIdentityDigest, SourceMember, SourceStream,
    UnixTimestampNanos, derive_question_digest_v1,
};
use evidentrail_evidence::{PassthroughNotFitReasonV1, PinnedTokenizer, TokenizerFailure};
use evidentrail_product::{MemoryProductV1, ProductError, ProductResultDecisionV1};
use evidentrail_schema::{ArtifactDigest, ResultId};
use evidentrail_store::{
    AliasExpansionRequestV1, DEFAULT_RESULT_TTL_NANOS, EvidenceAliasV1, ExpansionLimitV1,
    ExpansionRequestV1, ResultStoreError,
};

#[derive(Clone, Copy)]
struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

struct ByteTokenizer;

impl PinnedTokenizer for ByteTokenizer {
    fn digest(&self) -> ArtifactDigest {
        ArtifactDigest::from_bytes([0x51; 32])
    }

    fn count_tokens(&self, complete_render: &str) -> Result<u64, TokenizerFailure> {
        u64::try_from(complete_render.len()).map_err(|_| TokenizerFailure)
    }
}

struct FailingTokenizer;

impl PinnedTokenizer for FailingTokenizer {
    fn digest(&self) -> ArtifactDigest {
        ArtifactDigest::from_bytes([0x52; 32])
    }

    fn count_tokens(&self, _complete_render: &str) -> Result<u64, TokenizerFailure> {
        Err(TokenizerFailure)
    }
}

fn result(seed: u8) -> ResultId {
    ResultId::from_bytes([seed; 32])
}

fn question(seed: u8) -> [u8; 3] {
    [seed, 0xff, 0x00]
}

fn ledger(
    seed: u8,
    completeness: FetchCompleteness,
    records: Vec<RecordBytes>,
) -> evidentrail_core::EventLedger {
    let retrieval_id = RetrievalId::from_bytes([seed; 32]);
    let plan_id = PlanId::from_bytes([seed.wrapping_add(1); 32]);
    let plan_digest = PlanDigest::from_bytes([seed.wrapping_add(2); 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([seed.wrapping_add(3); 32]);
    let adapter = AdapterIdentity::new("CANARY_PRODUCT_ADAPTER", "CANARY_VERSION").unwrap();
    let identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let lane = LaneKey::new(
        SourceMember::new(b"CANARY_/private/product-secret.log".to_vec()).unwrap(),
        SourceStream::Stderr,
    );
    let mut builder =
        LedgerBuilder::new(identity.clone(), source_identity_digest, SourceExactPolicy);
    let mut payload_bytes = 0_u64;
    let mut source_bytes = 0_u64;
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
    let record_count = u64::try_from(records.len()).unwrap();
    let member_counts = if records.is_empty() {
        AttemptCounts::default()
    } else {
        AttemptCounts::new(1, 1)
    };
    let completion = FetchCompletion::new(
        identity,
        FetchTiming::new(UnixTimestampNanos::new(1), UnixTimestampNanos::new(2)),
        AcknowledgedCounts::new(record_count, payload_bytes, source_bytes),
        member_counts,
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

fn complete_ledger(seed: u8, records: Vec<RecordBytes>) -> evidentrail_core::EventLedger {
    ledger(
        seed,
        FetchCompleteness::complete(CompletenessProof::InMemoryFixtureExhausted),
        records,
    )
}

fn expansion_limit() -> ExpansionLimitV1 {
    ExpansionLimitV1::new(8, 1024, 1, 1).unwrap()
}

#[test]
fn fitting_result_is_retained_rendered_and_expandable_while_response_is_alive() {
    let ledger = complete_ledger(
        1,
        vec![
            RecordBytes::whole(vec![0xff, 0x00, b'A']),
            RecordBytes::whole(b"second".to_vec()),
        ],
    );
    let expected_ids = ledger
        .events()
        .iter()
        .map(|event| event.id())
        .collect::<Vec<_>>();
    let now = UnixTimestampNanos::new(100);
    let mut product = MemoryProductV1::new();

    let decision = product
        .create_result(
            result(1),
            &question(2),
            ledger,
            now,
            100_000,
            &ByteTokenizer,
        )
        .unwrap();
    let ProductResultDecisionV1::Rendered(rendered) = decision else {
        panic!("fixture must fit exact passthrough");
    };
    assert_eq!(
        rendered.expires_at().get(),
        now.get() + DEFAULT_RESULT_TTL_NANOS
    );
    assert_eq!(rendered.artifact().brief().evidence().len(), 2);
    assert_eq!(
        rendered.artifact().brief().question_digest(),
        derive_question_digest_v1(&question(2))
    );
    assert_eq!(
        rendered.artifact().brief().status().selection().code(),
        "passthrough"
    );
    assert_eq!(product.result_count(), 1);

    let references = rendered.references().cloned().collect::<Vec<_>>();
    for (reference, expected_id) in references.iter().zip(&expected_ids) {
        assert_eq!(
            reference.targets(),
            [evidentrail_core::EvidenceTargetRef::Event(*expected_id)]
        );
        assert_eq!(reference.expires_at(), rendered.expires_at());
        assert_eq!(
            reference.allowed_relations(),
            [
                ExpansionRelationV1::Exact,
                ExpansionRelationV1::SameLaneBeforeAfter,
                ExpansionRelationV1::GlobalBeforeAfter,
            ]
        );
    }

    let expansion = product
        .expand(
            ExpansionRequestV1::new(
                result(1),
                references[0].id(),
                ExpansionRelationV1::Exact,
                expansion_limit(),
            ),
            UnixTimestampNanos::new(101),
        )
        .unwrap();
    assert_eq!(expansion.events().len(), 1);
    assert_eq!(expansion.events()[0].exact_bytes(), &[0xff, 0x00, b'A']);

    let alias_expansion = product
        .expand_alias(
            AliasExpansionRequestV1::new(
                result(1),
                EvidenceAliasV1::new(result(1), 1).unwrap(),
                ExpansionRelationV1::Exact,
                expansion_limit(),
            ),
            UnixTimestampNanos::new(101),
        )
        .unwrap();
    assert_eq!(alias_expansion.reference_id(), references[0].id());
    assert_eq!(
        alias_expansion.events()[0].exact_bytes(),
        &[0xff, 0x00, b'A']
    );
    assert!(rendered.artifact().text().contains("    expand: E1 exact"));
    assert!(
        !rendered
            .artifact()
            .text()
            .contains(&references[0].id().to_string())
    );
    assert!(
        !rendered
            .artifact()
            .text()
            .contains(&expected_ids[0].to_string())
    );
}

#[test]
fn over_budget_result_is_retained_with_typed_compilation_handoff() {
    let ledger = complete_ledger(3, vec![RecordBytes::whole(b"large-enough".to_vec())]);
    let expected = ledger.fetch_completion().completeness().clone();
    let mut product = MemoryProductV1::new();

    let decision = product
        .create_result(
            result(3),
            &question(4),
            ledger,
            UnixTimestampNanos::new(200),
            0,
            &ByteTokenizer,
        )
        .unwrap();
    let ProductResultDecisionV1::CompilationRequired(handoff) = decision else {
        panic!("zero token budget cannot fit");
    };
    assert_eq!(handoff.acquisition(), &expected);
    assert_eq!(handoff.references().len(), 1);
    assert_eq!(
        handoff.not_fit().reason(),
        PassthroughNotFitReasonV1::TotalTokenBudgetExceeded
    );
    assert!(handoff.not_fit().required_tokens().is_some());
    assert_eq!(product.result_count(), 1);

    let response = product
        .expand(
            ExpansionRequestV1::new(
                result(3),
                handoff.references()[0].id(),
                ExpansionRelationV1::Exact,
                expansion_limit(),
            ),
            UnixTimestampNanos::new(201),
        )
        .unwrap();
    assert_eq!(response.events()[0].exact_bytes(), b"large-enough");
}

#[test]
fn empty_ledger_is_a_valid_exhaustive_passthrough_result() {
    let ledger = complete_ledger(5, Vec::new());
    let mut product = MemoryProductV1::new();
    let decision = product
        .create_result(
            result(5),
            &question(6),
            ledger,
            UnixTimestampNanos::new(300),
            100_000,
            &ByteTokenizer,
        )
        .unwrap();
    let ProductResultDecisionV1::Rendered(rendered) = decision else {
        panic!("empty exhaustive result must fit");
    };
    assert_eq!(rendered.references().len(), 0);
    assert_eq!(rendered.artifact().brief().evidence().len(), 0);
    assert_eq!(
        rendered
            .artifact()
            .brief()
            .status()
            .selection()
            .presentation_receipt()
            .persisted_count(),
        0
    );
    assert!(rendered.artifact().text().contains("EVIDENCE\n  (none)"));
}

#[test]
fn partial_and_unknown_acquisition_are_preserved_without_upgrade() {
    let states = [
        FetchCompleteness::partial(
            FetchPartialReasons::new(FetchPartialReason::SourceByteCap),
            Some(SourceCursor::new(b"CANARY_CONTINUATION".to_vec()).unwrap()),
        ),
        FetchCompleteness::unknown(FetchUnknownReason::RetentionUnobservable),
    ];
    for (offset, expected) in states.into_iter().enumerate() {
        let seed = 10 + u8::try_from(offset).unwrap();
        let ledger = ledger(
            seed,
            expected.clone(),
            vec![RecordBytes::whole(b"retained".to_vec())],
        );
        let mut product = MemoryProductV1::new();
        let decision = product
            .create_result(
                result(seed),
                &question(seed),
                ledger,
                UnixTimestampNanos::new(400),
                100_000,
                &ByteTokenizer,
            )
            .unwrap();
        let ProductResultDecisionV1::Rendered(rendered) = decision else {
            panic!("small fixture must fit");
        };
        assert_eq!(
            rendered.artifact().brief().status().acquisition(),
            &expected
        );
    }
}

#[test]
fn tokenizer_failure_rolls_back_inserted_ledger_and_references() {
    let ledger = complete_ledger(20, vec![RecordBytes::whole(b"CANARY_ROLLBACK".to_vec())]);
    let mut product = MemoryProductV1::new();
    let error = product
        .create_result(
            result(20),
            &question(21),
            ledger,
            UnixTimestampNanos::new(500),
            100_000,
            &FailingTokenizer,
        )
        .unwrap_err();

    assert_eq!(
        error.evidence_error(),
        Some(evidentrail_evidence::PassthroughBriefError::TokenizerFailure)
    );
    assert_eq!(product.result_count(), 0);
}

#[test]
fn result_id_collision_is_rejected_without_replacing_the_first_result() {
    let first = complete_ledger(30, vec![RecordBytes::whole(b"first".to_vec())]);
    let replacement = complete_ledger(31, vec![RecordBytes::whole(b"replacement".to_vec())]);
    let mut product = MemoryProductV1::new();
    let first = product
        .create_result(
            result(30),
            &question(30),
            first,
            UnixTimestampNanos::new(600),
            100_000,
            &ByteTokenizer,
        )
        .unwrap();
    let ProductResultDecisionV1::Rendered(first) = first else {
        panic!("first result must fit");
    };
    let reference_id = first.references().next().unwrap().id();

    let error = product
        .create_result(
            result(30),
            &question(31),
            replacement,
            UnixTimestampNanos::new(601),
            100_000,
            &ByteTokenizer,
        )
        .unwrap_err();
    assert_eq!(
        error.store_error(),
        Some(ResultStoreError::DuplicateResultId)
    );
    assert_eq!(product.result_count(), 1);
    let response = product
        .expand(
            ExpansionRequestV1::new(
                result(30),
                reference_id,
                ExpansionRelationV1::Exact,
                expansion_limit(),
            ),
            UnixTimestampNanos::new(602),
        )
        .unwrap();
    assert_eq!(response.events()[0].exact_bytes(), b"first");
}

#[test]
fn fixed_expiry_is_exclusive_and_cleanup_removes_the_result() {
    let now = UnixTimestampNanos::new(700);
    let expires = UnixTimestampNanos::new(now.get() + DEFAULT_RESULT_TTL_NANOS);
    let ledger = complete_ledger(40, vec![RecordBytes::whole(b"expiring".to_vec())]);
    let mut product = MemoryProductV1::new();
    let decision = product
        .create_result(
            result(40),
            &question(40),
            ledger,
            now,
            100_000,
            &ByteTokenizer,
        )
        .unwrap();
    let ProductResultDecisionV1::Rendered(rendered) = decision else {
        panic!("fixture must fit");
    };
    let request = ExpansionRequestV1::new(
        result(40),
        rendered.references().next().unwrap().id(),
        ExpansionRelationV1::Exact,
        expansion_limit(),
    );
    assert!(
        product
            .expand(request, UnixTimestampNanos::new(expires.get() - 1))
            .is_ok()
    );
    assert_eq!(
        product.expand(request, expires),
        Err(ResultStoreError::ReferenceUnavailable)
    );
    assert_eq!(product.cleanup_expired(expires), 1);
    assert_eq!(product.result_count(), 0);
}

#[test]
fn product_outcomes_and_errors_have_contentless_debug_views() {
    let ledger = complete_ledger(
        50,
        vec![RecordBytes::whole(
            b"CANARY_PRODUCT_PAYLOAD_SECRET".to_vec(),
        )],
    );
    let event_token = ledger.events()[0].id().to_string();
    let mut product = MemoryProductV1::new();
    let decision = product
        .create_result(
            result(50),
            b"CANARY_PRODUCT_QUESTION_SECRET",
            ledger,
            UnixTimestampNanos::new(800),
            100_000,
            &ByteTokenizer,
        )
        .unwrap();
    let ProductResultDecisionV1::Rendered(rendered) = decision else {
        panic!("fixture must fit");
    };
    let reference_token = rendered.references().next().unwrap().id().to_string();
    let outputs = [
        format!("{product:?}"),
        format!("{rendered:?}"),
        format!(
            "{:?}",
            ProductError::Store(ResultStoreError::DuplicateResultId)
        ),
        ProductError::Store(ResultStoreError::DuplicateResultId).to_string(),
    ];
    for output in outputs {
        for canary in [
            "CANARY_PRODUCT_PAYLOAD",
            "CANARY_PRODUCT_QUESTION_SECRET",
            "CANARY_PRODUCT_ADAPTER",
            "/private/product-secret.log",
            event_token.as_str(),
            reference_token.as_str(),
            result(50).canonical_token().as_str(),
        ] {
            assert!(!output.contains(canary));
        }
    }
}
