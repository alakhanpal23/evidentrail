use std::cell::Cell;
use std::collections::BTreeSet;

use evidentrail_compile::{
    CandidateLaneV1, PreparedThreeLaneProposalUniverseV1, ThreeLaneCompileDecisionV1,
    ThreeLaneNeedsMoreV1, compile_three_lanes_v1,
};
use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    BlockState, CompletenessProof, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink,
    EventLedger, EvidenceReferenceV1, EvidenceTargetRef, ExpansionRelationV1, FetchBoundaries,
    FetchCompleteness, FetchCompletion, FetchIdentity, FetchPartialReason, FetchPartialReasons,
    FetchTiming, LaneKey, LaneSequence, LedgerBuilder, PlanDigest, PlanId, PolicyAuthorization,
    RawEnvelopeIdentityV1, RawEnvelopeV1, RecordBytes, RecordState, RetrievalId,
    SourceIdentityDigest, SourceMember, SourceStream, UnixTimestampNanos,
    derive_question_digest_v1,
};
use evidentrail_evidence::{CompiledCostCertificationError, Utf8ByteTokenizerV1};
use evidentrail_framing::frame_source_lanes_v1;
use evidentrail_product::{
    DeterministicProductDecisionV1, EvidenceRankerFailureV1, EvidenceRankerOutputV1,
    EvidenceRankerV1, EvidenceRankingRequestV1, MemoryProductV1, ProductError,
    ProductResultDecisionV1,
};
use evidentrail_schema::{ResultId, bounds::JSON_SAFE_INTEGER_MAX};
use evidentrail_select::TotalTokenBudgetV1;
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

struct FixtureRecord {
    member: Vec<u8>,
    stream: SourceStream,
    lane_sequence: u64,
    record: RecordBytes,
}

fn fixture(
    member: &[u8],
    stream: SourceStream,
    lane_sequence: u64,
    record: RecordBytes,
) -> FixtureRecord {
    FixtureRecord {
        member: member.to_vec(),
        stream,
        lane_sequence,
        record,
    }
}

fn result(seed: u8) -> ResultId {
    ResultId::from_bytes([seed; 32])
}

fn ledger(seed: u8, completeness: FetchCompleteness, records: Vec<FixtureRecord>) -> EventLedger {
    let retrieval_id = RetrievalId::from_bytes([seed; 32]);
    let plan_id = PlanId::from_bytes([seed.wrapping_add(1); 32]);
    let plan_digest = PlanDigest::from_bytes([seed.wrapping_add(2); 32]);
    let source_identity = SourceIdentityDigest::from_bytes([seed.wrapping_add(3); 32]);
    let adapter = AdapterIdentity::new("deterministic-product-fixture", "v1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity =
        RawEnvelopeIdentityV1::new(retrieval_id, plan_id, plan_digest, adapter, source_identity);
    let mut builder =
        LedgerBuilder::new(fetch_identity.clone(), source_identity, SourceExactPolicy);
    let mut payload_bytes = 0_u64;
    let mut source_bytes = 0_u64;
    let mut members = BTreeSet::new();
    for (position, fixture) in records.iter().enumerate() {
        let sequence = u64::try_from(position).unwrap();
        payload_bytes = payload_bytes
            .checked_add(u64::try_from(fixture.record.payload_len()).unwrap())
            .unwrap();
        source_bytes = source_bytes
            .checked_add(u64::try_from(fixture.record.source_len()).unwrap())
            .unwrap();
        let member = SourceMember::new(fixture.member.clone()).unwrap();
        members.insert(member.clone());
        builder
            .accept(RawEnvelopeV1::new(
                envelope_identity.clone(),
                EnvelopeOrdering::new(
                    AcquisitionSequence::new(sequence),
                    LaneKey::new(member, fixture.stream.clone()),
                    LaneSequence::new(fixture.lane_sequence),
                ),
                fixture.record.clone(),
                RecordState::Complete,
            ))
            .unwrap();
    }
    let record_count = u64::try_from(records.len()).unwrap();
    let member_count = u64::try_from(members.len()).unwrap();
    builder
        .seal(
            FetchCompletion::new(
                fetch_identity,
                FetchTiming::new(UnixTimestampNanos::new(1), UnixTimestampNanos::new(2)),
                AcknowledgedCounts::new(record_count, payload_bytes, source_bytes),
                AttemptCounts::new(member_count, member_count),
                AttemptCounts::default(),
                FetchBoundaries::default(),
                [],
                AdapterOutcome::Finished,
                [],
                completeness,
            )
            .unwrap(),
        )
        .unwrap()
}

fn complete_ledger(seed: u8, records: Vec<FixtureRecord>) -> EventLedger {
    ledger(
        seed,
        FetchCompleteness::complete(CompletenessProof::InMemoryFixtureExhausted),
        records,
    )
}

fn expansion_limit() -> ExpansionLimitV1 {
    ExpansionLimitV1::new(8, 128 * 1024, 2, 2).unwrap()
}

fn compiler_probe(
    question: &[u8],
    ledger: &EventLedger,
    result_id: ResultId,
    budget: u64,
) -> ThreeLaneCompileDecisionV1 {
    let blocks = frame_source_lanes_v1(ledger).unwrap();
    compile_three_lanes_v1(
        question,
        ledger,
        &blocks,
        result_id,
        TotalTokenBudgetV1::new(budget).unwrap(),
        &Utf8ByteTokenizerV1::new(),
    )
    .unwrap()
}

fn oversized_records() -> Vec<FixtureRecord> {
    vec![
        fixture(
            b"app",
            SourceStream::Stderr,
            0,
            RecordBytes::whole(b"ERROR timeout while handling request".to_vec()),
        ),
        fixture(
            b"app",
            SourceStream::Stderr,
            1,
            RecordBytes::whole(vec![b'Z'; 50_000]),
        ),
    ]
}

fn single_lane_records(records: &[RecordBytes]) -> Vec<FixtureRecord> {
    records
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, record)| {
            fixture(
                b"table",
                SourceStream::LogStream,
                u64::try_from(index).unwrap(),
                record,
            )
        })
        .collect()
}

fn assert_exact_proposal_memberships(prepared: &PreparedThreeLaneProposalUniverseV1) {
    assert_eq!(
        u64::try_from(prepared.proposal_packets().len()).unwrap(),
        prepared.receipt().accounting().proposal_packet_count()
    );
    for packet in prepared.proposal_packets() {
        let metadata = prepared
            .proposal_metadata(packet.id())
            .expect("every proposal ID must resolve to exhaustive metadata");
        let mut canonical_metadata_members = metadata.ordered_event_ids().to_vec();
        canonical_metadata_members.sort_unstable();
        assert_eq!(packet.event_ids(), canonical_metadata_members);
    }
}

#[derive(Default)]
struct FailingRanker {
    calls: Cell<usize>,
}

impl EvidenceRankerV1 for FailingRanker {
    fn rank(
        &mut self,
        _request: &EvidenceRankingRequestV1,
    ) -> Result<EvidenceRankerOutputV1, EvidenceRankerFailureV1> {
        self.calls.set(self.calls.get() + 1);
        Err(EvidenceRankerFailureV1::Timeout)
    }
}

struct StaticOutputRanker {
    response: Vec<u8>,
}

impl EvidenceRankerV1 for StaticOutputRanker {
    fn rank(
        &mut self,
        _request: &EvidenceRankingRequestV1,
    ) -> Result<EvidenceRankerOutputV1, EvidenceRankerFailureV1> {
        Ok(EvidenceRankerOutputV1::new(
            self.response.clone(),
            [1; 32],
            [2; 32],
            3,
            Some(4),
            Some(5),
            Some(6),
        ))
    }
}

fn two_candidate_oversized_records() -> Vec<FixtureRecord> {
    let mut first = b"ERROR timeout alpha ".to_vec();
    first.resize(7_000, b'a');
    let mut second = b"ERROR timeout beta ".to_vec();
    second.resize(7_000, b'b');
    vec![
        fixture(b"app-a", SourceStream::Stderr, 0, RecordBytes::whole(first)),
        fixture(
            b"app-b",
            SourceStream::Stderr,
            0,
            RecordBytes::whole(second),
        ),
    ]
}

fn hosted_request_oversized_records() -> Vec<FixtureRecord> {
    let mut first = b"ERROR timeout alpha ".to_vec();
    first.resize(30_000, b'a');
    let mut second = b"ERROR timeout beta ".to_vec();
    second.resize(30_000, b'b');
    vec![
        fixture(b"app-a", SourceStream::Stderr, 0, RecordBytes::whole(first)),
        fixture(
            b"app-b",
            SourceStream::Stderr,
            0,
            RecordBytes::whole(second),
        ),
    ]
}

#[test]
fn hosted_assistance_is_post_feasibility_and_every_failure_is_exact_fallback() {
    let now = UnixTimestampNanos::new(99);
    let small = complete_ledger(
        90,
        vec![fixture(
            b"app",
            SourceStream::Stdout,
            0,
            RecordBytes::whole(b"small".to_vec()),
        )],
    );
    let mut passthrough_ranker = FailingRanker::default();
    let mut passthrough_product = MemoryProductV1::new();
    let passthrough = passthrough_product
        .create_hosted_ranked_result_v1(
            result(90),
            b"why?",
            small,
            now,
            100_000,
            &mut passthrough_ranker,
        )
        .unwrap();
    assert!(matches!(
        passthrough,
        DeterministicProductDecisionV1::Passthrough(_)
    ));
    assert_eq!(passthrough_ranker.calls.get(), 0);

    let source = complete_ledger(91, two_candidate_oversized_records());
    let mut deterministic_product = MemoryProductV1::new();
    let deterministic = deterministic_product
        .create_deterministic_result_v1(result(91), b"timeout", source.clone(), now, 10_000)
        .unwrap();
    let DeterministicProductDecisionV1::Compiled(deterministic) = deterministic else {
        panic!("fixture must compile");
    };

    let mut ranker = FailingRanker::default();
    let mut assisted_product = MemoryProductV1::new();
    let assisted = assisted_product
        .create_hosted_ranked_result_v1(result(91), b"timeout", source, now, 10_000, &mut ranker)
        .unwrap();
    let DeterministicProductDecisionV1::Compiled(assisted) = assisted else {
        panic!("fixture must compile");
    };
    assert_eq!(ranker.calls.get(), 1);
    assert_eq!(
        assisted.artifact().text(),
        deterministic.artifact().text(),
        "timeout fallback must be byte-identical"
    );
    let diagnostics = assisted.hosted_ranking_diagnostics().unwrap();
    assert_eq!(diagnostics.validation_code(), "not_received");
    assert_eq!(diagnostics.fallback_reason(), Some("timeout"));
    assert!(diagnostics.elapsed_nanos().is_some());

    let tiny_source = complete_ledger(92, two_candidate_oversized_records());
    let mut needs_more_ranker = FailingRanker::default();
    let mut needs_more_product = MemoryProductV1::new();
    let needs_more = needs_more_product
        .create_hosted_ranked_result_v1(
            result(92),
            b"timeout",
            tiny_source,
            now,
            1,
            &mut needs_more_ranker,
        )
        .unwrap();
    assert!(matches!(
        needs_more,
        DeterministicProductDecisionV1::NeedsMore(_)
    ));
    assert_eq!(needs_more_ranker.calls.get(), 0);
}

#[test]
fn contention_gated_hosted_assistance_calls_only_after_an_optional_exclusion() {
    let now = UnixTimestampNanos::new(100);
    let source = complete_ledger(96, two_candidate_oversized_records());
    let mut ranker = FailingRanker::default();
    let mut product = MemoryProductV1::new();
    let decision = product
        .create_contended_hosted_ranked_result_v1(
            result(96),
            b"timeout",
            source,
            now,
            10_000,
            &mut ranker,
        )
        .unwrap();
    let DeterministicProductDecisionV1::Compiled(compiled) = decision else {
        panic!("fixture must compile");
    };
    assert_eq!(ranker.calls.get(), 1);
    let diagnostics = compiled.hosted_ranking_diagnostics().unwrap();
    assert_eq!(diagnostics.application_code(), "apply_if_contended");
    assert_eq!(diagnostics.fallback_reason(), Some("timeout"));
}

#[test]
fn hosted_egress_cap_is_checked_before_the_ranker_and_falls_back_exactly() {
    let now = UnixTimestampNanos::new(101);
    let source = complete_ledger(93, hosted_request_oversized_records());
    let mut deterministic_product = MemoryProductV1::new();
    let deterministic = deterministic_product
        .create_deterministic_result_v1(result(93), b"timeout", source.clone(), now, 40_000)
        .unwrap();
    let DeterministicProductDecisionV1::Compiled(deterministic) = deterministic else {
        panic!("fixture must compile");
    };

    let mut ranker = FailingRanker::default();
    let mut assisted_product = MemoryProductV1::new();
    let assisted = assisted_product
        .create_hosted_ranked_result_v1(result(93), b"timeout", source, now, 40_000, &mut ranker)
        .unwrap();
    let DeterministicProductDecisionV1::Compiled(assisted) = assisted else {
        panic!("fixture must compile");
    };
    assert_eq!(ranker.calls.get(), 0);
    assert_eq!(assisted.artifact().text(), deterministic.artifact().text());
    let diagnostics = assisted.hosted_ranking_diagnostics().unwrap();
    assert_eq!(diagnostics.validation_code(), "not_sent");
    assert_eq!(diagnostics.fallback_reason(), Some("request_too_large"));
    assert_eq!(diagnostics.elapsed_nanos(), None);
}

#[test]
fn every_invalid_model_response_class_is_byte_identical_fallback() {
    let now = UnixTimestampNanos::new(102);
    let source = complete_ledger(94, two_candidate_oversized_records());
    let mut deterministic_product = MemoryProductV1::new();
    let deterministic = deterministic_product
        .create_deterministic_result_v1(result(94), b"timeout", source.clone(), now, 10_000)
        .unwrap();
    let DeterministicProductDecisionV1::Compiled(deterministic) = deterministic else {
        panic!("fixture must compile");
    };

    let mut responses = vec![
        b"not-json".to_vec(),
        br#"{"schema_version":2,"ranked_block_ids":["B1","B2"]}"#.to_vec(),
        br#"{"schema_version":1,"ranked_block_ids":["B1"]}"#.to_vec(),
        br#"{"schema_version":1,"ranked_block_ids":["B1","B1"]}"#.to_vec(),
        br#"{"schema_version":1,"ranked_block_ids":["B1","FOREIGN"]}"#.to_vec(),
        br#"{"schema_version":1,"ranked_block_ids":["B1","B2"],"extra":true}"#.to_vec(),
    ];
    responses.push(vec![
        b' ';
        evidentrail_product::MAX_HOSTED_RANKING_RESPONSE_BYTES_V1
            + 1
    ]);

    for (index, response) in responses.into_iter().enumerate() {
        let mut ranker = StaticOutputRanker { response };
        let mut assisted_product = MemoryProductV1::new();
        let assisted = assisted_product
            .create_hosted_ranked_result_v1(
                result(94),
                b"timeout",
                source.clone(),
                now,
                10_000,
                &mut ranker,
            )
            .unwrap();
        let DeterministicProductDecisionV1::Compiled(assisted) = assisted else {
            panic!("fixture must compile");
        };
        assert_eq!(
            assisted.artifact().text(),
            deterministic.artifact().text(),
            "invalid response class {index} must fall back exactly"
        );
        assert_eq!(
            assisted
                .hosted_ranking_diagnostics()
                .unwrap()
                .fallback_reason(),
            Some("invalid_response")
        );
    }
}

#[test]
fn shadow_mode_runs_valid_ranking_but_always_publishes_deterministic_bytes() {
    let now = UnixTimestampNanos::new(103);
    let source = complete_ledger(95, two_candidate_oversized_records());
    let mut deterministic_product = MemoryProductV1::new();
    let deterministic = deterministic_product
        .create_deterministic_result_v1(result(95), b"timeout", source.clone(), now, 10_000)
        .unwrap();
    let DeterministicProductDecisionV1::Compiled(deterministic) = deterministic else {
        panic!("fixture must compile");
    };
    let mut ranker = StaticOutputRanker {
        response: br#"{"schema_version":1,"ranked_block_ids":["B2","B1"]}"#.to_vec(),
    };
    let mut shadow_product = MemoryProductV1::new();
    let shadow = shadow_product
        .create_shadow_ranked_result_v1(result(95), b"timeout", source, now, 10_000, &mut ranker)
        .unwrap();
    let DeterministicProductDecisionV1::Compiled(shadow) = shadow else {
        panic!("fixture must compile");
    };
    assert_eq!(shadow.artifact().text(), deterministic.artifact().text());
    let diagnostics = shadow.hosted_ranking_diagnostics().unwrap();
    assert_eq!(diagnostics.application_code(), "shadow");
    assert_eq!(diagnostics.validation_code(), "accepted");
    assert!(diagnostics.proposal_changed().is_some());
}

#[test]
fn fitting_result_takes_exact_passthrough_and_publishes_aliases() {
    let source = complete_ledger(
        1,
        vec![fixture(
            b"app",
            SourceStream::Stdout,
            0,
            RecordBytes::framed(vec![0xff, 0, b'A'], b"\r\n".to_vec()),
        )],
    );
    let expected_event = source.events()[0].id();
    let now = UnixTimestampNanos::new(100);
    let mut product = MemoryProductV1::new();

    let decision = product
        .create_deterministic_result_v1(result(1), b"why?\xff", source, now, 100_000)
        .unwrap();
    let DeterministicProductDecisionV1::Passthrough(rendered) = decision else {
        panic!("small exact input must use passthrough");
    };
    assert_eq!(rendered.result_id(), result(1));
    assert_eq!(
        rendered.artifact().brief().question_digest(),
        derive_question_digest_v1(b"why?\xff")
    );
    assert_eq!(rendered.artifact().brief().evidence().len(), 1);
    assert_eq!(
        rendered.artifact().brief().evidence()[0].event_id(),
        expected_event
    );
    let expanded = product
        .expand_alias(
            AliasExpansionRequestV1::new(
                result(1),
                EvidenceAliasV1::new(result(1), 1).unwrap(),
                ExpansionRelationV1::Exact,
                expansion_limit(),
            ),
            now,
        )
        .unwrap();
    assert_eq!(
        expanded.events()[0].exact_bytes(),
        &[0xff, 0, b'A', b'\r', b'\n']
    );
}

#[test]
fn oversized_result_compiles_in_one_call_and_publishes_only_final_aliases() {
    let source = complete_ledger(2, oversized_records());
    let question = b"timeout request";
    let now = UnixTimestampNanos::new(200);
    let mut product = MemoryProductV1::new();

    let decision = product
        .create_deterministic_result_v1(result(2), question, source, now, 20_000)
        .unwrap();
    let DeterministicProductDecisionV1::Compiled(compiled) = decision else {
        panic!("oversized evidence should compile to a nonempty strict subset");
    };
    assert_eq!(compiled.result_id(), result(2));
    assert_eq!(
        compiled.artifact().brief().question_digest(),
        derive_question_digest_v1(question)
    );
    assert!(!compiled.artifact().brief().evidence().is_empty());
    assert!(compiled.artifact().brief().evidence().iter().all(|packet| {
        packet
            .events()
            .iter()
            .all(|event| event.authorized_bytes().len() < 50_000)
    }));
    assert!(
        compiled
            .artifact()
            .brief()
            .cost()
            .is_additive_bound_certified()
    );
    let audit = compiled
        .proposal_audit()
        .expect("production three-lane compilation must expose its audit");
    assert_eq!(audit.code(), "selected");
    let prepared = audit
        .prepared()
        .expect("selected audit must retain the prepared universe");
    assert_exact_proposal_memberships(prepared);
    let mut rendered_packet_ids = compiled
        .artifact()
        .brief()
        .evidence()
        .iter()
        .map(|packet| {
            let metadata = prepared
                .proposal_metadata(packet.packet_id())
                .expect("selected packet must resolve to exhaustive metadata");
            let mut expected_members = metadata.ordered_event_ids().to_vec();
            expected_members.sort_unstable();
            assert_eq!(packet.canonical_event_ids(), expected_members);
            packet.packet_id()
        })
        .collect::<Vec<_>>();
    rendered_packet_ids.sort_unstable();
    assert_eq!(
        audit
            .selected_packet_ids()
            .expect("selected audit must expose exact selected IDs"),
        rendered_packet_ids
    );
    assert_eq!(
        product
            .expand_alias(
                AliasExpansionRequestV1::new(
                    result(2),
                    EvidenceAliasV1::new(result(2), 1).unwrap(),
                    ExpansionRelationV1::Exact,
                    expansion_limit(),
                ),
                now,
            )
            .unwrap()
            .events()[0]
            .exact_bytes(),
        b"ERROR timeout while handling request"
    );
}

#[test]
fn mandatory_and_nonmandatory_budget_edges_return_retained_needs_more() {
    let uuid = b"550e8400-e29b-41d4-a716-446655440000";
    let mandatory_record = [
        b"ERROR request ".as_slice(),
        uuid,
        b" ".as_slice(),
        vec![b'M'; 40_000].as_slice(),
    ]
    .concat();
    let mandatory_source = complete_ledger(
        3,
        vec![
            fixture(
                b"api",
                SourceStream::Stderr,
                0,
                RecordBytes::whole(mandatory_record),
            ),
            fixture(
                b"api",
                SourceStream::Stderr,
                1,
                RecordBytes::whole(vec![b'N'; 50_000]),
            ),
        ],
    );
    let question = [b"request ".as_slice(), uuid].concat();
    let probe = compiler_probe(&question, &mandatory_source, result(3), 1_000_000);
    let selected = probe.selected().expect("probe budget must select");
    let mandatory_packet = selected
        .packet_metadata()
        .iter()
        .find(|packet| !packet.mandatory_reasons().is_empty())
        .expect("validated UUID must force its exact block");
    let mut canonical_events = mandatory_packet.ordered_event_ids().to_vec();
    canonical_events.sort_unstable();
    let mandatory_cost = selected
        .certification()
        .packet_cost(mandatory_packet.packet_id(), &canonical_events)
        .unwrap()
        .upper_bound_tokens();
    let fixed = selected
        .certification()
        .fixed_overhead()
        .upper_bound_tokens();
    let mandatory_budget = fixed.checked_add(mandatory_cost).unwrap() - 1;
    let now = UnixTimestampNanos::new(300);
    let mut mandatory_product = MemoryProductV1::new();
    let decision = mandatory_product
        .create_deterministic_result_v1(
            result(3),
            &question,
            mandatory_source,
            now,
            mandatory_budget,
        )
        .unwrap();
    let DeterministicProductDecisionV1::NeedsMore(needs_more) = decision else {
        panic!("mandatory packet over budget must not produce compiled success");
    };
    assert_eq!(
        needs_more.compiler_reason(),
        ThreeLaneNeedsMoreV1::MandatoryCostExceedsAvailablePacketBudget
    );
    assert_eq!(needs_more.result_id(), result(3));
    assert_eq!(
        needs_more.question_digest(),
        derive_question_digest_v1(&question)
    );
    assert_eq!(
        needs_more.expires_at().get(),
        now.get() + DEFAULT_RESULT_TTL_NANOS
    );
    assert_eq!(needs_more.references().len(), 2);
    let retained = mandatory_product
        .expand(
            ExpansionRequestV1::new(
                result(3),
                needs_more.references()[0].id(),
                ExpansionRelationV1::Exact,
                expansion_limit(),
            ),
            now,
        )
        .unwrap();
    assert_eq!(retained.events().len(), 1);
    assert_eq!(
        mandatory_product.expand_alias(
            AliasExpansionRequestV1::new(
                result(3),
                EvidenceAliasV1::new(result(3), 1).unwrap(),
                ExpansionRelationV1::Exact,
                expansion_limit(),
            ),
            now,
        ),
        Err(ResultStoreError::ReferenceUnavailable)
    );

    let fixed_source = complete_ledger(4, oversized_records());
    let fixed_probe = compiler_probe(b"timeout", &fixed_source, result(4), 1_000_000);
    let fixed_overhead = fixed_probe
        .selected()
        .expect("probe budget must select")
        .certification()
        .fixed_overhead()
        .upper_bound_tokens();
    for (offset, budget, reason) in [
        (
            0_u8,
            0_u64,
            ThreeLaneNeedsMoreV1::FixedOverheadExceedsTotalBudget,
        ),
        (
            1_u8,
            fixed_overhead,
            ThreeLaneNeedsMoreV1::NoSelectedPacketFits,
        ),
    ] {
        let mut product = MemoryProductV1::new();
        let decision = product
            .create_deterministic_result_v1(
                result(4 + offset),
                b"timeout",
                complete_ledger(4, oversized_records()),
                UnixTimestampNanos::new(400 + i128::from(offset)),
                budget,
            )
            .unwrap();
        let DeterministicProductDecisionV1::NeedsMore(needs_more) = decision else {
            panic!("budget edge must remain needs-more");
        };
        assert_eq!(needs_more.compiler_reason(), reason);
        assert!(!needs_more.references().is_empty());
    }
}

#[test]
fn partial_interleaved_arbitrary_bytes_compile_without_upgrading_acquisition() {
    let partial = FetchCompleteness::partial(
        FetchPartialReasons::new(FetchPartialReason::SourceByteCap),
        None,
    );
    let invalid = vec![
        0xff, 0, b'E', b'R', b'R', b'O', b'R', b' ', b't', b'i', b'm', b'e', b'o', b'u', b't',
    ];
    let source = ledger(
        5,
        partial.clone(),
        vec![
            fixture(
                b"api",
                SourceStream::Stderr,
                0,
                RecordBytes::whole(invalid.clone()),
            ),
            fixture(
                b"worker",
                SourceStream::Stdout,
                0,
                RecordBytes::whole(vec![b'N'; 50_000]),
            ),
            fixture(
                b"api",
                SourceStream::Stderr,
                1,
                RecordBytes::framed(b"request failed".to_vec(), b"\r\n".to_vec()),
            ),
        ],
    );
    let mut product = MemoryProductV1::new();
    let decision = product
        .create_deterministic_result_v1(
            result(5),
            &[0xff, 0, b't', b'i', b'm', b'e', b'o', b'u', b't'],
            source,
            UnixTimestampNanos::new(500),
            20_000,
        )
        .unwrap();
    let DeterministicProductDecisionV1::Compiled(compiled) = decision else {
        panic!("bounded relevant records should compile");
    };
    assert_eq!(compiled.artifact().brief().status().acquisition(), &partial);
    assert!(
        compiled
            .artifact()
            .brief()
            .evidence()
            .iter()
            .flat_map(|packet| packet.events())
            .any(|event| event.authorized_bytes() == invalid)
    );
    assert!(
        compiled
            .artifact()
            .brief()
            .evidence()
            .iter()
            .flat_map(|packet| packet.events())
            .all(|event| event.authorized_bytes().len() < 50_000)
    );
}

#[test]
fn replay_is_deterministic_and_result_question_bindings_are_exact() {
    let question = b"CANARY_RAW_QUESTION timeout request\xff";
    let run = || {
        let mut product = MemoryProductV1::new();
        let decision = product
            .create_deterministic_result_v1(
                result(6),
                question,
                complete_ledger(6, oversized_records()),
                UnixTimestampNanos::new(600),
                20_000,
            )
            .unwrap();
        let DeterministicProductDecisionV1::Compiled(compiled) = decision else {
            panic!("replay fixture must compile");
        };
        assert_eq!(compiled.result_id(), result(6));
        assert_eq!(
            compiled.artifact().brief().question_digest(),
            derive_question_digest_v1(question)
        );
        assert!(!compiled.artifact().text().contains("CANARY_RAW_QUESTION"));
        compiled.artifact().text().to_owned()
    };

    assert_eq!(run(), run());
}

#[test]
fn invalid_budget_and_needs_more_diagnostics_are_contentless() {
    const QUESTION_CANARY: &str = "CANARY_PRODUCT_QUESTION_9ee1";
    let mut invalid = MemoryProductV1::new();
    let error = invalid
        .create_deterministic_result_v1(
            result(7),
            QUESTION_CANARY.as_bytes(),
            complete_ledger(7, oversized_records()),
            UnixTimestampNanos::new(700),
            JSON_SAFE_INTEGER_MAX + 1,
        )
        .unwrap_err();
    assert!(error.token_budget_error().is_some());
    assert_eq!(invalid.result_count(), 0);

    let mut retained = MemoryProductV1::new();
    let decision = retained
        .create_deterministic_result_v1(
            result(8),
            QUESTION_CANARY.as_bytes(),
            complete_ledger(8, oversized_records()),
            UnixTimestampNanos::new(800),
            0,
        )
        .unwrap();
    let DeterministicProductDecisionV1::NeedsMore(needs_more) = decision else {
        panic!("zero budget must need more");
    };
    let rendered = format!("{error:?} {needs_more:?} {retained:?}");
    assert!(!rendered.contains(QUESTION_CANARY));
    assert!(!rendered.contains(&result(8).canonical_token()));
    assert!(!rendered.contains("deterministic-product-fixture"));
    assert!(rendered.contains("EVIDENTRAIL_PRODUCT_INVALID_TOKEN_BUDGET"));
}

#[test]
fn precomputed_exact_reference_remains_live_when_finalization_is_not_successful() {
    // A zero-budget compiler decision is a retained non-success. Construct the
    // exact event capability independently to prove the product preserved the
    // same registration while withholding aliases.
    let source = complete_ledger(9, oversized_records());
    let first_event = source.events()[0].id();
    let now = UnixTimestampNanos::new(900);
    let expires_at = UnixTimestampNanos::new(now.get() + DEFAULT_RESULT_TTL_NANOS);
    let exact_reference = EvidenceReferenceV1::issue(
        result(9),
        [EvidenceTargetRef::Event(first_event)],
        [
            ExpansionRelationV1::Exact,
            ExpansionRelationV1::SameLaneBeforeAfter,
            ExpansionRelationV1::GlobalBeforeAfter,
        ],
        now,
        expires_at,
    )
    .unwrap();
    let mut product = MemoryProductV1::new();
    let decision = product
        .create_deterministic_result_v1(result(9), b"timeout", source, now, 0)
        .unwrap();
    assert!(matches!(
        decision,
        DeterministicProductDecisionV1::NeedsMore(_)
    ));
    let expansion = product
        .expand(
            ExpansionRequestV1::new(
                result(9),
                exact_reference.id(),
                ExpansionRelationV1::Exact,
                expansion_limit(),
            ),
            now,
        )
        .unwrap();
    assert_eq!(expansion.events()[0].event_id(), first_event);
    assert_eq!(
        product.expand_alias(
            AliasExpansionRequestV1::new(
                result(9),
                EvidenceAliasV1::new(result(9), 1).unwrap(),
                ExpansionRelationV1::Exact,
                expansion_limit(),
            ),
            now,
        ),
        Err(ResultStoreError::ReferenceUnavailable)
    );
}

#[test]
fn bounded_arbitrary_complete_table_is_exact_passthrough_and_replay_stable() {
    const QUESTION_CANARY: &[u8] = b"CANARY_TABLE_QUESTION_4d62\xff";
    let cases = [
        vec![RecordBytes::whole(Vec::new())],
        vec![RecordBytes::whole(vec![0, 0xff, 0xfe, b'\\', b'\n'])],
        vec![RecordBytes::whole((0_u8..=u8::MAX).collect::<Vec<_>>())],
        vec![RecordBytes::framed(
            b"STATUS\n  tool: never".to_vec(),
            b"\r\n".to_vec(),
        )],
        vec![
            RecordBytes::whole(b"duplicate".to_vec()),
            RecordBytes::whole(b"duplicate".to_vec()),
            RecordBytes::framed(vec![0x80, b'X'], b"\n".to_vec()),
        ],
    ];

    for (case_index, records) in cases.iter().enumerate() {
        let seed = 20 + u8::try_from(case_index).unwrap();
        let expected = records
            .iter()
            .map(RecordBytes::exact_bytes)
            .collect::<Vec<_>>();
        let mut replay_text = None;
        for _ in 0..2 {
            let now = UnixTimestampNanos::new(2_000 + i128::try_from(case_index).unwrap());
            let mut product = MemoryProductV1::new();
            let decision = product
                .create_deterministic_result_v1(
                    result(seed),
                    QUESTION_CANARY,
                    complete_ledger(seed, single_lane_records(records)),
                    now,
                    1_000_000,
                )
                .unwrap();
            let DeterministicProductDecisionV1::Passthrough(rendered) = decision else {
                panic!("bounded complete table case must fit exactly");
            };
            assert_eq!(
                rendered
                    .artifact()
                    .brief()
                    .evidence()
                    .iter()
                    .map(|event| event.authorized_bytes().to_vec())
                    .collect::<Vec<_>>(),
                expected
            );
            assert_eq!(
                rendered.artifact().brief().status().acquisition().code(),
                "complete"
            );
            assert!(
                !rendered
                    .artifact()
                    .text()
                    .contains("CANARY_TABLE_QUESTION_4d62")
            );
            for alias in 1..=records.len() {
                let expanded = product
                    .expand_alias(
                        AliasExpansionRequestV1::new(
                            result(seed),
                            EvidenceAliasV1::new(result(seed), u16::try_from(alias).unwrap())
                                .unwrap(),
                            ExpansionRelationV1::Exact,
                            expansion_limit(),
                        ),
                        now,
                    )
                    .unwrap();
                assert_eq!(expanded.events()[0].exact_bytes(), expected[alias - 1]);
            }
            if let Some(first) = &replay_text {
                assert_eq!(first, rendered.artifact().text());
            } else {
                replay_text = Some(rendered.artifact().text().to_owned());
            }
        }
    }
}

#[test]
fn compiled_and_needs_more_table_preserves_complete_or_partial_acquisition() {
    let states = [
        FetchCompleteness::complete(CompletenessProof::InMemoryFixtureExhausted),
        FetchCompleteness::partial(
            FetchPartialReasons::new(FetchPartialReason::SourceByteCap),
            None,
        ),
    ];
    for (state_index, state) in states.iter().cloned().enumerate() {
        let seed = 30 + u8::try_from(state_index).unwrap();
        let now = UnixTimestampNanos::new(3_000 + i128::try_from(state_index).unwrap());
        let mut compiled_product = MemoryProductV1::new();
        let compiled = compiled_product
            .create_deterministic_result_v1(
                result(seed),
                b"CANARY_STATE_QUESTION timeout request",
                ledger(seed, state.clone(), oversized_records()),
                now,
                20_000,
            )
            .unwrap();
        let DeterministicProductDecisionV1::Compiled(compiled) = compiled else {
            panic!("oversized table case must compile");
        };
        assert_eq!(compiled.artifact().brief().status().acquisition(), &state);
        assert!(!compiled.artifact().text().contains("CANARY_STATE_QUESTION"));
        assert!(
            compiled_product
                .expand_alias(
                    AliasExpansionRequestV1::new(
                        result(seed),
                        EvidenceAliasV1::new(result(seed), 1).unwrap(),
                        ExpansionRelationV1::Exact,
                        expansion_limit(),
                    ),
                    now,
                )
                .is_ok()
        );

        let needs_more_result = result(seed.wrapping_add(10));
        let mut needs_more_product = MemoryProductV1::new();
        let needs_more = needs_more_product
            .create_deterministic_result_v1(
                needs_more_result,
                b"CANARY_STATE_QUESTION timeout request",
                ledger(seed, state.clone(), oversized_records()),
                now,
                0,
            )
            .unwrap();
        let DeterministicProductDecisionV1::NeedsMore(needs_more) = needs_more else {
            panic!("zero-budget table case must need more");
        };
        assert_eq!(needs_more.acquisition(), &state);
        assert!(!needs_more.references().is_empty());
        for reference in needs_more.references() {
            assert!(
                needs_more_product
                    .expand(
                        ExpansionRequestV1::new(
                            needs_more_result,
                            reference.id(),
                            ExpansionRelationV1::Exact,
                            expansion_limit(),
                        ),
                        now,
                    )
                    .is_ok()
            );
        }
        assert_eq!(
            needs_more_product.expand_alias(
                AliasExpansionRequestV1::new(
                    needs_more_result,
                    EvidenceAliasV1::new(needs_more_result, 1).unwrap(),
                    ExpansionRelationV1::Exact,
                    expansion_limit(),
                ),
                now,
            ),
            Err(ResultStoreError::ReferenceUnavailable)
        );
        assert!(!format!("{needs_more:?}").contains("CANARY_STATE_QUESTION"));
    }
}

#[test]
fn exact_passthrough_token_edge_is_inclusive_and_one_below_never_passthrough() {
    let records = oversized_records();
    let now = UnixTimestampNanos::new(4_000);
    let mut probe = MemoryProductV1::new();
    let probe_decision = probe
        .create_result(
            result(50),
            b"timeout request",
            complete_ledger(50, records),
            now,
            1_000_000,
            &Utf8ByteTokenizerV1::new(),
        )
        .unwrap();
    let ProductResultDecisionV1::Rendered(probe_rendered) = probe_decision else {
        panic!("probe budget must fit passthrough");
    };
    let exact_budget = probe_rendered
        .artifact()
        .brief()
        .budget()
        .total_rendered_tokens();
    assert!(exact_budget > 0);

    let mut exact = MemoryProductV1::new();
    assert!(matches!(
        exact
            .create_deterministic_result_v1(
                result(50),
                b"timeout request",
                complete_ledger(50, oversized_records()),
                now,
                exact_budget,
            )
            .unwrap(),
        DeterministicProductDecisionV1::Passthrough(_)
    ));

    let mut under = MemoryProductV1::new();
    let under_decision = under
        .create_deterministic_result_v1(
            result(50),
            b"timeout request",
            complete_ledger(50, oversized_records()),
            now,
            exact_budget - 1,
        )
        .unwrap();
    assert!(!matches!(
        under_decision,
        DeterministicProductDecisionV1::Passthrough(_)
    ));
}

#[test]
fn same_question_resume_after_repeat_hard_error_is_transactional_and_deterministic() {
    const QUESTION: &[u8] = b"CANARY_RESUME_QUESTION timeout request";
    let source = complete_ledger(60, oversized_records());
    let original_plan = source.plan_digest();
    let now = UnixTimestampNanos::new(6_000);
    let tokenizer = Utf8ByteTokenizerV1::new();
    let mut product = MemoryProductV1::new();
    let retained = product
        .create_result(
            result(60),
            QUESTION,
            source.clone(),
            now,
            20_000,
            &tokenizer,
        )
        .unwrap();
    let ProductResultDecisionV1::CompilationRequired(retained) = retained else {
        panic!("resume fixture must retain a passthrough miss");
    };
    let original_expiry = retained.expires_at();
    let original_references = retained
        .references()
        .iter()
        .map(EvidenceReferenceV1::id)
        .collect::<Vec<_>>();

    let foreign = compiler_probe(QUESTION, &source, result(61), 20_000);
    let foreign = foreign.selected().expect("foreign compiler must select");
    for attempt in 0..2 {
        let error = product
            .compile_retained_result(
                result(60),
                foreign.selection().clone(),
                foreign.certification(),
                UnixTimestampNanos::new(now.get() + i128::from(attempt)),
                &tokenizer,
            )
            .unwrap_err();
        assert_eq!(
            error.cost_certification_error(),
            Some(CompiledCostCertificationError::ResultBindingMismatch)
        );
        assert_eq!(product.result_count(), 1);
        for reference in &original_references {
            assert!(
                product
                    .expand(
                        ExpansionRequestV1::new(
                            result(60),
                            *reference,
                            ExpansionRelationV1::Exact,
                            expansion_limit(),
                        ),
                        now,
                    )
                    .is_ok()
            );
        }
        assert_eq!(
            product.expand_alias(
                AliasExpansionRequestV1::new(
                    result(60),
                    EvidenceAliasV1::new(result(60), 1).unwrap(),
                    ExpansionRelationV1::Exact,
                    expansion_limit(),
                ),
                now,
            ),
            Err(ResultStoreError::ReferenceUnavailable)
        );
    }

    for wrong_question in [
        b"CANARY_WRONG_RESUME_QUESTION".as_slice(),
        b"CANARY_WRONG_RESUME_QUESTION_AGAIN".as_slice(),
    ] {
        let error = product
            .resume_deterministic_result_v1(result(60), wrong_question, now)
            .unwrap_err();
        assert_eq!(error, ProductError::CompilationBindingMismatch);
        let rendered = format!("{error:?} {product:?}");
        assert!(!rendered.contains("CANARY_WRONG_RESUME_QUESTION"));
        assert_eq!(product.result_count(), 1);
    }

    let resumed = product
        .resume_deterministic_result_v1(result(60), QUESTION, now)
        .unwrap();
    let DeterministicProductDecisionV1::Compiled(resumed) = resumed else {
        panic!("same-question retry must complete the retained compilation");
    };
    assert_eq!(resumed.expires_at(), original_expiry);
    assert_eq!(resumed.artifact().brief().plan_digest(), original_plan);
    assert_eq!(
        resumed.artifact().brief().question_digest(),
        derive_question_digest_v1(QUESTION)
    );
    assert!(!resumed.artifact().text().contains("CANARY_RESUME_QUESTION"));
    assert!(
        product
            .expand_alias(
                AliasExpansionRequestV1::new(
                    result(60),
                    EvidenceAliasV1::new(result(60), 1).unwrap(),
                    ExpansionRelationV1::Exact,
                    expansion_limit(),
                ),
                now,
            )
            .is_ok()
    );

    let mut direct = MemoryProductV1::new();
    let direct = direct
        .create_deterministic_result_v1(result(60), QUESTION, source, now, 20_000)
        .unwrap();
    let DeterministicProductDecisionV1::Compiled(direct) = direct else {
        panic!("direct replay must compile");
    };
    assert_eq!(resumed.artifact().text(), direct.artifact().text());
    assert!(matches!(
        product.resume_deterministic_result_v1(result(60), QUESTION, now),
        Err(ProductError::CompilationUnavailable)
    ));
}

#[test]
fn resume_needs_more_preserves_references_budget_and_expiry_without_aliases() {
    let now = UnixTimestampNanos::new(7_000);
    let mut product = MemoryProductV1::new();
    let first = product
        .create_deterministic_result_v1(
            result(70),
            b"timeout request",
            complete_ledger(70, oversized_records()),
            now,
            0,
        )
        .unwrap();
    let DeterministicProductDecisionV1::NeedsMore(first) = first else {
        panic!("zero budget must remain needs-more");
    };
    let first_ids = first
        .references()
        .iter()
        .map(EvidenceReferenceV1::id)
        .collect::<Vec<_>>();
    let first_expiry = first.expires_at();
    let first_reason = first.compiler_reason();
    let first_budget = first.passthrough_not_fit().total_token_limit();
    let first_audit = first.proposal_audit().clone();
    assert_eq!(first_audit.code(), "budget_needs_more");
    assert_eq!(first_audit.reason(), Some(first_reason));
    assert!(first_audit.selected_packet_ids().is_none());
    let first_prepared = first_audit
        .prepared()
        .expect("budget needs-more must retain the exact prepared universe");
    assert_exact_proposal_memberships(first_prepared);
    assert!(first_audit.receipt().is_some());

    let resumed = product
        .resume_deterministic_result_v1(
            result(70),
            b"timeout request",
            UnixTimestampNanos::new(now.get() + 1),
        )
        .unwrap();
    let DeterministicProductDecisionV1::NeedsMore(resumed) = resumed else {
        panic!("unchanged retained miss must deterministically remain needs-more");
    };
    assert_eq!(resumed.compiler_reason(), first_reason);
    assert_eq!(resumed.proposal_audit(), &first_audit);
    assert_eq!(resumed.expires_at(), first_expiry);
    assert_eq!(
        resumed.passthrough_not_fit().total_token_limit(),
        first_budget
    );
    assert_eq!(
        resumed
            .references()
            .iter()
            .map(EvidenceReferenceV1::id)
            .collect::<Vec<_>>(),
        first_ids
    );
    for reference_id in first_ids {
        assert!(
            product
                .expand(
                    ExpansionRequestV1::new(
                        result(70),
                        reference_id,
                        ExpansionRelationV1::Exact,
                        expansion_limit(),
                    ),
                    UnixTimestampNanos::new(now.get() + 1),
                )
                .is_ok()
        );
    }
    assert_eq!(
        product.expand_alias(
            AliasExpansionRequestV1::new(
                result(70),
                EvidenceAliasV1::new(result(70), 1).unwrap(),
                ExpansionRelationV1::Exact,
                expansion_limit(),
            ),
            UnixTimestampNanos::new(now.get() + 1),
        ),
        Err(ResultStoreError::ReferenceUnavailable)
    );
}

#[test]
fn prepared_proposal_audit_is_identical_across_budgets_replay_and_resume() {
    let source = complete_ledger(71, oversized_records());
    let now = UnixTimestampNanos::new(7_100);
    let question = b"timeout request";

    let mut selected_product = MemoryProductV1::new();
    let selected = selected_product
        .create_deterministic_result_v1(result(71), question, source.clone(), now, 20_000)
        .unwrap();
    let DeterministicProductDecisionV1::Compiled(selected) = selected else {
        panic!("fitting proposal budget must compile");
    };
    let selected_audit = selected
        .proposal_audit()
        .expect("three-lane success must expose its proposal audit")
        .clone();
    assert_eq!(selected_audit.code(), "selected");

    let run_needs_more = || {
        let mut product = MemoryProductV1::new();
        let decision = product
            .create_deterministic_result_v1(result(71), question, source.clone(), now, 0)
            .unwrap();
        let DeterministicProductDecisionV1::NeedsMore(needs_more) = decision else {
            panic!("zero budget must retain the prepared proposal universe");
        };
        (product, needs_more.proposal_audit().clone())
    };
    let (mut needs_more_product, needs_more_audit) = run_needs_more();
    let (_, replay_audit) = run_needs_more();

    assert_eq!(selected_audit.input(), needs_more_audit.input());
    assert_eq!(selected_audit.receipt(), needs_more_audit.receipt());
    assert_eq!(selected_audit.prepared(), needs_more_audit.prepared());
    assert_eq!(needs_more_audit, replay_audit);
    assert_exact_proposal_memberships(
        needs_more_audit
            .prepared()
            .expect("budget needs-more must expose proposal membership"),
    );

    let resumed = needs_more_product
        .resume_deterministic_result_v1(
            result(71),
            question,
            UnixTimestampNanos::new(now.get() + 1),
        )
        .unwrap();
    let DeterministicProductDecisionV1::NeedsMore(resumed) = resumed else {
        panic!("the frozen zero budget must remain needs-more on resume");
    };
    assert_eq!(resumed.proposal_audit(), &needs_more_audit);
}

#[test]
fn incomplete_preparation_exposes_only_its_bound_input_receipt_and_is_redacted() {
    const V1_QUESTION_BYTE_CAP: usize = 64 * 1024;
    const QUESTION_CANARY: &[u8] = b"CANARY_PREPARATION_QUESTION";
    const MEMBER_CANARY: &[u8] = b"CANARY_PREPARATION_MEMBER";
    const PAYLOAD_CANARY: &[u8] = b"CANARY_PREPARATION_PAYLOAD";

    let mut oversized_question = QUESTION_CANARY.to_vec();
    oversized_question.resize(V1_QUESTION_BYTE_CAP + 1, b'q');
    let source = complete_ledger(
        72,
        vec![fixture(
            MEMBER_CANARY,
            SourceStream::Stderr,
            0,
            RecordBytes::whole([PAYLOAD_CANARY, vec![b'X'; 50_000].as_slice()].concat()),
        )],
    );
    let expected_plan = source.plan_digest();
    let now = UnixTimestampNanos::new(7_200);
    let mut product = MemoryProductV1::new();
    let decision = product
        .create_deterministic_result_v1(result(72), &oversized_question, source, now, 0)
        .unwrap();
    let DeterministicProductDecisionV1::NeedsMore(needs_more) = decision else {
        panic!("question cap must stop proposal preparation");
    };
    let audit = needs_more.proposal_audit().clone();
    assert_eq!(audit.code(), "preparation_incomplete");
    assert_eq!(audit.receipt(), None);
    assert!(audit.prepared().is_none());
    assert!(audit.selected_packet_ids().is_none());
    assert_eq!(audit.input().result_id(), result(72));
    assert_eq!(
        audit.input().question_digest(),
        derive_question_digest_v1(&oversized_question)
    );
    assert_eq!(audit.input().plan_digest(), expected_plan);
    assert_eq!(
        audit.reason().and_then(ThreeLaneNeedsMoreV1::lane),
        Some(CandidateLaneV1::Lexical)
    );
    assert_eq!(
        audit
            .reason()
            .and_then(ThreeLaneNeedsMoreV1::candidate_reason)
            .map(|reason| reason.code()),
        Some("question_bytes_cap")
    );

    let resumed = product
        .resume_deterministic_result_v1(
            result(72),
            &oversized_question,
            UnixTimestampNanos::new(now.get() + 1),
        )
        .unwrap();
    let DeterministicProductDecisionV1::NeedsMore(resumed) = resumed else {
        panic!("cached incomplete preparation must remain needs-more");
    };
    assert_eq!(resumed.proposal_audit(), &audit);
    let debug = format!("{needs_more:?} {audit:?} {resumed:?}");
    for canary in [QUESTION_CANARY, MEMBER_CANARY, PAYLOAD_CANARY] {
        assert!(
            !debug
                .as_bytes()
                .windows(canary.len())
                .any(|window| window == canary)
        );
    }
    assert!(!debug.contains(&result(72).canonical_token()));

    let empty_source = complete_ledger(73, Vec::new());
    let empty_plan = empty_source.plan_digest();
    let mut empty_product = MemoryProductV1::new();
    let empty = empty_product
        .create_deterministic_result_v1(result(73), b"CANARY_EMPTY_QUESTION", empty_source, now, 0)
        .unwrap();
    let DeterministicProductDecisionV1::NeedsMore(empty) = empty else {
        panic!("empty primary universe must be a typed non-success");
    };
    assert_eq!(
        empty.compiler_reason(),
        ThreeLaneNeedsMoreV1::EmptyPrimaryUniverse
    );
    assert_eq!(empty.proposal_audit().code(), "preparation_incomplete");
    assert_eq!(empty.proposal_audit().receipt(), None);
    assert_eq!(empty.proposal_audit().input().result_id(), result(73));
    assert_eq!(empty.proposal_audit().input().plan_digest(), empty_plan);
    assert!(!format!("{empty:?}").contains("CANARY_EMPTY_QUESTION"));
}

#[test]
fn resume_at_expiry_fails_without_reinsertion_or_ttl_extension() {
    let now = UnixTimestampNanos::new(8_000);
    let tokenizer = Utf8ByteTokenizerV1::new();
    let mut product = MemoryProductV1::new();
    let retained = product
        .create_result(
            result(80),
            b"timeout request",
            complete_ledger(80, oversized_records()),
            now,
            20_000,
            &tokenizer,
        )
        .unwrap();
    let ProductResultDecisionV1::CompilationRequired(retained) = retained else {
        panic!("expiry fixture must retain a passthrough miss");
    };
    let expiry = retained.expires_at();
    let reference = retained.references()[0].id();

    let error = product
        .resume_deterministic_result_v1(result(80), b"timeout request", expiry)
        .unwrap_err();
    assert_eq!(
        error.store_error(),
        Some(ResultStoreError::ReferenceUnavailable)
    );
    assert_eq!(product.result_count(), 1);
    assert_eq!(
        product.expand(
            ExpansionRequestV1::new(
                result(80),
                reference,
                ExpansionRelationV1::Exact,
                expansion_limit(),
            ),
            expiry,
        ),
        Err(ResultStoreError::ReferenceUnavailable)
    );
    assert_eq!(product.cleanup_expired(expiry), 1);
    assert_eq!(product.result_count(), 0);
    assert!(matches!(
        product.resume_deterministic_result_v1(result(80), b"timeout request", expiry),
        Err(ProductError::CompilationUnavailable)
    ));
}

#[test]
fn large_all_fallback_universe_returns_needs_more_when_no_representative_packet_fits() {
    const BLOCK_COUNT: usize = 257;
    let records = (0..BLOCK_COUNT)
        .map(|position| {
            let mut bytes = vec![b'Q'; 1_024];
            bytes.extend_from_slice(format!(" synthetic ordinary {position:04}").as_bytes());
            RecordBytes::framed(bytes, b"\n".to_vec())
        })
        .collect::<Vec<_>>();
    let expected_first = records.first().unwrap().exact_bytes();
    let expected_last = records.last().unwrap().exact_bytes();
    let source = complete_ledger(90, single_lane_records(&records));
    let blocks = frame_source_lanes_v1(&source).unwrap();
    assert_eq!(blocks.len(), BLOCK_COUNT);
    assert!(
        blocks
            .blocks()
            .iter()
            .all(|block| block.state() == BlockState::FallbackSingleton)
    );

    let now = UnixTimestampNanos::new(9_000);
    let mut threshold_probe = MemoryProductV1::new();
    let threshold_probe = threshold_probe
        .create_deterministic_result_v1(result(90), &[], source.clone(), now, 1_000_000)
        .unwrap();
    let DeterministicProductDecisionV1::Passthrough(threshold_probe) = threshold_probe else {
        panic!("the bounded threshold probe must fit passthrough");
    };
    let exact_passthrough_tokens = threshold_probe
        .artifact()
        .brief()
        .budget()
        .total_rendered_tokens();
    let compiled_budget = exact_passthrough_tokens.checked_sub(1).unwrap();
    let mut exact_edge_product = MemoryProductV1::new();
    assert!(matches!(
        exact_edge_product
            .create_deterministic_result_v1(
                result(90),
                &[],
                source.clone(),
                now,
                exact_passthrough_tokens,
            )
            .unwrap(),
        DeterministicProductDecisionV1::Passthrough(_)
    ));

    let fitting = compiler_probe(&[], &source, result(90), compiled_budget);
    let selected = fitting
        .selected()
        .expect("bounded representatives must fit");
    assert_eq!(selected.packet_metadata().len(), BLOCK_COUNT);
    let proposal_ids = selected
        .proposal_packet_ids()
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let certified_ids = selected
        .certification()
        .packet_bounds()
        .iter()
        .map(|bound| bound.packet_id())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        selected.certification().packet_bounds().len(),
        selected.proposal_packet_ids().len()
    );
    assert_eq!(certified_ids, proposal_ids);
    let proposal_accounting = selected.proposal_receipt().accounting();
    assert_eq!(
        proposal_accounting.exhaustive_primary_block_count(),
        u64::try_from(BLOCK_COUNT).unwrap()
    );
    assert_eq!(proposal_accounting.proposal_packet_count(), 9);
    assert_eq!(
        proposal_accounting.retained_raw_nonproposal_block_count(),
        u64::try_from(BLOCK_COUNT - 9).unwrap()
    );
    assert_eq!(
        proposal_accounting
            .proposal_packet_count()
            .checked_add(proposal_accounting.retained_raw_nonproposal_block_count()),
        Some(proposal_accounting.exhaustive_primary_block_count())
    );
    assert_eq!(
        proposal_accounting
            .proposal_unique_member_event_count()
            .checked_add(proposal_accounting.retained_raw_nonproposal_member_event_count()),
        Some(proposal_accounting.exhaustive_member_event_count())
    );
    assert_eq!(
        proposal_accounting
            .proposal_member_source_bytes()
            .checked_add(proposal_accounting.retained_raw_nonproposal_source_bytes()),
        Some(proposal_accounting.exhaustive_member_source_bytes())
    );
    assert!(selected.proposal_packet_ids().len() < BLOCK_COUNT);
    assert!(selected.selection().packets().len() < BLOCK_COUNT);
    let fixed_overhead = selected
        .certification()
        .fixed_overhead()
        .upper_bound_tokens();

    let mut compiled_product = MemoryProductV1::new();
    let compiled = compiled_product
        .create_deterministic_result_v1(result(90), &[], source.clone(), now, compiled_budget)
        .unwrap();
    let DeterministicProductDecisionV1::Compiled(compiled) = compiled else {
        panic!("bounded fallback representatives must compile when they fit");
    };
    let presentation = compiled.artifact().brief().coverage().presentation_counts();
    assert_eq!(presentation.persisted(), BLOCK_COUNT);
    assert!(presentation.shown_verbatim > 0);
    assert!(presentation.retained_raw > 0);

    let mut product = MemoryProductV1::new();
    let decision = product
        .create_deterministic_result_v1(result(90), &[], source, now, fixed_overhead)
        .unwrap();
    let DeterministicProductDecisionV1::NeedsMore(needs_more) = decision else {
        panic!("an empty selected packet set must not become compiled coverage");
    };
    assert_eq!(
        needs_more.compiler_reason(),
        ThreeLaneNeedsMoreV1::NoSelectedPacketFits
    );
    assert_eq!(needs_more.references().len(), BLOCK_COUNT);
    for (reference, expected) in [
        (&needs_more.references()[0], expected_first),
        (&needs_more.references()[BLOCK_COUNT - 1], expected_last),
    ] {
        let expansion = product
            .expand(
                ExpansionRequestV1::new(
                    result(90),
                    reference.id(),
                    ExpansionRelationV1::Exact,
                    expansion_limit(),
                ),
                now,
            )
            .unwrap();
        assert_eq!(expansion.events()[0].exact_bytes(), expected);
    }
    assert_eq!(
        product.expand_alias(
            AliasExpansionRequestV1::new(
                result(90),
                EvidenceAliasV1::new(result(90), 1).unwrap(),
                ExpansionRelationV1::Exact,
                expansion_limit(),
            ),
            now,
        ),
        Err(ResultStoreError::ReferenceUnavailable)
    );
}
