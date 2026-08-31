use std::collections::BTreeSet;

use evidentrail_candidates::{
    CANDIDATE_POLICY_NAME_V1, CANDIDATE_POLICY_VERSION_V1, CandidateBuildErrorV1,
    CandidateGenerationDecisionV1, CandidateNeedsMoreReasonV1, MAX_PRIMARY_BLOCKS_V1,
    MAX_QUERY_TERM_BYTES_V1, MAX_QUERY_TERMS_V1, MAX_QUERY_TOKENS_V1, MAX_QUESTION_BYTES_V1,
    MAX_VALIDATED_QUERY_IDENTIFIERS_V1, ValidatedIdentifierKindV1, generate_lexical_candidates_v1,
    preprocess_query_v1,
};
use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    CompletenessProof, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, EventLedger,
    FetchBoundaries, FetchCompleteness, FetchCompletion, FetchIdentity, FetchTiming, LaneKey,
    LaneSequence, LedgerBuilder, PlanDigest, PlanId, PolicyAuthorization, RawEnvelopeIdentityV1,
    RawEnvelopeV1, RecordBytes, RecordState, RetrievalId, SourceIdentityDigest, SourceMember,
    SourceStream, UnixTimestampNanos,
};
use evidentrail_framing::frame_source_lanes_v1;
use evidentrail_select::ProductionFacetKindV1;

struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

fn ledger(seed: u8, records: &[Vec<u8>]) -> EventLedger {
    let retrieval_id = RetrievalId::from_bytes([seed; 32]);
    let plan_id = PlanId::from_bytes([31; 32]);
    let plan_digest = PlanDigest::from_bytes([32; 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([33; 32]);
    let adapter = AdapterIdentity::new("candidate-fixture", "1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let lane = LaneKey::new(
        SourceMember::new(b"candidate-fixture-member".to_vec()).unwrap(),
        SourceStream::Stderr,
    );
    let mut builder = LedgerBuilder::new(
        fetch_identity.clone(),
        source_identity_digest,
        SourceExactPolicy,
    );
    let mut payload_bytes = 0u64;
    let mut source_bytes = 0u64;

    for (position, payload) in records.iter().enumerate() {
        payload_bytes = payload_bytes
            .checked_add(u64::try_from(payload.len()).unwrap())
            .unwrap();
        source_bytes = source_bytes
            .checked_add(u64::try_from(payload.len() + 1).unwrap())
            .unwrap();
        let sequence = u64::try_from(position).unwrap();
        builder
            .accept(RawEnvelopeV1::new(
                envelope_identity.clone(),
                EnvelopeOrdering::new(
                    AcquisitionSequence::new(sequence),
                    lane.clone(),
                    LaneSequence::new(sequence),
                ),
                RecordBytes::framed(payload.clone(), b"\n".to_vec()),
                RecordState::Complete,
            ))
            .unwrap();
    }

    let record_count = u64::try_from(records.len()).unwrap();
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
        FetchCompleteness::complete(CompletenessProof::OtherVersioned {
            version: 1,
            code: 101,
        }),
    )
    .unwrap();
    builder.seal(completion).unwrap()
}

fn ready(
    question: &[u8],
    blocks: &evidentrail_core::BlockIndex<'_>,
) -> evidentrail_candidates::LexicalCandidateUniverseV1 {
    match generate_lexical_candidates_v1(question, blocks).unwrap() {
        CandidateGenerationDecisionV1::Ready(universe) => universe,
        CandidateGenerationDecisionV1::NeedsMore(reason) => {
            panic!("unexpected needs_more: {}", reason.code())
        }
    }
}

fn needs_more(
    question: &[u8],
    blocks: &evidentrail_core::BlockIndex<'_>,
) -> CandidateNeedsMoreReasonV1 {
    match generate_lexical_candidates_v1(question, blocks).unwrap() {
        CandidateGenerationDecisionV1::Ready(_) => panic!("unexpected ready decision"),
        CandidateGenerationDecisionV1::NeedsMore(reason) => reason.reason(),
    }
}

#[test]
fn query_preprocessing_is_byte_oriented_order_stable_and_case_normalized() {
    let first = preprocess_query_v1(b"Why TIMEOUT cache Failure \xff marker").unwrap();
    let second = preprocess_query_v1(b"marker failure CACHE timeout why \xfe").unwrap();
    let first_terms = first
        .terms()
        .iter()
        .map(|term| term.canonical_token())
        .collect::<Vec<_>>();
    let second_terms = second
        .terms()
        .iter()
        .map(|term| term.canonical_token())
        .collect::<Vec<_>>();

    assert_eq!(
        first_terms,
        [
            b"cache".as_slice(),
            b"failure".as_slice(),
            b"marker".as_slice(),
            b"timeout".as_slice()
        ]
    );
    assert_eq!(first_terms, second_terms);
    assert_ne!(first.question_digest(), second.question_digest());
    assert!(first.identifiers().is_empty());
}

#[test]
fn lexical_matching_is_whole_token_only_and_bm25_style() {
    let records = [
        b"timeout timeout service".to_vec(),
        b"timeouts service".to_vec(),
        b"timeout service with several unrelated tokens".to_vec(),
    ];
    let ledger = ledger(1, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(b"TIMEOUT", &blocks);

    assert_eq!(universe.facets().len(), 1);
    assert_eq!(
        universe.facets()[0].kind(),
        ProductionFacetKindV1::QueryTerm
    );
    assert_eq!(universe.primary_blocks().len(), 3);
    assert_eq!(universe.primary_blocks()[0].affinities().len(), 1);
    assert!(universe.primary_blocks()[0].mandatory_reasons().is_empty());
    assert!(universe.primary_blocks()[1].affinities().is_empty());
    assert_eq!(universe.primary_blocks()[2].affinities().len(), 1);
    assert!(
        universe.primary_blocks()[0].affinities()[0]
            .affinity()
            .micros()
            > universe.primary_blocks()[2].affinities()[0]
                .affinity()
                .micros()
    );
}

#[test]
fn sentence_punctuation_does_not_corrupt_exact_token_boundaries() {
    let uuid = b"550e8400-e29b-41d4-a716-446655440000";
    let record = [b"timeout. request ".as_slice(), uuid, b"."].concat();
    let question = [b"timeout ".as_slice(), uuid].concat();
    let ledger = ledger(15, &[record]);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(&question, &blocks);

    assert_eq!(universe.mandatory_block_count(), 1);
    assert_eq!(universe.primary_blocks()[0].mandatory_reasons().len(), 1);
    assert_eq!(universe.primary_blocks()[0].affinities().len(), 2);
}

#[test]
fn dual_analysis_preserves_paths_and_finds_only_exact_path_components() {
    let uuid = b"550e8400-e29b-41d4-a716-446655440000";
    let records = [
        [
            b"timeout. endpoint=/api/users trace=https://collector/traces/".as_slice(),
            uuid,
        ]
        .concat(),
        b"timeouts endpoint=/api/userstories".to_vec(),
    ];
    let question = [b"timeout /api/users ".as_slice(), uuid].concat();
    let processed = preprocess_query_v1(&question).unwrap();
    let terms = processed
        .terms()
        .iter()
        .map(|term| term.canonical_token())
        .collect::<Vec<_>>();
    let ledger = ledger(19, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(&question, &blocks);

    assert!(terms.contains(&b"/api/users".as_slice()));
    assert_eq!(processed.identifiers().len(), 1);
    assert_eq!(universe.primary_blocks()[0].mandatory_reasons().len(), 1);
    assert_eq!(universe.primary_blocks()[1].mandatory_reasons().len(), 0);
    assert_eq!(universe.primary_blocks()[0].affinities().len(), 5);
    assert_eq!(universe.primary_blocks()[1].affinities().len(), 1);
}

#[test]
fn query_permutation_and_case_cannot_change_facets_or_affinities() {
    let records = [
        b"timeout cache failure".to_vec(),
        b"cache recovered".to_vec(),
    ];
    let ledger = ledger(2, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let first = ready(b"timeout CACHE failure", &blocks);
    let second = ready(b"FAILURE timeout cache", &blocks);

    assert_eq!(first.facets(), second.facets());
    assert_eq!(first.primary_blocks(), second.primary_blocks());
    assert_ne!(first.question_digest(), second.question_digest());
}

#[test]
fn only_closed_validated_identifier_shapes_become_mandatory() {
    let uuid = b"550e8400-e29b-41d4-a716-446655440000";
    let trace = b"4bf92f3577b34da6a3ce929d0e0e4736";
    let span = b"00f067aa0ba902b7";
    let unlabeled_hex = b"7bf92f3577b34da6a3ce929d0e0e4736";
    let question = [
        b"investigate ".as_slice(),
        uuid,
        b" trace_id=",
        trace,
        b" span-id:",
        span,
        b" E0425 /api/users ",
        unlabeled_hex,
    ]
    .concat();
    let record = [
        b"request ".as_slice(),
        uuid,
        b" trace_id=",
        trace,
        b" span_id=",
        span,
        b" compiler E0425 endpoint /api/users opaque ",
        unlabeled_hex,
    ]
    .concat();
    let processed = preprocess_query_v1(&question).unwrap();
    let ledger = ledger(3, &[record]);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(&question, &blocks);

    assert_eq!(processed.identifiers().len(), 4);
    assert_eq!(
        processed
            .identifiers()
            .iter()
            .map(|identifier| identifier.kind())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            ValidatedIdentifierKindV1::CanonicalUuid,
            ValidatedIdentifierKindV1::TraceIdHex128,
            ValidatedIdentifierKindV1::SpanIdHex64,
            ValidatedIdentifierKindV1::RustCompilerErrorCode,
        ])
    );
    assert_eq!(universe.mandatory_block_count(), 1);
    assert_eq!(universe.primary_blocks()[0].mandatory_reasons().len(), 4);
    assert!(
        universe
            .facets()
            .iter()
            .any(|facet| facet.kind() == ProductionFacetKindV1::QueryTerm)
    );
    assert!(universe.primary_blocks()[0].affinities().len() > 4);
}

#[test]
fn malformed_or_context_free_identifier_shapes_never_force_blocks() {
    let question = b"trace_id 00000000000000000000000000000000 \
        span_id 0000000000000000 \
        550e8400-e29b-01d4-a716-446655440000 \
        550e8400-e29b-41d4-c716-446655440000 \
        E0000 E123 4bf92f3577b34da6a3ce929d0e0e4736";
    let processed = preprocess_query_v1(question).unwrap();
    let ledger = ledger(4, &[question.to_vec()]);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(question, &blocks);

    assert!(processed.identifiers().is_empty());
    assert_eq!(universe.mandatory_block_count(), 0);
    assert!(universe.primary_blocks()[0].mandatory_reasons().is_empty());
}

#[test]
fn explicit_multi_token_and_dotted_trace_span_labels_are_supported() {
    let trace = b"4bf92f3577b34da6a3ce929d0e0e4736";
    let span = b"00f067aa0ba902b7";
    for question in [
        [b"trace id ".as_slice(), trace, b" span id ", span].concat(),
        [b"trace.id=".as_slice(), trace, b" span.id=", span].concat(),
    ] {
        let processed = preprocess_query_v1(&question).unwrap();
        assert_eq!(processed.identifiers().len(), 2);
        assert_eq!(
            processed
                .identifiers()
                .iter()
                .map(|identifier| identifier.kind())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                ValidatedIdentifierKindV1::TraceIdHex128,
                ValidatedIdentifierKindV1::SpanIdHex64,
            ])
        );
    }

    let bare = [trace.as_slice(), b" ", span].concat();
    assert!(preprocess_query_v1(&bare).unwrap().identifiers().is_empty());

    let valid_character_extremes = b"trace id 12345678901234567890123456789012 \
        trace.id=abcdefabcdefabcdefabcdefabcdefab \
        span.id=1234567890123456 span id abcdefabcdefabcd";
    assert_eq!(
        preprocess_query_v1(valid_character_extremes)
            .unwrap()
            .identifiers()
            .len(),
        4
    );
    let all_zero = b"trace id 00000000000000000000000000000000 \
        span.id=0000000000000000";
    assert!(
        preprocess_query_v1(all_zero)
            .unwrap()
            .identifiers()
            .is_empty()
    );
}

#[test]
fn typed_identifier_substrings_are_not_matches() {
    let uuid = b"550e8400-e29b-41d4-a716-446655440000";
    let trace = b"4bf92f3577b34da6a3ce929d0e0e4736";
    let question = [uuid.as_slice(), b" trace.id=", trace, b" E0425"].concat();
    let record = [b"prefix".as_slice(), uuid, b"suffix x", trace, b"y XE0425"].concat();
    let ledger = ledger(14, &[record]);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(&question, &blocks);

    assert_eq!(universe.mandatory_block_count(), 0);
    assert!(universe.primary_blocks()[0].mandatory_reasons().is_empty());
    assert!(
        universe.primary_blocks()[0]
            .affinities()
            .iter()
            .all(|affinity| {
                universe
                    .facets()
                    .iter()
                    .find(|facet| facet.facet().id() == affinity.facet_id())
                    .is_none_or(|facet| {
                        facet.kind() != ProductionFacetKindV1::ValidatedQueryIdentifier
                    })
            })
    );
}

#[test]
fn duplicate_payload_blocks_remain_distinct_occurrences() {
    let uuid = b"550e8400-e29b-41d4-a716-446655440000";
    let record = [b"request ".as_slice(), uuid].concat();
    let ledger = ledger(5, &[record.clone(), record]);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(uuid, &blocks);

    assert_eq!(universe.primary_blocks().len(), 2);
    assert_eq!(universe.mandatory_block_count(), 2);
    assert_ne!(
        universe.primary_blocks()[0].block_id(),
        universe.primary_blocks()[1].block_id()
    );
    assert_ne!(
        universe.primary_blocks()[0].packet_id(),
        universe.primary_blocks()[1].packet_id()
    );
    assert_ne!(
        universe.primary_blocks()[0].ordered_event_ids(),
        universe.primary_blocks()[1].ordered_event_ids()
    );
}

#[test]
fn reconstructed_stack_block_is_one_indivisible_candidate() {
    let records = [
        b"Traceback (most recent call last):".to_vec(),
        b"  File \"worker.py\", line 7, in run".to_vec(),
        b"ValueError: compiler E0425".to_vec(),
    ];
    let ledger = ledger(6, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    assert_eq!(blocks.len(), 1);
    let universe = ready(b"E0425", &blocks);

    assert_eq!(universe.primary_blocks().len(), 1);
    assert_eq!(universe.primary_blocks()[0].ordered_event_ids().len(), 3);
    assert_eq!(universe.primary_blocks()[0].mandatory_reasons().len(), 1);
    assert_eq!(
        universe.primary_blocks()[0].ordered_event_ids(),
        blocks.blocks()[0].member_ids()
    );
}

#[test]
fn invalid_utf8_and_nul_are_separators_not_lossy_decode_failures() {
    let record = [b"prefix".as_slice(), &[0xff, 0xfe, 0], b"ERROR", &[0]].concat();
    let ledger = ledger(7, &[record]);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(b"error", &blocks);

    assert_eq!(universe.primary_blocks()[0].affinities().len(), 1);
    assert_eq!(universe.primary_blocks()[0].ordered_event_ids().len(), 1);
}

#[test]
fn identifier_fanout_boundary_fails_closed_without_partial_output() {
    let uuid = b"550e8400-e29b-41d4-a716-446655440000";
    let make_records = |count: usize| {
        (0..count)
            .map(|position| {
                [
                    b"request ".as_slice(),
                    uuid,
                    format!(" occurrence-{position}").as_bytes(),
                ]
                .concat()
            })
            .collect::<Vec<_>>()
    };
    let at_cap_ledger = ledger(8, &make_records(64));
    let at_cap_blocks = frame_source_lanes_v1(&at_cap_ledger).unwrap();
    let at_cap = ready(uuid, &at_cap_blocks);
    assert_eq!(at_cap.mandatory_block_count(), 64);

    let over_cap_ledger = ledger(9, &make_records(65));
    let over_cap_blocks = frame_source_lanes_v1(&over_cap_ledger).unwrap();
    assert_eq!(
        needs_more(uuid, &over_cap_blocks),
        CandidateNeedsMoreReasonV1::IdentifierBlockFanoutCap
    );
}

#[test]
fn aggregate_mandatory_block_cap_is_not_hidden_by_per_identifier_fanout() {
    let first = b"550e8400-e29b-41d4-a716-446655440000";
    let second = b"550e8400-e29b-41d4-a716-446655440001";
    let mut records = (0..33)
        .map(|position| [first.as_slice(), format!(" first-{position}").as_bytes()].concat())
        .collect::<Vec<_>>();
    records
        .extend((0..33).map(|position| {
            [second.as_slice(), format!(" second-{position}").as_bytes()].concat()
        }));
    let question = [first.as_slice(), b" ", second].concat();
    let ledger = ledger(16, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();

    assert_eq!(
        needs_more(&question, &blocks),
        CandidateNeedsMoreReasonV1::MandatoryBlockCountCap
    );
}

#[test]
fn every_query_cap_has_an_exact_boundary_and_typed_failure() {
    let exact_question_bytes = vec![0xff; MAX_QUESTION_BYTES_V1];
    assert!(preprocess_query_v1(&exact_question_bytes).is_ok());
    assert_eq!(
        preprocess_query_v1(&vec![0xff; MAX_QUESTION_BYTES_V1 + 1])
            .unwrap_err()
            .reason(),
        CandidateNeedsMoreReasonV1::QuestionBytesCap
    );

    let exact_token = vec![b'x'; MAX_QUERY_TERM_BYTES_V1];
    assert!(preprocess_query_v1(&exact_token).is_ok());
    assert_eq!(
        preprocess_query_v1(&[b'x'; MAX_QUERY_TERM_BYTES_V1 + 1])
            .unwrap_err()
            .reason(),
        CandidateNeedsMoreReasonV1::QueryTokenBytesCap
    );

    let tokens = |count: usize| vec!["is"; count].join(" ").into_bytes();
    assert!(preprocess_query_v1(&tokens(MAX_QUERY_TOKENS_V1)).is_ok());
    assert_eq!(
        preprocess_query_v1(&tokens(MAX_QUERY_TOKENS_V1 + 1))
            .unwrap_err()
            .reason(),
        CandidateNeedsMoreReasonV1::QueryTokenCountCap
    );

    // Each compound contributes itself plus its two slash components.
    let compounds = |count: usize| vec!["a/b"; count].join(" ").into_bytes();
    assert!(preprocess_query_v1(&compounds(MAX_QUERY_TOKENS_V1 / 3)).is_ok());
    assert_eq!(
        preprocess_query_v1(&compounds(MAX_QUERY_TOKENS_V1 / 3 + 1))
            .unwrap_err()
            .reason(),
        CandidateNeedsMoreReasonV1::QueryTokenCountCap
    );

    let terms = |count: usize| {
        (0..count)
            .map(|position| format!("term{position:03}"))
            .collect::<Vec<_>>()
            .join(" ")
            .into_bytes()
    };
    assert!(preprocess_query_v1(&terms(MAX_QUERY_TERMS_V1)).is_ok());
    assert_eq!(
        preprocess_query_v1(&terms(MAX_QUERY_TERMS_V1 + 1))
            .unwrap_err()
            .reason(),
        CandidateNeedsMoreReasonV1::QueryTermCountCap
    );

    let identifiers = |count: usize| {
        (0..count)
            .map(|position| format!("550e8400-e29b-41d4-a716-{position:012x}"))
            .collect::<Vec<_>>()
            .join(" ")
            .into_bytes()
    };
    assert!(preprocess_query_v1(&identifiers(MAX_VALIDATED_QUERY_IDENTIFIERS_V1)).is_ok());
    assert_eq!(
        preprocess_query_v1(&identifiers(MAX_VALIDATED_QUERY_IDENTIFIERS_V1 + 1))
            .unwrap_err()
            .reason(),
        CandidateNeedsMoreReasonV1::ValidatedIdentifierCountCap
    );
}

#[test]
fn primary_block_count_cap_is_exhaustive_not_truncating() {
    let records = (0..=MAX_PRIMARY_BLOCKS_V1)
        .map(|position| format!("ordinary record {position}").into_bytes())
        .collect::<Vec<_>>();
    let ledger = ledger(10, &records);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    assert_eq!(blocks.len(), MAX_PRIMARY_BLOCKS_V1 + 1);
    assert_eq!(
        needs_more(b"ordinary", &blocks),
        CandidateNeedsMoreReasonV1::PrimaryBlockCountCap
    );
}

#[test]
fn deterministic_replay_preserves_occurrence_ids_facets_and_scores() {
    let records = [b"cache timeout E0425".to_vec(), b"cache recovered".to_vec()];
    let first_ledger = ledger(11, &records);
    let replay_ledger = ledger(11, &records);
    let first_blocks = frame_source_lanes_v1(&first_ledger).unwrap();
    let replay_blocks = frame_source_lanes_v1(&replay_ledger).unwrap();
    let first = ready(b"cache timeout E0425", &first_blocks);
    let replay = ready(b"cache timeout E0425", &replay_blocks);

    assert_eq!(first, replay);
    assert_eq!(first.contract_version(), 1);
    assert_eq!(first.policy_name(), CANDIDATE_POLICY_NAME_V1);
    assert_eq!(first.policy_version(), CANDIDATE_POLICY_VERSION_V1);
}

#[test]
fn runtime_surface_contains_only_two_active_lane_facet_kinds() {
    let record = b"timeout 550e8400-e29b-41d4-a716-446655440000".to_vec();
    let ledger = ledger(12, &[record]);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let universe = ready(b"timeout 550e8400-e29b-41d4-a716-446655440000", &blocks);

    assert!(universe.facets().iter().all(|facet| matches!(
        facet.kind(),
        ProductionFacetKindV1::QueryTerm | ProductionFacetKindV1::ValidatedQueryIdentifier
    )));
    assert_eq!(universe.primary_blocks().len(), blocks.len());
    assert_eq!(
        universe
            .primary_blocks()
            .iter()
            .flat_map(|block| block.ordered_event_ids())
            .copied()
            .collect::<BTreeSet<_>>(),
        ledger.events().iter().map(|event| event.id()).collect()
    );
}

#[test]
fn debug_errors_and_needs_more_never_expose_query_identifier_or_payload() {
    let canary = "SUPER_SECRET_QUERY_CANARY";
    let identifier = "550e8400-e29b-41d4-a716-446655440000";
    let question = format!("{canary} {identifier}");
    let record = format!("payload {canary} {identifier}").into_bytes();
    let processed = preprocess_query_v1(question.as_bytes()).unwrap();
    let ledger = ledger(13, &[record]);
    let blocks = frame_source_lanes_v1(&ledger).unwrap();
    let decision = generate_lexical_candidates_v1(question.as_bytes(), &blocks).unwrap();
    let too_long = preprocess_query_v1(&[b'x'; MAX_QUERY_TERM_BYTES_V1 + 1]).unwrap_err();

    let mut diagnostics = vec![
        format!("{processed:?}"),
        format!("{decision:?}"),
        format!("{too_long:?}"),
        too_long.to_string(),
        format!("{:?}", CandidateBuildErrorV1::FacetContractViolation),
    ];
    diagnostics.extend(processed.terms().iter().map(|term| format!("{term:?}")));
    diagnostics.extend(
        processed
            .identifiers()
            .iter()
            .map(|identifier| format!("{identifier:?}")),
    );
    for diagnostic in diagnostics {
        assert!(!diagnostic.contains(canary));
        assert!(!diagnostic.contains(identifier));
    }
}
