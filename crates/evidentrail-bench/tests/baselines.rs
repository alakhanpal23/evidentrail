use evidentrail_bench::{
    BenchmarkMethod, ByteBudget, DiagnosticRequirement, GrepHeadTail, GrepHeadTailConfig,
    MethodError, MethodInput, MetricError, QuotaHybrid, QuotaHybridConfig, RawChronological,
    SelectionReason, candidate_cost, diagnostic_requirement_coverage, required_evidence_recall,
};
use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    CompletenessProof, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, EventLedger,
    FetchBoundaries, FetchCompleteness, FetchCompletion, FetchIdentity, FetchTiming, LaneKey,
    LaneSequence, LedgerBuilder, PlanDigest, PlanId, PolicyAuthorization, PresentationReceipt,
    RawEnvelopeIdentityV1, RawEnvelopeV1, RecordBytes, RecordState, RetrievalId,
    SourceIdentityDigest, SourceMember, SourceStream, UnixTimestampNanos,
};

struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

fn ledger_with_id(seed: u8, raw_events: Vec<Vec<u8>>) -> EventLedger {
    let retrieval_id = RetrievalId::from_bytes([seed; 32]);
    let plan_id = PlanId::from_bytes([0xb1; 32]);
    let plan_digest = PlanDigest::from_bytes([0xb2; 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([0xb3; 32]);
    let adapter = AdapterIdentity::new("benchmark-fixture", "1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let lane = LaneKey::new(
        SourceMember::new(b"benchmark-fixture-member".to_vec()).unwrap(),
        SourceStream::OtherVersioned {
            version: 1,
            code: 1,
        },
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

fn ledger(raw_events: &[&[u8]]) -> EventLedger {
    ledger_with_id(
        1,
        raw_events
            .iter()
            .map(|raw| raw.to_vec())
            .collect::<Vec<_>>(),
    )
}

fn selected_ids(result: &evidentrail_bench::MethodResult) -> Vec<evidentrail_core::EventId> {
    result
        .selected()
        .iter()
        .map(|event| event.event_id())
        .collect()
}

#[test]
fn grep_finds_a_causal_clue_amid_noise_that_raw_prefix_misses() {
    let mut events = (0..12)
        .map(|index| format!("INFO healthy worker={index:02}\n").into_bytes())
        .collect::<Vec<_>>();
    events.push(b"WARN database TIMEOUT began after pool limit changed\n".to_vec());
    events.extend(
        (12..24)
            .map(|index| format!("ERROR downstream request failed id={index:02}\n").into_bytes()),
    );
    let ledger = ledger_with_id(2, events);
    let required = ledger.events()[12].id();
    let budget = ByteBudget::new(64);

    let raw = RawChronological
        .run(MethodInput::new(
            &ledger,
            b"what caused the database timeout around deployment?",
            budget,
        ))
        .unwrap();
    let grep = GrepHeadTail::new(GrepHeadTailConfig::new(1, 1))
        .run(MethodInput::new(
            &ledger,
            b"what caused the database timeout around deployment?",
            budget,
        ))
        .unwrap();

    assert_eq!(
        required_evidence_recall(&ledger, &raw, &[required])
            .unwrap()
            .ratio(),
        Some(0.0)
    );
    assert_eq!(
        required_evidence_recall(&ledger, &grep, &[required])
            .unwrap()
            .ratio(),
        Some(1.0)
    );
    assert_eq!(grep.selected()[0].event_id(), required);
    assert!(
        grep.selected()[0]
            .reasons()
            .contains(&SelectionReason::QueryTermMatch)
    );
}

#[test]
fn exact_identifier_and_full_query_matches_receive_explicit_reasons() {
    let ledger = ledger(&[b"request req-7 failed", b"request req-8 failed"]);
    let result = GrepHeadTail::new(GrepHeadTailConfig::new(0, 0))
        .run(MethodInput::new(&ledger, b"req-7", ByteBudget::new(64)))
        .unwrap();

    assert_eq!(selected_ids(&result), vec![ledger.events()[0].id()]);
    assert!(
        result.selected()[0]
            .reasons()
            .contains(&SelectionReason::FullQueryMatch)
    );
    assert!(
        result.selected()[0]
            .reasons()
            .contains(&SelectionReason::IdentifierMatch)
    );
}

#[test]
fn query_term_scoring_prefers_more_evidence_and_breaks_ties_by_source_order() {
    let ranked = ledger(&[
        b"database timeout symptom",
        b"deployment completed",
        b"database timeout after deployment",
    ]);
    let best = GrepHeadTail::new(GrepHeadTailConfig::new(0, 0))
        .run(MethodInput::new(
            &ranked,
            b"database timeout deployment",
            ByteBudget::new(b"database timeout after deployment".len()),
        ))
        .unwrap();
    assert_eq!(selected_ids(&best), vec![ranked.events()[2].id()]);

    let tied = ledger(&[b"timeout first", b"timeout later"]);
    let earliest = GrepHeadTail::new(GrepHeadTailConfig::new(0, 0))
        .run(MethodInput::new(
            &tied,
            b"timeout",
            ByteBudget::new(b"timeout first".len()),
        ))
        .unwrap();
    assert_eq!(selected_ids(&earliest), vec![tied.events()[0].id()]);
}

#[test]
fn raw_truncation_stops_at_the_first_event_that_does_not_fit() {
    let ledger = ledger(&[b"aaaa", b"0123456789", b"bbb"]);
    let result = RawChronological
        .run(MethodInput::new(&ledger, b"", ByteBudget::new(7)))
        .unwrap();

    assert_eq!(selected_ids(&result), vec![ledger.events()[0].id()]);
    assert_eq!(result.accounting().selected_source_bytes(), 4);
    assert_eq!(result.accounting().budget_excluded_candidate_count(), 2);
    assert_eq!(
        ledger.exact_bytes(result.selected()[0].event_id()).unwrap(),
        b"aaaa"
    );
}

#[test]
fn grep_skips_an_oversized_event_without_splitting_it() {
    let ledger = ledger(&[
        b"ERROR timeout payload that is too large",
        b"ERROR timeout",
        b"tail",
    ]);
    let result = GrepHeadTail::new(GrepHeadTailConfig::new(0, 0))
        .run(MethodInput::new(
            &ledger,
            b"error timeout",
            ByteBudget::new(b"ERROR timeout".len()),
        ))
        .unwrap();

    assert_eq!(selected_ids(&result), vec![ledger.events()[1].id()]);
    assert_eq!(
        result.accounting().selected_source_bytes(),
        b"ERROR timeout".len()
    );
    assert_eq!(result.accounting().budget_excluded_candidate_count(), 1);
}

#[test]
fn empty_query_disables_grep_and_uses_tail_then_head_sentinels() {
    let ledger = ledger(&[b"head", b"middle", b"tail"]);
    let result = GrepHeadTail::new(GrepHeadTailConfig::new(1, 1))
        .run(MethodInput::new(&ledger, b"", ByteBudget::new(32)))
        .unwrap();

    assert_eq!(
        selected_ids(&result),
        vec![ledger.events()[0].id(), ledger.events()[2].id()]
    );
    assert_eq!(result.accounting().candidate_event_count(), 2);
    assert_eq!(result.accounting().selected_source_bytes(), 8);
    assert!(
        result.selected()[0]
            .reasons()
            .contains(&SelectionReason::HeadSentinel)
    );
    assert!(
        result.selected()[1]
            .reasons()
            .contains(&SelectionReason::TailSentinel)
    );
}

#[test]
fn duplicate_payloads_remain_distinct_selected_events() {
    let ledger = ledger(&[b"ERROR duplicate", b"ERROR duplicate"]);
    let result = GrepHeadTail::new(GrepHeadTailConfig::new(0, 0))
        .run(MethodInput::new(
            &ledger,
            b"error duplicate",
            ByteBudget::new(64),
        ))
        .unwrap();

    assert_eq!(result.selected().len(), 2);
    assert_ne!(
        result.selected()[0].event_id(),
        result.selected()[1].event_id()
    );
    assert_eq!(
        result.accounting().selected_source_bytes(),
        b"ERROR duplicate".len() * 2
    );
}

#[test]
fn invalid_utf8_is_never_decoded_or_silently_dropped() {
    let invalid = vec![0xff, 0x00, b'E', b'R', b'R', b'O', b'R', b'\n'];
    let ledger = ledger_with_id(3, vec![invalid.clone(), b"ordinary tail\n".to_vec()]);
    let result = GrepHeadTail::new(GrepHeadTailConfig::new(1, 1))
        .run(MethodInput::new(&ledger, b"error", ByteBudget::new(64)))
        .unwrap();

    assert_eq!(result.selected().len(), 2);
    assert_eq!(
        ledger.exact_bytes(ledger.events()[0].id()).unwrap(),
        invalid.as_slice()
    );
    assert!(result.contains(ledger.events()[0].id()));

    let assignments = result.presentation_assignments(&ledger).unwrap();
    let receipt = PresentationReceipt::reconcile(&ledger, assignments).unwrap();
    assert_eq!(receipt.persisted_count(), 2);
    assert_eq!(receipt.counts().shown_verbatim, 2);
    assert_eq!(receipt.unaccounted_count(), 0);
}

#[test]
fn deterministic_replay_produces_identical_method_results() {
    let build = || {
        ledger_with_id(
            9,
            vec![
                b"head\n".to_vec(),
                b"WARN Cache Miss\n".to_vec(),
                b"tail\n".to_vec(),
            ],
        )
    };
    let first_ledger = build();
    let second_ledger = build();
    let method = GrepHeadTail::new(GrepHeadTailConfig::new(1, 1));

    let first = method
        .run(MethodInput::new(
            &first_ledger,
            b"cache miss",
            ByteBudget::new(64),
        ))
        .unwrap();
    let second = method
        .run(MethodInput::new(
            &second_ledger,
            b"cache miss",
            ByteBudget::new(64),
        ))
        .unwrap();

    assert_eq!(first, second);
}

#[test]
fn required_evidence_metrics_deduplicate_labels_and_mark_empty_sets_not_applicable() {
    let ledger = ledger(&[b"one", b"two"]);
    let result = RawChronological
        .run(MethodInput::new(&ledger, b"", ByteBudget::new(3)))
        .unwrap();
    let first = ledger.events()[0].id();

    let score = required_evidence_recall(&ledger, &result, &[first, first]).unwrap();
    assert_eq!(score.required_event_count(), 1);
    assert_eq!(score.selected_required_event_count(), 1);
    assert_eq!(score.missed_required_event_count(), 0);
    assert_eq!(score.ratio(), Some(1.0));

    let empty = required_evidence_recall(&ledger, &result, &[]).unwrap();
    assert_eq!(empty.required_event_count(), 0);
    assert_eq!(empty.ratio(), None);
}

#[test]
fn diagnostic_requirements_support_joint_evidence_and_sufficient_alternatives() {
    let ledger = ledger(&[b"cause", b"effect", b"alternate", b"secondary"]);
    let cause = ledger.events()[0].id();
    let effect = ledger.events()[1].id();
    let alternate = ledger.events()[2].id();
    let secondary = ledger.events()[3].id();
    let requirements = vec![
        DiagnosticRequirement::new(
            2.0,
            vec![vec![cause, effect, cause], vec![alternate], vec![alternate]],
        )
        .unwrap(),
        DiagnosticRequirement::new(1.0, vec![vec![secondary]]).unwrap(),
    ];

    assert_eq!(requirements[0].alternatives().len(), 2);
    let mut alternative_lengths = requirements[0]
        .alternatives()
        .iter()
        .map(Vec::len)
        .collect::<Vec<_>>();
    alternative_lengths.sort_unstable();
    assert_eq!(alternative_lengths, vec![1, 2]);

    let joint_only = RawChronological
        .run(MethodInput::new(
            &ledger,
            b"",
            ByteBudget::new(b"causeeffect".len()),
        ))
        .unwrap();
    let joint_score = diagnostic_requirement_coverage(&ledger, &joint_only, &requirements).unwrap();
    assert_eq!(joint_score.requirement_count(), 2);
    assert_eq!(joint_score.satisfied_requirement_count(), 1);
    assert_eq!(joint_score.missed_requirement_count(), 1);
    assert_eq!(joint_score.total_weight(), 3.0);
    assert_eq!(joint_score.satisfied_weight(), 2.0);
    assert_eq!(joint_score.weighted_recall(), Some(2.0 / 3.0));

    let alternate_only = GrepHeadTail::new(GrepHeadTailConfig::new(0, 0))
        .run(MethodInput::new(
            &ledger,
            b"alternate",
            ByteBudget::new(b"alternate".len()),
        ))
        .unwrap();
    assert_eq!(
        diagnostic_requirement_coverage(&ledger, &alternate_only, &requirements)
            .unwrap()
            .weighted_recall(),
        Some(2.0 / 3.0)
    );
}

#[test]
fn diagnostic_requirement_validation_is_contentless_and_zero_case_is_the_only_na() {
    let ledger = ledger(&[b"secret-payload"]);
    let selected_none = RawChronological
        .run(MethodInput::new(
            &ledger,
            b"secret-query",
            ByteBudget::new(0),
        ))
        .unwrap();
    let id = ledger.events()[0].id();

    assert_eq!(
        DiagnosticRequirement::new(1.0, Vec::<Vec<evidentrail_core::EventId>>::new()).unwrap_err(),
        MetricError::EmptyRequirement
    );
    assert_eq!(
        DiagnosticRequirement::new(1.0, vec![Vec::<evidentrail_core::EventId>::new()]).unwrap_err(),
        MetricError::EmptyRequirementAlternative
    );
    for invalid in [0.0, -1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let error = DiagnosticRequirement::new(invalid, vec![vec![id]]).unwrap_err();
        assert_eq!(error, MetricError::InvalidRequirementWeight);
        assert_eq!(
            error.to_string(),
            "EVIDENTRAIL_BENCH_METRIC_INVALID_REQUIREMENT_WEIGHT"
        );
        assert!(!format!("{error:?}").contains("secret"));
    }

    let empty = diagnostic_requirement_coverage(&ledger, &selected_none, &[]).unwrap();
    assert_eq!(empty.weighted_recall(), None);

    let nonempty = diagnostic_requirement_coverage(
        &ledger,
        &selected_none,
        &[DiagnosticRequirement::new(1.0, vec![vec![id]]).unwrap()],
    )
    .unwrap();
    assert_eq!(nonempty.weighted_recall(), Some(0.0));

    let overflowing = [
        DiagnosticRequirement::new(f64::MAX, vec![vec![id]]).unwrap(),
        DiagnosticRequirement::new(f64::MAX, vec![vec![id]]).unwrap(),
    ];
    assert_eq!(
        diagnostic_requirement_coverage(&ledger, &selected_none, &overflowing).unwrap_err(),
        MetricError::RequirementWeightSumNotFinite
    );
    assert!(!format!("{selected_none:?}").contains("secret-query"));
    assert!(!format!("{selected_none:?}").contains("secret-payload"));
}

#[test]
fn candidate_cost_deduplicates_references_but_not_distinct_source_events() {
    let ledger = ledger(&[b"same", b"same", b"longer"]);
    let first = ledger.events()[0].id();
    let second = ledger.events()[1].id();
    let cost = candidate_cost(&ledger, &[first, first, second, second]).unwrap();

    assert_eq!(cost.event_count(), 2);
    assert_eq!(cost.unique_source_bytes(), 8);
    let unknown = evidentrail_core::EventId::from_bytes([99; 32]);
    let error = candidate_cost(&ledger, &[unknown, unknown]).unwrap_err();
    assert_eq!(error, MetricError::UnknownCandidateEvent { count: 1 });
    assert_eq!(
        error.to_string(),
        "EVIDENTRAIL_BENCH_METRIC_UNKNOWN_CANDIDATE_EVENT"
    );

    let result = GrepHeadTail::new(GrepHeadTailConfig::new(3, 3))
        .run(MethodInput::new(&ledger, b"same", ByteBudget::new(64)))
        .unwrap();
    assert_eq!(result.accounting().candidate_cost().event_count(), 3);
    assert_eq!(
        result.accounting().candidate_cost().unique_source_bytes(),
        b"samesamelonger".len()
    );
}

#[test]
fn quota_hybrid_protects_each_view_before_redistributing_capacity() {
    let ledger = ledger(&[b"head", b"query-hit", b"middle", b"tail"]);
    let method = QuotaHybrid::new(QuotaHybridConfig::new(
        b"query-hit".len(),
        b"head".len(),
        b"tail".len(),
        0,
        1,
        1,
        0,
    ));
    let budget = ByteBudget::new(b"headquery-hittail".len());
    let result = method
        .run(MethodInput::new(&ledger, b"query-hit", budget))
        .unwrap();

    assert_eq!(
        selected_ids(&result),
        vec![
            ledger.events()[0].id(),
            ledger.events()[1].id(),
            ledger.events()[3].id()
        ]
    );
    assert!(
        result.selected()[0]
            .reasons()
            .contains(&SelectionReason::HeadSentinel)
    );
    assert!(
        result.selected()[2]
            .reasons()
            .contains(&SelectionReason::TailSentinel)
    );
}

#[test]
fn quota_hybrid_redistributes_unused_quota_in_stable_round_robin_order() {
    let ledger = ledger(&[b"H", b"query", b"C", b"T"]);
    let method = QuotaHybrid::new(QuotaHybridConfig::new(6, 0, 0, 0, 2, 1, 1));
    let first = method
        .run(MethodInput::new(&ledger, b"query", ByteBudget::new(8)))
        .unwrap();
    let second = method
        .run(MethodInput::new(&ledger, b"query", ByteBudget::new(8)))
        .unwrap();

    assert_eq!(first, second);
    assert_eq!(first.accounting().candidate_cost().event_count(), 4);
    assert_eq!(
        first.accounting().candidate_cost().unique_source_bytes(),
        b"HqueryCT".len()
    );
    assert_eq!(
        selected_ids(&first),
        vec![
            ledger.events()[0].id(),
            ledger.events()[1].id(),
            ledger.events()[2].id(),
            ledger.events()[3].id()
        ]
    );
}

#[test]
fn quota_hybrid_uses_evenly_spaced_whole_event_sentinels_and_raw_bytes() {
    let invalid = vec![0xff];
    let ledger = ledger_with_id(
        7,
        vec![
            invalid.clone(),
            b"1".to_vec(),
            b"2".to_vec(),
            b"3".to_vec(),
            b"4".to_vec(),
        ],
    );
    let result = QuotaHybrid::new(QuotaHybridConfig::new(0, 0, 0, 3, 0, 0, 3))
        .run(MethodInput::new(&ledger, b"\xff", ByteBudget::new(3)))
        .unwrap();

    assert_eq!(
        selected_ids(&result),
        vec![
            ledger.events()[0].id(),
            ledger.events()[2].id(),
            ledger.events()[4].id()
        ]
    );
    assert_eq!(
        ledger.exact_bytes(result.selected()[0].event_id()).unwrap(),
        invalid
    );
    assert!(
        result
            .selected()
            .iter()
            .all(|event| { event.reasons().contains(&SelectionReason::CoverageSentinel) })
    );
}

#[test]
fn quota_hybrid_rejects_over_reserved_budget_without_content() {
    let ledger = ledger(&[b"secret"]);
    let error = QuotaHybrid::new(QuotaHybridConfig::new(2, 2, 2, 2, 1, 1, 1))
        .run(MethodInput::new(
            &ledger,
            b"secret-query",
            ByteBudget::new(7),
        ))
        .unwrap_err();

    assert_eq!(error, MethodError::ReservedQuotaExceedsBudget);
    assert_eq!(
        error.to_string(),
        "EVIDENTRAIL_BENCH_RESERVED_QUOTA_EXCEEDS_BUDGET"
    );
    assert!(!format!("{error:?}").contains("secret"));
}
