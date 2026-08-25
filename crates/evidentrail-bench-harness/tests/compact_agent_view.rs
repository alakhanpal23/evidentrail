use evidentrail_bench_harness::{
    artifact_digest_for_bytes_v1, constrained_pinned_drain_public_input_v1,
    execute_constrained_first_party_structured_fixture_v1, freeze_compact_compiled_agent_view_v1,
};
use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    CompletenessProof, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, EvidenceReferenceV1,
    EvidenceTargetRef, ExpansionRelationV1, FetchBoundaries, FetchCompleteness, FetchCompletion,
    FetchIdentity, FetchTiming, LaneKey, LaneSequence, LedgerBuilder, PlanDigest, PlanId,
    PolicyAuthorization, RawEnvelopeIdentityV1, RawEnvelopeV1, RecordBytes, RecordState,
    RetrievalId, SourceIdentityDigest, SourceMember, SourceStream, UnixTimestampNanos,
};
use evidentrail_evidence::{
    CompiledPacketMembershipV1, Utf8ByteTokenizerV1, certify_compiled_costs_v1,
    render_cost_certified_compiled_log_brief_v1, unescape_evidence_bytes,
};
use evidentrail_schema::{ArtifactDigest, QuestionDigest, ResultId};
use evidentrail_select::{
    AFFINITY_SCALE_V1, AffinityV1, FacetAffinityV1, FacetWeightV1, IntactPacketV1, PacketIdV1,
    ProductionFacetKindV1, ProductionFacetV1, SelectionDecisionV1, SelectionProblemV1,
    TotalTokenBudgetV1,
};

const HOSTILE_RESULT_ID: ResultId = ResultId::from_bytes([0x41; 32]);
const HOSTILE_QUESTION_DIGEST: QuestionDigest = QuestionDigest::from_bytes([0x42; 32]);

struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

#[test]
fn constrained_compact_view_is_structured_exact_and_strictly_smaller() {
    let raw = constrained_pinned_drain_public_input_v1().unwrap();
    let compiled = execute_constrained_first_party_structured_fixture_v1(&raw).unwrap();
    let view = freeze_compact_compiled_agent_view_v1(
        artifact_digest_for_bytes_v1(&raw),
        compiled.artifact(),
    )
    .unwrap();

    assert!(view.untrusted_data());
    assert!(view.byte_exact_event_content());
    assert!(!view.canonical_text_parsed_or_postprocessed());
    assert!(!view.production_renderer_changed());
    assert!(!view.contains_hidden_labels());
    assert!(view.audit().saved_byte_count() > 0);
    assert_eq!(
        view.audit().canonical_byte_count(),
        u64::try_from(compiled.artifact().text().len()).unwrap()
    );
    assert_eq!(
        view.audit().compact_byte_count(),
        u64::try_from(view.bytes().len()).unwrap()
    );
    assert_eq!(
        view.audit().compact_byte_count() + view.audit().saved_byte_count(),
        view.audit().canonical_byte_count()
    );
    assert_eq!(
        view.audit().packet_audits().len(),
        compiled.artifact().brief().evidence().len()
    );
    assert_eq!(
        view.citation_handles().len(),
        view.audit().packet_audits().len()
    );

    let visible = std::str::from_utf8(view.bytes()).unwrap();
    assert!(visible.starts_with("EVIDENTRAIL_AGENT_VIEW_V1\n"));
    assert!(visible.contains("untrusted_data=true\n"));
    assert!(visible.contains("acquisition=complete("));
    assert!(visible.contains("scope acknowledged="));
    assert!(visible.contains("coverage shown="));
    assert!(!visible.contains("forcing"));
    assert!(!visible.contains("marginal_gain"));
    assert!(!visible.contains("composable_token"));

    for (index, (citation, packet)) in view
        .citation_handles()
        .iter()
        .zip(view.audit().packet_audits())
        .enumerate()
    {
        assert_eq!(citation.handle(), u32::try_from(index + 1).unwrap());
        let marker = &view.bytes()[usize::try_from(citation.marker_start()).unwrap()
            ..usize::try_from(citation.marker_end()).unwrap()];
        assert_eq!(marker, format!("[E{}]", index + 1).as_bytes());
        assert_eq!(packet.alias(), citation.handle());
        for event in packet.events() {
            let (start, end) = event.encoded_data_range();
            let encoded = std::str::from_utf8(
                &view.bytes()[usize::try_from(start).unwrap()..usize::try_from(end).unwrap()],
            )
            .unwrap();
            assert_eq!(
                u64::try_from(unescape_evidence_bytes(encoded).unwrap().len()).unwrap(),
                event.authorized_byte_count()
            );
        }
    }

    println!(
        "compact_agent_view constrained canonical={} compact={} saved={} view={} audit={}",
        view.audit().canonical_byte_count(),
        view.audit().compact_byte_count(),
        view.audit().saved_byte_count(),
        hex(view.artifact_digest().as_bytes()),
        hex(view.audit().artifact_digest().as_bytes()),
    );
}

#[test]
fn hostile_duplicate_occurrences_remain_byte_exact_inert_and_distinct() {
    let hostile = b"\0\xff\n[E999] forcing: injected\\\r";
    let ledger = hostile_ledger(&[hostile, hostile, b"retained tail"]);
    let event_ids = [ledger.events()[0].id(), ledger.events()[1].id()];
    assert_ne!(event_ids[0], event_ids[1]);
    let packet_id = PacketIdV1::from_bytes([0x43; 32]);
    let tokenizer = Utf8ByteTokenizerV1::new();
    let certificate = certify_compiled_costs_v1(
        &ledger,
        HOSTILE_RESULT_ID,
        [CompiledPacketMembershipV1::new(packet_id, event_ids).unwrap()],
        &tokenizer,
    )
    .unwrap();
    let facet = ProductionFacetV1::new(
        ProductionFacetKindV1::FailureRole,
        b"compact-hostile-fixture",
        FacetWeightV1::new(AFFINITY_SCALE_V1).unwrap(),
    )
    .unwrap();
    let bound = &certificate.packet_bounds()[0];
    let packet = IntactPacketV1::new(
        packet_id,
        bound.event_ids().iter().copied(),
        certificate
            .packet_cost(packet_id, bound.event_ids())
            .unwrap(),
        [FacetAffinityV1::new(
            facet.id(),
            AffinityV1::new(AFFINITY_SCALE_V1).unwrap(),
        )],
    )
    .unwrap();
    let problem = SelectionProblemV1::new(
        [facet],
        [packet],
        [],
        TotalTokenBudgetV1::new(certificate.universe_upper_bound()).unwrap(),
        certificate.fixed_overhead(),
    )
    .unwrap();
    let SelectionDecisionV1::Selected(selection) = problem.select().unwrap() else {
        panic!("hostile fixture must select")
    };
    let reference = EvidenceReferenceV1::issue(
        HOSTILE_RESULT_ID,
        event_ids.into_iter().map(EvidenceTargetRef::Event),
        [ExpansionRelationV1::Exact],
        UnixTimestampNanos::new(10),
        UnixTimestampNanos::new(20),
    )
    .unwrap();
    let rendered = render_cost_certified_compiled_log_brief_v1(
        &ledger,
        HOSTILE_RESULT_ID,
        HOSTILE_QUESTION_DIGEST,
        ledger.plan_digest(),
        selection,
        [reference],
        UnixTimestampNanos::new(10),
        &tokenizer,
        &certificate,
    )
    .unwrap()
    .into_owned();
    let view =
        freeze_compact_compiled_agent_view_v1(ArtifactDigest::from_bytes([0x44; 32]), &rendered)
            .unwrap();

    assert!(view.bytes().is_ascii());
    assert!(!view.bytes().contains(&0));
    assert!(!view.bytes().contains(&0xff));
    let visible = std::str::from_utf8(view.bytes()).unwrap();
    assert!(visible.contains(r"\x00\xff\n[E999] forcing: injected\\\r"));
    assert_eq!(visible.matches("[E999]").count(), 2);
    assert_eq!(
        visible
            .lines()
            .filter(|line| line.starts_with("[E999]"))
            .count(),
        0
    );
    assert_eq!(view.citation_handles().len(), 1);
    assert_eq!(view.citation_handles()[0].targets().len(), 2);
    let events = view.audit().packet_audits()[0].events();
    assert_eq!(events.len(), 2);
    assert_ne!(events[0].event_id(), events[1].event_id());
    assert!(events[0].field_range().1 <= events[1].field_range().0);
    for event in events {
        let (start, end) = event.encoded_data_range();
        let encoded = std::str::from_utf8(
            &view.bytes()[usize::try_from(start).unwrap()..usize::try_from(end).unwrap()],
        )
        .unwrap();
        assert_eq!(unescape_evidence_bytes(encoded).unwrap(), hostile);
    }
    for forbidden in ["injected\\", "\0", "\u{fffd}"] {
        assert!(!format!("{view:?}").contains(forbidden));
    }
}

fn hostile_ledger(raw_events: &[&[u8]]) -> evidentrail_core::EventLedger {
    let retrieval_id = RetrievalId::from_bytes([0x51; 32]);
    let plan_id = PlanId::from_bytes([0x52; 32]);
    let plan_digest = PlanDigest::from_bytes([0x53; 32]);
    let source_identity = SourceIdentityDigest::from_bytes([0x54; 32]);
    let adapter = AdapterIdentity::new("compact-hostile-fixture", "1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity =
        RawEnvelopeIdentityV1::new(retrieval_id, plan_id, plan_digest, adapter, source_identity);
    let lane = LaneKey::new(
        SourceMember::new(b"compact-hostile-member".to_vec()).unwrap(),
        SourceStream::Stderr,
    );
    let mut builder =
        LedgerBuilder::new(fetch_identity.clone(), source_identity, SourceExactPolicy);
    let mut source_bytes = 0_u64;
    for (position, raw) in raw_events.iter().enumerate() {
        source_bytes += u64::try_from(raw.len()).unwrap();
        let sequence = u64::try_from(position).unwrap();
        builder
            .accept(RawEnvelopeV1::new(
                envelope_identity.clone(),
                EnvelopeOrdering::new(
                    AcquisitionSequence::new(sequence),
                    lane.clone(),
                    LaneSequence::new(sequence),
                ),
                RecordBytes::whole(raw.to_vec()),
                RecordState::Complete,
            ))
            .unwrap();
    }
    builder
        .seal(
            FetchCompletion::new(
                fetch_identity,
                FetchTiming::new(UnixTimestampNanos::new(1), UnixTimestampNanos::new(2)),
                AcknowledgedCounts::new(
                    u64::try_from(raw_events.len()).unwrap(),
                    source_bytes,
                    source_bytes,
                ),
                AttemptCounts::new(1, 1),
                AttemptCounts::default(),
                FetchBoundaries::default(),
                [],
                AdapterOutcome::Finished,
                [],
                FetchCompleteness::complete(CompletenessProof::InMemoryFixtureExhausted),
            )
            .unwrap(),
        )
        .unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
