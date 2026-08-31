#[cfg(target_os = "macos")]
use evidentrail_bench::EvidenceTargetV1;
use evidentrail_bench::{
    SyntheticThreeLaneAblationCaseV1, synthetic_three_lane_ablation_corpus_identity_v1,
    synthetic_three_lane_selection_budget_schedule_v1,
};
#[cfg(target_os = "macos")]
use evidentrail_bench_harness::{
    CONSTRAINED_MATCHED_QUESTION_V1, CONSTRAINED_READER_CONTEXT_V1,
    CompactAgentViewAdmissionProposalV1, CompactAgentViewProductionAdmissionEvidenceV1,
    CompactAgentViewReaderMeasurementPairV1, DeterministicFixtureReaderModeV1,
    DeterministicFixtureReaderV1, HarnessLimitsV1, MacOsTimePeakRssObserverV1,
    ReaderCitationHandleV1, ReaderMethodArtifactV1, ReaderPublicInputV1, ReaderResourceCapsV1,
    compare_compact_agent_view_reader_receipts_v1, execute_deterministic_fixture_reader_v1,
    log_brief_compiled_method_descriptor_v1,
};
use evidentrail_bench_harness::{
    CompactAgentViewCaseReductionV1, CompactAgentViewChallengeClassV1,
    CompactAgentViewChallengeCorpusReceiptV1, CompactAgentViewChallengeObservationV1,
    CompactAgentViewCorpusReductionReceiptV1, CompactAgentViewNeedsMoreObservationV1,
    CompactAgentViewProductionCandidateParityV1, artifact_digest_for_bytes_v1,
    canonical_public_case_artifact_v1, constrained_pinned_drain_public_case_v1,
    constrained_pinned_drain_public_input_v1,
    execute_constrained_first_party_structured_fixture_v1, freeze_compact_compiled_agent_view_v1,
};
use evidentrail_compile::{
    PreparedThreeLaneSelectionDecisionV1, ThreeLaneAblationMaskV1,
    ThreeLaneAblationPreparationDecisionV1, prepare_three_lane_ablations_v1,
    select_prepared_three_lane_ablation_v1,
};
use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    BlockAssignment, BlockConfidence, BlockIndex, BlockState, CompletenessProof,
    DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, EventLedger, EvidenceReferenceV1,
    EvidenceTargetRef, ExpansionRelationV1, FetchBoundaries, FetchCompleteness, FetchCompletion,
    FetchIdentity, FetchPartialReason, FetchPartialReasons, FetchTiming, FetchUnknownReason,
    FramingPolicy, LaneKey, LaneSequence, LedgerBuilder, PlanDigest, PlanId, PolicyAuthorization,
    ProviderAttestationScopeDigestV1, ProviderAttestationValueV1, ProviderAttestationsV1,
    ProviderAttestedCorrelationV1, ProviderAttestedRelationKindV1, RawEnvelopeIdentityV1,
    RawEnvelopeV1, RecordBytes, RecordState, RetrievalId, SourceIdentityDigest, SourceMember,
    SourceStream, UnixTimestampNanos,
};
use evidentrail_evidence::{
    CompiledPacketMembershipV1, OwnedRenderedCompiledBriefV1, Utf8ByteTokenizerV1,
    certify_compiled_costs_v1, render_compiled_agent_view_candidate_v1,
    render_cost_certified_compiled_log_brief_v1,
};
use evidentrail_schema::{ArtifactDigest, QuestionDigest, ResultId};
use evidentrail_select::{
    AFFINITY_SCALE_V1, AffinityV1, FacetAffinityV1, FacetWeightV1, IntactPacketV1, PacketIdV1,
    ProductionFacetKindV1, ProductionFacetV1, SelectionDecisionV1, SelectionProblemV1,
    TotalTokenBudgetV1,
};

const RECORD_COUNT: usize = 12;
const STRUCTURAL_CANARY: &str = "CANARY_STRUCTURAL_INJECTION_72f1";
const CHALLENGE_QUESTION_DIGEST: QuestionDigest = QuestionDigest::from_bytes([0xe1; 32]);

struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

#[derive(Clone)]
struct SyntheticRecord {
    raw: Vec<u8>,
    terminator: Vec<u8>,
    stream: SourceStream,
    attestations: ProviderAttestationsV1,
}

impl SyntheticRecord {
    fn ordinary(position: usize) -> Self {
        Self {
            raw: format!("ordinary heartbeat {position:02}").into_bytes(),
            terminator: if position + 1 == RECORD_COUNT {
                Vec::new()
            } else if position % 3 == 0 {
                b"\r\n".to_vec()
            } else {
                b"\n".to_vec()
            },
            stream: SourceStream::Stderr,
            attestations: ProviderAttestationsV1::default(),
        }
    }
}

#[test]
fn frozen_six_case_corpus_has_strict_per_case_and_aggregate_reduction() {
    let (receipt, parities) = measure_frozen_corpus_with_production_parity();
    assert_eq!(receipt.expected_case_count(), 6);
    assert_eq!(receipt.rendered_case_count(), 5);
    assert_eq!(receipt.needs_more_case_count(), 1);
    assert_eq!(receipt.cases().len(), 5);
    assert!(
        receipt
            .cases()
            .iter()
            .all(|case| case.saved_byte_count() > 0)
    );
    assert_eq!(receipt.canonical_byte_count(), 11_530);
    assert_eq!(receipt.compact_byte_count(), 4_793);
    assert_eq!(receipt.saved_byte_count(), 6_737);
    assert_eq!(receipt.reduction_micros(), 584_301);
    assert_eq!(receipt.minimum_case_saved_bytes(), 797);
    assert_eq!(
        hex(receipt.artifact_digest().as_bytes()),
        "7019aa49bd165c57874e035a6811894b161a3b3493271e540863dbfd7fa1ec18"
    );
    assert!(!receipt.contains_hidden_labels());
    assert_eq!(parities.len(), 5);
    assert!(
        parities
            .iter()
            .all(|parity| parity.exact_text_alias_range_and_count_parity())
    );

    let mut reversed = receipt.cases().to_vec();
    reversed.reverse();
    let reordered = CompactAgentViewCorpusReductionReceiptV1::try_new(
        receipt.corpus_artifact_digest(),
        receipt.budget_schedule_artifact_digest(),
        receipt.expected_case_count(),
        receipt.needs_more_case_count(),
        reversed,
    )
    .unwrap();
    assert_eq!(reordered, receipt);

    println!(
        "compact_agent_view corpus canonical={} compact={} saved={} reduction_micros={} min_case_saved={} rendered={} needs_more={} production_parity_cases={} receipt={}",
        receipt.canonical_byte_count(),
        receipt.compact_byte_count(),
        receipt.saved_byte_count(),
        receipt.reduction_micros(),
        receipt.minimum_case_saved_bytes(),
        receipt.rendered_case_count(),
        receipt.needs_more_case_count(),
        parities.len(),
        hex(receipt.artifact_digest().as_bytes()),
    );
}

#[cfg(target_os = "macos")]
#[test]
fn deterministic_reader_preserves_answer_and_exact_citation_semantics() {
    let raw = constrained_pinned_drain_public_input_v1().unwrap();
    let compiled = execute_constrained_first_party_structured_fixture_v1(&raw).unwrap();
    let source_provenance = artifact_digest_for_bytes_v1(&raw);
    let view =
        freeze_compact_compiled_agent_view_v1(source_provenance, compiled.artifact()).unwrap();
    let public_case = constrained_pinned_drain_public_case_v1().unwrap();
    let public_case_artifact_digest = canonical_public_case_artifact_v1(&public_case)
        .unwrap()
        .artifact_digest();
    let canonical_bytes = compiled.artifact().text().as_bytes();
    let canonical_method = ReaderMethodArtifactV1::try_new(
        public_case_artifact_digest,
        log_brief_compiled_method_descriptor_v1(),
        source_provenance,
        artifact_digest_for_bytes_v1(canonical_bytes),
        canonical_bytes.to_vec(),
        canonical_citations(compiled.artifact()),
    )
    .unwrap();
    let context_artifact_digest = artifact_digest_for_bytes_v1(CONSTRAINED_READER_CONTEXT_V1);
    let canonical_input = ReaderPublicInputV1::try_new(
        public_case.clone(),
        CONSTRAINED_MATCHED_QUESTION_V1.to_vec(),
        context_artifact_digest,
        CONSTRAINED_READER_CONTEXT_V1.to_vec(),
        canonical_method,
    )
    .unwrap();
    let compact_input = ReaderPublicInputV1::try_new(
        public_case,
        CONSTRAINED_MATCHED_QUESTION_V1.to_vec(),
        context_artifact_digest,
        CONSTRAINED_READER_CONTEXT_V1.to_vec(),
        view.reader_method_artifact(public_case_artifact_digest)
            .unwrap(),
    )
    .unwrap();
    let reader = DeterministicFixtureReaderV1::try_new(
        std::path::PathBuf::from(env!("CARGO_BIN_EXE_evidentrail-bench-harness-helper")),
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        DeterministicFixtureReaderModeV1::Correct,
    )
    .unwrap();
    let observer = MacOsTimePeakRssObserverV1::try_system_v1().unwrap();
    let caps = ReaderResourceCapsV1::try_new(
        HarnessLimitsV1::try_new(8 * 1024 * 1024, 1024 * 1024, 64 * 1024, 10_000_000_000).unwrap(),
        8 * 1024 * 1024,
        1024 * 1024,
        2 * 1024 * 1024 * 1024,
        1,
    )
    .unwrap();
    let canonical_receipt =
        execute_deterministic_fixture_reader_v1(&observer, &reader, &canonical_input, caps)
            .unwrap();
    let compact_receipt =
        execute_deterministic_fixture_reader_v1(&observer, &reader, &compact_input, caps).unwrap();
    let preservation =
        compare_compact_agent_view_reader_receipts_v1(&canonical_receipt, &compact_receipt, &view)
            .unwrap();
    assert!(preservation.answers_preserved());
    assert!(preservation.citation_semantics_preserved());
    assert_eq!(
        canonical_receipt.answer_bytes(),
        compact_receipt.answer_bytes()
    );
    assert_eq!(preservation.cited_handles(), &[1, 2]);
    assert!(!preservation.hosted_reader_claimed());

    let (corpus, mut production_parities) = measure_frozen_corpus_with_production_parity();
    let proposal = CompactAgentViewAdmissionProposalV1::try_new(&preservation, &corpus).unwrap();
    assert_eq!(
        proposal.status().code(),
        "eligible_for_controlled_admission_review_not_admitted"
    );
    assert!(!proposal.production_change_authorized());
    assert!(!proposal.hosted_reader_validated());

    let (challenge_corpus, challenge_parities) =
        measure_admission_challenge_corpus(compiled.artifact(), &view, public_case_artifact_digest);
    production_parities.extend(challenge_parities);
    let measurement_pair = CompactAgentViewReaderMeasurementPairV1::try_new(
        &preservation,
        &view,
        &canonical_receipt,
        &compact_receipt,
    )
    .unwrap();
    let (_, foreign_view) = challenge_render_and_view(0xda, &[b"foreign view binding"]);
    let foreign_error = CompactAgentViewReaderMeasurementPairV1::try_new(
        &preservation,
        &foreign_view,
        &canonical_receipt,
        &compact_receipt,
    )
    .unwrap_err();
    assert_eq!(
        foreign_error.code(),
        "EVIDENTRAIL_BENCH_COMPACT_ADMISSION_COMPACT_VIEW_FAILURE"
    );
    assert!(!format!("{foreign_error:?}").contains("foreign view binding"));

    let mut incomplete_parities = production_parities.clone();
    incomplete_parities.pop();
    let incomplete_error = CompactAgentViewProductionAdmissionEvidenceV1::try_new(
        &corpus,
        &challenge_corpus,
        incomplete_parities,
        vec![measurement_pair],
    )
    .unwrap_err();
    assert_eq!(
        incomplete_error.code(),
        "EVIDENTRAIL_BENCH_COMPACT_ADMISSION_EVIDENCE_INCOMPLETE"
    );
    let admission = CompactAgentViewProductionAdmissionEvidenceV1::try_new(
        &corpus,
        &challenge_corpus,
        production_parities,
        vec![measurement_pair],
    )
    .unwrap();
    assert_eq!(admission.total_expected_case_count(), 11);
    assert_eq!(admission.total_rendered_case_count(), 9);
    assert_eq!(admission.total_needs_more_case_count(), 2);
    assert_eq!(admission.production_candidate_parities().len(), 9);
    assert_eq!(admission.measurement_pairs().len(), 1);
    assert!(admission.canonical_observed_wall_time_nanos() > 0);
    assert!(admission.compact_observed_wall_time_nanos() > 0);
    assert!(admission.maximum_canonical_direct_process_peak_rss_bytes() > 0);
    assert!(admission.maximum_compact_direct_process_peak_rss_bytes() > 0);
    assert!(!admission.production_behavior_changed());
    assert!(!admission.production_admitted());
    assert!(!admission.hosted_reader_used());
    assert!(!admission.scalar_performance_or_quality_winner_available());
    assert!(!admission.measurements_independently_attested());
    assert!(admission.direct_process_peak_rss_only());
    assert!(!admission.contains_hidden_labels());

    println!(
        "compact_agent_view admission preservation={} answer={} cited_handles={} proposal={} evidence={} total_cases={} rendered={} needs_more={} parity_cases={} canonical_bytes={} compact_bytes={} saved_bytes={} canonical_wall_nanos={} compact_wall_nanos={} canonical_direct_peak_rss={} compact_direct_peak_rss={} production_admitted=false hosted=false winner=false",
        hex(preservation.artifact_digest().as_bytes()),
        hex(preservation.answer_artifact_digest().as_bytes()),
        preservation.cited_handles().len(),
        hex(proposal.artifact_digest().as_bytes()),
        hex(admission.artifact_digest().as_bytes()),
        admission.total_expected_case_count(),
        admission.total_rendered_case_count(),
        admission.total_needs_more_case_count(),
        admission.production_candidate_parities().len(),
        admission.canonical_byte_count(),
        admission.compact_byte_count(),
        admission.saved_byte_count(),
        admission.canonical_observed_wall_time_nanos(),
        admission.compact_observed_wall_time_nanos(),
        admission.maximum_canonical_direct_process_peak_rss_bytes(),
        admission.maximum_compact_direct_process_peak_rss_bytes(),
    );
}

#[test]
fn bounded_admission_challenges_cover_bytes_citations_parity_and_needs_more() {
    let raw = constrained_pinned_drain_public_input_v1().unwrap();
    let compiled = execute_constrained_first_party_structured_fixture_v1(&raw).unwrap();
    let view = freeze_compact_compiled_agent_view_v1(
        artifact_digest_for_bytes_v1(&raw),
        compiled.artifact(),
    )
    .unwrap();
    let case = constrained_pinned_drain_public_case_v1().unwrap();
    let case_digest = canonical_public_case_artifact_v1(&case)
        .unwrap()
        .artifact_digest();
    let (receipt, parities) =
        measure_admission_challenge_corpus(compiled.artifact(), &view, case_digest);
    assert_eq!(receipt.cases().len(), 4);
    assert!(!receipt.needs_more().compact_view_emitted());
    assert_eq!(parities.len(), 4);
    assert_eq!(receipt.canonical_byte_count(), 16_815);
    assert_eq!(receipt.compact_byte_count(), 12_179);
    assert_eq!(receipt.saved_byte_count(), 4_636);
    assert_eq!(
        receipt.compact_byte_count() + receipt.saved_byte_count(),
        receipt.canonical_byte_count()
    );
    assert_eq!(receipt.citation_count(), 16);
    assert_eq!(receipt.event_count(), 23);
    assert_eq!(receipt.decoded_event_byte_count(), 9_025);
    assert_eq!(receipt.reduction_micros(), 275_706);
    assert_eq!(
        hex(receipt.artifact_digest().as_bytes()),
        "ac2ee0013b65d0b862f5b270a512912fbdde9cdd93577abd530e754e3f2976d0"
    );
    assert!(!receipt.contains_hidden_labels());
    assert!(
        parities
            .iter()
            .all(|parity| parity.exact_text_alias_range_and_count_parity())
    );
    let debug = format!("{receipt:?}");
    for forbidden in [
        "EVIDENTRAIL_AGENT_VIEW_V1",
        "Traceback",
        "[E999]",
        "repeat-me",
    ] {
        assert!(!debug.contains(forbidden));
    }

    let (ordinary, ordinary_view) = challenge_render_and_view(0xd8, &[b"ordinary unique"]);
    let error = CompactAgentViewChallengeObservationV1::try_new(
        ArtifactDigest::from_bytes([0xd9; 32]),
        CompactAgentViewChallengeClassV1::DuplicateOccurrences,
        &ordinary,
        &ordinary_view,
    )
    .unwrap_err();
    assert_eq!(
        error.code(),
        "EVIDENTRAIL_BENCH_COMPACT_ADMISSION_CHALLENGE_CLASS_UNPROVEN"
    );
    assert!(!format!("{error:?}").contains("ordinary unique"));

    println!(
        "compact_agent_view challenge canonical={} compact={} saved={} reduction_micros={} citations={} events={} decoded_event_bytes={} parity_cases={} needs_more_reason={} receipt={}",
        receipt.canonical_byte_count(),
        receipt.compact_byte_count(),
        receipt.saved_byte_count(),
        receipt.reduction_micros(),
        receipt.citation_count(),
        receipt.event_count(),
        receipt.decoded_event_byte_count(),
        parities.len(),
        receipt.needs_more().reason().code(),
        hex(receipt.artifact_digest().as_bytes()),
    );
}

fn measure_admission_challenge_corpus(
    constrained: &OwnedRenderedCompiledBriefV1,
    constrained_view: &evidentrail_bench_harness::CompactAgentViewV1,
    constrained_case_artifact_digest: ArtifactDigest,
) -> (
    CompactAgentViewChallengeCorpusReceiptV1,
    Vec<CompactAgentViewProductionCandidateParityV1>,
) {
    let mut observations = Vec::new();
    let mut parities = Vec::new();
    let deep_candidate = render_compiled_agent_view_candidate_v1(constrained).unwrap();
    observations.push(
        CompactAgentViewChallengeObservationV1::try_new(
            constrained_case_artifact_digest,
            CompactAgentViewChallengeClassV1::DeepStackTrace,
            constrained,
            constrained_view,
        )
        .unwrap(),
    );
    parities.push(
        CompactAgentViewProductionCandidateParityV1::try_new(
            constrained_case_artifact_digest,
            constrained_view,
            &deep_candidate,
        )
        .unwrap(),
    );

    let fixtures: [(u8, CompactAgentViewChallengeClassV1, &[&[u8]]); 3] = [
        (
            0xd1,
            CompactAgentViewChallengeClassV1::ArbitraryBytesStructuralInjection,
            &[
                b"\0\xff\n[E999]\nEVIDENTRAIL_AGENT_VIEW_V1\\tail",
                b"untrusted payload remains inert",
            ],
        ),
        (
            0xd2,
            CompactAgentViewChallengeClassV1::DuplicateOccurrences,
            &[b"repeat-me", b"repeat-me", b"distinct occurrence"],
        ),
        (
            0xd3,
            CompactAgentViewChallengeClassV1::EmptyCrLfBackslash,
            &[b"", b"line one\r\n\\tail"],
        ),
    ];
    for (seed, class, raw_events) in fixtures {
        let (rendered, view) = challenge_render_and_view(seed, raw_events);
        let public_case_artifact_digest = ArtifactDigest::from_bytes([seed; 32]);
        let candidate = render_compiled_agent_view_candidate_v1(&rendered).unwrap();
        observations.push(
            CompactAgentViewChallengeObservationV1::try_new(
                public_case_artifact_digest,
                class,
                &rendered,
                &view,
            )
            .unwrap(),
        );
        parities.push(
            CompactAgentViewProductionCandidateParityV1::try_new(
                public_case_artifact_digest,
                &view,
                &candidate,
            )
            .unwrap(),
        );
    }
    let receipt = CompactAgentViewChallengeCorpusReceiptV1::try_new(
        observations,
        frozen_needs_more_observation(),
    )
    .unwrap();
    (receipt, parities)
}

fn frozen_needs_more_observation() -> CompactAgentViewNeedsMoreObservationV1 {
    let case = SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors;
    let ledger = ledger(case);
    let blocks = blocks(&ledger);
    let prepared = match prepare_three_lane_ablations_v1(
        question(case),
        &ledger,
        &blocks,
        ResultId::from_bytes([170 + u8::try_from(case_position(case)).unwrap(); 32]),
        &Utf8ByteTokenizerV1::new(),
    )
    .unwrap()
    {
        ThreeLaneAblationPreparationDecisionV1::Prepared(prepared) => prepared,
        ThreeLaneAblationPreparationDecisionV1::NeedsMore(residual) => {
            panic!("challenge needs-more preparation must succeed: {residual:?}")
        }
    };
    let budget = synthetic_three_lane_selection_budget_schedule_v1().budget(case);
    match select_prepared_three_lane_ablation_v1(
        &ledger,
        prepared.configuration(ThreeLaneAblationMaskV1::Full),
        budget,
        &Utf8ByteTokenizerV1::new(),
    )
    .unwrap()
    {
        PreparedThreeLaneSelectionDecisionV1::NeedsMore(needs_more) => {
            CompactAgentViewNeedsMoreObservationV1::from_prepared(
                case.identity_digest(),
                budget,
                &needs_more,
            )
            .unwrap()
        }
        PreparedThreeLaneSelectionDecisionV1::Selected(_) => {
            panic!("frozen partial challenge must remain needs-more")
        }
    }
}

fn challenge_render_and_view(
    seed: u8,
    raw_events: &[&[u8]],
) -> (
    OwnedRenderedCompiledBriefV1,
    evidentrail_bench_harness::CompactAgentViewV1,
) {
    let ledger = challenge_ledger(seed, raw_events);
    let event_ids = ledger
        .events()
        .iter()
        .take(raw_events.len())
        .map(|event| event.id())
        .collect::<Vec<_>>();
    let result_id = ResultId::from_bytes([seed.wrapping_add(1); 32]);
    let packet_id = PacketIdV1::from_bytes([seed.wrapping_add(2); 32]);
    let tokenizer = Utf8ByteTokenizerV1::new();
    let certificate = certify_compiled_costs_v1(
        &ledger,
        result_id,
        [CompiledPacketMembershipV1::new(packet_id, event_ids.clone()).unwrap()],
        &tokenizer,
    )
    .unwrap();
    let facet_identity = [b"compact-admission-challenge-".as_slice(), &[seed]].concat();
    let facet = ProductionFacetV1::new(
        ProductionFacetKindV1::FailureRole,
        &facet_identity,
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
        panic!("challenge fixture must select")
    };
    let reference = EvidenceReferenceV1::issue(
        result_id,
        event_ids.iter().copied().map(EvidenceTargetRef::Event),
        [ExpansionRelationV1::Exact],
        UnixTimestampNanos::new(10),
        UnixTimestampNanos::new(20),
    )
    .unwrap();
    let rendered = render_cost_certified_compiled_log_brief_v1(
        &ledger,
        result_id,
        CHALLENGE_QUESTION_DIGEST,
        ledger.plan_digest(),
        selection,
        [reference],
        UnixTimestampNanos::new(10),
        &tokenizer,
        &certificate,
    )
    .unwrap()
    .into_owned();
    let view = freeze_compact_compiled_agent_view_v1(
        ArtifactDigest::from_bytes([seed.wrapping_add(3); 32]),
        &rendered,
    )
    .unwrap();
    (rendered, view)
}

fn challenge_ledger(seed: u8, raw_events: &[&[u8]]) -> EventLedger {
    let retrieval_id = RetrievalId::from_bytes([seed.wrapping_add(10); 32]);
    let plan_id = PlanId::from_bytes([seed.wrapping_add(11); 32]);
    let plan_digest = PlanDigest::from_bytes([seed.wrapping_add(12); 32]);
    let source_identity = SourceIdentityDigest::from_bytes([seed.wrapping_add(13); 32]);
    let adapter = AdapterIdentity::new("compact-admission-challenge", "1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity =
        RawEnvelopeIdentityV1::new(retrieval_id, plan_id, plan_digest, adapter, source_identity);
    let lane = LaneKey::new(SourceMember::new(vec![seed]).unwrap(), SourceStream::Stderr);
    let mut builder =
        LedgerBuilder::new(fetch_identity.clone(), source_identity, SourceExactPolicy);
    let mut source_bytes = 0_u64;
    let retained_raw = b"retained raw admission control".as_slice();
    for (position, raw) in raw_events
        .iter()
        .copied()
        .chain(std::iter::once(retained_raw))
        .enumerate()
    {
        let sequence = u64::try_from(position).unwrap();
        source_bytes += u64::try_from(raw.len()).unwrap();
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
                    u64::try_from(raw_events.len().checked_add(1).unwrap()).unwrap(),
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

fn measure_frozen_corpus_with_production_parity() -> (
    CompactAgentViewCorpusReductionReceiptV1,
    Vec<CompactAgentViewProductionCandidateParityV1>,
) {
    let schedule = synthetic_three_lane_selection_budget_schedule_v1();
    let mut reductions = Vec::new();
    let mut parities = Vec::new();
    let mut needs_more = 0_u64;
    for case in SyntheticThreeLaneAblationCaseV1::ALL {
        let ledger = ledger(case);
        let blocks = blocks(&ledger);
        let prepared = match prepare_three_lane_ablations_v1(
            question(case),
            &ledger,
            &blocks,
            ResultId::from_bytes([170 + u8::try_from(case_position(case)).unwrap(); 32]),
            &Utf8ByteTokenizerV1::new(),
        )
        .unwrap()
        {
            ThreeLaneAblationPreparationDecisionV1::Prepared(prepared) => prepared,
            ThreeLaneAblationPreparationDecisionV1::NeedsMore(residual) => {
                panic!("frozen corpus preparation must succeed: {residual:?}")
            }
        };
        let configured = prepared.configuration(ThreeLaneAblationMaskV1::Full);
        let decision = select_prepared_three_lane_ablation_v1(
            &ledger,
            configured,
            schedule.budget(case),
            &Utf8ByteTokenizerV1::new(),
        )
        .unwrap();
        let selected = match decision {
            PreparedThreeLaneSelectionDecisionV1::Selected(selected) => selected,
            PreparedThreeLaneSelectionDecisionV1::NeedsMore(_) => {
                needs_more += 1;
                continue;
            }
        };
        let selection = selected.selection().clone();
        let references = selection
            .packets()
            .iter()
            .map(|packet| {
                EvidenceReferenceV1::issue(
                    selected.result_id(),
                    packet
                        .packet()
                        .event_ids()
                        .iter()
                        .copied()
                        .map(EvidenceTargetRef::Event),
                    [ExpansionRelationV1::Exact],
                    UnixTimestampNanos::new(10),
                    UnixTimestampNanos::new(20),
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let rendered = render_cost_certified_compiled_log_brief_v1(
            &ledger,
            selected.result_id(),
            selected.question_digest(),
            ledger.plan_digest(),
            selection,
            references,
            UnixTimestampNanos::new(10),
            &Utf8ByteTokenizerV1::new(),
            selected.certification(),
        )
        .unwrap()
        .into_owned();
        let view =
            freeze_compact_compiled_agent_view_v1(selected.proposal_receipt().digest(), &rendered)
                .unwrap();
        let production_candidate = render_compiled_agent_view_candidate_v1(&rendered).unwrap();
        parities.push(
            CompactAgentViewProductionCandidateParityV1::try_new(
                case.identity_digest(),
                &view,
                &production_candidate,
            )
            .unwrap(),
        );
        reductions.push(CompactAgentViewCaseReductionV1::from_view(
            case.identity_digest(),
            &view,
        ));
    }

    let receipt = CompactAgentViewCorpusReductionReceiptV1::try_new(
        synthetic_three_lane_ablation_corpus_identity_v1(),
        ArtifactDigest::from_bytes(*schedule.digest().as_bytes()),
        u64::try_from(SyntheticThreeLaneAblationCaseV1::ALL.len()).unwrap(),
        needs_more,
        reductions,
    )
    .unwrap();
    (receipt, parities)
}

#[cfg(target_os = "macos")]
fn canonical_citations(
    rendered: &evidentrail_evidence::OwnedRenderedCompiledBriefV1,
) -> Vec<ReaderCitationHandleV1> {
    rendered
        .brief()
        .evidence()
        .iter()
        .enumerate()
        .map(|(index, packet)| {
            let handle = u32::try_from(index + 1).unwrap();
            let marker = format!("[E{handle}]");
            let starts = rendered
                .text()
                .as_bytes()
                .windows(marker.len())
                .enumerate()
                .filter_map(|(position, bytes)| (bytes == marker.as_bytes()).then_some(position))
                .collect::<Vec<_>>();
            assert_eq!(starts.len(), 1);
            ReaderCitationHandleV1::try_new(
                handle,
                packet
                    .events()
                    .iter()
                    .map(|event| EvidenceTargetV1::Event(event.event_id()))
                    .collect(),
                u64::try_from(starts[0]).unwrap(),
                u64::try_from(starts[0] + marker.len()).unwrap(),
            )
            .unwrap()
        })
        .collect()
}

fn case_position(case: SyntheticThreeLaneAblationCaseV1) -> usize {
    SyntheticThreeLaneAblationCaseV1::ALL
        .iter()
        .position(|candidate| *candidate == case)
        .unwrap()
}

fn question(case: SyntheticThreeLaneAblationCaseV1) -> &'static [u8] {
    match case {
        SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead => {
            b"diagnose 123e4567-e89b-12d3-a456-426614174000 CANARY_QUESTION_SHOULD_NOT_LEAK_920d"
        }
        SyntheticThreeLaneAblationCaseV1::MixedJointInterleaved => {
            b"diagnose 123e4567-e89b-12d3-a456-426614174999"
        }
        _ => b"",
    }
}

fn completeness(case: SyntheticThreeLaneAblationCaseV1) -> FetchCompleteness {
    match case {
        SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors => FetchCompleteness::partial(
            FetchPartialReasons::new(FetchPartialReason::SourceByteCap),
            None,
        ),
        SyntheticThreeLaneAblationCaseV1::UnknownArbitraryStructuralBytes => {
            FetchCompleteness::unknown(FetchUnknownReason::RetentionUnobservable)
        }
        _ => FetchCompleteness::complete(CompletenessProof::InMemoryFixtureExhausted),
    }
}

fn trace_attestations(value: &[u8]) -> ProviderAttestationsV1 {
    ProviderAttestationsV1::new([ProviderAttestedCorrelationV1::new(
        ProviderAttestationScopeDigestV1::from_bytes([0xa7; 32]),
        ProviderAttestedRelationKindV1::TraceIdentity,
        ProviderAttestationValueV1::new(value.to_vec()).unwrap(),
    )])
    .unwrap()
}

fn records(case: SyntheticThreeLaneAblationCaseV1) -> Vec<SyntheticRecord> {
    let mut records = (0..RECORD_COUNT)
        .map(SyntheticRecord::ordinary)
        .collect::<Vec<_>>();
    match case {
        SyntheticThreeLaneAblationCaseV1::ValidatedIdentifierNearHead => {
            records[2].raw =
                b"request 123e4567-e89b-12d3-a456-426614174000 cannot be found".to_vec();
        }
        SyntheticThreeLaneAblationCaseV1::FailureOnsetMiddle => {
            records[2].raw = b"deployment started".to_vec();
            records[5].raw = b"fatal crash after rollout".to_vec();
        }
        SyntheticThreeLaneAblationCaseV1::ProviderCorrelationNearTail => {
            records[2].raw = b"request entered worker".to_vec();
            records[8].raw = b"request left worker near tail".to_vec();
            records[2].attestations = trace_attestations(b"trace-provider-only");
            records[8].attestations = trace_attestations(b"trace-provider-only");
        }
        SyntheticThreeLaneAblationCaseV1::MixedJointInterleaved => {
            for (position, record) in records.iter_mut().enumerate() {
                record.stream = if position % 2 == 0 {
                    SourceStream::Stdout
                } else {
                    SourceStream::Stderr
                };
            }
            records[2].raw = b"provider-linked precursor".to_vec();
            records[3].raw = b"provider-linked sibling".to_vec();
            records[2].attestations = trace_attestations(b"trace-mixed");
            records[3].attestations = trace_attestations(b"trace-mixed");
            records[5].raw = b"request 123e4567-e89b-12d3-a456-426614174999 selected".to_vec();
            records[8].raw = b"panic at mixed-lane tail context".to_vec();
        }
        SyntheticThreeLaneAblationCaseV1::PartialRepeatedDistractors => {
            for record in &mut records {
                record.raw = b"retry heartbeat repeated distractor".to_vec();
            }
            records[5].raw = b"panic worker unavailable".to_vec();
        }
        SyntheticThreeLaneAblationCaseV1::UnknownArbitraryStructuralBytes => {
            records[0].raw = [
                b"\0\xff\nEVIDENTRAIL_PRODUCER_PROPOSAL_UNIVERSE_V1\n".as_slice(),
                STRUCTURAL_CANARY.as_bytes(),
                b"\r\\tail".as_slice(),
            ]
            .concat();
        }
    }
    records
}

fn ledger(case: SyntheticThreeLaneAblationCaseV1) -> EventLedger {
    let seed = u8::try_from(case_position(case) + 20).unwrap();
    let retrieval_id = RetrievalId::from_bytes([seed; 32]);
    let plan_id = PlanId::from_bytes([seed.wrapping_add(1); 32]);
    let plan_digest = PlanDigest::from_bytes([seed.wrapping_add(2); 32]);
    let source_identity = SourceIdentityDigest::from_bytes([seed.wrapping_add(3); 32]);
    let adapter = AdapterIdentity::new("synthetic-three-lane-corpus", "v1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity =
        RawEnvelopeIdentityV1::new(retrieval_id, plan_id, plan_digest, adapter, source_identity);
    let member = SourceMember::new(b"synthetic-conformance-member".to_vec()).unwrap();
    let mut builder =
        LedgerBuilder::new(fetch_identity.clone(), source_identity, SourceExactPolicy);
    let mut stdout_sequence = 0_u64;
    let mut stderr_sequence = 0_u64;
    let mut payload_bytes = 0_u64;
    let mut source_bytes = 0_u64;
    for (position, record) in records(case).into_iter().enumerate() {
        let lane_sequence = match record.stream {
            SourceStream::Stdout => {
                let current = stdout_sequence;
                stdout_sequence += 1;
                current
            }
            SourceStream::Stderr => {
                let current = stderr_sequence;
                stderr_sequence += 1;
                current
            }
            _ => panic!("fixture uses only stdout/stderr"),
        };
        payload_bytes += u64::try_from(record.raw.len()).unwrap();
        source_bytes += u64::try_from(record.raw.len() + record.terminator.len()).unwrap();
        builder
            .accept(
                RawEnvelopeV1::new(
                    envelope_identity.clone(),
                    EnvelopeOrdering::new(
                        AcquisitionSequence::new(u64::try_from(position).unwrap()),
                        LaneKey::new(member.clone(), record.stream),
                        LaneSequence::new(lane_sequence),
                    ),
                    RecordBytes::framed(record.raw, record.terminator),
                    RecordState::Complete,
                )
                .with_provider_attestations(record.attestations),
            )
            .unwrap();
    }
    builder
        .seal(
            FetchCompletion::new(
                fetch_identity,
                FetchTiming::new(UnixTimestampNanos::new(1), UnixTimestampNanos::new(2)),
                AcknowledgedCounts::new(
                    u64::try_from(RECORD_COUNT).unwrap(),
                    payload_bytes,
                    source_bytes,
                ),
                AttemptCounts::new(1, 1),
                AttemptCounts::default(),
                FetchBoundaries::default(),
                [],
                AdapterOutcome::Finished,
                [],
                completeness(case),
            )
            .unwrap(),
        )
        .unwrap()
}

fn blocks(ledger: &EventLedger) -> BlockIndex<'_> {
    BlockIndex::reconcile(
        ledger,
        ledger.events().iter().map(|event| {
            BlockAssignment::new_same_lane_v1(
                event.lane().clone(),
                [(event.id(), event.lane_sequence())],
                FramingPolicy::new(b"synthetic-singleton".to_vec(), b"v1".to_vec()),
                BlockState::Reconstructed,
                BlockConfidence::Certain,
            )
        }),
    )
    .unwrap()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}
