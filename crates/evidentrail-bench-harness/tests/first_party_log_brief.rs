use std::cell::Cell;

use evidentrail_bench::{
    BenchmarkBudgetV1, BenchmarkRunIdentityV1, EvidenceRepresentationClassV1, EvidenceTargetV1,
    EvidentrailBenchAnnotationSpecV1, EvidentrailBenchHiddenEvaluationManifestV1,
    EvidentrailBenchRunManifestV1, GovernedCaseArtifactBindingV1,
    GovernedRepresentationFidelityPolicyV1, MeasuredCandidateResources,
    MeasurementHarnessIdentityV1, TokenizerIdentityV1, WeightedDiagnosticRequirementV1,
    evaluate_governed_representation_fidelity_v1,
};
use evidentrail_bench_harness::{
    FirstPartyLogBriefBridgeErrorV1, artifact_digest_for_bytes_v1,
    canonical_public_run_manifest_artifact_v1, freeze_owned_compiled_log_brief_representation_v1,
    freeze_owned_passthrough_log_brief_representation_v1,
    freeze_passthrough_log_brief_representation_v1, log_brief_compiled_method_descriptor_v1,
    log_brief_passthrough_method_descriptor_v1,
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
    CompiledPacketMembershipV1, PassthroughBriefDecisionV1, PinnedTokenizer, TokenizerFailure,
    Utf8ByteTokenizerV1, certify_compiled_costs_v1, render_cost_certified_compiled_log_brief_v1,
    render_passthrough_log_brief_v1, utf8_byte_tokenizer_digest_v1,
};
use evidentrail_schema::{ArtifactDigest, QuestionDigest, ResultId};
use evidentrail_select::{
    AFFINITY_SCALE_V1, AffinityV1, FacetAffinityV1, FacetWeightV1, IntactPacketV1, PacketIdV1,
    ProductionFacetKindV1, ProductionFacetV1, SelectionDecisionV1, SelectionProblemV1,
    TotalTokenBudgetV1,
};

const TOKENIZER_DIGEST: ArtifactDigest = ArtifactDigest::from_bytes([0x71; 32]);
const RESULT_ID: ResultId = ResultId::from_bytes([0x72; 32]);
const QUESTION_DIGEST: QuestionDigest = QuestionDigest::from_bytes([0x73; 32]);

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

fn artifact(seed: u8) -> ArtifactDigest {
    ArtifactDigest::from_bytes([seed; 32])
}

fn ledger(raw_events: &[&[u8]]) -> evidentrail_core::EventLedger {
    let retrieval_id = RetrievalId::from_bytes([0x11; 32]);
    let plan_id = PlanId::from_bytes([0x12; 32]);
    let plan_digest = PlanDigest::from_bytes([0x13; 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([0x14; 32]);
    let adapter = AdapterIdentity::new("first-party-brief-fixture", "1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let lane = LaneKey::new(
        SourceMember::new(b"first-party-brief-source".to_vec()).unwrap(),
        SourceStream::Stderr,
    );
    let mut builder = LedgerBuilder::new(
        fetch_identity.clone(),
        source_identity_digest,
        SourceExactPolicy,
    );
    let mut source_bytes = 0_u64;
    for (position, raw) in raw_events.iter().enumerate() {
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
    let record_count = u64::try_from(raw_events.len()).unwrap();
    builder
        .seal(
            FetchCompletion::new(
                fetch_identity,
                FetchTiming::new(UnixTimestampNanos::new(1), UnixTimestampNanos::new(2)),
                AcknowledgedCounts::new(record_count, source_bytes, source_bytes),
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

fn references(ledger: &evidentrail_core::EventLedger) -> Vec<EvidenceReferenceV1> {
    ledger
        .events()
        .iter()
        .map(|event| {
            EvidenceReferenceV1::issue(
                RESULT_ID,
                [EvidenceTargetRef::Event(event.id())],
                [ExpansionRelationV1::Exact],
                UnixTimestampNanos::new(100),
                UnixTimestampNanos::new(200),
            )
            .unwrap()
        })
        .collect()
}

fn run_manifest(public_case: ArtifactDigest) -> EvidentrailBenchRunManifestV1 {
    let budget = BenchmarkBudgetV1::try_new(
        Some(100),
        Some(1_000_000),
        Some(1_000_000),
        Some(1_000_000),
        Some(1_000_000),
    )
    .unwrap();
    let identity = BenchmarkRunIdentityV1::try_new(
        Some(artifact(20)),
        Some(artifact(21)),
        Some(artifact(22)),
        Some(23),
        Some(budget),
    )
    .unwrap();
    EvidentrailBenchRunManifestV1::new(identity, [public_case]).unwrap()
}

#[test]
fn canonical_passthrough_bridge_is_reversibly_scoreable_and_occurrence_aware() {
    let raw = [0xff, 0x00, b'\\', b'\r', b'\n'];
    let ledger = ledger(&[&raw, &raw]);
    let tokenizer = ByteTokenizer::new();
    let decision = render_passthrough_log_brief_v1(
        &ledger,
        RESULT_ID,
        QUESTION_DIGEST,
        ledger.plan_digest(),
        references(&ledger),
        UnixTimestampNanos::new(150),
        1_000_000,
        &tokenizer,
    )
    .unwrap();
    let PassthroughBriefDecisionV1::Rendered(rendered) = decision else {
        panic!("fixture must fit the passthrough renderer")
    };
    let rendered = *rendered;
    assert_eq!(tokenizer.calls.get(), 1);

    let public_case = artifact(24);
    let manifest = run_manifest(public_case);
    let token_count = u64::try_from(rendered.text().len()).unwrap();
    let measured = MeasuredCandidateResources::try_new(token_count, 100, 1_000).unwrap();
    let receipt = freeze_passthrough_log_brief_representation_v1(
        &manifest,
        public_case,
        &ledger,
        &rendered,
        TokenizerIdentityV1::new(TOKENIZER_DIGEST),
        MeasurementHarnessIdentityV1::try_new(artifact(25), 1).unwrap(),
        measured,
    )
    .unwrap();
    let submission = receipt.submission();
    assert_eq!(
        submission.method(),
        log_brief_passthrough_method_descriptor_v1()
    );
    assert_ne!(
        submission.method(),
        log_brief_compiled_method_descriptor_v1()
    );
    assert_eq!(submission.claims().len(), 2);
    assert!(submission.claims().iter().all(|claim| {
        claim.class() == EvidenceRepresentationClassV1::SourceExactReversibleEncoding
            && claim.reversible_encoding().is_some()
            && claim.rendered_byte_range().is_some()
    }));
    assert_ne!(
        submission.claims()[0].rendered_byte_range(),
        submission.claims()[1].rendered_byte_range()
    );
    assert!(
        submission
            .claims()
            .iter()
            .all(|claim| claim.reversible_context_start().is_some())
    );
    assert_eq!(receipt.input_universe_charge().event_count(), 2);
    assert_eq!(
        receipt.input_universe_charge().source_bytes(),
        u64::try_from(raw.len() * 2).unwrap()
    );

    let annotation = EvidentrailBenchAnnotationSpecV1::new(
        public_case,
        [WeightedDiagnosticRequirementV1::new(
            1_000_000,
            [vec![
                EvidenceTargetV1::Event(ledger.events()[0].id()),
                EvidenceTargetV1::Event(ledger.events()[1].id()),
            ]],
        )
        .unwrap()],
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    let binding = GovernedCaseArtifactBindingV1::new(public_case, artifact(26));
    let canonical_run = canonical_public_run_manifest_artifact_v1(&manifest).unwrap();
    let hidden = EvidentrailBenchHiddenEvaluationManifestV1::new(
        canonical_run.artifact_digest(),
        &manifest,
        artifact(27),
        artifact(28),
        [binding],
    )
    .unwrap();
    let policy =
        GovernedRepresentationFidelityPolicyV1::source_exact_only(binding, &annotation).unwrap();
    let score = evaluate_governed_representation_fidelity_v1(
        hidden.resolve_case_binding(binding).unwrap(),
        &annotation,
        &ledger,
        None,
        submission,
        &policy,
    )
    .unwrap()
    .score_submission()
    .unwrap();
    assert_eq!(score.exact_weight_ratio(), (1_000_000, 1_000_000));

    assert_eq!(
        freeze_passthrough_log_brief_representation_v1(
            &manifest,
            public_case,
            &ledger,
            &rendered,
            TokenizerIdentityV1::new(TOKENIZER_DIGEST),
            MeasurementHarnessIdentityV1::try_new(artifact(25), 1).unwrap(),
            MeasuredCandidateResources::try_new(token_count + 1, 100, 1_000).unwrap(),
        ),
        Err(FirstPartyLogBriefBridgeErrorV1::MeasurementBindingMismatch)
    );
    let debug = format!("{submission:?}");
    for forbidden in ["first-party-brief-source", "\\xff", "annotation"] {
        assert!(!debug.contains(forbidden), "leaked {forbidden}: {debug}");
    }
    assert_eq!(
        artifact_digest_for_bytes_v1(rendered.text().as_bytes()),
        submission.rendered_candidate().artifact_digest()
    );

    let submission_artifact_digest = submission.artifact_digest();
    let owned = rendered.into_owned();
    let owned_receipt = freeze_owned_passthrough_log_brief_representation_v1(
        &manifest,
        public_case,
        &ledger,
        &owned,
        TokenizerIdentityV1::new(TOKENIZER_DIGEST),
        MeasurementHarnessIdentityV1::try_new(artifact(25), 1).unwrap(),
        measured,
    )
    .unwrap();
    assert_eq!(
        owned_receipt.submission().artifact_digest(),
        submission_artifact_digest
    );
    assert_eq!(
        owned_receipt.input_universe_charge(),
        receipt.input_universe_charge()
    );
}

#[test]
fn owned_compiled_bridge_claims_only_displayed_members_and_charges_full_universe() {
    let raw = [
        b"causal id=alpha\n".as_slice(),
        b"repeated noise\n",
        b"retained tail\n",
    ];
    let ledger = ledger(&raw);
    let selected_event = ledger.events()[0].id();
    let packet_id = PacketIdV1::from_bytes([0x81; 32]);
    let tokenizer = Utf8ByteTokenizerV1::new();
    let certificate = certify_compiled_costs_v1(
        &ledger,
        RESULT_ID,
        [CompiledPacketMembershipV1::new(packet_id, [selected_event]).unwrap()],
        &tokenizer,
    )
    .unwrap();
    let bound = &certificate.packet_bounds()[0];
    let facet = ProductionFacetV1::new(
        ProductionFacetKindV1::FailureRole,
        b"first-party-compiled-fixture",
        FacetWeightV1::new(AFFINITY_SCALE_V1).unwrap(),
    )
    .unwrap();
    let packet = IntactPacketV1::new(
        bound.packet_id(),
        bound.event_ids().iter().copied(),
        certificate
            .packet_cost(bound.packet_id(), bound.event_ids())
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
        panic!("the certified fixture must select its one packet")
    };
    let reference = EvidenceReferenceV1::issue(
        RESULT_ID,
        [EvidenceTargetRef::Event(selected_event)],
        [ExpansionRelationV1::Exact],
        UnixTimestampNanos::new(100),
        UnixTimestampNanos::new(200),
    )
    .unwrap();
    let rendered = render_cost_certified_compiled_log_brief_v1(
        &ledger,
        RESULT_ID,
        QUESTION_DIGEST,
        ledger.plan_digest(),
        selection,
        [reference],
        UnixTimestampNanos::new(150),
        &tokenizer,
        &certificate,
    )
    .unwrap()
    .into_owned();
    let public_case = artifact(29);
    let manifest = run_manifest(public_case);
    let token_count = rendered.brief().cost().total_rendered_tokens();
    let receipt = freeze_owned_compiled_log_brief_representation_v1(
        &manifest,
        public_case,
        &ledger,
        &rendered,
        TokenizerIdentityV1::new(utf8_byte_tokenizer_digest_v1()),
        MeasurementHarnessIdentityV1::try_new(artifact(30), 1).unwrap(),
        MeasuredCandidateResources::try_new(token_count, 100, 1_000).unwrap(),
    )
    .unwrap();

    assert_eq!(
        receipt.submission().method(),
        log_brief_compiled_method_descriptor_v1()
    );
    assert_eq!(receipt.submission().claims().len(), 1);
    assert_eq!(receipt.submission().claims()[0].event_id(), selected_event);
    assert_eq!(
        receipt
            .submission()
            .resources()
            .unique_candidate_event_count(),
        1
    );
    assert_eq!(
        receipt
            .submission()
            .resources()
            .unique_candidate_source_bytes(),
        u64::try_from(raw[0].len()).unwrap()
    );
    assert_eq!(receipt.input_universe_charge().event_count(), 3);
    assert_eq!(
        receipt.input_universe_charge().source_bytes(),
        raw.iter()
            .try_fold(0_u64, |total, bytes| {
                total.checked_add(u64::try_from(bytes.len()).unwrap())
            })
            .unwrap()
    );
    assert!(ledger.events()[1..].iter().all(|event| {
        !receipt
            .submission()
            .candidate_event_ids()
            .contains(&event.id())
    }));
}

#[test]
fn empty_ledger_passthrough_is_an_explicit_unsupported_benchmark_cohort() {
    let ledger = ledger(&[]);
    let tokenizer = ByteTokenizer::new();
    let decision = render_passthrough_log_brief_v1(
        &ledger,
        RESULT_ID,
        QUESTION_DIGEST,
        ledger.plan_digest(),
        [],
        UnixTimestampNanos::new(150),
        1_000_000,
        &tokenizer,
    )
    .unwrap();
    let PassthroughBriefDecisionV1::Rendered(rendered) = decision else {
        panic!("the product may render an exact empty-ledger artifact")
    };
    let rendered = *rendered;
    let public_case = artifact(31);
    assert_eq!(
        freeze_passthrough_log_brief_representation_v1(
            &run_manifest(public_case),
            public_case,
            &ledger,
            &rendered,
            TokenizerIdentityV1::new(TOKENIZER_DIGEST),
            MeasurementHarnessIdentityV1::try_new(artifact(32), 1).unwrap(),
            MeasuredCandidateResources::try_new(
                u64::try_from(rendered.text().len()).unwrap(),
                100,
                1_000,
            )
            .unwrap(),
        ),
        Err(FirstPartyLogBriefBridgeErrorV1::EmptyLedgerUnsupported)
    );
}
