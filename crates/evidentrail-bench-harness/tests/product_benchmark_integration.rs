use std::collections::BTreeSet;

use evidentrail_bench::{
    BenchmarkBudgetV1, BenchmarkRunIdentityV1, CandidateRendererIdentityV1,
    EvidenceRepresentationClaimV1, EvidenceTargetV1, EvidentrailBenchAnnotationSpecV1,
    EvidentrailBenchCaseSpecV1, EvidentrailBenchHiddenEvaluationManifestV1,
    EvidentrailBenchRunManifestV1, ExpectedAcquisitionClassV1,
    FrozenExternalRepresentationSubmissionV1, GovernedCaseArtifactBindingV1,
    GovernedRepresentationFidelityOutcomeV1, GovernedRepresentationFidelityPolicyV1,
    MeasuredCandidateResources, MeasurementEnvironmentV1, MeasurementHarnessIdentityV1,
    MethodDescriptor, NonExactFidelityDispositionV1, RenderedCandidateArtifactV1,
    RequirementFidelityPolicyV1, TokenizerIdentityV1, WeightedDiagnosticRequirementV1,
    evaluate_governed_representation_fidelity_v1,
};
use evidentrail_bench_harness::{
    FirstPartyLogBriefBridgeErrorV1, MatchedRepresentationArmV1, MatchedRepresentationComparisonV1,
    MatchedRepresentationErrorV1, MatchedResourceMeasurementTrustV1, MatchedRuntimeDimensionV1,
    PublicCaseInputBindingV1, StdinArtifactClassV1, StdinArtifactV1, artifact_digest_for_bytes_v1,
    canonical_public_case_artifact_v1, canonical_public_run_manifest_artifact_v1,
    compare_matched_representations_v1, freeze_bound_owned_compiled_log_brief_representation_v1,
    freeze_bound_owned_passthrough_log_brief_representation_v1,
};
use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    CompletenessProof, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, EventLedger,
    ExpansionRelationV1, FetchBoundaries, FetchCompleteness, FetchCompletion, FetchIdentity,
    FetchTiming, LaneKey, LaneSequence, LedgerBuilder, PlanDigest, PlanId, PolicyAuthorization,
    RawEnvelopeIdentityV1, RawEnvelopeV1, RecordBytes, RecordState, RetrievalId,
    SourceIdentityDigest, SourceMember, SourceStream, UnixTimestampNanos,
    derive_question_digest_v1,
};
use evidentrail_evidence::utf8_byte_tokenizer_digest_v1;
use evidentrail_product::{DeterministicProductDecisionV1, MemoryProductV1};
use evidentrail_schema::{ArtifactDigest, ResultId};
use evidentrail_store::{ExpansionLimitV1, ExpansionRequestV1};

const QUESTION: &[u8] = b"timeout request";
const PASSTHROUGH_PRODUCT_TOKEN_BUDGET: u64 = 100_000;
const COMPILED_PRODUCT_TOKEN_BUDGET: u64 = 20_000;
const NEEDS_MORE_PRODUCT_TOKEN_BUDGET: u64 = 0;
const SELF_ASSERTED_TEST_WALL_NANOS: u64 = 101;
const SELF_ASSERTED_TEST_PEAK_RSS_BYTES: u64 = 4_096;

struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

fn artifact(seed: u8) -> ArtifactDigest {
    ArtifactDigest::from_bytes([seed; 32])
}

fn result(seed: u8) -> ResultId {
    ResultId::from_bytes([seed; 32])
}

fn source_bytes() -> Vec<u8> {
    let mut bytes = b"ERROR timeout while handling request\n".to_vec();
    bytes.extend(std::iter::repeat_n(b'Z', 50_000));
    bytes
}

fn canonical_records(raw: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut records = Vec::new();
    let mut start = 0_usize;
    for (position, byte) in raw.iter().copied().enumerate() {
        if byte != b'\n' {
            continue;
        }
        let payload_end = if position > start && raw[position - 1] == b'\r' {
            position - 1
        } else {
            position
        };
        records.push((
            raw[start..payload_end].to_vec(),
            raw[payload_end..=position].to_vec(),
        ));
        start = position + 1;
    }
    if start < raw.len() {
        records.push((raw[start..].to_vec(), Vec::new()));
    }
    records
}

fn source_exact_ledger(raw: &[u8]) -> EventLedger {
    let retrieval_id = RetrievalId::from_bytes([0x41; 32]);
    let plan_id = PlanId::from_bytes([0x42; 32]);
    let plan_digest = PlanDigest::from_bytes([0x43; 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([0x44; 32]);
    let adapter = AdapterIdentity::new("product-benchmark-fixture", "1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let lane = LaneKey::new(
        SourceMember::new(b"canonical-public-source".to_vec()).unwrap(),
        SourceStream::Stderr,
    );
    let records = canonical_records(raw);
    let mut builder = LedgerBuilder::new(
        fetch_identity.clone(),
        source_identity_digest,
        SourceExactPolicy,
    );
    let mut payload_bytes = 0_u64;
    for (position, (payload, terminator)) in records.iter().enumerate() {
        let sequence = u64::try_from(position).unwrap();
        payload_bytes += u64::try_from(payload.len()).unwrap();
        builder
            .accept(RawEnvelopeV1::new(
                envelope_identity.clone(),
                EnvelopeOrdering::new(
                    AcquisitionSequence::new(sequence),
                    lane.clone(),
                    LaneSequence::new(sequence),
                ),
                RecordBytes::framed(payload.clone(), terminator.clone()),
                RecordState::Complete,
            ))
            .unwrap();
    }
    let record_count = u64::try_from(records.len()).unwrap();
    let source_byte_count = u64::try_from(raw.len()).unwrap();
    builder
        .seal(
            FetchCompletion::new(
                fetch_identity,
                FetchTiming::new(UnixTimestampNanos::new(1), UnixTimestampNanos::new(2)),
                AcknowledgedCounts::new(record_count, payload_bytes, source_byte_count),
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

fn benchmark_budget(token_cap: u64) -> BenchmarkBudgetV1 {
    BenchmarkBudgetV1::try_new(
        Some(2),
        Some(64 * 1024),
        Some(token_cap),
        Some(1_000_000_000),
        Some(1_000_000_000),
    )
    .unwrap()
}

fn public_case(raw: &[u8], ledger: &EventLedger) -> EvidentrailBenchCaseSpecV1 {
    EvidentrailBenchCaseSpecV1::new(
        [artifact_digest_for_bytes_v1(raw)],
        derive_question_digest_v1(QUESTION),
        ledger.plan_digest(),
        [artifact(0x51)],
        [artifact(0x52)],
        [
            benchmark_budget(PASSTHROUGH_PRODUCT_TOKEN_BUDGET).cap(),
            benchmark_budget(COMPILED_PRODUCT_TOKEN_BUDGET).cap(),
            benchmark_budget(NEEDS_MORE_PRODUCT_TOKEN_BUDGET).cap(),
        ],
        ExpectedAcquisitionClassV1::Complete,
    )
    .unwrap()
}

fn run_manifest(
    public_case_artifact_digest: ArtifactDigest,
    token_cap: u64,
    system: u8,
    build: u8,
) -> EvidentrailBenchRunManifestV1 {
    let identity = BenchmarkRunIdentityV1::try_new(
        Some(artifact(system)),
        Some(artifact(build)),
        Some(artifact(0x61)),
        Some(0x62),
        Some(benchmark_budget(token_cap)),
    )
    .unwrap();
    EvidentrailBenchRunManifestV1::new(identity, [public_case_artifact_digest]).unwrap()
}

fn bind_public_case(
    manifest: &EvidentrailBenchRunManifestV1,
    case: &EvidentrailBenchCaseSpecV1,
    raw: &[u8],
    ledger: &EventLedger,
) -> PublicCaseInputBindingV1 {
    PublicCaseInputBindingV1::try_new_canonical(
        manifest,
        case,
        StdinArtifactV1::try_new(
            StdinArtifactClassV1::PublicCase,
            artifact_digest_for_bytes_v1(raw),
            raw.to_vec(),
        )
        .unwrap(),
        ledger,
    )
    .unwrap()
}

fn measurement(tokens: u64) -> MeasuredCandidateResources {
    // Contract-only self-asserted observations. They are deliberately nonzero
    // and are never published as performance measurements or attestation.
    MeasuredCandidateResources::try_new(
        tokens,
        SELF_ASSERTED_TEST_WALL_NANOS,
        SELF_ASSERTED_TEST_PEAK_RSS_BYTES,
    )
    .unwrap()
}

fn expansion_limit() -> ExpansionLimitV1 {
    ExpansionLimitV1::new(8, 128 * 1024, 8, 8).unwrap()
}

fn assert_expansion_exact(
    product: &MemoryProductV1,
    result_id: ResultId,
    reference_id: evidentrail_schema::EvidenceReferenceId,
    ledger: &EventLedger,
    now: UnixTimestampNanos,
) {
    let expansion = product
        .expand(
            ExpansionRequestV1::new(
                result_id,
                reference_id,
                ExpansionRelationV1::Exact,
                expansion_limit(),
            ),
            now,
        )
        .unwrap();
    assert!(!expansion.truncated());
    assert!(!expansion.events().is_empty());
    for expanded in expansion.events() {
        let source = ledger.event(expanded.event_id()).unwrap();
        assert_eq!(expanded.exact_bytes(), source.raw());
    }
}

#[test]
fn actual_memory_product_owned_outputs_flow_through_governed_bridges() {
    let raw = source_bytes();
    let ledger = source_exact_ledger(&raw);
    let case = public_case(&raw, &ledger);
    let public_case_artifact = canonical_public_case_artifact_v1(&case).unwrap();
    let case_digest = public_case_artifact.artifact_digest();
    let passthrough_manifest =
        run_manifest(case_digest, PASSTHROUGH_PRODUCT_TOKEN_BUDGET, 0x70, 0x71);
    let compiled_manifest = run_manifest(case_digest, COMPILED_PRODUCT_TOKEN_BUDGET, 0x70, 0x71);
    let needs_more_manifest =
        run_manifest(case_digest, NEEDS_MORE_PRODUCT_TOKEN_BUDGET, 0x70, 0x71);
    let passthrough_case_input = bind_public_case(&passthrough_manifest, &case, &raw, &ledger);
    let compiled_case_input = bind_public_case(&compiled_manifest, &case, &raw, &ledger);
    let needs_more_case_input = bind_public_case(&needs_more_manifest, &case, &raw, &ledger);
    for binding in [
        &passthrough_case_input,
        &compiled_case_input,
        &needs_more_case_input,
    ] {
        assert_eq!(binding.public_case_artifact_digest(), case_digest);
        assert_eq!(binding.source_record_map().records().len(), ledger.len());
    }

    let now = UnixTimestampNanos::new(100);
    let mut passthrough_product = MemoryProductV1::new();
    let passthrough_decision = passthrough_product
        .create_deterministic_result_v1(
            result(1),
            QUESTION,
            ledger.clone(),
            now,
            PASSTHROUGH_PRODUCT_TOKEN_BUDGET,
        )
        .unwrap();
    let DeterministicProductDecisionV1::Passthrough(passthrough) = passthrough_decision else {
        panic!("the high-budget product arm must be exact passthrough")
    };
    assert_eq!(
        passthrough.artifact().brief().question_digest(),
        case.question_digest()
    );
    assert_eq!(
        passthrough.artifact().brief().budget().total_token_limit(),
        passthrough_manifest
            .identity()
            .budget()
            .canonical_candidate_tokens()
    );
    let passthrough_receipt = freeze_bound_owned_passthrough_log_brief_representation_v1(
        &passthrough_manifest,
        &case,
        &passthrough_case_input,
        &ledger,
        passthrough.artifact(),
        TokenizerIdentityV1::new(utf8_byte_tokenizer_digest_v1()),
        MeasurementHarnessIdentityV1::try_new(artifact(0x72), 1).unwrap(),
        measurement(
            passthrough
                .artifact()
                .brief()
                .budget()
                .total_rendered_tokens(),
        ),
    )
    .unwrap();
    assert_eq!(
        passthrough_receipt.input_universe_charge().event_count(),
        u64::try_from(ledger.len()).unwrap()
    );
    assert_eq!(
        passthrough_receipt.input_universe_charge().source_bytes(),
        u64::try_from(raw.len()).unwrap()
    );
    for reference in passthrough.references() {
        assert_expansion_exact(
            &passthrough_product,
            passthrough.result_id(),
            reference.id(),
            &ledger,
            now,
        );
    }

    let mut wrong_question_product = MemoryProductV1::new();
    let wrong_question_decision = wrong_question_product
        .create_deterministic_result_v1(
            result(5),
            b"different public question",
            ledger.clone(),
            now,
            PASSTHROUGH_PRODUCT_TOKEN_BUDGET,
        )
        .unwrap();
    let DeterministicProductDecisionV1::Passthrough(wrong_question) = wrong_question_decision
    else {
        panic!("the wrong-question fixture still fits passthrough")
    };
    assert_eq!(
        freeze_bound_owned_passthrough_log_brief_representation_v1(
            &passthrough_manifest,
            &case,
            &passthrough_case_input,
            &ledger,
            wrong_question.artifact(),
            TokenizerIdentityV1::new(utf8_byte_tokenizer_digest_v1()),
            MeasurementHarnessIdentityV1::try_new(artifact(0x72), 1).unwrap(),
            measurement(
                wrong_question
                    .artifact()
                    .brief()
                    .budget()
                    .total_rendered_tokens(),
            ),
        ),
        Err(FirstPartyLogBriefBridgeErrorV1::QuestionOrPlanBindingMismatch)
    );

    let mut compiled_product = MemoryProductV1::new();
    let compiled_decision = compiled_product
        .create_deterministic_result_v1(
            result(2),
            QUESTION,
            ledger.clone(),
            now,
            COMPILED_PRODUCT_TOKEN_BUDGET,
        )
        .unwrap();
    let DeterministicProductDecisionV1::Compiled(compiled) = compiled_decision else {
        panic!("the lower-budget product arm must compile")
    };
    assert_eq!(
        compiled.artifact().brief().question_digest(),
        case.question_digest()
    );
    assert_eq!(
        compiled.artifact().brief().cost().total_token_budget(),
        compiled_manifest
            .identity()
            .budget()
            .canonical_candidate_tokens()
    );
    assert!(
        compiled
            .artifact()
            .brief()
            .cost()
            .is_additive_bound_certified()
    );
    let displayed = compiled
        .artifact()
        .brief()
        .evidence()
        .iter()
        .flat_map(|packet| packet.events().iter().map(|event| event.event_id()))
        .collect::<BTreeSet<_>>();
    assert!(!displayed.is_empty());
    assert!(displayed.len() < ledger.len());
    let compiled_receipt = freeze_bound_owned_compiled_log_brief_representation_v1(
        &compiled_manifest,
        &case,
        &compiled_case_input,
        &ledger,
        compiled.artifact(),
        TokenizerIdentityV1::new(utf8_byte_tokenizer_digest_v1()),
        MeasurementHarnessIdentityV1::try_new(artifact(0x72), 1).unwrap(),
        measurement(compiled.artifact().brief().cost().total_rendered_tokens()),
    )
    .unwrap();
    assert_eq!(
        compiled_receipt
            .submission()
            .claims()
            .iter()
            .map(|claim| claim.event_id())
            .collect::<BTreeSet<_>>(),
        displayed
    );
    let retained_raw = ledger
        .events()
        .iter()
        .map(|event| event.id())
        .filter(|event_id| !displayed.contains(event_id))
        .collect::<BTreeSet<_>>();
    assert!(!retained_raw.is_empty());
    assert!(compiled_receipt.submission().claims().iter().all(|claim| {
        displayed.contains(&claim.event_id()) && !retained_raw.contains(&claim.event_id())
    }));
    assert_eq!(
        compiled_receipt.input_universe_charge().event_count(),
        u64::try_from(ledger.len()).unwrap()
    );
    assert_eq!(
        compiled_receipt.input_universe_charge().source_bytes(),
        u64::try_from(raw.len()).unwrap()
    );
    for reference in compiled.references() {
        assert_expansion_exact(
            &compiled_product,
            compiled.result_id(),
            reference.id(),
            &ledger,
            now,
        );
    }
    assert_eq!(
        freeze_bound_owned_compiled_log_brief_representation_v1(
            &passthrough_manifest,
            &case,
            &passthrough_case_input,
            &ledger,
            compiled.artifact(),
            TokenizerIdentityV1::new(utf8_byte_tokenizer_digest_v1()),
            MeasurementHarnessIdentityV1::try_new(artifact(0x72), 1).unwrap(),
            measurement(compiled.artifact().brief().cost().total_rendered_tokens()),
        ),
        Err(FirstPartyLogBriefBridgeErrorV1::ProductBudgetBindingMismatch)
    );

    let retained_target = *retained_raw.first().unwrap();
    let annotation = EvidentrailBenchAnnotationSpecV1::new(
        case_digest,
        [WeightedDiagnosticRequirementV1::new(
            1_000_000,
            [vec![EvidenceTargetV1::Event(retained_target)]],
        )
        .unwrap()],
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    let governed_binding = GovernedCaseArtifactBindingV1::new(case_digest, artifact(0x73));
    let compiled_run = canonical_public_run_manifest_artifact_v1(&compiled_manifest).unwrap();
    let hidden = EvidentrailBenchHiddenEvaluationManifestV1::new(
        compiled_run.artifact_digest(),
        &compiled_manifest,
        artifact(0x74),
        artifact(0x75),
        [governed_binding],
    )
    .unwrap();
    let policy =
        GovernedRepresentationFidelityPolicyV1::source_exact_only(governed_binding, &annotation)
            .unwrap();
    let retained_score = evaluate_governed_representation_fidelity_v1(
        hidden.resolve_case_binding(governed_binding).unwrap(),
        &annotation,
        &ledger,
        None,
        compiled_receipt.submission(),
        &policy,
    )
    .unwrap()
    .score_submission()
    .unwrap();
    assert_eq!(retained_score.exact_weight_ratio(), (0, 1_000_000));

    let mut needs_more_product = MemoryProductV1::new();
    let needs_more_decision = needs_more_product
        .create_deterministic_result_v1(
            result(3),
            QUESTION,
            ledger.clone(),
            now,
            NEEDS_MORE_PRODUCT_TOKEN_BUDGET,
        )
        .unwrap();
    let DeterministicProductDecisionV1::NeedsMore(needs_more) = needs_more_decision else {
        panic!("the zero-token product arm must remain typed needs-more")
    };
    assert_eq!(needs_more.question_digest(), case.question_digest());
    assert_eq!(
        needs_more.passthrough_not_fit().total_token_limit(),
        needs_more_manifest
            .identity()
            .budget()
            .canonical_candidate_tokens()
    );
    assert!(!needs_more.references().is_empty());
    assert_expansion_exact(
        &needs_more_product,
        needs_more.result_id(),
        needs_more.references()[0].id(),
        &ledger,
        now,
    );
}

fn external_pattern_submission(
    manifest: &EvidentrailBenchRunManifestV1,
    case_digest: ArtifactDigest,
    ledger: &EventLedger,
    event_id: evidentrail_schema::EventId,
    wall_time_nanos: u64,
    peak_memory_bytes: u64,
) -> FrozenExternalRepresentationSubmissionV1 {
    let rendered = b"opaque external pattern representation\n";
    let run = canonical_public_run_manifest_artifact_v1(manifest).unwrap();
    FrozenExternalRepresentationSubmissionV1::try_new_self_asserted(
        run.artifact_digest(),
        manifest,
        case_digest,
        MethodDescriptor::new("external-pattern-fixture", "1"),
        ledger,
        artifact(0x81),
        artifact(0x82),
        MeasurementEnvironmentV1::new(
            TokenizerIdentityV1::new(artifact(0x83)),
            CandidateRendererIdentityV1::try_new(artifact(0x84), 1).unwrap(),
            MeasurementHarnessIdentityV1::try_new(artifact(0x85), 1).unwrap(),
        ),
        RenderedCandidateArtifactV1::try_new(
            artifact_digest_for_bytes_v1(rendered),
            u64::try_from(rendered.len()).unwrap(),
        )
        .unwrap(),
        rendered,
        MeasuredCandidateResources::try_new(5, wall_time_nanos, peak_memory_bytes).unwrap(),
        [EvidenceRepresentationClaimV1::pattern_only(
            event_id,
            artifact(0x86),
        )],
    )
    .unwrap()
}

fn governed_outcomes(
    first_manifest: &EvidentrailBenchRunManifestV1,
    first_submission: &FrozenExternalRepresentationSubmissionV1,
    external_manifest: &EvidentrailBenchRunManifestV1,
    external_submission: &FrozenExternalRepresentationSubmissionV1,
    case_digest: ArtifactDigest,
    ledger: &EventLedger,
    event_id: evidentrail_schema::EventId,
) -> (
    GovernedRepresentationFidelityOutcomeV1,
    GovernedRepresentationFidelityOutcomeV1,
) {
    let annotation = EvidentrailBenchAnnotationSpecV1::new(
        case_digest,
        [WeightedDiagnosticRequirementV1::new(
            1_000_000,
            [vec![EvidenceTargetV1::Event(event_id)]],
        )
        .unwrap()],
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    let binding = GovernedCaseArtifactBindingV1::new(case_digest, artifact(0x87));
    let first_run = canonical_public_run_manifest_artifact_v1(first_manifest).unwrap();
    let external_run = canonical_public_run_manifest_artifact_v1(external_manifest).unwrap();
    let first_hidden = EvidentrailBenchHiddenEvaluationManifestV1::new(
        first_run.artifact_digest(),
        first_manifest,
        artifact(0x88),
        artifact(0x89),
        [binding],
    )
    .unwrap();
    let external_hidden = EvidentrailBenchHiddenEvaluationManifestV1::new(
        external_run.artifact_digest(),
        external_manifest,
        artifact(0x88),
        artifact(0x89),
        [binding],
    )
    .unwrap();
    let exact_policy =
        GovernedRepresentationFidelityPolicyV1::source_exact_only(binding, &annotation).unwrap();
    let external_rule = RequirementFidelityPolicyV1::try_new(
        [],
        NonExactFidelityDispositionV1::Reject,
        NonExactFidelityDispositionV1::Reject,
        NonExactFidelityDispositionV1::NeedsDownstreamVds,
    )
    .unwrap();
    let external_policy =
        GovernedRepresentationFidelityPolicyV1::try_new(binding, &annotation, [external_rule])
            .unwrap();
    (
        evaluate_governed_representation_fidelity_v1(
            first_hidden.resolve_case_binding(binding).unwrap(),
            &annotation,
            ledger,
            None,
            first_submission,
            &exact_policy,
        )
        .unwrap(),
        evaluate_governed_representation_fidelity_v1(
            external_hidden.resolve_case_binding(binding).unwrap(),
            &annotation,
            ledger,
            None,
            external_submission,
            &external_policy,
        )
        .unwrap(),
    )
}

#[test]
fn matched_scaffold_refuses_scalar_ordering_for_vds_and_zero_runtime_fields() {
    let raw = source_bytes();
    let ledger = source_exact_ledger(&raw);
    let case = public_case(&raw, &ledger);
    let case_digest = canonical_public_case_artifact_v1(&case)
        .unwrap()
        .artifact_digest();
    let first_manifest = run_manifest(case_digest, PASSTHROUGH_PRODUCT_TOKEN_BUDGET, 0x90, 0x91);
    let external_manifest = run_manifest(case_digest, PASSTHROUGH_PRODUCT_TOKEN_BUDGET, 0x92, 0x93);
    let now = UnixTimestampNanos::new(200);
    let mut product = MemoryProductV1::new();
    let decision = product
        .create_deterministic_result_v1(
            result(4),
            QUESTION,
            ledger.clone(),
            now,
            PASSTHROUGH_PRODUCT_TOKEN_BUDGET,
        )
        .unwrap();
    let DeterministicProductDecisionV1::Passthrough(first_party) = decision else {
        panic!("the comparison fixture must passthrough")
    };
    let case_input = bind_public_case(&first_manifest, &case, &raw, &ledger);
    let first_receipt = freeze_bound_owned_passthrough_log_brief_representation_v1(
        &first_manifest,
        &case,
        &case_input,
        &ledger,
        first_party.artifact(),
        TokenizerIdentityV1::new(utf8_byte_tokenizer_digest_v1()),
        MeasurementHarnessIdentityV1::try_new(artifact(0x94), 1).unwrap(),
        measurement(
            first_party
                .artifact()
                .brief()
                .budget()
                .total_rendered_tokens(),
        ),
    )
    .unwrap();
    let target = ledger.events()[0].id();
    let external =
        external_pattern_submission(&external_manifest, case_digest, &ledger, target, 202, 8_192);
    let (first_outcome, external_outcome) = governed_outcomes(
        &first_manifest,
        first_receipt.submission(),
        &external_manifest,
        &external,
        case_digest,
        &ledger,
        target,
    );
    let comparison = compare_matched_representations_v1(
        &first_manifest,
        first_receipt.submission(),
        first_outcome,
        &external_manifest,
        &external,
        external_outcome,
    )
    .unwrap();
    let MatchedRepresentationComparisonV1::NeedsDownstreamVds(needs_vds) = &comparison else {
        panic!("pattern-only external output must stop at downstream VDS")
    };
    assert!(!needs_vds.first_party_requires_vds());
    assert!(needs_vds.external_requires_vds());
    let arms = comparison.arms();
    assert_eq!(
        arms.first_party().method(),
        first_receipt.submission().method()
    );
    assert_eq!(arms.external().method(), external.method());
    assert_eq!(
        arms.first_party().resources(),
        first_receipt.submission().resources()
    );
    assert_eq!(arms.external().resources(), external.resources());
    for arm in [arms.first_party(), arms.external()] {
        assert_eq!(
            arm.measurement_trust(),
            MatchedResourceMeasurementTrustV1::SelfAssertedReproducibilityInput
        );
        assert!(!arm.measurement_trust().is_independently_attested());
        assert_ne!(arm.resources().wall_time_nanos(), 0);
        assert_ne!(arm.resources().peak_memory_bytes(), 0);
    }
    assert_eq!(
        comparison.exact_recall_ordering(),
        Err(MatchedRepresentationErrorV1::NeedsDownstreamVds)
    );

    for (wall, peak, dimension) in [
        (0, 8_192, MatchedRuntimeDimensionV1::WallTimeNanos),
        (202, 0, MatchedRuntimeDimensionV1::PeakMemoryBytes),
    ] {
        let unmeasured = external_pattern_submission(
            &external_manifest,
            case_digest,
            &ledger,
            target,
            wall,
            peak,
        );
        let (_, unmeasured_outcome) = governed_outcomes(
            &first_manifest,
            first_receipt.submission(),
            &external_manifest,
            &unmeasured,
            case_digest,
            &ledger,
            target,
        );
        assert_eq!(
            compare_matched_representations_v1(
                &first_manifest,
                first_receipt.submission(),
                first_outcome,
                &external_manifest,
                &unmeasured,
                unmeasured_outcome,
            ),
            Err(MatchedRepresentationErrorV1::MissingRuntimeMeasurement {
                arm: MatchedRepresentationArmV1::External,
                dimension,
            })
        );
    }

    let debug = format!("{comparison:?}");
    for forbidden in ["timeout request", "ERROR timeout", "annotation_artifact"] {
        assert!(!debug.contains(forbidden), "leaked {forbidden}: {debug}");
    }
}
