use std::collections::BTreeSet;

use evidentrail_bench::{
    BenchmarkBudgetV1, BenchmarkRunIdentityV1, CandidateResourceCap, EvidenceTargetV1,
    EvidentrailBenchAnnotationSpecV1, EvidentrailBenchCaseSpecV1,
    EvidentrailBenchHiddenEvaluationManifestV1, EvidentrailBenchRunManifestV1,
    ExpectedAcquisitionClassV1, FrozenProducerProposalFrontierPlanV1,
    FrozenPublicThreeLaneAblationBatchV1, FrozenThreeLaneAblationSetV1,
    GovernedCaseArtifactBindingV1, MeasuredProducerProposalResourcesV1,
    ProducerProposalMeasurementEnvironmentV1, ProducerProposalMeasurementReceiptV1,
    ProducerProposalRenderLimitV1, ProducerProposalResourceCapV1,
    ThreeLaneAblationEvaluationErrorV1, ThreeLaneAblationFreezeErrorV1, ThreeLaneAblationMaskV1,
    ThreeLaneAblationMeasurementAllocationV1, ThreeLaneAblationPublicPointInputV1,
    WeightedDiagnosticRequirementV1, canonical_producer_proposal_renderer_v1_identity,
    evaluate_governed_producer_proposals_v1, evaluate_governed_three_lane_ablation_batch_v1,
    freeze_prepared_three_lane_ablations_v1, freeze_public_three_lane_ablation_batch_v1,
    prepare_three_lane_ablations_v1, render_canonical_producer_proposals_v1,
    three_lane_ablation_config_digest_v1, three_lane_ablation_method_family_digest_v1,
};
use evidentrail_compile::{PreparedThreeLaneAblationSetV1, ThreeLaneAblationPreparationDecisionV1};
use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    BlockAssignment, BlockConfidence, BlockIndex, BlockState, CompletenessProof,
    DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, EventLedger, FetchBoundaries,
    FetchCompleteness, FetchCompletion, FetchIdentity, FetchTiming, FramingPolicy, LaneKey,
    LaneSequence, LedgerBuilder, PlanDigest, PlanId, PolicyAuthorization, RawEnvelopeIdentityV1,
    RawEnvelopeV1, RecordBytes, RecordState, ResultId, RetrievalId, SourceIdentityDigest,
    SourceMember, SourceStream, UnixTimestampNanos, derive_question_digest_v1,
};
use evidentrail_evidence::Utf8ByteTokenizerV1;
use evidentrail_schema::ArtifactDigest;

struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

fn artifact(seed: u8) -> ArtifactDigest {
    ArtifactDigest::from_bytes([seed; 32])
}

fn ledger(seed: u8, records: &[&[u8]]) -> EventLedger {
    let retrieval_id = RetrievalId::from_bytes([seed; 32]);
    let plan_id = PlanId::from_bytes([seed.wrapping_add(1); 32]);
    let plan_digest = PlanDigest::from_bytes([seed.wrapping_add(2); 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([seed.wrapping_add(3); 32]);
    let adapter = AdapterIdentity::new("bench-ablation-fixture", "1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let lane = LaneKey::new(
        SourceMember::new(b"bench-ablation-member".to_vec()).unwrap(),
        SourceStream::Stderr,
    );
    let mut builder = LedgerBuilder::new(
        fetch_identity.clone(),
        source_identity_digest,
        SourceExactPolicy,
    );
    let mut source_bytes = 0_u64;
    for (position, raw) in records.iter().enumerate() {
        source_bytes += u64::try_from(raw.len() + 1).unwrap();
        let sequence = u64::try_from(position).unwrap();
        builder
            .accept(RawEnvelopeV1::new(
                envelope_identity.clone(),
                EnvelopeOrdering::new(
                    AcquisitionSequence::new(sequence),
                    lane.clone(),
                    LaneSequence::new(sequence),
                ),
                RecordBytes::framed(raw.to_vec(), b"\n".to_vec()),
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
                    u64::try_from(records.len()).unwrap(),
                    source_bytes - u64::try_from(records.len()).unwrap(),
                    source_bytes,
                ),
                AttemptCounts::new(1, 1),
                AttemptCounts::default(),
                FetchBoundaries::default(),
                [],
                AdapterOutcome::Finished,
                [],
                FetchCompleteness::complete(CompletenessProof::OtherVersioned {
                    version: 1,
                    code: 212,
                }),
            )
            .unwrap(),
        )
        .unwrap()
}

fn singleton_blocks(ledger: &EventLedger) -> BlockIndex<'_> {
    BlockIndex::reconcile(
        ledger,
        ledger.events().iter().map(|event| {
            BlockAssignment::new_same_lane_v1(
                event.lane().clone(),
                [(event.id(), event.lane_sequence())],
                FramingPolicy::new(b"bench-ablation-singleton".to_vec(), b"1".to_vec()),
                BlockState::FallbackSingleton,
                BlockConfidence::Certain,
            )
        }),
    )
    .unwrap()
}

fn public_case(ledger: &EventLedger, question: &[u8]) -> EvidentrailBenchCaseSpecV1 {
    EvidentrailBenchCaseSpecV1::new(
        [artifact(1)],
        derive_question_digest_v1(question),
        ledger.plan_digest(),
        [artifact(2)],
        [artifact(3)],
        [CandidateResourceCap::try_new(99, 99, 99, 99, 99).unwrap()],
        ExpectedAcquisitionClassV1::Complete,
    )
    .unwrap()
}

fn governed_join(
    public_case_artifact: ArtifactDigest,
    annotation_artifact: ArtifactDigest,
) -> evidentrail_bench::GovernedCaseArtifactJoinV1 {
    let budget =
        BenchmarkBudgetV1::try_new(Some(99), Some(99), Some(99), Some(99), Some(99)).unwrap();
    let identity = BenchmarkRunIdentityV1::try_new(
        Some(artifact(90)),
        Some(artifact(91)),
        Some(artifact(92)),
        Some(1),
        Some(budget),
    )
    .unwrap();
    let public = EvidentrailBenchRunManifestV1::new(identity, [public_case_artifact]).unwrap();
    let binding = GovernedCaseArtifactBindingV1::new(public_case_artifact, annotation_artifact);
    let hidden = EvidentrailBenchHiddenEvaluationManifestV1::new(
        artifact(93),
        &public,
        artifact(94),
        artifact(95),
        [binding],
    )
    .unwrap();
    hidden.resolve_case_binding(binding).unwrap()
}

fn measurement_environment() -> ProducerProposalMeasurementEnvironmentV1 {
    let renderer = canonical_producer_proposal_renderer_v1_identity();
    ProducerProposalMeasurementEnvironmentV1::try_new(
        renderer.artifact_digest(),
        renderer.contract_version(),
        artifact(96),
        1,
        artifact(97),
        1,
    )
    .unwrap()
}

fn prepared(
    ledger: &EventLedger,
    blocks: &BlockIndex<'_>,
    question: &[u8],
) -> PreparedThreeLaneAblationSetV1 {
    prepared_with_result(ledger, blocks, question, 77)
}

fn prepared_with_result(
    ledger: &EventLedger,
    blocks: &BlockIndex<'_>,
    question: &[u8],
    result_seed: u8,
) -> PreparedThreeLaneAblationSetV1 {
    match prepare_three_lane_ablations_v1(
        question,
        ledger,
        blocks,
        ResultId::from_bytes([result_seed; 32]),
        &Utf8ByteTokenizerV1::new(),
    )
    .unwrap()
    {
        ThreeLaneAblationPreparationDecisionV1::Prepared(prepared) => *prepared,
        ThreeLaneAblationPreparationDecisionV1::NeedsMore(_) => panic!("fixture must prepare"),
    }
}

fn frozen_set(
    ledger: &EventLedger,
    blocks: &BlockIndex<'_>,
    question: &[u8],
    case_artifact: ArtifactDigest,
    result_seed: u8,
) -> (EvidentrailBenchCaseSpecV1, FrozenThreeLaneAblationSetV1) {
    let case = public_case(ledger, question);
    let prepared = prepared_with_result(ledger, blocks, question, result_seed);
    let frozen =
        freeze_prepared_three_lane_ablations_v1(case_artifact, &case, ledger, &prepared).unwrap();
    (case, frozen)
}

#[allow(clippy::too_many_arguments)]
fn public_point_input(
    ledger: &EventLedger,
    frozen: &FrozenThreeLaneAblationSetV1,
    actual_mask: ThreeLaneAblationMaskV1,
    claimed_mask: ThreeLaneAblationMaskV1,
    environment: ProducerProposalMeasurementEnvironmentV1,
    cap: ProducerProposalResourceCapV1,
    wall_time_nanos: u64,
    peak_rss_bytes: u64,
) -> ThreeLaneAblationPublicPointInputV1 {
    let universe = frozen.configuration(actual_mask).universe();
    let rendered = render_canonical_producer_proposals_v1(
        ledger,
        universe,
        ProducerProposalRenderLimitV1::hard_maximum(),
    )
    .unwrap();
    let measured = MeasuredProducerProposalResourcesV1::try_new(
        rendered.byte_count(),
        Some(wall_time_nanos),
        Some(peak_rss_bytes),
    )
    .unwrap();
    let receipt = ProducerProposalMeasurementReceiptV1::try_new_self_asserted_borrowed(
        universe,
        &rendered,
        environment,
        measured,
    )
    .unwrap();
    ThreeLaneAblationPublicPointInputV1::new(claimed_mask, cap, rendered, receipt)
}

fn public_point_inputs(
    ledger: &EventLedger,
    frozen: &FrozenThreeLaneAblationSetV1,
    environment: ProducerProposalMeasurementEnvironmentV1,
    caps: [ProducerProposalResourceCapV1; 4],
    wall_time_nanos: u64,
    peak_rss_bytes: u64,
) -> Vec<ThreeLaneAblationPublicPointInputV1> {
    ThreeLaneAblationMaskV1::ALL
        .into_iter()
        .enumerate()
        .map(|(index, mask)| {
            public_point_input(
                ledger,
                frozen,
                mask,
                mask,
                environment,
                caps[index],
                wall_time_nanos,
                peak_rss_bytes,
            )
        })
        .collect()
}

fn freeze_public_batch(
    case_artifact: ArtifactDigest,
    case: EvidentrailBenchCaseSpecV1,
    frozen: FrozenThreeLaneAblationSetV1,
    environment: ProducerProposalMeasurementEnvironmentV1,
    inputs: Vec<ThreeLaneAblationPublicPointInputV1>,
) -> Result<FrozenPublicThreeLaneAblationBatchV1, ThreeLaneAblationEvaluationErrorV1> {
    freeze_public_three_lane_ablation_batch_v1(
        case_artifact,
        case,
        frozen,
        environment,
        ThreeLaneAblationMeasurementAllocationV1::ConservativeSharedBatchFullChargeEachConfiguration,
        inputs,
    )
}

fn generous_proposal_cap() -> ProducerProposalResourceCapV1 {
    ProducerProposalResourceCapV1::try_new(1_000_000, 1_000_000, 1_000_000, 1_000_000, 1_000_000)
        .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn public_point_input_with_foreign_measurement(
    ledger: &EventLedger,
    frozen: &FrozenThreeLaneAblationSetV1,
    artifact_mask: ThreeLaneAblationMaskV1,
    measurement_mask: ThreeLaneAblationMaskV1,
    claimed_mask: ThreeLaneAblationMaskV1,
    environment: ProducerProposalMeasurementEnvironmentV1,
    cap: ProducerProposalResourceCapV1,
    wall_time_nanos: u64,
    peak_rss_bytes: u64,
) -> ThreeLaneAblationPublicPointInputV1 {
    let artifact_universe = frozen.configuration(artifact_mask).universe();
    let artifact = render_canonical_producer_proposals_v1(
        ledger,
        artifact_universe,
        ProducerProposalRenderLimitV1::hard_maximum(),
    )
    .unwrap();
    let measurement_universe = frozen.configuration(measurement_mask).universe();
    let measurement_artifact = render_canonical_producer_proposals_v1(
        ledger,
        measurement_universe,
        ProducerProposalRenderLimitV1::hard_maximum(),
    )
    .unwrap();
    let measured = MeasuredProducerProposalResourcesV1::try_new(
        measurement_artifact.byte_count(),
        Some(wall_time_nanos),
        Some(peak_rss_bytes),
    )
    .unwrap();
    let receipt = ProducerProposalMeasurementReceiptV1::try_new_self_asserted_borrowed(
        measurement_universe,
        &measurement_artifact,
        environment,
        measured,
    )
    .unwrap();
    ThreeLaneAblationPublicPointInputV1::new(claimed_mask, cap, artifact, receipt)
}

#[test]
fn prepared_masks_freeze_as_one_method_family_with_exact_distinct_identities() {
    let ledger = ledger(
        71,
        &[
            b"ordinary E0425",
            b"Traceback (most recent call last):",
            b"ValueError: failure",
        ],
    );
    let blocks = singleton_blocks(&ledger);
    let question = b"diagnose E0425 ValueError";
    let prepared = prepared(&ledger, &blocks, question);
    let case = public_case(&ledger, question);
    let frozen =
        freeze_prepared_three_lane_ablations_v1(artifact(71), &case, &ledger, &prepared).unwrap();
    let method = three_lane_ablation_method_family_digest_v1();

    assert_eq!(frozen.method_family_digest(), method);
    assert_eq!(frozen.configurations().len(), 4);
    assert_eq!(
        frozen
            .configurations()
            .iter()
            .map(|configuration| configuration.mask())
            .collect::<Vec<_>>(),
        ThreeLaneAblationMaskV1::ALL
    );
    assert!(frozen.configurations().iter().all(|configuration| {
        configuration.universe().producer().method_artifact_digest() == method
    }));
    assert_eq!(
        frozen
            .configurations()
            .iter()
            .map(|configuration| { configuration.universe().producer().config_artifact_digest() })
            .collect::<BTreeSet<_>>()
            .len(),
        4
    );
    assert_eq!(
        frozen
            .configurations()
            .iter()
            .map(|configuration| {
                configuration
                    .universe()
                    .producer()
                    .producer_receipt_artifact_digest()
            })
            .collect::<BTreeSet<_>>()
            .len(),
        4
    );
    let acquisition = frozen.configurations()[0].universe().acquisition_binding();
    assert!(
        frozen
            .configurations()
            .iter()
            .all(|configuration| configuration.universe().acquisition_binding() == acquisition)
    );
    for configuration in frozen.configurations() {
        let compiler = prepared.configuration(configuration.mask()).prepared();
        let expected = compiler
            .proposal_packets()
            .iter()
            .map(|packet| *packet.id().as_bytes())
            .collect::<BTreeSet<_>>();
        let actual = configuration
            .universe()
            .proposals()
            .iter()
            .map(|packet| *packet.id().as_bytes())
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected);
    }

    let environment = measurement_environment();
    let cap =
        evidentrail_bench::ProducerProposalResourceCapV1::try_new(99, 99, 99, 99, 99).unwrap();
    let frontier = FrozenProducerProposalFrontierPlanV1::try_new(
        environment,
        frozen
            .configurations()
            .iter()
            .map(|configuration| (configuration.universe(), cap)),
    )
    .unwrap();
    assert_eq!(frontier.method_artifact_digest(), method);
    assert_eq!(frontier.points().len(), 4);
    assert!(
        format!("{frozen:?}").contains("label_free_preparation_input_process_order_not_attested")
    );
}

#[test]
fn empty_ablated_proposal_universe_freezes_and_question_mismatch_is_contentless() {
    let ledger = ledger(72, &[b"ordinary line"]);
    let blocks = singleton_blocks(&ledger);
    let prepared = prepared(&ledger, &blocks, b"");
    let empty_configurations = prepared
        .configurations()
        .iter()
        .filter(|configuration| configuration.prepared().proposal_packets().is_empty())
        .map(|configuration| configuration.mask())
        .collect::<Vec<_>>();
    assert!(!empty_configurations.is_empty());
    let case = public_case(&ledger, b"");
    let frozen =
        freeze_prepared_three_lane_ablations_v1(artifact(72), &case, &ledger, &prepared).unwrap();
    for mask in &empty_configurations {
        let universe = frozen.configuration(*mask).universe();
        assert!(universe.proposals().is_empty());
        assert_eq!(universe.accounting().proposal_packet_count(), 0);
        assert_eq!(universe.accounting().unique_member_event_count(), 0);
        assert_eq!(universe.accounting().unique_member_source_bytes(), 0);
    }

    let empty = frozen.configuration(empty_configurations[0]).universe();
    let case_artifact = artifact(72);
    let annotation_artifact = artifact(73);
    let annotation = EvidentrailBenchAnnotationSpecV1::new(
        case_artifact,
        [WeightedDiagnosticRequirementV1::new(
            7,
            [vec![EvidenceTargetV1::Event(ledger.events()[0].id())]],
        )
        .unwrap()],
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    let rendered = render_canonical_producer_proposals_v1(
        &ledger,
        empty,
        ProducerProposalRenderLimitV1::hard_maximum(),
    )
    .unwrap();
    let measurement = ProducerProposalMeasurementReceiptV1::try_new_self_asserted(
        empty,
        rendered,
        measurement_environment(),
        MeasuredProducerProposalResourcesV1::try_new(0, Some(1), Some(1)).unwrap(),
    )
    .unwrap();
    let evaluation = evaluate_governed_producer_proposals_v1(
        governed_join(case_artifact, annotation_artifact),
        &case,
        &annotation,
        &ledger,
        &blocks,
        empty,
        measurement,
        ProducerProposalResourceCapV1::try_new(0, 0, 0, 1, 1).unwrap(),
    )
    .unwrap();
    assert_eq!(evaluation.recall().exact_weight_ratio(), (0, 7));
    assert_eq!(evaluation.resources().proposal_packet_count(), 0);
    assert!(evaluation.cap_violations().is_none());

    let wrong_case = public_case(&ledger, b"CANARY_WRONG_QUESTION");
    let error =
        freeze_prepared_three_lane_ablations_v1(artifact(72), &wrong_case, &ledger, &prepared)
            .unwrap_err();
    assert_eq!(
        error,
        ThreeLaneAblationFreezeErrorV1::QuestionBindingMismatch
    );
    let debug = format!("{error:?}");
    assert_eq!(
        debug,
        "ThreeLaneAblationFreezeErrorV1 { code: \"EVIDENTRAIL_BENCH_ABLATION_QUESTION_BINDING_MISMATCH\" }"
    );
    assert!(!debug.contains("CANARY_WRONG_QUESTION"));
}

#[test]
fn public_batch_freezes_all_outputs_before_governed_annotations_and_is_deterministic() {
    let ledger = ledger(
        73,
        &[
            b"CANARY_PUBLIC_LOG E0425",
            b"Traceback (most recent call last):",
            b"ValueError: failure",
        ],
    );
    let blocks = singleton_blocks(&ledger);
    let question = b"diagnose E0425 ValueError";
    let case_artifact = artifact(73);
    let (case, frozen) = frozen_set(&ledger, &blocks, question, case_artifact, 73);
    let environment = measurement_environment();
    let caps = [generous_proposal_cap(); 4];
    let inputs = public_point_inputs(&ledger, &frozen, environment, caps, 101, 202);
    let public = freeze_public_batch(
        case_artifact,
        case.clone(),
        frozen.clone(),
        environment,
        inputs,
    )
    .unwrap();
    let mut replay_inputs = public_point_inputs(&ledger, &frozen, environment, caps, 101, 202);
    replay_inputs.reverse();
    let replay = freeze_public_batch(
        case_artifact,
        case.clone(),
        frozen,
        environment,
        replay_inputs,
    )
    .unwrap();

    assert_eq!(public.digest(), replay.digest());
    assert_eq!(public.method_family_digest(), replay.method_family_digest());
    assert_eq!(public.acquisition_binding(), replay.acquisition_binding());
    assert_eq!(public.environment(), environment);
    assert_eq!(public.shared_wall_time_nanos(), 101);
    assert_eq!(public.shared_peak_rss_bytes(), 202);
    assert_eq!(public.points().len(), 4);
    assert_eq!(public.frontier_plan().points().len(), 4);
    assert_eq!(
        public
            .points()
            .iter()
            .map(|point| point.digest())
            .collect::<Vec<_>>(),
        replay
            .points()
            .iter()
            .map(|point| point.digest())
            .collect::<Vec<_>>()
    );
    for mask in ThreeLaneAblationMaskV1::ALL {
        let point = public.point(mask);
        assert_eq!(point.mask(), mask);
        assert_eq!(
            point.producer().method_artifact_digest(),
            three_lane_ablation_method_family_digest_v1()
        );
        assert_eq!(
            point.producer().config_artifact_digest(),
            three_lane_ablation_config_digest_v1(mask)
        );
        assert_eq!(
            point.measurement().rendered_artifact().artifact_digest(),
            point.canonical_artifact().artifact_digest()
        );
        assert_eq!(point.measurement().measured().wall_time_nanos(), 101);
        assert_eq!(point.measurement().measured().peak_rss_bytes(), 202);
    }
    let public_debug = format!("{public:?}");
    assert!(public_debug.contains("not_external_temporal_attestation"));
    assert!(!public_debug.contains("CANARY_PUBLIC_LOG"));
    assert!(!public_debug.contains("E0425"));

    // Hidden material is constructed only after the public package exists.
    let annotation_artifact = artifact(74);
    let annotation = EvidentrailBenchAnnotationSpecV1::new(
        case_artifact,
        [WeightedDiagnosticRequirementV1::new(
            11,
            [vec![EvidenceTargetV1::Event(ledger.events()[0].id())]],
        )
        .unwrap()],
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    let governed = evaluate_governed_three_lane_ablation_batch_v1(
        &public,
        governed_join(case_artifact, annotation_artifact),
        &annotation,
        &ledger,
        &blocks,
    )
    .unwrap();
    assert_eq!(governed.public_batch_digest(), public.digest());
    assert_eq!(governed.evaluations().len(), 4);
    assert_eq!(governed.frontier().points().len(), 4);
    assert!(!governed.contains_scalar_score());
    assert!(!governed.contains_auc());
    assert!(!governed.contains_verified_winner());
    for mask in ThreeLaneAblationMaskV1::ALL {
        let governed_point = governed.evaluation(mask);
        let public_point = public.point(mask);
        assert_eq!(governed_point.mask(), mask);
        assert_eq!(
            governed_point.evaluation().universe_digest(),
            public_point.universe_digest()
        );
        assert_eq!(
            governed_point.evaluation().producer(),
            public_point.producer()
        );
        assert_eq!(
            governed_point.evaluation().measurement_receipt_digest(),
            public_point.measurement().digest()
        );
        assert_eq!(
            governed_point.evaluation().resource_cap(),
            public_point.cap()
        );
    }
}

#[test]
fn public_batch_rejects_missing_duplicate_swapped_foreign_and_mismeasured_points() {
    let ledger = ledger(74, &[b"E0425", b"ERROR failure", b"ordinary tail"]);
    let blocks = singleton_blocks(&ledger);
    let question = b"diagnose E0425";
    let case_artifact = artifact(75);
    let (case, frozen) = frozen_set(&ledger, &blocks, question, case_artifact, 75);
    let environment = measurement_environment();
    let caps = [generous_proposal_cap(); 4];

    let mut missing = public_point_inputs(&ledger, &frozen, environment, caps, 10, 20);
    missing.pop();
    assert_eq!(
        freeze_public_batch(
            case_artifact,
            case.clone(),
            frozen.clone(),
            environment,
            missing,
        )
        .unwrap_err(),
        ThreeLaneAblationEvaluationErrorV1::MissingMasks { count: 1 }
    );

    let mut duplicate = public_point_inputs(&ledger, &frozen, environment, caps, 10, 20);
    duplicate.push(public_point_input(
        &ledger,
        &frozen,
        ThreeLaneAblationMaskV1::Full,
        ThreeLaneAblationMaskV1::Full,
        environment,
        generous_proposal_cap(),
        10,
        20,
    ));
    assert_eq!(
        freeze_public_batch(
            case_artifact,
            case.clone(),
            frozen.clone(),
            environment,
            duplicate,
        )
        .unwrap_err(),
        ThreeLaneAblationEvaluationErrorV1::DuplicateMask
    );

    let mut swapped = public_point_inputs(&ledger, &frozen, environment, caps, 10, 20);
    swapped[0] = public_point_input(
        &ledger,
        &frozen,
        ThreeLaneAblationMaskV1::WithoutLexical,
        ThreeLaneAblationMaskV1::Full,
        environment,
        generous_proposal_cap(),
        10,
        20,
    );
    assert_eq!(
        freeze_public_batch(
            case_artifact,
            case.clone(),
            frozen.clone(),
            environment,
            swapped,
        )
        .unwrap_err(),
        ThreeLaneAblationEvaluationErrorV1::CanonicalRenderBindingMismatch
    );

    let mut foreign_measurement = public_point_inputs(&ledger, &frozen, environment, caps, 10, 20);
    foreign_measurement[0] = public_point_input_with_foreign_measurement(
        &ledger,
        &frozen,
        ThreeLaneAblationMaskV1::Full,
        ThreeLaneAblationMaskV1::WithoutCoverage,
        ThreeLaneAblationMaskV1::Full,
        environment,
        generous_proposal_cap(),
        10,
        20,
    );
    assert_eq!(
        freeze_public_batch(
            case_artifact,
            case.clone(),
            frozen.clone(),
            environment,
            foreign_measurement,
        )
        .unwrap_err(),
        ThreeLaneAblationEvaluationErrorV1::MeasurementBindingMismatch
    );

    let foreign_environment = {
        let renderer = canonical_producer_proposal_renderer_v1_identity();
        ProducerProposalMeasurementEnvironmentV1::try_new(
            renderer.artifact_digest(),
            renderer.contract_version(),
            artifact(201),
            1,
            artifact(202),
            1,
        )
        .unwrap()
    };
    let environment_mismatch = public_point_inputs(&ledger, &frozen, environment, caps, 10, 20);
    assert_eq!(
        freeze_public_batch(
            case_artifact,
            case.clone(),
            frozen.clone(),
            foreign_environment,
            environment_mismatch,
        )
        .unwrap_err(),
        ThreeLaneAblationEvaluationErrorV1::MeasurementEnvironmentMismatch
    );

    let wrong_case_inputs = public_point_inputs(&ledger, &frozen, environment, caps, 10, 20);
    assert_eq!(
        freeze_public_batch(
            case_artifact,
            public_case(&ledger, b"CANARY_FOREIGN_QUESTION"),
            frozen.clone(),
            environment,
            wrong_case_inputs,
        )
        .unwrap_err(),
        ThreeLaneAblationEvaluationErrorV1::PublicCaseBindingMismatch
    );

    let shared_mismatch = ThreeLaneAblationMaskV1::ALL
        .into_iter()
        .enumerate()
        .map(|(index, mask)| {
            public_point_input(
                &ledger,
                &frozen,
                mask,
                mask,
                environment,
                generous_proposal_cap(),
                if index == 3 { 11 } else { 10 },
                20,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        freeze_public_batch(
            case_artifact,
            case.clone(),
            frozen.clone(),
            environment,
            shared_mismatch,
        )
        .unwrap_err(),
        ThreeLaneAblationEvaluationErrorV1::SharedBatchCostMismatch
    );

    let (_, foreign) = frozen_set(&ledger, &blocks, question, case_artifact, 76);
    let foreign_inputs = public_point_inputs(&ledger, &foreign, environment, caps, 10, 20);
    assert_eq!(
        freeze_public_batch(
            case_artifact,
            case.clone(),
            frozen.clone(),
            environment,
            foreign_inputs,
        )
        .unwrap_err(),
        ThreeLaneAblationEvaluationErrorV1::CanonicalRenderBindingMismatch
    );

    let original_inputs = public_point_inputs(&ledger, &frozen, environment, caps, 10, 20);
    let original = freeze_public_batch(
        case_artifact,
        case.clone(),
        frozen.clone(),
        environment,
        original_inputs,
    )
    .unwrap();
    let changed_cap =
        ProducerProposalResourceCapV1::try_new(999_999, 1_000_000, 1_000_000, 1_000_000, 1_000_000)
            .unwrap();
    let changed_inputs = public_point_inputs(
        &ledger,
        &frozen,
        environment,
        [changed_cap, caps[1], caps[2], caps[3]],
        10,
        20,
    );
    let changed =
        freeze_public_batch(case_artifact, case, frozen, environment, changed_inputs).unwrap();
    assert_ne!(original.digest(), changed.digest());
    assert_ne!(
        original.point(ThreeLaneAblationMaskV1::Full).digest(),
        changed.point(ThreeLaneAblationMaskV1::Full).digest()
    );
    let debug = format!(
        "{:?}",
        ThreeLaneAblationEvaluationErrorV1::MeasurementBindingMismatch
    );
    assert!(!debug.contains("E0425"));
    assert!(!debug.contains("ERROR failure"));
}

#[test]
fn all_infeasible_four_mask_batch_keeps_violations_and_empty_universes_out_of_frontier() {
    let ledger = ledger(76, &[b"ordinary line"]);
    let blocks = singleton_blocks(&ledger);
    let question = b"";
    let case_artifact = artifact(76);
    let (case, frozen) = frozen_set(&ledger, &blocks, question, case_artifact, 76);
    assert!(
        frozen
            .configurations()
            .iter()
            .any(|configuration| configuration.universe().proposals().is_empty())
    );
    let environment = measurement_environment();
    let zero_cap = ProducerProposalResourceCapV1::try_new(0, 0, 0, 0, 0).unwrap();
    let inputs = public_point_inputs(&ledger, &frozen, environment, [zero_cap; 4], 10, 20);
    let public =
        freeze_public_batch(case_artifact, case.clone(), frozen, environment, inputs).unwrap();
    let annotation = EvidentrailBenchAnnotationSpecV1::new(
        case_artifact,
        [WeightedDiagnosticRequirementV1::new(
            7,
            [vec![EvidenceTargetV1::Event(ledger.events()[0].id())]],
        )
        .unwrap()],
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    let governed = evaluate_governed_three_lane_ablation_batch_v1(
        &public,
        governed_join(case_artifact, artifact(77)),
        &annotation,
        &ledger,
        &blocks,
    )
    .unwrap();

    assert_eq!(governed.evaluations().len(), 4);
    assert_eq!(governed.frontier().points().len(), 4);
    assert_eq!(governed.frontier().eligible_points().count(), 0);
    assert_eq!(governed.frontier().ineligible_points().count(), 4);
    assert_eq!(governed.frontier().frontier_points().count(), 0);
    assert!(governed.evaluations().iter().all(|point| {
        point.evaluation().cap_violations().is_some()
            && point.evaluation().resources().wall_time_nanos() == 10
            && point.evaluation().resources().peak_rss_bytes() == 20
    }));
    assert!(governed.evaluations().iter().any(|point| {
        point.evaluation().resources().proposal_packet_count() == 0
            && point.evaluation().resources().unique_member_event_count() == 0
    }));
}
