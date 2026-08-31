use std::cell::Cell;

use evidentrail_bench::{
    BenchmarkBudgetV1, BenchmarkMethod, BenchmarkRunIdentityV1, ByteBudget,
    CandidateRendererIdentityV1, CandidateResourceCap, CandidateResourceDimension,
    EvidenceTargetV1, EvidentrailBenchAnnotationSpecV1, EvidentrailBenchCaseSpecV1,
    EvidentrailBenchHiddenEvaluationManifestV1, EvidentrailBenchRunManifestV1,
    ExpectedAcquisitionClassV1, FrozenCandidateRenderingV1, FrozenCandidateSelectionDigestV1,
    FrozenPublicCaseRunV1, FrozenPublicRunV1, GovernedCaseArtifactBindingV1, GrepHeadTail,
    GrepHeadTailConfig, HermeticGovernedCaseInputV1, HermeticPublicCaseInputV1,
    HermeticRunnerError, MeasuredCandidateResources, MeasurementEnvironmentV1,
    MeasurementHarnessIdentityV1, MeasurementProvenanceError, MeasurementProvenanceReceiptV1,
    MeasurementTrustBoundaryV1, MeasurementValidatedPublicRunV1, MethodDescriptor, MethodError,
    MethodInput, MethodResult, RawChronological, RenderedCandidateArtifactV1, TokenizerIdentityV1,
    WeightedDiagnosticRequirementV1, bind_hermetic_measurement_receipts_v1,
    evaluate_governed_case_with_presentation_v1, evaluate_measurement_validated_hermetic_run_v1,
    execute_hermetic_public_run_v1,
};
use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    CapKind, CapUsage, CompletenessProof, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink,
    EventLedger, FetchBoundaries, FetchCompleteness, FetchCompletion, FetchIdentity,
    FetchPartialReason, FetchPartialReasons, FetchTiming, LaneKey, LaneSequence, LedgerBuilder,
    PlanDigest, PlanId, PolicyAuthorization, PresentationAssignment, PresentationDisposition,
    PresentationReceipt, RawEnvelopeIdentityV1, RawEnvelopeV1, RecordBytes, RecordState,
    RetrievalId, SourceIdentityDigest, SourceMember, SourceStream, UnixTimestampNanos,
    derive_question_digest_v1,
};
use evidentrail_schema::bounds::JSON_SAFE_INTEGER_MAX;
use evidentrail_schema::{ArtifactDigest, QuestionDigest};

struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

fn artifact(seed: u8) -> ArtifactDigest {
    ArtifactDigest::from_bytes([seed; 32])
}

fn question(seed: u8) -> QuestionDigest {
    QuestionDigest::from_bytes([seed; 32])
}

fn build_ledger(
    seed: u8,
    raw_events: &[Vec<u8>],
    acquisition_class: ExpectedAcquisitionClassV1,
) -> EventLedger {
    let retrieval_id = RetrievalId::from_bytes([seed; 32]);
    let plan_id = PlanId::from_bytes([seed.wrapping_add(1); 32]);
    let plan_digest = PlanDigest::from_bytes([seed.wrapping_add(2); 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([seed.wrapping_add(3); 32]);
    let adapter = AdapterIdentity::new("hermetic-runner-fixture", "1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let lane = LaneKey::new(
        SourceMember::new(b"hermetic-runner-member".to_vec()).unwrap(),
        SourceStream::FileMember,
    );
    let mut builder = LedgerBuilder::new(
        fetch_identity.clone(),
        source_identity_digest,
        SourceExactPolicy,
    );
    let mut source_bytes = 0u64;
    for (position, raw) in raw_events.iter().enumerate() {
        let sequence = u64::try_from(position).unwrap();
        source_bytes = source_bytes
            .checked_add(u64::try_from(raw.len()).unwrap())
            .unwrap();
        builder
            .accept(RawEnvelopeV1::new(
                envelope_identity.clone(),
                EnvelopeOrdering::new(
                    AcquisitionSequence::new(sequence),
                    lane.clone(),
                    LaneSequence::new(sequence),
                ),
                RecordBytes::whole(raw.clone()),
                RecordState::Complete,
            ))
            .unwrap();
    }

    let record_count = u64::try_from(raw_events.len()).unwrap();
    let (adapter_outcome, cap_usage, completeness) = match acquisition_class {
        ExpectedAcquisitionClassV1::Complete => (
            AdapterOutcome::Finished,
            Vec::new(),
            FetchCompleteness::complete(CompletenessProof::OtherVersioned {
                version: 1,
                code: 83,
            }),
        ),
        ExpectedAcquisitionClassV1::Partial => (
            AdapterOutcome::SourceStopped,
            vec![CapUsage::new(
                CapKind::SourceBytes,
                source_bytes,
                source_bytes,
                true,
            )],
            FetchCompleteness::partial(
                FetchPartialReasons::new(FetchPartialReason::SourceByteCap),
                None,
            ),
        ),
        ExpectedAcquisitionClassV1::Unknown => (
            AdapterOutcome::Finished,
            Vec::new(),
            FetchCompleteness::unknown(
                evidentrail_core::FetchUnknownReason::ProviderHasNoCompletenessProof,
            ),
        ),
    };
    let completion = FetchCompletion::new(
        fetch_identity,
        FetchTiming::new(UnixTimestampNanos::new(100), UnixTimestampNanos::new(101)),
        AcknowledgedCounts::new(record_count, source_bytes, source_bytes),
        AttemptCounts::new(1, 1),
        AttemptCounts::default(),
        FetchBoundaries::default(),
        cap_usage,
        adapter_outcome,
        [],
        completeness,
    )
    .unwrap();
    builder.seal(completion).unwrap()
}

fn candidate_cap(values: [u64; 5]) -> CandidateResourceCap {
    CandidateResourceCap::try_new(values[0], values[1], values[2], values[3], values[4]).unwrap()
}

fn run_budget(values: [u64; 5]) -> BenchmarkBudgetV1 {
    BenchmarkBudgetV1::try_new(
        Some(values[0]),
        Some(values[1]),
        Some(values[2]),
        Some(values[3]),
        Some(values[4]),
    )
    .unwrap()
}

fn run_manifest(
    public_case_artifact_digests: impl IntoIterator<Item = ArtifactDigest>,
    budget: BenchmarkBudgetV1,
) -> EvidentrailBenchRunManifestV1 {
    let identity = BenchmarkRunIdentityV1::try_new(
        Some(artifact(240)),
        Some(artifact(241)),
        Some(artifact(242)),
        Some(17),
        Some(budget),
    )
    .unwrap();
    EvidentrailBenchRunManifestV1::new(identity, public_case_artifact_digests).unwrap()
}

fn hidden_manifest(
    run_manifest_artifact_digest: ArtifactDigest,
    manifest: &EvidentrailBenchRunManifestV1,
    bindings: impl IntoIterator<Item = GovernedCaseArtifactBindingV1>,
) -> EvidentrailBenchHiddenEvaluationManifestV1 {
    EvidentrailBenchHiddenEvaluationManifestV1::new(
        run_manifest_artifact_digest,
        manifest,
        artifact(238),
        artifact(239),
        bindings,
    )
    .unwrap()
}

fn public_case(
    seed: u8,
    ledger: &EventLedger,
    question_digest: QuestionDigest,
    budget: CandidateResourceCap,
    acquisition_class: ExpectedAcquisitionClassV1,
) -> EvidentrailBenchCaseSpecV1 {
    EvidentrailBenchCaseSpecV1::new(
        [artifact(seed.wrapping_add(80))],
        question_digest,
        ledger.plan_digest(),
        [artifact(seed.wrapping_add(81))],
        [artifact(seed.wrapping_add(82))],
        [budget],
        acquisition_class,
    )
    .unwrap()
}

fn annotation(
    public_case_artifact_digest: ArtifactDigest,
    target: EvidenceTargetV1,
) -> EvidentrailBenchAnnotationSpecV1 {
    EvidentrailBenchAnnotationSpecV1::new(
        public_case_artifact_digest,
        [WeightedDiagnosticRequirementV1::new(1_000_000, [vec![target]]).unwrap()],
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap()
}

fn measurements() -> MeasuredCandidateResources {
    MeasuredCandidateResources::try_new(10, 10, 10).unwrap()
}

fn measurement_environment() -> MeasurementEnvironmentV1 {
    MeasurementEnvironmentV1::new(
        TokenizerIdentityV1::new(artifact(230)),
        CandidateRendererIdentityV1::try_new(artifact(232), 1).unwrap(),
        MeasurementHarnessIdentityV1::try_new(artifact(231), 1).unwrap(),
    )
}

fn rendered_candidate() -> RenderedCandidateArtifactV1 {
    RenderedCandidateArtifactV1::try_new(artifact(233), 37).unwrap()
}

fn candidate_rendering(
    frozen_case: &FrozenPublicCaseRunV1<'_>,
    environment: MeasurementEnvironmentV1,
    rendered_candidate: RenderedCandidateArtifactV1,
) -> FrozenCandidateRenderingV1 {
    FrozenCandidateRenderingV1::new_self_asserted(
        frozen_case.public_case_artifact_digest(),
        frozen_case.candidate_selection_digest(),
        frozen_case.presentation_receipt().id(),
        environment.renderer(),
        rendered_candidate,
    )
}

fn measurement_receipt(
    frozen_run: &FrozenPublicRunV1<'_>,
    frozen_case: &FrozenPublicCaseRunV1<'_>,
    environment: MeasurementEnvironmentV1,
    rendered_candidate: RenderedCandidateArtifactV1,
    observed: MeasuredCandidateResources,
) -> MeasurementProvenanceReceiptV1 {
    MeasurementProvenanceReceiptV1::new_self_asserted(
        frozen_run.run_manifest_artifact_digest(),
        frozen_run.run_identity(),
        frozen_case.public_case_artifact_digest(),
        frozen_run.method(),
        frozen_case.candidate_selection_digest(),
        frozen_case.presentation_receipt().id(),
        environment,
        rendered_candidate,
        observed,
    )
}

fn bind_measurements(
    frozen_run: FrozenPublicRunV1<'_>,
    observed: MeasuredCandidateResources,
) -> MeasurementValidatedPublicRunV1<'_> {
    let environment = measurement_environment();
    let rendered_candidate = rendered_candidate();
    let renderings = frozen_run
        .cases()
        .iter()
        .map(|case| candidate_rendering(case, environment, rendered_candidate))
        .collect::<Vec<_>>();
    let receipts = frozen_run
        .cases()
        .iter()
        .map(|case| {
            measurement_receipt(&frozen_run, case, environment, rendered_candidate, observed)
        })
        .collect::<Vec<_>>();
    bind_hermetic_measurement_receipts_v1(frozen_run, environment, renderings, receipts).unwrap()
}

#[test]
fn four_case_runner_is_deterministic_frozen_then_governed_and_annotation_blind() {
    let budget_values = [16, 128, 100, 100, 100];
    let budget = candidate_cap(budget_values);
    let case_digests = [artifact(10), artifact(20), artifact(30), artifact(40)];
    let annotation_digests = [artifact(110), artifact(120), artifact(130), artifact(140)];
    let queries: [&[u8]; 4] = [b"", b"REQ-77", b"partial", b"\xffERR-9\x00"];
    let question_digests = queries.map(derive_question_digest_v1);

    let passthrough_raw = vec![b"boot\n".to_vec(), b"ready\n".to_vec(), b"done\n".to_vec()];
    let mut repetitive_raw = vec![b"heartbeat\n".to_vec(); 101];
    repetitive_raw[50] = b"root cause request-id=REQ-77\n".to_vec();
    let partial_raw = vec![
        b"partial start\n".to_vec(),
        b"partial clue\n".to_vec(),
        b"partial end\n".to_vec(),
    ];
    let hostile_raw = vec![
        b"\xffprefix\x00\n".to_vec(),
        b"\x80ERR-9\x00CANARY_RUNNER_SECRET\r\n".to_vec(),
        b"tail\xfe".to_vec(),
    ];
    let ledgers = [
        build_ledger(10, &passthrough_raw, ExpectedAcquisitionClassV1::Complete),
        build_ledger(20, &repetitive_raw, ExpectedAcquisitionClassV1::Complete),
        build_ledger(30, &partial_raw, ExpectedAcquisitionClassV1::Partial),
        build_ledger(40, &hostile_raw, ExpectedAcquisitionClassV1::Complete),
    ];
    let public_cases = (0..4)
        .map(|index| {
            public_case(
                u8::try_from(index).unwrap(),
                &ledgers[index],
                question_digests[index],
                budget,
                if index == 2 {
                    ExpectedAcquisitionClassV1::Partial
                } else {
                    ExpectedAcquisitionClassV1::Complete
                },
            )
        })
        .collect::<Vec<_>>();
    let annotations = [
        annotation(
            case_digests[0],
            EvidenceTargetV1::Event(ledgers[0].events()[1].id()),
        ),
        annotation(
            case_digests[1],
            EvidenceTargetV1::Event(ledgers[1].events()[50].id()),
        ),
        annotation(
            case_digests[2],
            EvidenceTargetV1::Event(ledgers[2].events()[1].id()),
        ),
        annotation(
            case_digests[3],
            EvidenceTargetV1::Event(ledgers[3].events()[1].id()),
        ),
    ];
    let manifest = run_manifest(case_digests, run_budget(budget_values));
    let governed_manifest = hidden_manifest(
        artifact(250),
        &manifest,
        (0..4).map(|index| {
            GovernedCaseArtifactBindingV1::new(case_digests[index], annotation_digests[index])
        }),
    );
    let method = GrepHeadTail::new(GrepHeadTailConfig::new(2, 2));
    let public_inputs = (0..4)
        .rev()
        .map(|index| {
            HermeticPublicCaseInputV1::new(
                case_digests[index],
                &public_cases[index],
                &ledgers[index],
                queries[index],
            )
        })
        .collect::<Vec<_>>();

    let frozen_a = execute_hermetic_public_run_v1(
        artifact(250),
        &manifest,
        &method,
        public_inputs.iter().copied(),
    )
    .unwrap();
    let frozen_b = execute_hermetic_public_run_v1(
        artifact(250),
        &manifest,
        &method,
        public_inputs.iter().copied(),
    )
    .unwrap();
    assert_eq!(
        frozen_a
            .cases()
            .iter()
            .map(|case| case.public_case_artifact_digest())
            .collect::<Vec<_>>(),
        case_digests
    );
    for (left, right) in frozen_a.cases().iter().zip(frozen_b.cases()) {
        assert_eq!(left.method_result(), right.method_result());
        assert_eq!(
            left.presentation_receipt().id(),
            right.presentation_receipt().id()
        );
        assert_eq!(
            left.candidate_selection_digest(),
            right.candidate_selection_digest()
        );
    }
    let validated_a = bind_measurements(frozen_a, measurements());
    let validated_b = bind_measurements(frozen_b, measurements());
    for (left, right) in validated_a.cases().iter().zip(validated_b.cases()) {
        assert_eq!(left.candidate_resources(), right.candidate_resources());
        assert_eq!(left.receipt(), right.receipt());
    }

    let governed_inputs = (0..4).rev().map(|index| {
        HermeticGovernedCaseInputV1::new(
            GovernedCaseArtifactBindingV1::new(case_digests[index], annotation_digests[index]),
            &annotations[index],
            None,
        )
    });
    let aggregate = evaluate_measurement_validated_hermetic_run_v1(
        &validated_a,
        &governed_manifest,
        governed_inputs,
    )
    .unwrap();
    assert_eq!(aggregate.public_aggregate().case_count(), 4);
    assert_eq!(aggregate.public_aggregate().complete_case_count(), 3);
    assert_eq!(aggregate.public_aggregate().partial_case_count(), 1);
    assert_eq!(
        aggregate
            .public_aggregate()
            .accounting()
            .source_byte_budget(),
        4 * budget_values[1]
    );
    assert_eq!(
        aggregate.governed_recall().exact_weight_ratio(),
        (4_000_000, 4_000_000)
    );

    let frozen_a = validated_a.frozen_run();
    let passthrough = &frozen_a.cases()[0];
    assert_eq!(
        passthrough.method_result().selected().len(),
        passthrough.ledger().len()
    );
    let repetitive = &frozen_a.cases()[1];
    assert!(repetitive.ledger().len() > repetitive.method_result().selected().len());
    assert_eq!(
        validated_a.cases()[1]
            .candidate_resources()
            .unique_candidate_event_count(),
        5
    );
    assert_eq!(
        validated_a.cases()[1]
            .candidate_resources()
            .unique_candidate_source_bytes(),
        4 * u64::try_from(b"heartbeat\n".len()).unwrap()
            + u64::try_from(b"root cause request-id=REQ-77\n".len()).unwrap()
    );
    assert!(
        repetitive
            .method_result()
            .contains(repetitive.ledger().events()[50].id())
    );
    assert!(
        frozen_a.cases()[3]
            .method_result()
            .contains(frozen_a.cases()[3].ledger().events()[1].id())
    );
    let public_debug = format!("{frozen_a:?}").to_ascii_lowercase();
    for forbidden in [
        "canary_runner_secret",
        "annotation",
        "requirement",
        "recall",
        "satisfied",
        "weight",
        "target",
    ] {
        assert!(!public_debug.contains(forbidden));
    }
    assert!(!format!("{:?}", public_inputs[3]).contains("ERR-9"));
    assert!(public_cases.iter().all(|case| {
        !format!("{case:?}")
            .to_ascii_lowercase()
            .contains("annotation")
    }));
    assert!(
        !format!("{manifest:?}")
            .to_ascii_lowercase()
            .contains("annotation")
    );

    let alternate_large_annotation = annotation(
        case_digests[1],
        EvidenceTargetV1::Event(ledgers[1].events()[49].id()),
    );
    let alternate_annotation_digests = [
        annotation_digests[0],
        artifact(150),
        annotation_digests[2],
        annotation_digests[3],
    ];
    let alternate_governed_manifest = hidden_manifest(
        artifact(250),
        &manifest,
        (0..4).map(|index| {
            GovernedCaseArtifactBindingV1::new(
                case_digests[index],
                alternate_annotation_digests[index],
            )
        }),
    );
    let alternate_governed_inputs = (0..4).map(|index| {
        HermeticGovernedCaseInputV1::new(
            GovernedCaseArtifactBindingV1::new(
                case_digests[index],
                alternate_annotation_digests[index],
            ),
            if index == 1 {
                &alternate_large_annotation
            } else {
                &annotations[index]
            },
            None,
        )
    });
    let alternate = evaluate_measurement_validated_hermetic_run_v1(
        &validated_a,
        &alternate_governed_manifest,
        alternate_governed_inputs,
    )
    .unwrap();
    assert_eq!(alternate.public_aggregate(), aggregate.public_aggregate());
    assert_eq!(
        alternate.governed_recall().exact_weight_ratio(),
        (3_000_000, 4_000_000)
    );
}

struct CountingMethod<'counter> {
    calls: &'counter Cell<usize>,
}

impl BenchmarkMethod for CountingMethod<'_> {
    fn descriptor(&self) -> MethodDescriptor {
        RawChronological::DESCRIPTOR
    }

    fn run(&self, input: MethodInput<'_>) -> Result<MethodResult, MethodError> {
        self.calls.set(self.calls.get() + 1);
        RawChronological.run(input)
    }
}

#[test]
fn public_cohort_and_bindings_fail_before_any_method_invocation() {
    let budget_values = [8, 64, 64, 64, 64];
    let cap = candidate_cap(budget_values);
    let case_digest = artifact(1);
    let extra_digest = artifact(2);
    let question_digest = derive_question_digest_v1(b"query");
    let ledger = build_ledger(
        50,
        &[b"CANARY_PUBLIC_BINDING\n".to_vec()],
        ExpectedAcquisitionClassV1::Complete,
    );
    let case = public_case(
        5,
        &ledger,
        question_digest,
        cap,
        ExpectedAcquisitionClassV1::Complete,
    );
    let manifest = run_manifest([case_digest], run_budget(budget_values));
    let input = HermeticPublicCaseInputV1::new(case_digest, &case, &ledger, b"query");
    let extra = HermeticPublicCaseInputV1::new(extra_digest, &case, &ledger, b"query");
    let calls = Cell::new(0);
    let method = CountingMethod { calls: &calls };

    assert_eq!(
        execute_hermetic_public_run_v1(artifact(9), &manifest, &method, []).unwrap_err(),
        HermeticRunnerError::MissingPublicCaseInputs { count: 1 }
    );
    assert_eq!(
        execute_hermetic_public_run_v1(artifact(9), &manifest, &method, [input, input])
            .unwrap_err(),
        HermeticRunnerError::DuplicatePublicCaseInput
    );
    assert_eq!(
        execute_hermetic_public_run_v1(artifact(9), &manifest, &method, [input, extra])
            .unwrap_err(),
        HermeticRunnerError::ExtraPublicCaseInputs { count: 1 }
    );
    let wrong_question =
        HermeticPublicCaseInputV1::new(case_digest, &case, &ledger, b"CANARY_QUERY");
    let question_error =
        execute_hermetic_public_run_v1(artifact(9), &manifest, &method, [wrong_question])
            .unwrap_err();
    assert_eq!(question_error, HermeticRunnerError::QuestionDigestMismatch);
    assert!(!format!("{question_error:?}").contains("CANARY_QUERY"));

    let wrong_ledger = build_ledger(
        51,
        &[b"CANARY_WRONG_PLAN\n".to_vec()],
        ExpectedAcquisitionClassV1::Complete,
    );
    let wrong_plan = HermeticPublicCaseInputV1::new(case_digest, &case, &wrong_ledger, b"query");
    assert_eq!(
        execute_hermetic_public_run_v1(artifact(9), &manifest, &method, [wrong_plan]).unwrap_err(),
        HermeticRunnerError::PlanDigestMismatch
    );

    let undeclared_cap = candidate_cap([8, 63, 64, 64, 64]);
    let undeclared_case = public_case(
        5,
        &ledger,
        question_digest,
        undeclared_cap,
        ExpectedAcquisitionClassV1::Complete,
    );
    let undeclared_input =
        HermeticPublicCaseInputV1::new(case_digest, &undeclared_case, &ledger, b"query");
    let error = execute_hermetic_public_run_v1(artifact(9), &manifest, &method, [undeclared_input])
        .unwrap_err();
    assert_eq!(error, HermeticRunnerError::BudgetPointNotDeclared);
    assert_eq!(calls.get(), 0);
    assert!(!format!("{error:?}").contains("CANARY_PUBLIC_BINDING"));
}

#[test]
fn supplied_resource_measurements_are_required_and_every_dimension_is_enforced() {
    let budget_values = [4, 64, 5, 5, 5];
    let cap = candidate_cap(budget_values);
    let case_digest = artifact(61);
    let question_digest = derive_question_digest_v1(b"");
    let ledger = build_ledger(
        60,
        &[b"CANARY_RESOURCE_PAYLOAD\n".to_vec()],
        ExpectedAcquisitionClassV1::Complete,
    );
    let case = public_case(
        63,
        &ledger,
        question_digest,
        cap,
        ExpectedAcquisitionClassV1::Complete,
    );
    let manifest = run_manifest([case_digest], run_budget(budget_values));
    let dimensions = [
        (
            MeasuredCandidateResources::try_new(6, 1, 1).unwrap(),
            CandidateResourceDimension::CanonicalCandidateTokens,
        ),
        (
            MeasuredCandidateResources::try_new(1, 6, 1).unwrap(),
            CandidateResourceDimension::WallTimeNanos,
        ),
        (
            MeasuredCandidateResources::try_new(1, 1, 6).unwrap(),
            CandidateResourceDimension::PeakMemoryBytes,
        ),
    ];
    for (measured, dimension) in dimensions {
        let input = HermeticPublicCaseInputV1::new(case_digest, &case, &ledger, b"");
        let frozen =
            execute_hermetic_public_run_v1(artifact(65), &manifest, &RawChronological, [input])
                .unwrap();
        let environment = measurement_environment();
        let rendered_candidate = rendered_candidate();
        let rendering = candidate_rendering(&frozen.cases()[0], environment, rendered_candidate);
        let receipt = measurement_receipt(
            &frozen,
            &frozen.cases()[0],
            environment,
            rendered_candidate,
            measured,
        );
        let error =
            bind_hermetic_measurement_receipts_v1(frozen, environment, [rendering], [receipt])
                .unwrap_err();
        let violations = error.candidate_cap_violations().unwrap();
        assert_eq!(violations.dimensions(), &[dimension]);
        assert!(!format!("{error:?}").contains("CANARY_RESOURCE_PAYLOAD"));
    }
}

#[test]
fn inherent_candidate_dimensions_are_derived_from_distinct_ledger_events() {
    let scenarios = [
        (
            [1, 64, 64, 64, 64],
            vec![b"same".to_vec(), b"same".to_vec()],
            CandidateResourceDimension::UniqueCandidateEventCount,
        ),
        (
            [4, 3, 64, 64, 64],
            vec![b"oversized".to_vec()],
            CandidateResourceDimension::UniqueCandidateSourceBytes,
        ),
    ];

    for (index, (budget_values, raw, expected_dimension)) in scenarios.into_iter().enumerate() {
        let seed = 66_u8 + u8::try_from(index).unwrap();
        let case_digest = artifact(seed);
        let question_digest = derive_question_digest_v1(b"");
        let ledger = build_ledger(seed, &raw, ExpectedAcquisitionClassV1::Complete);
        let case = public_case(
            seed,
            &ledger,
            question_digest,
            candidate_cap(budget_values),
            ExpectedAcquisitionClassV1::Complete,
        );
        let manifest = run_manifest([case_digest], run_budget(budget_values));
        let frozen = execute_hermetic_public_run_v1(
            artifact(90),
            &manifest,
            &RawChronological,
            [HermeticPublicCaseInputV1::new(
                case_digest,
                &case,
                &ledger,
                b"",
            )],
        )
        .unwrap();
        let environment = measurement_environment();
        let rendered_candidate = rendered_candidate();
        let rendering = candidate_rendering(&frozen.cases()[0], environment, rendered_candidate);
        let receipt = measurement_receipt(
            &frozen,
            &frozen.cases()[0],
            environment,
            rendered_candidate,
            measurements(),
        );
        let error =
            bind_hermetic_measurement_receipts_v1(frozen, environment, [rendering], [receipt])
                .unwrap_err();
        assert_eq!(
            error.candidate_cap_violations().unwrap().dimensions(),
            &[expected_dimension]
        );
    }
}

#[test]
fn measurement_provenance_rejects_every_binding_before_governed_labels() {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Variant {
        RenderingSelection,
        RenderingPresentation,
        RenderingRendererIdentity,
        RenderingRendererVersion,
        RunManifest,
        RunIdentity,
        Method,
        Selection,
        Presentation,
        Tokenizer,
        RendererIdentity,
        RendererVersion,
        HarnessIdentity,
        HarnessVersion,
        RenderedArtifact,
        RenderedByteCount,
    }

    impl Variant {
        const fn expected(self) -> HermeticRunnerError {
            match self {
                Self::RenderingSelection => {
                    HermeticRunnerError::CandidateRenderingSelectionMismatch
                }
                Self::RenderingPresentation => {
                    HermeticRunnerError::CandidateRenderingPresentationMismatch
                }
                Self::RenderingRendererIdentity => {
                    HermeticRunnerError::CandidateRenderingRendererIdentityMismatch
                }
                Self::RenderingRendererVersion => {
                    HermeticRunnerError::CandidateRenderingRendererVersionMismatch
                }
                Self::RunManifest => HermeticRunnerError::MeasurementRunManifestArtifactMismatch,
                Self::RunIdentity => HermeticRunnerError::MeasurementRunIdentityMismatch,
                Self::Method => HermeticRunnerError::MeasurementMethodMismatch,
                Self::Selection => HermeticRunnerError::MeasurementCandidateSelectionMismatch,
                Self::Presentation => HermeticRunnerError::MeasurementPresentationReceiptMismatch,
                Self::Tokenizer => HermeticRunnerError::MeasurementTokenizerIdentityMismatch,
                Self::RendererIdentity => HermeticRunnerError::MeasurementRendererIdentityMismatch,
                Self::RendererVersion => HermeticRunnerError::MeasurementRendererVersionMismatch,
                Self::HarnessIdentity => HermeticRunnerError::MeasurementHarnessIdentityMismatch,
                Self::HarnessVersion => HermeticRunnerError::MeasurementHarnessVersionMismatch,
                Self::RenderedArtifact => {
                    HermeticRunnerError::MeasurementRenderedCandidateArtifactMismatch
                }
                Self::RenderedByteCount => {
                    HermeticRunnerError::MeasurementRenderedCandidateByteCountMismatch
                }
            }
        }
    }

    let budget_values = [4, 128, 128, 128, 128];
    let case_digest = artifact(91);
    let ledger = build_ledger(
        90,
        &[b"CANARY_MEASUREMENT_PAYLOAD\n".to_vec()],
        ExpectedAcquisitionClassV1::Complete,
    );
    let case = public_case(
        93,
        &ledger,
        derive_question_digest_v1(b"measurement query"),
        candidate_cap(budget_values),
        ExpectedAcquisitionClassV1::Complete,
    );
    let manifest = run_manifest([case_digest], run_budget(budget_values));
    let freeze = || {
        execute_hermetic_public_run_v1(
            artifact(94),
            &manifest,
            &RawChronological,
            [HermeticPublicCaseInputV1::new(
                case_digest,
                &case,
                &ledger,
                b"measurement query",
            )],
        )
        .unwrap()
    };
    let environment = measurement_environment();
    let rendered = rendered_candidate();

    let baseline = freeze();
    let baseline_receipt = measurement_receipt(
        &baseline,
        &baseline.cases()[0],
        environment,
        rendered,
        measurements(),
    );
    assert_eq!(
        baseline_receipt.trust_boundary(),
        MeasurementTrustBoundaryV1::SelfAssertedReproducibilityInput
    );
    let receipt_debug = format!("{baseline_receipt:?}").to_ascii_lowercase();
    for forbidden in [
        "canary_measurement_payload",
        "measurement query",
        "annotation",
        "requirement",
        "root_cause",
        "recall",
        "score",
        "target",
    ] {
        assert!(!receipt_debug.contains(forbidden));
    }

    assert_eq!(
        CandidateRendererIdentityV1::try_new(artifact(1), 0).unwrap_err(),
        MeasurementProvenanceError::ZeroRendererContractVersion
    );
    assert_eq!(
        CandidateRendererIdentityV1::try_new(artifact(1), JSON_SAFE_INTEGER_MAX + 1).unwrap_err(),
        MeasurementProvenanceError::RendererContractVersionExceedsJsonSafeInteger
    );
    assert_eq!(
        RenderedCandidateArtifactV1::try_new(artifact(1), JSON_SAFE_INTEGER_MAX + 1).unwrap_err(),
        MeasurementProvenanceError::RenderedCandidateBytesExceedJsonSafeInteger
    );
    assert_eq!(
        MeasurementHarnessIdentityV1::try_new(artifact(1), 0).unwrap_err(),
        MeasurementProvenanceError::ZeroHarnessContractVersion
    );
    assert_eq!(
        MeasurementHarnessIdentityV1::try_new(artifact(1), JSON_SAFE_INTEGER_MAX + 1).unwrap_err(),
        MeasurementProvenanceError::HarnessContractVersionExceedsJsonSafeInteger
    );

    let missing_rendering =
        bind_hermetic_measurement_receipts_v1(baseline, environment, [], [baseline_receipt])
            .unwrap_err();
    assert_eq!(
        missing_rendering,
        HermeticRunnerError::MissingCandidateRenderings { count: 1 }
    );

    let duplicate = freeze();
    let duplicate_rendering = candidate_rendering(&duplicate.cases()[0], environment, rendered);
    let duplicate_receipt = measurement_receipt(
        &duplicate,
        &duplicate.cases()[0],
        environment,
        rendered,
        measurements(),
    );
    assert_eq!(
        bind_hermetic_measurement_receipts_v1(
            duplicate,
            environment,
            [duplicate_rendering, duplicate_rendering],
            [duplicate_receipt],
        )
        .unwrap_err(),
        HermeticRunnerError::DuplicateCandidateRendering
    );

    let extra_rendering_run = freeze();
    let valid_rendering =
        candidate_rendering(&extra_rendering_run.cases()[0], environment, rendered);
    let extra_rendering = FrozenCandidateRenderingV1::new_self_asserted(
        artifact(202),
        extra_rendering_run.cases()[0].candidate_selection_digest(),
        extra_rendering_run.cases()[0].presentation_receipt().id(),
        environment.renderer(),
        rendered,
    );
    let valid_receipt = measurement_receipt(
        &extra_rendering_run,
        &extra_rendering_run.cases()[0],
        environment,
        rendered,
        measurements(),
    );
    assert_eq!(
        bind_hermetic_measurement_receipts_v1(
            extra_rendering_run,
            environment,
            [valid_rendering, extra_rendering],
            [valid_receipt],
        )
        .unwrap_err(),
        HermeticRunnerError::ExtraCandidateRenderings { count: 1 }
    );

    let missing_receipt = freeze();
    let missing_receipt_rendering =
        candidate_rendering(&missing_receipt.cases()[0], environment, rendered);
    assert_eq!(
        bind_hermetic_measurement_receipts_v1(
            missing_receipt,
            environment,
            [missing_receipt_rendering],
            [],
        )
        .unwrap_err(),
        HermeticRunnerError::MissingMeasurementReceipts { count: 1 }
    );

    let duplicate_receipts = freeze();
    let duplicate_receipts_rendering =
        candidate_rendering(&duplicate_receipts.cases()[0], environment, rendered);
    let duplicate_receipt = measurement_receipt(
        &duplicate_receipts,
        &duplicate_receipts.cases()[0],
        environment,
        rendered,
        measurements(),
    );
    assert_eq!(
        bind_hermetic_measurement_receipts_v1(
            duplicate_receipts,
            environment,
            [duplicate_receipts_rendering],
            [duplicate_receipt, duplicate_receipt],
        )
        .unwrap_err(),
        HermeticRunnerError::DuplicateMeasurementReceipt
    );

    let extra_receipt_run = freeze();
    let valid_rendering = candidate_rendering(&extra_receipt_run.cases()[0], environment, rendered);
    let valid_receipt = measurement_receipt(
        &extra_receipt_run,
        &extra_receipt_run.cases()[0],
        environment,
        rendered,
        measurements(),
    );
    let extra_receipt = MeasurementProvenanceReceiptV1::new_self_asserted(
        extra_receipt_run.run_manifest_artifact_digest(),
        extra_receipt_run.run_identity(),
        artifact(203),
        extra_receipt_run.method(),
        extra_receipt_run.cases()[0].candidate_selection_digest(),
        extra_receipt_run.cases()[0].presentation_receipt().id(),
        environment,
        rendered,
        measurements(),
    );
    assert_eq!(
        bind_hermetic_measurement_receipts_v1(
            extra_receipt_run,
            environment,
            [valid_rendering],
            [valid_receipt, extra_receipt],
        )
        .unwrap_err(),
        HermeticRunnerError::ExtraMeasurementReceipts { count: 1 }
    );

    for variant in [
        Variant::RenderingSelection,
        Variant::RenderingPresentation,
        Variant::RenderingRendererIdentity,
        Variant::RenderingRendererVersion,
        Variant::RunManifest,
        Variant::RunIdentity,
        Variant::Method,
        Variant::Selection,
        Variant::Presentation,
        Variant::Tokenizer,
        Variant::RendererIdentity,
        Variant::RendererVersion,
        Variant::HarnessIdentity,
        Variant::HarnessVersion,
        Variant::RenderedArtifact,
        Variant::RenderedByteCount,
    ] {
        let frozen = freeze();
        let frozen_case = &frozen.cases()[0];
        let wrong_selection = FrozenCandidateSelectionDigestV1::from_bytes([0xA5; 32]);
        let wrong_presentation = evidentrail_core::PresentationReceiptId::from_bytes([0xA6; 32]);
        let rendering_renderer = CandidateRendererIdentityV1::try_new(
            if variant == Variant::RenderingRendererIdentity {
                artifact(195)
            } else {
                environment.renderer().artifact_digest()
            },
            if variant == Variant::RenderingRendererVersion {
                2
            } else {
                environment.renderer().contract_version()
            },
        )
        .unwrap();
        let rendering = FrozenCandidateRenderingV1::new_self_asserted(
            case_digest,
            if variant == Variant::RenderingSelection {
                wrong_selection
            } else {
                frozen_case.candidate_selection_digest()
            },
            if variant == Variant::RenderingPresentation {
                wrong_presentation
            } else {
                frozen_case.presentation_receipt().id()
            },
            rendering_renderer,
            rendered,
        );

        let base_identity = frozen.run_identity();
        let receipt_identity = if variant == Variant::RunIdentity {
            BenchmarkRunIdentityV1::try_new(
                Some(artifact(196)),
                Some(base_identity.build_artifact_digest()),
                Some(base_identity.dataset_artifact_digest()),
                Some(base_identity.seed()),
                Some(base_identity.budget()),
            )
            .unwrap()
        } else {
            base_identity
        };
        let receipt_renderer = CandidateRendererIdentityV1::try_new(
            if variant == Variant::RendererIdentity {
                artifact(197)
            } else {
                environment.renderer().artifact_digest()
            },
            if variant == Variant::RendererVersion {
                2
            } else {
                environment.renderer().contract_version()
            },
        )
        .unwrap();
        let receipt_harness = MeasurementHarnessIdentityV1::try_new(
            if variant == Variant::HarnessIdentity {
                artifact(198)
            } else {
                environment.harness().artifact_digest()
            },
            if variant == Variant::HarnessVersion {
                2
            } else {
                environment.harness().contract_version()
            },
        )
        .unwrap();
        let receipt_environment = MeasurementEnvironmentV1::new(
            TokenizerIdentityV1::new(if variant == Variant::Tokenizer {
                artifact(199)
            } else {
                environment.tokenizer().artifact_digest()
            }),
            receipt_renderer,
            receipt_harness,
        );
        let receipt_rendered = RenderedCandidateArtifactV1::try_new(
            if variant == Variant::RenderedArtifact {
                artifact(200)
            } else {
                rendered.artifact_digest()
            },
            if variant == Variant::RenderedByteCount {
                rendered.byte_count() + 1
            } else {
                rendered.byte_count()
            },
        )
        .unwrap();
        let receipt = MeasurementProvenanceReceiptV1::new_self_asserted(
            if variant == Variant::RunManifest {
                artifact(201)
            } else {
                frozen.run_manifest_artifact_digest()
            },
            receipt_identity,
            case_digest,
            if variant == Variant::Method {
                MethodDescriptor::new("wrong-method", "1")
            } else {
                frozen.method()
            },
            if variant == Variant::Selection {
                wrong_selection
            } else {
                frozen_case.candidate_selection_digest()
            },
            if variant == Variant::Presentation {
                wrong_presentation
            } else {
                frozen_case.presentation_receipt().id()
            },
            receipt_environment,
            receipt_rendered,
            measurements(),
        );
        let error =
            bind_hermetic_measurement_receipts_v1(frozen, environment, [rendering], [receipt])
                .unwrap_err();
        assert_eq!(error, variant.expected());
        let error_debug = format!("{error:?}").to_ascii_lowercase();
        assert!(!error_debug.contains("canary_measurement_payload"));
        assert!(!error_debug.contains("measurement query"));
    }

    let valid = freeze();
    let valid_rendering = candidate_rendering(&valid.cases()[0], environment, rendered);
    let valid_receipt = measurement_receipt(
        &valid,
        &valid.cases()[0],
        environment,
        rendered,
        measurements(),
    );
    let validated = bind_hermetic_measurement_receipts_v1(
        valid,
        environment,
        [valid_rendering],
        [valid_receipt],
    )
    .unwrap();
    assert_eq!(validated.cases()[0].receipt(), valid_receipt);
    let validated_debug = format!("{validated:?}").to_ascii_lowercase();
    for forbidden in ["annotation", "requirement", "recall", "score", "target"] {
        assert!(!validated_debug.contains(forbidden));
    }
}

#[test]
fn governed_cohort_is_exact_and_errors_remain_contentless() {
    let budget_values = [4, 64, 64, 64, 64];
    let cap = candidate_cap(budget_values);
    let case_digest = artifact(71);
    let annotation_digest = artifact(72);
    let question_digest = derive_question_digest_v1(b"");
    let ledger = build_ledger(
        70,
        &[b"CANARY_GOVERNED_PAYLOAD\n".to_vec()],
        ExpectedAcquisitionClassV1::Complete,
    );
    let case = public_case(
        74,
        &ledger,
        question_digest,
        cap,
        ExpectedAcquisitionClassV1::Complete,
    );
    let annotation = annotation(
        case_digest,
        EvidenceTargetV1::Event(ledger.events()[0].id()),
    );
    let manifest = run_manifest([case_digest], run_budget(budget_values));
    let frozen = execute_hermetic_public_run_v1(
        artifact(75),
        &manifest,
        &RawChronological,
        [HermeticPublicCaseInputV1::new(
            case_digest,
            &case,
            &ledger,
            b"",
        )],
    )
    .unwrap();
    let validated = bind_measurements(frozen, measurements());
    let governed_manifest = hidden_manifest(
        artifact(75),
        &manifest,
        [GovernedCaseArtifactBindingV1::new(
            case_digest,
            annotation_digest,
        )],
    );
    let governed = HermeticGovernedCaseInputV1::new(
        GovernedCaseArtifactBindingV1::new(case_digest, annotation_digest),
        &annotation,
        None,
    );
    assert_eq!(
        evaluate_measurement_validated_hermetic_run_v1(&validated, &governed_manifest, [])
            .unwrap_err(),
        HermeticRunnerError::MissingGovernedCaseInputs { count: 1 }
    );
    assert_eq!(
        evaluate_measurement_validated_hermetic_run_v1(
            &validated,
            &governed_manifest,
            [governed, governed],
        )
        .unwrap_err(),
        HermeticRunnerError::DuplicateGovernedCaseInput
    );
    let extra = HermeticGovernedCaseInputV1::new(
        GovernedCaseArtifactBindingV1::new(artifact(76), annotation_digest),
        &annotation,
        None,
    );
    assert_eq!(
        evaluate_measurement_validated_hermetic_run_v1(
            &validated,
            &governed_manifest,
            [governed, extra],
        )
        .unwrap_err(),
        HermeticRunnerError::ExtraGovernedCaseInputs { count: 1 }
    );
    let wrong_binding = HermeticGovernedCaseInputV1::new(
        GovernedCaseArtifactBindingV1::new(case_digest, artifact(77)),
        &annotation,
        None,
    );
    let error = evaluate_measurement_validated_hermetic_run_v1(
        &validated,
        &governed_manifest,
        [wrong_binding],
    )
    .unwrap_err();
    assert_eq!(error, HermeticRunnerError::GovernedArtifactBindingMismatch);
    assert!(!format!("{error:?}").contains("CANARY_GOVERNED_PAYLOAD"));

    let wrong_run_manifest = hidden_manifest(
        artifact(78),
        &manifest,
        [GovernedCaseArtifactBindingV1::new(
            case_digest,
            annotation_digest,
        )],
    );
    assert_eq!(
        evaluate_measurement_validated_hermetic_run_v1(
            &validated,
            &wrong_run_manifest,
            [governed],
        )
        .unwrap_err(),
        HermeticRunnerError::GovernedHiddenManifestRunMismatch
    );
}

#[test]
fn governed_evaluator_rejects_a_same_count_receipt_for_the_wrong_events() {
    let ledger = build_ledger(
        80,
        &[b"first".to_vec(), b"second".to_vec()],
        ExpectedAcquisitionClassV1::Complete,
    );
    let case_digest = artifact(81);
    let annotation_digest = artifact(82);
    let case = public_case(
        83,
        &ledger,
        question(84),
        candidate_cap([2, 64, 64, 64, 64]),
        ExpectedAcquisitionClassV1::Complete,
    );
    let annotation = annotation(
        case_digest,
        EvidenceTargetV1::Event(ledger.events()[0].id()),
    );
    let manifest = run_manifest([case_digest], run_budget([2, 64, 64, 64, 64]));
    let governed_manifest = hidden_manifest(
        artifact(85),
        &manifest,
        [GovernedCaseArtifactBindingV1::new(
            case_digest,
            annotation_digest,
        )],
    );
    let result = RawChronological
        .run(MethodInput::new(&ledger, b"", ByteBudget::new(5)))
        .unwrap();
    let wrong_receipt = PresentationReceipt::reconcile(
        &ledger,
        [
            PresentationAssignment::new(
                ledger.events()[0].id(),
                PresentationDisposition::RetainedRaw,
            ),
            PresentationAssignment::new(
                ledger.events()[1].id(),
                PresentationDisposition::ShownVerbatim,
            ),
        ],
    )
    .unwrap();

    let error = evaluate_governed_case_with_presentation_v1(
        governed_manifest
            .resolve_case_binding(GovernedCaseArtifactBindingV1::new(
                case_digest,
                annotation_digest,
            ))
            .unwrap(),
        &case,
        &annotation,
        &ledger,
        &result,
        &wrong_receipt,
        None,
    )
    .unwrap_err();
    assert_eq!(
        error.code(),
        "EVIDENTRAIL_BENCH_EVAL_PRESENTATION_RECEIPT_MISMATCH"
    );
}
