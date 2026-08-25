use evidentrail_bench::{
    BenchmarkBudgetV1, BenchmarkRunIdentityDimensionV1, BenchmarkRunIdentityV1,
    CandidateResourceDimension, EvidentrailBenchHiddenEvaluationManifestV1, EvidentrailBenchRunManifestV1,
    ExternalSystemResultEnvelopeV1, GovernedCaseArtifactBindingV1, MeasuredCandidateResources,
    RunManifestError, candidate_resource_envelope,
};
use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    CompletenessProof, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, EventLedger,
    FetchBoundaries, FetchCompleteness, FetchCompletion, FetchIdentity, FetchTiming, LaneKey,
    LaneSequence, LedgerBuilder, PlanDigest, PlanId, PolicyAuthorization, RawEnvelopeIdentityV1,
    RawEnvelopeV1, RecordBytes, RecordState, RetrievalId, SourceIdentityDigest, SourceMember,
    SourceStream, UnixTimestampNanos,
};
use evidentrail_schema::ArtifactDigest;
use evidentrail_schema::bounds::JSON_SAFE_INTEGER_MAX;

struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

fn artifact(seed: u8) -> ArtifactDigest {
    ArtifactDigest::from_bytes([seed; 32])
}

fn try_budget(values: [Option<u64>; 5]) -> Result<BenchmarkBudgetV1, RunManifestError> {
    BenchmarkBudgetV1::try_new(values[0], values[1], values[2], values[3], values[4])
}

fn budget(values: [u64; 5]) -> BenchmarkBudgetV1 {
    try_budget(values.map(Some)).unwrap()
}

fn identity(
    system: u8,
    build: u8,
    dataset: u8,
    seed: u64,
    budget: BenchmarkBudgetV1,
) -> BenchmarkRunIdentityV1 {
    BenchmarkRunIdentityV1::try_new(
        Some(artifact(system)),
        Some(artifact(build)),
        Some(artifact(dataset)),
        Some(seed),
        Some(budget),
    )
    .unwrap()
}

fn run(
    system: u8,
    build: u8,
    dataset: u8,
    seed: u64,
    budget: BenchmarkBudgetV1,
    cases: &[u8],
) -> EvidentrailBenchRunManifestV1 {
    EvidentrailBenchRunManifestV1::new(
        identity(system, build, dataset, seed, budget),
        cases.iter().copied().map(artifact),
    )
    .unwrap()
}

fn one_event_ledger(raw: &[u8]) -> EventLedger {
    let retrieval_id = RetrievalId::from_bytes([81; 32]);
    let plan_id = PlanId::from_bytes([82; 32]);
    let plan_digest = PlanDigest::from_bytes([83; 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([84; 32]);
    let adapter = AdapterIdentity::new("run-manifest-fixture", "1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let lane = LaneKey::new(
        SourceMember::new(b"run-manifest-member".to_vec()).unwrap(),
        SourceStream::OtherVersioned {
            version: 1,
            code: 4,
        },
    );
    let mut builder = LedgerBuilder::new(
        fetch_identity.clone(),
        source_identity_digest,
        SourceExactPolicy,
    );
    builder
        .accept(RawEnvelopeV1::new(
            envelope_identity,
            EnvelopeOrdering::new(AcquisitionSequence::new(0), lane, LaneSequence::new(0)),
            RecordBytes::whole(raw.to_vec()),
            RecordState::Complete,
        ))
        .unwrap();

    let source_bytes = u64::try_from(raw.len()).unwrap();
    let completion = FetchCompletion::new(
        fetch_identity,
        FetchTiming::new(UnixTimestampNanos::new(0), UnixTimestampNanos::new(1)),
        AcknowledgedCounts::new(1, source_bytes, source_bytes),
        AttemptCounts::new(1, 1),
        AttemptCounts::default(),
        FetchBoundaries::default(),
        [],
        AdapterOutcome::Finished,
        [],
        FetchCompleteness::complete(CompletenessProof::OtherVersioned {
            version: 1,
            code: 4,
        }),
    )
    .unwrap();
    builder.seal(completion).unwrap()
}

#[test]
fn every_budget_dimension_is_required_and_explicit_zero_is_present() {
    let dimensions = [
        CandidateResourceDimension::UniqueCandidateEventCount,
        CandidateResourceDimension::UniqueCandidateSourceBytes,
        CandidateResourceDimension::CanonicalCandidateTokens,
        CandidateResourceDimension::WallTimeNanos,
        CandidateResourceDimension::PeakMemoryBytes,
    ];

    for (missing_index, expected_dimension) in dimensions.into_iter().enumerate() {
        let mut values = [Some(1); 5];
        values[missing_index] = None;
        assert_eq!(
            try_budget(values),
            Err(RunManifestError::MissingBudgetDimension {
                dimension: expected_dimension,
            })
        );
    }

    let zero = budget([0; 5]);
    assert_eq!(zero.unique_candidate_event_count(), 0);
    assert_eq!(zero.unique_candidate_source_bytes(), 0);
    assert_eq!(zero.canonical_candidate_tokens(), 0);
    assert_eq!(zero.wall_time_nanos(), 0);
    assert_eq!(zero.peak_memory_bytes(), 0);
}

#[test]
fn budget_and_seed_values_stay_in_the_json_exact_integer_range() {
    let dimensions = [
        CandidateResourceDimension::UniqueCandidateEventCount,
        CandidateResourceDimension::UniqueCandidateSourceBytes,
        CandidateResourceDimension::CanonicalCandidateTokens,
        CandidateResourceDimension::WallTimeNanos,
        CandidateResourceDimension::PeakMemoryBytes,
    ];
    for (overflow_index, expected_dimension) in dimensions.into_iter().enumerate() {
        let mut values = [Some(1); 5];
        values[overflow_index] = Some(JSON_SAFE_INTEGER_MAX + 1);
        assert_eq!(
            try_budget(values),
            Err(RunManifestError::BudgetDimensionExceedsJsonSafeInteger {
                dimension: expected_dimension,
            })
        );
    }

    let upper = budget([JSON_SAFE_INTEGER_MAX; 5]);
    assert_eq!(upper.peak_memory_bytes(), JSON_SAFE_INTEGER_MAX);
    assert_eq!(
        BenchmarkRunIdentityV1::try_new(
            Some(artifact(1)),
            Some(artifact(2)),
            Some(artifact(3)),
            Some(JSON_SAFE_INTEGER_MAX + 1),
            Some(upper),
        ),
        Err(RunManifestError::SeedExceedsJsonSafeInteger)
    );
    assert_eq!(
        identity(1, 2, 3, JSON_SAFE_INTEGER_MAX, upper).seed(),
        JSON_SAFE_INTEGER_MAX
    );
}

#[test]
fn every_run_identity_dimension_is_required() {
    let complete_budget = budget([1; 5]);
    let cases = [
        (
            None,
            Some(artifact(2)),
            Some(artifact(3)),
            Some(4),
            Some(complete_budget),
            BenchmarkRunIdentityDimensionV1::System,
        ),
        (
            Some(artifact(1)),
            None,
            Some(artifact(3)),
            Some(4),
            Some(complete_budget),
            BenchmarkRunIdentityDimensionV1::Build,
        ),
        (
            Some(artifact(1)),
            Some(artifact(2)),
            None,
            Some(4),
            Some(complete_budget),
            BenchmarkRunIdentityDimensionV1::Dataset,
        ),
        (
            Some(artifact(1)),
            Some(artifact(2)),
            Some(artifact(3)),
            None,
            Some(complete_budget),
            BenchmarkRunIdentityDimensionV1::Seed,
        ),
        (
            Some(artifact(1)),
            Some(artifact(2)),
            Some(artifact(3)),
            Some(4),
            None,
            BenchmarkRunIdentityDimensionV1::Budget,
        ),
    ];

    for (system, build, dataset, seed, budget, expected_dimension) in cases {
        assert_eq!(
            BenchmarkRunIdentityV1::try_new(system, build, dataset, seed, budget),
            Err(RunManifestError::MissingRunIdentityDimension {
                dimension: expected_dimension,
            })
        );
    }
}

#[test]
fn public_run_is_canonical_and_hidden_evaluation_is_a_separate_type() {
    let run_identity = identity(1, 2, 3, 4, budget([5, 6, 7, 8, 9]));
    let public = EvidentrailBenchRunManifestV1::new(
        run_identity,
        [artifact(13), artifact(11), artifact(13), artifact(12)],
    )
    .unwrap();
    assert_eq!(public.identity(), run_identity);
    assert_eq!(
        public.public_case_artifact_digests(),
        &[artifact(11), artifact(12), artifact(13)]
    );
    assert_eq!(
        EvidentrailBenchRunManifestV1::new(run_identity, []),
        Err(RunManifestError::EmptyPublicCaseArtifacts)
    );

    let hidden = EvidentrailBenchHiddenEvaluationManifestV1::new(
        artifact(20),
        &public,
        artifact(21),
        artifact(22),
        [
            GovernedCaseArtifactBindingV1::new(artifact(13), artifact(33)),
            GovernedCaseArtifactBindingV1::new(artifact(11), artifact(31)),
            GovernedCaseArtifactBindingV1::new(artifact(12), artifact(32)),
        ],
    )
    .unwrap();
    assert_eq!(hidden.public_run_manifest_artifact_digest(), artifact(20));
    assert_eq!(hidden.annotation_set_artifact_digest(), artifact(21));
    assert_eq!(hidden.scoring_spec_artifact_digest(), artifact(22));
    assert_eq!(
        hidden.case_bindings(),
        &[
            GovernedCaseArtifactBindingV1::new(artifact(11), artifact(31)),
            GovernedCaseArtifactBindingV1::new(artifact(12), artifact(32)),
            GovernedCaseArtifactBindingV1::new(artifact(13), artifact(33)),
        ]
    );

    assert_eq!(
        EvidentrailBenchHiddenEvaluationManifestV1::new(
            artifact(20),
            &public,
            artifact(21),
            artifact(22),
            [],
        ),
        Err(RunManifestError::EmptyGovernedCaseBindings)
    );
    assert_eq!(
        EvidentrailBenchHiddenEvaluationManifestV1::new(
            artifact(20),
            &public,
            artifact(21),
            artifact(22),
            [
                GovernedCaseArtifactBindingV1::new(artifact(11), artifact(31)),
                GovernedCaseArtifactBindingV1::new(artifact(12), artifact(32)),
            ],
        ),
        Err(RunManifestError::MissingGovernedCaseBindings { count: 1 })
    );
    assert_eq!(
        EvidentrailBenchHiddenEvaluationManifestV1::new(
            artifact(20),
            &public,
            artifact(21),
            artifact(22),
            [
                GovernedCaseArtifactBindingV1::new(artifact(11), artifact(31)),
                GovernedCaseArtifactBindingV1::new(artifact(12), artifact(32)),
                GovernedCaseArtifactBindingV1::new(artifact(13), artifact(33)),
                GovernedCaseArtifactBindingV1::new(artifact(14), artifact(34)),
            ],
        ),
        Err(RunManifestError::ExtraGovernedCaseBindings { count: 1 })
    );
    assert_eq!(
        EvidentrailBenchHiddenEvaluationManifestV1::new(
            artifact(20),
            &public,
            artifact(21),
            artifact(22),
            [
                GovernedCaseArtifactBindingV1::new(artifact(11), artifact(31)),
                GovernedCaseArtifactBindingV1::new(artifact(11), artifact(35)),
                GovernedCaseArtifactBindingV1::new(artifact(12), artifact(32)),
                GovernedCaseArtifactBindingV1::new(artifact(13), artifact(33)),
            ],
        ),
        Err(RunManifestError::DuplicateGovernedPublicCaseArtifact)
    );
    assert_eq!(
        EvidentrailBenchHiddenEvaluationManifestV1::new(
            artifact(20),
            &public,
            artifact(21),
            artifact(22),
            [
                GovernedCaseArtifactBindingV1::new(artifact(11), artifact(31)),
                GovernedCaseArtifactBindingV1::new(artifact(12), artifact(31)),
                GovernedCaseArtifactBindingV1::new(artifact(13), artifact(33)),
            ],
        ),
        Err(RunManifestError::DuplicateGovernedAnnotationArtifact)
    );

    // The public constructor/getter surface has no annotation, adjudication,
    // score, root-cause, or fix input. Those governed links live in `hidden`.
    let public_debug = format!("{public:?}");
    for forbidden in [
        "annotation_set_artifact_digest",
        "scoring_spec_artifact_digest",
        "score_artifact_digest",
        "root_cause",
        "fix",
    ] {
        assert!(!public_debug.contains(forbidden));
    }
}

#[test]
fn paired_runs_require_the_same_public_cohort_seed_and_exact_budget() {
    let exact_budget = budget([10, 20, 30, 40, 50]);
    let left = run(1, 2, 3, 4, exact_budget, &[11, 12]);
    let different_system_and_build = run(5, 6, 3, 4, exact_budget, &[12, 11]);
    assert_eq!(
        left.ensure_paired_comparable_with(&different_system_and_build),
        Ok(())
    );

    assert_eq!(
        left.ensure_paired_comparable_with(&run(5, 6, 7, 4, exact_budget, &[11, 12])),
        Err(RunManifestError::DatasetIdentityMismatch)
    );
    assert_eq!(
        left.ensure_paired_comparable_with(&run(5, 6, 3, 4, exact_budget, &[11, 13])),
        Err(RunManifestError::PublicCaseCohortMismatch)
    );
    assert_eq!(
        left.ensure_paired_comparable_with(&run(5, 6, 3, 9, exact_budget, &[11, 12])),
        Err(RunManifestError::SeedMismatch)
    );

    let uniformly_larger = run(5, 6, 3, 4, budget([11, 21, 31, 41, 51]), &[11, 12]);
    assert_eq!(
        left.ensure_paired_comparable_with(&uniformly_larger),
        Err(RunManifestError::BudgetMismatch)
    );

    let crossed_left = run(1, 2, 3, 4, budget([1, 2, 1, 1, 1]), &[11]);
    let crossed_right = run(5, 6, 3, 4, budget([2, 1, 1, 1, 1]), &[11]);
    assert_eq!(
        crossed_left.ensure_paired_comparable_with(&crossed_right),
        Err(RunManifestError::IncomparableBudgets)
    );
}

#[test]
fn external_result_is_score_free_case_bound_and_resource_checked() {
    let ledger = one_event_ledger(b"abc");
    let event_id = ledger.events()[0].id();
    let resources = candidate_resource_envelope(
        &ledger,
        &[event_id],
        MeasuredCandidateResources::try_new(2, 4, 5).unwrap(),
    )
    .unwrap();
    let public = run(1, 2, 3, 4, budget([1, 3, 2, 4, 5]), &[11]);
    let result = ExternalSystemResultEnvelopeV1::new(
        artifact(30),
        &public,
        artifact(11),
        artifact(31),
        artifact(32),
        resources,
    )
    .unwrap();

    assert_eq!(result.public_run_manifest_artifact_digest(), artifact(30));
    assert_eq!(result.run_identity(), public.identity());
    assert_eq!(result.public_case_artifact_digest(), artifact(11));
    assert_eq!(result.raw_output_artifact_digest(), artifact(31));
    assert_eq!(result.normalized_output_artifact_digest(), artifact(32));
    assert_eq!(result.candidate_resources(), resources);
    let debug = format!("{result:?}");
    assert!(debug.contains("contains_score: false"));
    assert!(!debug.to_ascii_lowercase().contains("annotation"));
    assert!(!debug.contains("score_artifact_digest"));
    assert!(!debug.contains("annotation_set_artifact_digest"));

    assert_eq!(
        ExternalSystemResultEnvelopeV1::new(
            artifact(30),
            &public,
            artifact(99),
            artifact(31),
            artifact(32),
            resources,
        ),
        Err(RunManifestError::UnknownPublicCaseArtifact)
    );
    let under_budget = run(1, 2, 3, 4, budget([1, 2, 2, 4, 5]), &[11]);
    assert_eq!(
        ExternalSystemResultEnvelopeV1::new(
            artifact(30),
            &under_budget,
            artifact(11),
            artifact(31),
            artifact(32),
            resources,
        ),
        Err(RunManifestError::CandidateResourceCapExceeded)
    );
}

#[test]
fn run_diagnostics_do_not_expose_identity_or_output_canaries() {
    const CANARY: u8 = 0x5a;
    let canary = artifact(CANARY);
    let run_identity = BenchmarkRunIdentityV1::try_new(
        Some(canary),
        Some(canary),
        Some(canary),
        Some(5_555),
        Some(budget([5_555; 5])),
    )
    .unwrap();
    let public = EvidentrailBenchRunManifestV1::new(run_identity, [canary]).unwrap();
    let hidden = EvidentrailBenchHiddenEvaluationManifestV1::new(
        canary,
        &public,
        canary,
        canary,
        [GovernedCaseArtifactBindingV1::new(canary, artifact(91))],
    )
    .unwrap();

    let rendered = [
        format!("{run_identity:?}"),
        format!("{public:?}"),
        format!("{hidden:?}"),
        format!(
            "{:?}",
            RunManifestError::MissingBudgetDimension {
                dimension: CandidateResourceDimension::WallTimeNanos,
            }
        ),
        RunManifestError::IncomparableBudgets.to_string(),
    ];
    for output in rendered {
        assert!(!output.contains("ZZZZ"));
        assert!(!output.contains("5a5a5a5a"));
        assert!(!output.contains("artifact_sha256_"));
        assert!(!output.contains("5555"));
    }
}
