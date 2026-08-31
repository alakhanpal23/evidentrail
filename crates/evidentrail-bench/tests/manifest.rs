use std::collections::BTreeSet;

use evidentrail_bench::{
    CandidateResourceCap, EvidenceTargetV1, EvidentrailBenchAnnotationSpecV1,
    EvidentrailBenchCaseSpecV1, ExpectedAcquisitionClassV1, ManifestError,
    WeightedDiagnosticRequirementV1,
};
use evidentrail_schema::bounds::JSON_SAFE_INTEGER_MAX;
use evidentrail_schema::{ArtifactDigest, BlockId, EventId, PlanDigest, QuestionDigest};

fn artifact(seed: u8) -> ArtifactDigest {
    ArtifactDigest::from_bytes([seed; 32])
}

fn event(seed: u8) -> EvidenceTargetV1 {
    EvidenceTargetV1::Event(EventId::from_bytes([seed; 32]))
}

fn block(seed: u8) -> EvidenceTargetV1 {
    EvidenceTargetV1::Block(BlockId::from_bytes([seed; 32]))
}

fn budget(value: u64) -> CandidateResourceCap {
    CandidateResourceCap::try_new(value, value, value, value, value).unwrap()
}

fn requirement() -> WeightedDiagnosticRequirementV1 {
    WeightedDiagnosticRequirementV1::new(1_000_000, vec![vec![event(1)]]).unwrap()
}

fn case_with(
    sources: Vec<ArtifactDigest>,
    splits: Vec<ArtifactDigest>,
    leakage: Vec<ArtifactDigest>,
    budgets: Vec<CandidateResourceCap>,
) -> Result<EvidentrailBenchCaseSpecV1, ManifestError> {
    EvidentrailBenchCaseSpecV1::new(
        sources,
        QuestionDigest::from_bytes([21; 32]),
        PlanDigest::from_bytes([22; 32]),
        splits,
        leakage,
        budgets,
        ExpectedAcquisitionClassV1::Partial,
    )
}

#[test]
fn integer_weighted_requirements_canonicalize_jointly_sufficient_alternatives() {
    let event_one = event(1);
    let event_two = event(2);
    let block_one = block(1);
    let requirement = WeightedDiagnosticRequirementV1::new(
        1_250_000,
        vec![
            vec![block_one, event_one, event_one],
            vec![event_one, block_one],
            vec![event_two, event_two],
        ],
    )
    .unwrap();

    let weight: u64 = requirement.weight_micros();
    assert_eq!(weight, 1_250_000);
    assert_eq!(
        requirement.alternatives(),
        &[vec![event_one, block_one], vec![event_two]]
    );
    assert!(!requirement.is_satisfied_by(&BTreeSet::from([event_one])));
    assert!(requirement.is_satisfied_by(&BTreeSet::from([event_one, block_one])));
    assert!(requirement.is_satisfied_by(&BTreeSet::from([event_two])));
}

#[test]
fn public_case_is_canonical_and_contains_no_annotation_identity() {
    let lower_budget = budget(10);
    let upper_budget = budget(20);
    let case = EvidentrailBenchCaseSpecV1::new(
        [artifact(3), artifact(1), artifact(3), artifact(2)],
        QuestionDigest::from_bytes([40; 32]),
        PlanDigest::from_bytes([41; 32]),
        [artifact(12), artifact(11), artifact(12)],
        [artifact(22), artifact(21), artifact(22)],
        [upper_budget, lower_budget, upper_budget],
        ExpectedAcquisitionClassV1::Unknown,
    )
    .unwrap();

    assert_eq!(
        case.source_artifact_digests(),
        &[artifact(1), artifact(2), artifact(3)]
    );
    assert_eq!(case.split_artifact_digests(), &[artifact(11), artifact(12)]);
    assert_eq!(
        case.leakage_artifact_digests(),
        &[artifact(21), artifact(22)]
    );
    assert_eq!(case.budget_points(), &[lower_budget, upper_budget]);
    assert_eq!(case.question_digest(), QuestionDigest::from_bytes([40; 32]));
    assert_eq!(case.plan_digest(), PlanDigest::from_bytes([41; 32]));
    assert_eq!(
        case.expected_acquisition_class(),
        ExpectedAcquisitionClassV1::Unknown
    );
    // The public constructor/getter surface has no annotation, evidence, role,
    // cause, or fix argument. Its debug projection exposes public counts only.
    let debug = format!("{case:?}").to_ascii_lowercase();
    for hidden_field in [
        "annotation",
        "diagnostic_requirements",
        "precursor_targets",
        "symptom_targets",
        "root_cause",
        "fix",
    ] {
        assert!(!debug.contains(hidden_field));
    }
}

#[test]
fn annotation_links_to_the_public_case_and_canonicalizes_optional_roles() {
    let public_case_artifact = artifact(70);
    let annotation = EvidentrailBenchAnnotationSpecV1::new(
        public_case_artifact,
        [requirement()],
        Some(vec![block(2), event(3), block(2)]),
        None,
        Some(vec![event(8), event(7), event(8)]),
        Some(vec![event(9)]),
        Some(vec![block(10)]),
    )
    .unwrap();

    assert_eq!(
        annotation.public_case_artifact_digest(),
        public_case_artifact
    );
    assert_eq!(annotation.diagnostic_requirements(), &[requirement()]);
    assert_eq!(
        annotation.precursor_targets(),
        Some(&[event(3), block(2)][..])
    );
    assert_eq!(annotation.symptom_targets(), None);
    assert_eq!(
        annotation.supporting_targets(),
        Some(&[event(7), event(8)][..])
    );
    assert_eq!(annotation.distractor_targets(), Some(&[event(9)][..]));
    assert_eq!(annotation.unsafe_targets(), Some(&[block(10)][..]));
}

#[test]
fn manifest_constructors_reject_empty_and_out_of_bound_values() {
    assert_eq!(
        WeightedDiagnosticRequirementV1::new(0, vec![vec![event(1)]]),
        Err(ManifestError::InvalidRequirementWeightMicros)
    );
    assert_eq!(
        WeightedDiagnosticRequirementV1::new(JSON_SAFE_INTEGER_MAX + 1, vec![vec![event(1)]],),
        Err(ManifestError::InvalidRequirementWeightMicros)
    );
    assert_eq!(
        WeightedDiagnosticRequirementV1::new(1, Vec::<Vec<EvidenceTargetV1>>::new(),),
        Err(ManifestError::EmptyRequirementAlternatives)
    );
    assert_eq!(
        WeightedDiagnosticRequirementV1::new(1, vec![Vec::<EvidenceTargetV1>::new()]),
        Err(ManifestError::EmptyRequirementAlternative)
    );
    assert_eq!(
        WeightedDiagnosticRequirementV1::new(JSON_SAFE_INTEGER_MAX, vec![vec![event(1)]],)
            .unwrap()
            .weight_micros(),
        JSON_SAFE_INTEGER_MAX
    );

    assert_eq!(
        case_with(
            vec![],
            vec![artifact(2)],
            vec![artifact(3)],
            vec![budget(1)]
        ),
        Err(ManifestError::EmptySourceArtifacts)
    );
    assert_eq!(
        case_with(
            vec![artifact(1)],
            vec![],
            vec![artifact(3)],
            vec![budget(1)]
        ),
        Err(ManifestError::EmptySplitArtifacts)
    );
    assert_eq!(
        case_with(
            vec![artifact(1)],
            vec![artifact(2)],
            vec![],
            vec![budget(1)]
        ),
        Err(ManifestError::EmptyLeakageArtifacts)
    );
    assert_eq!(
        case_with(
            vec![artifact(1)],
            vec![artifact(2)],
            vec![artifact(3)],
            vec![]
        ),
        Err(ManifestError::EmptyBudgetPoints)
    );
    let unsafe_budget =
        CandidateResourceCap::try_new(JSON_SAFE_INTEGER_MAX + 1, 1, 1, 1, 1).unwrap();
    assert_eq!(
        case_with(
            vec![artifact(1)],
            vec![artifact(2)],
            vec![artifact(3)],
            vec![unsafe_budget],
        ),
        Err(ManifestError::BudgetPointExceedsJsonSafeInteger)
    );

    assert_eq!(
        EvidentrailBenchAnnotationSpecV1::new(artifact(4), [], None, None, None, None, None,),
        Err(ManifestError::EmptyDiagnosticRequirements)
    );
    assert_eq!(
        EvidentrailBenchAnnotationSpecV1::new(
            artifact(4),
            [requirement()],
            Some(vec![]),
            None,
            None,
            None,
            None,
        ),
        Err(ManifestError::EmptyRoleTargetSet)
    );
}

#[test]
fn manifest_debug_and_errors_do_not_expose_digest_or_target_canaries() {
    const CANARY: u8 = 0x5a;
    let canary_artifact = ArtifactDigest::from_bytes([CANARY; 32]);
    let canary_target = EvidenceTargetV1::Event(EventId::from_bytes([CANARY; 32]));
    let requirement = WeightedDiagnosticRequirementV1::new(1, vec![vec![canary_target]]).unwrap();
    let case = EvidentrailBenchCaseSpecV1::new(
        [canary_artifact],
        QuestionDigest::from_bytes([CANARY; 32]),
        PlanDigest::from_bytes([CANARY; 32]),
        [canary_artifact],
        [canary_artifact],
        [budget(1)],
        ExpectedAcquisitionClassV1::Complete,
    )
    .unwrap();
    let annotation = EvidentrailBenchAnnotationSpecV1::new(
        canary_artifact,
        [requirement.clone()],
        Some(vec![canary_target]),
        None,
        None,
        None,
        None,
    )
    .unwrap();

    let rendered = [
        format!("{canary_target:?}"),
        format!("{requirement:?}"),
        format!("{case:?}"),
        format!("{annotation:?}"),
        format!("{:?}", ManifestError::EmptyRoleTargetSet),
        ManifestError::EmptyRoleTargetSet.to_string(),
    ];
    for output in rendered {
        assert!(!output.contains("ZZZZ"));
        assert!(!output.contains("5a5a5a5a"));
        assert!(!output.contains("artifact_sha256_"));
        assert!(!output.contains("question_sha256_"));
        assert!(!output.contains("plan_sha256_"));
        assert!(!output.contains("evt_"));
    }
}
