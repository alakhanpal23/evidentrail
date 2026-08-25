use std::path::PathBuf;

use evidentrail_bench::{
    BenchmarkBudgetV1, BenchmarkRunIdentityV1, CandidateRendererIdentityV1,
    EvidentrailBenchAnnotationSpecV1, EvidentrailBenchCaseSpecV1, EvidentrailBenchHiddenEvaluationManifestV1,
    EvidentrailBenchRunManifestV1, EvidenceTargetV1, ExpectedAcquisitionClassV1,
    ExternalSystemResultEnvelopeV1, FrozenCandidateSelectionDigestV1,
    GovernedCaseArtifactBindingV1, GovernedRepresentationFidelityPolicyV1,
    MeasuredCandidateResources, MeasurementEnvironmentV1, MeasurementHarnessIdentityV1,
    MeasurementTrustBoundaryV1, MethodDescriptor, NonExactFidelityDispositionV1,
    PinnedTransformedExpectationV1, RenderedCandidateArtifactV1, RequirementFidelityPolicyV1,
    TokenizerIdentityV1, WeightedDiagnosticRequirementV1, candidate_resource_envelope,
    evaluate_governed_representation_fidelity_v1,
};
use evidentrail_bench_harness::{
    LEGACY_DRAIN_FULL_MEMBERSHIP_STDOUT_CAP_V1, LEGACY_DRAIN_PINNED_COMMIT_V1,
    CanonicalTokenCountProvenanceV1, ClosedEnvironmentV1, LegacyDrainAdapterModeV1,
    LegacyDrainAdapterV1, LegacyDrainFidelityBridgeErrorV1, LegacyDrainFullMembershipSupportV1,
    LegacyDrainInputAssessmentV1, LegacyDrainNormalizationErrorV1, LegacyDrainUnsupportedInputV1,
    ExecutableBuildV1, ExitCategoryV1, ExternalOutputContractV1, HarnessError,
    HarnessLimitDimensionV1, HarnessLimitsV1, HarnessTerminationCauseV1, InvocationInputContractV1,
    PeakRssProvenanceV1, PublicCaseInputBindingV1, PublicCaseResolutionTrustV1,
    PublicCaseStdinBindingV1, PublicExternalResultSubmissionV1, PublicSubprocessInvocationV1,
    SelfAssertedExternalMeasurementReceiptV1, StdinArtifactClassV1, StdinArtifactV1,
    StreamCaptureStateV1, artifact_digest_for_bytes_v1, artifact_digest_for_file_v1,
    canonical_public_case_artifact_v1, canonical_public_run_manifest_artifact_v1,
    legacy_drain_compact_method_descriptor_v1, legacy_drain_full_membership_method_descriptor_v1,
    execute_public_subprocess_v1, freeze_legacy_drain_full_membership_representation_v1,
    strict_identity_normalize_v1, strict_normalize_pinned_legacy_drain_full_membership_v1,
    strict_normalize_pinned_legacy_drain_output_v1,
};
use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    CompletenessProof, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, EventLedger,
    FetchBoundaries, FetchCompleteness, FetchCompletion, FetchIdentity, FetchTiming,
    FetchUnknownReason, LaneKey, LaneSequence, LedgerBuilder, PlanDigest, PlanId,
    PolicyAuthorization, PolicyDigest, RawEnvelopeIdentityV1, RawEnvelopeV1, RecordBytes,
    RecordState, RetrievalId, SourceIdentityDigest, SourceMember, SourceStream, UnixTimestampNanos,
};
use evidentrail_schema::{ArtifactDigest, PresentationReceiptId, QuestionDigest};

// Hermetic success-path helpers should not become timeout tests merely because
// several Rust test processes are contending for CPU. Ten seconds stays well
// below the fixture run's declared 60-second wall cap while leaving scheduling
// headroom. The dedicated timeout contract below keeps its explicit 30 ms cap.
const ORDINARY_HELPER_WALL_NANOS: u64 = 10_000_000_000;

struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

struct OmitSecondPolicy;

impl DeterministicPolicy for OmitSecondPolicy {
    fn authorize(&self, envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        if envelope.ordering().acquisition_sequence().get() == 1 {
            PolicyAuthorization::OmittedByPolicy {
                policy_digest: PolicyDigest::from_bytes([0x96; 32]),
            }
        } else {
            PolicyAuthorization::SourceExact
        }
    }
}

fn artifact(seed: u8) -> ArtifactDigest {
    ArtifactDigest::from_bytes([seed; 32])
}

fn helper_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_evidentrail-bench-harness-helper"))
}

fn explicit_cwd() -> PathBuf {
    std::env::current_dir().unwrap().canonicalize().unwrap()
}

fn budget() -> BenchmarkBudgetV1 {
    BenchmarkBudgetV1::try_new(
        Some(1_000_000),
        Some(64 * 1024 * 1024),
        Some(10_000_000),
        Some(60_000_000_000),
        Some(10_000_000_000),
    )
    .unwrap()
}

fn public_case_artifact(case: &EvidentrailBenchCaseSpecV1) -> ArtifactDigest {
    canonical_public_case_artifact_v1(case)
        .unwrap()
        .artifact_digest()
}

fn run_manifest(case: &EvidentrailBenchCaseSpecV1) -> EvidentrailBenchRunManifestV1 {
    run_manifest_with_build(case, artifact_digest_for_file_v1(&helper_path()).unwrap())
}

fn run_manifest_with_build(
    case: &EvidentrailBenchCaseSpecV1,
    build_artifact_digest: ArtifactDigest,
) -> EvidentrailBenchRunManifestV1 {
    run_manifest_with_build_and_cases(build_artifact_digest, [public_case_artifact(case)])
}

fn run_manifest_with_build_and_cases(
    build_artifact_digest: ArtifactDigest,
    cases: impl IntoIterator<Item = ArtifactDigest>,
) -> EvidentrailBenchRunManifestV1 {
    let identity = BenchmarkRunIdentityV1::try_new(
        Some(artifact(1)),
        Some(build_artifact_digest),
        Some(artifact(3)),
        Some(4),
        Some(budget()),
    )
    .unwrap();
    EvidentrailBenchRunManifestV1::new(identity, cases).unwrap()
}

fn pinned_drain_helper_manifest(case: &EvidentrailBenchCaseSpecV1) -> EvidentrailBenchRunManifestV1 {
    let identity = BenchmarkRunIdentityV1::try_new(
        Some(artifact_digest_for_bytes_v1(
            LEGACY_DRAIN_PINNED_COMMIT_V1.as_bytes(),
        )),
        Some(artifact_digest_for_file_v1(&helper_path()).unwrap()),
        Some(artifact(3)),
        Some(4),
        Some(budget()),
    )
    .unwrap();
    EvidentrailBenchRunManifestV1::new(identity, [public_case_artifact(case)]).unwrap()
}

fn limits(stdin: u64, stdout: u64, stderr: u64, wall_nanos: u64) -> HarnessLimitsV1 {
    HarnessLimitsV1::try_new(stdin, stdout, stderr, wall_nanos).unwrap()
}

fn synthetic_stdin(bytes: &[u8]) -> StdinArtifactV1 {
    StdinArtifactV1::try_new(
        StdinArtifactClassV1::HermeticSyntheticFixture,
        artifact_digest_for_bytes_v1(bytes),
        bytes.to_vec(),
    )
    .unwrap()
}

fn public_case(input: &[u8]) -> EvidentrailBenchCaseSpecV1 {
    public_case_with_sources([artifact_digest_for_bytes_v1(input)])
}

fn public_case_with_sources(
    sources: impl IntoIterator<Item = ArtifactDigest>,
) -> EvidentrailBenchCaseSpecV1 {
    EvidentrailBenchCaseSpecV1::new(
        sources,
        QuestionDigest::from_bytes([92; 32]),
        PlanDigest::from_bytes([93; 32]),
        [artifact(94)],
        [artifact(95)],
        [budget().cap()],
        ExpectedAcquisitionClassV1::Complete,
    )
    .unwrap()
}

fn program_for(manifest: &EvidentrailBenchRunManifestV1) -> ExecutableBuildV1 {
    let identity = manifest.identity();
    ExecutableBuildV1::try_new(
        identity.system_artifact_digest(),
        identity.build_artifact_digest(),
        helper_path(),
        vec!["echo".to_owned()],
        explicit_cwd(),
        ClosedEnvironmentV1::empty(),
        ExternalOutputContractV1::ExactIdentityNormalizer,
        None,
    )
    .unwrap()
}

fn bind_case_input(
    manifest: &EvidentrailBenchRunManifestV1,
    case: &EvidentrailBenchCaseSpecV1,
    stdin: StdinArtifactV1,
) -> PublicCaseInputBindingV1 {
    let ledger = source_exact_ledger(stdin.bytes());
    PublicCaseInputBindingV1::try_new_canonical(manifest, case, stdin, &ledger).unwrap()
}

fn invocation_with(
    arguments: &[&str],
    input: &[u8],
    limits: HarnessLimitsV1,
    environment: ClosedEnvironmentV1,
    cwd: PathBuf,
    output_contract: ExternalOutputContractV1,
) -> PublicSubprocessInvocationV1 {
    let case = public_case(input);
    let manifest = run_manifest(&case);
    let identity = manifest.identity();
    let program = ExecutableBuildV1::try_new(
        identity.system_artifact_digest(),
        identity.build_artifact_digest(),
        helper_path(),
        arguments.iter().map(|value| (*value).to_owned()).collect(),
        cwd,
        environment,
        output_contract,
        Some("hermetic-helper-v1".to_owned()),
    )
    .unwrap();
    let case_input = bind_case_input(&manifest, &case, synthetic_stdin(input));
    PublicSubprocessInvocationV1::try_new(
        &manifest,
        case_input,
        program,
        limits,
        InvocationInputContractV1::ByteExact,
    )
    .unwrap()
}

fn default_invocation(arguments: &[&str], input: &[u8]) -> PublicSubprocessInvocationV1 {
    invocation_with(
        arguments,
        input,
        limits(
            1024 * 1024,
            1024 * 1024,
            1024 * 1024,
            ORDINARY_HELPER_WALL_NANOS,
        ),
        ClosedEnvironmentV1::empty(),
        explicit_cwd(),
        ExternalOutputContractV1::ExactIdentityNormalizer,
    )
}

fn source_exact_ledger(raw: &[u8]) -> EventLedger {
    ledger_with_policy(raw, SourceExactPolicy)
}

fn ledger_with_policy(raw: &[u8], policy: impl DeterministicPolicy) -> EventLedger {
    ledger_with_policy_and_completeness(
        raw,
        policy,
        FetchCompleteness::complete(CompletenessProof::OtherVersioned {
            version: 1,
            code: 10,
        }),
    )
}

fn ledger_with_policy_and_completeness(
    raw: &[u8],
    policy: impl DeterministicPolicy,
    completeness: FetchCompleteness,
) -> EventLedger {
    let retrieval_id = RetrievalId::from_bytes([51; 32]);
    let plan_id = PlanId::from_bytes([52; 32]);
    let plan_digest = PlanDigest::from_bytes([93; 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([54; 32]);
    let adapter = AdapterIdentity::new("harness-test", "1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let lane = LaneKey::new(
        SourceMember::new(b"harness-synthetic-member".to_vec()).unwrap(),
        SourceStream::OtherVersioned {
            version: 1,
            code: 10,
        },
    );
    let mut builder = LedgerBuilder::new(fetch_identity.clone(), source_identity_digest, policy);
    let records = canonical_records(raw);
    for (sequence, (payload, terminator)) in records.iter().enumerate() {
        let sequence = u64::try_from(sequence).unwrap();
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
    let byte_count = u64::try_from(raw.len()).unwrap();
    let payload_byte_count = records
        .iter()
        .map(|(payload, _)| payload.len() as u64)
        .sum();
    let record_count = u64::try_from(records.len()).unwrap();
    let completion = FetchCompletion::new(
        fetch_identity,
        FetchTiming::new(UnixTimestampNanos::new(0), UnixTimestampNanos::new(1)),
        AcknowledgedCounts::new(record_count, payload_byte_count, byte_count),
        AttemptCounts::new(1, 1),
        AttemptCounts::default(),
        FetchBoundaries::default(),
        [],
        AdapterOutcome::Finished,
        [],
        completeness,
    )
    .unwrap();
    builder.seal(completion).unwrap()
}

fn canonical_records(raw: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut records = Vec::new();
    let mut start = 0;
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

#[test]
fn limits_environment_and_errors_are_checked_and_contentless() {
    assert_eq!(
        HarnessLimitsV1::try_new(0, 0, 0, 0),
        Err(HarnessError::ZeroWallDeadline)
    );
    assert_eq!(
        HarnessLimitsV1::try_new(64 * 1024 * 1024 + 1, 0, 0, 1),
        Err(HarnessError::LimitExceedsHardBound {
            dimension: HarnessLimitDimensionV1::StdinBytes,
        })
    );
    assert_eq!(
        ClosedEnvironmentV1::try_new(&["PATH"], &[("SECRET_TOKEN", "canary-secret")]),
        Err(HarnessError::EnvironmentNameNotAllowlisted)
    );
    assert_eq!(
        ClosedEnvironmentV1::try_new(&["bad-name"], &[]),
        Err(HarnessError::InvalidEnvironmentName)
    );
    let debug = format!(
        "{:?}",
        ClosedEnvironmentV1::try_new(&["SECRET_TOKEN"], &[("SECRET_TOKEN", "canary-secret")])
            .unwrap()
    );
    assert!(!debug.contains("canary-secret"));
    assert!(!format!("{:?}", HarnessError::SpawnFailed).contains("canary"));
}

#[test]
fn exact_binary_echo_preserves_invalid_utf8_nul_and_raw_artifact_digests() {
    let input = b"public\0fixture\xff\n";
    let invocation = default_invocation(&["echo-with-stderr"], input);
    let receipt = execute_public_subprocess_v1(&invocation).unwrap();

    assert_eq!(receipt.exit_category(), ExitCategoryV1::Success);
    assert!(receipt.child_reaped());
    assert_eq!(receipt.stdout().state(), StreamCaptureStateV1::Complete);
    assert_eq!(receipt.stdout().bytes(), input);
    assert_eq!(
        receipt.stdout().complete_artifact_digest(),
        Some(artifact_digest_for_bytes_v1(input))
    );
    assert_eq!(receipt.stderr().bytes(), b"synthetic-stderr\0\xff");
    assert_eq!(
        receipt.stderr().complete_artifact_digest(),
        Some(artifact_digest_for_bytes_v1(b"synthetic-stderr\0\xff"))
    );
    assert!(receipt.executable_path_digest_verified_before_spawn());
    assert!(receipt.executable_path_digest_verified_after_spawn());
}

#[test]
fn command_uses_explicit_cwd_and_closed_allowlisted_environment() {
    let cwd = explicit_cwd();
    let cwd_receipt = execute_public_subprocess_v1(&invocation_with(
        &["probe-cwd"],
        b"",
        limits(0, 4096, 4096, ORDINARY_HELPER_WALL_NANOS),
        ClosedEnvironmentV1::empty(),
        cwd.clone(),
        ExternalOutputContractV1::ExactIdentityNormalizer,
    ))
    .unwrap();
    assert_eq!(
        cwd_receipt.stdout().bytes(),
        cwd.to_string_lossy().as_bytes()
    );

    let absent = execute_public_subprocess_v1(&invocation_with(
        &["probe-env", "PATH"],
        b"",
        limits(0, 4096, 4096, ORDINARY_HELPER_WALL_NANOS),
        ClosedEnvironmentV1::empty(),
        cwd.clone(),
        ExternalOutputContractV1::ExactIdentityNormalizer,
    ))
    .unwrap();
    assert_eq!(absent.stdout().bytes(), b"<missing>");

    let allowed = ClosedEnvironmentV1::try_new(
        &["HARNESS_ALLOWED"],
        &[("HARNESS_ALLOWED", "explicit-value")],
    )
    .unwrap();
    let present = execute_public_subprocess_v1(&invocation_with(
        &["probe-env", "HARNESS_ALLOWED"],
        b"",
        limits(0, 4096, 4096, ORDINARY_HELPER_WALL_NANOS),
        allowed,
        cwd,
        ExternalOutputContractV1::ExactIdentityNormalizer,
    ))
    .unwrap();
    assert_eq!(present.stdout().bytes(), b"explicit-value");

    let shell_syntax = b"$(printf SHELL_EXPANDED)";
    let literal_argument = execute_public_subprocess_v1(&invocation_with(
        &["probe-arg", "$(printf SHELL_EXPANDED)"],
        b"",
        limits(0, 4096, 4096, ORDINARY_HELPER_WALL_NANOS),
        ClosedEnvironmentV1::empty(),
        explicit_cwd(),
        ExternalOutputContractV1::ExactIdentityNormalizer,
    ))
    .unwrap();
    assert_eq!(literal_argument.stdout().bytes(), shell_syntax);
}

#[test]
fn identity_and_public_case_bindings_fail_before_spawn() {
    let empty_case = public_case(b"");
    let manifest = run_manifest(&empty_case);
    let identity = manifest.identity();
    let wrong_program = ExecutableBuildV1::try_new(
        identity.system_artifact_digest(),
        artifact(200),
        helper_path(),
        vec!["echo".to_owned()],
        explicit_cwd(),
        ClosedEnvironmentV1::empty(),
        ExternalOutputContractV1::ExactIdentityNormalizer,
        None,
    )
    .unwrap();
    assert_eq!(
        PublicSubprocessInvocationV1::try_new(
            &manifest,
            bind_case_input(&manifest, &empty_case, synthetic_stdin(b"")),
            wrong_program,
            limits(0, 1, 1, 1),
            InvocationInputContractV1::ByteExact,
        ),
        Err(HarnessError::BuildArtifactMismatch)
    );

    let declared_wrong_build = artifact(202);
    let wrong_build_manifest = run_manifest_with_build(&empty_case, declared_wrong_build);
    let wrong_build_program = ExecutableBuildV1::try_new(
        wrong_build_manifest.identity().system_artifact_digest(),
        declared_wrong_build,
        helper_path(),
        vec!["echo".to_owned()],
        explicit_cwd(),
        ClosedEnvironmentV1::empty(),
        ExternalOutputContractV1::ExactIdentityNormalizer,
        None,
    )
    .unwrap();
    let wrong_build_invocation = PublicSubprocessInvocationV1::try_new(
        &wrong_build_manifest,
        bind_case_input(&wrong_build_manifest, &empty_case, synthetic_stdin(b"")),
        wrong_build_program,
        limits(0, 1, 1, 1_000_000),
        InvocationInputContractV1::ByteExact,
    )
    .unwrap();
    assert_eq!(
        execute_public_subprocess_v1(&wrong_build_invocation),
        Err(HarnessError::ExecutableArtifactDigestMismatch)
    );

    let invocation = default_invocation(&["echo"], b"one");
    let mut wrong_bytes = helper_path();
    wrong_bytes.set_file_name("not-the-helper");
    let wrong_path_program = ExecutableBuildV1::try_new(
        invocation.run_identity().system_artifact_digest(),
        invocation.run_identity().build_artifact_digest(),
        wrong_bytes,
        vec!["echo".to_owned()],
        explicit_cwd(),
        ClosedEnvironmentV1::empty(),
        ExternalOutputContractV1::ExactIdentityNormalizer,
        None,
    )
    .unwrap();
    let wrong_path_invocation = PublicSubprocessInvocationV1::try_new(
        &manifest,
        bind_case_input(&manifest, &empty_case, synthetic_stdin(b"")),
        wrong_path_program,
        limits(0, 1, 1, 1),
        InvocationInputContractV1::ByteExact,
    )
    .unwrap();
    assert_eq!(
        execute_public_subprocess_v1(&wrong_path_invocation),
        Err(HarnessError::ArtifactReadFailed)
    );

    assert_eq!(
        StdinArtifactV1::try_new(
            StdinArtifactClassV1::PublicCase,
            artifact(201),
            b"canary-payload".to_vec(),
        ),
        Err(HarnessError::StdinArtifactDigestMismatch)
    );

    let foreign_case = public_case(b"foreign");
    let foreign_ledger = source_exact_ledger(b"foreign");
    assert_eq!(
        PublicCaseInputBindingV1::try_new_canonical(
            &manifest,
            &foreign_case,
            synthetic_stdin(b"foreign"),
            &foreign_ledger,
        ),
        Err(HarnessError::UnknownPublicCaseArtifact)
    );
    let too_large_case = public_case(b"too-large");
    let too_large_manifest = run_manifest(&too_large_case);
    assert_eq!(
        PublicSubprocessInvocationV1::try_new(
            &too_large_manifest,
            bind_case_input(
                &too_large_manifest,
                &too_large_case,
                synthetic_stdin(b"too-large")
            ),
            program_for(&too_large_manifest),
            limits(1, 1, 1, 1),
            InvocationInputContractV1::ByteExact,
        ),
        Err(HarnessError::StdinByteCapExceeded)
    );
}

#[test]
fn public_case_stdin_is_exact_single_source_and_has_no_synthetic_bypass() {
    let case_a_bytes = b"declared case a";
    let case_b_bytes = b"declared case b";
    let case_a = public_case(case_a_bytes);
    let case_b = public_case(case_b_bytes);
    let multi_source = public_case_with_sources([
        artifact_digest_for_bytes_v1(case_a_bytes),
        artifact_digest_for_bytes_v1(case_b_bytes),
    ]);
    let manifest = run_manifest_with_build_and_cases(
        artifact_digest_for_file_v1(&helper_path()).unwrap(),
        [
            public_case_artifact(&case_a),
            public_case_artifact(&case_b),
            public_case_artifact(&multi_source),
        ],
    );
    let ledger_a = source_exact_ledger(case_a_bytes);
    let ledger_b = source_exact_ledger(case_b_bytes);

    assert_eq!(
        PublicCaseInputBindingV1::try_new_canonical(
            &manifest,
            &case_a,
            synthetic_stdin(case_b_bytes),
            &ledger_b,
        ),
        Err(HarnessError::PublicCaseStdinArtifactMismatch)
    );
    assert_eq!(
        PublicCaseInputBindingV1::try_new_canonical(
            &manifest,
            &case_b,
            synthetic_stdin(case_a_bytes),
            &ledger_a,
        ),
        Err(HarnessError::PublicCaseStdinArtifactMismatch)
    );

    assert_eq!(
        PublicCaseInputBindingV1::try_new_canonical(
            &manifest,
            &multi_source,
            synthetic_stdin(case_a_bytes),
            &ledger_a,
        ),
        Err(HarnessError::PublicCaseSourceCountUnsupported)
    );

    let public_stdin = StdinArtifactV1::try_new(
        StdinArtifactClassV1::PublicCase,
        artifact_digest_for_bytes_v1(case_a_bytes),
        case_a_bytes.to_vec(),
    )
    .unwrap();
    let public_case_input = bind_case_input(&manifest, &case_a, public_stdin);
    let public_invocation = PublicSubprocessInvocationV1::try_new(
        &manifest,
        public_case_input,
        program_for(&manifest),
        limits(1024, 1024, 1024, ORDINARY_HELPER_WALL_NANOS),
        InvocationInputContractV1::ByteExact,
    )
    .unwrap();
    let synthetic_case_input = bind_case_input(&manifest, &case_a, synthetic_stdin(case_a_bytes));
    let synthetic_invocation = PublicSubprocessInvocationV1::try_new(
        &manifest,
        synthetic_case_input,
        program_for(&manifest),
        limits(1024, 1024, 1024, ORDINARY_HELPER_WALL_NANOS),
        InvocationInputContractV1::ByteExact,
    )
    .unwrap();
    assert_eq!(
        public_invocation.case_stdin_binding(),
        PublicCaseStdinBindingV1::SingleDeclaredSourceExactArtifact
    );
    assert_eq!(
        public_invocation.case_resolution_trust(),
        PublicCaseResolutionTrustV1::CanonicalPublicCaseArtifactAndSourceExactLedger
    );
    assert_ne!(public_invocation.digest(), synthetic_invocation.digest());

    let other_case = public_case(case_a_bytes);
    let other_run = run_manifest_with_build(&other_case, artifact(97));
    let input_bound_to_other_run =
        bind_case_input(&other_run, &other_case, synthetic_stdin(case_a_bytes));
    assert_eq!(
        PublicSubprocessInvocationV1::try_new(
            &manifest,
            input_bound_to_other_run,
            program_for(&manifest),
            limits(1024, 1024, 1024, ORDINARY_HELPER_WALL_NANOS),
            InvocationInputContractV1::ByteExact,
        ),
        Err(HarnessError::CaseInputRunIdentityMismatch)
    );
}

#[test]
fn canonical_public_case_and_source_records_are_exact_and_occurrence_aware() {
    let input = b"dup\r\ndup\r\n\nfinal";
    let case = public_case(input);
    let case_artifact = canonical_public_case_artifact_v1(&case).unwrap();
    assert_eq!(
        case_artifact.artifact_digest(),
        artifact_digest_for_bytes_v1(case_artifact.bytes())
    );
    let manifest = run_manifest_with_build_and_cases(
        artifact_digest_for_file_v1(&helper_path()).unwrap(),
        [case_artifact.artifact_digest()],
    );
    let stdin = synthetic_stdin(input);
    let ledger = source_exact_ledger(input);
    let binding =
        PublicCaseInputBindingV1::try_new_canonical(&manifest, &case, stdin, &ledger).unwrap();
    let records = binding.source_record_map().records();
    assert_eq!(records.len(), 4);
    assert_eq!(
        records
            .iter()
            .map(|record| (
                record.source_record_ordinal(),
                record.source_byte_start(),
                record.payload_byte_end(),
                record.source_byte_end(),
            ))
            .collect::<Vec<_>>(),
        [
            (0, 0, 3, 5),
            (1, 5, 8, 10),
            (2, 10, 10, 11),
            (3, 11, 16, 16)
        ]
    );
    assert_eq!(
        binding
            .source_record_map()
            .exact_record_bytes(binding.stdin(), 0),
        Some(&b"dup\r\n"[..])
    );
    assert_eq!(
        records[0].exact_record_artifact_digest(),
        records[1].exact_record_artifact_digest()
    );
    assert_ne!(records[0].event_id(), records[1].event_id());

    let retained = binding
        .source_record_map()
        .legacy_drain_retained_records(binding.stdin())
        .unwrap();
    assert_eq!(
        retained
            .records()
            .iter()
            .map(|record| (record.retained_index(), record.source_record_ordinal()))
            .collect::<Vec<_>>(),
        [(0, 0), (1, 1), (2, 3)]
    );
    assert_eq!(
        retained.record_for_retained_index(1).unwrap().event_id(),
        records[1].event_id()
    );

    let wrong_ledger = source_exact_ledger(b"dup\r\ntam\r\n\nfinal");
    assert_eq!(
        PublicCaseInputBindingV1::try_new_canonical(
            &manifest,
            &case,
            synthetic_stdin(input),
            &wrong_ledger,
        ),
        Err(HarnessError::SourceRecordLedgerEventMismatch)
    );
    let one_record_case = public_case(b"dup\r\n");
    let one_record_manifest = run_manifest(&one_record_case);
    let extra_omitted_receipt_entry = ledger_with_policy(b"dup\r\nomitted\n", OmitSecondPolicy);
    assert_eq!(
        PublicCaseInputBindingV1::try_new_canonical(
            &one_record_manifest,
            &one_record_case,
            synthetic_stdin(b"dup\r\n"),
            &extra_omitted_receipt_entry,
        ),
        Err(HarnessError::SourceRecordAcquisitionReceiptMismatch)
    );
    let unknown_completion = ledger_with_policy_and_completeness(
        input,
        SourceExactPolicy,
        FetchCompleteness::unknown(FetchUnknownReason::ProviderHasNoCompletenessProof),
    );
    assert_eq!(
        PublicCaseInputBindingV1::try_new_canonical(
            &manifest,
            &case,
            synthetic_stdin(input),
            &unknown_completion,
        ),
        Err(HarnessError::PublicCaseAcquisitionClassMismatch)
    );
    let debug = format!("{binding:?}");
    for forbidden in ["dup", "final", "annotation", "gold", "root_cause"] {
        assert!(!debug.contains(forbidden), "leaked {forbidden}: {debug}");
    }
}

#[test]
fn canonical_public_run_manifest_is_derived_and_rejects_loose_manifest_pairing() {
    let input = b"public run artifact\n";
    let case = public_case(input);
    let case_digest = public_case_artifact(&case);
    let manifest = run_manifest_with_build_and_cases(
        artifact_digest_for_file_v1(&helper_path()).unwrap(),
        [case_digest],
    );
    let manifest_artifact = canonical_public_run_manifest_artifact_v1(&manifest).unwrap();
    assert_eq!(
        manifest_artifact.artifact_digest(),
        artifact_digest_for_bytes_v1(manifest_artifact.bytes())
    );

    let binding = bind_case_input(&manifest, &case, synthetic_stdin(input));
    assert_eq!(
        binding
            .canonical_public_run_manifest_artifact()
            .artifact_digest(),
        manifest_artifact.artifact_digest()
    );

    let identity = manifest.identity();
    let changed_seed_identity = BenchmarkRunIdentityV1::try_new(
        Some(identity.system_artifact_digest()),
        Some(identity.build_artifact_digest()),
        Some(identity.dataset_artifact_digest()),
        Some(identity.seed() + 1),
        Some(identity.budget()),
    )
    .unwrap();
    let changed_seed = EvidentrailBenchRunManifestV1::new(changed_seed_identity, [case_digest]).unwrap();
    let changed_build = run_manifest_with_build_and_cases(artifact(211), [case_digest]);
    let changed_cohort =
        EvidentrailBenchRunManifestV1::new(identity, [case_digest, artifact(212)]).unwrap();
    for changed in [&changed_seed, &changed_build, &changed_cohort] {
        assert_ne!(
            manifest_artifact.artifact_digest(),
            canonical_public_run_manifest_artifact_v1(changed)
                .unwrap()
                .artifact_digest()
        );
    }

    assert_eq!(
        PublicSubprocessInvocationV1::try_new(
            &changed_cohort,
            binding,
            program_for(&changed_cohort),
            limits(1024, 1024, 1024, ORDINARY_HELPER_WALL_NANOS),
            InvocationInputContractV1::ByteExact,
        ),
        Err(HarnessError::CaseInputRunManifestArtifactMismatch)
    );
    let debug = format!("{manifest_artifact:?}").to_ascii_lowercase();
    for forbidden in ["annotation", "requirement", "root_cause", "recall"] {
        assert!(!debug.contains(forbidden), "leaked {forbidden}: {debug}");
    }
}

#[test]
fn stdout_and_stderr_caps_are_bounded_and_children_are_reaped() {
    for (arguments, expected) in [
        (
            ["emit-stdout", "1048576"],
            HarnessTerminationCauseV1::StdoutByteCap,
        ),
        (
            ["emit-stderr", "1048576"],
            HarnessTerminationCauseV1::StderrByteCap,
        ),
    ] {
        let receipt = execute_public_subprocess_v1(&invocation_with(
            &arguments,
            b"",
            limits(0, 97, 97, ORDINARY_HELPER_WALL_NANOS),
            ClosedEnvironmentV1::empty(),
            explicit_cwd(),
            ExternalOutputContractV1::ExactIdentityNormalizer,
        ))
        .unwrap();
        assert_eq!(receipt.exit_category(), ExitCategoryV1::HarnessTerminated);
        assert!(receipt.termination_causes().contains(&expected));
        assert!(receipt.stdout().byte_count() <= 97);
        assert!(receipt.stderr().byte_count() <= 97);
        assert!(receipt.child_reaped());
    }

    let exact = execute_public_subprocess_v1(&invocation_with(
        &["emit-stdout", "97"],
        b"",
        limits(0, 97, 0, ORDINARY_HELPER_WALL_NANOS),
        ClosedEnvironmentV1::empty(),
        explicit_cwd(),
        ExternalOutputContractV1::ExactIdentityNormalizer,
    ))
    .unwrap();
    assert_eq!(exact.exit_category(), ExitCategoryV1::Success);
    assert_eq!(exact.stdout().state(), StreamCaptureStateV1::Complete);
    assert_eq!(exact.stdout().byte_count(), 97);
}

#[test]
fn wall_deadline_kills_and_reaps_and_nonzero_is_typed() {
    let timeout = execute_public_subprocess_v1(&invocation_with(
        &["sleep-ms", "1000"],
        b"",
        limits(0, 64, 64, 30_000_000),
        ClosedEnvironmentV1::empty(),
        explicit_cwd(),
        ExternalOutputContractV1::ExactIdentityNormalizer,
    ))
    .unwrap();
    assert_eq!(timeout.exit_category(), ExitCategoryV1::HarnessTerminated);
    assert_eq!(
        timeout.termination_causes(),
        &[HarnessTerminationCauseV1::WallDeadline]
    );
    assert!(timeout.child_reaped());

    let nonzero = execute_public_subprocess_v1(&default_invocation(&["exit", "23"], b"")).unwrap();
    assert_eq!(
        nonzero.exit_category(),
        ExitCategoryV1::Nonzero { code: 23 }
    );
    assert!(nonzero.child_reaped());
}

#[test]
fn legacy_drain_contract_is_pinned_normalizing_and_opaque() {
    let adapter = LegacyDrainAdapterV1::try_new(7).unwrap();
    assert_eq!(
        adapter.fixed_argv(),
        ["--grouper", "drain", "--format", "json", "--samples", "7"]
    );
    assert_eq!(
        adapter.assess_input(b"valid\n\xff").unwrap(),
        LegacyDrainInputAssessmentV1::Unsupported(LegacyDrainUnsupportedInputV1::InvalidUtf8)
    );
    let input = b"one\r\n  \r\ntwo\nfinal";
    let LegacyDrainInputAssessmentV1::SupportedWithNormalization(normalization) =
        adapter.assess_input(input).unwrap()
    else {
        panic!("valid UTF-8 must be explicitly normalizing");
    };
    assert_eq!(normalization.input_byte_count(), input.len() as u64);
    assert_eq!(normalization.logical_line_count(), 4);
    assert_eq!(normalization.retained_nonblank_line_count(), 3);
    assert_eq!(normalization.dropped_blank_line_count(), 1);
    assert_eq!(normalization.lf_terminator_count(), 3);
    assert_eq!(normalization.crlf_terminator_count(), 2);
    assert!(!normalization.final_lf_present());
    assert!(normalization.blank_lines_are_dropped());
    assert!(normalization.line_terminators_are_discarded());
    assert!(normalization.whitespace_may_be_tokenized_and_rejoined());
    assert!(normalization.timestamp_and_level_may_be_extracted());

    let case = public_case(input);
    let manifest = run_manifest(&case);
    let case_input = bind_case_input(&manifest, &case, synthetic_stdin(input));
    let (invocation, _) = adapter
        .build_public_invocation(
            &manifest,
            case_input,
            helper_path(),
            explicit_cwd(),
            ClosedEnvironmentV1::empty(),
            limits(input.len() as u64, 4096, 4096, ORDINARY_HELPER_WALL_NANOS),
        )
        .unwrap();
    assert_eq!(
        invocation.program().adapter_revision(),
        Some(LEGACY_DRAIN_PINNED_COMMIT_V1)
    );
    assert_eq!(
        invocation.program().output_contract(),
        ExternalOutputContractV1::OpaqueArtifactOnly
    );
    assert_eq!(
        invocation.input_contract(),
        InvocationInputContractV1::LegacyDrainRawTextKnownNormalization
    );
    let execution = execute_public_subprocess_v1(&invocation).unwrap();
    assert_eq!(
        strict_identity_normalize_v1(&execution),
        Err(HarnessError::OutputNormalizationUnsupported)
    );
    assert!(!format!("{adapter:?}").contains("hosted_evidentrail: true"));
}

#[test]
fn full_membership_arm_derives_cap_and_enforces_its_frozen_resource_envelope() {
    let input = b"INFO one\n\nWARN two\nplain three";
    let case = public_case(input);
    let manifest = run_manifest(&case);
    let full_limits = limits(
        input.len() as u64,
        LEGACY_DRAIN_FULL_MEMBERSHIP_STDOUT_CAP_V1,
        4096,
        ORDINARY_HELPER_WALL_NANOS,
    );
    let case_input = bind_case_input(&manifest, &case, synthetic_stdin(input));
    let adapter =
        LegacyDrainAdapterV1::try_new_full_membership(&manifest, &case_input, full_limits).unwrap();
    assert_eq!(adapter.mode(), LegacyDrainAdapterModeV1::FullMembershipAudit);
    assert_eq!(adapter.sample_cap(), 3);
    assert_eq!(
        adapter.fixed_argv(),
        ["--grouper", "drain", "--format", "json", "--samples", "3"]
    );
    let (invocation, _) = adapter
        .build_public_invocation(
            &manifest,
            case_input,
            helper_path(),
            explicit_cwd(),
            ClosedEnvironmentV1::empty(),
            full_limits,
        )
        .unwrap();
    assert_eq!(
        invocation.input_contract(),
        InvocationInputContractV1::LegacyDrainRawTextFullMembership
    );

    let low_output_case_input = bind_case_input(&manifest, &case, synthetic_stdin(input));
    assert_eq!(
        LegacyDrainAdapterV1::try_new_full_membership(
            &manifest,
            &low_output_case_input,
            limits(input.len() as u64, 4096, 4096, ORDINARY_HELPER_WALL_NANOS,),
        ),
        Err(HarnessError::FullMembershipStdoutCapInsufficient)
    );

    let non_ascii = "INFO café\n".as_bytes();
    let non_ascii_case = public_case(non_ascii);
    let non_ascii_manifest = run_manifest(&non_ascii_case);
    let non_ascii_input = bind_case_input(
        &non_ascii_manifest,
        &non_ascii_case,
        synthetic_stdin(non_ascii),
    );
    assert_eq!(
        LegacyDrainAdapterV1::assess_full_membership_case(&non_ascii_input).unwrap(),
        LegacyDrainFullMembershipSupportV1::UnsupportedNonAsciiUtf8
    );
    assert_eq!(
        LegacyDrainAdapterV1::try_new_full_membership(
            &non_ascii_manifest,
            &non_ascii_input,
            limits(
                non_ascii.len() as u64,
                LEGACY_DRAIN_FULL_MEMBERSHIP_STDOUT_CAP_V1,
                4096,
                ORDINARY_HELPER_WALL_NANOS,
            ),
        ),
        Err(HarnessError::FullMembershipInputNormalizationUnsupported)
    );

    let empty_case = public_case(b"");
    let empty_manifest = run_manifest(&empty_case);
    let empty_input = bind_case_input(&empty_manifest, &empty_case, synthetic_stdin(b""));
    assert_eq!(
        LegacyDrainAdapterV1::try_new_full_membership(
            &empty_manifest,
            &empty_input,
            limits(
                0,
                LEGACY_DRAIN_FULL_MEMBERSHIP_STDOUT_CAP_V1,
                4096,
                ORDINARY_HELPER_WALL_NANOS,
            ),
        ),
        Err(HarnessError::FullMembershipEmptyInput)
    );

    let identity = manifest.identity();
    let constrained_budget = BenchmarkBudgetV1::try_new(
        Some(2),
        Some(1),
        Some(identity.budget().canonical_candidate_tokens()),
        Some(identity.budget().wall_time_nanos()),
        Some(identity.budget().peak_memory_bytes()),
    )
    .unwrap();
    let constrained_identity = BenchmarkRunIdentityV1::try_new(
        Some(identity.system_artifact_digest()),
        Some(identity.build_artifact_digest()),
        Some(identity.dataset_artifact_digest()),
        Some(identity.seed()),
        Some(constrained_budget),
    )
    .unwrap();
    let constrained_manifest =
        EvidentrailBenchRunManifestV1::new(constrained_identity, [public_case_artifact(&case)]).unwrap();
    let constrained_input = bind_case_input(&constrained_manifest, &case, synthetic_stdin(input));
    assert_eq!(
        LegacyDrainAdapterV1::try_new_full_membership(
            &constrained_manifest,
            &constrained_input,
            full_limits,
        ),
        Err(HarnessError::FullMembershipCandidateBudgetInsufficient)
    );
}

#[test]
fn full_membership_normalizer_proves_occurrences_but_never_exact_evidence_credit() {
    let input =
        b"2026-08-24T12:00:00Z INFO item id=alpha\n2026-08-24T12:00:01Z INFO item id=beta\n";
    let case = public_case(input);
    let manifest = pinned_drain_helper_manifest(&case);
    let ledger = source_exact_ledger(input);
    let case_input = PublicCaseInputBindingV1::try_new_canonical(
        &manifest,
        &case,
        synthetic_stdin(input),
        &ledger,
    )
    .unwrap();
    let full_limits = limits(
        input.len() as u64,
        LEGACY_DRAIN_FULL_MEMBERSHIP_STDOUT_CAP_V1,
        4096,
        ORDINARY_HELPER_WALL_NANOS,
    );
    let adapter =
        LegacyDrainAdapterV1::try_new_full_membership(&manifest, &case_input, full_limits).unwrap();
    let (invocation, _) = adapter
        .build_public_invocation(
            &manifest,
            case_input,
            helper_path(),
            explicit_cwd(),
            ClosedEnvironmentV1::empty(),
            full_limits,
        )
        .unwrap();
    let execution = execute_public_subprocess_v1(&invocation).unwrap();
    let artifact = strict_normalize_pinned_legacy_drain_full_membership_v1(
        &invocation,
        &execution,
        Default::default(),
    )
    .unwrap();
    assert_eq!(artifact.charged_candidate_event_count(), 2);
    assert_eq!(
        artifact.charged_candidate_source_bytes(),
        input.len() as u64
    );
    assert_eq!(
        artifact.candidate_event_ids().collect::<Vec<_>>(),
        ledger
            .events()
            .iter()
            .map(|event| event.id())
            .collect::<Vec<_>>()
    );
    assert_eq!(artifact.pattern_memberships().len(), 2);
    assert_eq!(artifact.transformed_samples().len(), 2);
    assert_eq!(
        artifact.pattern_memberships()[0].group_pattern_artifact_digest(),
        artifact.pattern_memberships()[1].group_pattern_artifact_digest()
    );
    assert_ne!(
        artifact.transformed_samples()[0].transformed_sample_artifact_digest(),
        artifact.transformed_samples()[1].transformed_sample_artifact_digest()
    );
    assert!(artifact.occurrence_membership_proven());
    assert!(artifact.resource_and_compression_accounting_available());
    assert!(!artifact.diagnostic_evidence_recall_scoreable());
    assert!(!artifact.source_exact_or_shown_verbatim());
    assert!(artifact.full_execution_measurement_required());
    let rendered_candidate = RenderedCandidateArtifactV1::try_new(
        artifact.raw_stdout_artifact_digest(),
        artifact.raw_stdout_byte_count(),
    )
    .unwrap();
    let fidelity_environment = MeasurementEnvironmentV1::new(
        TokenizerIdentityV1::new(artifact_digest_for_bytes_v1(b"fidelity-tokenizer-v1")),
        CandidateRendererIdentityV1::try_new(
            artifact_digest_for_bytes_v1(b"legacy-drain-full-stdout-renderer-v1"),
            1,
        )
        .unwrap(),
        MeasurementHarnessIdentityV1::try_new(
            artifact_digest_for_bytes_v1(b"legacy-drain-full-fidelity-harness-v1"),
            1,
        )
        .unwrap(),
    );
    let fidelity_receipt = freeze_legacy_drain_full_membership_representation_v1(
        &manifest,
        &ledger,
        &execution,
        &artifact,
        fidelity_environment,
        rendered_candidate,
        CanonicalTokenCountProvenanceV1::ExternallySuppliedNotAttested { tokens: 128 },
        PeakRssProvenanceV1::ExternallySuppliedNotAttested { bytes: 4096 },
    )
    .unwrap();
    assert_eq!(
        fidelity_receipt.submission().method(),
        legacy_drain_full_membership_method_descriptor_v1()
    );
    assert_ne!(
        fidelity_receipt.submission().method(),
        legacy_drain_compact_method_descriptor_v1()
    );
    assert_eq!(
        fidelity_receipt
            .submission()
            .resources()
            .unique_candidate_event_count(),
        2
    );
    assert_eq!(
        fidelity_receipt
            .submission()
            .resources()
            .unique_candidate_source_bytes(),
        input.len() as u64
    );
    assert_eq!(fidelity_receipt.submission().claims().len(), 4);

    let public_case_artifact = public_case_artifact(&case);
    let annotation = EvidentrailBenchAnnotationSpecV1::new(
        public_case_artifact,
        [WeightedDiagnosticRequirementV1::new(
            1_000_000,
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
    let governed_binding = GovernedCaseArtifactBindingV1::new(
        public_case_artifact,
        artifact_digest_for_bytes_v1(b"fidelity-annotation-v1"),
    );
    let hidden = EvidentrailBenchHiddenEvaluationManifestV1::new(
        canonical_public_run_manifest_artifact_v1(&manifest)
            .unwrap()
            .artifact_digest(),
        &manifest,
        artifact_digest_for_bytes_v1(b"fidelity-annotation-set-v1"),
        artifact_digest_for_bytes_v1(b"fidelity-scoring-policy-v1"),
        [governed_binding],
    )
    .unwrap();
    let exact_only =
        GovernedRepresentationFidelityPolicyV1::source_exact_only(governed_binding, &annotation)
            .unwrap();
    let exact_only_score = evaluate_governed_representation_fidelity_v1(
        hidden.resolve_case_binding(governed_binding).unwrap(),
        &annotation,
        &ledger,
        None,
        fidelity_receipt.submission(),
        &exact_only,
    )
    .unwrap()
    .score_submission()
    .unwrap();
    assert_eq!(exact_only_score.exact_weight_ratio(), (0, 1_000_000));

    let expected_transform = artifact.transformed_samples()[0];
    let defer_rule = RequirementFidelityPolicyV1::try_new(
        [PinnedTransformedExpectationV1::new(
            expected_transform.event_id(),
            expected_transform.transformed_sample_artifact_digest(),
        )],
        NonExactFidelityDispositionV1::NeedsDownstreamVds,
        NonExactFidelityDispositionV1::Reject,
        NonExactFidelityDispositionV1::Reject,
    )
    .unwrap();
    let defer_policy = GovernedRepresentationFidelityPolicyV1::try_new(
        governed_binding,
        &annotation,
        [defer_rule],
    )
    .unwrap();
    let deferred = evaluate_governed_representation_fidelity_v1(
        hidden.resolve_case_binding(governed_binding).unwrap(),
        &annotation,
        &ledger,
        None,
        fidelity_receipt.submission(),
        &defer_policy,
    )
    .unwrap();
    assert_eq!(
        deferred.score_submission(),
        Err(evidentrail_bench::RepresentationFidelityErrorV1::NeedsDownstreamVds)
    );

    let compact_case_input = PublicCaseInputBindingV1::try_new_canonical(
        &manifest,
        &case,
        synthetic_stdin(input),
        &ledger,
    )
    .unwrap();
    let compact_adapter = LegacyDrainAdapterV1::try_new(2).unwrap();
    let compact_limits = limits(input.len() as u64, 4096, 4096, ORDINARY_HELPER_WALL_NANOS);
    let (compact_invocation, _) = compact_adapter
        .build_public_invocation(
            &manifest,
            compact_case_input,
            helper_path(),
            explicit_cwd(),
            ClosedEnvironmentV1::empty(),
            compact_limits,
        )
        .unwrap();
    let compact_execution = execute_public_subprocess_v1(&compact_invocation).unwrap();
    assert_eq!(
        freeze_legacy_drain_full_membership_representation_v1(
            &manifest,
            &ledger,
            &compact_execution,
            &artifact,
            fidelity_environment,
            rendered_candidate,
            CanonicalTokenCountProvenanceV1::ExternallySuppliedNotAttested { tokens: 128 },
            PeakRssProvenanceV1::ExternallySuppliedNotAttested { bytes: 4096 },
        ),
        Err(LegacyDrainFidelityBridgeErrorV1::ExecutionBindingMismatch)
    );
    let fidelity_debug = format!("{fidelity_receipt:?}").to_ascii_lowercase();
    for forbidden in ["item id=alpha", "annotation", "requirement", "recall"] {
        assert!(!fidelity_debug.contains(forbidden), "leaked {forbidden}");
    }
    assert_eq!(
        strict_normalize_pinned_legacy_drain_output_v1(&invocation, &execution, Default::default(),),
        Err(LegacyDrainNormalizationErrorV1::UnsupportedInvocation)
    );
    let debug = format!("{artifact:?}").to_ascii_lowercase();
    for forbidden in [
        "item id=alpha",
        "annotation",
        "shownverbatim: true",
        "recall: true",
    ] {
        assert!(!debug.contains(forbidden), "leaked {forbidden}: {debug}");
    }

    let tampered_input = b"2026-08-24T12:00:00Z INFO tamper\n";
    let tampered_case = public_case(tampered_input);
    let tampered_manifest = pinned_drain_helper_manifest(&tampered_case);
    let tampered_ledger = source_exact_ledger(tampered_input);
    let tampered_binding = PublicCaseInputBindingV1::try_new_canonical(
        &tampered_manifest,
        &tampered_case,
        synthetic_stdin(tampered_input),
        &tampered_ledger,
    )
    .unwrap();
    let tampered_limits = limits(
        tampered_input.len() as u64,
        LEGACY_DRAIN_FULL_MEMBERSHIP_STDOUT_CAP_V1,
        4096,
        ORDINARY_HELPER_WALL_NANOS,
    );
    let tampered_adapter = LegacyDrainAdapterV1::try_new_full_membership(
        &tampered_manifest,
        &tampered_binding,
        tampered_limits,
    )
    .unwrap();
    let (tampered_invocation, _) = tampered_adapter
        .build_public_invocation(
            &tampered_manifest,
            tampered_binding,
            helper_path(),
            explicit_cwd(),
            ClosedEnvironmentV1::empty(),
            tampered_limits,
        )
        .unwrap();
    let tampered_execution = execute_public_subprocess_v1(&tampered_invocation).unwrap();
    assert_eq!(
        strict_normalize_pinned_legacy_drain_full_membership_v1(
            &tampered_invocation,
            &tampered_execution,
            Default::default(),
        ),
        Err(LegacyDrainNormalizationErrorV1::SampleNormalizationMismatch)
    );
}

#[test]
fn score_free_submission_binds_normalized_output_and_self_asserted_measurement() {
    let input = b"synthetic selected event\n";
    let case = public_case(input);
    let manifest = run_manifest(&case);
    let public_case_artifact = public_case_artifact(&case);
    let execution = execute_public_subprocess_v1(&default_invocation(&["echo"], input)).unwrap();
    let normalized = strict_identity_normalize_v1(&execution).unwrap();
    let ledger = source_exact_ledger(input);
    let event_id = ledger.events()[0].id();
    let peak_rss = 4096;
    let resources = candidate_resource_envelope(
        &ledger,
        &[event_id],
        MeasuredCandidateResources::try_new(6, execution.wall_time_nanos(), peak_rss).unwrap(),
    )
    .unwrap();
    let environment = MeasurementEnvironmentV1::new(
        TokenizerIdentityV1::new(artifact(20)),
        CandidateRendererIdentityV1::try_new(artifact(21), 1).unwrap(),
        MeasurementHarnessIdentityV1::try_new(artifact(22), 1).unwrap(),
    );
    let rendered = RenderedCandidateArtifactV1::try_new(
        normalized.normalized_artifact_digest(),
        normalized.normalized_byte_count(),
    )
    .unwrap();
    let measurement = SelfAssertedExternalMeasurementReceiptV1::try_new(
        &execution,
        normalized,
        MethodDescriptor::new("hermetic-external-helper", "1"),
        FrozenCandidateSelectionDigestV1::from_bytes([23; 32]),
        PresentationReceiptId::from_bytes([24; 32]),
        environment,
        rendered,
        resources,
        PeakRssProvenanceV1::ExternallySuppliedNotAttested { bytes: peak_rss },
    )
    .unwrap();
    assert_eq!(
        measurement.trust_boundary(),
        MeasurementTrustBoundaryV1::SelfAssertedReproducibilityInput
    );
    assert!(
        !measurement
            .peak_rss_provenance()
            .is_independently_attested()
    );

    let result = ExternalSystemResultEnvelopeV1::new(
        execution.run_manifest_artifact_digest(),
        &manifest,
        public_case_artifact,
        normalized.raw_stdout_artifact_digest(),
        normalized.normalized_artifact_digest(),
        resources,
    )
    .unwrap();
    let submission =
        PublicExternalResultSubmissionV1::try_new(&execution, normalized, result, measurement)
            .unwrap();
    assert_eq!(submission.result(), result);

    let wrong_result = ExternalSystemResultEnvelopeV1::new(
        execution.run_manifest_artifact_digest(),
        &manifest,
        public_case_artifact,
        artifact(40),
        normalized.normalized_artifact_digest(),
        resources,
    )
    .unwrap();
    assert_eq!(
        PublicExternalResultSubmissionV1::try_new(
            &execution,
            normalized,
            wrong_result,
            measurement,
        ),
        Err(HarnessError::PublicResultBindingMismatch)
    );

    let debug = format!("{submission:?}").to_ascii_lowercase();
    for forbidden in [
        "synthetic selected event",
        "annotation",
        "requirement",
        "root_cause",
        "recall",
        "evidence target",
    ] {
        assert!(!debug.contains(forbidden), "leaked {forbidden}: {debug}");
    }
}

#[test]
fn measurement_rejects_renderer_wall_and_peak_bindings() {
    let input = b"binding fixture";
    let execution = execute_public_subprocess_v1(&default_invocation(&["echo"], input)).unwrap();
    let normalized = strict_identity_normalize_v1(&execution).unwrap();
    let ledger = source_exact_ledger(input);
    let resources = candidate_resource_envelope(
        &ledger,
        &[ledger.events()[0].id()],
        MeasuredCandidateResources::try_new(1, execution.wall_time_nanos(), 5).unwrap(),
    )
    .unwrap();
    let environment = MeasurementEnvironmentV1::new(
        TokenizerIdentityV1::new(artifact(50)),
        CandidateRendererIdentityV1::try_new(artifact(51), 1).unwrap(),
        MeasurementHarnessIdentityV1::try_new(artifact(52), 1).unwrap(),
    );
    let base_arguments = (
        MethodDescriptor::new("helper", "1"),
        FrozenCandidateSelectionDigestV1::from_bytes([53; 32]),
        PresentationReceiptId::from_bytes([54; 32]),
    );

    let wrong_rendered =
        RenderedCandidateArtifactV1::try_new(artifact(55), input.len() as u64).unwrap();
    assert_eq!(
        SelfAssertedExternalMeasurementReceiptV1::try_new(
            &execution,
            normalized,
            base_arguments.0,
            base_arguments.1,
            base_arguments.2,
            environment,
            wrong_rendered,
            resources,
            PeakRssProvenanceV1::ExternallySuppliedNotAttested { bytes: 5 },
        ),
        Err(HarnessError::MeasurementBindingMismatch)
    );

    let rendered = RenderedCandidateArtifactV1::try_new(
        normalized.normalized_artifact_digest(),
        normalized.normalized_byte_count(),
    )
    .unwrap();
    assert_eq!(
        SelfAssertedExternalMeasurementReceiptV1::try_new(
            &execution,
            normalized,
            base_arguments.0,
            base_arguments.1,
            base_arguments.2,
            environment,
            rendered,
            resources,
            PeakRssProvenanceV1::ExternallySuppliedNotAttested { bytes: 6 },
        ),
        Err(HarnessError::MeasurementBindingMismatch)
    );
}

#[test]
fn invocation_debug_omits_paths_arguments_environment_values_and_payloads() {
    let canary = "CANARY_EXTERNAL_HIDDEN_VALUE";
    let environment = ClosedEnvironmentV1::try_new(&["CANARY"], &[("CANARY", canary)]).unwrap();
    let invocation = invocation_with(
        &["echo", "CANARY_ARGUMENT"],
        b"CANARY_STDIN_PAYLOAD",
        limits(64, 64, 64, ORDINARY_HELPER_WALL_NANOS),
        environment,
        explicit_cwd(),
        ExternalOutputContractV1::ExactIdentityNormalizer,
    );
    let debug = format!("{invocation:?}");
    for forbidden in [
        canary,
        "CANARY_ARGUMENT",
        "CANARY_STDIN_PAYLOAD",
        helper_path().to_string_lossy().as_ref(),
        "annotation_artifact",
        "hidden_evaluation",
    ] {
        assert!(!debug.contains(forbidden), "leaked {forbidden}: {debug}");
    }
}

#[test]
fn file_digest_rejects_non_files() {
    assert_eq!(
        artifact_digest_for_file_v1(&explicit_cwd()),
        Err(HarnessError::ArtifactNotRegularFile)
    );
}
