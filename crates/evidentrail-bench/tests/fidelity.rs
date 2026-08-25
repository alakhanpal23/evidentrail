use evidentrail_bench::{
    BenchmarkBudgetV1, BenchmarkRunIdentityV1, CandidateRendererIdentityV1,
    EvidentrailBenchAnnotationSpecV1, EvidentrailBenchHiddenEvaluationManifestV1, EvidentrailBenchRunManifestV1,
    EvidenceRepresentationClaimV1, EvidenceTargetV1, FrozenExternalRepresentationSubmissionV1,
    GovernedCaseArtifactBindingV1, GovernedRepresentationFidelityOutcomeV1,
    GovernedRepresentationFidelityPolicyV1, MAX_PINNED_TRANSFORMS_PER_REQUIREMENT_V1,
    MAX_REPRESENTATION_CLAIMS_V1, MeasuredCandidateResources, MeasurementEnvironmentV1,
    MeasurementHarnessIdentityV1, MethodDescriptor, NonExactFidelityDispositionV1,
    PinnedTransformedExpectationV1, RenderedCandidateArtifactV1, RepresentationFidelityErrorV1,
    RequirementFidelityPolicyV1, ReversibleEncodingIdentityV1, TokenizerIdentityV1,
    WeightedDiagnosticRequirementV1, ascii_byte_escape_v1_identity,
    derive_reversible_encoded_representation_artifact_digest_v1,
    derive_source_exact_representation_artifact_digest_v1,
    evaluate_governed_representation_fidelity_v1,
};
use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    BlockAssignment, BlockConfidence, BlockIndex, BlockState, CompletenessProof,
    DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, EventLedger, FetchBoundaries,
    FetchCompleteness, FetchCompletion, FetchIdentity, FetchTiming, FramingPolicy, LaneKey,
    LaneSequence, LedgerBuilder, PlanDigest, PlanId, PolicyAuthorization, RawEnvelopeIdentityV1,
    RawEnvelopeV1, RecordBytes, RecordState, RetrievalId, SourceIdentityDigest, SourceMember,
    SourceStream, UnixTimestampNanos,
};
use evidentrail_schema::{ArtifactDigest, EventId};
use sha2::{Digest as _, Sha256};

const TRANSFORMED_RENDERING: &[u8] = b"normalized external representation\n";
const PASSTHROUGH_ESCAPE_FIELD_PREFIX: &[u8] =
    b"\n    data_encoding: ascii_byte_escape_v1\n    data: ";

struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

fn artifact(seed: u8) -> ArtifactDigest {
    ArtifactDigest::from_bytes([seed; 32])
}

fn ledger(seed: u8, raw_events: &[&[u8]]) -> EventLedger {
    let retrieval_id = RetrievalId::from_bytes([seed; 32]);
    let plan_id = PlanId::from_bytes([seed.wrapping_add(1); 32]);
    let plan_digest = PlanDigest::from_bytes([seed.wrapping_add(2); 32]);
    let source_identity_digest = SourceIdentityDigest::from_bytes([seed.wrapping_add(3); 32]);
    let adapter = AdapterIdentity::new("fidelity-fixture", "1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let lane = LaneKey::new(
        SourceMember::new(b"fidelity-source".to_vec()).unwrap(),
        SourceStream::FileMember,
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
                    code: 91,
                }),
            )
            .unwrap(),
        )
        .unwrap()
}

fn run_manifest(public_case: ArtifactDigest) -> EvidentrailBenchRunManifestV1 {
    let budget = BenchmarkBudgetV1::try_new(
        Some(1_000_000),
        Some(64 * 1024 * 1024),
        Some(10_000_000),
        Some(10_000_000_000),
        Some(10_000_000_000),
    )
    .unwrap();
    let identity = BenchmarkRunIdentityV1::try_new(
        Some(artifact(1)),
        Some(artifact(2)),
        Some(artifact(3)),
        Some(4),
        Some(budget),
    )
    .unwrap();
    EvidentrailBenchRunManifestV1::new(identity, [public_case]).unwrap()
}

fn environment() -> MeasurementEnvironmentV1 {
    MeasurementEnvironmentV1::new(
        TokenizerIdentityV1::new(artifact(10)),
        CandidateRendererIdentityV1::try_new(artifact(11), 1).unwrap(),
        MeasurementHarnessIdentityV1::try_new(artifact(12), 1).unwrap(),
    )
}

fn submission(
    ledger: &EventLedger,
    public_case: ArtifactDigest,
    rendered_bytes: &[u8],
    claims: impl IntoIterator<Item = EvidenceRepresentationClaimV1>,
) -> Result<FrozenExternalRepresentationSubmissionV1, RepresentationFidelityErrorV1> {
    submission_for_run_artifact(artifact(13), ledger, public_case, rendered_bytes, claims)
}

fn submission_for_run_artifact(
    public_run_manifest_artifact_digest: ArtifactDigest,
    ledger: &EventLedger,
    public_case: ArtifactDigest,
    rendered_bytes: &[u8],
    claims: impl IntoIterator<Item = EvidenceRepresentationClaimV1>,
) -> Result<FrozenExternalRepresentationSubmissionV1, RepresentationFidelityErrorV1> {
    FrozenExternalRepresentationSubmissionV1::try_new_self_asserted(
        public_run_manifest_artifact_digest,
        &run_manifest(public_case),
        public_case,
        MethodDescriptor::new("external-fidelity-fixture", "1"),
        ledger,
        artifact(14),
        artifact(15),
        environment(),
        RenderedCandidateArtifactV1::try_new(
            raw_artifact_digest(rendered_bytes),
            u64::try_from(rendered_bytes.len()).unwrap(),
        )
        .unwrap(),
        rendered_bytes,
        MeasuredCandidateResources::try_new(32, 64, 128).unwrap(),
        claims,
    )
}

#[test]
fn governed_join_rejects_a_same_case_submission_from_a_foreign_public_run() {
    let ledger = ledger(20, &[b"foreign-run-canary\n"]);
    let event_id = ledger.events()[0].id();
    let public_case = artifact(21);
    let annotation = annotation(
        public_case,
        [requirement(
            1_000_000,
            [vec![EvidenceTargetV1::Event(event_id)]],
        )],
    );
    let foreign_submission = submission_for_run_artifact(
        artifact(99),
        &ledger,
        public_case,
        TRANSFORMED_RENDERING,
        [pattern(event_id, artifact(22))],
    )
    .unwrap();
    let (binding, case_join) = join(public_case);
    let policy =
        GovernedRepresentationFidelityPolicyV1::source_exact_only(binding, &annotation).unwrap();
    assert_eq!(
        evaluate_governed_representation_fidelity_v1(
            case_join,
            &annotation,
            &ledger,
            None,
            &foreign_submission,
            &policy,
        ),
        Err(RepresentationFidelityErrorV1::PublicRunManifestBindingMismatch)
    );
}

fn annotation(
    public_case: ArtifactDigest,
    requirements: impl IntoIterator<Item = WeightedDiagnosticRequirementV1>,
) -> EvidentrailBenchAnnotationSpecV1 {
    EvidentrailBenchAnnotationSpecV1::new(public_case, requirements, None, None, None, None, None)
        .unwrap()
}

fn requirement(
    weight: u64,
    alternatives: impl IntoIterator<Item = Vec<EvidenceTargetV1>>,
) -> WeightedDiagnosticRequirementV1 {
    WeightedDiagnosticRequirementV1::new(weight, alternatives).unwrap()
}

fn binding(public_case: ArtifactDigest) -> GovernedCaseArtifactBindingV1 {
    GovernedCaseArtifactBindingV1::new(public_case, artifact(200))
}

fn join(
    public_case: ArtifactDigest,
) -> (
    GovernedCaseArtifactBindingV1,
    evidentrail_bench::GovernedCaseArtifactJoinV1,
) {
    let binding = binding(public_case);
    let run_manifest = run_manifest(public_case);
    let hidden = EvidentrailBenchHiddenEvaluationManifestV1::new(
        artifact(13),
        &run_manifest,
        artifact(201),
        artifact(202),
        [binding],
    )
    .unwrap();
    (binding, hidden.resolve_case_binding(binding).unwrap())
}

fn transformed(
    event_id: EventId,
    transformed_artifact: ArtifactDigest,
) -> EvidenceRepresentationClaimV1 {
    EvidenceRepresentationClaimV1::source_validated_transformed_sample(
        event_id,
        transformed_artifact,
    )
}

fn pattern(event_id: EventId, pattern_artifact: ArtifactDigest) -> EvidenceRepresentationClaimV1 {
    EvidenceRepresentationClaimV1::pattern_only(event_id, pattern_artifact)
}

fn exact(event_id: EventId, raw: &[u8], start: u64) -> EvidenceRepresentationClaimV1 {
    let end = start
        .checked_add(u64::try_from(raw.len()).unwrap())
        .unwrap();
    EvidenceRepresentationClaimV1::source_exact_shown_verbatim(
        event_id,
        derive_source_exact_representation_artifact_digest_v1(raw).unwrap(),
        start,
        end,
    )
}

fn reversible_exact(
    event_id: EventId,
    encoded: &[u8],
    context_start: u64,
) -> EvidenceRepresentationClaimV1 {
    let identity = ascii_byte_escape_v1_identity();
    let start = context_start
        .checked_add(u64::try_from(PASSTHROUGH_ESCAPE_FIELD_PREFIX.len()).unwrap())
        .unwrap();
    let end = start
        .checked_add(u64::try_from(encoded.len()).unwrap())
        .unwrap();
    EvidenceRepresentationClaimV1::source_exact_reversible_encoding(
        event_id,
        identity,
        derive_reversible_encoded_representation_artifact_digest_v1(identity, encoded).unwrap(),
        context_start,
        start,
        end,
    )
}

fn reversible_field(encoded: &[u8]) -> Vec<u8> {
    [PASSTHROUGH_ESCAPE_FIELD_PREFIX, encoded, b"\n"].concat()
}

fn raw_artifact_digest(bytes: &[u8]) -> ArtifactDigest {
    ArtifactDigest::from_bytes(Sha256::digest(bytes).into())
}

fn score(
    outcome: GovernedRepresentationFidelityOutcomeV1,
) -> evidentrail_bench::GovernedRepresentationScoreSubmissionV1 {
    outcome.score_submission().unwrap()
}

#[test]
fn source_exact_is_byte_and_whitespace_sensitive() {
    let raw = b"ERROR  id=alpha\r\n";
    let ledger = ledger(30, &[raw]);
    let event_id = ledger.events()[0].id();
    let public_case = artifact(31);
    let annotation = annotation(
        public_case,
        [requirement(
            1_000_000,
            [vec![EvidenceTargetV1::Event(event_id)]],
        )],
    );
    let (binding, case_join) = join(public_case);
    let policy =
        GovernedRepresentationFidelityPolicyV1::source_exact_only(binding, &annotation).unwrap();
    let valid = submission(&ledger, public_case, raw, [exact(event_id, raw, 0)]).unwrap();
    let scored = score(
        evaluate_governed_representation_fidelity_v1(
            case_join,
            &annotation,
            &ledger,
            None,
            &valid,
            &policy,
        )
        .unwrap(),
    );
    assert_eq!(scored.exact_weight_ratio(), (1_000_000, 1_000_000));

    assert_eq!(
        submission(
            &ledger,
            public_case,
            b"ERROR id=alpha\n",
            [exact(event_id, b"ERROR id=alpha\n", 0)],
        ),
        Err(RepresentationFidelityErrorV1::SourceExactDigestMismatch { count: 1 })
    );
}

#[test]
fn canonical_reversible_encoding_scores_invalid_utf8_nul_crlf_and_backslashes() {
    let raw = [0xff, 0x00, b'\\', b'\r', b'\n', b'\t', b' ', b'~'];
    let encoded = br"\xff\x00\\\r\n\t ~";
    let ledger = ledger(33, &[&raw]);
    let event_id = ledger.events()[0].id();
    let public_case = artifact(34);
    let annotation = annotation(
        public_case,
        [requirement(
            1_250_000,
            [vec![EvidenceTargetV1::Event(event_id)]],
        )],
    );
    let rendered = reversible_field(encoded);
    let submission = submission(
        &ledger,
        public_case,
        &rendered,
        [reversible_exact(event_id, encoded, 0)],
    )
    .unwrap();
    let (binding, case_join) = join(public_case);
    let policy =
        GovernedRepresentationFidelityPolicyV1::source_exact_only(binding, &annotation).unwrap();
    let scored = score(
        evaluate_governed_representation_fidelity_v1(
            case_join,
            &annotation,
            &ledger,
            None,
            &submission,
            &policy,
        )
        .unwrap(),
    );
    assert_eq!(scored.exact_weight_ratio(), (1_250_000, 1_250_000));
}

#[test]
fn reversible_encoding_rejects_unknown_malformed_and_mutated_material() {
    let identity = ascii_byte_escape_v1_identity();
    assert_eq!(
        ReversibleEncodingIdentityV1::try_new(artifact(35), identity.contract_version()),
        Err(RepresentationFidelityErrorV1::UnknownReversibleEncoding)
    );
    assert_eq!(
        ReversibleEncodingIdentityV1::try_new(
            identity.artifact_digest(),
            identity.contract_version() + 1,
        ),
        Err(RepresentationFidelityErrorV1::UnknownReversibleEncoding)
    );

    let ledger = ledger(36, &[&[0xff]]);
    let event_id = ledger.events()[0].id();
    let public_case = artifact(37);
    for malformed in [
        br"\xFF".as_slice(),
        br"\x5c".as_slice(),
        br"\".as_slice(),
        b"\n".as_slice(),
    ] {
        let rendered = reversible_field(malformed);
        let data_start = u64::try_from(PASSTHROUGH_ESCAPE_FIELD_PREFIX.len()).unwrap();
        let claim = EvidenceRepresentationClaimV1::source_exact_reversible_encoding(
            event_id,
            identity,
            artifact(38),
            0,
            data_start,
            data_start + u64::try_from(malformed.len()).unwrap(),
        );
        assert_eq!(
            submission(&ledger, public_case, &rendered, [claim]),
            Err(RepresentationFidelityErrorV1::MalformedReversibleEncoding)
        );
    }

    let mutated = br"\xfe";
    let rendered = reversible_field(mutated);
    assert_eq!(
        submission(
            &ledger,
            public_case,
            &rendered,
            [reversible_exact(event_id, mutated, 0)],
        ),
        Err(RepresentationFidelityErrorV1::ReversibleDecodedBytesMismatch)
    );

    let valid = br"\xff";
    let rendered = reversible_field(valid);
    let data_start = u64::try_from(PASSTHROUGH_ESCAPE_FIELD_PREFIX.len()).unwrap();
    let wrong_digest = EvidenceRepresentationClaimV1::source_exact_reversible_encoding(
        event_id,
        identity,
        artifact(38),
        0,
        data_start,
        data_start + u64::try_from(valid.len()).unwrap(),
    );
    assert_eq!(
        submission(&ledger, public_case, &rendered, [wrong_digest]),
        Err(RepresentationFidelityErrorV1::ReversibleEncodingDigestMismatch)
    );

    let malformed_context = b"\n    data_encoding: ASCII_BYTE_ESCAPE_V1\n    data: ";
    let rendered = [malformed_context.as_slice(), valid, b"\n"].concat();
    let data_start = u64::try_from(malformed_context.len()).unwrap();
    let claim = EvidenceRepresentationClaimV1::source_exact_reversible_encoding(
        event_id,
        identity,
        derive_reversible_encoded_representation_artifact_digest_v1(identity, valid).unwrap(),
        0,
        data_start,
        data_start + u64::try_from(valid.len()).unwrap(),
    );
    assert_eq!(
        submission(&ledger, public_case, &rendered, [claim]),
        Err(RepresentationFidelityErrorV1::MalformedReversibleEncodingContext)
    );
}

#[test]
fn duplicate_identical_events_need_distinct_reversible_ranges() {
    let raw = b"dup\\\0\r\n";
    let encoded = br"dup\\\x00\r\n";
    let ledger = ledger(38, &[raw, raw]);
    let first = ledger.events()[0].id();
    let second = ledger.events()[1].id();
    let public_case = artifact(39);
    let first_field = reversible_field(encoded);
    let second_offset = u64::try_from(first_field.len()).unwrap();
    let rendered = [first_field.as_slice(), reversible_field(encoded).as_slice()].concat();
    let claims = [
        reversible_exact(first, encoded, 0),
        reversible_exact(second, encoded, second_offset),
    ];
    let valid_submission = submission(&ledger, public_case, &rendered, claims).unwrap();
    let annotation = annotation(
        public_case,
        [requirement(
            600_000,
            [vec![
                EvidenceTargetV1::Event(first),
                EvidenceTargetV1::Event(second),
            ]],
        )],
    );
    let (binding, case_join) = join(public_case);
    let policy =
        GovernedRepresentationFidelityPolicyV1::source_exact_only(binding, &annotation).unwrap();
    let scored = score(
        evaluate_governed_representation_fidelity_v1(
            case_join,
            &annotation,
            &ledger,
            None,
            &valid_submission,
            &policy,
        )
        .unwrap(),
    );
    assert_eq!(scored.exact_weight_ratio(), (600_000, 600_000));

    assert_eq!(
        submission(
            &ledger,
            public_case,
            &first_field,
            [
                reversible_exact(first, encoded, 0),
                reversible_exact(second, encoded, 0),
            ],
        ),
        Err(RepresentationFidelityErrorV1::OverlappingProvenRepresentationRanges)
    );
}

#[test]
fn empty_events_need_distinct_nonempty_field_context_proofs() {
    let ledger = ledger(39, &[b"", b""]);
    let first = ledger.events()[0].id();
    let second = ledger.events()[1].id();
    let public_case = artifact(40);
    let first_field = reversible_field(b"");
    let second_offset = u64::try_from(first_field.len()).unwrap();
    let second_field = reversible_field(b"");
    let rendered = [first_field.as_slice(), second_field.as_slice()].concat();

    let valid = submission(
        &ledger,
        public_case,
        &rendered,
        [
            reversible_exact(first, b"", 0),
            reversible_exact(second, b"", second_offset),
        ],
    )
    .unwrap();
    assert_eq!(valid.claims().len(), 2);
    assert!(valid.claims().iter().all(|claim| {
        claim
            .rendered_byte_range()
            .is_some_and(|(start, end)| start == end)
    }));

    assert_eq!(
        submission(
            &ledger,
            public_case,
            &first_field,
            [
                reversible_exact(first, b"", 0),
                reversible_exact(second, b"", 0),
            ],
        ),
        Err(RepresentationFidelityErrorV1::OverlappingProvenRepresentationRanges)
    );
}

#[test]
fn transformed_samples_require_exact_hidden_expectations_but_never_static_credit() {
    let ledger = ledger(40, &[b"item id=alpha\n", b"item id=beta\n"]);
    let alpha = ledger.events()[0].id();
    let beta = ledger.events()[1].id();
    let alpha_transform = artifact(41);
    let beta_transform = artifact(42);
    let public_case = artifact(43);
    let annotation = annotation(
        public_case,
        [requirement(
            750_000,
            [vec![
                EvidenceTargetV1::Event(alpha),
                EvidenceTargetV1::Event(beta),
            ]],
        )],
    );
    let submission = submission(
        &ledger,
        public_case,
        TRANSFORMED_RENDERING,
        [
            transformed(alpha, alpha_transform),
            transformed(beta, beta_transform),
        ],
    )
    .unwrap();
    let (binding, case_join) = join(public_case);
    let only_alpha = RequirementFidelityPolicyV1::try_new(
        [PinnedTransformedExpectationV1::new(alpha, alpha_transform)],
        NonExactFidelityDispositionV1::NeedsDownstreamVds,
        NonExactFidelityDispositionV1::Reject,
        NonExactFidelityDispositionV1::Reject,
    )
    .unwrap();
    let policy =
        GovernedRepresentationFidelityPolicyV1::try_new(binding, &annotation, [only_alpha])
            .unwrap();
    let partial = score(
        evaluate_governed_representation_fidelity_v1(
            case_join,
            &annotation,
            &ledger,
            None,
            &submission,
            &policy,
        )
        .unwrap(),
    );
    assert_eq!(partial.exact_weight_ratio(), (0, 750_000));

    let (_, full_join) = join(public_case);
    let full_rule = RequirementFidelityPolicyV1::try_new(
        [
            PinnedTransformedExpectationV1::new(alpha, alpha_transform),
            PinnedTransformedExpectationV1::new(beta, beta_transform),
        ],
        NonExactFidelityDispositionV1::NeedsDownstreamVds,
        NonExactFidelityDispositionV1::Reject,
        NonExactFidelityDispositionV1::Reject,
    )
    .unwrap();
    let full_policy =
        GovernedRepresentationFidelityPolicyV1::try_new(binding, &annotation, [full_rule]).unwrap();
    let full = evaluate_governed_representation_fidelity_v1(
        full_join,
        &annotation,
        &ledger,
        None,
        &submission,
        &full_policy,
    )
    .unwrap();
    assert!(matches!(
        full,
        GovernedRepresentationFidelityOutcomeV1::NeedsDownstreamVds(_)
    ));
    assert_eq!(
        full.score_submission(),
        Err(RepresentationFidelityErrorV1::NeedsDownstreamVds)
    );
}

#[test]
fn template_overmerge_is_rejected_by_default_or_deferred_without_credit() {
    let ledger = ledger(
        50,
        &[b"tenant=good status=ok\n", b"tenant=bad status=failed\n"],
    );
    let causal = ledger.events()[1].id();
    let public_case = artifact(51);
    let annotation = annotation(
        public_case,
        [requirement(
            900_000,
            [vec![EvidenceTargetV1::Event(causal)]],
        )],
    );
    let shared_overmerged_pattern = artifact(52);
    let submission = submission(
        &ledger,
        public_case,
        TRANSFORMED_RENDERING,
        [
            pattern(ledger.events()[0].id(), shared_overmerged_pattern),
            pattern(causal, shared_overmerged_pattern),
        ],
    )
    .unwrap();
    let (binding, case_join) = join(public_case);
    let reject =
        GovernedRepresentationFidelityPolicyV1::source_exact_only(binding, &annotation).unwrap();
    let rejected = score(
        evaluate_governed_representation_fidelity_v1(
            case_join,
            &annotation,
            &ledger,
            None,
            &submission,
            &reject,
        )
        .unwrap(),
    );
    assert_eq!(rejected.exact_weight_ratio(), (0, 900_000));

    let (_, deferred_join) = join(public_case);
    let defer_rule = RequirementFidelityPolicyV1::try_new(
        [],
        NonExactFidelityDispositionV1::Reject,
        NonExactFidelityDispositionV1::Reject,
        NonExactFidelityDispositionV1::NeedsDownstreamVds,
    )
    .unwrap();
    let defer = GovernedRepresentationFidelityPolicyV1::try_new(binding, &annotation, [defer_rule])
        .unwrap();
    let outcome = evaluate_governed_representation_fidelity_v1(
        deferred_join,
        &annotation,
        &ledger,
        None,
        &submission,
        &defer,
    )
    .unwrap();
    let GovernedRepresentationFidelityOutcomeV1::NeedsDownstreamVds(needs_vds) = outcome else {
        panic!("pattern-only fidelity must not become a score")
    };
    assert_eq!(needs_vds.unresolved_requirement_count(), 1);
    assert_eq!(
        outcome.score_submission(),
        Err(RepresentationFidelityErrorV1::NeedsDownstreamVds)
    );
}

#[test]
fn stack_trace_patterns_need_vds_while_complete_exact_bytes_can_score() {
    let raw = [
        b"Traceback (most recent call last):\n".as_slice(),
        b"  File \"worker.py\", line 7\n".as_slice(),
        b"ValueError: tenant alpha\n".as_slice(),
    ];
    let ledger = ledger(60, &raw);
    let block_index = whole_ledger_block(&ledger);
    let block_id = block_index.blocks()[0].id();
    let public_case = artifact(61);
    let annotation = annotation(
        public_case,
        [requirement(
            2_000_000,
            [vec![EvidenceTargetV1::Block(block_id)]],
        )],
    );
    let pattern_claims = ledger
        .events()
        .iter()
        .map(|event| pattern(event.id(), artifact(62)))
        .collect::<Vec<_>>();
    let pattern_submission =
        submission(&ledger, public_case, TRANSFORMED_RENDERING, pattern_claims).unwrap();
    let (binding, pattern_join) = join(public_case);
    let defer_rule = RequirementFidelityPolicyV1::try_new(
        [],
        NonExactFidelityDispositionV1::Reject,
        NonExactFidelityDispositionV1::NeedsDownstreamVds,
        NonExactFidelityDispositionV1::NeedsDownstreamVds,
    )
    .unwrap();
    let defer_policy =
        GovernedRepresentationFidelityPolicyV1::try_new(binding, &annotation, [defer_rule])
            .unwrap();
    assert!(matches!(
        evaluate_governed_representation_fidelity_v1(
            pattern_join,
            &annotation,
            &ledger,
            Some(&block_index),
            &pattern_submission,
            &defer_policy,
        )
        .unwrap(),
        GovernedRepresentationFidelityOutcomeV1::NeedsDownstreamVds(_)
    ));

    let rendered_exact = raw.concat();
    let mut exact_offset = 0_u64;
    let exact_claims = ledger
        .events()
        .iter()
        .zip(raw)
        .map(|(event, bytes)| {
            let claim = exact(event.id(), bytes, exact_offset);
            exact_offset = exact_offset
                .checked_add(u64::try_from(bytes.len()).unwrap())
                .unwrap();
            claim
        })
        .collect::<Vec<_>>();
    let exact_submission = submission(&ledger, public_case, &rendered_exact, exact_claims).unwrap();
    let (_, exact_join) = join(public_case);
    let exact_policy =
        GovernedRepresentationFidelityPolicyV1::source_exact_only(binding, &annotation).unwrap();
    let exact_score = score(
        evaluate_governed_representation_fidelity_v1(
            exact_join,
            &annotation,
            &ledger,
            Some(&block_index),
            &exact_submission,
            &exact_policy,
        )
        .unwrap(),
    );
    assert_eq!(exact_score.exact_weight_ratio(), (2_000_000, 2_000_000));
}

#[test]
fn missing_samples_cannot_be_upgraded_to_vds_or_credit() {
    let ledger = ledger(70, &[b"first\n", b"second\n"]);
    let first = ledger.events()[0].id();
    let second = ledger.events()[1].id();
    let public_case = artifact(71);
    let annotation = annotation(
        public_case,
        [requirement(
            500_000,
            [vec![
                EvidenceTargetV1::Event(first),
                EvidenceTargetV1::Event(second),
            ]],
        )],
    );
    let submission = submission(
        &ledger,
        public_case,
        TRANSFORMED_RENDERING,
        [transformed(first, artifact(72))],
    )
    .unwrap();
    let (binding, join) = join(public_case);
    let rule = RequirementFidelityPolicyV1::try_new(
        [],
        NonExactFidelityDispositionV1::Reject,
        NonExactFidelityDispositionV1::NeedsDownstreamVds,
        NonExactFidelityDispositionV1::NeedsDownstreamVds,
    )
    .unwrap();
    let policy =
        GovernedRepresentationFidelityPolicyV1::try_new(binding, &annotation, [rule]).unwrap();
    let scored = score(
        evaluate_governed_representation_fidelity_v1(
            join,
            &annotation,
            &ledger,
            None,
            &submission,
            &policy,
        )
        .unwrap(),
    );
    assert_eq!(scored.exact_weight_ratio(), (0, 500_000));
}

#[test]
fn duplicates_bounds_and_diagnostics_fail_closed() {
    let ledger = ledger(80, &[b"CANARY-secret\n", b"CANARY-secret\n"]);
    let event_id = ledger.events()[0].id();
    let duplicate_occurrence_id = ledger.events()[1].id();
    let public_case = artifact(81);
    let duplicate = [
        transformed(event_id, artifact(82)),
        transformed(event_id, artifact(83)),
    ];
    assert_eq!(
        submission(&ledger, public_case, TRANSFORMED_RENDERING, duplicate),
        Err(RepresentationFidelityErrorV1::DuplicateEventRepresentationClass)
    );

    let rendered_exact = b"CANARY-secret\n";
    assert_eq!(
        submission(
            &ledger,
            public_case,
            rendered_exact,
            [
                exact(event_id, rendered_exact, 0),
                exact(duplicate_occurrence_id, rendered_exact, 0),
            ],
        ),
        Err(RepresentationFidelityErrorV1::OverlappingProvenRepresentationRanges)
    );

    let too_many = (0..=MAX_REPRESENTATION_CLAIMS_V1)
        .map(|_| pattern(event_id, artifact(84)))
        .collect::<Vec<_>>();
    assert_eq!(
        submission(&ledger, public_case, TRANSFORMED_RENDERING, too_many),
        Err(RepresentationFidelityErrorV1::TooManyRepresentationClaims)
    );

    let expectation = PinnedTransformedExpectationV1::new(event_id, artifact(85));
    assert_eq!(
        RequirementFidelityPolicyV1::try_new(
            [expectation, expectation],
            NonExactFidelityDispositionV1::Reject,
            NonExactFidelityDispositionV1::Reject,
            NonExactFidelityDispositionV1::Reject,
        ),
        Err(RepresentationFidelityErrorV1::DuplicatePinnedTransform)
    );
    let excessive_acceptances = (0..=MAX_PINNED_TRANSFORMS_PER_REQUIREMENT_V1)
        .map(|index| {
            let mut bytes = [0_u8; 32];
            bytes[..8].copy_from_slice(&u64::try_from(index).unwrap().to_le_bytes());
            PinnedTransformedExpectationV1::new(event_id, ArtifactDigest::from_bytes(bytes))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        RequirementFidelityPolicyV1::try_new(
            excessive_acceptances,
            NonExactFidelityDispositionV1::Reject,
            NonExactFidelityDispositionV1::Reject,
            NonExactFidelityDispositionV1::Reject,
        ),
        Err(RepresentationFidelityErrorV1::TooManyPinnedTransforms)
    );

    let debug = format!(
        "{:?}",
        submission(
            &ledger,
            public_case,
            TRANSFORMED_RENDERING,
            [pattern(event_id, artifact(86))],
        )
        .unwrap()
    );
    for forbidden in ["CANARY-secret", "evt_", "artifact_sha256_", "annotation"] {
        assert!(!debug.contains(forbidden), "leaked {forbidden}: {debug}");
    }
    assert!(
        !format!("{:?}", RepresentationFidelityErrorV1::UnknownClaimedEvent)
            .contains("CANARY-secret")
    );
}

fn whole_ledger_block<'ledger>(ledger: &'ledger EventLedger) -> BlockIndex<'ledger> {
    let members = ledger
        .events()
        .iter()
        .map(|event| (event.id(), event.lane_sequence()))
        .collect::<Vec<_>>();
    BlockIndex::reconcile(
        ledger,
        [BlockAssignment::new_same_lane_v1(
            ledger.events()[0].lane().clone(),
            members,
            FramingPolicy::new(b"stack-trace-v1".to_vec(), b"1".to_vec()),
            BlockState::Reconstructed,
            BlockConfidence::High,
        )],
    )
    .unwrap()
}
