#![cfg(target_os = "macos")]

use std::error::Error as StdError;
use std::fmt;
use std::path::PathBuf;
use std::process::Command;

use evidentrail_bench::{EvidentrailBenchAnnotationSpecV1, WeightedDiagnosticRequirementV1};
use evidentrail_bench_harness::{
    CONSTRAINED_MATCHED_QUESTION_V1, CONSTRAINED_READER_CONTEXT_V1, CompactAgentViewErrorV1,
    ConstrainedMatchedCaseErrorV1, ConstrainedReaderPairErrorV1,
    ConstrainedReaderPairRepeatabilityV1, DeterministicFixtureReaderModeV1,
    DeterministicFixtureReaderV1, FirstPartyConstrainedSubprocessErrorV1,
    FirstPartyConstrainedSubprocessTargetV1, GovernedReaderTruthV1, HarnessError, HarnessLimitsV1,
    HostedReaderJsonlErrorV1, HostedReaderModelMessagesV1, LEGACY_DRAIN_PINNED_COMMIT_V1,
    MacOsTimePeakRssObserverV1, PeakRssObserverErrorV1, PinnedLegacyDrainExecutionTargetV1,
    PreparedPinnedDrainMatchedCaseErrorV1, ReaderAbstentionAssessmentV1, ReaderCauseGranularityV1,
    ReaderErrorV1, ReaderPublicInputV1, ReaderResourceCapsV1, artifact_digest_for_bytes_v1,
    compare_compact_agent_view_reader_receipts_v1, constrained_pinned_drain_public_input_v1,
    evaluate_governed_constrained_reader_pair_v1,
    execute_constrained_first_party_structured_fixture_v1, execute_constrained_reader_pair_v1,
    execute_deterministic_fixture_reader_v1, freeze_compact_compiled_agent_view_v1,
    prepare_constrained_pinned_drain_matched_case_v1, prepare_constrained_reader_input_pair_v1,
};
use evidentrail_schema::ArtifactDigest;

const CHECKOUT: &str = "/opt/evidentrail-bench/legacy-drain";
const EXECUTABLE: &str = "/opt/evidentrail-bench/legacy-drain/target/debug/legacy-drain";
const GIT_EXECUTABLE: &str = "/usr/bin/git";
const EXPECTED_BUILD_DIGEST: ArtifactDigest = ArtifactDigest::from_bytes([
    0x40, 0xa8, 0x3d, 0xb5, 0x9c, 0xf2, 0x02, 0x46, 0x38, 0x13, 0x63, 0xed, 0xdb, 0x2d, 0x27, 0xc5,
    0x6a, 0x38, 0x6d, 0x9e, 0x4d, 0xcf, 0x32, 0xac, 0x81, 0x15, 0xf5, 0x5b, 0x94, 0x45, 0xd2, 0x20,
]);

/// Exact opt-in command:
///
/// `cargo test -p evidentrail-bench-harness --test pinned_paired_reader_smoke pinned_actual_constrained_pair_runs_deterministic_reader -- --ignored --exact --nocapture --test-threads=1`
///
/// This executes only the public synthetic constrained case. It does not call
/// a hosted reader or hosted Evidentrail and emits no scalar/winner/fairness claim.
#[test]
#[ignore = "opt-in actual pinned legacy-drain plus deterministic reader; no hosted calls"]
fn pinned_actual_constrained_pair_runs_deterministic_reader() -> Result<(), PinnedReaderSmokeErrorV1>
{
    assert_checkout_state_v1()?;
    let helper = PathBuf::from(env!("CARGO_BIN_EXE_evidentrail-bench-harness-helper"));
    let cwd = std::env::current_dir().map_err(|_| PinnedReaderSmokeErrorV1::TargetUnavailable)?;
    let first_party = FirstPartyConstrainedSubprocessTargetV1::try_new(&helper, &cwd)?;
    let drain = PinnedLegacyDrainExecutionTargetV1::try_new_verified_local_checkout(
        CHECKOUT,
        EXECUTABLE,
        GIT_EXECUTABLE,
    )?;
    if drain.executable_build_artifact_digest() != EXPECTED_BUILD_DIGEST {
        return Err(PinnedReaderSmokeErrorV1::BuildArtifactMismatch);
    }
    let prepared = prepare_constrained_pinned_drain_matched_case_v1(first_party, drain)?;
    let finalized_product = prepared.try_finalize()?;
    let inputs = prepare_constrained_reader_input_pair_v1(&prepared)?;
    let raw = constrained_pinned_drain_public_input_v1()?;
    let structured = execute_constrained_first_party_structured_fixture_v1(&raw)?;
    if structured.artifact().text().as_bytes() != inputs.first_party().method_artifact().bytes() {
        return Err(PinnedReaderSmokeErrorV1::ReceiptBindingMismatch);
    }
    let compact_view = freeze_compact_compiled_agent_view_v1(
        inputs.first_party_source_receipt_artifact_digest(),
        structured.artifact(),
    )?;
    let compact_input = ReaderPublicInputV1::try_new(
        prepared.public_case().clone(),
        CONSTRAINED_MATCHED_QUESTION_V1.to_vec(),
        artifact_digest_for_bytes_v1(CONSTRAINED_READER_CONTEXT_V1),
        CONSTRAINED_READER_CONTEXT_V1.to_vec(),
        compact_view.reader_method_artifact(prepared.public_case_artifact_digest())?,
    )?;
    if inputs.drain_source_exact_citation_handle_count() != 0
        || inputs.drain_pattern_membership_promoted_to_source_exact_citations()
        || !inputs
            .drain()
            .method_artifact()
            .citation_handles()
            .is_empty()
        || inputs.contains_hidden_labels()
        || inputs.first_party_source_receipt_artifact_digest()
            != finalized_product
                .first_party_receipt()
                .submission()
                .artifact_digest()
        || inputs.drain_source_receipt_artifact_digest()
            != prepared.drain_full_membership().artifact_digest()
    {
        return Err(PinnedReaderSmokeErrorV1::ReceiptBindingMismatch);
    }
    let first_messages = HostedReaderModelMessagesV1::try_new(inputs.first_party())?;
    let drain_messages = HostedReaderModelMessagesV1::try_new(inputs.drain())?;
    if first_messages.prompt_template_artifact_digest()
        != drain_messages.prompt_template_artifact_digest()
        || first_messages.public_input_artifact_digest() != inputs.first_party().artifact_digest()
        || drain_messages.public_input_artifact_digest() != inputs.drain().artifact_digest()
    {
        return Err(PinnedReaderSmokeErrorV1::ReceiptBindingMismatch);
    }

    let observer = MacOsTimePeakRssObserverV1::try_system_v1()?;
    let reader = DeterministicFixtureReaderV1::try_new(
        helper,
        cwd,
        DeterministicFixtureReaderModeV1::Correct,
    )?;
    let caps = reader_caps_v1()?;
    let first_pair = execute_constrained_reader_pair_v1(&observer, &reader, inputs.clone(), caps)?;
    let second_pair = execute_constrained_reader_pair_v1(&observer, &reader, inputs.clone(), caps)?;
    let compact_reader =
        execute_deterministic_fixture_reader_v1(&observer, &reader, &compact_input, caps)?;
    let compact_preservation = compare_compact_agent_view_reader_receipts_v1(
        first_pair.first_party(),
        &compact_reader,
        &compact_view,
    )?;
    let repeatability =
        ConstrainedReaderPairRepeatabilityV1::try_new(&[first_pair.clone(), second_pair])?;
    if repeatability.trial_count() != 2
        || repeatability.first_party().answer_artifact_digest()
            != first_pair.first_party().answer_artifact_digest()
        || repeatability.drain().answer_artifact_digest()
            != first_pair.drain().answer_artifact_digest()
        || repeatability.reader_configuration_artifact_digest()
            != first_pair.reader_configuration_artifact_digest()
        || repeatability.caps() != caps
        || repeatability.contains_hidden_labels()
        || repeatability.contains_scalar_score_or_winner()
        || !compact_preservation.answers_preserved()
        || !compact_preservation.citation_semantics_preserved()
        || compact_preservation.hosted_reader_claimed()
        || compact_view.audit().canonical_byte_count() != 13_936
        || compact_view.audit().compact_byte_count() != 10_612
        || compact_view.audit().saved_byte_count() != 3_324
    {
        return Err(PinnedReaderSmokeErrorV1::RepeatabilityMismatch);
    }
    let governed =
        evaluate_governed_constrained_reader_pair_v1(&first_pair, &governed_truth_v1(&inputs)?)?;
    let first_score = governed.first_party().score();
    let drain_score = governed.drain().score();
    if governed.scalar_score_available()
        || governed.winner_available()
        || governed.hosted_reader_used()
        || governed.comparative_quality_or_fairness_claim()
        || !first_score.cause_code_verified()
        || !first_score.cause_granularity_verified()
        || !first_score.diagnosis_present()
        || first_score.cited_handle_count() != 2
        || first_score.valid_citation_count() != 2
        || first_score.invalid_citation_count() != 0
        || first_score.satisfied_requirement_count() != 2
        || first_score.total_requirement_count() != 2
        || first_score.satisfied_requirement_weight_micros() != 3_000_000
        || first_score.total_requirement_weight_micros() != 3_000_000
        || first_score.unsupported_claim_count() != 0
        || first_score.forbidden_claim_count() != 0
        || first_score.abstention() != ReaderAbstentionAssessmentV1::NotExercised
        || first_score.uncertainty_micros() != 125_000
        || !drain_score.cause_code_verified()
        || !drain_score.cause_granularity_verified()
        || !drain_score.diagnosis_present()
        || drain_score.cited_handle_count() != 2
        || drain_score.valid_citation_count() != 0
        || drain_score.invalid_citation_count() != 2
        || drain_score.satisfied_requirement_count() != 0
        || drain_score.total_requirement_count() != 2
        || drain_score.satisfied_requirement_weight_micros() != 0
        || drain_score.total_requirement_weight_micros() != 3_000_000
        || drain_score.unsupported_claim_count() != 0
        || drain_score.forbidden_claim_count() != 0
        || drain_score.abstention() != ReaderAbstentionAssessmentV1::NotExercised
        || drain_score.uncertainty_micros() != 125_000
        || governed.first_party().resources().wall_time_nanos() == 0
        || governed.drain().resources().wall_time_nanos() == 0
        || governed
            .first_party()
            .resources()
            .direct_process_peak_rss_bytes()
            == 0
        || governed.drain().resources().direct_process_peak_rss_bytes() == 0
    {
        return Err(PinnedReaderSmokeErrorV1::GovernedOutcomeMismatch);
    }

    println!(
        "pinned_paired_reader commit={} drain_build={} public_case={} producer_first={} producer_drain={} finalized_product={} input_pair={} first_method={} drain_method={} hosted_prompt_template={} first_model_messages={} drain_model_messages={} deterministic_reader_config={} equal_reader_caps=true repeatability={} reader_trials={} first_answer={} drain_answer={} governed_pair={} compact_view={} compact_audit={} compact_preservation={} compact_canonical_bytes={} compact_agent_bytes={} compact_saved_bytes={} compact_answer_preserved=true compact_citations_preserved=true first_cause_verified={} first_granularity_verified={} first_diagnosis_present={} first_valid_citations={} first_invalid_citations={} first_requirements_satisfied={}/{} first_weight_satisfied={}/{} drain_cause_verified={} drain_granularity_verified={} drain_diagnosis_present={} drain_valid_citations={} drain_invalid_citations={} drain_requirements_satisfied={}/{} drain_weight_satisfied={}/{} unsupported_claims=0 forbidden_claims=0 abstention=not_exercised uncertainty_micros=125000 first_prompt_bytes={} first_answer_bytes={} first_wall_nanos={} first_direct_process_peak_rss_bytes={} drain_prompt_bytes={} drain_answer_bytes={} drain_wall_nanos={} drain_direct_process_peak_rss_bytes={} drain_source_exact_citations=0 scalar=false winner=false comparative_quality_or_fairness_claim=false hosted_reader=false",
        LEGACY_DRAIN_PINNED_COMMIT_V1,
        hex(EXPECTED_BUILD_DIGEST.as_bytes()),
        hex(prepared.public_case_artifact_digest().as_bytes()),
        hex(prepared.proposal_audit().artifact_digest().as_bytes()),
        hex(prepared
            .drain_full_membership()
            .artifact_digest()
            .as_bytes()),
        hex(finalized_product.artifact_digest().as_bytes()),
        hex(inputs.artifact_digest().as_bytes()),
        hex(inputs
            .first_party()
            .method_artifact()
            .binding_artifact_digest()
            .as_bytes()),
        hex(inputs
            .drain()
            .method_artifact()
            .binding_artifact_digest()
            .as_bytes()),
        hex(first_messages.prompt_template_artifact_digest().as_bytes()),
        hex(first_messages.artifact_digest().as_bytes()),
        hex(drain_messages.artifact_digest().as_bytes()),
        hex(first_pair.reader_configuration_artifact_digest().as_bytes()),
        hex(repeatability.artifact_digest().as_bytes()),
        repeatability.trial_count(),
        hex(first_pair.first_party().answer_artifact_digest().as_bytes()),
        hex(first_pair.drain().answer_artifact_digest().as_bytes()),
        hex(governed.artifact_digest().as_bytes()),
        hex(compact_view.artifact_digest().as_bytes()),
        hex(compact_view.audit().artifact_digest().as_bytes()),
        hex(compact_preservation.artifact_digest().as_bytes()),
        compact_view.audit().canonical_byte_count(),
        compact_view.audit().compact_byte_count(),
        compact_view.audit().saved_byte_count(),
        first_score.cause_code_verified(),
        first_score.cause_granularity_verified(),
        first_score.diagnosis_present(),
        first_score.valid_citation_count(),
        first_score.invalid_citation_count(),
        first_score.satisfied_requirement_count(),
        first_score.total_requirement_count(),
        first_score.satisfied_requirement_weight_micros(),
        first_score.total_requirement_weight_micros(),
        drain_score.cause_code_verified(),
        drain_score.cause_granularity_verified(),
        drain_score.diagnosis_present(),
        drain_score.valid_citation_count(),
        drain_score.invalid_citation_count(),
        drain_score.satisfied_requirement_count(),
        drain_score.total_requirement_count(),
        drain_score.satisfied_requirement_weight_micros(),
        drain_score.total_requirement_weight_micros(),
        governed
            .first_party()
            .resources()
            .prompt_canonical_utf8_byte_tokens(),
        governed
            .first_party()
            .resources()
            .answer_canonical_utf8_byte_tokens(),
        governed.first_party().resources().wall_time_nanos(),
        governed
            .first_party()
            .resources()
            .direct_process_peak_rss_bytes(),
        governed
            .drain()
            .resources()
            .prompt_canonical_utf8_byte_tokens(),
        governed
            .drain()
            .resources()
            .answer_canonical_utf8_byte_tokens(),
        governed.drain().resources().wall_time_nanos(),
        governed.drain().resources().direct_process_peak_rss_bytes(),
    );
    assert_checkout_state_v1()?;
    Ok(())
}

fn reader_caps_v1() -> Result<ReaderResourceCapsV1, PinnedReaderSmokeErrorV1> {
    Ok(ReaderResourceCapsV1::try_new(
        HarnessLimitsV1::try_new(8 * 1024 * 1024, 1024 * 1024, 64 * 1024, 10_000_000_000)?,
        8 * 1024 * 1024,
        1024 * 1024,
        2 * 1024 * 1024 * 1024,
        1,
    )?)
}

fn governed_truth_v1(
    inputs: &evidentrail_bench_harness::ConstrainedReaderInputPairV1,
) -> Result<GovernedReaderTruthV1, PinnedReaderSmokeErrorV1> {
    let handles = inputs.first_party().method_artifact().citation_handles();
    if handles.len() < 2 {
        return Err(PinnedReaderSmokeErrorV1::ReceiptBindingMismatch);
    }
    let first = WeightedDiagnosticRequirementV1::new(1_000_000, [handles[0].targets().to_vec()])
        .map_err(|_| PinnedReaderSmokeErrorV1::DomainConstructionFailed)?;
    let mut joint = handles[0].targets().to_vec();
    joint.extend_from_slice(handles[1].targets());
    let second = WeightedDiagnosticRequirementV1::new(2_000_000, [joint])
        .map_err(|_| PinnedReaderSmokeErrorV1::DomainConstructionFailed)?;
    let annotation = EvidentrailBenchAnnotationSpecV1::new(
        inputs.public_case_artifact_digest(),
        [first, second],
        None,
        None,
        None,
        None,
        None,
    )
    .map_err(|_| PinnedReaderSmokeErrorV1::DomainConstructionFailed)?;
    Ok(GovernedReaderTruthV1::try_new(
        inputs.public_case_artifact_digest(),
        annotation,
        true,
        vec!["db_pool_exhaustion".to_owned()],
        vec![ReaderCauseGranularityV1::RootCause],
        vec![
            "connection_pressure".to_owned(),
            "requests_blocked".to_owned(),
        ],
        vec!["network_fault".to_owned()],
    )?)
}

fn assert_checkout_state_v1() -> Result<(), PinnedReaderSmokeErrorV1> {
    let head = git_stdout_v1(&["rev-parse", "HEAD"])?;
    if trim_ascii(&head) != LEGACY_DRAIN_PINNED_COMMIT_V1.as_bytes() {
        return Err(PinnedReaderSmokeErrorV1::RevisionMismatch);
    }
    if !git_stdout_v1(&["status", "--porcelain=v1", "--untracked-files=all"])?.is_empty() {
        return Err(PinnedReaderSmokeErrorV1::WorktreeDirty);
    }
    Ok(())
}

fn git_stdout_v1(arguments: &[&str]) -> Result<Vec<u8>, PinnedReaderSmokeErrorV1> {
    let output = Command::new(GIT_EXECUTABLE)
        .env_clear()
        .arg("-C")
        .arg(CHECKOUT)
        .args(arguments)
        .output()
        .map_err(|_| PinnedReaderSmokeErrorV1::GitUnavailable)?;
    if !output.status.success() {
        return Err(PinnedReaderSmokeErrorV1::GitCommandFailed);
    }
    Ok(output.stdout)
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |position| position + 1);
    &bytes[start..end]
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PinnedReaderSmokeErrorV1 {
    TargetUnavailable,
    GitUnavailable,
    GitCommandFailed,
    RevisionMismatch,
    WorktreeDirty,
    BuildArtifactMismatch,
    DomainConstructionFailed,
    ReceiptBindingMismatch,
    RepeatabilityMismatch,
    GovernedOutcomeMismatch,
    Prepared(PreparedPinnedDrainMatchedCaseErrorV1),
    FirstParty(FirstPartyConstrainedSubprocessErrorV1),
    Constrained(ConstrainedMatchedCaseErrorV1),
    Pair(ConstrainedReaderPairErrorV1),
    Reader(ReaderErrorV1),
    Harness(HarnessError),
    Observer(PeakRssObserverErrorV1),
    Hosted(HostedReaderJsonlErrorV1),
    Compact(CompactAgentViewErrorV1),
}

impl PinnedReaderSmokeErrorV1 {
    const fn code(self) -> &'static str {
        match self {
            Self::TargetUnavailable => "EVIDENTRAIL_BENCH_PINNED_READER_TARGET_UNAVAILABLE",
            Self::GitUnavailable => "EVIDENTRAIL_BENCH_PINNED_READER_GIT_UNAVAILABLE",
            Self::GitCommandFailed => "EVIDENTRAIL_BENCH_PINNED_READER_GIT_COMMAND_FAILED",
            Self::RevisionMismatch => "EVIDENTRAIL_BENCH_PINNED_READER_REVISION_MISMATCH",
            Self::WorktreeDirty => "EVIDENTRAIL_BENCH_PINNED_READER_WORKTREE_DIRTY",
            Self::BuildArtifactMismatch => {
                "EVIDENTRAIL_BENCH_PINNED_READER_BUILD_ARTIFACT_MISMATCH"
            }
            Self::DomainConstructionFailed => {
                "EVIDENTRAIL_BENCH_PINNED_READER_DOMAIN_CONSTRUCTION_FAILED"
            }
            Self::ReceiptBindingMismatch => {
                "EVIDENTRAIL_BENCH_PINNED_READER_RECEIPT_BINDING_MISMATCH"
            }
            Self::RepeatabilityMismatch => "EVIDENTRAIL_BENCH_PINNED_READER_REPEATABILITY_MISMATCH",
            Self::GovernedOutcomeMismatch => {
                "EVIDENTRAIL_BENCH_PINNED_READER_GOVERNED_OUTCOME_MISMATCH"
            }
            Self::Prepared(error) => error.code(),
            Self::FirstParty(error) => error.code(),
            Self::Constrained(error) => error.code(),
            Self::Pair(error) => error.code(),
            Self::Reader(error) => error.code(),
            Self::Harness(error) => error.code(),
            Self::Observer(error) => error.code(),
            Self::Hosted(error) => error.code(),
            Self::Compact(error) => error.code(),
        }
    }
}

impl fmt::Debug for PinnedReaderSmokeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedReaderSmokeErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for PinnedReaderSmokeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for PinnedReaderSmokeErrorV1 {}

impl From<PreparedPinnedDrainMatchedCaseErrorV1> for PinnedReaderSmokeErrorV1 {
    fn from(error: PreparedPinnedDrainMatchedCaseErrorV1) -> Self {
        Self::Prepared(error)
    }
}

impl From<FirstPartyConstrainedSubprocessErrorV1> for PinnedReaderSmokeErrorV1 {
    fn from(error: FirstPartyConstrainedSubprocessErrorV1) -> Self {
        Self::FirstParty(error)
    }
}

impl From<ConstrainedMatchedCaseErrorV1> for PinnedReaderSmokeErrorV1 {
    fn from(error: ConstrainedMatchedCaseErrorV1) -> Self {
        Self::Constrained(error)
    }
}

impl From<ConstrainedReaderPairErrorV1> for PinnedReaderSmokeErrorV1 {
    fn from(error: ConstrainedReaderPairErrorV1) -> Self {
        Self::Pair(error)
    }
}

impl From<ReaderErrorV1> for PinnedReaderSmokeErrorV1 {
    fn from(error: ReaderErrorV1) -> Self {
        Self::Reader(error)
    }
}

impl From<HarnessError> for PinnedReaderSmokeErrorV1 {
    fn from(error: HarnessError) -> Self {
        Self::Harness(error)
    }
}

impl From<PeakRssObserverErrorV1> for PinnedReaderSmokeErrorV1 {
    fn from(error: PeakRssObserverErrorV1) -> Self {
        Self::Observer(error)
    }
}

impl From<HostedReaderJsonlErrorV1> for PinnedReaderSmokeErrorV1 {
    fn from(error: HostedReaderJsonlErrorV1) -> Self {
        Self::Hosted(error)
    }
}

impl From<CompactAgentViewErrorV1> for PinnedReaderSmokeErrorV1 {
    fn from(error: CompactAgentViewErrorV1) -> Self {
        Self::Compact(error)
    }
}
