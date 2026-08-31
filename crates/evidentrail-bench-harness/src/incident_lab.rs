use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_cli::{StdinBriefModeV1, StdinBriefOutcomeV1, compile_explicit_stdin_v1};
use evidentrail_core::UnixTimestampNanos;
use evidentrail_schema::ArtifactDigest;
use serde::{Deserialize, Serialize};

use crate::process::{RawSubprocessSpecV1, execute_raw_subprocess_v1};
use crate::{
    ExecutableBuildV1, ExitCategoryV1, HarnessLimitsV1, StdinDeliveryV1, StreamCaptureStateV1,
    artifact_digest_for_bytes_v1,
};

pub const EXECUTABLE_INCIDENT_LAB_CONTRACT_VERSION_V1: u16 = 1;

const INCIDENT_CASE_DOMAIN_V1: &[u8] = b"evidentrail/bench-harness/executable-incident-case/v1";
const INCIDENT_RUN_DOMAIN_V1: &[u8] = b"evidentrail/bench-harness/executable-incident-run/v1";
const INCIDENT_FREEZE_DOMAIN_V1: &[u8] = b"evidentrail/bench-harness/executable-incident-freeze/v1";
const INCIDENT_ARM_DOMAIN_V1: &[u8] = b"evidentrail/bench-harness/executable-incident-arm/v1";
const INCIDENT_AGENT_PROMPT_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/incident-agent-prompt/v1";
const INCIDENT_AGENT_RECEIPT_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/incident-agent-receipt/v1";
const INCIDENT_VERIFIER_DOMAIN_V1: &[u8] = b"evidentrail/bench-harness/incident-verifier/v1";
const INCIDENT_TRUTH_DOMAIN_V1: &[u8] = b"evidentrail/bench-harness/incident-truth/v1";

const MAX_INCIDENT_QUESTION_BYTES_V1: usize = 64 * 1024;
const MAX_INCIDENT_CONTEXT_BYTES_V1: usize = 4 * 1024 * 1024;
const MAX_INCIDENT_PATCH_BYTES_V1: usize = 1024 * 1024;
const MAX_INCIDENT_ALIASES_V1: usize = 512;
const MAX_INCIDENT_CODES_V1: usize = 512;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IncidentLogStreamV1 {
    Stdout,
    Stderr,
}

impl IncidentLogStreamV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

impl fmt::Debug for IncidentLogStreamV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IncidentLogStreamV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IncidentExitExpectationV1 {
    Success,
    Nonzero(i32),
}

impl IncidentExitExpectationV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Nonzero(_) => "nonzero",
        }
    }

    fn accepts(self, actual: ExitCategoryV1) -> bool {
        match (self, actual) {
            (Self::Success, ExitCategoryV1::Success) => true,
            (Self::Nonzero(expected), ExitCategoryV1::Nonzero { code }) => expected == code,
            _ => false,
        }
    }
}

impl fmt::Debug for IncidentExitExpectationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("IncidentExitExpectationV1");
        debug.field("code", &self.code());
        if let Self::Nonzero(code) = self {
            debug.field("exit_code", code);
        }
        debug.finish()
    }
}

/// Label-free recipe for executing one incident producer. It accepts one exact
/// executable and argv, never a shell command. The selected stream is the exact
/// log artifact; no stdout/stderr merge can invent ordering.
#[derive(Clone, PartialEq, Eq)]
pub struct ExecutableIncidentCaseV1 {
    artifact_digest: ArtifactDigest,
    program: ExecutableBuildV1,
    stdin: Box<[u8]>,
    question: Box<[u8]>,
    context: Box<[u8]>,
    log_stream: IncidentLogStreamV1,
    expected_exit: IncidentExitExpectationV1,
    require_other_stream_empty: bool,
    limits: HarnessLimitsV1,
}

impl ExecutableIncidentCaseV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        program: ExecutableBuildV1,
        stdin: Vec<u8>,
        question: Vec<u8>,
        context: Vec<u8>,
        log_stream: IncidentLogStreamV1,
        expected_exit: IncidentExitExpectationV1,
        require_other_stream_empty: bool,
        limits: HarnessLimitsV1,
    ) -> Result<Self, ExecutableIncidentErrorV1> {
        if question.is_empty() {
            return Err(ExecutableIncidentErrorV1::EmptyQuestion);
        }
        if question.len() > MAX_INCIDENT_QUESTION_BYTES_V1 {
            return Err(ExecutableIncidentErrorV1::QuestionTooLarge);
        }
        if context.len() > MAX_INCIDENT_CONTEXT_BYTES_V1 {
            return Err(ExecutableIncidentErrorV1::ContextTooLarge);
        }
        if u64::try_from(stdin.len()).map_err(|_| ExecutableIncidentErrorV1::CountOverflow)?
            > limits.stdin_bytes()
        {
            return Err(ExecutableIncidentErrorV1::StdinExceedsCap);
        }
        let artifact_digest = derive_case_digest_v1(
            &program,
            &stdin,
            &question,
            &context,
            log_stream,
            expected_exit,
            require_other_stream_empty,
            limits,
        )?;
        Ok(Self {
            artifact_digest,
            program,
            stdin: stdin.into_boxed_slice(),
            question: question.into_boxed_slice(),
            context: context.into_boxed_slice(),
            log_stream,
            expected_exit,
            require_other_stream_empty,
            limits,
        })
    }

    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn question(&self) -> &[u8] {
        &self.question
    }

    #[must_use]
    pub const fn context(&self) -> &[u8] {
        &self.context
    }

    #[must_use]
    pub const fn log_stream(&self) -> IncidentLogStreamV1 {
        self.log_stream
    }
}

impl fmt::Debug for ExecutableIncidentCaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutableIncidentCaseV1")
            .field(
                "contract_version",
                &EXECUTABLE_INCIDENT_LAB_CONTRACT_VERSION_V1,
            )
            .field("artifact_identity_present", &true)
            .field("program", &self.program)
            .field("stdin_byte_count", &self.stdin.len())
            .field("question_byte_count", &self.question.len())
            .field("context_byte_count", &self.context.len())
            .field("log_stream", &self.log_stream)
            .field("expected_exit", &self.expected_exit)
            .field(
                "require_other_stream_empty",
                &self.require_other_stream_empty,
            )
            .field("limits", &self.limits)
            .field("contains_governed_truth", &false)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ExecutableIncidentRunV1 {
    artifact_digest: ArtifactDigest,
    case_artifact_digest: ArtifactDigest,
    log_artifact_digest: ArtifactDigest,
    log_bytes: Box<[u8]>,
    stdout_artifact_digest: ArtifactDigest,
    stderr_artifact_digest: ArtifactDigest,
    stdout_byte_count: u64,
    stderr_byte_count: u64,
    wall_time_nanos: u64,
    exit_category: ExitCategoryV1,
}

impl ExecutableIncidentRunV1 {
    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn case_artifact_digest(&self) -> ArtifactDigest {
        self.case_artifact_digest
    }

    #[must_use]
    pub const fn log_artifact_digest(&self) -> ArtifactDigest {
        self.log_artifact_digest
    }

    #[must_use]
    pub const fn log_bytes(&self) -> &[u8] {
        &self.log_bytes
    }

    #[must_use]
    pub const fn wall_time_nanos(&self) -> u64 {
        self.wall_time_nanos
    }

    #[must_use]
    pub const fn exit_category(&self) -> ExitCategoryV1 {
        self.exit_category
    }
}

impl fmt::Debug for ExecutableIncidentRunV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutableIncidentRunV1")
            .field("artifact_identity_present", &true)
            .field("case_binding_present", &true)
            .field("log_artifact_identity_present", &true)
            .field("log_byte_count", &self.log_bytes.len())
            .field("stdout_byte_count", &self.stdout_byte_count)
            .field("stderr_byte_count", &self.stderr_byte_count)
            .field("wall_time_nanos", &self.wall_time_nanos)
            .field("exit_category", &self.exit_category)
            .field("contains_log_bytes", &false)
            .finish()
    }
}

/// Two byte-identical executions of one producer. Wall time is deliberately
/// retained per run but excluded from the repeatability equality gate.
#[derive(Clone, PartialEq, Eq)]
pub struct FrozenExecutableIncidentV1 {
    artifact_digest: ArtifactDigest,
    case_artifact_digest: ArtifactDigest,
    log_artifact_digest: ArtifactDigest,
    log_bytes: Box<[u8]>,
    first: ExecutableIncidentRunV1,
    second: ExecutableIncidentRunV1,
}

impl FrozenExecutableIncidentV1 {
    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn case_artifact_digest(&self) -> ArtifactDigest {
        self.case_artifact_digest
    }

    #[must_use]
    pub const fn log_artifact_digest(&self) -> ArtifactDigest {
        self.log_artifact_digest
    }

    #[must_use]
    pub const fn log_bytes(&self) -> &[u8] {
        &self.log_bytes
    }

    #[must_use]
    pub const fn first_run(&self) -> &ExecutableIncidentRunV1 {
        &self.first
    }

    #[must_use]
    pub const fn second_run(&self) -> &ExecutableIncidentRunV1 {
        &self.second
    }
}

impl fmt::Debug for FrozenExecutableIncidentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenExecutableIncidentV1")
            .field("artifact_identity_present", &true)
            .field("case_binding_present", &true)
            .field("log_artifact_identity_present", &true)
            .field("log_byte_count", &self.log_bytes.len())
            .field("repeat_count", &2_u8)
            .field("byte_repeatable", &true)
            .finish()
    }
}

pub fn freeze_executable_incident_v1(
    case: &ExecutableIncidentCaseV1,
) -> Result<FrozenExecutableIncidentV1, ExecutableIncidentErrorV1> {
    let first = execute_incident_once_v1(case)?;
    let second = execute_incident_once_v1(case)?;
    if first.log_bytes != second.log_bytes
        || first.log_artifact_digest != second.log_artifact_digest
        || first.stdout_artifact_digest != second.stdout_artifact_digest
        || first.stderr_artifact_digest != second.stderr_artifact_digest
        || first.stdout_byte_count != second.stdout_byte_count
        || first.stderr_byte_count != second.stderr_byte_count
        || first.exit_category != second.exit_category
    {
        return Err(ExecutableIncidentErrorV1::IncidentNotRepeatable);
    }
    let artifact_digest = digest_fields_v1(
        INCIDENT_FREEZE_DOMAIN_V1,
        &[
            case.artifact_digest.as_bytes(),
            first.log_artifact_digest.as_bytes(),
            first.artifact_digest.as_bytes(),
            second.artifact_digest.as_bytes(),
        ],
    )?;
    Ok(FrozenExecutableIncidentV1 {
        artifact_digest,
        case_artifact_digest: case.artifact_digest,
        log_artifact_digest: first.log_artifact_digest,
        log_bytes: first.log_bytes.clone(),
        first,
        second,
    })
}

fn execute_incident_once_v1(
    case: &ExecutableIncidentCaseV1,
) -> Result<ExecutableIncidentRunV1, ExecutableIncidentErrorV1> {
    let execution = execute_raw_subprocess_v1(RawSubprocessSpecV1 {
        program: &case.program,
        stdin_bytes: &case.stdin,
        limits: case.limits,
    })?;
    if execution.stdin_delivery != StdinDeliveryV1::Complete
        || execution.stdout.state() != StreamCaptureStateV1::Complete
        || execution.stderr.state() != StreamCaptureStateV1::Complete
        || !execution.termination_causes.is_empty()
        || !execution.child_reaped
        || !execution.executable_path_digest_verified_before_spawn
        || !execution.executable_path_digest_verified_after_spawn
    {
        return Err(ExecutableIncidentErrorV1::IncidentExecutionIncomplete);
    }
    if !case.expected_exit.accepts(execution.exit_category) {
        return Err(ExecutableIncidentErrorV1::UnexpectedIncidentExit);
    }
    let (selected, other) = match case.log_stream {
        IncidentLogStreamV1::Stdout => (&execution.stdout, &execution.stderr),
        IncidentLogStreamV1::Stderr => (&execution.stderr, &execution.stdout),
    };
    if selected.bytes().is_empty() {
        return Err(ExecutableIncidentErrorV1::EmptyIncidentLog);
    }
    if case.require_other_stream_empty && !other.bytes().is_empty() {
        return Err(ExecutableIncidentErrorV1::UnexpectedOtherStream);
    }
    let stdout_byte_count = checked_len(execution.stdout.byte_count())?;
    let stderr_byte_count = checked_len(execution.stderr.byte_count())?;
    let log_bytes = selected.bytes().to_vec().into_boxed_slice();
    let log_artifact_digest = selected.artifact_digest();
    let exit_bytes = exit_binding_v1(execution.exit_category);
    let artifact_digest = digest_fields_v1(
        INCIDENT_RUN_DOMAIN_V1,
        &[
            case.artifact_digest.as_bytes(),
            log_artifact_digest.as_bytes(),
            execution.stdout.artifact_digest().as_bytes(),
            execution.stderr.artifact_digest().as_bytes(),
            &exit_bytes,
        ],
    )?;
    Ok(ExecutableIncidentRunV1 {
        artifact_digest,
        case_artifact_digest: case.artifact_digest,
        log_artifact_digest,
        log_bytes,
        stdout_artifact_digest: execution.stdout.artifact_digest(),
        stderr_artifact_digest: execution.stderr.artifact_digest(),
        stdout_byte_count,
        stderr_byte_count,
        wall_time_nanos: execution.wall_time_nanos,
        exit_category: execution.exit_category,
    })
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IncidentArmKindV1 {
    EvidentrailBrief,
    GrepHeadTail,
    RawWholeRecordPrefix,
}

impl IncidentArmKindV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EvidentrailBrief => "evidentrail_brief",
            Self::GrepHeadTail => "grep_head_tail",
            Self::RawWholeRecordPrefix => "raw_whole_record_prefix",
        }
    }
}

impl fmt::Debug for IncidentArmKindV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IncidentArmKindV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct IncidentMethodArtifactV1 {
    artifact_digest: ArtifactDigest,
    case_artifact_digest: ArtifactDigest,
    source_log_artifact_digest: ArtifactDigest,
    kind: IncidentArmKindV1,
    bytes: Box<[u8]>,
    budget_bytes: u64,
    complete_source: bool,
    citation_aliases: Vec<u32>,
}

impl IncidentMethodArtifactV1 {
    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn case_artifact_digest(&self) -> ArtifactDigest {
        self.case_artifact_digest
    }

    #[must_use]
    pub const fn source_log_artifact_digest(&self) -> ArtifactDigest {
        self.source_log_artifact_digest
    }

    #[must_use]
    pub const fn kind(&self) -> IncidentArmKindV1 {
        self.kind
    }

    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn budget_bytes(&self) -> u64 {
        self.budget_bytes
    }

    #[must_use]
    pub const fn complete_source(&self) -> bool {
        self.complete_source
    }

    #[must_use]
    pub fn citation_aliases(&self) -> &[u32] {
        &self.citation_aliases
    }
}

impl fmt::Debug for IncidentMethodArtifactV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IncidentMethodArtifactV1")
            .field("artifact_identity_present", &true)
            .field("case_binding_present", &true)
            .field("source_log_binding_present", &true)
            .field("kind", &self.kind)
            .field("byte_count", &self.bytes.len())
            .field("budget_bytes", &self.budget_bytes)
            .field("complete_source", &self.complete_source)
            .field("citation_alias_count", &self.citation_aliases.len())
            .field("content_redacted", &true)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum IncidentArmDecisionV1 {
    Available(IncidentMethodArtifactV1),
    NeedsMore {
        kind: IncidentArmKindV1,
        reason_code: &'static str,
    },
}

impl IncidentArmDecisionV1 {
    #[must_use]
    pub const fn kind(&self) -> IncidentArmKindV1 {
        match self {
            Self::Available(artifact) => artifact.kind(),
            Self::NeedsMore { kind, .. } => *kind,
        }
    }

    #[must_use]
    pub const fn artifact(&self) -> Option<&IncidentMethodArtifactV1> {
        match self {
            Self::Available(artifact) => Some(artifact),
            Self::NeedsMore { .. } => None,
        }
    }
}

impl fmt::Debug for IncidentArmDecisionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("IncidentArmDecisionV1");
        debug.field("kind", &self.kind());
        match self {
            Self::Available(artifact) => debug.field("decision", &"available").field(
                "artifact_identity_present",
                &artifact
                    .artifact_digest()
                    .as_bytes()
                    .iter()
                    .any(|byte| *byte != 0),
            ),
            Self::NeedsMore { reason_code, .. } => debug
                .field("decision", &"needs_more")
                .field("reason_code", reason_code),
        };
        debug.finish()
    }
}

pub fn prepare_incident_method_arms_v1(
    case: &ExecutableIncidentCaseV1,
    incident: &FrozenExecutableIncidentV1,
    budget_bytes: u64,
) -> Result<[IncidentArmDecisionV1; 3], ExecutableIncidentErrorV1> {
    if incident.case_artifact_digest != case.artifact_digest {
        return Err(ExecutableIncidentErrorV1::IncidentCaseBindingMismatch);
    }
    let budget = usize::try_from(budget_bytes)
        .map_err(|_| ExecutableIncidentErrorV1::InvalidArtifactBudget)?;
    if budget == 0 {
        return Err(ExecutableIncidentErrorV1::InvalidArtifactBudget);
    }
    let raw = raw_prefix_arm_v1(case, incident, budget_bytes, budget)?;
    let grep = grep_head_tail_arm_v1(case, incident, budget_bytes, budget)?;
    let evidentrail = evidentrail_arm_v1(case, incident, budget_bytes)?;
    Ok([evidentrail, grep, raw])
}

fn raw_prefix_arm_v1(
    case: &ExecutableIncidentCaseV1,
    incident: &FrozenExecutableIncidentV1,
    budget_bytes: u64,
    budget: usize,
) -> Result<IncidentArmDecisionV1, ExecutableIncidentErrorV1> {
    let records = exact_record_ranges_v1(incident.log_bytes());
    let mut end = 0;
    for range in records {
        if range.1 > budget {
            break;
        }
        end = range.1;
    }
    if end == 0 {
        return Ok(IncidentArmDecisionV1::NeedsMore {
            kind: IncidentArmKindV1::RawWholeRecordPrefix,
            reason_code: "no_whole_record_fits",
        });
    }
    make_arm_v1(
        case,
        incident,
        IncidentArmKindV1::RawWholeRecordPrefix,
        incident.log_bytes()[..end].to_vec(),
        budget_bytes,
        end == incident.log_bytes().len(),
        Vec::new(),
    )
    .map(IncidentArmDecisionV1::Available)
}

fn grep_head_tail_arm_v1(
    case: &ExecutableIncidentCaseV1,
    incident: &FrozenExecutableIncidentV1,
    budget_bytes: u64,
    budget: usize,
) -> Result<IncidentArmDecisionV1, ExecutableIncidentErrorV1> {
    let ranges = exact_record_ranges_v1(incident.log_bytes());
    let terms = query_terms_v1(case.question());
    let mut priorities = Vec::new();
    for (index, range) in ranges.iter().copied().enumerate() {
        let record = &incident.log_bytes()[range.0..range.1];
        if terms
            .iter()
            .any(|term| ascii_contains_case_insensitive_v1(record, term))
        {
            priorities.push(index);
        }
    }
    for index in (0..ranges.len()).rev() {
        priorities.push(index);
    }
    for index in 0..ranges.len() {
        priorities.push(index);
    }
    let mut selected = BTreeSet::new();
    let mut used = 0_usize;
    for index in priorities {
        if selected.contains(&index) {
            continue;
        }
        let range = ranges[index];
        let cost = range.1 - range.0;
        if used.checked_add(cost).is_some_and(|next| next <= budget) {
            selected.insert(index);
            used += cost;
        }
    }
    if selected.is_empty() {
        return Ok(IncidentArmDecisionV1::NeedsMore {
            kind: IncidentArmKindV1::GrepHeadTail,
            reason_code: "no_whole_record_fits",
        });
    }
    let mut bytes = Vec::with_capacity(used);
    for index in selected {
        let range = ranges[index];
        bytes.extend_from_slice(&incident.log_bytes()[range.0..range.1]);
    }
    let complete_source = bytes == incident.log_bytes();
    make_arm_v1(
        case,
        incident,
        IncidentArmKindV1::GrepHeadTail,
        bytes,
        budget_bytes,
        complete_source,
        Vec::new(),
    )
    .map(IncidentArmDecisionV1::Available)
}

fn evidentrail_arm_v1(
    case: &ExecutableIncidentCaseV1,
    incident: &FrozenExecutableIncidentV1,
    budget_bytes: u64,
) -> Result<IncidentArmDecisionV1, ExecutableIncidentErrorV1> {
    let outcome = compile_explicit_stdin_v1(
        incident.log_bytes(),
        case.question(),
        budget_bytes,
        *incident.artifact_digest.as_bytes(),
        UnixTimestampNanos::new(1),
    )
    .map_err(|_| ExecutableIncidentErrorV1::EvidentrailExecutionFailed)?;
    match outcome {
        StdinBriefOutcomeV1::Rendered(rendered) => {
            let bytes = rendered.text().as_bytes().to_vec();
            let aliases = extract_aliases_v1(&bytes)?;
            make_arm_v1(
                case,
                incident,
                IncidentArmKindV1::EvidentrailBrief,
                bytes,
                budget_bytes,
                rendered.mode() == StdinBriefModeV1::Passthrough,
                aliases,
            )
            .map(IncidentArmDecisionV1::Available)
        }
        StdinBriefOutcomeV1::NeedsMore(_) => Ok(IncidentArmDecisionV1::NeedsMore {
            kind: IncidentArmKindV1::EvidentrailBrief,
            reason_code: "evidentrail_needs_more",
        }),
    }
}

fn make_arm_v1(
    case: &ExecutableIncidentCaseV1,
    incident: &FrozenExecutableIncidentV1,
    kind: IncidentArmKindV1,
    bytes: Vec<u8>,
    budget_bytes: u64,
    complete_source: bool,
    citation_aliases: Vec<u32>,
) -> Result<IncidentMethodArtifactV1, ExecutableIncidentErrorV1> {
    if bytes.is_empty()
        || u64::try_from(bytes.len()).map_err(|_| ExecutableIncidentErrorV1::CountOverflow)?
            > budget_bytes
    {
        return Err(ExecutableIncidentErrorV1::ArtifactBudgetViolation);
    }
    let material_digest = artifact_digest_for_bytes_v1(&bytes);
    let budget_binding = budget_bytes.to_be_bytes();
    let complete_binding = [u8::from(complete_source)];
    let artifact_digest = digest_fields_v1(
        INCIDENT_ARM_DOMAIN_V1,
        &[
            case.artifact_digest.as_bytes(),
            incident.log_artifact_digest.as_bytes(),
            kind.code().as_bytes(),
            &budget_binding,
            &complete_binding,
            material_digest.as_bytes(),
        ],
    )?;
    Ok(IncidentMethodArtifactV1 {
        artifact_digest,
        case_artifact_digest: case.artifact_digest,
        source_log_artifact_digest: incident.log_artifact_digest,
        kind,
        bytes: bytes.into_boxed_slice(),
        budget_bytes,
        complete_source,
        citation_aliases,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IncidentAgentCapsV1 {
    prompt_bytes: u64,
    answer_bytes: u64,
    stderr_bytes: u64,
    wall_time_nanos: u64,
}

impl IncidentAgentCapsV1 {
    pub fn try_new(
        prompt_bytes: u64,
        answer_bytes: u64,
        stderr_bytes: u64,
        wall_time_nanos: u64,
    ) -> Result<Self, ExecutableIncidentErrorV1> {
        HarnessLimitsV1::try_new(prompt_bytes, answer_bytes, stderr_bytes, wall_time_nanos)?;
        if prompt_bytes == 0 || answer_bytes == 0 {
            return Err(ExecutableIncidentErrorV1::InvalidAgentCaps);
        }
        Ok(Self {
            prompt_bytes,
            answer_bytes,
            stderr_bytes,
            wall_time_nanos,
        })
    }
}

impl fmt::Debug for IncidentAgentCapsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IncidentAgentCapsV1")
            .field("prompt_bytes", &self.prompt_bytes)
            .field("answer_bytes", &self.answer_bytes)
            .field("stderr_bytes", &self.stderr_bytes)
            .field("wall_time_nanos", &self.wall_time_nanos)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IncidentAgentAnswerV1 {
    schema_version: u16,
    abstained: bool,
    cause_code: Option<String>,
    patch_hex: Option<String>,
    cited_aliases: Vec<u32>,
    claim_codes: Vec<String>,
    uncertainty_micros: u64,
}

impl IncidentAgentAnswerV1 {
    #[must_use]
    pub const fn abstained(&self) -> bool {
        self.abstained
    }

    #[must_use]
    pub fn cause_code(&self) -> Option<&str> {
        self.cause_code.as_deref()
    }

    pub fn patch_bytes(&self) -> Result<Option<Vec<u8>>, ExecutableIncidentErrorV1> {
        self.patch_hex.as_deref().map(decode_hex_v1).transpose()
    }

    #[must_use]
    pub fn cited_aliases(&self) -> &[u32] {
        &self.cited_aliases
    }

    #[must_use]
    pub fn claim_codes(&self) -> &[String] {
        &self.claim_codes
    }

    #[must_use]
    pub const fn uncertainty_micros(&self) -> u64 {
        self.uncertainty_micros
    }
}

impl fmt::Debug for IncidentAgentAnswerV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IncidentAgentAnswerV1")
            .field("schema_version", &self.schema_version)
            .field("abstained", &self.abstained)
            .field("cause_code_present", &self.cause_code.is_some())
            .field("patch_present", &self.patch_hex.is_some())
            .field("citation_count", &self.cited_aliases.len())
            .field("claim_count", &self.claim_codes.len())
            .field("uncertainty_micros", &self.uncertainty_micros)
            .field("content_redacted", &true)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct IncidentAgentExecutionV1 {
    artifact_digest: ArtifactDigest,
    case_artifact_digest: ArtifactDigest,
    method_artifact_digest: ArtifactDigest,
    prompt_artifact_digest: ArtifactDigest,
    prompt_byte_count: u64,
    answer_artifact_digest: ArtifactDigest,
    answer_byte_count: u64,
    wall_time_nanos: u64,
    agent_system_artifact_digest: ArtifactDigest,
    agent_build_artifact_digest: ArtifactDigest,
    caps: IncidentAgentCapsV1,
    answer: IncidentAgentAnswerV1,
}

impl IncidentAgentExecutionV1 {
    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn method_artifact_digest(&self) -> ArtifactDigest {
        self.method_artifact_digest
    }

    #[must_use]
    pub const fn answer(&self) -> &IncidentAgentAnswerV1 {
        &self.answer
    }

    #[must_use]
    pub const fn prompt_byte_count(&self) -> u64 {
        self.prompt_byte_count
    }

    #[must_use]
    pub const fn answer_byte_count(&self) -> u64 {
        self.answer_byte_count
    }

    #[must_use]
    pub const fn wall_time_nanos(&self) -> u64 {
        self.wall_time_nanos
    }
}

impl fmt::Debug for IncidentAgentExecutionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IncidentAgentExecutionV1")
            .field("artifact_identity_present", &true)
            .field("case_binding_present", &true)
            .field("method_binding_present", &true)
            .field("prompt_artifact_identity_present", &true)
            .field("prompt_byte_count", &self.prompt_byte_count)
            .field("answer_artifact_identity_present", &true)
            .field("answer_byte_count", &self.answer_byte_count)
            .field("wall_time_nanos", &self.wall_time_nanos)
            .field("agent_system_binding_present", &true)
            .field("agent_build_binding_present", &true)
            .field("caps", &self.caps)
            .field("answer", &self.answer)
            .finish()
    }
}

pub fn execute_incident_agent_v1(
    program: &ExecutableBuildV1,
    case: &ExecutableIncidentCaseV1,
    artifact: &IncidentMethodArtifactV1,
    caps: IncidentAgentCapsV1,
) -> Result<IncidentAgentExecutionV1, ExecutableIncidentErrorV1> {
    if artifact.case_artifact_digest != case.artifact_digest {
        return Err(ExecutableIncidentErrorV1::IncidentCaseBindingMismatch);
    }
    let prompt = build_agent_prompt_v1(case, artifact)?;
    let prompt_byte_count = checked_len(prompt.len())?;
    if prompt_byte_count > caps.prompt_bytes {
        return Err(ExecutableIncidentErrorV1::AgentPromptTooLarge);
    }
    let limits = HarnessLimitsV1::try_new(
        caps.prompt_bytes,
        caps.answer_bytes,
        caps.stderr_bytes,
        caps.wall_time_nanos,
    )?;
    let execution = execute_raw_subprocess_v1(RawSubprocessSpecV1 {
        program,
        stdin_bytes: &prompt,
        limits,
    })?;
    if execution.stdin_delivery != StdinDeliveryV1::Complete
        || execution.exit_category != ExitCategoryV1::Success
        || execution.stdout.state() != StreamCaptureStateV1::Complete
        || execution.stderr.state() != StreamCaptureStateV1::Complete
        || !execution.stderr.bytes().is_empty()
        || !execution.termination_causes.is_empty()
        || !execution.child_reaped
    {
        return Err(ExecutableIncidentErrorV1::AgentExecutionIncomplete);
    }
    let answer = parse_agent_answer_v1(execution.stdout.bytes())?;
    let prompt_artifact_digest = artifact_digest_for_bytes_v1(&prompt);
    let answer_artifact_digest = execution.stdout.artifact_digest();
    let answer_byte_count = checked_len(execution.stdout.byte_count())?;
    let caps_binding = agent_caps_binding_v1(caps);
    let artifact_digest = digest_fields_v1(
        INCIDENT_AGENT_RECEIPT_DOMAIN_V1,
        &[
            case.artifact_digest.as_bytes(),
            artifact.artifact_digest.as_bytes(),
            program.system_artifact_digest().as_bytes(),
            program.executable_build_artifact_digest().as_bytes(),
            &caps_binding,
            prompt_artifact_digest.as_bytes(),
            answer_artifact_digest.as_bytes(),
        ],
    )?;
    Ok(IncidentAgentExecutionV1 {
        artifact_digest,
        case_artifact_digest: case.artifact_digest,
        method_artifact_digest: artifact.artifact_digest,
        prompt_artifact_digest,
        prompt_byte_count,
        answer_artifact_digest,
        answer_byte_count,
        wall_time_nanos: execution.wall_time_nanos,
        agent_system_artifact_digest: program.system_artifact_digest(),
        agent_build_artifact_digest: program.executable_build_artifact_digest(),
        caps,
        answer,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IncidentVerifierCapsV1 {
    patch_bytes: u64,
    stdout_bytes: u64,
    stderr_bytes: u64,
    wall_time_nanos: u64,
}

impl IncidentVerifierCapsV1 {
    pub fn try_new(
        patch_bytes: u64,
        stdout_bytes: u64,
        stderr_bytes: u64,
        wall_time_nanos: u64,
    ) -> Result<Self, ExecutableIncidentErrorV1> {
        HarnessLimitsV1::try_new(patch_bytes, stdout_bytes, stderr_bytes, wall_time_nanos)?;
        if patch_bytes == 0 {
            return Err(ExecutableIncidentErrorV1::InvalidVerifierCaps);
        }
        Ok(Self {
            patch_bytes,
            stdout_bytes,
            stderr_bytes,
            wall_time_nanos,
        })
    }
}

impl fmt::Debug for IncidentVerifierCapsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IncidentVerifierCapsV1")
            .field("patch_bytes", &self.patch_bytes)
            .field("stdout_bytes", &self.stdout_bytes)
            .field("stderr_bytes", &self.stderr_bytes)
            .field("wall_time_nanos", &self.wall_time_nanos)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct IncidentVerifierExecutionV1 {
    artifact_digest: ArtifactDigest,
    patch_artifact_digest: ArtifactDigest,
    passed: bool,
    wall_time_nanos: u64,
    stdout_byte_count: u64,
    stderr_byte_count: u64,
    verifier_system_artifact_digest: ArtifactDigest,
    verifier_build_artifact_digest: ArtifactDigest,
    caps: IncidentVerifierCapsV1,
}

impl IncidentVerifierExecutionV1 {
    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn patch_artifact_digest(&self) -> ArtifactDigest {
        self.patch_artifact_digest
    }

    #[must_use]
    pub const fn passed(&self) -> bool {
        self.passed
    }
}

impl fmt::Debug for IncidentVerifierExecutionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IncidentVerifierExecutionV1")
            .field("artifact_identity_present", &true)
            .field("patch_artifact_identity_present", &true)
            .field("passed", &self.passed)
            .field("wall_time_nanos", &self.wall_time_nanos)
            .field("stdout_byte_count", &self.stdout_byte_count)
            .field("stderr_byte_count", &self.stderr_byte_count)
            .field("verifier_system_binding_present", &true)
            .field("verifier_build_binding_present", &true)
            .field("caps", &self.caps)
            .field("content_redacted", &true)
            .finish()
    }
}

pub fn execute_incident_verifier_v1(
    program: &ExecutableBuildV1,
    patch: &[u8],
    caps: IncidentVerifierCapsV1,
) -> Result<IncidentVerifierExecutionV1, ExecutableIncidentErrorV1> {
    if patch.is_empty() || patch.len() > MAX_INCIDENT_PATCH_BYTES_V1 {
        return Err(ExecutableIncidentErrorV1::InvalidPatch);
    }
    let patch_byte_count = checked_len(patch.len())?;
    if patch_byte_count > caps.patch_bytes {
        return Err(ExecutableIncidentErrorV1::PatchExceedsCap);
    }
    let limits = HarnessLimitsV1::try_new(
        caps.patch_bytes,
        caps.stdout_bytes,
        caps.stderr_bytes,
        caps.wall_time_nanos,
    )?;
    let execution = execute_raw_subprocess_v1(RawSubprocessSpecV1 {
        program,
        stdin_bytes: patch,
        limits,
    })?;
    if execution.stdin_delivery != StdinDeliveryV1::Complete
        || execution.stdout.state() != StreamCaptureStateV1::Complete
        || execution.stderr.state() != StreamCaptureStateV1::Complete
        || !execution.termination_causes.is_empty()
        || !execution.child_reaped
    {
        return Err(ExecutableIncidentErrorV1::VerifierExecutionIncomplete);
    }
    let passed = execution.exit_category == ExitCategoryV1::Success;
    let patch_artifact_digest = artifact_digest_for_bytes_v1(patch);
    let exit = exit_binding_v1(execution.exit_category);
    let caps_binding = verifier_caps_binding_v1(caps);
    let artifact_digest = digest_fields_v1(
        INCIDENT_VERIFIER_DOMAIN_V1,
        &[
            patch_artifact_digest.as_bytes(),
            program.system_artifact_digest().as_bytes(),
            program.executable_build_artifact_digest().as_bytes(),
            &caps_binding,
            execution.stdout.artifact_digest().as_bytes(),
            execution.stderr.artifact_digest().as_bytes(),
            &exit,
        ],
    )?;
    Ok(IncidentVerifierExecutionV1 {
        artifact_digest,
        patch_artifact_digest,
        passed,
        wall_time_nanos: execution.wall_time_nanos,
        stdout_byte_count: checked_len(execution.stdout.byte_count())?,
        stderr_byte_count: checked_len(execution.stderr.byte_count())?,
        verifier_system_artifact_digest: program.system_artifact_digest(),
        verifier_build_artifact_digest: program.executable_build_artifact_digest(),
        caps,
    })
}

#[derive(Clone, PartialEq, Eq)]
pub struct GovernedIncidentTruthV1 {
    artifact_digest: ArtifactDigest,
    case_artifact_digest: ArtifactDigest,
    answerable: bool,
    accepted_cause_codes: Vec<String>,
    forbidden_claim_codes: Vec<String>,
}

impl GovernedIncidentTruthV1 {
    pub fn try_new(
        case_artifact_digest: ArtifactDigest,
        answerable: bool,
        accepted_cause_codes: Vec<String>,
        forbidden_claim_codes: Vec<String>,
    ) -> Result<Self, ExecutableIncidentErrorV1> {
        let accepted_cause_codes = checked_codes_v1(accepted_cause_codes)?;
        let forbidden_claim_codes = checked_codes_v1(forbidden_claim_codes)?;
        if (answerable && accepted_cause_codes.is_empty())
            || (!answerable && !accepted_cause_codes.is_empty())
        {
            return Err(ExecutableIncidentErrorV1::InvalidGovernedTruth);
        }
        let answerable_binding = [u8::from(answerable)];
        let mut fields: Vec<&[u8]> = vec![case_artifact_digest.as_bytes(), &answerable_binding];
        for code in &accepted_cause_codes {
            fields.push(code.as_bytes());
        }
        for code in &forbidden_claim_codes {
            fields.push(code.as_bytes());
        }
        let artifact_digest = digest_fields_v1(INCIDENT_TRUTH_DOMAIN_V1, &fields)?;
        Ok(Self {
            artifact_digest,
            case_artifact_digest,
            answerable,
            accepted_cause_codes,
            forbidden_claim_codes,
        })
    }
}

impl fmt::Debug for GovernedIncidentTruthV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedIncidentTruthV1")
            .field("artifact_identity_present", &true)
            .field("case_binding_present", &true)
            .field("answerable", &self.answerable)
            .field("accepted_cause_count", &self.accepted_cause_codes.len())
            .field("forbidden_claim_count", &self.forbidden_claim_codes.len())
            .field("hidden_values_redacted", &true)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IncidentVerificationV1 {
    Passed,
    Failed,
    NotRun,
}

impl IncidentVerificationV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::NotRun => "not_run",
        }
    }
}

impl fmt::Debug for IncidentVerificationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IncidentVerificationV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GovernedIncidentOutcomeV1 {
    cause_verified: bool,
    valid_citation_count: u64,
    invalid_citation_count: u64,
    forbidden_claim_count: u64,
    abstention_appropriate: bool,
    verification: IncidentVerificationV1,
    task_success: bool,
    vds_at_budget: bool,
}

impl GovernedIncidentOutcomeV1 {
    #[must_use]
    pub const fn cause_verified(self) -> bool {
        self.cause_verified
    }

    #[must_use]
    pub const fn valid_citation_count(self) -> u64 {
        self.valid_citation_count
    }

    #[must_use]
    pub const fn invalid_citation_count(self) -> u64 {
        self.invalid_citation_count
    }

    #[must_use]
    pub const fn forbidden_claim_count(self) -> u64 {
        self.forbidden_claim_count
    }

    #[must_use]
    pub const fn abstention_appropriate(self) -> bool {
        self.abstention_appropriate
    }

    #[must_use]
    pub const fn verification(self) -> IncidentVerificationV1 {
        self.verification
    }

    #[must_use]
    pub const fn task_success(self) -> bool {
        self.task_success
    }

    #[must_use]
    pub const fn vds_at_budget(self) -> bool {
        self.vds_at_budget
    }
}

impl fmt::Debug for GovernedIncidentOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedIncidentOutcomeV1")
            .field("cause_verified", &self.cause_verified)
            .field("valid_citation_count", &self.valid_citation_count)
            .field("invalid_citation_count", &self.invalid_citation_count)
            .field("forbidden_claim_count", &self.forbidden_claim_count)
            .field("abstention_appropriate", &self.abstention_appropriate)
            .field("verification", &self.verification)
            .field("task_success", &self.task_success)
            .field("vds_at_budget", &self.vds_at_budget)
            .field("scalar_score_available", &false)
            .finish()
    }
}

pub fn evaluate_governed_incident_v1(
    incident: &FrozenExecutableIncidentV1,
    artifact: &IncidentMethodArtifactV1,
    agent: &IncidentAgentExecutionV1,
    verifier: Option<&IncidentVerifierExecutionV1>,
    truth: &GovernedIncidentTruthV1,
) -> Result<GovernedIncidentOutcomeV1, ExecutableIncidentErrorV1> {
    if incident.case_artifact_digest != truth.case_artifact_digest
        || artifact.case_artifact_digest != truth.case_artifact_digest
        || artifact.source_log_artifact_digest != incident.log_artifact_digest
        || agent.case_artifact_digest != truth.case_artifact_digest
        || agent.method_artifact_digest != artifact.artifact_digest
    {
        return Err(ExecutableIncidentErrorV1::GovernedBindingMismatch);
    }
    let answer = &agent.answer;
    let cause_verified = answer.cause_code().is_some_and(|code| {
        truth
            .accepted_cause_codes
            .iter()
            .any(|accepted| accepted == code)
    });
    let alias_catalog = artifact
        .citation_aliases
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut valid_citation_count = 0_u64;
    let mut invalid_citation_count = 0_u64;
    for alias in answer.cited_aliases() {
        let target = if alias_catalog.contains(alias) {
            &mut valid_citation_count
        } else {
            &mut invalid_citation_count
        };
        *target = target
            .checked_add(1)
            .ok_or(ExecutableIncidentErrorV1::CountOverflow)?;
    }
    let forbidden_claim_count = checked_len(
        answer
            .claim_codes()
            .iter()
            .filter(|code| truth.forbidden_claim_codes.contains(code))
            .count(),
    )?;
    let patch = answer.patch_bytes()?;
    let verification = match (patch.as_deref(), verifier) {
        (Some(patch), Some(verifier)) => {
            if verifier.patch_artifact_digest != artifact_digest_for_bytes_v1(patch) {
                return Err(ExecutableIncidentErrorV1::VerifierPatchBindingMismatch);
            }
            if verifier.passed {
                IncidentVerificationV1::Passed
            } else {
                IncidentVerificationV1::Failed
            }
        }
        (None, None) => IncidentVerificationV1::NotRun,
        _ => return Err(ExecutableIncidentErrorV1::VerifierPatchBindingMismatch),
    };
    let abstention_appropriate = answer.abstained != truth.answerable;
    let task_success = verification == IncidentVerificationV1::Passed;
    let citation_grounded =
        !alias_catalog.is_empty() && valid_citation_count > 0 && invalid_citation_count == 0;
    let vds_at_budget = truth.answerable
        && !answer.abstained
        && cause_verified
        && citation_grounded
        && forbidden_claim_count == 0
        && task_success;
    Ok(GovernedIncidentOutcomeV1 {
        cause_verified,
        valid_citation_count,
        invalid_citation_count,
        forbidden_claim_count,
        abstention_appropriate,
        verification,
        task_success,
        vds_at_budget,
    })
}

fn build_agent_prompt_v1(
    case: &ExecutableIncidentCaseV1,
    artifact: &IncidentMethodArtifactV1,
) -> Result<Vec<u8>, ExecutableIncidentErrorV1> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"EVIDENTRAIL_EXECUTABLE_INCIDENT_AGENT_V1\n");
    append_hex_line_v1(&mut bytes, b"case", case.artifact_digest.as_bytes());
    append_hex_line_v1(&mut bytes, b"question", case.question());
    append_hex_line_v1(&mut bytes, b"context", case.context());
    append_hex_line_v1(&mut bytes, b"method_kind", artifact.kind.code().as_bytes());
    append_hex_line_v1(&mut bytes, b"method_artifact", artifact.bytes());
    bytes.extend_from_slice(b"citation_aliases=");
    for (index, alias) in artifact.citation_aliases.iter().enumerate() {
        if index > 0 {
            bytes.push(b',');
        }
        bytes.extend_from_slice(alias.to_string().as_bytes());
    }
    bytes.push(b'\n');
    let digest = digest_fields_v1(
        INCIDENT_AGENT_PROMPT_DOMAIN_V1,
        &[
            case.artifact_digest.as_bytes(),
            artifact.artifact_digest.as_bytes(),
            &bytes,
        ],
    )?;
    append_hex_line_v1(&mut bytes, b"prompt_binding", digest.as_bytes());
    Ok(bytes)
}

fn parse_agent_answer_v1(bytes: &[u8]) -> Result<IncidentAgentAnswerV1, ExecutableIncidentErrorV1> {
    if bytes.is_empty() {
        return Err(ExecutableIncidentErrorV1::EmptyAgentAnswer);
    }
    let answer = serde_json::from_slice::<IncidentAgentAnswerV1>(bytes)
        .map_err(|_| ExecutableIncidentErrorV1::MalformedAgentAnswer)?;
    let canonical =
        serde_json::to_vec(&answer).map_err(|_| ExecutableIncidentErrorV1::MalformedAgentAnswer)?;
    if canonical != bytes {
        return Err(ExecutableIncidentErrorV1::NonCanonicalAgentAnswer);
    }
    validate_agent_answer_v1(&answer)?;
    Ok(answer)
}

fn validate_agent_answer_v1(
    answer: &IncidentAgentAnswerV1,
) -> Result<(), ExecutableIncidentErrorV1> {
    if answer.schema_version != 1 || answer.uncertainty_micros > 1_000_000 {
        return Err(ExecutableIncidentErrorV1::InvalidAgentAnswer);
    }
    if answer.cited_aliases.len() > MAX_INCIDENT_ALIASES_V1
        || !answer
            .cited_aliases
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || answer.cited_aliases.contains(&0)
    {
        return Err(ExecutableIncidentErrorV1::InvalidAgentAnswer);
    }
    let claims = checked_codes_v1(answer.claim_codes.clone())?;
    if claims != answer.claim_codes {
        return Err(ExecutableIncidentErrorV1::InvalidAgentAnswer);
    }
    match answer.abstained {
        true => {
            if answer.cause_code.is_some()
                || answer.patch_hex.is_some()
                || !answer.cited_aliases.is_empty()
                || !answer.claim_codes.is_empty()
            {
                return Err(ExecutableIncidentErrorV1::InvalidAgentAnswer);
            }
        }
        false => {
            let Some(cause) = answer.cause_code.as_deref() else {
                return Err(ExecutableIncidentErrorV1::InvalidAgentAnswer);
            };
            validate_code_v1(cause)?;
            let Some(patch_hex) = answer.patch_hex.as_deref() else {
                return Err(ExecutableIncidentErrorV1::InvalidAgentAnswer);
            };
            let patch = decode_hex_v1(patch_hex)?;
            if patch.is_empty() || patch.len() > MAX_INCIDENT_PATCH_BYTES_V1 {
                return Err(ExecutableIncidentErrorV1::InvalidPatch);
            }
        }
    }
    Ok(())
}

fn exact_record_ranges_v1(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut start = 0;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte == b'\n' {
            ranges.push((start, index + 1));
            start = index + 1;
        }
    }
    if start < bytes.len() {
        ranges.push((start, bytes.len()));
    }
    ranges
}

fn query_terms_v1(question: &[u8]) -> Vec<Vec<u8>> {
    let mut terms = BTreeSet::new();
    let mut current = Vec::new();
    for byte in question.iter().copied().chain(std::iter::once(b' ')) {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            current.push(byte.to_ascii_lowercase());
        } else if !current.is_empty() {
            if current.len() >= 3
                && !matches!(
                    current.as_slice(),
                    b"the" | b"why" | b"did" | b"with" | b"from" | b"what"
                )
            {
                terms.insert(std::mem::take(&mut current));
            }
            current.clear();
        }
    }
    terms.into_iter().collect()
}

fn ascii_contains_case_insensitive_v1(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.windows(needle.len()).any(|window| {
            window
                .iter()
                .zip(needle)
                .all(|(left, right)| left.to_ascii_lowercase() == *right)
        })
}

fn extract_aliases_v1(bytes: &[u8]) -> Result<Vec<u32>, ExecutableIncidentErrorV1> {
    let mut aliases = BTreeSet::new();
    let mut index = 0;
    while index + 3 < bytes.len() {
        if bytes[index] == b'[' && bytes[index + 1] == b'E' {
            let start = index + 2;
            let mut end = start;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            if end > start && end < bytes.len() && bytes[end] == b']' {
                let digits = std::str::from_utf8(&bytes[start..end])
                    .map_err(|_| ExecutableIncidentErrorV1::InvalidEvidentrailAlias)?;
                let alias = digits
                    .parse::<u32>()
                    .map_err(|_| ExecutableIncidentErrorV1::InvalidEvidentrailAlias)?;
                if alias == 0 {
                    return Err(ExecutableIncidentErrorV1::InvalidEvidentrailAlias);
                }
                aliases.insert(alias);
                index = end + 1;
                continue;
            }
        }
        index += 1;
    }
    if aliases.len() > MAX_INCIDENT_ALIASES_V1 {
        return Err(ExecutableIncidentErrorV1::TooManyEvidentrailAliases);
    }
    Ok(aliases.into_iter().collect())
}

fn checked_codes_v1(codes: Vec<String>) -> Result<Vec<String>, ExecutableIncidentErrorV1> {
    if codes.len() > MAX_INCIDENT_CODES_V1 {
        return Err(ExecutableIncidentErrorV1::TooManyCodes);
    }
    for code in &codes {
        validate_code_v1(code)?;
    }
    if !codes.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(ExecutableIncidentErrorV1::NonCanonicalCodes);
    }
    Ok(codes)
}

fn validate_code_v1(code: &str) -> Result<(), ExecutableIncidentErrorV1> {
    if code.is_empty()
        || code.len() > 128
        || !code.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'-' | b'.' | b'/')
        })
    {
        return Err(ExecutableIncidentErrorV1::InvalidCode);
    }
    Ok(())
}

fn append_hex_line_v1(output: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    output.extend_from_slice(name);
    output.push(b'=');
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in value {
        output.push(HEX[usize::from(byte >> 4)]);
        output.push(HEX[usize::from(byte & 0x0f)]);
    }
    output.push(b'\n');
}

fn decode_hex_v1(value: &str) -> Result<Vec<u8>, ExecutableIncidentErrorV1> {
    let bytes = value.as_bytes();
    if bytes.len() % 2 != 0 || bytes.len() / 2 > MAX_INCIDENT_PATCH_BYTES_V1 {
        return Err(ExecutableIncidentErrorV1::InvalidPatchEncoding);
    }
    bytes
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble_v1(pair[0])?;
            let low = hex_nibble_v1(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble_v1(byte: u8) -> Result<u8, ExecutableIncidentErrorV1> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ExecutableIncidentErrorV1::InvalidPatchEncoding),
    }
}

#[allow(clippy::too_many_arguments)]
fn derive_case_digest_v1(
    program: &ExecutableBuildV1,
    stdin: &[u8],
    question: &[u8],
    context: &[u8],
    stream: IncidentLogStreamV1,
    exit: IncidentExitExpectationV1,
    other_empty: bool,
    limits: HarnessLimitsV1,
) -> Result<ArtifactDigest, ExecutableIncidentErrorV1> {
    let stdin_digest = artifact_digest_for_bytes_v1(stdin);
    let question_digest = artifact_digest_for_bytes_v1(question);
    let context_digest = artifact_digest_for_bytes_v1(context);
    let exit = match exit {
        IncidentExitExpectationV1::Success => 0_i64.to_be_bytes(),
        IncidentExitExpectationV1::Nonzero(code) => i64::from(code).to_be_bytes(),
    };
    let mut material = Vec::new();
    append_field_v1(&mut material, INCIDENT_CASE_DOMAIN_V1)?;
    let executable_path = program
        .executable_path()
        .to_str()
        .ok_or(ExecutableIncidentErrorV1::Harness)?;
    let cwd = program
        .cwd()
        .to_str()
        .ok_or(ExecutableIncidentErrorV1::Harness)?;
    for field in [
        program.system_artifact_digest().as_bytes().as_slice(),
        program
            .executable_build_artifact_digest()
            .as_bytes()
            .as_slice(),
        stdin_digest.as_bytes().as_slice(),
        question_digest.as_bytes().as_slice(),
        context_digest.as_bytes().as_slice(),
        executable_path.as_bytes(),
        cwd.as_bytes(),
        program.output_contract().code().as_bytes(),
        program.adapter_revision().unwrap_or("").as_bytes(),
        stream.code().as_bytes(),
        &exit,
        &[u8::from(other_empty)],
    ] {
        append_field_v1(&mut material, field)?;
    }
    for argument in program.argv() {
        append_field_v1(&mut material, argument.as_bytes())?;
    }
    for name in program.environment().allowed_names() {
        append_field_v1(&mut material, name.as_bytes())?;
    }
    for binding in program.environment().bindings() {
        append_field_v1(&mut material, binding.name().as_bytes())?;
        append_field_v1(&mut material, binding.value().as_bytes())?;
    }
    for value in [
        limits.stdin_bytes(),
        limits.stdout_bytes(),
        limits.stderr_bytes(),
        limits.wall_nanos(),
    ] {
        append_field_v1(&mut material, &value.to_be_bytes())?;
    }
    Ok(artifact_digest_for_bytes_v1(&material))
}

fn agent_caps_binding_v1(caps: IncidentAgentCapsV1) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    for (index, value) in [
        caps.prompt_bytes,
        caps.answer_bytes,
        caps.stderr_bytes,
        caps.wall_time_nanos,
    ]
    .into_iter()
    .enumerate()
    {
        let start = index * 8;
        bytes[start..start + 8].copy_from_slice(&value.to_be_bytes());
    }
    bytes
}

fn verifier_caps_binding_v1(caps: IncidentVerifierCapsV1) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    for (index, value) in [
        caps.patch_bytes,
        caps.stdout_bytes,
        caps.stderr_bytes,
        caps.wall_time_nanos,
    ]
    .into_iter()
    .enumerate()
    {
        let start = index * 8;
        bytes[start..start + 8].copy_from_slice(&value.to_be_bytes());
    }
    bytes
}

fn digest_fields_v1(
    domain: &[u8],
    fields: &[&[u8]],
) -> Result<ArtifactDigest, ExecutableIncidentErrorV1> {
    let mut material = Vec::new();
    append_field_v1(&mut material, domain)?;
    for field in fields {
        append_field_v1(&mut material, field)?;
    }
    Ok(artifact_digest_for_bytes_v1(&material))
}

fn append_field_v1(output: &mut Vec<u8>, field: &[u8]) -> Result<(), ExecutableIncidentErrorV1> {
    output.extend_from_slice(&checked_len(field.len())?.to_be_bytes());
    output.extend_from_slice(field);
    Ok(())
}

fn checked_len(value: usize) -> Result<u64, ExecutableIncidentErrorV1> {
    u64::try_from(value).map_err(|_| ExecutableIncidentErrorV1::CountOverflow)
}

fn exit_binding_v1(exit: ExitCategoryV1) -> [u8; 9] {
    let (tag, value) = match exit {
        ExitCategoryV1::Success => (0, 0_i64),
        ExitCategoryV1::Nonzero { code } => (1, i64::from(code)),
        ExitCategoryV1::Signaled { signal } => (2, i64::from(signal.unwrap_or(i32::MIN))),
        ExitCategoryV1::HarnessTerminated => (3, 0_i64),
    };
    let mut bytes = [0_u8; 9];
    bytes[0] = tag;
    bytes[1..].copy_from_slice(&value.to_be_bytes());
    bytes
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ExecutableIncidentErrorV1 {
    Harness,
    EmptyQuestion,
    QuestionTooLarge,
    ContextTooLarge,
    StdinExceedsCap,
    CountOverflow,
    IncidentExecutionIncomplete,
    UnexpectedIncidentExit,
    EmptyIncidentLog,
    UnexpectedOtherStream,
    IncidentNotRepeatable,
    IncidentCaseBindingMismatch,
    InvalidArtifactBudget,
    ArtifactBudgetViolation,
    EvidentrailExecutionFailed,
    InvalidEvidentrailAlias,
    TooManyEvidentrailAliases,
    InvalidAgentCaps,
    AgentPromptTooLarge,
    AgentExecutionIncomplete,
    EmptyAgentAnswer,
    MalformedAgentAnswer,
    NonCanonicalAgentAnswer,
    InvalidAgentAnswer,
    InvalidPatch,
    InvalidPatchEncoding,
    InvalidVerifierCaps,
    PatchExceedsCap,
    VerifierExecutionIncomplete,
    InvalidGovernedTruth,
    GovernedBindingMismatch,
    VerifierPatchBindingMismatch,
    TooManyCodes,
    NonCanonicalCodes,
    InvalidCode,
}

impl ExecutableIncidentErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Harness => "EVIDENTRAIL_INCIDENT_HARNESS",
            Self::EmptyQuestion => "EVIDENTRAIL_INCIDENT_EMPTY_QUESTION",
            Self::QuestionTooLarge => "EVIDENTRAIL_INCIDENT_QUESTION_TOO_LARGE",
            Self::ContextTooLarge => "EVIDENTRAIL_INCIDENT_CONTEXT_TOO_LARGE",
            Self::StdinExceedsCap => "EVIDENTRAIL_INCIDENT_STDIN_EXCEEDS_CAP",
            Self::CountOverflow => "EVIDENTRAIL_INCIDENT_COUNT_OVERFLOW",
            Self::IncidentExecutionIncomplete => "EVIDENTRAIL_INCIDENT_EXECUTION_INCOMPLETE",
            Self::UnexpectedIncidentExit => "EVIDENTRAIL_INCIDENT_UNEXPECTED_EXIT",
            Self::EmptyIncidentLog => "EVIDENTRAIL_INCIDENT_EMPTY_LOG",
            Self::UnexpectedOtherStream => "EVIDENTRAIL_INCIDENT_UNEXPECTED_OTHER_STREAM",
            Self::IncidentNotRepeatable => "EVIDENTRAIL_INCIDENT_NOT_REPEATABLE",
            Self::IncidentCaseBindingMismatch => "EVIDENTRAIL_INCIDENT_CASE_BINDING_MISMATCH",
            Self::InvalidArtifactBudget => "EVIDENTRAIL_INCIDENT_INVALID_ARTIFACT_BUDGET",
            Self::ArtifactBudgetViolation => "EVIDENTRAIL_INCIDENT_ARTIFACT_BUDGET_VIOLATION",
            Self::EvidentrailExecutionFailed => "EVIDENTRAIL_INCIDENT_EVIDENTRAIL_EXECUTION_FAILED",
            Self::InvalidEvidentrailAlias => "EVIDENTRAIL_INCIDENT_INVALID_EVIDENTRAIL_ALIAS",
            Self::TooManyEvidentrailAliases => "EVIDENTRAIL_INCIDENT_TOO_MANY_EVIDENTRAIL_ALIASES",
            Self::InvalidAgentCaps => "EVIDENTRAIL_INCIDENT_INVALID_AGENT_CAPS",
            Self::AgentPromptTooLarge => "EVIDENTRAIL_INCIDENT_AGENT_PROMPT_TOO_LARGE",
            Self::AgentExecutionIncomplete => "EVIDENTRAIL_INCIDENT_AGENT_EXECUTION_INCOMPLETE",
            Self::EmptyAgentAnswer => "EVIDENTRAIL_INCIDENT_EMPTY_AGENT_ANSWER",
            Self::MalformedAgentAnswer => "EVIDENTRAIL_INCIDENT_MALFORMED_AGENT_ANSWER",
            Self::NonCanonicalAgentAnswer => "EVIDENTRAIL_INCIDENT_NONCANONICAL_AGENT_ANSWER",
            Self::InvalidAgentAnswer => "EVIDENTRAIL_INCIDENT_INVALID_AGENT_ANSWER",
            Self::InvalidPatch => "EVIDENTRAIL_INCIDENT_INVALID_PATCH",
            Self::InvalidPatchEncoding => "EVIDENTRAIL_INCIDENT_INVALID_PATCH_ENCODING",
            Self::InvalidVerifierCaps => "EVIDENTRAIL_INCIDENT_INVALID_VERIFIER_CAPS",
            Self::PatchExceedsCap => "EVIDENTRAIL_INCIDENT_PATCH_EXCEEDS_CAP",
            Self::VerifierExecutionIncomplete => "EVIDENTRAIL_INCIDENT_VERIFIER_INCOMPLETE",
            Self::InvalidGovernedTruth => "EVIDENTRAIL_INCIDENT_INVALID_GOVERNED_TRUTH",
            Self::GovernedBindingMismatch => "EVIDENTRAIL_INCIDENT_GOVERNED_BINDING_MISMATCH",
            Self::VerifierPatchBindingMismatch => "EVIDENTRAIL_INCIDENT_VERIFIER_PATCH_MISMATCH",
            Self::TooManyCodes => "EVIDENTRAIL_INCIDENT_TOO_MANY_CODES",
            Self::NonCanonicalCodes => "EVIDENTRAIL_INCIDENT_NONCANONICAL_CODES",
            Self::InvalidCode => "EVIDENTRAIL_INCIDENT_INVALID_CODE",
        }
    }
}

impl From<crate::HarnessError> for ExecutableIncidentErrorV1 {
    fn from(_: crate::HarnessError) -> Self {
        Self::Harness
    }
}

impl fmt::Debug for ExecutableIncidentErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutableIncidentErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for ExecutableIncidentErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ExecutableIncidentErrorV1 {}
