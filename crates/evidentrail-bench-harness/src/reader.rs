use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;
use std::path::PathBuf;

use evidentrail_bench::{
    EvidenceTargetV1, EvidentrailBenchAnnotationSpecV1, EvidentrailBenchCaseSpecV1,
    MethodDescriptor,
};
use evidentrail_core::derive_question_digest_v1;
use evidentrail_schema::bounds::JSON_SAFE_INTEGER_MAX;
use evidentrail_schema::{ArtifactDigest, QuestionDigest};
use serde::{Deserialize, Serialize};

use crate::peak_rss_observer::{RawMacOsTimePeakRssV1, execute_raw_with_macos_time_peak_rss_v1};
use crate::process::{RawSubprocessExecutionV1, RawSubprocessSpecV1};
use crate::{
    CapturedStreamV1, ClosedEnvironmentV1, ExecutableBuildV1, ExitCategoryV1,
    ExternalOutputContractV1, HarnessError, HarnessLimitsV1, MacOsTimePeakRssObserverV1,
    PeakRssObserverErrorV1, StdinDeliveryV1, StreamCaptureStateV1, artifact_digest_for_bytes_v1,
    artifact_digest_for_file_v1, canonical_public_case_artifact_v1,
};

pub const READER_SINGLE_SHOT_CONTRACT_VERSION_V1: u16 = 1;
pub const READER_ANSWER_SCHEMA_VERSION_V1: u16 = 1;
pub const READER_PROMPT_TEMPLATE_VERSION_V1: u16 = 1;
pub const DETERMINISTIC_FIXTURE_READER_CONTRACT_VERSION_V1: u16 = 1;

pub const MAX_READER_QUESTION_BYTES_V1: u64 = 64 * 1024;
pub const MAX_READER_CONTEXT_BYTES_V1: u64 = 16 * 1024 * 1024;
pub const MAX_READER_METHOD_ARTIFACT_BYTES_V1: u64 = 16 * 1024 * 1024;
pub const MAX_READER_ANSWER_BYTES_V1: u64 = 4 * 1024 * 1024;
pub const MAX_READER_CITATIONS_V1: u64 = 16_384;
pub const MAX_READER_CLAIMS_V1: u64 = 16_384;

const MAX_READER_DIAGNOSIS_BYTES_V1: usize = 64 * 1024;
const MAX_READER_CODE_BYTES_V1: usize = 256;
const MAX_READER_ABSTENTION_REASON_BYTES_V1: usize = 4 * 1024;
const FIXTURE_ADAPTER_REVISION_V1: &str = "evidentrail-bench-reader-fixture-v1";
const FIXTURE_SYSTEM_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/deterministic-reader-fixture-system/v1";
const FIXTURE_CONFIG_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/deterministic-reader-fixture-config/v1";
const METHOD_ARTIFACT_DOMAIN_V1: &[u8] = b"evidentrail/bench-harness/reader-method-artifact/v1";
const PUBLIC_INPUT_DOMAIN_V1: &[u8] = b"evidentrail/bench-harness/reader-public-input/v1";
const PROMPT_ARTIFACT_DOMAIN_V1: &[u8] = b"evidentrail/bench-harness/reader-prompt/v1";
const RECEIPT_ARTIFACT_DOMAIN_V1: &[u8] = b"evidentrail/bench-harness/reader-receipt/v1";
const REPEATABILITY_ARTIFACT_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/reader-repeatability/v1";
const GOVERNED_TRUTH_ARTIFACT_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/reader-governed-truth/v1";
const PROMPT_TEMPLATE_V1: &[u8] = b"EVIDENTRAIL_BENCH_READER_PROMPT_V1\n\
tainted_fields=lowercase_hex_only\n\
answer=canonical_json_v1\n\
tool_actions=forbidden\n\
citations=declared_integer_handles_only\n";
const UTF8_BYTE_TOKENIZER_CONTRACT_V1: &[u8] =
    b"evidentrail/bench-harness/reader-utf8-byte-tokenizer/v1";

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReaderCitationHandleV1 {
    handle: u32,
    targets: Vec<EvidenceTargetV1>,
    marker_start: u64,
    marker_end: u64,
}

impl ReaderCitationHandleV1 {
    pub fn try_new(
        handle: u32,
        targets: Vec<EvidenceTargetV1>,
        marker_start: u64,
        marker_end: u64,
    ) -> Result<Self, ReaderErrorV1> {
        if handle == 0 || marker_start >= marker_end || marker_end > JSON_SAFE_INTEGER_MAX {
            return Err(ReaderErrorV1::InvalidCitationHandle);
        }
        if targets.is_empty() {
            return Err(ReaderErrorV1::EmptyCitationTargets);
        }
        checked_collection_len(targets.len(), MAX_READER_CITATIONS_V1)?;
        let canonical_targets = targets.iter().copied().collect::<BTreeSet<_>>();
        if canonical_targets.len() != targets.len() {
            return Err(ReaderErrorV1::DuplicateCitationTarget);
        }
        Ok(Self {
            handle,
            targets: canonical_targets.into_iter().collect(),
            marker_start,
            marker_end,
        })
    }

    #[must_use]
    pub const fn handle(&self) -> u32 {
        self.handle
    }

    #[must_use]
    pub fn targets(&self) -> &[EvidenceTargetV1] {
        &self.targets
    }

    #[must_use]
    pub const fn marker_start(&self) -> u64 {
        self.marker_start
    }

    #[must_use]
    pub const fn marker_end(&self) -> u64 {
        self.marker_end
    }
}

impl fmt::Debug for ReaderCitationHandleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReaderCitationHandleV1")
            .field("handle", &self.handle)
            .field("target_count", &self.targets.len())
            .field("target_identities_redacted", &true)
            .field("marker_byte_count", &(self.marker_end - self.marker_start))
            .finish()
    }
}

/// Exact public representation handed to the reader. `bytes` are tainted
/// method output; citation handles are public occurrence identities available
/// to the reader, not governed labels.
#[derive(Clone, PartialEq, Eq)]
pub struct ReaderMethodArtifactV1 {
    public_case_artifact_digest: ArtifactDigest,
    method: MethodDescriptor,
    source_provenance_artifact_digest: ArtifactDigest,
    artifact_digest: ArtifactDigest,
    bytes: Box<[u8]>,
    citation_handles: Vec<ReaderCitationHandleV1>,
    binding_artifact_digest: ArtifactDigest,
}

impl ReaderMethodArtifactV1 {
    pub fn try_new(
        public_case_artifact_digest: ArtifactDigest,
        method: MethodDescriptor,
        source_provenance_artifact_digest: ArtifactDigest,
        artifact_digest: ArtifactDigest,
        bytes: Vec<u8>,
        citation_handles: Vec<ReaderCitationHandleV1>,
    ) -> Result<Self, ReaderErrorV1> {
        validate_method_descriptor_v1(method)?;
        checked_nonempty_bounded_len(
            bytes.len(),
            MAX_READER_METHOD_ARTIFACT_BYTES_V1,
            ReaderErrorV1::EmptyMethodArtifact,
            ReaderErrorV1::MethodArtifactTooLarge,
        )?;
        if artifact_digest_for_bytes_v1(&bytes) != artifact_digest {
            return Err(ReaderErrorV1::MethodArtifactDigestMismatch);
        }
        checked_collection_len(citation_handles.len(), MAX_READER_CITATIONS_V1)?;
        let mut seen_handles = BTreeSet::new();
        let mut seen_targets = BTreeSet::new();
        let mut marker_ranges = Vec::with_capacity(citation_handles.len());
        for citation in &citation_handles {
            if !seen_handles.insert(citation.handle()) {
                return Err(ReaderErrorV1::DuplicateCitationHandle);
            }
            for target in citation.targets() {
                if !seen_targets.insert(*target) {
                    return Err(ReaderErrorV1::DuplicateCitationTarget);
                }
            }
            let start = usize::try_from(citation.marker_start())
                .map_err(|_| ReaderErrorV1::InvalidCitationMarkerRange)?;
            let end = usize::try_from(citation.marker_end())
                .map_err(|_| ReaderErrorV1::InvalidCitationMarkerRange)?;
            let Some(marker_bytes) = bytes.get(start..end) else {
                return Err(ReaderErrorV1::InvalidCitationMarkerRange);
            };
            let explicit_marker = format!("[EVIDENTRAIL_EVIDENCE:{}]", citation.handle());
            let canonical_brief_marker = format!("[E{}]", citation.handle());
            if marker_bytes != explicit_marker.as_bytes()
                && marker_bytes != canonical_brief_marker.as_bytes()
            {
                return Err(ReaderErrorV1::CitationMarkerMismatch);
            }
            marker_ranges.push((start, end));
        }
        marker_ranges.sort_unstable();
        if marker_ranges
            .windows(2)
            .any(|ranges| ranges[0].1 > ranges[1].0)
        {
            return Err(ReaderErrorV1::CitationMarkerOverlap);
        }
        if !citation_handles
            .windows(2)
            .all(|pair| pair[0].handle() < pair[1].handle())
        {
            return Err(ReaderErrorV1::NonCanonicalCitationHandles);
        }
        let binding_artifact_digest = derive_method_artifact_binding_v1(
            public_case_artifact_digest,
            method,
            source_provenance_artifact_digest,
            artifact_digest,
            &citation_handles,
        )?;
        Ok(Self {
            public_case_artifact_digest,
            method,
            source_provenance_artifact_digest,
            artifact_digest,
            bytes: bytes.into_boxed_slice(),
            citation_handles,
            binding_artifact_digest,
        })
    }

    #[must_use]
    pub const fn public_case_artifact_digest(&self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn method(&self) -> MethodDescriptor {
        self.method
    }

    #[must_use]
    pub const fn source_provenance_artifact_digest(&self) -> ArtifactDigest {
        self.source_provenance_artifact_digest
    }

    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn citation_handles(&self) -> &[ReaderCitationHandleV1] {
        &self.citation_handles
    }

    #[must_use]
    pub const fn binding_artifact_digest(&self) -> ArtifactDigest {
        self.binding_artifact_digest
    }

    fn targets_for_handle(&self, handle: u32) -> Option<&[EvidenceTargetV1]> {
        self.citation_handles
            .binary_search_by_key(&handle, |citation| citation.handle())
            .ok()
            .map(|index| self.citation_handles[index].targets())
    }
}

impl fmt::Debug for ReaderMethodArtifactV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReaderMethodArtifactV1")
            .field("public_case_binding_present", &true)
            .field("method_binding_present", &true)
            .field("source_provenance_binding_present", &true)
            .field("artifact_identity_present", &true)
            .field("byte_count", &self.bytes.len())
            .field("citation_handle_count", &self.citation_handles.len())
            .field("contains_hidden_labels", &false)
            .finish()
    }
}

/// Label-free public input for one reader call.
#[derive(Clone, PartialEq, Eq)]
pub struct ReaderPublicInputV1 {
    public_case: EvidentrailBenchCaseSpecV1,
    public_case_artifact_digest: ArtifactDigest,
    question: Box<[u8]>,
    question_digest: QuestionDigest,
    context: Box<[u8]>,
    context_artifact_digest: ArtifactDigest,
    method_artifact: ReaderMethodArtifactV1,
    artifact_digest: ArtifactDigest,
}

impl ReaderPublicInputV1 {
    pub fn try_new(
        public_case: EvidentrailBenchCaseSpecV1,
        question: Vec<u8>,
        context_artifact_digest: ArtifactDigest,
        context: Vec<u8>,
        method_artifact: ReaderMethodArtifactV1,
    ) -> Result<Self, ReaderErrorV1> {
        checked_nonempty_bounded_len(
            question.len(),
            MAX_READER_QUESTION_BYTES_V1,
            ReaderErrorV1::EmptyQuestion,
            ReaderErrorV1::QuestionTooLarge,
        )?;
        let question_digest = derive_question_digest_v1(&question);
        if question_digest != public_case.question_digest() {
            return Err(ReaderErrorV1::QuestionDigestMismatch);
        }
        checked_nonempty_bounded_len(
            context.len(),
            MAX_READER_CONTEXT_BYTES_V1,
            ReaderErrorV1::EmptyContext,
            ReaderErrorV1::ContextTooLarge,
        )?;
        if artifact_digest_for_bytes_v1(&context) != context_artifact_digest {
            return Err(ReaderErrorV1::ContextArtifactDigestMismatch);
        }
        let canonical_case = canonical_public_case_artifact_v1(&public_case)?;
        let public_case_artifact_digest = canonical_case.artifact_digest();
        if method_artifact.public_case_artifact_digest() != public_case_artifact_digest {
            return Err(ReaderErrorV1::MethodCaseBindingMismatch);
        }
        let artifact_digest = derive_public_input_artifact_v1(
            public_case_artifact_digest,
            question_digest,
            &question,
            context_artifact_digest,
            &context,
            method_artifact.binding_artifact_digest(),
        )?;
        Ok(Self {
            public_case,
            public_case_artifact_digest,
            question: question.into_boxed_slice(),
            question_digest,
            context: context.into_boxed_slice(),
            context_artifact_digest,
            method_artifact,
            artifact_digest,
        })
    }

    #[must_use]
    pub const fn public_case(&self) -> &EvidentrailBenchCaseSpecV1 {
        &self.public_case
    }

    #[must_use]
    pub const fn public_case_artifact_digest(&self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn question(&self) -> &[u8] {
        &self.question
    }

    #[must_use]
    pub const fn question_digest(&self) -> QuestionDigest {
        self.question_digest
    }

    #[must_use]
    pub const fn context(&self) -> &[u8] {
        &self.context
    }

    #[must_use]
    pub const fn context_artifact_digest(&self) -> ArtifactDigest {
        self.context_artifact_digest
    }

    #[must_use]
    pub const fn method_artifact(&self) -> &ReaderMethodArtifactV1 {
        &self.method_artifact
    }

    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }
}

impl fmt::Debug for ReaderPublicInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReaderPublicInputV1")
            .field("public_case_binding_present", &true)
            .field("question_byte_count", &self.question.len())
            .field("question_identity_present", &true)
            .field("context_byte_count", &self.context.len())
            .field("context_identity_present", &true)
            .field("method_artifact", &self.method_artifact)
            .field("contains_hidden_labels", &false)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DeterministicFixtureReaderModeV1 {
    Correct,
    Abstain,
    AlternateValid,
    InvalidCitation,
    AdversarialNondeterministic,
    Malformed,
    Oversize,
    Timeout,
    ToolAction,
}

impl DeterministicFixtureReaderModeV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Correct => "correct",
            Self::Abstain => "abstain",
            Self::AlternateValid => "alternate-valid",
            Self::InvalidCitation => "invalid-citation",
            Self::AdversarialNondeterministic => "adversarial-nondeterministic",
            Self::Malformed => "malformed",
            Self::Oversize => "oversize",
            Self::Timeout => "timeout",
            Self::ToolAction => "tool-action",
        }
    }
}

impl fmt::Debug for DeterministicFixtureReaderModeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeterministicFixtureReaderModeV1")
            .field("code", &self.code())
            .finish()
    }
}

/// A pinned, local deterministic fixture command. This V1 target class admits
/// no environment bindings or hosted-provider configuration. The harness does
/// not claim an OS network sandbox; it admits only this exact fixture contract.
#[derive(Clone, PartialEq, Eq)]
pub struct DeterministicFixtureReaderV1 {
    program: ExecutableBuildV1,
    mode: DeterministicFixtureReaderModeV1,
    configuration_artifact_digest: ArtifactDigest,
}

impl DeterministicFixtureReaderV1 {
    pub fn try_new(
        executable_path: PathBuf,
        cwd: PathBuf,
        mode: DeterministicFixtureReaderModeV1,
    ) -> Result<Self, ReaderErrorV1> {
        let executable_build_artifact_digest = artifact_digest_for_file_v1(&executable_path)?;
        let system_artifact_digest = derive_fixture_system_artifact_v1(
            executable_build_artifact_digest,
            DETERMINISTIC_FIXTURE_READER_CONTRACT_VERSION_V1,
        )?;
        let program = ExecutableBuildV1::try_new(
            system_artifact_digest,
            executable_build_artifact_digest,
            executable_path,
            vec![
                "--evidentrail-bench-reader-fixture-v1".to_owned(),
                mode.code().to_owned(),
            ],
            cwd,
            ClosedEnvironmentV1::empty(),
            ExternalOutputContractV1::ExactIdentityNormalizer,
            Some(FIXTURE_ADAPTER_REVISION_V1.to_owned()),
        )?;
        let configuration_artifact_digest =
            derive_fixture_configuration_artifact_v1(&program, mode)?;
        Ok(Self {
            program,
            mode,
            configuration_artifact_digest,
        })
    }

    #[must_use]
    pub const fn program(&self) -> &ExecutableBuildV1 {
        &self.program
    }

    #[must_use]
    pub const fn mode(&self) -> DeterministicFixtureReaderModeV1 {
        self.mode
    }

    #[must_use]
    pub const fn configuration_artifact_digest(&self) -> ArtifactDigest {
        self.configuration_artifact_digest
    }

    #[must_use]
    pub const fn hosted_provider_calls_allowed(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn host_network_isolation_claimed(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn fixture_contract_only(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn deterministic_output_expected(&self) -> bool {
        !matches!(
            self.mode,
            DeterministicFixtureReaderModeV1::AdversarialNondeterministic
        )
    }
}

impl fmt::Debug for DeterministicFixtureReaderV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeterministicFixtureReaderV1")
            .field("program", &self.program)
            .field("mode", &self.mode)
            .field("configuration_identity_present", &true)
            .field("hosted_provider_calls_allowed", &false)
            .field("host_network_isolation_claimed", &false)
            .field("fixture_contract_only", &true)
            .field(
                "deterministic_output_expected",
                &self.deterministic_output_expected(),
            )
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReaderResourceCapsV1 {
    harness_limits: HarnessLimitsV1,
    prompt_token_cap: u64,
    answer_token_cap: u64,
    peak_rss_byte_cap: u64,
    reader_call_cap: u64,
    tokenizer_artifact_digest: ArtifactDigest,
}

impl ReaderResourceCapsV1 {
    pub fn try_new(
        harness_limits: HarnessLimitsV1,
        prompt_token_cap: u64,
        answer_token_cap: u64,
        peak_rss_byte_cap: u64,
        reader_call_cap: u64,
    ) -> Result<Self, ReaderErrorV1> {
        for value in [prompt_token_cap, answer_token_cap, peak_rss_byte_cap] {
            if value == 0 || value > JSON_SAFE_INTEGER_MAX {
                return Err(ReaderErrorV1::InvalidResourceCap);
            }
        }
        if reader_call_cap != 1 {
            return Err(ReaderErrorV1::ReaderCallCapMustBeOne);
        }
        if answer_token_cap > MAX_READER_ANSWER_BYTES_V1
            || prompt_token_cap > harness_limits.stdin_bytes()
            || harness_limits.stdout_bytes() > answer_token_cap
        {
            return Err(ReaderErrorV1::InconsistentResourceCaps);
        }
        Ok(Self {
            harness_limits,
            prompt_token_cap,
            answer_token_cap,
            peak_rss_byte_cap,
            reader_call_cap,
            tokenizer_artifact_digest: artifact_digest_for_bytes_v1(
                UTF8_BYTE_TOKENIZER_CONTRACT_V1,
            ),
        })
    }

    #[must_use]
    pub const fn harness_limits(self) -> HarnessLimitsV1 {
        self.harness_limits
    }

    #[must_use]
    pub const fn prompt_token_cap(self) -> u64 {
        self.prompt_token_cap
    }

    #[must_use]
    pub const fn answer_token_cap(self) -> u64 {
        self.answer_token_cap
    }

    #[must_use]
    pub const fn peak_rss_byte_cap(self) -> u64 {
        self.peak_rss_byte_cap
    }

    #[must_use]
    pub const fn reader_call_cap(self) -> u64 {
        self.reader_call_cap
    }

    #[must_use]
    pub const fn tokenizer_contract(self) -> &'static str {
        "canonical_utf8_bytes_v1"
    }

    #[must_use]
    pub const fn tokenizer_artifact_digest(self) -> ArtifactDigest {
        self.tokenizer_artifact_digest
    }
}

impl fmt::Debug for ReaderResourceCapsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReaderResourceCapsV1")
            .field("harness_limits", &self.harness_limits)
            .field("prompt_token_cap", &self.prompt_token_cap)
            .field("answer_token_cap", &self.answer_token_cap)
            .field("peak_rss_byte_cap", &self.peak_rss_byte_cap)
            .field("reader_call_cap", &self.reader_call_cap)
            .field("tokenizer_contract", &self.tokenizer_contract())
            .field("tokenizer_identity_present", &true)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ReaderPromptV1 {
    bytes: Box<[u8]>,
    artifact_digest: ArtifactDigest,
    template_artifact_digest: ArtifactDigest,
    canonical_token_count: u64,
}

impl ReaderPromptV1 {
    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn template_artifact_digest(&self) -> ArtifactDigest {
        self.template_artifact_digest
    }

    #[must_use]
    pub const fn canonical_token_count(&self) -> u64 {
        self.canonical_token_count
    }

    /// The V1 bytes are a canonical, injection-resistant subprocess transport.
    /// They are not claimed to be the future hosted model-visible message.
    #[must_use]
    pub const fn canonical_subprocess_transport(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn model_visible_prompt_claimed(&self) -> bool {
        false
    }
}

impl fmt::Debug for ReaderPromptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReaderPromptV1")
            .field("byte_count", &self.bytes.len())
            .field("artifact_identity_present", &true)
            .field("template_identity_present", &true)
            .field("canonical_token_count", &self.canonical_token_count)
            .field("tainted_fields_hex_encoded", &true)
            .field("canonical_subprocess_transport", &true)
            .field("model_visible_prompt_claimed", &false)
            .field("contains_hidden_labels", &false)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReaderCauseGranularityV1 {
    RootCause,
    ContributingCause,
    Symptom,
    Unspecified,
}

impl ReaderCauseGranularityV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::RootCause => "root_cause",
            Self::ContributingCause => "contributing_cause",
            Self::Symptom => "symptom",
            Self::Unspecified => "unspecified",
        }
    }
}

impl fmt::Debug for ReaderCauseGranularityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReaderCauseGranularityV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReaderAnswerV1 {
    schema_version: u16,
    abstained: bool,
    abstention_reason: Option<String>,
    cause_code: Option<String>,
    cause_granularity: ReaderCauseGranularityV1,
    diagnosis: Option<String>,
    citation_handles: Vec<u32>,
    claim_codes: Vec<String>,
    uncertainty_micros: u64,
    tool_actions: Vec<String>,
}

impl ReaderAnswerV1 {
    #[must_use]
    pub const fn abstained(&self) -> bool {
        self.abstained
    }

    #[must_use]
    pub fn cause_code(&self) -> Option<&str> {
        self.cause_code.as_deref()
    }

    #[must_use]
    pub const fn cause_granularity(&self) -> ReaderCauseGranularityV1 {
        self.cause_granularity
    }

    #[must_use]
    pub fn diagnosis(&self) -> Option<&str> {
        self.diagnosis.as_deref()
    }

    #[must_use]
    pub fn citation_handles(&self) -> &[u32] {
        &self.citation_handles
    }

    #[must_use]
    pub fn claim_codes(&self) -> &[String] {
        &self.claim_codes
    }

    #[must_use]
    pub const fn uncertainty_micros(&self) -> u64 {
        self.uncertainty_micros
    }

    #[must_use]
    pub fn tool_action_count(&self) -> usize {
        self.tool_actions.len()
    }
}

impl fmt::Debug for ReaderAnswerV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReaderAnswerV1")
            .field("schema_version", &self.schema_version)
            .field("abstained", &self.abstained)
            .field(
                "abstention_reason_present",
                &self.abstention_reason.is_some(),
            )
            .field("cause_present", &self.cause_code.is_some())
            .field("cause_granularity", &self.cause_granularity)
            .field("diagnosis_present", &self.diagnosis.is_some())
            .field("citation_count", &self.citation_handles.len())
            .field("claim_count", &self.claim_codes.len())
            .field("uncertainty_micros", &self.uncertainty_micros)
            .field("tool_action_count", &self.tool_actions.len())
            .field("content_redacted", &true)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct FrozenReaderSingleShotReceiptV1 {
    artifact_digest: ArtifactDigest,
    public_input: ReaderPublicInputV1,
    target: DeterministicFixtureReaderV1,
    caps: ReaderResourceCapsV1,
    prompt: ReaderPromptV1,
    answer: ReaderAnswerV1,
    answer_artifact_digest: ArtifactDigest,
    answer_bytes: Box<[u8]>,
    answer_canonical_token_count: u64,
    wall_time_nanos: u64,
    peak_rss_bytes: u64,
    stdout: CapturedStreamV1,
    stderr: CapturedStreamV1,
    observer_measurement_mechanism_artifact_digest: ArtifactDigest,
    observer_raw_report_artifact_digest: ArtifactDigest,
    observer_raw_report_byte_count: u64,
}

impl FrozenReaderSingleShotReceiptV1 {
    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn public_input(&self) -> &ReaderPublicInputV1 {
        &self.public_input
    }

    #[must_use]
    pub const fn target(&self) -> &DeterministicFixtureReaderV1 {
        &self.target
    }

    #[must_use]
    pub const fn caps(&self) -> ReaderResourceCapsV1 {
        self.caps
    }

    #[must_use]
    pub const fn prompt(&self) -> &ReaderPromptV1 {
        &self.prompt
    }

    #[must_use]
    pub const fn answer(&self) -> &ReaderAnswerV1 {
        &self.answer
    }

    #[must_use]
    pub const fn answer_artifact_digest(&self) -> ArtifactDigest {
        self.answer_artifact_digest
    }

    #[must_use]
    pub const fn answer_bytes(&self) -> &[u8] {
        &self.answer_bytes
    }

    #[must_use]
    pub const fn answer_canonical_token_count(&self) -> u64 {
        self.answer_canonical_token_count
    }

    #[must_use]
    pub const fn wall_time_nanos(&self) -> u64 {
        self.wall_time_nanos
    }

    #[must_use]
    pub const fn stdin_delivery(&self) -> StdinDeliveryV1 {
        StdinDeliveryV1::Complete
    }

    #[must_use]
    pub const fn exit_category(&self) -> ExitCategoryV1 {
        ExitCategoryV1::Success
    }

    #[must_use]
    pub const fn child_reaped(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn peak_rss_bytes(&self) -> u64 {
        self.peak_rss_bytes
    }

    #[must_use]
    pub const fn reader_call_count(&self) -> u64 {
        1
    }

    #[must_use]
    pub const fn stdout(&self) -> &CapturedStreamV1 {
        &self.stdout
    }

    #[must_use]
    pub const fn stderr(&self) -> &CapturedStreamV1 {
        &self.stderr
    }

    #[must_use]
    pub const fn observer_measurement_mechanism_artifact_digest(&self) -> ArtifactDigest {
        self.observer_measurement_mechanism_artifact_digest
    }

    #[must_use]
    pub const fn observer_raw_report_artifact_digest(&self) -> ArtifactDigest {
        self.observer_raw_report_artifact_digest
    }

    #[must_use]
    pub const fn observer_raw_report_byte_count(&self) -> u64 {
        self.observer_raw_report_byte_count
    }

    #[must_use]
    pub const fn independently_attested(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn directly_timed_process_only(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn child_tree_peak_rss_claimed(&self) -> bool {
        false
    }

    /// V1 observes RSS after the direct process exits. It rejects a completed
    /// observation above the cap but does not claim a live memory kill.
    #[must_use]
    pub const fn live_peak_rss_enforcement_claimed(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn contains_hidden_labels(&self) -> bool {
        false
    }
}

impl fmt::Debug for FrozenReaderSingleShotReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenReaderSingleShotReceiptV1")
            .field("receipt_identity_present", &true)
            .field("public_input", &self.public_input)
            .field("target", &self.target)
            .field("caps", &self.caps)
            .field("prompt", &self.prompt)
            .field("answer", &self.answer)
            .field("answer_artifact_identity_present", &true)
            .field("answer_byte_count", &self.answer_bytes.len())
            .field(
                "answer_canonical_token_count",
                &self.answer_canonical_token_count,
            )
            .field("wall_time_nanos", &self.wall_time_nanos)
            .field("peak_rss_bytes", &self.peak_rss_bytes)
            .field("reader_call_count", &1_u64)
            .field("observer_mechanism_bound", &true)
            .field("observer_raw_report_bound", &true)
            .field("independently_attested", &false)
            .field("directly_timed_process_only", &true)
            .field("child_tree_peak_rss_claimed", &false)
            .field("live_peak_rss_enforcement_claimed", &false)
            .field("contains_hidden_labels", &false)
            .finish()
    }
}

pub fn execute_deterministic_fixture_reader_v1(
    observer: &MacOsTimePeakRssObserverV1,
    target: &DeterministicFixtureReaderV1,
    public_input: &ReaderPublicInputV1,
    caps: ReaderResourceCapsV1,
) -> Result<FrozenReaderSingleShotReceiptV1, ReaderErrorV1> {
    let prompt = build_reader_prompt_v1(public_input)?;
    if prompt.canonical_token_count() > caps.prompt_token_cap()
        || prompt.canonical_token_count() > caps.harness_limits().stdin_bytes()
    {
        return Err(ReaderErrorV1::PromptCapExceeded);
    }
    let observed = execute_raw_with_macos_time_peak_rss_v1(
        observer,
        RawSubprocessSpecV1 {
            program: target.program(),
            stdin_bytes: prompt.bytes(),
            limits: caps.harness_limits(),
        },
    )?;
    validate_successful_reader_execution_v1(&observed.execution)?;
    let execution = observed.execution;
    let rss = observed.peak_rss?;
    if rss.peak_rss_bytes > caps.peak_rss_byte_cap() {
        return Err(ReaderErrorV1::PeakRssCapExceeded);
    }
    let answer_bytes = execution.stdout.bytes().to_vec();
    let answer_canonical_token_count = checked_len(answer_bytes.len())?;
    if answer_canonical_token_count > caps.answer_token_cap() {
        return Err(ReaderErrorV1::AnswerTokenCapExceeded);
    }
    let answer = parse_strict_reader_answer_v1(&answer_bytes)?;
    let answer_artifact_digest = artifact_digest_for_bytes_v1(&answer_bytes);
    let artifact_digest = derive_reader_receipt_artifact_v1(
        public_input,
        target,
        caps,
        &prompt,
        &execution,
        &rss,
        answer_artifact_digest,
        answer_canonical_token_count,
    )?;
    Ok(FrozenReaderSingleShotReceiptV1 {
        artifact_digest,
        public_input: public_input.clone(),
        target: target.clone(),
        caps,
        prompt,
        answer,
        answer_artifact_digest,
        answer_bytes: answer_bytes.into_boxed_slice(),
        answer_canonical_token_count,
        wall_time_nanos: execution.wall_time_nanos,
        peak_rss_bytes: rss.peak_rss_bytes,
        stdout: execution.stdout,
        stderr: execution.stderr,
        observer_measurement_mechanism_artifact_digest: rss.measurement_mechanism_artifact_digest,
        observer_raw_report_artifact_digest: rss.raw_report_artifact_digest,
        observer_raw_report_byte_count: rss.raw_report_byte_count,
    })
}

#[derive(Clone, PartialEq, Eq)]
pub struct ReaderRepeatabilityReceiptV1 {
    artifact_digest: ArtifactDigest,
    trial_count: u64,
    public_input_artifact_digest: ArtifactDigest,
    method_artifact_binding_digest: ArtifactDigest,
    reader_configuration_artifact_digest: ArtifactDigest,
    answer_artifact_digest: ArtifactDigest,
    trial_receipt_artifact_digests: Vec<ArtifactDigest>,
}

impl ReaderRepeatabilityReceiptV1 {
    pub fn try_new(trials: &[FrozenReaderSingleShotReceiptV1]) -> Result<Self, ReaderErrorV1> {
        if trials.len() < 2 {
            return Err(ReaderErrorV1::InsufficientRepeatabilityTrials);
        }
        checked_collection_len(trials.len(), 31)?;
        let first = &trials[0];
        for trial in &trials[1..] {
            if trial.public_input.artifact_digest() != first.public_input.artifact_digest()
                || trial
                    .public_input
                    .method_artifact()
                    .binding_artifact_digest()
                    != first
                        .public_input
                        .method_artifact()
                        .binding_artifact_digest()
                || trial.target.configuration_artifact_digest()
                    != first.target.configuration_artifact_digest()
                || trial.target.program().executable_build_artifact_digest()
                    != first.target.program().executable_build_artifact_digest()
                || trial.prompt.artifact_digest() != first.prompt.artifact_digest()
                || trial.caps != first.caps
            {
                return Err(ReaderErrorV1::RepeatabilityBindingMismatch);
            }
            if trial.answer_artifact_digest != first.answer_artifact_digest {
                return Err(ReaderErrorV1::ReaderNondeterministic);
            }
        }
        let trial_count = checked_len(trials.len())?;
        let trial_receipt_artifact_digests = trials
            .iter()
            .map(FrozenReaderSingleShotReceiptV1::artifact_digest)
            .collect::<Vec<_>>();
        let artifact_digest = derive_repeatability_artifact_v1(
            trial_count,
            first.public_input.artifact_digest(),
            first
                .public_input
                .method_artifact()
                .binding_artifact_digest(),
            first.target.configuration_artifact_digest(),
            first.answer_artifact_digest,
            &trial_receipt_artifact_digests,
        )?;
        Ok(Self {
            artifact_digest,
            trial_count,
            public_input_artifact_digest: first.public_input.artifact_digest(),
            method_artifact_binding_digest: first
                .public_input
                .method_artifact()
                .binding_artifact_digest(),
            reader_configuration_artifact_digest: first.target.configuration_artifact_digest(),
            answer_artifact_digest: first.answer_artifact_digest,
            trial_receipt_artifact_digests,
        })
    }

    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn trial_count(&self) -> u64 {
        self.trial_count
    }

    #[must_use]
    pub const fn public_input_artifact_digest(&self) -> ArtifactDigest {
        self.public_input_artifact_digest
    }

    #[must_use]
    pub const fn method_artifact_binding_digest(&self) -> ArtifactDigest {
        self.method_artifact_binding_digest
    }

    #[must_use]
    pub const fn reader_configuration_artifact_digest(&self) -> ArtifactDigest {
        self.reader_configuration_artifact_digest
    }

    #[must_use]
    pub const fn answer_artifact_digest(&self) -> ArtifactDigest {
        self.answer_artifact_digest
    }

    #[must_use]
    pub fn trial_receipt_artifact_digests(&self) -> &[ArtifactDigest] {
        &self.trial_receipt_artifact_digests
    }

    #[must_use]
    pub const fn contains_hidden_labels(&self) -> bool {
        false
    }
}

impl fmt::Debug for ReaderRepeatabilityReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReaderRepeatabilityReceiptV1")
            .field("artifact_identity_present", &true)
            .field("trial_count", &self.trial_count)
            .field("public_input_binding_present", &true)
            .field("method_artifact_binding_present", &true)
            .field("reader_configuration_binding_present", &true)
            .field("answer_binding_present", &true)
            .field(
                "trial_receipt_count",
                &self.trial_receipt_artifact_digests.len(),
            )
            .field("contains_hidden_labels", &false)
            .finish()
    }
}

/// Governed truth enters only after one public reader receipt has frozen.
#[derive(Clone, PartialEq, Eq)]
pub struct GovernedReaderTruthV1 {
    artifact_digest: ArtifactDigest,
    public_case_artifact_digest: ArtifactDigest,
    annotation: EvidentrailBenchAnnotationSpecV1,
    answerable: bool,
    accepted_cause_codes: BTreeSet<String>,
    accepted_granularities: BTreeSet<ReaderCauseGranularityV1>,
    supported_claim_codes: BTreeSet<String>,
    forbidden_claim_codes: BTreeSet<String>,
}

impl GovernedReaderTruthV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        public_case_artifact_digest: ArtifactDigest,
        annotation: EvidentrailBenchAnnotationSpecV1,
        answerable: bool,
        accepted_cause_codes: Vec<String>,
        accepted_granularities: Vec<ReaderCauseGranularityV1>,
        supported_claim_codes: Vec<String>,
        forbidden_claim_codes: Vec<String>,
    ) -> Result<Self, ReaderErrorV1> {
        if annotation.public_case_artifact_digest() != public_case_artifact_digest {
            return Err(ReaderErrorV1::GovernedCaseBindingMismatch);
        }
        let accepted_cause_codes = checked_code_set(accepted_cause_codes)?;
        let accepted_granularities = accepted_granularities.into_iter().collect::<BTreeSet<_>>();
        if answerable && (accepted_cause_codes.is_empty() || accepted_granularities.is_empty()) {
            return Err(ReaderErrorV1::MissingAnswerableTruth);
        }
        if !answerable && (!accepted_cause_codes.is_empty() || !accepted_granularities.is_empty()) {
            return Err(ReaderErrorV1::UnexpectedUnanswerableTruth);
        }
        if accepted_granularities.contains(&ReaderCauseGranularityV1::Unspecified) {
            return Err(ReaderErrorV1::InvalidGovernedGranularity);
        }
        let supported_claim_codes = checked_code_set(supported_claim_codes)?;
        let forbidden_claim_codes = checked_code_set(forbidden_claim_codes)?;
        if !supported_claim_codes.is_disjoint(&forbidden_claim_codes) {
            return Err(ReaderErrorV1::GovernedClaimSetsOverlap);
        }
        let artifact_digest = derive_governed_truth_artifact_v1(
            public_case_artifact_digest,
            &annotation,
            answerable,
            &accepted_cause_codes,
            &accepted_granularities,
            &supported_claim_codes,
            &forbidden_claim_codes,
        )?;
        Ok(Self {
            artifact_digest,
            public_case_artifact_digest,
            annotation,
            answerable,
            accepted_cause_codes,
            accepted_granularities,
            supported_claim_codes,
            forbidden_claim_codes,
        })
    }

    #[must_use]
    pub(crate) const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }
}

impl fmt::Debug for GovernedReaderTruthV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedReaderTruthV1")
            .field("public_case_binding_present", &true)
            .field("answerable", &self.answerable)
            .field("accepted_cause_count", &self.accepted_cause_codes.len())
            .field(
                "accepted_granularity_count",
                &self.accepted_granularities.len(),
            )
            .field("supported_claim_count", &self.supported_claim_codes.len())
            .field("forbidden_claim_count", &self.forbidden_claim_codes.len())
            .field("annotation", &self.annotation)
            .field("content_redacted", &true)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ReaderAbstentionAssessmentV1 {
    Appropriate,
    Inappropriate,
    NotExercised,
}

impl ReaderAbstentionAssessmentV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Appropriate => "appropriate",
            Self::Inappropriate => "inappropriate",
            Self::NotExercised => "not_exercised",
        }
    }
}

impl fmt::Debug for ReaderAbstentionAssessmentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReaderAbstentionAssessmentV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GovernedReaderScoreV1 {
    cause_code_verified: bool,
    cause_granularity_verified: bool,
    diagnosis_present: bool,
    cited_handle_count: u64,
    valid_citation_count: u64,
    invalid_citation_count: u64,
    satisfied_requirement_count: u64,
    total_requirement_count: u64,
    satisfied_requirement_weight_micros: u64,
    total_requirement_weight_micros: u64,
    unsupported_claim_count: u64,
    forbidden_claim_count: u64,
    abstention: ReaderAbstentionAssessmentV1,
    uncertainty_micros: u64,
}

impl GovernedReaderScoreV1 {
    #[must_use]
    pub const fn cause_code_verified(self) -> bool {
        self.cause_code_verified
    }

    #[must_use]
    pub const fn cause_granularity_verified(self) -> bool {
        self.cause_granularity_verified
    }

    #[must_use]
    pub const fn diagnosis_present(self) -> bool {
        self.diagnosis_present
    }

    #[must_use]
    pub const fn cited_handle_count(self) -> u64 {
        self.cited_handle_count
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
    pub const fn satisfied_requirement_count(self) -> u64 {
        self.satisfied_requirement_count
    }

    #[must_use]
    pub const fn total_requirement_count(self) -> u64 {
        self.total_requirement_count
    }

    #[must_use]
    pub const fn satisfied_requirement_weight_micros(self) -> u64 {
        self.satisfied_requirement_weight_micros
    }

    #[must_use]
    pub const fn total_requirement_weight_micros(self) -> u64 {
        self.total_requirement_weight_micros
    }

    #[must_use]
    pub const fn unsupported_claim_count(self) -> u64 {
        self.unsupported_claim_count
    }

    #[must_use]
    pub const fn forbidden_claim_count(self) -> u64 {
        self.forbidden_claim_count
    }

    #[must_use]
    pub const fn abstention(self) -> ReaderAbstentionAssessmentV1 {
        self.abstention
    }

    #[must_use]
    pub const fn uncertainty_micros(self) -> u64 {
        self.uncertainty_micros
    }

    #[must_use]
    pub const fn scalar_score_available(self) -> bool {
        false
    }

    #[must_use]
    pub const fn llm_judge_used(self) -> bool {
        false
    }
}

impl fmt::Debug for GovernedReaderScoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedReaderScoreV1")
            .field("cause_code_verified", &self.cause_code_verified)
            .field(
                "cause_granularity_verified",
                &self.cause_granularity_verified,
            )
            .field("diagnosis_present", &self.diagnosis_present)
            .field("cited_handle_count", &self.cited_handle_count)
            .field("valid_citation_count", &self.valid_citation_count)
            .field("invalid_citation_count", &self.invalid_citation_count)
            .field(
                "satisfied_requirement_count",
                &self.satisfied_requirement_count,
            )
            .field("total_requirement_count", &self.total_requirement_count)
            .field(
                "satisfied_requirement_weight_micros",
                &self.satisfied_requirement_weight_micros,
            )
            .field(
                "total_requirement_weight_micros",
                &self.total_requirement_weight_micros,
            )
            .field("unsupported_claim_count", &self.unsupported_claim_count)
            .field("forbidden_claim_count", &self.forbidden_claim_count)
            .field("abstention", &self.abstention)
            .field("uncertainty_micros", &self.uncertainty_micros)
            .field("scalar_score_available", &false)
            .field("llm_judge_used", &false)
            .field("hidden_values_redacted", &true)
            .finish()
    }
}

pub fn evaluate_governed_reader_v1(
    receipt: &FrozenReaderSingleShotReceiptV1,
    truth: &GovernedReaderTruthV1,
) -> Result<GovernedReaderScoreV1, ReaderErrorV1> {
    if receipt.public_input.public_case_artifact_digest() != truth.public_case_artifact_digest
        || truth.annotation.public_case_artifact_digest() != truth.public_case_artifact_digest
    {
        return Err(ReaderErrorV1::GovernedCaseBindingMismatch);
    }
    let answer = receipt.answer();
    let cause_code_verified = answer
        .cause_code()
        .is_some_and(|code| truth.accepted_cause_codes.contains(code));
    let cause_granularity_verified = truth
        .accepted_granularities
        .contains(&answer.cause_granularity());
    let diagnosis_present = answer.diagnosis().is_some();

    let mut selected_targets = BTreeSet::new();
    let mut valid_citation_count = 0_u64;
    let mut invalid_citation_count = 0_u64;
    for handle in answer.citation_handles() {
        match receipt
            .public_input
            .method_artifact
            .targets_for_handle(*handle)
        {
            Some(targets) => {
                selected_targets.extend(targets.iter().copied());
                valid_citation_count = valid_citation_count
                    .checked_add(1)
                    .ok_or(ReaderErrorV1::ScoreOverflow)?;
            }
            None => {
                invalid_citation_count = invalid_citation_count
                    .checked_add(1)
                    .ok_or(ReaderErrorV1::ScoreOverflow)?;
            }
        }
    }
    let cited_handle_count = checked_len(answer.citation_handles().len())?;
    let mut satisfied_requirement_count = 0_u64;
    let total_requirement_count = checked_len(truth.annotation.diagnostic_requirements().len())?;
    let mut satisfied_requirement_weight_micros = 0_u64;
    let mut total_requirement_weight_micros = 0_u64;
    for requirement in truth.annotation.diagnostic_requirements() {
        total_requirement_weight_micros = total_requirement_weight_micros
            .checked_add(requirement.weight_micros())
            .ok_or(ReaderErrorV1::ScoreOverflow)?;
        if requirement.is_satisfied_by(&selected_targets) {
            satisfied_requirement_count = satisfied_requirement_count
                .checked_add(1)
                .ok_or(ReaderErrorV1::ScoreOverflow)?;
            satisfied_requirement_weight_micros = satisfied_requirement_weight_micros
                .checked_add(requirement.weight_micros())
                .ok_or(ReaderErrorV1::ScoreOverflow)?;
        }
    }
    let unsupported_claim_count = checked_len(
        answer
            .claim_codes()
            .iter()
            .filter(|claim| !truth.supported_claim_codes.contains(claim.as_str()))
            .count(),
    )?;
    let forbidden_claim_count = checked_len(
        answer
            .claim_codes()
            .iter()
            .filter(|claim| truth.forbidden_claim_codes.contains(claim.as_str()))
            .count(),
    )?;
    let abstention = match (truth.answerable, answer.abstained()) {
        (false, true) => ReaderAbstentionAssessmentV1::Appropriate,
        (true, true) | (false, false) => ReaderAbstentionAssessmentV1::Inappropriate,
        (true, false) => ReaderAbstentionAssessmentV1::NotExercised,
    };
    Ok(GovernedReaderScoreV1 {
        cause_code_verified,
        cause_granularity_verified,
        diagnosis_present,
        cited_handle_count,
        valid_citation_count,
        invalid_citation_count,
        satisfied_requirement_count,
        total_requirement_count,
        satisfied_requirement_weight_micros,
        total_requirement_weight_micros,
        unsupported_claim_count,
        forbidden_claim_count,
        abstention,
        uncertainty_micros: answer.uncertainty_micros(),
    })
}

fn build_reader_prompt_v1(input: &ReaderPublicInputV1) -> Result<ReaderPromptV1, ReaderErrorV1> {
    let template_artifact_digest = artifact_digest_for_bytes_v1(PROMPT_TEMPLATE_V1);
    let mut bytes = PROMPT_TEMPLATE_V1.to_vec();
    append_ascii_line(
        &mut bytes,
        "contract_version",
        READER_SINGLE_SHOT_CONTRACT_VERSION_V1,
    )?;
    append_ascii_line(
        &mut bytes,
        "answer_schema_version",
        READER_ANSWER_SCHEMA_VERSION_V1,
    )?;
    append_ascii_line(
        &mut bytes,
        "prompt_template_version",
        READER_PROMPT_TEMPLATE_VERSION_V1,
    )?;
    append_hex_line(
        &mut bytes,
        "public_case_artifact",
        input.public_case_artifact_digest().as_bytes(),
    );
    append_hex_line(&mut bytes, "question", input.question());
    append_hex_line(&mut bytes, "context", input.context());
    append_hex_line(
        &mut bytes,
        "method_name",
        input.method_artifact.method().name().as_bytes(),
    );
    append_hex_line(
        &mut bytes,
        "method_version",
        input.method_artifact.method().version().as_bytes(),
    );
    append_hex_line(&mut bytes, "method_artifact", input.method_artifact.bytes());
    bytes.extend_from_slice(b"citation_handles=");
    for (index, citation) in input.method_artifact.citation_handles().iter().enumerate() {
        if index > 0 {
            bytes.push(b',');
        }
        bytes.extend_from_slice(citation.handle().to_string().as_bytes());
        bytes.push(b':');
        let target_kind = citation_kind_summary_v1(citation.targets());
        bytes.extend_from_slice(target_kind.as_bytes());
    }
    bytes.push(b'\n');
    let canonical_token_count = checked_len(bytes.len())?;
    let mut binding = Vec::new();
    append_field(&mut binding, PROMPT_ARTIFACT_DOMAIN_V1)?;
    append_field(&mut binding, template_artifact_digest.as_bytes())?;
    append_field(&mut binding, input.artifact_digest().as_bytes())?;
    append_field(&mut binding, &bytes)?;
    let artifact_digest = artifact_digest_for_bytes_v1(&binding);
    Ok(ReaderPromptV1 {
        bytes: bytes.into_boxed_slice(),
        artifact_digest,
        template_artifact_digest,
        canonical_token_count,
    })
}

fn citation_kind_summary_v1(targets: &[EvidenceTargetV1]) -> &'static str {
    let contains_event = targets
        .iter()
        .any(|target| matches!(target, EvidenceTargetV1::Event(_)));
    let contains_block = targets
        .iter()
        .any(|target| matches!(target, EvidenceTargetV1::Block(_)));
    match (contains_event, contains_block) {
        (true, false) => "event_set",
        (false, true) => "block_set",
        (true, true) => "mixed_set",
        (false, false) => "empty",
    }
}

pub(crate) fn parse_strict_reader_answer_v1(bytes: &[u8]) -> Result<ReaderAnswerV1, ReaderErrorV1> {
    checked_nonempty_bounded_len(
        bytes.len(),
        MAX_READER_ANSWER_BYTES_V1,
        ReaderErrorV1::EmptyAnswer,
        ReaderErrorV1::AnswerTooLarge,
    )?;
    let answer = serde_json::from_slice::<ReaderAnswerV1>(bytes)
        .map_err(|_| ReaderErrorV1::MalformedAnswer)?;
    if answer.schema_version != READER_ANSWER_SCHEMA_VERSION_V1 {
        return Err(ReaderErrorV1::UnsupportedAnswerSchema);
    }
    validate_reader_answer_semantics_v1(&answer)?;
    let canonical = serde_json::to_vec(&answer).map_err(|_| ReaderErrorV1::MalformedAnswer)?;
    if canonical != bytes {
        return Err(ReaderErrorV1::NonCanonicalAnswer);
    }
    Ok(answer)
}

fn validate_reader_answer_semantics_v1(answer: &ReaderAnswerV1) -> Result<(), ReaderErrorV1> {
    if answer.uncertainty_micros > 1_000_000 {
        return Err(ReaderErrorV1::InvalidUncertaintyMicros);
    }
    if !answer.tool_actions.is_empty() {
        return Err(ReaderErrorV1::ToolActionsForbidden);
    }
    checked_collection_len(answer.citation_handles.len(), MAX_READER_CITATIONS_V1)?;
    if answer.citation_handles.contains(&0)
        || !answer
            .citation_handles
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    {
        return Err(ReaderErrorV1::NonCanonicalAnswerCitations);
    }
    checked_collection_len(answer.claim_codes.len(), MAX_READER_CLAIMS_V1)?;
    for code in &answer.claim_codes {
        validate_code(code)?;
    }
    if !answer.claim_codes.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(ReaderErrorV1::NonCanonicalAnswerClaims);
    }
    match answer.abstained {
        true => {
            let Some(reason) = answer.abstention_reason.as_deref() else {
                return Err(ReaderErrorV1::InvalidAbstentionShape);
            };
            validate_nonempty_text(reason, MAX_READER_ABSTENTION_REASON_BYTES_V1)?;
            if answer.cause_code.is_some()
                || answer.diagnosis.is_some()
                || answer.cause_granularity != ReaderCauseGranularityV1::Unspecified
                || !answer.citation_handles.is_empty()
                || !answer.claim_codes.is_empty()
            {
                return Err(ReaderErrorV1::InvalidAbstentionShape);
            }
        }
        false => {
            if answer.abstention_reason.is_some()
                || answer.cause_granularity == ReaderCauseGranularityV1::Unspecified
            {
                return Err(ReaderErrorV1::InvalidAnswerShape);
            }
            let Some(cause_code) = answer.cause_code.as_deref() else {
                return Err(ReaderErrorV1::InvalidAnswerShape);
            };
            validate_code(cause_code)?;
            let Some(diagnosis) = answer.diagnosis.as_deref() else {
                return Err(ReaderErrorV1::InvalidAnswerShape);
            };
            validate_nonempty_text(diagnosis, MAX_READER_DIAGNOSIS_BYTES_V1)?;
        }
    }
    Ok(())
}

fn validate_successful_reader_execution_v1(
    execution: &RawSubprocessExecutionV1,
) -> Result<(), ReaderErrorV1> {
    if execution.stdin_delivery != StdinDeliveryV1::Complete
        || execution.exit_category != ExitCategoryV1::Success
        || execution.stdout.state() != StreamCaptureStateV1::Complete
        || execution.stderr.state() != StreamCaptureStateV1::Complete
        || !execution.termination_causes.is_empty()
        || !execution.child_reaped
        || !execution.executable_path_digest_verified_before_spawn
        || !execution.executable_path_digest_verified_after_spawn
    {
        return Err(ReaderErrorV1::ReaderExecutionIncomplete);
    }
    if !execution.stderr.bytes().is_empty() {
        return Err(ReaderErrorV1::ReaderStderrNotEmpty);
    }
    Ok(())
}

fn validate_method_descriptor_v1(method: MethodDescriptor) -> Result<(), ReaderErrorV1> {
    if method.name().is_empty()
        || method.version().is_empty()
        || method.name().len() > MAX_READER_CODE_BYTES_V1
        || method.version().len() > MAX_READER_CODE_BYTES_V1
        || method
            .name()
            .bytes()
            .chain(method.version().bytes())
            .any(|byte| byte == 0 || !byte.is_ascii_graphic())
    {
        return Err(ReaderErrorV1::InvalidMethodDescriptor);
    }
    Ok(())
}

fn validate_code(code: &str) -> Result<(), ReaderErrorV1> {
    if code.is_empty()
        || code.len() > MAX_READER_CODE_BYTES_V1
        || !code.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
    {
        return Err(ReaderErrorV1::InvalidAnswerCode);
    }
    Ok(())
}

fn validate_nonempty_text(value: &str, max_bytes: usize) -> Result<(), ReaderErrorV1> {
    if value.is_empty() || value.len() > max_bytes || value.as_bytes().contains(&0) {
        return Err(ReaderErrorV1::InvalidAnswerText);
    }
    Ok(())
}

fn checked_code_set(values: Vec<String>) -> Result<BTreeSet<String>, ReaderErrorV1> {
    checked_collection_len(values.len(), MAX_READER_CLAIMS_V1)?;
    let mut result = BTreeSet::new();
    for value in values {
        validate_code(&value)?;
        if !result.insert(value) {
            return Err(ReaderErrorV1::DuplicateGovernedCode);
        }
    }
    Ok(result)
}

fn checked_nonempty_bounded_len(
    len: usize,
    max: u64,
    empty: ReaderErrorV1,
    oversized: ReaderErrorV1,
) -> Result<u64, ReaderErrorV1> {
    if len == 0 {
        return Err(empty);
    }
    let len = checked_len(len)?;
    if len > max {
        return Err(oversized);
    }
    Ok(len)
}

fn checked_collection_len(len: usize, max: u64) -> Result<u64, ReaderErrorV1> {
    let len = checked_len(len)?;
    if len > max || len > JSON_SAFE_INTEGER_MAX {
        return Err(ReaderErrorV1::CollectionTooLarge);
    }
    Ok(len)
}

fn checked_len(len: usize) -> Result<u64, ReaderErrorV1> {
    u64::try_from(len).map_err(|_| ReaderErrorV1::ArtifactLengthOverflow)
}

fn append_ascii_line(output: &mut Vec<u8>, name: &str, value: u16) -> Result<(), ReaderErrorV1> {
    output.extend_from_slice(name.as_bytes());
    output.push(b'=');
    output.extend_from_slice(value.to_string().as_bytes());
    output.push(b'\n');
    if checked_len(output.len())? > JSON_SAFE_INTEGER_MAX {
        return Err(ReaderErrorV1::ArtifactLengthOverflow);
    }
    Ok(())
}

fn append_hex_line(output: &mut Vec<u8>, name: &str, value: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    output.extend_from_slice(name.as_bytes());
    output.push(b'=');
    for byte in value {
        output.push(HEX[usize::from(byte >> 4)]);
        output.push(HEX[usize::from(byte & 0x0f)]);
    }
    output.push(b'\n');
}

fn append_field(output: &mut Vec<u8>, field: &[u8]) -> Result<(), ReaderErrorV1> {
    let length = checked_len(field.len())?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(field);
    Ok(())
}

fn append_target(output: &mut Vec<u8>, target: EvidenceTargetV1) -> Result<(), ReaderErrorV1> {
    match target {
        EvidenceTargetV1::Event(event_id) => {
            append_field(output, b"event")?;
            append_field(output, event_id.as_bytes())?;
        }
        EvidenceTargetV1::Block(block_id) => {
            append_field(output, b"block")?;
            append_field(output, block_id.as_bytes())?;
        }
    }
    Ok(())
}

fn derive_method_artifact_binding_v1(
    case: ArtifactDigest,
    method: MethodDescriptor,
    source_provenance: ArtifactDigest,
    artifact: ArtifactDigest,
    citations: &[ReaderCitationHandleV1],
) -> Result<ArtifactDigest, ReaderErrorV1> {
    let mut bytes = Vec::new();
    append_field(&mut bytes, METHOD_ARTIFACT_DOMAIN_V1)?;
    append_field(&mut bytes, case.as_bytes())?;
    append_field(&mut bytes, method.name().as_bytes())?;
    append_field(&mut bytes, method.version().as_bytes())?;
    append_field(&mut bytes, source_provenance.as_bytes())?;
    append_field(&mut bytes, artifact.as_bytes())?;
    append_field(&mut bytes, &checked_len(citations.len())?.to_le_bytes())?;
    for citation in citations {
        append_field(&mut bytes, &citation.handle().to_le_bytes())?;
        append_field(&mut bytes, &citation.marker_start().to_le_bytes())?;
        append_field(&mut bytes, &citation.marker_end().to_le_bytes())?;
        append_field(
            &mut bytes,
            &checked_len(citation.targets().len())?.to_le_bytes(),
        )?;
        for target in citation.targets() {
            append_target(&mut bytes, *target)?;
        }
    }
    Ok(artifact_digest_for_bytes_v1(&bytes))
}

fn derive_public_input_artifact_v1(
    case: ArtifactDigest,
    question_digest: QuestionDigest,
    question: &[u8],
    context_digest: ArtifactDigest,
    context: &[u8],
    method_binding: ArtifactDigest,
) -> Result<ArtifactDigest, ReaderErrorV1> {
    let mut bytes = Vec::new();
    append_field(&mut bytes, PUBLIC_INPUT_DOMAIN_V1)?;
    append_field(&mut bytes, case.as_bytes())?;
    append_field(&mut bytes, question_digest.as_bytes())?;
    append_field(&mut bytes, question)?;
    append_field(&mut bytes, context_digest.as_bytes())?;
    append_field(&mut bytes, context)?;
    append_field(&mut bytes, method_binding.as_bytes())?;
    Ok(artifact_digest_for_bytes_v1(&bytes))
}

fn derive_fixture_system_artifact_v1(
    build: ArtifactDigest,
    contract_version: u16,
) -> Result<ArtifactDigest, ReaderErrorV1> {
    let mut bytes = Vec::new();
    append_field(&mut bytes, FIXTURE_SYSTEM_DOMAIN_V1)?;
    append_field(&mut bytes, &contract_version.to_le_bytes())?;
    append_field(&mut bytes, build.as_bytes())?;
    Ok(artifact_digest_for_bytes_v1(&bytes))
}

fn derive_fixture_configuration_artifact_v1(
    program: &ExecutableBuildV1,
    mode: DeterministicFixtureReaderModeV1,
) -> Result<ArtifactDigest, ReaderErrorV1> {
    let mut bytes = Vec::new();
    append_field(&mut bytes, FIXTURE_CONFIG_DOMAIN_V1)?;
    append_field(
        &mut bytes,
        &DETERMINISTIC_FIXTURE_READER_CONTRACT_VERSION_V1.to_le_bytes(),
    )?;
    append_field(&mut bytes, mode.code().as_bytes())?;
    append_field(&mut bytes, PROMPT_TEMPLATE_V1)?;
    append_field(&mut bytes, program.system_artifact_digest().as_bytes())?;
    append_field(
        &mut bytes,
        program.executable_build_artifact_digest().as_bytes(),
    )?;
    append_field(
        &mut bytes,
        program
            .executable_path()
            .to_str()
            .ok_or(ReaderErrorV1::ReaderConfigurationEncodingInvalid)?
            .as_bytes(),
    )?;
    append_field(
        &mut bytes,
        program
            .cwd()
            .to_str()
            .ok_or(ReaderErrorV1::ReaderConfigurationEncodingInvalid)?
            .as_bytes(),
    )?;
    append_field(
        &mut bytes,
        &checked_len(program.argv().len())?.to_le_bytes(),
    )?;
    for argument in program.argv() {
        append_field(&mut bytes, argument.as_bytes())?;
    }
    append_field(
        &mut bytes,
        &checked_len(program.environment().allowed_names().len())?.to_le_bytes(),
    )?;
    append_field(
        &mut bytes,
        &checked_len(program.environment().bindings().len())?.to_le_bytes(),
    )?;
    append_field(&mut bytes, program.output_contract().code().as_bytes())?;
    append_field(
        &mut bytes,
        program.adapter_revision().unwrap_or_default().as_bytes(),
    )?;
    Ok(artifact_digest_for_bytes_v1(&bytes))
}

#[allow(clippy::too_many_arguments)]
fn derive_reader_receipt_artifact_v1(
    input: &ReaderPublicInputV1,
    target: &DeterministicFixtureReaderV1,
    caps: ReaderResourceCapsV1,
    prompt: &ReaderPromptV1,
    execution: &RawSubprocessExecutionV1,
    rss: &RawMacOsTimePeakRssV1,
    answer_artifact: ArtifactDigest,
    answer_tokens: u64,
) -> Result<ArtifactDigest, ReaderErrorV1> {
    let mut bytes = Vec::new();
    append_field(&mut bytes, RECEIPT_ARTIFACT_DOMAIN_V1)?;
    append_field(
        &mut bytes,
        &READER_SINGLE_SHOT_CONTRACT_VERSION_V1.to_le_bytes(),
    )?;
    append_field(&mut bytes, input.artifact_digest().as_bytes())?;
    append_field(&mut bytes, input.public_case_artifact_digest().as_bytes())?;
    append_field(
        &mut bytes,
        input.method_artifact.binding_artifact_digest().as_bytes(),
    )?;
    append_field(
        &mut bytes,
        target.program.system_artifact_digest().as_bytes(),
    )?;
    append_field(
        &mut bytes,
        target.program.executable_build_artifact_digest().as_bytes(),
    )?;
    append_field(&mut bytes, target.configuration_artifact_digest.as_bytes())?;
    append_field(&mut bytes, prompt.template_artifact_digest().as_bytes())?;
    append_field(&mut bytes, prompt.artifact_digest().as_bytes())?;
    for cap in [
        caps.harness_limits().stdin_bytes(),
        caps.harness_limits().stdout_bytes(),
        caps.harness_limits().stderr_bytes(),
        caps.harness_limits().wall_nanos(),
        caps.prompt_token_cap(),
        caps.answer_token_cap(),
        caps.peak_rss_byte_cap(),
        caps.reader_call_cap(),
    ] {
        append_field(&mut bytes, &cap.to_le_bytes())?;
    }
    append_field(&mut bytes, caps.tokenizer_artifact_digest().as_bytes())?;
    append_field(&mut bytes, execution.stdout.artifact_digest().as_bytes())?;
    append_field(&mut bytes, execution.stderr.artifact_digest().as_bytes())?;
    append_field(&mut bytes, execution.stdin_delivery.code().as_bytes())?;
    append_field(&mut bytes, execution.exit_category.code().as_bytes())?;
    append_field(&mut bytes, execution.stdout.state().code().as_bytes())?;
    append_field(&mut bytes, execution.stderr.state().code().as_bytes())?;
    append_field(
        &mut bytes,
        &checked_len(execution.termination_causes.len())?.to_le_bytes(),
    )?;
    for cause in &execution.termination_causes {
        append_field(&mut bytes, cause.code().as_bytes())?;
    }
    append_field(&mut bytes, &[u8::from(execution.child_reaped)])?;
    append_field(
        &mut bytes,
        &[u8::from(
            execution.executable_path_digest_verified_before_spawn,
        )],
    )?;
    append_field(
        &mut bytes,
        &[u8::from(
            execution.executable_path_digest_verified_after_spawn,
        )],
    )?;
    append_field(&mut bytes, &execution.wall_time_nanos.to_le_bytes())?;
    append_field(&mut bytes, answer_artifact.as_bytes())?;
    append_field(&mut bytes, &answer_tokens.to_le_bytes())?;
    append_field(
        &mut bytes,
        rss.observer_executable_build_artifact_digest.as_bytes(),
    )?;
    append_field(&mut bytes, rss.observer_digest_before_spawn.as_bytes())?;
    append_field(&mut bytes, rss.observer_digest_after_reap.as_bytes())?;
    append_field(&mut bytes, rss.report_format_artifact_digest.as_bytes())?;
    append_field(
        &mut bytes,
        rss.measurement_mechanism_artifact_digest.as_bytes(),
    )?;
    append_field(&mut bytes, rss.raw_report_artifact_digest.as_bytes())?;
    append_field(&mut bytes, &rss.raw_report_byte_count.to_le_bytes())?;
    append_field(&mut bytes, &rss.peak_rss_bytes.to_le_bytes())?;
    Ok(artifact_digest_for_bytes_v1(&bytes))
}

fn derive_repeatability_artifact_v1(
    trial_count: u64,
    input: ArtifactDigest,
    method: ArtifactDigest,
    config: ArtifactDigest,
    answer: ArtifactDigest,
    trial_receipts: &[ArtifactDigest],
) -> Result<ArtifactDigest, ReaderErrorV1> {
    let mut bytes = Vec::new();
    append_field(&mut bytes, REPEATABILITY_ARTIFACT_DOMAIN_V1)?;
    append_field(&mut bytes, &trial_count.to_le_bytes())?;
    append_field(&mut bytes, input.as_bytes())?;
    append_field(&mut bytes, method.as_bytes())?;
    append_field(&mut bytes, config.as_bytes())?;
    append_field(&mut bytes, answer.as_bytes())?;
    for receipt in trial_receipts {
        append_field(&mut bytes, receipt.as_bytes())?;
    }
    Ok(artifact_digest_for_bytes_v1(&bytes))
}

#[allow(clippy::too_many_arguments)]
fn derive_governed_truth_artifact_v1(
    public_case: ArtifactDigest,
    annotation: &EvidentrailBenchAnnotationSpecV1,
    answerable: bool,
    accepted_causes: &BTreeSet<String>,
    accepted_granularities: &BTreeSet<ReaderCauseGranularityV1>,
    supported_claims: &BTreeSet<String>,
    forbidden_claims: &BTreeSet<String>,
) -> Result<ArtifactDigest, ReaderErrorV1> {
    let mut bytes = Vec::new();
    append_field(&mut bytes, GOVERNED_TRUTH_ARTIFACT_DOMAIN_V1)?;
    append_field(&mut bytes, public_case.as_bytes())?;
    append_field(&mut bytes, &[u8::from(answerable)])?;
    append_field(
        &mut bytes,
        &checked_len(annotation.diagnostic_requirements().len())?.to_le_bytes(),
    )?;
    for requirement in annotation.diagnostic_requirements() {
        append_field(&mut bytes, &requirement.weight_micros().to_le_bytes())?;
        append_field(
            &mut bytes,
            &checked_len(requirement.alternatives().len())?.to_le_bytes(),
        )?;
        for alternative in requirement.alternatives() {
            append_field(&mut bytes, &checked_len(alternative.len())?.to_le_bytes())?;
            for target in alternative {
                append_evidence_target_v1(&mut bytes, *target)?;
            }
        }
    }
    for targets in [
        annotation.precursor_targets(),
        annotation.symptom_targets(),
        annotation.supporting_targets(),
        annotation.distractor_targets(),
        annotation.unsafe_targets(),
    ] {
        match targets {
            Some(targets) => {
                append_field(&mut bytes, &[1])?;
                append_field(&mut bytes, &checked_len(targets.len())?.to_le_bytes())?;
                for target in targets {
                    append_evidence_target_v1(&mut bytes, *target)?;
                }
            }
            None => append_field(&mut bytes, &[0])?,
        }
    }
    append_code_set_v1(&mut bytes, accepted_causes)?;
    append_field(
        &mut bytes,
        &checked_len(accepted_granularities.len())?.to_le_bytes(),
    )?;
    for granularity in accepted_granularities {
        append_field(&mut bytes, granularity.code().as_bytes())?;
    }
    append_code_set_v1(&mut bytes, supported_claims)?;
    append_code_set_v1(&mut bytes, forbidden_claims)?;
    Ok(artifact_digest_for_bytes_v1(&bytes))
}

fn append_evidence_target_v1(
    bytes: &mut Vec<u8>,
    target: EvidenceTargetV1,
) -> Result<(), ReaderErrorV1> {
    match target {
        EvidenceTargetV1::Event(event_id) => {
            append_field(bytes, b"event")?;
            append_field(bytes, event_id.as_bytes())
        }
        EvidenceTargetV1::Block(block_id) => {
            append_field(bytes, b"block")?;
            append_field(bytes, block_id.as_bytes())
        }
    }
}

fn append_code_set_v1(bytes: &mut Vec<u8>, codes: &BTreeSet<String>) -> Result<(), ReaderErrorV1> {
    append_field(bytes, &checked_len(codes.len())?.to_le_bytes())?;
    for code in codes {
        append_field(bytes, code.as_bytes())?;
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ReaderErrorV1 {
    InvalidCitationHandle,
    EmptyCitationTargets,
    InvalidCitationMarkerRange,
    CitationMarkerMismatch,
    CitationMarkerOverlap,
    DuplicateCitationHandle,
    NonCanonicalCitationHandles,
    DuplicateCitationTarget,
    EmptyMethodArtifact,
    MethodArtifactTooLarge,
    MethodArtifactDigestMismatch,
    InvalidMethodDescriptor,
    ReaderConfigurationEncodingInvalid,
    EmptyQuestion,
    QuestionTooLarge,
    QuestionDigestMismatch,
    EmptyContext,
    ContextTooLarge,
    ContextArtifactDigestMismatch,
    MethodCaseBindingMismatch,
    InvalidResourceCap,
    ReaderCallCapMustBeOne,
    InconsistentResourceCaps,
    PromptCapExceeded,
    PeakRssCapExceeded,
    AnswerTokenCapExceeded,
    ReaderExecutionIncomplete,
    ReaderStderrNotEmpty,
    EmptyAnswer,
    AnswerTooLarge,
    MalformedAnswer,
    UnsupportedAnswerSchema,
    NonCanonicalAnswer,
    InvalidUncertaintyMicros,
    ToolActionsForbidden,
    NonCanonicalAnswerCitations,
    NonCanonicalAnswerClaims,
    InvalidAbstentionShape,
    InvalidAnswerShape,
    InvalidAnswerCode,
    InvalidAnswerText,
    CollectionTooLarge,
    ArtifactLengthOverflow,
    InsufficientRepeatabilityTrials,
    RepeatabilityBindingMismatch,
    ReaderNondeterministic,
    GovernedCaseBindingMismatch,
    MissingAnswerableTruth,
    UnexpectedUnanswerableTruth,
    InvalidGovernedGranularity,
    GovernedClaimSetsOverlap,
    DuplicateGovernedCode,
    ScoreOverflow,
    Harness(HarnessError),
    PeakRssObserver(PeakRssObserverErrorV1),
}

impl ReaderErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidCitationHandle => "EVIDENTRAIL_BENCH_READER_INVALID_CITATION_HANDLE",
            Self::EmptyCitationTargets => "EVIDENTRAIL_BENCH_READER_EMPTY_CITATION_TARGETS",
            Self::InvalidCitationMarkerRange => {
                "EVIDENTRAIL_BENCH_READER_INVALID_CITATION_MARKER_RANGE"
            }
            Self::CitationMarkerMismatch => "EVIDENTRAIL_BENCH_READER_CITATION_MARKER_MISMATCH",
            Self::CitationMarkerOverlap => "EVIDENTRAIL_BENCH_READER_CITATION_MARKER_OVERLAP",
            Self::DuplicateCitationHandle => "EVIDENTRAIL_BENCH_READER_DUPLICATE_CITATION_HANDLE",
            Self::NonCanonicalCitationHandles => {
                "EVIDENTRAIL_BENCH_READER_NONCANONICAL_CITATION_HANDLES"
            }
            Self::DuplicateCitationTarget => "EVIDENTRAIL_BENCH_READER_DUPLICATE_CITATION_TARGET",
            Self::EmptyMethodArtifact => "EVIDENTRAIL_BENCH_READER_EMPTY_METHOD_ARTIFACT",
            Self::MethodArtifactTooLarge => "EVIDENTRAIL_BENCH_READER_METHOD_ARTIFACT_TOO_LARGE",
            Self::MethodArtifactDigestMismatch => {
                "EVIDENTRAIL_BENCH_READER_METHOD_ARTIFACT_DIGEST_MISMATCH"
            }
            Self::InvalidMethodDescriptor => "EVIDENTRAIL_BENCH_READER_INVALID_METHOD_DESCRIPTOR",
            Self::ReaderConfigurationEncodingInvalid => {
                "EVIDENTRAIL_BENCH_READER_CONFIGURATION_ENCODING_INVALID"
            }
            Self::EmptyQuestion => "EVIDENTRAIL_BENCH_READER_EMPTY_QUESTION",
            Self::QuestionTooLarge => "EVIDENTRAIL_BENCH_READER_QUESTION_TOO_LARGE",
            Self::QuestionDigestMismatch => "EVIDENTRAIL_BENCH_READER_QUESTION_DIGEST_MISMATCH",
            Self::EmptyContext => "EVIDENTRAIL_BENCH_READER_EMPTY_CONTEXT",
            Self::ContextTooLarge => "EVIDENTRAIL_BENCH_READER_CONTEXT_TOO_LARGE",
            Self::ContextArtifactDigestMismatch => {
                "EVIDENTRAIL_BENCH_READER_CONTEXT_ARTIFACT_DIGEST_MISMATCH"
            }
            Self::MethodCaseBindingMismatch => {
                "EVIDENTRAIL_BENCH_READER_METHOD_CASE_BINDING_MISMATCH"
            }
            Self::InvalidResourceCap => "EVIDENTRAIL_BENCH_READER_INVALID_RESOURCE_CAP",
            Self::ReaderCallCapMustBeOne => "EVIDENTRAIL_BENCH_READER_CALL_CAP_MUST_BE_ONE",
            Self::InconsistentResourceCaps => "EVIDENTRAIL_BENCH_READER_INCONSISTENT_RESOURCE_CAPS",
            Self::PromptCapExceeded => "EVIDENTRAIL_BENCH_READER_PROMPT_CAP_EXCEEDED",
            Self::PeakRssCapExceeded => "EVIDENTRAIL_BENCH_READER_PEAK_RSS_CAP_EXCEEDED",
            Self::AnswerTokenCapExceeded => "EVIDENTRAIL_BENCH_READER_ANSWER_TOKEN_CAP_EXCEEDED",
            Self::ReaderExecutionIncomplete => "EVIDENTRAIL_BENCH_READER_EXECUTION_INCOMPLETE",
            Self::ReaderStderrNotEmpty => "EVIDENTRAIL_BENCH_READER_STDERR_NOT_EMPTY",
            Self::EmptyAnswer => "EVIDENTRAIL_BENCH_READER_EMPTY_ANSWER",
            Self::AnswerTooLarge => "EVIDENTRAIL_BENCH_READER_ANSWER_TOO_LARGE",
            Self::MalformedAnswer => "EVIDENTRAIL_BENCH_READER_MALFORMED_ANSWER",
            Self::UnsupportedAnswerSchema => "EVIDENTRAIL_BENCH_READER_UNSUPPORTED_ANSWER_SCHEMA",
            Self::NonCanonicalAnswer => "EVIDENTRAIL_BENCH_READER_NONCANONICAL_ANSWER",
            Self::InvalidUncertaintyMicros => "EVIDENTRAIL_BENCH_READER_INVALID_UNCERTAINTY_MICROS",
            Self::ToolActionsForbidden => "EVIDENTRAIL_BENCH_READER_TOOL_ACTIONS_FORBIDDEN",
            Self::NonCanonicalAnswerCitations => {
                "EVIDENTRAIL_BENCH_READER_NONCANONICAL_ANSWER_CITATIONS"
            }
            Self::NonCanonicalAnswerClaims => "EVIDENTRAIL_BENCH_READER_NONCANONICAL_ANSWER_CLAIMS",
            Self::InvalidAbstentionShape => "EVIDENTRAIL_BENCH_READER_INVALID_ABSTENTION_SHAPE",
            Self::InvalidAnswerShape => "EVIDENTRAIL_BENCH_READER_INVALID_ANSWER_SHAPE",
            Self::InvalidAnswerCode => "EVIDENTRAIL_BENCH_READER_INVALID_ANSWER_CODE",
            Self::InvalidAnswerText => "EVIDENTRAIL_BENCH_READER_INVALID_ANSWER_TEXT",
            Self::CollectionTooLarge => "EVIDENTRAIL_BENCH_READER_COLLECTION_TOO_LARGE",
            Self::ArtifactLengthOverflow => "EVIDENTRAIL_BENCH_READER_ARTIFACT_LENGTH_OVERFLOW",
            Self::InsufficientRepeatabilityTrials => {
                "EVIDENTRAIL_BENCH_READER_INSUFFICIENT_REPEATABILITY_TRIALS"
            }
            Self::RepeatabilityBindingMismatch => {
                "EVIDENTRAIL_BENCH_READER_REPEATABILITY_BINDING_MISMATCH"
            }
            Self::ReaderNondeterministic => "EVIDENTRAIL_BENCH_READER_NONDETERMINISTIC",
            Self::GovernedCaseBindingMismatch => {
                "EVIDENTRAIL_BENCH_READER_GOVERNED_CASE_BINDING_MISMATCH"
            }
            Self::MissingAnswerableTruth => "EVIDENTRAIL_BENCH_READER_MISSING_ANSWERABLE_TRUTH",
            Self::UnexpectedUnanswerableTruth => {
                "EVIDENTRAIL_BENCH_READER_UNEXPECTED_UNANSWERABLE_TRUTH"
            }
            Self::InvalidGovernedGranularity => {
                "EVIDENTRAIL_BENCH_READER_INVALID_GOVERNED_GRANULARITY"
            }
            Self::GovernedClaimSetsOverlap => {
                "EVIDENTRAIL_BENCH_READER_GOVERNED_CLAIM_SETS_OVERLAP"
            }
            Self::DuplicateGovernedCode => "EVIDENTRAIL_BENCH_READER_DUPLICATE_GOVERNED_CODE",
            Self::ScoreOverflow => "EVIDENTRAIL_BENCH_READER_SCORE_OVERFLOW",
            Self::Harness(error) => error.code(),
            Self::PeakRssObserver(error) => error.code(),
        }
    }
}

impl fmt::Debug for ReaderErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReaderErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for ReaderErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ReaderErrorV1 {}

impl From<HarnessError> for ReaderErrorV1 {
    fn from(error: HarnessError) -> Self {
        Self::Harness(error)
    }
}

impl From<PeakRssObserverErrorV1> for ReaderErrorV1 {
    fn from(error: PeakRssObserverErrorV1) -> Self {
        Self::PeakRssObserver(error)
    }
}
