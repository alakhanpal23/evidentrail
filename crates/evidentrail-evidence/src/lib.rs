//! Deterministic, model-independent evidence artifacts.
//!
//! This crate renders exact passthrough results and deterministic compiled
//! selections of intact packets. It never generates a diagnosis, modifies
//! evidence, queries a source, or accesses result storage.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;

use evidentrail_core::{
    EventId, EventLedger, EvidenceReferenceV1, EvidenceTargetRef, ExactnessBasis,
    ExpansionRelationV1, FetchCompleteness, PassthroughDecision, ResultStatusV1,
    UnixTimestampNanos, WholeRenderAssessmentV1, select_whole_render_passthrough,
};
use evidentrail_schema::bounds::{
    JSON_SAFE_INTEGER_MAX, MAX_LOG_BRIEF_EVIDENCE_PACKETS, MAX_WIRE_OBJECT_BYTES,
};
use evidentrail_schema::{
    AcquisitionReceiptId, ArtifactDigest, EvidenceReferenceId, PlanDigest, PresentationCounts,
    PresentationReceiptId, QuestionDigest, ResultId, SourceStream,
};
use sha2::{Digest, Sha256};

mod compiled;
mod compiled_agent_view;
mod compiled_cost;

pub use compiled_agent_view::{
    COMPILED_AGENT_VIEW_CANDIDATE_CONTRACT_VERSION_V1,
    COMPILED_AGENT_VIEW_CANDIDATE_RENDERER_CONTRACT_VERSION_V1, CompiledAgentViewCandidateAuditV1,
    CompiledAgentViewCandidateCitationV1, CompiledAgentViewCandidateErrorV1,
    CompiledAgentViewCandidateEventProofV1, CompiledAgentViewCandidateV1,
    compiled_agent_view_candidate_renderer_digest_v1, render_compiled_agent_view_candidate_v1,
};

pub use compiled::{
    COMPILED_LOG_BRIEF_CONTRACT_VERSION_V1, COMPILED_TEXT_RENDERER_CONTRACT_VERSION_V1,
    CompiledBriefError, CompiledCostAccountingV1, CompiledCostModelViolationReasonV1,
    CompiledCoverageV1, CompiledEventEvidenceV1, CompiledEvidencePacketV1, CompiledLogBriefV1,
    OwnedCompiledEventEvidenceV1, OwnedCompiledEvidencePacketV1, OwnedCompiledLogBriefV1,
    OwnedRenderedCompiledBriefV1, RenderedCompiledBriefV1, compiled_cost_model_v1,
    compiled_renderer_digest_v1, render_compiled_log_brief_v1,
    render_cost_certified_compiled_log_brief_v1,
};
pub use compiled_cost::{
    AsciiRenderTokenBoundContractV1, CompiledCostCertificationError, CompiledCostCertificationV1,
    CompiledPacketCostBoundV1, CompiledPacketMembershipV1, Utf8ByteTokenizerV1,
    certify_compiled_costs_v1, utf8_byte_tokenizer_digest_v1,
};

/// Semantic contract version for [`PassthroughLogBriefV1`].
pub const PASSTHROUGH_LOG_BRIEF_CONTRACT_VERSION_V1: u16 = 1;

/// Contract version of the canonical passthrough text renderer.
pub const PASSTHROUGH_TEXT_RENDERER_CONTRACT_VERSION_V1: u16 = 1;

const RENDERER_MANIFEST_V1: &[u8] = b"evidentrail-evidence/passthrough-text-renderer/v1\0sections=status,scope,evidence,coverage\0evidence-bytes=ascii-byte-escape-v1\0text-citations=result-scoped-ordinal-alias-v1\0structured-ids=full-canonical\0newlines=lf\0diagnosis=none";

/// A tokenizer whose exact implementation/version is identified by a digest.
///
/// Implementations must count the complete supplied render. The renderer makes
/// exactly one count call and never adds independently counted fragments.
pub trait PinnedTokenizer {
    fn digest(&self) -> ArtifactDigest;

    fn count_tokens(&self, complete_render: &str) -> Result<u64, TokenizerFailure>;
}

/// Contentless failure returned by a pinned tokenizer implementation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TokenizerFailure;

impl TokenizerFailure {
    pub const CODE: &'static str = "EVIDENTRAIL_EVIDENCE_TOKENIZER_FAILURE";
}

impl fmt::Debug for TokenizerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TokenizerFailure")
    }
}

impl fmt::Display for TokenizerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(Self::CODE)
    }
}

impl StdError for TokenizerFailure {}

/// Frozen identity of the canonical v1 passthrough renderer.
#[must_use]
pub fn passthrough_renderer_digest_v1() -> ArtifactDigest {
    ArtifactDigest::from_bytes(Sha256::digest(RENDERER_MANIFEST_V1).into())
}

/// Exact budget accounting for one complete rendered artifact.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PassthroughRenderBudgetV1 {
    total_token_limit: u64,
    total_rendered_tokens: u64,
    total_rendered_bytes: u64,
    tokenizer_digest: ArtifactDigest,
    renderer_digest: ArtifactDigest,
}

impl PassthroughRenderBudgetV1 {
    #[must_use]
    pub const fn total_token_limit(self) -> u64 {
        self.total_token_limit
    }

    #[must_use]
    pub const fn total_rendered_tokens(self) -> u64 {
        self.total_rendered_tokens
    }

    #[must_use]
    pub const fn total_rendered_bytes(self) -> u64 {
        self.total_rendered_bytes
    }

    #[must_use]
    pub const fn tokenizer_digest(self) -> ArtifactDigest {
        self.tokenizer_digest
    }

    #[must_use]
    pub const fn renderer_digest(self) -> ArtifactDigest {
        self.renderer_digest
    }
}

impl fmt::Debug for PassthroughRenderBudgetV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PassthroughRenderBudgetV1")
            .field("total_token_limit", &self.total_token_limit)
            .field("total_rendered_tokens", &self.total_rendered_tokens)
            .field("total_rendered_bytes", &self.total_rendered_bytes)
            .finish()
    }
}

/// Content and expansion capability for one exact event packet.
pub struct PassthroughEvidenceV1<'ledger> {
    ordinal: usize,
    event_id: EventId,
    reference: EvidenceReferenceV1,
    exactness_basis: ExactnessBasis,
    stream: SourceStream,
    authorized_bytes: &'ledger [u8],
}

impl<'ledger> PassthroughEvidenceV1<'ledger> {
    #[must_use]
    pub const fn ordinal(&self) -> usize {
        self.ordinal
    }

    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn reference(&self) -> &EvidenceReferenceV1 {
        &self.reference
    }

    #[must_use]
    pub const fn exactness_basis(&self) -> ExactnessBasis {
        self.exactness_basis
    }

    #[must_use]
    pub const fn stream(&self) -> &SourceStream {
        &self.stream
    }

    /// Exact authorized bytes, including a source-defined terminator when one
    /// was retained. Post-policy events are not mislabeled source-exact.
    #[must_use]
    pub const fn authorized_bytes(&self) -> &'ledger [u8] {
        self.authorized_bytes
    }
}

impl fmt::Debug for PassthroughEvidenceV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PassthroughEvidenceV1")
            .field("ordinal", &self.ordinal)
            .field("exactness_code", &self.exactness_basis.code())
            .field("stream_code", &self.stream.code())
            .field("authorized_byte_count", &self.authorized_bytes.len())
            .field(
                "allowed_relation_count",
                &self.reference.allowed_relations().len(),
            )
            .finish()
    }
}

/// Exhaustive receipt-backed coverage summary for the passthrough result.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PassthroughCoverageV1 {
    acquisition_receipt_id: AcquisitionReceiptId,
    presentation_receipt_id: PresentationReceiptId,
    acknowledged_records: usize,
    presentation_counts: PresentationCounts,
    source_exact_records: usize,
    post_policy_records: usize,
    omitted_by_policy_records: usize,
}

impl PassthroughCoverageV1 {
    #[must_use]
    pub const fn acquisition_receipt_id(self) -> AcquisitionReceiptId {
        self.acquisition_receipt_id
    }

    #[must_use]
    pub const fn presentation_receipt_id(self) -> PresentationReceiptId {
        self.presentation_receipt_id
    }

    #[must_use]
    pub const fn acknowledged_records(self) -> usize {
        self.acknowledged_records
    }

    #[must_use]
    pub const fn presentation_counts(self) -> PresentationCounts {
        self.presentation_counts
    }

    #[must_use]
    pub const fn source_exact_records(self) -> usize {
        self.source_exact_records
    }

    #[must_use]
    pub const fn post_policy_records(self) -> usize {
        self.post_policy_records
    }

    #[must_use]
    pub const fn omitted_by_policy_records(self) -> usize {
        self.omitted_by_policy_records
    }
}

impl fmt::Debug for PassthroughCoverageV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PassthroughCoverageV1")
            .field("acknowledged_records", &self.acknowledged_records)
            .field("presentation_counts", &self.presentation_counts)
            .field("source_exact_records", &self.source_exact_records)
            .field("post_policy_records", &self.post_policy_records)
            .field("omitted_by_policy_records", &self.omitted_by_policy_records)
            .finish()
    }
}

/// Structured exact-passthrough result. Evidence bytes remain borrowed from
/// the immutable ledger and are never decoded or normalized.
pub struct PassthroughLogBriefV1<'ledger> {
    result_id: ResultId,
    question_digest: QuestionDigest,
    plan_digest: PlanDigest,
    reference_authorized_at: UnixTimestampNanos,
    status: ResultStatusV1,
    budget: PassthroughRenderBudgetV1,
    coverage: PassthroughCoverageV1,
    evidence: Vec<PassthroughEvidenceV1<'ledger>>,
}

impl<'ledger> PassthroughLogBriefV1<'ledger> {
    #[must_use]
    pub const fn contract_version(&self) -> u16 {
        PASSTHROUGH_LOG_BRIEF_CONTRACT_VERSION_V1
    }

    #[must_use]
    pub const fn result_id(&self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn question_digest(&self) -> QuestionDigest {
        self.question_digest
    }

    #[must_use]
    pub const fn plan_digest(&self) -> PlanDigest {
        self.plan_digest
    }

    #[must_use]
    pub const fn reference_authorized_at(&self) -> UnixTimestampNanos {
        self.reference_authorized_at
    }

    #[must_use]
    pub const fn untrusted_data(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn status(&self) -> &ResultStatusV1 {
        &self.status
    }

    #[must_use]
    pub const fn budget(&self) -> PassthroughRenderBudgetV1 {
        self.budget
    }

    #[must_use]
    pub const fn coverage(&self) -> PassthroughCoverageV1 {
        self.coverage
    }

    #[must_use]
    pub fn evidence(&self) -> &[PassthroughEvidenceV1<'ledger>] {
        &self.evidence
    }
}

impl fmt::Debug for PassthroughLogBriefV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PassthroughLogBriefV1")
            .field("contract_version", &self.contract_version())
            .field("untrusted_data", &true)
            .field("acquisition_code", &self.status.acquisition().code())
            .field("selection_code", &self.status.selection().code())
            .field("evidence_count", &self.evidence.len())
            .field("budget", &self.budget)
            .field("coverage", &self.coverage)
            .finish()
    }
}

/// Successful structured brief and its canonical deterministic text view.
pub struct RenderedPassthroughBriefV1<'ledger> {
    brief: PassthroughLogBriefV1<'ledger>,
    text: String,
}

impl<'ledger> RenderedPassthroughBriefV1<'ledger> {
    #[must_use]
    pub const fn brief(&self) -> &PassthroughLogBriefV1<'ledger> {
        &self.brief
    }

    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl fmt::Debug for RenderedPassthroughBriefV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedPassthroughBriefV1")
            .field("brief", &self.brief)
            .field("text_bytes", &self.text.len())
            .finish()
    }
}

/// Owned evidence packet for product responses that must outlive a temporary
/// immutable ledger borrow.
pub struct OwnedPassthroughEvidenceV1 {
    ordinal: usize,
    event_id: EventId,
    reference: EvidenceReferenceV1,
    exactness_basis: ExactnessBasis,
    stream: SourceStream,
    authorized_bytes: Vec<u8>,
}

impl OwnedPassthroughEvidenceV1 {
    #[must_use]
    pub const fn ordinal(&self) -> usize {
        self.ordinal
    }

    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn reference(&self) -> &EvidenceReferenceV1 {
        &self.reference
    }

    #[must_use]
    pub const fn exactness_basis(&self) -> ExactnessBasis {
        self.exactness_basis
    }

    #[must_use]
    pub const fn stream(&self) -> &SourceStream {
        &self.stream
    }

    #[must_use]
    pub fn authorized_bytes(&self) -> &[u8] {
        &self.authorized_bytes
    }
}

impl fmt::Debug for OwnedPassthroughEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedPassthroughEvidenceV1")
            .field("ordinal", &self.ordinal)
            .field("exactness_code", &self.exactness_basis.code())
            .field("stream_code", &self.stream.code())
            .field("authorized_byte_count", &self.authorized_bytes.len())
            .field(
                "allowed_relation_count",
                &self.reference.allowed_relations().len(),
            )
            .finish()
    }
}

/// Owned form of the structured passthrough brief.
pub struct OwnedPassthroughLogBriefV1 {
    result_id: ResultId,
    question_digest: QuestionDigest,
    plan_digest: PlanDigest,
    reference_authorized_at: UnixTimestampNanos,
    status: ResultStatusV1,
    budget: PassthroughRenderBudgetV1,
    coverage: PassthroughCoverageV1,
    evidence: Vec<OwnedPassthroughEvidenceV1>,
}

impl OwnedPassthroughLogBriefV1 {
    #[must_use]
    pub const fn contract_version(&self) -> u16 {
        PASSTHROUGH_LOG_BRIEF_CONTRACT_VERSION_V1
    }

    #[must_use]
    pub const fn result_id(&self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn question_digest(&self) -> QuestionDigest {
        self.question_digest
    }

    #[must_use]
    pub const fn plan_digest(&self) -> PlanDigest {
        self.plan_digest
    }

    #[must_use]
    pub const fn reference_authorized_at(&self) -> UnixTimestampNanos {
        self.reference_authorized_at
    }

    #[must_use]
    pub const fn untrusted_data(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn status(&self) -> &ResultStatusV1 {
        &self.status
    }

    #[must_use]
    pub const fn budget(&self) -> PassthroughRenderBudgetV1 {
        self.budget
    }

    #[must_use]
    pub const fn coverage(&self) -> PassthroughCoverageV1 {
        self.coverage
    }

    #[must_use]
    pub fn evidence(&self) -> &[OwnedPassthroughEvidenceV1] {
        &self.evidence
    }
}

impl fmt::Debug for OwnedPassthroughLogBriefV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedPassthroughLogBriefV1")
            .field("contract_version", &self.contract_version())
            .field("untrusted_data", &true)
            .field("acquisition_code", &self.status.acquisition().code())
            .field("selection_code", &self.status.selection().code())
            .field("evidence_count", &self.evidence.len())
            .field("budget", &self.budget)
            .field("coverage", &self.coverage)
            .finish()
    }
}

/// Owned canonical artifact returned by the memory-only product lifecycle.
pub struct OwnedRenderedPassthroughBriefV1 {
    brief: OwnedPassthroughLogBriefV1,
    text: String,
}

impl OwnedRenderedPassthroughBriefV1 {
    #[must_use]
    pub const fn brief(&self) -> &OwnedPassthroughLogBriefV1 {
        &self.brief
    }

    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl fmt::Debug for OwnedRenderedPassthroughBriefV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedRenderedPassthroughBriefV1")
            .field("brief", &self.brief)
            .field("text_bytes", &self.text.len())
            .finish()
    }
}

impl RenderedPassthroughBriefV1<'_> {
    /// Copy only authorized evidence bytes so the exact structured artifact can
    /// outlive its immutable ledger borrow. Text and budget are moved unchanged;
    /// conversion never renders or tokenizes again.
    #[must_use]
    pub fn into_owned(self) -> OwnedRenderedPassthroughBriefV1 {
        let PassthroughLogBriefV1 {
            result_id,
            question_digest,
            plan_digest,
            reference_authorized_at,
            status,
            budget,
            coverage,
            evidence,
        } = self.brief;
        let evidence = evidence
            .into_iter()
            .map(|packet| OwnedPassthroughEvidenceV1 {
                ordinal: packet.ordinal,
                event_id: packet.event_id,
                reference: packet.reference,
                exactness_basis: packet.exactness_basis,
                stream: packet.stream,
                authorized_bytes: packet.authorized_bytes.to_vec(),
            })
            .collect();
        OwnedRenderedPassthroughBriefV1 {
            brief: OwnedPassthroughLogBriefV1 {
                result_id,
                question_digest,
                plan_digest,
                reference_authorized_at,
                status,
                budget,
                coverage,
                evidence,
            },
            text: self.text,
        }
    }
}

/// Why exact passthrough cannot be returned as the final artifact.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PassthroughNotFitReasonV1 {
    TotalTokenBudgetExceeded,
    RenderedByteLimitExceeded,
}

impl PassthroughNotFitReasonV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TotalTokenBudgetExceeded => "total_token_budget_exceeded",
            Self::RenderedByteLimitExceeded => "rendered_byte_limit_exceeded",
        }
    }
}

impl fmt::Debug for PassthroughNotFitReasonV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PassthroughNotFitReasonV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Typed handoff to the compilation/needs-more decision layer. No partial
/// evidence text or sliced event is exposed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PassthroughNotFitV1 {
    reason: PassthroughNotFitReasonV1,
    total_token_limit: u64,
    required_tokens: Option<u64>,
    tokenizer_digest: ArtifactDigest,
    renderer_digest: ArtifactDigest,
}

impl PassthroughNotFitV1 {
    #[must_use]
    pub const fn reason(self) -> PassthroughNotFitReasonV1 {
        self.reason
    }

    #[must_use]
    pub const fn total_token_limit(self) -> u64 {
        self.total_token_limit
    }

    #[must_use]
    pub const fn required_tokens(self) -> Option<u64> {
        self.required_tokens
    }

    #[must_use]
    pub const fn tokenizer_digest(self) -> ArtifactDigest {
        self.tokenizer_digest
    }

    #[must_use]
    pub const fn renderer_digest(self) -> ArtifactDigest {
        self.renderer_digest
    }
}

impl fmt::Debug for PassthroughNotFitV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PassthroughNotFitV1")
            .field("reason_code", &self.reason.code())
            .field("total_token_limit", &self.total_token_limit)
            .field("required_tokens", &self.required_tokens)
            .finish()
    }
}

/// Result of the final exact-render budget gate.
pub enum PassthroughBriefDecisionV1<'ledger> {
    Rendered(Box<RenderedPassthroughBriefV1<'ledger>>),
    CompilationRequired(PassthroughNotFitV1),
}

impl PassthroughBriefDecisionV1<'_> {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Rendered(_) => "rendered",
            Self::CompilationRequired(_) => "compilation_required",
        }
    }
}

impl fmt::Debug for PassthroughBriefDecisionV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PassthroughBriefDecisionV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Invalid semantic input to the exact passthrough brief builder.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PassthroughBriefError {
    PlanDigestMismatch,
    PassthroughStatusInvariantViolation,
    TooManyEvidenceEvents,
    ReferenceCountMismatch,
    ReferenceUnavailable,
    ReferenceTargetMustBeOneEvent,
    ReferenceTargetsUnknownEvent,
    DuplicateReferenceTarget,
    DuplicateReferenceIdentity,
    MissingEventReference,
    TokenizerFailure,
    TokenCountOutOfRange,
    RenderedByteCountOverflow,
}

impl PassthroughBriefError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PlanDigestMismatch => "EVIDENTRAIL_EVIDENCE_PLAN_DIGEST_MISMATCH",
            Self::PassthroughStatusInvariantViolation => {
                "EVIDENTRAIL_EVIDENCE_PASSTHROUGH_STATUS_INVARIANT_VIOLATION"
            }
            Self::TooManyEvidenceEvents => "EVIDENTRAIL_EVIDENCE_TOO_MANY_EVENTS",
            Self::ReferenceCountMismatch => "EVIDENTRAIL_EVIDENCE_REFERENCE_COUNT_MISMATCH",
            Self::ReferenceUnavailable => "EVIDENTRAIL_EVIDENCE_REFERENCE_UNAVAILABLE",
            Self::ReferenceTargetMustBeOneEvent => {
                "EVIDENTRAIL_EVIDENCE_REFERENCE_TARGET_MUST_BE_ONE_EVENT"
            }
            Self::ReferenceTargetsUnknownEvent => "EVIDENTRAIL_EVIDENCE_REFERENCE_TARGETS_UNKNOWN_EVENT",
            Self::DuplicateReferenceTarget => "EVIDENTRAIL_EVIDENCE_DUPLICATE_REFERENCE_TARGET",
            Self::DuplicateReferenceIdentity => "EVIDENTRAIL_EVIDENCE_DUPLICATE_REFERENCE_IDENTITY",
            Self::MissingEventReference => "EVIDENTRAIL_EVIDENCE_MISSING_EVENT_REFERENCE",
            Self::TokenizerFailure => "EVIDENTRAIL_EVIDENCE_TOKENIZER_FAILURE",
            Self::TokenCountOutOfRange => "EVIDENTRAIL_EVIDENCE_TOKEN_COUNT_OUT_OF_RANGE",
            Self::RenderedByteCountOverflow => "EVIDENTRAIL_EVIDENCE_RENDERED_BYTE_COUNT_OVERFLOW",
        }
    }
}

impl fmt::Debug for PassthroughBriefError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PassthroughBriefError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for PassthroughBriefError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for PassthroughBriefError {}

/// Build and canonically render an exact passthrough brief.
///
/// `references` are expected to have been registered by the caller's result
/// store. This store-independent layer verifies their complete semantic
/// binding but does not claim to verify external registration or lifetime.
#[allow(clippy::too_many_arguments)]
pub fn render_passthrough_log_brief_v1<'ledger, T>(
    ledger: &'ledger EventLedger,
    result_id: ResultId,
    question_digest: QuestionDigest,
    plan_digest: PlanDigest,
    references: impl IntoIterator<Item = EvidenceReferenceV1>,
    now: UnixTimestampNanos,
    total_token_limit: u64,
    tokenizer: &T,
) -> Result<PassthroughBriefDecisionV1<'ledger>, PassthroughBriefError>
where
    T: PinnedTokenizer + ?Sized,
{
    if ledger.plan_digest() != plan_digest {
        return Err(PassthroughBriefError::PlanDigestMismatch);
    }
    if ledger.len() > MAX_LOG_BRIEF_EVIDENCE_PACKETS {
        return Err(PassthroughBriefError::TooManyEvidenceEvents);
    }

    let references = bind_references(ledger, result_id, references, now)?;
    let evidence = ledger
        .events()
        .iter()
        .enumerate()
        .zip(references)
        .map(|((ordinal, event), reference)| PassthroughEvidenceV1 {
            ordinal,
            event_id: event.id(),
            reference,
            exactness_basis: event.exactness_basis(),
            stream: event.lane().stream().clone(),
            authorized_bytes: event.raw(),
        })
        .collect::<Vec<_>>();

    let tokenizer_digest = tokenizer.digest();
    let renderer_digest = passthrough_renderer_digest_v1();
    let mut text = BoundedText::new(MAX_WIRE_OBJECT_BYTES);
    if render_text(&mut text, ledger, result_id, &evidence).is_err() {
        return Ok(PassthroughBriefDecisionV1::CompilationRequired(
            PassthroughNotFitV1 {
                reason: PassthroughNotFitReasonV1::RenderedByteLimitExceeded,
                total_token_limit,
                required_tokens: None,
                tokenizer_digest,
                renderer_digest,
            },
        ));
    }
    let text = text.finish();
    let total_rendered_tokens = tokenizer
        .count_tokens(&text)
        .map_err(|_| PassthroughBriefError::TokenizerFailure)?;
    if total_rendered_tokens > JSON_SAFE_INTEGER_MAX {
        return Err(PassthroughBriefError::TokenCountOutOfRange);
    }
    let assessment = WholeRenderAssessmentV1::new(total_rendered_tokens, total_token_limit);
    let selection = match select_whole_render_passthrough(ledger, assessment)
        .map_err(|_| PassthroughBriefError::PassthroughStatusInvariantViolation)?
    {
        PassthroughDecision::Selected(selection) => selection,
        PassthroughDecision::CompilationRequired(_) => {
            return Ok(PassthroughBriefDecisionV1::CompilationRequired(
                PassthroughNotFitV1 {
                    reason: PassthroughNotFitReasonV1::TotalTokenBudgetExceeded,
                    total_token_limit,
                    required_tokens: Some(total_rendered_tokens),
                    tokenizer_digest,
                    renderer_digest,
                },
            ));
        }
    };
    let status = ResultStatusV1::passthrough(ledger, selection)
        .map_err(|_| PassthroughBriefError::PassthroughStatusInvariantViolation)?;

    let total_rendered_bytes =
        u64::try_from(text.len()).map_err(|_| PassthroughBriefError::RenderedByteCountOverflow)?;
    let acquisition_counts = ledger.acquisition_receipt().counts();
    let presentation_receipt = status.selection().presentation_receipt();
    let coverage = PassthroughCoverageV1 {
        acquisition_receipt_id: ledger.acquisition_receipt_id(),
        presentation_receipt_id: presentation_receipt.id(),
        acknowledged_records: ledger.acquisition_receipt().acknowledged_count(),
        presentation_counts: presentation_receipt.counts(),
        source_exact_records: acquisition_counts.source_exact,
        post_policy_records: acquisition_counts.post_policy,
        omitted_by_policy_records: acquisition_counts.omitted_by_policy,
    };
    let brief = PassthroughLogBriefV1 {
        result_id,
        question_digest,
        plan_digest,
        reference_authorized_at: now,
        status,
        budget: PassthroughRenderBudgetV1 {
            total_token_limit,
            total_rendered_tokens,
            total_rendered_bytes,
            tokenizer_digest,
            renderer_digest,
        },
        coverage,
        evidence,
    };

    Ok(PassthroughBriefDecisionV1::Rendered(Box::new(
        RenderedPassthroughBriefV1 { brief, text },
    )))
}

fn bind_references(
    ledger: &EventLedger,
    result_id: ResultId,
    references: impl IntoIterator<Item = EvidenceReferenceV1>,
    now: UnixTimestampNanos,
) -> Result<Vec<EvidenceReferenceV1>, PassthroughBriefError> {
    let references = references.into_iter().collect::<Vec<_>>();
    if references.len() != ledger.len() {
        return Err(PassthroughBriefError::ReferenceCountMismatch);
    }

    let mut by_event = BTreeMap::new();
    let mut reference_ids = BTreeSet::<EvidenceReferenceId>::new();
    for reference in references {
        reference
            .authorize(result_id, ExpansionRelationV1::Exact, now)
            .map_err(|_| PassthroughBriefError::ReferenceUnavailable)?;
        let [EvidenceTargetRef::Event(event_id)] = reference.targets() else {
            return Err(PassthroughBriefError::ReferenceTargetMustBeOneEvent);
        };
        if !ledger.contains(*event_id) {
            return Err(PassthroughBriefError::ReferenceTargetsUnknownEvent);
        }
        if !reference_ids.insert(reference.id()) {
            return Err(PassthroughBriefError::DuplicateReferenceIdentity);
        }
        if by_event.insert(*event_id, reference).is_some() {
            return Err(PassthroughBriefError::DuplicateReferenceTarget);
        }
    }

    ledger
        .events()
        .iter()
        .map(|event| {
            by_event
                .remove(&event.id())
                .ok_or(PassthroughBriefError::MissingEventReference)
        })
        .collect()
}

fn render_text(
    text: &mut BoundedText,
    ledger: &EventLedger,
    result_id: ResultId,
    evidence: &[PassthroughEvidenceV1<'_>],
) -> Result<(), RenderLimitExceeded> {
    text.push("STATUS\n")?;
    text.push("  result: ")?;
    text.push(&result_id.canonical_token())?;
    text.push("\n  untrusted_data: true\n  acquisition: ")?;
    render_acquisition(text, ledger.fetch_completion().completeness())?;
    text.push("\n  selection: PASSTHROUGH\n\n")?;

    let acquisition_counts = ledger.acquisition_receipt().counts();
    text.push("SCOPE\n  acknowledged_records: ")?;
    text.push_usize(ledger.acquisition_receipt().acknowledged_count())?;
    text.push("\n  persisted_events: ")?;
    text.push_usize(ledger.len())?;
    text.push("\n  policy_omitted_records: ")?;
    text.push_usize(acquisition_counts.omitted_by_policy)?;
    text.push("\n\nEVIDENCE\n")?;
    if evidence.is_empty() {
        text.push("  (none)\n")?;
    }
    for item in evidence {
        text.push("  [E")?;
        text.push_usize(item.ordinal + 1)?;
        text.push("]\n    expand: E")?;
        text.push_usize(item.ordinal + 1)?;
        text.push(" ")?;
        for (index, relation) in item.reference.allowed_relations().iter().enumerate() {
            if index != 0 {
                text.push(",")?;
            }
            text.push(relation.code())?;
        }
        text.push("\n    exactness: ")?;
        text.push(item.exactness_basis.code())?;
        text.push("\n    stream: ")?;
        text.push(item.stream.code())?;
        text.push("\n    data_encoding: ascii_byte_escape_v1\n    data: ")?;
        text.push_escaped(item.authorized_bytes)?;
        text.push("\n")?;
    }

    text.push("\nCOVERAGE\n  shown_verbatim: ")?;
    text.push_usize(ledger.len())?;
    text.push("\n  pattern_represented: ")?;
    text.push_usize(0)?;
    text.push("\n  retained_raw: ")?;
    text.push_usize(0)?;
    text.push("\n  source_exact_records: ")?;
    text.push_usize(acquisition_counts.source_exact)?;
    text.push("\n  post_policy_records: ")?;
    text.push_usize(acquisition_counts.post_policy)?;
    text.push("\n  policy_omitted_records: ")?;
    text.push_usize(acquisition_counts.omitted_by_policy)?;
    text.push("\n")?;
    Ok(())
}

fn render_acquisition(
    text: &mut BoundedText,
    completeness: &FetchCompleteness,
) -> Result<(), RenderLimitExceeded> {
    match completeness {
        FetchCompleteness::Complete { proof } => {
            text.push("COMPLETE (")?;
            text.push(proof.code())?;
            text.push(")")?;
        }
        FetchCompleteness::Partial { reasons, .. } => {
            text.push("PARTIAL (")?;
            for (index, reason) in reasons.iter().enumerate() {
                if index != 0 {
                    text.push(",")?;
                }
                text.push(reason.code())?;
            }
            text.push(")")?;
        }
        FetchCompleteness::Unknown { reason } => {
            text.push("UNKNOWN (")?;
            text.push(reason.code())?;
            text.push(")")?;
        }
    }
    Ok(())
}

/// Canonically escape arbitrary evidence bytes onto one physical ASCII line.
///
/// Printable ASCII remains readable except that `\\` becomes `\\\\`.
/// Newline, carriage return, and tab become `\\n`, `\\r`, and `\\t`;
/// every other byte becomes lowercase `\\xhh`.
#[must_use]
pub fn escape_evidence_bytes(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len());
    for byte in bytes {
        push_escaped_byte(&mut encoded, *byte);
    }
    encoded
}

/// Decode the unique canonical single-line evidence representation.
pub fn unescape_evidence_bytes(encoded: &str) -> Result<Vec<u8>, EvidenceEscapeError> {
    let encoded = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut offset = 0;
    while offset < encoded.len() {
        let byte = encoded[offset];
        if byte == b'\\' {
            let escape = *encoded
                .get(offset + 1)
                .ok_or(EvidenceEscapeError::TruncatedEscape)?;
            match escape {
                b'\\' => {
                    decoded.push(b'\\');
                    offset += 2;
                }
                b'n' => {
                    decoded.push(b'\n');
                    offset += 2;
                }
                b'r' => {
                    decoded.push(b'\r');
                    offset += 2;
                }
                b't' => {
                    decoded.push(b'\t');
                    offset += 2;
                }
                b'x' => {
                    let high = *encoded
                        .get(offset + 2)
                        .ok_or(EvidenceEscapeError::TruncatedEscape)?;
                    let low = *encoded
                        .get(offset + 3)
                        .ok_or(EvidenceEscapeError::TruncatedEscape)?;
                    let high = hex_value(high).ok_or(EvidenceEscapeError::InvalidDigit)?;
                    let low = hex_value(low).ok_or(EvidenceEscapeError::InvalidDigit)?;
                    let decoded_byte = (high << 4) | low;
                    if matches!(decoded_byte, b'\\' | b'\n' | b'\r' | b'\t' | 0x20..=0x7e) {
                        return Err(EvidenceEscapeError::NonCanonicalByte);
                    }
                    decoded.push(decoded_byte);
                    offset += 4;
                }
                _ => return Err(EvidenceEscapeError::InvalidEscape),
            }
        } else if (0x20..=0x7e).contains(&byte) {
            decoded.push(byte);
            offset += 1;
        } else {
            return Err(EvidenceEscapeError::NonCanonicalByte);
        }
    }
    Ok(decoded)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EvidenceEscapeError {
    TruncatedEscape,
    InvalidEscape,
    InvalidDigit,
    NonCanonicalByte,
}

impl EvidenceEscapeError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TruncatedEscape => "EVIDENTRAIL_EVIDENCE_ESCAPE_TRUNCATED",
            Self::InvalidEscape => "EVIDENTRAIL_EVIDENCE_ESCAPE_INVALID_SEQUENCE",
            Self::InvalidDigit => "EVIDENTRAIL_EVIDENCE_ESCAPE_INVALID_DIGIT",
            Self::NonCanonicalByte => "EVIDENTRAIL_EVIDENCE_ESCAPE_NON_CANONICAL_BYTE",
        }
    }
}

impl fmt::Debug for EvidenceEscapeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceEscapeError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for EvidenceEscapeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for EvidenceEscapeError {}

fn hex_digit(nibble: u8) -> char {
    char::from(b"0123456789abcdef"[usize::from(nibble)])
}

fn push_escaped_byte(destination: &mut String, byte: u8) {
    match byte {
        b'\\' => destination.push_str("\\\\"),
        b'\n' => destination.push_str("\\n"),
        b'\r' => destination.push_str("\\r"),
        b'\t' => destination.push_str("\\t"),
        0x20..=0x7e => destination.push(char::from(byte)),
        _ => {
            destination.push_str("\\x");
            destination.push(hex_digit(byte >> 4));
            destination.push(hex_digit(byte & 0x0f));
        }
    }
}

fn escaped_len(bytes: &[u8]) -> Option<usize> {
    bytes.iter().try_fold(0_usize, |length, byte| {
        let encoded = match byte {
            b'\\' | b'\n' | b'\r' | b'\t' => 2,
            0x20..=0x7e => 1,
            _ => 4,
        };
        length.checked_add(encoded)
    })
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[derive(Clone, Copy)]
struct RenderLimitExceeded;

struct BoundedText {
    value: String,
    limit: usize,
}

impl BoundedText {
    fn new(limit: usize) -> Self {
        Self {
            value: String::new(),
            limit,
        }
    }

    fn push(&mut self, value: &str) -> Result<(), RenderLimitExceeded> {
        let new_len = self
            .value
            .len()
            .checked_add(value.len())
            .ok_or(RenderLimitExceeded)?;
        if new_len > self.limit {
            return Err(RenderLimitExceeded);
        }
        self.value.push_str(value);
        Ok(())
    }

    fn push_usize(&mut self, value: usize) -> Result<(), RenderLimitExceeded> {
        self.push(&value.to_string())
    }

    fn push_escaped(&mut self, bytes: &[u8]) -> Result<(), RenderLimitExceeded> {
        let encoded_len = escaped_len(bytes).ok_or(RenderLimitExceeded)?;
        let new_len = self
            .value
            .len()
            .checked_add(encoded_len)
            .ok_or(RenderLimitExceeded)?;
        if new_len > self.limit {
            return Err(RenderLimitExceeded);
        }
        for byte in bytes {
            push_escaped_byte(&mut self.value, *byte);
        }
        Ok(())
    }

    fn finish(self) -> String {
        self.value
    }
}
