//! Deterministic orchestration for one Evidentrail result.
//!
//! This crate does not acquire sources, invoke models, generate diagnoses,
//! or generate production randomness. Memory mode and Unix V2 durable mode
//! share the same compiler and renderer. Durable guarantees come from the
//! injected repository and external key authority; the process-local authority
//! is test-only. Callers supply the opaque random-by-contract result identity.

#[cfg(unix)]
mod durable_lifecycle;
mod encrypted_retention;
mod hosted_ranking;
mod streaming_v3;

#[cfg(unix)]
pub use durable_lifecycle::{
    DurableProductErrorV2, DurableProductExpansionV2, DurableProductV2, DurableStartupRecoveryV2,
    durable_product_build_context_v2,
};

pub use encrypted_retention::{
    AuthenticatedEncryptedRetentionErrorV1, AuthenticatedEncryptedRetentionV1,
    AuthenticatedRetentionExpansionV1, AuthenticatedRetentionPublicationV1,
};
pub use hosted_ranking::{
    EVIDENCE_RANKING_SCHEMA_VERSION_V1, EvidenceRankerFailureV1, EvidenceRankerOutputV1,
    EvidenceRankerV1, EvidenceRankingCandidateV1, EvidenceRankingRequestV1,
    HostedRankingDiagnosticsV1, MAX_HOSTED_RANKING_CANDIDATES_V1,
    MAX_HOSTED_RANKING_ESCAPED_INPUT_BYTES_V1, MAX_HOSTED_RANKING_RESPONSE_BYTES_V1,
    RankingConsumerV1, RankingValidationErrorV1, ValidatedEvidenceRankingV1,
    consume_evidence_ranking_v1, ranking_priorities_v1, validate_evidence_ranking_response_v1,
};
pub use streaming_v3::{
    AnalysisPlanV3, MAX_ANALYSIS_PARTITION_BLOCKS_V3, MAX_ANALYSIS_PARTITION_BYTES_V3,
    MAX_ANALYSIS_PARTITIONS_V3, StreamingAnalysisContextV3, StreamingLaneContextV3,
    StreamingPerformanceReceiptV3, StreamingProductErrorV3, StreamingProductV3,
    streaming_product_build_context_v3,
};

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fmt;
use std::time::Instant;

use evidentrail_compile::{
    CertifiedThreeLaneSelectionV1, PreparedThreeLaneProposalUniverseV1,
    PreparedThreeLaneSelectionDecisionV1, ProposalPreparationInputReceiptV1,
    ProposalUniverseReceiptV1, ThreeLaneCompileErrorV1, ThreeLaneNeedsMoreV1,
    ThreeLaneProposalPreparationDecisionV1, ThreeLaneProposalPreparationNeedsMoreV1,
    prepare_three_lane_proposal_universe_v1, select_prepared_three_lane_proposals_v1,
    select_prepared_three_lane_proposals_with_priorities_v1,
};
use evidentrail_core::{
    EventLedger, EvidenceReferenceV1, FetchCompleteness, PlanDigest, ResultId, UnixTimestampNanos,
    derive_question_digest_v1,
};
use evidentrail_evidence::{
    CompiledBriefError, CompiledCostCertificationError, CompiledCostCertificationV1,
    CompiledPacketMembershipV1, OwnedRenderedCompiledBriefV1, OwnedRenderedPassthroughBriefV1,
    PassthroughBriefDecisionV1, PassthroughBriefError, PassthroughNotFitV1, PinnedTokenizer,
    Utf8ByteTokenizerV1, certify_compiled_costs_v1, escape_evidence_bytes,
    render_compiled_log_brief_v1, render_cost_certified_compiled_log_brief_v1,
    render_passthrough_log_brief_v1,
};
use evidentrail_framing::frame_source_lanes_v1;
use evidentrail_schema::QuestionDigest;
use evidentrail_select::{
    PacketIdV1, SelectionV1, TokenValueConstructionError, TotalTokenBudgetV1,
};
use evidentrail_store::{
    AliasExpansionRequestV1, ExpansionRequestV1, ExpansionResponseV1, MemoryResultStore,
    ResultStoreError,
};

/// Successfully retained and rendered exact passthrough result.
pub struct RenderedProductResultV1 {
    expires_at: UnixTimestampNanos,
    artifact: OwnedRenderedPassthroughBriefV1,
}

impl RenderedProductResultV1 {
    #[must_use]
    pub const fn result_id(&self) -> ResultId {
        self.artifact.brief().result_id()
    }

    #[must_use]
    pub const fn expires_at(&self) -> UnixTimestampNanos {
        self.expires_at
    }

    #[must_use]
    pub const fn artifact(&self) -> &OwnedRenderedPassthroughBriefV1 {
        &self.artifact
    }

    #[must_use]
    pub fn references(&self) -> impl ExactSizeIterator<Item = &EvidenceReferenceV1> {
        self.artifact
            .brief()
            .evidence()
            .iter()
            .map(|packet| packet.reference())
    }
}

impl fmt::Debug for RenderedProductResultV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedProductResultV1")
            .field("artifact", &self.artifact)
            .field("fixed_expiry_present", &true)
            .finish()
    }
}

/// Successfully retained, whole-render-certified deterministic compiled result.
pub struct CompiledProductResultV1 {
    expires_at: UnixTimestampNanos,
    artifact: OwnedRenderedCompiledBriefV1,
    proposal_audit: Option<Box<ThreeLaneProposalAuditV1>>,
    hosted_ranking_diagnostics: Option<Box<HostedRankingDiagnosticsV1>>,
}

/// Truthful audit state for the production three-lane preparation/selection
/// path. Low-level caller-supplied compilation APIs never synthesize it.
#[derive(Clone, PartialEq, Eq)]
pub struct ThreeLaneProposalAuditV1 {
    state: ThreeLaneProposalAuditStateV1,
}

#[derive(Clone, PartialEq, Eq)]
enum ThreeLaneProposalAuditStateV1 {
    Selected {
        prepared: Box<PreparedThreeLaneProposalUniverseV1>,
        selected_packet_ids: Vec<PacketIdV1>,
    },
    BudgetNeedsMore {
        prepared: Box<PreparedThreeLaneProposalUniverseV1>,
        reason: ThreeLaneNeedsMoreV1,
    },
    PreparationIncomplete {
        input: Box<ProposalPreparationInputReceiptV1>,
        reason: ThreeLaneNeedsMoreV1,
    },
}

impl ThreeLaneProposalAuditV1 {
    fn selected(
        prepared: PreparedThreeLaneProposalUniverseV1,
        selected_packet_ids: impl IntoIterator<Item = PacketIdV1>,
    ) -> Result<Self, ProductError> {
        let mut selected_packet_ids = selected_packet_ids.into_iter().collect::<Vec<_>>();
        selected_packet_ids.sort_unstable();
        if selected_packet_ids
            .windows(2)
            .any(|pair| pair[0] == pair[1])
            || selected_packet_ids
                .iter()
                .any(|packet_id| prepared.proposal_metadata(*packet_id).is_none())
        {
            return Err(ProductError::CompilationBindingMismatch);
        }
        Ok(Self {
            state: ThreeLaneProposalAuditStateV1::Selected {
                prepared: Box::new(prepared),
                selected_packet_ids,
            },
        })
    }

    fn budget_needs_more(
        prepared: PreparedThreeLaneProposalUniverseV1,
        reason: ThreeLaneNeedsMoreV1,
    ) -> Self {
        Self {
            state: ThreeLaneProposalAuditStateV1::BudgetNeedsMore {
                prepared: Box::new(prepared),
                reason,
            },
        }
    }

    fn preparation_incomplete(
        input: ProposalPreparationInputReceiptV1,
        reason: ThreeLaneNeedsMoreV1,
    ) -> Self {
        Self {
            state: ThreeLaneProposalAuditStateV1::PreparationIncomplete {
                input: Box::new(input),
                reason,
            },
        }
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        match &self.state {
            ThreeLaneProposalAuditStateV1::Selected { .. } => "selected",
            ThreeLaneProposalAuditStateV1::BudgetNeedsMore { .. } => "budget_needs_more",
            ThreeLaneProposalAuditStateV1::PreparationIncomplete { .. } => "preparation_incomplete",
        }
    }

    #[must_use]
    pub const fn input(&self) -> ProposalPreparationInputReceiptV1 {
        match &self.state {
            ThreeLaneProposalAuditStateV1::Selected { prepared, .. }
            | ThreeLaneProposalAuditStateV1::BudgetNeedsMore { prepared, .. } => {
                prepared.receipt().input()
            }
            ThreeLaneProposalAuditStateV1::PreparationIncomplete { input, .. } => **input,
        }
    }

    #[must_use]
    pub const fn receipt(&self) -> Option<ProposalUniverseReceiptV1> {
        match &self.state {
            ThreeLaneProposalAuditStateV1::Selected { prepared, .. }
            | ThreeLaneProposalAuditStateV1::BudgetNeedsMore { prepared, .. } => {
                Some(prepared.receipt())
            }
            ThreeLaneProposalAuditStateV1::PreparationIncomplete { .. } => None,
        }
    }

    #[must_use]
    pub const fn prepared(&self) -> Option<&PreparedThreeLaneProposalUniverseV1> {
        match &self.state {
            ThreeLaneProposalAuditStateV1::Selected { prepared, .. }
            | ThreeLaneProposalAuditStateV1::BudgetNeedsMore { prepared, .. } => Some(prepared),
            ThreeLaneProposalAuditStateV1::PreparationIncomplete { .. } => None,
        }
    }

    #[must_use]
    pub fn selected_packet_ids(&self) -> Option<&[PacketIdV1]> {
        match &self.state {
            ThreeLaneProposalAuditStateV1::Selected {
                selected_packet_ids,
                ..
            } => Some(selected_packet_ids),
            ThreeLaneProposalAuditStateV1::BudgetNeedsMore { .. }
            | ThreeLaneProposalAuditStateV1::PreparationIncomplete { .. } => None,
        }
    }

    #[must_use]
    pub const fn reason(&self) -> Option<ThreeLaneNeedsMoreV1> {
        match &self.state {
            ThreeLaneProposalAuditStateV1::Selected { .. } => None,
            ThreeLaneProposalAuditStateV1::BudgetNeedsMore { reason, .. }
            | ThreeLaneProposalAuditStateV1::PreparationIncomplete { reason, .. } => Some(*reason),
        }
    }
}

impl fmt::Debug for ThreeLaneProposalAuditV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ThreeLaneProposalAuditV1")
            .field("state", &self.code())
            .field(
                "selected_packet_count",
                &self.selected_packet_ids().map(<[PacketIdV1]>::len),
            )
            .field("reason", &self.reason())
            .finish()
    }
}

/// Fixture-only compiled result whose additive costs were caller declarations.
///
/// The complete render was still tokenized, but this type deliberately makes no
/// certification claim about the selection's pre-render additive cost inputs.
pub struct DeclaredCostCompiledProductResultV1 {
    expires_at: UnixTimestampNanos,
    artifact: OwnedRenderedCompiledBriefV1,
}

impl DeclaredCostCompiledProductResultV1 {
    #[must_use]
    pub const fn result_id(&self) -> ResultId {
        self.artifact.brief().result_id()
    }

    #[must_use]
    pub const fn expires_at(&self) -> UnixTimestampNanos {
        self.expires_at
    }

    #[must_use]
    pub const fn artifact(&self) -> &OwnedRenderedCompiledBriefV1 {
        &self.artifact
    }

    #[must_use]
    pub fn references(&self) -> impl ExactSizeIterator<Item = &EvidenceReferenceV1> {
        self.artifact
            .brief()
            .evidence()
            .iter()
            .map(|packet| packet.reference())
    }

    /// Caller-declared fixture compilation never has a production three-lane
    /// proposal audit.
    #[must_use]
    pub const fn proposal_audit(&self) -> Option<&ThreeLaneProposalAuditV1> {
        None
    }
}

impl fmt::Debug for DeclaredCostCompiledProductResultV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeclaredCostCompiledProductResultV1")
            .field("artifact", &self.artifact)
            .field("fixed_expiry_present", &true)
            .finish()
    }
}

impl CompiledProductResultV1 {
    #[must_use]
    pub const fn result_id(&self) -> ResultId {
        self.artifact.brief().result_id()
    }

    #[must_use]
    pub const fn expires_at(&self) -> UnixTimestampNanos {
        self.expires_at
    }

    #[must_use]
    pub const fn artifact(&self) -> &OwnedRenderedCompiledBriefV1 {
        &self.artifact
    }

    #[must_use]
    pub fn references(&self) -> impl ExactSizeIterator<Item = &EvidenceReferenceV1> {
        self.artifact
            .brief()
            .evidence()
            .iter()
            .map(|packet| packet.reference())
    }

    /// Present only when the result was produced by the closed three-lane
    /// prepare/select orchestration. Low-level certified compilation is
    /// intentionally unaudited.
    #[must_use]
    pub fn proposal_audit(&self) -> Option<&ThreeLaneProposalAuditV1> {
        self.proposal_audit.as_deref()
    }

    /// Contentless diagnostics for an explicitly requested ranking attempt.
    /// `None` means no hosted-ranking attempt was eligible on this result path.
    /// A present `not_sent` record means a local egress gate prevented contact.
    #[must_use]
    pub fn hosted_ranking_diagnostics(&self) -> Option<&HostedRankingDiagnosticsV1> {
        self.hosted_ranking_diagnostics.as_deref()
    }
}

impl fmt::Debug for CompiledProductResultV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledProductResultV1")
            .field("artifact", &self.artifact)
            .field(
                "proposal_audit_state",
                &self.proposal_audit().map(ThreeLaneProposalAuditV1::code),
            )
            .field(
                "hosted_ranking_attempted",
                &self.hosted_ranking_diagnostics.is_some(),
            )
            .field("fixed_expiry_present", &true)
            .finish()
    }
}

/// Retained result requiring a later compiled/needs-more decision. No false
/// passthrough status or partial evidence rendering is carried here.
pub struct CompilationRequiredV1 {
    result_id: ResultId,
    question_digest: QuestionDigest,
    plan_digest: PlanDigest,
    expires_at: UnixTimestampNanos,
    acquisition: FetchCompleteness,
    references: Vec<EvidenceReferenceV1>,
    not_fit: PassthroughNotFitV1,
}

impl CompilationRequiredV1 {
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
    pub const fn expires_at(&self) -> UnixTimestampNanos {
        self.expires_at
    }

    #[must_use]
    pub const fn acquisition(&self) -> &FetchCompleteness {
        &self.acquisition
    }

    #[must_use]
    pub fn references(&self) -> &[EvidenceReferenceV1] {
        &self.references
    }

    #[must_use]
    pub const fn not_fit(&self) -> PassthroughNotFitV1 {
        self.not_fit
    }
}

impl fmt::Debug for CompilationRequiredV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompilationRequiredV1")
            .field("acquisition_code", &self.acquisition.code())
            .field("reference_count", &self.references.len())
            .field("not_fit", &self.not_fit)
            .field("fixed_expiry_present", &true)
            .finish()
    }
}

/// Honest product result of attempting exact passthrough first.
pub enum ProductResultDecisionV1 {
    Rendered(Box<RenderedProductResultV1>),
    CompilationRequired(Box<CompilationRequiredV1>),
}

/// Retained result for which deterministic compilation produced no honest
/// packet selection under the supplied total budget.
pub struct RetainedNeedsMoreProductResultV1 {
    result_id: ResultId,
    question_digest: QuestionDigest,
    plan_digest: PlanDigest,
    expires_at: UnixTimestampNanos,
    acquisition: FetchCompleteness,
    references: Vec<EvidenceReferenceV1>,
    passthrough_not_fit: PassthroughNotFitV1,
    compiler_reason: ThreeLaneNeedsMoreV1,
    proposal_audit: Box<ThreeLaneProposalAuditV1>,
}

impl RetainedNeedsMoreProductResultV1 {
    fn from_compilation_required(
        required: CompilationRequiredV1,
        compiler_reason: ThreeLaneNeedsMoreV1,
        proposal_audit: ThreeLaneProposalAuditV1,
    ) -> Self {
        Self {
            result_id: required.result_id,
            question_digest: required.question_digest,
            plan_digest: required.plan_digest,
            expires_at: required.expires_at,
            acquisition: required.acquisition,
            references: required.references,
            passthrough_not_fit: required.not_fit,
            compiler_reason,
            proposal_audit: Box::new(proposal_audit),
        }
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
    pub const fn expires_at(&self) -> UnixTimestampNanos {
        self.expires_at
    }

    #[must_use]
    pub const fn acquisition(&self) -> &FetchCompleteness {
        &self.acquisition
    }

    #[must_use]
    pub fn references(&self) -> &[EvidenceReferenceV1] {
        &self.references
    }

    #[must_use]
    pub const fn passthrough_not_fit(&self) -> PassthroughNotFitV1 {
        self.passthrough_not_fit
    }

    #[must_use]
    pub const fn compiler_reason(&self) -> ThreeLaneNeedsMoreV1 {
        self.compiler_reason
    }

    #[must_use]
    pub const fn proposal_audit(&self) -> &ThreeLaneProposalAuditV1 {
        &self.proposal_audit
    }
}

impl fmt::Debug for RetainedNeedsMoreProductResultV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedNeedsMoreProductResultV1")
            .field("acquisition_code", &self.acquisition.code())
            .field("reference_count", &self.references.len())
            .field("passthrough_not_fit", &self.passthrough_not_fit)
            .field("compiler_reason", &self.compiler_reason)
            .field("proposal_audit_state", &self.proposal_audit.code())
            .field("fixed_expiry_present", &true)
            .finish()
    }
}

/// Closed production decision from the one-call deterministic pipeline.
pub enum DeterministicProductDecisionV1 {
    Passthrough(Box<RenderedProductResultV1>),
    Compiled(Box<CompiledProductResultV1>),
    NeedsMore(Box<RetainedNeedsMoreProductResultV1>),
}

impl DeterministicProductDecisionV1 {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Passthrough(_) => "passthrough",
            Self::Compiled(_) => "compiled",
            Self::NeedsMore(_) => "needs_more",
        }
    }
}

impl fmt::Debug for DeterministicProductDecisionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeterministicProductDecisionV1")
            .field("code", &self.code())
            .finish()
    }
}

impl ProductResultDecisionV1 {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Rendered(_) => "rendered",
            Self::CompilationRequired(_) => "compilation_required",
        }
    }
}

impl fmt::Debug for ProductResultDecisionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductResultDecisionV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Contentless orchestration failure. Store and evidence failures remain typed
/// internally while public formatting exposes only the product code.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProductError {
    Store(ResultStoreError),
    Evidence(PassthroughBriefError),
    CompiledEvidence(CompiledBriefError),
    CostCertification(CompiledCostCertificationError),
    TokenBudget(TokenValueConstructionError),
    FramingFailure,
    Compiler(ThreeLaneCompileErrorV1),
    CompilationUnavailable,
    CompilationBindingMismatch,
}

impl ProductError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Store(_) => "EVIDENTRAIL_PRODUCT_STORE_FAILURE",
            Self::Evidence(_) => "EVIDENTRAIL_PRODUCT_EVIDENCE_FAILURE",
            Self::CompiledEvidence(_) => "EVIDENTRAIL_PRODUCT_COMPILED_EVIDENCE_FAILURE",
            Self::CostCertification(_) => "EVIDENTRAIL_PRODUCT_COST_CERTIFICATION_FAILURE",
            Self::TokenBudget(_) => "EVIDENTRAIL_PRODUCT_INVALID_TOKEN_BUDGET",
            Self::FramingFailure => "EVIDENTRAIL_PRODUCT_FRAMING_FAILURE",
            Self::Compiler(_) => "EVIDENTRAIL_PRODUCT_COMPILER_FAILURE",
            Self::CompilationUnavailable => "EVIDENTRAIL_PRODUCT_COMPILATION_UNAVAILABLE",
            Self::CompilationBindingMismatch => "EVIDENTRAIL_PRODUCT_COMPILATION_BINDING_MISMATCH",
        }
    }

    #[must_use]
    pub const fn store_error(self) -> Option<ResultStoreError> {
        match self {
            Self::Store(error) => Some(error),
            Self::Evidence(_)
            | Self::CompiledEvidence(_)
            | Self::CostCertification(_)
            | Self::TokenBudget(_)
            | Self::FramingFailure
            | Self::Compiler(_)
            | Self::CompilationUnavailable
            | Self::CompilationBindingMismatch => None,
        }
    }

    #[must_use]
    pub const fn evidence_error(self) -> Option<PassthroughBriefError> {
        match self {
            Self::Evidence(error) => Some(error),
            Self::Store(_)
            | Self::CompiledEvidence(_)
            | Self::CostCertification(_)
            | Self::TokenBudget(_)
            | Self::FramingFailure
            | Self::Compiler(_)
            | Self::CompilationUnavailable
            | Self::CompilationBindingMismatch => None,
        }
    }

    #[must_use]
    pub const fn compiled_evidence_error(self) -> Option<CompiledBriefError> {
        match self {
            Self::CompiledEvidence(error) => Some(error),
            Self::Store(_)
            | Self::Evidence(_)
            | Self::CostCertification(_)
            | Self::TokenBudget(_)
            | Self::FramingFailure
            | Self::Compiler(_)
            | Self::CompilationUnavailable
            | Self::CompilationBindingMismatch => None,
        }
    }

    #[must_use]
    pub const fn cost_certification_error(self) -> Option<CompiledCostCertificationError> {
        match self {
            Self::CostCertification(error) => Some(error),
            Self::Store(_)
            | Self::Evidence(_)
            | Self::CompiledEvidence(_)
            | Self::TokenBudget(_)
            | Self::FramingFailure
            | Self::Compiler(_)
            | Self::CompilationUnavailable
            | Self::CompilationBindingMismatch => None,
        }
    }

    #[must_use]
    pub const fn token_budget_error(self) -> Option<TokenValueConstructionError> {
        match self {
            Self::TokenBudget(error) => Some(error),
            Self::Store(_)
            | Self::Evidence(_)
            | Self::CompiledEvidence(_)
            | Self::CostCertification(_)
            | Self::FramingFailure
            | Self::Compiler(_)
            | Self::CompilationUnavailable
            | Self::CompilationBindingMismatch => None,
        }
    }

    #[must_use]
    pub const fn compiler_error(self) -> Option<ThreeLaneCompileErrorV1> {
        match self {
            Self::Compiler(error) => Some(error),
            Self::Store(_)
            | Self::Evidence(_)
            | Self::CompiledEvidence(_)
            | Self::CostCertification(_)
            | Self::TokenBudget(_)
            | Self::FramingFailure
            | Self::CompilationUnavailable
            | Self::CompilationBindingMismatch => None,
        }
    }
}

impl fmt::Debug for ProductError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for ProductError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ProductError {}

#[derive(Clone, PartialEq, Eq)]
enum RetainedThreeLanePreparationV1 {
    Prepared(Box<PreparedThreeLaneProposalUniverseV1>),
    Incomplete(Box<ThreeLaneProposalPreparationNeedsMoreV1>),
}

impl RetainedThreeLanePreparationV1 {
    const fn input(&self) -> ProposalPreparationInputReceiptV1 {
        match self {
            Self::Prepared(prepared) => prepared.receipt().input(),
            Self::Incomplete(incomplete) => incomplete.input(),
        }
    }
}

impl fmt::Debug for RetainedThreeLanePreparationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedThreeLanePreparationV1")
            .field(
                "state",
                &match self {
                    Self::Prepared(_) => "prepared",
                    Self::Incomplete(_) => "incomplete",
                },
            )
            .finish()
    }
}

/// Memory-only owner of retained result ledgers and expansion capabilities.
#[derive(Clone)]
struct RetainedCompilationV1 {
    question_digest: QuestionDigest,
    plan_digest: PlanDigest,
    expires_at: UnixTimestampNanos,
    acquisition: FetchCompleteness,
    references: Vec<EvidenceReferenceV1>,
    not_fit: PassthroughNotFitV1,
    three_lane_preparation: Option<RetainedThreeLanePreparationV1>,
}

impl RetainedCompilationV1 {
    fn into_compilation_required(self, result_id: ResultId) -> CompilationRequiredV1 {
        CompilationRequiredV1 {
            result_id,
            question_digest: self.question_digest,
            plan_digest: self.plan_digest,
            expires_at: self.expires_at,
            acquisition: self.acquisition,
            references: self.references,
            not_fit: self.not_fit,
        }
    }
}

fn verify_compiler_wrapper_binding_v1(
    expected_result_id: ResultId,
    expected_question_digest: QuestionDigest,
    actual_result_id: ResultId,
    actual_question_digest: QuestionDigest,
) -> Result<(), ProductError> {
    if actual_result_id != expected_result_id || actual_question_digest != expected_question_digest
    {
        return Err(ProductError::CompilationBindingMismatch);
    }
    Ok(())
}

fn verify_retained_preparation_binding_v1(
    required: &CompilationRequiredV1,
    preparation: &RetainedThreeLanePreparationV1,
    ledger: &EventLedger,
    tokenizer: &Utf8ByteTokenizerV1,
) -> Result<(), ProductError> {
    let input = preparation.input();
    let tokenizer_bound = tokenizer.ascii_render_bound_contract();
    if input.result_id() != required.result_id
        || input.question_digest() != required.question_digest
        || input.retrieval_id() != ledger.retrieval_id()
        || input.plan_id() != ledger.plan_id()
        || input.plan_digest() != required.plan_digest
        || input.plan_digest() != ledger.plan_digest()
        || input.source_identity_digest() != ledger.source_identity_digest()
        || input.acquisition_receipt_id() != ledger.acquisition_receipt_id()
        || input.tokenizer_digest() != tokenizer.digest()
        || input.tokenizer_bound_contract_digest() != tokenizer_bound.contract_digest()
        || required.not_fit.tokenizer_digest() != input.tokenizer_digest()
    {
        return Err(ProductError::CompilationBindingMismatch);
    }
    Ok(())
}

fn assisted_selection_v1(
    ledger: &EventLedger,
    question_bytes: &[u8],
    prepared: &PreparedThreeLaneProposalUniverseV1,
    total_token_budget: TotalTokenBudgetV1,
    tokenizer: &Utf8ByteTokenizerV1,
    deterministic: Box<CertifiedThreeLaneSelectionV1>,
    attempt: HostedRankingAttemptV1<'_>,
) -> (
    Box<CertifiedThreeLaneSelectionV1>,
    Option<HostedRankingDiagnosticsV1>,
) {
    let application_code = attempt.application.code();
    let mandatory = prepared
        .mandatory()
        .iter()
        .map(|entry| entry.packet_id())
        .collect::<std::collections::BTreeSet<_>>();
    let mut seen = std::collections::BTreeSet::new();
    let mut deterministic_ids = Vec::new();
    for packet_id in deterministic
        .selection()
        .packets()
        .iter()
        .map(|selected| selected.packet().id())
        .chain(prepared.proposal_packets().iter().map(|packet| packet.id()))
    {
        if !mandatory.contains(&packet_id) && seen.insert(packet_id) {
            deterministic_ids.push(packet_id);
        }
    }
    deterministic_ids.truncate(MAX_HOSTED_RANKING_CANDIDATES_V1);
    if deterministic_ids.len() < 2 {
        return (deterministic, None);
    }

    let escaped_question = escape_evidence_bytes(question_bytes);
    if escaped_question.len() > MAX_HOSTED_RANKING_ESCAPED_INPUT_BYTES_V1 {
        return (
            deterministic,
            Some(HostedRankingDiagnosticsV1::not_sent(
                application_code,
                "request_too_large",
            )),
        );
    }
    let mut escaped_input_bytes = escaped_question.len();
    let mut candidates = Vec::with_capacity(deterministic_ids.len());
    for (index, packet_id) in deterministic_ids.iter().copied().enumerate() {
        let Some(metadata) = prepared.proposal_metadata(packet_id) else {
            return (deterministic, None);
        };
        let mut exact_block = Vec::new();
        for event_id in metadata.ordered_event_ids() {
            let Ok(event) = ledger.event(*event_id) else {
                return (deterministic, None);
            };
            exact_block.extend_from_slice(event.raw());
        }
        let escaped_block = escape_evidence_bytes(&exact_block);
        escaped_input_bytes = match escaped_input_bytes.checked_add(escaped_block.len()) {
            Some(total) if total <= MAX_HOSTED_RANKING_ESCAPED_INPUT_BYTES_V1 => total,
            Some(_) | None => {
                return (
                    deterministic,
                    Some(HostedRankingDiagnosticsV1::not_sent(
                        application_code,
                        "request_too_large",
                    )),
                );
            }
        };
        candidates.push(EvidenceRankingCandidateV1::new(
            format!("B{}", index + 1),
            packet_id,
            escaped_block,
        ));
    }
    let request = EvidenceRankingRequestV1::new(escaped_question, candidates);
    let ranking_started = Instant::now();
    let output = match attempt.ranker.rank(&request) {
        Ok(output) => output,
        Err(error) => {
            return (
                deterministic,
                Some(HostedRankingDiagnosticsV1::provider_failure(
                    application_code,
                    error,
                    u64::try_from(ranking_started.elapsed().as_nanos()).unwrap_or(u64::MAX),
                )),
            );
        }
    };
    let ranking =
        match validate_evidence_ranking_response_v1(output.response_json(), request.candidates()) {
            Ok(ranking) => ranking,
            Err(error) => {
                return (
                    deterministic,
                    Some(HostedRankingDiagnosticsV1::invalid(
                        application_code,
                        &output,
                        error,
                    )),
                );
            }
        };
    let consumed = consume_evidence_ranking_v1(
        RankingConsumerV1::BoundedFourthAffinity,
        &deterministic_ids,
        &ranking,
    );
    let priorities = ranking_priorities_v1(&consumed);
    let assisted = select_prepared_three_lane_proposals_with_priorities_v1(
        ledger,
        prepared.clone(),
        total_token_budget,
        tokenizer,
        &priorities,
    );
    match assisted {
        Ok(PreparedThreeLaneSelectionDecisionV1::Selected(assisted)) => {
            let proposal_changed = assisted
                .selection()
                .packets()
                .iter()
                .map(|selected| selected.packet().id())
                .ne(deterministic
                    .selection()
                    .packets()
                    .iter()
                    .map(|selected| selected.packet().id()));
            let diagnostics = Some(HostedRankingDiagnosticsV1::accepted(
                application_code,
                proposal_changed,
                &output,
                ranking.ranked_packet_ids(),
            ));
            match attempt.application {
                HostedRankingApplicationV1::Apply => (assisted, diagnostics),
                HostedRankingApplicationV1::Shadow => (deterministic, diagnostics),
            }
        }
        Ok(PreparedThreeLaneSelectionDecisionV1::NeedsMore(_)) | Err(_) => (
            deterministic,
            Some(HostedRankingDiagnosticsV1::accepted_but_fallback(
                application_code,
                &output,
                ranking.ranked_packet_ids(),
            )),
        ),
    }
}

#[derive(Clone, Copy)]
enum HostedRankingApplicationV1 {
    Apply,
    Shadow,
}

struct HostedRankingAttemptV1<'a> {
    ranker: &'a mut dyn EvidenceRankerV1,
    application: HostedRankingApplicationV1,
}

impl HostedRankingApplicationV1 {
    const fn code(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::Shadow => "shadow",
        }
    }
}

#[derive(Default)]
pub struct MemoryProductV1 {
    store: MemoryResultStore,
    retained_compilations: BTreeMap<ResultId, RetainedCompilationV1>,
}

impl MemoryProductV1 {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run the complete deterministic V1 product path in one call.
    ///
    /// Exact passthrough is attempted first with the built-in UTF-8 byte
    /// tokenizer. On a miss, the retained ledger is deterministically framed,
    /// all three active candidate lanes are compiled while `question_bytes`
    /// remains only a borrowed call input, and the exact returned selection and
    /// certificate are finalized through the certified renderer. A compiler
    /// needs-more decision keeps the result and its exact expansion references
    /// retained without publishing evidence aliases.
    pub fn create_deterministic_result_v1(
        &mut self,
        result_id: ResultId,
        question_bytes: &[u8],
        ledger: EventLedger,
        now: UnixTimestampNanos,
        total_token_limit: u64,
    ) -> Result<DeterministicProductDecisionV1, ProductError> {
        TotalTokenBudgetV1::new(total_token_limit).map_err(ProductError::TokenBudget)?;
        let tokenizer = Utf8ByteTokenizerV1::new();
        let initial = self.create_result(
            result_id,
            question_bytes,
            ledger,
            now,
            total_token_limit,
            &tokenizer,
        )?;
        let required = match initial {
            ProductResultDecisionV1::Rendered(rendered) => {
                return Ok(DeterministicProductDecisionV1::Passthrough(rendered));
            }
            ProductResultDecisionV1::CompilationRequired(required) => required,
        };
        self.compile_retained_miss_v1(result_id, question_bytes, *required, now, &tokenizer, None)
    }

    /// Run the deterministic pipeline with one optional hosted-ranking call.
    /// Passthrough and every deterministic `needs_more` decision return before
    /// the ranker is contacted. Any ranking failure returns the already
    /// computed deterministic selection without retrying.
    pub fn create_hosted_ranked_result_v1<R: EvidenceRankerV1>(
        &mut self,
        result_id: ResultId,
        question_bytes: &[u8],
        ledger: EventLedger,
        now: UnixTimestampNanos,
        total_token_limit: u64,
        ranker: &mut R,
    ) -> Result<DeterministicProductDecisionV1, ProductError> {
        TotalTokenBudgetV1::new(total_token_limit).map_err(ProductError::TokenBudget)?;
        let tokenizer = Utf8ByteTokenizerV1::new();
        let initial = self.create_result(
            result_id,
            question_bytes,
            ledger,
            now,
            total_token_limit,
            &tokenizer,
        )?;
        let required = match initial {
            ProductResultDecisionV1::Rendered(rendered) => {
                return Ok(DeterministicProductDecisionV1::Passthrough(rendered));
            }
            ProductResultDecisionV1::CompilationRequired(required) => required,
        };
        self.compile_retained_miss_v1(
            result_id,
            question_bytes,
            *required,
            now,
            &tokenizer,
            Some(HostedRankingAttemptV1 {
                ranker,
                application: HostedRankingApplicationV1::Apply,
            }),
        )
    }

    /// Run the complete hosted-ranking path but always render the already
    /// computed deterministic selection. Contentless diagnostics report
    /// whether the validated assisted proposal would have changed it.
    pub fn create_shadow_ranked_result_v1<R: EvidenceRankerV1>(
        &mut self,
        result_id: ResultId,
        question_bytes: &[u8],
        ledger: EventLedger,
        now: UnixTimestampNanos,
        total_token_limit: u64,
        ranker: &mut R,
    ) -> Result<DeterministicProductDecisionV1, ProductError> {
        TotalTokenBudgetV1::new(total_token_limit).map_err(ProductError::TokenBudget)?;
        let tokenizer = Utf8ByteTokenizerV1::new();
        let initial = self.create_result(
            result_id,
            question_bytes,
            ledger,
            now,
            total_token_limit,
            &tokenizer,
        )?;
        let required = match initial {
            ProductResultDecisionV1::Rendered(rendered) => {
                return Ok(DeterministicProductDecisionV1::Passthrough(rendered));
            }
            ProductResultDecisionV1::CompilationRequired(required) => required,
        };
        self.compile_retained_miss_v1(
            result_id,
            question_bytes,
            *required,
            now,
            &tokenizer,
            Some(HostedRankingAttemptV1 {
                ranker,
                application: HostedRankingApplicationV1::Shadow,
            }),
        )
    }

    /// Resume the deterministic compiler for an existing retained passthrough
    /// miss without reacquiring or reinserting its ledger.
    ///
    /// The caller must resupply the exact question bytes. Only their digest is
    /// compared with retained state; raw question bytes are never stored. The
    /// original total budget, tokenizer identity, plan digest, references, and
    /// fixed expiry remain authoritative. Failures and needs-more outcomes do
    /// not publish aliases or mutate those retained capabilities.
    pub fn resume_deterministic_result_v1(
        &mut self,
        result_id: ResultId,
        question_bytes: &[u8],
        now: UnixTimestampNanos,
    ) -> Result<DeterministicProductDecisionV1, ProductError> {
        let retained = self
            .retained_compilations
            .get(&result_id)
            .cloned()
            .ok_or(ProductError::CompilationUnavailable)?;
        let required = retained.into_compilation_required(result_id);
        let tokenizer = Utf8ByteTokenizerV1::new();
        self.compile_retained_miss_v1(result_id, question_bytes, required, now, &tokenizer, None)
    }

    fn compile_retained_miss_v1(
        &mut self,
        result_id: ResultId,
        question_bytes: &[u8],
        required: CompilationRequiredV1,
        now: UnixTimestampNanos,
        tokenizer: &Utf8ByteTokenizerV1,
        mut hosted_attempt: Option<HostedRankingAttemptV1<'_>>,
    ) -> Result<DeterministicProductDecisionV1, ProductError> {
        let expected_question_digest = derive_question_digest_v1(question_bytes);
        verify_compiler_wrapper_binding_v1(
            result_id,
            expected_question_digest,
            required.result_id,
            required.question_digest,
        )?;
        if required.not_fit.tokenizer_digest() != tokenizer.digest() {
            return Err(ProductError::CompilationBindingMismatch);
        }
        let total_token_budget = TotalTokenBudgetV1::new(required.not_fit.total_token_limit())
            .map_err(ProductError::TokenBudget)?;
        // Touch the retained ledger on every attempt so expiry remains
        // authoritative even when preparation is already cached.
        let cached_preparation = self
            .retained_compilations
            .get(&result_id)
            .and_then(|retained| retained.three_lane_preparation.clone());
        let preparation = match cached_preparation {
            Some(preparation) => {
                let retained_ledger = self
                    .store
                    .ledger(result_id, now)
                    .map_err(ProductError::Store)?;
                verify_retained_preparation_binding_v1(
                    &required,
                    &preparation,
                    retained_ledger,
                    tokenizer,
                )?;
                preparation
            }
            None => {
                let decision = {
                    let retained_ledger = self
                        .store
                        .ledger(result_id, now)
                        .map_err(ProductError::Store)?;
                    let blocks = frame_source_lanes_v1(retained_ledger)
                        .map_err(|_| ProductError::FramingFailure)?;
                    prepare_three_lane_proposal_universe_v1(
                        question_bytes,
                        retained_ledger,
                        &blocks,
                        result_id,
                        tokenizer,
                    )
                    .map_err(ProductError::Compiler)?
                };
                let preparation = match decision {
                    ThreeLaneProposalPreparationDecisionV1::Prepared(prepared) => {
                        RetainedThreeLanePreparationV1::Prepared(prepared)
                    }
                    ThreeLaneProposalPreparationDecisionV1::NeedsMore(incomplete) => {
                        RetainedThreeLanePreparationV1::Incomplete(incomplete)
                    }
                };
                let retained = self
                    .retained_compilations
                    .get_mut(&result_id)
                    .ok_or(ProductError::CompilationUnavailable)?;
                retained.three_lane_preparation = Some(preparation.clone());
                preparation
            }
        };

        match preparation {
            RetainedThreeLanePreparationV1::Incomplete(incomplete) => {
                let reason = incomplete.reason();
                let audit =
                    ThreeLaneProposalAuditV1::preparation_incomplete(incomplete.input(), reason);
                Ok(DeterministicProductDecisionV1::NeedsMore(Box::new(
                    RetainedNeedsMoreProductResultV1::from_compilation_required(
                        required, reason, audit,
                    ),
                )))
            }
            RetainedThreeLanePreparationV1::Prepared(prepared) => {
                let frozen_prepared = *prepared;
                let selection_decision = {
                    let retained_ledger = self
                        .store
                        .ledger(result_id, now)
                        .map_err(ProductError::Store)?;
                    select_prepared_three_lane_proposals_v1(
                        retained_ledger,
                        frozen_prepared.clone(),
                        total_token_budget,
                        tokenizer,
                    )
                    .map_err(ProductError::Compiler)?
                };
                let deterministic_compiled = match selection_decision {
                    PreparedThreeLaneSelectionDecisionV1::NeedsMore(needs_more) => {
                        let reason = needs_more.reason();
                        let returned_prepared = needs_more.into_prepared();
                        if returned_prepared != frozen_prepared {
                            return Err(ProductError::CompilationBindingMismatch);
                        }
                        let audit =
                            ThreeLaneProposalAuditV1::budget_needs_more(returned_prepared, reason);
                        return Ok(DeterministicProductDecisionV1::NeedsMore(Box::new(
                            RetainedNeedsMoreProductResultV1::from_compilation_required(
                                required, reason, audit,
                            ),
                        )));
                    }
                    PreparedThreeLaneSelectionDecisionV1::Selected(compiled) => compiled,
                };
                let (compiled, hosted_ranking_diagnostics) =
                    if let Some(attempt) = hosted_attempt.take() {
                        let retained_ledger = self
                            .store
                            .ledger(result_id, now)
                            .map_err(ProductError::Store)?;
                        assisted_selection_v1(
                            retained_ledger,
                            question_bytes,
                            &frozen_prepared,
                            total_token_budget,
                            tokenizer,
                            deterministic_compiled,
                            attempt,
                        )
                    } else {
                        (deterministic_compiled, None)
                    };
                verify_compiler_wrapper_binding_v1(
                    required.result_id,
                    required.question_digest,
                    compiled.result_id(),
                    compiled.question_digest(),
                )?;
                verify_compiler_wrapper_binding_v1(
                    result_id,
                    expected_question_digest,
                    compiled.result_id(),
                    compiled.question_digest(),
                )?;
                let mut frozen_proposal_ids = frozen_prepared
                    .proposal_packets()
                    .iter()
                    .map(|packet| packet.id())
                    .collect::<Vec<_>>();
                frozen_proposal_ids.sort_unstable();
                if compiled.proposal_receipt() != frozen_prepared.receipt()
                    || compiled.proposal_packet_ids() != frozen_proposal_ids.as_slice()
                {
                    return Err(ProductError::CompilationBindingMismatch);
                }
                let audit = ThreeLaneProposalAuditV1::selected(
                    frozen_prepared,
                    compiled
                        .selection()
                        .packets()
                        .iter()
                        .map(|selected| selected.packet().id()),
                )?;
                let selection = compiled.selection().clone();
                let certification = compiled.certification().clone();
                let mut result = self.compile_retained_result(
                    result_id,
                    selection,
                    &certification,
                    now,
                    tokenizer,
                )?;
                result.proposal_audit = Some(Box::new(audit));
                result.hosted_ranking_diagnostics = hosted_ranking_diagnostics.map(Box::new);
                Ok(DeterministicProductDecisionV1::Compiled(Box::new(result)))
            }
        }
    }

    /// Low-level staged API: retain one sealed result, atomically register
    /// per-event references, and attempt the canonical exact passthrough
    /// render. Production callers should normally use
    /// [`Self::create_deterministic_result_v1`].
    ///
    /// Hard renderer/tokenizer failures roll the insertion back. A valid
    /// over-budget result remains retained for compilation and exact expansion.
    pub fn create_result<T>(
        &mut self,
        result_id: ResultId,
        question_bytes: &[u8],
        ledger: EventLedger,
        now: UnixTimestampNanos,
        total_token_limit: u64,
        tokenizer: &T,
    ) -> Result<ProductResultDecisionV1, ProductError>
    where
        T: PinnedTokenizer + ?Sized,
    {
        let question_digest = derive_question_digest_v1(question_bytes);
        let plan_digest = ledger.plan_digest();
        let acquisition = ledger.fetch_completion().completeness().clone();
        let registered = self
            .store
            .insert_with_event_references(result_id, ledger, now)
            .map_err(ProductError::Store)?;
        let expires_at = registered.expires_at();
        let references = registered.references().to_vec();

        let decision = match self.store.ledger(result_id, now) {
            Ok(stored_ledger) => render_passthrough_log_brief_v1(
                stored_ledger,
                result_id,
                question_digest,
                plan_digest,
                references.clone(),
                now,
                total_token_limit,
                tokenizer,
            ),
            Err(error) => {
                self.store.delete(result_id);
                return Err(ProductError::Store(error));
            }
        };

        match decision {
            Ok(PassthroughBriefDecisionV1::Rendered(rendered)) => {
                let artifact = (*rendered).into_owned();
                if let Err(error) = self.store.publish_event_aliases(result_id, now) {
                    self.store.delete(result_id);
                    return Err(ProductError::Store(error));
                }
                Ok(ProductResultDecisionV1::Rendered(Box::new(
                    RenderedProductResultV1 {
                        expires_at,
                        artifact,
                    },
                )))
            }
            Ok(PassthroughBriefDecisionV1::CompilationRequired(not_fit)) => {
                self.retained_compilations.insert(
                    result_id,
                    RetainedCompilationV1 {
                        question_digest,
                        plan_digest,
                        expires_at,
                        acquisition: acquisition.clone(),
                        references: references.clone(),
                        not_fit,
                        three_lane_preparation: None,
                    },
                );
                Ok(ProductResultDecisionV1::CompilationRequired(Box::new(
                    CompilationRequiredV1 {
                        result_id,
                        question_digest,
                        plan_digest,
                        expires_at,
                        acquisition,
                        references,
                        not_fit,
                    },
                )))
            }
            Err(error) => {
                self.store.delete(result_id);
                self.retained_compilations.remove(&result_id);
                Err(ProductError::Evidence(error))
            }
        }
    }

    /// Compile exact renderer costs for a proposed, event-disjoint packet
    /// universe against the retained ledger.
    ///
    /// The returned certificate supplies the only production packet costs that
    /// may be fed into the selector and later accepted by
    /// [`Self::compile_retained_result`]. This performs no rendering and makes
    /// no store mutation.
    pub fn certify_retained_compilation_costs(
        &self,
        result_id: ResultId,
        memberships: impl IntoIterator<Item = CompiledPacketMembershipV1>,
        now: UnixTimestampNanos,
        tokenizer: &Utf8ByteTokenizerV1,
    ) -> Result<CompiledCostCertificationV1, ProductError> {
        let retained = self
            .retained_compilations
            .get(&result_id)
            .cloned()
            .ok_or(ProductError::CompilationUnavailable)?;
        if retained.not_fit.tokenizer_digest() != tokenizer.digest() {
            return Err(ProductError::CompilationBindingMismatch);
        }
        let ledger = self
            .store
            .ledger(result_id, now)
            .map_err(ProductError::Store)?;
        certify_compiled_costs_v1(ledger, result_id, memberships, tokenizer)
            .map_err(ProductError::CostCertification)
    }

    /// Compile an existing retained canonical passthrough miss from a sealed
    /// renderer-derived cost certificate.
    ///
    /// The tokenizer identity and total budget must match the original not-fit
    /// decision. Packet references are prepared without mutation. Only exact
    /// certificate/ledger/result/selection agreement followed by successful
    /// whole-render tokenization atomically replaces the old event-reference
    /// alias manifest. Any failure preserves the retained result and its exact
    /// expansion capabilities.
    pub fn compile_retained_result(
        &mut self,
        result_id: ResultId,
        selection: SelectionV1,
        certification: &CompiledCostCertificationV1,
        now: UnixTimestampNanos,
        tokenizer: &Utf8ByteTokenizerV1,
    ) -> Result<CompiledProductResultV1, ProductError> {
        let retained = self
            .retained_compilations
            .get(&result_id)
            .cloned()
            .ok_or(ProductError::CompilationUnavailable)?;
        if retained.not_fit.tokenizer_digest() != tokenizer.digest()
            || retained.not_fit.total_token_limit() != selection.total_token_budget().tokens()
        {
            return Err(ProductError::CompilationBindingMismatch);
        }
        {
            let stored_ledger = self
                .store
                .ledger(result_id, now)
                .map_err(ProductError::Store)?;
            certification
                .verify_selection(stored_ledger, result_id, &selection, tokenizer)
                .map_err(ProductError::CostCertification)?;
        }
        let packet_event_ids = selection
            .packets()
            .iter()
            .map(|selected| selected.packet().event_ids().to_vec())
            .collect::<Vec<_>>();
        let prepared = self
            .store
            .prepare_packet_references(result_id, packet_event_ids, now)
            .map_err(ProductError::Store)?;
        let expires_at = prepared.expires_at();
        let references = prepared.references().to_vec();

        let rendered = match self.store.ledger(result_id, now) {
            Ok(stored_ledger) => render_cost_certified_compiled_log_brief_v1(
                stored_ledger,
                result_id,
                retained.question_digest,
                retained.plan_digest,
                selection,
                references,
                now,
                tokenizer,
                certification,
            ),
            Err(error) => return Err(ProductError::Store(error)),
        };
        match rendered {
            Ok(rendered) => {
                let artifact = rendered.into_owned();
                self.store
                    .commit_packet_references(prepared, now)
                    .map_err(ProductError::Store)?;
                self.retained_compilations.remove(&result_id);
                Ok(CompiledProductResultV1 {
                    expires_at,
                    artifact,
                    proposal_audit: None,
                    hosted_ranking_diagnostics: None,
                })
            }
            Err(error) => Err(ProductError::CompiledEvidence(error)),
        }
    }

    /// Explicit fixture path for legacy caller-declared packet costs.
    ///
    /// This never returns [`CompiledProductResultV1`] and therefore cannot
    /// expose the manual cost claims as certified product accounting.
    #[doc(hidden)]
    pub fn compile_retained_result_with_declared_costs_for_fixture<T>(
        &mut self,
        result_id: ResultId,
        selection: SelectionV1,
        now: UnixTimestampNanos,
        tokenizer: &T,
    ) -> Result<DeclaredCostCompiledProductResultV1, ProductError>
    where
        T: PinnedTokenizer + ?Sized,
    {
        let retained = self
            .retained_compilations
            .get(&result_id)
            .cloned()
            .ok_or(ProductError::CompilationUnavailable)?;
        if retained.not_fit.tokenizer_digest() != tokenizer.digest()
            || retained.not_fit.total_token_limit() != selection.total_token_budget().tokens()
        {
            return Err(ProductError::CompilationBindingMismatch);
        }
        let packet_event_ids = selection
            .packets()
            .iter()
            .map(|selected| selected.packet().event_ids().to_vec())
            .collect::<Vec<_>>();
        let prepared = self
            .store
            .prepare_packet_references(result_id, packet_event_ids, now)
            .map_err(ProductError::Store)?;
        let expires_at = prepared.expires_at();
        let references = prepared.references().to_vec();

        let rendered = match self.store.ledger(result_id, now) {
            Ok(stored_ledger) => render_compiled_log_brief_v1(
                stored_ledger,
                result_id,
                retained.question_digest,
                retained.plan_digest,
                selection,
                references,
                now,
                tokenizer,
            ),
            Err(error) => return Err(ProductError::Store(error)),
        };
        match rendered {
            Ok(rendered) => {
                let artifact = rendered.into_owned();
                self.store
                    .commit_packet_references(prepared, now)
                    .map_err(ProductError::Store)?;
                self.retained_compilations.remove(&result_id);
                Ok(DeclaredCostCompiledProductResultV1 {
                    expires_at,
                    artifact,
                })
            }
            Err(error) => Err(ProductError::CompiledEvidence(error)),
        }
    }

    pub fn expand(
        &self,
        request: ExpansionRequestV1,
        now: UnixTimestampNanos,
    ) -> Result<ExpansionResponseV1, ResultStoreError> {
        self.store.expand(request, now)
    }

    /// Expand a result-scoped short citation such as `E1`. Alias resolution is
    /// confined to the immutable manifest created with that result.
    pub fn expand_alias(
        &self,
        request: AliasExpansionRequestV1,
        now: UnixTimestampNanos,
    ) -> Result<ExpansionResponseV1, ResultStoreError> {
        if self
            .retained_compilations
            .contains_key(&request.result_id())
        {
            return Err(ResultStoreError::ReferenceUnavailable);
        }
        self.store.expand_alias(request, now)
    }

    pub fn cleanup_expired(&mut self, now: UnixTimestampNanos) -> usize {
        let removed = self.store.cleanup_expired(now);
        self.retained_compilations
            .retain(|_, retained| now < retained.expires_at);
        removed
    }

    #[must_use]
    pub fn result_count(&self) -> usize {
        self.store.result_count()
    }
}

impl fmt::Debug for MemoryProductV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryProductV1")
            .field("backend", &"memory_only")
            .field("result_count", &self.store.result_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiler_wrapper_binding_rejects_result_and_question_drift_independently() {
        let result_id = ResultId::from_bytes([0x31; 32]);
        let question_digest = QuestionDigest::from_bytes([0x41; 32]);
        assert_eq!(
            verify_compiler_wrapper_binding_v1(
                result_id,
                question_digest,
                result_id,
                question_digest,
            ),
            Ok(())
        );
        for (actual_result, actual_question) in [
            (ResultId::from_bytes([0x32; 32]), question_digest),
            (result_id, QuestionDigest::from_bytes([0x42; 32])),
        ] {
            assert_eq!(
                verify_compiler_wrapper_binding_v1(
                    result_id,
                    question_digest,
                    actual_result,
                    actual_question,
                ),
                Err(ProductError::CompilationBindingMismatch)
            );
        }
    }
}
