//! Bounded memory and durable product entry points for explicit standard input.
//!
//! Neither mode reopens a source path, crawls a workspace, nor inspects ambient
//! logs. The caller owns the exact bytes, supplies one question, and receives
//! either the canonical deterministic Log Brief or an honest `needs_more`
//! decision. Memory remains the binary default. On Unix, injected V1 and V2
//! backends provide authenticated exact expansion; V2 returns a rendered result
//! only after repository publication authority has been verified.

mod external_corpus_v3;
mod hosted_ranking;
mod incident_analysis;
mod mcp;

pub use incident_analysis::{
    AnalysisError, AnalysisReport, EvidenceCitation, FaultType, Hypothesis, IncidentReasoner,
    ModelAssessment, OpenAiIncidentReasoner, ServiceTopology, analyze_with_reasoner,
    analyze_with_reasoner_and_metrics,
};

use std::error::Error as StdError;
use std::fmt;
use std::io::Read;

use evidentrail_compile::ThreeLaneNeedsMoreV1;
use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    CompletenessProof, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, EventLedger,
    FetchBoundaries, FetchCompleteness, FetchCompletion, FetchIdentity, FetchTiming, LaneKey,
    LaneSequence, LedgerBuilder, PlanDigest, PlanId, PolicyAuthorization, RawEnvelopeIdentityV1,
    RawEnvelopeV1, RecordBytes, RecordState, RetrievalId, SourceIdentityDigest, SourceMember,
    SourceStream, UnixTimestampNanos, derive_source_exact_event_id_v1,
};
#[cfg(unix)]
use evidentrail_product::AuthenticatedEncryptedRetentionV1;
use evidentrail_product::{
    CompiledProductResultV1, DeterministicProductDecisionV1, EvidenceRankerV1,
    HostedRankingDiagnosticsV1, MemoryProductV1, ProductError, RankingConsumerV1,
    RenderedProductResultV1, StreamingAnalysisContextV3, StreamingProductV3,
    streaming_product_build_context_v3,
};
#[cfg(unix)]
use evidentrail_product::{DurableProductErrorV2, DurableProductV2};
use evidentrail_schema::ResultId;
use evidentrail_schema::bounds::{
    JSON_SAFE_INTEGER_MAX, MAX_AUTHORIZED_RECORD_BYTES, MAX_WIRE_OBJECT_BYTES,
};
#[cfg(unix)]
use evidentrail_snapshot_format::ExpectedCoreResultManifestContextV1;
#[cfg(unix)]
use evidentrail_store::KeyAuthorityV2;
use evidentrail_store::{
    AliasExpansionRequestV1, ExpansionResponseV1, MAX_STREAM_RECORDS_V3,
    MAX_STREAM_SOURCE_BYTES_V3, ResultStoreError, RetainedAcquisitionFinishV3,
    RetainedEventInputV3, RetainedEventStoreErrorV3, RetainedEventStoreV3, RetainedStoreBeginV3,
};
#[cfg(unix)]
use evidentrail_store::{
    AuthenticatedFilesystemRestartCoordinatorV1, CreatingKeyContextV1,
    FilesystemBundlePublicationV1, KeyProviderV1,
};
use sha2::{Digest as _, Sha256};

pub use external_corpus_v3::{
    ExternalCorpusImportErrorV3, ExternalCorpusImportReportV3,
    import_external_adjudicated_corpus_v3,
};
pub use hosted_ranking::{
    FROZEN_INPUT_PRICE_MICROUSD_PER_MILLION_TOKENS_V1,
    FROZEN_OUTPUT_PRICE_MICROUSD_PER_MILLION_TOKENS_V1,
    HOSTED_RANKING_CHARACTERIZATION_DEADLINE_V1, HOSTED_RANKING_DEADLINE_V1,
    HOSTED_RANKING_LATENCY_CHALLENGER_MODEL_V1, HOSTED_RANKING_MEASUREMENT_DEADLINE_V2,
    HostedRankingDiagnosticRecordV1, LATENCY_CHALLENGER_INPUT_PRICE_MICROUSD_PER_MILLION_TOKENS_V1,
    LATENCY_CHALLENGER_OUTPUT_PRICE_MICROUSD_PER_MILLION_TOKENS_V1, OpenAiEvidenceRankerV1,
    PINNED_HOSTED_RANKING_MODEL_V1, hosted_ranking_characterization_configuration_digest_v1,
    hosted_ranking_configuration_digest_v1,
    hosted_ranking_latency_challenger_configuration_digest_v1,
    hosted_ranking_measurement_configuration_digest_v2, hosted_ranking_provider_digest_v1,
};
#[cfg(unix)]
pub use mcp::{
    AuthenticatedPublishingMcpRetentionBackendV1, AuthenticatedRecoveredMcpRetentionBackendV1,
    DurablePublishingMcpRetentionBackendV2,
};
pub use mcp::{
    MCP_PROTOCOL_VERSION_V1, McpAliasExpansionV1, McpExpandedEventV1, McpRetentionBackendErrorV1,
    McpRetentionBackendV1, McpRetentionModeV1, MemoryOnlyMcpRetentionBackendV1, run_mcp_stdio_v1,
    run_mcp_stdio_with_backend_v1,
};

/// Maximum exact log bytes accepted by the V1 standard-input entry point.
pub const MAX_STDIN_BYTES_V1: usize = MAX_WIRE_OBJECT_BYTES;
/// Maximum source records accepted by one V1 standard-input invocation.
pub const MAX_STDIN_RECORDS_V1: usize = 100_000;
/// Maximum question bytes accepted by one V1 standard-input invocation.
pub const MAX_QUESTION_BYTES_V1: usize = 64 * 1024;
/// Default whole-render budget used by the command-line binary. V1 certifies
/// the conservative UTF-8-byte tokenizer, so one rendered byte is one budget
/// unit; this value is not advertised as an OpenAI/model token count.
pub const DEFAULT_TOKEN_BUDGET_V1: u64 = 20_000;

const IDENTITY_DOMAIN_V1: &[u8] = b"evidentrail/cli/explicit-stdin-identity/v1\0";
const PLAN_DOMAIN_V1: &[u8] = b"evidentrail/cli/explicit-stdin-plan/v1\0";
const SOURCE_DOMAIN_V1: &[u8] = b"evidentrail/cli/explicit-stdin-source/v1\0";
const STDIN_COMPLETENESS_CODE_V1: u16 = 1;
const IDENTITY_DOMAIN_V3: &[u8] = b"evidentrail/cli/explicit-stream-identity/v3\0";
const PLAN_DOMAIN_V3: &[u8] = b"evidentrail/cli/explicit-stream-plan/v3\0";
const SOURCE_DOMAIN_V3: &[u8] = b"evidentrail/cli/explicit-stream-source/v3\0";
const STDIN_COMPLETENESS_CODE_V3: u16 = 3;

/// Public V3 input limits. They are intentionally independent of the V1 wire
/// object cap so a `Read` implementation is never materialized as one object.
pub const MAX_STDIN_BYTES_V3: u64 = MAX_STREAM_SOURCE_BYTES_V3;
pub const MAX_STDIN_RECORDS_V3: u64 = MAX_STREAM_RECORDS_V3;

#[derive(Clone, Copy)]
struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

/// Whether the successful canonical artifact used passthrough or compilation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StdinBriefModeV1 {
    Passthrough,
    Compiled,
}

impl StdinBriefModeV1 {
    /// Stable public mode code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Passthrough => "passthrough",
            Self::Compiled => "compiled",
        }
    }
}

impl fmt::Debug for StdinBriefModeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StdinBriefModeV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Canonical successful output plus non-sensitive execution counts.
pub struct RenderedStdinBriefV1 {
    mode: StdinBriefModeV1,
    result_id: ResultId,
    expires_at: UnixTimestampNanos,
    text: String,
    source_record_count: u64,
    source_byte_count: u64,
    evidence_alias_count: u64,
}

impl RenderedStdinBriefV1 {
    #[must_use]
    pub const fn mode(&self) -> StdinBriefModeV1 {
        self.mode
    }

    #[must_use]
    pub const fn result_id(&self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn expires_at(&self) -> UnixTimestampNanos {
        self.expires_at
    }

    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub const fn source_record_count(&self) -> u64 {
        self.source_record_count
    }

    #[must_use]
    pub const fn source_byte_count(&self) -> u64 {
        self.source_byte_count
    }

    #[must_use]
    pub const fn evidence_alias_count(&self) -> u64 {
        self.evidence_alias_count
    }
}

impl fmt::Debug for RenderedStdinBriefV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedStdinBriefV1")
            .field("mode", &self.mode)
            .field("result_id_present", &true)
            .field("rendered_byte_count", &self.text.len())
            .field("source_record_count", &self.source_record_count)
            .field("source_byte_count", &self.source_byte_count)
            .field("evidence_alias_count", &self.evidence_alias_count)
            .field("fixed_expiry_present", &true)
            .finish()
    }
}

/// Honest bounded failure to construct a useful artifact at the supplied budget.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StdinBriefNeedsMoreV1 {
    result_id: ResultId,
    expires_at: UnixTimestampNanos,
    reason: ThreeLaneNeedsMoreV1,
    source_record_count: u64,
    source_byte_count: u64,
}

impl StdinBriefNeedsMoreV1 {
    #[must_use]
    pub const fn result_id(self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn reason(self) -> ThreeLaneNeedsMoreV1 {
        self.reason
    }

    #[must_use]
    pub const fn expires_at(self) -> UnixTimestampNanos {
        self.expires_at
    }

    #[must_use]
    pub const fn source_record_count(self) -> u64 {
        self.source_record_count
    }

    #[must_use]
    pub const fn source_byte_count(self) -> u64 {
        self.source_byte_count
    }
}

impl fmt::Debug for StdinBriefNeedsMoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StdinBriefNeedsMoreV1")
            .field("result_id_present", &true)
            .field("reason", &self.reason)
            .field("source_record_count", &self.source_record_count)
            .field("source_byte_count", &self.source_byte_count)
            .field("fixed_expiry_present", &true)
            .finish()
    }
}

/// Product decision returned by the explicit-standard-input entry point.
pub enum StdinBriefOutcomeV1 {
    Rendered(RenderedStdinBriefV1),
    NeedsMore(StdinBriefNeedsMoreV1),
}

impl StdinBriefOutcomeV1 {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Rendered(rendered) => rendered.mode.code(),
            Self::NeedsMore(_) => "needs_more",
        }
    }

    /// Result identity shared by rendered and honest `needs_more` outcomes.
    #[must_use]
    pub const fn result_id(&self) -> ResultId {
        match self {
            Self::Rendered(rendered) => rendered.result_id(),
            Self::NeedsMore(needs_more) => needs_more.result_id(),
        }
    }

    #[must_use]
    pub const fn expires_at(&self) -> UnixTimestampNanos {
        match self {
            Self::Rendered(rendered) => rendered.expires_at(),
            Self::NeedsMore(needs_more) => needs_more.expires_at(),
        }
    }
}

impl fmt::Debug for StdinBriefOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StdinBriefOutcomeV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Contentless failure from bounded input validation or product execution.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StdinBriefErrorV1 {
    EmptyInput,
    InputTooLarge,
    TooManyRecords,
    RecordTooLarge,
    EmptyQuestion,
    QuestionTooLarge,
    InvalidTokenBudget,
    IdentityConstruction,
    CountOverflow,
    LedgerConstruction,
    CompletionConstruction,
    ProductExecution,
}

impl StdinBriefErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyInput => "EVIDENTRAIL_CLI_EMPTY_INPUT",
            Self::InputTooLarge => "EVIDENTRAIL_CLI_INPUT_TOO_LARGE",
            Self::TooManyRecords => "EVIDENTRAIL_CLI_TOO_MANY_RECORDS",
            Self::RecordTooLarge => "EVIDENTRAIL_CLI_RECORD_TOO_LARGE",
            Self::EmptyQuestion => "EVIDENTRAIL_CLI_EMPTY_QUESTION",
            Self::QuestionTooLarge => "EVIDENTRAIL_CLI_QUESTION_TOO_LARGE",
            Self::InvalidTokenBudget => "EVIDENTRAIL_CLI_INVALID_TOKEN_BUDGET",
            Self::IdentityConstruction => "EVIDENTRAIL_CLI_IDENTITY_CONSTRUCTION_FAILURE",
            Self::CountOverflow => "EVIDENTRAIL_CLI_COUNT_OVERFLOW",
            Self::LedgerConstruction => "EVIDENTRAIL_CLI_LEDGER_CONSTRUCTION_FAILURE",
            Self::CompletionConstruction => "EVIDENTRAIL_CLI_COMPLETION_CONSTRUCTION_FAILURE",
            Self::ProductExecution => "EVIDENTRAIL_CLI_PRODUCT_EXECUTION_FAILURE",
        }
    }
}

impl fmt::Debug for StdinBriefErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StdinBriefErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for StdinBriefErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for StdinBriefErrorV1 {}

/// Contentless failure from the real V2 durable stdin path.
#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableStdinErrorV2 {
    Input(StdinBriefErrorV1),
    Durable(DurableProductErrorV2),
}

#[cfg(unix)]
impl DurableStdinErrorV2 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Input(error) => error.code(),
            Self::Durable(error) => error.code(),
        }
    }
}

#[cfg(unix)]
impl fmt::Debug for DurableStdinErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableStdinErrorV2")
            .field("code", &self.code())
            .finish()
    }
}

#[cfg(unix)]
impl fmt::Display for DurableStdinErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

#[cfg(unix)]
impl StdError for DurableStdinErrorV2 {}

/// One memory-resident explicit-input product session.
///
/// Keeping this value alive keeps the exact authorized events and the frozen
/// result-scoped alias manifest available for bounded expansion until the
/// result's fixed TTL expires. Dropping it destroys the only store copy. This
/// is a process-local service primitive, not persistence or a durable-ack
/// boundary.
pub struct StdinBriefSessionV1 {
    product: MemoryProductV1,
    outcome: StdinBriefOutcomeV1,
    created_at: UnixTimestampNanos,
    retention_state: StdinSessionRetentionStateV1,
}

enum FinalizedStdinArtifactV1 {
    Passthrough(Box<RenderedProductResultV1>),
    Compiled(Box<CompiledProductResultV1>),
}

enum StdinSessionRetentionStateV1 {
    Rendered(FinalizedStdinArtifactV1),
    NeedsMore,
    EncryptedAwaitingFilesystem,
    Published,
}

impl StdinSessionRetentionStateV1 {
    const fn code(&self) -> &'static str {
        match self {
            Self::Rendered(_) => "memory_only_rendered",
            Self::NeedsMore => "memory_only_needs_more",
            Self::EncryptedAwaitingFilesystem => "encrypted_awaiting_filesystem",
            Self::Published => "ciphertext_published",
        }
    }
}

/// Contentless failure from the opt-in authenticated ciphertext publication
/// bridge. The default CLI and MCP entry points never call this bridge.
#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatedStdinPublicationErrorV1 {
    NeedsMoreNotPublishable,
    AlreadyPublished,
    EncryptedRetentionFailed,
    ExpectedContextUnavailable,
    FilesystemPublicationFailed,
}

#[cfg(unix)]
impl AuthenticatedStdinPublicationErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NeedsMoreNotPublishable => {
                "EVIDENTRAIL_CLI_AUTHENTICATED_PUBLICATION_NEEDS_MORE_NOT_PUBLISHABLE"
            }
            Self::AlreadyPublished => "EVIDENTRAIL_CLI_AUTHENTICATED_PUBLICATION_ALREADY_PUBLISHED",
            Self::EncryptedRetentionFailed => {
                "EVIDENTRAIL_CLI_AUTHENTICATED_PUBLICATION_RETENTION_FAILED"
            }
            Self::ExpectedContextUnavailable => {
                "EVIDENTRAIL_CLI_AUTHENTICATED_PUBLICATION_CONTEXT_UNAVAILABLE"
            }
            Self::FilesystemPublicationFailed => {
                "EVIDENTRAIL_CLI_AUTHENTICATED_PUBLICATION_FILESYSTEM_FAILED"
            }
        }
    }
}

#[cfg(unix)]
impl fmt::Debug for AuthenticatedStdinPublicationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedStdinPublicationErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

#[cfg(unix)]
impl fmt::Display for AuthenticatedStdinPublicationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

#[cfg(unix)]
impl StdError for AuthenticatedStdinPublicationErrorV1 {}

/// Successful opt-in ciphertext publication and the exact authority context
/// that an independently configured restart backend must supply again.
///
/// This is not a durability, Keychain, provider-discovery, or rollback claim.
#[cfg(unix)]
#[derive(Clone, Copy)]
pub struct AuthenticatedStdinPublicationV1 {
    result_id: ResultId,
    expected_context: ExpectedCoreResultManifestContextV1,
    filesystem_publication: FilesystemBundlePublicationV1,
}

#[cfg(unix)]
impl AuthenticatedStdinPublicationV1 {
    #[must_use]
    pub const fn result_id(self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn expected_context(self) -> ExpectedCoreResultManifestContextV1 {
        self.expected_context
    }

    #[must_use]
    pub const fn filesystem_publication(self) -> FilesystemBundlePublicationV1 {
        self.filesystem_publication
    }
}

#[cfg(unix)]
impl fmt::Debug for AuthenticatedStdinPublicationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedStdinPublicationV1")
            .field("filesystem_publication", &self.filesystem_publication)
            .field("authority_context_present", &true)
            .finish_non_exhaustive()
    }
}

impl StdinBriefSessionV1 {
    /// Borrow the canonical initial decision without exposing retained log
    /// bytes through diagnostics or an auxiliary representation.
    #[must_use]
    pub const fn outcome(&self) -> &StdinBriefOutcomeV1 {
        &self.outcome
    }

    #[must_use]
    pub const fn expires_at(&self) -> UnixTimestampNanos {
        self.outcome.expires_at()
    }

    /// Exact execution instant used to construct this result's immutable
    /// lifetime. Authenticated publication uses this value rather than a
    /// later wall-clock observation or TTL subtraction.
    #[must_use]
    pub const fn created_at(&self) -> UnixTimestampNanos {
        self.created_at
    }

    /// Contentless hosted-ranking diagnostics, when this retained session used
    /// the explicitly assisted compiled path.
    #[must_use]
    pub fn hosted_ranking_diagnostics(&self) -> Option<&HostedRankingDiagnosticsV1> {
        match &self.retention_state {
            StdinSessionRetentionStateV1::Rendered(FinalizedStdinArtifactV1::Compiled(
                compiled,
            )) => compiled.hosted_ranking_diagnostics(),
            StdinSessionRetentionStateV1::Rendered(FinalizedStdinArtifactV1::Passthrough(_))
            | StdinSessionRetentionStateV1::NeedsMore
            | StdinSessionRetentionStateV1::EncryptedAwaitingFilesystem
            | StdinSessionRetentionStateV1::Published => None,
        }
    }

    /// Read-only proposal audit for benchmark integrity checks. It exposes
    /// packet identities and receipts, never retained source bytes.
    #[must_use]
    pub fn proposal_audit(&self) -> Option<&evidentrail_product::ThreeLaneProposalAuditV1> {
        match &self.retention_state {
            StdinSessionRetentionStateV1::Rendered(FinalizedStdinArtifactV1::Compiled(
                compiled,
            )) => compiled.proposal_audit(),
            StdinSessionRetentionStateV1::Rendered(FinalizedStdinArtifactV1::Passthrough(_))
            | StdinSessionRetentionStateV1::NeedsMore
            | StdinSessionRetentionStateV1::EncryptedAwaitingFilesystem
            | StdinSessionRetentionStateV1::Published => None,
        }
    }

    /// Expand a published short evidence alias inside this session's retained
    /// product. The request remains explicitly result-scoped and bounded by
    /// the store contract.
    pub fn expand_alias(
        &self,
        request: AliasExpansionRequestV1,
        now: UnixTimestampNanos,
    ) -> Result<ExpansionResponseV1, ResultStoreError> {
        self.product.expand_alias(request, now)
    }

    /// Opt in to authenticated encrypted retention and ciphertext filesystem
    /// publication for one already-rendered result.
    ///
    /// On successful encrypted migration the product ledger and finalized
    /// structured artifact owner are released before filesystem publication.
    /// The already-returned display text in [`StdinBriefOutcomeV1`] remains
    /// caller-owned in this session until the caller drops or consumes it; this
    /// method does not pretend to erase that display. If the filesystem step
    /// fails, the injected `retention` still owns the sealed ciphertext and
    /// this method may be retried; source bytes are never reacquired.
    /// `needs_more` has no alias manifest and is never publishable.
    #[cfg(unix)]
    pub fn publish_authenticated_restart_v1<P, R>(
        &mut self,
        retention: &mut AuthenticatedEncryptedRetentionV1<P>,
        key_context: &CreatingKeyContextV1,
        coordinator: &AuthenticatedFilesystemRestartCoordinatorV1<R>,
        now: UnixTimestampNanos,
    ) -> Result<AuthenticatedStdinPublicationV1, AuthenticatedStdinPublicationErrorV1>
    where
        P: KeyProviderV1,
        R: KeyProviderV1 + ?Sized,
    {
        let result_id = self.outcome.result_id();
        match &self.retention_state {
            StdinSessionRetentionStateV1::Rendered(finalized) => {
                let migration = match finalized {
                    FinalizedStdinArtifactV1::Passthrough(rendered) => {
                        self.product.migrate_passthrough_to_authenticated_retention(
                            retention,
                            key_context,
                            rendered,
                            now,
                        )
                    }
                    FinalizedStdinArtifactV1::Compiled(rendered) => {
                        self.product.migrate_compiled_to_authenticated_retention(
                            retention,
                            key_context,
                            rendered,
                            now,
                        )
                    }
                };
                migration
                    .map_err(|_| AuthenticatedStdinPublicationErrorV1::EncryptedRetentionFailed)?;
                self.retention_state = StdinSessionRetentionStateV1::EncryptedAwaitingFilesystem;
            }
            StdinSessionRetentionStateV1::NeedsMore => {
                return Err(AuthenticatedStdinPublicationErrorV1::NeedsMoreNotPublishable);
            }
            StdinSessionRetentionStateV1::EncryptedAwaitingFilesystem => {}
            StdinSessionRetentionStateV1::Published => {
                return Err(AuthenticatedStdinPublicationErrorV1::AlreadyPublished);
            }
        }

        let expected_context = retention
            .expected_restart_context(result_id)
            .map_err(|_| AuthenticatedStdinPublicationErrorV1::ExpectedContextUnavailable)?;
        let filesystem_publication = retention
            .publish_restart_bundle(coordinator, result_id, now)
            .map_err(|_| AuthenticatedStdinPublicationErrorV1::FilesystemPublicationFailed)?;
        self.retention_state = StdinSessionRetentionStateV1::Published;
        Ok(AuthenticatedStdinPublicationV1 {
            result_id,
            expected_context,
            filesystem_publication,
        })
    }

    /// Consume the session and intentionally discard all retained expansion
    /// state, preserving the historical one-shot API behavior.
    #[must_use]
    pub fn into_outcome(self) -> StdinBriefOutcomeV1 {
        self.outcome
    }
}

impl fmt::Debug for StdinBriefSessionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StdinBriefSessionV1")
            .field("outcome", &self.outcome)
            .field("backend", &"memory_only")
            .field("durable", &false)
            .field("retention_state", &self.retention_state.code())
            .finish()
    }
}

/// Contentless failure from the V3 incremental reader and shared compiler.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StdinBriefErrorV3 {
    Input(StdinBriefErrorV1),
    ReadFailure,
    Store(RetainedEventStoreErrorV3),
    Product,
}

impl StdinBriefErrorV3 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Input(error) => error.code(),
            Self::ReadFailure => "EVIDENTRAIL_CLI_STDIN_READ_FAILURE",
            Self::Store(error) => error.code(),
            Self::Product => "EVIDENTRAIL_CLI_PRODUCT_V3_EXECUTION_FAILURE",
        }
    }
}

impl fmt::Debug for StdinBriefErrorV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StdinBriefErrorV3")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for StdinBriefErrorV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for StdinBriefErrorV3 {}

/// Retained V3 session. The backend remains the sole expansion owner after
/// compilation; a `needs_more` outcome has already destroyed it.
pub struct StdinBriefSessionV3<B> {
    product: StreamingProductV3<B>,
    outcome: StdinBriefOutcomeV1,
}

impl<B: RetainedEventStoreV3> StdinBriefSessionV3<B> {
    #[must_use]
    pub const fn outcome(&self) -> &StdinBriefOutcomeV1 {
        &self.outcome
    }

    #[must_use]
    pub const fn product(&self) -> &StreamingProductV3<B> {
        &self.product
    }

    #[must_use]
    pub fn into_outcome(self) -> StdinBriefOutcomeV1 {
        self.outcome
    }

    #[must_use]
    pub fn into_parts(self) -> (StdinBriefOutcomeV1, B) {
        (self.outcome, self.product.into_backend())
    }
}

impl<B> fmt::Debug for StdinBriefSessionV3<B> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StdinBriefSessionV3")
            .field("outcome", &self.outcome)
            .field("backend", &"retained_event_store_v3")
            .finish_non_exhaustive()
    }
}

/// Incrementally compile one explicit byte stream through V3.
///
/// Reader chunking is not semantic: identities, records, the authenticated
/// acquisition manifest, partitions, and output depend only on the exact byte
/// stream and explicit configuration. CRLF, invalid UTF-8, NUL, blank records,
/// and an unterminated final record are retained byte-for-byte.
pub fn compile_explicit_stream_v3<R: Read, B: RetainedEventStoreV3>(
    reader: R,
    question: &[u8],
    token_budget: u64,
    identity_seed: [u8; 32],
    now: UnixTimestampNanos,
    backend: B,
) -> Result<StdinBriefSessionV3<B>, StdinBriefErrorV3> {
    compile_explicit_stream_internal_v3(
        reader,
        question,
        token_budget,
        identity_seed,
        now,
        backend,
        false,
    )
}

/// Runs the same V3 path with contentless engineering instrumentation enabled.
/// The resulting numeric receipt is profiling evidence, not certification.
pub fn compile_explicit_stream_profiled_v3<R: Read, B: RetainedEventStoreV3>(
    reader: R,
    question: &[u8],
    token_budget: u64,
    identity_seed: [u8; 32],
    now: UnixTimestampNanos,
    backend: B,
) -> Result<StdinBriefSessionV3<B>, StdinBriefErrorV3> {
    compile_explicit_stream_internal_v3(
        reader,
        question,
        token_budget,
        identity_seed,
        now,
        backend,
        true,
    )
}

fn compile_explicit_stream_internal_v3<R: Read, B: RetainedEventStoreV3>(
    mut reader: R,
    question: &[u8],
    token_budget: u64,
    identity_seed: [u8; 32],
    now: UnixTimestampNanos,
    backend: B,
    profile: bool,
) -> Result<StdinBriefSessionV3<B>, StdinBriefErrorV3> {
    validate_explicit_configuration_v3(question, token_budget).map_err(StdinBriefErrorV3::Input)?;
    let budget_bytes = token_budget.to_be_bytes();
    let question_digest = digest_parts_v3(b"question", &[question]);
    let build_context = streaming_product_build_context_v3();
    let namespace = digest_parts_v3(
        b"namespace",
        &[
            &identity_seed,
            &question_digest,
            &budget_bytes,
            &build_context,
        ],
    );
    let result_id = ResultId::from_bytes(digest_parts_v3(b"result-id", &[&namespace]));
    let retrieval_id = RetrievalId::from_bytes(digest_parts_v3(b"retrieval-id", &[&namespace]));
    let plan_id = PlanId::from_bytes(digest_parts_v3(b"plan-id", &[&namespace, &question_digest]));
    let plan_digest = PlanDigest::from_bytes(digest_parts_v3(
        PLAN_DOMAIN_V3,
        &[&question_digest, &budget_bytes, &build_context],
    ));
    let source_identity_digest = SourceIdentityDigest::from_bytes(digest_parts_v3(
        SOURCE_DOMAIN_V3,
        &[&identity_seed, &namespace],
    ));
    let adapter = AdapterIdentity::new("evidentrail-cli-explicit-stdin", "v3")
        .map_err(|_| StdinBriefErrorV3::Input(StdinBriefErrorV1::IdentityConstruction))?;
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let lane = LaneKey::new(
        SourceMember::new(b"explicit-stdin".to_vec())
            .map_err(|_| StdinBriefErrorV3::Input(StdinBriefErrorV1::IdentityConstruction))?,
        SourceStream::OtherVersioned {
            version: 3,
            code: 1,
        },
    );
    let expires_at = now
        .get()
        .checked_add(evidentrail_store::DEFAULT_RESULT_TTL_NANOS)
        .ok_or(StdinBriefErrorV3::Input(StdinBriefErrorV1::CountOverflow))?;
    let mut product = StreamingProductV3::new(backend);
    if profile {
        product.enable_performance_instrumentation();
    }
    product
        .backend_mut()
        .begin(RetainedStoreBeginV3 {
            result_id,
            namespace,
            created_unix_nanos: now.get(),
            expires_unix_nanos: expires_at,
        })
        .map_err(StdinBriefErrorV3::Store)?;

    let mut stream = StreamCountersV3::default();
    let mut input_hasher = Sha256::new();
    input_hasher.update(IDENTITY_DOMAIN_V3);
    input_hasher.update(b"input");
    let acquisition = read_exact_records_v3(&mut reader, &mut input_hasher, |record| {
        accept_stream_record_v3(
            product.backend_mut(),
            &envelope_identity,
            &lane,
            &mut stream,
            record,
        )
    });
    if let Err(error) = acquisition {
        let _ = product.backend_mut().destroy_authority_first();
        return Err(error);
    }
    if stream.record_count == 0 {
        let _ = product.backend_mut().destroy_authority_first();
        return Err(StdinBriefErrorV3::Input(StdinBriefErrorV1::EmptyInput));
    }
    let input_digest: [u8; 32] = input_hasher.finalize().into();
    let completion = FetchCompletion::new(
        fetch_identity.clone(),
        FetchTiming::new(now, now),
        AcknowledgedCounts::new(
            stream.record_count,
            stream.payload_byte_count,
            stream.source_byte_count,
        ),
        AttemptCounts::new(1, 1),
        AttemptCounts::default(),
        FetchBoundaries::default(),
        [],
        AdapterOutcome::Finished,
        [],
        FetchCompleteness::complete(CompletenessProof::OtherVersioned {
            version: 3,
            code: STDIN_COMPLETENESS_CODE_V3,
        }),
    )
    .map_err(|_| StdinBriefErrorV3::Input(StdinBriefErrorV1::CompletionConstruction))?;
    let completion_digest = digest_parts_v3(
        b"completion",
        &[
            &stream.record_count.to_be_bytes(),
            &stream.payload_byte_count.to_be_bytes(),
            &stream.source_byte_count.to_be_bytes(),
            &input_digest,
        ],
    );
    let manifest = match product
        .backend_mut()
        .finish_acquisition(RetainedAcquisitionFinishV3 {
            record_count: stream.record_count,
            payload_byte_count: stream.payload_byte_count,
            source_byte_count: stream.source_byte_count,
            input_digest,
            completion_digest,
        }) {
        Ok(manifest) => manifest,
        Err(error) => {
            let _ = product.backend_mut().destroy_authority_first();
            return Err(StdinBriefErrorV3::Store(error));
        }
    };
    let analysis_context = StreamingAnalysisContextV3::new(
        fetch_identity,
        envelope_identity,
        source_identity_digest,
        lane,
        completion,
    );
    let decision = match product.compile_store(
        result_id,
        question,
        &analysis_context,
        manifest,
        now,
        token_budget,
    ) {
        Ok(decision) => decision,
        Err(_) => {
            let _ = product.backend_mut().destroy_authority_first();
            return Err(StdinBriefErrorV3::Product);
        }
    };
    let (outcome, _) = retained_outcome_v1(
        decision,
        result_id,
        stream.record_count,
        stream.source_byte_count,
    )
    .map_err(StdinBriefErrorV3::Input)?;
    Ok(StdinBriefSessionV3 { product, outcome })
}

#[derive(Default)]
struct StreamCountersV3 {
    record_count: u64,
    payload_byte_count: u64,
    source_byte_count: u64,
}

fn validate_explicit_configuration_v3(
    question: &[u8],
    token_budget: u64,
) -> Result<(), StdinBriefErrorV1> {
    if question.is_empty() {
        return Err(StdinBriefErrorV1::EmptyQuestion);
    }
    if question.len() > MAX_QUESTION_BYTES_V1 {
        return Err(StdinBriefErrorV1::QuestionTooLarge);
    }
    if token_budget == 0 || token_budget > JSON_SAFE_INTEGER_MAX {
        return Err(StdinBriefErrorV1::InvalidTokenBudget);
    }
    Ok(())
}

fn read_exact_records_v3(
    reader: &mut impl Read,
    input_hasher: &mut Sha256,
    mut accept: impl FnMut(RecordBytes) -> Result<(), StdinBriefErrorV3>,
) -> Result<(), StdinBriefErrorV3> {
    let mut chunk = [0u8; 64 * 1024];
    let mut pending = Vec::new();
    let mut total = 0u64;
    loop {
        let read = reader
            .read(&mut chunk)
            .map_err(|_| StdinBriefErrorV3::ReadFailure)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(StdinBriefErrorV3::Input(StdinBriefErrorV1::CountOverflow))?;
        if total > MAX_STDIN_BYTES_V3 {
            return Err(StdinBriefErrorV3::Input(StdinBriefErrorV1::InputTooLarge));
        }
        input_hasher.update(&chunk[..read]);
        let mut start = 0usize;
        for newline in (0..read).filter(|position| chunk[*position] == b'\n') {
            pending.extend_from_slice(&chunk[start..=newline]);
            if pending.len() > MAX_AUTHORIZED_RECORD_BYTES {
                return Err(StdinBriefErrorV3::Input(StdinBriefErrorV1::RecordTooLarge));
            }
            let terminator_start = if pending.len() >= 2 && pending[pending.len() - 2] == b'\r' {
                pending.len() - 2
            } else {
                pending.len() - 1
            };
            let terminator = pending.split_off(terminator_start);
            accept(RecordBytes::framed(
                std::mem::take(&mut pending),
                terminator,
            ))?;
            start = newline + 1;
        }
        pending.extend_from_slice(&chunk[start..read]);
        if pending.len() > MAX_AUTHORIZED_RECORD_BYTES {
            return Err(StdinBriefErrorV3::Input(StdinBriefErrorV1::RecordTooLarge));
        }
    }
    if !pending.is_empty() {
        accept(RecordBytes::whole(pending))?;
    }
    Ok(())
}

fn accept_stream_record_v3<B: RetainedEventStoreV3>(
    backend: &mut B,
    identity: &RawEnvelopeIdentityV1,
    lane: &LaneKey,
    counters: &mut StreamCountersV3,
    record: RecordBytes,
) -> Result<(), StdinBriefErrorV3> {
    if counters.record_count >= MAX_STDIN_RECORDS_V3 {
        return Err(StdinBriefErrorV3::Input(StdinBriefErrorV1::TooManyRecords));
    }
    let sequence = counters.record_count;
    let payload_len = record.payload_len();
    let terminator_len = record.terminator().map_or(0, <[u8]>::len);
    let exact = record.exact_bytes();
    let envelope = RawEnvelopeV1::new(
        identity.clone(),
        EnvelopeOrdering::new(
            AcquisitionSequence::new(sequence),
            lane.clone(),
            LaneSequence::new(sequence),
        ),
        record,
        RecordState::Complete,
    );
    let event_id = derive_source_exact_event_id_v1(&envelope);
    backend
        .append(RetainedEventInputV3 {
            event_id,
            acquisition_ordinal: sequence,
            lane_ordinal: 0,
            lane_sequence: sequence,
            payload_len: u32::try_from(payload_len)
                .map_err(|_| StdinBriefErrorV3::Input(StdinBriefErrorV1::RecordTooLarge))?,
            terminator_len: u8::try_from(terminator_len)
                .map_err(|_| StdinBriefErrorV3::Input(StdinBriefErrorV1::RecordTooLarge))?,
            exact_bytes: &exact,
        })
        .map_err(StdinBriefErrorV3::Store)?;
    counters.record_count = counters
        .record_count
        .checked_add(1)
        .ok_or(StdinBriefErrorV3::Input(StdinBriefErrorV1::CountOverflow))?;
    counters.payload_byte_count = counters
        .payload_byte_count
        .checked_add(payload_len as u64)
        .ok_or(StdinBriefErrorV3::Input(StdinBriefErrorV1::CountOverflow))?;
    counters.source_byte_count = counters
        .source_byte_count
        .checked_add(exact.len() as u64)
        .ok_or(StdinBriefErrorV3::Input(StdinBriefErrorV1::CountOverflow))?;
    Ok(())
}

fn digest_parts_v3(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(IDENTITY_DOMAIN_V3);
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Compile exact, explicitly supplied standard-input bytes into one Log Brief.
///
/// `identity_seed` must be fresh cryptographic randomness in production. It is
/// an explicit argument so tests and benchmark adapters can reproduce an exact
/// artifact without replacing the production randomness contract in schema.
pub fn compile_explicit_stdin_v1(
    input: &[u8],
    question: &[u8],
    token_budget: u64,
    identity_seed: [u8; 32],
    now: UnixTimestampNanos,
) -> Result<StdinBriefOutcomeV1, StdinBriefErrorV1> {
    compile_explicit_stdin_retained_v1(input, question, token_budget, identity_seed, now)
        .map(StdinBriefSessionV1::into_outcome)
}

/// Compile explicit input while retaining the exact memory-only result for
/// result-scoped expansion in a resident CLI/MCP service.
///
/// This follows the identical acquisition, policy, compiler, renderer, and
/// budget path as [`compile_explicit_stdin_v1`]. The only difference is
/// ownership: the returned session keeps the memory product alive.
pub fn compile_explicit_stdin_retained_v1(
    input: &[u8],
    question: &[u8],
    token_budget: u64,
    identity_seed: [u8; 32],
    now: UnixTimestampNanos,
) -> Result<StdinBriefSessionV1, StdinBriefErrorV1> {
    compile_memory_session_v1(
        input,
        question,
        token_budget,
        identity_seed,
        now,
        |product, result_id, ledger| {
            product.create_deterministic_result_v1(result_id, question, ledger, now, token_budget)
        },
    )
}

fn compile_memory_session_v1(
    input: &[u8],
    question: &[u8],
    token_budget: u64,
    identity_seed: [u8; 32],
    now: UnixTimestampNanos,
    compile: impl FnOnce(
        &mut MemoryProductV1,
        ResultId,
        EventLedger,
    ) -> Result<DeterministicProductDecisionV1, ProductError>,
) -> Result<StdinBriefSessionV1, StdinBriefErrorV1> {
    let PreparedExplicitStdinV1 {
        result_id,
        ledger,
        record_count,
        source_byte_count,
    } = prepare_explicit_stdin_v1(input, question, token_budget, identity_seed, now)?;
    let mut product = MemoryProductV1::new();
    let decision = compile(&mut product, result_id, ledger)
        .map_err(|_| StdinBriefErrorV1::ProductExecution)?;
    let (outcome, retention_state) =
        retained_outcome_v1(decision, result_id, record_count, source_byte_count)?;
    Ok(StdinBriefSessionV1 {
        product,
        outcome,
        created_at: now,
        retention_state,
    })
}

/// Retained-session form of explicit input with one optional hosted-ranking
/// attempt after the deterministic passthrough and `needs_more` gates.
pub fn compile_explicit_stdin_retained_with_ranker_v1<R: EvidenceRankerV1>(
    input: &[u8],
    question: &[u8],
    token_budget: u64,
    identity_seed: [u8; 32],
    now: UnixTimestampNanos,
    ranker: &mut R,
) -> Result<StdinBriefSessionV1, StdinBriefErrorV1> {
    compile_memory_session_v1(
        input,
        question,
        token_budget,
        identity_seed,
        now,
        |product, result_id, ledger| {
            product.create_hosted_ranked_result_v1(
                result_id,
                question,
                ledger,
                now,
                token_budget,
                ranker,
            )
        },
    )
}

/// Retained-session hosted ranking that contacts the ranker only when the
/// deterministic budget excludes a model-visible optional candidate.
pub fn compile_explicit_stdin_retained_with_contended_ranker_v1<R: EvidenceRankerV1>(
    input: &[u8],
    question: &[u8],
    token_budget: u64,
    identity_seed: [u8; 32],
    now: UnixTimestampNanos,
    ranker: &mut R,
) -> Result<StdinBriefSessionV1, StdinBriefErrorV1> {
    compile_memory_session_v1(
        input,
        question,
        token_budget,
        identity_seed,
        now,
        |product, result_id, ledger| {
            product.create_contended_hosted_ranked_result_v1(
                result_id,
                question,
                ledger,
                now,
                token_budget,
                ranker,
            )
        },
    )
}

/// Retained internal-shadow form of hosted ranking. It performs the same one
/// eligible call and validation but always publishes deterministic selection.
pub fn compile_explicit_stdin_retained_with_shadow_ranker_v1<R: EvidenceRankerV1>(
    input: &[u8],
    question: &[u8],
    token_budget: u64,
    identity_seed: [u8; 32],
    now: UnixTimestampNanos,
    ranker: &mut R,
) -> Result<StdinBriefSessionV1, StdinBriefErrorV1> {
    compile_memory_session_v1(
        input,
        question,
        token_budget,
        identity_seed,
        now,
        |product, result_id, ledger| {
            product.create_shadow_ranked_result_v1(
                result_id,
                question,
                ledger,
                now,
                token_budget,
                ranker,
            )
        },
    )
}

/// Internal-shadow form of contention-gated hosted ranking.
pub fn compile_explicit_stdin_retained_with_contended_shadow_ranker_v1<R: EvidenceRankerV1>(
    input: &[u8],
    question: &[u8],
    token_budget: u64,
    identity_seed: [u8; 32],
    now: UnixTimestampNanos,
    ranker: &mut R,
) -> Result<StdinBriefSessionV1, StdinBriefErrorV1> {
    compile_memory_session_v1(
        input,
        question,
        token_budget,
        identity_seed,
        now,
        |product, result_id, ledger| {
            product.create_contended_shadow_ranked_result_v1(
                result_id,
                question,
                ledger,
                now,
                token_budget,
                ranker,
            )
        },
    )
}

/// Benchmark-only retained evaluation of one ranking consumer. This is not a
/// CLI or MCP product surface and must be used only with explicitly authorized
/// synthetic inputs.
#[allow(clippy::too_many_arguments)]
pub fn compile_explicit_stdin_retained_with_evaluation_ranker_v1<R: EvidenceRankerV1>(
    input: &[u8],
    question: &[u8],
    token_budget: u64,
    identity_seed: [u8; 32],
    now: UnixTimestampNanos,
    ranker: &mut R,
    consumer: RankingConsumerV1,
) -> Result<StdinBriefSessionV1, StdinBriefErrorV1> {
    compile_memory_session_v1(
        input,
        question,
        token_budget,
        identity_seed,
        now,
        |product, result_id, ledger| {
            product.create_evaluation_ranked_result_v1(
                result_id,
                question,
                ledger,
                now,
                token_budget,
                ranker,
                consumer,
            )
        },
    )
}

/// Benchmark-only shadow evaluation for an explicitly selected consumer.
#[allow(clippy::too_many_arguments)]
pub fn compile_explicit_stdin_retained_with_shadow_consumer_v1<R: EvidenceRankerV1>(
    input: &[u8],
    question: &[u8],
    token_budget: u64,
    identity_seed: [u8; 32],
    now: UnixTimestampNanos,
    ranker: &mut R,
    consumer: RankingConsumerV1,
) -> Result<StdinBriefSessionV1, StdinBriefErrorV1> {
    compile_memory_session_v1(
        input,
        question,
        token_budget,
        identity_seed,
        now,
        |product, result_id, ledger| {
            product.create_shadow_ranked_result_for_consumer_v1(
                result_id,
                question,
                ledger,
                now,
                token_budget,
                ranker,
                consumer,
            )
        },
    )
}

/// Compile through the same deterministic product path as memory mode, but
/// return the public outcome only after the injected V2 repository has
/// durably advanced and reread matching `PUBLISHED` authority.
#[cfg(unix)]
pub fn compile_explicit_stdin_durable_v2<A: KeyAuthorityV2>(
    product: &mut DurableProductV2<A>,
    input: &[u8],
    question: &[u8],
    token_budget: u64,
    identity_seed: [u8; 32],
    now: UnixTimestampNanos,
) -> Result<StdinBriefOutcomeV1, DurableStdinErrorV2> {
    let PreparedExplicitStdinV1 {
        result_id,
        ledger,
        record_count,
        source_byte_count,
    } = prepare_explicit_stdin_v1(input, question, token_budget, identity_seed, now)
        .map_err(DurableStdinErrorV2::Input)?;
    let decision = product
        .create_deterministic_result_v2(result_id, question, ledger, now, token_budget)
        .map_err(DurableStdinErrorV2::Durable)?;
    retained_outcome_v1(decision, result_id, record_count, source_byte_count)
        .map(|(outcome, _)| outcome)
        .map_err(DurableStdinErrorV2::Input)
}

struct PreparedExplicitStdinV1 {
    result_id: ResultId,
    ledger: evidentrail_core::EventLedger,
    record_count: u64,
    source_byte_count: u64,
}

fn prepare_explicit_stdin_v1(
    input: &[u8],
    question: &[u8],
    token_budget: u64,
    identity_seed: [u8; 32],
    now: UnixTimestampNanos,
) -> Result<PreparedExplicitStdinV1, StdinBriefErrorV1> {
    if input.is_empty() {
        return Err(StdinBriefErrorV1::EmptyInput);
    }
    if input.len() > MAX_STDIN_BYTES_V1 {
        return Err(StdinBriefErrorV1::InputTooLarge);
    }
    if question.is_empty() {
        return Err(StdinBriefErrorV1::EmptyQuestion);
    }
    if question.len() > MAX_QUESTION_BYTES_V1 {
        return Err(StdinBriefErrorV1::QuestionTooLarge);
    }
    if token_budget == 0 || token_budget > JSON_SAFE_INTEGER_MAX {
        return Err(StdinBriefErrorV1::InvalidTokenBudget);
    }

    let records = split_exact_records_v1(input)?;
    let record_count =
        u64::try_from(records.len()).map_err(|_| StdinBriefErrorV1::CountOverflow)?;
    let source_byte_count =
        u64::try_from(input.len()).map_err(|_| StdinBriefErrorV1::CountOverflow)?;
    let payload_byte_count = records.iter().try_fold(0_u64, |total, record| {
        let payload =
            u64::try_from(record.payload_len()).map_err(|_| StdinBriefErrorV1::CountOverflow)?;
        total
            .checked_add(payload)
            .ok_or(StdinBriefErrorV1::CountOverflow)
    })?;

    let input_digest = digest_parts_v1(b"input", &[input]);
    let question_digest = digest_parts_v1(b"question", &[question]);
    let budget_bytes = token_budget.to_be_bytes();
    let retrieval_id = RetrievalId::from_bytes(digest_parts_v1(
        b"retrieval-id",
        &[&identity_seed, &input_digest],
    ));
    let plan_id = PlanId::from_bytes(digest_parts_v1(
        b"plan-id",
        &[&identity_seed, &question_digest],
    ));
    let plan_digest = PlanDigest::from_bytes(digest_parts_v1(
        PLAN_DOMAIN_V1,
        &[&input_digest, &question_digest, &budget_bytes],
    ));
    let source_identity_digest = SourceIdentityDigest::from_bytes(digest_parts_v1(
        SOURCE_DOMAIN_V1,
        &[&identity_seed, &input_digest],
    ));
    let result_id = ResultId::from_bytes(digest_parts_v1(
        b"result-id",
        &[&identity_seed, &plan_digest.as_bytes()[..]],
    ));
    let adapter = AdapterIdentity::new("evidentrail-cli-explicit-stdin", "v1")
        .map_err(|_| StdinBriefErrorV1::IdentityConstruction)?;
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity = RawEnvelopeIdentityV1::new(
        retrieval_id,
        plan_id,
        plan_digest,
        adapter,
        source_identity_digest,
    );
    let lane = LaneKey::new(
        SourceMember::new(b"explicit-stdin".to_vec())
            .map_err(|_| StdinBriefErrorV1::IdentityConstruction)?,
        SourceStream::OtherVersioned {
            version: 1,
            code: 1,
        },
    );
    let mut builder = LedgerBuilder::new(
        fetch_identity.clone(),
        source_identity_digest,
        SourceExactPolicy,
    );
    for (position, record) in records.into_iter().enumerate() {
        let sequence = u64::try_from(position).map_err(|_| StdinBriefErrorV1::CountOverflow)?;
        builder
            .accept(RawEnvelopeV1::new(
                envelope_identity.clone(),
                EnvelopeOrdering::new(
                    AcquisitionSequence::new(sequence),
                    lane.clone(),
                    LaneSequence::new(sequence),
                ),
                record,
                RecordState::Complete,
            ))
            .map_err(|_| StdinBriefErrorV1::LedgerConstruction)?;
    }
    let completion = FetchCompletion::new(
        fetch_identity,
        FetchTiming::new(now, now),
        AcknowledgedCounts::new(record_count, payload_byte_count, source_byte_count),
        AttemptCounts::new(1, 1),
        AttemptCounts::default(),
        FetchBoundaries::default(),
        [],
        AdapterOutcome::Finished,
        [],
        FetchCompleteness::complete(CompletenessProof::OtherVersioned {
            version: 1,
            code: STDIN_COMPLETENESS_CODE_V1,
        }),
    )
    .map_err(|_| StdinBriefErrorV1::CompletionConstruction)?;
    let ledger = builder
        .seal(completion)
        .map_err(|_| StdinBriefErrorV1::LedgerConstruction)?;
    Ok(PreparedExplicitStdinV1 {
        result_id,
        ledger,
        record_count,
        source_byte_count,
    })
}

fn retained_outcome_v1(
    decision: DeterministicProductDecisionV1,
    result_id: ResultId,
    record_count: u64,
    source_byte_count: u64,
) -> Result<(StdinBriefOutcomeV1, StdinSessionRetentionStateV1), StdinBriefErrorV1> {
    Ok(match decision {
        DeterministicProductDecisionV1::Passthrough(rendered) => {
            let expires_at = rendered.expires_at();
            let evidence_alias_count = u64::try_from(rendered.references().count())
                .map_err(|_| StdinBriefErrorV1::CountOverflow)?;
            (
                StdinBriefOutcomeV1::Rendered(RenderedStdinBriefV1 {
                    mode: StdinBriefModeV1::Passthrough,
                    result_id,
                    expires_at,
                    text: rendered.artifact().text().to_owned(),
                    source_record_count: record_count,
                    source_byte_count,
                    evidence_alias_count,
                }),
                StdinSessionRetentionStateV1::Rendered(FinalizedStdinArtifactV1::Passthrough(
                    rendered,
                )),
            )
        }
        DeterministicProductDecisionV1::Compiled(rendered) => {
            let expires_at = rendered.expires_at();
            let evidence_alias_count = u64::try_from(rendered.references().count())
                .map_err(|_| StdinBriefErrorV1::CountOverflow)?;
            (
                StdinBriefOutcomeV1::Rendered(RenderedStdinBriefV1 {
                    mode: StdinBriefModeV1::Compiled,
                    result_id,
                    expires_at,
                    text: rendered.artifact().text().to_owned(),
                    source_record_count: record_count,
                    source_byte_count,
                    evidence_alias_count,
                }),
                StdinSessionRetentionStateV1::Rendered(FinalizedStdinArtifactV1::Compiled(
                    rendered,
                )),
            )
        }
        DeterministicProductDecisionV1::NeedsMore(needs_more) => (
            StdinBriefOutcomeV1::NeedsMore(StdinBriefNeedsMoreV1 {
                result_id,
                expires_at: needs_more.expires_at(),
                reason: needs_more.compiler_reason(),
                source_record_count: record_count,
                source_byte_count,
            }),
            StdinSessionRetentionStateV1::NeedsMore,
        ),
    })
}

fn split_exact_records_v1(input: &[u8]) -> Result<Vec<RecordBytes>, StdinBriefErrorV1> {
    let mut records = Vec::new();
    let mut start = 0_usize;
    for (newline, _) in input.iter().enumerate().filter(|(_, byte)| **byte == b'\n') {
        let terminator_start = if newline > start && input[newline - 1] == b'\r' {
            newline - 1
        } else {
            newline
        };
        push_record_v1(
            &mut records,
            RecordBytes::framed(
                input[start..terminator_start].to_vec(),
                input[terminator_start..=newline].to_vec(),
            ),
        )?;
        start = newline
            .checked_add(1)
            .ok_or(StdinBriefErrorV1::CountOverflow)?;
    }
    if start < input.len() {
        push_record_v1(&mut records, RecordBytes::whole(input[start..].to_vec()))?;
    }
    if records.is_empty() {
        return Err(StdinBriefErrorV1::EmptyInput);
    }
    Ok(records)
}

fn push_record_v1(
    records: &mut Vec<RecordBytes>,
    record: RecordBytes,
) -> Result<(), StdinBriefErrorV1> {
    if record.source_len() > MAX_AUTHORIZED_RECORD_BYTES {
        return Err(StdinBriefErrorV1::RecordTooLarge);
    }
    if records.len() >= MAX_STDIN_RECORDS_V1 {
        return Err(StdinBriefErrorV1::TooManyRecords);
    }
    records.push(record);
    Ok(())
}

fn digest_parts_v1(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(IDENTITY_DOMAIN_V1);
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use evidentrail_core::ExpansionRelationV1;
    use evidentrail_store::{
        AliasExpansionRequestV1, DEFAULT_RESULT_TTL_NANOS, EvidenceAliasV1, ExpansionLimitV1,
        PackedMemoryEventStoreV3, RetainedEventStoreStateV3,
    };

    struct ChunkedReader<'a> {
        bytes: &'a [u8],
        position: usize,
        chunk: usize,
    }

    impl Read for ChunkedReader<'_> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if self.position == self.bytes.len() {
                return Ok(0);
            }
            let count = self
                .chunk
                .min(output.len())
                .min(self.bytes.len() - self.position);
            output[..count].copy_from_slice(&self.bytes[self.position..self.position + count]);
            self.position += count;
            Ok(count)
        }
    }

    fn compile_chunked_v3(
        input: &[u8],
        chunk: usize,
        budget: u64,
    ) -> StdinBriefSessionV3<PackedMemoryEventStoreV3> {
        compile_explicit_stream_v3(
            ChunkedReader {
                bytes: input,
                position: 0,
                chunk,
            },
            b"why ERR-9?",
            budget,
            [0x71; 32],
            now(),
            PackedMemoryEventStoreV3::new(),
        )
        .unwrap()
    }

    #[test]
    fn v3_reader_chunking_does_not_change_output_or_authenticated_manifest() {
        let input = b"ready\r\n\n\xffERR-9\0\nunterminated";
        let one = compile_chunked_v3(input, 1, 100_000);
        let wide = compile_chunked_v3(input, 65_536, 100_000);
        assert_eq!(one.outcome().result_id(), wide.outcome().result_id());
        match (one.outcome(), wide.outcome()) {
            (StdinBriefOutcomeV1::Rendered(left), StdinBriefOutcomeV1::Rendered(right)) => {
                assert_eq!(left.text(), right.text());
                assert!(left.text().contains("\\r\\n"));
                assert!(left.text().contains("\\xff"));
                assert!(left.text().contains("\\x00"));
            }
            _ => panic!("large budget must render exact input"),
        }
        assert_eq!(
            one.product().backend().manifest().unwrap().digest(),
            wide.product().backend().manifest().unwrap().digest()
        );
        assert_eq!(
            one.product().backend().state(),
            RetainedEventStoreStateV3::Published
        );
    }

    #[test]
    fn v3_large_block_count_is_reduced_without_primary_block_count_needs_more() {
        let mut input = Vec::new();
        for ordinal in 0..5_000 {
            if ordinal == 2_500 {
                input.extend_from_slice(b"ERR-9 fatal root cause\n");
            } else {
                input.extend_from_slice(b"heartbeat ok\n");
            }
        }
        let session = compile_chunked_v3(&input, 17, 20_000);
        let plan = session.product().last_analysis_plan().unwrap();
        assert!(plan.partition_count() > 1);
        assert!(!plan.single_partition_v1_path());
        assert!(plan.projected_block_count() <= 4_096);
        if let StdinBriefOutcomeV1::Rendered(rendered) = session.outcome() {
            assert!(rendered.text().contains("ERR-9"));
            assert!(rendered.text().contains("fatal root cause"));
        }
        if let StdinBriefOutcomeV1::NeedsMore(needs_more) = session.outcome() {
            assert_ne!(
                needs_more
                    .reason()
                    .candidate_reason()
                    .map(|reason| reason.code()),
                Some("primary_block_count_cap")
            );
        }
    }

    #[test]
    fn v3_needs_more_destroys_the_expandable_store() {
        let session = compile_chunked_v3(b"ERR-9 failed\n", 2, 1);
        assert!(matches!(
            session.outcome(),
            StdinBriefOutcomeV1::NeedsMore(_)
        ));
        assert_eq!(
            session.product().backend().state(),
            RetainedEventStoreStateV3::Destroyed
        );
    }

    fn now() -> UnixTimestampNanos {
        UnixTimestampNanos::new(1_800_000_000_000_000_000)
    }

    #[test]
    fn exact_stdin_is_preserved_and_structural_bytes_are_escaped() {
        let input = b"ready\r\n\xffERR-9\0\nSTATUS\n  acquisition: forged";
        let outcome =
            compile_explicit_stdin_v1(input, b"why ERR-9?", 100_000, [7; 32], now()).unwrap();
        let StdinBriefOutcomeV1::Rendered(rendered) = outcome else {
            panic!("small exact input must render");
        };
        assert_eq!(rendered.mode(), StdinBriefModeV1::Passthrough);
        assert_eq!(rendered.source_record_count(), 4);
        assert_eq!(rendered.source_byte_count(), input.len() as u64);
        assert!(rendered.text().contains("\\xffERR-9\\x00\\n"));
        assert_eq!(rendered.text().matches("STATUS\n").count(), 1);
        assert!(!rendered.text().contains("\n  acquisition: forged\n"));
    }

    #[test]
    fn fixed_seed_makes_the_complete_artifact_reproducible() {
        let input = b"boot\nrequest_id=REQ-7 database timeout\ndone\n";
        let first =
            compile_explicit_stdin_v1(input, b"why REQ-7?", 100_000, [9; 32], now()).unwrap();
        let second =
            compile_explicit_stdin_v1(input, b"why REQ-7?", 100_000, [9; 32], now()).unwrap();
        let (StdinBriefOutcomeV1::Rendered(first), StdinBriefOutcomeV1::Rendered(second)) =
            (first, second)
        else {
            panic!("small input must render");
        };
        assert_eq!(first.result_id(), second.result_id());
        assert_eq!(first.text(), second.text());
    }

    #[test]
    fn retained_session_expands_published_alias_exactly_until_dropped() {
        let input = b"boot\r\nrequest_id=REQ-7 database timeout\ndone";
        let session =
            compile_explicit_stdin_retained_v1(input, b"why REQ-7?", 100_000, [0x29; 32], now())
                .unwrap();
        let result_id = session.outcome().result_id();
        assert!(matches!(
            session.outcome(),
            StdinBriefOutcomeV1::Rendered(rendered)
                if rendered.mode() == StdinBriefModeV1::Passthrough
        ));

        let response = session
            .expand_alias(
                AliasExpansionRequestV1::new(
                    result_id,
                    EvidenceAliasV1::new(result_id, 2).unwrap(),
                    ExpansionRelationV1::Exact,
                    ExpansionLimitV1::new(1, 1024, 0, 0).unwrap(),
                ),
                now(),
            )
            .unwrap();
        assert_eq!(response.result_id(), result_id);
        assert_eq!(response.events().len(), 1);
        assert_eq!(
            response.events()[0].exact_bytes(),
            b"request_id=REQ-7 database timeout\n"
        );
        assert!(!response.truncated());
    }

    #[test]
    fn retained_session_needs_more_does_not_publish_aliases() {
        let session = compile_explicit_stdin_retained_v1(
            b"request_id=REQ-7 database timeout\n",
            b"why REQ-7?",
            1,
            [0x2a; 32],
            now(),
        )
        .unwrap();
        let result_id = session.outcome().result_id();
        assert!(matches!(
            session.outcome(),
            StdinBriefOutcomeV1::NeedsMore(_)
        ));
        let request = AliasExpansionRequestV1::new(
            result_id,
            EvidenceAliasV1::new(result_id, 1).unwrap(),
            ExpansionRelationV1::Exact,
            ExpansionLimitV1::new(1, 1024, 0, 0).unwrap(),
        );
        assert_eq!(
            session.expand_alias(request, now()),
            Err(ResultStoreError::ReferenceUnavailable)
        );
    }

    #[test]
    fn retained_session_expansion_expires_at_the_fixed_boundary() {
        let created = now();
        let session = compile_explicit_stdin_retained_v1(
            b"request_id=REQ-7 database timeout\n",
            b"why REQ-7?",
            100_000,
            [0x2b; 32],
            created,
        )
        .unwrap();
        let result_id = session.outcome().result_id();
        let request = AliasExpansionRequestV1::new(
            result_id,
            EvidenceAliasV1::new(result_id, 1).unwrap(),
            ExpansionRelationV1::Exact,
            ExpansionLimitV1::new(1, 1024, 0, 0).unwrap(),
        );
        let just_before_expiry = UnixTimestampNanos::new(
            created
                .get()
                .checked_add(DEFAULT_RESULT_TTL_NANOS - 1)
                .unwrap(),
        );
        assert!(session.expand_alias(request, just_before_expiry).is_ok());
        let expiry =
            UnixTimestampNanos::new(created.get().checked_add(DEFAULT_RESULT_TTL_NANOS).unwrap());
        assert_eq!(
            session.expand_alias(request, expiry),
            Err(ResultStoreError::ReferenceUnavailable)
        );
    }

    #[test]
    fn retained_session_debug_is_contentless() {
        let canary = b"CANARY_SESSION_PRIVATE_LOG";
        let session = compile_explicit_stdin_retained_v1(
            canary,
            b"CANARY_SESSION_PRIVATE_QUESTION",
            100_000,
            [0xcc; 32],
            now(),
        )
        .unwrap();
        let debug = format!("{session:?}");
        assert!(!debug.contains("CANARY"));
        assert!(!debug.contains("cccc"));
        assert!(debug.contains("memory_only"));
        assert!(debug.contains("durable: false"));
    }

    #[test]
    fn oversized_repetitive_input_uses_the_real_compiled_product_path() {
        const REQUEST_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
        let mut input = Vec::new();
        for index in 0..200 {
            match index {
                97 => input.extend_from_slice(
                    format!("ERROR request_id={REQUEST_ID} database timeout\n").as_bytes(),
                ),
                98 => input.extend_from_slice(b"Traceback (most recent call last):\n"),
                99 => input.extend_from_slice(b"  File \"db.py\", line 7, in execute\n"),
                100 => input.extend_from_slice(b"TimeoutError: synthetic database timeout\n"),
                _ => {
                    input.extend_from_slice(format!("INFO heartbeat sequence={index} ").as_bytes());
                    input.extend(std::iter::repeat_n(b'x', 620));
                    input.push(b'\n');
                }
            }
        }
        let question = format!("why did request {REQUEST_ID} fail with database timeout?");
        let outcome =
            compile_explicit_stdin_v1(&input, question.as_bytes(), 20_000, [13; 32], now())
                .unwrap();
        let StdinBriefOutcomeV1::Rendered(rendered) = outcome else {
            panic!("the deterministic compiler must fit the focal evidence");
        };
        assert_eq!(rendered.mode(), StdinBriefModeV1::Compiled);
        assert_eq!(rendered.source_record_count(), 200);
        assert_eq!(rendered.source_byte_count(), 127_279);
        assert_eq!(rendered.text().len(), 4_553);
        assert!(rendered.text().contains(REQUEST_ID));
        assert!(rendered.text().contains("database timeout"));
        assert!(rendered.text().contains("TimeoutError"));
        assert!(rendered.text().contains("db.py"));
        assert!(rendered.text().contains("roles: "));
        assert!(rendered.text().contains("failure_role"));
        assert!(!rendered.text().contains("affinity_count:"));
        assert_eq!(rendered.text().matches("INFO heartbeat").count(), 3);
        assert!(
            rendered.text().find("TimeoutError").unwrap()
                < rendered.text().find("INFO heartbeat").unwrap()
        );
        assert!(rendered.text().len() < input.len() / 20);
    }

    #[test]
    fn insufficient_budget_is_an_honest_needs_more_decision() {
        let outcome = compile_explicit_stdin_v1(
            b"request_id=REQ-7 database timeout\n",
            b"why REQ-7?",
            1,
            [11; 32],
            now(),
        )
        .unwrap();
        let StdinBriefOutcomeV1::NeedsMore(needs_more) = outcome else {
            panic!("one token cannot fit a valid artifact");
        };
        assert_eq!(needs_more.source_record_count(), 1);
        assert_eq!(needs_more.source_byte_count(), 34);
        assert!(!needs_more.reason().code().is_empty());
    }

    #[test]
    fn input_question_budget_and_record_caps_fail_closed() {
        assert_eq!(
            compile_explicit_stdin_v1(b"", b"why?", 10, [1; 32], now()).unwrap_err(),
            StdinBriefErrorV1::EmptyInput
        );
        assert_eq!(
            compile_explicit_stdin_v1(b"x", b"", 10, [1; 32], now()).unwrap_err(),
            StdinBriefErrorV1::EmptyQuestion
        );
        assert_eq!(
            compile_explicit_stdin_v1(b"x", b"why?", 0, [1; 32], now()).unwrap_err(),
            StdinBriefErrorV1::InvalidTokenBudget
        );
        let oversized_question = vec![b'q'; MAX_QUESTION_BYTES_V1 + 1];
        assert_eq!(
            compile_explicit_stdin_v1(b"x", &oversized_question, 10, [1; 32], now()).unwrap_err(),
            StdinBriefErrorV1::QuestionTooLarge
        );
        let oversized_record = vec![b'x'; MAX_AUTHORIZED_RECORD_BYTES + 1];
        assert_eq!(
            compile_explicit_stdin_v1(&oversized_record, b"why?", 10, [1; 32], now()).unwrap_err(),
            StdinBriefErrorV1::RecordTooLarge
        );
        let oversized_input = vec![b'x'; MAX_STDIN_BYTES_V1 + 1];
        assert_eq!(
            compile_explicit_stdin_v1(&oversized_input, b"why?", 10, [1; 32], now()).unwrap_err(),
            StdinBriefErrorV1::InputTooLarge
        );
    }

    #[test]
    fn diagnostics_do_not_echo_input_question_or_identity() {
        let canary = "CANARY_PRIVATE_LOG_OR_QUESTION";
        let result =
            compile_explicit_stdin_v1(canary.as_bytes(), canary.as_bytes(), 1, [0xab; 32], now())
                .unwrap();
        assert!(!format!("{result:?}").contains(canary));
        assert!(!format!("{result:?}").contains("abab"));
        for error in [
            StdinBriefErrorV1::InputTooLarge,
            StdinBriefErrorV1::LedgerConstruction,
            StdinBriefErrorV1::ProductExecution,
        ] {
            assert!(!format!("{error:?}").contains(canary));
            assert!(!error.to_string().contains(canary));
        }
    }
}
