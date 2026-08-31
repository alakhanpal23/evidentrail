//! Publication-gated V2 product orchestration.
//!
//! This module is the single semantic bridge between an immutable authorized
//! ledger and the durable repository state machine. It deliberately keeps the
//! compiler and renderer identical to memory mode, and installs expansion
//! capabilities only after `PUBLISHED` authority has been reread through
//! repository recovery.

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_core::{EventLedger, EvidenceReferenceId, ExpansionRelationV1, UnixTimestampNanos};
use evidentrail_snapshot_format::{
    BuildContextDigestsV1, LifecycleDigestV1, OperationIdV1, ResultLifecycleStateV1,
    derive_lifecycle_digest_v1,
};
use evidentrail_store::{
    AliasExpansionRequestV1, BatchCommitInputV2, CreatingKeyContextV1, DataCommitInputV2,
    DisplayedAliasManifestEntryV1, DisplayedAliasManifestV1, DurableEventInputV2,
    DurableExpansionV2, DurableRepositoryErrorV2, DurableResultRepositoryV2, KeyAuthorityV2,
    MAX_DURABLE_BATCH_EVENTS_V2, RecoveryDispositionV2, SealInputV2,
};
use sha2::{Digest, Sha256};

use crate::encrypted_retention::{
    FrozenReferenceV1, PreparedReferenceManifestV1, prepare_compiled_manifest,
    prepare_passthrough_manifest,
};
use crate::{DeterministicProductDecisionV1, MemoryProductV1, ProductError};

const OPERATION_DOMAIN_V2: &[u8] = b"evidentrail.product.operation.v2";
const REQUEST_DOMAIN_V2: &[u8] = b"evidentrail.product.request.v2";
const TRANSFORMATION_DOMAIN_V2: &[u8] = b"evidentrail.product.transformations.v2";
const FETCH_DOMAIN_V2: &[u8] = b"evidentrail.product.fetch-completion.v2";
const REFERENCES_DOMAIN_V2: &[u8] = b"evidentrail.product.references.v2";
const STATUS_DOMAIN_V2: &[u8] = b"evidentrail.product.status.v2";
const BUILD_COMPILER_V2: &[u8] = b"evidentrail-compile/three-lane/v1";
const BUILD_RENDERER_V2: &[u8] = b"evidentrail-evidence/log-brief/v1";
const BUILD_TOKENIZER_V2: &[u8] = b"evidentrail-evidence/utf8-byte-tokenizer/v1";
const BUILD_POLICY_V2: &[u8] = b"evidentrail-product/authorized-ledger/v1";
const BUILD_CONTRACT_V2: &[u8] = b"evidentrail-product/durable-lifecycle/v2";
// Every product batch includes one semantic receipt in addition to the two
// repository-owned frames, so it must leave one slot below the repository's
// event-only maximum.
const DURABLE_PRODUCT_BATCH_EVENTS_V2: usize = MAX_DURABLE_BATCH_EVENTS_V2 - 1;

type ProductArtifactBytesV2 = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Stable, contentless durable product failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableProductErrorV2 {
    InvalidTime,
    InvalidArtifact,
    RepositoryUnavailable,
    AuthorityLocked,
    AuthorityUnavailable,
    PublicationFailed,
    ResultUnavailable,
    ReferenceUnavailable,
    InsufficientExpansionBudget,
    RollbackOrCorruption,
    ReissueRequired,
    CompilationFailed,
}

impl DurableProductErrorV2 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidTime => "EVIDENTRAIL_PRODUCT_DURABLE_INVALID_TIME",
            Self::InvalidArtifact => "EVIDENTRAIL_PRODUCT_DURABLE_INVALID_ARTIFACT",
            Self::RepositoryUnavailable => "EVIDENTRAIL_PRODUCT_DURABLE_REPOSITORY_UNAVAILABLE",
            Self::AuthorityLocked => "EVIDENTRAIL_PRODUCT_DURABLE_AUTHORITY_LOCKED",
            Self::AuthorityUnavailable => "EVIDENTRAIL_PRODUCT_DURABLE_AUTHORITY_UNAVAILABLE",
            Self::PublicationFailed => "EVIDENTRAIL_PRODUCT_DURABLE_PUBLICATION_FAILED",
            Self::ResultUnavailable => "EVIDENTRAIL_PRODUCT_DURABLE_RESULT_UNAVAILABLE",
            Self::ReferenceUnavailable => "EVIDENTRAIL_PRODUCT_DURABLE_REFERENCE_UNAVAILABLE",
            Self::InsufficientExpansionBudget => {
                "EVIDENTRAIL_PRODUCT_DURABLE_INSUFFICIENT_EXPANSION_BUDGET"
            }
            Self::RollbackOrCorruption => "EVIDENTRAIL_PRODUCT_DURABLE_ROLLBACK_OR_CORRUPTION",
            Self::ReissueRequired => "EVIDENTRAIL_PRODUCT_DURABLE_REISSUE_REQUIRED",
            Self::CompilationFailed => "EVIDENTRAIL_PRODUCT_DURABLE_COMPILATION_FAILED",
        }
    }
}

impl fmt::Debug for DurableProductErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableProductErrorV2")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for DurableProductErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for DurableProductErrorV2 {}

/// Exact durable expansion authorized by one frozen displayed alias.
pub struct DurableProductExpansionV2 {
    result_id: evidentrail_schema::ResultId,
    reference_id: EvidenceReferenceId,
    inner: DurableExpansionV2,
}

/// Contentless startup-reconciliation accounting. Result identities are
/// intentionally not exposed through this product surface.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DurableStartupRecoveryV2 {
    visible: usize,
    resumable: usize,
    reissue_required: usize,
    unavailable: usize,
}

impl DurableStartupRecoveryV2 {
    #[must_use]
    pub const fn visible(self) -> usize {
        self.visible
    }

    #[must_use]
    pub const fn resumable(self) -> usize {
        self.resumable
    }

    #[must_use]
    pub const fn reissue_required(self) -> usize {
        self.reissue_required
    }

    #[must_use]
    pub const fn unavailable(self) -> usize {
        self.unavailable
    }
}

impl DurableProductExpansionV2 {
    #[must_use]
    pub const fn result_id(&self) -> evidentrail_schema::ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn reference_id(&self) -> EvidenceReferenceId {
        self.reference_id
    }

    #[must_use]
    pub fn events(&self) -> &[evidentrail_store::OpenedDurableEventV2] {
        self.inner.events()
    }

    #[must_use]
    pub const fn returned_bytes(&self) -> usize {
        self.inner.returned_bytes()
    }

    #[must_use]
    pub const fn relation(&self) -> ExpansionRelationV1 {
        ExpansionRelationV1::Exact
    }

    #[must_use]
    pub const fn truncated(&self) -> bool {
        false
    }
}

impl fmt::Debug for DurableProductExpansionV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableProductExpansionV2")
            .field("event_count", &self.events().len())
            .field("returned_bytes", &self.returned_bytes())
            .field("relation", &ExpansionRelationV1::Exact)
            .finish()
    }
}

struct PublishedCapabilityV2 {
    expires_at: UnixTimestampNanos,
    aliases: Vec<FrozenReferenceV1>,
}

/// Durable product coordinator over an injected V2 authority.
///
/// The coordinator exposes no result enumeration and no EventId expansion.
/// Callers must present a previously returned result identity and alias; the
/// frozen manifest is then checked independently before indexed expansion.
pub struct DurableProductV2<A> {
    repository: DurableResultRepositoryV2<A>,
    published: BTreeMap<evidentrail_schema::ResultId, PublishedCapabilityV2>,
}

impl<A: KeyAuthorityV2> DurableProductV2<A> {
    #[must_use]
    pub fn new(repository: DurableResultRepositoryV2<A>) -> Self {
        Self {
            repository,
            published: BTreeMap::new(),
        }
    }

    #[must_use]
    pub const fn repository(&self) -> &DurableResultRepositoryV2<A> {
        &self.repository
    }

    /// Reconcile trusted-authority entries and active filesystem objects at
    /// startup without exposing a result catalog. Authenticated published
    /// alias manifests are reopened into the private capability map so a
    /// caller that retained a result identity and alias can expand after a
    /// process or machine restart.
    pub fn reconcile_startup(
        &mut self,
        now: UnixTimestampNanos,
    ) -> Result<DurableStartupRecoveryV2, DurableProductErrorV2> {
        let now = i64::try_from(now.get()).map_err(|_| DurableProductErrorV2::InvalidTime)?;
        let report = self
            .repository
            .recover_all(now, |_| Some(durable_product_build_context_v2()))
            .map_err(map_repository_error)?;
        let mut summary = DurableStartupRecoveryV2::default();
        for entry in report.entries() {
            match entry.disposition() {
                RecoveryDispositionV2::AlreadyVisible
                | RecoveryDispositionV2::CompletedPublication => {
                    let aliases = self
                        .repository
                        .reopen_published_alias_manifest(entry.result_id(), now)
                        .map_err(map_repository_error)?;
                    self.install_recovered_capability(aliases);
                    summary.visible += 1;
                }
                RecoveryDispositionV2::ResumeOpen | RecoveryDispositionV2::ResumeCompilation => {
                    summary.resumable += 1
                }
                RecoveryDispositionV2::ReissueRequired => summary.reissue_required += 1,
                RecoveryDispositionV2::Absent
                | RecoveryDispositionV2::Expired
                | RecoveryDispositionV2::Quarantined
                | RecoveryDispositionV2::RollbackOrCorruption => summary.unavailable += 1,
            }
        }
        Ok(summary)
    }

    fn install_recovered_capability(&mut self, manifest: DisplayedAliasManifestV1) {
        let result_id = manifest.result_id();
        let aliases = manifest
            .entries()
            .iter()
            .map(|entry| FrozenReferenceV1 {
                reference: entry.reference().clone(),
                ordered_event_ids: entry.ordered_event_ids().to_vec(),
            })
            .collect();
        self.published.insert(
            result_id,
            PublishedCapabilityV2 {
                expires_at: manifest.expires_at(),
                aliases,
            },
        );
    }

    /// Persist the authorized data, run the shared deterministic semantic
    /// compiler, seal the exact public products, and publish authority.
    /// Nothing is inserted into the visible capability map until a matching
    /// `PUBLISHED` record and final repository have been reread.
    pub fn create_deterministic_result_v2(
        &mut self,
        result_id: evidentrail_schema::ResultId,
        question_bytes: &[u8],
        ledger: EventLedger,
        now: UnixTimestampNanos,
        total_token_budget: u64,
    ) -> Result<DeterministicProductDecisionV1, DurableProductErrorV2> {
        let created = i64::try_from(now.get()).map_err(|_| DurableProductErrorV2::InvalidTime)?;
        let expires_at = now
            .get()
            .checked_add(evidentrail_store::DEFAULT_RESULT_TTL_NANOS)
            .ok_or(DurableProductErrorV2::InvalidTime)?;
        let expires = i64::try_from(expires_at).map_err(|_| DurableProductErrorV2::InvalidTime)?;
        let key_context = CreatingKeyContextV1::new(result_id, created, expires)
            .map_err(|_| DurableProductErrorV2::InvalidTime)?;
        let request = encode_request(result_id, question_bytes, total_token_budget, &ledger)?;
        self.repository
            .begin(
                result_id,
                created,
                expires,
                operation(result_id, 0, b"begin"),
                &request,
            )
            .map_err(map_repository_error)?;

        for (ordinal, events) in ledger
            .events()
            .chunks(DURABLE_PRODUCT_BATCH_EVENTS_V2)
            .enumerate()
        {
            let ordinal =
                u64::try_from(ordinal).map_err(|_| DurableProductErrorV2::RepositoryUnavailable)?;
            let durable_events = events
                .iter()
                .map(|event| {
                    DurableEventInputV2::new(
                        event.id(),
                        event.exactness_basis(),
                        event.raw().to_vec(),
                    )
                    .map_err(map_repository_error)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let semantic_receipt = encode_batch_semantics(ordinal, &durable_events);
            let batch = BatchCommitInputV2::new(
                ordinal,
                operation(result_id, ordinal, b"batch"),
                durable_events,
                vec![semantic_receipt],
                Vec::new(),
            )
            .map_err(map_repository_error)?;
            self.repository
                .commit_batch(result_id, &batch)
                .map_err(map_repository_error)?;
        }

        let build_context = durable_product_build_context_v2();
        self.repository
            .commit_data(
                result_id,
                DataCommitInputV2 {
                    operation: operation(result_id, 0, b"data"),
                    question_configuration: derive_lifecycle_digest_v1(&request),
                    acquisition_receipt: LifecycleDigestV1::from_bytes(
                        *ledger.acquisition_receipt_id().as_bytes(),
                    ),
                    transformation_receipts: transformation_digest(&ledger),
                    fetch_completion: fetch_digest(&ledger),
                    source_identity: LifecycleDigestV1::from_bytes(
                        *ledger.source_identity_digest().as_bytes(),
                    ),
                    build_context,
                },
            )
            .map_err(map_repository_error)?;

        let mut memory = MemoryProductV1::new();
        let decision = memory
            .create_deterministic_result_v1(
                result_id,
                question_bytes,
                ledger,
                now,
                total_token_budget,
            )
            .map_err(map_compilation_error)?;
        let prepared = match &decision {
            DeterministicProductDecisionV1::Passthrough(result) => {
                let references = memory
                    .store
                    .registered_reference_metadata(result_id, now)
                    .map_err(|_| DurableProductErrorV2::InvalidArtifact)?;
                prepare_passthrough_manifest(
                    &key_context,
                    memory
                        .store
                        .ledger(result_id, now)
                        .map_err(|_| DurableProductErrorV2::InvalidArtifact)?,
                    result.artifact(),
                    references,
                )
                .map_err(|_| DurableProductErrorV2::InvalidArtifact)?
            }
            DeterministicProductDecisionV1::Compiled(result) => {
                let references = memory
                    .store
                    .registered_reference_metadata(result_id, now)
                    .map_err(|_| DurableProductErrorV2::InvalidArtifact)?;
                prepare_compiled_manifest(
                    &key_context,
                    memory
                        .store
                        .ledger(result_id, now)
                        .map_err(|_| DurableProductErrorV2::InvalidArtifact)?,
                    result.artifact(),
                    references,
                )
                .map_err(|_| DurableProductErrorV2::InvalidArtifact)?
            }
            DeterministicProductDecisionV1::NeedsMore(_) => {
                self.repository
                    .destroy(result_id)
                    .map_err(map_repository_error)?;
                return Ok(decision);
            }
        };
        let alias_manifest = displayed_alias_manifest(&key_context, &prepared)?;
        let (log_brief, presentation_receipt, status) = product_bytes(&decision)?;
        let references = encode_references(&prepared);
        self.repository
            .seal(
                result_id,
                &SealInputV2 {
                    operation: operation(result_id, 0, b"seal"),
                    log_brief,
                    references,
                    presentation_receipt,
                    status,
                    alias_manifest: alias_manifest.encode(),
                },
            )
            .map_err(map_repository_error)?;
        self.repository
            .publish(result_id, operation(result_id, 0, b"publish"))
            .map_err(map_repository_error)?;
        match self
            .repository
            .recover(result_id, created, Some(build_context))
            .map_err(map_repository_error)?
        {
            RecoveryDispositionV2::AlreadyVisible => {}
            RecoveryDispositionV2::RollbackOrCorruption => {
                return Err(DurableProductErrorV2::RollbackOrCorruption);
            }
            _ => return Err(DurableProductErrorV2::PublicationFailed),
        }
        let authority =
            self.repository
                .authority()
                .snapshot(result_id)
                .map_err(|error| match error {
                    evidentrail_store::KeyAuthorityErrorV2::Locked => {
                        DurableProductErrorV2::AuthorityLocked
                    }
                    _ => DurableProductErrorV2::AuthorityUnavailable,
                })?;
        if authority.state() != ResultLifecycleStateV1::Published
            || authority.publication_generation() == 0
        {
            return Err(DurableProductErrorV2::PublicationFailed);
        }
        let aliases = prepared
            .aliases
            .iter()
            .map(|id| {
                prepared
                    .references
                    .get(id)
                    .map(|frozen| FrozenReferenceV1 {
                        reference: frozen.reference.clone(),
                        ordered_event_ids: frozen.ordered_event_ids.clone(),
                    })
                    .ok_or(DurableProductErrorV2::InvalidArtifact)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.published.insert(
            result_id,
            PublishedCapabilityV2 {
                expires_at: UnixTimestampNanos::new(expires_at),
                aliases,
            },
        );
        Ok(decision)
    }

    /// Expand only a displayed, exact alias from a result installed after
    /// publication verification.
    pub fn expand_alias(
        &self,
        request: AliasExpansionRequestV1,
        now: UnixTimestampNanos,
    ) -> Result<DurableProductExpansionV2, DurableProductErrorV2> {
        if request.relation() != ExpansionRelationV1::Exact
            || request.alias().result_id() != request.result_id()
        {
            return Err(DurableProductErrorV2::ReferenceUnavailable);
        }
        let published = self
            .published
            .get(&request.result_id())
            .ok_or(DurableProductErrorV2::ResultUnavailable)?;
        if now >= published.expires_at {
            return Err(DurableProductErrorV2::ResultUnavailable);
        }
        let index = usize::from(request.alias().one_based_ordinal() - 1);
        let frozen = published
            .aliases
            .get(index)
            .ok_or(DurableProductErrorV2::ReferenceUnavailable)?;
        frozen
            .reference
            .authorize(request.result_id(), ExpansionRelationV1::Exact, now)
            .map_err(|_| DurableProductErrorV2::ReferenceUnavailable)?;
        let limit = request.limit();
        if frozen.ordered_event_ids.len() > limit.max_events() {
            return Err(DurableProductErrorV2::InsufficientExpansionBudget);
        }
        let now = i64::try_from(now.get()).map_err(|_| DurableProductErrorV2::InvalidTime)?;
        let inner = self
            .repository
            .expand(
                request.result_id(),
                &frozen.ordered_event_ids,
                limit.max_events(),
                limit.max_bytes(),
                now,
            )
            .map_err(map_repository_error)?;
        Ok(DurableProductExpansionV2 {
            result_id: request.result_id(),
            reference_id: frozen.reference.id(),
            inner,
        })
    }

    /// Reconcile a caller-presented result without revealing any result
    /// catalog. Startup reconciliation installs all verified published alias
    /// capabilities; this narrower method exposes only the disposition.
    pub fn recover_presented_result(
        &self,
        result_id: evidentrail_schema::ResultId,
        now: UnixTimestampNanos,
    ) -> Result<RecoveryDispositionV2, DurableProductErrorV2> {
        let now = i64::try_from(now.get()).map_err(|_| DurableProductErrorV2::InvalidTime)?;
        self.repository
            .recover(result_id, now, Some(durable_product_build_context_v2()))
            .map_err(map_repository_error)
    }

    /// Fixed-expiry cleanup over the non-enumerable in-process capability set.
    pub fn cleanup_expired(&mut self, now: UnixTimestampNanos) -> usize {
        // Tool activity is the periodic maintenance clock for stdio mode.
        // Recovery performs Keychain-first expiry for every trusted entry;
        // failures remain unavailable and are retried on the next maintenance
        // pass rather than changing a tool response into an enumeration oracle.
        if let Ok(now_i64) = i64::try_from(now.get()) {
            let _ = self
                .repository
                .recover_all(now_i64, |_| Some(durable_product_build_context_v2()));
        }
        let expired = self
            .published
            .iter()
            .filter_map(|(result_id, result)| (now >= result.expires_at).then_some(*result_id))
            .collect::<Vec<_>>();
        let before = self.published.len();
        for result_id in expired {
            let _ = self.repository.destroy(result_id);
            self.published.remove(&result_id);
        }
        before - self.published.len()
    }

    #[must_use]
    pub fn published_result_count(&self) -> usize {
        self.published.len()
    }
}

impl<A> fmt::Debug for DurableProductV2<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableProductV2")
            .field("published_result_count", &self.published.len())
            .field("content_redacted", &true)
            .finish()
    }
}

#[must_use]
pub fn durable_product_build_context_v2() -> BuildContextDigestsV1 {
    BuildContextDigestsV1::new(
        derive_lifecycle_digest_v1(BUILD_COMPILER_V2),
        derive_lifecycle_digest_v1(BUILD_RENDERER_V2),
        derive_lifecycle_digest_v1(BUILD_TOKENIZER_V2),
        derive_lifecycle_digest_v1(BUILD_POLICY_V2),
        derive_lifecycle_digest_v1(BUILD_CONTRACT_V2),
    )
}

fn operation(
    result_id: evidentrail_schema::ResultId,
    ordinal: u64,
    purpose: &[u8],
) -> OperationIdV1 {
    let mut hasher = Sha256::new();
    hasher.update(OPERATION_DOMAIN_V2);
    hasher.update(result_id.as_bytes());
    hasher.update(ordinal.to_be_bytes());
    hasher.update((purpose.len() as u64).to_be_bytes());
    hasher.update(purpose);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    OperationIdV1::from_bytes(bytes)
}

fn encode_request(
    result_id: evidentrail_schema::ResultId,
    question: &[u8],
    budget: u64,
    ledger: &EventLedger,
) -> Result<Vec<u8>, DurableProductErrorV2> {
    let question_len =
        u64::try_from(question.len()).map_err(|_| DurableProductErrorV2::RepositoryUnavailable)?;
    let mut encoded = Vec::with_capacity(128 + question.len());
    encoded.extend_from_slice(REQUEST_DOMAIN_V2);
    encoded.extend_from_slice(result_id.as_bytes());
    encoded.extend_from_slice(ledger.plan_digest().as_bytes());
    encoded.extend_from_slice(&budget.to_be_bytes());
    encoded.extend_from_slice(&question_len.to_be_bytes());
    encoded.extend_from_slice(question);
    Ok(encoded)
}

fn encode_batch_semantics(ordinal: u64, events: &[DurableEventInputV2]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(ordinal.to_be_bytes());
    for event in events {
        hasher.update(event.event_id().as_bytes());
        hasher.update(event.exactness_basis().code().as_bytes());
        hasher.update((event.authorized_bytes().len() as u64).to_be_bytes());
        hasher.update(Sha256::digest(event.authorized_bytes()));
    }
    hasher.finalize().to_vec()
}

fn transformation_digest(ledger: &EventLedger) -> LifecycleDigestV1 {
    let mut hasher = Sha256::new();
    hasher.update(TRANSFORMATION_DOMAIN_V2);
    for receipt in ledger.transformation_receipts() {
        hasher.update(receipt.id().as_bytes());
    }
    LifecycleDigestV1::from_bytes(hasher.finalize().into())
}

fn fetch_digest(ledger: &EventLedger) -> LifecycleDigestV1 {
    let mut hasher = Sha256::new();
    hasher.update(FETCH_DOMAIN_V2);
    hasher.update(ledger.retrieval_id().as_bytes());
    hasher.update(ledger.plan_id().as_bytes());
    hasher.update(ledger.acquisition_receipt_id().as_bytes());
    hasher.update(ledger.fetch_completion().completeness().code().as_bytes());
    LifecycleDigestV1::from_bytes(hasher.finalize().into())
}

fn displayed_alias_manifest(
    key_context: &CreatingKeyContextV1,
    prepared: &PreparedReferenceManifestV1,
) -> Result<DisplayedAliasManifestV1, DurableProductErrorV2> {
    let entries = prepared
        .aliases
        .iter()
        .enumerate()
        .map(|(index, id)| {
            let frozen = prepared
                .references
                .get(id)
                .ok_or(DurableProductErrorV2::InvalidArtifact)?;
            let ordinal =
                u16::try_from(index + 1).map_err(|_| DurableProductErrorV2::InvalidArtifact)?;
            DisplayedAliasManifestEntryV1::new(
                prepared.result_id,
                ordinal,
                frozen.reference.clone(),
                frozen.ordered_event_ids.iter().copied(),
            )
            .map_err(|_| DurableProductErrorV2::InvalidArtifact)
        })
        .collect::<Result<Vec<_>, _>>()?;
    DisplayedAliasManifestV1::new(
        prepared.result_id,
        UnixTimestampNanos::new(i128::from(key_context.expires_unix_nanos())),
        entries,
    )
    .map_err(|_| DurableProductErrorV2::InvalidArtifact)
}

fn encode_references(prepared: &PreparedReferenceManifestV1) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(REFERENCES_DOMAIN_V2);
    for (id, frozen) in &prepared.references {
        hasher.update(id.as_bytes());
        hasher.update((frozen.ordered_event_ids.len() as u64).to_be_bytes());
        for event_id in &frozen.ordered_event_ids {
            hasher.update(event_id.as_bytes());
        }
    }
    hasher.finalize().to_vec()
}

fn product_bytes(
    decision: &DeterministicProductDecisionV1,
) -> Result<ProductArtifactBytesV2, DurableProductErrorV2> {
    let (text, status, receipt) = match decision {
        DeterministicProductDecisionV1::Passthrough(result) => {
            let brief = result.artifact().brief();
            (
                result.artifact().text(),
                brief.status(),
                brief.status().selection().presentation_receipt(),
            )
        }
        DeterministicProductDecisionV1::Compiled(result) => {
            let brief = result.artifact().brief();
            (
                result.artifact().text(),
                brief.status(),
                brief.status().selection().presentation_receipt(),
            )
        }
        DeterministicProductDecisionV1::NeedsMore(_) => {
            return Err(DurableProductErrorV2::InvalidArtifact);
        }
    };
    let mut status_bytes = Vec::new();
    status_bytes.extend_from_slice(STATUS_DOMAIN_V2);
    status_bytes.extend_from_slice(status.acquisition().code().as_bytes());
    status_bytes.push(0);
    status_bytes.extend_from_slice(status.selection().code().as_bytes());
    Ok((
        text.as_bytes().to_vec(),
        receipt.id().as_bytes().to_vec(),
        status_bytes,
    ))
}

fn map_compilation_error(_error: ProductError) -> DurableProductErrorV2 {
    DurableProductErrorV2::CompilationFailed
}

fn map_repository_error(error: DurableRepositoryErrorV2) -> DurableProductErrorV2 {
    match error {
        DurableRepositoryErrorV2::AuthorityUnavailable => {
            DurableProductErrorV2::AuthorityUnavailable
        }
        DurableRepositoryErrorV2::AuthorityLocked => DurableProductErrorV2::AuthorityLocked,
        DurableRepositoryErrorV2::PublicationFailed => DurableProductErrorV2::PublicationFailed,
        DurableRepositoryErrorV2::ResultUnavailable => DurableProductErrorV2::ResultUnavailable,
        DurableRepositoryErrorV2::RollbackOrCorruption
        | DurableRepositoryErrorV2::AuthenticationFailed
        | DurableRepositoryErrorV2::CommitmentMismatch => {
            DurableProductErrorV2::RollbackOrCorruption
        }
        DurableRepositoryErrorV2::ReissueRequired => DurableProductErrorV2::ReissueRequired,
        DurableRepositoryErrorV2::CapacityExceeded => {
            DurableProductErrorV2::InsufficientExpansionBudget
        }
        _ => DurableProductErrorV2::RepositoryUnavailable,
    }
}
