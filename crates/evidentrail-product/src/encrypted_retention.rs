//! Authenticated, process-local encrypted retention after a final artifact has
//! already been rendered.
//!
//! This module deliberately does not render, select, acquire, or diagnose. It
//! borrows the plaintext ledger only while publishing one encrypted frame per
//! persisted event, then retains only encrypted repository state and immutable
//! capability metadata. On Unix it can hand an already-authenticated sealed
//! repository result to the bounded ciphertext filesystem/restart
//! coordinator; this does not persist the capability metadata and makes no
//! rollback, cross-process-locking, sudden-power-loss durability, complete
//! product recovery, or external-publication claim.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;

use evidentrail_core::{
    EventId, EventLedger, EvidenceReferenceId, EvidenceReferenceV1, EvidenceTargetRef,
    ExpansionRelationV1, UnixTimestampNanos,
};
use evidentrail_evidence::{OwnedRenderedCompiledBriefV1, OwnedRenderedPassthroughBriefV1};
use evidentrail_snapshot_format::{
    AcquisitionCompletionRecordV1, CoreManifestComponentsV1, CoreResultManifestV1,
    ExpectedCoreResultManifestContextV1, FrameObjectKindV1, SourceOutcomeTableV1,
};
use evidentrail_store::{
    AliasExpansionRequestV1, CreatingKeyContextV1, DEFAULT_RESULT_TTL_NANOS,
    DisplayedAliasManifestEntryV1, DisplayedAliasManifestV1, EncryptedCoreResultDestroyOutcomeV1,
    EncryptedCoreResultRepositoryErrorV1, ExpansionRequestV1, KeyProviderV1,
    MemoryEncryptedCoreResultRepositoryV1, OpenedEncryptedCoreResultEventV1,
};
#[cfg(unix)]
use evidentrail_store::{
    AuthenticatedFilesystemRestartCoordinatorV1, AuthenticatedFilesystemRestartErrorV1,
    FilesystemBundlePublicationV1,
};

use crate::{CompiledProductResultV1, MemoryProductV1, RenderedProductResultV1};

/// Stable, contentless failure for post-render encrypted retention or exact
/// expansion.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatedEncryptedRetentionErrorV1 {
    PlaintextResultUnavailable,
    DuplicateResult,
    InvalidArtifactBinding,
    InvalidReferenceManifest,
    SnapshotProjectionFailed,
    RepositoryFailed,
    ReferenceUnavailable,
    InsufficientExpansionBudget,
    ArithmeticOverflow,
}

impl AuthenticatedEncryptedRetentionErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PlaintextResultUnavailable => {
                "EVIDENTRAIL_AUTHENTICATED_RETENTION_PLAINTEXT_RESULT_UNAVAILABLE"
            }
            Self::DuplicateResult => "EVIDENTRAIL_AUTHENTICATED_RETENTION_DUPLICATE_RESULT",
            Self::InvalidArtifactBinding => {
                "EVIDENTRAIL_AUTHENTICATED_RETENTION_INVALID_ARTIFACT_BINDING"
            }
            Self::InvalidReferenceManifest => {
                "EVIDENTRAIL_AUTHENTICATED_RETENTION_INVALID_REFERENCE_MANIFEST"
            }
            Self::SnapshotProjectionFailed => {
                "EVIDENTRAIL_AUTHENTICATED_RETENTION_SNAPSHOT_PROJECTION_FAILED"
            }
            Self::RepositoryFailed => "EVIDENTRAIL_AUTHENTICATED_RETENTION_REPOSITORY_FAILED",
            Self::ReferenceUnavailable => "EVIDENTRAIL_AUTHENTICATED_RETENTION_REFERENCE_UNAVAILABLE",
            Self::InsufficientExpansionBudget => {
                "EVIDENTRAIL_AUTHENTICATED_RETENTION_INSUFFICIENT_EXPANSION_BUDGET"
            }
            Self::ArithmeticOverflow => "EVIDENTRAIL_AUTHENTICATED_RETENTION_ARITHMETIC_OVERFLOW",
        }
    }
}

impl fmt::Debug for AuthenticatedEncryptedRetentionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedEncryptedRetentionErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for AuthenticatedEncryptedRetentionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for AuthenticatedEncryptedRetentionErrorV1 {}

/// Contentless publication facts returned only after the exact typed manifest,
/// every event frame, and provider key seal have become authoritative in the
/// process-local encrypted repository.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedRetentionPublicationV1 {
    result_id: evidentrail_schema::ResultId,
    persisted_event_count: usize,
    registered_reference_count: usize,
    published_alias_count: usize,
}

impl AuthenticatedRetentionPublicationV1 {
    #[must_use]
    pub const fn result_id(self) -> evidentrail_schema::ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn persisted_event_count(self) -> usize {
        self.persisted_event_count
    }

    #[must_use]
    pub const fn registered_reference_count(self) -> usize {
        self.registered_reference_count
    }

    #[must_use]
    pub const fn published_alias_count(self) -> usize {
        self.published_alias_count
    }
}

impl fmt::Debug for AuthenticatedRetentionPublicationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedRetentionPublicationV1")
            .field("persisted_event_count", &self.persisted_event_count)
            .field(
                "registered_reference_count",
                &self.registered_reference_count,
            )
            .field("published_alias_count", &self.published_alias_count)
            .finish()
    }
}

/// Atomic, exact-only expansion of one retained capability.
///
/// Each event owner contains one complete AEAD-opened authorized-outcome
/// frame. Dropping the response zeroizes those owned plaintext allocations.
pub struct AuthenticatedRetentionExpansionV1 {
    result_id: evidentrail_schema::ResultId,
    reference_id: EvidenceReferenceId,
    events: Vec<OpenedEncryptedCoreResultEventV1>,
    returned_bytes: usize,
}

impl AuthenticatedRetentionExpansionV1 {
    #[must_use]
    pub const fn result_id(&self) -> evidentrail_schema::ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn reference_id(&self) -> EvidenceReferenceId {
        self.reference_id
    }

    #[must_use]
    pub fn events(&self) -> &[OpenedEncryptedCoreResultEventV1] {
        &self.events
    }

    #[must_use]
    pub const fn returned_bytes(&self) -> usize {
        self.returned_bytes
    }

    /// Exact encrypted expansion never returns a prefix.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        false
    }
}

impl fmt::Debug for AuthenticatedRetentionExpansionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedRetentionExpansionV1")
            .field("relation", &ExpansionRelationV1::Exact)
            .field("event_count", &self.events.len())
            .field("returned_bytes", &self.returned_bytes)
            .field("truncated", &false)
            .finish()
    }
}

pub(crate) struct FrozenReferenceV1 {
    pub(crate) reference: EvidenceReferenceV1,
    pub(crate) ordered_event_ids: Vec<EventId>,
}

struct RetainedResultMetadataV1 {
    expected: ExpectedCoreResultManifestContextV1,
    references: BTreeMap<EvidenceReferenceId, FrozenReferenceV1>,
    aliases: Vec<EvidenceReferenceId>,
}

pub(crate) struct PreparedReferenceManifestV1 {
    pub(crate) result_id: evidentrail_schema::ResultId,
    pub(crate) references: BTreeMap<EvidenceReferenceId, FrozenReferenceV1>,
    pub(crate) aliases: Vec<EvidenceReferenceId>,
}

/// Provider-generic process-local encrypted retention for finalized artifacts.
///
/// The adapter owns ciphertext/key-provider coordination and frozen reference
/// metadata only. It never owns an `EventLedger`, rendered artifact, question,
/// source path, or plaintext product store.
pub struct AuthenticatedEncryptedRetentionV1<P> {
    repository: MemoryEncryptedCoreResultRepositoryV1<P>,
    results: BTreeMap<evidentrail_schema::ResultId, RetainedResultMetadataV1>,
}

impl<P: KeyProviderV1> AuthenticatedEncryptedRetentionV1<P> {
    #[must_use]
    pub fn new(repository: MemoryEncryptedCoreResultRepositoryV1<P>) -> Self {
        Self {
            repository,
            results: BTreeMap::new(),
        }
    }

    /// Publish a finalized exact-passthrough artifact without retaining its
    /// rendered text or evidence-byte copies.
    fn retain_passthrough_result(
        &mut self,
        key_context: &CreatingKeyContextV1,
        ledger: &EventLedger,
        result: &RenderedProductResultV1,
        additional_references: impl IntoIterator<Item = EvidenceReferenceV1>,
    ) -> Result<AuthenticatedRetentionPublicationV1, AuthenticatedEncryptedRetentionErrorV1> {
        if result.result_id() != key_context.result_id()
            || !fixed_product_lifetime_matches(
                result.expires_at(),
                key_context.created_unix_nanos(),
                key_context.expires_unix_nanos(),
            )
        {
            return Err(AuthenticatedEncryptedRetentionErrorV1::InvalidArtifactBinding);
        }
        let prepared = prepare_passthrough_manifest(
            key_context,
            ledger,
            result.artifact(),
            additional_references,
        )?;
        self.publish(key_context, ledger, prepared)
    }

    /// Publish a finalized production compiled artifact. `additional_references`
    /// preserves full capabilities issued before compilation; they remain
    /// addressable by ID but never become short aliases unless the rendered
    /// artifact displays them.
    fn retain_compiled_result(
        &mut self,
        key_context: &CreatingKeyContextV1,
        ledger: &EventLedger,
        result: &CompiledProductResultV1,
        additional_references: impl IntoIterator<Item = EvidenceReferenceV1>,
    ) -> Result<AuthenticatedRetentionPublicationV1, AuthenticatedEncryptedRetentionErrorV1> {
        if result.result_id() != key_context.result_id()
            || !fixed_product_lifetime_matches(
                result.expires_at(),
                key_context.created_unix_nanos(),
                key_context.expires_unix_nanos(),
            )
        {
            return Err(AuthenticatedEncryptedRetentionErrorV1::InvalidArtifactBinding);
        }
        let prepared = prepare_compiled_manifest(
            key_context,
            ledger,
            result.artifact(),
            additional_references,
        )?;
        self.publish(key_context, ledger, prepared)
    }

    fn publish(
        &mut self,
        key_context: &CreatingKeyContextV1,
        ledger: &EventLedger,
        prepared: PreparedReferenceManifestV1,
    ) -> Result<AuthenticatedRetentionPublicationV1, AuthenticatedEncryptedRetentionErrorV1> {
        let result_id = key_context.result_id();
        if prepared.result_id != result_id {
            return Err(AuthenticatedEncryptedRetentionErrorV1::InvalidArtifactBinding);
        }
        if self.results.contains_key(&result_id) {
            return Err(AuthenticatedEncryptedRetentionErrorV1::DuplicateResult);
        }

        // Construct every fallible metadata value before repository mutation.
        // After a successful seal, installation below is a single infallible
        // map insert, so an encrypted orphan cannot be published without its
        // matching immutable capability metadata.
        let expected = ExpectedCoreResultManifestContextV1::new(
            result_id,
            ledger.source_identity_digest(),
            ledger.acquisition_receipt_id(),
            key_context.created_unix_nanos(),
            key_context.expires_unix_nanos(),
        )
        .map_err(|_| AuthenticatedEncryptedRetentionErrorV1::SnapshotProjectionFailed)?;

        self.repository
            .begin_staged_result(
                key_context,
                ledger.source_identity_digest(),
                ledger.acquisition_receipt_id(),
            )
            .map_err(|_| AuthenticatedEncryptedRetentionErrorV1::RepositoryFailed)?;

        let publication = self.publish_staged(key_context, ledger, &prepared);
        if let Err(error) = publication {
            // Destruction is best effort. Even if ciphertext cleanup is
            // fault-injected, no reference metadata is published and the
            // provider key authority is destroyed first by the repository.
            let _ = self.repository.destroy(&result_id);
            return Err(error);
        }

        let persisted_event_count = ledger.len();
        let registered_reference_count = prepared.references.len();
        let published_alias_count = prepared.aliases.len();
        let prior = self.results.insert(
            result_id,
            RetainedResultMetadataV1 {
                expected,
                references: prepared.references,
                aliases: prepared.aliases,
            },
        );
        debug_assert!(prior.is_none());
        Ok(AuthenticatedRetentionPublicationV1 {
            result_id,
            persisted_event_count,
            registered_reference_count,
            published_alias_count,
        })
    }

    fn publish_staged(
        &self,
        key_context: &CreatingKeyContextV1,
        ledger: &EventLedger,
        prepared: &PreparedReferenceManifestV1,
    ) -> Result<(), AuthenticatedEncryptedRetentionErrorV1> {
        let result_id = key_context.result_id();
        for event in ledger.events() {
            self.repository
                .stage_authorized_event(
                    &result_id,
                    event.id(),
                    event.exactness_basis(),
                    event.raw(),
                )
                .map_err(|_| AuthenticatedEncryptedRetentionErrorV1::RepositoryFailed)?;
        }
        if ledger.is_empty() {
            // The catalog contract is nonempty. This structural seal frame
            // contains no source bytes and creates no event-index entry.
            self.repository
                .stage_frame(&result_id, FrameObjectKindV1::AcquisitionSeal, b"")
                .map_err(|_| AuthenticatedEncryptedRetentionErrorV1::RepositoryFailed)?;
        }

        let alias_entries = prepared
            .aliases
            .iter()
            .enumerate()
            .map(|(index, reference_id)| {
                let frozen = prepared
                    .references
                    .get(reference_id)
                    .ok_or(AuthenticatedEncryptedRetentionErrorV1::InvalidReferenceManifest)?;
                let ordinal = u16::try_from(index + 1)
                    .map_err(|_| AuthenticatedEncryptedRetentionErrorV1::ArithmeticOverflow)?;
                DisplayedAliasManifestEntryV1::new(
                    result_id,
                    ordinal,
                    frozen.reference.clone(),
                    frozen.ordered_event_ids.iter().copied(),
                )
                .map_err(|_| AuthenticatedEncryptedRetentionErrorV1::InvalidReferenceManifest)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let alias_manifest = DisplayedAliasManifestV1::new(
            result_id,
            UnixTimestampNanos::new(i128::from(key_context.expires_unix_nanos())),
            alias_entries,
        )
        .map_err(|_| AuthenticatedEncryptedRetentionErrorV1::InvalidReferenceManifest)?;
        self.repository
            .stage_displayed_alias_manifest(&result_id, &alias_manifest)
            .map_err(|_| AuthenticatedEncryptedRetentionErrorV1::RepositoryFailed)?;

        let catalog = self
            .repository
            .staged_segment_catalog(&result_id)
            .map_err(|_| AuthenticatedEncryptedRetentionErrorV1::RepositoryFailed)?;
        let event_index = self
            .repository
            .staged_event_expansion_index(&result_id)
            .map_err(|_| AuthenticatedEncryptedRetentionErrorV1::RepositoryFailed)?;
        let ledger_event_count = u64::try_from(ledger.len())
            .map_err(|_| AuthenticatedEncryptedRetentionErrorV1::ArithmeticOverflow)?;
        if event_index.entry_count() != ledger_event_count {
            return Err(AuthenticatedEncryptedRetentionErrorV1::SnapshotProjectionFailed);
        }
        let source_outcomes = SourceOutcomeTableV1::new(ledger.acquisition_receipt(), &event_index)
            .map_err(|_| AuthenticatedEncryptedRetentionErrorV1::SnapshotProjectionFailed)?;
        let completion = AcquisitionCompletionRecordV1::new_verified(
            ledger.fetch_completion(),
            ledger.acquisition_receipt(),
        )
        .map_err(|_| AuthenticatedEncryptedRetentionErrorV1::SnapshotProjectionFailed)?;
        let components =
            CoreManifestComponentsV1::new(&catalog, &event_index, &source_outcomes, &completion)
                .map_err(|_| AuthenticatedEncryptedRetentionErrorV1::SnapshotProjectionFailed)?;
        let manifest = CoreResultManifestV1::new(
            result_id,
            ledger.source_identity_digest(),
            ledger.acquisition_receipt_id(),
            &components,
        )
        .map_err(|_| AuthenticatedEncryptedRetentionErrorV1::SnapshotProjectionFailed)?;
        self.repository
            .seal_staged_result(&result_id, &manifest)
            .map_err(|_| AuthenticatedEncryptedRetentionErrorV1::RepositoryFailed)?;
        Ok(())
    }

    /// Resolve a final artifact's short alias only inside the supplied result,
    /// then perform one atomic exact expansion.
    pub fn expand_alias(
        &self,
        request: AliasExpansionRequestV1,
        now: UnixTimestampNanos,
    ) -> Result<AuthenticatedRetentionExpansionV1, AuthenticatedEncryptedRetentionErrorV1> {
        if request.relation() != ExpansionRelationV1::Exact
            || request.alias().result_id() != request.result_id()
        {
            return Err(AuthenticatedEncryptedRetentionErrorV1::ReferenceUnavailable);
        }
        let retained = self
            .results
            .get(&request.result_id())
            .ok_or(AuthenticatedEncryptedRetentionErrorV1::ReferenceUnavailable)?;
        let alias_index = usize::from(request.alias().one_based_ordinal() - 1);
        let reference_id = *retained
            .aliases
            .get(alias_index)
            .ok_or(AuthenticatedEncryptedRetentionErrorV1::ReferenceUnavailable)?;
        self.expand_frozen(request.result_id(), reference_id, request.limit(), now)
    }

    /// Expand one already-issued full reference. V1 deliberately supports only
    /// `Exact`; lane/global neighborhood relations require authenticated
    /// ordering indexes that this narrow retained metadata does not contain.
    pub fn expand_reference(
        &self,
        request: ExpansionRequestV1,
        now: UnixTimestampNanos,
    ) -> Result<AuthenticatedRetentionExpansionV1, AuthenticatedEncryptedRetentionErrorV1> {
        if request.relation() != ExpansionRelationV1::Exact {
            return Err(AuthenticatedEncryptedRetentionErrorV1::ReferenceUnavailable);
        }
        self.expand_frozen(
            request.result_id(),
            request.reference_id(),
            request.limit(),
            now,
        )
    }

    fn expand_frozen(
        &self,
        result_id: evidentrail_schema::ResultId,
        reference_id: EvidenceReferenceId,
        limit: evidentrail_store::ExpansionLimitV1,
        now: UnixTimestampNanos,
    ) -> Result<AuthenticatedRetentionExpansionV1, AuthenticatedEncryptedRetentionErrorV1> {
        let retained = self
            .results
            .get(&result_id)
            .ok_or(AuthenticatedEncryptedRetentionErrorV1::ReferenceUnavailable)?;
        let frozen = retained
            .references
            .get(&reference_id)
            .ok_or(AuthenticatedEncryptedRetentionErrorV1::ReferenceUnavailable)?;
        if now.get() < i128::from(retained.expected.created_unix_nanos())
            || now.get() >= i128::from(retained.expected.expires_unix_nanos())
        {
            return Err(AuthenticatedEncryptedRetentionErrorV1::ReferenceUnavailable);
        }
        frozen
            .reference
            .authorize(result_id, ExpansionRelationV1::Exact, now)
            .map_err(|_| AuthenticatedEncryptedRetentionErrorV1::ReferenceUnavailable)?;
        if frozen.ordered_event_ids.len() > limit.max_events() {
            return Err(AuthenticatedEncryptedRetentionErrorV1::InsufficientExpansionBudget);
        }

        let mut events = Vec::with_capacity(frozen.ordered_event_ids.len());
        let mut returned_bytes = 0_usize;
        for event_id in &frozen.ordered_event_ids {
            let opened = self
                .repository
                .open_stored_event(retained.expected, *event_id)
                .map_err(|_| AuthenticatedEncryptedRetentionErrorV1::ReferenceUnavailable)?;
            returned_bytes = returned_bytes
                .checked_add(opened.as_bytes().len())
                .ok_or(AuthenticatedEncryptedRetentionErrorV1::ArithmeticOverflow)?;
            if returned_bytes > limit.max_bytes() {
                return Err(AuthenticatedEncryptedRetentionErrorV1::InsufficientExpansionBudget);
            }
            events.push(opened);
        }
        Ok(AuthenticatedRetentionExpansionV1 {
            result_id,
            reference_id,
            events,
            returned_bytes,
        })
    }

    /// Destroy key authority and remove this process's frozen capability map.
    pub fn destroy(
        &mut self,
        result_id: evidentrail_schema::ResultId,
    ) -> Result<EncryptedCoreResultDestroyOutcomeV1, AuthenticatedEncryptedRetentionErrorV1> {
        match self.repository.destroy(&result_id) {
            Ok(outcome) => {
                self.results.remove(&result_id);
                Ok(outcome)
            }
            Err(EncryptedCoreResultRepositoryErrorV1::CiphertextCleanupFailed) => {
                // The repository destroys key authority before attempting
                // ciphertext cleanup. Remove capabilities immediately so this
                // process does not count or present an unreadable result.
                self.results.remove(&result_id);
                Err(AuthenticatedEncryptedRetentionErrorV1::RepositoryFailed)
            }
            Err(_) => Err(AuthenticatedEncryptedRetentionErrorV1::RepositoryFailed),
        }
    }

    /// Best-effort process-local expiry cleanup. Results whose key provider is
    /// temporarily unavailable remain counted but expansion is still denied by
    /// the fixed authenticated time boundary.
    pub fn cleanup_expired(&mut self, now: UnixTimestampNanos) -> usize {
        let expired = self
            .results
            .iter()
            .filter_map(|(result_id, retained)| {
                (now.get() >= i128::from(retained.expected.expires_unix_nanos()))
                    .then_some(*result_id)
            })
            .collect::<Vec<_>>();
        let before = self.results.len();
        for result_id in expired {
            let _ = self.destroy(result_id);
        }
        before - self.results.len()
    }

    #[must_use]
    pub fn result_count(&self) -> usize {
        self.results.len()
    }

    /// Publish the ciphertext bundle for one already-finalized retained result
    /// through the authenticated filesystem coordinator.
    ///
    /// The coordinator first asks this retention repository to authenticate
    /// and export the fully sealed result. This method writes no ledger,
    /// rendered text, question, or source path. The frozen displayed-alias
    /// capability manifest is already part of the authenticated ciphertext;
    /// restarted V1 recovery may expose only those exact aliases. It does not
    /// restore the rendered artifact or provide raw EventId lookup.
    #[cfg(unix)]
    pub fn publish_restart_bundle<R: KeyProviderV1 + ?Sized>(
        &self,
        coordinator: &AuthenticatedFilesystemRestartCoordinatorV1<R>,
        result_id: evidentrail_schema::ResultId,
        now: UnixTimestampNanos,
    ) -> Result<FilesystemBundlePublicationV1, AuthenticatedFilesystemRestartErrorV1> {
        let retained = self
            .results
            .get(&result_id)
            .ok_or(AuthenticatedFilesystemRestartErrorV1::ResultUnavailable)?;
        coordinator.publish_from_repository(&self.repository, retained.expected, now)
    }

    /// Return the exact independently retained authority context required by
    /// a later authenticated restart. This is opaque authority metadata, not
    /// source discovery and not proof that any filesystem publication exists.
    #[cfg(unix)]
    pub fn expected_restart_context(
        &self,
        result_id: evidentrail_schema::ResultId,
    ) -> Result<ExpectedCoreResultManifestContextV1, AuthenticatedFilesystemRestartErrorV1> {
        self.results
            .get(&result_id)
            .map(|retained| retained.expected)
            .ok_or(AuthenticatedFilesystemRestartErrorV1::ResultUnavailable)
    }

    #[cfg(any(test, feature = "internal-test-provider"))]
    pub fn repository_for_test(&self) -> &MemoryEncryptedCoreResultRepositoryV1<P> {
        &self.repository
    }
}

impl<P> fmt::Debug for AuthenticatedEncryptedRetentionV1<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedEncryptedRetentionV1")
            .field("backend", &"process_local_authenticated_encrypted")
            .field("result_count", &self.results.len())
            .finish()
    }
}

impl MemoryProductV1 {
    /// Transactionally replace this product's plaintext passthrough ledger with
    /// process-local authenticated encrypted retention. The plaintext entry is
    /// deleted only after encrypted publication succeeds.
    pub fn migrate_passthrough_to_authenticated_retention<P: KeyProviderV1>(
        &mut self,
        retention: &mut AuthenticatedEncryptedRetentionV1<P>,
        key_context: &CreatingKeyContextV1,
        result: &RenderedProductResultV1,
        now: UnixTimestampNanos,
    ) -> Result<AuthenticatedRetentionPublicationV1, AuthenticatedEncryptedRetentionErrorV1> {
        let result_id = result.result_id();
        let references = self
            .store
            .registered_reference_metadata(result_id, now)
            .map_err(|_| AuthenticatedEncryptedRetentionErrorV1::PlaintextResultUnavailable)?;
        let publication = {
            let ledger = self
                .store
                .ledger(result_id, now)
                .map_err(|_| AuthenticatedEncryptedRetentionErrorV1::PlaintextResultUnavailable)?;
            retention.retain_passthrough_result(key_context, ledger, result, references)?
        };
        self.store.delete(result_id);
        self.retained_compilations.remove(&result_id);
        Ok(publication)
    }

    /// Transactionally replace this product's plaintext compiled-result ledger
    /// while preserving every full reference issued before compilation. Only
    /// the packet references displayed by the final artifact become aliases.
    pub fn migrate_compiled_to_authenticated_retention<P: KeyProviderV1>(
        &mut self,
        retention: &mut AuthenticatedEncryptedRetentionV1<P>,
        key_context: &CreatingKeyContextV1,
        result: &CompiledProductResultV1,
        now: UnixTimestampNanos,
    ) -> Result<AuthenticatedRetentionPublicationV1, AuthenticatedEncryptedRetentionErrorV1> {
        let result_id = result.result_id();
        let references = self
            .store
            .registered_reference_metadata(result_id, now)
            .map_err(|_| AuthenticatedEncryptedRetentionErrorV1::PlaintextResultUnavailable)?;
        let publication = {
            let ledger = self
                .store
                .ledger(result_id, now)
                .map_err(|_| AuthenticatedEncryptedRetentionErrorV1::PlaintextResultUnavailable)?;
            retention.retain_compiled_result(key_context, ledger, result, references)?
        };
        self.store.delete(result_id);
        self.retained_compilations.remove(&result_id);
        Ok(publication)
    }
}

pub(crate) fn prepare_passthrough_manifest(
    key_context: &CreatingKeyContextV1,
    ledger: &EventLedger,
    artifact: &OwnedRenderedPassthroughBriefV1,
    additional_references: impl IntoIterator<Item = EvidenceReferenceV1>,
) -> Result<PreparedReferenceManifestV1, AuthenticatedEncryptedRetentionErrorV1> {
    let brief = artifact.brief();
    validate_brief_authority(
        key_context,
        brief.result_id(),
        brief.reference_authorized_at(),
        brief.plan_digest() == ledger.plan_digest()
            && brief.status().acquisition() == ledger.fetch_completion().completeness(),
    )?;
    if brief.evidence().len() != ledger.len() {
        return Err(AuthenticatedEncryptedRetentionErrorV1::InvalidArtifactBinding);
    }

    let mut references = BTreeMap::new();
    let mut aliases = Vec::with_capacity(brief.evidence().len());
    for (ordinal, (evidence, event)) in brief.evidence().iter().zip(ledger.events()).enumerate() {
        if evidence.ordinal() != ordinal
            || evidence.event_id() != event.id()
            || evidence.exactness_basis() != event.exactness_basis()
            || evidence.authorized_bytes() != event.raw()
        {
            return Err(AuthenticatedEncryptedRetentionErrorV1::InvalidArtifactBinding);
        }
        let frozen = freeze_displayed_reference(
            key_context,
            ledger,
            evidence.reference(),
            brief.reference_authorized_at(),
            &[event.id()],
        )?;
        aliases.push(evidence.reference().id());
        insert_frozen(&mut references, frozen)?;
    }
    merge_additional_references(key_context, ledger, additional_references, &mut references)?;
    validate_aliases(&aliases, &references)?;
    Ok(PreparedReferenceManifestV1 {
        result_id: brief.result_id(),
        references,
        aliases,
    })
}

pub(crate) fn prepare_compiled_manifest(
    key_context: &CreatingKeyContextV1,
    ledger: &EventLedger,
    artifact: &OwnedRenderedCompiledBriefV1,
    additional_references: impl IntoIterator<Item = EvidenceReferenceV1>,
) -> Result<PreparedReferenceManifestV1, AuthenticatedEncryptedRetentionErrorV1> {
    let brief = artifact.brief();
    validate_brief_authority(
        key_context,
        brief.result_id(),
        brief.reference_authorized_at(),
        brief.plan_digest() == ledger.plan_digest()
            && brief.status().acquisition() == ledger.fetch_completion().completeness(),
    )?;
    if brief.evidence().is_empty() {
        return Err(AuthenticatedEncryptedRetentionErrorV1::InvalidArtifactBinding);
    }

    let positions = ledger_positions(ledger);
    let mut displayed_events = BTreeSet::new();
    let mut references = BTreeMap::new();
    let mut aliases = Vec::with_capacity(brief.evidence().len());
    for (ordinal, packet) in brief.evidence().iter().enumerate() {
        if packet.ordinal() != ordinal || packet.events().is_empty() {
            return Err(AuthenticatedEncryptedRetentionErrorV1::InvalidArtifactBinding);
        }
        let ordered_event_ids = packet
            .events()
            .iter()
            .map(|event| event.event_id())
            .collect::<Vec<_>>();
        validate_strict_ledger_order(&ordered_event_ids, &positions)?;
        let canonical_set = packet
            .canonical_event_ids()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if canonical_set.len() != packet.canonical_event_ids().len()
            || canonical_set != ordered_event_ids.iter().copied().collect()
        {
            return Err(AuthenticatedEncryptedRetentionErrorV1::InvalidArtifactBinding);
        }
        for event_evidence in packet.events() {
            let event = ledger
                .event(event_evidence.event_id())
                .map_err(|_| AuthenticatedEncryptedRetentionErrorV1::InvalidArtifactBinding)?;
            if !displayed_events.insert(event.id())
                || event_evidence.exactness_basis() != event.exactness_basis()
                || event_evidence.authorized_bytes() != event.raw()
            {
                return Err(AuthenticatedEncryptedRetentionErrorV1::InvalidArtifactBinding);
            }
        }
        let frozen = freeze_displayed_reference(
            key_context,
            ledger,
            packet.reference(),
            brief.reference_authorized_at(),
            &ordered_event_ids,
        )?;
        aliases.push(packet.reference().id());
        insert_frozen(&mut references, frozen)?;
    }
    merge_additional_references(key_context, ledger, additional_references, &mut references)?;
    validate_aliases(&aliases, &references)?;
    Ok(PreparedReferenceManifestV1 {
        result_id: brief.result_id(),
        references,
        aliases,
    })
}

fn validate_brief_authority(
    key_context: &CreatingKeyContextV1,
    artifact_result_id: evidentrail_schema::ResultId,
    reference_authorized_at: UnixTimestampNanos,
    domain_binding_matches: bool,
) -> Result<(), AuthenticatedEncryptedRetentionErrorV1> {
    if artifact_result_id != key_context.result_id()
        || reference_authorized_at.get() < i128::from(key_context.created_unix_nanos())
        || reference_authorized_at.get() >= i128::from(key_context.expires_unix_nanos())
        || !domain_binding_matches
    {
        return Err(AuthenticatedEncryptedRetentionErrorV1::InvalidArtifactBinding);
    }
    Ok(())
}

fn fixed_product_lifetime_matches(
    expires_at: UnixTimestampNanos,
    key_created_unix_nanos: i64,
    key_expires_unix_nanos: i64,
) -> bool {
    expires_at.get() == i128::from(key_expires_unix_nanos)
        && expires_at
            .get()
            .checked_sub(DEFAULT_RESULT_TTL_NANOS)
            .is_some_and(|created_at| created_at == i128::from(key_created_unix_nanos))
}

fn merge_additional_references(
    key_context: &CreatingKeyContextV1,
    ledger: &EventLedger,
    additional_references: impl IntoIterator<Item = EvidenceReferenceV1>,
    references: &mut BTreeMap<EvidenceReferenceId, FrozenReferenceV1>,
) -> Result<(), AuthenticatedEncryptedRetentionErrorV1> {
    let positions = ledger_positions(ledger);
    for reference in additional_references {
        validate_reference_authority(key_context, &reference)?;
        let mut event_ids = reference
            .targets()
            .iter()
            .map(|target| match target {
                EvidenceTargetRef::Event(event_id) if positions.contains_key(event_id) => {
                    Ok(*event_id)
                }
                EvidenceTargetRef::Event(_) | EvidenceTargetRef::Block(_) => {
                    Err(AuthenticatedEncryptedRetentionErrorV1::InvalidReferenceManifest)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        event_ids.sort_unstable_by_key(|event_id| positions[event_id]);
        let frozen = FrozenReferenceV1 {
            reference,
            ordered_event_ids: event_ids,
        };
        insert_frozen(references, frozen)?;
    }
    Ok(())
}

fn freeze_displayed_reference(
    key_context: &CreatingKeyContextV1,
    ledger: &EventLedger,
    reference: &EvidenceReferenceV1,
    reference_authorized_at: UnixTimestampNanos,
    ordered_event_ids: &[EventId],
) -> Result<FrozenReferenceV1, AuthenticatedEncryptedRetentionErrorV1> {
    validate_reference_authority(key_context, reference)?;
    if reference.issued_at() != reference_authorized_at {
        return Err(AuthenticatedEncryptedRetentionErrorV1::InvalidReferenceManifest);
    }
    let reference_events = reference
        .targets()
        .iter()
        .map(|target| match target {
            EvidenceTargetRef::Event(event_id) if ledger.contains(*event_id) => Ok(*event_id),
            EvidenceTargetRef::Event(_) | EvidenceTargetRef::Block(_) => {
                Err(AuthenticatedEncryptedRetentionErrorV1::InvalidReferenceManifest)
            }
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let ordered_set = ordered_event_ids.iter().copied().collect::<BTreeSet<_>>();
    if reference_events.len() != reference.targets().len()
        || ordered_set.len() != ordered_event_ids.len()
        || reference_events != ordered_set
    {
        return Err(AuthenticatedEncryptedRetentionErrorV1::InvalidReferenceManifest);
    }
    Ok(FrozenReferenceV1 {
        reference: reference.clone(),
        ordered_event_ids: ordered_event_ids.to_vec(),
    })
}

fn validate_reference_authority(
    key_context: &CreatingKeyContextV1,
    reference: &EvidenceReferenceV1,
) -> Result<(), AuthenticatedEncryptedRetentionErrorV1> {
    let created_at = UnixTimestampNanos::new(i128::from(key_context.created_unix_nanos()));
    let expires_at = UnixTimestampNanos::new(i128::from(key_context.expires_unix_nanos()));
    if reference.result_id() != key_context.result_id()
        || reference.issued_at() < created_at
        || reference.issued_at() >= expires_at
        || reference.expires_at() != expires_at
        || reference
            .authorize(
                key_context.result_id(),
                ExpansionRelationV1::Exact,
                reference.issued_at(),
            )
            .is_err()
    {
        return Err(AuthenticatedEncryptedRetentionErrorV1::InvalidReferenceManifest);
    }
    Ok(())
}

fn insert_frozen(
    references: &mut BTreeMap<EvidenceReferenceId, FrozenReferenceV1>,
    frozen: FrozenReferenceV1,
) -> Result<(), AuthenticatedEncryptedRetentionErrorV1> {
    match references.get(&frozen.reference.id()) {
        Some(existing)
            if existing.reference == frozen.reference
                && existing.ordered_event_ids == frozen.ordered_event_ids =>
        {
            Ok(())
        }
        Some(_) => Err(AuthenticatedEncryptedRetentionErrorV1::InvalidReferenceManifest),
        None => {
            references.insert(frozen.reference.id(), frozen);
            Ok(())
        }
    }
}

fn validate_aliases(
    aliases: &[EvidenceReferenceId],
    references: &BTreeMap<EvidenceReferenceId, FrozenReferenceV1>,
) -> Result<(), AuthenticatedEncryptedRetentionErrorV1> {
    let unique = aliases.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() != aliases.len()
        || aliases
            .iter()
            .any(|reference_id| !references.contains_key(reference_id))
    {
        return Err(AuthenticatedEncryptedRetentionErrorV1::InvalidReferenceManifest);
    }
    Ok(())
}

fn ledger_positions(ledger: &EventLedger) -> BTreeMap<EventId, usize> {
    ledger
        .events()
        .iter()
        .enumerate()
        .map(|(position, event)| (event.id(), position))
        .collect()
}

fn validate_strict_ledger_order(
    event_ids: &[EventId],
    positions: &BTreeMap<EventId, usize>,
) -> Result<(), AuthenticatedEncryptedRetentionErrorV1> {
    let mut previous = None;
    for event_id in event_ids {
        let position = positions
            .get(event_id)
            .copied()
            .ok_or(AuthenticatedEncryptedRetentionErrorV1::InvalidArtifactBinding)?;
        if previous.is_some_and(|prior| prior >= position) {
            return Err(AuthenticatedEncryptedRetentionErrorV1::InvalidArtifactBinding);
        }
        previous = Some(position);
    }
    Ok(())
}
