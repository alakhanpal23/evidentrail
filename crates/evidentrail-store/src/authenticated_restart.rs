//! Authenticated, process-local restart coordination over ciphertext bundles.
//!
//! This module composes the memory encrypted repository, the Unix
//! ciphertext-only filesystem substrate, and an independently retained
//! `KeyProviderV1`. A filesystem object is never visible through the recovered
//! repository until the provider record, full caller-supplied authority,
//! manifest AEAD, seal binding, catalog, frame chain, and canonical bundle have
//! all authenticated. Invalid candidates are renamed into create-only
//! quarantine and are never deleted.
//!
//! The independently supplied expected context is an authority input, not a
//! fact learned from an unauthenticated filename. This process-local bridge
//! makes no rollback-prevention, cross-process-locking, sudden-power-loss
//! durability, Keychain, or complete product-recovery claim.

use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;

use evidentrail_core::{ExpansionRelationV1, UnixTimestampNanos};
use evidentrail_schema::{EventId, EvidenceReferenceId, ResultId};
use evidentrail_snapshot_format::{ExpectedCoreResultManifestContextV1, ResultKeyRecordStateV1};

use crate::{
    AliasExpansionRequestV1, DisplayedAliasManifestV1, EncryptedCoreResultDestroyOutcomeV1,
    EncryptedCoreResultRepositoryErrorV1, ExpectedKeyContextV1, FilesystemBundlePublicationV1,
    FilesystemSealedBundleErrorV1, FilesystemSealedBundleStoreV1, KeyProviderErrorV1,
    KeyProviderV1, KeyRecordListStateV1, MemoryEncryptedCoreResultRepositoryV1,
    OpenedEncryptedCoreResultEventV1, SealedEncryptedCoreResultBundleV1,
};

/// Stable, contentless authenticated-restart failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatedFilesystemRestartErrorV1 {
    OutsideValidity,
    SourceRepositoryUnavailable,
    FilesystemUnavailable,
    ProviderUnavailable,
    CandidateQuarantined,
    QuarantineFailed,
    CapacityUnavailable,
    RepositoryUnavailable,
    ResultUnavailable,
    EventUnavailable,
    AliasUnavailable,
    InsufficientExpansionBudget,
}

impl AuthenticatedFilesystemRestartErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::OutsideValidity => "EVIDENTRAIL_AUTHENTICATED_RESTART_OUTSIDE_VALIDITY",
            Self::SourceRepositoryUnavailable => {
                "EVIDENTRAIL_AUTHENTICATED_RESTART_SOURCE_REPOSITORY_UNAVAILABLE"
            }
            Self::FilesystemUnavailable => "EVIDENTRAIL_AUTHENTICATED_RESTART_FILESYSTEM_UNAVAILABLE",
            Self::ProviderUnavailable => "EVIDENTRAIL_AUTHENTICATED_RESTART_PROVIDER_UNAVAILABLE",
            Self::CandidateQuarantined => "EVIDENTRAIL_AUTHENTICATED_RESTART_CANDIDATE_QUARANTINED",
            Self::QuarantineFailed => "EVIDENTRAIL_AUTHENTICATED_RESTART_QUARANTINE_FAILED",
            Self::CapacityUnavailable => "EVIDENTRAIL_AUTHENTICATED_RESTART_CAPACITY_UNAVAILABLE",
            Self::RepositoryUnavailable => "EVIDENTRAIL_AUTHENTICATED_RESTART_REPOSITORY_UNAVAILABLE",
            Self::ResultUnavailable => "EVIDENTRAIL_AUTHENTICATED_RESTART_RESULT_UNAVAILABLE",
            Self::EventUnavailable => "EVIDENTRAIL_AUTHENTICATED_RESTART_EVENT_UNAVAILABLE",
            Self::AliasUnavailable => "EVIDENTRAIL_AUTHENTICATED_RESTART_ALIAS_UNAVAILABLE",
            Self::InsufficientExpansionBudget => {
                "EVIDENTRAIL_AUTHENTICATED_RESTART_INSUFFICIENT_EXPANSION_BUDGET"
            }
        }
    }
}

impl fmt::Debug for AuthenticatedFilesystemRestartErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedFilesystemRestartErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for AuthenticatedFilesystemRestartErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for AuthenticatedFilesystemRestartErrorV1 {}

/// Whether authenticated recovery installed a new in-memory result or proved
/// that the byte-identical result was already visible.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatedFilesystemRecoveryDispositionV1 {
    Imported,
    AlreadyVisible,
}

impl AuthenticatedFilesystemRecoveryDispositionV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Imported => "EVIDENTRAIL_AUTHENTICATED_RESTART_IMPORTED",
            Self::AlreadyVisible => "EVIDENTRAIL_AUTHENTICATED_RESTART_ALREADY_VISIBLE",
        }
    }
}

impl fmt::Debug for AuthenticatedFilesystemRecoveryDispositionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedFilesystemRecoveryDispositionV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Contentless recovery publication returned only after full authentication.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedFilesystemRecoveryPublicationV1 {
    result_id: ResultId,
    disposition: AuthenticatedFilesystemRecoveryDispositionV1,
}

impl AuthenticatedFilesystemRecoveryPublicationV1 {
    #[must_use]
    pub const fn result_id(self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn disposition(self) -> AuthenticatedFilesystemRecoveryDispositionV1 {
        self.disposition
    }
}

impl fmt::Debug for AuthenticatedFilesystemRecoveryPublicationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedFilesystemRecoveryPublicationV1")
            .field("disposition", &self.disposition)
            .finish_non_exhaustive()
    }
}

/// Atomic exact expansion returned by a recovered displayed alias.
///
/// Every event owner contains one complete zeroizing AEAD-opened allocation.
/// If a later event or byte cap fails, all earlier temporary owners are dropped
/// before the error is returned.
pub struct RecoveredProductAliasExpansionV1 {
    result_id: ResultId,
    reference_id: EvidenceReferenceId,
    events: Vec<OpenedEncryptedCoreResultEventV1>,
    returned_bytes: usize,
}

impl RecoveredProductAliasExpansionV1 {
    #[must_use]
    pub const fn result_id(&self) -> ResultId {
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

    #[must_use]
    pub const fn truncated(&self) -> bool {
        false
    }
}

impl fmt::Debug for RecoveredProductAliasExpansionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveredProductAliasExpansionV1")
            .field("relation", &ExpansionRelationV1::Exact)
            .field("event_count", &self.events.len())
            .field("returned_bytes", &self.returned_bytes)
            .field("truncated", &false)
            .finish()
    }
}

/// Narrow recovered product capability.
///
/// It exposes no raw repository, EventId lookup, full-reference lookup,
/// neighborhood relation, source refresh, or mutable alias installation. The
/// authenticated frozen manifest is the only `E<n>` namespace it can resolve.
pub struct RecoveredExactAliasResultV1<P: KeyProviderV1 + ?Sized> {
    repository: Arc<MemoryEncryptedCoreResultRepositoryV1<Arc<P>>>,
    expected: ExpectedCoreResultManifestContextV1,
    manifest: DisplayedAliasManifestV1,
    disposition: AuthenticatedFilesystemRecoveryDispositionV1,
}

impl<P: KeyProviderV1 + ?Sized> RecoveredExactAliasResultV1<P> {
    #[must_use]
    pub const fn result_id(&self) -> ResultId {
        self.expected.result_id()
    }

    #[must_use]
    pub fn alias_count(&self) -> usize {
        self.manifest.entries().len()
    }

    #[must_use]
    pub const fn recovery_disposition(&self) -> AuthenticatedFilesystemRecoveryDispositionV1 {
        self.disposition
    }

    /// Resolve and expand one displayed exact alias atomically.
    pub fn expand_alias(
        &self,
        request: AliasExpansionRequestV1,
        now: UnixTimestampNanos,
    ) -> Result<RecoveredProductAliasExpansionV1, AuthenticatedFilesystemRestartErrorV1> {
        let limit = request.limit();
        if ensure_active(self.expected, now).is_err()
            || request.result_id() != self.expected.result_id()
            || request.alias().result_id() != self.expected.result_id()
            || request.relation() != ExpansionRelationV1::Exact
            || limit.before() != 0
            || limit.after() != 0
        {
            return Err(AuthenticatedFilesystemRestartErrorV1::AliasUnavailable);
        }
        let index = usize::from(request.alias().one_based_ordinal() - 1);
        let entry = self
            .manifest
            .entries()
            .get(index)
            .ok_or(AuthenticatedFilesystemRestartErrorV1::AliasUnavailable)?;
        if entry.ordinal() != request.alias().one_based_ordinal()
            || entry.allowed_relation() != ExpansionRelationV1::Exact
            || entry
                .reference()
                .authorize(self.expected.result_id(), ExpansionRelationV1::Exact, now)
                .is_err()
        {
            return Err(AuthenticatedFilesystemRestartErrorV1::AliasUnavailable);
        }
        if entry.ordered_event_ids().len() > limit.max_events() {
            return Err(AuthenticatedFilesystemRestartErrorV1::InsufficientExpansionBudget);
        }
        let mut events = Vec::with_capacity(entry.ordered_event_ids().len());
        let mut returned_bytes = 0usize;
        for event_id in entry.ordered_event_ids() {
            let opened = self
                .repository
                .open_stored_event(self.expected, *event_id)
                .map_err(|_| AuthenticatedFilesystemRestartErrorV1::AliasUnavailable)?;
            returned_bytes = returned_bytes
                .checked_add(opened.as_bytes().len())
                .ok_or(AuthenticatedFilesystemRestartErrorV1::InsufficientExpansionBudget)?;
            if returned_bytes > limit.max_bytes() {
                return Err(AuthenticatedFilesystemRestartErrorV1::InsufficientExpansionBudget);
            }
            events.push(opened);
        }
        Ok(RecoveredProductAliasExpansionV1 {
            result_id: self.expected.result_id(),
            reference_id: entry.reference().id(),
            events,
            returned_bytes,
        })
    }
}

impl<P: KeyProviderV1 + ?Sized> fmt::Debug for RecoveredExactAliasResultV1<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveredExactAliasResultV1")
            .field("alias_count", &self.manifest.entries().len())
            .field("allowed_relation", &ExpansionRelationV1::Exact)
            .field("recovery_disposition", &self.disposition)
            .finish_non_exhaustive()
    }
}

/// A fresh in-memory authenticated repository above one ciphertext directory.
///
/// The provider is shared by `Arc` only because it represents independently
/// retained key authority across process-local repository instances. The Arc
/// delegation clones no opened key material.
pub struct AuthenticatedFilesystemRestartCoordinatorV1<P: KeyProviderV1 + ?Sized> {
    filesystem: FilesystemSealedBundleStoreV1,
    provider: Arc<P>,
    repository: Arc<MemoryEncryptedCoreResultRepositoryV1<Arc<P>>>,
}

impl<P: KeyProviderV1 + ?Sized> AuthenticatedFilesystemRestartCoordinatorV1<P> {
    pub fn new(
        filesystem: FilesystemSealedBundleStoreV1,
        provider: Arc<P>,
        repository_capacity: usize,
    ) -> Result<Self, AuthenticatedFilesystemRestartErrorV1> {
        let repository = Arc::new(
            MemoryEncryptedCoreResultRepositoryV1::new(Arc::clone(&provider), repository_capacity)
                .map_err(map_repository_construction_error)?,
        );
        Ok(Self {
            filesystem,
            provider,
            repository,
        })
    }

    /// Authenticate a published source repository, export ciphertext only,
    /// then invoke the filesystem's ordered create-only publication protocol.
    pub fn publish_from_repository<Q: KeyProviderV1>(
        &self,
        source: &MemoryEncryptedCoreResultRepositoryV1<Q>,
        expected: ExpectedCoreResultManifestContextV1,
        now: UnixTimestampNanos,
    ) -> Result<FilesystemBundlePublicationV1, AuthenticatedFilesystemRestartErrorV1> {
        ensure_active(expected, now)?;
        if self.provider_preflight(expected) != ProviderPreflightV1::Authenticated {
            return Err(AuthenticatedFilesystemRestartErrorV1::ProviderUnavailable);
        }
        let bundle = source
            .export_sealed_bundle(expected)
            .map_err(|_| AuthenticatedFilesystemRestartErrorV1::SourceRepositoryUnavailable)?;
        self.filesystem
            .publish(&bundle)
            .map_err(|_| AuthenticatedFilesystemRestartErrorV1::FilesystemUnavailable)
    }

    /// Strictly read, authenticate, and atomically import one candidate.
    ///
    /// Provider/backend unavailability and aggregate memory capacity never
    /// quarantine a candidate. A structurally invalid object, a missing or
    /// non-sealed independently enumerated key record, or a candidate that
    /// fails complete manifest/catalog authentication is quarantined without
    /// deletion.
    pub fn recover(
        &self,
        expected: ExpectedCoreResultManifestContextV1,
        now: UnixTimestampNanos,
    ) -> Result<AuthenticatedFilesystemRecoveryPublicationV1, AuthenticatedFilesystemRestartErrorV1>
    {
        ensure_active(expected, now)?;
        let bundle = match self.filesystem.read(expected.result_id()) {
            Ok(bundle) => bundle,
            Err(error) if filesystem_error_is_candidate_invalid(error) => {
                return self.quarantine(expected.result_id());
            }
            Err(FilesystemSealedBundleErrorV1::ResultUnavailable) => {
                return Err(AuthenticatedFilesystemRestartErrorV1::ResultUnavailable);
            }
            Err(_) => {
                return Err(AuthenticatedFilesystemRestartErrorV1::FilesystemUnavailable);
            }
        };
        let canonical_bundle = bundle.encode();

        match self.provider_preflight(expected) {
            ProviderPreflightV1::Authenticated => {}
            ProviderPreflightV1::Unavailable => {
                return Err(AuthenticatedFilesystemRestartErrorV1::ProviderUnavailable);
            }
            ProviderPreflightV1::Invalid => return self.quarantine(expected.result_id()),
        }

        match self.repository.import_sealed_bundle(expected, bundle) {
            Ok(publication) => Ok(AuthenticatedFilesystemRecoveryPublicationV1 {
                result_id: publication.result_id(),
                disposition: AuthenticatedFilesystemRecoveryDispositionV1::Imported,
            }),
            Err(EncryptedCoreResultRepositoryErrorV1::DuplicateResult) => {
                let existing = self
                    .repository
                    .export_sealed_bundle(expected)
                    .map_err(map_existing_repository_error)?;
                if existing.encode() != canonical_bundle {
                    return self.quarantine(expected.result_id());
                }
                Ok(AuthenticatedFilesystemRecoveryPublicationV1 {
                    result_id: expected.result_id(),
                    disposition: AuthenticatedFilesystemRecoveryDispositionV1::AlreadyVisible,
                })
            }
            Err(
                EncryptedCoreResultRepositoryErrorV1::CapacityExceeded
                | EncryptedCoreResultRepositoryErrorV1::FrameCountCap
                | EncryptedCoreResultRepositoryErrorV1::SegmentCountCap
                | EncryptedCoreResultRepositoryErrorV1::FrameByteCap,
            ) => Err(AuthenticatedFilesystemRestartErrorV1::CapacityUnavailable),
            Err(EncryptedCoreResultRepositoryErrorV1::KeyProviderFailed) => {
                Err(AuthenticatedFilesystemRestartErrorV1::ProviderUnavailable)
            }
            Err(
                EncryptedCoreResultRepositoryErrorV1::RepositoryUnavailable
                | EncryptedCoreResultRepositoryErrorV1::PublicationFailed,
            ) => Err(AuthenticatedFilesystemRestartErrorV1::RepositoryUnavailable),
            Err(_) => self.quarantine(expected.result_id()),
        }
    }

    /// Recover one finalized product result and return only its authenticated
    /// displayed exact-alias capability.
    ///
    /// A private validation repository authenticates and decodes the alias
    /// frame before the coordinator's visible repository is mutated. Thus a
    /// malformed, substituted, missing, or duplicate alias manifest is never
    /// transiently reachable through the returned handle.
    pub fn recover_exact_alias_result(
        &self,
        expected: ExpectedCoreResultManifestContextV1,
        now: UnixTimestampNanos,
    ) -> Result<RecoveredExactAliasResultV1<P>, AuthenticatedFilesystemRestartErrorV1> {
        ensure_active(expected, now)?;
        let bundle = match self.filesystem.read(expected.result_id()) {
            Ok(bundle) => bundle,
            Err(error) if filesystem_error_is_candidate_invalid(error) => {
                return self.quarantine(expected.result_id());
            }
            Err(FilesystemSealedBundleErrorV1::ResultUnavailable) => {
                return Err(AuthenticatedFilesystemRestartErrorV1::ResultUnavailable);
            }
            Err(_) => {
                return Err(AuthenticatedFilesystemRestartErrorV1::FilesystemUnavailable);
            }
        };
        let canonical_bundle = bundle.encode();
        match self.provider_preflight(expected) {
            ProviderPreflightV1::Authenticated => {}
            ProviderPreflightV1::Unavailable => {
                return Err(AuthenticatedFilesystemRestartErrorV1::ProviderUnavailable);
            }
            ProviderPreflightV1::Invalid => return self.quarantine(expected.result_id()),
        }

        let validation_repository =
            MemoryEncryptedCoreResultRepositoryV1::new(Arc::clone(&self.provider), 1)
                .map_err(map_repository_construction_error)?;
        let validation_bundle = SealedEncryptedCoreResultBundleV1::decode(&canonical_bundle)
            .map_err(|_| AuthenticatedFilesystemRestartErrorV1::RepositoryUnavailable)?;
        match validation_repository.import_sealed_bundle(expected, validation_bundle) {
            Ok(_) => {}
            Err(
                EncryptedCoreResultRepositoryErrorV1::CapacityExceeded
                | EncryptedCoreResultRepositoryErrorV1::FrameCountCap
                | EncryptedCoreResultRepositoryErrorV1::SegmentCountCap
                | EncryptedCoreResultRepositoryErrorV1::FrameByteCap,
            ) => return Err(AuthenticatedFilesystemRestartErrorV1::CapacityUnavailable),
            Err(EncryptedCoreResultRepositoryErrorV1::KeyProviderFailed) => {
                return Err(AuthenticatedFilesystemRestartErrorV1::ProviderUnavailable);
            }
            Err(EncryptedCoreResultRepositoryErrorV1::RepositoryUnavailable) => {
                return Err(AuthenticatedFilesystemRestartErrorV1::RepositoryUnavailable);
            }
            Err(_) => return self.quarantine(expected.result_id()),
        }
        let alias_manifest = match validation_repository.open_displayed_alias_manifest(expected) {
            Ok(manifest) => manifest,
            Err(EncryptedCoreResultRepositoryErrorV1::KeyProviderFailed) => {
                return Err(AuthenticatedFilesystemRestartErrorV1::ProviderUnavailable);
            }
            Err(EncryptedCoreResultRepositoryErrorV1::RepositoryUnavailable) => {
                return Err(AuthenticatedFilesystemRestartErrorV1::RepositoryUnavailable);
            }
            Err(_) => return self.quarantine(expected.result_id()),
        };

        let visible_bundle = SealedEncryptedCoreResultBundleV1::decode(&canonical_bundle)
            .map_err(|_| AuthenticatedFilesystemRestartErrorV1::RepositoryUnavailable)?;
        let disposition = match self
            .repository
            .import_sealed_bundle(expected, visible_bundle)
        {
            Ok(_) => AuthenticatedFilesystemRecoveryDispositionV1::Imported,
            Err(EncryptedCoreResultRepositoryErrorV1::DuplicateResult) => {
                let existing = self
                    .repository
                    .export_sealed_bundle(expected)
                    .map_err(map_existing_repository_error)?;
                if existing.encode() != canonical_bundle {
                    return self.quarantine(expected.result_id());
                }
                AuthenticatedFilesystemRecoveryDispositionV1::AlreadyVisible
            }
            Err(
                EncryptedCoreResultRepositoryErrorV1::CapacityExceeded
                | EncryptedCoreResultRepositoryErrorV1::FrameCountCap
                | EncryptedCoreResultRepositoryErrorV1::SegmentCountCap
                | EncryptedCoreResultRepositoryErrorV1::FrameByteCap,
            ) => return Err(AuthenticatedFilesystemRestartErrorV1::CapacityUnavailable),
            Err(EncryptedCoreResultRepositoryErrorV1::KeyProviderFailed) => {
                return Err(AuthenticatedFilesystemRestartErrorV1::ProviderUnavailable);
            }
            Err(
                EncryptedCoreResultRepositoryErrorV1::RepositoryUnavailable
                | EncryptedCoreResultRepositoryErrorV1::PublicationFailed,
            ) => return Err(AuthenticatedFilesystemRestartErrorV1::RepositoryUnavailable),
            Err(_) => return self.quarantine(expected.result_id()),
        };
        Ok(RecoveredExactAliasResultV1 {
            repository: Arc::clone(&self.repository),
            expected,
            manifest: alias_manifest,
            disposition,
        })
    }

    /// Open one complete authorized event only from an already authenticated,
    /// visible in-memory result and only inside its fixed validity interval.
    pub fn open_event(
        &self,
        expected: ExpectedCoreResultManifestContextV1,
        event_id: EventId,
        now: UnixTimestampNanos,
    ) -> Result<OpenedEncryptedCoreResultEventV1, AuthenticatedFilesystemRestartErrorV1> {
        ensure_active(expected, now)?;
        self.repository
            .open_stored_event(expected, event_id)
            .map_err(|_| AuthenticatedFilesystemRestartErrorV1::EventUnavailable)
    }

    /// Destroy provider key authority and the fresh process-local repository
    /// entry. The ciphertext filesystem object is deliberately retained.
    pub fn destroy_visible_result(
        &self,
        result_id: &ResultId,
    ) -> Result<EncryptedCoreResultDestroyOutcomeV1, AuthenticatedFilesystemRestartErrorV1> {
        self.repository
            .destroy(result_id)
            .map_err(|_| AuthenticatedFilesystemRestartErrorV1::RepositoryUnavailable)
    }

    pub fn visible_result_count(&self) -> Result<usize, AuthenticatedFilesystemRestartErrorV1> {
        self.repository
            .len()
            .map_err(|_| AuthenticatedFilesystemRestartErrorV1::RepositoryUnavailable)
    }

    fn provider_preflight(
        &self,
        expected: ExpectedCoreResultManifestContextV1,
    ) -> ProviderPreflightV1 {
        let records = match self.provider.list_managed_records() {
            Ok(records) => records,
            Err(KeyProviderErrorV1::Locked | KeyProviderErrorV1::Unavailable) => {
                return ProviderPreflightV1::Unavailable;
            }
            Err(_) => return ProviderPreflightV1::Unavailable,
        };
        let mut matches = records
            .iter()
            .filter(|record| record.result_id() == expected.result_id());
        let Some(record) = matches.next().copied() else {
            return ProviderPreflightV1::Invalid;
        };
        if matches.next().is_some()
            || record.state() != KeyRecordListStateV1::Sealed
            || record.root_key_version().is_none()
            || record.created_unix_nanos() != Some(expected.created_unix_nanos())
            || record.expires_unix_nanos() != Some(expected.expires_unix_nanos())
        {
            return ProviderPreflightV1::Invalid;
        }

        let key_context = match ExpectedKeyContextV1::new(
            expected.created_unix_nanos(),
            expected.expires_unix_nanos(),
        ) {
            Ok(context) => context,
            Err(_) => return ProviderPreflightV1::Invalid,
        };
        let opened = match self
            .provider
            .open_result_key(&expected.result_id(), &key_context)
        {
            Ok(opened) => opened,
            Err(KeyProviderErrorV1::Locked | KeyProviderErrorV1::Unavailable) => {
                return ProviderPreflightV1::Unavailable;
            }
            Err(_) => return ProviderPreflightV1::Unavailable,
        };
        if opened.result_id() != expected.result_id()
            || opened.created_unix_nanos() != expected.created_unix_nanos()
            || opened.expires_unix_nanos() != expected.expires_unix_nanos()
            || opened.state() != ResultKeyRecordStateV1::Sealed
            || opened.seal_binding().is_none()
        {
            return ProviderPreflightV1::Invalid;
        }
        ProviderPreflightV1::Authenticated
    }

    fn quarantine<T>(
        &self,
        result_id: ResultId,
    ) -> Result<T, AuthenticatedFilesystemRestartErrorV1> {
        self.filesystem
            .quarantine_final_candidate(result_id)
            .map_err(|_| AuthenticatedFilesystemRestartErrorV1::QuarantineFailed)?;
        Err(AuthenticatedFilesystemRestartErrorV1::CandidateQuarantined)
    }
}

impl<P: KeyProviderV1 + ?Sized> fmt::Debug for AuthenticatedFilesystemRestartCoordinatorV1<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedFilesystemRestartCoordinatorV1(<redacted>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProviderPreflightV1 {
    Authenticated,
    Unavailable,
    Invalid,
}

fn ensure_active(
    expected: ExpectedCoreResultManifestContextV1,
    now: UnixTimestampNanos,
) -> Result<(), AuthenticatedFilesystemRestartErrorV1> {
    if now.get() < i128::from(expected.created_unix_nanos())
        || now.get() >= i128::from(expected.expires_unix_nanos())
    {
        return Err(AuthenticatedFilesystemRestartErrorV1::OutsideValidity);
    }
    Ok(())
}

fn filesystem_error_is_candidate_invalid(error: FilesystemSealedBundleErrorV1) -> bool {
    matches!(
        error,
        FilesystemSealedBundleErrorV1::UnsafeObject
            | FilesystemSealedBundleErrorV1::PermissionMismatch
            | FilesystemSealedBundleErrorV1::HardLinkRejected
            | FilesystemSealedBundleErrorV1::BundleTooLarge
            | FilesystemSealedBundleErrorV1::ReadFailed
            | FilesystemSealedBundleErrorV1::ObjectChangedDuringRead
            | FilesystemSealedBundleErrorV1::BundleDecodeFailed
            | FilesystemSealedBundleErrorV1::AuthorityMismatch
    )
}

fn map_repository_construction_error(
    error: EncryptedCoreResultRepositoryErrorV1,
) -> AuthenticatedFilesystemRestartErrorV1 {
    match error {
        EncryptedCoreResultRepositoryErrorV1::InvalidCapacity
        | EncryptedCoreResultRepositoryErrorV1::CapacityExceeded => {
            AuthenticatedFilesystemRestartErrorV1::CapacityUnavailable
        }
        _ => AuthenticatedFilesystemRestartErrorV1::RepositoryUnavailable,
    }
}

fn map_existing_repository_error(
    error: EncryptedCoreResultRepositoryErrorV1,
) -> AuthenticatedFilesystemRestartErrorV1 {
    match error {
        EncryptedCoreResultRepositoryErrorV1::KeyProviderFailed => {
            AuthenticatedFilesystemRestartErrorV1::ProviderUnavailable
        }
        EncryptedCoreResultRepositoryErrorV1::RepositoryUnavailable => {
            AuthenticatedFilesystemRestartErrorV1::RepositoryUnavailable
        }
        _ => AuthenticatedFilesystemRestartErrorV1::ResultUnavailable,
    }
}
