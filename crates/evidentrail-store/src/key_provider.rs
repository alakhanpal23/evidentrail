use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;

use evidentrail_schema::ResultId;
use evidentrail_snapshot_format::{
    FrameNonceV1, MAX_TOTAL_FRAMES_PER_RESULT_V1, ManifestNonceV1, OpenedSealBindingV1,
    ResultDekV1, ResultKeyRecordStateV1, ResultKeySealTransitionV1, RootKeyVersionV1,
    SealBindingV1,
};

/// Maximum V1 nonce issuances in one result-DEK snapshot-object namespace.
///
/// The namespace has room for every frame admitted by the V1 catalog plus one
/// outer manifest. Provider implementations must fail closed before drawing
/// entropy once this lifetime issuance bound is exhausted.
pub const MAX_SNAPSHOT_OBJECT_NONCES_PER_RESULT_V1: u64 = MAX_TOTAL_FRAMES_PER_RESULT_V1 + 1;

/// Stable construction failure for authenticated result-key time contexts.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeyContextErrorV1 {
    InvalidResultId,
    InvalidTimeRange,
}

impl KeyContextErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidResultId => "EVIDENTRAIL_KEY_CONTEXT_INVALID_RESULT_ID",
            Self::InvalidTimeRange => "EVIDENTRAIL_KEY_CONTEXT_INVALID_TIME_RANGE",
        }
    }
}

impl fmt::Debug for KeyContextErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyContextErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for KeyContextErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for KeyContextErrorV1 {}

/// Checked input for creating one result-key record.
///
/// The caller has already generated the opaque random `ResultId`. Times occupy
/// the complete signed 64-bit nanosecond domain and are never arithmetically
/// widened or silently clamped here; expiry must be strictly after creation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CreatingKeyContextV1 {
    result_id: ResultId,
    created_unix_nanos: i64,
    expires_unix_nanos: i64,
}

impl CreatingKeyContextV1 {
    pub fn new(
        result_id: ResultId,
        created_unix_nanos: i64,
        expires_unix_nanos: i64,
    ) -> Result<Self, KeyContextErrorV1> {
        if result_id.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(KeyContextErrorV1::InvalidResultId);
        }
        validate_time_range(created_unix_nanos, expires_unix_nanos)?;
        Ok(Self {
            result_id,
            created_unix_nanos,
            expires_unix_nanos,
        })
    }

    #[must_use]
    pub const fn result_id(self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn created_unix_nanos(self) -> i64 {
        self.created_unix_nanos
    }

    #[must_use]
    pub const fn expires_unix_nanos(self) -> i64 {
        self.expires_unix_nanos
    }

    #[must_use]
    pub const fn expected_context(self) -> ExpectedKeyContextV1 {
        ExpectedKeyContextV1 {
            created_unix_nanos: self.created_unix_nanos,
            expires_unix_nanos: self.expires_unix_nanos,
        }
    }
}

impl fmt::Debug for CreatingKeyContextV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CreatingKeyContextV1(<redacted>)")
    }
}

/// Caller expectation authenticated when an existing result key is opened.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExpectedKeyContextV1 {
    created_unix_nanos: i64,
    expires_unix_nanos: i64,
}

impl ExpectedKeyContextV1 {
    pub fn new(
        created_unix_nanos: i64,
        expires_unix_nanos: i64,
    ) -> Result<Self, KeyContextErrorV1> {
        validate_time_range(created_unix_nanos, expires_unix_nanos)?;
        Ok(Self {
            created_unix_nanos,
            expires_unix_nanos,
        })
    }

    #[must_use]
    pub const fn created_unix_nanos(self) -> i64 {
        self.created_unix_nanos
    }

    #[must_use]
    pub const fn expires_unix_nanos(self) -> i64 {
        self.expires_unix_nanos
    }
}

impl fmt::Debug for ExpectedKeyContextV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExpectedKeyContextV1(<redacted>)")
    }
}

fn validate_time_range(created: i64, expires: i64) -> Result<(), KeyContextErrorV1> {
    if expires <= created {
        return Err(KeyContextErrorV1::InvalidTimeRange);
    }
    Ok(())
}

/// Stable, contentless provider-boundary failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeyProviderErrorV1 {
    InvalidCapacity,
    Locked,
    Unavailable,
    DuplicateResult,
    CapacityExceeded,
    EntropyUnavailable,
    EntropyRejected,
    SecretEntropyRepeated,
    SecretMatchesResultId,
    DuplicateNonce,
    SnapshotNonceNamespaceExhausted,
    RootReplacementRefused,
    RootVersionExhausted,
    UpdateFailed,
    DifferentSecondSeal,
}

impl KeyProviderErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidCapacity => "EVIDENTRAIL_KEY_PROVIDER_INVALID_CAPACITY",
            Self::Locked => "EVIDENTRAIL_KEY_PROVIDER_LOCKED",
            Self::Unavailable => "EVIDENTRAIL_KEY_PROVIDER_UNAVAILABLE",
            Self::DuplicateResult => "EVIDENTRAIL_KEY_PROVIDER_DUPLICATE_RESULT",
            Self::CapacityExceeded => "EVIDENTRAIL_KEY_PROVIDER_CAPACITY_EXCEEDED",
            Self::EntropyUnavailable => "EVIDENTRAIL_KEY_PROVIDER_ENTROPY_UNAVAILABLE",
            Self::EntropyRejected => "EVIDENTRAIL_KEY_PROVIDER_ENTROPY_REJECTED",
            Self::SecretEntropyRepeated => "EVIDENTRAIL_KEY_PROVIDER_SECRET_ENTROPY_REPEATED",
            Self::SecretMatchesResultId => "EVIDENTRAIL_KEY_PROVIDER_SECRET_MATCHES_RESULT_ID",
            Self::DuplicateNonce => "EVIDENTRAIL_KEY_PROVIDER_DUPLICATE_NONCE",
            Self::SnapshotNonceNamespaceExhausted => {
                "EVIDENTRAIL_KEY_PROVIDER_SNAPSHOT_NONCE_NAMESPACE_EXHAUSTED"
            }
            Self::RootReplacementRefused => "EVIDENTRAIL_KEY_PROVIDER_ROOT_REPLACEMENT_REFUSED",
            Self::RootVersionExhausted => "EVIDENTRAIL_KEY_PROVIDER_ROOT_VERSION_EXHAUSTED",
            Self::UpdateFailed => "EVIDENTRAIL_KEY_PROVIDER_UPDATE_FAILED",
            Self::DifferentSecondSeal => "EVIDENTRAIL_KEY_PROVIDER_DIFFERENT_SECOND_SEAL",
        }
    }
}

impl fmt::Debug for KeyProviderErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyProviderErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for KeyProviderErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for KeyProviderErrorV1 {}

/// Authenticated result-key material for one active read or write operation.
///
/// This owner is deliberately not `Clone`. Its DEK and optional opened seal
/// binding retain the zeroizing owners supplied by `evidentrail-snapshot-format`.
pub struct OpenedResultKeyV1 {
    result_id: ResultId,
    root_key_version: RootKeyVersionV1,
    created_unix_nanos: i64,
    expires_unix_nanos: i64,
    state: ResultKeyRecordStateV1,
    result_dek: ResultDekV1,
    seal_binding: Option<OpenedSealBindingV1>,
}

impl OpenedResultKeyV1 {
    #[cfg(any(test, feature = "internal-test-provider"))]
    pub(crate) fn new(
        result_id: ResultId,
        root_key_version: RootKeyVersionV1,
        created_unix_nanos: i64,
        expires_unix_nanos: i64,
        state: ResultKeyRecordStateV1,
        result_dek: ResultDekV1,
        seal_binding: Option<OpenedSealBindingV1>,
    ) -> Self {
        Self {
            result_id,
            root_key_version,
            created_unix_nanos,
            expires_unix_nanos,
            state,
            result_dek,
            seal_binding,
        }
    }

    #[must_use]
    pub const fn result_id(&self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn root_key_version(&self) -> RootKeyVersionV1 {
        self.root_key_version
    }

    #[must_use]
    pub const fn created_unix_nanos(&self) -> i64 {
        self.created_unix_nanos
    }

    #[must_use]
    pub const fn expires_unix_nanos(&self) -> i64 {
        self.expires_unix_nanos
    }

    #[must_use]
    pub const fn state(&self) -> ResultKeyRecordStateV1 {
        self.state
    }

    #[must_use]
    pub const fn result_dek(&self) -> &ResultDekV1 {
        &self.result_dek
    }

    #[must_use]
    pub const fn seal_binding(&self) -> Option<&OpenedSealBindingV1> {
        self.seal_binding.as_ref()
    }
}

impl fmt::Debug for OpenedResultKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenedResultKeyV1")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// Idempotent destruction outcome. Neither variant claims filesystem erasure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeyDestroyOutcomeV1 {
    Destroyed,
    AlreadyAbsent,
}

impl KeyDestroyOutcomeV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Destroyed => "EVIDENTRAIL_KEY_PROVIDER_DESTROYED",
            Self::AlreadyAbsent => "EVIDENTRAIL_KEY_PROVIDER_ALREADY_ABSENT",
        }
    }
}

impl fmt::Debug for KeyDestroyOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyDestroyOutcomeV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Contentless state visible during provider-scoped enumeration.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeyRecordListStateV1 {
    Creating,
    Sealed,
    Corrupt,
}

impl KeyRecordListStateV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Creating => "EVIDENTRAIL_KEY_RECORD_CREATING",
            Self::Sealed => "EVIDENTRAIL_KEY_RECORD_SEALED",
            Self::Corrupt => "EVIDENTRAIL_KEY_RECORD_CORRUPT",
        }
    }
}

impl fmt::Debug for KeyRecordListStateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyRecordListStateV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Bounded, contentless metadata returned by provider enumeration.
///
/// Accessors intentionally expose only the random result identity and the
/// fixed numeric fields needed by future cleanup/recovery coordination. Debug
/// formatting exposes only the coarse record state.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeyRecordMetadataV1 {
    result_id: ResultId,
    root_key_version: Option<RootKeyVersionV1>,
    created_unix_nanos: Option<i64>,
    expires_unix_nanos: Option<i64>,
    state: KeyRecordListStateV1,
}

impl KeyRecordMetadataV1 {
    #[cfg(any(test, feature = "internal-test-provider"))]
    pub(crate) const fn authenticated(
        result_id: ResultId,
        root_key_version: RootKeyVersionV1,
        created_unix_nanos: i64,
        expires_unix_nanos: i64,
        state: KeyRecordListStateV1,
    ) -> Self {
        Self {
            result_id,
            root_key_version: Some(root_key_version),
            created_unix_nanos: Some(created_unix_nanos),
            expires_unix_nanos: Some(expires_unix_nanos),
            state,
        }
    }

    /// A corrupt provider record remains enumerable by its provider-owned
    /// random account identity so cleanup can destroy it. Root version and
    /// times are deliberately absent: undecodable or unauthenticated outer
    /// bytes cannot establish those facts.
    #[cfg(any(test, feature = "internal-test-provider"))]
    pub(crate) const fn corrupt(result_id: ResultId) -> Self {
        Self {
            result_id,
            root_key_version: None,
            created_unix_nanos: None,
            expires_unix_nanos: None,
            state: KeyRecordListStateV1::Corrupt,
        }
    }

    #[must_use]
    pub const fn result_id(self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn root_key_version(self) -> Option<RootKeyVersionV1> {
        self.root_key_version
    }

    #[must_use]
    pub const fn created_unix_nanos(self) -> Option<i64> {
        self.created_unix_nanos
    }

    #[must_use]
    pub const fn expires_unix_nanos(self) -> Option<i64> {
        self.expires_unix_nanos
    }

    #[must_use]
    pub const fn state(self) -> KeyRecordListStateV1 {
        self.state
    }
}

impl fmt::Debug for KeyRecordMetadataV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyRecordMetadataV1")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// Synchronous, state-oriented boundary for authenticated result-key records.
///
/// It deliberately exposes neither a generic password operation nor root and
/// derived key bytes. Implementations serialize provider-specific operations
/// as required by their backend. `open_result_key` must collapse missing,
/// corrupt, and wrong-context records to [`KeyProviderErrorV1::Unavailable`].
pub trait KeyProviderV1: Send + Sync {
    fn ensure_root_key(&self) -> Result<RootKeyVersionV1, KeyProviderErrorV1>;

    fn create_result_key(
        &self,
        context: &CreatingKeyContextV1,
    ) -> Result<OpenedResultKeyV1, KeyProviderErrorV1>;

    /// Issue one fresh nonce for the result's snapshot-object AEAD namespace.
    ///
    /// Manifest and frame issuance must share the same per-result byte
    /// registry because both borrow the one result DEK. Implementations burn
    /// every successfully drawn nonce before returning it and reject reuse;
    /// callers must not accept or substitute arbitrary nonce bytes. Issuance
    /// also fails before drawing entropy at
    /// [`MAX_SNAPSHOT_OBJECT_NONCES_PER_RESULT_V1`].
    fn issue_snapshot_manifest_nonce(
        &self,
        result_id: &ResultId,
    ) -> Result<ManifestNonceV1, KeyProviderErrorV1>;

    /// Issue one fresh frame nonce from the exact same result-scoped byte
    /// namespace as manifest nonces. The provider, never its caller, chooses
    /// the bytes; purpose does not relax uniqueness under the one result DEK.
    fn issue_snapshot_frame_nonce(
        &self,
        result_id: &ResultId,
    ) -> Result<FrameNonceV1, KeyProviderErrorV1>;

    fn open_result_key(
        &self,
        result_id: &ResultId,
        expected_context: &ExpectedKeyContextV1,
    ) -> Result<OpenedResultKeyV1, KeyProviderErrorV1>;

    /// Seal exactly once. An idempotent success may be returned only when the
    /// supplied binding has the exact same canonical V1 bytes as the already
    /// authenticated binding; a different second binding must fail.
    fn seal_result_key(
        &self,
        result_id: &ResultId,
        binding: &SealBindingV1,
    ) -> Result<ResultKeySealTransitionV1, KeyProviderErrorV1>;

    fn destroy_result_key(
        &self,
        result_id: &ResultId,
    ) -> Result<KeyDestroyOutcomeV1, KeyProviderErrorV1>;

    fn list_managed_records(&self) -> Result<Vec<KeyRecordMetadataV1>, KeyProviderErrorV1>;
}

/// Behavior-identical shared ownership for a provider whose backend already
/// satisfies the provider's synchronization contract.
///
/// This delegation adds no provider state, caches no opened key, and does not
/// clone key material. It permits two process-local repositories to exercise
/// export/import against the same independently sealed provider authority.
impl<P: KeyProviderV1 + ?Sized> KeyProviderV1 for Arc<P> {
    fn ensure_root_key(&self) -> Result<RootKeyVersionV1, KeyProviderErrorV1> {
        (**self).ensure_root_key()
    }

    fn create_result_key(
        &self,
        context: &CreatingKeyContextV1,
    ) -> Result<OpenedResultKeyV1, KeyProviderErrorV1> {
        (**self).create_result_key(context)
    }

    fn issue_snapshot_manifest_nonce(
        &self,
        result_id: &ResultId,
    ) -> Result<ManifestNonceV1, KeyProviderErrorV1> {
        (**self).issue_snapshot_manifest_nonce(result_id)
    }

    fn issue_snapshot_frame_nonce(
        &self,
        result_id: &ResultId,
    ) -> Result<FrameNonceV1, KeyProviderErrorV1> {
        (**self).issue_snapshot_frame_nonce(result_id)
    }

    fn open_result_key(
        &self,
        result_id: &ResultId,
        expected_context: &ExpectedKeyContextV1,
    ) -> Result<OpenedResultKeyV1, KeyProviderErrorV1> {
        (**self).open_result_key(result_id, expected_context)
    }

    fn seal_result_key(
        &self,
        result_id: &ResultId,
        binding: &SealBindingV1,
    ) -> Result<ResultKeySealTransitionV1, KeyProviderErrorV1> {
        (**self).seal_result_key(result_id, binding)
    }

    fn destroy_result_key(
        &self,
        result_id: &ResultId,
    ) -> Result<KeyDestroyOutcomeV1, KeyProviderErrorV1> {
        (**self).destroy_result_key(result_id)
    }

    fn list_managed_records(&self) -> Result<Vec<KeyRecordMetadataV1>, KeyProviderErrorV1> {
        (**self).list_managed_records()
    }
}
