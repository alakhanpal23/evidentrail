use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::ResultId;
use sha2::{Digest, Sha256};

pub const OPERATION_ID_BYTES_V1: usize = 16;
pub const LIFECYCLE_DIGEST_BYTES_V1: usize = 32;
pub const RESULT_NONCE_PREFIX_BYTES_V1: usize = 16;
pub const RESULT_AUTHORITY_RECORD_BYTES_V2: usize = 512;
pub const RESULT_AUTHORITY_RECORD_VERSION_V2: u16 = 2;

const AUTHORITY_MAGIC_V2: [u8; 8] = *b"EVRAUT02";
const BUILD_CONTEXT_DOMAIN_V1: &[u8] = b"evidentrail.build-context.v1";

/// Four-state durable result lifecycle. Filesystem presence is never a state.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResultLifecycleStateV1 {
    Open,
    DataCommitted,
    Sealed,
    Published,
}

impl ResultLifecycleStateV1 {
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Open => 1,
            Self::DataCommitted => 2,
            Self::Sealed => 3,
            Self::Published => 4,
        }
    }

    fn from_code(code: u16) -> Result<Self, LifecycleRecordErrorV1> {
        match code {
            1 => Ok(Self::Open),
            2 => Ok(Self::DataCommitted),
            3 => Ok(Self::Sealed),
            4 => Ok(Self::Published),
            _ => Err(LifecycleRecordErrorV1::UnknownState),
        }
    }

    #[must_use]
    pub const fn may_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Open, Self::DataCommitted)
                | (Self::DataCommitted, Self::Sealed)
                | (Self::Sealed, Self::Published)
        )
    }
}

impl fmt::Debug for ResultLifecycleStateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResultLifecycleStateV1")
            .field("code", &self.code())
            .finish()
    }
}

macro_rules! opaque_fixed_bytes {
    ($name:ident, $bytes:expr, $debug:literal) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $bytes]);

        impl $name {
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $bytes]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $bytes] {
                &self.0
            }

            #[must_use]
            pub fn is_zero(self) -> bool {
                self.0.iter().all(|byte| *byte == 0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str($debug)
            }
        }
    };
}

opaque_fixed_bytes!(
    OperationIdV1,
    OPERATION_ID_BYTES_V1,
    "OperationIdV1(<redacted>)"
);
opaque_fixed_bytes!(
    LifecycleDigestV1,
    LIFECYCLE_DIGEST_BYTES_V1,
    "LifecycleDigestV1(<redacted>)"
);
opaque_fixed_bytes!(
    ResultNoncePrefixV1,
    RESULT_NONCE_PREFIX_BYTES_V1,
    "ResultNoncePrefixV1(<redacted>)"
);

/// Hash canonical operation input before using an operation identity.
#[must_use]
pub fn derive_lifecycle_digest_v1(bytes: &[u8]) -> LifecycleDigestV1 {
    LifecycleDigestV1::from_bytes(Sha256::digest(bytes).into())
}

/// Exact compiler/configuration identity required to resume after data commit.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BuildContextDigestsV1 {
    compiler: LifecycleDigestV1,
    renderer: LifecycleDigestV1,
    tokenizer: LifecycleDigestV1,
    policy: LifecycleDigestV1,
    contract: LifecycleDigestV1,
}

impl BuildContextDigestsV1 {
    #[must_use]
    pub const fn new(
        compiler: LifecycleDigestV1,
        renderer: LifecycleDigestV1,
        tokenizer: LifecycleDigestV1,
        policy: LifecycleDigestV1,
        contract: LifecycleDigestV1,
    ) -> Self {
        Self {
            compiler,
            renderer,
            tokenizer,
            policy,
            contract,
        }
    }

    #[must_use]
    pub fn aggregate(self) -> LifecycleDigestV1 {
        let mut hasher = Sha256::new();
        hasher.update(BUILD_CONTEXT_DOMAIN_V1);
        hasher.update(self.compiler.as_bytes());
        hasher.update(self.renderer.as_bytes());
        hasher.update(self.tokenizer.as_bytes());
        hasher.update(self.policy.as_bytes());
        hasher.update(self.contract.as_bytes());
        LifecycleDigestV1::from_bytes(hasher.finalize().into())
    }
}

impl fmt::Debug for BuildContextDigestsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BuildContextDigestsV1(<redacted>)")
    }
}

/// Trusted commitments installed by the `DATA_COMMITTED -> SEALED` transition.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SealCommitmentsV1 {
    final_manifest: LifecycleDigestV1,
    data_manifest: LifecycleDigestV1,
    event_index: LifecycleDigestV1,
    frame_chain: LifecycleDigestV1,
    products: LifecycleDigestV1,
}

impl SealCommitmentsV1 {
    #[must_use]
    pub const fn new(
        final_manifest: LifecycleDigestV1,
        data_manifest: LifecycleDigestV1,
        event_index: LifecycleDigestV1,
        frame_chain: LifecycleDigestV1,
        products: LifecycleDigestV1,
    ) -> Self {
        Self {
            final_manifest,
            data_manifest,
            event_index,
            frame_chain,
            products,
        }
    }

    #[must_use]
    pub const fn final_manifest(self) -> LifecycleDigestV1 {
        self.final_manifest
    }

    #[must_use]
    pub const fn data_manifest(self) -> LifecycleDigestV1 {
        self.data_manifest
    }

    #[must_use]
    pub const fn event_index(self) -> LifecycleDigestV1 {
        self.event_index
    }

    #[must_use]
    pub const fn frame_chain(self) -> LifecycleDigestV1 {
        self.frame_chain
    }

    #[must_use]
    pub const fn products(self) -> LifecycleDigestV1 {
        self.products
    }
}

impl fmt::Debug for SealCommitmentsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SealCommitmentsV1(<redacted>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LifecycleTransitionV1 {
    Applied,
    AlreadyApplied,
}

impl fmt::Debug for LifecycleTransitionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::Applied => "EVIDENTRAIL_LIFECYCLE_APPLIED",
            Self::AlreadyApplied => "EVIDENTRAIL_LIFECYCLE_ALREADY_APPLIED",
        };
        formatter
            .debug_struct("LifecycleTransitionV1")
            .field("code", &code)
            .finish()
    }
}

/// Counter range reserved atomically in the external authority before use.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NonceReservationV1 {
    prefix: ResultNoncePrefixV1,
    first_counter: u64,
    count: u64,
}

impl NonceReservationV1 {
    pub fn new(
        prefix: ResultNoncePrefixV1,
        first_counter: u64,
        count: u64,
    ) -> Result<Self, LifecycleRecordErrorV1> {
        if prefix.is_zero() || count == 0 || first_counter.checked_add(count).is_none() {
            return Err(LifecycleRecordErrorV1::InvalidNonceReservation);
        }
        Ok(Self {
            prefix,
            first_counter,
            count,
        })
    }

    #[must_use]
    pub const fn prefix(self) -> ResultNoncePrefixV1 {
        self.prefix
    }

    #[must_use]
    pub const fn first_counter(self) -> u64 {
        self.first_counter
    }

    #[must_use]
    pub const fn count(self) -> u64 {
        self.count
    }

    pub fn nonce_at(self, index: u64) -> Result<[u8; 24], LifecycleRecordErrorV1> {
        if index >= self.count {
            return Err(LifecycleRecordErrorV1::InvalidNonceReservation);
        }
        let counter = self
            .first_counter
            .checked_add(index)
            .ok_or(LifecycleRecordErrorV1::NonceNamespaceExhausted)?;
        let mut nonce = [0u8; 24];
        nonce[..16].copy_from_slice(self.prefix.as_bytes());
        nonce[16..].copy_from_slice(&counter.to_be_bytes());
        Ok(nonce)
    }
}

impl fmt::Debug for NonceReservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NonceReservationV1")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

/// Stable, contentless lifecycle/authority-record failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LifecycleRecordErrorV1 {
    InvalidOperationId,
    InvalidNoncePrefix,
    InvalidNonceReservation,
    NonceNamespaceExhausted,
    InvalidTimeRange,
    InvalidStateTransition,
    OperationConflict,
    BuildContextMismatch,
    PublicationGenerationInvalid,
    InvalidEncodedLength,
    InvalidMagic,
    UnsupportedVersion,
    UnknownState,
    NonzeroFlags,
    NonzeroReserved,
    NoncanonicalState,
}

impl LifecycleRecordErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidOperationId => "EVIDENTRAIL_LIFECYCLE_INVALID_OPERATION_ID",
            Self::InvalidNoncePrefix => "EVIDENTRAIL_LIFECYCLE_INVALID_NONCE_PREFIX",
            Self::InvalidNonceReservation => "EVIDENTRAIL_LIFECYCLE_INVALID_NONCE_RESERVATION",
            Self::NonceNamespaceExhausted => "EVIDENTRAIL_LIFECYCLE_NONCE_NAMESPACE_EXHAUSTED",
            Self::InvalidTimeRange => "EVIDENTRAIL_LIFECYCLE_INVALID_TIME_RANGE",
            Self::InvalidStateTransition => "EVIDENTRAIL_LIFECYCLE_INVALID_STATE_TRANSITION",
            Self::OperationConflict => "EVIDENTRAIL_LIFECYCLE_OPERATION_CONFLICT",
            Self::BuildContextMismatch => "EVIDENTRAIL_LIFECYCLE_BUILD_CONTEXT_MISMATCH",
            Self::PublicationGenerationInvalid => "EVIDENTRAIL_LIFECYCLE_PUBLICATION_GENERATION_INVALID",
            Self::InvalidEncodedLength => "EVIDENTRAIL_LIFECYCLE_INVALID_ENCODED_LENGTH",
            Self::InvalidMagic => "EVIDENTRAIL_LIFECYCLE_INVALID_MAGIC",
            Self::UnsupportedVersion => "EVIDENTRAIL_LIFECYCLE_UNSUPPORTED_VERSION",
            Self::UnknownState => "EVIDENTRAIL_LIFECYCLE_UNKNOWN_STATE",
            Self::NonzeroFlags => "EVIDENTRAIL_LIFECYCLE_NONZERO_FLAGS",
            Self::NonzeroReserved => "EVIDENTRAIL_LIFECYCLE_NONZERO_RESERVED",
            Self::NoncanonicalState => "EVIDENTRAIL_LIFECYCLE_NONCANONICAL_STATE",
        }
    }
}

impl fmt::Debug for LifecycleRecordErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LifecycleRecordErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for LifecycleRecordErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for LifecycleRecordErrorV1 {}

/// Fixed-width V2 metadata stored by the external key authority.
///
/// The wrapped DEK remains provider-private. This record is the trusted state,
/// nonce high-water mark, recovery context, and publication root that the
/// provider stores beside that secret.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ResultAuthorityRecordV2 {
    result_id: ResultId,
    created_unix_nanos: i64,
    expires_unix_nanos: i64,
    state: ResultLifecycleStateV1,
    nonce_prefix: ResultNoncePrefixV1,
    nonce_high_water: u64,
    publication_generation: u64,
    begin_operation: OperationIdV1,
    begin_digest: LifecycleDigestV1,
    data_operation: OperationIdV1,
    data_digest: LifecycleDigestV1,
    build_context: LifecycleDigestV1,
    seal_operation: OperationIdV1,
    seal_commitments: SealCommitmentsV1,
    publish_operation: OperationIdV1,
    repository_commitment: LifecycleDigestV1,
    pending_nonce_operation: OperationIdV1,
    pending_nonce_digest: LifecycleDigestV1,
    pending_nonce_first: u64,
    pending_nonce_count: u64,
}

impl ResultAuthorityRecordV2 {
    pub fn new_open(
        result_id: ResultId,
        created_unix_nanos: i64,
        expires_unix_nanos: i64,
        nonce_prefix: ResultNoncePrefixV1,
        operation: OperationIdV1,
        canonical_digest: LifecycleDigestV1,
    ) -> Result<Self, LifecycleRecordErrorV1> {
        if result_id.as_bytes().iter().all(|byte| *byte == 0)
            || expires_unix_nanos <= created_unix_nanos
        {
            return Err(LifecycleRecordErrorV1::InvalidTimeRange);
        }
        if nonce_prefix.is_zero() {
            return Err(LifecycleRecordErrorV1::InvalidNoncePrefix);
        }
        if operation.is_zero() {
            return Err(LifecycleRecordErrorV1::InvalidOperationId);
        }
        Ok(Self {
            result_id,
            created_unix_nanos,
            expires_unix_nanos,
            state: ResultLifecycleStateV1::Open,
            nonce_prefix,
            nonce_high_water: 0,
            publication_generation: 0,
            begin_operation: operation,
            begin_digest: canonical_digest,
            data_operation: OperationIdV1::from_bytes([0; OPERATION_ID_BYTES_V1]),
            data_digest: LifecycleDigestV1::from_bytes([0; LIFECYCLE_DIGEST_BYTES_V1]),
            build_context: LifecycleDigestV1::from_bytes([0; LIFECYCLE_DIGEST_BYTES_V1]),
            seal_operation: OperationIdV1::from_bytes([0; OPERATION_ID_BYTES_V1]),
            seal_commitments: zero_seal_commitments(),
            publish_operation: OperationIdV1::from_bytes([0; OPERATION_ID_BYTES_V1]),
            repository_commitment: LifecycleDigestV1::from_bytes([0; LIFECYCLE_DIGEST_BYTES_V1]),
            pending_nonce_operation: OperationIdV1::from_bytes([0; OPERATION_ID_BYTES_V1]),
            pending_nonce_digest: LifecycleDigestV1::from_bytes([0; LIFECYCLE_DIGEST_BYTES_V1]),
            pending_nonce_first: 0,
            pending_nonce_count: 0,
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
    pub const fn state(self) -> ResultLifecycleStateV1 {
        self.state
    }

    #[must_use]
    pub const fn nonce_prefix(self) -> ResultNoncePrefixV1 {
        self.nonce_prefix
    }

    #[must_use]
    pub const fn nonce_high_water(self) -> u64 {
        self.nonce_high_water
    }

    #[must_use]
    pub const fn publication_generation(self) -> u64 {
        self.publication_generation
    }

    #[must_use]
    pub const fn data_digest(self) -> LifecycleDigestV1 {
        self.data_digest
    }

    #[must_use]
    pub const fn build_context(self) -> LifecycleDigestV1 {
        self.build_context
    }

    #[must_use]
    pub const fn seal_commitments(self) -> SealCommitmentsV1 {
        self.seal_commitments
    }

    #[must_use]
    pub const fn repository_commitment(self) -> LifecycleDigestV1 {
        self.repository_commitment
    }

    #[must_use]
    pub fn matches_begin(
        self,
        created_unix_nanos: i64,
        expires_unix_nanos: i64,
        operation: OperationIdV1,
        canonical_digest: LifecycleDigestV1,
    ) -> bool {
        self.created_unix_nanos == created_unix_nanos
            && self.expires_unix_nanos == expires_unix_nanos
            && self.begin_operation == operation
            && self.begin_digest == canonical_digest
    }

    pub fn reserve_nonce_range(
        &mut self,
        count: u64,
    ) -> Result<NonceReservationV1, LifecycleRecordErrorV1> {
        if count == 0 {
            return Err(LifecycleRecordErrorV1::InvalidNonceReservation);
        }
        let next = self
            .nonce_high_water
            .checked_add(count)
            .ok_or(LifecycleRecordErrorV1::NonceNamespaceExhausted)?;
        let reservation = NonceReservationV1::new(self.nonce_prefix, self.nonce_high_water, count)?;
        self.nonce_high_water = next;
        Ok(reservation)
    }

    /// Atomically records an in-flight reservation in the authority record.
    /// An exact retry returns the same counters; a different operation cannot
    /// pass the single-writer crash boundary until the durable writer clears it.
    pub fn reserve_pending_nonce_range(
        &mut self,
        operation: OperationIdV1,
        canonical_digest: LifecycleDigestV1,
        count: u64,
    ) -> Result<NonceReservationV1, LifecycleRecordErrorV1> {
        if operation.is_zero() || count == 0 {
            return Err(LifecycleRecordErrorV1::InvalidNonceReservation);
        }
        if !self.pending_nonce_operation.is_zero() {
            if self.pending_nonce_operation == operation
                && self.pending_nonce_digest == canonical_digest
                && self.pending_nonce_count == count
            {
                return NonceReservationV1::new(self.nonce_prefix, self.pending_nonce_first, count);
            }
            return Err(LifecycleRecordErrorV1::OperationConflict);
        }
        let reservation = self.reserve_nonce_range(count)?;
        self.pending_nonce_operation = operation;
        self.pending_nonce_digest = canonical_digest;
        self.pending_nonce_first = reservation.first_counter();
        self.pending_nonce_count = count;
        Ok(reservation)
    }

    pub fn complete_pending_nonce_range(
        &mut self,
        operation: OperationIdV1,
        canonical_digest: LifecycleDigestV1,
    ) -> Result<LifecycleTransitionV1, LifecycleRecordErrorV1> {
        if self.pending_nonce_operation.is_zero() {
            return Ok(LifecycleTransitionV1::AlreadyApplied);
        }
        if self.pending_nonce_operation != operation
            || self.pending_nonce_digest != canonical_digest
        {
            return Err(LifecycleRecordErrorV1::OperationConflict);
        }
        self.pending_nonce_operation = OperationIdV1::from_bytes([0; OPERATION_ID_BYTES_V1]);
        self.pending_nonce_digest = LifecycleDigestV1::from_bytes([0; LIFECYCLE_DIGEST_BYTES_V1]);
        self.pending_nonce_first = 0;
        self.pending_nonce_count = 0;
        Ok(LifecycleTransitionV1::Applied)
    }

    #[must_use]
    pub fn has_pending_nonce_reservation(self) -> bool {
        !self.pending_nonce_operation.is_zero()
    }

    pub fn commit_data(
        &mut self,
        operation: OperationIdV1,
        canonical_digest: LifecycleDigestV1,
        build_context: BuildContextDigestsV1,
    ) -> Result<LifecycleTransitionV1, LifecycleRecordErrorV1> {
        if operation.is_zero() {
            return Err(LifecycleRecordErrorV1::InvalidOperationId);
        }
        let aggregate = build_context.aggregate();
        if self.state >= ResultLifecycleStateV1::DataCommitted {
            if self.data_operation == operation
                && self.data_digest == canonical_digest
                && self.build_context == aggregate
            {
                return Ok(LifecycleTransitionV1::AlreadyApplied);
            }
            return Err(LifecycleRecordErrorV1::OperationConflict);
        }
        if self.state != ResultLifecycleStateV1::Open || self.has_pending_nonce_reservation() {
            return Err(LifecycleRecordErrorV1::InvalidStateTransition);
        }
        self.data_operation = operation;
        self.data_digest = canonical_digest;
        self.build_context = aggregate;
        self.state = ResultLifecycleStateV1::DataCommitted;
        Ok(LifecycleTransitionV1::Applied)
    }

    pub fn validate_resume_context(
        self,
        build_context: BuildContextDigestsV1,
    ) -> Result<(), LifecycleRecordErrorV1> {
        if self.state != ResultLifecycleStateV1::DataCommitted
            || self.has_pending_nonce_reservation()
        {
            return Err(LifecycleRecordErrorV1::InvalidStateTransition);
        }
        if self.build_context != build_context.aggregate() {
            return Err(LifecycleRecordErrorV1::BuildContextMismatch);
        }
        Ok(())
    }

    pub fn seal(
        &mut self,
        operation: OperationIdV1,
        commitments: SealCommitmentsV1,
    ) -> Result<LifecycleTransitionV1, LifecycleRecordErrorV1> {
        if operation.is_zero() {
            return Err(LifecycleRecordErrorV1::InvalidOperationId);
        }
        if self.state >= ResultLifecycleStateV1::Sealed {
            if self.seal_operation == operation && self.seal_commitments == commitments {
                return Ok(LifecycleTransitionV1::AlreadyApplied);
            }
            return Err(LifecycleRecordErrorV1::OperationConflict);
        }
        if self.state != ResultLifecycleStateV1::DataCommitted {
            return Err(LifecycleRecordErrorV1::InvalidStateTransition);
        }
        self.seal_operation = operation;
        self.seal_commitments = commitments;
        self.state = ResultLifecycleStateV1::Sealed;
        Ok(LifecycleTransitionV1::Applied)
    }

    pub fn publish(
        &mut self,
        operation: OperationIdV1,
        generation: u64,
        repository_commitment: LifecycleDigestV1,
    ) -> Result<LifecycleTransitionV1, LifecycleRecordErrorV1> {
        if operation.is_zero() {
            return Err(LifecycleRecordErrorV1::InvalidOperationId);
        }
        if self.state == ResultLifecycleStateV1::Published {
            if self.publish_operation == operation
                && self.publication_generation == generation
                && self.repository_commitment == repository_commitment
            {
                return Ok(LifecycleTransitionV1::AlreadyApplied);
            }
            return Err(LifecycleRecordErrorV1::OperationConflict);
        }
        if self.state != ResultLifecycleStateV1::Sealed
            || generation == 0
            || self.has_pending_nonce_reservation()
        {
            return Err(LifecycleRecordErrorV1::PublicationGenerationInvalid);
        }
        self.publish_operation = operation;
        self.publication_generation = generation;
        self.repository_commitment = repository_commitment;
        self.state = ResultLifecycleStateV1::Published;
        Ok(LifecycleTransitionV1::Applied)
    }

    #[must_use]
    pub fn encode(self) -> [u8; RESULT_AUTHORITY_RECORD_BYTES_V2] {
        let mut encoded = [0u8; RESULT_AUTHORITY_RECORD_BYTES_V2];
        encoded[0..8].copy_from_slice(&AUTHORITY_MAGIC_V2);
        encoded[8..10].copy_from_slice(&RESULT_AUTHORITY_RECORD_VERSION_V2.to_be_bytes());
        encoded[10..12].copy_from_slice(&self.state.code().to_be_bytes());
        encoded[16..48].copy_from_slice(self.result_id.as_bytes());
        encoded[48..56].copy_from_slice(&self.created_unix_nanos.to_be_bytes());
        encoded[56..64].copy_from_slice(&self.expires_unix_nanos.to_be_bytes());
        encoded[64..80].copy_from_slice(self.nonce_prefix.as_bytes());
        encoded[80..88].copy_from_slice(&self.nonce_high_water.to_be_bytes());
        encoded[88..96].copy_from_slice(&self.publication_generation.to_be_bytes());
        encoded[96..112].copy_from_slice(self.begin_operation.as_bytes());
        encoded[112..144].copy_from_slice(self.begin_digest.as_bytes());
        encoded[144..160].copy_from_slice(self.data_operation.as_bytes());
        encoded[160..192].copy_from_slice(self.data_digest.as_bytes());
        encoded[192..224].copy_from_slice(self.build_context.as_bytes());
        encoded[224..240].copy_from_slice(self.seal_operation.as_bytes());
        encoded[240..272].copy_from_slice(self.seal_commitments.final_manifest.as_bytes());
        encoded[272..304].copy_from_slice(self.seal_commitments.data_manifest.as_bytes());
        encoded[304..336].copy_from_slice(self.seal_commitments.event_index.as_bytes());
        encoded[336..368].copy_from_slice(self.seal_commitments.frame_chain.as_bytes());
        encoded[368..400].copy_from_slice(self.seal_commitments.products.as_bytes());
        encoded[400..416].copy_from_slice(self.publish_operation.as_bytes());
        encoded[416..448].copy_from_slice(self.repository_commitment.as_bytes());
        encoded[448..464].copy_from_slice(self.pending_nonce_operation.as_bytes());
        encoded[464..496].copy_from_slice(self.pending_nonce_digest.as_bytes());
        encoded[496..504].copy_from_slice(&self.pending_nonce_first.to_be_bytes());
        encoded[504..512].copy_from_slice(&self.pending_nonce_count.to_be_bytes());
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, LifecycleRecordErrorV1> {
        if encoded.len() != RESULT_AUTHORITY_RECORD_BYTES_V2 {
            return Err(LifecycleRecordErrorV1::InvalidEncodedLength);
        }
        if encoded[0..8] != AUTHORITY_MAGIC_V2 {
            return Err(LifecycleRecordErrorV1::InvalidMagic);
        }
        if read_u16(encoded, 8) != RESULT_AUTHORITY_RECORD_VERSION_V2 {
            return Err(LifecycleRecordErrorV1::UnsupportedVersion);
        }
        if encoded[12..16].iter().any(|byte| *byte != 0) {
            return Err(LifecycleRecordErrorV1::NonzeroFlags);
        }
        let record = Self {
            result_id: ResultId::from_bytes(read_array(encoded, 16)),
            created_unix_nanos: read_i64(encoded, 48),
            expires_unix_nanos: read_i64(encoded, 56),
            state: ResultLifecycleStateV1::from_code(read_u16(encoded, 10))?,
            nonce_prefix: ResultNoncePrefixV1::from_bytes(read_array(encoded, 64)),
            nonce_high_water: read_u64(encoded, 80),
            publication_generation: read_u64(encoded, 88),
            begin_operation: OperationIdV1::from_bytes(read_array(encoded, 96)),
            begin_digest: LifecycleDigestV1::from_bytes(read_array(encoded, 112)),
            data_operation: OperationIdV1::from_bytes(read_array(encoded, 144)),
            data_digest: LifecycleDigestV1::from_bytes(read_array(encoded, 160)),
            build_context: LifecycleDigestV1::from_bytes(read_array(encoded, 192)),
            seal_operation: OperationIdV1::from_bytes(read_array(encoded, 224)),
            seal_commitments: SealCommitmentsV1::new(
                LifecycleDigestV1::from_bytes(read_array(encoded, 240)),
                LifecycleDigestV1::from_bytes(read_array(encoded, 272)),
                LifecycleDigestV1::from_bytes(read_array(encoded, 304)),
                LifecycleDigestV1::from_bytes(read_array(encoded, 336)),
                LifecycleDigestV1::from_bytes(read_array(encoded, 368)),
            ),
            publish_operation: OperationIdV1::from_bytes(read_array(encoded, 400)),
            repository_commitment: LifecycleDigestV1::from_bytes(read_array(encoded, 416)),
            pending_nonce_operation: OperationIdV1::from_bytes(read_array(encoded, 448)),
            pending_nonce_digest: LifecycleDigestV1::from_bytes(read_array(encoded, 464)),
            pending_nonce_first: read_u64(encoded, 496),
            pending_nonce_count: read_u64(encoded, 504),
        };
        record.validate_canonical()?;
        Ok(record)
    }

    fn validate_canonical(self) -> Result<(), LifecycleRecordErrorV1> {
        if self.result_id.as_bytes().iter().all(|byte| *byte == 0)
            || self.expires_unix_nanos <= self.created_unix_nanos
            || self.nonce_prefix.is_zero()
            || self.begin_operation.is_zero()
        {
            return Err(LifecycleRecordErrorV1::NoncanonicalState);
        }
        let data_zero = self.data_operation.is_zero()
            && self.data_digest.is_zero()
            && self.build_context.is_zero();
        let seal_zero =
            self.seal_operation.is_zero() && self.seal_commitments == zero_seal_commitments();
        let publish_zero = self.publish_operation.is_zero()
            && self.publication_generation == 0
            && self.repository_commitment.is_zero();
        let pending_zero = self.pending_nonce_operation.is_zero()
            && self.pending_nonce_digest.is_zero()
            && self.pending_nonce_first == 0
            && self.pending_nonce_count == 0;
        let pending_valid = !self.pending_nonce_operation.is_zero()
            && self.pending_nonce_count > 0
            && self
                .pending_nonce_first
                .checked_add(self.pending_nonce_count)
                == Some(self.nonce_high_water);
        let canonical = match self.state {
            ResultLifecycleStateV1::Open => data_zero && seal_zero && publish_zero,
            ResultLifecycleStateV1::DataCommitted => {
                !self.data_operation.is_zero() && seal_zero && publish_zero
            }
            ResultLifecycleStateV1::Sealed => {
                !self.data_operation.is_zero() && !self.seal_operation.is_zero() && publish_zero
            }
            ResultLifecycleStateV1::Published => {
                !self.data_operation.is_zero()
                    && !self.seal_operation.is_zero()
                    && !self.publish_operation.is_zero()
                    && self.publication_generation > 0
            }
        };
        if !canonical || !(pending_zero || pending_valid) {
            return Err(LifecycleRecordErrorV1::NoncanonicalState);
        }
        Ok(())
    }
}

impl fmt::Debug for ResultAuthorityRecordV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResultAuthorityRecordV2")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

const fn zero_seal_commitments() -> SealCommitmentsV1 {
    let zero = LifecycleDigestV1::from_bytes([0; LIFECYCLE_DIGEST_BYTES_V1]);
    SealCommitmentsV1::new(zero, zero, zero, zero, zero)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(read_array(bytes, offset))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(read_array(bytes, offset))
}

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_be_bytes(read_array(bytes, offset))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut result = [0u8; N];
    result.copy_from_slice(&bytes[offset..offset + N]);
    result
}
