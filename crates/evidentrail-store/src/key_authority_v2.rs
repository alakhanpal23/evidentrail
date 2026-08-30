use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use evidentrail_schema::ResultId;
use evidentrail_snapshot_format::{
    BuildContextDigestsV1, LifecycleDigestV1, LifecycleRecordErrorV1, LifecycleTransitionV1,
    NonceReservationV1, OperationIdV1, ResultAuthorityRecordV2, ResultDekV1, ResultNoncePrefixV1,
    SealCommitmentsV1,
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AuthorityDestroyOutcomeV2 {
    Destroyed,
    AlreadyAbsent,
}

impl fmt::Debug for AuthorityDestroyOutcomeV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::Destroyed => "EVIDENTRAIL_AUTHORITY_V2_DESTROYED",
            Self::AlreadyAbsent => "EVIDENTRAIL_AUTHORITY_V2_ALREADY_ABSENT",
        };
        formatter
            .debug_struct("AuthorityDestroyOutcomeV2")
            .field("code", &code)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeyAuthorityErrorV2 {
    Locked,
    Unavailable,
    NotFound,
    DuplicateResult,
    CapacityExceeded,
    EntropyUnavailable,
    OperationConflict,
    InvalidTransition,
    NonceNamespaceExhausted,
    UpdateFailed,
}

impl KeyAuthorityErrorV2 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Locked => "EVIDENTRAIL_AUTHORITY_V2_LOCKED",
            Self::Unavailable => "EVIDENTRAIL_AUTHORITY_V2_UNAVAILABLE",
            Self::NotFound => "EVIDENTRAIL_AUTHORITY_V2_NOT_FOUND",
            Self::DuplicateResult => "EVIDENTRAIL_AUTHORITY_V2_DUPLICATE_RESULT",
            Self::CapacityExceeded => "EVIDENTRAIL_AUTHORITY_V2_CAPACITY_EXCEEDED",
            Self::EntropyUnavailable => "EVIDENTRAIL_AUTHORITY_V2_ENTROPY_UNAVAILABLE",
            Self::OperationConflict => "EVIDENTRAIL_AUTHORITY_V2_OPERATION_CONFLICT",
            Self::InvalidTransition => "EVIDENTRAIL_AUTHORITY_V2_INVALID_TRANSITION",
            Self::NonceNamespaceExhausted => "EVIDENTRAIL_AUTHORITY_V2_NONCE_NAMESPACE_EXHAUSTED",
            Self::UpdateFailed => "EVIDENTRAIL_AUTHORITY_V2_UPDATE_FAILED",
        }
    }
}

impl fmt::Debug for KeyAuthorityErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyAuthorityErrorV2")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for KeyAuthorityErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for KeyAuthorityErrorV2 {}

impl From<LifecycleRecordErrorV1> for KeyAuthorityErrorV2 {
    fn from(error: LifecycleRecordErrorV1) -> Self {
        match error {
            LifecycleRecordErrorV1::OperationConflict => Self::OperationConflict,
            LifecycleRecordErrorV1::NonceNamespaceExhausted => Self::NonceNamespaceExhausted,
            LifecycleRecordErrorV1::InvalidStateTransition
            | LifecycleRecordErrorV1::BuildContextMismatch
            | LifecycleRecordErrorV1::PublicationGenerationInvalid => Self::InvalidTransition,
            _ => Self::UpdateFailed,
        }
    }
}

/// External trusted-root boundary used by the durable repository.
///
/// Production implementations store the V2 record and wrapped DEK in macOS
/// Keychain (or an equivalent Linux authority) and serialize each mutation.
/// Reservations must advance the high-water mark atomically before returning.
pub trait KeyAuthorityV2: Send + Sync {
    fn begin(
        &self,
        result_id: ResultId,
        created_unix_nanos: i64,
        expires_unix_nanos: i64,
        operation: OperationIdV1,
        canonical_digest: LifecycleDigestV1,
    ) -> Result<(ResultAuthorityRecordV2, LifecycleTransitionV1), KeyAuthorityErrorV2>;

    fn reserve_nonce_range(
        &self,
        result_id: ResultId,
        operation: OperationIdV1,
        canonical_digest: LifecycleDigestV1,
        count: u64,
    ) -> Result<NonceReservationV1, KeyAuthorityErrorV2>;

    fn complete_nonce_reservation(
        &self,
        result_id: ResultId,
        operation: OperationIdV1,
        canonical_digest: LifecycleDigestV1,
    ) -> Result<LifecycleTransitionV1, KeyAuthorityErrorV2>;

    fn commit_data(
        &self,
        result_id: ResultId,
        operation: OperationIdV1,
        canonical_digest: LifecycleDigestV1,
        build_context: BuildContextDigestsV1,
    ) -> Result<LifecycleTransitionV1, KeyAuthorityErrorV2>;

    fn seal(
        &self,
        result_id: ResultId,
        operation: OperationIdV1,
        commitments: SealCommitmentsV1,
    ) -> Result<LifecycleTransitionV1, KeyAuthorityErrorV2>;

    /// Reserves the next repository-wide publication generation in the
    /// trusted authority. Exact retries return the same generation.
    fn reserve_publication_generation(
        &self,
        result_id: ResultId,
        operation: OperationIdV1,
        repository_commitment: LifecycleDigestV1,
    ) -> Result<u64, KeyAuthorityErrorV2>;

    fn publish(
        &self,
        result_id: ResultId,
        operation: OperationIdV1,
        generation: u64,
        repository_commitment: LifecycleDigestV1,
    ) -> Result<LifecycleTransitionV1, KeyAuthorityErrorV2>;

    fn snapshot(&self, result_id: ResultId)
    -> Result<ResultAuthorityRecordV2, KeyAuthorityErrorV2>;

    fn with_result_key<R, F>(
        &self,
        result_id: ResultId,
        operation: F,
    ) -> Result<R, KeyAuthorityErrorV2>
    where
        F: FnOnce(&ResultAuthorityRecordV2, &ResultDekV1) -> Result<R, KeyAuthorityErrorV2>;

    fn destroy(
        &self,
        result_id: ResultId,
    ) -> Result<AuthorityDestroyOutcomeV2, KeyAuthorityErrorV2>;

    fn list(&self) -> Result<Vec<ResultAuthorityRecordV2>, KeyAuthorityErrorV2>;
}

impl<A: KeyAuthorityV2 + ?Sized> KeyAuthorityV2 for Arc<A> {
    fn begin(
        &self,
        result_id: ResultId,
        created_unix_nanos: i64,
        expires_unix_nanos: i64,
        operation: OperationIdV1,
        canonical_digest: LifecycleDigestV1,
    ) -> Result<(ResultAuthorityRecordV2, LifecycleTransitionV1), KeyAuthorityErrorV2> {
        (**self).begin(
            result_id,
            created_unix_nanos,
            expires_unix_nanos,
            operation,
            canonical_digest,
        )
    }

    fn reserve_nonce_range(
        &self,
        result_id: ResultId,
        operation: OperationIdV1,
        canonical_digest: LifecycleDigestV1,
        count: u64,
    ) -> Result<NonceReservationV1, KeyAuthorityErrorV2> {
        (**self).reserve_nonce_range(result_id, operation, canonical_digest, count)
    }

    fn complete_nonce_reservation(
        &self,
        result_id: ResultId,
        operation: OperationIdV1,
        canonical_digest: LifecycleDigestV1,
    ) -> Result<LifecycleTransitionV1, KeyAuthorityErrorV2> {
        (**self).complete_nonce_reservation(result_id, operation, canonical_digest)
    }

    fn commit_data(
        &self,
        result_id: ResultId,
        operation: OperationIdV1,
        canonical_digest: LifecycleDigestV1,
        build_context: BuildContextDigestsV1,
    ) -> Result<LifecycleTransitionV1, KeyAuthorityErrorV2> {
        (**self).commit_data(result_id, operation, canonical_digest, build_context)
    }

    fn seal(
        &self,
        result_id: ResultId,
        operation: OperationIdV1,
        commitments: SealCommitmentsV1,
    ) -> Result<LifecycleTransitionV1, KeyAuthorityErrorV2> {
        (**self).seal(result_id, operation, commitments)
    }

    fn reserve_publication_generation(
        &self,
        result_id: ResultId,
        operation: OperationIdV1,
        repository_commitment: LifecycleDigestV1,
    ) -> Result<u64, KeyAuthorityErrorV2> {
        (**self).reserve_publication_generation(result_id, operation, repository_commitment)
    }

    fn publish(
        &self,
        result_id: ResultId,
        operation: OperationIdV1,
        generation: u64,
        repository_commitment: LifecycleDigestV1,
    ) -> Result<LifecycleTransitionV1, KeyAuthorityErrorV2> {
        (**self).publish(result_id, operation, generation, repository_commitment)
    }

    fn snapshot(
        &self,
        result_id: ResultId,
    ) -> Result<ResultAuthorityRecordV2, KeyAuthorityErrorV2> {
        (**self).snapshot(result_id)
    }

    fn with_result_key<R, F>(
        &self,
        result_id: ResultId,
        operation: F,
    ) -> Result<R, KeyAuthorityErrorV2>
    where
        F: FnOnce(&ResultAuthorityRecordV2, &ResultDekV1) -> Result<R, KeyAuthorityErrorV2>,
    {
        (**self).with_result_key(result_id, operation)
    }

    fn destroy(
        &self,
        result_id: ResultId,
    ) -> Result<AuthorityDestroyOutcomeV2, KeyAuthorityErrorV2> {
        (**self).destroy(result_id)
    }

    fn list(&self) -> Result<Vec<ResultAuthorityRecordV2>, KeyAuthorityErrorV2> {
        (**self).list()
    }
}

struct ProcessAuthorityEntryV2 {
    record: ResultAuthorityRecordV2,
    result_dek: ResultDekV1,
    nonce_operations: BTreeMap<OperationIdV1, (LifecycleDigestV1, u64, NonceReservationV1)>,
}

/// Process-local conformance authority.
///
/// This is intentionally not a production durability or rollback anchor. It
/// exists for deterministic repository tests and for embedders that provide no
/// durable mode. Production durable mode must inject a Keychain-backed
/// implementation of [`KeyAuthorityV2`].
pub struct ProcessKeyAuthorityV2 {
    capacity: usize,
    entries: Mutex<BTreeMap<ResultId, ProcessAuthorityEntryV2>>,
    publication_state: Mutex<ProcessPublicationStateV2>,
}

#[derive(Default)]
struct ProcessPublicationStateV2 {
    high_water: u64,
    operations: BTreeMap<(ResultId, OperationIdV1), (LifecycleDigestV1, u64)>,
}

impl ProcessKeyAuthorityV2 {
    pub fn new(capacity: usize) -> Result<Self, KeyAuthorityErrorV2> {
        if capacity == 0 {
            return Err(KeyAuthorityErrorV2::CapacityExceeded);
        }
        Ok(Self {
            capacity,
            entries: Mutex::new(BTreeMap::new()),
            publication_state: Mutex::new(ProcessPublicationStateV2::default()),
        })
    }

    fn lock_entries(
        &self,
    ) -> Result<MutexGuard<'_, BTreeMap<ResultId, ProcessAuthorityEntryV2>>, KeyAuthorityErrorV2>
    {
        self.entries.lock().map_err(|_| KeyAuthorityErrorV2::Locked)
    }
}

impl KeyAuthorityV2 for ProcessKeyAuthorityV2 {
    fn begin(
        &self,
        result_id: ResultId,
        created_unix_nanos: i64,
        expires_unix_nanos: i64,
        operation: OperationIdV1,
        canonical_digest: LifecycleDigestV1,
    ) -> Result<(ResultAuthorityRecordV2, LifecycleTransitionV1), KeyAuthorityErrorV2> {
        let mut entries = self.lock_entries()?;
        if let Some(entry) = entries.get(&result_id) {
            let encoded = entry.record.encode();
            let existing = ResultAuthorityRecordV2::decode(&encoded)
                .map_err(|_| KeyAuthorityErrorV2::Unavailable)?;
            if existing.matches_begin(
                created_unix_nanos,
                expires_unix_nanos,
                operation,
                canonical_digest,
            ) {
                return Ok((existing, LifecycleTransitionV1::AlreadyApplied));
            }
            return Err(KeyAuthorityErrorV2::OperationConflict);
        }
        if entries.len() == self.capacity {
            return Err(KeyAuthorityErrorV2::CapacityExceeded);
        }
        let mut dek_bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(dek_bytes.as_mut()).map_err(|_| KeyAuthorityErrorV2::EntropyUnavailable)?;
        let result_dek = ResultDekV1::from_zeroizing(dek_bytes)
            .map_err(|_| KeyAuthorityErrorV2::EntropyUnavailable)?;
        let mut prefix = [0u8; 16];
        getrandom::fill(&mut prefix).map_err(|_| KeyAuthorityErrorV2::EntropyUnavailable)?;
        let record = ResultAuthorityRecordV2::new_open(
            result_id,
            created_unix_nanos,
            expires_unix_nanos,
            ResultNoncePrefixV1::from_bytes(prefix),
            operation,
            canonical_digest,
        )?;
        entries.insert(
            result_id,
            ProcessAuthorityEntryV2 {
                record,
                result_dek,
                nonce_operations: BTreeMap::new(),
            },
        );
        Ok((record, LifecycleTransitionV1::Applied))
    }

    fn reserve_nonce_range(
        &self,
        result_id: ResultId,
        operation: OperationIdV1,
        canonical_digest: LifecycleDigestV1,
        count: u64,
    ) -> Result<NonceReservationV1, KeyAuthorityErrorV2> {
        let mut entries = self.lock_entries()?;
        let entry = entries
            .get_mut(&result_id)
            .ok_or(KeyAuthorityErrorV2::NotFound)?;
        if let Some((digest, existing_count, reservation)) = entry.nonce_operations.get(&operation)
        {
            if *digest == canonical_digest && *existing_count == count {
                return Ok(*reservation);
            }
            return Err(KeyAuthorityErrorV2::OperationConflict);
        }
        let reservation =
            entry
                .record
                .reserve_pending_nonce_range(operation, canonical_digest, count)?;
        entry
            .nonce_operations
            .insert(operation, (canonical_digest, count, reservation));
        Ok(reservation)
    }

    fn complete_nonce_reservation(
        &self,
        result_id: ResultId,
        operation: OperationIdV1,
        canonical_digest: LifecycleDigestV1,
    ) -> Result<LifecycleTransitionV1, KeyAuthorityErrorV2> {
        let mut entries = self.lock_entries()?;
        let entry = entries
            .get_mut(&result_id)
            .ok_or(KeyAuthorityErrorV2::NotFound)?;
        let Some((digest, _, _)) = entry.nonce_operations.get(&operation) else {
            return Err(KeyAuthorityErrorV2::OperationConflict);
        };
        if *digest != canonical_digest {
            return Err(KeyAuthorityErrorV2::OperationConflict);
        }
        entry
            .record
            .complete_pending_nonce_range(operation, canonical_digest)
            .map_err(Into::into)
    }

    fn commit_data(
        &self,
        result_id: ResultId,
        operation: OperationIdV1,
        canonical_digest: LifecycleDigestV1,
        build_context: BuildContextDigestsV1,
    ) -> Result<LifecycleTransitionV1, KeyAuthorityErrorV2> {
        let mut entries = self.lock_entries()?;
        entries
            .get_mut(&result_id)
            .ok_or(KeyAuthorityErrorV2::NotFound)?
            .record
            .commit_data(operation, canonical_digest, build_context)
            .map_err(Into::into)
    }

    fn seal(
        &self,
        result_id: ResultId,
        operation: OperationIdV1,
        commitments: SealCommitmentsV1,
    ) -> Result<LifecycleTransitionV1, KeyAuthorityErrorV2> {
        let mut entries = self.lock_entries()?;
        entries
            .get_mut(&result_id)
            .ok_or(KeyAuthorityErrorV2::NotFound)?
            .record
            .seal(operation, commitments)
            .map_err(Into::into)
    }

    fn reserve_publication_generation(
        &self,
        result_id: ResultId,
        operation: OperationIdV1,
        repository_commitment: LifecycleDigestV1,
    ) -> Result<u64, KeyAuthorityErrorV2> {
        if operation.is_zero() {
            return Err(KeyAuthorityErrorV2::OperationConflict);
        }
        let record = self.snapshot(result_id)?;
        if record.state() != evidentrail_snapshot_format::ResultLifecycleStateV1::Sealed {
            return Err(KeyAuthorityErrorV2::InvalidTransition);
        }
        let mut state = self
            .publication_state
            .lock()
            .map_err(|_| KeyAuthorityErrorV2::Locked)?;
        if let Some((digest, generation)) = state.operations.get(&(result_id, operation)) {
            if *digest == repository_commitment {
                return Ok(*generation);
            }
            return Err(KeyAuthorityErrorV2::OperationConflict);
        }
        let generation = state
            .high_water
            .checked_add(1)
            .ok_or(KeyAuthorityErrorV2::InvalidTransition)?;
        state.high_water = generation;
        state
            .operations
            .insert((result_id, operation), (repository_commitment, generation));
        Ok(generation)
    }

    fn publish(
        &self,
        result_id: ResultId,
        operation: OperationIdV1,
        generation: u64,
        repository_commitment: LifecycleDigestV1,
    ) -> Result<LifecycleTransitionV1, KeyAuthorityErrorV2> {
        let mut entries = self.lock_entries()?;
        entries
            .get_mut(&result_id)
            .ok_or(KeyAuthorityErrorV2::NotFound)?
            .record
            .publish(operation, generation, repository_commitment)
            .map_err(Into::into)
    }

    fn snapshot(
        &self,
        result_id: ResultId,
    ) -> Result<ResultAuthorityRecordV2, KeyAuthorityErrorV2> {
        self.lock_entries()?
            .get(&result_id)
            .map(|entry| entry.record)
            .ok_or(KeyAuthorityErrorV2::NotFound)
    }

    fn with_result_key<R, F>(
        &self,
        result_id: ResultId,
        operation: F,
    ) -> Result<R, KeyAuthorityErrorV2>
    where
        F: FnOnce(&ResultAuthorityRecordV2, &ResultDekV1) -> Result<R, KeyAuthorityErrorV2>,
    {
        let entries = self.lock_entries()?;
        let entry = entries
            .get(&result_id)
            .ok_or(KeyAuthorityErrorV2::NotFound)?;
        operation(&entry.record, &entry.result_dek)
    }

    fn destroy(
        &self,
        result_id: ResultId,
    ) -> Result<AuthorityDestroyOutcomeV2, KeyAuthorityErrorV2> {
        let removed = self.lock_entries()?.remove(&result_id).is_some();
        if removed {
            self.publication_state
                .lock()
                .map_err(|_| KeyAuthorityErrorV2::Locked)?
                .operations
                .retain(|(candidate, _), _| *candidate != result_id);
        }
        Ok(if removed {
            AuthorityDestroyOutcomeV2::Destroyed
        } else {
            AuthorityDestroyOutcomeV2::AlreadyAbsent
        })
    }

    fn list(&self) -> Result<Vec<ResultAuthorityRecordV2>, KeyAuthorityErrorV2> {
        Ok(self
            .lock_entries()?
            .values()
            .map(|entry| entry.record)
            .collect())
    }
}

impl fmt::Debug for ProcessKeyAuthorityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self
            .entries
            .lock()
            .map(|entries| entries.len())
            .unwrap_or(0);
        formatter
            .debug_struct("ProcessKeyAuthorityV2")
            .field("record_count", &count)
            .finish_non_exhaustive()
    }
}
