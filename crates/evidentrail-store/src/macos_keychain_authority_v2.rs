use std::fmt;
use std::sync::{Mutex, MutexGuard};

use evidentrail_schema::ResultId;
use evidentrail_snapshot_format::{
    BuildContextDigestsV1, LifecycleDigestV1, LifecycleTransitionV1, NonceReservationV1,
    OperationIdV1, ResultAuthorityRecordV2, ResultDekV1, ResultLifecycleStateV1,
    ResultNoncePrefixV1, SealCommitmentsV1,
};
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::base::Error as SecurityFrameworkError;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, SearchResult};
use security_framework::passwords::{
    PasswordOptions, delete_generic_password_options, generic_password,
    set_generic_password_options,
};
use security_framework_sys::base::{
    errSecAuthFailed as ERR_SEC_AUTH_FAILED, errSecItemNotFound as ERR_SEC_ITEM_NOT_FOUND,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{AuthorityDestroyOutcomeV2, KeyAuthorityErrorV2, KeyAuthorityV2};

const RESULT_SERVICE_V2: &str = "ai.evidentrail.snapshot-envelope.v1";
const PUBLICATION_SERVICE_V2: &str = "ai.evidentrail.snapshot-publication.v2";
const PUBLICATION_ACCOUNT_V2: &str = "global";
const ACCESS_PROBE_ACCOUNT_V2: &str = "access-probe";
const ACCESS_PROBE_VALUE_V2: &[u8] = b"evidentrail-keychain-access-probe-v2";
const DEFAULT_KEYCHAIN_AUTHORITY_CAPACITY_V2: usize = 16_384;

const ENTRY_MAGIC_V2: [u8; 8] = *b"EVRKEY02";
const ENTRY_VERSION_V2: u16 = 2;
const ENTRY_HEADER_BYTES_V2: usize = 16;
const RECORD_BYTES_V2: usize = 512;
const DEK_BYTES_V2: usize = 32;
const OPERATION_BYTES_V2: usize = 16;
const DIGEST_BYTES_V2: usize = 32;
const ENTRY_BYTES_V2: usize = 680;

const PUBLICATION_MAGIC_V2: [u8; 8] = *b"EVRPUB02";
const PUBLICATION_STATE_BYTES_V2: usize = 24;

// Security.framework does not currently export all legacy Keychain status
// constants through its sys crate.
const ERR_SEC_NOT_AVAILABLE: i32 = -25_291;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25_308;
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34_018;

/// Production macOS data-protection Keychain authority for durable results.
///
/// Each result's lifecycle record and raw result encryption key are one atomic
/// Keychain value. Items are device-bound, non-synchronizing, and available
/// only while the user session is unlocked. Repository files contain neither
/// the key nor the trusted lifecycle state.
pub struct MacOsKeychainAuthorityV2 {
    capacity: usize,
    result_service: String,
    publication_service: String,
    serialized: Mutex<()>,
}

impl MacOsKeychainAuthorityV2 {
    /// Open the fixed production Keychain namespace.
    pub fn production() -> Result<Self, KeyAuthorityErrorV2> {
        Self::new(DEFAULT_KEYCHAIN_AUTHORITY_CAPACITY_V2)
    }

    /// Open the fixed production Keychain namespace with an explicit bound.
    pub fn new(capacity: usize) -> Result<Self, KeyAuthorityErrorV2> {
        Self::with_services(
            capacity,
            RESULT_SERVICE_V2.to_owned(),
            PUBLICATION_SERVICE_V2.to_owned(),
        )
    }

    /// Verify that the host executable can create, read, and delete an item in
    /// its data-protection Keychain namespace without touching ciphertext.
    pub fn verify_access(&self) -> Result<(), KeyAuthorityErrorV2> {
        let _guard = self.lock()?;
        let options = Self::password_options(&self.publication_service, ACCESS_PROBE_ACCOUNT_V2);
        match delete_generic_password_options(options) {
            Ok(()) => {}
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => {}
            Err(error) => return Err(map_security_error(error)),
        }
        Self::set_value(
            &self.publication_service,
            ACCESS_PROBE_ACCOUNT_V2,
            ACCESS_PROBE_VALUE_V2,
            true,
        )?;
        let observed = Self::get_value(&self.publication_service, ACCESS_PROBE_ACCOUNT_V2)?;
        if observed.as_slice() != ACCESS_PROBE_VALUE_V2 {
            return Err(KeyAuthorityErrorV2::Unavailable);
        }
        let options = Self::password_options(&self.publication_service, ACCESS_PROBE_ACCOUNT_V2);
        delete_generic_password_options(options).map_err(map_security_error)
    }

    #[doc(hidden)]
    pub fn isolated_for_tests(
        capacity: usize,
        namespace: &str,
    ) -> Result<Self, KeyAuthorityErrorV2> {
        if namespace.is_empty() || namespace.len() > 96 {
            return Err(KeyAuthorityErrorV2::Unavailable);
        }
        Self::with_services(
            capacity,
            format!("{RESULT_SERVICE_V2}.test.{namespace}"),
            format!("{PUBLICATION_SERVICE_V2}.test.{namespace}"),
        )
    }

    fn with_services(
        capacity: usize,
        result_service: String,
        publication_service: String,
    ) -> Result<Self, KeyAuthorityErrorV2> {
        if capacity == 0 {
            return Err(KeyAuthorityErrorV2::CapacityExceeded);
        }
        Ok(Self {
            capacity,
            result_service,
            publication_service,
            serialized: Mutex::new(()),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, ()>, KeyAuthorityErrorV2> {
        self.serialized
            .lock()
            .map_err(|_| KeyAuthorityErrorV2::Unavailable)
    }

    fn result_account(result_id: ResultId) -> String {
        result_id.canonical_token()
    }

    fn password_options(service: &str, account: &str) -> PasswordOptions {
        let mut options = PasswordOptions::new_generic_password(service, account);
        options.set_access_synchronized(Some(false));
        options.use_protected_keychain();
        options
    }

    fn create_options(
        service: &str,
        account: &str,
    ) -> Result<PasswordOptions, KeyAuthorityErrorV2> {
        let mut options = Self::password_options(service, account);
        let control = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            0,
        )
        .map_err(map_security_error)?;
        options.set_access_control(control);
        Ok(options)
    }

    fn get_value(service: &str, account: &str) -> Result<Zeroizing<Vec<u8>>, KeyAuthorityErrorV2> {
        generic_password(Self::password_options(service, account))
            .map(Zeroizing::new)
            .map_err(map_security_error)
    }

    fn set_value(
        service: &str,
        account: &str,
        value: &[u8],
        create: bool,
    ) -> Result<(), KeyAuthorityErrorV2> {
        let options = if create {
            Self::create_options(service, account)?
        } else {
            Self::password_options(service, account)
        };
        set_generic_password_options(value, options).map_err(map_security_error)
    }

    fn get_entry(&self, result_id: ResultId) -> Result<KeychainEntryV2, KeyAuthorityErrorV2> {
        let encoded = Self::get_value(&self.result_service, &Self::result_account(result_id))?;
        KeychainEntryV2::decode(&encoded, result_id)
    }

    fn set_entry(
        &self,
        result_id: ResultId,
        entry: &KeychainEntryV2,
        create: bool,
    ) -> Result<(), KeyAuthorityErrorV2> {
        let encoded = entry.encode();
        Self::set_value(
            &self.result_service,
            &Self::result_account(result_id),
            &encoded,
            create,
        )
    }

    fn mutate_entry<R>(
        &self,
        result_id: ResultId,
        mutation: impl FnOnce(&mut KeychainEntryV2) -> Result<R, KeyAuthorityErrorV2>,
    ) -> Result<R, KeyAuthorityErrorV2> {
        let _guard = self.lock()?;
        let mut entry = self.get_entry(result_id)?;
        let output = mutation(&mut entry)?;
        self.set_entry(result_id, &entry, false)?;
        Ok(output)
    }

    fn search_entries(&self) -> Result<Vec<KeychainEntryV2>, KeyAuthorityErrorV2> {
        let mut search = ItemSearchOptions::new();
        search
            .class(ItemClass::generic_password())
            .service(&self.result_service)
            .cloud_sync(Some(false))
            .ignore_legacy_keychains()
            .load_data(true)
            .limit(Limit::All);
        let results = match search.search() {
            Ok(results) => results,
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => return Ok(Vec::new()),
            Err(error) => return Err(map_security_error(error)),
        };
        let mut entries = Vec::with_capacity(results.len());
        for result in results {
            let SearchResult::Data(bytes) = result else {
                return Err(KeyAuthorityErrorV2::Unavailable);
            };
            entries.push(KeychainEntryV2::decode_unbound(&Zeroizing::new(bytes))?);
        }
        Ok(entries)
    }

    fn read_publication_high_water(&self) -> Result<u64, KeyAuthorityErrorV2> {
        match Self::get_value(&self.publication_service, PUBLICATION_ACCOUNT_V2) {
            Ok(encoded) => decode_publication_state(&encoded),
            Err(KeyAuthorityErrorV2::NotFound) => Ok(0),
            Err(error) => Err(error),
        }
    }

    fn write_publication_high_water(
        &self,
        high_water: u64,
        create: bool,
    ) -> Result<(), KeyAuthorityErrorV2> {
        let encoded = encode_publication_state(high_water);
        Self::set_value(
            &self.publication_service,
            PUBLICATION_ACCOUNT_V2,
            &encoded,
            create,
        )
    }
}

impl KeyAuthorityV2 for MacOsKeychainAuthorityV2 {
    fn begin(
        &self,
        result_id: ResultId,
        created_unix_nanos: i64,
        expires_unix_nanos: i64,
        operation: OperationIdV1,
        canonical_digest: LifecycleDigestV1,
    ) -> Result<(ResultAuthorityRecordV2, LifecycleTransitionV1), KeyAuthorityErrorV2> {
        let _guard = self.lock()?;
        match self.get_entry(result_id) {
            Ok(entry) => {
                if entry.record.matches_begin(
                    created_unix_nanos,
                    expires_unix_nanos,
                    operation,
                    canonical_digest,
                ) {
                    return Ok((entry.record, LifecycleTransitionV1::AlreadyApplied));
                }
                return Err(KeyAuthorityErrorV2::OperationConflict);
            }
            Err(KeyAuthorityErrorV2::NotFound) => {}
            Err(error) => return Err(error),
        }
        if self.search_entries()?.len() >= self.capacity {
            return Err(KeyAuthorityErrorV2::CapacityExceeded);
        }

        let mut dek = Zeroizing::new([0_u8; DEK_BYTES_V2]);
        getrandom::fill(dek.as_mut()).map_err(|_| KeyAuthorityErrorV2::EntropyUnavailable)?;
        if dek.iter().all(|byte| *byte == 0) {
            return Err(KeyAuthorityErrorV2::EntropyUnavailable);
        }
        let mut nonce_prefix = [0_u8; 16];
        getrandom::fill(&mut nonce_prefix).map_err(|_| KeyAuthorityErrorV2::EntropyUnavailable)?;
        let record = ResultAuthorityRecordV2::new_open(
            result_id,
            created_unix_nanos,
            expires_unix_nanos,
            ResultNoncePrefixV1::from_bytes(nonce_prefix),
            operation,
            canonical_digest,
        )?;
        let entry = KeychainEntryV2::new(record, dek);
        self.set_entry(result_id, &entry, true)?;
        Ok((record, LifecycleTransitionV1::Applied))
    }

    fn reserve_nonce_range(
        &self,
        result_id: ResultId,
        operation: OperationIdV1,
        canonical_digest: LifecycleDigestV1,
        count: u64,
    ) -> Result<NonceReservationV1, KeyAuthorityErrorV2> {
        self.mutate_entry(result_id, |entry| {
            if !entry.last_nonce_operation.is_zero() {
                if entry.last_nonce_operation == operation
                    && entry.last_nonce_digest == canonical_digest
                    && entry.last_nonce_count == count
                {
                    return NonceReservationV1::new(
                        entry.record.nonce_prefix(),
                        entry.last_nonce_first,
                        count,
                    )
                    .map_err(Into::into);
                }
                if entry.record.has_pending_nonce_reservation() {
                    return Err(KeyAuthorityErrorV2::OperationConflict);
                }
            }
            let reservation =
                entry
                    .record
                    .reserve_pending_nonce_range(operation, canonical_digest, count)?;
            entry.last_nonce_operation = operation;
            entry.last_nonce_digest = canonical_digest;
            entry.last_nonce_first = reservation.first_counter();
            entry.last_nonce_count = count;
            Ok(reservation)
        })
    }

    fn complete_nonce_reservation(
        &self,
        result_id: ResultId,
        operation: OperationIdV1,
        canonical_digest: LifecycleDigestV1,
    ) -> Result<LifecycleTransitionV1, KeyAuthorityErrorV2> {
        self.mutate_entry(result_id, |entry| {
            if entry.last_nonce_operation != operation
                || entry.last_nonce_digest != canonical_digest
            {
                return Err(KeyAuthorityErrorV2::OperationConflict);
            }
            entry
                .record
                .complete_pending_nonce_range(operation, canonical_digest)
                .map_err(Into::into)
        })
    }

    fn commit_data(
        &self,
        result_id: ResultId,
        operation: OperationIdV1,
        canonical_digest: LifecycleDigestV1,
        build_context: BuildContextDigestsV1,
    ) -> Result<LifecycleTransitionV1, KeyAuthorityErrorV2> {
        self.mutate_entry(result_id, |entry| {
            entry
                .record
                .commit_data(operation, canonical_digest, build_context)
                .map_err(Into::into)
        })
    }

    fn seal(
        &self,
        result_id: ResultId,
        operation: OperationIdV1,
        commitments: SealCommitmentsV1,
    ) -> Result<LifecycleTransitionV1, KeyAuthorityErrorV2> {
        self.mutate_entry(result_id, |entry| {
            entry
                .record
                .seal(operation, commitments)
                .map_err(Into::into)
        })
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
        let _guard = self.lock()?;
        let mut entry = self.get_entry(result_id)?;
        if entry.record.state() != ResultLifecycleStateV1::Sealed {
            return Err(KeyAuthorityErrorV2::InvalidTransition);
        }
        if !entry.publication_operation.is_zero() {
            if entry.publication_operation == operation
                && entry.publication_digest == repository_commitment
            {
                let high_water = self.read_publication_high_water()?;
                if high_water < entry.publication_generation {
                    self.write_publication_high_water(
                        entry.publication_generation,
                        high_water == 0,
                    )?;
                }
                return Ok(entry.publication_generation);
            }
            return Err(KeyAuthorityErrorV2::OperationConflict);
        }
        let old_high_water = self.read_publication_high_water()?;
        let observed_high_water =
            self.search_entries()?
                .into_iter()
                .fold(old_high_water, |high_water, candidate| {
                    high_water
                        .max(candidate.record.publication_generation())
                        .max(candidate.publication_generation)
                });
        let generation = observed_high_water
            .checked_add(1)
            .ok_or(KeyAuthorityErrorV2::InvalidTransition)?;
        entry.publication_operation = operation;
        entry.publication_digest = repository_commitment;
        entry.publication_generation = generation;
        self.set_entry(result_id, &entry, false)?;
        // Persist the per-result reservation first. If the following global
        // update fails or the process crashes, an exact retry returns this
        // generation and every other allocator observes it during its scan.
        self.write_publication_high_water(generation, old_high_water == 0)?;
        Ok(generation)
    }

    fn publish(
        &self,
        result_id: ResultId,
        operation: OperationIdV1,
        generation: u64,
        repository_commitment: LifecycleDigestV1,
    ) -> Result<LifecycleTransitionV1, KeyAuthorityErrorV2> {
        self.mutate_entry(result_id, |entry| {
            if entry.publication_operation != operation
                || entry.publication_digest != repository_commitment
                || entry.publication_generation != generation
            {
                return Err(KeyAuthorityErrorV2::OperationConflict);
            }
            entry
                .record
                .publish(operation, generation, repository_commitment)
                .map_err(Into::into)
        })
    }

    fn snapshot(
        &self,
        result_id: ResultId,
    ) -> Result<ResultAuthorityRecordV2, KeyAuthorityErrorV2> {
        let _guard = self.lock()?;
        Ok(self.get_entry(result_id)?.record)
    }

    fn with_result_key<R, F>(
        &self,
        result_id: ResultId,
        operation: F,
    ) -> Result<R, KeyAuthorityErrorV2>
    where
        F: FnOnce(&ResultAuthorityRecordV2, &ResultDekV1) -> Result<R, KeyAuthorityErrorV2>,
    {
        let _guard = self.lock()?;
        let entry = self.get_entry(result_id)?;
        let result_dek = ResultDekV1::from_zeroizing(Zeroizing::new(*entry.result_dek))
            .map_err(|_| KeyAuthorityErrorV2::Unavailable)?;
        operation(&entry.record, &result_dek)
    }

    fn destroy(
        &self,
        result_id: ResultId,
    ) -> Result<AuthorityDestroyOutcomeV2, KeyAuthorityErrorV2> {
        let _guard = self.lock()?;
        let options =
            Self::password_options(&self.result_service, &Self::result_account(result_id));
        match delete_generic_password_options(options) {
            Ok(()) => Ok(AuthorityDestroyOutcomeV2::Destroyed),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => {
                Ok(AuthorityDestroyOutcomeV2::AlreadyAbsent)
            }
            Err(error) => Err(map_security_error(error)),
        }
    }

    fn list(&self) -> Result<Vec<ResultAuthorityRecordV2>, KeyAuthorityErrorV2> {
        let _guard = self.lock()?;
        Ok(self
            .search_entries()?
            .into_iter()
            .map(|entry| entry.record)
            .collect())
    }
}

impl fmt::Debug for MacOsKeychainAuthorityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacOsKeychainAuthorityV2")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

struct KeychainEntryV2 {
    record: ResultAuthorityRecordV2,
    result_dek: Zeroizing<[u8; DEK_BYTES_V2]>,
    last_nonce_operation: OperationIdV1,
    last_nonce_digest: LifecycleDigestV1,
    last_nonce_first: u64,
    last_nonce_count: u64,
    publication_operation: OperationIdV1,
    publication_digest: LifecycleDigestV1,
    publication_generation: u64,
}

impl KeychainEntryV2 {
    fn new(record: ResultAuthorityRecordV2, result_dek: Zeroizing<[u8; DEK_BYTES_V2]>) -> Self {
        Self {
            record,
            result_dek,
            last_nonce_operation: OperationIdV1::from_bytes([0; OPERATION_BYTES_V2]),
            last_nonce_digest: LifecycleDigestV1::from_bytes([0; DIGEST_BYTES_V2]),
            last_nonce_first: 0,
            last_nonce_count: 0,
            publication_operation: OperationIdV1::from_bytes([0; OPERATION_BYTES_V2]),
            publication_digest: LifecycleDigestV1::from_bytes([0; DIGEST_BYTES_V2]),
            publication_generation: 0,
        }
    }

    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut encoded = Zeroizing::new(vec![0_u8; ENTRY_BYTES_V2]);
        encoded[0..8].copy_from_slice(&ENTRY_MAGIC_V2);
        encoded[8..10].copy_from_slice(&ENTRY_VERSION_V2.to_be_bytes());
        encoded[ENTRY_HEADER_BYTES_V2..ENTRY_HEADER_BYTES_V2 + RECORD_BYTES_V2]
            .copy_from_slice(&self.record.encode());
        encoded[528..560].copy_from_slice(self.result_dek.as_ref());
        encoded[560..576].copy_from_slice(self.last_nonce_operation.as_bytes());
        encoded[576..608].copy_from_slice(self.last_nonce_digest.as_bytes());
        encoded[608..616].copy_from_slice(&self.last_nonce_first.to_be_bytes());
        encoded[616..624].copy_from_slice(&self.last_nonce_count.to_be_bytes());
        encoded[624..640].copy_from_slice(self.publication_operation.as_bytes());
        encoded[640..672].copy_from_slice(self.publication_digest.as_bytes());
        encoded[672..680].copy_from_slice(&self.publication_generation.to_be_bytes());
        encoded
    }

    fn decode(encoded: &[u8], expected_result_id: ResultId) -> Result<Self, KeyAuthorityErrorV2> {
        let entry = Self::decode_unbound(encoded)?;
        if entry.record.result_id() != expected_result_id {
            return Err(KeyAuthorityErrorV2::Unavailable);
        }
        Ok(entry)
    }

    fn decode_unbound(encoded: &[u8]) -> Result<Self, KeyAuthorityErrorV2> {
        if encoded.len() != ENTRY_BYTES_V2
            || encoded[0..8] != ENTRY_MAGIC_V2
            || read_u16(encoded, 8) != ENTRY_VERSION_V2
            || encoded[10..16].iter().any(|byte| *byte != 0)
        {
            return Err(KeyAuthorityErrorV2::Unavailable);
        }
        let record = ResultAuthorityRecordV2::decode(&encoded[16..528])
            .map_err(|_| KeyAuthorityErrorV2::Unavailable)?;
        let result_dek = Zeroizing::new(read_array(encoded, 528));
        if result_dek.iter().all(|byte| *byte == 0) {
            return Err(KeyAuthorityErrorV2::Unavailable);
        }
        let entry = Self {
            record,
            result_dek,
            last_nonce_operation: OperationIdV1::from_bytes(read_array(encoded, 560)),
            last_nonce_digest: LifecycleDigestV1::from_bytes(read_array(encoded, 576)),
            last_nonce_first: read_u64(encoded, 608),
            last_nonce_count: read_u64(encoded, 616),
            publication_operation: OperationIdV1::from_bytes(read_array(encoded, 624)),
            publication_digest: LifecycleDigestV1::from_bytes(read_array(encoded, 640)),
            publication_generation: read_u64(encoded, 672),
        };
        let nonce_zero = entry.last_nonce_operation.is_zero()
            && entry.last_nonce_digest.is_zero()
            && entry.last_nonce_first == 0
            && entry.last_nonce_count == 0;
        let nonce_valid = !entry.last_nonce_operation.is_zero() && entry.last_nonce_count > 0;
        let publication_zero = entry.publication_operation.is_zero()
            && entry.publication_digest.is_zero()
            && entry.publication_generation == 0;
        let publication_valid = !entry.publication_operation.is_zero()
            && !entry.publication_digest.is_zero()
            && entry.publication_generation > 0;
        if !(nonce_zero || nonce_valid) || !(publication_zero || publication_valid) {
            return Err(KeyAuthorityErrorV2::Unavailable);
        }
        Ok(entry)
    }
}

fn encode_publication_state(high_water: u64) -> [u8; PUBLICATION_STATE_BYTES_V2] {
    let mut encoded = [0_u8; PUBLICATION_STATE_BYTES_V2];
    encoded[0..8].copy_from_slice(&PUBLICATION_MAGIC_V2);
    encoded[8..10].copy_from_slice(&ENTRY_VERSION_V2.to_be_bytes());
    encoded[16..24].copy_from_slice(&high_water.to_be_bytes());
    encoded
}

fn decode_publication_state(encoded: &[u8]) -> Result<u64, KeyAuthorityErrorV2> {
    if encoded.len() != PUBLICATION_STATE_BYTES_V2
        || encoded[0..8] != PUBLICATION_MAGIC_V2
        || read_u16(encoded, 8) != ENTRY_VERSION_V2
        || encoded[10..16].iter().any(|byte| *byte != 0)
    {
        return Err(KeyAuthorityErrorV2::Unavailable);
    }
    Ok(read_u64(encoded, 16))
}

fn map_security_error(error: SecurityFrameworkError) -> KeyAuthorityErrorV2 {
    match error.code() {
        ERR_SEC_ITEM_NOT_FOUND => KeyAuthorityErrorV2::NotFound,
        ERR_SEC_INTERACTION_NOT_ALLOWED | ERR_SEC_AUTH_FAILED => KeyAuthorityErrorV2::Locked,
        ERR_SEC_NOT_AVAILABLE | ERR_SEC_MISSING_ENTITLEMENT => KeyAuthorityErrorV2::Unavailable,
        _ => KeyAuthorityErrorV2::UpdateFailed,
    }
}

fn read_u16(encoded: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(read_array(encoded, offset))
}

fn read_u64(encoded: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(read_array(encoded, offset))
}

fn read_array<const N: usize>(encoded: &[u8], offset: usize) -> [u8; N] {
    let mut bytes = [0_u8; N];
    bytes.copy_from_slice(&encoded[offset..offset + N]);
    bytes
}

impl Drop for KeychainEntryV2 {
    fn drop(&mut self) {
        self.result_dek.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keychain_envelope_and_publication_state_are_canonical_and_bound() {
        let result_id = ResultId::from_bytes([0x71; 32]);
        let record = ResultAuthorityRecordV2::new_open(
            result_id,
            10,
            20,
            ResultNoncePrefixV1::from_bytes([0x72; 16]),
            OperationIdV1::from_bytes([0x73; 16]),
            LifecycleDigestV1::from_bytes([0x74; 32]),
        )
        .unwrap();
        let entry = KeychainEntryV2::new(record, Zeroizing::new([0x75; 32]));
        let encoded = entry.encode();
        let decoded = KeychainEntryV2::decode(&encoded, result_id).unwrap();
        assert_eq!(decoded.record, record);
        assert_eq!(decoded.result_dek.as_ref(), &[0x75; 32]);
        assert!(matches!(
            KeychainEntryV2::decode(&encoded, ResultId::from_bytes([0x76; 32])),
            Err(KeyAuthorityErrorV2::Unavailable)
        ));

        let publication = encode_publication_state(41);
        assert_eq!(decode_publication_state(&publication), Ok(41));
        let mut corrupted = publication;
        corrupted[15] = 1;
        assert_eq!(
            decode_publication_state(&corrupted),
            Err(KeyAuthorityErrorV2::Unavailable)
        );
    }
}
