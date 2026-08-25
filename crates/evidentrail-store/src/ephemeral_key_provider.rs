use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Mutex, MutexGuard};

use evidentrail_schema::ResultId;
use evidentrail_snapshot_format::{
    DekWrapNonceV1, DerivedResultKeysV1, EntropySourceV1, FrameNonceV1,
    KEY_ENVELOPE_NONCE_BYTES_V1, KeyEnvelopeContextV1, ManifestNonceV1, OpenedSealBindingV1,
    RESULT_DEK_BYTES_V1, RESULT_KEY_RECORD_BYTES_V1, ResultDekV1, ResultKeyRecordStateV1,
    ResultKeyRecordV1, ResultKeySealTransitionV1, RootKekV1, RootKeyVersionV1,
    SEAL_BINDING_BYTES_V1, SealBindingNonceV1, SealBindingV1, seal_binding_v1, wrap_result_dek_v1,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    CreatingKeyContextV1, ExpectedKeyContextV1, KeyDestroyOutcomeV1, KeyProviderErrorV1,
    KeyProviderV1, KeyRecordListStateV1, KeyRecordMetadataV1, OpenedResultKeyV1,
};

/// Hard lifetime issuance bound for the internal ephemeral provider.
///
/// Destroyed result identities remain tombstoned so one derived-key namespace
/// is never silently reused. Consequently this bounds total identities issued
/// during one provider instance, not merely the currently live map size.
pub const MAX_EPHEMERAL_KEY_RECORDS_V1: usize = 4_096;
const MAX_EPHEMERAL_ROOT_GENERATIONS_V1: usize = MAX_EPHEMERAL_KEY_RECORDS_V1 + 1;
const SECRET_EQUALITY_COMMITMENT_DOMAIN_V1: &[u8] = b"evidentrail.store.ephemeral.secret-equality.v1";

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProviderModeV1 {
    Ready,
    Locked,
    Unavailable,
}

struct RootRecordV1 {
    version: RootKeyVersionV1,
    key: RootKekV1,
}

struct StoredKeyRecordV1 {
    context: KeyEnvelopeContextV1,
    encoded: [u8; RESULT_KEY_RECORD_BYTES_V1],
    pending_seal: Option<PendingSealUpdateV1>,
}

// This private candidate exists only to inject an atomic in-memory update
// failure. It is not a recovery journal and makes no durability or crash-
// ambiguity claim. Exact retry re-authenticates and republishes these same
// encrypted bytes without issuing another nonce.
struct PendingSealUpdateV1 {
    binding_bytes: [u8; SEAL_BINDING_BYTES_V1],
    encoded: [u8; RESULT_KEY_RECORD_BYTES_V1],
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum EnvelopeNonceKindV1 {
    DekWrap,
    SealBinding,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct IssuedEnvelopeNonceV1 {
    result_id: ResultId,
    kind: EnvelopeNonceKindV1,
    bytes: [u8; KEY_ENVELOPE_NONCE_BYTES_V1],
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct IssuedSnapshotObjectNonceV1 {
    result_id: ResultId,
    bytes: [u8; KEY_ENVELOPE_NONCE_BYTES_V1],
}

struct EphemeralStateV1<E> {
    entropy: E,
    root: Option<RootRecordV1>,
    last_root_version: u32,
    root_generation_count: usize,
    records: BTreeMap<ResultId, StoredKeyRecordV1>,
    issued_result_ids: BTreeSet<ResultId>,
    // Private equality-only commitments prevent catastrophic injected-RNG
    // repeats without retaining or exporting another plaintext secret copy.
    issued_secret_commitments: BTreeSet<[u8; 32]>,
    issued_nonces: BTreeSet<IssuedEnvelopeNonceV1>,
    // Manifest and future frame nonces intentionally share this per-result
    // namespace because both use the same result DEK.
    issued_snapshot_object_nonces: BTreeSet<IssuedSnapshotObjectNonceV1>,
    snapshot_object_nonce_counts: BTreeMap<ResultId, u64>,
    capacity: usize,
    mode: ProviderModeV1,
    fail_next_update: bool,
    failed_seal_updates_remaining: u8,
}

/// Internal-only, in-memory implementation of [`KeyProviderV1`].
///
/// The type is absent from default builds. It serializes all operations with a
/// mutex, retains only canonical encrypted result-key records, and is intended
/// solely for deterministic tests before a real platform key provider exists.
/// It makes no persistence, durability, recovery, Keychain, or production RNG
/// claim.
pub struct EphemeralKeyProviderV1<E> {
    state: Mutex<EphemeralStateV1<E>>,
}

impl<E: EntropySourceV1> EphemeralKeyProviderV1<E> {
    pub fn new(entropy: E, capacity: usize) -> Result<Self, KeyProviderErrorV1> {
        if capacity == 0 || capacity > MAX_EPHEMERAL_KEY_RECORDS_V1 {
            return Err(KeyProviderErrorV1::InvalidCapacity);
        }
        Ok(Self {
            state: Mutex::new(EphemeralStateV1 {
                entropy,
                root: None,
                last_root_version: 0,
                root_generation_count: 0,
                records: BTreeMap::new(),
                issued_result_ids: BTreeSet::new(),
                issued_secret_commitments: BTreeSet::new(),
                issued_nonces: BTreeSet::new(),
                issued_snapshot_object_nonces: BTreeSet::new(),
                snapshot_object_nonce_counts: BTreeMap::new(),
                capacity,
                mode: ProviderModeV1::Ready,
                fail_next_update: false,
                failed_seal_updates_remaining: 0,
            }),
        })
    }

    /// Internal fault injection: model a locked platform provider.
    pub fn set_locked_for_test(&self, locked: bool) -> Result<(), KeyProviderErrorV1> {
        self.lock_state()?.mode = if locked {
            ProviderModeV1::Locked
        } else {
            ProviderModeV1::Ready
        };
        Ok(())
    }

    /// Internal fault injection: model a generally unavailable provider.
    pub fn set_unavailable_for_test(&self, unavailable: bool) -> Result<(), KeyProviderErrorV1> {
        self.lock_state()?.mode = if unavailable {
            ProviderModeV1::Unavailable
        } else {
            ProviderModeV1::Ready
        };
        Ok(())
    }

    /// Internal fault injection: fail the next create or seal publication.
    pub fn fail_next_update_for_test(&self) -> Result<(), KeyProviderErrorV1> {
        self.lock_state()?.fail_next_update = true;
        Ok(())
    }

    /// Internal fault injection: fail only the next seal publication, without
    /// consuming the fault during result-key creation.
    pub fn fail_next_seal_update_for_test(&self) -> Result<(), KeyProviderErrorV1> {
        self.lock_state()?.failed_seal_updates_remaining = 1;
        Ok(())
    }

    /// Internal fault injection: fail both attempts made by the provisional
    /// encrypted repository's one-retry seal policy.
    pub fn fail_next_two_seal_updates_for_test(&self) -> Result<(), KeyProviderErrorV1> {
        self.lock_state()?.failed_seal_updates_remaining = 2;
        Ok(())
    }

    /// Internal fault injection: mutate one encrypted outer-record byte.
    pub fn corrupt_record_byte_for_test(
        &self,
        result_id: &ResultId,
        offset: usize,
    ) -> Result<(), KeyProviderErrorV1> {
        if offset >= RESULT_KEY_RECORD_BYTES_V1 {
            return Err(KeyProviderErrorV1::Unavailable);
        }
        let mut state = self.lock_state()?;
        let record = state
            .records
            .get_mut(result_id)
            .ok_or(KeyProviderErrorV1::Unavailable)?;
        record.encoded[offset] ^= 0x80;
        Ok(())
    }

    /// Internal fault injection: model external root-key deletion.
    pub fn drop_root_for_test(&self) -> Result<(), KeyProviderErrorV1> {
        self.lock_state()?.root = None;
        Ok(())
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, EphemeralStateV1<E>>, KeyProviderErrorV1> {
        self.state
            .lock()
            .map_err(|_| KeyProviderErrorV1::Unavailable)
    }
}

impl<E> fmt::Debug for EphemeralKeyProviderV1<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EphemeralKeyProviderV1")
            .field("availability", &"internal-test-only")
            .finish_non_exhaustive()
    }
}

impl<E: EntropySourceV1 + Send> KeyProviderV1 for EphemeralKeyProviderV1<E> {
    fn ensure_root_key(&self) -> Result<RootKeyVersionV1, KeyProviderErrorV1> {
        let mut state = self.lock_state()?;
        ensure_operational(&state)?;
        ensure_root(&mut state)
    }

    fn create_result_key(
        &self,
        context: &CreatingKeyContextV1,
    ) -> Result<OpenedResultKeyV1, KeyProviderErrorV1> {
        let mut state = self.lock_state()?;
        ensure_operational(&state)?;

        let result_id = context.result_id();
        if state.issued_result_ids.contains(&result_id) {
            return Err(KeyProviderErrorV1::DuplicateResult);
        }
        if state.issued_result_ids.len() >= state.capacity {
            return Err(KeyProviderErrorV1::CapacityExceeded);
        }
        if state
            .issued_secret_commitments
            .contains(&secret_equality_commitment(result_id.as_bytes()))
        {
            return Err(KeyProviderErrorV1::SecretMatchesResultId);
        }

        let root = state.root.as_ref().ok_or(KeyProviderErrorV1::Unavailable)?;
        let root_key_version = root.version;
        let keys = root
            .key
            .derive_result_keys(result_id, root_key_version)
            .map_err(|_| KeyProviderErrorV1::Unavailable)?;
        let envelope_context = KeyEnvelopeContextV1::new(
            root_key_version,
            result_id,
            context.created_unix_nanos(),
            context.expires_unix_nanos(),
        )
        .map_err(|_| KeyProviderErrorV1::Unavailable)?;

        let dek_bytes = fill_nonzero::<_, RESULT_DEK_BYTES_V1>(&mut state.entropy)?;
        let dek_commitment = secret_equality_commitment(&dek_bytes);
        if dek_commitment == secret_equality_commitment(result_id.as_bytes())
            || state
                .issued_result_ids
                .iter()
                .any(|issued| secret_equality_commitment(issued.as_bytes()) == dek_commitment)
        {
            return Err(KeyProviderErrorV1::SecretMatchesResultId);
        }
        if !state.issued_secret_commitments.insert(dek_commitment) {
            return Err(KeyProviderErrorV1::SecretEntropyRepeated);
        }
        state.issued_result_ids.insert(result_id);
        let result_dek = ResultDekV1::from_zeroizing(dek_bytes)
            .map_err(|_| KeyProviderErrorV1::EntropyRejected)?;
        let wrap_nonce = issue_nonce(&mut state, result_id, EnvelopeNonceKindV1::DekWrap)?;
        let wrapped = wrap_result_dek_v1(
            &keys.dek_wrap_key(),
            &envelope_context,
            DekWrapNonceV1::from_bytes(wrap_nonce),
            &result_dek,
        )
        .map_err(|_| KeyProviderErrorV1::Unavailable)?;
        let record =
            ResultKeyRecordV1::new_creating(envelope_context, &keys.dek_wrap_key(), wrapped)
                .map_err(|_| KeyProviderErrorV1::Unavailable)?;
        let encoded = record.encode();

        if consume_failed_update(&mut state) {
            return Err(KeyProviderErrorV1::UpdateFailed);
        }
        state.records.insert(
            result_id,
            StoredKeyRecordV1 {
                context: envelope_context,
                encoded,
                pending_seal: None,
            },
        );

        Ok(OpenedResultKeyV1::new(
            result_id,
            root_key_version,
            context.created_unix_nanos(),
            context.expires_unix_nanos(),
            ResultKeyRecordStateV1::Creating,
            result_dek,
            None,
        ))
    }

    fn issue_snapshot_manifest_nonce(
        &self,
        result_id: &ResultId,
    ) -> Result<ManifestNonceV1, KeyProviderErrorV1> {
        let mut state = self.lock_state()?;
        ensure_operational(&state)?;
        let authenticated = authenticate_record(&state, result_id)?;
        if authenticated.record.state() != ResultKeyRecordStateV1::Creating {
            return Err(KeyProviderErrorV1::Unavailable);
        }
        drop(authenticated);

        issue_snapshot_object_nonce(&mut state, *result_id).map(ManifestNonceV1::from_bytes)
    }

    fn issue_snapshot_frame_nonce(
        &self,
        result_id: &ResultId,
    ) -> Result<FrameNonceV1, KeyProviderErrorV1> {
        let mut state = self.lock_state()?;
        ensure_operational(&state)?;
        let authenticated = authenticate_record(&state, result_id)?;
        if authenticated.record.state() != ResultKeyRecordStateV1::Creating {
            return Err(KeyProviderErrorV1::Unavailable);
        }
        drop(authenticated);

        issue_snapshot_object_nonce(&mut state, *result_id).map(FrameNonceV1::from_bytes)
    }

    fn open_result_key(
        &self,
        result_id: &ResultId,
        expected_context: &ExpectedKeyContextV1,
    ) -> Result<OpenedResultKeyV1, KeyProviderErrorV1> {
        let state = self.lock_state()?;
        ensure_operational(&state)?;
        let authenticated = authenticate_record(&state, result_id)?;
        if authenticated.record.context().created_unix_nanos()
            != expected_context.created_unix_nanos()
            || authenticated.record.context().expires_unix_nanos()
                != expected_context.expires_unix_nanos()
        {
            return Err(KeyProviderErrorV1::Unavailable);
        }

        let context = *authenticated.record.context();
        Ok(OpenedResultKeyV1::new(
            *result_id,
            context.root_key_version(),
            context.created_unix_nanos(),
            context.expires_unix_nanos(),
            authenticated.record.state(),
            authenticated.result_dek,
            authenticated.seal_binding,
        ))
    }

    fn seal_result_key(
        &self,
        result_id: &ResultId,
        binding: &SealBindingV1,
    ) -> Result<ResultKeySealTransitionV1, KeyProviderErrorV1> {
        let mut state = self.lock_state()?;
        ensure_operational(&state)?;
        let mut authenticated = authenticate_record(&state, result_id)?;

        if let Some(pending) = state
            .records
            .get(result_id)
            .and_then(|stored| stored.pending_seal.as_ref())
        {
            if pending.binding_bytes != binding.encode() {
                return Err(KeyProviderErrorV1::DifferentSecondSeal);
            }
            let pending_record =
                ResultKeyRecordV1::decode(authenticated.record.context(), &pending.encoded)
                    .map_err(|_| KeyProviderErrorV1::Unavailable)?;
            if pending_record.state() != ResultKeyRecordStateV1::Sealed {
                return Err(KeyProviderErrorV1::Unavailable);
            }
            let pending_dek = pending_record
                .open_result_dek(&authenticated.keys.dek_wrap_key())
                .map_err(|_| KeyProviderErrorV1::Unavailable)?;
            drop(pending_dek);
            let pending_binding = pending_record
                .open_sealed_binding(&authenticated.keys.seal_key())
                .map_err(|_| KeyProviderErrorV1::Unavailable)?
                .ok_or(KeyProviderErrorV1::Unavailable)?;
            if !same_binding(&pending_binding, binding) {
                return Err(KeyProviderErrorV1::Unavailable);
            }
            if consume_failed_seal_update(&mut state) || consume_failed_update(&mut state) {
                return Err(KeyProviderErrorV1::UpdateFailed);
            }
            let stored = state
                .records
                .get_mut(result_id)
                .ok_or(KeyProviderErrorV1::Unavailable)?;
            let pending = stored
                .pending_seal
                .take()
                .ok_or(KeyProviderErrorV1::Unavailable)?;
            stored.encoded = pending.encoded;
            return Ok(ResultKeySealTransitionV1::Applied);
        }

        if authenticated.record.state() == ResultKeyRecordStateV1::Sealed {
            let existing = authenticated
                .seal_binding
                .as_ref()
                .ok_or(KeyProviderErrorV1::Unavailable)?;
            return if same_binding(existing, binding) {
                Ok(ResultKeySealTransitionV1::AlreadySealedSame)
            } else {
                Err(KeyProviderErrorV1::DifferentSecondSeal)
            };
        }

        let nonce = issue_nonce(&mut state, *result_id, EnvelopeNonceKindV1::SealBinding)?;
        let context = *authenticated.record.context();
        let sealed = seal_binding_v1(
            &authenticated.keys.seal_key(),
            &context,
            SealBindingNonceV1::from_bytes(nonce),
            binding,
        )
        .map_err(|_| KeyProviderErrorV1::Unavailable)?;
        let transition = authenticated
            .record
            .transition_to_sealed(
                &authenticated.keys.dek_wrap_key(),
                &authenticated.keys.seal_key(),
                sealed,
            )
            .map_err(|_| KeyProviderErrorV1::Unavailable)?;
        if transition != ResultKeySealTransitionV1::Applied {
            return Err(KeyProviderErrorV1::Unavailable);
        }
        let encoded = authenticated.record.encode();

        if consume_failed_seal_update(&mut state) || consume_failed_update(&mut state) {
            let stored = state
                .records
                .get_mut(result_id)
                .ok_or(KeyProviderErrorV1::Unavailable)?;
            stored.pending_seal = Some(PendingSealUpdateV1 {
                binding_bytes: binding.encode(),
                encoded,
            });
            return Err(KeyProviderErrorV1::UpdateFailed);
        }
        let stored = state
            .records
            .get_mut(result_id)
            .ok_or(KeyProviderErrorV1::Unavailable)?;
        stored.encoded = encoded;
        stored.pending_seal = None;
        Ok(transition)
    }

    fn destroy_result_key(
        &self,
        result_id: &ResultId,
    ) -> Result<KeyDestroyOutcomeV1, KeyProviderErrorV1> {
        let mut state = self.lock_state()?;
        ensure_operational(&state)?;
        Ok(if state.records.remove(result_id).is_some() {
            KeyDestroyOutcomeV1::Destroyed
        } else {
            KeyDestroyOutcomeV1::AlreadyAbsent
        })
    }

    fn list_managed_records(&self) -> Result<Vec<KeyRecordMetadataV1>, KeyProviderErrorV1> {
        let state = self.lock_state()?;
        ensure_operational(&state)?;
        let mut metadata = Vec::with_capacity(state.records.len());
        for result_id in state.records.keys() {
            let record_metadata = match authenticate_record(&state, result_id) {
                Ok(authenticated) => {
                    let record_state = match authenticated.record.state() {
                        ResultKeyRecordStateV1::Creating => KeyRecordListStateV1::Creating,
                        ResultKeyRecordStateV1::Sealed => KeyRecordListStateV1::Sealed,
                    };
                    let authenticated_context = *authenticated.record.context();
                    KeyRecordMetadataV1::authenticated(
                        *result_id,
                        authenticated_context.root_key_version(),
                        authenticated_context.created_unix_nanos(),
                        authenticated_context.expires_unix_nanos(),
                        record_state,
                    )
                }
                Err(_) => KeyRecordMetadataV1::corrupt(*result_id),
            };
            metadata.push(record_metadata);
        }
        Ok(metadata)
    }
}

struct AuthenticatedRecordV1 {
    record: ResultKeyRecordV1,
    keys: DerivedResultKeysV1,
    result_dek: ResultDekV1,
    seal_binding: Option<OpenedSealBindingV1>,
}

fn authenticate_record<E: EntropySourceV1>(
    state: &EphemeralStateV1<E>,
    result_id: &ResultId,
) -> Result<AuthenticatedRecordV1, KeyProviderErrorV1> {
    let stored = state
        .records
        .get(result_id)
        .ok_or(KeyProviderErrorV1::Unavailable)?;
    let root = state.root.as_ref().ok_or(KeyProviderErrorV1::Unavailable)?;
    if root.version != stored.context.root_key_version() {
        return Err(KeyProviderErrorV1::Unavailable);
    }
    let keys = root
        .key
        .derive_result_keys(*result_id, root.version)
        .map_err(|_| KeyProviderErrorV1::Unavailable)?;
    let record = ResultKeyRecordV1::decode(&stored.context, &stored.encoded)
        .map_err(|_| KeyProviderErrorV1::Unavailable)?;
    let result_dek = record
        .open_result_dek(&keys.dek_wrap_key())
        .map_err(|_| KeyProviderErrorV1::Unavailable)?;
    let seal_binding = record
        .open_sealed_binding(&keys.seal_key())
        .map_err(|_| KeyProviderErrorV1::Unavailable)?;
    Ok(AuthenticatedRecordV1 {
        record,
        keys,
        result_dek,
        seal_binding,
    })
}

fn ensure_operational<E>(state: &EphemeralStateV1<E>) -> Result<(), KeyProviderErrorV1> {
    match state.mode {
        ProviderModeV1::Ready => Ok(()),
        ProviderModeV1::Locked => Err(KeyProviderErrorV1::Locked),
        ProviderModeV1::Unavailable => Err(KeyProviderErrorV1::Unavailable),
    }
}

fn ensure_root<E: EntropySourceV1>(
    state: &mut EphemeralStateV1<E>,
) -> Result<RootKeyVersionV1, KeyProviderErrorV1> {
    if let Some(root) = &state.root {
        return Ok(root.version);
    }
    if !state.records.is_empty() {
        return Err(KeyProviderErrorV1::RootReplacementRefused);
    }
    if state.root_generation_count >= MAX_EPHEMERAL_ROOT_GENERATIONS_V1 {
        return Err(KeyProviderErrorV1::RootVersionExhausted);
    }
    let next_version = state
        .last_root_version
        .checked_add(1)
        .ok_or(KeyProviderErrorV1::RootVersionExhausted)?;
    let version = RootKeyVersionV1::new(next_version)
        .map_err(|_| KeyProviderErrorV1::RootVersionExhausted)?;
    let bytes = fill_nonzero::<_, 32>(&mut state.entropy)?;
    let commitment = secret_equality_commitment(&bytes);
    if state
        .issued_result_ids
        .iter()
        .any(|issued| secret_equality_commitment(issued.as_bytes()) == commitment)
    {
        return Err(KeyProviderErrorV1::SecretMatchesResultId);
    }
    if !state.issued_secret_commitments.insert(commitment) {
        return Err(KeyProviderErrorV1::SecretEntropyRepeated);
    }
    let key = RootKekV1::from_zeroizing(bytes).map_err(|_| KeyProviderErrorV1::EntropyRejected)?;
    state.root = Some(RootRecordV1 { version, key });
    state.last_root_version = next_version;
    state.root_generation_count += 1;
    Ok(version)
}

fn fill_nonzero<E: EntropySourceV1, const N: usize>(
    entropy: &mut E,
) -> Result<Zeroizing<[u8; N]>, KeyProviderErrorV1> {
    let mut bytes = Zeroizing::new([0u8; N]);
    entropy
        .fill_bytes(bytes.as_mut())
        .map_err(|_| KeyProviderErrorV1::EntropyUnavailable)?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(KeyProviderErrorV1::EntropyRejected);
    }
    Ok(bytes)
}

fn issue_nonce<E: EntropySourceV1>(
    state: &mut EphemeralStateV1<E>,
    result_id: ResultId,
    kind: EnvelopeNonceKindV1,
) -> Result<[u8; KEY_ENVELOPE_NONCE_BYTES_V1], KeyProviderErrorV1> {
    let bytes = fill_nonzero::<_, KEY_ENVELOPE_NONCE_BYTES_V1>(&mut state.entropy)?;
    let value = *bytes;
    if !state.issued_nonces.insert(IssuedEnvelopeNonceV1 {
        result_id,
        kind,
        bytes: value,
    }) {
        return Err(KeyProviderErrorV1::DuplicateNonce);
    }
    Ok(value)
}

fn consume_failed_update<E>(state: &mut EphemeralStateV1<E>) -> bool {
    if !state.fail_next_update {
        return false;
    }
    state.fail_next_update = false;
    true
}

fn consume_failed_seal_update<E>(state: &mut EphemeralStateV1<E>) -> bool {
    if state.failed_seal_updates_remaining == 0 {
        return false;
    }
    state.failed_seal_updates_remaining -= 1;
    true
}

// Manifest and future frame callers deliberately route through this one
// purpose-agnostic registry. Purpose is not part of the uniqueness key because
// both object classes use the same result DEK.
fn issue_snapshot_object_nonce<E: EntropySourceV1>(
    state: &mut EphemeralStateV1<E>,
    result_id: ResultId,
) -> Result<[u8; KEY_ENVELOPE_NONCE_BYTES_V1], KeyProviderErrorV1> {
    let issued_count = state
        .snapshot_object_nonce_counts
        .get(&result_id)
        .copied()
        .unwrap_or(0);
    if issued_count >= crate::MAX_SNAPSHOT_OBJECT_NONCES_PER_RESULT_V1 {
        return Err(KeyProviderErrorV1::SnapshotNonceNamespaceExhausted);
    }

    let bytes = fill_nonzero::<_, KEY_ENVELOPE_NONCE_BYTES_V1>(&mut state.entropy)?;
    let value = *bytes;
    if !state
        .issued_snapshot_object_nonces
        .insert(IssuedSnapshotObjectNonceV1 {
            result_id,
            bytes: value,
        })
    {
        return Err(KeyProviderErrorV1::DuplicateNonce);
    }
    state
        .snapshot_object_nonce_counts
        .insert(result_id, issued_count + 1);
    Ok(value)
}

fn secret_equality_commitment(bytes: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SECRET_EQUALITY_COMMITMENT_DOMAIN_V1);
    hasher.update(32u64.to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn same_binding(opened: &OpenedSealBindingV1, expected: &SealBindingV1) -> bool {
    opened.manifest_commitment() == expected.manifest_commitment()
        && opened.final_frame_commitment() == expected.final_frame_commitment()
        && opened.total_frame_count() == expected.total_frame_count()
        && opened.segment_count() == expected.segment_count()
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use evidentrail_snapshot_format::{EntropySourceFailureV1, FrameCommitmentV1, ManifestCommitmentV1};

    use super::*;
    use crate::KeyContextErrorV1;

    enum EntropyStep {
        Bytes(Vec<u8>),
        Unavailable,
    }

    struct ScriptedEntropy {
        steps: VecDeque<EntropyStep>,
    }

    impl ScriptedEntropy {
        fn new(steps: impl IntoIterator<Item = EntropyStep>) -> Self {
            Self {
                steps: steps.into_iter().collect(),
            }
        }
    }

    impl EntropySourceV1 for ScriptedEntropy {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropySourceFailureV1> {
            match self.steps.pop_front() {
                Some(EntropyStep::Bytes(bytes)) if bytes.len() == destination.len() => {
                    destination.copy_from_slice(&bytes);
                    Ok(())
                }
                Some(EntropyStep::Bytes(_)) | Some(EntropyStep::Unavailable) | None => {
                    Err(EntropySourceFailureV1::Unavailable)
                }
            }
        }
    }

    fn bytes(length: usize, value: u8) -> EntropyStep {
        EntropyStep::Bytes(vec![value; length])
    }

    fn result_id(value: u8) -> ResultId {
        ResultId::from_bytes([value; 32])
    }

    fn context(value: u8) -> CreatingKeyContextV1 {
        CreatingKeyContextV1::new(result_id(value), 1_000, 2_000).unwrap()
    }

    fn binding(value: u8) -> SealBindingV1 {
        SealBindingV1::new(
            ManifestCommitmentV1::from_bytes([value; 32]),
            FrameCommitmentV1::from_bytes([value.wrapping_add(1); 32]),
            3,
            1,
        )
        .unwrap()
    }

    fn ready_provider(
        extra_steps: impl IntoIterator<Item = EntropyStep>,
    ) -> EphemeralKeyProviderV1<ScriptedEntropy> {
        let steps = std::iter::once(bytes(32, 0x11)).chain(extra_steps);
        let provider = EphemeralKeyProviderV1::new(ScriptedEntropy::new(steps), 16).unwrap();
        assert_eq!(provider.ensure_root_key().unwrap().get(), 1);
        provider
    }

    #[test]
    fn checked_contexts_cover_i64_boundaries_and_redact() {
        assert_eq!(
            CreatingKeyContextV1::new(ResultId::from_bytes([0; 32]), 0, 1),
            Err(KeyContextErrorV1::InvalidResultId)
        );
        assert_eq!(
            ExpectedKeyContextV1::new(7, 7),
            Err(KeyContextErrorV1::InvalidTimeRange)
        );
        assert_eq!(
            ExpectedKeyContextV1::new(8, 7),
            Err(KeyContextErrorV1::InvalidTimeRange)
        );
        let context = CreatingKeyContextV1::new(result_id(0x63), i64::MIN, i64::MAX).unwrap();
        assert_eq!(context.created_unix_nanos(), i64::MIN);
        assert_eq!(context.expires_unix_nanos(), i64::MAX);
        assert_eq!(format!("{context:?}"), "CreatingKeyContextV1(<redacted>)");
        assert_eq!(
            format!("{:?}", context.expected_context()),
            "ExpectedKeyContextV1(<redacted>)"
        );
    }

    #[test]
    fn full_creating_sealed_open_list_destroy_lifecycle_is_authenticated() {
        let provider = ready_provider([
            bytes(32, 0x22),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x33),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x44),
        ]);
        let context = context(0x51);
        let opened = provider.create_result_key(&context).unwrap();
        assert_eq!(opened.result_id(), context.result_id());
        assert_eq!(opened.root_key_version().get(), 1);
        assert_eq!(opened.state(), ResultKeyRecordStateV1::Creating);
        assert!(opened.seal_binding().is_none());

        let reopened = provider
            .open_result_key(&context.result_id(), &context.expected_context())
            .unwrap();
        assert_eq!(reopened.state(), ResultKeyRecordStateV1::Creating);
        assert_eq!(reopened.expires_unix_nanos(), 2_000);

        let seal = binding(0x71);
        assert_eq!(
            provider
                .seal_result_key(&context.result_id(), &seal)
                .unwrap(),
            ResultKeySealTransitionV1::Applied
        );
        let sealed = provider
            .open_result_key(&context.result_id(), &context.expected_context())
            .unwrap();
        assert_eq!(sealed.state(), ResultKeyRecordStateV1::Sealed);
        let opened_binding = sealed.seal_binding().unwrap();
        assert_eq!(
            opened_binding.manifest_commitment(),
            seal.manifest_commitment()
        );
        assert_eq!(opened_binding.total_frame_count(), 3);
        let canonical_retry = SealBindingV1::decode(&seal.encode()).unwrap();
        assert_eq!(
            provider
                .seal_result_key(&context.result_id(), &canonical_retry)
                .unwrap(),
            ResultKeySealTransitionV1::AlreadySealedSame
        );
        assert_eq!(
            provider.seal_result_key(&context.result_id(), &binding(0x72)),
            Err(KeyProviderErrorV1::DifferentSecondSeal)
        );

        let listed = provider.list_managed_records().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].result_id(), context.result_id());
        assert_eq!(listed[0].state(), KeyRecordListStateV1::Sealed);
        assert_eq!(
            provider.destroy_result_key(&context.result_id()).unwrap(),
            KeyDestroyOutcomeV1::Destroyed
        );
        assert_eq!(
            provider.destroy_result_key(&context.result_id()).unwrap(),
            KeyDestroyOutcomeV1::AlreadyAbsent
        );
        assert_eq!(
            provider
                .open_result_key(&context.result_id(), &context.expected_context())
                .err(),
            Some(KeyProviderErrorV1::Unavailable)
        );
        assert!(provider.list_managed_records().unwrap().is_empty());
    }

    #[test]
    fn concurrent_duplicate_creation_has_one_winner_and_one_record() {
        let provider = Arc::new(ready_provider([
            bytes(32, 0x22),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x33),
        ]));
        let barrier = Arc::new(Barrier::new(3));
        let context = context(0x52);
        let mut handles = Vec::new();
        for _ in 0..2 {
            let provider = Arc::clone(&provider);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                provider.create_result_key(&context)
            }));
        }
        barrier.wait();
        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| { matches!(outcome, Err(KeyProviderErrorV1::DuplicateResult)) })
                .count(),
            1
        );
        assert_eq!(provider.list_managed_records().unwrap().len(), 1);
    }

    #[test]
    fn entropy_and_nonce_failures_publish_no_result_or_seal() {
        let unavailable =
            EphemeralKeyProviderV1::new(ScriptedEntropy::new([EntropyStep::Unavailable]), 1)
                .unwrap();
        assert_eq!(
            unavailable.ensure_root_key(),
            Err(KeyProviderErrorV1::EntropyUnavailable)
        );

        let zero_root =
            EphemeralKeyProviderV1::new(ScriptedEntropy::new([bytes(32, 0)]), 1).unwrap();
        assert_eq!(
            zero_root.ensure_root_key(),
            Err(KeyProviderErrorV1::EntropyRejected)
        );

        let unavailable_dek = ready_provider([EntropyStep::Unavailable]);
        assert_eq!(
            unavailable_dek.create_result_key(&context(0x50)).err(),
            Some(KeyProviderErrorV1::EntropyUnavailable)
        );
        assert!(unavailable_dek.list_managed_records().unwrap().is_empty());

        let zero_dek = ready_provider([bytes(RESULT_DEK_BYTES_V1, 0)]);
        assert_eq!(
            zero_dek.create_result_key(&context(0x53)).err(),
            Some(KeyProviderErrorV1::EntropyRejected)
        );
        assert!(zero_dek.list_managed_records().unwrap().is_empty());

        let zero_wrap_nonce = ready_provider([
            bytes(RESULT_DEK_BYTES_V1, 0x22),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0),
            bytes(RESULT_DEK_BYTES_V1, 0x22),
        ]);
        let failed_context = context(0x54);
        assert_eq!(
            zero_wrap_nonce.create_result_key(&failed_context).err(),
            Some(KeyProviderErrorV1::EntropyRejected)
        );
        assert!(zero_wrap_nonce.list_managed_records().unwrap().is_empty());
        assert_eq!(
            zero_wrap_nonce.create_result_key(&failed_context).err(),
            Some(KeyProviderErrorV1::DuplicateResult)
        );
        assert_eq!(
            zero_wrap_nonce.create_result_key(&context(0x5f)).err(),
            Some(KeyProviderErrorV1::SecretEntropyRepeated)
        );

        let zero_seal_nonce = ready_provider([
            bytes(RESULT_DEK_BYTES_V1, 0x22),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x33),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0),
        ]);
        let zero_seal_context = context(0x55);
        zero_seal_nonce
            .create_result_key(&zero_seal_context)
            .unwrap();
        assert_eq!(
            zero_seal_nonce.seal_result_key(&zero_seal_context.result_id(), &binding(0x71)),
            Err(KeyProviderErrorV1::EntropyRejected)
        );
        assert_eq!(
            zero_seal_nonce
                .open_result_key(
                    &zero_seal_context.result_id(),
                    &zero_seal_context.expected_context()
                )
                .unwrap()
                .state(),
            ResultKeyRecordStateV1::Creating
        );

        let unavailable_seal_nonce = ready_provider([
            bytes(RESULT_DEK_BYTES_V1, 0x25),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x35),
            EntropyStep::Unavailable,
        ]);
        let unavailable_context = context(0x60);
        unavailable_seal_nonce
            .create_result_key(&unavailable_context)
            .unwrap();
        assert_eq!(
            unavailable_seal_nonce
                .seal_result_key(&unavailable_context.result_id(), &binding(0x75)),
            Err(KeyProviderErrorV1::EntropyUnavailable)
        );
        assert_eq!(
            unavailable_seal_nonce
                .open_result_key(
                    &unavailable_context.result_id(),
                    &unavailable_context.expected_context()
                )
                .unwrap()
                .state(),
            ResultKeyRecordStateV1::Creating
        );
    }

    #[test]
    fn failed_seal_updates_are_atomic_and_retry_the_exact_pending_ciphertext() {
        let provider = ready_provider([
            bytes(RESULT_DEK_BYTES_V1, 0x22),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x33),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x44),
        ]);
        let sealed_context = context(0x57);
        provider.create_result_key(&sealed_context).unwrap();
        provider.fail_next_update_for_test().unwrap();
        let seal = binding(0x72);
        assert_eq!(
            provider.seal_result_key(&sealed_context.result_id(), &seal),
            Err(KeyProviderErrorV1::UpdateFailed)
        );
        assert_eq!(
            provider
                .open_result_key(
                    &sealed_context.result_id(),
                    &sealed_context.expected_context()
                )
                .unwrap()
                .state(),
            ResultKeyRecordStateV1::Creating
        );
        assert_eq!(
            provider.seal_result_key(&sealed_context.result_id(), &binding(0x73)),
            Err(KeyProviderErrorV1::DifferentSecondSeal)
        );
        provider.fail_next_update_for_test().unwrap();
        assert_eq!(
            provider.seal_result_key(&sealed_context.result_id(), &seal),
            Err(KeyProviderErrorV1::UpdateFailed)
        );
        assert_eq!(
            provider
                .seal_result_key(&sealed_context.result_id(), &seal)
                .unwrap(),
            ResultKeySealTransitionV1::Applied
        );

        let corrupted_pending = ready_provider([
            bytes(RESULT_DEK_BYTES_V1, 0x25),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x35),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x45),
        ]);
        let corrupt_context = context(0x58);
        corrupted_pending
            .create_result_key(&corrupt_context)
            .unwrap();
        corrupted_pending.fail_next_update_for_test().unwrap();
        let corrupt_seal = binding(0x74);
        assert_eq!(
            corrupted_pending.seal_result_key(&corrupt_context.result_id(), &corrupt_seal),
            Err(KeyProviderErrorV1::UpdateFailed)
        );
        {
            let mut state = corrupted_pending.lock_state().unwrap();
            let pending = state
                .records
                .get_mut(&corrupt_context.result_id())
                .unwrap()
                .pending_seal
                .as_mut()
                .unwrap();
            pending.encoded[200] ^= 0x80;
        }
        assert_eq!(
            corrupted_pending.seal_result_key(&corrupt_context.result_id(), &corrupt_seal),
            Err(KeyProviderErrorV1::Unavailable)
        );
        assert_eq!(
            corrupted_pending
                .open_result_key(
                    &corrupt_context.result_id(),
                    &corrupt_context.expected_context()
                )
                .unwrap()
                .state(),
            ResultKeyRecordStateV1::Creating
        );
    }

    #[test]
    fn failed_create_publication_leaves_no_record_and_burns_its_namespace() {
        let provider = ready_provider([
            bytes(RESULT_DEK_BYTES_V1, 0x26),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x36),
            bytes(RESULT_DEK_BYTES_V1, 0x26),
        ]);
        let failed_context = context(0x59);
        provider.fail_next_update_for_test().unwrap();
        assert_eq!(
            provider.create_result_key(&failed_context).err(),
            Some(KeyProviderErrorV1::UpdateFailed)
        );
        assert!(provider.list_managed_records().unwrap().is_empty());
        assert_eq!(
            provider
                .open_result_key(
                    &failed_context.result_id(),
                    &failed_context.expected_context()
                )
                .err(),
            Some(KeyProviderErrorV1::Unavailable)
        );
        assert_eq!(
            provider.create_result_key(&failed_context).err(),
            Some(KeyProviderErrorV1::DuplicateResult)
        );
        assert_eq!(
            provider.create_result_key(&context(0x5a)).err(),
            Some(KeyProviderErrorV1::SecretEntropyRepeated)
        );
    }

    #[test]
    fn duplicate_envelope_nonce_output_is_rejected_in_its_key_scope() {
        let provider = ready_provider([
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x31),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x31),
        ]);
        let mut state = provider.lock_state().unwrap();
        assert_eq!(
            issue_nonce(
                &mut state,
                result_id(0x56),
                EnvelopeNonceKindV1::SealBinding
            )
            .unwrap(),
            [0x31; KEY_ENVELOPE_NONCE_BYTES_V1]
        );
        assert_eq!(
            issue_nonce(
                &mut state,
                result_id(0x56),
                EnvelopeNonceKindV1::SealBinding
            ),
            Err(KeyProviderErrorV1::DuplicateNonce)
        );
    }

    #[test]
    fn snapshot_nonce_namespace_burns_reuse_and_entropy_failures_are_atomic() {
        let provider = ready_provider([
            bytes(RESULT_DEK_BYTES_V1, 0x22),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x33),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x44),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x44),
            EntropyStep::Unavailable,
        ]);
        let issued_context = context(0x56);
        provider.create_result_key(&issued_context).unwrap();
        assert_eq!(
            provider
                .issue_snapshot_manifest_nonce(&issued_context.result_id())
                .unwrap()
                .as_bytes(),
            &[0x44; KEY_ENVELOPE_NONCE_BYTES_V1]
        );
        assert_eq!(
            provider.issue_snapshot_manifest_nonce(&issued_context.result_id()),
            Err(KeyProviderErrorV1::DuplicateNonce)
        );
        assert_eq!(
            provider.issue_snapshot_manifest_nonce(&issued_context.result_id()),
            Err(KeyProviderErrorV1::EntropyUnavailable)
        );
        assert_eq!(
            provider
                .lock_state()
                .unwrap()
                .issued_snapshot_object_nonces
                .len(),
            1
        );
        assert_eq!(
            provider
                .lock_state()
                .unwrap()
                .snapshot_object_nonce_counts
                .get(&issued_context.result_id()),
            Some(&1)
        );
        assert_eq!(
            provider
                .open_result_key(
                    &issued_context.result_id(),
                    &issued_context.expected_context()
                )
                .unwrap()
                .state(),
            ResultKeyRecordStateV1::Creating
        );

        let zero_then_valid = ready_provider([
            bytes(RESULT_DEK_BYTES_V1, 0x25),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x35),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x45),
        ]);
        let zero_context = context(0x57);
        zero_then_valid.create_result_key(&zero_context).unwrap();
        assert_eq!(
            zero_then_valid.issue_snapshot_manifest_nonce(&zero_context.result_id()),
            Err(KeyProviderErrorV1::EntropyRejected)
        );
        assert!(
            zero_then_valid
                .lock_state()
                .unwrap()
                .issued_snapshot_object_nonces
                .is_empty()
        );
        assert_eq!(
            zero_then_valid
                .issue_snapshot_manifest_nonce(&zero_context.result_id())
                .unwrap()
                .as_bytes(),
            &[0x45; KEY_ENVELOPE_NONCE_BYTES_V1]
        );

        zero_then_valid
            .destroy_result_key(&zero_context.result_id())
            .unwrap();
        assert_eq!(
            zero_then_valid.issue_snapshot_manifest_nonce(&zero_context.result_id()),
            Err(KeyProviderErrorV1::Unavailable)
        );
    }

    #[test]
    fn snapshot_nonce_exhaustion_is_checked_before_entropy_and_shared_by_object_kind() {
        let provider = ready_provider([
            bytes(RESULT_DEK_BYTES_V1, 0x26),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x36),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x46),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x46),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x47),
        ]);
        let issued_context = context(0x5a);
        provider.create_result_key(&issued_context).unwrap();

        assert_eq!(
            provider
                .issue_snapshot_frame_nonce(&issued_context.result_id())
                .unwrap()
                .as_bytes(),
            &[0x46; KEY_ENVELOPE_NONCE_BYTES_V1]
        );
        assert_eq!(
            provider.issue_snapshot_manifest_nonce(&issued_context.result_id()),
            Err(KeyProviderErrorV1::DuplicateNonce)
        );

        {
            let mut state = provider.lock_state().unwrap();
            state.snapshot_object_nonce_counts.insert(
                issued_context.result_id(),
                crate::MAX_SNAPSHOT_OBJECT_NONCES_PER_RESULT_V1,
            );
        }
        assert_eq!(
            provider.issue_snapshot_manifest_nonce(&issued_context.result_id()),
            Err(KeyProviderErrorV1::SnapshotNonceNamespaceExhausted)
        );

        // Reset only the synthetic count. The next draw must still be the
        // queued value, proving exhaustion did not consume entropy or mutate
        // the actual burned-nonce registry.
        {
            let mut state = provider.lock_state().unwrap();
            state
                .snapshot_object_nonce_counts
                .insert(issued_context.result_id(), 1);
        }
        assert_eq!(
            provider
                .issue_snapshot_manifest_nonce(&issued_context.result_id())
                .unwrap()
                .as_bytes(),
            &[0x47; KEY_ENVELOPE_NONCE_BYTES_V1]
        );
        let state = provider.lock_state().unwrap();
        assert_eq!(state.issued_snapshot_object_nonces.len(), 2);
        assert_eq!(
            state
                .snapshot_object_nonce_counts
                .get(&issued_context.result_id()),
            Some(&2)
        );
    }

    #[test]
    fn identical_snapshot_nonce_bytes_are_scoped_by_distinct_result_deks() {
        let provider = ready_provider([
            bytes(RESULT_DEK_BYTES_V1, 0x21),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x31),
            bytes(RESULT_DEK_BYTES_V1, 0x22),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x32),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x55),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x55),
        ]);
        let first = context(0x58);
        let second = context(0x59);
        provider.create_result_key(&first).unwrap();
        provider.create_result_key(&second).unwrap();
        assert_eq!(
            provider
                .issue_snapshot_manifest_nonce(&first.result_id())
                .unwrap()
                .as_bytes(),
            &[0x55; KEY_ENVELOPE_NONCE_BYTES_V1]
        );
        assert_eq!(
            provider
                .issue_snapshot_manifest_nonce(&second.result_id())
                .unwrap()
                .as_bytes(),
            &[0x55; KEY_ENVELOPE_NONCE_BYTES_V1]
        );
        assert_eq!(
            provider
                .lock_state()
                .unwrap()
                .issued_snapshot_object_nonces
                .len(),
            2
        );
    }

    #[test]
    fn secret_entropy_never_repeats_or_equals_a_public_result_identity() {
        let repeated_dek = ready_provider([
            bytes(RESULT_DEK_BYTES_V1, 0x22),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x31),
            bytes(RESULT_DEK_BYTES_V1, 0x22),
        ]);
        repeated_dek.create_result_key(&context(0x61)).unwrap();
        assert_eq!(
            repeated_dek.create_result_key(&context(0x62)).err(),
            Some(KeyProviderErrorV1::SecretEntropyRepeated)
        );
        assert_eq!(repeated_dek.list_managed_records().unwrap().len(), 1);

        let dek_equals_own_id = ready_provider([bytes(RESULT_DEK_BYTES_V1, 0x63)]);
        assert_eq!(
            dek_equals_own_id.create_result_key(&context(0x63)).err(),
            Some(KeyProviderErrorV1::SecretMatchesResultId)
        );
        assert!(dek_equals_own_id.list_managed_records().unwrap().is_empty());

        let dek_equals_prior_id = ready_provider([
            bytes(RESULT_DEK_BYTES_V1, 0x24),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x34),
            bytes(RESULT_DEK_BYTES_V1, 0x64),
        ]);
        dek_equals_prior_id
            .create_result_key(&context(0x64))
            .unwrap();
        assert_eq!(
            dek_equals_prior_id.create_result_key(&context(0x65)).err(),
            Some(KeyProviderErrorV1::SecretMatchesResultId)
        );

        let result_equals_root = ready_provider([]);
        assert_eq!(
            result_equals_root.create_result_key(&context(0x11)).err(),
            Some(KeyProviderErrorV1::SecretMatchesResultId)
        );

        let repeated_root = EphemeralKeyProviderV1::new(
            ScriptedEntropy::new([bytes(32, 0x71), bytes(32, 0x71)]),
            2,
        )
        .unwrap();
        repeated_root.ensure_root_key().unwrap();
        repeated_root.drop_root_for_test().unwrap();
        assert_eq!(
            repeated_root.ensure_root_key(),
            Err(KeyProviderErrorV1::SecretEntropyRepeated)
        );

        let root_equals_tombstoned_id = EphemeralKeyProviderV1::new(
            ScriptedEntropy::new([
                bytes(32, 0x72),
                bytes(RESULT_DEK_BYTES_V1, 0x73),
                bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x74),
                bytes(32, 0x75),
            ]),
            2,
        )
        .unwrap();
        root_equals_tombstoned_id.ensure_root_key().unwrap();
        let tombstoned = context(0x75);
        root_equals_tombstoned_id
            .create_result_key(&tombstoned)
            .unwrap();
        root_equals_tombstoned_id
            .destroy_result_key(&tombstoned.result_id())
            .unwrap();
        root_equals_tombstoned_id.drop_root_for_test().unwrap();
        assert_eq!(
            root_equals_tombstoned_id.ensure_root_key(),
            Err(KeyProviderErrorV1::SecretMatchesResultId)
        );
    }

    #[test]
    fn missing_corrupt_and_wrong_context_opens_are_indistinguishable() {
        let provider = ready_provider([
            bytes(RESULT_DEK_BYTES_V1, 0x22),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x33),
        ]);
        let context = context(0x58);
        provider.create_result_key(&context).unwrap();

        let wrong_context = ExpectedKeyContextV1::new(1_000, 2_001).unwrap();
        assert_eq!(
            provider
                .open_result_key(&context.result_id(), &wrong_context)
                .err(),
            Some(KeyProviderErrorV1::Unavailable)
        );
        assert_eq!(
            provider
                .open_result_key(&result_id(0x59), &context.expected_context())
                .err(),
            Some(KeyProviderErrorV1::Unavailable)
        );

        provider
            .corrupt_record_byte_for_test(&context.result_id(), 100)
            .unwrap();
        assert_eq!(
            provider
                .open_result_key(&context.result_id(), &context.expected_context())
                .err(),
            Some(KeyProviderErrorV1::Unavailable)
        );
        let listed = provider.list_managed_records().unwrap();
        assert_eq!(listed[0].state(), KeyRecordListStateV1::Corrupt);
        assert_eq!(listed[0].root_key_version(), None);
        assert_eq!(listed[0].created_unix_nanos(), None);
        assert_eq!(listed[0].expires_unix_nanos(), None);
    }

    #[test]
    fn locked_unavailable_and_root_loss_states_never_fallback() {
        let provider = ready_provider([
            bytes(RESULT_DEK_BYTES_V1, 0x22),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x33),
            bytes(32, 0x66),
        ]);
        let context = context(0x5a);
        provider.create_result_key(&context).unwrap();

        provider.set_locked_for_test(true).unwrap();
        assert_eq!(provider.ensure_root_key(), Err(KeyProviderErrorV1::Locked));
        assert_eq!(
            provider
                .open_result_key(&context.result_id(), &context.expected_context())
                .err(),
            Some(KeyProviderErrorV1::Locked)
        );
        assert_eq!(
            provider.list_managed_records(),
            Err(KeyProviderErrorV1::Locked)
        );
        provider.set_locked_for_test(false).unwrap();

        provider.set_unavailable_for_test(true).unwrap();
        assert_eq!(
            provider
                .open_result_key(&context.result_id(), &context.expected_context())
                .err(),
            Some(KeyProviderErrorV1::Unavailable)
        );
        provider.set_unavailable_for_test(false).unwrap();

        provider.drop_root_for_test().unwrap();
        assert_eq!(
            provider.ensure_root_key(),
            Err(KeyProviderErrorV1::RootReplacementRefused)
        );
        assert_eq!(
            provider
                .open_result_key(&context.result_id(), &context.expected_context())
                .err(),
            Some(KeyProviderErrorV1::Unavailable)
        );
        assert_eq!(
            provider.destroy_result_key(&context.result_id()).unwrap(),
            KeyDestroyOutcomeV1::Destroyed
        );
        assert_eq!(provider.ensure_root_key().unwrap().get(), 2);
        assert_eq!(
            provider.create_result_key(&context).err(),
            Some(KeyProviderErrorV1::DuplicateResult)
        );
    }

    #[test]
    fn enumeration_and_all_debug_output_are_contentless() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EphemeralKeyProviderV1<ScriptedEntropy>>();

        let provider = ready_provider([
            bytes(RESULT_DEK_BYTES_V1, 0x22),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x33),
        ]);
        let context = CreatingKeyContextV1::new(result_id(0xca), -9_876_543, 8_765_432).unwrap();
        let opened = provider.create_result_key(&context).unwrap();
        let listed = provider.list_managed_records().unwrap();
        let result_token = context.result_id().canonical_token();
        let outputs = [
            format!("{provider:?}"),
            format!("{context:?}"),
            format!("{:?}", context.expected_context()),
            format!("{opened:?}"),
            format!("{:?}", opened.result_dek()),
            format!("{:?}", listed[0]),
            format!("{:?}", KeyProviderErrorV1::Unavailable),
        ];
        for output in outputs {
            assert!(!output.contains(&result_token));
            assert!(!output.contains("9876543"));
            assert!(!output.contains("8765432"));
            assert!(!output.contains("cacaca"));
            assert!(!output.contains("222222"));
            assert!(!output.contains("333333"));
        }
        assert_eq!(listed[0].root_key_version().unwrap().get(), 1);
        assert_eq!(listed[0].created_unix_nanos(), Some(-9_876_543));
        assert_eq!(listed[0].expires_unix_nanos(), Some(8_765_432));
    }

    #[test]
    fn capacity_is_bounded_and_destroyed_identities_cannot_be_reissued() {
        assert_eq!(
            EphemeralKeyProviderV1::new(ScriptedEntropy::new([]), 0).err(),
            Some(KeyProviderErrorV1::InvalidCapacity)
        );
        assert_eq!(
            EphemeralKeyProviderV1::new(ScriptedEntropy::new([]), MAX_EPHEMERAL_KEY_RECORDS_V1 + 1)
                .err(),
            Some(KeyProviderErrorV1::InvalidCapacity)
        );

        let provider = ready_provider([
            bytes(RESULT_DEK_BYTES_V1, 0x22),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x33),
        ]);
        let retired_context = context(0x5b);
        provider.create_result_key(&retired_context).unwrap();
        provider
            .destroy_result_key(&retired_context.result_id())
            .unwrap();
        assert_eq!(
            provider.create_result_key(&retired_context).err(),
            Some(KeyProviderErrorV1::DuplicateResult)
        );

        let one_record = EphemeralKeyProviderV1::new(
            ScriptedEntropy::new([
                bytes(32, 0x11),
                bytes(RESULT_DEK_BYTES_V1, 0x22),
                bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x33),
            ]),
            1,
        )
        .unwrap();
        one_record.ensure_root_key().unwrap();
        one_record.create_result_key(&context(0x5d)).unwrap();
        assert_eq!(
            one_record.create_result_key(&context(0x5e)).err(),
            Some(KeyProviderErrorV1::CapacityExceeded)
        );
    }

    #[test]
    fn poisoned_serialization_boundary_fails_closed_without_exposing_a_record() {
        let provider = ready_provider([
            bytes(RESULT_DEK_BYTES_V1, 0x22),
            bytes(KEY_ENVELOPE_NONCE_BYTES_V1, 0x33),
        ]);
        let context = context(0x5c);
        provider.create_result_key(&context).unwrap();

        let poison = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = provider.state.lock().unwrap();
            panic!("intentional contentless provider poison");
        }));
        assert!(poison.is_err());
        assert_eq!(
            provider
                .open_result_key(&context.result_id(), &context.expected_context())
                .err(),
            Some(KeyProviderErrorV1::Unavailable)
        );
        assert_eq!(
            provider.list_managed_records(),
            Err(KeyProviderErrorV1::Unavailable)
        );
        assert_eq!(
            provider.destroy_result_key(&context.result_id()),
            Err(KeyProviderErrorV1::Unavailable)
        );
    }
}
