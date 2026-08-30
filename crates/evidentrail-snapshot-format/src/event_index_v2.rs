use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::{EventId, ExactnessBasis, PolicyDigest, TransformationReceiptId};
use sha2::{Digest, Sha256};

use crate::{
    FRAME_COMMITMENT_BYTES_V1, FrameCommitmentV1, LIFECYCLE_DIGEST_BYTES_V1, LifecycleDigestV1,
    MAX_ENCODED_FRAME_BYTES_V2, SnapshotObjectKindV2,
};

pub const AUTHENTICATED_EVENT_INDEX_VERSION_V2: u16 = 2;
pub const AUTHENTICATED_EVENT_INDEX_HEADER_BYTES_V2: usize = 128;
pub const AUTHENTICATED_EVENT_INDEX_ENTRY_BYTES_V2: usize = 192;
pub const MAX_AUTHENTICATED_EVENT_INDEX_ENTRIES_V2: usize = 1_000_000;
/// Maximum entries in one encrypted index shard. At the fixed 192-byte entry
/// width, the largest shard is 3,145,856 bytes including its header and is
/// therefore safely below the 8-MiB frame plaintext ceiling.
pub const MAX_AUTHENTICATED_EVENT_INDEX_SHARD_ENTRIES_V2: usize = 16_384;
pub const MAX_AUTHENTICATED_EVENT_INDEX_SHARDS_V2: usize = MAX_AUTHENTICATED_EVENT_INDEX_ENTRIES_V2
    .div_ceil(MAX_AUTHENTICATED_EVENT_INDEX_SHARD_ENTRIES_V2);
pub const AUTHENTICATED_EVENT_INDEX_DIRECTORY_HEADER_BYTES_V2: usize = 128;
pub const AUTHENTICATED_EVENT_INDEX_SHARD_DESCRIPTOR_BYTES_V2: usize = 128;

const INDEX_MAGIC_V2: [u8; 8] = *b"EVREIX02";
const INDEX_DIGEST_DOMAIN_V2: &[u8] = b"evidentrail.snapshot.event-index.v2";
const INDEX_DIRECTORY_MAGIC_V2: [u8; 8] = *b"EVREID02";
const INDEX_DIRECTORY_DIGEST_DOMAIN_V2: &[u8] = b"evidentrail.snapshot.event-index-directory.v2";

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EventFrameLocatorV2 {
    segment_ordinal: u64,
    frame_sequence: u32,
    global_sequence: u64,
    byte_offset: u64,
    encoded_length: u32,
    plaintext_length: u32,
    frame_commitment: FrameCommitmentV1,
}

impl EventFrameLocatorV2 {
    pub fn new(
        segment_ordinal: u64,
        frame_sequence: u32,
        global_sequence: u64,
        byte_offset: u64,
        encoded_length: u32,
        plaintext_length: u32,
        frame_commitment: FrameCommitmentV1,
    ) -> Result<Self, AuthenticatedEventIndexErrorV2> {
        if encoded_length == 0
            || usize::try_from(encoded_length)
                .map_err(|_| AuthenticatedEventIndexErrorV2::ArithmeticOverflow)?
                > MAX_ENCODED_FRAME_BYTES_V2
            || usize::try_from(plaintext_length)
                .map_err(|_| AuthenticatedEventIndexErrorV2::ArithmeticOverflow)?
                > crate::MAX_FRAME_PLAINTEXT_BYTES_V1
            || byte_offset.checked_add(u64::from(encoded_length)).is_none()
            || frame_commitment == FrameCommitmentV1::ZERO
        {
            return Err(AuthenticatedEventIndexErrorV2::InvalidLocator);
        }
        Ok(Self {
            segment_ordinal,
            frame_sequence,
            global_sequence,
            byte_offset,
            encoded_length,
            plaintext_length,
            frame_commitment,
        })
    }

    #[must_use]
    pub const fn segment_ordinal(self) -> u64 {
        self.segment_ordinal
    }

    #[must_use]
    pub const fn frame_sequence(self) -> u32 {
        self.frame_sequence
    }

    #[must_use]
    pub const fn global_sequence(self) -> u64 {
        self.global_sequence
    }

    #[must_use]
    pub const fn byte_offset(self) -> u64 {
        self.byte_offset
    }

    #[must_use]
    pub const fn encoded_length(self) -> u32 {
        self.encoded_length
    }

    #[must_use]
    pub const fn plaintext_length(self) -> u32 {
        self.plaintext_length
    }

    #[must_use]
    pub const fn frame_commitment(self) -> FrameCommitmentV1 {
        self.frame_commitment
    }
}

impl fmt::Debug for EventFrameLocatorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EventFrameLocatorV2(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticatedEventIndexEntryV2 {
    event_id: EventId,
    exactness_basis: ExactnessBasis,
    locator: EventFrameLocatorV2,
}

impl AuthenticatedEventIndexEntryV2 {
    #[must_use]
    pub const fn new(
        event_id: EventId,
        exactness_basis: ExactnessBasis,
        locator: EventFrameLocatorV2,
    ) -> Self {
        Self {
            event_id,
            exactness_basis,
            locator,
        }
    }

    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn exactness_basis(&self) -> ExactnessBasis {
        self.exactness_basis
    }

    #[must_use]
    pub const fn locator(&self) -> EventFrameLocatorV2 {
        self.locator
    }

    fn encode(&self) -> [u8; AUTHENTICATED_EVENT_INDEX_ENTRY_BYTES_V2] {
        let mut encoded = [0u8; AUTHENTICATED_EVENT_INDEX_ENTRY_BYTES_V2];
        encoded[0..32].copy_from_slice(self.event_id.as_bytes());
        encoded[34..36]
            .copy_from_slice(&SnapshotObjectKindV2::AuthorizedEvent.code().to_be_bytes());
        encoded[40..48].copy_from_slice(&self.locator.segment_ordinal.to_be_bytes());
        encoded[48..52].copy_from_slice(&self.locator.frame_sequence.to_be_bytes());
        encoded[56..64].copy_from_slice(&self.locator.global_sequence.to_be_bytes());
        encoded[64..72].copy_from_slice(&self.locator.byte_offset.to_be_bytes());
        encoded[72..76].copy_from_slice(&self.locator.encoded_length.to_be_bytes());
        encoded[76..80].copy_from_slice(&self.locator.plaintext_length.to_be_bytes());
        encoded[80..112].copy_from_slice(self.locator.frame_commitment.as_bytes());
        match self.exactness_basis {
            ExactnessBasis::SourceExact => encoded[32..34].copy_from_slice(&1u16.to_be_bytes()),
            ExactnessBasis::PostPolicy {
                policy_digest,
                transformation_receipt_id,
            } => {
                encoded[32..34].copy_from_slice(&2u16.to_be_bytes());
                encoded[112..144].copy_from_slice(policy_digest.as_bytes());
                encoded[144..176].copy_from_slice(transformation_receipt_id.as_bytes());
            }
        }
        encoded
    }

    fn decode(encoded: &[u8]) -> Result<Self, AuthenticatedEventIndexErrorV2> {
        if encoded.len() != AUTHENTICATED_EVENT_INDEX_ENTRY_BYTES_V2
            || encoded[36..40]
                .iter()
                .chain(encoded[52..56].iter())
                .chain(encoded[176..].iter())
                .any(|byte| *byte != 0)
        {
            return Err(AuthenticatedEventIndexErrorV2::NoncanonicalEntry);
        }
        if read_u16(encoded, 34) != SnapshotObjectKindV2::AuthorizedEvent.code() {
            return Err(AuthenticatedEventIndexErrorV2::UnsupportedObjectKind);
        }
        let policy = read_array(encoded, 112);
        let receipt = read_array(encoded, 144);
        let exactness_basis = match read_u16(encoded, 32) {
            1 if policy.iter().all(|byte| *byte == 0) && receipt.iter().all(|byte| *byte == 0) => {
                ExactnessBasis::SourceExact
            }
            2 if policy.iter().any(|byte| *byte != 0) && receipt.iter().any(|byte| *byte != 0) => {
                ExactnessBasis::PostPolicy {
                    policy_digest: PolicyDigest::from_bytes(policy),
                    transformation_receipt_id: TransformationReceiptId::from_bytes(receipt),
                }
            }
            _ => return Err(AuthenticatedEventIndexErrorV2::NoncanonicalExactness),
        };
        Ok(Self::new(
            EventId::from_bytes(read_array(encoded, 0)),
            exactness_basis,
            EventFrameLocatorV2::new(
                read_u64(encoded, 40),
                read_u32(encoded, 48),
                read_u64(encoded, 56),
                read_u64(encoded, 64),
                read_u32(encoded, 72),
                read_u32(encoded, 76),
                FrameCommitmentV1::from_bytes(read_array(encoded, 80)),
            )?,
        ))
    }
}

impl fmt::Debug for AuthenticatedEventIndexEntryV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedEventIndexEntryV2(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticatedEventIndexV2 {
    entries: Vec<AuthenticatedEventIndexEntryV2>,
    final_frame_commitment: FrameCommitmentV1,
    total_authorized_bytes: u64,
}

impl AuthenticatedEventIndexV2 {
    pub fn new(
        mut entries: Vec<AuthenticatedEventIndexEntryV2>,
        final_frame_commitment: FrameCommitmentV1,
    ) -> Result<Self, AuthenticatedEventIndexErrorV2> {
        if entries.len() > MAX_AUTHENTICATED_EVENT_INDEX_SHARD_ENTRIES_V2
            || (!entries.is_empty() && final_frame_commitment == FrameCommitmentV1::ZERO)
        {
            return Err(AuthenticatedEventIndexErrorV2::ShardEntryCountCap);
        }
        entries.sort_by_key(AuthenticatedEventIndexEntryV2::event_id);
        let mut event_ids = BTreeSet::new();
        let mut frames = BTreeSet::new();
        let mut total_authorized_bytes = 0u64;
        for entry in &entries {
            if !event_ids.insert(entry.event_id)
                || !frames.insert((
                    entry.locator.segment_ordinal,
                    entry.locator.frame_sequence,
                    entry.locator.byte_offset,
                ))
            {
                return Err(AuthenticatedEventIndexErrorV2::DuplicateEntry);
            }
            total_authorized_bytes = total_authorized_bytes
                .checked_add(u64::from(entry.locator.plaintext_length))
                .ok_or(AuthenticatedEventIndexErrorV2::ArithmeticOverflow)?;
        }
        Ok(Self {
            entries,
            final_frame_commitment,
            total_authorized_bytes,
        })
    }

    #[must_use]
    pub fn entries(&self) -> &[AuthenticatedEventIndexEntryV2] {
        &self.entries
    }

    #[must_use]
    pub fn get(&self, event_id: EventId) -> Option<&AuthenticatedEventIndexEntryV2> {
        self.entries
            .binary_search_by_key(&event_id, AuthenticatedEventIndexEntryV2::event_id)
            .ok()
            .map(|index| &self.entries[index])
    }

    #[must_use]
    pub fn encoded_len(&self) -> usize {
        AUTHENTICATED_EVENT_INDEX_HEADER_BYTES_V2
            + self.entries.len() * AUTHENTICATED_EVENT_INDEX_ENTRY_BYTES_V2
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = vec![0u8; AUTHENTICATED_EVENT_INDEX_HEADER_BYTES_V2];
        encoded[0..8].copy_from_slice(&INDEX_MAGIC_V2);
        encoded[8..10].copy_from_slice(&AUTHENTICATED_EVENT_INDEX_VERSION_V2.to_be_bytes());
        encoded[10..12].copy_from_slice(&1u16.to_be_bytes());
        encoded[12..14].copy_from_slice(&SnapshotObjectKindV2::EventIndex.code().to_be_bytes());
        encoded[16..24].copy_from_slice(&(self.entries.len() as u64).to_be_bytes());
        encoded[24..32].copy_from_slice(&self.total_authorized_bytes.to_be_bytes());
        encoded[32..64].copy_from_slice(self.final_frame_commitment.as_bytes());
        for entry in &self.entries {
            encoded.extend_from_slice(&entry.encode());
        }
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, AuthenticatedEventIndexErrorV2> {
        if encoded.len() < AUTHENTICATED_EVENT_INDEX_HEADER_BYTES_V2
            || encoded[0..8] != INDEX_MAGIC_V2
        {
            return Err(AuthenticatedEventIndexErrorV2::InvalidEncodedLength);
        }
        if read_u16(encoded, 8) != AUTHENTICATED_EVENT_INDEX_VERSION_V2
            || read_u16(encoded, 10) != 1
        {
            return Err(AuthenticatedEventIndexErrorV2::UnsupportedVersion);
        }
        if read_u16(encoded, 12) != SnapshotObjectKindV2::EventIndex.code() {
            return Err(AuthenticatedEventIndexErrorV2::UnsupportedObjectKind);
        }
        if encoded[14..16]
            .iter()
            .chain(encoded[64..AUTHENTICATED_EVENT_INDEX_HEADER_BYTES_V2].iter())
            .any(|byte| *byte != 0)
        {
            return Err(AuthenticatedEventIndexErrorV2::NonzeroReserved);
        }
        let count = usize::try_from(read_u64(encoded, 16))
            .map_err(|_| AuthenticatedEventIndexErrorV2::EntryCountCap)?;
        if count > MAX_AUTHENTICATED_EVENT_INDEX_SHARD_ENTRIES_V2 {
            return Err(AuthenticatedEventIndexErrorV2::ShardEntryCountCap);
        }
        let expected = AUTHENTICATED_EVENT_INDEX_HEADER_BYTES_V2
            .checked_add(
                count
                    .checked_mul(AUTHENTICATED_EVENT_INDEX_ENTRY_BYTES_V2)
                    .ok_or(AuthenticatedEventIndexErrorV2::ArithmeticOverflow)?,
            )
            .ok_or(AuthenticatedEventIndexErrorV2::ArithmeticOverflow)?;
        if encoded.len() != expected {
            return Err(AuthenticatedEventIndexErrorV2::InvalidEncodedLength);
        }
        let mut entries = Vec::with_capacity(count);
        for chunk in encoded[AUTHENTICATED_EVENT_INDEX_HEADER_BYTES_V2..]
            .chunks_exact(AUTHENTICATED_EVENT_INDEX_ENTRY_BYTES_V2)
        {
            entries.push(AuthenticatedEventIndexEntryV2::decode(chunk)?);
        }
        let index = Self::new(
            entries,
            FrameCommitmentV1::from_bytes(read_array(encoded, 32)),
        )?;
        if index.total_authorized_bytes != read_u64(encoded, 24) {
            return Err(AuthenticatedEventIndexErrorV2::AggregateMismatch);
        }
        Ok(index)
    }

    #[must_use]
    pub fn digest(&self) -> LifecycleDigestV1 {
        derive_authenticated_event_index_digest_v2(&self.encode())
    }
}

/// Authenticated routing metadata for one bounded event-index shard.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedEventIndexShardDescriptorV2 {
    ordinal: u32,
    entry_count: u32,
    first_event_id: EventId,
    last_event_id: EventId,
    shard_digest: LifecycleDigestV1,
    total_authorized_bytes: u64,
    encoded_length: u32,
}

impl AuthenticatedEventIndexShardDescriptorV2 {
    fn from_index(
        ordinal: u32,
        index: &AuthenticatedEventIndexV2,
    ) -> Result<Self, AuthenticatedEventIndexErrorV2> {
        if index.entries.is_empty()
            || index.entries.len() > MAX_AUTHENTICATED_EVENT_INDEX_SHARD_ENTRIES_V2
        {
            return Err(AuthenticatedEventIndexErrorV2::ShardEntryCountCap);
        }
        Ok(Self {
            ordinal,
            entry_count: u32::try_from(index.entries.len())
                .map_err(|_| AuthenticatedEventIndexErrorV2::ArithmeticOverflow)?,
            first_event_id: index.entries[0].event_id,
            last_event_id: index.entries[index.entries.len() - 1].event_id,
            shard_digest: index.digest(),
            total_authorized_bytes: index.total_authorized_bytes,
            encoded_length: u32::try_from(index.encoded_len())
                .map_err(|_| AuthenticatedEventIndexErrorV2::ArithmeticOverflow)?,
        })
    }

    #[must_use]
    pub const fn ordinal(self) -> u32 {
        self.ordinal
    }

    #[must_use]
    pub const fn entry_count(self) -> u32 {
        self.entry_count
    }

    #[must_use]
    pub const fn first_event_id(self) -> EventId {
        self.first_event_id
    }

    #[must_use]
    pub const fn last_event_id(self) -> EventId {
        self.last_event_id
    }

    #[must_use]
    pub const fn shard_digest(self) -> LifecycleDigestV1 {
        self.shard_digest
    }

    #[must_use]
    pub const fn encoded_length(self) -> u32 {
        self.encoded_length
    }

    fn encode(self) -> [u8; AUTHENTICATED_EVENT_INDEX_SHARD_DESCRIPTOR_BYTES_V2] {
        let mut encoded = [0u8; AUTHENTICATED_EVENT_INDEX_SHARD_DESCRIPTOR_BYTES_V2];
        encoded[0..4].copy_from_slice(&self.ordinal.to_be_bytes());
        encoded[4..8].copy_from_slice(&self.entry_count.to_be_bytes());
        encoded[8..40].copy_from_slice(self.first_event_id.as_bytes());
        encoded[40..72].copy_from_slice(self.last_event_id.as_bytes());
        encoded[72..104].copy_from_slice(self.shard_digest.as_bytes());
        encoded[104..112].copy_from_slice(&self.total_authorized_bytes.to_be_bytes());
        encoded[112..116].copy_from_slice(&self.encoded_length.to_be_bytes());
        encoded
    }

    fn decode(encoded: &[u8]) -> Result<Self, AuthenticatedEventIndexErrorV2> {
        if encoded.len() != AUTHENTICATED_EVENT_INDEX_SHARD_DESCRIPTOR_BYTES_V2
            || encoded[116..].iter().any(|byte| *byte != 0)
        {
            return Err(AuthenticatedEventIndexErrorV2::NoncanonicalEntry);
        }
        let descriptor = Self {
            ordinal: read_u32(encoded, 0),
            entry_count: read_u32(encoded, 4),
            first_event_id: EventId::from_bytes(read_array(encoded, 8)),
            last_event_id: EventId::from_bytes(read_array(encoded, 40)),
            shard_digest: LifecycleDigestV1::from_bytes(read_array(encoded, 72)),
            total_authorized_bytes: read_u64(encoded, 104),
            encoded_length: read_u32(encoded, 112),
        };
        if descriptor.entry_count == 0
            || descriptor.entry_count as usize > MAX_AUTHENTICATED_EVENT_INDEX_SHARD_ENTRIES_V2
            || descriptor.first_event_id > descriptor.last_event_id
            || descriptor
                .shard_digest
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            || descriptor.encoded_length as usize > crate::MAX_FRAME_PLAINTEXT_BYTES_V1
        {
            return Err(AuthenticatedEventIndexErrorV2::NoncanonicalEntry);
        }
        Ok(descriptor)
    }
}

impl fmt::Debug for AuthenticatedEventIndexShardDescriptorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedEventIndexShardDescriptorV2")
            .field("ordinal", &self.ordinal)
            .field("entry_count", &self.entry_count)
            .finish_non_exhaustive()
    }
}

/// Compact root for a sorted set of bounded event-index shards.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticatedEventIndexDirectoryV2 {
    descriptors: Vec<AuthenticatedEventIndexShardDescriptorV2>,
    final_frame_commitment: FrameCommitmentV1,
    event_count: u64,
    total_authorized_bytes: u64,
}

impl AuthenticatedEventIndexDirectoryV2 {
    pub fn from_shards(
        shards: &[AuthenticatedEventIndexV2],
        final_frame_commitment: FrameCommitmentV1,
    ) -> Result<Self, AuthenticatedEventIndexErrorV2> {
        if shards.len() > MAX_AUTHENTICATED_EVENT_INDEX_SHARDS_V2
            || (!shards.is_empty() && final_frame_commitment == FrameCommitmentV1::ZERO)
        {
            return Err(AuthenticatedEventIndexErrorV2::ShardCountCap);
        }
        let mut descriptors = Vec::with_capacity(shards.len());
        for (ordinal, shard) in shards.iter().enumerate() {
            descriptors.push(AuthenticatedEventIndexShardDescriptorV2::from_index(
                u32::try_from(ordinal)
                    .map_err(|_| AuthenticatedEventIndexErrorV2::ArithmeticOverflow)?,
                shard,
            )?);
        }
        Self::new(descriptors, final_frame_commitment)
    }

    fn new(
        descriptors: Vec<AuthenticatedEventIndexShardDescriptorV2>,
        final_frame_commitment: FrameCommitmentV1,
    ) -> Result<Self, AuthenticatedEventIndexErrorV2> {
        if descriptors.len() > MAX_AUTHENTICATED_EVENT_INDEX_SHARDS_V2 {
            return Err(AuthenticatedEventIndexErrorV2::ShardCountCap);
        }
        let mut event_count = 0u64;
        let mut total_authorized_bytes = 0u64;
        let mut previous_last = None;
        for (expected, descriptor) in descriptors.iter().enumerate() {
            if descriptor.ordinal as usize != expected
                || previous_last.is_some_and(|last| last >= descriptor.first_event_id)
            {
                return Err(AuthenticatedEventIndexErrorV2::NoncanonicalShardOrder);
            }
            previous_last = Some(descriptor.last_event_id);
            event_count = event_count
                .checked_add(u64::from(descriptor.entry_count))
                .ok_or(AuthenticatedEventIndexErrorV2::ArithmeticOverflow)?;
            total_authorized_bytes = total_authorized_bytes
                .checked_add(descriptor.total_authorized_bytes)
                .ok_or(AuthenticatedEventIndexErrorV2::ArithmeticOverflow)?;
        }
        if event_count > MAX_AUTHENTICATED_EVENT_INDEX_ENTRIES_V2 as u64 {
            return Err(AuthenticatedEventIndexErrorV2::EntryCountCap);
        }
        Ok(Self {
            descriptors,
            final_frame_commitment,
            event_count,
            total_authorized_bytes,
        })
    }

    #[must_use]
    pub fn descriptors(&self) -> &[AuthenticatedEventIndexShardDescriptorV2] {
        &self.descriptors
    }

    #[must_use]
    pub const fn event_count(&self) -> u64 {
        self.event_count
    }

    #[must_use]
    pub fn shard_for(
        &self,
        event_id: EventId,
    ) -> Option<&AuthenticatedEventIndexShardDescriptorV2> {
        let position = self
            .descriptors
            .partition_point(|descriptor| descriptor.last_event_id < event_id);
        self.descriptors
            .get(position)
            .filter(|descriptor| descriptor.first_event_id <= event_id)
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = vec![0u8; AUTHENTICATED_EVENT_INDEX_DIRECTORY_HEADER_BYTES_V2];
        encoded[0..8].copy_from_slice(&INDEX_DIRECTORY_MAGIC_V2);
        encoded[8..10].copy_from_slice(&AUTHENTICATED_EVENT_INDEX_VERSION_V2.to_be_bytes());
        encoded[10..12].copy_from_slice(
            &SnapshotObjectKindV2::EventIndexDirectory
                .code()
                .to_be_bytes(),
        );
        encoded[16..20].copy_from_slice(&(self.descriptors.len() as u32).to_be_bytes());
        encoded[24..32].copy_from_slice(&self.event_count.to_be_bytes());
        encoded[32..40].copy_from_slice(&self.total_authorized_bytes.to_be_bytes());
        encoded[40..72].copy_from_slice(self.final_frame_commitment.as_bytes());
        for descriptor in &self.descriptors {
            encoded.extend_from_slice(&descriptor.encode());
        }
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, AuthenticatedEventIndexErrorV2> {
        if encoded.len() < AUTHENTICATED_EVENT_INDEX_DIRECTORY_HEADER_BYTES_V2
            || encoded[0..8] != INDEX_DIRECTORY_MAGIC_V2
            || read_u16(encoded, 8) != AUTHENTICATED_EVENT_INDEX_VERSION_V2
            || read_u16(encoded, 10) != SnapshotObjectKindV2::EventIndexDirectory.code()
            || encoded[12..16]
                .iter()
                .chain(encoded[20..24].iter())
                .chain(encoded[72..128].iter())
                .any(|byte| *byte != 0)
        {
            return Err(AuthenticatedEventIndexErrorV2::InvalidEncodedLength);
        }
        let count = read_u32(encoded, 16) as usize;
        if count > MAX_AUTHENTICATED_EVENT_INDEX_SHARDS_V2 {
            return Err(AuthenticatedEventIndexErrorV2::ShardCountCap);
        }
        let expected = AUTHENTICATED_EVENT_INDEX_DIRECTORY_HEADER_BYTES_V2
            .checked_add(
                count
                    .checked_mul(AUTHENTICATED_EVENT_INDEX_SHARD_DESCRIPTOR_BYTES_V2)
                    .ok_or(AuthenticatedEventIndexErrorV2::ArithmeticOverflow)?,
            )
            .ok_or(AuthenticatedEventIndexErrorV2::ArithmeticOverflow)?;
        if encoded.len() != expected {
            return Err(AuthenticatedEventIndexErrorV2::InvalidEncodedLength);
        }
        let mut descriptors = Vec::with_capacity(count);
        for chunk in encoded[AUTHENTICATED_EVENT_INDEX_DIRECTORY_HEADER_BYTES_V2..]
            .chunks_exact(AUTHENTICATED_EVENT_INDEX_SHARD_DESCRIPTOR_BYTES_V2)
        {
            descriptors.push(AuthenticatedEventIndexShardDescriptorV2::decode(chunk)?);
        }
        let directory = Self::new(
            descriptors,
            FrameCommitmentV1::from_bytes(read_array(encoded, 40)),
        )?;
        if directory.event_count != read_u64(encoded, 24)
            || directory.total_authorized_bytes != read_u64(encoded, 32)
        {
            return Err(AuthenticatedEventIndexErrorV2::AggregateMismatch);
        }
        Ok(directory)
    }

    pub fn verify_shard(
        &self,
        descriptor: AuthenticatedEventIndexShardDescriptorV2,
        shard: &AuthenticatedEventIndexV2,
    ) -> Result<(), AuthenticatedEventIndexErrorV2> {
        if AuthenticatedEventIndexShardDescriptorV2::from_index(descriptor.ordinal, shard)?
            != descriptor
        {
            return Err(AuthenticatedEventIndexErrorV2::AggregateMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> LifecycleDigestV1 {
        let mut hasher = Sha256::new();
        hasher.update(INDEX_DIRECTORY_DIGEST_DOMAIN_V2);
        hasher.update(self.encode());
        LifecycleDigestV1::from_bytes(hasher.finalize().into())
    }
}

impl fmt::Debug for AuthenticatedEventIndexV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedEventIndexV2")
            .field("entry_count", &self.entries.len())
            .field("total_authorized_bytes", &self.total_authorized_bytes)
            .finish()
    }
}

impl fmt::Debug for AuthenticatedEventIndexDirectoryV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedEventIndexDirectoryV2")
            .field("shard_count", &self.descriptors.len())
            .field("event_count", &self.event_count)
            .field("total_authorized_bytes", &self.total_authorized_bytes)
            .finish_non_exhaustive()
    }
}

#[must_use]
pub fn derive_authenticated_event_index_digest_v2(bytes: &[u8]) -> LifecycleDigestV1 {
    let mut hasher = Sha256::new();
    hasher.update(INDEX_DIGEST_DOMAIN_V2);
    hasher.update(bytes);
    let digest: [u8; LIFECYCLE_DIGEST_BYTES_V1] = hasher.finalize().into();
    LifecycleDigestV1::from_bytes(digest)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatedEventIndexErrorV2 {
    InvalidEncodedLength,
    UnsupportedVersion,
    UnsupportedObjectKind,
    NonzeroReserved,
    EntryCountCap,
    DuplicateEntry,
    InvalidLocator,
    NoncanonicalEntry,
    NoncanonicalExactness,
    AggregateMismatch,
    ArithmeticOverflow,
    ShardEntryCountCap,
    ShardCountCap,
    NoncanonicalShardOrder,
}

impl AuthenticatedEventIndexErrorV2 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidEncodedLength => "EVIDENTRAIL_EVENT_INDEX_V2_INVALID_ENCODED_LENGTH",
            Self::UnsupportedVersion => "EVIDENTRAIL_EVENT_INDEX_V2_UNSUPPORTED_VERSION",
            Self::UnsupportedObjectKind => "EVIDENTRAIL_EVENT_INDEX_V2_UNSUPPORTED_OBJECT_KIND",
            Self::NonzeroReserved => "EVIDENTRAIL_EVENT_INDEX_V2_NONZERO_RESERVED",
            Self::EntryCountCap => "EVIDENTRAIL_EVENT_INDEX_V2_ENTRY_COUNT_CAP",
            Self::DuplicateEntry => "EVIDENTRAIL_EVENT_INDEX_V2_DUPLICATE_ENTRY",
            Self::InvalidLocator => "EVIDENTRAIL_EVENT_INDEX_V2_INVALID_LOCATOR",
            Self::NoncanonicalEntry => "EVIDENTRAIL_EVENT_INDEX_V2_NONCANONICAL_ENTRY",
            Self::NoncanonicalExactness => "EVIDENTRAIL_EVENT_INDEX_V2_NONCANONICAL_EXACTNESS",
            Self::AggregateMismatch => "EVIDENTRAIL_EVENT_INDEX_V2_AGGREGATE_MISMATCH",
            Self::ArithmeticOverflow => "EVIDENTRAIL_EVENT_INDEX_V2_ARITHMETIC_OVERFLOW",
            Self::ShardEntryCountCap => "EVIDENTRAIL_EVENT_INDEX_V2_SHARD_ENTRY_COUNT_CAP",
            Self::ShardCountCap => "EVIDENTRAIL_EVENT_INDEX_V2_SHARD_COUNT_CAP",
            Self::NoncanonicalShardOrder => "EVIDENTRAIL_EVENT_INDEX_V2_NONCANONICAL_SHARD_ORDER",
        }
    }
}

impl fmt::Debug for AuthenticatedEventIndexErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedEventIndexErrorV2")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for AuthenticatedEventIndexErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for AuthenticatedEventIndexErrorV2 {}

const _: () = assert!(FRAME_COMMITMENT_BYTES_V1 == LIFECYCLE_DIGEST_BYTES_V1);

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(read_array(bytes, offset))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(read_array(bytes, offset))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(read_array(bytes, offset))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut result = [0u8; N];
    result.copy_from_slice(&bytes[offset..offset + N]);
    result
}
