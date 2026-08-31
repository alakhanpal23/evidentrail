use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::EventId;
use sha2::{Digest, Sha256};

use crate::{
    EventFrameLocatorV2, LifecycleDigestV1, NonceReservationV1, OperationIdV1, SnapshotObjectKindV2,
};

pub const DURABLE_BATCH_JOURNAL_VERSION_V2: u16 = 2;
pub const DURABLE_BATCH_JOURNAL_HEADER_BYTES_V2: usize = 128;
pub const DURABLE_ACKNOWLEDGEMENT_BYTES_V2: usize = 128;
pub const MAX_DURABLE_ACKNOWLEDGEMENTS_V2: usize = 4_094;

const JOURNAL_MAGIC_V2: [u8; 8] = *b"EVRJRN02";
const ACK_DIGEST_DOMAIN_V2: &[u8] = b"evidentrail.snapshot.acknowledgements.v2";
const JOURNAL_DIGEST_DOMAIN_V2: &[u8] = b"evidentrail.snapshot.batch-journal.v2";

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DurableAcknowledgementV2 {
    event_id: EventId,
    locator: EventFrameLocatorV2,
}

impl DurableAcknowledgementV2 {
    #[must_use]
    pub const fn new(event_id: EventId, locator: EventFrameLocatorV2) -> Self {
        Self { event_id, locator }
    }

    #[must_use]
    pub const fn event_id(self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn locator(self) -> EventFrameLocatorV2 {
        self.locator
    }

    fn encode(self) -> [u8; DURABLE_ACKNOWLEDGEMENT_BYTES_V2] {
        let mut encoded = [0u8; DURABLE_ACKNOWLEDGEMENT_BYTES_V2];
        encoded[0..32].copy_from_slice(self.event_id.as_bytes());
        encoded[32..40].copy_from_slice(&self.locator.segment_ordinal().to_be_bytes());
        encoded[40..44].copy_from_slice(&self.locator.frame_sequence().to_be_bytes());
        encoded[48..56].copy_from_slice(&self.locator.global_sequence().to_be_bytes());
        encoded[56..64].copy_from_slice(&self.locator.byte_offset().to_be_bytes());
        encoded[64..68].copy_from_slice(&self.locator.encoded_length().to_be_bytes());
        encoded[68..72].copy_from_slice(&self.locator.plaintext_length().to_be_bytes());
        encoded[72..104].copy_from_slice(self.locator.frame_commitment().as_bytes());
        encoded
    }

    fn decode(encoded: &[u8]) -> Result<Self, DurableBatchJournalErrorV2> {
        if encoded.len() != DURABLE_ACKNOWLEDGEMENT_BYTES_V2
            || encoded[44..48]
                .iter()
                .chain(encoded[104..].iter())
                .any(|byte| *byte != 0)
        {
            return Err(DurableBatchJournalErrorV2::NoncanonicalAcknowledgement);
        }
        let locator = EventFrameLocatorV2::new(
            read_u64(encoded, 32),
            read_u32(encoded, 40),
            read_u64(encoded, 48),
            read_u64(encoded, 56),
            read_u32(encoded, 64),
            read_u32(encoded, 68),
            crate::FrameCommitmentV1::from_bytes(read_array(encoded, 72)),
        )
        .map_err(|_| DurableBatchJournalErrorV2::NoncanonicalAcknowledgement)?;
        Ok(Self::new(
            EventId::from_bytes(read_array(encoded, 0)),
            locator,
        ))
    }
}

impl fmt::Debug for DurableAcknowledgementV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurableAcknowledgementV2(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DurableBatchJournalV2 {
    batch_ordinal: u64,
    operation: OperationIdV1,
    canonical_digest: LifecycleDigestV1,
    nonce_first: u64,
    nonce_count: u64,
    acknowledgements: Vec<DurableAcknowledgementV2>,
}

impl DurableBatchJournalV2 {
    pub fn new(
        batch_ordinal: u64,
        operation: OperationIdV1,
        canonical_digest: LifecycleDigestV1,
        reservation: NonceReservationV1,
        acknowledgements: Vec<DurableAcknowledgementV2>,
    ) -> Result<Self, DurableBatchJournalErrorV2> {
        if operation.is_zero()
            || acknowledgements.len() > MAX_DURABLE_ACKNOWLEDGEMENTS_V2
            || reservation.count() == 0
        {
            return Err(DurableBatchJournalErrorV2::InvalidHeader);
        }
        let mut event_ids = BTreeSet::new();
        let mut locations = BTreeSet::new();
        for acknowledgement in &acknowledgements {
            let locator = acknowledgement.locator;
            if !event_ids.insert(acknowledgement.event_id)
                || !locations.insert((locator.segment_ordinal(), locator.frame_sequence()))
            {
                return Err(DurableBatchJournalErrorV2::DuplicateAcknowledgement);
            }
        }
        Ok(Self {
            batch_ordinal,
            operation,
            canonical_digest,
            nonce_first: reservation.first_counter(),
            nonce_count: reservation.count(),
            acknowledgements,
        })
    }

    #[must_use]
    pub const fn batch_ordinal(&self) -> u64 {
        self.batch_ordinal
    }

    #[must_use]
    pub const fn operation(&self) -> OperationIdV1 {
        self.operation
    }

    #[must_use]
    pub const fn canonical_digest(&self) -> LifecycleDigestV1 {
        self.canonical_digest
    }

    #[must_use]
    pub fn acknowledgements(&self) -> &[DurableAcknowledgementV2] {
        &self.acknowledgements
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut entries =
            Vec::with_capacity(self.acknowledgements.len() * DURABLE_ACKNOWLEDGEMENT_BYTES_V2);
        for acknowledgement in &self.acknowledgements {
            entries.extend_from_slice(&acknowledgement.encode());
        }
        let mut encoded = vec![0u8; DURABLE_BATCH_JOURNAL_HEADER_BYTES_V2];
        encoded[0..8].copy_from_slice(&JOURNAL_MAGIC_V2);
        encoded[8..10].copy_from_slice(&DURABLE_BATCH_JOURNAL_VERSION_V2.to_be_bytes());
        encoded[10..12].copy_from_slice(
            &SnapshotObjectKindV2::OperationalReceipt
                .code()
                .to_be_bytes(),
        );
        encoded[16..24].copy_from_slice(&self.batch_ordinal.to_be_bytes());
        encoded[24..40].copy_from_slice(self.operation.as_bytes());
        encoded[40..72].copy_from_slice(self.canonical_digest.as_bytes());
        encoded[72..80].copy_from_slice(&self.nonce_first.to_be_bytes());
        encoded[80..88].copy_from_slice(&self.nonce_count.to_be_bytes());
        encoded[88..92].copy_from_slice(&(self.acknowledgements.len() as u32).to_be_bytes());
        encoded[96..128].copy_from_slice(&derive_acknowledgement_digest(&entries));
        encoded.extend_from_slice(&entries);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, DurableBatchJournalErrorV2> {
        if encoded.len() < DURABLE_BATCH_JOURNAL_HEADER_BYTES_V2
            || encoded[0..8] != JOURNAL_MAGIC_V2
            || read_u16(encoded, 8) != DURABLE_BATCH_JOURNAL_VERSION_V2
            || read_u16(encoded, 10) != SnapshotObjectKindV2::OperationalReceipt.code()
            || encoded[12..16]
                .iter()
                .chain(encoded[92..96].iter())
                .any(|byte| *byte != 0)
        {
            return Err(DurableBatchJournalErrorV2::InvalidHeader);
        }
        let count = read_u32(encoded, 88) as usize;
        if count > MAX_DURABLE_ACKNOWLEDGEMENTS_V2 {
            return Err(DurableBatchJournalErrorV2::AcknowledgementCountCap);
        }
        let expected = DURABLE_BATCH_JOURNAL_HEADER_BYTES_V2
            .checked_add(
                count
                    .checked_mul(DURABLE_ACKNOWLEDGEMENT_BYTES_V2)
                    .ok_or(DurableBatchJournalErrorV2::InvalidEncodedLength)?,
            )
            .ok_or(DurableBatchJournalErrorV2::InvalidEncodedLength)?;
        if encoded.len() != expected {
            return Err(DurableBatchJournalErrorV2::InvalidEncodedLength);
        }
        let entries = &encoded[DURABLE_BATCH_JOURNAL_HEADER_BYTES_V2..];
        if encoded[96..128] != derive_acknowledgement_digest(entries) {
            return Err(DurableBatchJournalErrorV2::AcknowledgementDigestMismatch);
        }
        let mut acknowledgements = Vec::with_capacity(count);
        for chunk in entries.chunks_exact(DURABLE_ACKNOWLEDGEMENT_BYTES_V2) {
            acknowledgements.push(DurableAcknowledgementV2::decode(chunk)?);
        }
        let reservation = NonceReservationV1::new(
            crate::ResultNoncePrefixV1::from_bytes([1; 16]),
            read_u64(encoded, 72),
            read_u64(encoded, 80),
        )
        .map_err(|_| DurableBatchJournalErrorV2::InvalidHeader)?;
        Self::new(
            read_u64(encoded, 16),
            OperationIdV1::from_bytes(read_array(encoded, 24)),
            LifecycleDigestV1::from_bytes(read_array(encoded, 40)),
            reservation,
            acknowledgements,
        )
    }

    #[must_use]
    pub fn digest(&self) -> LifecycleDigestV1 {
        let mut hasher = Sha256::new();
        hasher.update(JOURNAL_DIGEST_DOMAIN_V2);
        hasher.update(self.encode());
        LifecycleDigestV1::from_bytes(hasher.finalize().into())
    }
}

impl fmt::Debug for DurableBatchJournalV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableBatchJournalV2")
            .field("batch_ordinal", &self.batch_ordinal)
            .field("acknowledgement_count", &self.acknowledgements.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DurableBatchJournalErrorV2 {
    InvalidEncodedLength,
    InvalidHeader,
    AcknowledgementCountCap,
    NoncanonicalAcknowledgement,
    DuplicateAcknowledgement,
    AcknowledgementDigestMismatch,
}

impl DurableBatchJournalErrorV2 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidEncodedLength => "EVIDENTRAIL_BATCH_JOURNAL_V2_INVALID_ENCODED_LENGTH",
            Self::InvalidHeader => "EVIDENTRAIL_BATCH_JOURNAL_V2_INVALID_HEADER",
            Self::AcknowledgementCountCap => {
                "EVIDENTRAIL_BATCH_JOURNAL_V2_ACKNOWLEDGEMENT_COUNT_CAP"
            }
            Self::NoncanonicalAcknowledgement => {
                "EVIDENTRAIL_BATCH_JOURNAL_V2_NONCANONICAL_ACKNOWLEDGEMENT"
            }
            Self::DuplicateAcknowledgement => {
                "EVIDENTRAIL_BATCH_JOURNAL_V2_DUPLICATE_ACKNOWLEDGEMENT"
            }
            Self::AcknowledgementDigestMismatch => {
                "EVIDENTRAIL_BATCH_JOURNAL_V2_ACKNOWLEDGEMENT_DIGEST_MISMATCH"
            }
        }
    }
}

impl fmt::Debug for DurableBatchJournalErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for DurableBatchJournalErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for DurableBatchJournalErrorV2 {}

fn derive_acknowledgement_digest(entries: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ACK_DIGEST_DOMAIN_V2);
    hasher.update(entries);
    hasher.finalize().into()
}

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
    let mut result = [0; N];
    result.copy_from_slice(&bytes[offset..offset + N]);
    result
}
