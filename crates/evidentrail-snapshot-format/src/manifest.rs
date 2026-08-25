use std::fmt;

use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use evidentrail_schema::ResultId;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    ManifestKeyViewV1, OUTER_VERSION_V1, SnapshotFormatErrorV1, XCHACHA20_POLY1305_SUITE_ID_V1,
};

pub const MANIFEST_HEADER_BYTES_V1: usize = 120;
pub const MANIFEST_NONCE_BYTES_V1: usize = 24;
pub const MANIFEST_TAG_BYTES_V1: usize = 16;
pub const MANIFEST_COMMITMENT_BYTES_V1: usize = 32;
/// Frozen numeric encoding of the ADR's `Manifest` outer object kind.
pub const MANIFEST_OBJECT_KIND_V1: u16 = 1;

/// Outer allocation limit only. The future manifest payload codec must impose
/// its own field, collection, and nesting limits within this envelope.
pub const MAX_MANIFEST_PLAINTEXT_BYTES_V1: usize = 16 * 1024 * 1024;
pub const MAX_MANIFEST_CIPHERTEXT_BYTES_V1: usize =
    MAX_MANIFEST_PLAINTEXT_BYTES_V1 + MANIFEST_TAG_BYTES_V1;
pub const MAX_ENCODED_MANIFEST_BYTES_V1: usize =
    MANIFEST_HEADER_BYTES_V1 + MAX_MANIFEST_CIPHERTEXT_BYTES_V1;

pub const MANIFEST_AAD_DOMAIN_V1: &[u8] = b"evidentrail.snapshot.manifest.v1";
pub const MANIFEST_AAD_BYTES_V1: usize = MANIFEST_AAD_DOMAIN_V1.len() + MANIFEST_HEADER_BYTES_V1;

const MANIFEST_MAGIC_V1: [u8; 8] = *b"EVRMNF01";
const MANIFEST_COMMITMENT_DOMAIN_V1: &[u8] = b"evidentrail.snapshot.manifest-commit.v1";

/// Injected manifest nonce. Production generation and result-wide uniqueness
/// across frames and the manifest belong to the store writer.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ManifestNonceV1([u8; MANIFEST_NONCE_BYTES_V1]);

impl ManifestNonceV1 {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; MANIFEST_NONCE_BYTES_V1]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; MANIFEST_NONCE_BYTES_V1] {
        &self.0
    }
}

impl fmt::Debug for ManifestNonceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManifestNonceV1(<redacted>)")
    }
}

/// Domain-separated digest of one complete manifest header and ciphertext.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ManifestCommitmentV1([u8; MANIFEST_COMMITMENT_BYTES_V1]);

impl ManifestCommitmentV1 {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; MANIFEST_COMMITMENT_BYTES_V1]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; MANIFEST_COMMITMENT_BYTES_V1] {
        &self.0
    }
}

impl fmt::Debug for ManifestCommitmentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManifestCommitmentV1(<redacted>)")
    }
}

/// Constructor-validated fixed-width outer manifest header from ADR 0004.
///
/// A typed result identity is retained exactly. Its required randomness cannot
/// be verified by a format parser and belongs to the future store boundary.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ManifestHeaderV1 {
    payload_schema: u16,
    result_id: ResultId,
    object_sequence: u64,
    created_unix_nanos: i64,
    expires_unix_nanos: i64,
    plaintext_length: u32,
    ciphertext_length: u32,
    nonce: ManifestNonceV1,
}

impl ManifestHeaderV1 {
    pub fn new(
        payload_schema: u16,
        result_id: ResultId,
        object_sequence: u64,
        created_unix_nanos: i64,
        expires_unix_nanos: i64,
        plaintext_length: u32,
        nonce: ManifestNonceV1,
    ) -> Result<Self, SnapshotFormatErrorV1> {
        if payload_schema == 0 {
            return Err(SnapshotFormatErrorV1::InvalidPayloadSchema);
        }
        if object_sequence != 0 {
            return Err(SnapshotFormatErrorV1::InvalidObjectSequence);
        }
        if expires_unix_nanos <= created_unix_nanos {
            return Err(SnapshotFormatErrorV1::InvalidTimeRange);
        }
        let plaintext_usize =
            usize::try_from(plaintext_length).map_err(|_| SnapshotFormatErrorV1::LengthOverflow)?;
        if plaintext_usize > MAX_MANIFEST_PLAINTEXT_BYTES_V1 {
            return Err(SnapshotFormatErrorV1::PlaintextTooLarge);
        }
        let ciphertext_length = plaintext_length
            .checked_add(
                u32::try_from(MANIFEST_TAG_BYTES_V1)
                    .map_err(|_| SnapshotFormatErrorV1::LengthOverflow)?,
            )
            .ok_or(SnapshotFormatErrorV1::LengthOverflow)?;
        Ok(Self {
            payload_schema,
            result_id,
            object_sequence,
            created_unix_nanos,
            expires_unix_nanos,
            plaintext_length,
            ciphertext_length,
            nonce,
        })
    }

    #[must_use]
    pub const fn payload_schema(&self) -> u16 {
        self.payload_schema
    }

    #[must_use]
    pub const fn result_id(&self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn object_sequence(&self) -> u64 {
        self.object_sequence
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
    pub const fn plaintext_length(&self) -> u32 {
        self.plaintext_length
    }

    #[must_use]
    pub const fn ciphertext_length(&self) -> u32 {
        self.ciphertext_length
    }

    #[must_use]
    pub const fn nonce(&self) -> ManifestNonceV1 {
        self.nonce
    }

    #[must_use]
    pub fn encode(&self) -> [u8; MANIFEST_HEADER_BYTES_V1] {
        let mut encoded = [0u8; MANIFEST_HEADER_BYTES_V1];
        encoded[0..8].copy_from_slice(&MANIFEST_MAGIC_V1);
        encoded[8..10].copy_from_slice(&OUTER_VERSION_V1.to_be_bytes());
        encoded[10..12].copy_from_slice(&XCHACHA20_POLY1305_SUITE_ID_V1.to_be_bytes());
        encoded[12..14].copy_from_slice(&self.payload_schema.to_be_bytes());
        encoded[14..16].copy_from_slice(&MANIFEST_OBJECT_KIND_V1.to_be_bytes());
        encoded[16..48].copy_from_slice(self.result_id.as_bytes());
        encoded[48..56].copy_from_slice(&self.object_sequence.to_be_bytes());
        encoded[56..64].copy_from_slice(&self.created_unix_nanos.to_be_bytes());
        encoded[64..72].copy_from_slice(&self.expires_unix_nanos.to_be_bytes());
        encoded[72..76].copy_from_slice(&self.plaintext_length.to_be_bytes());
        encoded[76..80].copy_from_slice(&self.ciphertext_length.to_be_bytes());
        encoded[80..104].copy_from_slice(self.nonce.as_bytes());
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, SnapshotFormatErrorV1> {
        if encoded.len() != MANIFEST_HEADER_BYTES_V1 {
            return Err(SnapshotFormatErrorV1::InvalidEncodedLength);
        }
        if encoded[0..8] != MANIFEST_MAGIC_V1 {
            return Err(SnapshotFormatErrorV1::InvalidMagic);
        }
        if read_u16(encoded, 8) != OUTER_VERSION_V1 {
            return Err(SnapshotFormatErrorV1::UnsupportedOuterVersion);
        }
        if read_u16(encoded, 10) != XCHACHA20_POLY1305_SUITE_ID_V1 {
            return Err(SnapshotFormatErrorV1::UnsupportedSuite);
        }
        if read_u16(encoded, 14) != MANIFEST_OBJECT_KIND_V1 {
            return Err(SnapshotFormatErrorV1::UnsupportedObjectKind);
        }
        if encoded[104..120].iter().any(|byte| *byte != 0) {
            return Err(SnapshotFormatErrorV1::NonzeroReserved);
        }
        let header = Self::new(
            read_u16(encoded, 12),
            ResultId::from_bytes(read_array(encoded, 16)),
            read_u64(encoded, 48),
            read_i64(encoded, 56),
            read_i64(encoded, 64),
            read_u32(encoded, 72),
            ManifestNonceV1::from_bytes(read_array(encoded, 80)),
        )?;
        if read_u32(encoded, 76) != header.ciphertext_length {
            return Err(SnapshotFormatErrorV1::CiphertextLengthMismatch);
        }
        Ok(header)
    }
}

impl fmt::Debug for ManifestHeaderV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManifestHeaderV1")
            .field("payload_schema", &self.payload_schema)
            .field("object_sequence", &self.object_sequence)
            .field("plaintext_length", &self.plaintext_length)
            .field("ciphertext_length", &self.ciphertext_length)
            .finish()
    }
}

/// One authenticated outer manifest object. Its plaintext schema is opaque.
#[derive(PartialEq, Eq)]
pub struct SealedManifestV1 {
    header: ManifestHeaderV1,
    ciphertext: Vec<u8>,
    tag: [u8; MANIFEST_TAG_BYTES_V1],
    commitment: ManifestCommitmentV1,
}

impl SealedManifestV1 {
    #[must_use]
    pub const fn header(&self) -> &ManifestHeaderV1 {
        &self.header
    }

    #[must_use]
    pub const fn commitment(&self) -> ManifestCommitmentV1 {
        self.commitment
    }

    #[must_use]
    pub fn encoded_len(&self) -> usize {
        MANIFEST_HEADER_BYTES_V1 + self.ciphertext.len() + MANIFEST_TAG_BYTES_V1
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(self.encoded_len());
        encoded.extend_from_slice(&self.header.encode());
        encoded.extend_from_slice(&self.ciphertext);
        encoded.extend_from_slice(&self.tag);
        encoded
    }

    pub fn decode(
        expected_result_id: ResultId,
        encoded: &[u8],
    ) -> Result<Self, SnapshotFormatErrorV1> {
        if encoded.len() < MANIFEST_HEADER_BYTES_V1 {
            return Err(SnapshotFormatErrorV1::InvalidEncodedLength);
        }
        let header = ManifestHeaderV1::decode(&encoded[..MANIFEST_HEADER_BYTES_V1])?;
        if header.result_id() != expected_result_id {
            return Err(SnapshotFormatErrorV1::ResultMismatch);
        }
        let ciphertext_length = usize::try_from(header.ciphertext_length())
            .map_err(|_| SnapshotFormatErrorV1::LengthOverflow)?;
        let expected_length = MANIFEST_HEADER_BYTES_V1
            .checked_add(ciphertext_length)
            .ok_or(SnapshotFormatErrorV1::LengthOverflow)?;
        if expected_length > MAX_ENCODED_MANIFEST_BYTES_V1 || encoded.len() != expected_length {
            return Err(SnapshotFormatErrorV1::InvalidEncodedLength);
        }
        let ciphertext_end = expected_length
            .checked_sub(MANIFEST_TAG_BYTES_V1)
            .ok_or(SnapshotFormatErrorV1::LengthOverflow)?;
        let ciphertext = encoded[MANIFEST_HEADER_BYTES_V1..ciphertext_end].to_vec();
        let mut tag = [0u8; MANIFEST_TAG_BYTES_V1];
        tag.copy_from_slice(&encoded[ciphertext_end..expected_length]);
        let commitment = derive_manifest_commitment(&header, &ciphertext, &tag);
        Ok(Self {
            header,
            ciphertext,
            tag,
            commitment,
        })
    }
}

impl fmt::Debug for SealedManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedManifestV1")
            .field("header", &self.header)
            .field("ciphertext_bytes", &self.ciphertext.len())
            .field("tag_bytes", &MANIFEST_TAG_BYTES_V1)
            .finish()
    }
}

/// Authenticated manifest plaintext which clears its allocation on drop.
pub struct OpenedManifestV1(Zeroizing<Vec<u8>>);

impl OpenedManifestV1 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for OpenedManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenedManifestV1")
            .field("byte_count", &self.0.len())
            .finish()
    }
}

/// Exact manifest AAD: domain || encoded fixed-width header.
#[must_use]
pub fn canonical_manifest_aad_v1(header: &ManifestHeaderV1) -> [u8; MANIFEST_AAD_BYTES_V1] {
    let mut aad = [0u8; MANIFEST_AAD_BYTES_V1];
    aad[..MANIFEST_AAD_DOMAIN_V1.len()].copy_from_slice(MANIFEST_AAD_DOMAIN_V1);
    aad[MANIFEST_AAD_DOMAIN_V1.len()..].copy_from_slice(&header.encode());
    aad
}

/// Seal opaque, bounded manifest plaintext using caller-injected key and nonce.
/// This function authenticates the nonce but makes no uniqueness claim.
pub fn seal_manifest_v1(
    key: &ManifestKeyViewV1<'_>,
    header: ManifestHeaderV1,
    plaintext: &[u8],
) -> Result<SealedManifestV1, SnapshotFormatErrorV1> {
    if plaintext.len()
        != usize::try_from(header.plaintext_length())
            .map_err(|_| SnapshotFormatErrorV1::LengthOverflow)?
    {
        return Err(SnapshotFormatErrorV1::PlaintextLengthMismatch);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| SnapshotFormatErrorV1::AuthenticationFailed)?;
    let nonce = XNonce::from(*header.nonce().as_bytes());
    let aad = canonical_manifest_aad_v1(&header);
    let mut ciphertext = plaintext.to_vec();
    let tag = match cipher.encrypt_inout_detached(&nonce, &aad, ciphertext.as_mut_slice().into()) {
        Ok(tag) => tag,
        Err(_) => {
            ciphertext.zeroize();
            return Err(SnapshotFormatErrorV1::AuthenticationFailed);
        }
    };
    let tag: [u8; MANIFEST_TAG_BYTES_V1] = tag.into();
    let commitment = derive_manifest_commitment(&header, &ciphertext, &tag);
    Ok(SealedManifestV1 {
        header,
        ciphertext,
        tag,
        commitment,
    })
}

/// Authenticate the exact expected result identity before releasing plaintext.
pub fn open_manifest_v1(
    key: &ManifestKeyViewV1<'_>,
    expected_result_id: ResultId,
    manifest: &SealedManifestV1,
) -> Result<OpenedManifestV1, SnapshotFormatErrorV1> {
    if manifest.header.result_id() != expected_result_id {
        return Err(SnapshotFormatErrorV1::ResultMismatch);
    }
    let expected_commitment =
        derive_manifest_commitment(&manifest.header, &manifest.ciphertext, &manifest.tag);
    if expected_commitment != manifest.commitment {
        return Err(SnapshotFormatErrorV1::CommitmentMismatch);
    }
    if manifest.ciphertext.len()
        != usize::try_from(manifest.header.plaintext_length())
            .map_err(|_| SnapshotFormatErrorV1::LengthOverflow)?
    {
        return Err(SnapshotFormatErrorV1::CiphertextLengthMismatch);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| SnapshotFormatErrorV1::AuthenticationFailed)?;
    let nonce = XNonce::from(*manifest.header.nonce().as_bytes());
    let aad = canonical_manifest_aad_v1(&manifest.header);
    let tag = Tag::from(manifest.tag);
    let mut plaintext = Zeroizing::new(manifest.ciphertext.clone());
    cipher
        .decrypt_inout_detached(&nonce, &aad, plaintext.as_mut_slice().into(), &tag)
        .map_err(|_| SnapshotFormatErrorV1::AuthenticationFailed)?;
    Ok(OpenedManifestV1(plaintext))
}

fn derive_manifest_commitment(
    header: &ManifestHeaderV1,
    ciphertext: &[u8],
    tag: &[u8; MANIFEST_TAG_BYTES_V1],
) -> ManifestCommitmentV1 {
    let mut hasher = Sha256::new();
    hasher.update(MANIFEST_COMMITMENT_DOMAIN_V1);
    hasher.update(header.encode());
    hasher.update(ciphertext);
    hasher.update(tag);
    ManifestCommitmentV1::from_bytes(hasher.finalize().into())
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

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_be_bytes(read_array(bytes, offset))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut output = [0u8; N];
    output.copy_from_slice(&bytes[offset..offset + N]);
    output
}

const _: () = assert!(MANIFEST_NONCE_BYTES_V1 == 24);
