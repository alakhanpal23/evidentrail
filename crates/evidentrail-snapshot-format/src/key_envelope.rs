use std::error::Error as StdError;
use std::fmt;

use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use evidentrail_schema::ResultId;
use zeroize::Zeroizing;

use crate::{
    DERIVED_KEY_BYTES_V1, DekWrapKeyViewV1, FrameCommitmentV1, MAX_FRAMES_PER_SEGMENT_V1,
    ManifestCommitmentV1, ResultDekV1, RootKeyVersionV1, SealKeyViewV1,
};

pub const KEY_RECORD_VERSION_V1: u16 = 1;
pub const KEY_ENVELOPE_CONTEXT_BYTES_V1: usize = 54;
pub const KEY_ENVELOPE_NONCE_BYTES_V1: usize = 24;
pub const KEY_ENVELOPE_TAG_BYTES_V1: usize = 16;
pub const WRAPPED_RESULT_DEK_BYTES_V1: usize =
    KEY_ENVELOPE_NONCE_BYTES_V1 + DERIVED_KEY_BYTES_V1 + KEY_ENVELOPE_TAG_BYTES_V1;

pub const DEK_WRAP_AAD_DOMAIN_V1: &[u8] = b"evidentrail.snapshot.dek-wrap.v1";
pub const DEK_WRAP_AAD_BYTES_V1: usize =
    DEK_WRAP_AAD_DOMAIN_V1.len() + KEY_ENVELOPE_CONTEXT_BYTES_V1;
pub const SEAL_BINDING_AAD_DOMAIN_V1: &[u8] = b"evidentrail.snapshot.seal-binding.v1";
pub const SEAL_BINDING_AAD_BYTES_V1: usize =
    SEAL_BINDING_AAD_DOMAIN_V1.len() + KEY_ENVELOPE_CONTEXT_BYTES_V1;

pub const SEAL_BINDING_BYTES_V1: usize = 80;
pub const SEALED_SEAL_BINDING_BYTES_V1: usize =
    KEY_ENVELOPE_NONCE_BYTES_V1 + SEAL_BINDING_BYTES_V1 + KEY_ENVELOPE_TAG_BYTES_V1;

/// Frozen V1 storage bounds. A writer may choose lower policy caps.
pub const MAX_SEGMENTS_PER_RESULT_V1: u64 = 4_096;
pub const MAX_TOTAL_FRAMES_PER_RESULT_V1: u64 =
    MAX_SEGMENTS_PER_RESULT_V1 * MAX_FRAMES_PER_SEGMENT_V1 as u64;

/// Stable, contentless failure returned by the key-envelope primitive.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeyEnvelopeErrorV1 {
    InvalidEncodedLength,
    UnsupportedRecordVersion,
    InvalidRootKeyVersion,
    InvalidTimeRange,
    KeyContextMismatch,
    InvalidTotalFrameCount,
    InvalidSegmentCount,
    InvalidCountRelation,
    InvalidDecryptedDek,
    AuthenticationFailed,
}

impl KeyEnvelopeErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidEncodedLength => "EVIDENTRAIL_KEY_ENVELOPE_INVALID_ENCODED_LENGTH",
            Self::UnsupportedRecordVersion => "EVIDENTRAIL_KEY_ENVELOPE_UNSUPPORTED_RECORD_VERSION",
            Self::InvalidRootKeyVersion => "EVIDENTRAIL_KEY_ENVELOPE_INVALID_ROOT_KEY_VERSION",
            Self::InvalidTimeRange => "EVIDENTRAIL_KEY_ENVELOPE_INVALID_TIME_RANGE",
            Self::KeyContextMismatch => "EVIDENTRAIL_KEY_ENVELOPE_KEY_CONTEXT_MISMATCH",
            Self::InvalidTotalFrameCount => "EVIDENTRAIL_KEY_ENVELOPE_INVALID_TOTAL_FRAME_COUNT",
            Self::InvalidSegmentCount => "EVIDENTRAIL_KEY_ENVELOPE_INVALID_SEGMENT_COUNT",
            Self::InvalidCountRelation => "EVIDENTRAIL_KEY_ENVELOPE_INVALID_COUNT_RELATION",
            Self::InvalidDecryptedDek => "EVIDENTRAIL_KEY_ENVELOPE_INVALID_DECRYPTED_DEK",
            Self::AuthenticationFailed => "EVIDENTRAIL_KEY_ENVELOPE_AUTHENTICATION_FAILED",
        }
    }
}

impl fmt::Debug for KeyEnvelopeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyEnvelopeErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for KeyEnvelopeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for KeyEnvelopeErrorV1 {}

/// Canonical result-key record context authenticated by both envelope kinds.
///
/// Encoding is exactly `record_version:u16 || root_key_version:u32 ||
/// result_id[32] || created_unix_nanos:i64 || expires_unix_nanos:i64`, with all
/// integers unsigned/signed big-endian as declared.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeyEnvelopeContextV1 {
    root_key_version: RootKeyVersionV1,
    result_id: ResultId,
    created_unix_nanos: i64,
    expires_unix_nanos: i64,
}

impl KeyEnvelopeContextV1 {
    pub fn new(
        root_key_version: RootKeyVersionV1,
        result_id: ResultId,
        created_unix_nanos: i64,
        expires_unix_nanos: i64,
    ) -> Result<Self, KeyEnvelopeErrorV1> {
        if expires_unix_nanos <= created_unix_nanos {
            return Err(KeyEnvelopeErrorV1::InvalidTimeRange);
        }
        Ok(Self {
            root_key_version,
            result_id,
            created_unix_nanos,
            expires_unix_nanos,
        })
    }

    #[must_use]
    pub const fn record_version(&self) -> u16 {
        KEY_RECORD_VERSION_V1
    }

    #[must_use]
    pub const fn root_key_version(&self) -> RootKeyVersionV1 {
        self.root_key_version
    }

    #[must_use]
    pub const fn result_id(&self) -> ResultId {
        self.result_id
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
    pub fn encode(&self) -> [u8; KEY_ENVELOPE_CONTEXT_BYTES_V1] {
        let mut encoded = [0u8; KEY_ENVELOPE_CONTEXT_BYTES_V1];
        encoded[0..2].copy_from_slice(&KEY_RECORD_VERSION_V1.to_be_bytes());
        encoded[2..6].copy_from_slice(&self.root_key_version.canonical_bytes());
        encoded[6..38].copy_from_slice(self.result_id.as_bytes());
        encoded[38..46].copy_from_slice(&self.created_unix_nanos.to_be_bytes());
        encoded[46..54].copy_from_slice(&self.expires_unix_nanos.to_be_bytes());
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, KeyEnvelopeErrorV1> {
        if encoded.len() != KEY_ENVELOPE_CONTEXT_BYTES_V1 {
            return Err(KeyEnvelopeErrorV1::InvalidEncodedLength);
        }
        if read_u16(encoded, 0) != KEY_RECORD_VERSION_V1 {
            return Err(KeyEnvelopeErrorV1::UnsupportedRecordVersion);
        }
        let root_key_version = RootKeyVersionV1::new(read_u32(encoded, 2))
            .map_err(|_| KeyEnvelopeErrorV1::InvalidRootKeyVersion)?;
        Self::new(
            root_key_version,
            ResultId::from_bytes(read_array(encoded, 6)),
            read_i64(encoded, 38),
            read_i64(encoded, 46),
        )
    }
}

impl fmt::Debug for KeyEnvelopeContextV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyEnvelopeContextV1(<redacted>)")
    }
}

/// Exact AAD for the one result-DEK wrapping operation.
#[must_use]
pub fn canonical_dek_wrap_aad_v1(context: &KeyEnvelopeContextV1) -> [u8; DEK_WRAP_AAD_BYTES_V1] {
    prefixed_context::<DEK_WRAP_AAD_BYTES_V1>(DEK_WRAP_AAD_DOMAIN_V1, context)
}

/// Exact AAD for the one final seal-binding operation.
#[must_use]
pub fn canonical_seal_binding_aad_v1(
    context: &KeyEnvelopeContextV1,
) -> [u8; SEAL_BINDING_AAD_BYTES_V1] {
    prefixed_context::<SEAL_BINDING_AAD_BYTES_V1>(SEAL_BINDING_AAD_DOMAIN_V1, context)
}

/// Injected nonce for the one DEK-wrap object under a derived wrapping key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DekWrapNonceV1([u8; KEY_ENVELOPE_NONCE_BYTES_V1]);

impl DekWrapNonceV1 {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_ENVELOPE_NONCE_BYTES_V1]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_ENVELOPE_NONCE_BYTES_V1] {
        &self.0
    }
}

impl fmt::Debug for DekWrapNonceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DekWrapNonceV1(<redacted>)")
    }
}

/// Injected nonce for the one seal-binding object under a derived seal key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SealBindingNonceV1([u8; KEY_ENVELOPE_NONCE_BYTES_V1]);

impl SealBindingNonceV1 {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_ENVELOPE_NONCE_BYTES_V1]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_ENVELOPE_NONCE_BYTES_V1] {
        &self.0
    }
}

impl fmt::Debug for SealBindingNonceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SealBindingNonceV1(<redacted>)")
    }
}

/// Fixed-size ciphertext envelope for one 32-byte result DEK.
#[derive(PartialEq, Eq)]
pub struct WrappedResultDekV1 {
    nonce: DekWrapNonceV1,
    ciphertext: [u8; DERIVED_KEY_BYTES_V1],
    tag: [u8; KEY_ENVELOPE_TAG_BYTES_V1],
}

impl WrappedResultDekV1 {
    #[must_use]
    pub const fn nonce(&self) -> DekWrapNonceV1 {
        self.nonce
    }

    #[must_use]
    pub fn encode(&self) -> [u8; WRAPPED_RESULT_DEK_BYTES_V1] {
        let mut encoded = [0u8; WRAPPED_RESULT_DEK_BYTES_V1];
        encoded[..KEY_ENVELOPE_NONCE_BYTES_V1].copy_from_slice(self.nonce.as_bytes());
        let ciphertext_end = KEY_ENVELOPE_NONCE_BYTES_V1 + DERIVED_KEY_BYTES_V1;
        encoded[KEY_ENVELOPE_NONCE_BYTES_V1..ciphertext_end].copy_from_slice(&self.ciphertext);
        encoded[ciphertext_end..].copy_from_slice(&self.tag);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, KeyEnvelopeErrorV1> {
        if encoded.len() != WRAPPED_RESULT_DEK_BYTES_V1 {
            return Err(KeyEnvelopeErrorV1::InvalidEncodedLength);
        }
        let ciphertext_end = KEY_ENVELOPE_NONCE_BYTES_V1 + DERIVED_KEY_BYTES_V1;
        Ok(Self {
            nonce: DekWrapNonceV1::from_bytes(read_array(encoded, 0)),
            ciphertext: read_array(encoded, KEY_ENVELOPE_NONCE_BYTES_V1),
            tag: read_array(encoded, ciphertext_end),
        })
    }
}

impl fmt::Debug for WrappedResultDekV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WrappedResultDekV1")
            .field("ciphertext_bytes", &DERIVED_KEY_BYTES_V1)
            .field("tag_bytes", &KEY_ENVELOPE_TAG_BYTES_V1)
            .finish()
    }
}

/// Wrap exactly one already-generated result DEK with injected context/nonce.
///
/// This pure primitive cannot enforce provider lifecycle or a second call with
/// the same derived key. The future provider must authorize exactly one wrap
/// object for each result record.
pub fn wrap_result_dek_v1(
    key: &DekWrapKeyViewV1<'_>,
    context: &KeyEnvelopeContextV1,
    nonce: DekWrapNonceV1,
    dek: &ResultDekV1,
) -> Result<WrappedResultDekV1, KeyEnvelopeErrorV1> {
    validate_key_context(key.result_id(), key.root_key_version(), context)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| KeyEnvelopeErrorV1::AuthenticationFailed)?;
    let nonce_bytes = XNonce::from(*nonce.as_bytes());
    let aad = canonical_dek_wrap_aad_v1(context);
    let mut ciphertext = Zeroizing::new([0u8; DERIVED_KEY_BYTES_V1]);
    ciphertext.copy_from_slice(dek.as_bytes());
    let tag = cipher
        .encrypt_inout_detached(&nonce_bytes, &aad, (&mut ciphertext[..]).into())
        .map_err(|_| KeyEnvelopeErrorV1::AuthenticationFailed)?;
    Ok(WrappedResultDekV1 {
        nonce,
        ciphertext: *ciphertext,
        tag: tag.into(),
    })
}

/// Authenticate and open a wrapped DEK under the exact expected context.
pub fn open_wrapped_result_dek_v1(
    key: &DekWrapKeyViewV1<'_>,
    expected_context: &KeyEnvelopeContextV1,
    wrapped: &WrappedResultDekV1,
) -> Result<ResultDekV1, KeyEnvelopeErrorV1> {
    validate_key_context(key.result_id(), key.root_key_version(), expected_context)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| KeyEnvelopeErrorV1::AuthenticationFailed)?;
    let nonce = XNonce::from(*wrapped.nonce.as_bytes());
    let aad = canonical_dek_wrap_aad_v1(expected_context);
    let tag = Tag::from(wrapped.tag);
    let mut plaintext = Zeroizing::new(wrapped.ciphertext);
    cipher
        .decrypt_inout_detached(&nonce, &aad, (&mut plaintext[..]).into(), &tag)
        .map_err(|_| KeyEnvelopeErrorV1::AuthenticationFailed)?;
    ResultDekV1::from_zeroizing(plaintext).map_err(|_| KeyEnvelopeErrorV1::InvalidDecryptedDek)
}

/// Canonical final manifest/chain facts protected by the distinct seal key.
#[derive(PartialEq, Eq)]
pub struct SealBindingV1 {
    manifest_commitment: ManifestCommitmentV1,
    final_frame_commitment: FrameCommitmentV1,
    total_frame_count: u64,
    segment_count: u64,
}

impl SealBindingV1 {
    pub fn new(
        manifest_commitment: ManifestCommitmentV1,
        final_frame_commitment: FrameCommitmentV1,
        total_frame_count: u64,
        segment_count: u64,
    ) -> Result<Self, KeyEnvelopeErrorV1> {
        validate_seal_counts(total_frame_count, segment_count)?;
        Ok(Self {
            manifest_commitment,
            final_frame_commitment,
            total_frame_count,
            segment_count,
        })
    }

    #[must_use]
    pub const fn manifest_commitment(&self) -> ManifestCommitmentV1 {
        self.manifest_commitment
    }

    #[must_use]
    pub const fn final_frame_commitment(&self) -> FrameCommitmentV1 {
        self.final_frame_commitment
    }

    #[must_use]
    pub const fn total_frame_count(&self) -> u64 {
        self.total_frame_count
    }

    #[must_use]
    pub const fn segment_count(&self) -> u64 {
        self.segment_count
    }

    #[must_use]
    pub fn encode(&self) -> [u8; SEAL_BINDING_BYTES_V1] {
        let mut encoded = [0u8; SEAL_BINDING_BYTES_V1];
        encoded[0..32].copy_from_slice(self.manifest_commitment.as_bytes());
        encoded[32..64].copy_from_slice(self.final_frame_commitment.as_bytes());
        encoded[64..72].copy_from_slice(&self.total_frame_count.to_be_bytes());
        encoded[72..80].copy_from_slice(&self.segment_count.to_be_bytes());
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, KeyEnvelopeErrorV1> {
        if encoded.len() != SEAL_BINDING_BYTES_V1 {
            return Err(KeyEnvelopeErrorV1::InvalidEncodedLength);
        }
        Self::new(
            ManifestCommitmentV1::from_bytes(read_array(encoded, 0)),
            FrameCommitmentV1::from_bytes(read_array(encoded, 32)),
            read_u64(encoded, 64),
            read_u64(encoded, 72),
        )
    }
}

impl fmt::Debug for SealBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SealBindingV1(<redacted>)")
    }
}

/// Fixed-size ciphertext envelope for one final seal binding.
#[derive(PartialEq, Eq)]
pub struct SealedSealBindingV1 {
    nonce: SealBindingNonceV1,
    ciphertext: [u8; SEAL_BINDING_BYTES_V1],
    tag: [u8; KEY_ENVELOPE_TAG_BYTES_V1],
}

impl SealedSealBindingV1 {
    #[must_use]
    pub const fn nonce(&self) -> SealBindingNonceV1 {
        self.nonce
    }

    #[must_use]
    pub fn encode(&self) -> [u8; SEALED_SEAL_BINDING_BYTES_V1] {
        let mut encoded = [0u8; SEALED_SEAL_BINDING_BYTES_V1];
        encoded[..KEY_ENVELOPE_NONCE_BYTES_V1].copy_from_slice(self.nonce.as_bytes());
        let ciphertext_end = KEY_ENVELOPE_NONCE_BYTES_V1 + SEAL_BINDING_BYTES_V1;
        encoded[KEY_ENVELOPE_NONCE_BYTES_V1..ciphertext_end].copy_from_slice(&self.ciphertext);
        encoded[ciphertext_end..].copy_from_slice(&self.tag);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, KeyEnvelopeErrorV1> {
        if encoded.len() != SEALED_SEAL_BINDING_BYTES_V1 {
            return Err(KeyEnvelopeErrorV1::InvalidEncodedLength);
        }
        let ciphertext_end = KEY_ENVELOPE_NONCE_BYTES_V1 + SEAL_BINDING_BYTES_V1;
        Ok(Self {
            nonce: SealBindingNonceV1::from_bytes(read_array(encoded, 0)),
            ciphertext: read_array(encoded, KEY_ENVELOPE_NONCE_BYTES_V1),
            tag: read_array(encoded, ciphertext_end),
        })
    }
}

impl fmt::Debug for SealedSealBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedSealBindingV1")
            .field("ciphertext_bytes", &SEAL_BINDING_BYTES_V1)
            .field("tag_bytes", &KEY_ENVELOPE_TAG_BYTES_V1)
            .finish()
    }
}

/// Authenticated seal-binding plaintext retained in a zeroizing fixed buffer.
///
/// Only typed fields are exposed; there is no generic plaintext-byte export.
pub struct OpenedSealBindingV1(Zeroizing<[u8; SEAL_BINDING_BYTES_V1]>);

impl OpenedSealBindingV1 {
    #[must_use]
    pub fn manifest_commitment(&self) -> ManifestCommitmentV1 {
        ManifestCommitmentV1::from_bytes(read_array(&self.0[..], 0))
    }

    #[must_use]
    pub fn final_frame_commitment(&self) -> FrameCommitmentV1 {
        FrameCommitmentV1::from_bytes(read_array(&self.0[..], 32))
    }

    #[must_use]
    pub fn total_frame_count(&self) -> u64 {
        read_u64(&self.0[..], 64)
    }

    #[must_use]
    pub fn segment_count(&self) -> u64 {
        read_u64(&self.0[..], 72)
    }
}

impl fmt::Debug for OpenedSealBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenedSealBindingV1(<redacted>)")
    }
}

/// Encrypt one checked final seal binding with injected context/nonce.
///
/// The future provider owns the exactly-once `Creating -> Sealed` transition;
/// this pure primitive performs no state transition or nonce generation.
pub fn seal_binding_v1(
    key: &SealKeyViewV1<'_>,
    context: &KeyEnvelopeContextV1,
    nonce: SealBindingNonceV1,
    binding: &SealBindingV1,
) -> Result<SealedSealBindingV1, KeyEnvelopeErrorV1> {
    validate_key_context(key.result_id(), key.root_key_version(), context)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| KeyEnvelopeErrorV1::AuthenticationFailed)?;
    let nonce_bytes = XNonce::from(*nonce.as_bytes());
    let aad = canonical_seal_binding_aad_v1(context);
    let mut ciphertext = Zeroizing::new(binding.encode());
    let tag = cipher
        .encrypt_inout_detached(&nonce_bytes, &aad, (&mut ciphertext[..]).into())
        .map_err(|_| KeyEnvelopeErrorV1::AuthenticationFailed)?;
    Ok(SealedSealBindingV1 {
        nonce,
        ciphertext: *ciphertext,
        tag: tag.into(),
    })
}

/// Authenticate and open the final binding under the exact expected context.
pub fn open_seal_binding_v1(
    key: &SealKeyViewV1<'_>,
    expected_context: &KeyEnvelopeContextV1,
    sealed: &SealedSealBindingV1,
) -> Result<OpenedSealBindingV1, KeyEnvelopeErrorV1> {
    validate_key_context(key.result_id(), key.root_key_version(), expected_context)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| KeyEnvelopeErrorV1::AuthenticationFailed)?;
    let nonce = XNonce::from(*sealed.nonce.as_bytes());
    let aad = canonical_seal_binding_aad_v1(expected_context);
    let tag = Tag::from(sealed.tag);
    let mut plaintext = Zeroizing::new(sealed.ciphertext);
    cipher
        .decrypt_inout_detached(&nonce, &aad, (&mut plaintext[..]).into(), &tag)
        .map_err(|_| KeyEnvelopeErrorV1::AuthenticationFailed)?;
    SealBindingV1::decode(&plaintext[..])?;
    Ok(OpenedSealBindingV1(plaintext))
}

fn validate_seal_counts(
    total_frame_count: u64,
    segment_count: u64,
) -> Result<(), KeyEnvelopeErrorV1> {
    if total_frame_count == 0 || total_frame_count > MAX_TOTAL_FRAMES_PER_RESULT_V1 {
        return Err(KeyEnvelopeErrorV1::InvalidTotalFrameCount);
    }
    if segment_count == 0 || segment_count > MAX_SEGMENTS_PER_RESULT_V1 {
        return Err(KeyEnvelopeErrorV1::InvalidSegmentCount);
    }
    let capacity = segment_count
        .checked_mul(u64::from(MAX_FRAMES_PER_SEGMENT_V1))
        .ok_or(KeyEnvelopeErrorV1::InvalidCountRelation)?;
    if segment_count > total_frame_count || total_frame_count > capacity {
        return Err(KeyEnvelopeErrorV1::InvalidCountRelation);
    }
    Ok(())
}

fn validate_key_context(
    result_id: ResultId,
    root_key_version: RootKeyVersionV1,
    context: &KeyEnvelopeContextV1,
) -> Result<(), KeyEnvelopeErrorV1> {
    if result_id != context.result_id() || root_key_version != context.root_key_version() {
        return Err(KeyEnvelopeErrorV1::KeyContextMismatch);
    }
    Ok(())
}

fn prefixed_context<const N: usize>(domain: &[u8], context: &KeyEnvelopeContextV1) -> [u8; N] {
    let mut aad = [0u8; N];
    aad[..domain.len()].copy_from_slice(domain);
    aad[domain.len()..].copy_from_slice(&context.encode());
    aad
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

const _: () = assert!(KEY_ENVELOPE_NONCE_BYTES_V1 == 24);
