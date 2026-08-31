use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::ResultId;

use crate::{
    DekWrapKeyViewV1, KEY_RECORD_VERSION_V1, KeyEnvelopeContextV1, KeyEnvelopeErrorV1,
    OpenedSealBindingV1, ResultDekV1, RootKeyVersionV1, SEALED_SEAL_BINDING_BYTES_V1,
    SealKeyViewV1, SealedSealBindingV1, WRAPPED_RESULT_DEK_BYTES_V1, WrappedResultDekV1,
    XCHACHA20_POLY1305_SUITE_ID_V1, open_seal_binding_v1, open_wrapped_result_dek_v1,
};

pub const RESULT_KEY_RECORD_BYTES_V1: usize = 280;
pub const RESULT_KEY_RECORD_CREATING_STATE_V1: u16 = 1;
pub const RESULT_KEY_RECORD_SEALED_STATE_V1: u16 = 2;

const RESULT_KEY_RECORD_MAGIC_V1: [u8; 8] = *b"EVRKEY01";
const WRAPPED_RESULT_DEK_LENGTH_FIELD_V1: u16 = WRAPPED_RESULT_DEK_BYTES_V1 as u16;
const SEALED_BINDING_LENGTH_FIELD_V1: u16 = SEALED_SEAL_BINDING_BYTES_V1 as u16;
const WRAPPED_DEK_OFFSET_V1: usize = 72;
const WRAPPED_DEK_END_V1: usize = WRAPPED_DEK_OFFSET_V1 + WRAPPED_RESULT_DEK_BYTES_V1;
const SEALED_BINDING_OFFSET_V1: usize = WRAPPED_DEK_END_V1;
const SEALED_BINDING_END_V1: usize = SEALED_BINDING_OFFSET_V1 + SEALED_SEAL_BINDING_BYTES_V1;
const TRAILING_RESERVED_OFFSET_V1: usize = SEALED_BINDING_END_V1;

/// Stable, contentless failure returned by the outer result-key record codec.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ResultKeyRecordErrorV1 {
    InvalidEncodedLength,
    InvalidMagic,
    UnsupportedRecordVersion,
    UnsupportedSuite,
    InvalidRootKeyVersion,
    InvalidTimeRange,
    ContextMismatch,
    InvalidWrappedDekLength,
    UnknownState,
    InvalidSealedBindingLength,
    NonzeroReserved,
    NoncanonicalCreatingLayout,
    NoncanonicalSealedLayout,
    WrappedDekAuthenticationFailed,
    SealedBindingAuthenticationFailed,
    DifferentSecondSeal,
}

impl ResultKeyRecordErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidEncodedLength => "EVIDENTRAIL_RESULT_KEY_RECORD_INVALID_ENCODED_LENGTH",
            Self::InvalidMagic => "EVIDENTRAIL_RESULT_KEY_RECORD_INVALID_MAGIC",
            Self::UnsupportedRecordVersion => {
                "EVIDENTRAIL_RESULT_KEY_RECORD_UNSUPPORTED_RECORD_VERSION"
            }
            Self::UnsupportedSuite => "EVIDENTRAIL_RESULT_KEY_RECORD_UNSUPPORTED_SUITE",
            Self::InvalidRootKeyVersion => "EVIDENTRAIL_RESULT_KEY_RECORD_INVALID_ROOT_KEY_VERSION",
            Self::InvalidTimeRange => "EVIDENTRAIL_RESULT_KEY_RECORD_INVALID_TIME_RANGE",
            Self::ContextMismatch => "EVIDENTRAIL_RESULT_KEY_RECORD_CONTEXT_MISMATCH",
            Self::InvalidWrappedDekLength => {
                "EVIDENTRAIL_RESULT_KEY_RECORD_INVALID_WRAPPED_DEK_LENGTH"
            }
            Self::UnknownState => "EVIDENTRAIL_RESULT_KEY_RECORD_UNKNOWN_STATE",
            Self::InvalidSealedBindingLength => {
                "EVIDENTRAIL_RESULT_KEY_RECORD_INVALID_SEALED_BINDING_LENGTH"
            }
            Self::NonzeroReserved => "EVIDENTRAIL_RESULT_KEY_RECORD_NONZERO_RESERVED",
            Self::NoncanonicalCreatingLayout => {
                "EVIDENTRAIL_RESULT_KEY_RECORD_NONCANONICAL_CREATING_LAYOUT"
            }
            Self::NoncanonicalSealedLayout => {
                "EVIDENTRAIL_RESULT_KEY_RECORD_NONCANONICAL_SEALED_LAYOUT"
            }
            Self::WrappedDekAuthenticationFailed => {
                "EVIDENTRAIL_RESULT_KEY_RECORD_WRAPPED_DEK_AUTHENTICATION_FAILED"
            }
            Self::SealedBindingAuthenticationFailed => {
                "EVIDENTRAIL_RESULT_KEY_RECORD_SEALED_BINDING_AUTHENTICATION_FAILED"
            }
            Self::DifferentSecondSeal => "EVIDENTRAIL_RESULT_KEY_RECORD_DIFFERENT_SECOND_SEAL",
        }
    }
}

impl fmt::Debug for ResultKeyRecordErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResultKeyRecordErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for ResultKeyRecordErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ResultKeyRecordErrorV1 {}

/// Non-sensitive state discriminator for the outer key record.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ResultKeyRecordStateV1 {
    Creating,
    Sealed,
}

impl ResultKeyRecordStateV1 {
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Creating => RESULT_KEY_RECORD_CREATING_STATE_V1,
            Self::Sealed => RESULT_KEY_RECORD_SEALED_STATE_V1,
        }
    }
}

impl fmt::Debug for ResultKeyRecordStateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResultKeyRecordStateV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Explicit outcome of an attempted `Creating -> Sealed` transition.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ResultKeySealTransitionV1 {
    Applied,
    AlreadySealedSame,
}

impl ResultKeySealTransitionV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Applied => "EVIDENTRAIL_RESULT_KEY_SEAL_APPLIED",
            Self::AlreadySealedSame => "EVIDENTRAIL_RESULT_KEY_SEAL_ALREADY_SAME",
        }
    }
}

impl fmt::Debug for ResultKeySealTransitionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResultKeySealTransitionV1")
            .field("code", &self.code())
            .finish()
    }
}

enum ResultKeyRecordStateDataV1 {
    Creating,
    Sealed(SealedSealBindingV1),
}

/// Fixed-width canonical outer record intended for a future key provider.
///
/// This value owns only ciphertext and context metadata. It does not implement
/// `Clone`, perform provider operations, or claim that its bytes were persisted
/// or externally authenticated.
pub struct ResultKeyRecordV1 {
    context: KeyEnvelopeContextV1,
    wrapped_dek: WrappedResultDekV1,
    state: ResultKeyRecordStateDataV1,
}

impl ResultKeyRecordV1 {
    /// Construct a Creating record after authenticating the supplied wrapped
    /// DEK under the same result/version/time context.
    pub fn new_creating(
        context: KeyEnvelopeContextV1,
        wrap_key: &DekWrapKeyViewV1<'_>,
        wrapped_dek: WrappedResultDekV1,
    ) -> Result<Self, ResultKeyRecordErrorV1> {
        let opened = open_wrapped_result_dek_v1(wrap_key, &context, &wrapped_dek)
            .map_err(map_wrapped_dek_error)?;
        drop(opened);
        Ok(Self {
            context,
            wrapped_dek,
            state: ResultKeyRecordStateDataV1::Creating,
        })
    }

    #[must_use]
    pub const fn context(&self) -> &KeyEnvelopeContextV1 {
        &self.context
    }

    #[must_use]
    pub const fn state(&self) -> ResultKeyRecordStateV1 {
        match &self.state {
            ResultKeyRecordStateDataV1::Creating => ResultKeyRecordStateV1::Creating,
            ResultKeyRecordStateDataV1::Sealed(_) => ResultKeyRecordStateV1::Sealed,
        }
    }

    #[must_use]
    pub const fn wrapped_dek(&self) -> &WrappedResultDekV1 {
        &self.wrapped_dek
    }

    #[must_use]
    pub const fn sealed_binding(&self) -> Option<&SealedSealBindingV1> {
        match &self.state {
            ResultKeyRecordStateDataV1::Creating => None,
            ResultKeyRecordStateDataV1::Sealed(sealed) => Some(sealed),
        }
    }

    /// Open the immutable wrapped DEK under this record's exact context.
    pub fn open_result_dek(
        &self,
        wrap_key: &DekWrapKeyViewV1<'_>,
    ) -> Result<ResultDekV1, ResultKeyRecordErrorV1> {
        open_wrapped_result_dek_v1(wrap_key, &self.context, &self.wrapped_dek)
            .map_err(map_wrapped_dek_error)
    }

    /// Open the final seal binding when this record is sealed.
    pub fn open_sealed_binding(
        &self,
        seal_key: &SealKeyViewV1<'_>,
    ) -> Result<Option<OpenedSealBindingV1>, ResultKeyRecordErrorV1> {
        match &self.state {
            ResultKeyRecordStateDataV1::Creating => Ok(None),
            ResultKeyRecordStateDataV1::Sealed(sealed) => {
                open_seal_binding_v1(seal_key, &self.context, sealed)
                    .map(Some)
                    .map_err(map_sealed_binding_error)
            }
        }
    }

    /// Apply the only permitted state transition.
    ///
    /// Repeating the byte-identical, authenticated seal is explicitly
    /// idempotent and returns `AlreadySealedSame`. Any different second seal is
    /// rejected without modifying this record.
    pub fn transition_to_sealed(
        &mut self,
        wrap_key: &DekWrapKeyViewV1<'_>,
        seal_key: &SealKeyViewV1<'_>,
        candidate: SealedSealBindingV1,
    ) -> Result<ResultKeySealTransitionV1, ResultKeyRecordErrorV1> {
        // A structurally decoded Creating record may still carry tampered
        // ciphertext. Never publish a seal over an unusable immutable DEK.
        let opened_dek = open_wrapped_result_dek_v1(wrap_key, &self.context, &self.wrapped_dek)
            .map_err(map_wrapped_dek_error)?;
        drop(opened_dek);
        let opened = open_seal_binding_v1(seal_key, &self.context, &candidate)
            .map_err(map_sealed_binding_error)?;
        drop(opened);

        match &self.state {
            ResultKeyRecordStateDataV1::Creating => {
                self.state = ResultKeyRecordStateDataV1::Sealed(candidate);
                Ok(ResultKeySealTransitionV1::Applied)
            }
            ResultKeyRecordStateDataV1::Sealed(existing) if existing == &candidate => {
                Ok(ResultKeySealTransitionV1::AlreadySealedSame)
            }
            ResultKeyRecordStateDataV1::Sealed(_) => {
                Err(ResultKeyRecordErrorV1::DifferentSecondSeal)
            }
        }
    }

    /// Exact fixed-width big-endian outer record encoding.
    #[must_use]
    pub fn encode(&self) -> [u8; RESULT_KEY_RECORD_BYTES_V1] {
        let mut encoded = [0u8; RESULT_KEY_RECORD_BYTES_V1];
        encoded[0..8].copy_from_slice(&RESULT_KEY_RECORD_MAGIC_V1);
        encoded[8..10].copy_from_slice(&KEY_RECORD_VERSION_V1.to_be_bytes());
        encoded[10..12].copy_from_slice(&XCHACHA20_POLY1305_SUITE_ID_V1.to_be_bytes());
        encoded[12..16].copy_from_slice(&self.context.root_key_version().canonical_bytes());
        encoded[16..48].copy_from_slice(self.context.result_id().as_bytes());
        encoded[48..56].copy_from_slice(&self.context.created_unix_nanos().to_be_bytes());
        encoded[56..64].copy_from_slice(&self.context.expires_unix_nanos().to_be_bytes());
        encoded[64..66].copy_from_slice(&WRAPPED_RESULT_DEK_LENGTH_FIELD_V1.to_be_bytes());
        encoded[66..68].copy_from_slice(&self.state().code().to_be_bytes());
        encoded[WRAPPED_DEK_OFFSET_V1..WRAPPED_DEK_END_V1]
            .copy_from_slice(&self.wrapped_dek.encode());
        if let ResultKeyRecordStateDataV1::Sealed(sealed) = &self.state {
            encoded[68..70].copy_from_slice(&SEALED_BINDING_LENGTH_FIELD_V1.to_be_bytes());
            encoded[SEALED_BINDING_OFFSET_V1..SEALED_BINDING_END_V1]
                .copy_from_slice(&sealed.encode());
        }
        encoded
    }

    /// Decode only under the caller's exact expected context. All fixed fields,
    /// lengths, state-specific padding, and reserved bytes are validated before
    /// the future provider needs to derive a key or invoke AEAD.
    pub fn decode(
        expected_context: &KeyEnvelopeContextV1,
        encoded: &[u8],
    ) -> Result<Self, ResultKeyRecordErrorV1> {
        if encoded.len() != RESULT_KEY_RECORD_BYTES_V1 {
            return Err(ResultKeyRecordErrorV1::InvalidEncodedLength);
        }
        if encoded[0..8] != RESULT_KEY_RECORD_MAGIC_V1 {
            return Err(ResultKeyRecordErrorV1::InvalidMagic);
        }
        if read_u16(encoded, 8) != KEY_RECORD_VERSION_V1 {
            return Err(ResultKeyRecordErrorV1::UnsupportedRecordVersion);
        }
        if read_u16(encoded, 10) != XCHACHA20_POLY1305_SUITE_ID_V1 {
            return Err(ResultKeyRecordErrorV1::UnsupportedSuite);
        }
        if encoded[70..WRAPPED_DEK_OFFSET_V1]
            .iter()
            .chain(encoded[TRAILING_RESERVED_OFFSET_V1..].iter())
            .any(|byte| *byte != 0)
        {
            return Err(ResultKeyRecordErrorV1::NonzeroReserved);
        }

        let root_key_version = RootKeyVersionV1::new(read_u32(encoded, 12))
            .map_err(|_| ResultKeyRecordErrorV1::InvalidRootKeyVersion)?;
        let context = KeyEnvelopeContextV1::new(
            root_key_version,
            ResultId::from_bytes(read_array(encoded, 16)),
            read_i64(encoded, 48),
            read_i64(encoded, 56),
        )
        .map_err(|_| ResultKeyRecordErrorV1::InvalidTimeRange)?;
        if context != *expected_context {
            return Err(ResultKeyRecordErrorV1::ContextMismatch);
        }
        if usize::from(read_u16(encoded, 64)) != WRAPPED_RESULT_DEK_BYTES_V1 {
            return Err(ResultKeyRecordErrorV1::InvalidWrappedDekLength);
        }
        let wrapped_dek =
            WrappedResultDekV1::decode(&encoded[WRAPPED_DEK_OFFSET_V1..WRAPPED_DEK_END_V1])
                .map_err(|_| ResultKeyRecordErrorV1::InvalidWrappedDekLength)?;

        let sealed_length = usize::from(read_u16(encoded, 68));
        let sealed_bytes = &encoded[SEALED_BINDING_OFFSET_V1..SEALED_BINDING_END_V1];
        let state = match read_u16(encoded, 66) {
            RESULT_KEY_RECORD_CREATING_STATE_V1 => {
                if sealed_length != 0 || sealed_bytes.iter().any(|byte| *byte != 0) {
                    return Err(ResultKeyRecordErrorV1::NoncanonicalCreatingLayout);
                }
                ResultKeyRecordStateDataV1::Creating
            }
            RESULT_KEY_RECORD_SEALED_STATE_V1 => {
                if sealed_length != SEALED_SEAL_BINDING_BYTES_V1 {
                    return Err(ResultKeyRecordErrorV1::InvalidSealedBindingLength);
                }
                if sealed_bytes.iter().all(|byte| *byte == 0) {
                    return Err(ResultKeyRecordErrorV1::NoncanonicalSealedLayout);
                }
                let sealed = SealedSealBindingV1::decode(sealed_bytes)
                    .map_err(|_| ResultKeyRecordErrorV1::InvalidSealedBindingLength)?;
                ResultKeyRecordStateDataV1::Sealed(sealed)
            }
            _ => return Err(ResultKeyRecordErrorV1::UnknownState),
        };

        Ok(Self {
            context,
            wrapped_dek,
            state,
        })
    }
}

impl fmt::Debug for ResultKeyRecordV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResultKeyRecordV1")
            .field("state", &self.state())
            .field("encoded_bytes", &RESULT_KEY_RECORD_BYTES_V1)
            .finish()
    }
}

fn map_wrapped_dek_error(error: KeyEnvelopeErrorV1) -> ResultKeyRecordErrorV1 {
    match error {
        KeyEnvelopeErrorV1::KeyContextMismatch => ResultKeyRecordErrorV1::ContextMismatch,
        _ => ResultKeyRecordErrorV1::WrappedDekAuthenticationFailed,
    }
}

fn map_sealed_binding_error(error: KeyEnvelopeErrorV1) -> ResultKeyRecordErrorV1 {
    match error {
        KeyEnvelopeErrorV1::KeyContextMismatch => ResultKeyRecordErrorV1::ContextMismatch,
        _ => ResultKeyRecordErrorV1::SealedBindingAuthenticationFailed,
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(read_array(bytes, offset))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(read_array(bytes, offset))
}

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_be_bytes(read_array(bytes, offset))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut output = [0u8; N];
    output.copy_from_slice(&bytes[offset..offset + N]);
    output
}

const _: () = assert!(WRAPPED_DEK_END_V1 == SEALED_BINDING_OFFSET_V1);
const _: () = assert!(SEALED_BINDING_END_V1 == TRAILING_RESERVED_OFFSET_V1);
const _: () = assert!(TRAILING_RESERVED_OFFSET_V1 + 16 == RESULT_KEY_RECORD_BYTES_V1);
const _: () = assert!(WRAPPED_RESULT_DEK_LENGTH_FIELD_V1 as usize == WRAPPED_RESULT_DEK_BYTES_V1);
const _: () = assert!(SEALED_BINDING_LENGTH_FIELD_V1 as usize == SEALED_SEAL_BINDING_BYTES_V1);
