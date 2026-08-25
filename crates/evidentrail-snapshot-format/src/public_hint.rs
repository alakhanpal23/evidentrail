use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::ResultId;

use crate::{RootKeyVersionV1, XCHACHA20_POLY1305_SUITE_ID_V1};

/// Exact byte width of the immutable `public.v1` cleanup hint.
pub const PUBLIC_CLEANUP_HINT_BYTES_V1: usize = 82;
/// Frozen V1 outer codec version for `public.v1`.
pub const PUBLIC_CLEANUP_HINT_VERSION_V1: u16 = 1;

const PUBLIC_CLEANUP_HINT_MAGIC_V1: [u8; 8] = *b"EVRPUB01";
const RESULT_ID_OFFSET_V1: usize = 14;
const RESULT_ID_END_V1: usize = 46;
const ROOT_KEY_VERSION_OFFSET_V1: usize = 46;
const CREATED_AT_OFFSET_V1: usize = 50;
const EXPIRES_AT_OFFSET_V1: usize = 58;
const RESERVED_OFFSET_V1: usize = 66;

/// Stable, contentless failure returned by the public cleanup-hint codec.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PublicCleanupHintErrorV1 {
    InvalidEncodedLength,
    InvalidMagic,
    UnsupportedVersion,
    UnsupportedSuite,
    InvalidResultId,
    InvalidRootKeyVersion,
    InvalidManifestPayloadSchemaVersion,
    InvalidTimeRange,
    NonzeroReserved,
}

impl PublicCleanupHintErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidEncodedLength => "EVIDENTRAIL_PUBLIC_HINT_INVALID_ENCODED_LENGTH",
            Self::InvalidMagic => "EVIDENTRAIL_PUBLIC_HINT_INVALID_MAGIC",
            Self::UnsupportedVersion => "EVIDENTRAIL_PUBLIC_HINT_UNSUPPORTED_VERSION",
            Self::UnsupportedSuite => "EVIDENTRAIL_PUBLIC_HINT_UNSUPPORTED_SUITE",
            Self::InvalidResultId => "EVIDENTRAIL_PUBLIC_HINT_INVALID_RESULT_ID",
            Self::InvalidRootKeyVersion => "EVIDENTRAIL_PUBLIC_HINT_INVALID_ROOT_KEY_VERSION",
            Self::InvalidManifestPayloadSchemaVersion => {
                "EVIDENTRAIL_PUBLIC_HINT_INVALID_MANIFEST_PAYLOAD_SCHEMA_VERSION"
            }
            Self::InvalidTimeRange => "EVIDENTRAIL_PUBLIC_HINT_INVALID_TIME_RANGE",
            Self::NonzeroReserved => "EVIDENTRAIL_PUBLIC_HINT_NONZERO_RESERVED",
        }
    }
}

impl fmt::Debug for PublicCleanupHintErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicCleanupHintErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for PublicCleanupHintErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for PublicCleanupHintErrorV1 {}

/// Immutable, unauthenticated `public.v1` cleanup hint from ADR 0004.
///
/// The format is exactly:
///
/// ```text
/// magic[8] | version:u16 | suite:u16 | manifest_payload_schema:u16 |
/// result_id[32] | root_key_version:u32 |
/// created_unix_nanos:i64 | expires_unix_nanos:i64 | reserved[16]=0
/// ```
///
/// All integers are big-endian. The random nature of a nonzero `ResultId`
/// remains the store's responsibility and cannot be proven by this parser.
/// These bytes are an untrusted C1 hint: they may trigger conservative earlier
/// cleanup, but cannot authorize an open, extend the expiry authenticated by a
/// result-key record, or establish any filesystem/durability fact. No source,
/// retrieval, path, question, event, content, or policy identity has a field.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicCleanupHintV1 {
    manifest_payload_schema_version: u16,
    result_id: ResultId,
    root_key_version: RootKeyVersionV1,
    created_unix_nanos: i64,
    expires_unix_nanos: i64,
}

impl PublicCleanupHintV1 {
    pub fn new(
        manifest_payload_schema_version: u16,
        result_id: ResultId,
        root_key_version: RootKeyVersionV1,
        created_unix_nanos: i64,
        expires_unix_nanos: i64,
    ) -> Result<Self, PublicCleanupHintErrorV1> {
        if manifest_payload_schema_version == 0 {
            return Err(PublicCleanupHintErrorV1::InvalidManifestPayloadSchemaVersion);
        }
        if result_id.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(PublicCleanupHintErrorV1::InvalidResultId);
        }
        if expires_unix_nanos <= created_unix_nanos {
            return Err(PublicCleanupHintErrorV1::InvalidTimeRange);
        }
        Ok(Self {
            manifest_payload_schema_version,
            result_id,
            root_key_version,
            created_unix_nanos,
            expires_unix_nanos,
        })
    }

    #[must_use]
    pub const fn version(&self) -> u16 {
        PUBLIC_CLEANUP_HINT_VERSION_V1
    }

    #[must_use]
    pub const fn suite_id(&self) -> u16 {
        XCHACHA20_POLY1305_SUITE_ID_V1
    }

    #[must_use]
    pub const fn manifest_payload_schema_version(&self) -> u16 {
        self.manifest_payload_schema_version
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

    /// Encode the exact fixed-width big-endian `public.v1` object.
    #[must_use]
    pub fn encode(&self) -> [u8; PUBLIC_CLEANUP_HINT_BYTES_V1] {
        let mut encoded = [0u8; PUBLIC_CLEANUP_HINT_BYTES_V1];
        encoded[0..8].copy_from_slice(&PUBLIC_CLEANUP_HINT_MAGIC_V1);
        encoded[8..10].copy_from_slice(&PUBLIC_CLEANUP_HINT_VERSION_V1.to_be_bytes());
        encoded[10..12].copy_from_slice(&XCHACHA20_POLY1305_SUITE_ID_V1.to_be_bytes());
        encoded[12..14].copy_from_slice(&self.manifest_payload_schema_version.to_be_bytes());
        encoded[RESULT_ID_OFFSET_V1..RESULT_ID_END_V1].copy_from_slice(self.result_id.as_bytes());
        encoded[ROOT_KEY_VERSION_OFFSET_V1..CREATED_AT_OFFSET_V1]
            .copy_from_slice(&self.root_key_version.canonical_bytes());
        encoded[CREATED_AT_OFFSET_V1..EXPIRES_AT_OFFSET_V1]
            .copy_from_slice(&self.created_unix_nanos.to_be_bytes());
        encoded[EXPIRES_AT_OFFSET_V1..RESERVED_OFFSET_V1]
            .copy_from_slice(&self.expires_unix_nanos.to_be_bytes());
        encoded
    }

    /// Strictly decode one complete canonical `public.v1` object.
    pub fn decode(encoded: &[u8]) -> Result<Self, PublicCleanupHintErrorV1> {
        if encoded.len() != PUBLIC_CLEANUP_HINT_BYTES_V1 {
            return Err(PublicCleanupHintErrorV1::InvalidEncodedLength);
        }
        if encoded[0..8] != PUBLIC_CLEANUP_HINT_MAGIC_V1 {
            return Err(PublicCleanupHintErrorV1::InvalidMagic);
        }
        if read_u16(encoded, 8) != PUBLIC_CLEANUP_HINT_VERSION_V1 {
            return Err(PublicCleanupHintErrorV1::UnsupportedVersion);
        }
        if read_u16(encoded, 10) != XCHACHA20_POLY1305_SUITE_ID_V1 {
            return Err(PublicCleanupHintErrorV1::UnsupportedSuite);
        }
        if encoded[RESERVED_OFFSET_V1..].iter().any(|byte| *byte != 0) {
            return Err(PublicCleanupHintErrorV1::NonzeroReserved);
        }
        let root_key_version = RootKeyVersionV1::new(read_u32(encoded, ROOT_KEY_VERSION_OFFSET_V1))
            .map_err(|_| PublicCleanupHintErrorV1::InvalidRootKeyVersion)?;
        Self::new(
            read_u16(encoded, 12),
            ResultId::from_bytes(read_array(encoded, RESULT_ID_OFFSET_V1)),
            root_key_version,
            read_i64(encoded, CREATED_AT_OFFSET_V1),
            read_i64(encoded, EXPIRES_AT_OFFSET_V1),
        )
    }
}

impl fmt::Debug for PublicCleanupHintV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublicCleanupHintV1(<redacted>)")
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

const _: () = assert!(RESULT_ID_END_V1 - RESULT_ID_OFFSET_V1 == 32);
const _: () = assert!(RESERVED_OFFSET_V1 + 16 == PUBLIC_CLEANUP_HINT_BYTES_V1);
