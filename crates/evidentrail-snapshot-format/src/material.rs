use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::ResultId;
use zeroize::Zeroizing;

use crate::{FrameNonceV1, ManifestNonceV1, SnapshotFormatErrorV1};

pub const RESULT_DEK_BYTES_V1: usize = 32;

/// Contentless failure emitted by an injected entropy source.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EntropySourceFailureV1 {
    Unavailable,
}

impl EntropySourceFailureV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "EVIDENTRAIL_ENTROPY_SOURCE_UNAVAILABLE",
        }
    }
}

impl fmt::Debug for EntropySourceFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EntropySourceFailureV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for EntropySourceFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for EntropySourceFailureV1 {}

/// Injectable exact-fill entropy boundary used by crypto-material issuance.
pub trait EntropySourceV1 {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropySourceFailureV1>;
}

/// Operating-system entropy backed by pinned `getrandom`.
#[derive(Clone, Copy, Default)]
pub struct OsEntropyV1;

impl EntropySourceV1 for OsEntropyV1 {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropySourceFailureV1> {
        getrandom::fill(destination).map_err(|_| EntropySourceFailureV1::Unavailable)
    }
}

impl fmt::Debug for OsEntropyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OsEntropyV1")
    }
}

/// Sole retained owner of one per-result data-encryption key.
///
/// Frame and manifest operations can only borrow typed views; neither view owns
/// or copies the key. `Zeroizing` controls this selected allocation but cannot
/// erase caller copies, registers, swap, or compiler-created temporaries.
pub struct ResultDekV1(Zeroizing<[u8; RESULT_DEK_BYTES_V1]>);

impl ResultDekV1 {
    /// Take ownership of a zeroizing key buffer, suitable for a future key
    /// provider's authenticated unwrap result.
    pub fn from_zeroizing(
        bytes: Zeroizing<[u8; RESULT_DEK_BYTES_V1]>,
    ) -> Result<Self, SnapshotFormatErrorV1> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(SnapshotFormatErrorV1::AllZeroEntropyOutput);
        }
        Ok(Self(bytes))
    }

    /// Construct deterministic fixture material.
    ///
    /// The by-value input can leave stack/register copies and is not the future
    /// production unwrapping path.
    pub fn from_test_bytes(
        bytes: [u8; RESULT_DEK_BYTES_V1],
    ) -> Result<Self, SnapshotFormatErrorV1> {
        Self::from_zeroizing(Zeroizing::new(bytes))
    }

    #[must_use]
    pub fn frame_key(&self) -> FrameKeyViewV1<'_> {
        FrameKeyViewV1(&self.0)
    }

    #[must_use]
    pub fn manifest_key(&self) -> ManifestKeyViewV1<'_> {
        ManifestKeyViewV1(&self.0)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; RESULT_DEK_BYTES_V1] {
        &self.0
    }
}

impl fmt::Debug for ResultDekV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResultDekV1(<redacted>)")
    }
}

/// Non-owning frame-key view borrowed from one `ResultDekV1`.
pub struct FrameKeyViewV1<'a>(&'a [u8; RESULT_DEK_BYTES_V1]);

impl FrameKeyViewV1<'_> {
    pub(crate) const fn as_bytes(&self) -> &[u8; RESULT_DEK_BYTES_V1] {
        self.0
    }
}

impl fmt::Debug for FrameKeyViewV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrameKeyViewV1(<redacted>)")
    }
}

/// Non-owning manifest-key view borrowed from the same `ResultDekV1`.
pub struct ManifestKeyViewV1<'a>(&'a [u8; RESULT_DEK_BYTES_V1]);

impl ManifestKeyViewV1<'_> {
    pub(crate) const fn as_bytes(&self) -> &[u8; RESULT_DEK_BYTES_V1] {
        self.0
    }
}

impl fmt::Debug for ManifestKeyViewV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManifestKeyViewV1(<redacted>)")
    }
}

/// One result's entropy source and shared frame/manifest nonce registry.
struct ResultNonceCoordinatorV1<E> {
    entropy: E,
    result_id: ResultId,
    issued: BTreeSet<[u8; 24]>,
}

impl<E: EntropySourceV1> ResultNonceCoordinatorV1<E> {
    fn new(entropy: E, result_id: ResultId) -> Self {
        Self {
            entropy,
            result_id,
            issued: BTreeSet::new(),
        }
    }

    fn issue_bytes(&mut self) -> Result<[u8; 24], SnapshotFormatErrorV1> {
        let mut candidate = Zeroizing::new([0u8; 24]);
        self.entropy
            .fill_bytes(candidate.as_mut())
            .map_err(|_| SnapshotFormatErrorV1::EntropyUnavailable)?;
        if candidate.iter().all(|byte| *byte == 0) {
            return Err(SnapshotFormatErrorV1::AllZeroEntropyOutput);
        }
        let bytes = *candidate;
        if self.issued.contains(&bytes) {
            return Err(SnapshotFormatErrorV1::DuplicateNonce);
        }
        self.issued.insert(bytes);
        Ok(bytes)
    }

    const fn result_id(&self) -> ResultId {
        self.result_id
    }

    fn issued_count(&self) -> usize {
        self.issued.len()
    }
}

impl<E> fmt::Debug for ResultNonceCoordinatorV1<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResultNonceCoordinatorV1")
            .field("issued_nonce_count", &self.issued.len())
            .finish()
    }
}

/// Generated identity, sole DEK owner, and result-wide nonce authority.
///
/// Failed entropy, all-zero output, and nonce-reuse attempts do not mutate the
/// visible nonce registry. The injected entropy source may consume an attempted
/// draw, but no identity, key, or nonce is returned for a failed operation.
pub struct ResultCryptoMaterialV1<E> {
    dek: ResultDekV1,
    nonces: ResultNonceCoordinatorV1<E>,
}

impl<E: EntropySourceV1> ResultCryptoMaterialV1<E> {
    pub fn generate(mut entropy: E) -> Result<Self, SnapshotFormatErrorV1> {
        let mut result_bytes = Zeroizing::new([0u8; 32]);
        entropy
            .fill_bytes(result_bytes.as_mut())
            .map_err(|_| SnapshotFormatErrorV1::EntropyUnavailable)?;
        if result_bytes.iter().all(|byte| *byte == 0) {
            return Err(SnapshotFormatErrorV1::AllZeroEntropyOutput);
        }

        let mut dek_bytes = Zeroizing::new([0u8; RESULT_DEK_BYTES_V1]);
        entropy
            .fill_bytes(dek_bytes.as_mut())
            .map_err(|_| SnapshotFormatErrorV1::EntropyUnavailable)?;
        if dek_bytes.iter().all(|byte| *byte == 0) {
            return Err(SnapshotFormatErrorV1::AllZeroEntropyOutput);
        }
        if *result_bytes == *dek_bytes {
            return Err(SnapshotFormatErrorV1::RepeatedEntropyOutput);
        }

        let result_id = ResultId::from_bytes(*result_bytes);
        Ok(Self {
            dek: ResultDekV1::from_zeroizing(dek_bytes)?,
            nonces: ResultNonceCoordinatorV1::new(entropy, result_id),
        })
    }

    #[must_use]
    pub const fn result_id(&self) -> ResultId {
        self.nonces.result_id()
    }

    #[must_use]
    pub const fn dek(&self) -> &ResultDekV1 {
        &self.dek
    }

    #[must_use]
    pub fn issued_nonce_count(&self) -> usize {
        self.nonces.issued_count()
    }

    pub fn issue_frame_nonce(&mut self) -> Result<FrameNonceV1, SnapshotFormatErrorV1> {
        self.nonces.issue_bytes().map(FrameNonceV1::from_bytes)
    }

    pub fn issue_manifest_nonce(&mut self) -> Result<ManifestNonceV1, SnapshotFormatErrorV1> {
        self.nonces.issue_bytes().map(ManifestNonceV1::from_bytes)
    }
}

impl ResultCryptoMaterialV1<OsEntropyV1> {
    pub fn generate_os() -> Result<Self, SnapshotFormatErrorV1> {
        Self::generate(OsEntropyV1)
    }
}

impl<E> fmt::Debug for ResultCryptoMaterialV1<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResultCryptoMaterialV1")
            .field("issued_nonce_count", &self.nonces.issued.len())
            .finish()
    }
}
