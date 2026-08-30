use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::ResultId;
use sha2::{Digest, Sha256};

use crate::{FrameCommitmentV1, LifecycleDigestV1, SnapshotObjectKindV2};

pub const DATA_MANIFEST_BYTES_V2: usize = 448;
pub const FINAL_MANIFEST_BYTES_V2: usize = 384;
pub const REPOSITORY_MANIFEST_VERSION_V2: u16 = 2;

const DATA_MAGIC_V2: [u8; 8] = *b"EVRDAT02";
const FINAL_MAGIC_V2: [u8; 8] = *b"EVRFIN02";
const DATA_DIGEST_DOMAIN_V2: &[u8] = b"evidentrail.snapshot.data-manifest.v2";
const FINAL_DIGEST_DOMAIN_V2: &[u8] = b"evidentrail.snapshot.final-manifest.v2";

/// Immutable acquisition boundary. Operational storage facts are deliberately
/// absent; all fields affect deterministic recompilation or exact expansion.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DataManifestV2 {
    result_id: ResultId,
    batch_count: u64,
    event_count: u64,
    request: LifecycleDigestV1,
    question_configuration: LifecycleDigestV1,
    batch_chain: LifecycleDigestV1,
    event_index: LifecycleDigestV1,
    acquisition_receipt: LifecycleDigestV1,
    transformation_receipts: LifecycleDigestV1,
    fetch_completion: LifecycleDigestV1,
    source_identity: LifecycleDigestV1,
    build_context: LifecycleDigestV1,
    frame_chain: FrameCommitmentV1,
}

impl DataManifestV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        result_id: ResultId,
        batch_count: u64,
        event_count: u64,
        request: LifecycleDigestV1,
        question_configuration: LifecycleDigestV1,
        batch_chain: LifecycleDigestV1,
        event_index: LifecycleDigestV1,
        acquisition_receipt: LifecycleDigestV1,
        transformation_receipts: LifecycleDigestV1,
        fetch_completion: LifecycleDigestV1,
        source_identity: LifecycleDigestV1,
        build_context: LifecycleDigestV1,
        frame_chain: FrameCommitmentV1,
    ) -> Result<Self, RepositoryManifestErrorV2> {
        if result_id.as_bytes().iter().all(|byte| *byte == 0)
            || (event_count > 0 && frame_chain == FrameCommitmentV1::ZERO)
        {
            return Err(RepositoryManifestErrorV2::NoncanonicalManifest);
        }
        Ok(Self {
            result_id,
            batch_count,
            event_count,
            request,
            question_configuration,
            batch_chain,
            event_index,
            acquisition_receipt,
            transformation_receipts,
            fetch_completion,
            source_identity,
            build_context,
            frame_chain,
        })
    }

    #[must_use]
    pub const fn result_id(self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn batch_count(self) -> u64 {
        self.batch_count
    }

    #[must_use]
    pub const fn event_count(self) -> u64 {
        self.event_count
    }

    #[must_use]
    pub const fn event_index(self) -> LifecycleDigestV1 {
        self.event_index
    }

    #[must_use]
    pub const fn request(self) -> LifecycleDigestV1 {
        self.request
    }

    #[must_use]
    pub const fn question_configuration(self) -> LifecycleDigestV1 {
        self.question_configuration
    }

    #[must_use]
    pub const fn batch_chain(self) -> LifecycleDigestV1 {
        self.batch_chain
    }

    #[must_use]
    pub const fn acquisition_receipt(self) -> LifecycleDigestV1 {
        self.acquisition_receipt
    }

    #[must_use]
    pub const fn transformation_receipts(self) -> LifecycleDigestV1 {
        self.transformation_receipts
    }

    #[must_use]
    pub const fn fetch_completion(self) -> LifecycleDigestV1 {
        self.fetch_completion
    }

    #[must_use]
    pub const fn source_identity(self) -> LifecycleDigestV1 {
        self.source_identity
    }

    #[must_use]
    pub const fn build_context(self) -> LifecycleDigestV1 {
        self.build_context
    }

    #[must_use]
    pub const fn frame_chain(self) -> FrameCommitmentV1 {
        self.frame_chain
    }

    #[must_use]
    pub fn encode(self) -> [u8; DATA_MANIFEST_BYTES_V2] {
        let mut encoded = [0u8; DATA_MANIFEST_BYTES_V2];
        encoded[0..8].copy_from_slice(&DATA_MAGIC_V2);
        encoded[8..10].copy_from_slice(&REPOSITORY_MANIFEST_VERSION_V2.to_be_bytes());
        encoded[10..12].copy_from_slice(&SnapshotObjectKindV2::DataManifest.code().to_be_bytes());
        encoded[16..48].copy_from_slice(self.result_id.as_bytes());
        encoded[48..56].copy_from_slice(&self.batch_count.to_be_bytes());
        encoded[56..64].copy_from_slice(&self.event_count.to_be_bytes());
        encoded[64..96].copy_from_slice(self.request.as_bytes());
        encoded[96..128].copy_from_slice(self.question_configuration.as_bytes());
        encoded[128..160].copy_from_slice(self.batch_chain.as_bytes());
        encoded[160..192].copy_from_slice(self.event_index.as_bytes());
        encoded[192..224].copy_from_slice(self.acquisition_receipt.as_bytes());
        encoded[224..256].copy_from_slice(self.transformation_receipts.as_bytes());
        encoded[256..288].copy_from_slice(self.fetch_completion.as_bytes());
        encoded[288..320].copy_from_slice(self.source_identity.as_bytes());
        encoded[320..352].copy_from_slice(self.build_context.as_bytes());
        encoded[352..384].copy_from_slice(self.frame_chain.as_bytes());
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, RepositoryManifestErrorV2> {
        if encoded.len() != DATA_MANIFEST_BYTES_V2 {
            return Err(RepositoryManifestErrorV2::InvalidEncodedLength);
        }
        if encoded[0..8] != DATA_MAGIC_V2 {
            return Err(RepositoryManifestErrorV2::InvalidMagic);
        }
        if read_u16(encoded, 8) != REPOSITORY_MANIFEST_VERSION_V2 {
            return Err(RepositoryManifestErrorV2::UnsupportedVersion);
        }
        if read_u16(encoded, 10) != SnapshotObjectKindV2::DataManifest.code() {
            return Err(RepositoryManifestErrorV2::UnsupportedObjectKind);
        }
        if encoded[12..16]
            .iter()
            .chain(encoded[384..].iter())
            .any(|byte| *byte != 0)
        {
            return Err(RepositoryManifestErrorV2::NonzeroReserved);
        }
        Self::new(
            ResultId::from_bytes(read_array(encoded, 16)),
            read_u64(encoded, 48),
            read_u64(encoded, 56),
            LifecycleDigestV1::from_bytes(read_array(encoded, 64)),
            LifecycleDigestV1::from_bytes(read_array(encoded, 96)),
            LifecycleDigestV1::from_bytes(read_array(encoded, 128)),
            LifecycleDigestV1::from_bytes(read_array(encoded, 160)),
            LifecycleDigestV1::from_bytes(read_array(encoded, 192)),
            LifecycleDigestV1::from_bytes(read_array(encoded, 224)),
            LifecycleDigestV1::from_bytes(read_array(encoded, 256)),
            LifecycleDigestV1::from_bytes(read_array(encoded, 288)),
            LifecycleDigestV1::from_bytes(read_array(encoded, 320)),
            FrameCommitmentV1::from_bytes(read_array(encoded, 352)),
        )
    }

    #[must_use]
    pub fn digest(self) -> LifecycleDigestV1 {
        derive_manifest_digest(DATA_DIGEST_DOMAIN_V2, &self.encode())
    }
}

impl fmt::Debug for DataManifestV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataManifestV2")
            .field("batch_count", &self.batch_count)
            .field("event_count", &self.event_count)
            .finish_non_exhaustive()
    }
}

/// Final immutable product boundary. This manifest is itself stored as an
/// authenticated frame; its digest is installed in external authority.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FinalManifestV2 {
    result_id: ResultId,
    data_manifest: LifecycleDigestV1,
    event_index: LifecycleDigestV1,
    frame_chain: FrameCommitmentV1,
    log_brief: LifecycleDigestV1,
    references: LifecycleDigestV1,
    presentation_receipt: LifecycleDigestV1,
    status: LifecycleDigestV1,
    alias_manifest: LifecycleDigestV1,
    product_frame_count: u64,
    event_count: u64,
}

impl FinalManifestV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        result_id: ResultId,
        data_manifest: LifecycleDigestV1,
        event_index: LifecycleDigestV1,
        frame_chain: FrameCommitmentV1,
        log_brief: LifecycleDigestV1,
        references: LifecycleDigestV1,
        presentation_receipt: LifecycleDigestV1,
        status: LifecycleDigestV1,
        alias_manifest: LifecycleDigestV1,
        product_frame_count: u64,
        event_count: u64,
    ) -> Result<Self, RepositoryManifestErrorV2> {
        if result_id.as_bytes().iter().all(|byte| *byte == 0)
            || product_frame_count == 0
            || (event_count > 0 && frame_chain == FrameCommitmentV1::ZERO)
        {
            return Err(RepositoryManifestErrorV2::NoncanonicalManifest);
        }
        Ok(Self {
            result_id,
            data_manifest,
            event_index,
            frame_chain,
            log_brief,
            references,
            presentation_receipt,
            status,
            alias_manifest,
            product_frame_count,
            event_count,
        })
    }

    #[must_use]
    pub const fn result_id(self) -> ResultId {
        self.result_id
    }

    #[must_use]
    pub const fn data_manifest(self) -> LifecycleDigestV1 {
        self.data_manifest
    }

    #[must_use]
    pub const fn event_index(self) -> LifecycleDigestV1 {
        self.event_index
    }

    #[must_use]
    pub const fn frame_chain(self) -> FrameCommitmentV1 {
        self.frame_chain
    }

    #[must_use]
    pub const fn product_digests(self) -> [LifecycleDigestV1; 5] {
        [
            self.log_brief,
            self.references,
            self.presentation_receipt,
            self.status,
            self.alias_manifest,
        ]
    }

    #[must_use]
    pub fn product_commitment(self) -> LifecycleDigestV1 {
        let mut hasher = Sha256::new();
        hasher.update(b"evidentrail.snapshot.products.v2");
        hasher.update(self.log_brief.as_bytes());
        hasher.update(self.references.as_bytes());
        hasher.update(self.presentation_receipt.as_bytes());
        hasher.update(self.status.as_bytes());
        hasher.update(self.alias_manifest.as_bytes());
        LifecycleDigestV1::from_bytes(hasher.finalize().into())
    }

    #[must_use]
    pub fn encode(self) -> [u8; FINAL_MANIFEST_BYTES_V2] {
        let mut encoded = [0u8; FINAL_MANIFEST_BYTES_V2];
        encoded[0..8].copy_from_slice(&FINAL_MAGIC_V2);
        encoded[8..10].copy_from_slice(&REPOSITORY_MANIFEST_VERSION_V2.to_be_bytes());
        encoded[10..12].copy_from_slice(&SnapshotObjectKindV2::FinalManifest.code().to_be_bytes());
        encoded[16..48].copy_from_slice(self.result_id.as_bytes());
        encoded[48..80].copy_from_slice(self.data_manifest.as_bytes());
        encoded[80..112].copy_from_slice(self.event_index.as_bytes());
        encoded[112..144].copy_from_slice(self.frame_chain.as_bytes());
        encoded[144..176].copy_from_slice(self.log_brief.as_bytes());
        encoded[176..208].copy_from_slice(self.references.as_bytes());
        encoded[208..240].copy_from_slice(self.presentation_receipt.as_bytes());
        encoded[240..272].copy_from_slice(self.status.as_bytes());
        encoded[272..304].copy_from_slice(self.alias_manifest.as_bytes());
        encoded[304..312].copy_from_slice(&self.product_frame_count.to_be_bytes());
        encoded[312..320].copy_from_slice(&self.event_count.to_be_bytes());
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, RepositoryManifestErrorV2> {
        if encoded.len() != FINAL_MANIFEST_BYTES_V2 {
            return Err(RepositoryManifestErrorV2::InvalidEncodedLength);
        }
        if encoded[0..8] != FINAL_MAGIC_V2 {
            return Err(RepositoryManifestErrorV2::InvalidMagic);
        }
        if read_u16(encoded, 8) != REPOSITORY_MANIFEST_VERSION_V2 {
            return Err(RepositoryManifestErrorV2::UnsupportedVersion);
        }
        if read_u16(encoded, 10) != SnapshotObjectKindV2::FinalManifest.code() {
            return Err(RepositoryManifestErrorV2::UnsupportedObjectKind);
        }
        if encoded[12..16]
            .iter()
            .chain(encoded[320..].iter())
            .any(|byte| *byte != 0)
        {
            return Err(RepositoryManifestErrorV2::NonzeroReserved);
        }
        Self::new(
            ResultId::from_bytes(read_array(encoded, 16)),
            LifecycleDigestV1::from_bytes(read_array(encoded, 48)),
            LifecycleDigestV1::from_bytes(read_array(encoded, 80)),
            FrameCommitmentV1::from_bytes(read_array(encoded, 112)),
            LifecycleDigestV1::from_bytes(read_array(encoded, 144)),
            LifecycleDigestV1::from_bytes(read_array(encoded, 176)),
            LifecycleDigestV1::from_bytes(read_array(encoded, 208)),
            LifecycleDigestV1::from_bytes(read_array(encoded, 240)),
            LifecycleDigestV1::from_bytes(read_array(encoded, 272)),
            read_u64(encoded, 304),
            read_u64(encoded, 312),
        )
    }

    #[must_use]
    pub fn digest(self) -> LifecycleDigestV1 {
        derive_manifest_digest(FINAL_DIGEST_DOMAIN_V2, &self.encode())
    }
}

impl fmt::Debug for FinalManifestV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalManifestV2")
            .field("product_frame_count", &self.product_frame_count)
            .field("event_count", &self.event_count)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RepositoryManifestErrorV2 {
    InvalidEncodedLength,
    InvalidMagic,
    UnsupportedVersion,
    UnsupportedObjectKind,
    NonzeroReserved,
    NoncanonicalManifest,
}

impl RepositoryManifestErrorV2 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidEncodedLength => "EVIDENTRAIL_REPOSITORY_MANIFEST_INVALID_ENCODED_LENGTH",
            Self::InvalidMagic => "EVIDENTRAIL_REPOSITORY_MANIFEST_INVALID_MAGIC",
            Self::UnsupportedVersion => "EVIDENTRAIL_REPOSITORY_MANIFEST_UNSUPPORTED_VERSION",
            Self::UnsupportedObjectKind => "EVIDENTRAIL_REPOSITORY_MANIFEST_UNSUPPORTED_OBJECT_KIND",
            Self::NonzeroReserved => "EVIDENTRAIL_REPOSITORY_MANIFEST_NONZERO_RESERVED",
            Self::NoncanonicalManifest => "EVIDENTRAIL_REPOSITORY_MANIFEST_NONCANONICAL",
        }
    }
}

impl fmt::Debug for RepositoryManifestErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepositoryManifestErrorV2")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for RepositoryManifestErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for RepositoryManifestErrorV2 {}

fn derive_manifest_digest(domain: &[u8], bytes: &[u8]) -> LifecycleDigestV1 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    LifecycleDigestV1::from_bytes(hasher.finalize().into())
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(read_array(bytes, offset))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(read_array(bytes, offset))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut result = [0u8; N];
    result.copy_from_slice(&bytes[offset..offset + N]);
    result
}
