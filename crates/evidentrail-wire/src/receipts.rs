use evidentrail_core::{
    AcquisitionOutcome, EventLedger, ExactnessBasis, PresentationDisposition, PresentationReceipt,
};
use evidentrail_schema::bounds::MAX_RECEIPT_CHUNK_ENTRIES;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canonical::canonical_json;
use crate::codec::parse_hash_token;
use crate::{WireErrorV1, decode_artifact};

pub const ACQUISITION_RECEIPT_CONTRACT_V1: &str = "evidentrail.acquisition_receipt";
pub const ACQUISITION_RECEIPT_CHUNK_CONTRACT_V1: &str = "evidentrail.acquisition_receipt_chunk";
pub const PRESENTATION_RECEIPT_CONTRACT_V1: &str = "evidentrail.presentation_receipt";
pub const PRESENTATION_RECEIPT_CHUNK_CONTRACT_V1: &str = "evidentrail.presentation_receipt_chunk";

pub(crate) fn schema_for_contract_v1(contract: &str) -> Option<schemars::Schema> {
    match contract {
        ACQUISITION_RECEIPT_CONTRACT_V1 | PRESENTATION_RECEIPT_CONTRACT_V1 => {
            Some(schemars::schema_for!(ReceiptManifestWireV1))
        }
        ACQUISITION_RECEIPT_CHUNK_CONTRACT_V1 => {
            Some(schemars::schema_for!(AcquisitionChunkWireV1))
        }
        PRESENTATION_RECEIPT_CHUNK_CONTRACT_V1 => {
            Some(schemars::schema_for!(PresentationChunkWireV1))
        }
        _ => None,
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ChunkedReceiptArtifactV1 {
    manifest_bytes: Vec<u8>,
    chunks: Vec<Vec<u8>>,
}
impl ChunkedReceiptArtifactV1 {
    #[must_use]
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }
    #[must_use]
    pub fn chunks(&self) -> &[Vec<u8>] {
        &self.chunks
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ReceiptManifestWireV1 {
    contract: String,
    contract_version: u16,
    receipt_id: String,
    retrieval_id: String,
    entry_count: u64,
    chunk_count: u64,
    chunk_digests: Vec<String>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct AcquisitionChunkWireV1 {
    contract: String,
    contract_version: u16,
    receipt_id: String,
    retrieval_id: String,
    chunk_index: u64,
    entry_offset: u64,
    entries: Vec<AcquisitionEntryWireV1>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct AcquisitionEntryWireV1 {
    source_record_id: String,
    outcome: AcquisitionOutcomeWireV1,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum AcquisitionOutcomeWireV1 {
    SourceExact {
        event_id: String,
    },
    PostPolicy {
        event_id: String,
        policy_digest: String,
        transformation_receipt_id: String,
    },
    OmittedByPolicy {
        policy_digest: String,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct PresentationChunkWireV1 {
    contract: String,
    contract_version: u16,
    receipt_id: String,
    retrieval_id: String,
    chunk_index: u64,
    entry_offset: u64,
    entries: Vec<PresentationEntryWireV1>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct PresentationEntryWireV1 {
    event_id: String,
    disposition: PresentationDispositionWireV1,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum PresentationDispositionWireV1 {
    ShownVerbatim,
    PatternRepresented { pattern_id: String },
    RetainedRaw,
}

pub fn encode_acquisition_receipt_v1(
    ledger: &EventLedger,
) -> Result<ChunkedReceiptArtifactV1, WireErrorV1> {
    let receipt = ledger.acquisition_receipt();
    let receipt_id = ledger.acquisition_receipt_id().to_string();
    let retrieval_id = ledger.retrieval_id().to_string();
    let entries = receipt
        .entries()
        .iter()
        .map(|entry| AcquisitionEntryWireV1 {
            source_record_id: entry.source_record_id().to_string(),
            outcome: match entry.outcome() {
                AcquisitionOutcome::Persisted {
                    event_id,
                    exactness_basis: ExactnessBasis::SourceExact,
                } => AcquisitionOutcomeWireV1::SourceExact {
                    event_id: event_id.to_string(),
                },
                AcquisitionOutcome::Persisted {
                    event_id,
                    exactness_basis:
                        ExactnessBasis::PostPolicy {
                            policy_digest,
                            transformation_receipt_id,
                        },
                } => AcquisitionOutcomeWireV1::PostPolicy {
                    event_id: event_id.to_string(),
                    policy_digest: policy_digest.to_string(),
                    transformation_receipt_id: transformation_receipt_id.to_string(),
                },
                AcquisitionOutcome::OmittedByPolicy { policy_digest } => {
                    AcquisitionOutcomeWireV1::OmittedByPolicy {
                        policy_digest: policy_digest.to_string(),
                    }
                }
            },
        })
        .collect::<Vec<_>>();
    encode_chunks(
        ACQUISITION_RECEIPT_CONTRACT_V1,
        &receipt_id,
        &retrieval_id,
        entries
            .chunks(MAX_RECEIPT_CHUNK_ENTRIES)
            .enumerate()
            .map(|(index, chunk)| {
                canonical_json(&AcquisitionChunkWireV1 {
                    contract: ACQUISITION_RECEIPT_CHUNK_CONTRACT_V1.into(),
                    contract_version: 1,
                    receipt_id: receipt_id.clone(),
                    retrieval_id: retrieval_id.clone(),
                    chunk_index: index as u64,
                    entry_offset: (index * MAX_RECEIPT_CHUNK_ENTRIES) as u64,
                    entries: chunk.to_vec(),
                })
                .map_err(|_| WireErrorV1::CanonicalizationFailed)
            })
            .collect::<Result<Vec<_>, _>>()?,
        entries.len(),
    )
}

pub fn encode_presentation_receipt_v1(
    ledger: &EventLedger,
    receipt: &PresentationReceipt,
) -> Result<ChunkedReceiptArtifactV1, WireErrorV1> {
    if receipt.retrieval_id() != ledger.retrieval_id()
        || receipt
            .entries()
            .iter()
            .zip(ledger.events())
            .any(|(entry, event)| entry.event_id() != event.id())
        || receipt.entries().len() != ledger.len()
    {
        return Err(WireErrorV1::CrossContext);
    }
    let receipt_id = receipt.id().to_string();
    let retrieval_id = ledger.retrieval_id().to_string();
    let entries = receipt
        .entries()
        .iter()
        .map(|entry| PresentationEntryWireV1 {
            event_id: entry.event_id().to_string(),
            disposition: match entry.disposition() {
                PresentationDisposition::ShownVerbatim => {
                    PresentationDispositionWireV1::ShownVerbatim
                }
                PresentationDisposition::PatternRepresented { pattern_id } => {
                    PresentationDispositionWireV1::PatternRepresented {
                        pattern_id: pattern_id.to_string(),
                    }
                }
                PresentationDisposition::RetainedRaw => PresentationDispositionWireV1::RetainedRaw,
            },
        })
        .collect::<Vec<_>>();
    encode_chunks(
        PRESENTATION_RECEIPT_CONTRACT_V1,
        &receipt_id,
        &retrieval_id,
        entries
            .chunks(MAX_RECEIPT_CHUNK_ENTRIES)
            .enumerate()
            .map(|(index, chunk)| {
                canonical_json(&PresentationChunkWireV1 {
                    contract: PRESENTATION_RECEIPT_CHUNK_CONTRACT_V1.into(),
                    contract_version: 1,
                    receipt_id: receipt_id.clone(),
                    retrieval_id: retrieval_id.clone(),
                    chunk_index: index as u64,
                    entry_offset: (index * MAX_RECEIPT_CHUNK_ENTRIES) as u64,
                    entries: chunk.to_vec(),
                })
                .map_err(|_| WireErrorV1::CanonicalizationFailed)
            })
            .collect::<Result<Vec<_>, _>>()?,
        entries.len(),
    )
}

fn encode_chunks(
    contract: &str,
    receipt_id: &str,
    retrieval_id: &str,
    chunks: Vec<Vec<u8>>,
    entry_count: usize,
) -> Result<ChunkedReceiptArtifactV1, WireErrorV1> {
    let manifest = ReceiptManifestWireV1 {
        contract: contract.into(),
        contract_version: 1,
        receipt_id: receipt_id.into(),
        retrieval_id: retrieval_id.into(),
        entry_count: entry_count as u64,
        chunk_count: chunks.len() as u64,
        chunk_digests: chunks
            .iter()
            .map(|bytes| format!("artifact_sha256_{}", hex(&Sha256::digest(bytes))))
            .collect(),
    };
    Ok(ChunkedReceiptArtifactV1 {
        manifest_bytes: canonical_json(&manifest)
            .map_err(|_| WireErrorV1::CanonicalizationFailed)?,
        chunks,
    })
}

pub fn decode_acquisition_receipt_v1(
    manifest: &[u8],
    chunks: &[&[u8]],
) -> Result<ChunkedReceiptArtifactV1, WireErrorV1> {
    decode_chunks(
        manifest,
        chunks,
        ACQUISITION_RECEIPT_CONTRACT_V1,
        ACQUISITION_RECEIPT_CHUNK_CONTRACT_V1,
        true,
    )
}
pub fn decode_presentation_receipt_v1(
    manifest: &[u8],
    chunks: &[&[u8]],
) -> Result<ChunkedReceiptArtifactV1, WireErrorV1> {
    decode_chunks(
        manifest,
        chunks,
        PRESENTATION_RECEIPT_CONTRACT_V1,
        PRESENTATION_RECEIPT_CHUNK_CONTRACT_V1,
        false,
    )
}

fn decode_chunks(
    manifest_bytes: &[u8],
    chunks: &[&[u8]],
    root_contract: &str,
    chunk_contract: &str,
    acquisition: bool,
) -> Result<ChunkedReceiptArtifactV1, WireErrorV1> {
    let artifact = decode_artifact(manifest_bytes)?;
    if artifact.descriptor().name() != root_contract {
        return Err(WireErrorV1::UnsupportedContract);
    }
    let manifest: ReceiptManifestWireV1 =
        serde_json::from_slice(manifest_bytes).map_err(|_| WireErrorV1::Malformed)?;
    if manifest.chunk_count as usize != chunks.len() || manifest.chunk_digests.len() != chunks.len()
    {
        return Err(WireErrorV1::SemanticallyInvalid);
    }
    let mut entry_count = 0_usize;
    let mut owned = Vec::new();
    for (index, bytes) in chunks.iter().enumerate() {
        let chunk_artifact = decode_artifact(bytes)?;
        if chunk_artifact.descriptor().name() != chunk_contract
            || manifest.chunk_digests[index]
                != format!("artifact_sha256_{}", hex(&Sha256::digest(bytes)))
        {
            return Err(WireErrorV1::IdentityMismatch);
        }
        let (receipt_id, retrieval_id, chunk_index, offset, count) = if acquisition {
            let chunk: AcquisitionChunkWireV1 =
                serde_json::from_slice(bytes).map_err(|_| WireErrorV1::Malformed)?;
            for entry in &chunk.entries {
                validate_acquisition(entry)?;
            }
            (
                chunk.receipt_id,
                chunk.retrieval_id,
                chunk.chunk_index,
                chunk.entry_offset,
                chunk.entries.len(),
            )
        } else {
            let chunk: PresentationChunkWireV1 =
                serde_json::from_slice(bytes).map_err(|_| WireErrorV1::Malformed)?;
            for entry in &chunk.entries {
                validate_presentation(entry)?;
            }
            (
                chunk.receipt_id,
                chunk.retrieval_id,
                chunk.chunk_index,
                chunk.entry_offset,
                chunk.entries.len(),
            )
        };
        if receipt_id != manifest.receipt_id
            || retrieval_id != manifest.retrieval_id
            || chunk_index != index as u64
            || offset != entry_count as u64
            || count > MAX_RECEIPT_CHUNK_ENTRIES
        {
            return Err(WireErrorV1::CrossContext);
        }
        entry_count += count;
        owned.push(bytes.to_vec());
    }
    if entry_count as u64 != manifest.entry_count {
        return Err(WireErrorV1::SemanticallyInvalid);
    }
    Ok(ChunkedReceiptArtifactV1 {
        manifest_bytes: manifest_bytes.to_vec(),
        chunks: owned,
    })
}
fn validate_acquisition(entry: &AcquisitionEntryWireV1) -> Result<(), WireErrorV1> {
    parse_hash_token(&entry.source_record_id, "srec_")?;
    match &entry.outcome {
        AcquisitionOutcomeWireV1::SourceExact { event_id } => {
            parse_hash_token(event_id, "evt_")?;
        }
        AcquisitionOutcomeWireV1::PostPolicy {
            event_id,
            policy_digest,
            transformation_receipt_id,
        } => {
            parse_hash_token(event_id, "evt_")?;
            parse_hash_token(policy_digest, "policy_sha256_")?;
            parse_hash_token(transformation_receipt_id, "txrcpt_")?;
        }
        AcquisitionOutcomeWireV1::OmittedByPolicy { policy_digest } => {
            parse_hash_token(policy_digest, "policy_sha256_")?;
        }
    }
    Ok(())
}
fn validate_presentation(entry: &PresentationEntryWireV1) -> Result<(), WireErrorV1> {
    parse_hash_token(&entry.event_id, "evt_")?;
    if let PresentationDispositionWireV1::PatternRepresented { pattern_id } = &entry.disposition {
        parse_hash_token(pattern_id, "pat_")?;
    }
    Ok(())
}

pub fn verify_acquisition_receipt_v1_against(
    manifest: &[u8],
    chunks: &[&[u8]],
    ledger: &EventLedger,
) -> Result<ChunkedReceiptArtifactV1, WireErrorV1> {
    let decoded = decode_acquisition_receipt_v1(manifest, chunks)?;
    let expected = encode_acquisition_receipt_v1(ledger)?;
    if decoded != expected {
        return Err(WireErrorV1::CrossContext);
    }
    Ok(decoded)
}
pub fn verify_presentation_receipt_v1_against(
    manifest: &[u8],
    chunks: &[&[u8]],
    ledger: &EventLedger,
    receipt: &PresentationReceipt,
) -> Result<ChunkedReceiptArtifactV1, WireErrorV1> {
    let decoded = decode_presentation_receipt_v1(manifest, chunks)?;
    let expected = encode_presentation_receipt_v1(ledger, receipt)?;
    if decoded != expected {
        return Err(WireErrorV1::CrossContext);
    }
    Ok(decoded)
}
fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(H[(byte >> 4) as usize] as char);
        out.push(H[(byte & 15) as usize] as char);
    }
    out
}
