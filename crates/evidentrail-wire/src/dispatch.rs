use crate::canonical::canonical_json;
use crate::{ContractDescriptorV1, WireErrorV1, contract_registry_v1};
use evidentrail_schema::bounds::MAX_WIRE_OBJECT_BYTES;
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;

struct ArtifactHeaderV1 {
    contract: String,
    contract_version: u16,
}

impl<'de> Deserialize<'de> for ArtifactHeaderV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct HeaderVisitor;
        impl<'de> Visitor<'de> for HeaderVisitor {
            type Value = ArtifactHeaderV1;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a versioned artifact object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut contract = None;
                let mut contract_version = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "contract" => {
                            if contract.is_some() {
                                return Err(serde::de::Error::duplicate_field("contract"));
                            }
                            contract = Some(map.next_value()?);
                        }
                        "contract_version" => {
                            if contract_version.is_some() {
                                return Err(serde::de::Error::duplicate_field("contract_version"));
                            }
                            contract_version = Some(map.next_value()?);
                        }
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(ArtifactHeaderV1 {
                    contract: contract
                        .ok_or_else(|| serde::de::Error::missing_field("contract"))?,
                    contract_version: contract_version
                        .ok_or_else(|| serde::de::Error::missing_field("contract_version"))?,
                })
            }
        }
        deserializer.deserialize_map(HeaderVisitor)
    }
}

/// Structurally canonical bytes. This grants no context authority.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalArtifactV1 {
    descriptor: ContractDescriptorV1,
    canonical_bytes: Vec<u8>,
}

impl CanonicalArtifactV1 {
    #[must_use]
    pub const fn descriptor(&self) -> ContractDescriptorV1 {
        self.descriptor
    }
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

impl fmt::Debug for CanonicalArtifactV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanonicalArtifactV1")
            .field("contract", &self.descriptor.name())
            .field("contract_version", &self.descriptor.supported_version())
            .field("canonical_byte_count", &self.canonical_bytes.len())
            .field("context_verified", &false)
            .finish()
    }
}

/// Dispatch by a streaming header visitor before any bounded generic JSON tree is built.
pub fn decode_artifact(bytes: &[u8]) -> Result<CanonicalArtifactV1, WireErrorV1> {
    if bytes.is_empty() {
        return Err(WireErrorV1::EmptyDocument);
    }
    if bytes.len() > MAX_WIRE_OBJECT_BYTES {
        return Err(WireErrorV1::DocumentTooLarge);
    }
    let header: ArtifactHeaderV1 =
        serde_json::from_slice(bytes).map_err(|_| WireErrorV1::Malformed)?;
    let descriptor = contract_registry_v1()
        .into_iter()
        .find(|entry| entry.name() == header.contract)
        .ok_or(WireErrorV1::UnsupportedContract)?;
    if header.contract_version != descriptor.supported_version() {
        return Err(WireErrorV1::UnsupportedVersion);
    }
    if bytes.len() > descriptor.maximum_bytes() {
        return Err(WireErrorV1::DocumentTooLarge);
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| WireErrorV1::Malformed)?;
    let regenerated = canonical_json(&value).map_err(|_| WireErrorV1::CanonicalizationFailed)?;
    if regenerated != bytes {
        return Err(WireErrorV1::NonCanonical);
    }
    Ok(CanonicalArtifactV1 {
        descriptor,
        canonical_bytes: bytes.to_vec(),
    })
}
