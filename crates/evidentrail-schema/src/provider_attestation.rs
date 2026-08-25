//! Closed adapter-attested correlation vocabulary.
//!
//! This module only preserves scoped native equality assertions. Candidate
//! lane 3 does not consume this vocabulary yet; enabling it requires a
//! separate, explicitly reviewed integration pass.
//!
//! Attestations are not source-position identity. `evidentrail-core` leaves them out
//! of `SourceRecordId` and omitted-policy receipts, and commits a nonempty
//! canonical set only to an authorized persisted event identity.

use std::error::Error as StdError;
use std::fmt;

use crate::bounds::{
    MAX_PROVIDER_ATTESTATION_VALUE_BYTES_V1, MAX_PROVIDER_ATTESTATIONS_PER_EVENT_V1,
};

const DIGEST_BYTES: usize = 32;

/// Opaque digest of the complete tenant/provider/source correlation scope.
///
/// Adapters must derive this outside the schema layer using a domain-separated
/// construction that includes every namespace boundary required to forbid
/// cross-tenant, cross-provider, and cross-source joins. Equality of opaque
/// values never overrides inequality of this scope.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderAttestationScopeDigestV1([u8; DIGEST_BYTES]);

impl ProviderAttestationScopeDigestV1 {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }
}

impl fmt::Debug for ProviderAttestationScopeDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderAttestationScopeDigestV1(<redacted>)")
    }
}

/// Closed V1 identity relation vocabulary.
///
/// Equality means only that an adapter reported the same native identifier in
/// the same opaque scope. It does not assert parenthood, causality, temporal
/// order, or service topology.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProviderAttestedRelationKindV1 {
    TraceIdentity,
    RequestIdentity,
    SessionIdentity,
    HostIdentity,
    ContainerIdentity,
    DeploymentIdentity,
    ServiceIdentity,
}

impl ProviderAttestedRelationKindV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TraceIdentity => "trace_identity",
            Self::RequestIdentity => "request_identity",
            Self::SessionIdentity => "session_identity",
            Self::HostIdentity => "host_identity",
            Self::ContainerIdentity => "container_identity",
            Self::DeploymentIdentity => "deployment_identity",
            Self::ServiceIdentity => "service_identity",
        }
    }
}

/// Closed provenance of a V1 provider attestation.
///
/// V1 admits only a value supplied by an adapter from a provider-native field.
/// Payload parsing, inference, normalization, and model output have no variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProviderAttestationOriginV1 {
    AdapterNativeField,
}

impl ProviderAttestationOriginV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AdapterNativeField => "adapter_native_field",
        }
    }
}

/// Bounded opaque provider-native identity bytes.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderAttestationValueV1(Vec<u8>);

impl ProviderAttestationValueV1 {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, ProviderAttestationConstructionError> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(ProviderAttestationConstructionError::EmptyValue);
        }
        if bytes.len() > MAX_PROVIDER_ATTESTATION_VALUE_BYTES_V1 {
            return Err(ProviderAttestationConstructionError::ValueTooLarge);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ProviderAttestationValueV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderAttestationValueV1")
            .field("byte_count", &self.0.len())
            .finish()
    }
}

/// One scoped provider-native equality assertion.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderAttestedCorrelationV1 {
    scope_digest: ProviderAttestationScopeDigestV1,
    relation_kind: ProviderAttestedRelationKindV1,
    origin: ProviderAttestationOriginV1,
    value: ProviderAttestationValueV1,
}

impl ProviderAttestedCorrelationV1 {
    #[must_use]
    pub const fn new(
        scope_digest: ProviderAttestationScopeDigestV1,
        relation_kind: ProviderAttestedRelationKindV1,
        value: ProviderAttestationValueV1,
    ) -> Self {
        Self {
            scope_digest,
            relation_kind,
            origin: ProviderAttestationOriginV1::AdapterNativeField,
            value,
        }
    }

    #[must_use]
    pub const fn scope_digest(&self) -> ProviderAttestationScopeDigestV1 {
        self.scope_digest
    }

    #[must_use]
    pub const fn relation_kind(&self) -> ProviderAttestedRelationKindV1 {
        self.relation_kind
    }

    #[must_use]
    pub const fn origin(&self) -> ProviderAttestationOriginV1 {
        self.origin
    }

    #[must_use]
    pub const fn value(&self) -> &ProviderAttestationValueV1 {
        &self.value
    }
}

impl fmt::Debug for ProviderAttestedCorrelationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderAttestedCorrelationV1")
            .field("relation_kind", &self.relation_kind.code())
            .field("origin", &self.origin.code())
            .field("value_bytes", &self.value.as_bytes().len())
            .finish()
    }
}

/// Canonical, sorted, duplicate-free provider attestations for one envelope.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ProviderAttestationsV1 {
    entries: Vec<ProviderAttestedCorrelationV1>,
}

impl ProviderAttestationsV1 {
    pub fn new(
        entries: impl IntoIterator<Item = ProviderAttestedCorrelationV1>,
    ) -> Result<Self, ProviderAttestationConstructionError> {
        let mut canonical_entries = Vec::new();
        for entry in entries {
            if canonical_entries.len() >= MAX_PROVIDER_ATTESTATIONS_PER_EVENT_V1 {
                return Err(ProviderAttestationConstructionError::TooManyAttestations);
            }
            canonical_entries.push(entry);
        }
        canonical_entries.sort_unstable();
        canonical_entries.dedup();
        Ok(Self {
            entries: canonical_entries,
        })
    }

    #[must_use]
    pub fn entries(&self) -> &[ProviderAttestedCorrelationV1] {
        &self.entries
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl fmt::Debug for ProviderAttestationsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderAttestationsV1")
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

/// Stable contentless construction failure for provider attestations.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProviderAttestationConstructionError {
    EmptyValue,
    ValueTooLarge,
    TooManyAttestations,
}

impl ProviderAttestationConstructionError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyValue => "EVIDENTRAIL_SCHEMA_PROVIDER_ATTESTATION_EMPTY_VALUE",
            Self::ValueTooLarge => "EVIDENTRAIL_SCHEMA_PROVIDER_ATTESTATION_VALUE_TOO_LARGE",
            Self::TooManyAttestations => "EVIDENTRAIL_SCHEMA_TOO_MANY_PROVIDER_ATTESTATIONS",
        }
    }
}

impl fmt::Debug for ProviderAttestationConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderAttestationConstructionError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for ProviderAttestationConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ProviderAttestationConstructionError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(
        scope: u8,
        kind: ProviderAttestedRelationKindV1,
        value: Vec<u8>,
    ) -> ProviderAttestedCorrelationV1 {
        ProviderAttestedCorrelationV1::new(
            ProviderAttestationScopeDigestV1::from_bytes([scope; 32]),
            kind,
            ProviderAttestationValueV1::new(value).unwrap(),
        )
    }

    #[test]
    fn values_and_sets_enforce_exact_caps_before_deduplication() {
        assert_eq!(
            ProviderAttestationValueV1::new(Vec::<u8>::new()).unwrap_err(),
            ProviderAttestationConstructionError::EmptyValue,
        );
        assert!(
            ProviderAttestationValueV1::new(vec![0; MAX_PROVIDER_ATTESTATION_VALUE_BYTES_V1])
                .is_ok()
        );
        assert_eq!(
            ProviderAttestationValueV1::new(vec![0; MAX_PROVIDER_ATTESTATION_VALUE_BYTES_V1 + 1])
                .unwrap_err(),
            ProviderAttestationConstructionError::ValueTooLarge,
        );
        let entries = (0..MAX_PROVIDER_ATTESTATIONS_PER_EVENT_V1)
            .map(|index| {
                entry(
                    1,
                    ProviderAttestedRelationKindV1::TraceIdentity,
                    index.to_be_bytes().to_vec(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            ProviderAttestationsV1::new(entries.clone()).unwrap().len(),
            entries.len()
        );
        let mut too_many = entries;
        too_many.push(entry(
            1,
            ProviderAttestedRelationKindV1::TraceIdentity,
            b"overflow".to_vec(),
        ));
        assert_eq!(
            ProviderAttestationsV1::new(too_many).unwrap_err(),
            ProviderAttestationConstructionError::TooManyAttestations,
        );
    }

    #[test]
    fn construction_is_sorted_deduplicated_and_scope_sensitive() {
        let shared = entry(
            1,
            ProviderAttestedRelationKindV1::RequestIdentity,
            vec![0xff, 0, b'/', b'\n'],
        );
        let other_scope = entry(
            2,
            ProviderAttestedRelationKindV1::RequestIdentity,
            vec![0xff, 0, b'/', b'\n'],
        );
        let attestations =
            ProviderAttestationsV1::new([other_scope.clone(), shared.clone(), shared]).unwrap();
        assert_eq!(attestations.len(), 2);
        assert!(
            attestations
                .entries()
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
        assert_ne!(
            attestations.entries()[0].scope_digest(),
            attestations.entries()[1].scope_digest()
        );
        assert!(
            attestations
                .entries()
                .iter()
                .all(|entry| entry.origin() == ProviderAttestationOriginV1::AdapterNativeField)
        );
    }

    #[test]
    fn vocabulary_is_closed_noncausal_and_debug_is_contentless() {
        let kinds = [
            ProviderAttestedRelationKindV1::TraceIdentity,
            ProviderAttestedRelationKindV1::RequestIdentity,
            ProviderAttestedRelationKindV1::SessionIdentity,
            ProviderAttestedRelationKindV1::HostIdentity,
            ProviderAttestedRelationKindV1::ContainerIdentity,
            ProviderAttestedRelationKindV1::DeploymentIdentity,
            ProviderAttestedRelationKindV1::ServiceIdentity,
        ];
        assert_eq!(kinds.len(), 7);
        assert!(kinds.iter().all(|kind| !kind.code().contains("parent")));
        const CANARY: &[u8] = b"CANARY_PROVIDER_VALUE_13ad";
        let value = ProviderAttestationValueV1::new(CANARY.to_vec()).unwrap();
        let correlation = ProviderAttestedCorrelationV1::new(
            ProviderAttestationScopeDigestV1::from_bytes([0xca; 32]),
            ProviderAttestedRelationKindV1::TraceIdentity,
            value.clone(),
        );
        let attestations = ProviderAttestationsV1::new([correlation.clone()]).unwrap();
        let rendered = format!(
            "{value:?} {correlation:?} {attestations:?} {:?} {:?}",
            ProviderAttestationScopeDigestV1::from_bytes([0xca; 32]),
            ProviderAttestationConstructionError::EmptyValue,
        );
        assert!(!rendered.contains(std::str::from_utf8(CANARY).unwrap()));
        assert!(!rendered.contains("cacaca"));
        assert!(rendered.contains("EVIDENTRAIL_SCHEMA_PROVIDER_ATTESTATION_EMPTY_VALUE"));
    }
}
