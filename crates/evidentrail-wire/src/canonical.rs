use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::PlanVerificationError;

pub(crate) fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, PlanVerificationError> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|_| PlanVerificationError::CanonicalizationFailed)
}

pub(crate) fn domain_hash(domain: &[u8], body: &[u8]) -> Result<[u8; 32], PlanVerificationError> {
    let domain_length =
        u64::try_from(domain.len()).map_err(|_| PlanVerificationError::CanonicalizationFailed)?;
    let body_length =
        u64::try_from(body.len()).map_err(|_| PlanVerificationError::CanonicalizationFailed)?;

    let mut hasher = Sha256::new();
    hasher.update(domain_length.to_le_bytes());
    hasher.update(domain);
    hasher.update(body_length.to_le_bytes());
    hasher.update(body);
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonicalize_fixture(input: &str, expected: &str) {
        let parsed: serde_json::Value = serde_json::from_str(input).expect("valid RFC fixture");
        let actual = canonical_json(&parsed).expect("RFC fixture must canonicalize");
        assert_eq!(actual, expected.trim_end().as_bytes());
    }

    #[test]
    fn passes_rfc_8785_primitive_serialization_vector() {
        canonicalize_fixture(
            include_str!("../tests/fixtures/rfc8785/values.input.json"),
            include_str!("../tests/fixtures/rfc8785/values.expected.json"),
        );
    }

    #[test]
    fn passes_rfc_8785_utf16_property_sorting_vector() {
        canonicalize_fixture(
            include_str!("../tests/fixtures/rfc8785/weird.input.json"),
            include_str!("../tests/fixtures/rfc8785/weird.expected.json"),
        );
    }

    #[test]
    fn length_framing_separates_domain_and_body_boundaries() {
        assert_ne!(
            domain_hash(b"ab", b"c").unwrap(),
            domain_hash(b"a", b"bc").unwrap()
        );
    }
}
