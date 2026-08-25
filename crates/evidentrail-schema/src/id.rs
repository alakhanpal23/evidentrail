use std::fmt;

const HASH_BYTES: usize = 32;
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

fn canonical_token(prefix: &str, bytes: &[u8; HASH_BYTES]) -> String {
    let mut token = String::with_capacity(prefix.len() + (HASH_BYTES * 2));
    token.push_str(prefix);
    for byte in bytes {
        token.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        token.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    token
}

macro_rules! hash_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; HASH_BYTES]);

        impl $name {
            #[must_use]
            pub const fn from_bytes(bytes: [u8; HASH_BYTES]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; HASH_BYTES] {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str($prefix)?;
                for byte in self.0 {
                    write!(formatter, "{byte:02x}")?;
                }
                Ok(())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

hash_id!(RetrievalId, "ret_");
hash_id!(PlanId, "plan_");
hash_id!(PlanDigest, "plan_sha256_");
hash_id!(SourceIdentityDigest, "source_sha256_");
hash_id!(SourceRecordId, "srec_");
hash_id!(EventId, "evt_");
hash_id!(BlockId, "blk_");
hash_id!(ContentHash, "sha256_");
hash_id!(PolicyDigest, "policy_sha256_");
hash_id!(InternalPathPolicyDigest, "internal_path_policy_sha256_");
hash_id!(
    LocalFileCertificationProfileDigest,
    "local_file_certification_profile_sha256_"
);
hash_id!(TransformationReceiptId, "txrcpt_");
hash_id!(QuestionDigest, "question_sha256_");
hash_id!(EvidenceReferenceId, "eref_");
hash_id!(RepositoryIdentityDigest, "repo_sha256_");
hash_id!(BindingId, "bind_");
hash_id!(BindingDigest, "binding_sha256_");
hash_id!(ArtifactDigest, "artifact_sha256_");
hash_id!(PatternId, "pat_");
hash_id!(AcquisitionReceiptId, "acqrcpt_");
hash_id!(PresentationReceiptId, "prcpt_");

/// Opaque, store-generated identity for one local result.
///
/// Production values are random by contract. Random generation belongs to the
/// result store, not this schema crate. Unlike hashes and references this type
/// deliberately has no `Display` implementation; serialization must opt in by
/// calling [`ResultId::canonical_token`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResultId([u8; HASH_BYTES]);

impl ResultId {
    /// Construct a value from store-provided randomness or a deterministic test
    /// fixture.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; HASH_BYTES]) -> Self {
        Self(bytes)
    }

    /// Access the opaque bytes for storage binding and result-local hashing.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_BYTES] {
        &self.0
    }

    /// Produce the only canonical external token form for a result identity.
    #[must_use]
    pub fn canonical_token(&self) -> String {
        canonical_token("result_", &self.0)
    }
}

impl fmt::Debug for ResultId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResultId(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_hash_id_contract<T>(
        value: T,
        expected_prefix: &str,
        expected_type_name: &str,
        as_bytes: impl FnOnce(&T) -> &[u8; HASH_BYTES],
    ) where
        T: fmt::Display + fmt::Debug,
    {
        let token = value.to_string();
        assert_eq!(token.len(), expected_prefix.len() + (HASH_BYTES * 2));
        assert!(token.starts_with(expected_prefix));
        assert!(
            token[expected_prefix.len()..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert_eq!(as_bytes(&value), &[0xab; HASH_BYTES]);

        let debug = format!("{value:?}");
        assert_eq!(debug, format!("{expected_type_name}(<redacted>)"));
        assert!(!debug.contains(&token));
        assert!(!debug.contains("abab"));
    }

    macro_rules! assert_new_hash_id {
        ($type:ident, $prefix:literal) => {{
            let value = $type::from_bytes([0xab; HASH_BYTES]);
            assert_hash_id_contract(value, $prefix, stringify!($type), $type::as_bytes);
        }};
    }

    #[test]
    fn new_hash_and_reference_ids_have_unique_canonical_prefixes() {
        assert_new_hash_id!(QuestionDigest, "question_sha256_");
        assert_new_hash_id!(EvidenceReferenceId, "eref_");
        assert_new_hash_id!(RepositoryIdentityDigest, "repo_sha256_");
        assert_new_hash_id!(BindingId, "bind_");
        assert_new_hash_id!(BindingDigest, "binding_sha256_");
        assert_new_hash_id!(InternalPathPolicyDigest, "internal_path_policy_sha256_");
        assert_new_hash_id!(
            LocalFileCertificationProfileDigest,
            "local_file_certification_profile_sha256_"
        );
        assert_new_hash_id!(ArtifactDigest, "artifact_sha256_");
        assert_new_hash_id!(PatternId, "pat_");
        assert_new_hash_id!(AcquisitionReceiptId, "acqrcpt_");
        assert_new_hash_id!(PresentationReceiptId, "prcpt_");
    }

    #[test]
    fn result_id_requires_explicit_canonical_token_conversion() {
        let result_id = ResultId::from_bytes([0xcd; HASH_BYTES]);
        let token = result_id.canonical_token();

        assert_eq!(token, format!("result_{}", "cd".repeat(HASH_BYTES)));
        assert_eq!(token.len(), "result_".len() + (HASH_BYTES * 2));
        assert_eq!(result_id.as_bytes(), &[0xcd; HASH_BYTES]);
        assert_eq!(format!("{result_id:?}"), "ResultId(<redacted>)");
        assert!(!format!("{result_id:?}").contains("cdcd"));
    }

    #[test]
    fn every_new_prefix_is_distinct() {
        let prefixes = [
            "result_",
            "question_sha256_",
            "eref_",
            "repo_sha256_",
            "bind_",
            "binding_sha256_",
            "internal_path_policy_sha256_",
            "local_file_certification_profile_sha256_",
            "artifact_sha256_",
            "pat_",
            "acqrcpt_",
            "prcpt_",
        ];

        for (index, prefix) in prefixes.iter().enumerate() {
            assert!(!prefixes[..index].contains(prefix));
        }
    }
}
