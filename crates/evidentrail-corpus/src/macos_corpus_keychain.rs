//! Persistent per-source SQLCipher keys. Keychain entries contain no log text.

use std::fmt::Write as _;

use core_foundation::data::CFData;
use security_framework::item::{ItemAddOptions, ItemAddValue, ItemClass, Location};
use security_framework::passwords::{
    PasswordOptions, delete_generic_password_options, generic_password,
};
use security_framework_sys::base::{
    errSecDuplicateItem as ERR_SEC_DUPLICATE_ITEM, errSecItemNotFound as ERR_SEC_ITEM_NOT_FOUND,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

const SERVICE: &str = "ai.evidentrail.corpus-key.login.v1";
const MAGIC: &[u8; 8] = b"EVCRKEY1";
const ENTRY_LEN: usize = 8 + 32 + 32 + 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorpusKeychainErrorV1 {
    AlreadyExists,
    NotFound,
    ScopeMismatch,
    Unavailable,
}

impl CorpusKeychainErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AlreadyExists => "EVIDENTRAIL_CORPUS_KEY_ALREADY_EXISTS",
            Self::NotFound => "EVIDENTRAIL_CORPUS_KEY_NOT_FOUND",
            Self::ScopeMismatch => "EVIDENTRAIL_CORPUS_KEY_SCOPE_MISMATCH",
            Self::Unavailable => "EVIDENTRAIL_CORPUS_KEYCHAIN_UNAVAILABLE",
        }
    }
}

/// Uses one add-only Keychain item per tenant/source pair. A Keychain key is
/// never serialized into the corpus, a manifest, an argument, or an env var.
pub struct MacOsCorpusKeychainV1 {
    service: String,
}

impl MacOsCorpusKeychainV1 {
    #[must_use]
    pub fn production() -> Self {
        Self {
            service: SERVICE.to_owned(),
        }
    }

    /// Separate namespace for live Keychain integration tests.
    #[doc(hidden)]
    pub fn isolated_for_tests(namespace: &str) -> Result<Self, CorpusKeychainErrorV1> {
        if namespace.is_empty() || namespace.len() > 96 || !namespace.is_ascii() {
            return Err(CorpusKeychainErrorV1::Unavailable);
        }
        Ok(Self {
            service: format!("{SERVICE}.test.{namespace}"),
        })
    }

    fn account(tenant_digest: &[u8; 32], source_digest: &[u8; 32]) -> String {
        let mut hash = Sha256::new();
        hash.update(b"evidentrail/corpus-key-account/v1\0");
        hash.update(tenant_digest);
        hash.update(source_digest);
        let mut account = String::with_capacity(64);
        for byte in hash.finalize() {
            write!(&mut account, "{byte:02x}").expect("writing to String cannot fail");
        }
        account
    }

    fn options(&self, account: &str) -> PasswordOptions {
        PasswordOptions::new_generic_password(&self.service, account)
    }

    /// Create a fresh key exactly once. The Keychain add is atomic and rejects
    /// duplicate accounts instead of overwriting an existing corpus key.
    pub fn create(
        &self,
        tenant_digest: &[u8; 32],
        source_digest: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, CorpusKeychainErrorV1> {
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *key).map_err(|_| CorpusKeychainErrorV1::Unavailable)?;
        let entry = encode(tenant_digest, source_digest, &key);
        let account = Self::account(tenant_digest, source_digest);
        let mut options = ItemAddOptions::new(ItemAddValue::Data {
            class: ItemClass::generic_password(),
            data: CFData::from_buffer(&entry),
        });
        options
            .set_service(&self.service)
            .set_account_name(account)
            .set_location(Location::DefaultFileKeychain);
        match options.add() {
            Ok(()) => Ok(key),
            Err(error) if error.code() == ERR_SEC_DUPLICATE_ITEM => {
                Err(CorpusKeychainErrorV1::AlreadyExists)
            }
            Err(_) => Err(CorpusKeychainErrorV1::Unavailable),
        }
    }

    pub fn load(
        &self,
        tenant_digest: &[u8; 32],
        source_digest: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, CorpusKeychainErrorV1> {
        let account = Self::account(tenant_digest, source_digest);
        let entry = Zeroizing::new(generic_password(self.options(&account)).map_err(|error| {
            if error.code() == ERR_SEC_ITEM_NOT_FOUND {
                CorpusKeychainErrorV1::NotFound
            } else {
                CorpusKeychainErrorV1::Unavailable
            }
        })?);
        decode(&entry, tenant_digest, source_digest)
    }

    /// Delete the key after corpus and derived-state revocation is committed.
    /// Losing this item makes remaining SQLCipher files unreadable.
    pub fn destroy(
        &self,
        tenant_digest: &[u8; 32],
        source_digest: &[u8; 32],
    ) -> Result<(), CorpusKeychainErrorV1> {
        let account = Self::account(tenant_digest, source_digest);
        delete_generic_password_options(self.options(&account)).map_err(|error| {
            if error.code() == ERR_SEC_ITEM_NOT_FOUND {
                CorpusKeychainErrorV1::NotFound
            } else {
                CorpusKeychainErrorV1::Unavailable
            }
        })
    }
}

fn encode(tenant: &[u8; 32], source: &[u8; 32], key: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    let mut entry = Zeroizing::new(Vec::with_capacity(ENTRY_LEN));
    entry.extend_from_slice(MAGIC);
    entry.extend_from_slice(tenant);
    entry.extend_from_slice(source);
    entry.extend_from_slice(key);
    entry
}

fn decode(
    entry: &[u8],
    tenant: &[u8; 32],
    source: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, CorpusKeychainErrorV1> {
    if entry.len() != ENTRY_LEN
        || &entry[..8] != MAGIC
        || &entry[8..40] != tenant
        || &entry[40..72] != source
    {
        return Err(CorpusKeychainErrorV1::ScopeMismatch);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&entry[72..]);
    if key.iter().all(|byte| *byte == 0) {
        return Err(CorpusKeychainErrorV1::ScopeMismatch);
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn entry_codec_binds_both_scopes_and_rejects_zero_key() {
        let tenant = [1; 32];
        let source = [2; 32];
        let entry = encode(&tenant, &source, &[3; 32]);
        assert_eq!(*decode(&entry, &tenant, &source).unwrap(), [3; 32]);
        assert_eq!(
            decode(&entry, &[4; 32], &source),
            Err(CorpusKeychainErrorV1::ScopeMismatch)
        );
        assert_eq!(
            decode(&encode(&tenant, &source, &[0; 32]), &tenant, &source),
            Err(CorpusKeychainErrorV1::ScopeMismatch)
        );
    }

    #[test]
    #[ignore = "requires an unlocked macOS login Keychain"]
    fn keychain_create_load_and_destroy_are_source_bound() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let authority =
            MacOsCorpusKeychainV1::isolated_for_tests(&format!("{}-{suffix}", std::process::id()))
                .unwrap();
        let tenant = [1; 32];
        let source = [2; 32];
        let created = authority.create(&tenant, &source).unwrap();
        assert_eq!(authority.load(&tenant, &source).unwrap(), created);
        assert_eq!(
            authority.create(&tenant, &source),
            Err(CorpusKeychainErrorV1::AlreadyExists)
        );
        assert_eq!(
            authority.load(&tenant, &[3; 32]),
            Err(CorpusKeychainErrorV1::NotFound)
        );
        authority.destroy(&tenant, &source).unwrap();
        assert_eq!(
            authority.load(&tenant, &source),
            Err(CorpusKeychainErrorV1::NotFound)
        );
    }
}
