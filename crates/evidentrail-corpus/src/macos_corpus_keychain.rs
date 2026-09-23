//! Persistent per-source SQLCipher keys. Keychain entries contain no log text.

use std::fmt::Write as _;

use core_foundation::data::CFData;
use security_framework::item::{
    ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, Limit, Location, SearchResult,
};
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
const BOUND_MAGIC: &[u8; 8] = b"EVCRKEY2";
const ENTRY_LEN: usize = 8 + 32 + 32 + 32;
const BOUND_HEADER_LEN: usize = ENTRY_LEN + 2;
const MAX_DESCRIPTOR_BYTES: usize = 2048;
const MAX_CONNECTED_SOURCES: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectedSourceDescriptorV1 {
    pub source_digest: [u8; 32],
    /// Non-secret, canonical provider binding; credentials must live in a
    /// separate authority. The caller parses and validates its schema.
    pub descriptor: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorpusKeychainErrorV1 {
    AlreadyExists,
    NotFound,
    ScopeMismatch,
    Unavailable,
    InvalidDescriptor,
    CapacityExceeded,
}

impl CorpusKeychainErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AlreadyExists => "EVIDENTRAIL_CORPUS_KEY_ALREADY_EXISTS",
            Self::NotFound => "EVIDENTRAIL_CORPUS_KEY_NOT_FOUND",
            Self::ScopeMismatch => "EVIDENTRAIL_CORPUS_KEY_SCOPE_MISMATCH",
            Self::Unavailable => "EVIDENTRAIL_CORPUS_KEYCHAIN_UNAVAILABLE",
            Self::InvalidDescriptor => "EVIDENTRAIL_CORPUS_INVALID_DESCRIPTOR",
            Self::CapacityExceeded => "EVIDENTRAIL_CORPUS_CONNECTION_CAPACITY_EXCEEDED",
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

    /// Deterministic identity of an immutable, non-secret provider binding.
    pub fn source_digest_for_descriptor(
        descriptor: &[u8],
    ) -> Result<[u8; 32], CorpusKeychainErrorV1> {
        if descriptor.is_empty() || descriptor.len() > MAX_DESCRIPTOR_BYTES {
            return Err(CorpusKeychainErrorV1::InvalidDescriptor);
        }
        let mut hash = Sha256::new();
        hash.update(b"evidentrail/connected-source-descriptor/v1\0");
        hash.update(descriptor);
        Ok(hash.finalize().into())
    }

    /// Register one immutable connection. The descriptor must contain no
    /// credential; provider-specific validation belongs to the caller.
    pub fn create_bound(
        &self,
        tenant_digest: &[u8; 32],
        descriptor: &[u8],
    ) -> Result<([u8; 32], Zeroizing<[u8; 32]>), CorpusKeychainErrorV1> {
        let source_digest = Self::source_digest_for_descriptor(descriptor)?;
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *key).map_err(|_| CorpusKeychainErrorV1::Unavailable)?;
        let mut entry = encode(tenant_digest, &source_digest, &key);
        entry[..8].copy_from_slice(BOUND_MAGIC);
        entry.extend_from_slice(&(descriptor.len() as u16).to_be_bytes());
        entry.extend_from_slice(descriptor);
        self.add_entry(tenant_digest, &source_digest, &entry)?;
        Ok((source_digest, key))
    }

    /// Discover connections for one tenant without returning their keys.
    /// Malformed entries fail closed; they are never silently skipped.
    pub fn list_bound(
        &self,
        tenant_digest: &[u8; 32],
    ) -> Result<Vec<ConnectedSourceDescriptorV1>, CorpusKeychainErrorV1> {
        let mut search = ItemSearchOptions::new();
        // Password searches cannot combine all matches with returned secret
        // data. Enumerate attributes, then load each exact account separately.
        search
            .class(ItemClass::generic_password())
            .service(&self.service)
            .load_attributes(true)
            .limit(Limit::All);
        let results = match search.search() {
            Ok(results) => results,
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => return Ok(Vec::new()),
            Err(_) => return Err(CorpusKeychainErrorV1::Unavailable),
        };
        if results.len() > MAX_CONNECTED_SOURCES {
            return Err(CorpusKeychainErrorV1::CapacityExceeded);
        }
        let mut connected = Vec::new();
        for result in results {
            let SearchResult::Dict(_) = result else {
                return Err(CorpusKeychainErrorV1::Unavailable);
            };
            let attributes = result
                .simplify_dict()
                .ok_or(CorpusKeychainErrorV1::Unavailable)?;
            let account = attributes
                .get("acct")
                .ok_or(CorpusKeychainErrorV1::Unavailable)?;
            if account.len() != 64 || !account.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(CorpusKeychainErrorV1::ScopeMismatch);
            }
            let entry = Zeroizing::new(
                generic_password(self.options(account))
                    .map_err(|_| CorpusKeychainErrorV1::Unavailable)?,
            );
            if entry.len() < ENTRY_LEN || &entry[..8] != BOUND_MAGIC {
                if entry.len() == ENTRY_LEN && &entry[..8] == MAGIC {
                    continue;
                }
                return Err(CorpusKeychainErrorV1::ScopeMismatch);
            }
            if &entry[8..40] != tenant_digest {
                continue;
            }
            let mut source_digest = [0u8; 32];
            source_digest.copy_from_slice(&entry[40..72]);
            if *account != Self::account(tenant_digest, &source_digest) {
                return Err(CorpusKeychainErrorV1::ScopeMismatch);
            }
            let descriptor = decode_bound_descriptor(&entry, tenant_digest, &source_digest)?;
            connected.push(ConnectedSourceDescriptorV1 {
                source_digest,
                descriptor: descriptor.to_vec(),
            });
        }
        connected.sort_by(|left, right| left.source_digest.cmp(&right.source_digest));
        if connected
            .windows(2)
            .any(|pair| pair[0].source_digest == pair[1].source_digest)
        {
            return Err(CorpusKeychainErrorV1::ScopeMismatch);
        }
        Ok(connected)
    }

    fn add_entry(
        &self,
        tenant_digest: &[u8; 32],
        source_digest: &[u8; 32],
        entry: &[u8],
    ) -> Result<(), CorpusKeychainErrorV1> {
        let account = Self::account(tenant_digest, source_digest);
        let mut options = ItemAddOptions::new(ItemAddValue::Data {
            class: ItemClass::generic_password(),
            data: CFData::from_buffer(entry),
        });
        options
            .set_service(&self.service)
            .set_account_name(account)
            .set_location(Location::DefaultFileKeychain);
        match options.add() {
            Ok(()) => Ok(()),
            Err(error) if error.code() == ERR_SEC_DUPLICATE_ITEM => {
                Err(CorpusKeychainErrorV1::AlreadyExists)
            }
            Err(_) => Err(CorpusKeychainErrorV1::Unavailable),
        }
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
        self.add_entry(tenant_digest, source_digest, &entry)?;
        Ok(key)
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
    if entry.len() != ENTRY_LEN && (entry.len() < BOUND_HEADER_LEN || &entry[..8] != BOUND_MAGIC) {
        return Err(CorpusKeychainErrorV1::ScopeMismatch);
    }
    if !(&entry[..8] == MAGIC || &entry[..8] == BOUND_MAGIC)
        || &entry[8..40] != tenant
        || &entry[40..72] != source
    {
        return Err(CorpusKeychainErrorV1::ScopeMismatch);
    }
    if &entry[..8] == BOUND_MAGIC {
        decode_bound_descriptor(entry, tenant, source)?;
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&entry[72..104]);
    if key.iter().all(|byte| *byte == 0) {
        return Err(CorpusKeychainErrorV1::ScopeMismatch);
    }
    Ok(key)
}

fn decode_bound_descriptor<'a>(
    entry: &'a [u8],
    tenant: &[u8; 32],
    source: &[u8; 32],
) -> Result<&'a [u8], CorpusKeychainErrorV1> {
    if entry.len() < BOUND_HEADER_LEN
        || &entry[..8] != BOUND_MAGIC
        || &entry[8..40] != tenant
        || &entry[40..72] != source
    {
        return Err(CorpusKeychainErrorV1::ScopeMismatch);
    }
    let len = u16::from_be_bytes([entry[104], entry[105]]) as usize;
    if len == 0 || len > MAX_DESCRIPTOR_BYTES || entry.len() != BOUND_HEADER_LEN + len {
        return Err(CorpusKeychainErrorV1::InvalidDescriptor);
    }
    let descriptor = &entry[BOUND_HEADER_LEN..];
    if MacOsCorpusKeychainV1::source_digest_for_descriptor(descriptor)? != *source {
        return Err(CorpusKeychainErrorV1::ScopeMismatch);
    }
    Ok(descriptor)
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
    fn bound_descriptor_identity_is_stable_and_checked_on_load() {
        let tenant = [1; 32];
        let descriptor = b"cloudwatch:account:region:group";
        let source = MacOsCorpusKeychainV1::source_digest_for_descriptor(descriptor).unwrap();
        let mut entry = encode(&tenant, &source, &[9; 32]);
        entry[..8].copy_from_slice(BOUND_MAGIC);
        entry.extend_from_slice(&(descriptor.len() as u16).to_be_bytes());
        entry.extend_from_slice(descriptor);
        assert_eq!(*decode(&entry, &tenant, &source).unwrap(), [9; 32]);
        entry[BOUND_HEADER_LEN] ^= 1;
        assert_eq!(
            decode(&entry, &tenant, &source),
            Err(CorpusKeychainErrorV1::ScopeMismatch)
        );
        assert_eq!(
            MacOsCorpusKeychainV1::source_digest_for_descriptor(&[]),
            Err(CorpusKeychainErrorV1::InvalidDescriptor)
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

        let descriptor = b"cloudwatch:account:region:group";
        let (bound_source, bound_key) = authority.create_bound(&tenant, descriptor).unwrap();
        assert_eq!(authority.load(&tenant, &bound_source).unwrap(), bound_key);
        assert_eq!(
            authority.list_bound(&tenant).unwrap(),
            vec![ConnectedSourceDescriptorV1 {
                source_digest: bound_source,
                descriptor: descriptor.to_vec(),
            }]
        );
        assert!(authority.list_bound(&[5; 32]).unwrap().is_empty());
        authority.destroy(&tenant, &bound_source).unwrap();
        assert!(authority.list_bound(&tenant).unwrap().is_empty());
    }
}
