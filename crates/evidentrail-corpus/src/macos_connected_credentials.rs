//! Opaque provider credentials bound to one local tenant and connected source.
//! Separate from the corpus-key service so listing sources never returns secrets.

use std::fmt::Write as _;

use core_foundation::data::CFData;
use security_framework::item::{
    ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, ItemUpdateOptions, ItemUpdateValue,
    Location, update_item,
};
use security_framework::passwords::{
    PasswordOptions, delete_generic_password_options, generic_password,
};
use security_framework_sys::base::{
    errSecDuplicateItem as ERR_SEC_DUPLICATE_ITEM, errSecItemNotFound as ERR_SEC_ITEM_NOT_FOUND,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::CorpusKeychainErrorV1;

const SERVICE: &str = "ai.evidentrail.connected-credential.login.v1";
const MAGIC: &[u8; 8] = b"EVCRSEC1";
const HEADER_LEN: usize = 8 + 32 + 32 + 2;
const MAX_SECRET_BYTES: usize = 4096;

pub struct MacOsConnectedCredentialKeychainV1 {
    service: String,
}

impl MacOsConnectedCredentialKeychainV1 {
    #[must_use]
    pub fn production() -> Self {
        Self {
            service: SERVICE.to_owned(),
        }
    }

    #[doc(hidden)]
    pub fn isolated_for_tests(namespace: &str) -> Result<Self, CorpusKeychainErrorV1> {
        if namespace.is_empty() || namespace.len() > 96 || !namespace.is_ascii() {
            return Err(CorpusKeychainErrorV1::Unavailable);
        }
        Ok(Self {
            service: format!("{SERVICE}.test.{namespace}"),
        })
    }

    fn account(tenant: &[u8; 32], source: &[u8; 32]) -> String {
        let mut hash = Sha256::new();
        hash.update(b"evidentrail/connected-credential-account/v1\0");
        hash.update(tenant);
        hash.update(source);
        let mut account = String::with_capacity(64);
        for byte in hash.finalize() {
            write!(&mut account, "{byte:02x}").expect("writing to String cannot fail");
        }
        account
    }

    fn options(&self, account: &str) -> PasswordOptions {
        PasswordOptions::new_generic_password(&self.service, account)
    }

    /// Add once. The caller must validate the provider credential format and
    /// verify read access before registration. Never put the secret in argv.
    pub fn create(
        &self,
        tenant: &[u8; 32],
        source: &[u8; 32],
        secret: &[u8],
    ) -> Result<(), CorpusKeychainErrorV1> {
        let entry = encode(tenant, source, secret)?;
        let mut options = ItemAddOptions::new(ItemAddValue::Data {
            class: ItemClass::generic_password(),
            data: CFData::from_buffer(&entry),
        });
        options
            .set_service(&self.service)
            .set_account_name(Self::account(tenant, source))
            .set_location(Location::DefaultFileKeychain);
        match options.add() {
            Ok(()) => Ok(()),
            Err(error) if error.code() == ERR_SEC_DUPLICATE_ITEM => {
                Err(CorpusKeychainErrorV1::AlreadyExists)
            }
            Err(_) => Err(CorpusKeychainErrorV1::Unavailable),
        }
    }

    /// Load only the exact tenant/source binding. Returned bytes are wiped on
    /// drop by the caller's `Zeroizing` wrapper.
    pub fn load(
        &self,
        tenant: &[u8; 32],
        source: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, CorpusKeychainErrorV1> {
        let account = Self::account(tenant, source);
        let entry = Zeroizing::new(generic_password(self.options(&account)).map_err(|error| {
            if error.code() == ERR_SEC_ITEM_NOT_FOUND {
                CorpusKeychainErrorV1::NotFound
            } else {
                CorpusKeychainErrorV1::Unavailable
            }
        })?);
        decode(&entry, tenant, source)
    }

    /// Atomically replace an existing source-bound item. Refuse a missing or
    /// corrupted item rather than silently registering a new credential.
    pub fn replace(
        &self,
        tenant: &[u8; 32],
        source: &[u8; 32],
        secret: &[u8],
    ) -> Result<(), CorpusKeychainErrorV1> {
        let _prior = self.load(tenant, source)?;
        let entry = encode(tenant, source, secret)?;
        let account = Self::account(tenant, source);
        let mut search = ItemSearchOptions::new();
        search
            .class(ItemClass::generic_password())
            .service(&self.service)
            .account(&account);
        let mut update = ItemUpdateOptions::new();
        update.set_value(ItemUpdateValue::Data(CFData::from_buffer(&entry)));
        update_item(&search, &update).map_err(|error| {
            if error.code() == ERR_SEC_ITEM_NOT_FOUND {
                CorpusKeychainErrorV1::NotFound
            } else {
                CorpusKeychainErrorV1::Unavailable
            }
        })?;
        if self.load(tenant, source)?.as_slice() != secret {
            return Err(CorpusKeychainErrorV1::Unavailable);
        }
        Ok(())
    }

    pub fn destroy(
        &self,
        tenant: &[u8; 32],
        source: &[u8; 32],
    ) -> Result<(), CorpusKeychainErrorV1> {
        let account = Self::account(tenant, source);
        delete_generic_password_options(self.options(&account)).map_err(|error| {
            if error.code() == ERR_SEC_ITEM_NOT_FOUND {
                CorpusKeychainErrorV1::NotFound
            } else {
                CorpusKeychainErrorV1::Unavailable
            }
        })
    }
}

fn encode(
    tenant: &[u8; 32],
    source: &[u8; 32],
    secret: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CorpusKeychainErrorV1> {
    if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
        return Err(CorpusKeychainErrorV1::InvalidDescriptor);
    }
    let mut entry = Zeroizing::new(Vec::with_capacity(HEADER_LEN + secret.len()));
    entry.extend_from_slice(MAGIC);
    entry.extend_from_slice(tenant);
    entry.extend_from_slice(source);
    entry.extend_from_slice(&(secret.len() as u16).to_be_bytes());
    entry.extend_from_slice(secret);
    Ok(entry)
}

fn decode(
    entry: &[u8],
    tenant: &[u8; 32],
    source: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, CorpusKeychainErrorV1> {
    if entry.len() < HEADER_LEN
        || &entry[..8] != MAGIC
        || &entry[8..40] != tenant
        || &entry[40..72] != source
    {
        return Err(CorpusKeychainErrorV1::ScopeMismatch);
    }
    let length = u16::from_be_bytes([entry[72], entry[73]]) as usize;
    if length == 0 || length > MAX_SECRET_BYTES || entry.len() != HEADER_LEN + length {
        return Err(CorpusKeychainErrorV1::ScopeMismatch);
    }
    Ok(Zeroizing::new(entry[HEADER_LEN..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_encoding_is_source_bound_and_strictly_bounded() {
        let tenant = [1; 32];
        let source = [2; 32];
        let mut encoded = encode(&tenant, &source, b"api:app").unwrap();
        assert_eq!(&*decode(&encoded, &tenant, &source).unwrap(), b"api:app");
        assert_eq!(
            decode(&encoded, &tenant, &[3; 32]),
            Err(CorpusKeychainErrorV1::ScopeMismatch)
        );
        encoded.push(0);
        assert_eq!(
            decode(&encoded, &tenant, &source),
            Err(CorpusKeychainErrorV1::ScopeMismatch)
        );
        assert!(encode(&tenant, &source, &[]).is_err());
        assert!(encode(&tenant, &source, &[1; MAX_SECRET_BYTES + 1]).is_err());
    }

    #[test]
    #[ignore = "requires an unlocked macOS login Keychain"]
    fn keychain_create_load_revoke_is_tenant_and_source_bound() {
        let authority = MacOsConnectedCredentialKeychainV1::isolated_for_tests(&format!(
            "{}-provider-secret",
            std::process::id()
        ))
        .unwrap();
        let tenant = [4; 32];
        let source = [5; 32];
        authority
            .create(&tenant, &source, b"private-api:private-app")
            .unwrap();
        assert_eq!(
            &*authority.load(&tenant, &source).unwrap(),
            b"private-api:private-app"
        );
        assert!(authority.load(&tenant, &[6; 32]).is_err());
        assert!(authority.create(&tenant, &source, b"replacement").is_err());
        authority.replace(&tenant, &source, b"replacement").unwrap();
        assert_eq!(&*authority.load(&tenant, &source).unwrap(), b"replacement");
        authority.destroy(&tenant, &source).unwrap();
        assert!(authority.load(&tenant, &source).is_err());
        assert_eq!(
            authority.replace(&tenant, &source, b"again"),
            Err(CorpusKeychainErrorV1::NotFound)
        );
    }
}
