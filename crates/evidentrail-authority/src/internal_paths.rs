use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fmt;
use std::sync::{RwLock, RwLockReadGuard};

use evidentrail_schema::{
    InternalPathPolicyDigest, UnixFileObjectIdV1, UnixLocalFileLocatorV1,
    bounds::{
        MAX_UNIX_LOCAL_FILE_COMPONENT_BYTES, MAX_UNIX_LOCAL_FILE_COMPONENTS,
        MAX_UNIX_LOCAL_FILE_LOCATOR_BYTES,
    },
};
use sha2::{Digest, Sha256};

/// Domain for the deterministic configured-root/alias policy digest.
pub const INTERNAL_PATH_POLICY_DIGEST_DOMAIN_V1: &str = "evidentrail/internal-path-policy/v1";
/// Maximum configured reserved roots plus aliases in V1.
pub const MAX_INTERNAL_PATH_PREFIXES_V1: usize = 1_024;
/// Maximum aggregate configured path bytes in V1.
pub const MAX_INTERNAL_PATH_POLICY_BYTES_V1: usize = 4 * 1024 * 1024;

const INTERNAL_PATH_POLICY_VERSION_V1: u16 = 1;

/// Canonical absolute Unix byte path used only as internal-path policy input.
///
/// It is component parsed at construction so prefix checks cannot confuse
/// `/internal` with `/internal-other`. The raw bytes are intentionally not
/// exposed through formatting. Construction checks only the byte
/// representation; application initialization must supply a path obtained from
/// the supported filesystem canonicalization boundary.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CanonicalUnixPathV1 {
    bytes: Vec<u8>,
    components: Vec<Vec<u8>>,
}

impl CanonicalUnixPathV1 {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, CanonicalUnixPathConstructionError> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(CanonicalUnixPathConstructionError::Empty);
        }
        if bytes.len() > MAX_UNIX_LOCAL_FILE_LOCATOR_BYTES {
            return Err(CanonicalUnixPathConstructionError::TooLong);
        }
        if bytes[0] != b'/' {
            return Err(CanonicalUnixPathConstructionError::NotAbsolute);
        }
        if bytes.contains(&0) {
            return Err(CanonicalUnixPathConstructionError::ContainsNul);
        }
        if bytes.len() > 1 && bytes.ends_with(b"/") {
            return Err(CanonicalUnixPathConstructionError::TrailingSeparator);
        }
        if bytes.windows(2).any(|pair| pair == b"//") {
            return Err(CanonicalUnixPathConstructionError::DuplicateSeparator);
        }

        let mut components = Vec::new();
        if bytes != b"/" {
            for component in bytes[1..].split(|byte| *byte == b'/') {
                if components.len() == MAX_UNIX_LOCAL_FILE_COMPONENTS {
                    return Err(CanonicalUnixPathConstructionError::TooManyComponents);
                }
                if component == b"." {
                    return Err(CanonicalUnixPathConstructionError::DotComponent);
                }
                if component == b".." {
                    return Err(CanonicalUnixPathConstructionError::DotDotComponent);
                }
                if component.len() > MAX_UNIX_LOCAL_FILE_COMPONENT_BYTES {
                    return Err(CanonicalUnixPathConstructionError::ComponentTooLong);
                }
                components.push(component.to_vec());
            }
        }

        Ok(Self { bytes, components })
    }

    fn is_prefix_of_locator(&self, locator: &UnixLocalFileLocatorV1) -> bool {
        if self.components.is_empty() {
            return true;
        }
        let mut candidate = Vec::new();
        if locator.root() != b"/" {
            candidate.extend(locator.root()[1..].split(|byte| *byte == b'/'));
        }
        candidate.extend(locator.relative_components().iter().map(Vec::as_slice));
        self.components.len() <= candidate.len()
            && self
                .components
                .iter()
                .map(Vec::as_slice)
                .zip(candidate)
                .all(|(reserved, candidate)| reserved == candidate)
    }
}

impl fmt::Debug for CanonicalUnixPathV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalUnixPathV1")
            .field("path_present", &true)
            .finish()
    }
}

/// Invalid canonical internal path configuration.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CanonicalUnixPathConstructionError {
    Empty,
    TooLong,
    NotAbsolute,
    ContainsNul,
    TrailingSeparator,
    DuplicateSeparator,
    TooManyComponents,
    DotComponent,
    DotDotComponent,
    ComponentTooLong,
}

impl CanonicalUnixPathConstructionError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Empty => "EVIDENTRAIL_INTERNAL_PATH_EMPTY",
            Self::TooLong => "EVIDENTRAIL_INTERNAL_PATH_TOO_LONG",
            Self::NotAbsolute => "EVIDENTRAIL_INTERNAL_PATH_NOT_ABSOLUTE",
            Self::ContainsNul => "EVIDENTRAIL_INTERNAL_PATH_CONTAINS_NUL",
            Self::TrailingSeparator => "EVIDENTRAIL_INTERNAL_PATH_TRAILING_SEPARATOR",
            Self::DuplicateSeparator => "EVIDENTRAIL_INTERNAL_PATH_DUPLICATE_SEPARATOR",
            Self::TooManyComponents => "EVIDENTRAIL_INTERNAL_PATH_TOO_MANY_COMPONENTS",
            Self::DotComponent => "EVIDENTRAIL_INTERNAL_PATH_DOT_COMPONENT",
            Self::DotDotComponent => "EVIDENTRAIL_INTERNAL_PATH_DOT_DOT_COMPONENT",
            Self::ComponentTooLong => "EVIDENTRAIL_INTERNAL_PATH_COMPONENT_TOO_LONG",
        }
    }
}

impl fmt::Debug for CanonicalUnixPathConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalUnixPathConstructionError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for CanonicalUnixPathConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for CanonicalUnixPathConstructionError {}

/// Immutable internal-path configuration. Dynamic file identities are
/// deliberately not part of this value or its digest.
#[derive(Clone, PartialEq, Eq)]
pub struct InternalPathPolicyV1 {
    reserved_roots: Vec<CanonicalUnixPathV1>,
    reserved_aliases: Vec<CanonicalUnixPathV1>,
    digest: InternalPathPolicyDigest,
}

impl InternalPathPolicyV1 {
    pub fn new<R, A>(
        reserved_roots: R,
        reserved_aliases: A,
    ) -> Result<Self, InternalPathPolicyConstructionError>
    where
        R: IntoIterator<Item = CanonicalUnixPathV1>,
        A: IntoIterator<Item = CanonicalUnixPathV1>,
    {
        let mut reserved_roots = collect_bounded_paths(reserved_roots)?;
        let mut reserved_aliases = collect_bounded_paths(reserved_aliases)?;
        if reserved_roots.len() + reserved_aliases.len() > MAX_INTERNAL_PATH_PREFIXES_V1 {
            return Err(InternalPathPolicyConstructionError::TooManyPaths);
        }
        let total_bytes = reserved_roots
            .iter()
            .chain(&reserved_aliases)
            .try_fold(0_usize, |total, path| total.checked_add(path.bytes.len()))
            .ok_or(InternalPathPolicyConstructionError::PolicyTooLarge)?;
        if total_bytes > MAX_INTERNAL_PATH_POLICY_BYTES_V1 {
            return Err(InternalPathPolicyConstructionError::PolicyTooLarge);
        }
        if reserved_roots.is_empty() && reserved_aliases.is_empty() {
            return Err(InternalPathPolicyConstructionError::EmptyPolicy);
        }

        reserved_roots.sort();
        reserved_aliases.sort();
        if contains_duplicate(&reserved_roots)
            || contains_duplicate(&reserved_aliases)
            || reserved_roots
                .iter()
                .any(|root| reserved_aliases.binary_search(root).is_ok())
        {
            return Err(InternalPathPolicyConstructionError::DuplicatePath);
        }

        let digest = derive_policy_digest(&reserved_roots, &reserved_aliases);
        Ok(Self {
            reserved_roots,
            reserved_aliases,
            digest,
        })
    }

    #[must_use]
    pub const fn digest(&self) -> InternalPathPolicyDigest {
        self.digest
    }

    fn rejects_locator(&self, locator: &UnixLocalFileLocatorV1) -> bool {
        self.reserved_roots
            .iter()
            .chain(&self.reserved_aliases)
            .any(|reserved| reserved.is_prefix_of_locator(locator))
    }
}

impl fmt::Debug for InternalPathPolicyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InternalPathPolicyV1")
            .field("reserved_roots_present", &!self.reserved_roots.is_empty())
            .field(
                "reserved_aliases_present",
                &!self.reserved_aliases.is_empty(),
            )
            .field("policy_digest_present", &true)
            .finish()
    }
}

fn collect_bounded_paths<I>(
    paths: I,
) -> Result<Vec<CanonicalUnixPathV1>, InternalPathPolicyConstructionError>
where
    I: IntoIterator<Item = CanonicalUnixPathV1>,
{
    let mut collected = Vec::new();
    for path in paths {
        if collected.len() == MAX_INTERNAL_PATH_PREFIXES_V1 {
            return Err(InternalPathPolicyConstructionError::TooManyPaths);
        }
        collected.push(path);
    }
    Ok(collected)
}

fn contains_duplicate(paths: &[CanonicalUnixPathV1]) -> bool {
    paths.windows(2).any(|pair| pair[0] == pair[1])
}

fn derive_policy_digest(
    roots: &[CanonicalUnixPathV1],
    aliases: &[CanonicalUnixPathV1],
) -> InternalPathPolicyDigest {
    let mut body = Vec::new();
    body.extend_from_slice(&INTERNAL_PATH_POLICY_VERSION_V1.to_le_bytes());
    append_paths(&mut body, roots);
    append_paths(&mut body, aliases);

    let domain = INTERNAL_PATH_POLICY_DIGEST_DOMAIN_V1.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    hasher.update((body.len() as u64).to_le_bytes());
    hasher.update(body);
    InternalPathPolicyDigest::from_bytes(hasher.finalize().into())
}

fn append_paths(body: &mut Vec<u8>, paths: &[CanonicalUnixPathV1]) {
    body.extend_from_slice(&(paths.len() as u64).to_le_bytes());
    for path in paths {
        body.extend_from_slice(&(path.bytes.len() as u64).to_le_bytes());
        body.extend_from_slice(&path.bytes);
    }
}

/// Invalid internal-path policy configuration.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InternalPathPolicyConstructionError {
    EmptyPolicy,
    TooManyPaths,
    PolicyTooLarge,
    DuplicatePath,
}

impl InternalPathPolicyConstructionError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyPolicy => "EVIDENTRAIL_INTERNAL_PATH_POLICY_EMPTY",
            Self::TooManyPaths => "EVIDENTRAIL_INTERNAL_PATH_POLICY_TOO_MANY_PATHS",
            Self::PolicyTooLarge => "EVIDENTRAIL_INTERNAL_PATH_POLICY_TOO_LARGE",
            Self::DuplicatePath => "EVIDENTRAIL_INTERNAL_PATH_POLICY_DUPLICATE_PATH",
        }
    }
}

impl fmt::Debug for InternalPathPolicyConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InternalPathPolicyConstructionError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for InternalPathPolicyConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for InternalPathPolicyConstructionError {}

/// Mutable memory-only registry for configured exclusions and active internal
/// Unix object identities.
pub struct InternalPathRegistryV1 {
    state: RwLock<InternalPathRegistryState>,
}

impl InternalPathRegistryV1 {
    #[must_use]
    pub fn new(policy: InternalPathPolicyV1) -> Self {
        Self {
            state: RwLock::new(InternalPathRegistryState {
                policy,
                active_identities: BTreeMap::new(),
            }),
        }
    }

    /// Atomically replace configured roots and aliases without changing active
    /// identities. This blocks while any read lease exists.
    pub fn replace_policy(
        &self,
        policy: InternalPathPolicyV1,
    ) -> Result<(), InternalPathRegistryError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| InternalPathRegistryError::StateUnavailable)?;
        state.policy = policy;
        Ok(())
    }

    /// Register an internal object identity before publishing or using it.
    pub fn register_active_identity(
        &self,
        identity: UnixFileObjectIdV1,
    ) -> Result<(), InternalPathRegistryError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| InternalPathRegistryError::StateUnavailable)?;
        let registration_count = state.active_identities.entry(identity).or_insert(0);
        *registration_count = registration_count
            .checked_add(1)
            .ok_or(InternalPathRegistryError::IdentityRegistrationOverflow)?;
        Ok(())
    }

    /// Unregister only after the internal object has been unlinked.
    pub fn unregister_active_identity(
        &self,
        identity: UnixFileObjectIdV1,
    ) -> Result<(), InternalPathRegistryError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| InternalPathRegistryError::StateUnavailable)?;
        let registration_count = state
            .active_identities
            .get_mut(&identity)
            .ok_or(InternalPathRegistryError::IdentityNotRegistered)?;
        if *registration_count == 1 {
            state.active_identities.remove(&identity);
        } else {
            *registration_count -= 1;
        }
        Ok(())
    }

    /// Acquire a policy lease after atomically checking the expected digest and
    /// canonical candidate path.
    ///
    /// The caller must retain this lease across open and `fstat`, then call
    /// [`InternalPathReadLeaseV1::check_opened_identity`]. That sequence makes
    /// path and hard-link checks atomic with respect to policy/identity updates.
    pub fn read_lease_for_locator(
        &self,
        locator: &UnixLocalFileLocatorV1,
        expected_policy_digest: InternalPathPolicyDigest,
    ) -> Result<InternalPathReadLeaseV1<'_>, InternalPathRegistryError> {
        let guard = self
            .state
            .read()
            .map_err(|_| InternalPathRegistryError::StateUnavailable)?;
        if guard.policy.digest() != expected_policy_digest {
            return Err(InternalPathRegistryError::PolicyDigestMismatch);
        }
        if guard.policy.rejects_locator(locator) {
            return Err(InternalPathRegistryError::CanonicalPathReserved);
        }
        Ok(InternalPathReadLeaseV1 { guard })
    }
}

impl fmt::Debug for InternalPathRegistryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InternalPathRegistryV1")
            .field("state_present", &true)
            .finish()
    }
}

struct InternalPathRegistryState {
    policy: InternalPathPolicyV1,
    active_identities: BTreeMap<UnixFileObjectIdV1, usize>,
}

/// Read lease keeping canonical-path and opened-identity exclusions atomic
/// against registry updates.
pub struct InternalPathReadLeaseV1<'registry> {
    guard: RwLockReadGuard<'registry, InternalPathRegistryState>,
}

impl InternalPathReadLeaseV1<'_> {
    #[must_use]
    pub fn policy_digest(&self) -> InternalPathPolicyDigest {
        self.guard.policy.digest()
    }

    pub fn check_opened_identity(
        &self,
        identity: UnixFileObjectIdV1,
    ) -> Result<(), InternalPathRegistryError> {
        if self.guard.active_identities.contains_key(&identity) {
            return Err(InternalPathRegistryError::OpenedIdentityReserved);
        }
        Ok(())
    }
}

impl fmt::Debug for InternalPathReadLeaseV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InternalPathReadLeaseV1")
            .field("policy_digest_present", &true)
            .finish()
    }
}

/// Contentless internal-path registry failures.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InternalPathRegistryError {
    StateUnavailable,
    PolicyDigestMismatch,
    CanonicalPathReserved,
    OpenedIdentityReserved,
    IdentityRegistrationOverflow,
    IdentityNotRegistered,
}

impl InternalPathRegistryError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::StateUnavailable => "EVIDENTRAIL_INTERNAL_PATH_REGISTRY_STATE_UNAVAILABLE",
            Self::PolicyDigestMismatch => "EVIDENTRAIL_INTERNAL_PATH_REGISTRY_POLICY_MISMATCH",
            Self::CanonicalPathReserved => "EVIDENTRAIL_INTERNAL_PATH_REGISTRY_PATH_RESERVED",
            Self::OpenedIdentityReserved => "EVIDENTRAIL_INTERNAL_PATH_REGISTRY_IDENTITY_RESERVED",
            Self::IdentityRegistrationOverflow => {
                "EVIDENTRAIL_INTERNAL_PATH_REGISTRY_IDENTITY_REGISTRATION_OVERFLOW"
            }
            Self::IdentityNotRegistered => "EVIDENTRAIL_INTERNAL_PATH_REGISTRY_IDENTITY_NOT_REGISTERED",
        }
    }
}

impl fmt::Debug for InternalPathRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InternalPathRegistryError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for InternalPathRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for InternalPathRegistryError {}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::*;

    fn policy() -> InternalPathPolicyV1 {
        InternalPathPolicyV1::new(
            [CanonicalUnixPathV1::new(b"/internal".to_vec()).unwrap()],
            [],
        )
        .unwrap()
    }

    #[test]
    fn poisoned_state_fails_closed() {
        let registry = InternalPathRegistryV1::new(policy());
        let digest = policy().digest();
        let locator =
            UnixLocalFileLocatorV1::new(b"/external".to_vec(), [b"log".to_vec()]).unwrap();
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _guard = registry.state.write().unwrap();
            panic!("poison registry for test");
        }));

        assert_eq!(
            registry
                .read_lease_for_locator(&locator, digest)
                .unwrap_err(),
            InternalPathRegistryError::StateUnavailable
        );
    }
}
