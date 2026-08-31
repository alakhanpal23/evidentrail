use std::error::Error as StdError;
use std::fmt;
use std::path::Path;

#[cfg(target_os = "macos")]
use evidentrail_authority::InternalPathRegistryError;
use evidentrail_authority::InternalPathRegistryV1;
use evidentrail_schema::{InternalPathPolicyDigest, UnixFileSnapshotV1};

/// Stable V1 capability advertised by a successful metadata-only probe.
pub const LOCAL_FILE_METADATA_CAPABILITY_CODE_V1: &str =
    "EVIDENTRAIL_LOCAL_DISCOVERY_EXPLICIT_SINGLE_REGULAR_FILE_METADATA_ONLY_V1";
/// Stable statement that discovery performed no content acquisition.
pub const LOCAL_FILE_CONTENT_NOT_READ_CODE_V1: &str =
    "EVIDENTRAIL_LOCAL_DISCOVERY_CONTENT_NOT_READ";
/// Stable statement that discovery conferred no source authority.
pub const LOCAL_FILE_AUTHORIZATION_NOT_GRANTED_CODE_V1: &str =
    "EVIDENTRAIL_LOCAL_DISCOVERY_AUTHORIZATION_NOT_GRANTED";
/// Stable statement that discovery minted no host certification.
pub const LOCAL_FILE_CERTIFICATION_NOT_GRANTED_CODE_V1: &str =
    "EVIDENTRAIL_LOCAL_DISCOVERY_CERTIFICATION_NOT_GRANTED";

/// Metadata-only observation for one explicit regular-file candidate.
///
/// The snapshot is sensitive local metadata, not authority. This value has no
/// locator, read method, descriptor, binding, plan, certification, or
/// execution conversion. A later approval flow must independently construct
/// and verify all of those contracts.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LocalFileMetadataDiscoveryV1 {
    snapshot: UnixFileSnapshotV1,
}

impl LocalFileMetadataDiscoveryV1 {
    #[must_use]
    pub const fn snapshot(self) -> UnixFileSnapshotV1 {
        self.snapshot
    }

    #[must_use]
    pub const fn capability_code(self) -> &'static str {
        LOCAL_FILE_METADATA_CAPABILITY_CODE_V1
    }

    #[must_use]
    pub const fn content_access_code(self) -> &'static str {
        LOCAL_FILE_CONTENT_NOT_READ_CODE_V1
    }

    #[must_use]
    pub const fn authorization_code(self) -> &'static str {
        LOCAL_FILE_AUTHORIZATION_NOT_GRANTED_CODE_V1
    }

    #[must_use]
    pub const fn certification_code(self) -> &'static str {
        LOCAL_FILE_CERTIFICATION_NOT_GRANTED_CODE_V1
    }

    #[must_use]
    pub const fn content_was_read(self) -> bool {
        false
    }

    #[must_use]
    pub const fn authorization_granted(self) -> bool {
        false
    }

    #[must_use]
    pub const fn host_certification_granted(self) -> bool {
        false
    }
}

impl fmt::Debug for LocalFileMetadataDiscoveryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalFileMetadataDiscoveryV1")
            .field("capability_code", &self.capability_code())
            .field("metadata_snapshot_present", &true)
            .field("content_read", &false)
            .field("authorization_granted", &false)
            .field("host_certification_granted", &false)
            .finish()
    }
}

/// Inspect metadata for one explicit local-file candidate without reading it.
///
/// The caller-owned internal-path registry lease is held across two
/// descriptor-relative metadata observations. Canonical reserved roots and
/// registered active internal file identities therefore fail before success.
/// This function does not invoke the host-certification authority and cannot
/// produce a binding, plan, authorization, executable token, or completion.
pub fn discover_local_file_metadata_v1(
    path: &Path,
    internal_paths: &InternalPathRegistryV1,
    expected_internal_policy_digest: InternalPathPolicyDigest,
) -> Result<LocalFileMetadataDiscoveryV1, LocalFileDiscoveryError> {
    discover_local_file_metadata_on_supported_platform_v1(
        path,
        internal_paths,
        expected_internal_policy_digest,
    )
}

#[cfg(target_os = "macos")]
fn discover_local_file_metadata_on_supported_platform_v1(
    path: &Path,
    internal_paths: &InternalPathRegistryV1,
    expected_internal_policy_digest: InternalPathPolicyDigest,
) -> Result<LocalFileMetadataDiscoveryV1, LocalFileDiscoveryError> {
    use std::path::Component;

    use evidentrail_schema::UnixLocalFileLocatorV1;
    use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};

    if !cfg!(any(target_arch = "aarch64", target_arch = "x86_64")) {
        return Err(LocalFileDiscoveryError::UnsupportedArchitecture);
    }

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| LocalFileDiscoveryError::CurrentDirectoryUnavailable)?
            .join(path)
    };
    let mut components = Vec::new();
    let mut rooted = false;
    for component in absolute.components() {
        match component {
            Component::RootDir => {
                rooted = true;
                components.clear();
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if components.pop().is_none() {
                    return Err(LocalFileDiscoveryError::InvalidPath);
                }
            }
            Component::Normal(component) => {
                use std::os::unix::ffi::OsStrExt as _;
                components.push(component.as_bytes().to_vec());
            }
            Component::Prefix(_) => return Err(LocalFileDiscoveryError::InvalidPath),
        }
    }
    if !rooted || components.is_empty() {
        return Err(LocalFileDiscoveryError::InvalidPath);
    }
    let locator = UnixLocalFileLocatorV1::new(b"/".to_vec(), components.clone())
        .map_err(|_| LocalFileDiscoveryError::InvalidPath)?;
    let internal_lease = internal_paths
        .read_lease_for_locator(&locator, expected_internal_policy_digest)
        .map_err(map_internal_path_error)?;

    fn observe(components: &[Vec<u8>]) -> Result<UnixFileSnapshotV1, LocalFileDiscoveryError> {
        let mut parent_fd = fs::open(
            b"/".as_slice(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| LocalFileDiscoveryError::RootOpenFailed)?;
        for component in &components[..components.len() - 1] {
            let metadata = fs::statat(&parent_fd, component.as_slice(), AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| LocalFileDiscoveryError::MetadataUnavailable)?;
            match FileType::from_raw_mode(metadata.st_mode) {
                FileType::Symlink => return Err(LocalFileDiscoveryError::SymlinkRejected),
                FileType::Directory => {}
                _ => return Err(LocalFileDiscoveryError::IntermediateNotDirectory),
            }
            parent_fd = fs::openat(
                &parent_fd,
                component.as_slice(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| LocalFileDiscoveryError::ComponentOpenFailed)?;
        }

        let final_component = components
            .last()
            .ok_or(LocalFileDiscoveryError::InvalidPath)?;
        let file_stat = fs::statat(
            &parent_fd,
            final_component.as_slice(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| LocalFileDiscoveryError::MetadataUnavailable)?;
        match FileType::from_raw_mode(file_stat.st_mode) {
            FileType::Symlink => return Err(LocalFileDiscoveryError::SymlinkRejected),
            FileType::RegularFile => {}
            _ => return Err(LocalFileDiscoveryError::FinalObjectNotRegular),
        }
        let parent_stat =
            fs::fstat(&parent_fd).map_err(|_| LocalFileDiscoveryError::MetadataUnavailable)?;
        let filesystem =
            fs::fstatfs(&parent_fd).map_err(|_| LocalFileDiscoveryError::FilesystemUnavailable)?;
        if crate::preflight::observed_filesystem(&filesystem)
            != crate::preflight::ObservedFilesystemV1::Apfs
        {
            return Err(LocalFileDiscoveryError::UnsupportedFilesystem);
        }
        crate::preflight::snapshot_from_stats(&parent_stat, &file_stat)
            .map_err(|_| LocalFileDiscoveryError::MetadataOutOfRange)
    }

    let first = observe(&components)?;
    internal_lease
        .check_opened_identity(first.file())
        .map_err(map_internal_path_error)?;
    let second = observe(&components)?;
    internal_lease
        .check_opened_identity(second.file())
        .map_err(map_internal_path_error)?;
    if first != second {
        return Err(LocalFileDiscoveryError::PathChanged);
    }
    Ok(LocalFileMetadataDiscoveryV1 { snapshot: second })
}

#[cfg(not(target_os = "macos"))]
fn discover_local_file_metadata_on_supported_platform_v1(
    path: &Path,
    internal_paths: &InternalPathRegistryV1,
    expected_internal_policy_digest: InternalPathPolicyDigest,
) -> Result<LocalFileMetadataDiscoveryV1, LocalFileDiscoveryError> {
    let _ = (path, internal_paths, expected_internal_policy_digest);
    Err(LocalFileDiscoveryError::UnsupportedOperatingSystem)
}

#[cfg(target_os = "macos")]
fn map_internal_path_error(error: InternalPathRegistryError) -> LocalFileDiscoveryError {
    match error {
        InternalPathRegistryError::CanonicalPathReserved
        | InternalPathRegistryError::OpenedIdentityReserved => {
            LocalFileDiscoveryError::InternalPathReserved
        }
        InternalPathRegistryError::StateUnavailable
        | InternalPathRegistryError::PolicyDigestMismatch
        | InternalPathRegistryError::IdentityRegistrationOverflow
        | InternalPathRegistryError::IdentityNotRegistered => {
            LocalFileDiscoveryError::InternalPathStateUnavailable
        }
    }
}

/// Contentless metadata-discovery failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LocalFileDiscoveryError {
    UnsupportedOperatingSystem,
    UnsupportedArchitecture,
    UnsupportedFilesystem,
    CurrentDirectoryUnavailable,
    InvalidPath,
    InternalPathStateUnavailable,
    InternalPathReserved,
    RootOpenFailed,
    MetadataUnavailable,
    ComponentOpenFailed,
    IntermediateNotDirectory,
    SymlinkRejected,
    FinalObjectNotRegular,
    FilesystemUnavailable,
    MetadataOutOfRange,
    PathChanged,
}

impl LocalFileDiscoveryError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedOperatingSystem => "EVIDENTRAIL_LOCAL_DISCOVERY_UNSUPPORTED_OS",
            Self::UnsupportedArchitecture => "EVIDENTRAIL_LOCAL_DISCOVERY_UNSUPPORTED_ARCHITECTURE",
            Self::UnsupportedFilesystem => "EVIDENTRAIL_LOCAL_DISCOVERY_UNSUPPORTED_FILESYSTEM",
            Self::CurrentDirectoryUnavailable => {
                "EVIDENTRAIL_LOCAL_DISCOVERY_CURRENT_DIRECTORY_UNAVAILABLE"
            }
            Self::InvalidPath => "EVIDENTRAIL_LOCAL_DISCOVERY_INVALID_PATH",
            Self::InternalPathStateUnavailable => {
                "EVIDENTRAIL_LOCAL_DISCOVERY_INTERNAL_PATH_STATE_UNAVAILABLE"
            }
            Self::InternalPathReserved => "EVIDENTRAIL_LOCAL_DISCOVERY_INTERNAL_PATH_RESERVED",
            Self::RootOpenFailed => "EVIDENTRAIL_LOCAL_DISCOVERY_ROOT_OPEN_FAILED",
            Self::MetadataUnavailable => "EVIDENTRAIL_LOCAL_DISCOVERY_METADATA_UNAVAILABLE",
            Self::ComponentOpenFailed => "EVIDENTRAIL_LOCAL_DISCOVERY_COMPONENT_OPEN_FAILED",
            Self::IntermediateNotDirectory => {
                "EVIDENTRAIL_LOCAL_DISCOVERY_INTERMEDIATE_NOT_DIRECTORY"
            }
            Self::SymlinkRejected => "EVIDENTRAIL_LOCAL_DISCOVERY_SYMLINK_REJECTED",
            Self::FinalObjectNotRegular => "EVIDENTRAIL_LOCAL_DISCOVERY_FINAL_NOT_REGULAR",
            Self::FilesystemUnavailable => "EVIDENTRAIL_LOCAL_DISCOVERY_FILESYSTEM_UNAVAILABLE",
            Self::MetadataOutOfRange => "EVIDENTRAIL_LOCAL_DISCOVERY_METADATA_OUT_OF_RANGE",
            Self::PathChanged => "EVIDENTRAIL_LOCAL_DISCOVERY_PATH_CHANGED",
        }
    }
}

impl fmt::Debug for LocalFileDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalFileDiscoveryError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for LocalFileDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for LocalFileDiscoveryError {}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::fs;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use evidentrail_authority::{CanonicalUnixPathV1, InternalPathPolicyV1};

    use super::*;

    static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!(
                    "evidentrail-local-file-discovery-{}-{sequence}",
                    std::process::id()
                ));
            fs::create_dir(&root).unwrap();
            Self { root }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.root.join(name)
        }

        fn registry(&self, reserved: &Path) -> (InternalPathRegistryV1, InternalPathPolicyDigest) {
            let policy = InternalPathPolicyV1::new(
                [CanonicalUnixPathV1::new(reserved.as_os_str().as_bytes().to_vec()).unwrap()],
                [],
            )
            .unwrap();
            let digest = policy.digest();
            (InternalPathRegistryV1::new(policy), digest)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn unreadable_regular_file_is_observed_without_content_or_authority() {
        let fixture = Fixture::new();
        let candidate = fixture.path("CONTENT_CANARY.log");
        let content = b"SECRET_CONTENT_CANARY\0\xff\n";
        fs::write(&candidate, content).unwrap();
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o000)).unwrap();
        let (registry, digest) = fixture.registry(&fixture.path("internal"));

        let discovery = discover_local_file_metadata_v1(&candidate, &registry, digest).unwrap();
        assert_eq!(
            discovery.snapshot().size(),
            u64::try_from(content.len()).unwrap()
        );
        assert_eq!(
            discovery.capability_code(),
            LOCAL_FILE_METADATA_CAPABILITY_CODE_V1
        );
        assert_eq!(
            discovery.content_access_code(),
            LOCAL_FILE_CONTENT_NOT_READ_CODE_V1
        );
        assert!(!discovery.content_was_read());
        assert!(!discovery.authorization_granted());
        assert!(!discovery.host_certification_granted());
        let debug = format!("{discovery:?}");
        assert!(!debug.contains("CONTENT_CANARY"));
        assert!(!debug.contains("SECRET_CONTENT_CANARY"));
        assert!(!debug.contains(fixture.root.to_str().unwrap()));
    }

    #[test]
    fn symlinks_special_objects_and_internal_paths_fail_closed() {
        let fixture = Fixture::new();
        let ordinary = fixture.path("ordinary.log");
        fs::write(&ordinary, b"ORDINARY_SECRET").unwrap();
        let internal = fixture.path("internal");
        fs::create_dir(&internal).unwrap();
        let internal_file = internal.join("snapshot.bin");
        fs::write(&internal_file, b"INTERNAL_SECRET").unwrap();
        let (registry, digest) = fixture.registry(&internal);

        let final_alias = fixture.path("final-alias.log");
        symlink(&ordinary, &final_alias).unwrap();
        assert_eq!(
            discover_local_file_metadata_v1(&final_alias, &registry, digest),
            Err(LocalFileDiscoveryError::SymlinkRejected)
        );

        let real_directory = fixture.path("real-directory");
        fs::create_dir(&real_directory).unwrap();
        fs::write(real_directory.join("nested.log"), b"NESTED_SECRET").unwrap();
        let directory_alias = fixture.path("directory-alias");
        symlink(&real_directory, &directory_alias).unwrap();
        assert_eq!(
            discover_local_file_metadata_v1(&directory_alias.join("nested.log"), &registry, digest,),
            Err(LocalFileDiscoveryError::SymlinkRejected)
        );
        assert_eq!(
            discover_local_file_metadata_v1(&real_directory, &registry, digest),
            Err(LocalFileDiscoveryError::FinalObjectNotRegular)
        );
        assert_eq!(
            discover_local_file_metadata_v1(&internal_file, &registry, digest),
            Err(LocalFileDiscoveryError::InternalPathReserved)
        );
    }

    #[test]
    fn active_internal_identity_and_diagnostics_remain_contentless() {
        let fixture = Fixture::new();
        let candidate = fixture.path("PATH_CANARY.log");
        fs::write(&candidate, b"IDENTITY_SECRET").unwrap();
        let (registry, digest) = fixture.registry(&fixture.path("internal"));
        let observed = discover_local_file_metadata_v1(&candidate, &registry, digest).unwrap();
        registry
            .register_active_identity(observed.snapshot().file())
            .unwrap();
        let error = discover_local_file_metadata_v1(&candidate, &registry, digest).unwrap_err();
        assert_eq!(error, LocalFileDiscoveryError::InternalPathReserved);
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("PATH_CANARY"));
        assert!(!rendered.contains("IDENTITY_SECRET"));
        assert!(!rendered.contains(fixture.root.to_str().unwrap()));
    }
}

#[cfg(all(test, not(target_os = "macos")))]
mod unsupported_tests {
    use evidentrail_authority::{CanonicalUnixPathV1, InternalPathPolicyV1};

    use super::*;

    #[test]
    fn unsupported_platform_rejects_before_path_access() {
        let policy = InternalPathPolicyV1::new(
            [CanonicalUnixPathV1::new(b"/evidentrail-internal".to_vec()).unwrap()],
            [],
        )
        .unwrap();
        let digest = policy.digest();
        let registry = InternalPathRegistryV1::new(policy);
        assert_eq!(
            discover_local_file_metadata_v1(
                Path::new("/CONTENT_CANARY_DOES_NOT_EXIST"),
                &registry,
                digest,
            ),
            Err(LocalFileDiscoveryError::UnsupportedOperatingSystem)
        );
    }
}
