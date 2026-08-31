use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path};
use std::sync::{Mutex, MutexGuard};

use evidentrail_schema::ResultId;
use rustix::fd::OwnedFd;
use rustix::fs::{self, AtFlags, Dir, FileType, Mode, OFlags, RenameFlags};

use crate::{
    MAX_SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_BYTES_V1,
    SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_HEADER_BYTES_V1, SealedEncryptedCoreResultBundleV1,
};

pub const MAX_FILESYSTEM_BUNDLE_DIRECTORY_ENTRIES_V1: usize = 8_192;

const ROOT_MODE_V1: u32 = 0o700;
const FILE_MODE_V1: u32 = 0o600;
const FINAL_PREFIX_V1: &str = "r_";
const FINAL_SUFFIX_V1: &str = ".sealed-bundle.v1";
const TEMP_PREFIX_V1: &str = ".creating-r_";
const TEMP_SUFFIX_V1: &str = ".sealed-bundle.v1.tmp";
const QUARANTINE_PREFIX_V1: &str = ".quarantine-";
const RESULT_HEX_BYTES_V1: usize = 64;

/// Stable, contentless ciphertext-filesystem failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FilesystemSealedBundleErrorV1 {
    InvalidRootPath,
    RootUnavailable,
    RootNotDirectory,
    RootOwnerMismatch,
    RootPermissionMismatch,
    RepositoryUnavailable,
    DuplicateResult,
    TemporaryExists,
    TemporaryCreateFailed,
    UnsafeObject,
    PermissionMismatch,
    HardLinkRejected,
    BundleTooLarge,
    WriteFailed,
    FileSyncFailed,
    AtomicPublishFailed,
    DirectorySyncFailed,
    ReadBackFailed,
    ResultUnavailable,
    ReadFailed,
    ObjectChangedDuringRead,
    BundleDecodeFailed,
    AuthorityMismatch,
    DirectoryEntryCap,
    DirectoryScanFailed,
    QuarantineCollision,
    QuarantineFailed,
}

impl FilesystemSealedBundleErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidRootPath => "EVIDENTRAIL_FILESYSTEM_BUNDLE_INVALID_ROOT_PATH",
            Self::RootUnavailable => "EVIDENTRAIL_FILESYSTEM_BUNDLE_ROOT_UNAVAILABLE",
            Self::RootNotDirectory => "EVIDENTRAIL_FILESYSTEM_BUNDLE_ROOT_NOT_DIRECTORY",
            Self::RootOwnerMismatch => "EVIDENTRAIL_FILESYSTEM_BUNDLE_ROOT_OWNER_MISMATCH",
            Self::RootPermissionMismatch => {
                "EVIDENTRAIL_FILESYSTEM_BUNDLE_ROOT_PERMISSION_MISMATCH"
            }
            Self::RepositoryUnavailable => "EVIDENTRAIL_FILESYSTEM_BUNDLE_REPOSITORY_UNAVAILABLE",
            Self::DuplicateResult => "EVIDENTRAIL_FILESYSTEM_BUNDLE_DUPLICATE_RESULT",
            Self::TemporaryExists => "EVIDENTRAIL_FILESYSTEM_BUNDLE_TEMPORARY_EXISTS",
            Self::TemporaryCreateFailed => "EVIDENTRAIL_FILESYSTEM_BUNDLE_TEMPORARY_CREATE_FAILED",
            Self::UnsafeObject => "EVIDENTRAIL_FILESYSTEM_BUNDLE_UNSAFE_OBJECT",
            Self::PermissionMismatch => "EVIDENTRAIL_FILESYSTEM_BUNDLE_PERMISSION_MISMATCH",
            Self::HardLinkRejected => "EVIDENTRAIL_FILESYSTEM_BUNDLE_HARD_LINK_REJECTED",
            Self::BundleTooLarge => "EVIDENTRAIL_FILESYSTEM_BUNDLE_TOO_LARGE",
            Self::WriteFailed => "EVIDENTRAIL_FILESYSTEM_BUNDLE_WRITE_FAILED",
            Self::FileSyncFailed => "EVIDENTRAIL_FILESYSTEM_BUNDLE_FILE_SYNC_FAILED",
            Self::AtomicPublishFailed => "EVIDENTRAIL_FILESYSTEM_BUNDLE_ATOMIC_PUBLISH_FAILED",
            Self::DirectorySyncFailed => "EVIDENTRAIL_FILESYSTEM_BUNDLE_DIRECTORY_SYNC_FAILED",
            Self::ReadBackFailed => "EVIDENTRAIL_FILESYSTEM_BUNDLE_READ_BACK_FAILED",
            Self::ResultUnavailable => "EVIDENTRAIL_FILESYSTEM_BUNDLE_RESULT_UNAVAILABLE",
            Self::ReadFailed => "EVIDENTRAIL_FILESYSTEM_BUNDLE_READ_FAILED",
            Self::ObjectChangedDuringRead => {
                "EVIDENTRAIL_FILESYSTEM_BUNDLE_OBJECT_CHANGED_DURING_READ"
            }
            Self::BundleDecodeFailed => "EVIDENTRAIL_FILESYSTEM_BUNDLE_DECODE_FAILED",
            Self::AuthorityMismatch => "EVIDENTRAIL_FILESYSTEM_BUNDLE_AUTHORITY_MISMATCH",
            Self::DirectoryEntryCap => "EVIDENTRAIL_FILESYSTEM_BUNDLE_DIRECTORY_ENTRY_CAP",
            Self::DirectoryScanFailed => "EVIDENTRAIL_FILESYSTEM_BUNDLE_DIRECTORY_SCAN_FAILED",
            Self::QuarantineCollision => "EVIDENTRAIL_FILESYSTEM_BUNDLE_QUARANTINE_COLLISION",
            Self::QuarantineFailed => "EVIDENTRAIL_FILESYSTEM_BUNDLE_QUARANTINE_FAILED",
        }
    }
}

impl fmt::Debug for FilesystemSealedBundleErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FilesystemSealedBundleErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for FilesystemSealedBundleErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for FilesystemSealedBundleErrorV1 {}

/// The strongest truthful success returned by this substrate.
///
/// Both requested barriers completed and the final name was reopened and
/// strictly decoded. This is deliberately not named `Durable`: it makes no
/// sudden-power-loss, rollback-prevention, recovery, or external-publication
/// guarantee.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FilesystemBundlePublicationV1 {
    BarrierIssuedAndReadBack,
}

impl FilesystemBundlePublicationV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        "EVIDENTRAIL_FILESYSTEM_BUNDLE_BARRIER_ISSUED_AND_READ_BACK"
    }
}

impl fmt::Debug for FilesystemBundlePublicationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FilesystemBundlePublicationV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Conservative classification from a locked, descriptor-relative root scan.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FilesystemBundleRecoveryClassificationV1 {
    StructurallyValidFinal,
    InterruptedTemporaryQuarantined,
    InvalidCiphertextQuarantined,
    AuthorityMismatchQuarantined,
    UnsafeMetadataQuarantined,
    NoncanonicalAliasQuarantined,
    ConflictingStateQuarantined,
    ExistingQuarantine,
    ForeignEntry,
}

impl FilesystemBundleRecoveryClassificationV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::StructurallyValidFinal => "EVIDENTRAIL_BUNDLE_RECOVERY_STRUCTURALLY_VALID_FINAL",
            Self::InterruptedTemporaryQuarantined => {
                "EVIDENTRAIL_BUNDLE_RECOVERY_INTERRUPTED_TEMPORARY_QUARANTINED"
            }
            Self::InvalidCiphertextQuarantined => {
                "EVIDENTRAIL_BUNDLE_RECOVERY_INVALID_CIPHERTEXT_QUARANTINED"
            }
            Self::AuthorityMismatchQuarantined => {
                "EVIDENTRAIL_BUNDLE_RECOVERY_AUTHORITY_MISMATCH_QUARANTINED"
            }
            Self::UnsafeMetadataQuarantined => {
                "EVIDENTRAIL_BUNDLE_RECOVERY_UNSAFE_METADATA_QUARANTINED"
            }
            Self::NoncanonicalAliasQuarantined => {
                "EVIDENTRAIL_BUNDLE_RECOVERY_NONCANONICAL_ALIAS_QUARANTINED"
            }
            Self::ConflictingStateQuarantined => {
                "EVIDENTRAIL_BUNDLE_RECOVERY_CONFLICTING_STATE_QUARANTINED"
            }
            Self::ExistingQuarantine => "EVIDENTRAIL_BUNDLE_RECOVERY_EXISTING_QUARANTINE",
            Self::ForeignEntry => "EVIDENTRAIL_BUNDLE_RECOVERY_FOREIGN_ENTRY",
        }
    }
}

impl fmt::Debug for FilesystemBundleRecoveryClassificationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FilesystemBundleRecoveryClassificationV1")
            .field("code", &self.code())
            .finish()
    }
}

/// One contentless recovery observation. Explicit access to the random result
/// identity is available for later provider coordination, but Debug omits it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FilesystemBundleRecoveryEntryV1 {
    result_id: Option<ResultId>,
    classification: FilesystemBundleRecoveryClassificationV1,
}

impl FilesystemBundleRecoveryEntryV1 {
    #[must_use]
    pub const fn result_id(self) -> Option<ResultId> {
        self.result_id
    }

    #[must_use]
    pub const fn classification(self) -> FilesystemBundleRecoveryClassificationV1 {
        self.classification
    }
}

impl fmt::Debug for FilesystemBundleRecoveryEntryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FilesystemBundleRecoveryEntryV1")
            .field("classification", &self.classification)
            .finish_non_exhaustive()
    }
}

pub struct FilesystemBundleRecoveryReportV1 {
    entries: Vec<FilesystemBundleRecoveryEntryV1>,
}

impl FilesystemBundleRecoveryReportV1 {
    #[must_use]
    pub fn entries(&self) -> &[FilesystemBundleRecoveryEntryV1] {
        &self.entries
    }
}

impl fmt::Debug for FilesystemBundleRecoveryReportV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FilesystemBundleRecoveryReportV1")
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

#[cfg(any(test, feature = "internal-test-provider"))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FilesystemBundleFaultPointV1 {
    PartialWrite { byte_count: usize },
    BeforeFileSync,
    BeforeAtomicPublish,
    BeforeDirectorySync,
    BeforeReadBack,
}

#[cfg(any(test, feature = "internal-test-provider"))]
impl FilesystemBundleFaultPointV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PartialWrite { .. } => "EVIDENTRAIL_FILESYSTEM_BUNDLE_FAULT_PARTIAL_WRITE",
            Self::BeforeFileSync => "EVIDENTRAIL_FILESYSTEM_BUNDLE_FAULT_BEFORE_FILE_SYNC",
            Self::BeforeAtomicPublish => {
                "EVIDENTRAIL_FILESYSTEM_BUNDLE_FAULT_BEFORE_ATOMIC_PUBLISH"
            }
            Self::BeforeDirectorySync => {
                "EVIDENTRAIL_FILESYSTEM_BUNDLE_FAULT_BEFORE_DIRECTORY_SYNC"
            }
            Self::BeforeReadBack => "EVIDENTRAIL_FILESYSTEM_BUNDLE_FAULT_BEFORE_READ_BACK",
        }
    }
}

#[cfg(any(test, feature = "internal-test-provider"))]
impl fmt::Debug for FilesystemBundleFaultPointV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FilesystemBundleFaultPointV1")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FilesystemBundleOperationV1 {
    TemporaryCreated,
    BytesWritten,
    FileSynced,
    PublishedNoReplace,
    DirectorySynced,
    ReadBackVerified,
    QuarantinedNoReplace,
    QuarantineDirectorySynced,
}

impl FilesystemBundleOperationV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TemporaryCreated => "EVIDENTRAIL_FILESYSTEM_BUNDLE_OP_TEMPORARY_CREATED",
            Self::BytesWritten => "EVIDENTRAIL_FILESYSTEM_BUNDLE_OP_BYTES_WRITTEN",
            Self::FileSynced => "EVIDENTRAIL_FILESYSTEM_BUNDLE_OP_FILE_SYNCED",
            Self::PublishedNoReplace => "EVIDENTRAIL_FILESYSTEM_BUNDLE_OP_PUBLISHED_NO_REPLACE",
            Self::DirectorySynced => "EVIDENTRAIL_FILESYSTEM_BUNDLE_OP_DIRECTORY_SYNCED",
            Self::ReadBackVerified => "EVIDENTRAIL_FILESYSTEM_BUNDLE_OP_READ_BACK_VERIFIED",
            Self::QuarantinedNoReplace => "EVIDENTRAIL_FILESYSTEM_BUNDLE_OP_QUARANTINED_NO_REPLACE",
            Self::QuarantineDirectorySynced => {
                "EVIDENTRAIL_FILESYSTEM_BUNDLE_OP_QUARANTINE_DIRECTORY_SYNCED"
            }
        }
    }
}

impl fmt::Debug for FilesystemBundleOperationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FilesystemBundleOperationV1")
            .field("code", &self.code())
            .finish()
    }
}

#[cfg(any(test, feature = "internal-test-provider"))]
#[derive(Default)]
struct FilesystemTestStateV1 {
    fault: Option<FilesystemBundleFaultPointV1>,
    operations: Vec<FilesystemBundleOperationV1>,
}

/// Descriptor-relative ciphertext-only publication substrate.
///
/// Construction walks an absolute root one component at a time with
/// `O_NOFOLLOW`, then retains only the opened directory descriptor. Result
/// operations accept `ResultId`, never a caller path. This layer performs no
/// provider or AEAD authentication: callers must pass every read bundle through
/// the existing authenticated repository import. It makes no Keychain,
/// rollback-prevention, cross-process-locking, sudden-power-loss, recovery
/// completion, or durable-publication claim.
pub struct FilesystemSealedBundleStoreV1 {
    root_fd: OwnedFd,
    operation_lock: Mutex<()>,
    #[cfg(any(test, feature = "internal-test-provider"))]
    test_state: Mutex<FilesystemTestStateV1>,
}

impl FilesystemSealedBundleStoreV1 {
    pub fn open_existing_root(root: &Path) -> Result<Self, FilesystemSealedBundleErrorV1> {
        let root_fd = open_root_without_symlinks(root)?;
        validate_root_fd(&root_fd)?;
        Ok(Self {
            root_fd,
            operation_lock: Mutex::new(()),
            #[cfg(any(test, feature = "internal-test-provider"))]
            test_state: Mutex::new(FilesystemTestStateV1::default()),
        })
    }

    /// Create, sync, atomically publish without replacement, sync the root,
    /// and strictly read back one ciphertext bundle.
    pub fn publish(
        &self,
        bundle: &SealedEncryptedCoreResultBundleV1,
    ) -> Result<FilesystemBundlePublicationV1, FilesystemSealedBundleErrorV1> {
        let _guard = self.lock_operations()?;
        validate_root_fd(&self.root_fd)?;
        let encoded = bundle.encode();
        if encoded.len() < SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_HEADER_BYTES_V1
            || encoded.len() > MAX_SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_BYTES_V1
        {
            return Err(FilesystemSealedBundleErrorV1::BundleTooLarge);
        }
        let result_id = bundle.result_id();
        let final_name = sealed_bundle_filename_v1(result_id);
        let temporary_name = sealed_bundle_temporary_filename_v1(result_id);
        if entry_exists(&self.root_fd, &final_name)? {
            return Err(FilesystemSealedBundleErrorV1::DuplicateResult);
        }

        let temporary_fd = match fs::openat(
            &self.root_fd,
            temporary_name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::EXIST) => {
                return Err(FilesystemSealedBundleErrorV1::TemporaryExists);
            }
            Err(_) => return Err(FilesystemSealedBundleErrorV1::TemporaryCreateFailed),
        };
        validate_regular_file_fd(&temporary_fd, Some(0))?;
        self.record_operation(FilesystemBundleOperationV1::TemporaryCreated)?;
        let mut temporary_file = File::from(temporary_fd);

        #[cfg(any(test, feature = "internal-test-provider"))]
        if let Some(FilesystemBundleFaultPointV1::PartialWrite { byte_count }) = self
            .take_fault_if(|fault| {
                matches!(fault, FilesystemBundleFaultPointV1::PartialWrite { .. })
            })?
        {
            let prefix = byte_count.min(encoded.len());
            temporary_file
                .write_all(&encoded[..prefix])
                .map_err(|_| FilesystemSealedBundleErrorV1::WriteFailed)?;
            return Err(FilesystemSealedBundleErrorV1::WriteFailed);
        }

        temporary_file
            .write_all(&encoded)
            .map_err(|_| FilesystemSealedBundleErrorV1::WriteFailed)?;
        let expected_size = i64::try_from(encoded.len())
            .map_err(|_| FilesystemSealedBundleErrorV1::BundleTooLarge)?;
        validate_regular_file_fd(&temporary_file, Some(expected_size))?;
        self.record_operation(FilesystemBundleOperationV1::BytesWritten)?;
        #[cfg(any(test, feature = "internal-test-provider"))]
        self.fail_if(FilesystemBundleFaultPointV1::BeforeFileSync)?;
        temporary_file
            .sync_all()
            .map_err(|_| FilesystemSealedBundleErrorV1::FileSyncFailed)?;
        let synced_temporary = validate_regular_file_fd(&temporary_file, Some(expected_size))?;
        self.record_operation(FilesystemBundleOperationV1::FileSynced)?;
        #[cfg(any(test, feature = "internal-test-provider"))]
        self.fail_if(FilesystemBundleFaultPointV1::BeforeAtomicPublish)?;
        if let Err(error) = fs::renameat_with(
            &self.root_fd,
            temporary_name.as_str(),
            &self.root_fd,
            final_name.as_str(),
            RenameFlags::NOREPLACE,
        ) {
            if error == rustix::io::Errno::EXIST {
                self.remove_owned_temporary(&temporary_name, &synced_temporary)?;
                return Err(FilesystemSealedBundleErrorV1::DuplicateResult);
            }
            return Err(FilesystemSealedBundleErrorV1::AtomicPublishFailed);
        }
        let published_fd = validate_regular_file_fd(&temporary_file, Some(expected_size))?;
        let published_path = fs::statat(
            &self.root_fd,
            final_name.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| FilesystemSealedBundleErrorV1::ObjectChangedDuringRead)?;
        validate_regular_file_stat(&published_path, Some(expected_size))?;
        if synced_temporary.st_dev != published_fd.st_dev
            || synced_temporary.st_ino != published_fd.st_ino
            || published_fd.st_dev != published_path.st_dev
            || published_fd.st_ino != published_path.st_ino
        {
            return Err(FilesystemSealedBundleErrorV1::ObjectChangedDuringRead);
        }
        self.record_operation(FilesystemBundleOperationV1::PublishedNoReplace)?;
        #[cfg(any(test, feature = "internal-test-provider"))]
        self.fail_if(FilesystemBundleFaultPointV1::BeforeDirectorySync)?;
        fs::fsync(&self.root_fd).map_err(|_| FilesystemSealedBundleErrorV1::DirectorySyncFailed)?;
        self.record_operation(FilesystemBundleOperationV1::DirectorySynced)?;
        #[cfg(any(test, feature = "internal-test-provider"))]
        self.fail_if(FilesystemBundleFaultPointV1::BeforeReadBack)?;
        let read_back = self.read_named_bundle(final_name.as_str(), result_id)?;
        if read_back.encode() != encoded {
            return Err(FilesystemSealedBundleErrorV1::ReadBackFailed);
        }
        self.record_operation(FilesystemBundleOperationV1::ReadBackVerified)?;
        Ok(FilesystemBundlePublicationV1::BarrierIssuedAndReadBack)
    }

    /// Strictly reopen and decode the canonical final object for `result_id`.
    /// Structural success is not provider authentication.
    pub fn read(
        &self,
        result_id: ResultId,
    ) -> Result<SealedEncryptedCoreResultBundleV1, FilesystemSealedBundleErrorV1> {
        let _guard = self.lock_operations()?;
        validate_root_fd(&self.root_fd)?;
        self.read_named_bundle(sealed_bundle_filename_v1(result_id).as_str(), result_id)
    }

    /// Scan bounded root entries, preserve valid finals, and move every
    /// interrupted, invalid, unsafe, noncanonical, or conflicting owned name to
    /// a create-only quarantine name. Nothing is auto-published or deleted.
    pub fn recover_and_quarantine(
        &self,
    ) -> Result<FilesystemBundleRecoveryReportV1, FilesystemSealedBundleErrorV1> {
        let _guard = self.lock_operations()?;
        validate_root_fd(&self.root_fd)?;
        let mut directory = Dir::read_from(&self.root_fd)
            .map_err(|_| FilesystemSealedBundleErrorV1::DirectoryScanFailed)?;
        let mut names = Vec::new();
        for entry in &mut directory {
            let entry = entry.map_err(|_| FilesystemSealedBundleErrorV1::DirectoryScanFailed)?;
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            if names.len() >= MAX_FILESYSTEM_BUNDLE_DIRECTORY_ENTRIES_V1 {
                return Err(FilesystemSealedBundleErrorV1::DirectoryEntryCap);
            }
            names.push(bytes.to_vec());
        }
        names.sort();

        let mut report_entries = Vec::with_capacity(names.len());
        let mut grouped = BTreeMap::<ResultId, Vec<ActiveEntryV1>>::new();
        for bytes in names {
            match classify_name(&bytes) {
                NameClassificationV1::Active(active) => {
                    grouped.entry(active.result_id).or_default().push(active);
                }
                NameClassificationV1::ExistingQuarantine => {
                    report_entries.push(FilesystemBundleRecoveryEntryV1 {
                        result_id: None,
                        classification:
                            FilesystemBundleRecoveryClassificationV1::ExistingQuarantine,
                    });
                }
                NameClassificationV1::Foreign => {
                    report_entries.push(FilesystemBundleRecoveryEntryV1 {
                        result_id: None,
                        classification: FilesystemBundleRecoveryClassificationV1::ForeignEntry,
                    });
                }
            }
        }

        for (result_id, entries) in grouped {
            if entries.len() > 1 {
                if let Some((final_entry, temporary_entry)) =
                    exact_matching_final_and_temp(&entries)
                {
                    let final_bundle = self.read_named_bundle(&final_entry.name, result_id);
                    let temporary_bundle = self.read_named_bundle(&temporary_entry.name, result_id);
                    if matches!((final_bundle, temporary_bundle), (Ok(final_bundle), Ok(temporary_bundle)) if final_bundle.encode() == temporary_bundle.encode())
                    {
                        report_entries.push(FilesystemBundleRecoveryEntryV1 {
                            result_id: Some(result_id),
                            classification:
                                FilesystemBundleRecoveryClassificationV1::StructurallyValidFinal,
                        });
                        self.quarantine_name(&temporary_entry.name)?;
                        report_entries.push(FilesystemBundleRecoveryEntryV1 {
                            result_id: Some(result_id),
                            classification: FilesystemBundleRecoveryClassificationV1::InterruptedTemporaryQuarantined,
                        });
                        continue;
                    }
                }
                for entry in entries {
                    self.quarantine_name(&entry.name)?;
                    report_entries.push(FilesystemBundleRecoveryEntryV1 {
                        result_id: Some(result_id),
                        classification:
                            FilesystemBundleRecoveryClassificationV1::ConflictingStateQuarantined,
                    });
                }
                continue;
            }

            let entry = entries
                .into_iter()
                .next()
                .ok_or(FilesystemSealedBundleErrorV1::DirectoryScanFailed)?;
            if entry.kind == ActiveEntryKindV1::Alias {
                self.quarantine_name(&entry.name)?;
                report_entries.push(FilesystemBundleRecoveryEntryV1 {
                    result_id: Some(result_id),
                    classification:
                        FilesystemBundleRecoveryClassificationV1::NoncanonicalAliasQuarantined,
                });
                continue;
            }

            let inspection = self.read_named_bundle(&entry.name, result_id);
            if entry.kind == ActiveEntryKindV1::Final && inspection.is_ok() {
                report_entries.push(FilesystemBundleRecoveryEntryV1 {
                    result_id: Some(result_id),
                    classification:
                        FilesystemBundleRecoveryClassificationV1::StructurallyValidFinal,
                });
                continue;
            }
            let classification = match inspection {
                Ok(_) => FilesystemBundleRecoveryClassificationV1::InterruptedTemporaryQuarantined,
                Err(FilesystemSealedBundleErrorV1::AuthorityMismatch) => {
                    FilesystemBundleRecoveryClassificationV1::AuthorityMismatchQuarantined
                }
                Err(
                    FilesystemSealedBundleErrorV1::UnsafeObject
                    | FilesystemSealedBundleErrorV1::PermissionMismatch
                    | FilesystemSealedBundleErrorV1::HardLinkRejected,
                ) => FilesystemBundleRecoveryClassificationV1::UnsafeMetadataQuarantined,
                Err(_) => FilesystemBundleRecoveryClassificationV1::InvalidCiphertextQuarantined,
            };
            self.quarantine_name(&entry.name)?;
            report_entries.push(FilesystemBundleRecoveryEntryV1 {
                result_id: Some(result_id),
                classification,
            });
        }
        Ok(FilesystemBundleRecoveryReportV1 {
            entries: report_entries,
        })
    }

    /// Move one exact canonical final name into create-only quarantine.
    ///
    /// This crate-private seam exists for the authenticated restart
    /// coordinator. It never follows the candidate and never deletes it. The
    /// coordinator invokes it only after either strict structural decoding or
    /// complete provider/manifest authentication has failed against an
    /// independently supplied authority context.
    pub(crate) fn quarantine_final_candidate(
        &self,
        result_id: ResultId,
    ) -> Result<(), FilesystemSealedBundleErrorV1> {
        let _guard = self.lock_operations()?;
        validate_root_fd(&self.root_fd)?;
        let name = sealed_bundle_filename_v1(result_id);
        if !entry_name_exists_exact(&self.root_fd, name.as_bytes())? {
            return Err(FilesystemSealedBundleErrorV1::ResultUnavailable);
        }
        self.quarantine_name(&name)
    }

    #[cfg(any(test, feature = "internal-test-provider"))]
    pub fn fail_next_for_test(
        &self,
        fault: FilesystemBundleFaultPointV1,
    ) -> Result<(), FilesystemSealedBundleErrorV1> {
        let mut state = self.lock_test_state()?;
        state.fault = Some(fault);
        Ok(())
    }

    #[cfg(any(test, feature = "internal-test-provider"))]
    pub fn operations_for_test(
        &self,
    ) -> Result<Vec<FilesystemBundleOperationV1>, FilesystemSealedBundleErrorV1> {
        Ok(self.lock_test_state()?.operations.clone())
    }

    fn read_named_bundle(
        &self,
        name: &str,
        expected_result_id: ResultId,
    ) -> Result<SealedEncryptedCoreResultBundleV1, FilesystemSealedBundleErrorV1> {
        if !entry_name_exists_exact(&self.root_fd, name.as_bytes())? {
            return Err(FilesystemSealedBundleErrorV1::ResultUnavailable);
        }
        let path_stat = fs::statat(&self.root_fd, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| FilesystemSealedBundleErrorV1::ResultUnavailable)?;
        validate_regular_file_stat(&path_stat, None)?;
        let fd = fs::openat(
            &self.root_fd,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| FilesystemSealedBundleErrorV1::ResultUnavailable)?;
        let before = validate_regular_file_fd(&fd, None)?;
        if path_stat.st_dev != before.st_dev || path_stat.st_ino != before.st_ino {
            return Err(FilesystemSealedBundleErrorV1::ObjectChangedDuringRead);
        }
        let size = usize::try_from(before.st_size)
            .map_err(|_| FilesystemSealedBundleErrorV1::BundleTooLarge)?;
        if !(SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_HEADER_BYTES_V1
            ..=MAX_SEALED_ENCRYPTED_CORE_RESULT_BUNDLE_BYTES_V1)
            .contains(&size)
        {
            return Err(FilesystemSealedBundleErrorV1::BundleTooLarge);
        }
        let mut file = File::from(fd);
        let mut encoded = vec![0u8; size];
        file.read_exact(&mut encoded)
            .map_err(|_| FilesystemSealedBundleErrorV1::ReadFailed)?;
        let mut trailing = [0u8; 1];
        if file
            .read(&mut trailing)
            .map_err(|_| FilesystemSealedBundleErrorV1::ReadFailed)?
            != 0
        {
            return Err(FilesystemSealedBundleErrorV1::ReadFailed);
        }
        let after = validate_regular_file_fd(&file, Some(before.st_size))?;
        if !same_file_snapshot(&before, &after) {
            return Err(FilesystemSealedBundleErrorV1::ObjectChangedDuringRead);
        }
        let path_after = fs::statat(&self.root_fd, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| FilesystemSealedBundleErrorV1::ObjectChangedDuringRead)?;
        validate_regular_file_stat(&path_after, Some(after.st_size))?;
        if path_after.st_dev != after.st_dev
            || path_after.st_ino != after.st_ino
            || !same_file_snapshot(&after, &path_after)
            || !entry_name_exists_exact(&self.root_fd, name.as_bytes())?
        {
            return Err(FilesystemSealedBundleErrorV1::ObjectChangedDuringRead);
        }
        let bundle = SealedEncryptedCoreResultBundleV1::decode(&encoded)
            .map_err(|_| FilesystemSealedBundleErrorV1::BundleDecodeFailed)?;
        if bundle.result_id() != expected_result_id {
            return Err(FilesystemSealedBundleErrorV1::AuthorityMismatch);
        }
        if bundle.encode() != encoded {
            return Err(FilesystemSealedBundleErrorV1::BundleDecodeFailed);
        }
        Ok(bundle)
    }

    fn quarantine_name(&self, source_name: &str) -> Result<(), FilesystemSealedBundleErrorV1> {
        let quarantine_name = format!("{QUARANTINE_PREFIX_V1}{source_name}");
        if entry_exists(&self.root_fd, &quarantine_name)? {
            return Err(FilesystemSealedBundleErrorV1::QuarantineCollision);
        }
        fs::renameat_with(
            &self.root_fd,
            source_name,
            &self.root_fd,
            quarantine_name.as_str(),
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| {
            if error == rustix::io::Errno::EXIST {
                FilesystemSealedBundleErrorV1::QuarantineCollision
            } else {
                FilesystemSealedBundleErrorV1::QuarantineFailed
            }
        })?;
        self.record_operation(FilesystemBundleOperationV1::QuarantinedNoReplace)?;
        fs::fsync(&self.root_fd).map_err(|_| FilesystemSealedBundleErrorV1::DirectorySyncFailed)?;
        self.record_operation(FilesystemBundleOperationV1::QuarantineDirectorySynced)?;
        Ok(())
    }

    fn remove_owned_temporary(
        &self,
        temporary_name: &str,
        owned: &rustix::fs::Stat,
    ) -> Result<(), FilesystemSealedBundleErrorV1> {
        let current = match fs::statat(&self.root_fd, temporary_name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(current) => current,
            Err(rustix::io::Errno::NOENT) => return Ok(()),
            Err(_) => return Err(FilesystemSealedBundleErrorV1::AtomicPublishFailed),
        };
        if current.st_dev != owned.st_dev || current.st_ino != owned.st_ino {
            return Err(FilesystemSealedBundleErrorV1::ObjectChangedDuringRead);
        }
        fs::unlinkat(&self.root_fd, temporary_name, AtFlags::empty())
            .map_err(|_| FilesystemSealedBundleErrorV1::AtomicPublishFailed)
    }

    fn lock_operations(&self) -> Result<MutexGuard<'_, ()>, FilesystemSealedBundleErrorV1> {
        self.operation_lock
            .lock()
            .map_err(|_| FilesystemSealedBundleErrorV1::RepositoryUnavailable)
    }

    #[cfg(any(test, feature = "internal-test-provider"))]
    fn lock_test_state(
        &self,
    ) -> Result<MutexGuard<'_, FilesystemTestStateV1>, FilesystemSealedBundleErrorV1> {
        self.test_state
            .lock()
            .map_err(|_| FilesystemSealedBundleErrorV1::RepositoryUnavailable)
    }

    #[cfg(any(test, feature = "internal-test-provider"))]
    fn take_fault_if(
        &self,
        predicate: impl FnOnce(FilesystemBundleFaultPointV1) -> bool,
    ) -> Result<Option<FilesystemBundleFaultPointV1>, FilesystemSealedBundleErrorV1> {
        let mut state = self.lock_test_state()?;
        if state.fault.is_some_and(predicate) {
            Ok(state.fault.take())
        } else {
            Ok(None)
        }
    }

    #[cfg(any(test, feature = "internal-test-provider"))]
    fn fail_if(
        &self,
        expected: FilesystemBundleFaultPointV1,
    ) -> Result<(), FilesystemSealedBundleErrorV1> {
        if self.take_fault_if(|fault| fault == expected)?.is_some() {
            return Err(match expected {
                FilesystemBundleFaultPointV1::PartialWrite { .. } => {
                    FilesystemSealedBundleErrorV1::WriteFailed
                }
                FilesystemBundleFaultPointV1::BeforeFileSync => {
                    FilesystemSealedBundleErrorV1::FileSyncFailed
                }
                FilesystemBundleFaultPointV1::BeforeAtomicPublish => {
                    FilesystemSealedBundleErrorV1::AtomicPublishFailed
                }
                FilesystemBundleFaultPointV1::BeforeDirectorySync => {
                    FilesystemSealedBundleErrorV1::DirectorySyncFailed
                }
                FilesystemBundleFaultPointV1::BeforeReadBack => {
                    FilesystemSealedBundleErrorV1::ReadBackFailed
                }
            });
        }
        Ok(())
    }

    fn record_operation(
        &self,
        operation: FilesystemBundleOperationV1,
    ) -> Result<(), FilesystemSealedBundleErrorV1> {
        #[cfg(any(test, feature = "internal-test-provider"))]
        self.lock_test_state()?.operations.push(operation);
        #[cfg(not(any(test, feature = "internal-test-provider")))]
        let _ = operation;
        Ok(())
    }
}

impl fmt::Debug for FilesystemSealedBundleStoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FilesystemSealedBundleStoreV1(<redacted>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ActiveEntryKindV1 {
    Final,
    Temporary,
    Alias,
}

struct ActiveEntryV1 {
    result_id: ResultId,
    kind: ActiveEntryKindV1,
    name: String,
}

enum NameClassificationV1 {
    Active(ActiveEntryV1),
    ExistingQuarantine,
    Foreign,
}

fn classify_name(bytes: &[u8]) -> NameClassificationV1 {
    let Ok(name) = std::str::from_utf8(bytes) else {
        return NameClassificationV1::Foreign;
    };
    if name.starts_with(QUARANTINE_PREFIX_V1) {
        return NameClassificationV1::ExistingQuarantine;
    }
    if let Some(result_id) = parse_canonical_name(name, FINAL_PREFIX_V1, FINAL_SUFFIX_V1) {
        return NameClassificationV1::Active(ActiveEntryV1 {
            result_id,
            kind: ActiveEntryKindV1::Final,
            name: name.to_owned(),
        });
    }
    if let Some(result_id) = parse_canonical_name(name, TEMP_PREFIX_V1, TEMP_SUFFIX_V1) {
        return NameClassificationV1::Active(ActiveEntryV1 {
            result_id,
            kind: ActiveEntryKindV1::Temporary,
            name: name.to_owned(),
        });
    }
    let lowered = name.to_ascii_lowercase();
    if lowered != name {
        if let Some(result_id) = parse_canonical_name(&lowered, FINAL_PREFIX_V1, FINAL_SUFFIX_V1)
            .or_else(|| parse_canonical_name(&lowered, TEMP_PREFIX_V1, TEMP_SUFFIX_V1))
        {
            return NameClassificationV1::Active(ActiveEntryV1 {
                result_id,
                kind: ActiveEntryKindV1::Alias,
                name: name.to_owned(),
            });
        }
    }
    NameClassificationV1::Foreign
}

fn exact_matching_final_and_temp(
    entries: &[ActiveEntryV1],
) -> Option<(&ActiveEntryV1, &ActiveEntryV1)> {
    if entries.len() != 2 {
        return None;
    }
    let final_entry = entries
        .iter()
        .find(|entry| entry.kind == ActiveEntryKindV1::Final)?;
    let temporary_entry = entries
        .iter()
        .find(|entry| entry.kind == ActiveEntryKindV1::Temporary)?;
    Some((final_entry, temporary_entry))
}

fn open_root_without_symlinks(root: &Path) -> Result<OwnedFd, FilesystemSealedBundleErrorV1> {
    if !root.is_absolute() {
        return Err(FilesystemSealedBundleErrorV1::InvalidRootPath);
    }
    let canonical =
        std::fs::canonicalize(root).map_err(|_| FilesystemSealedBundleErrorV1::RootUnavailable)?;
    if canonical != root {
        return Err(FilesystemSealedBundleErrorV1::InvalidRootPath);
    }
    let mut current = fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| FilesystemSealedBundleErrorV1::RootUnavailable)?;
    let mut saw_normal = false;
    for component in root.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                saw_normal = true;
                current = fs::openat(
                    &current,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| FilesystemSealedBundleErrorV1::RootUnavailable)?;
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(FilesystemSealedBundleErrorV1::InvalidRootPath);
            }
        }
    }
    if !saw_normal {
        return Err(FilesystemSealedBundleErrorV1::InvalidRootPath);
    }
    Ok(current)
}

fn validate_root_fd(root_fd: &OwnedFd) -> Result<(), FilesystemSealedBundleErrorV1> {
    let stat = fs::fstat(root_fd).map_err(|_| FilesystemSealedBundleErrorV1::RootUnavailable)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(FilesystemSealedBundleErrorV1::RootNotDirectory);
    }
    if stat.st_uid != rustix::process::geteuid().as_raw() {
        return Err(FilesystemSealedBundleErrorV1::RootOwnerMismatch);
    }
    // `mode_t` is `u16` on macOS and `u32` on Linux. Keep the checked,
    // lossless normalization explicit across both supported Unix targets.
    #[allow(clippy::useless_conversion)]
    let mode = u32::from(stat.st_mode);
    if mode & 0o7777 != ROOT_MODE_V1 {
        return Err(FilesystemSealedBundleErrorV1::RootPermissionMismatch);
    }
    Ok(())
}

fn validate_regular_file_fd<Fd: rustix::fd::AsFd>(
    fd: Fd,
    expected_size: Option<i64>,
) -> Result<rustix::fs::Stat, FilesystemSealedBundleErrorV1> {
    let stat = fs::fstat(fd).map_err(|_| FilesystemSealedBundleErrorV1::UnsafeObject)?;
    validate_regular_file_stat(&stat, expected_size)?;
    Ok(stat)
}

fn validate_regular_file_stat(
    stat: &rustix::fs::Stat,
    expected_size: Option<i64>,
) -> Result<(), FilesystemSealedBundleErrorV1> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != rustix::process::geteuid().as_raw()
    {
        return Err(FilesystemSealedBundleErrorV1::UnsafeObject);
    }
    #[allow(clippy::useless_conversion)]
    let mode = u32::from(stat.st_mode);
    if mode & 0o7777 != FILE_MODE_V1 {
        return Err(FilesystemSealedBundleErrorV1::PermissionMismatch);
    }
    if stat.st_nlink != 1 {
        return Err(FilesystemSealedBundleErrorV1::HardLinkRejected);
    }
    if stat.st_size < 0 || expected_size.is_some_and(|size| stat.st_size != size) {
        return Err(FilesystemSealedBundleErrorV1::UnsafeObject);
    }
    Ok(())
}

fn same_file_snapshot(first: &rustix::fs::Stat, second: &rustix::fs::Stat) -> bool {
    first.st_dev == second.st_dev
        && first.st_ino == second.st_ino
        && first.st_mode == second.st_mode
        && first.st_nlink == second.st_nlink
        && first.st_size == second.st_size
        && first.st_mtime == second.st_mtime
        && first.st_mtime_nsec == second.st_mtime_nsec
        && first.st_ctime == second.st_ctime
        && first.st_ctime_nsec == second.st_ctime_nsec
}

fn entry_exists(root_fd: &OwnedFd, name: &str) -> Result<bool, FilesystemSealedBundleErrorV1> {
    match fs::statat(root_fd, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(_) => Err(FilesystemSealedBundleErrorV1::RootUnavailable),
    }
}

fn entry_name_exists_exact(
    root_fd: &OwnedFd,
    expected: &[u8],
) -> Result<bool, FilesystemSealedBundleErrorV1> {
    let mut directory =
        Dir::read_from(root_fd).map_err(|_| FilesystemSealedBundleErrorV1::DirectoryScanFailed)?;
    let mut inspected = 0usize;
    for entry in &mut directory {
        let entry = entry.map_err(|_| FilesystemSealedBundleErrorV1::DirectoryScanFailed)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        inspected = inspected
            .checked_add(1)
            .ok_or(FilesystemSealedBundleErrorV1::DirectoryEntryCap)?;
        if inspected > MAX_FILESYSTEM_BUNDLE_DIRECTORY_ENTRIES_V1 {
            return Err(FilesystemSealedBundleErrorV1::DirectoryEntryCap);
        }
        if name == expected {
            return Ok(true);
        }
    }
    Ok(false)
}

#[must_use]
pub fn sealed_bundle_filename_v1(result_id: ResultId) -> String {
    format_result_name(FINAL_PREFIX_V1, result_id, FINAL_SUFFIX_V1)
}

#[must_use]
pub fn sealed_bundle_temporary_filename_v1(result_id: ResultId) -> String {
    format_result_name(TEMP_PREFIX_V1, result_id, TEMP_SUFFIX_V1)
}

fn format_result_name(prefix: &str, result_id: ResultId, suffix: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(prefix.len() + RESULT_HEX_BYTES_V1 + suffix.len());
    name.push_str(prefix);
    for byte in result_id.as_bytes() {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    name.push_str(suffix);
    name
}

fn parse_canonical_name(name: &str, prefix: &str, suffix: &str) -> Option<ResultId> {
    let hex = name.strip_prefix(prefix)?.strip_suffix(suffix)?;
    if hex.len() != RESULT_HEX_BYTES_V1 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    if hex.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return None;
    }
    let mut result = [0u8; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        result[index] = decode_hex(pair[0])?.checked_mul(16)? + decode_hex(pair[1])?;
    }
    Some(ResultId::from_bytes(result))
}

fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}
