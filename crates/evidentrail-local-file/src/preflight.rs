use std::error::Error as StdError;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use evidentrail_authority::{RegistryAuthorizationError, RegistryAuthorizedLocalFilePlanV1};
use evidentrail_schema::{
    FetchIdentity, LocalFileArchitectureV1, LocalFileDeadlineModelV1, LocalFileFilesystemV1,
    LocalFileOperatingSystemV1, LocalFilePlanCapsV1, LocalFileRuntimeProfileV1, PlanId,
    SourceIdentityDigest, SourceMember, UnixFileObjectIdV1, UnixFileSnapshotV1, UnixFileTypeV1,
    UnixLocalFileLocatorV1, UnixTimestampNanos,
};
use evidentrail_wire::{VerifiedLocalFilePlanV1, derive_local_file_source_identity_digest_v1};
use rustix::fd::OwnedFd;
use rustix::fs::{self, FileType, Mode, OFlags, Stat};

/// Perform the safe, zero-content-read local-file V1 descriptor preflight.
///
/// This public entrypoint obtains all host facts from the running process and
/// accepts no caller-provided host assertion. Until an externally governed
/// certification record is frozen in this crate, an otherwise valid plan and
/// live platform observation end with
/// [`LocalFilePreflightError::CertificationProfileNotAdmitted`] before any path
/// access, and no token is issued.
pub fn preflight_local_file_v1<'binding_registry, 'path_registry>(
    plan: &VerifiedLocalFilePlanV1,
    authority: RegistryAuthorizedLocalFilePlanV1<'binding_registry, 'path_registry>,
) -> Result<PreflightedLocalFileV1<'binding_registry, 'path_registry>, LocalFilePreflightError> {
    preflight_with(
        plan,
        authority,
        &FrozenCertificationAuthorityV1,
        &LiveFilesystemObserverV1,
        &SystemWallClockV1,
        &NoopPathAccessObserverV1,
        || {},
    )
}

/// Owned, descriptor-backed preflight result.
///
/// This type intentionally exposes neither a raw descriptor nor a read method.
/// It is not an executable plan, an acknowledgement, or a completion proof.
/// A later streaming slice must consume it inside this crate and repeat the
/// required immediately-before-read and post-read validations.
pub struct PreflightedLocalFileV1<'binding_registry, 'path_registry> {
    pub(crate) authority: RegistryAuthorizedLocalFilePlanV1<'binding_registry, 'path_registry>,
    pub(crate) root_fd: OwnedFd,
    pub(crate) file_fd: OwnedFd,
    pub(crate) certified_host: LiveHostCertificationV1,
    pub(crate) facts: LocalFileExecutionFactsV1,
}

impl PreflightedLocalFileV1<'_, '_> {
    #[must_use]
    pub const fn plan_id(&self) -> PlanId {
        self.facts.fetch_identity.plan_id()
    }

    /// This preflight never constitutes a completion proof.
    #[must_use]
    pub const fn is_completion_proof(&self) -> bool {
        false
    }
}

impl fmt::Debug for PreflightedLocalFileV1<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.root_fd, &self.file_fd, &self.certified_host);
        formatter
            .debug_struct("PreflightedLocalFileV1")
            .field("plan_identity_present", &true)
            .field("owned_root_handle_present", &true)
            .field("owned_file_handle_present", &true)
            .field("live_host_certification_present", &true)
            .field("read_api_exposed", &false)
            .field("completion_proof", &false)
            .finish()
    }
}

fn preflight_with<'binding_registry, 'path_registry, C, F, T, A, H>(
    plan: &VerifiedLocalFilePlanV1,
    authority: RegistryAuthorizedLocalFilePlanV1<'binding_registry, 'path_registry>,
    certification_authority: &C,
    filesystem_observer: &F,
    clock: &T,
    path_access_observer: &A,
    between_passes: H,
) -> Result<PreflightedLocalFileV1<'binding_registry, 'path_registry>, LocalFilePreflightError>
where
    C: CertificationAuthorityV1,
    F: FilesystemObserverV1,
    T: SealedWallClockV1,
    A: PathAccessObserverV1,
    H: FnOnce(),
{
    if authority.plan_id() != plan.plan_id() {
        return Err(LocalFilePreflightError::PlanAuthorizationMismatch);
    }

    let observed_at = clock.now()?;
    let facts = LocalFileExecutionFactsV1::from_plan(plan);
    validate_fresh_authority_time(&facts, &authority, observed_at)?;
    let profile = plan.material().runtime_profile();
    let live_platform = observe_live_platform(profile)?;
    // Governance admission intentionally precedes every path syscall. The
    // public authority is frozen closed until an external tested matrix is
    // committed here; no caller assertion can bypass this boundary.
    let certified_host = certification_authority.admit(profile, &live_platform)?;

    path_access_observer.before_path_access();
    let first = open_selection(plan.material().locator(), filesystem_observer)?;
    let first_snapshot = validate_selection(&facts, &authority, &first)?;
    validate_filesystems(profile, first.root_filesystem, first.file_filesystem)?;

    between_passes();

    path_access_observer.before_path_access();
    let second = open_selection(plan.material().locator(), filesystem_observer)?;
    let second_snapshot = validate_selection(&facts, &authority, &second)?;
    validate_filesystems(profile, second.root_filesystem, second.file_filesystem)?;
    if second_snapshot != first_snapshot {
        return Err(LocalFilePreflightError::PathRevalidationMismatch);
    }

    let retained_root_stat =
        fs::fstat(&first.root_fd).map_err(|_| LocalFilePreflightError::RootMetadataUnavailable)?;
    let retained_file_stat =
        fs::fstat(&first.file_fd).map_err(|_| LocalFilePreflightError::FileMetadataUnavailable)?;
    validate_file_offset(&first.file_fd)?;
    let retained_root_filesystem = filesystem_observer.observe(&first.root_fd)?;
    let retained_file_filesystem = filesystem_observer.observe(&first.file_fd)?;
    validate_filesystems(profile, retained_root_filesystem, retained_file_filesystem)?;
    let retained_snapshot = snapshot_from_stats(&retained_root_stat, &retained_file_stat)?;
    if retained_snapshot != first_snapshot {
        return Err(LocalFilePreflightError::RetainedHandleChanged);
    }
    validate_source_identity(&facts, retained_snapshot)?;
    authority
        .check_opened_identity_not_internal(retained_snapshot.file())
        .map_err(map_registry_error)?;
    let final_observed_at = clock.now()?;
    validate_fresh_authority_time(&facts, &authority, final_observed_at)?;

    Ok(PreflightedLocalFileV1 {
        authority,
        root_fd: first.root_fd,
        file_fd: first.file_fd,
        certified_host,
        facts,
    })
}

pub(crate) fn validate_fresh_authority_time(
    facts: &LocalFileExecutionFactsV1,
    authority: &RegistryAuthorizedLocalFilePlanV1<'_, '_>,
    observed_at: UnixTimestampNanos,
) -> Result<(), LocalFilePreflightError> {
    if observed_at < authority.checked_at() {
        return Err(LocalFilePreflightError::WallClockRegressed);
    }
    if observed_at < facts.created_at
        || observed_at >= facts.execute_before
        || facts
            .proof_expires_at
            .is_some_and(|expires_at| observed_at >= expires_at)
    {
        return Err(LocalFilePreflightError::AuthorityOutsideValidity);
    }
    Ok(())
}

pub(crate) struct LocalFileExecutionFactsV1 {
    pub(crate) fetch_identity: FetchIdentity,
    pub(crate) source_identity_digest: SourceIdentityDigest,
    pub(crate) locator: UnixLocalFileLocatorV1,
    pub(crate) runtime_profile: LocalFileRuntimeProfileV1,
    pub(crate) source_member: SourceMember,
    pub(crate) snapshot: UnixFileSnapshotV1,
    pub(crate) caps: LocalFilePlanCapsV1,
    pub(crate) created_at: UnixTimestampNanos,
    pub(crate) execute_before: UnixTimestampNanos,
    pub(crate) proof_expires_at: Option<UnixTimestampNanos>,
}

impl LocalFileExecutionFactsV1 {
    fn from_plan(plan: &VerifiedLocalFilePlanV1) -> Self {
        let material = plan.material();
        Self {
            fetch_identity: FetchIdentity::new(
                material.retrieval_id(),
                plan.plan_id(),
                plan.plan_digest(),
                material.source_identity().adapter().clone(),
            ),
            source_identity_digest: material.source_identity().digest(),
            locator: material.locator().clone(),
            runtime_profile: material.runtime_profile(),
            source_member: material.source_member().clone(),
            snapshot: material.snapshot(),
            caps: material.caps(),
            created_at: material.created_at(),
            execute_before: material.execute_before(),
            proof_expires_at: material.source_identity().proof_expires_at(),
        }
    }
}

impl fmt::Debug for LocalFileExecutionFactsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalFileExecutionFactsV1")
            .field("fetch_identity_present", &true)
            .field("source_identity_present", &true)
            .field("locator_present", &true)
            .field("source_member_present", &true)
            .field("snapshot_present", &true)
            .field("caps_present", &true)
            .field("validity_interval_present", &true)
            .finish()
    }
}

/// Private injection seam. Production uses the live OS wall clock; only this
/// module's tests can provide a deterministic observation.
trait SealedWallClockV1 {
    fn now(&self) -> Result<UnixTimestampNanos, LocalFilePreflightError>;
}

struct SystemWallClockV1;

impl SealedWallClockV1 for SystemWallClockV1 {
    fn now(&self) -> Result<UnixTimestampNanos, LocalFilePreflightError> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| LocalFilePreflightError::WallClockUnavailable)?;
        let nanoseconds = i128::try_from(elapsed.as_nanos())
            .map_err(|_| LocalFilePreflightError::WallClockUnavailable)?;
        Ok(UnixTimestampNanos::new(nanoseconds))
    }
}

trait PathAccessObserverV1 {
    fn before_path_access(&self);
}

struct NoopPathAccessObserverV1;

impl PathAccessObserverV1 for NoopPathAccessObserverV1 {
    fn before_path_access(&self) {}
}

struct OpenedSelection {
    root_fd: OwnedFd,
    file_fd: OwnedFd,
    root_stat: Stat,
    file_stat: Stat,
    root_filesystem: ObservedFilesystemV1,
    file_filesystem: ObservedFilesystemV1,
}

fn open_selection<F: FilesystemObserverV1>(
    locator: &UnixLocalFileLocatorV1,
    filesystem_observer: &F,
) -> Result<OpenedSelection, LocalFilePreflightError> {
    let root_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let root_fd = fs::open(locator.root(), root_flags, Mode::empty())
        .map_err(|_| LocalFilePreflightError::RootOpenFailed)?;
    let root_stat =
        fs::fstat(&root_fd).map_err(|_| LocalFilePreflightError::RootMetadataUnavailable)?;
    if FileType::from_raw_mode(root_stat.st_mode) != FileType::Directory {
        return Err(LocalFilePreflightError::RootNotDirectory);
    }
    let root_filesystem = filesystem_observer.observe(&root_fd)?;

    let mut directory_chain = vec![root_fd];
    let components = locator.relative_components();
    for component in &components[..components.len() - 1] {
        let next = fs::openat(
            directory_chain
                .last()
                .ok_or(LocalFilePreflightError::MemberOpenFailed)?,
            component.as_slice(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| LocalFilePreflightError::MemberOpenFailed)?;
        directory_chain.push(next);
    }

    let final_component = components
        .last()
        .ok_or(LocalFilePreflightError::MemberOpenFailed)?;
    let file_fd = fs::openat(
        directory_chain
            .last()
            .ok_or(LocalFilePreflightError::MemberOpenFailed)?,
        final_component.as_slice(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| LocalFilePreflightError::MemberOpenFailed)?;
    let file_stat =
        fs::fstat(&file_fd).map_err(|_| LocalFilePreflightError::FileMetadataUnavailable)?;
    if FileType::from_raw_mode(file_stat.st_mode) != FileType::RegularFile {
        return Err(LocalFilePreflightError::FinalObjectNotRegular);
    }
    validate_file_offset(&file_fd)?;
    let file_filesystem = filesystem_observer.observe(&file_fd)?;

    let root_fd = directory_chain.remove(0);
    Ok(OpenedSelection {
        root_fd,
        file_fd,
        root_stat,
        file_stat,
        root_filesystem,
        file_filesystem,
    })
}

fn validate_file_offset(file_fd: &OwnedFd) -> Result<(), LocalFilePreflightError> {
    let offset = fs::seek(file_fd, fs::SeekFrom::Current(0))
        .map_err(|_| LocalFilePreflightError::FileOffsetUnavailable)?;
    if offset != 0 {
        return Err(LocalFilePreflightError::FileOffsetMismatch);
    }
    Ok(())
}

fn validate_selection(
    facts: &LocalFileExecutionFactsV1,
    authority: &RegistryAuthorizedLocalFilePlanV1<'_, '_>,
    selection: &OpenedSelection,
) -> Result<UnixFileSnapshotV1, LocalFilePreflightError> {
    let observed = snapshot_from_stats(&selection.root_stat, &selection.file_stat)?;
    let planned = facts.snapshot;
    if observed.root() != planned.root() {
        return Err(LocalFilePreflightError::RootIdentityMismatch);
    }
    if observed.file() != planned.file() {
        return Err(LocalFilePreflightError::FileIdentityMismatch);
    }
    if observed != planned {
        return Err(LocalFilePreflightError::SnapshotMismatch);
    }
    validate_source_identity(facts, observed)?;
    authority
        .check_opened_identity_not_internal(observed.file())
        .map_err(map_registry_error)?;
    Ok(observed)
}

pub(crate) fn snapshot_from_stats(
    root_stat: &Stat,
    file_stat: &Stat,
) -> Result<UnixFileSnapshotV1, LocalFilePreflightError> {
    if FileType::from_raw_mode(root_stat.st_mode) != FileType::Directory {
        return Err(LocalFilePreflightError::RootNotDirectory);
    }
    if FileType::from_raw_mode(file_stat.st_mode) != FileType::RegularFile {
        return Err(LocalFilePreflightError::FinalObjectNotRegular);
    }

    let root = object_id_from_stat(root_stat)?;
    let file = object_id_from_stat(file_stat)?;
    let mode = u32::from(file_stat.st_mode);
    let link_count = u64::from(file_stat.st_nlink);
    let size = u64::try_from(file_stat.st_size)
        .map_err(|_| LocalFilePreflightError::MetadataOutOfRange)?;
    let modified_seconds = file_stat.st_mtime;
    let modified_nanoseconds = file_stat.st_mtime_nsec;
    let changed_seconds = file_stat.st_ctime;
    let changed_nanoseconds = file_stat.st_ctime_nsec;

    UnixFileSnapshotV1::new(
        root,
        file,
        UnixFileTypeV1::Regular,
        mode,
        link_count,
        size,
        modified_seconds,
        modified_nanoseconds,
        changed_seconds,
        changed_nanoseconds,
        0,
        size,
    )
    .map_err(|_| LocalFilePreflightError::MetadataOutOfRange)
}

fn object_id_from_stat(stat: &Stat) -> Result<UnixFileObjectIdV1, LocalFilePreflightError> {
    let device =
        u64::try_from(stat.st_dev).map_err(|_| LocalFilePreflightError::MetadataOutOfRange)?;
    let inode = stat.st_ino;
    Ok(UnixFileObjectIdV1::new(device, inode))
}

pub(crate) fn validate_source_identity(
    facts: &LocalFileExecutionFactsV1,
    snapshot: UnixFileSnapshotV1,
) -> Result<(), LocalFilePreflightError> {
    let derived = derive_local_file_source_identity_digest_v1(
        &facts.locator,
        snapshot,
        facts.runtime_profile,
    )
    .map_err(|_| LocalFilePreflightError::SourceIdentityMismatch)?;
    if derived != facts.source_identity_digest {
        return Err(LocalFilePreflightError::SourceIdentityMismatch);
    }
    Ok(())
}

fn map_registry_error(error: RegistryAuthorizationError) -> LocalFilePreflightError {
    match error {
        RegistryAuthorizationError::BindingStateUnavailable
        | RegistryAuthorizationError::InternalPathStateUnavailable => {
            LocalFilePreflightError::AuthorityStateUnavailable
        }
        RegistryAuthorizationError::BindingRevoked
        | RegistryAuthorizationError::BindingOutsideValidity
        | RegistryAuthorizationError::PlanOutsideValidity => {
            LocalFilePreflightError::AuthorityOutsideValidity
        }
        RegistryAuthorizationError::InternalPathPolicyMismatch => {
            LocalFilePreflightError::InternalPathPolicyMismatch
        }
        RegistryAuthorizationError::CanonicalPathReserved => {
            LocalFilePreflightError::CanonicalPathReserved
        }
        RegistryAuthorizationError::OpenedIdentityReserved => {
            LocalFilePreflightError::InternalIdentityReserved
        }
        RegistryAuthorizationError::BindingNotCurrent
        | RegistryAuthorizationError::BindingRepositoryMismatch
        | RegistryAuthorizationError::BindingArtifactMismatch
        | RegistryAuthorizationError::PlanDoesNotNarrowBinding => {
            LocalFilePreflightError::LiveAuthorityMismatch
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObservedFilesystemV1 {
    Apfs,
    Other,
}

trait FilesystemObserverV1 {
    fn observe(&self, fd: &OwnedFd) -> Result<ObservedFilesystemV1, LocalFilePreflightError>;
}

struct LiveFilesystemObserverV1;

impl FilesystemObserverV1 for LiveFilesystemObserverV1 {
    fn observe(&self, fd: &OwnedFd) -> Result<ObservedFilesystemV1, LocalFilePreflightError> {
        let facts = fs::fstatfs(fd).map_err(|_| LocalFilePreflightError::FilesystemUnavailable)?;
        Ok(observed_filesystem(&facts))
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn observed_filesystem(facts: &fs::StatFs) -> ObservedFilesystemV1 {
    let apfs = [
        i8::try_from(b'a').expect("ASCII fits c_char"),
        i8::try_from(b'p').expect("ASCII fits c_char"),
        i8::try_from(b'f').expect("ASCII fits c_char"),
        i8::try_from(b's').expect("ASCII fits c_char"),
        0,
    ];
    if facts.f_fstypename.starts_with(&apfs) {
        ObservedFilesystemV1::Apfs
    } else {
        ObservedFilesystemV1::Other
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn observed_filesystem(_facts: &fs::StatFs) -> ObservedFilesystemV1 {
    ObservedFilesystemV1::Other
}

pub(crate) fn validate_filesystems(
    profile: LocalFileRuntimeProfileV1,
    root: ObservedFilesystemV1,
    file: ObservedFilesystemV1,
) -> Result<(), LocalFilePreflightError> {
    if profile.filesystem() != LocalFileFilesystemV1::Apfs
        || root != ObservedFilesystemV1::Apfs
        || file != ObservedFilesystemV1::Apfs
    {
        return Err(LocalFilePreflightError::FilesystemMismatch);
    }
    Ok(())
}

struct LivePlatformObservationV1 {
    release: Vec<u8>,
    version: Vec<u8>,
    architecture: LocalFileArchitectureV1,
}

fn observe_live_platform(
    profile: LocalFileRuntimeProfileV1,
) -> Result<LivePlatformObservationV1, LocalFilePreflightError> {
    if profile.operating_system() != LocalFileOperatingSystemV1::MacOs
        || profile.deadline_model() != LocalFileDeadlineModelV1::CooperativeBetweenIoCalls
    {
        return Err(LocalFilePreflightError::RuntimeProfileMismatch);
    }
    if !cfg!(target_os = "macos") {
        return Err(LocalFilePreflightError::UnsupportedOperatingSystem);
    }

    let uname = rustix::system::uname();
    if uname.sysname().to_bytes() != b"Darwin" {
        return Err(LocalFilePreflightError::UnsupportedOperatingSystem);
    }
    let architecture = live_architecture()?;
    if profile.architecture() != architecture {
        return Err(LocalFilePreflightError::ArchitectureMismatch);
    }
    Ok(LivePlatformObservationV1 {
        release: uname.release().to_bytes().to_vec(),
        version: uname.version().to_bytes().to_vec(),
        architecture,
    })
}

fn live_architecture() -> Result<LocalFileArchitectureV1, LocalFilePreflightError> {
    if cfg!(target_arch = "aarch64") {
        Ok(LocalFileArchitectureV1::Aarch64)
    } else if cfg!(target_arch = "x86_64") {
        Ok(LocalFileArchitectureV1::X86_64)
    } else {
        Err(LocalFilePreflightError::ArchitectureMismatch)
    }
}

pub(crate) struct LiveHostCertificationV1 {
    _private: (),
}

trait CertificationAuthorityV1 {
    fn admit(
        &self,
        profile: LocalFileRuntimeProfileV1,
        observation: &LivePlatformObservationV1,
    ) -> Result<LiveHostCertificationV1, LocalFilePreflightError>;
}

struct FrozenCertificationAuthorityV1;

impl CertificationAuthorityV1 for FrozenCertificationAuthorityV1 {
    fn admit(
        &self,
        _profile: LocalFileRuntimeProfileV1,
        observation: &LivePlatformObservationV1,
    ) -> Result<LiveHostCertificationV1, LocalFilePreflightError> {
        let _ = (
            &observation.release,
            &observation.version,
            observation.architecture,
        );
        // Intentionally empty until the external certification matrix freezes
        // an exact profile digest and allowed Darwin build set.
        Err(LocalFilePreflightError::CertificationProfileNotAdmitted)
    }
}

#[cfg(test)]
pub(crate) fn preflight_with_test_certification_v1<'binding_registry, 'path_registry>(
    plan: &VerifiedLocalFilePlanV1,
    authority: RegistryAuthorizedLocalFilePlanV1<'binding_registry, 'path_registry>,
) -> Result<PreflightedLocalFileV1<'binding_registry, 'path_registry>, LocalFilePreflightError> {
    preflight_with(
        plan,
        authority,
        &TestOnlyCertificationAuthorityV1,
        &LiveFilesystemObserverV1,
        &SystemWallClockV1,
        &NoopPathAccessObserverV1,
        || {},
    )
}

#[cfg(test)]
struct TestOnlyCertificationAuthorityV1;

#[cfg(test)]
impl CertificationAuthorityV1 for TestOnlyCertificationAuthorityV1 {
    fn admit(
        &self,
        profile: LocalFileRuntimeProfileV1,
        observation: &LivePlatformObservationV1,
    ) -> Result<LiveHostCertificationV1, LocalFilePreflightError> {
        if observation.release.is_empty()
            || observation.version.is_empty()
            || observation.architecture != profile.architecture()
        {
            return Err(LocalFilePreflightError::CertificationProfileNotAdmitted);
        }
        Ok(LiveHostCertificationV1 { _private: () })
    }
}

/// Contentless zero-read local-file preflight failures.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LocalFilePreflightError {
    PlanAuthorizationMismatch,
    WallClockUnavailable,
    WallClockRegressed,
    AuthorityOutsideValidity,
    AuthorityStateUnavailable,
    LiveAuthorityMismatch,
    UnsupportedOperatingSystem,
    RuntimeProfileMismatch,
    ArchitectureMismatch,
    RootOpenFailed,
    RootMetadataUnavailable,
    RootNotDirectory,
    RootIdentityMismatch,
    MemberOpenFailed,
    FileMetadataUnavailable,
    FileOffsetUnavailable,
    FileOffsetMismatch,
    FinalObjectNotRegular,
    FileIdentityMismatch,
    SnapshotMismatch,
    MetadataOutOfRange,
    FilesystemUnavailable,
    FilesystemMismatch,
    SourceIdentityMismatch,
    InternalPathPolicyMismatch,
    CanonicalPathReserved,
    InternalIdentityReserved,
    PathRevalidationMismatch,
    RetainedHandleChanged,
    CertificationProfileNotAdmitted,
}

impl LocalFilePreflightError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PlanAuthorizationMismatch => "EVIDENTRAIL_LOCAL_PREFLIGHT_PLAN_AUTH_MISMATCH",
            Self::WallClockUnavailable => "EVIDENTRAIL_LOCAL_PREFLIGHT_WALL_CLOCK_UNAVAILABLE",
            Self::WallClockRegressed => "EVIDENTRAIL_LOCAL_PREFLIGHT_WALL_CLOCK_REGRESSED",
            Self::AuthorityOutsideValidity => "EVIDENTRAIL_LOCAL_PREFLIGHT_AUTHORITY_OUTSIDE_VALIDITY",
            Self::AuthorityStateUnavailable => "EVIDENTRAIL_LOCAL_PREFLIGHT_AUTHORITY_STATE_UNAVAILABLE",
            Self::LiveAuthorityMismatch => "EVIDENTRAIL_LOCAL_PREFLIGHT_LIVE_AUTHORITY_MISMATCH",
            Self::UnsupportedOperatingSystem => "EVIDENTRAIL_LOCAL_PREFLIGHT_UNSUPPORTED_OS",
            Self::RuntimeProfileMismatch => "EVIDENTRAIL_LOCAL_PREFLIGHT_RUNTIME_PROFILE_MISMATCH",
            Self::ArchitectureMismatch => "EVIDENTRAIL_LOCAL_PREFLIGHT_ARCHITECTURE_MISMATCH",
            Self::RootOpenFailed => "EVIDENTRAIL_LOCAL_PREFLIGHT_ROOT_OPEN_FAILED",
            Self::RootMetadataUnavailable => "EVIDENTRAIL_LOCAL_PREFLIGHT_ROOT_METADATA_UNAVAILABLE",
            Self::RootNotDirectory => "EVIDENTRAIL_LOCAL_PREFLIGHT_ROOT_NOT_DIRECTORY",
            Self::RootIdentityMismatch => "EVIDENTRAIL_LOCAL_PREFLIGHT_ROOT_IDENTITY_MISMATCH",
            Self::MemberOpenFailed => "EVIDENTRAIL_LOCAL_PREFLIGHT_MEMBER_OPEN_FAILED",
            Self::FileMetadataUnavailable => "EVIDENTRAIL_LOCAL_PREFLIGHT_FILE_METADATA_UNAVAILABLE",
            Self::FileOffsetUnavailable => "EVIDENTRAIL_LOCAL_PREFLIGHT_FILE_OFFSET_UNAVAILABLE",
            Self::FileOffsetMismatch => "EVIDENTRAIL_LOCAL_PREFLIGHT_FILE_OFFSET_MISMATCH",
            Self::FinalObjectNotRegular => "EVIDENTRAIL_LOCAL_PREFLIGHT_FINAL_NOT_REGULAR",
            Self::FileIdentityMismatch => "EVIDENTRAIL_LOCAL_PREFLIGHT_FILE_IDENTITY_MISMATCH",
            Self::SnapshotMismatch => "EVIDENTRAIL_LOCAL_PREFLIGHT_SNAPSHOT_MISMATCH",
            Self::MetadataOutOfRange => "EVIDENTRAIL_LOCAL_PREFLIGHT_METADATA_OUT_OF_RANGE",
            Self::FilesystemUnavailable => "EVIDENTRAIL_LOCAL_PREFLIGHT_FILESYSTEM_UNAVAILABLE",
            Self::FilesystemMismatch => "EVIDENTRAIL_LOCAL_PREFLIGHT_FILESYSTEM_MISMATCH",
            Self::SourceIdentityMismatch => "EVIDENTRAIL_LOCAL_PREFLIGHT_SOURCE_IDENTITY_MISMATCH",
            Self::InternalPathPolicyMismatch => {
                "EVIDENTRAIL_LOCAL_PREFLIGHT_INTERNAL_PATH_POLICY_MISMATCH"
            }
            Self::CanonicalPathReserved => "EVIDENTRAIL_LOCAL_PREFLIGHT_CANONICAL_PATH_RESERVED",
            Self::InternalIdentityReserved => "EVIDENTRAIL_LOCAL_PREFLIGHT_INTERNAL_IDENTITY_RESERVED",
            Self::PathRevalidationMismatch => "EVIDENTRAIL_LOCAL_PREFLIGHT_PATH_REVALIDATION_MISMATCH",
            Self::RetainedHandleChanged => "EVIDENTRAIL_LOCAL_PREFLIGHT_RETAINED_HANDLE_CHANGED",
            Self::CertificationProfileNotAdmitted => {
                "EVIDENTRAIL_LOCAL_PREFLIGHT_CERTIFICATION_PROFILE_NOT_ADMITTED"
            }
        }
    }
}

impl fmt::Debug for LocalFilePreflightError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalFilePreflightError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for LocalFilePreflightError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for LocalFilePreflightError {}

#[cfg(all(test, target_os = "macos"))]
mod tests;
