use std::cell::{Cell, RefCell};
use std::ffi::OsStr;
use std::fs::{
    self as std_fs, File, FileTimes, OpenOptions, Permissions, hard_link, set_permissions,
};
use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use evidentrail_authority::{
    CanonicalUnixPathV1, InternalPathPolicyV1, InternalPathRegistryV1,
    LiveApprovedBindingRegistryV1, RegistryAuthorizedLocalFilePlanV1,
    authorize_local_file_plan_with_registries_v1,
};
use evidentrail_schema::{
    AdapterIdentity, ApprovedLocalFileBindingMaterialV1, ApprovedLocalFileLocatorAuthorityV1,
    BindingId, IdentityProofKindV1, InternalPathPolicyDigest, LOCAL_FILE_ADAPTER_KIND_V1,
    LOCAL_FILE_ADAPTER_VERSION_V1, LocalFileArchitectureV1, LocalFileCertificationProfileDigest,
    LocalFileDeadlineModelV1, LocalFileFilesystemV1, LocalFileOperatingSystemV1,
    LocalFileOrderingV1, LocalFilePlanCapsV1, LocalFileQueryPlanMaterialV1,
    LocalFileRuntimeProfileV1, LocalFileSnapshotModeV1, PolicyDigest, RepositoryIdentityDigest,
    RetrievalId, SourceIdentityV1, UnixFileObjectIdV1, UnixFileSnapshotV1, UnixFileTypeV1,
    UnixLocalFileLocatorV1, UnixTimestampNanos,
};
use evidentrail_wire::{
    ApprovedLocalFileBindingV1, VerifiedLocalFilePlanV1,
    derive_local_file_source_identity_digest_v1, derive_local_file_source_member_v1,
    encode_approved_local_file_binding_v1, encode_local_file_plan_v1,
};
use rustix::fs::{FileType, SeekFrom};

use super::*;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const NANOS_PER_SECOND: i128 = 1_000_000_000;

struct SyntheticFixture {
    container: PathBuf,
    root: PathBuf,
    internal: PathBuf,
}

impl SyntheticFixture {
    fn new() -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let requested = std::env::temp_dir().join(format!(
            "evidentrail-local-file-preflight-{}-{sequence}",
            std::process::id()
        ));
        Self::create(requested)
    }

    fn new_short() -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let requested = Path::new("/tmp").join(format!("evr-pf-{}-{sequence}", std::process::id()));
        Self::create(requested)
    }

    fn create(requested: PathBuf) -> Self {
        std_fs::create_dir(&requested).unwrap();
        let container = std_fs::canonicalize(requested).unwrap();
        let root = container.join("approved-root");
        let internal = container.join("internal-store");
        std_fs::create_dir(&root).unwrap();
        std_fs::create_dir(&internal).unwrap();
        Self {
            container,
            root,
            internal,
        }
    }

    fn policy(&self) -> InternalPathPolicyV1 {
        InternalPathPolicyV1::new(
            [CanonicalUnixPathV1::new(path_bytes(&self.internal)).unwrap()],
            [],
        )
        .unwrap()
    }

    fn write_file(&self, components: &[&[u8]], bytes: &[u8]) -> PathBuf {
        let path = selected_path(&self.root, components);
        if let Some(parent) = path.parent() {
            std_fs::create_dir_all(parent).unwrap();
        }
        std_fs::write(&path, bytes).unwrap();
        path
    }
}

impl Drop for SyntheticFixture {
    fn drop(&mut self) {
        let _ = std_fs::remove_dir_all(&self.container);
    }
}

struct Documents {
    binding: ApprovedLocalFileBindingV1,
    plan: VerifiedLocalFilePlanV1,
    checked_at: UnixTimestampNanos,
}

impl Documents {
    fn new(
        root: &Path,
        components: &[&[u8]],
        internal_policy_digest: InternalPathPolicyDigest,
        profile: LocalFileRuntimeProfileV1,
    ) -> Self {
        let checked_at = now_nanos();
        let valid_from = UnixTimestampNanos::new(checked_at.get() - 60 * NANOS_PER_SECOND);
        let created_at = UnixTimestampNanos::new(checked_at.get() - 30 * NANOS_PER_SECOND);
        let execute_before = UnixTimestampNanos::new(checked_at.get() + 300 * NANOS_PER_SECOND);
        let expires_at = UnixTimestampNanos::new(checked_at.get() + 600 * NANOS_PER_SECOND);
        let locator = locator(root, components);
        let snapshot = snapshot(root, &selected_path(root, components));
        let maximum_caps = LocalFilePlanCapsV1::new(1_048_576, 4_096, 65_536, 60_000).unwrap();
        let binding_material = ApprovedLocalFileBindingMaterialV1::new(
            BindingId::from_bytes([0x11; 32]),
            1,
            RepositoryIdentityDigest::from_bytes([0x22; 32]),
            AdapterIdentity::new(LOCAL_FILE_ADAPTER_KIND_V1, LOCAL_FILE_ADAPTER_VERSION_V1)
                .unwrap(),
            ApprovedLocalFileLocatorAuthorityV1::new(locator.clone(), snapshot.root()),
            1,
            PolicyDigest::from_bytes([0x33; 32]),
            internal_policy_digest,
            profile,
            LocalFileSnapshotModeV1::WholeFileFixedHighWater,
            LocalFileOrderingV1::SingleFileByteOrder,
            maximum_caps,
            valid_from,
            expires_at,
        )
        .unwrap();
        let binding = encode_approved_local_file_binding_v1(&binding_material).unwrap();
        let source_identity = SourceIdentityV1::new(
            binding.material().adapter().clone(),
            *binding.binding_ref(),
            derive_local_file_source_identity_digest_v1(&locator, snapshot, profile).unwrap(),
            IdentityProofKindV1::LocalFileMetadata,
            valid_from,
            Some(expires_at),
        )
        .unwrap();
        let plan_material = LocalFileQueryPlanMaterialV1::new(
            RetrievalId::from_bytes([0x44; 32]),
            binding.material().repository_identity(),
            source_identity,
            locator.clone(),
            profile,
            derive_local_file_source_member_v1(&locator).unwrap(),
            snapshot,
            LocalFileSnapshotModeV1::WholeFileFixedHighWater,
            LocalFileOrderingV1::SingleFileByteOrder,
            LocalFileOrderingV1::SingleFileByteOrder,
            internal_policy_digest,
            binding.material().policy_version().get(),
            binding.material().policy_digest(),
            LocalFilePlanCapsV1::new(1_048_576, 2_048, 32_768, 30_000).unwrap(),
            created_at,
            execute_before,
            None,
        )
        .unwrap();
        let plan = encode_local_file_plan_v1(&plan_material).unwrap();
        Self {
            binding,
            plan,
            checked_at,
        }
    }
}

fn path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

fn selected_path(root: &Path, components: &[&[u8]]) -> PathBuf {
    components
        .iter()
        .fold(root.to_path_buf(), |path, component| {
            path.join(OsStr::from_bytes(component))
        })
}

fn locator(root: &Path, components: &[&[u8]]) -> UnixLocalFileLocatorV1 {
    UnixLocalFileLocatorV1::new(
        path_bytes(root),
        components
            .iter()
            .map(|component| component.to_vec())
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

fn snapshot(root: &Path, selected: &Path) -> UnixFileSnapshotV1 {
    let root_metadata = std_fs::metadata(root).unwrap();
    let file_metadata = std_fs::metadata(selected).unwrap();
    UnixFileSnapshotV1::new(
        UnixFileObjectIdV1::new(root_metadata.dev(), root_metadata.ino()),
        UnixFileObjectIdV1::new(file_metadata.dev(), file_metadata.ino()),
        UnixFileTypeV1::Regular,
        file_metadata.mode(),
        file_metadata.nlink(),
        file_metadata.size(),
        file_metadata.mtime(),
        file_metadata.mtime_nsec(),
        file_metadata.ctime(),
        file_metadata.ctime_nsec(),
        0,
        file_metadata.size(),
    )
    .unwrap()
}

fn now_nanos() -> UnixTimestampNanos {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    UnixTimestampNanos::new(i128::try_from(elapsed.as_nanos()).unwrap())
}

fn runtime_profile(architecture: LocalFileArchitectureV1) -> LocalFileRuntimeProfileV1 {
    LocalFileRuntimeProfileV1::new(
        LocalFileOperatingSystemV1::MacOs,
        LocalFileFilesystemV1::Apfs,
        architecture,
        LocalFileDeadlineModelV1::CooperativeBetweenIoCalls,
        LocalFileCertificationProfileDigest::from_bytes([0x55; 32]),
    )
    .unwrap()
}

fn current_runtime_profile() -> LocalFileRuntimeProfileV1 {
    runtime_profile(live_architecture().unwrap())
}

fn install_binding(docs: &Documents) -> LiveApprovedBindingRegistryV1 {
    let registry = LiveApprovedBindingRegistryV1::new();
    registry.install(docs.binding.clone()).unwrap();
    registry
}

fn authorize<'binding_registry, 'path_registry>(
    docs: &Documents,
    bindings: &'binding_registry LiveApprovedBindingRegistryV1,
    internal_paths: &'path_registry InternalPathRegistryV1,
) -> RegistryAuthorizedLocalFilePlanV1<'binding_registry, 'path_registry> {
    authorize_local_file_plan_with_registries_v1(
        &docs.plan,
        &docs.binding,
        bindings,
        internal_paths,
        docs.checked_at,
    )
    .unwrap()
}

struct TestCertificationAuthorityV1;

impl CertificationAuthorityV1 for TestCertificationAuthorityV1 {
    fn admit(
        &self,
        profile: LocalFileRuntimeProfileV1,
        observation: &LivePlatformObservationV1,
    ) -> Result<LiveHostCertificationV1, LocalFilePreflightError> {
        assert_eq!(profile.architecture(), observation.architecture);
        assert!(!observation.release.is_empty());
        assert!(!observation.version.is_empty());
        Ok(LiveHostCertificationV1 { _private: () })
    }
}

struct FixedClockV1(UnixTimestampNanos);

impl SealedWallClockV1 for FixedClockV1 {
    fn now(&self) -> Result<UnixTimestampNanos, LocalFilePreflightError> {
        Ok(self.0)
    }
}

struct MutableWallClockV1(Cell<UnixTimestampNanos>);

impl MutableWallClockV1 {
    fn set(&self, observed_at: UnixTimestampNanos) {
        self.0.set(observed_at);
    }
}

impl SealedWallClockV1 for MutableWallClockV1 {
    fn now(&self) -> Result<UnixTimestampNanos, LocalFilePreflightError> {
        Ok(self.0.get())
    }
}

#[derive(Default)]
struct CountingPathAccessObserverV1(Cell<usize>);

impl PathAccessObserverV1 for CountingPathAccessObserverV1 {
    fn before_path_access(&self) {
        self.0.set(self.0.get() + 1);
    }
}

struct OtherFilesystemObserverV1;

impl FilesystemObserverV1 for OtherFilesystemObserverV1 {
    fn observe(&self, _fd: &OwnedFd) -> Result<ObservedFilesystemV1, LocalFilePreflightError> {
        Ok(ObservedFilesystemV1::Other)
    }
}

#[derive(Default)]
struct RejectingReadTrapFilesystemObserverV1 {
    opened_file_descriptions: RefCell<Vec<OwnedFd>>,
}

impl FilesystemObserverV1 for RejectingReadTrapFilesystemObserverV1 {
    fn observe(&self, fd: &OwnedFd) -> Result<ObservedFilesystemV1, LocalFilePreflightError> {
        let stat =
            rustix::fs::fstat(fd).map_err(|_| LocalFilePreflightError::FilesystemUnavailable)?;
        if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile {
            self.opened_file_descriptions.borrow_mut().push(
                fd.try_clone()
                    .map_err(|_| LocalFilePreflightError::FilesystemUnavailable)?,
            );
            Ok(ObservedFilesystemV1::Other)
        } else {
            Ok(ObservedFilesystemV1::Apfs)
        }
    }
}

fn private_preflight<'binding_registry, 'path_registry, F, H>(
    docs: &Documents,
    authority: RegistryAuthorizedLocalFilePlanV1<'binding_registry, 'path_registry>,
    filesystem_observer: &F,
    between_passes: H,
) -> Result<PreflightedLocalFileV1<'binding_registry, 'path_registry>, LocalFilePreflightError>
where
    F: FilesystemObserverV1,
    H: FnOnce(),
{
    preflight_with(
        &docs.plan,
        authority,
        &TestCertificationAuthorityV1,
        filesystem_observer,
        &FixedClockV1(docs.checked_at),
        &NoopPathAccessObserverV1,
        between_passes,
    )
}

fn assert_error_in(error: LocalFilePreflightError, expected: &[LocalFilePreflightError]) {
    assert!(expected.contains(&error), "unexpected error: {error:?}");
}

fn basic_fixture() -> (SyntheticFixture, InternalPathPolicyV1, Documents, PathBuf) {
    let fixture = SyntheticFixture::new();
    let file = fixture.write_file(&[b"nested", b"service.log"], b"alpha\nbeta\n");
    let policy = fixture.policy();
    let docs = Documents::new(
        &fixture.root,
        &[b"nested", b"service.log"],
        policy.digest(),
        current_runtime_profile(),
    );
    (fixture, policy, docs, file)
}

#[cfg(target_os = "macos")]
#[test]
fn explicit_live_matrix_admission_enables_public_executable_preflight() {
    let (_fixture, policy, docs, _file) = basic_fixture();
    let bindings = install_binding(&docs);
    let internal_paths = InternalPathRegistryV1::new(policy);
    let admission = crate::admit_current_local_file_host_v1().unwrap();
    let preflight = preflight_admitted_local_file_v1(
        &docs.plan,
        authorize(&docs, &bindings, &internal_paths),
        &admission,
    )
    .unwrap();
    assert_eq!(preflight.plan_id(), docs.plan.plan_id());
    assert_eq!(
        rustix::fs::seek(&preflight.file_fd, SeekFrom::Current(0)).unwrap(),
        0
    );
    assert!(!preflight.is_completion_proof());
}

#[test]
fn frozen_certification_and_expired_authority_touch_no_paths() {
    let (_fixture, policy, docs, _file) = basic_fixture();
    let bindings = install_binding(&docs);
    let internal_paths = InternalPathRegistryV1::new(policy);
    let path_accesses = CountingPathAccessObserverV1::default();
    let error = preflight_with(
        &docs.plan,
        authorize(&docs, &bindings, &internal_paths),
        &FrozenCertificationAuthorityV1,
        &LiveFilesystemObserverV1,
        &FixedClockV1(docs.checked_at),
        &path_accesses,
        || {},
    )
    .unwrap_err();
    assert_eq!(
        error,
        LocalFilePreflightError::CertificationProfileNotAdmitted
    );
    assert_eq!(path_accesses.0.get(), 0);

    let public_error =
        preflight_local_file_v1(&docs.plan, authorize(&docs, &bindings, &internal_paths))
            .unwrap_err();
    assert_eq!(
        public_error,
        LocalFilePreflightError::CertificationProfileNotAdmitted
    );

    let expired_path_accesses = CountingPathAccessObserverV1::default();
    let error = preflight_with(
        &docs.plan,
        authorize(&docs, &bindings, &internal_paths),
        &TestCertificationAuthorityV1,
        &LiveFilesystemObserverV1,
        &FixedClockV1(docs.plan.material().execute_before()),
        &expired_path_accesses,
        || {},
    )
    .unwrap_err();
    assert_eq!(error, LocalFilePreflightError::AuthorityOutsideValidity);
    assert_eq!(expired_path_accesses.0.get(), 0);
}

#[test]
fn expiry_during_the_race_window_prevents_token_issuance() {
    let (_fixture, policy, docs, _file) = basic_fixture();
    let bindings = install_binding(&docs);
    let internal_paths = InternalPathRegistryV1::new(policy);
    let clock = MutableWallClockV1(Cell::new(docs.checked_at));
    let error = preflight_with(
        &docs.plan,
        authorize(&docs, &bindings, &internal_paths),
        &TestCertificationAuthorityV1,
        &LiveFilesystemObserverV1,
        &clock,
        &NoopPathAccessObserverV1,
        || clock.set(docs.plan.material().execute_before()),
    )
    .unwrap_err();
    assert_eq!(error, LocalFilePreflightError::AuthorityOutsideValidity);
}

#[test]
fn private_preflight_owns_handles_keeps_offset_zero_and_is_not_completion() {
    let (fixture, policy, docs, _file) = basic_fixture();
    let bindings = install_binding(&docs);
    let internal_paths = InternalPathRegistryV1::new(policy);
    let token = private_preflight(
        &docs,
        authorize(&docs, &bindings, &internal_paths),
        &LiveFilesystemObserverV1,
        || {},
    )
    .unwrap();
    assert_eq!(token.plan_id(), docs.plan.plan_id());
    assert!(!token.is_completion_proof());
    assert_eq!(
        rustix::fs::seek(&token.file_fd, SeekFrom::Current(0)).unwrap(),
        0
    );
    let rendered = format!("{token:?}");
    assert!(!rendered.contains(fixture.root.to_string_lossy().as_ref()));
    assert!(!rendered.contains("service.log"));
    assert!(rendered.contains("read_api_exposed: false"));
    assert!(rendered.contains("completion_proof: false"));
}

#[test]
fn filesystem_rejection_preserves_the_open_file_description_at_offset_zero() {
    let (_fixture, policy, docs, _file) = basic_fixture();
    let bindings = install_binding(&docs);
    let internal_paths = InternalPathRegistryV1::new(policy);
    let observer = RejectingReadTrapFilesystemObserverV1::default();
    let error = private_preflight(
        &docs,
        authorize(&docs, &bindings, &internal_paths),
        &observer,
        || {},
    )
    .unwrap_err();
    assert_eq!(error, LocalFilePreflightError::FilesystemMismatch);
    let descriptions = observer.opened_file_descriptions.borrow();
    assert_eq!(descriptions.len(), 1);
    assert_eq!(
        rustix::fs::seek(&descriptions[0], SeekFrom::Current(0)).unwrap(),
        0
    );
}

#[test]
fn descriptor_walk_rejects_nested_and_final_symlinks() {
    {
        let fixture = SyntheticFixture::new();
        let actual = fixture.root.join("actual");
        std_fs::create_dir(&actual).unwrap();
        std_fs::write(actual.join("service.log"), b"nested-target").unwrap();
        symlink(&actual, fixture.root.join("jump")).unwrap();
        let policy = fixture.policy();
        let docs = Documents::new(
            &fixture.root,
            &[b"jump", b"service.log"],
            policy.digest(),
            current_runtime_profile(),
        );
        let bindings = install_binding(&docs);
        let internal_paths = InternalPathRegistryV1::new(policy);
        let error = private_preflight(
            &docs,
            authorize(&docs, &bindings, &internal_paths),
            &LiveFilesystemObserverV1,
            || {},
        )
        .unwrap_err();
        assert_eq!(error, LocalFilePreflightError::MemberOpenFailed);
    }

    {
        let fixture = SyntheticFixture::new();
        let actual = fixture.write_file(&[b"actual.log"], b"final-target");
        symlink(actual, fixture.root.join("link.log")).unwrap();
        let policy = fixture.policy();
        let docs = Documents::new(
            &fixture.root,
            &[b"link.log"],
            policy.digest(),
            current_runtime_profile(),
        );
        let bindings = install_binding(&docs);
        let internal_paths = InternalPathRegistryV1::new(policy);
        let error = private_preflight(
            &docs,
            authorize(&docs, &bindings, &internal_paths),
            &LiveFilesystemObserverV1,
            || {},
        )
        .unwrap_err();
        assert_eq!(error, LocalFilePreflightError::MemberOpenFailed);
    }
}

#[test]
fn second_descriptor_pass_rejects_root_and_member_replacement() {
    {
        let (fixture, policy, docs, _file) = basic_fixture();
        let bindings = install_binding(&docs);
        let internal_paths = InternalPathRegistryV1::new(policy);
        let old_root = fixture.container.join("displaced-root");
        let replacement_root = fixture.root.clone();
        let error = private_preflight(
            &docs,
            authorize(&docs, &bindings, &internal_paths),
            &LiveFilesystemObserverV1,
            || {
                std_fs::rename(&replacement_root, &old_root).unwrap();
                std_fs::create_dir(&replacement_root).unwrap();
                std_fs::create_dir(replacement_root.join("nested")).unwrap();
                std_fs::write(
                    replacement_root.join("nested/service.log"),
                    b"alpha\nbeta\n",
                )
                .unwrap();
            },
        )
        .unwrap_err();
        assert_eq!(error, LocalFilePreflightError::RootIdentityMismatch);
    }

    {
        let (fixture, policy, docs, file) = basic_fixture();
        let bindings = install_binding(&docs);
        let internal_paths = InternalPathRegistryV1::new(policy);
        let displaced = fixture.container.join("displaced-member.log");
        let replacement = file.clone();
        let error = private_preflight(
            &docs,
            authorize(&docs, &bindings, &internal_paths),
            &LiveFilesystemObserverV1,
            || {
                std_fs::rename(&replacement, &displaced).unwrap();
                std_fs::write(&replacement, b"alpha\nbeta\n").unwrap();
            },
        )
        .unwrap_err();
        assert_eq!(error, LocalFilePreflightError::FileIdentityMismatch);
    }
}

#[test]
fn active_internal_hard_link_is_rejected_by_opened_identity() {
    let fixture = SyntheticFixture::new();
    let internal_file = fixture.internal.join("active.segment");
    std_fs::write(&internal_file, b"internal-ciphertext").unwrap();
    let outside_link = fixture.root.join("approved.log");
    hard_link(&internal_file, &outside_link).unwrap();
    let policy = fixture.policy();
    let docs = Documents::new(
        &fixture.root,
        &[b"approved.log"],
        policy.digest(),
        current_runtime_profile(),
    );
    let bindings = install_binding(&docs);
    let internal_paths = InternalPathRegistryV1::new(policy);
    internal_paths
        .register_active_identity(docs.plan.material().snapshot().file())
        .unwrap();
    let error = private_preflight(
        &docs,
        authorize(&docs, &bindings, &internal_paths),
        &LiveFilesystemObserverV1,
        || {},
    )
    .unwrap_err();
    assert_eq!(error, LocalFilePreflightError::InternalIdentityReserved);
}

#[test]
fn special_object_is_rejected_without_blocking_or_reading() {
    let fixture = SyntheticFixture::new_short();
    let socket_path = fixture.root.join("service.sock");
    let _listener = UnixListener::bind(&socket_path).unwrap();
    let policy = fixture.policy();
    let docs = Documents::new(
        &fixture.root,
        &[b"service.sock"],
        policy.digest(),
        current_runtime_profile(),
    );
    let bindings = install_binding(&docs);
    let internal_paths = InternalPathRegistryV1::new(policy);
    let error = private_preflight(
        &docs,
        authorize(&docs, &bindings, &internal_paths),
        &LiveFilesystemObserverV1,
        || {},
    )
    .unwrap_err();
    assert_error_in(
        error,
        &[
            LocalFilePreflightError::MemberOpenFailed,
            LocalFilePreflightError::FinalObjectNotRegular,
        ],
    );
}

fn mutation_error<M>(mutate: M) -> LocalFilePreflightError
where
    M: FnOnce(&Path),
{
    let (_fixture, policy, docs, file) = basic_fixture();
    mutate(&file);
    let bindings = install_binding(&docs);
    let internal_paths = InternalPathRegistryV1::new(policy);
    private_preflight(
        &docs,
        authorize(&docs, &bindings, &internal_paths),
        &LiveFilesystemObserverV1,
        || {},
    )
    .unwrap_err()
}

#[test]
fn exact_snapshot_rejects_chmod_touch_append_and_truncate() {
    let chmod_error = mutation_error(|file| {
        set_permissions(file, Permissions::from_mode(0o600)).unwrap();
    });
    assert_eq!(chmod_error, LocalFilePreflightError::SnapshotMismatch);

    let touch_error = mutation_error(|file| {
        File::open(file)
            .unwrap()
            .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(1_234_567)))
            .unwrap();
    });
    assert_eq!(touch_error, LocalFilePreflightError::SnapshotMismatch);

    let append_error = mutation_error(|file| {
        OpenOptions::new()
            .append(true)
            .open(file)
            .unwrap()
            .write_all(b"later")
            .unwrap();
    });
    assert_eq!(append_error, LocalFilePreflightError::SnapshotMismatch);

    let truncate_error = mutation_error(|file| {
        OpenOptions::new()
            .write(true)
            .open(file)
            .unwrap()
            .set_len(1)
            .unwrap();
    });
    assert_eq!(truncate_error, LocalFilePreflightError::SnapshotMismatch);
}

#[test]
fn filesystem_and_runtime_profile_mismatches_fail_closed() {
    {
        let (_fixture, policy, docs, _file) = basic_fixture();
        let bindings = install_binding(&docs);
        let internal_paths = InternalPathRegistryV1::new(policy);
        let error = private_preflight(
            &docs,
            authorize(&docs, &bindings, &internal_paths),
            &OtherFilesystemObserverV1,
            || {},
        )
        .unwrap_err();
        assert_eq!(error, LocalFilePreflightError::FilesystemMismatch);
    }

    {
        let fixture = SyntheticFixture::new();
        fixture.write_file(&[b"service.log"], b"profile-mismatch");
        let policy = fixture.policy();
        let opposite_architecture = match live_architecture().unwrap() {
            LocalFileArchitectureV1::Aarch64 => LocalFileArchitectureV1::X86_64,
            LocalFileArchitectureV1::X86_64 => LocalFileArchitectureV1::Aarch64,
            LocalFileArchitectureV1::OtherVersioned { .. } => unreachable!(),
        };
        let docs = Documents::new(
            &fixture.root,
            &[b"service.log"],
            policy.digest(),
            runtime_profile(opposite_architecture),
        );
        let bindings = install_binding(&docs);
        let internal_paths = InternalPathRegistryV1::new(policy);
        let path_accesses = CountingPathAccessObserverV1::default();
        let error = preflight_with(
            &docs.plan,
            authorize(&docs, &bindings, &internal_paths),
            &TestCertificationAuthorityV1,
            &LiveFilesystemObserverV1,
            &FixedClockV1(docs.checked_at),
            &path_accesses,
            || {},
        )
        .unwrap_err();
        assert_eq!(error, LocalFilePreflightError::ArchitectureMismatch);
        assert_eq!(path_accesses.0.get(), 0);
    }
}

#[test]
fn public_errors_and_debug_surfaces_are_contentless() {
    let (fixture, policy, docs, _file) = basic_fixture();
    let bindings = install_binding(&docs);
    let internal_paths = InternalPathRegistryV1::new(policy);
    let error = preflight_local_file_v1(&docs.plan, authorize(&docs, &bindings, &internal_paths))
        .unwrap_err();
    let sensitive_root = fixture.root.to_string_lossy();
    let sensitive_hash = docs.plan.plan_digest().to_string();
    for rendered in [format!("{error:?}"), error.to_string()] {
        assert!(!rendered.contains(sensitive_root.as_ref()));
        assert!(!rendered.contains("service.log"));
        assert!(!rendered.contains(&sensitive_hash));
    }
}
