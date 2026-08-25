use std::fs::{self as std_fs, OpenOptions};
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{DirBuilderExt as _, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use evidentrail_schema::{LocalFileArchitectureV1, UnixFileObjectIdV1};
use rustix::fd::OwnedFd;
use rustix::fs::{self as rfs, FileType, Mode, OFlags, Stat};

use super::{
    LocalFileHostCertificationCellV1 as Cell, LocalFileHostCertificationMatrixErrorV1 as Error,
    LocalFileHostCertificationReceiptV1, LocalFileHostIdentityDigestV1, REQUIRED_CELLS_V1,
    derive_host_identity_digest,
};
use crate::preflight::{ObservedFilesystemV1, observed_filesystem, snapshot_from_stats};

static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct HostFactsV1 {
    darwin_identity_valid: bool,
    architecture: Option<LocalFileArchitectureV1>,
    architecture_identity_valid: bool,
    identity_digest: LocalFileHostIdentityDigestV1,
}

struct MatrixFixtureV1 {
    root: PathBuf,
}

impl MatrixFixtureV1 {
    fn create() -> Result<Self, Error> {
        let base =
            std_fs::canonicalize(std::env::temp_dir()).map_err(|_| Error::FixtureUnavailable)?;
        for _ in 0..1_024 {
            let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = base.join(format!(
                "evidentrail-local-host-matrix-{}-{sequence}",
                std::process::id()
            ));
            let created = std_fs::DirBuilder::new().mode(0o700).create(&root);
            match created {
                Ok(()) => return Ok(Self { root }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(Error::FixtureUnavailable),
            }
        }
        Err(Error::FixtureUnavailable)
    }

    fn cell_root(&self, cell: Cell) -> CellResult<PathBuf> {
        let root = self.root.join(format!("cell-{:02}", cell as u16));
        std_fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .map_err(|_| ())?;
        Ok(root)
    }
}

impl Drop for MatrixFixtureV1 {
    fn drop(&mut self) {
        let _ = std_fs::remove_dir_all(&self.root);
    }
}

type CellResult<T = ()> = Result<T, ()>;

pub(super) fn run() -> Result<LocalFileHostCertificationReceiptV1, Error> {
    let host = observe_host();
    let fixture = MatrixFixtureV1::create()?;
    for cell in REQUIRED_CELLS_V1 {
        run_cell(&fixture, &host, cell).map_err(|()| Error::CellFailed(cell))?;
    }
    let architecture = host
        .architecture
        .ok_or(Error::CellFailed(Cell::SupportedArchitectureIdentity))?;
    Ok(LocalFileHostCertificationReceiptV1::all_passed(
        architecture,
        host.identity_digest,
    ))
}

fn observe_host() -> HostFactsV1 {
    let uname = rustix::system::uname();
    let sysname = uname.sysname().to_bytes();
    let release = uname.release().to_bytes();
    let version = uname.version().to_bytes();
    let machine = uname.machine().to_bytes();
    let architecture = compiled_architecture();
    let architecture_identity_valid = match architecture {
        Some(LocalFileArchitectureV1::Aarch64) => machine == b"arm64",
        Some(LocalFileArchitectureV1::X86_64) => machine == b"x86_64",
        Some(LocalFileArchitectureV1::OtherVersioned { .. }) | None => false,
    };
    HostFactsV1 {
        darwin_identity_valid: sysname == b"Darwin" && !release.is_empty() && !version.is_empty(),
        architecture,
        architecture_identity_valid,
        identity_digest: derive_host_identity_digest(&[sysname, release, version, machine]),
    }
}

fn compiled_architecture() -> Option<LocalFileArchitectureV1> {
    #[cfg(target_arch = "aarch64")]
    {
        return Some(LocalFileArchitectureV1::Aarch64);
    }
    #[cfg(target_arch = "x86_64")]
    {
        return Some(LocalFileArchitectureV1::X86_64);
    }
    #[allow(unreachable_code)]
    None
}

fn run_cell(fixture: &MatrixFixtureV1, host: &HostFactsV1, cell: Cell) -> CellResult {
    match cell {
        Cell::DarwinOperatingSystemIdentity => host.darwin_identity_valid.then_some(()).ok_or(()),
        Cell::SupportedArchitectureIdentity => (host.architecture.is_some()
            && host.architecture_identity_valid)
            .then_some(())
            .ok_or(()),
        Cell::ApfsFixtureFilesystemIdentity => apfs_fixture_filesystem_identity(fixture, cell),
        Cell::DescriptorRelativeRegularFileAccepted => {
            descriptor_relative_regular_file_accepted(fixture, cell)
        }
        Cell::DescriptorRelativeFinalSymlinkNofollowRejected => {
            descriptor_relative_final_symlink_nofollow_rejected(fixture, cell)
        }
        Cell::DescriptorRelativeAncestorSymlinkNofollowRejected => {
            descriptor_relative_ancestor_symlink_nofollow_rejected(fixture, cell)
        }
        Cell::DescriptorRelativeNonRegularFileRejected => {
            descriptor_relative_non_regular_file_rejected(fixture, cell)
        }
        Cell::RetainedFileDescriptorIdentityStableAfterPathReplacement => {
            retained_file_descriptor_stable_after_path_replacement(fixture, cell)
        }
        Cell::RetainedRootDescriptorIdentityStableAfterRootRename => {
            retained_root_descriptor_stable_after_root_rename(fixture, cell)
        }
        Cell::HardLinkObjectIdentityDetected => hard_link_object_identity_detected(fixture, cell),
        Cell::AppendSnapshotChangeDetected => append_snapshot_change_detected(fixture, cell),
        Cell::TruncateSnapshotChangeDetected => truncate_snapshot_change_detected(fixture, cell),
        Cell::RootAndFileFstatfsConsistent => root_and_file_fstatfs_consistent(fixture, cell),
    }
}

fn apfs_fixture_filesystem_identity(fixture: &MatrixFixtureV1, cell: Cell) -> CellResult {
    let root = fixture.cell_root(cell)?;
    let root_fd = open_directory(&root)?;
    let facts = rfs::fstatfs(&root_fd).map_err(|_| ())?;
    (observed_filesystem(&facts) == ObservedFilesystemV1::Apfs)
        .then_some(())
        .ok_or(())
}

fn descriptor_relative_regular_file_accepted(fixture: &MatrixFixtureV1, cell: Cell) -> CellResult {
    let root = fixture.cell_root(cell)?;
    write_synthetic(&root.join("regular.log"), b"matrix-regular\0\xff\n")?;
    let root_fd = open_directory(&root)?;
    let file_fd = open_final(&root_fd, b"regular.log")?;
    let stat = rfs::fstat(&file_fd).map_err(|_| ())?;
    let offset = rfs::seek(&file_fd, rfs::SeekFrom::Current(0)).map_err(|_| ())?;
    (FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile && offset == 0)
        .then_some(())
        .ok_or(())
}

fn descriptor_relative_final_symlink_nofollow_rejected(
    fixture: &MatrixFixtureV1,
    cell: Cell,
) -> CellResult {
    let root = fixture.cell_root(cell)?;
    write_synthetic(&root.join("target.log"), b"matrix-final-target")?;
    symlink("target.log", root.join("alias.log")).map_err(|_| ())?;
    let root_fd = open_directory(&root)?;
    rfs::openat(
        &root_fd,
        b"alias.log".as_slice(),
        final_open_flags(),
        Mode::empty(),
    )
    .is_err()
    .then_some(())
    .ok_or(())
}

fn descriptor_relative_ancestor_symlink_nofollow_rejected(
    fixture: &MatrixFixtureV1,
    cell: Cell,
) -> CellResult {
    let root = fixture.cell_root(cell)?;
    let real = root.join("real");
    std_fs::DirBuilder::new()
        .mode(0o700)
        .create(&real)
        .map_err(|_| ())?;
    write_synthetic(&real.join("nested.log"), b"matrix-ancestor-target")?;
    symlink("real", root.join("alias")).map_err(|_| ())?;
    let root_fd = open_directory(&root)?;
    rfs::openat(
        &root_fd,
        b"alias".as_slice(),
        directory_open_flags(),
        Mode::empty(),
    )
    .is_err()
    .then_some(())
    .ok_or(())
}

fn descriptor_relative_non_regular_file_rejected(
    fixture: &MatrixFixtureV1,
    cell: Cell,
) -> CellResult {
    let root = fixture.cell_root(cell)?;
    std_fs::DirBuilder::new()
        .mode(0o700)
        .create(root.join("not-a-file"))
        .map_err(|_| ())?;
    let root_fd = open_directory(&root)?;
    let candidate = open_final(&root_fd, b"not-a-file")?;
    let stat = rfs::fstat(&candidate).map_err(|_| ())?;
    (FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile)
        .then_some(())
        .ok_or(())
}

fn retained_file_descriptor_stable_after_path_replacement(
    fixture: &MatrixFixtureV1,
    cell: Cell,
) -> CellResult {
    let root = fixture.cell_root(cell)?;
    let selected = root.join("selected.log");
    write_synthetic(&selected, b"matrix-retained-file-original")?;
    let root_fd = open_directory(&root)?;
    let retained_file_fd = open_final(&root_fd, b"selected.log")?;
    let before = descriptor_snapshot(&root_fd, &retained_file_fd)?;

    std_fs::rename(&selected, root.join("displaced.log")).map_err(|_| ())?;
    write_synthetic(&selected, b"matrix-retained-file-replacement")?;

    let retained_root_stat = rfs::fstat(&root_fd).map_err(|_| ())?;
    let retained_file_stat = rfs::fstat(&retained_file_fd).map_err(|_| ())?;
    let replacement_fd = open_final(&root_fd, b"selected.log")?;
    let replacement_stat = rfs::fstat(&replacement_fd).map_err(|_| ())?;
    (object_identity(&retained_root_stat)? == before.root()
        && object_identity(&retained_file_stat)? == before.file()
        && object_identity(&replacement_stat)? != before.file())
    .then_some(())
    .ok_or(())
}

fn retained_root_descriptor_stable_after_root_rename(
    fixture: &MatrixFixtureV1,
    cell: Cell,
) -> CellResult {
    let parent = fixture.cell_root(cell)?;
    let selected_root = parent.join("selected-root");
    std_fs::DirBuilder::new()
        .mode(0o700)
        .create(&selected_root)
        .map_err(|_| ())?;
    write_synthetic(
        &selected_root.join("selected.log"),
        b"matrix-retained-root-original",
    )?;
    let retained_root_fd = open_directory(&selected_root)?;
    let retained_file_fd = open_final(&retained_root_fd, b"selected.log")?;
    let before = descriptor_snapshot(&retained_root_fd, &retained_file_fd)?;

    std_fs::rename(&selected_root, parent.join("displaced-root")).map_err(|_| ())?;
    std_fs::DirBuilder::new()
        .mode(0o700)
        .create(&selected_root)
        .map_err(|_| ())?;
    write_synthetic(
        &selected_root.join("selected.log"),
        b"matrix-retained-root-replacement",
    )?;

    let replacement_root_fd = open_directory(&selected_root)?;
    let replacement_root_stat = rfs::fstat(&replacement_root_fd).map_err(|_| ())?;
    let retained_root_stat = rfs::fstat(&retained_root_fd).map_err(|_| ())?;
    let retained_file_stat = rfs::fstat(&retained_file_fd).map_err(|_| ())?;
    (object_identity(&retained_root_stat)? == before.root()
        && object_identity(&retained_file_stat)? == before.file()
        && object_identity(&replacement_root_stat)? != before.root())
    .then_some(())
    .ok_or(())
}

fn hard_link_object_identity_detected(fixture: &MatrixFixtureV1, cell: Cell) -> CellResult {
    let root = fixture.cell_root(cell)?;
    let original = root.join("internal.segment");
    let alias = root.join("outside.log");
    write_synthetic(&original, b"matrix-hard-link")?;
    std_fs::hard_link(&original, &alias).map_err(|_| ())?;
    let root_fd = open_directory(&root)?;
    let original_fd = open_final(&root_fd, b"internal.segment")?;
    let alias_fd = open_final(&root_fd, b"outside.log")?;
    let original_stat = rfs::fstat(&original_fd).map_err(|_| ())?;
    let alias_stat = rfs::fstat(&alias_fd).map_err(|_| ())?;
    (object_identity(&original_stat)? == object_identity(&alias_stat)?
        && original_stat.st_nlink >= 2
        && alias_stat.st_nlink >= 2)
        .then_some(())
        .ok_or(())
}

fn append_snapshot_change_detected(fixture: &MatrixFixtureV1, cell: Cell) -> CellResult {
    let root = fixture.cell_root(cell)?;
    let selected = root.join("append.log");
    write_synthetic(&selected, b"matrix-append-before")?;
    let root_fd = open_directory(&root)?;
    let file_fd = open_final(&root_fd, b"append.log")?;
    let before = descriptor_snapshot(&root_fd, &file_fd)?;
    OpenOptions::new()
        .append(true)
        .open(&selected)
        .and_then(|mut file| file.write_all(b"-after"))
        .map_err(|_| ())?;
    let after = descriptor_snapshot(&root_fd, &file_fd)?;
    (after.file() == before.file() && after != before && after.size() > before.size())
        .then_some(())
        .ok_or(())
}

fn truncate_snapshot_change_detected(fixture: &MatrixFixtureV1, cell: Cell) -> CellResult {
    let root = fixture.cell_root(cell)?;
    let selected = root.join("truncate.log");
    write_synthetic(&selected, b"matrix-truncate-before")?;
    let root_fd = open_directory(&root)?;
    let file_fd = open_final(&root_fd, b"truncate.log")?;
    let before = descriptor_snapshot(&root_fd, &file_fd)?;
    OpenOptions::new()
        .write(true)
        .open(&selected)
        .and_then(|file| file.set_len(1))
        .map_err(|_| ())?;
    let after = descriptor_snapshot(&root_fd, &file_fd)?;
    (after.file() == before.file() && after != before && after.size() < before.size())
        .then_some(())
        .ok_or(())
}

fn root_and_file_fstatfs_consistent(fixture: &MatrixFixtureV1, cell: Cell) -> CellResult {
    let root = fixture.cell_root(cell)?;
    write_synthetic(&root.join("selected.log"), b"matrix-fstatfs")?;
    let root_fd = open_directory(&root)?;
    let file_fd = open_final(&root_fd, b"selected.log")?;
    let root_stat = rfs::fstat(&root_fd).map_err(|_| ())?;
    let file_stat = rfs::fstat(&file_fd).map_err(|_| ())?;
    let root_facts = rfs::fstatfs(&root_fd).map_err(|_| ())?;
    let file_facts = rfs::fstatfs(&file_fd).map_err(|_| ())?;
    (observed_filesystem(&root_facts) == ObservedFilesystemV1::Apfs
        && observed_filesystem(&file_facts) == ObservedFilesystemV1::Apfs
        && root_stat.st_dev == file_stat.st_dev
        && root_facts.f_type == file_facts.f_type
        && root_facts.f_fstypename == file_facts.f_fstypename)
        .then_some(())
        .ok_or(())
}

fn write_synthetic(path: &Path, bytes: &[u8]) -> CellResult {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| ())?;
    file.write_all(bytes).map_err(|_| ())?;
    file.sync_all().map_err(|_| ())
}

fn open_directory(path: &Path) -> CellResult<OwnedFd> {
    rfs::open(
        path.as_os_str().as_bytes(),
        directory_open_flags(),
        Mode::empty(),
    )
    .map_err(|_| ())
}

fn open_final(root_fd: &OwnedFd, name: &[u8]) -> CellResult<OwnedFd> {
    rfs::openat(root_fd, name, final_open_flags(), Mode::empty()).map_err(|_| ())
}

fn directory_open_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn final_open_flags() -> OFlags {
    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC
}

fn descriptor_snapshot(
    root_fd: &OwnedFd,
    file_fd: &OwnedFd,
) -> CellResult<evidentrail_schema::UnixFileSnapshotV1> {
    let root_stat = rfs::fstat(root_fd).map_err(|_| ())?;
    let file_stat = rfs::fstat(file_fd).map_err(|_| ())?;
    snapshot_from_stats(&root_stat, &file_stat).map_err(|_| ())
}

fn object_identity(stat: &Stat) -> CellResult<UnixFileObjectIdV1> {
    let device = u64::try_from(stat.st_dev).map_err(|_| ())?;
    Ok(UnixFileObjectIdV1::new(device, stat.st_ino))
}
