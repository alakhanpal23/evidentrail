use std::error::Error as StdError;
use std::fmt;

use crate::bounds::{
    JSON_SAFE_INTEGER_MAX, MAX_AUTHORIZED_RECORD_BYTES, MAX_UNIX_LOCAL_FILE_COMPONENT_BYTES,
    MAX_UNIX_LOCAL_FILE_COMPONENTS, MAX_UNIX_LOCAL_FILE_LOCATOR_BYTES,
    MAX_UNIX_LOCAL_FILE_ROOT_BYTES,
};
use crate::{
    IdentityProofKindV1, InternalPathPolicyDigest, LocalFileCertificationProfileDigest,
    PolicyDigest, RepositoryIdentityDigest, RetrievalId, SourceCursor, SourceIdentityV1,
    SourceMember, UnixTimestampNanos,
};

/// Adapter-kind token accepted by the Unix local-file V1 plan contract.
pub const LOCAL_FILE_ADAPTER_KIND_V1: &str = "local-file";
/// Exact implementation version accepted by the Unix local-file V1 contract.
pub const LOCAL_FILE_ADAPTER_VERSION_V1: &str = "1.0.0";

/// Byte-exact canonical root plus one root-relative member path for Unix
/// local-file V1. The bytes are sensitive authority material, not a display
/// path. Construction performs only representation checks; descriptor-relative
/// containment and opened-handle revalidation remain execution-time duties.
#[derive(Clone, PartialEq, Eq)]
pub struct UnixLocalFileLocatorV1 {
    root: Vec<u8>,
    relative_components: Vec<Vec<u8>>,
    total_path_bytes: usize,
}

impl UnixLocalFileLocatorV1 {
    pub fn new<R, I, C>(
        root: R,
        relative_components: I,
    ) -> Result<Self, UnixLocalFileLocatorConstructionError>
    where
        R: Into<Vec<u8>>,
        I: IntoIterator<Item = C>,
        C: Into<Vec<u8>>,
    {
        let root = root.into();
        validate_canonical_root(&root)?;

        let mut components = Vec::new();
        let mut total_path_bytes = root.len();
        for raw_component in relative_components {
            if components.len() == MAX_UNIX_LOCAL_FILE_COMPONENTS {
                return Err(UnixLocalFileLocatorConstructionError::TooManyComponents);
            }

            let component = raw_component.into();
            validate_relative_component(&component, components.is_empty())?;
            let separator_bytes = usize::from(root.as_slice() != b"/" || !components.is_empty());
            total_path_bytes = total_path_bytes
                .checked_add(separator_bytes)
                .and_then(|total| total.checked_add(component.len()))
                .ok_or(UnixLocalFileLocatorConstructionError::TotalPathTooLong)?;
            if total_path_bytes > MAX_UNIX_LOCAL_FILE_LOCATOR_BYTES {
                return Err(UnixLocalFileLocatorConstructionError::TotalPathTooLong);
            }
            components.push(component);
        }

        if components.is_empty() {
            return Err(UnixLocalFileLocatorConstructionError::EmptyMember);
        }

        Ok(Self {
            root,
            relative_components: components,
            total_path_bytes,
        })
    }

    #[must_use]
    pub fn root(&self) -> &[u8] {
        &self.root
    }

    #[must_use]
    pub fn relative_components(&self) -> &[Vec<u8>] {
        &self.relative_components
    }

    #[must_use]
    pub const fn total_path_bytes(&self) -> usize {
        self.total_path_bytes
    }
}

impl fmt::Debug for UnixLocalFileLocatorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnixLocalFileLocatorV1")
            .field("root_present", &true)
            .field("relative_component_count", &self.relative_components.len())
            .field("total_path_byte_count", &self.total_path_bytes)
            .finish()
    }
}

fn validate_canonical_root(root: &[u8]) -> Result<(), UnixLocalFileLocatorConstructionError> {
    if root.is_empty() {
        return Err(UnixLocalFileLocatorConstructionError::EmptyRoot);
    }
    if root.len() > MAX_UNIX_LOCAL_FILE_ROOT_BYTES {
        return Err(UnixLocalFileLocatorConstructionError::RootTooLong);
    }
    if root[0] != b'/' {
        return Err(UnixLocalFileLocatorConstructionError::RootNotAbsolute);
    }
    if root.contains(&0) {
        return Err(UnixLocalFileLocatorConstructionError::RootContainsNul);
    }
    if root.len() > 1 && root.ends_with(b"/") {
        return Err(UnixLocalFileLocatorConstructionError::TrailingSeparator);
    }
    if root.windows(2).any(|pair| pair == b"//") {
        return Err(UnixLocalFileLocatorConstructionError::DuplicateSeparator);
    }

    for component in root[1..].split(|byte| *byte == b'/') {
        if component == b"." {
            return Err(UnixLocalFileLocatorConstructionError::DotComponent);
        }
        if component == b".." {
            return Err(UnixLocalFileLocatorConstructionError::DotDotComponent);
        }
        if component.len() > MAX_UNIX_LOCAL_FILE_COMPONENT_BYTES {
            return Err(UnixLocalFileLocatorConstructionError::ComponentTooLong);
        }
    }
    Ok(())
}

fn validate_relative_component(
    component: &[u8],
    first: bool,
) -> Result<(), UnixLocalFileLocatorConstructionError> {
    if component.is_empty() {
        return Err(UnixLocalFileLocatorConstructionError::EmptyComponent);
    }
    if first && component[0] == b'/' {
        return Err(UnixLocalFileLocatorConstructionError::AbsoluteMember);
    }
    if component.contains(&0) {
        return Err(UnixLocalFileLocatorConstructionError::ComponentContainsNul);
    }
    if component.contains(&b'/') {
        return Err(UnixLocalFileLocatorConstructionError::SlashInComponent);
    }
    if component == b"." {
        return Err(UnixLocalFileLocatorConstructionError::DotComponent);
    }
    if component == b".." {
        return Err(UnixLocalFileLocatorConstructionError::DotDotComponent);
    }
    if component.len() > MAX_UNIX_LOCAL_FILE_COMPONENT_BYTES {
        return Err(UnixLocalFileLocatorConstructionError::ComponentTooLong);
    }
    Ok(())
}

/// Invalid byte-exact Unix local-file locator construction.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UnixLocalFileLocatorConstructionError {
    EmptyRoot,
    RootTooLong,
    RootNotAbsolute,
    RootContainsNul,
    EmptyMember,
    TooManyComponents,
    EmptyComponent,
    AbsoluteMember,
    ComponentContainsNul,
    SlashInComponent,
    DotComponent,
    DotDotComponent,
    ComponentTooLong,
    DuplicateSeparator,
    TrailingSeparator,
    TotalPathTooLong,
}

impl UnixLocalFileLocatorConstructionError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyRoot => "EVIDENTRAIL_UNIX_LOCAL_FILE_LOCATOR_EMPTY_ROOT",
            Self::RootTooLong => "EVIDENTRAIL_UNIX_LOCAL_FILE_LOCATOR_ROOT_TOO_LONG",
            Self::RootNotAbsolute => "EVIDENTRAIL_UNIX_LOCAL_FILE_LOCATOR_ROOT_NOT_ABSOLUTE",
            Self::RootContainsNul => "EVIDENTRAIL_UNIX_LOCAL_FILE_LOCATOR_ROOT_CONTAINS_NUL",
            Self::EmptyMember => "EVIDENTRAIL_UNIX_LOCAL_FILE_LOCATOR_EMPTY_MEMBER",
            Self::TooManyComponents => "EVIDENTRAIL_UNIX_LOCAL_FILE_LOCATOR_TOO_MANY_COMPONENTS",
            Self::EmptyComponent => "EVIDENTRAIL_UNIX_LOCAL_FILE_LOCATOR_EMPTY_COMPONENT",
            Self::AbsoluteMember => "EVIDENTRAIL_UNIX_LOCAL_FILE_LOCATOR_ABSOLUTE_MEMBER",
            Self::ComponentContainsNul => {
                "EVIDENTRAIL_UNIX_LOCAL_FILE_LOCATOR_COMPONENT_CONTAINS_NUL"
            }
            Self::SlashInComponent => "EVIDENTRAIL_UNIX_LOCAL_FILE_LOCATOR_SLASH_IN_COMPONENT",
            Self::DotComponent => "EVIDENTRAIL_UNIX_LOCAL_FILE_LOCATOR_DOT_COMPONENT",
            Self::DotDotComponent => "EVIDENTRAIL_UNIX_LOCAL_FILE_LOCATOR_DOT_DOT_COMPONENT",
            Self::ComponentTooLong => "EVIDENTRAIL_UNIX_LOCAL_FILE_LOCATOR_COMPONENT_TOO_LONG",
            Self::DuplicateSeparator => "EVIDENTRAIL_UNIX_LOCAL_FILE_LOCATOR_DUPLICATE_SEPARATOR",
            Self::TrailingSeparator => "EVIDENTRAIL_UNIX_LOCAL_FILE_LOCATOR_TRAILING_SEPARATOR",
            Self::TotalPathTooLong => "EVIDENTRAIL_UNIX_LOCAL_FILE_LOCATOR_TOTAL_PATH_TOO_LONG",
        }
    }
}

impl fmt::Debug for UnixLocalFileLocatorConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnixLocalFileLocatorConstructionError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for UnixLocalFileLocatorConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for UnixLocalFileLocatorConstructionError {}

/// Operating-system family admitted by the local-file V1 certification
/// profile.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LocalFileOperatingSystemV1 {
    MacOs,
    OtherVersioned { version: u16, code: u16 },
}

impl LocalFileOperatingSystemV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::MacOs => "macos",
            Self::OtherVersioned { .. } => "other_versioned",
        }
    }
}

impl fmt::Debug for LocalFileOperatingSystemV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalFileOperatingSystemV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Filesystem family admitted by the local-file V1 certification profile.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LocalFileFilesystemV1 {
    Apfs,
    OtherVersioned { version: u16, code: u16 },
}

impl LocalFileFilesystemV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Apfs => "apfs",
            Self::OtherVersioned { .. } => "other_versioned",
        }
    }
}

impl fmt::Debug for LocalFileFilesystemV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalFileFilesystemV1")
            .field("code", &self.code())
            .finish()
    }
}

/// CPU architecture selected by a local-file V1 certification profile.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LocalFileArchitectureV1 {
    Aarch64,
    X86_64,
    OtherVersioned { version: u16, code: u16 },
}

impl LocalFileArchitectureV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Aarch64 => "aarch64",
            Self::X86_64 => "x86_64",
            Self::OtherVersioned { .. } => "other_versioned",
        }
    }
}

impl fmt::Debug for LocalFileArchitectureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalFileArchitectureV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Deadline-observation semantics selected by local-file V1.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LocalFileDeadlineModelV1 {
    CooperativeBetweenIoCalls,
    OtherVersioned { version: u16, code: u16 },
}

impl LocalFileDeadlineModelV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::CooperativeBetweenIoCalls => "cooperative_deadline_between_io_calls_v1",
            Self::OtherVersioned { .. } => "other_versioned",
        }
    }
}

impl fmt::Debug for LocalFileDeadlineModelV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalFileDeadlineModelV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Selected local runtime family and externally governed certification matrix.
///
/// The digest identifies an immutable tested OS/filesystem/build matrix. This
/// value does not claim that the current host belongs to that matrix and does
/// not carry a free-form build string. A later live execution binding must
/// record the observed build/profile and prove matrix membership separately.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LocalFileRuntimeProfileV1 {
    operating_system: LocalFileOperatingSystemV1,
    filesystem: LocalFileFilesystemV1,
    architecture: LocalFileArchitectureV1,
    deadline_model: LocalFileDeadlineModelV1,
    certification_profile_digest: LocalFileCertificationProfileDigest,
}

impl LocalFileRuntimeProfileV1 {
    pub fn new(
        operating_system: LocalFileOperatingSystemV1,
        filesystem: LocalFileFilesystemV1,
        architecture: LocalFileArchitectureV1,
        deadline_model: LocalFileDeadlineModelV1,
        certification_profile_digest: LocalFileCertificationProfileDigest,
    ) -> Result<Self, LocalFileRuntimeProfileConstructionError> {
        if operating_system != LocalFileOperatingSystemV1::MacOs {
            return Err(LocalFileRuntimeProfileConstructionError::UnsupportedOperatingSystem);
        }
        if filesystem != LocalFileFilesystemV1::Apfs {
            return Err(LocalFileRuntimeProfileConstructionError::UnsupportedFilesystem);
        }
        if !matches!(
            architecture,
            LocalFileArchitectureV1::Aarch64 | LocalFileArchitectureV1::X86_64
        ) {
            return Err(LocalFileRuntimeProfileConstructionError::UnsupportedArchitecture);
        }
        if deadline_model != LocalFileDeadlineModelV1::CooperativeBetweenIoCalls {
            return Err(LocalFileRuntimeProfileConstructionError::UnsupportedDeadlineModel);
        }
        Ok(Self {
            operating_system,
            filesystem,
            architecture,
            deadline_model,
            certification_profile_digest,
        })
    }

    #[must_use]
    pub const fn operating_system(self) -> LocalFileOperatingSystemV1 {
        self.operating_system
    }

    #[must_use]
    pub const fn filesystem(self) -> LocalFileFilesystemV1 {
        self.filesystem
    }

    #[must_use]
    pub const fn architecture(self) -> LocalFileArchitectureV1 {
        self.architecture
    }

    #[must_use]
    pub const fn deadline_model(self) -> LocalFileDeadlineModelV1 {
        self.deadline_model
    }

    #[must_use]
    pub const fn certification_profile_digest(self) -> LocalFileCertificationProfileDigest {
        self.certification_profile_digest
    }
}

impl fmt::Debug for LocalFileRuntimeProfileV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalFileRuntimeProfileV1")
            .field("operating_system_code", &self.operating_system.code())
            .field("filesystem_code", &self.filesystem.code())
            .field("architecture_code", &self.architecture.code())
            .field("deadline_model_code", &self.deadline_model.code())
            .field("certification_profile_digest_present", &true)
            .finish()
    }
}

/// Invalid local-file runtime/certification profile construction.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LocalFileRuntimeProfileConstructionError {
    UnsupportedOperatingSystem,
    UnsupportedFilesystem,
    UnsupportedArchitecture,
    UnsupportedDeadlineModel,
}

impl LocalFileRuntimeProfileConstructionError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedOperatingSystem => {
                "EVIDENTRAIL_LOCAL_FILE_RUNTIME_PROFILE_UNSUPPORTED_OPERATING_SYSTEM"
            }
            Self::UnsupportedFilesystem => {
                "EVIDENTRAIL_LOCAL_FILE_RUNTIME_PROFILE_UNSUPPORTED_FILESYSTEM"
            }
            Self::UnsupportedArchitecture => {
                "EVIDENTRAIL_LOCAL_FILE_RUNTIME_PROFILE_UNSUPPORTED_ARCHITECTURE"
            }
            Self::UnsupportedDeadlineModel => {
                "EVIDENTRAIL_LOCAL_FILE_RUNTIME_PROFILE_UNSUPPORTED_DEADLINE_MODEL"
            }
        }
    }
}

impl fmt::Debug for LocalFileRuntimeProfileConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalFileRuntimeProfileConstructionError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for LocalFileRuntimeProfileConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for LocalFileRuntimeProfileConstructionError {}

/// Stable Unix object identity observed without reading file contents.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixFileObjectIdV1 {
    device: u64,
    inode: u64,
}

impl UnixFileObjectIdV1 {
    #[must_use]
    pub const fn new(device: u64, inode: u64) -> Self {
        Self { device, inode }
    }

    #[must_use]
    pub const fn device(self) -> u64 {
        self.device
    }

    #[must_use]
    pub const fn inode(self) -> u64 {
        self.inode
    }
}

impl fmt::Debug for UnixFileObjectIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnixFileObjectIdV1")
            .field("device_present", &true)
            .field("inode_present", &true)
            .finish()
    }
}

/// File type committed by a Unix local-file snapshot.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UnixFileTypeV1 {
    Regular,
    OtherVersioned { version: u16, code: u16 },
}

impl UnixFileTypeV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Regular => "regular",
            Self::OtherVersioned { .. } => "other_versioned",
        }
    }
}

impl fmt::Debug for UnixFileTypeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnixFileTypeV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Exact range semantics authorized by a local-file V1 plan.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LocalFileSnapshotModeV1 {
    WholeFileFixedHighWater,
    OtherVersioned { version: u16, code: u16 },
}

impl LocalFileSnapshotModeV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::WholeFileFixedHighWater => "whole_file_fixed_high_water_v1",
            Self::OtherVersioned { .. } => "other_versioned",
        }
    }
}

impl fmt::Debug for LocalFileSnapshotModeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalFileSnapshotModeV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Requested or declared ordering for a local-file V1 plan.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LocalFileOrderingV1 {
    SingleFileByteOrder,
    OtherVersioned { version: u16, code: u16 },
}

impl LocalFileOrderingV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SingleFileByteOrder => "single_file_byte_order_v1",
            Self::OtherVersioned { .. } => "other_versioned",
        }
    }
}

impl fmt::Debug for LocalFileOrderingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalFileOrderingV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Immutable metadata facts defining the exact Unix regular-file snapshot
/// authorized by a local-file plan.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UnixFileSnapshotV1 {
    root: UnixFileObjectIdV1,
    file: UnixFileObjectIdV1,
    file_type: UnixFileTypeV1,
    mode: u32,
    link_count: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    start_offset: u64,
    high_water_exclusive: u64,
}

impl UnixFileSnapshotV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        root: UnixFileObjectIdV1,
        file: UnixFileObjectIdV1,
        file_type: UnixFileTypeV1,
        mode: u32,
        link_count: u64,
        size: u64,
        modified_seconds: i64,
        modified_nanoseconds: i64,
        changed_seconds: i64,
        changed_nanoseconds: i64,
        start_offset: u64,
        high_water_exclusive: u64,
    ) -> Result<Self, UnixFileSnapshotConstructionError> {
        if file_type != UnixFileTypeV1::Regular {
            return Err(UnixFileSnapshotConstructionError::UnsupportedFileType);
        }
        if link_count == 0 {
            return Err(UnixFileSnapshotConstructionError::ZeroLinkCount);
        }
        if !(0..1_000_000_000).contains(&modified_nanoseconds) {
            return Err(UnixFileSnapshotConstructionError::ModifiedNanosecondsOutOfRange);
        }
        if !(0..1_000_000_000).contains(&changed_nanoseconds) {
            return Err(UnixFileSnapshotConstructionError::ChangedNanosecondsOutOfRange);
        }
        if start_offset != 0 {
            return Err(UnixFileSnapshotConstructionError::NonzeroStartOffset);
        }
        if high_water_exclusive != size {
            return Err(UnixFileSnapshotConstructionError::HighWaterDoesNotEqualSize);
        }

        Ok(Self {
            root,
            file,
            file_type,
            mode,
            link_count,
            size,
            modified_seconds,
            modified_nanoseconds,
            changed_seconds,
            changed_nanoseconds,
            start_offset,
            high_water_exclusive,
        })
    }

    #[must_use]
    pub const fn root(self) -> UnixFileObjectIdV1 {
        self.root
    }

    #[must_use]
    pub const fn file(self) -> UnixFileObjectIdV1 {
        self.file
    }

    #[must_use]
    pub const fn file_type(self) -> UnixFileTypeV1 {
        self.file_type
    }

    #[must_use]
    pub const fn mode(self) -> u32 {
        self.mode
    }

    #[must_use]
    pub const fn link_count(self) -> u64 {
        self.link_count
    }

    #[must_use]
    pub const fn size(self) -> u64 {
        self.size
    }

    #[must_use]
    pub const fn modified_seconds(self) -> i64 {
        self.modified_seconds
    }

    #[must_use]
    pub const fn modified_nanoseconds(self) -> i64 {
        self.modified_nanoseconds
    }

    #[must_use]
    pub const fn changed_seconds(self) -> i64 {
        self.changed_seconds
    }

    #[must_use]
    pub const fn changed_nanoseconds(self) -> i64 {
        self.changed_nanoseconds
    }

    #[must_use]
    pub const fn start_offset(self) -> u64 {
        self.start_offset
    }

    #[must_use]
    pub const fn high_water_exclusive(self) -> u64 {
        self.high_water_exclusive
    }
}

impl fmt::Debug for UnixFileSnapshotV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnixFileSnapshotV1")
            .field("file_type_code", &self.file_type.code())
            .field("root_identity_present", &true)
            .field("file_identity_present", &true)
            .field("fixed_range_present", &true)
            .finish()
    }
}

/// Invalid Unix fixed-snapshot construction.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UnixFileSnapshotConstructionError {
    UnsupportedFileType,
    ZeroLinkCount,
    ModifiedNanosecondsOutOfRange,
    ChangedNanosecondsOutOfRange,
    NonzeroStartOffset,
    HighWaterDoesNotEqualSize,
}

impl UnixFileSnapshotConstructionError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedFileType => "EVIDENTRAIL_UNIX_FILE_SNAPSHOT_UNSUPPORTED_FILE_TYPE",
            Self::ZeroLinkCount => "EVIDENTRAIL_UNIX_FILE_SNAPSHOT_ZERO_LINK_COUNT",
            Self::ModifiedNanosecondsOutOfRange => {
                "EVIDENTRAIL_UNIX_FILE_SNAPSHOT_MODIFIED_NANOSECONDS_OUT_OF_RANGE"
            }
            Self::ChangedNanosecondsOutOfRange => {
                "EVIDENTRAIL_UNIX_FILE_SNAPSHOT_CHANGED_NANOSECONDS_OUT_OF_RANGE"
            }
            Self::NonzeroStartOffset => "EVIDENTRAIL_UNIX_FILE_SNAPSHOT_NONZERO_START_OFFSET",
            Self::HighWaterDoesNotEqualSize => {
                "EVIDENTRAIL_UNIX_FILE_SNAPSHOT_HIGH_WATER_DOES_NOT_EQUAL_SIZE"
            }
        }
    }
}

impl fmt::Debug for UnixFileSnapshotConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnixFileSnapshotConstructionError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for UnixFileSnapshotConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for UnixFileSnapshotConstructionError {}

/// Hard caps for one explicitly approved local-file acquisition.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LocalFilePlanCapsV1 {
    source_bytes: u64,
    records: u64,
    per_record_bytes: u64,
    wall_time_millis: u64,
}

impl LocalFilePlanCapsV1 {
    pub fn new(
        source_bytes: u64,
        records: u64,
        per_record_bytes: u64,
        wall_time_millis: u64,
    ) -> Result<Self, LocalFilePlanCapsConstructionError> {
        if source_bytes == 0 {
            return Err(LocalFilePlanCapsConstructionError::ZeroSourceBytes);
        }
        if records == 0 {
            return Err(LocalFilePlanCapsConstructionError::ZeroRecords);
        }
        if per_record_bytes == 0 {
            return Err(LocalFilePlanCapsConstructionError::ZeroPerRecordBytes);
        }
        if wall_time_millis == 0 {
            return Err(LocalFilePlanCapsConstructionError::ZeroWallTimeMillis);
        }
        if source_bytes > JSON_SAFE_INTEGER_MAX {
            return Err(LocalFilePlanCapsConstructionError::SourceBytesNotJsonSafe);
        }
        if records > JSON_SAFE_INTEGER_MAX {
            return Err(LocalFilePlanCapsConstructionError::RecordsNotJsonSafe);
        }
        if per_record_bytes > JSON_SAFE_INTEGER_MAX {
            return Err(LocalFilePlanCapsConstructionError::PerRecordBytesNotJsonSafe);
        }
        if wall_time_millis > JSON_SAFE_INTEGER_MAX {
            return Err(LocalFilePlanCapsConstructionError::WallTimeMillisNotJsonSafe);
        }
        if per_record_bytes > MAX_AUTHORIZED_RECORD_BYTES as u64 {
            return Err(LocalFilePlanCapsConstructionError::PerRecordBytesAboveHardMaximum);
        }
        if per_record_bytes > source_bytes {
            return Err(LocalFilePlanCapsConstructionError::PerRecordBytesAboveSourceCap);
        }

        Ok(Self {
            source_bytes,
            records,
            per_record_bytes,
            wall_time_millis,
        })
    }

    #[must_use]
    pub const fn source_bytes(self) -> u64 {
        self.source_bytes
    }

    #[must_use]
    pub const fn records(self) -> u64 {
        self.records
    }

    #[must_use]
    pub const fn per_record_bytes(self) -> u64 {
        self.per_record_bytes
    }

    #[must_use]
    pub const fn wall_time_millis(self) -> u64 {
        self.wall_time_millis
    }
}

impl fmt::Debug for LocalFilePlanCapsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalFilePlanCapsV1")
            .field("source_bytes_present", &true)
            .field("records_present", &true)
            .field("per_record_bytes_present", &true)
            .field("wall_time_millis_present", &true)
            .finish()
    }
}

/// Invalid local-file cap construction.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LocalFilePlanCapsConstructionError {
    ZeroSourceBytes,
    ZeroRecords,
    ZeroPerRecordBytes,
    ZeroWallTimeMillis,
    SourceBytesNotJsonSafe,
    RecordsNotJsonSafe,
    PerRecordBytesNotJsonSafe,
    WallTimeMillisNotJsonSafe,
    PerRecordBytesAboveHardMaximum,
    PerRecordBytesAboveSourceCap,
}

impl LocalFilePlanCapsConstructionError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ZeroSourceBytes => "EVIDENTRAIL_LOCAL_FILE_CAPS_ZERO_SOURCE_BYTES",
            Self::ZeroRecords => "EVIDENTRAIL_LOCAL_FILE_CAPS_ZERO_RECORDS",
            Self::ZeroPerRecordBytes => "EVIDENTRAIL_LOCAL_FILE_CAPS_ZERO_PER_RECORD_BYTES",
            Self::ZeroWallTimeMillis => "EVIDENTRAIL_LOCAL_FILE_CAPS_ZERO_WALL_TIME_MILLIS",
            Self::SourceBytesNotJsonSafe => {
                "EVIDENTRAIL_LOCAL_FILE_CAPS_SOURCE_BYTES_NOT_JSON_SAFE"
            }
            Self::RecordsNotJsonSafe => "EVIDENTRAIL_LOCAL_FILE_CAPS_RECORDS_NOT_JSON_SAFE",
            Self::PerRecordBytesNotJsonSafe => {
                "EVIDENTRAIL_LOCAL_FILE_CAPS_PER_RECORD_BYTES_NOT_JSON_SAFE"
            }
            Self::WallTimeMillisNotJsonSafe => {
                "EVIDENTRAIL_LOCAL_FILE_CAPS_WALL_TIME_MILLIS_NOT_JSON_SAFE"
            }
            Self::PerRecordBytesAboveHardMaximum => {
                "EVIDENTRAIL_LOCAL_FILE_CAPS_PER_RECORD_BYTES_ABOVE_HARD_MAXIMUM"
            }
            Self::PerRecordBytesAboveSourceCap => {
                "EVIDENTRAIL_LOCAL_FILE_CAPS_PER_RECORD_BYTES_ABOVE_SOURCE_CAP"
            }
        }
    }
}

impl fmt::Debug for LocalFilePlanCapsConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalFilePlanCapsConstructionError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for LocalFilePlanCapsConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for LocalFilePlanCapsConstructionError {}

/// Canonical semantic material for one local-file plan.
///
/// This is not a verified or executable plan. It deliberately excludes
/// `PlanId` and `PlanDigest`; a later canonical wire/core boundary computes
/// and verifies those identities over this material.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalFileQueryPlanMaterialV1 {
    retrieval_id: RetrievalId,
    repository_identity: RepositoryIdentityDigest,
    source_identity: SourceIdentityV1,
    locator: UnixLocalFileLocatorV1,
    runtime_profile: LocalFileRuntimeProfileV1,
    source_member: SourceMember,
    snapshot: UnixFileSnapshotV1,
    snapshot_mode: LocalFileSnapshotModeV1,
    requested_ordering: LocalFileOrderingV1,
    declared_ordering: LocalFileOrderingV1,
    internal_path_policy_digest: InternalPathPolicyDigest,
    policy_version: u32,
    policy_digest: PolicyDigest,
    caps: LocalFilePlanCapsV1,
    created_at: UnixTimestampNanos,
    execute_before: UnixTimestampNanos,
    authorized_continuation: Option<SourceCursor>,
}

impl LocalFileQueryPlanMaterialV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        retrieval_id: RetrievalId,
        repository_identity: RepositoryIdentityDigest,
        source_identity: SourceIdentityV1,
        locator: UnixLocalFileLocatorV1,
        runtime_profile: LocalFileRuntimeProfileV1,
        source_member: SourceMember,
        snapshot: UnixFileSnapshotV1,
        snapshot_mode: LocalFileSnapshotModeV1,
        requested_ordering: LocalFileOrderingV1,
        declared_ordering: LocalFileOrderingV1,
        internal_path_policy_digest: InternalPathPolicyDigest,
        policy_version: u32,
        policy_digest: PolicyDigest,
        caps: LocalFilePlanCapsV1,
        created_at: UnixTimestampNanos,
        execute_before: UnixTimestampNanos,
        authorized_continuation: Option<SourceCursor>,
    ) -> Result<Self, LocalFileQueryPlanConstructionError> {
        if source_identity.adapter().kind() != LOCAL_FILE_ADAPTER_KIND_V1 {
            return Err(LocalFileQueryPlanConstructionError::UnsupportedAdapterKind);
        }
        if source_identity.adapter().version() != LOCAL_FILE_ADAPTER_VERSION_V1 {
            return Err(LocalFileQueryPlanConstructionError::UnsupportedAdapterVersion);
        }
        if source_identity.proof_kind() != IdentityProofKindV1::LocalFileMetadata {
            return Err(LocalFileQueryPlanConstructionError::UnsupportedSourceProof);
        }
        if source_member.as_bytes().len() != 32 {
            return Err(LocalFileQueryPlanConstructionError::InvalidSourceMemberLength);
        }
        if snapshot_mode != LocalFileSnapshotModeV1::WholeFileFixedHighWater {
            return Err(LocalFileQueryPlanConstructionError::UnsupportedSnapshotMode);
        }
        if requested_ordering != LocalFileOrderingV1::SingleFileByteOrder {
            return Err(LocalFileQueryPlanConstructionError::UnsupportedRequestedOrdering);
        }
        if declared_ordering != LocalFileOrderingV1::SingleFileByteOrder {
            return Err(LocalFileQueryPlanConstructionError::UnsupportedDeclaredOrdering);
        }
        if policy_version == 0 {
            return Err(LocalFileQueryPlanConstructionError::ZeroPolicyVersion);
        }
        if snapshot.high_water_exclusive() > caps.source_bytes() {
            return Err(LocalFileQueryPlanConstructionError::SnapshotAboveSourceByteCap);
        }
        if authorized_continuation.is_some() {
            return Err(LocalFileQueryPlanConstructionError::UnsupportedContinuation);
        }
        if execute_before.get() <= created_at.get() {
            return Err(LocalFileQueryPlanConstructionError::ExecuteBeforeNotAfterCreation);
        }
        if source_identity.proof_observed_at().get() > created_at.get() {
            return Err(LocalFileQueryPlanConstructionError::SourceProofObservedAfterCreation);
        }
        if source_identity
            .proof_expires_at()
            .is_some_and(|expires_at| expires_at.get() <= created_at.get())
        {
            return Err(LocalFileQueryPlanConstructionError::SourceProofExpiredAtCreation);
        }
        if source_identity
            .proof_expires_at()
            .is_some_and(|expires_at| execute_before.get() > expires_at.get())
        {
            return Err(LocalFileQueryPlanConstructionError::PlanOutlivesSourceProof);
        }

        Ok(Self {
            retrieval_id,
            repository_identity,
            source_identity,
            locator,
            runtime_profile,
            source_member,
            snapshot,
            snapshot_mode,
            requested_ordering,
            declared_ordering,
            internal_path_policy_digest,
            policy_version,
            policy_digest,
            caps,
            created_at,
            execute_before,
            authorized_continuation,
        })
    }

    #[must_use]
    pub const fn retrieval_id(&self) -> RetrievalId {
        self.retrieval_id
    }

    #[must_use]
    pub const fn repository_identity(&self) -> RepositoryIdentityDigest {
        self.repository_identity
    }

    #[must_use]
    pub const fn source_identity(&self) -> &SourceIdentityV1 {
        &self.source_identity
    }

    /// Sensitive byte-exact authority locator. It must never enter ordinary
    /// diagnostics, telemetry, or envelope member identity.
    #[must_use]
    pub const fn locator(&self) -> &UnixLocalFileLocatorV1 {
        &self.locator
    }

    /// Planned runtime family and governed certification-matrix reference.
    /// This is not a live runtime observation or certification claim.
    #[must_use]
    pub const fn runtime_profile(&self) -> LocalFileRuntimeProfileV1 {
        self.runtime_profile
    }

    /// The one opaque 32-byte source member derived from `locator` by the wire
    /// authority boundary. The scalar field prevents a zero-member or
    /// multi-member local-file plan from being represented.
    #[must_use]
    pub const fn source_member(&self) -> &SourceMember {
        &self.source_member
    }

    #[must_use]
    pub const fn snapshot(&self) -> UnixFileSnapshotV1 {
        self.snapshot
    }

    #[must_use]
    pub const fn snapshot_mode(&self) -> LocalFileSnapshotModeV1 {
        self.snapshot_mode
    }

    #[must_use]
    pub const fn requested_ordering(&self) -> LocalFileOrderingV1 {
        self.requested_ordering
    }

    #[must_use]
    pub const fn declared_ordering(&self) -> LocalFileOrderingV1 {
        self.declared_ordering
    }

    #[must_use]
    pub const fn internal_path_policy_digest(&self) -> InternalPathPolicyDigest {
        self.internal_path_policy_digest
    }

    #[must_use]
    pub const fn policy_version(&self) -> u32 {
        self.policy_version
    }

    #[must_use]
    pub const fn policy_digest(&self) -> PolicyDigest {
        self.policy_digest
    }

    #[must_use]
    pub const fn caps(&self) -> LocalFilePlanCapsV1 {
        self.caps
    }

    #[must_use]
    pub const fn created_at(&self) -> UnixTimestampNanos {
        self.created_at
    }

    #[must_use]
    pub const fn execute_before(&self) -> UnixTimestampNanos {
        self.execute_before
    }

    #[must_use]
    pub const fn authorized_continuation(&self) -> Option<&SourceCursor> {
        self.authorized_continuation.as_ref()
    }
}

impl fmt::Debug for LocalFileQueryPlanMaterialV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalFileQueryPlanMaterialV1")
            .field("retrieval_id_present", &true)
            .field("repository_identity_present", &true)
            .field("locator_present", &true)
            .field("runtime_profile_present", &true)
            .field("source_member_count", &1)
            .field("snapshot_present", &true)
            .field("snapshot_mode_code", &self.snapshot_mode.code())
            .field("requested_ordering_code", &self.requested_ordering.code())
            .field("declared_ordering_code", &self.declared_ordering.code())
            .field("internal_path_policy_digest_present", &true)
            .field(
                "authorized_continuation_present",
                &self.authorized_continuation.is_some(),
            )
            .finish()
    }
}

/// Invalid local-file query-plan material construction.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LocalFileQueryPlanConstructionError {
    UnsupportedAdapterKind,
    UnsupportedAdapterVersion,
    UnsupportedSourceProof,
    InvalidSourceMemberLength,
    UnsupportedSnapshotMode,
    UnsupportedRequestedOrdering,
    UnsupportedDeclaredOrdering,
    ZeroPolicyVersion,
    SnapshotAboveSourceByteCap,
    UnsupportedContinuation,
    ExecuteBeforeNotAfterCreation,
    SourceProofObservedAfterCreation,
    SourceProofExpiredAtCreation,
    PlanOutlivesSourceProof,
}

impl LocalFileQueryPlanConstructionError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedAdapterKind => "EVIDENTRAIL_LOCAL_FILE_PLAN_UNSUPPORTED_ADAPTER_KIND",
            Self::UnsupportedAdapterVersion => {
                "EVIDENTRAIL_LOCAL_FILE_PLAN_UNSUPPORTED_ADAPTER_VERSION"
            }
            Self::UnsupportedSourceProof => "EVIDENTRAIL_LOCAL_FILE_PLAN_UNSUPPORTED_SOURCE_PROOF",
            Self::InvalidSourceMemberLength => {
                "EVIDENTRAIL_LOCAL_FILE_PLAN_INVALID_SOURCE_MEMBER_LENGTH"
            }
            Self::UnsupportedSnapshotMode => {
                "EVIDENTRAIL_LOCAL_FILE_PLAN_UNSUPPORTED_SNAPSHOT_MODE"
            }
            Self::UnsupportedRequestedOrdering => {
                "EVIDENTRAIL_LOCAL_FILE_PLAN_UNSUPPORTED_REQUESTED_ORDERING"
            }
            Self::UnsupportedDeclaredOrdering => {
                "EVIDENTRAIL_LOCAL_FILE_PLAN_UNSUPPORTED_DECLARED_ORDERING"
            }
            Self::ZeroPolicyVersion => "EVIDENTRAIL_LOCAL_FILE_PLAN_ZERO_POLICY_VERSION",
            Self::SnapshotAboveSourceByteCap => {
                "EVIDENTRAIL_LOCAL_FILE_PLAN_SNAPSHOT_ABOVE_SOURCE_BYTE_CAP"
            }
            Self::UnsupportedContinuation => "EVIDENTRAIL_LOCAL_FILE_PLAN_UNSUPPORTED_CONTINUATION",
            Self::ExecuteBeforeNotAfterCreation => {
                "EVIDENTRAIL_LOCAL_FILE_PLAN_EXECUTE_BEFORE_NOT_AFTER_CREATION"
            }
            Self::SourceProofObservedAfterCreation => {
                "EVIDENTRAIL_LOCAL_FILE_PLAN_SOURCE_PROOF_OBSERVED_AFTER_CREATION"
            }
            Self::SourceProofExpiredAtCreation => {
                "EVIDENTRAIL_LOCAL_FILE_PLAN_SOURCE_PROOF_EXPIRED_AT_CREATION"
            }
            Self::PlanOutlivesSourceProof => "EVIDENTRAIL_LOCAL_FILE_PLAN_OUTLIVES_SOURCE_PROOF",
        }
    }
}

impl fmt::Debug for LocalFileQueryPlanConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalFileQueryPlanConstructionError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for LocalFileQueryPlanConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for LocalFileQueryPlanConstructionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AdapterIdentity, BindingDigest, BindingId, BindingRefV1, SourceIdentityDigest};

    fn source_identity(
        adapter_kind: &str,
        proof_kind: IdentityProofKindV1,
        observed_at: i128,
        expires_at: Option<i128>,
    ) -> SourceIdentityV1 {
        source_identity_with_adapter(
            adapter_kind,
            LOCAL_FILE_ADAPTER_VERSION_V1,
            proof_kind,
            observed_at,
            expires_at,
        )
    }

    fn source_identity_with_adapter(
        adapter_kind: &str,
        adapter_version: &str,
        proof_kind: IdentityProofKindV1,
        observed_at: i128,
        expires_at: Option<i128>,
    ) -> SourceIdentityV1 {
        SourceIdentityV1::new(
            AdapterIdentity::new(adapter_kind, adapter_version).unwrap(),
            BindingRefV1::new(
                BindingId::from_bytes([1; 32]),
                1,
                BindingDigest::from_bytes([2; 32]),
            )
            .unwrap(),
            SourceIdentityDigest::from_bytes([3; 32]),
            proof_kind,
            UnixTimestampNanos::new(observed_at),
            expires_at.map(UnixTimestampNanos::new),
        )
        .unwrap()
    }

    fn snapshot(size: u64) -> UnixFileSnapshotV1 {
        UnixFileSnapshotV1::new(
            UnixFileObjectIdV1::new(101, 202),
            UnixFileObjectIdV1::new(101, 303),
            UnixFileTypeV1::Regular,
            0o100_640,
            2,
            size,
            -1_700_000_000,
            123_456_789,
            -1_699_999_999,
            987_654_321,
            0,
            size,
        )
        .unwrap()
    }

    fn locator() -> UnixLocalFileLocatorV1 {
        UnixLocalFileLocatorV1::new(
            b"/var/log".to_vec(),
            [b"app".to_vec(), b"current.log".to_vec()],
        )
        .unwrap()
    }

    fn runtime_profile(architecture: LocalFileArchitectureV1) -> LocalFileRuntimeProfileV1 {
        LocalFileRuntimeProfileV1::new(
            LocalFileOperatingSystemV1::MacOs,
            LocalFileFilesystemV1::Apfs,
            architecture,
            LocalFileDeadlineModelV1::CooperativeBetweenIoCalls,
            LocalFileCertificationProfileDigest::from_bytes([6; 32]),
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn plan_with(
        source_identity: SourceIdentityV1,
        snapshot: UnixFileSnapshotV1,
        snapshot_mode: LocalFileSnapshotModeV1,
        requested_ordering: LocalFileOrderingV1,
        declared_ordering: LocalFileOrderingV1,
        policy_version: u32,
        caps: LocalFilePlanCapsV1,
        created_at: i128,
        execute_before: i128,
        continuation: Option<&[u8]>,
    ) -> Result<LocalFileQueryPlanMaterialV1, LocalFileQueryPlanConstructionError> {
        LocalFileQueryPlanMaterialV1::new(
            RetrievalId::from_bytes([9; 32]),
            RepositoryIdentityDigest::from_bytes([8; 32]),
            source_identity,
            locator(),
            runtime_profile(LocalFileArchitectureV1::Aarch64),
            SourceMember::new([7; 32]).unwrap(),
            snapshot,
            snapshot_mode,
            requested_ordering,
            declared_ordering,
            InternalPathPolicyDigest::from_bytes([5; 32]),
            policy_version,
            PolicyDigest::from_bytes([4; 32]),
            caps,
            UnixTimestampNanos::new(created_at),
            UnixTimestampNanos::new(execute_before),
            continuation.map(|bytes| SourceCursor::new(bytes.to_vec()).unwrap()),
        )
    }

    fn plan(
        source_identity: SourceIdentityV1,
        created_at: i128,
        execute_before: i128,
        continuation: Option<&[u8]>,
    ) -> Result<LocalFileQueryPlanMaterialV1, LocalFileQueryPlanConstructionError> {
        plan_with(
            source_identity,
            snapshot(1_024),
            LocalFileSnapshotModeV1::WholeFileFixedHighWater,
            LocalFileOrderingV1::SingleFileByteOrder,
            LocalFileOrderingV1::SingleFileByteOrder,
            7,
            LocalFilePlanCapsV1::new(1_024, 10, 512, 5_000).unwrap(),
            created_at,
            execute_before,
            continuation,
        )
    }

    #[test]
    fn every_cap_must_be_nonzero() {
        let cases = [
            (
                LocalFilePlanCapsV1::new(0, 1, 1, 1).unwrap_err(),
                LocalFilePlanCapsConstructionError::ZeroSourceBytes,
            ),
            (
                LocalFilePlanCapsV1::new(1, 0, 1, 1).unwrap_err(),
                LocalFilePlanCapsConstructionError::ZeroRecords,
            ),
            (
                LocalFilePlanCapsV1::new(1, 1, 0, 1).unwrap_err(),
                LocalFilePlanCapsConstructionError::ZeroPerRecordBytes,
            ),
            (
                LocalFilePlanCapsV1::new(1, 1, 1, 0).unwrap_err(),
                LocalFilePlanCapsConstructionError::ZeroWallTimeMillis,
            ),
        ];

        for (actual, expected) in cases {
            assert_eq!(actual, expected);
            assert_eq!(actual.to_string(), actual.code());
            assert!(format!("{actual:?}").contains(actual.code()));
        }
    }

    #[test]
    fn every_wire_numeric_cap_must_be_json_safe() {
        assert_eq!(
            LocalFilePlanCapsV1::new(JSON_SAFE_INTEGER_MAX + 1, 1, 1, 1).unwrap_err(),
            LocalFilePlanCapsConstructionError::SourceBytesNotJsonSafe
        );
        assert_eq!(
            LocalFilePlanCapsV1::new(1, JSON_SAFE_INTEGER_MAX + 1, 1, 1).unwrap_err(),
            LocalFilePlanCapsConstructionError::RecordsNotJsonSafe
        );
        assert_eq!(
            LocalFilePlanCapsV1::new(JSON_SAFE_INTEGER_MAX, 1, JSON_SAFE_INTEGER_MAX + 1, 1)
                .unwrap_err(),
            LocalFilePlanCapsConstructionError::PerRecordBytesNotJsonSafe
        );
        assert_eq!(
            LocalFilePlanCapsV1::new(1, 1, 1, JSON_SAFE_INTEGER_MAX + 1).unwrap_err(),
            LocalFilePlanCapsConstructionError::WallTimeMillisNotJsonSafe
        );

        let boundary = LocalFilePlanCapsV1::new(
            JSON_SAFE_INTEGER_MAX,
            JSON_SAFE_INTEGER_MAX,
            MAX_AUTHORIZED_RECORD_BYTES as u64,
            JSON_SAFE_INTEGER_MAX,
        )
        .unwrap();
        assert_eq!(boundary.source_bytes(), JSON_SAFE_INTEGER_MAX);
        assert_eq!(boundary.records(), JSON_SAFE_INTEGER_MAX);
        assert_eq!(boundary.wall_time_millis(), JSON_SAFE_INTEGER_MAX);
    }

    #[test]
    fn per_record_cap_obeys_hard_and_source_boundaries() {
        let hard_boundary = LocalFilePlanCapsV1::new(
            MAX_AUTHORIZED_RECORD_BYTES as u64,
            1,
            MAX_AUTHORIZED_RECORD_BYTES as u64,
            1,
        )
        .unwrap();
        assert_eq!(
            hard_boundary.per_record_bytes(),
            MAX_AUTHORIZED_RECORD_BYTES as u64
        );

        assert_eq!(
            LocalFilePlanCapsV1::new(
                (MAX_AUTHORIZED_RECORD_BYTES as u64) + 1,
                1,
                (MAX_AUTHORIZED_RECORD_BYTES as u64) + 1,
                1,
            )
            .unwrap_err(),
            LocalFilePlanCapsConstructionError::PerRecordBytesAboveHardMaximum
        );
        assert_eq!(
            LocalFilePlanCapsV1::new(31, 1, 32, 1).unwrap_err(),
            LocalFilePlanCapsConstructionError::PerRecordBytesAboveSourceCap
        );

        let source_boundary = LocalFilePlanCapsV1::new(32, 1, 32, 1).unwrap();
        assert_eq!(source_boundary.source_bytes(), 32);
        assert_eq!(source_boundary.per_record_bytes(), 32);
    }

    #[test]
    fn unix_snapshot_facts_are_fixed_and_constructor_checked() {
        let valid = snapshot(1_024);
        assert_eq!(valid.root(), UnixFileObjectIdV1::new(101, 202));
        assert_eq!(valid.file(), UnixFileObjectIdV1::new(101, 303));
        assert_eq!(valid.file_type(), UnixFileTypeV1::Regular);
        assert_eq!(valid.mode(), 0o100_640);
        assert_eq!(valid.link_count(), 2);
        assert_eq!(valid.size(), 1_024);
        assert_eq!(valid.modified_seconds(), -1_700_000_000);
        assert_eq!(valid.modified_nanoseconds(), 123_456_789);
        assert_eq!(valid.changed_seconds(), -1_699_999_999);
        assert_eq!(valid.changed_nanoseconds(), 987_654_321);
        assert_eq!(valid.start_offset(), 0);
        assert_eq!(valid.high_water_exclusive(), 1_024);

        let construct =
            |file_type, link_count, modified_nanos, changed_nanos, start, high_water| {
                UnixFileSnapshotV1::new(
                    UnixFileObjectIdV1::new(101, 202),
                    UnixFileObjectIdV1::new(101, 303),
                    file_type,
                    0o100_640,
                    link_count,
                    1_024,
                    10,
                    modified_nanos,
                    11,
                    changed_nanos,
                    start,
                    high_water,
                )
            };
        let cases = [
            (
                construct(
                    UnixFileTypeV1::OtherVersioned {
                        version: 1,
                        code: 7,
                    },
                    1,
                    0,
                    0,
                    0,
                    1_024,
                )
                .unwrap_err(),
                UnixFileSnapshotConstructionError::UnsupportedFileType,
            ),
            (
                construct(UnixFileTypeV1::Regular, 0, 0, 0, 0, 1_024).unwrap_err(),
                UnixFileSnapshotConstructionError::ZeroLinkCount,
            ),
            (
                construct(UnixFileTypeV1::Regular, 1, -1, 0, 0, 1_024).unwrap_err(),
                UnixFileSnapshotConstructionError::ModifiedNanosecondsOutOfRange,
            ),
            (
                construct(UnixFileTypeV1::Regular, 1, 0, 1_000_000_000, 0, 1_024).unwrap_err(),
                UnixFileSnapshotConstructionError::ChangedNanosecondsOutOfRange,
            ),
            (
                construct(UnixFileTypeV1::Regular, 1, 0, 0, 1, 1_024).unwrap_err(),
                UnixFileSnapshotConstructionError::NonzeroStartOffset,
            ),
            (
                construct(UnixFileTypeV1::Regular, 1, 0, 0, 0, 1_023).unwrap_err(),
                UnixFileSnapshotConstructionError::HighWaterDoesNotEqualSize,
            ),
        ];
        for (actual, expected) in cases {
            assert_eq!(actual, expected);
            assert_eq!(actual.to_string(), actual.code());
            assert!(format!("{actual:?}").contains(actual.code()));
        }
    }

    #[test]
    fn unix_locator_requires_one_canonical_bounded_root_relative_member() {
        let valid = UnixLocalFileLocatorV1::new(
            b"/var/log".to_vec(),
            [b"app".to_vec(), vec![b'f', b'i', b'l', b'e', 0xff]],
        )
        .unwrap();
        assert_eq!(valid.root(), b"/var/log");
        assert_eq!(valid.relative_components().len(), 2);
        assert_eq!(
            valid.relative_components()[1],
            [b'f', b'i', b'l', b'e', 0xff]
        );
        assert_eq!(valid.total_path_bytes(), 18);

        let root = UnixLocalFileLocatorV1::new(b"/".to_vec(), [b"file".to_vec()]).unwrap();
        assert_eq!(root.total_path_bytes(), 5);

        let mut oversized_root = vec![b'a'; MAX_UNIX_LOCAL_FILE_ROOT_BYTES + 1];
        oversized_root[0] = b'/';
        let long_root_component = {
            let mut bytes = vec![b'a'; MAX_UNIX_LOCAL_FILE_COMPONENT_BYTES + 2];
            bytes[0] = b'/';
            bytes
        };
        let total_overflow_root = {
            let mut bytes = vec![b'a'; MAX_UNIX_LOCAL_FILE_COMPONENT_BYTES + 1];
            bytes[0] = b'/';
            bytes
        };
        let maximum_components =
            vec![vec![b'x'; MAX_UNIX_LOCAL_FILE_COMPONENT_BYTES]; MAX_UNIX_LOCAL_FILE_COMPONENTS];
        let cases = [
            (
                UnixLocalFileLocatorV1::new(Vec::new(), [b"x".to_vec()]).unwrap_err(),
                UnixLocalFileLocatorConstructionError::EmptyRoot,
            ),
            (
                UnixLocalFileLocatorV1::new(oversized_root, [b"x".to_vec()]).unwrap_err(),
                UnixLocalFileLocatorConstructionError::RootTooLong,
            ),
            (
                UnixLocalFileLocatorV1::new(b"var/log".to_vec(), [b"x".to_vec()]).unwrap_err(),
                UnixLocalFileLocatorConstructionError::RootNotAbsolute,
            ),
            (
                UnixLocalFileLocatorV1::new(b"/var\0log".to_vec(), [b"x".to_vec()]).unwrap_err(),
                UnixLocalFileLocatorConstructionError::RootContainsNul,
            ),
            (
                UnixLocalFileLocatorV1::new(b"/var/log".to_vec(), Vec::<Vec<u8>>::new())
                    .unwrap_err(),
                UnixLocalFileLocatorConstructionError::EmptyMember,
            ),
            (
                UnixLocalFileLocatorV1::new(
                    b"/".to_vec(),
                    vec![b"x".to_vec(); MAX_UNIX_LOCAL_FILE_COMPONENTS + 1],
                )
                .unwrap_err(),
                UnixLocalFileLocatorConstructionError::TooManyComponents,
            ),
            (
                UnixLocalFileLocatorV1::new(b"/".to_vec(), [Vec::new()]).unwrap_err(),
                UnixLocalFileLocatorConstructionError::EmptyComponent,
            ),
            (
                UnixLocalFileLocatorV1::new(b"/".to_vec(), [b"/etc".to_vec()]).unwrap_err(),
                UnixLocalFileLocatorConstructionError::AbsoluteMember,
            ),
            (
                UnixLocalFileLocatorV1::new(b"/".to_vec(), [b"a\0b".to_vec()]).unwrap_err(),
                UnixLocalFileLocatorConstructionError::ComponentContainsNul,
            ),
            (
                UnixLocalFileLocatorV1::new(b"/".to_vec(), [b"a/b".to_vec()]).unwrap_err(),
                UnixLocalFileLocatorConstructionError::SlashInComponent,
            ),
            (
                UnixLocalFileLocatorV1::new(b"/".to_vec(), [b".".to_vec()]).unwrap_err(),
                UnixLocalFileLocatorConstructionError::DotComponent,
            ),
            (
                UnixLocalFileLocatorV1::new(b"/".to_vec(), [b"..".to_vec()]).unwrap_err(),
                UnixLocalFileLocatorConstructionError::DotDotComponent,
            ),
            (
                UnixLocalFileLocatorV1::new(
                    b"/".to_vec(),
                    [vec![b'x'; MAX_UNIX_LOCAL_FILE_COMPONENT_BYTES + 1]],
                )
                .unwrap_err(),
                UnixLocalFileLocatorConstructionError::ComponentTooLong,
            ),
            (
                UnixLocalFileLocatorV1::new(long_root_component, [b"x".to_vec()]).unwrap_err(),
                UnixLocalFileLocatorConstructionError::ComponentTooLong,
            ),
            (
                UnixLocalFileLocatorV1::new(b"/var//log".to_vec(), [b"x".to_vec()]).unwrap_err(),
                UnixLocalFileLocatorConstructionError::DuplicateSeparator,
            ),
            (
                UnixLocalFileLocatorV1::new(b"/var/log/".to_vec(), [b"x".to_vec()]).unwrap_err(),
                UnixLocalFileLocatorConstructionError::TrailingSeparator,
            ),
            (
                UnixLocalFileLocatorV1::new(b"/var/./log".to_vec(), [b"x".to_vec()]).unwrap_err(),
                UnixLocalFileLocatorConstructionError::DotComponent,
            ),
            (
                UnixLocalFileLocatorV1::new(b"/var/../log".to_vec(), [b"x".to_vec()]).unwrap_err(),
                UnixLocalFileLocatorConstructionError::DotDotComponent,
            ),
            (
                UnixLocalFileLocatorV1::new(total_overflow_root, maximum_components).unwrap_err(),
                UnixLocalFileLocatorConstructionError::TotalPathTooLong,
            ),
        ];

        for (actual, expected) in cases {
            assert_eq!(actual, expected);
            assert_eq!(actual.to_string(), actual.code());
            assert!(format!("{actual:?}").contains(actual.code()));
        }

        let debug = format!("{valid:?}");
        assert_eq!(
            debug,
            "UnixLocalFileLocatorV1 { root_present: true, relative_component_count: 2, total_path_byte_count: 18 }"
        );
        assert!(!debug.contains("/var/log"));
        assert!(!debug.contains("file"));
    }

    #[test]
    fn runtime_profile_is_typed_governed_authority_not_a_certification_claim() {
        for architecture in [
            LocalFileArchitectureV1::Aarch64,
            LocalFileArchitectureV1::X86_64,
        ] {
            let profile = runtime_profile(architecture);
            assert_eq!(
                profile.operating_system(),
                LocalFileOperatingSystemV1::MacOs
            );
            assert_eq!(profile.filesystem(), LocalFileFilesystemV1::Apfs);
            assert_eq!(profile.architecture(), architecture);
            assert_eq!(
                profile.deadline_model(),
                LocalFileDeadlineModelV1::CooperativeBetweenIoCalls
            );
            assert_eq!(
                profile.certification_profile_digest(),
                LocalFileCertificationProfileDigest::from_bytes([6; 32])
            );
        }

        let other_os = LocalFileOperatingSystemV1::OtherVersioned {
            version: 1,
            code: 7,
        };
        let other_filesystem = LocalFileFilesystemV1::OtherVersioned {
            version: 1,
            code: 7,
        };
        let other_architecture = LocalFileArchitectureV1::OtherVersioned {
            version: 1,
            code: 7,
        };
        let other_deadline = LocalFileDeadlineModelV1::OtherVersioned {
            version: 1,
            code: 7,
        };
        let digest = LocalFileCertificationProfileDigest::from_bytes([6; 32]);
        let cases = [
            (
                LocalFileRuntimeProfileV1::new(
                    other_os,
                    LocalFileFilesystemV1::Apfs,
                    LocalFileArchitectureV1::Aarch64,
                    LocalFileDeadlineModelV1::CooperativeBetweenIoCalls,
                    digest,
                )
                .unwrap_err(),
                LocalFileRuntimeProfileConstructionError::UnsupportedOperatingSystem,
            ),
            (
                LocalFileRuntimeProfileV1::new(
                    LocalFileOperatingSystemV1::MacOs,
                    other_filesystem,
                    LocalFileArchitectureV1::Aarch64,
                    LocalFileDeadlineModelV1::CooperativeBetweenIoCalls,
                    digest,
                )
                .unwrap_err(),
                LocalFileRuntimeProfileConstructionError::UnsupportedFilesystem,
            ),
            (
                LocalFileRuntimeProfileV1::new(
                    LocalFileOperatingSystemV1::MacOs,
                    LocalFileFilesystemV1::Apfs,
                    other_architecture,
                    LocalFileDeadlineModelV1::CooperativeBetweenIoCalls,
                    digest,
                )
                .unwrap_err(),
                LocalFileRuntimeProfileConstructionError::UnsupportedArchitecture,
            ),
            (
                LocalFileRuntimeProfileV1::new(
                    LocalFileOperatingSystemV1::MacOs,
                    LocalFileFilesystemV1::Apfs,
                    LocalFileArchitectureV1::Aarch64,
                    other_deadline,
                    digest,
                )
                .unwrap_err(),
                LocalFileRuntimeProfileConstructionError::UnsupportedDeadlineModel,
            ),
        ];
        for (actual, expected) in cases {
            assert_eq!(actual, expected);
            assert_eq!(actual.to_string(), actual.code());
            assert!(format!("{actual:?}").contains(actual.code()));
        }

        let debug = format!("{:?}", runtime_profile(LocalFileArchitectureV1::Aarch64));
        assert_eq!(
            debug,
            "LocalFileRuntimeProfileV1 { operating_system_code: \"macos\", filesystem_code: \"apfs\", architecture_code: \"aarch64\", deadline_model_code: \"cooperative_deadline_between_io_calls_v1\", certification_profile_digest_present: true }"
        );
        assert!(!debug.contains("0606"));
        assert!(!debug.contains("build"));
    }

    #[test]
    fn local_plan_requires_a_derived_width_member_token() {
        let source_identity = source_identity(
            LOCAL_FILE_ADAPTER_KIND_V1,
            IdentityProofKindV1::LocalFileMetadata,
            1,
            None,
        );
        let error = LocalFileQueryPlanMaterialV1::new(
            RetrievalId::from_bytes([9; 32]),
            RepositoryIdentityDigest::from_bytes([8; 32]),
            source_identity,
            locator(),
            runtime_profile(LocalFileArchitectureV1::Aarch64),
            SourceMember::new([7; 31]).unwrap(),
            snapshot(1_024),
            LocalFileSnapshotModeV1::WholeFileFixedHighWater,
            LocalFileOrderingV1::SingleFileByteOrder,
            LocalFileOrderingV1::SingleFileByteOrder,
            InternalPathPolicyDigest::from_bytes([5; 32]),
            7,
            PolicyDigest::from_bytes([4; 32]),
            LocalFilePlanCapsV1::new(1_024, 10, 512, 5_000).unwrap(),
            UnixTimestampNanos::new(2),
            UnixTimestampNanos::new(3),
            None,
        )
        .unwrap_err();

        assert_eq!(
            error,
            LocalFileQueryPlanConstructionError::InvalidSourceMemberLength
        );
        assert_eq!(error.to_string(), error.code());
    }

    #[test]
    fn plan_time_boundaries_are_exclusive_and_cannot_outlive_source_proof() {
        let proof_boundary = plan(
            source_identity(
                LOCAL_FILE_ADAPTER_KIND_V1,
                IdentityProofKindV1::LocalFileMetadata,
                10,
                Some(21),
            ),
            20,
            21,
            None,
        )
        .unwrap();
        assert_eq!(proof_boundary.created_at().get(), 20);
        assert_eq!(proof_boundary.execute_before().get(), 21);

        for execute_before in [19, 20] {
            assert_eq!(
                plan(
                    source_identity(
                        LOCAL_FILE_ADAPTER_KIND_V1,
                        IdentityProofKindV1::LocalFileMetadata,
                        10,
                        None,
                    ),
                    20,
                    execute_before,
                    None,
                )
                .unwrap_err(),
                LocalFileQueryPlanConstructionError::ExecuteBeforeNotAfterCreation
            );
        }
        assert_eq!(
            plan(
                source_identity(
                    LOCAL_FILE_ADAPTER_KIND_V1,
                    IdentityProofKindV1::LocalFileMetadata,
                    21,
                    None,
                ),
                20,
                21,
                None,
            )
            .unwrap_err(),
            LocalFileQueryPlanConstructionError::SourceProofObservedAfterCreation
        );
        assert_eq!(
            plan(
                source_identity(
                    LOCAL_FILE_ADAPTER_KIND_V1,
                    IdentityProofKindV1::LocalFileMetadata,
                    10,
                    Some(20),
                ),
                20,
                21,
                None,
            )
            .unwrap_err(),
            LocalFileQueryPlanConstructionError::SourceProofExpiredAtCreation
        );
        assert_eq!(
            plan(
                source_identity(
                    LOCAL_FILE_ADAPTER_KIND_V1,
                    IdentityProofKindV1::LocalFileMetadata,
                    10,
                    Some(21),
                ),
                20,
                22,
                None,
            )
            .unwrap_err(),
            LocalFileQueryPlanConstructionError::PlanOutlivesSourceProof
        );
    }

    #[test]
    fn plan_rejects_unsupported_unix_authority_and_range_facts() {
        let valid_source = || {
            source_identity(
                LOCAL_FILE_ADAPTER_KIND_V1,
                IdentityProofKindV1::LocalFileMetadata,
                1,
                None,
            )
        };
        let caps = || LocalFilePlanCapsV1::new(1_024, 10, 512, 5_000).unwrap();
        let unsupported = LocalFileOrderingV1::OtherVersioned {
            version: 1,
            code: 9,
        };

        let cases = [
            (
                plan(
                    source_identity(
                        "other-adapter",
                        IdentityProofKindV1::LocalFileMetadata,
                        1,
                        None,
                    ),
                    2,
                    3,
                    None,
                )
                .unwrap_err(),
                LocalFileQueryPlanConstructionError::UnsupportedAdapterKind,
            ),
            (
                plan(
                    source_identity_with_adapter(
                        LOCAL_FILE_ADAPTER_KIND_V1,
                        "CANARY_UNSUPPORTED_VERSION",
                        IdentityProofKindV1::LocalFileMetadata,
                        1,
                        None,
                    ),
                    2,
                    3,
                    None,
                )
                .unwrap_err(),
                LocalFileQueryPlanConstructionError::UnsupportedAdapterVersion,
            ),
            (
                plan(
                    source_identity(
                        LOCAL_FILE_ADAPTER_KIND_V1,
                        IdentityProofKindV1::ReplayManifest,
                        1,
                        None,
                    ),
                    2,
                    3,
                    None,
                )
                .unwrap_err(),
                LocalFileQueryPlanConstructionError::UnsupportedSourceProof,
            ),
            (
                plan_with(
                    valid_source(),
                    snapshot(1_024),
                    LocalFileSnapshotModeV1::OtherVersioned {
                        version: 1,
                        code: 9,
                    },
                    LocalFileOrderingV1::SingleFileByteOrder,
                    LocalFileOrderingV1::SingleFileByteOrder,
                    7,
                    caps(),
                    2,
                    3,
                    None,
                )
                .unwrap_err(),
                LocalFileQueryPlanConstructionError::UnsupportedSnapshotMode,
            ),
            (
                plan_with(
                    valid_source(),
                    snapshot(1_024),
                    LocalFileSnapshotModeV1::WholeFileFixedHighWater,
                    unsupported,
                    LocalFileOrderingV1::SingleFileByteOrder,
                    7,
                    caps(),
                    2,
                    3,
                    None,
                )
                .unwrap_err(),
                LocalFileQueryPlanConstructionError::UnsupportedRequestedOrdering,
            ),
            (
                plan_with(
                    valid_source(),
                    snapshot(1_024),
                    LocalFileSnapshotModeV1::WholeFileFixedHighWater,
                    LocalFileOrderingV1::SingleFileByteOrder,
                    unsupported,
                    7,
                    caps(),
                    2,
                    3,
                    None,
                )
                .unwrap_err(),
                LocalFileQueryPlanConstructionError::UnsupportedDeclaredOrdering,
            ),
            (
                plan_with(
                    valid_source(),
                    snapshot(1_025),
                    LocalFileSnapshotModeV1::WholeFileFixedHighWater,
                    LocalFileOrderingV1::SingleFileByteOrder,
                    LocalFileOrderingV1::SingleFileByteOrder,
                    7,
                    caps(),
                    2,
                    3,
                    None,
                )
                .unwrap_err(),
                LocalFileQueryPlanConstructionError::SnapshotAboveSourceByteCap,
            ),
            (
                plan(valid_source(), 2, 3, Some(b"CANARY_CURSOR_TOKEN")).unwrap_err(),
                LocalFileQueryPlanConstructionError::UnsupportedContinuation,
            ),
        ];

        for (actual, expected) in cases {
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn policy_version_must_be_nonzero() {
        let error = plan_with(
            source_identity(
                LOCAL_FILE_ADAPTER_KIND_V1,
                IdentityProofKindV1::LocalFileMetadata,
                1,
                None,
            ),
            snapshot(1_024),
            LocalFileSnapshotModeV1::WholeFileFixedHighWater,
            LocalFileOrderingV1::SingleFileByteOrder,
            LocalFileOrderingV1::SingleFileByteOrder,
            0,
            LocalFilePlanCapsV1::new(1_024, 10, 512, 5_000).unwrap(),
            2,
            3,
            None,
        )
        .unwrap_err();

        assert_eq!(
            error,
            LocalFileQueryPlanConstructionError::ZeroPolicyVersion
        );
        assert_eq!(
            error.code(),
            "EVIDENTRAIL_LOCAL_FILE_PLAN_ZERO_POLICY_VERSION"
        );
    }

    #[test]
    fn local_material_retains_only_typed_local_contract_fields() {
        let plan = plan(
            source_identity(
                LOCAL_FILE_ADAPTER_KIND_V1,
                IdentityProofKindV1::LocalFileMetadata,
                1,
                None,
            ),
            2,
            3,
            None,
        )
        .unwrap();

        assert_eq!(plan.retrieval_id(), RetrievalId::from_bytes([9; 32]));
        assert_eq!(
            plan.repository_identity(),
            RepositoryIdentityDigest::from_bytes([8; 32])
        );
        assert_eq!(
            plan.source_identity().adapter().kind(),
            LOCAL_FILE_ADAPTER_KIND_V1
        );
        assert_eq!(plan.source_member().as_bytes(), &[7; 32]);
        assert_eq!(plan.locator(), &locator());
        assert_eq!(
            plan.runtime_profile(),
            runtime_profile(LocalFileArchitectureV1::Aarch64)
        );
        assert_eq!(plan.policy_version(), 7);
        assert_eq!(plan.policy_digest(), PolicyDigest::from_bytes([4; 32]));
        assert_eq!(plan.snapshot(), snapshot(1_024));
        assert_eq!(
            plan.snapshot_mode(),
            LocalFileSnapshotModeV1::WholeFileFixedHighWater
        );
        assert_eq!(
            plan.requested_ordering(),
            LocalFileOrderingV1::SingleFileByteOrder
        );
        assert_eq!(
            plan.declared_ordering(),
            LocalFileOrderingV1::SingleFileByteOrder
        );
        assert_eq!(
            plan.internal_path_policy_digest(),
            InternalPathPolicyDigest::from_bytes([5; 32])
        );
        assert_eq!(plan.caps().source_bytes(), 1024);
        assert_eq!(plan.caps().wall_time_millis(), 5_000);
        assert!(plan.authorized_continuation().is_none());
    }

    #[test]
    fn plan_and_cap_debug_never_expose_adapter_member_cursor_policy_or_time() {
        const ADAPTER_CANARY: &str = "CANARY_ADAPTER_/secret/path";
        let material = plan(
            source_identity(
                ADAPTER_CANARY,
                IdentityProofKindV1::LocalFileMetadata,
                8_765_432_100,
                None,
            ),
            8_765_432_101,
            8_765_432_102,
            None,
        )
        .unwrap_err();

        assert_eq!(
            material,
            LocalFileQueryPlanConstructionError::UnsupportedAdapterKind
        );

        let material = plan(
            source_identity(
                LOCAL_FILE_ADAPTER_KIND_V1,
                IdentityProofKindV1::LocalFileMetadata,
                8_765_432_100,
                None,
            ),
            8_765_432_101,
            8_765_432_102,
            None,
        )
        .unwrap();

        let plan_debug = format!("{material:?}");
        let caps_debug = format!("{:?}", material.caps());
        assert_eq!(
            plan_debug,
            "LocalFileQueryPlanMaterialV1 { retrieval_id_present: true, repository_identity_present: true, locator_present: true, runtime_profile_present: true, source_member_count: 1, snapshot_present: true, snapshot_mode_code: \"whole_file_fixed_high_water_v1\", requested_ordering_code: \"single_file_byte_order_v1\", declared_ordering_code: \"single_file_byte_order_v1\", internal_path_policy_digest_present: true, authorized_continuation_present: false }"
        );
        assert_eq!(
            caps_debug,
            "LocalFilePlanCapsV1 { source_bytes_present: true, records_present: true, per_record_bytes_present: true, wall_time_millis_present: true }"
        );
        for secret in [
            ADAPTER_CANARY,
            "CANARY_UNSUPPORTED_VERSION",
            "/var/log",
            "current.log",
            "CANARY_CURSOR_TOKEN",
            "0404",
            "8765432100",
        ] {
            assert!(!plan_debug.contains(secret));
            assert!(!caps_debug.contains(secret));
        }

        let snapshot_debug = format!("{:?}", material.snapshot());
        let object_debug = format!("{:?}", material.snapshot().file());
        assert_eq!(
            snapshot_debug,
            "UnixFileSnapshotV1 { file_type_code: \"regular\", root_identity_present: true, file_identity_present: true, fixed_range_present: true }"
        );
        assert_eq!(
            object_debug,
            "UnixFileObjectIdV1 { device_present: true, inode_present: true }"
        );

        let continuation_error = plan(
            source_identity(
                LOCAL_FILE_ADAPTER_KIND_V1,
                IdentityProofKindV1::LocalFileMetadata,
                1,
                None,
            ),
            2,
            3,
            Some(b"CANARY_CURSOR_TOKEN"),
        )
        .unwrap_err();
        assert!(!format!("{continuation_error:?}").contains("CANARY_CURSOR_TOKEN"));

        let error = plan(
            source_identity(
                LOCAL_FILE_ADAPTER_KIND_V1,
                IdentityProofKindV1::LocalFileMetadata,
                1,
                None,
            ),
            3,
            2,
            None,
        )
        .unwrap_err();
        assert_eq!(
            format!("{error:?}"),
            "LocalFileQueryPlanConstructionError { code: \"EVIDENTRAIL_LOCAL_FILE_PLAN_EXECUTE_BEFORE_NOT_AFTER_CREATION\" }"
        );
        assert_eq!(error.to_string(), error.code());
    }
}
