use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::{LocalFileArchitectureV1, LocalFileFilesystemV1, LocalFileOperatingSystemV1};
use sha2::{Digest as _, Sha256};

#[cfg(target_os = "macos")]
mod macos;

/// Frozen version of the evidence-only local-file host matrix.
pub const HOST_CERTIFICATION_MATRIX_VERSION_V1: u16 = 1;
/// Number of required V1 matrix cells. A receipt exists only after all pass.
pub const HOST_CERTIFICATION_MATRIX_CELL_COUNT_V1: usize = 13;
/// Domain for the deterministic V1 matrix receipt digest.
pub const LOCAL_FILE_HOST_CERTIFICATION_RECEIPT_DOMAIN_V1: &str =
    "evidentrail/local-file/host-certification-matrix-receipt/v1";
/// Stable status emitted only after every V1 matrix cell passes.
pub const LOCAL_FILE_HOST_MATRIX_ALL_CELLS_PASSED_CODE_V1: &str =
    "EVIDENTRAIL_LOCAL_HOST_MATRIX_ALL_CELLS_PASSED";
/// Stable reminder that matrix evidence is not public-preflight admission.
pub const LOCAL_FILE_HOST_MATRIX_PREFLIGHT_NOT_ADMITTED_CODE_V1: &str =
    "EVIDENTRAIL_LOCAL_HOST_MATRIX_EVIDENCE_ONLY_PREFLIGHT_NOT_ADMITTED";
/// Stable status for an explicit process-local admission minted only after a
/// successful live execution of every frozen matrix cell.
pub const LOCAL_FILE_HOST_EXECUTION_ADMITTED_CODE_V1: &str =
    "EVIDENTRAIL_LOCAL_HOST_EXECUTION_ADMITTED_AFTER_LIVE_MATRIX";
const LOCAL_FILE_HOST_IDENTITY_DOMAIN_V1: &str = "evidentrail/local-file/host-identity/v1";
const RECEIPT_DIGEST_PREFIX_V1: &str = "local_file_host_matrix_receipt_sha256_";

/// One independently exercised behavior in the frozen V1 host matrix.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum LocalFileHostCertificationCellV1 {
    DarwinOperatingSystemIdentity = 1,
    SupportedArchitectureIdentity = 2,
    ApfsFixtureFilesystemIdentity = 3,
    DescriptorRelativeRegularFileAccepted = 4,
    DescriptorRelativeFinalSymlinkNofollowRejected = 5,
    DescriptorRelativeAncestorSymlinkNofollowRejected = 6,
    DescriptorRelativeNonRegularFileRejected = 7,
    RetainedFileDescriptorIdentityStableAfterPathReplacement = 8,
    RetainedRootDescriptorIdentityStableAfterRootRename = 9,
    HardLinkObjectIdentityDetected = 10,
    AppendSnapshotChangeDetected = 11,
    TruncateSnapshotChangeDetected = 12,
    RootAndFileFstatfsConsistent = 13,
}

impl LocalFileHostCertificationCellV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::DarwinOperatingSystemIdentity => "darwin_operating_system_identity",
            Self::SupportedArchitectureIdentity => "supported_architecture_identity",
            Self::ApfsFixtureFilesystemIdentity => "apfs_fixture_filesystem_identity",
            Self::DescriptorRelativeRegularFileAccepted => {
                "descriptor_relative_regular_file_accepted"
            }
            Self::DescriptorRelativeFinalSymlinkNofollowRejected => {
                "descriptor_relative_final_symlink_nofollow_rejected"
            }
            Self::DescriptorRelativeAncestorSymlinkNofollowRejected => {
                "descriptor_relative_ancestor_symlink_nofollow_rejected"
            }
            Self::DescriptorRelativeNonRegularFileRejected => {
                "descriptor_relative_non_regular_file_rejected"
            }
            Self::RetainedFileDescriptorIdentityStableAfterPathReplacement => {
                "retained_file_descriptor_identity_stable_after_path_replacement"
            }
            Self::RetainedRootDescriptorIdentityStableAfterRootRename => {
                "retained_root_descriptor_identity_stable_after_root_rename"
            }
            Self::HardLinkObjectIdentityDetected => "hard_link_object_identity_detected",
            Self::AppendSnapshotChangeDetected => "append_snapshot_change_detected",
            Self::TruncateSnapshotChangeDetected => "truncate_snapshot_change_detected",
            Self::RootAndFileFstatfsConsistent => "root_and_file_fstatfs_consistent",
        }
    }

    const fn canonical_code(self) -> u16 {
        self as u16
    }
}

impl fmt::Debug for LocalFileHostCertificationCellV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalFileHostCertificationCellV1")
            .field("code", &self.code())
            .finish()
    }
}

const REQUIRED_CELLS_V1: [LocalFileHostCertificationCellV1;
    HOST_CERTIFICATION_MATRIX_CELL_COUNT_V1] = [
    LocalFileHostCertificationCellV1::DarwinOperatingSystemIdentity,
    LocalFileHostCertificationCellV1::SupportedArchitectureIdentity,
    LocalFileHostCertificationCellV1::ApfsFixtureFilesystemIdentity,
    LocalFileHostCertificationCellV1::DescriptorRelativeRegularFileAccepted,
    LocalFileHostCertificationCellV1::DescriptorRelativeFinalSymlinkNofollowRejected,
    LocalFileHostCertificationCellV1::DescriptorRelativeAncestorSymlinkNofollowRejected,
    LocalFileHostCertificationCellV1::DescriptorRelativeNonRegularFileRejected,
    LocalFileHostCertificationCellV1::RetainedFileDescriptorIdentityStableAfterPathReplacement,
    LocalFileHostCertificationCellV1::RetainedRootDescriptorIdentityStableAfterRootRename,
    LocalFileHostCertificationCellV1::HardLinkObjectIdentityDetected,
    LocalFileHostCertificationCellV1::AppendSnapshotChangeDetected,
    LocalFileHostCertificationCellV1::TruncateSnapshotChangeDetected,
    LocalFileHostCertificationCellV1::RootAndFileFstatfsConsistent,
];

/// Opaque digest of the observed Darwin sysname/release/version/machine.
///
/// Each exact byte field is independently `u64` little-endian length framed
/// under `evidentrail/local-file/host-identity/v1`. The underlying host strings are
/// never retained or formatted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LocalFileHostIdentityDigestV1([u8; 32]);

impl LocalFileHostIdentityDigestV1 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for LocalFileHostIdentityDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalFileHostIdentityDigestV1(<redacted>)")
    }
}

/// Deterministic digest of the versioned, all-passed matrix receipt.
///
/// The domain-separated body freezes little-endian matrix/OS/architecture/
/// filesystem codes, the opaque host-identity digest, and every ordered
/// `(u16 cell code, u8 passed)` pair. A semantics change requires a new matrix
/// version.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LocalFileHostCertificationReceiptDigestV1([u8; 32]);

impl LocalFileHostCertificationReceiptDigestV1 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Explicit canonical external token; `Debug` remains redacted.
    #[must_use]
    pub fn canonical_token(&self) -> String {
        let mut token = String::with_capacity(RECEIPT_DIGEST_PREFIX_V1.len() + 64);
        token.push_str(RECEIPT_DIGEST_PREFIX_V1);
        for byte in self.0 {
            use std::fmt::Write as _;
            write!(token, "{byte:02x}").expect("writing to String cannot fail");
        }
        token
    }
}

impl fmt::Debug for LocalFileHostCertificationReceiptDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalFileHostCertificationReceiptDigestV1(<redacted>)")
    }
}

/// Evidence that every frozen V1 host-semantics cell passed on one live host.
///
/// This receipt is deliberately not wired into preflight admission. It is not
/// an authorization, host certificate, binding, executable token, or proof
/// that a future host observation is equivalent to this one.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LocalFileHostCertificationReceiptV1 {
    architecture: LocalFileArchitectureV1,
    host_identity_digest: LocalFileHostIdentityDigestV1,
    passed_cells: [LocalFileHostCertificationCellV1; HOST_CERTIFICATION_MATRIX_CELL_COUNT_V1],
    receipt_digest: LocalFileHostCertificationReceiptDigestV1,
}

impl LocalFileHostCertificationReceiptV1 {
    fn all_passed(
        architecture: LocalFileArchitectureV1,
        host_identity_digest: LocalFileHostIdentityDigestV1,
    ) -> Self {
        let receipt_digest = derive_receipt_digest(architecture, host_identity_digest);
        Self {
            architecture,
            host_identity_digest,
            passed_cells: REQUIRED_CELLS_V1,
            receipt_digest,
        }
    }

    #[must_use]
    pub const fn matrix_version(&self) -> u16 {
        HOST_CERTIFICATION_MATRIX_VERSION_V1
    }

    #[must_use]
    pub const fn operating_system(&self) -> LocalFileOperatingSystemV1 {
        LocalFileOperatingSystemV1::MacOs
    }

    #[must_use]
    pub const fn architecture(&self) -> LocalFileArchitectureV1 {
        self.architecture
    }

    #[must_use]
    pub const fn filesystem(&self) -> LocalFileFilesystemV1 {
        LocalFileFilesystemV1::Apfs
    }

    #[must_use]
    pub const fn host_identity_digest(&self) -> LocalFileHostIdentityDigestV1 {
        self.host_identity_digest
    }

    #[must_use]
    pub const fn passed_cells(
        &self,
    ) -> &[LocalFileHostCertificationCellV1; HOST_CERTIFICATION_MATRIX_CELL_COUNT_V1] {
        &self.passed_cells
    }

    #[must_use]
    pub const fn receipt_digest(&self) -> LocalFileHostCertificationReceiptDigestV1 {
        self.receipt_digest
    }

    #[must_use]
    pub const fn status_code(&self) -> &'static str {
        LOCAL_FILE_HOST_MATRIX_ALL_CELLS_PASSED_CODE_V1
    }

    #[must_use]
    pub const fn preflight_admission_code(&self) -> &'static str {
        LOCAL_FILE_HOST_MATRIX_PREFLIGHT_NOT_ADMITTED_CODE_V1
    }

    /// The matrix runner cannot authorize any source or admit public preflight.
    #[must_use]
    pub const fn authorizes_preflight(&self) -> bool {
        false
    }

    /// The matrix receipt is evidence, never a live host certificate.
    #[must_use]
    pub const fn is_host_certificate(&self) -> bool {
        false
    }
}

impl fmt::Debug for LocalFileHostCertificationReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalFileHostCertificationReceiptV1")
            .field("matrix_version", &self.matrix_version())
            .field("operating_system_code", &self.operating_system().code())
            .field("architecture_code", &self.architecture.code())
            .field("filesystem_code", &self.filesystem().code())
            .field("passed_cell_count", &self.passed_cells.len())
            .field("host_identity_digest_present", &true)
            .field("receipt_digest_present", &true)
            .field("matrix_status_code", &self.status_code())
            .field("preflight_admission_code", &self.preflight_admission_code())
            .field("authorizes_preflight", &false)
            .field("host_certificate", &false)
            .finish()
    }
}

/// Contentless failure from a live matrix run.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LocalFileHostCertificationMatrixErrorV1 {
    UnsupportedOperatingSystem,
    FixtureUnavailable,
    CellFailed(LocalFileHostCertificationCellV1),
}

impl LocalFileHostCertificationMatrixErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedOperatingSystem => "EVIDENTRAIL_LOCAL_HOST_MATRIX_UNSUPPORTED_OS",
            Self::FixtureUnavailable => "EVIDENTRAIL_LOCAL_HOST_MATRIX_FIXTURE_UNAVAILABLE",
            Self::CellFailed(_) => "EVIDENTRAIL_LOCAL_HOST_MATRIX_CELL_FAILED",
        }
    }

    #[must_use]
    pub const fn failed_cell(self) -> Option<LocalFileHostCertificationCellV1> {
        match self {
            Self::CellFailed(cell) => Some(cell),
            Self::UnsupportedOperatingSystem | Self::FixtureUnavailable => None,
        }
    }
}

impl fmt::Debug for LocalFileHostCertificationMatrixErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalFileHostCertificationMatrixErrorV1")
            .field("code", &self.code())
            .field(
                "failed_cell_code",
                &self
                    .failed_cell()
                    .map(LocalFileHostCertificationCellV1::code),
            )
            .finish()
    }
}

impl fmt::Display for LocalFileHostCertificationMatrixErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for LocalFileHostCertificationMatrixErrorV1 {}

/// Exercise the complete evidence-only V1 matrix against live host semantics.
///
/// The macOS implementation creates only synthetic fixtures below the process
/// temporary directory, verifies that their descriptors reside on APFS, and
/// removes them best-effort. No caller path or log content is accepted.
pub fn run_local_file_host_certification_matrix_v1()
-> Result<LocalFileHostCertificationReceiptV1, LocalFileHostCertificationMatrixErrorV1> {
    #[cfg(target_os = "macos")]
    {
        macos::run()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(LocalFileHostCertificationMatrixErrorV1::UnsupportedOperatingSystem)
    }
}

/// Process-local executable admission minted from a successful live matrix
/// run. It is intentionally non-serializable and cannot be reconstructed from
/// the receipt digest alone.
pub struct LocalFileExecutionAdmissionV1 {
    receipt: LocalFileHostCertificationReceiptV1,
}

impl LocalFileExecutionAdmissionV1 {
    #[must_use]
    pub const fn status_code(&self) -> &'static str {
        LOCAL_FILE_HOST_EXECUTION_ADMITTED_CODE_V1
    }

    #[must_use]
    pub(crate) const fn receipt(&self) -> &LocalFileHostCertificationReceiptV1 {
        &self.receipt
    }
}

impl fmt::Debug for LocalFileExecutionAdmissionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalFileExecutionAdmissionV1")
            .field("live_matrix_passed", &true)
            .field("process_local", &true)
            .field("serializable", &false)
            .field("status_code", &self.status_code())
            .finish()
    }
}

/// Run the complete live host matrix and mint a non-serializable admission
/// only if every cell passes. A cached receipt or caller assertion is never
/// accepted by this boundary.
pub fn admit_current_local_file_host_v1()
-> Result<LocalFileExecutionAdmissionV1, LocalFileHostCertificationMatrixErrorV1> {
    run_local_file_host_certification_matrix_v1()
        .map(|receipt| LocalFileExecutionAdmissionV1 { receipt })
}

fn derive_host_identity_digest(fields: &[&[u8]]) -> LocalFileHostIdentityDigestV1 {
    let mut body = Vec::new();
    for field in fields {
        body.extend_from_slice(&(field.len() as u64).to_le_bytes());
        body.extend_from_slice(field);
    }
    LocalFileHostIdentityDigestV1(domain_separated_digest(
        LOCAL_FILE_HOST_IDENTITY_DOMAIN_V1,
        &body,
    ))
}

fn derive_receipt_digest(
    architecture: LocalFileArchitectureV1,
    host_identity_digest: LocalFileHostIdentityDigestV1,
) -> LocalFileHostCertificationReceiptDigestV1 {
    let mut body = Vec::with_capacity(2 + 2 + 2 + 2 + 32 + 2 + (3 * REQUIRED_CELLS_V1.len()));
    body.extend_from_slice(&HOST_CERTIFICATION_MATRIX_VERSION_V1.to_le_bytes());
    body.extend_from_slice(&operating_system_code(LocalFileOperatingSystemV1::MacOs).to_le_bytes());
    body.extend_from_slice(&architecture_code(architecture).to_le_bytes());
    body.extend_from_slice(&filesystem_code(LocalFileFilesystemV1::Apfs).to_le_bytes());
    body.extend_from_slice(host_identity_digest.as_bytes());
    body.extend_from_slice(&(REQUIRED_CELLS_V1.len() as u16).to_le_bytes());
    for cell in REQUIRED_CELLS_V1 {
        body.extend_from_slice(&cell.canonical_code().to_le_bytes());
        body.push(1);
    }
    LocalFileHostCertificationReceiptDigestV1(domain_separated_digest(
        LOCAL_FILE_HOST_CERTIFICATION_RECEIPT_DOMAIN_V1,
        &body,
    ))
}

fn domain_separated_digest(domain: &str, body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_le_bytes());
    hasher.update(domain.as_bytes());
    hasher.update((body.len() as u64).to_le_bytes());
    hasher.update(body);
    hasher.finalize().into()
}

const fn operating_system_code(value: LocalFileOperatingSystemV1) -> u16 {
    match value {
        LocalFileOperatingSystemV1::MacOs => 1,
        LocalFileOperatingSystemV1::OtherVersioned { .. } => 0,
    }
}

const fn architecture_code(value: LocalFileArchitectureV1) -> u16 {
    match value {
        LocalFileArchitectureV1::Aarch64 => 1,
        LocalFileArchitectureV1::X86_64 => 2,
        LocalFileArchitectureV1::OtherVersioned { .. } => 0,
    }
}

const fn filesystem_code(value: LocalFileFilesystemV1) -> u16 {
    match value {
        LocalFileFilesystemV1::Apfs => 1,
        LocalFileFilesystemV1::OtherVersioned { .. } => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_digest_derivation_is_frozen_and_domain_separated() {
        let host = LocalFileHostIdentityDigestV1([0x42; 32]);
        let arm = derive_receipt_digest(LocalFileArchitectureV1::Aarch64, host);
        let x86 = derive_receipt_digest(LocalFileArchitectureV1::X86_64, host);
        assert_eq!(
            arm.canonical_token(),
            "local_file_host_matrix_receipt_sha256_63b30799c85e2839b27ab91529c819a7d8f1bbcd668bd48c8ead721f15f3c95a"
        );
        assert_ne!(arm, x86);
        assert_ne!(
            *arm.as_bytes(),
            domain_separated_digest("evidentrail/local-file/wrong-domain/v1", &[0x42; 32])
        );
    }

    #[test]
    fn cell_vocabulary_is_complete_unique_and_stably_ordered() {
        assert_eq!(
            REQUIRED_CELLS_V1.len(),
            HOST_CERTIFICATION_MATRIX_CELL_COUNT_V1
        );
        for (index, cell) in REQUIRED_CELLS_V1.iter().enumerate() {
            assert_eq!(usize::from(cell.canonical_code()), index + 1);
            assert!(!cell.code().is_empty());
            assert!(!REQUIRED_CELLS_V1[..index].contains(cell));
        }
    }

    #[test]
    fn formatting_is_contentless_and_receipt_has_no_authority() {
        let host = LocalFileHostIdentityDigestV1([0xca; 32]);
        let receipt =
            LocalFileHostCertificationReceiptV1::all_passed(LocalFileArchitectureV1::Aarch64, host);
        let token = receipt.receipt_digest().canonical_token();
        let debug = format!(
            "{receipt:?} {:?} {:?}",
            receipt.host_identity_digest(),
            receipt.receipt_digest()
        );
        assert!(!receipt.authorizes_preflight());
        assert!(!receipt.is_host_certificate());
        assert_eq!(
            receipt.status_code(),
            "EVIDENTRAIL_LOCAL_HOST_MATRIX_ALL_CELLS_PASSED"
        );
        assert_eq!(
            receipt.preflight_admission_code(),
            "EVIDENTRAIL_LOCAL_HOST_MATRIX_EVIDENCE_ONLY_PREFLIGHT_NOT_ADMITTED"
        );
        assert!(!debug.contains("CONTENT_CANARY"));
        assert!(!debug.contains("PATH_CANARY"));
        assert!(!debug.contains("cacaca"));
        assert!(!debug.contains(&token));

        let error = LocalFileHostCertificationMatrixErrorV1::CellFailed(
            LocalFileHostCertificationCellV1::AppendSnapshotChangeDetected,
        );
        let error_text = format!("{error:?} {error}");
        assert_eq!(error.code(), "EVIDENTRAIL_LOCAL_HOST_MATRIX_CELL_FAILED");
        assert!(!error_text.contains("CONTENT_CANARY"));
        assert!(!error_text.contains("PATH_CANARY"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn executable_admission_requires_a_fresh_live_matrix_and_is_contentless() {
        let admission = admit_current_local_file_host_v1().unwrap();
        assert_eq!(
            admission.status_code(),
            "EVIDENTRAIL_LOCAL_HOST_EXECUTION_ADMITTED_AFTER_LIVE_MATRIX"
        );
        let debug = format!("{admission:?}");
        assert!(!debug.contains("local_file_host_matrix_receipt_sha256_"));
        assert!(!debug.contains("PATH_CANARY"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn real_apfs_matrix_passes_deterministically_without_admission_authority() {
        let first = run_local_file_host_certification_matrix_v1().unwrap();
        let second = run_local_file_host_certification_matrix_v1().unwrap();
        assert_eq!(first, second);
        assert_eq!(first.matrix_version(), HOST_CERTIFICATION_MATRIX_VERSION_V1);
        assert_eq!(first.operating_system(), LocalFileOperatingSystemV1::MacOs);
        assert_eq!(first.filesystem(), LocalFileFilesystemV1::Apfs);
        assert_eq!(first.passed_cells(), &REQUIRED_CELLS_V1);
        assert!(!first.authorizes_preflight());
        assert!(!first.is_host_certificate());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn unsupported_platform_fails_before_any_fixture_claim() {
        assert_eq!(
            run_local_file_host_certification_matrix_v1(),
            Err(LocalFileHostCertificationMatrixErrorV1::UnsupportedOperatingSystem)
        );
    }
}
