use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use evidentrail_bench::{
    BenchmarkRunIdentityV1, EvidentrailBenchCaseSpecV1, EvidentrailBenchRunManifestV1,
    ExpectedAcquisitionClassV1,
};
use evidentrail_core::{EventLedger, FetchCompleteness};
use evidentrail_schema::ArtifactDigest;
use sha2::{Digest as _, Sha256};

use crate::{
    CanonicalPublicCaseArtifactV1, CanonicalPublicRunManifestArtifactV1,
    CanonicalPublicSourceRecordMapV1, canonical_public_case_artifact_v1,
    canonical_public_run_manifest_artifact_v1,
};

const INVOCATION_DOMAIN_V1: &[u8] = b"evidentrail/bench-harness/subprocess-invocation/v1";

/// Absolute hard bound for each stdin/stdout/stderr stream.
pub const MAX_HARNESS_STREAM_BYTES_V1: u64 = 64 * 1024 * 1024;
/// Absolute hard bound for a subprocess wall deadline (one hour).
pub const MAX_HARNESS_WALL_NANOS_V1: u64 = 60 * 60 * 1_000_000_000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HarnessLimitDimensionV1 {
    StdinBytes,
    StdoutBytes,
    StderrBytes,
    WallNanos,
}

impl HarnessLimitDimensionV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::StdinBytes => "stdin_bytes",
            Self::StdoutBytes => "stdout_bytes",
            Self::StderrBytes => "stderr_bytes",
            Self::WallNanos => "wall_nanos",
        }
    }
}

impl fmt::Debug for HarnessLimitDimensionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HarnessLimitDimensionV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Explicit hard limits for one subprocess execution.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HarnessLimitsV1 {
    stdin_bytes: u64,
    stdout_bytes: u64,
    stderr_bytes: u64,
    wall_nanos: u64,
}

impl HarnessLimitsV1 {
    pub fn try_new(
        stdin_bytes: u64,
        stdout_bytes: u64,
        stderr_bytes: u64,
        wall_nanos: u64,
    ) -> Result<Self, HarnessError> {
        for (value, dimension) in [
            (stdin_bytes, HarnessLimitDimensionV1::StdinBytes),
            (stdout_bytes, HarnessLimitDimensionV1::StdoutBytes),
            (stderr_bytes, HarnessLimitDimensionV1::StderrBytes),
        ] {
            if value > MAX_HARNESS_STREAM_BYTES_V1 {
                return Err(HarnessError::LimitExceedsHardBound { dimension });
            }
            usize::try_from(value)
                .map_err(|_| HarnessError::LimitNotRepresentable { dimension })?;
        }
        if wall_nanos == 0 {
            return Err(HarnessError::ZeroWallDeadline);
        }
        if wall_nanos > MAX_HARNESS_WALL_NANOS_V1 {
            return Err(HarnessError::LimitExceedsHardBound {
                dimension: HarnessLimitDimensionV1::WallNanos,
            });
        }
        Ok(Self {
            stdin_bytes,
            stdout_bytes,
            stderr_bytes,
            wall_nanos,
        })
    }

    #[must_use]
    pub const fn stdin_bytes(self) -> u64 {
        self.stdin_bytes
    }

    #[must_use]
    pub const fn stdout_bytes(self) -> u64 {
        self.stdout_bytes
    }

    #[must_use]
    pub const fn stderr_bytes(self) -> u64 {
        self.stderr_bytes
    }

    #[must_use]
    pub const fn wall_nanos(self) -> u64 {
        self.wall_nanos
    }
}

impl fmt::Debug for HarnessLimitsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HarnessLimitsV1")
            .field("stdin_bytes", &self.stdin_bytes)
            .field("stdout_bytes", &self.stdout_bytes)
            .field("stderr_bytes", &self.stderr_bytes)
            .field("wall_nanos", &self.wall_nanos)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct EnvironmentBindingV1 {
    name: String,
    value: String,
}

impl EnvironmentBindingV1 {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for EnvironmentBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvironmentBindingV1")
            .field("name_present", &true)
            .field("value_byte_count", &self.value.len())
            .finish()
    }
}

/// Environment policy applied after `Command::env_clear`.
///
/// Names are restricted to portable uppercase ASCII identifiers. Every
/// binding must appear in the separate allowlist; unspecified ambient values
/// are never inherited.
#[derive(Clone, PartialEq, Eq)]
pub struct ClosedEnvironmentV1 {
    allowed_names: Vec<String>,
    bindings: Vec<EnvironmentBindingV1>,
}

impl ClosedEnvironmentV1 {
    pub fn try_new(
        allowed_names: &[&str],
        bindings: &[(&str, &str)],
    ) -> Result<Self, HarnessError> {
        let mut allowed = BTreeSet::new();
        for name in allowed_names {
            validate_environment_name(name)?;
            if !allowed.insert((*name).to_owned()) {
                return Err(HarnessError::DuplicateEnvironmentAllowlistName);
            }
        }

        let mut seen_bindings = BTreeSet::new();
        let mut canonical_bindings = Vec::with_capacity(bindings.len());
        for (name, value) in bindings {
            validate_environment_name(name)?;
            if value.as_bytes().contains(&0) {
                return Err(HarnessError::InvalidEnvironmentValue);
            }
            if !allowed.contains(*name) {
                return Err(HarnessError::EnvironmentNameNotAllowlisted);
            }
            if !seen_bindings.insert((*name).to_owned()) {
                return Err(HarnessError::DuplicateEnvironmentBinding);
            }
            canonical_bindings.push(EnvironmentBindingV1 {
                name: (*name).to_owned(),
                value: (*value).to_owned(),
            });
        }
        canonical_bindings.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        Ok(Self {
            allowed_names: allowed.into_iter().collect(),
            bindings: canonical_bindings,
        })
    }

    #[must_use]
    pub fn empty() -> Self {
        Self {
            allowed_names: Vec::new(),
            bindings: Vec::new(),
        }
    }

    #[must_use]
    pub fn allowed_names(&self) -> &[String] {
        &self.allowed_names
    }

    #[must_use]
    pub fn bindings(&self) -> &[EnvironmentBindingV1] {
        &self.bindings
    }
}

impl fmt::Debug for ClosedEnvironmentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClosedEnvironmentV1")
            .field("ambient_environment_cleared", &true)
            .field("allowlist_count", &self.allowed_names.len())
            .field("binding_count", &self.bindings.len())
            .finish()
    }
}

fn validate_environment_name(name: &str) -> Result<(), HarnessError> {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return Err(HarnessError::InvalidEnvironmentName);
    };
    if !(first == b'_' || first.is_ascii_uppercase())
        || !bytes.all(|byte| byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(HarnessError::InvalidEnvironmentName);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ExternalOutputContractV1 {
    /// Preserve stdout as an opaque artifact. A dedicated strict versioned
    /// parser may validate its public structure, but event semantics require a
    /// separate occurrence-aware source-membership proof.
    OpaqueArtifactOnly,
    /// The exact stdout bytes are themselves the normalized public artifact.
    /// Intended for hermetic helpers and explicitly byte-exact adapters.
    ExactIdentityNormalizer,
}

impl ExternalOutputContractV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::OpaqueArtifactOnly => "opaque_artifact_only",
            Self::ExactIdentityNormalizer => "exact_identity_normalizer",
        }
    }
}

impl fmt::Debug for ExternalOutputContractV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExternalOutputContractV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Exact executable and process policy. Execution never invokes a shell.
#[derive(Clone, PartialEq, Eq)]
pub struct ExecutableBuildV1 {
    system_artifact_digest: ArtifactDigest,
    executable_build_artifact_digest: ArtifactDigest,
    executable_path: PathBuf,
    argv: Vec<String>,
    cwd: PathBuf,
    environment: ClosedEnvironmentV1,
    output_contract: ExternalOutputContractV1,
    adapter_revision: Option<String>,
}

impl ExecutableBuildV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        system_artifact_digest: ArtifactDigest,
        executable_build_artifact_digest: ArtifactDigest,
        executable_path: PathBuf,
        argv: Vec<String>,
        cwd: PathBuf,
        environment: ClosedEnvironmentV1,
        output_contract: ExternalOutputContractV1,
        adapter_revision: Option<String>,
    ) -> Result<Self, HarnessError> {
        validate_absolute_utf8_path(&executable_path, HarnessError::InvalidExecutablePath)?;
        validate_absolute_utf8_path(&cwd, HarnessError::InvalidWorkingDirectory)?;
        for argument in &argv {
            if argument.as_bytes().contains(&0) {
                return Err(HarnessError::InvalidArgument);
            }
        }
        if adapter_revision
            .as_ref()
            .is_some_and(|revision| revision.is_empty() || revision.as_bytes().contains(&0))
        {
            return Err(HarnessError::InvalidAdapterRevision);
        }
        Ok(Self {
            system_artifact_digest,
            executable_build_artifact_digest,
            executable_path,
            argv,
            cwd,
            environment,
            output_contract,
            adapter_revision,
        })
    }

    #[must_use]
    pub const fn system_artifact_digest(&self) -> ArtifactDigest {
        self.system_artifact_digest
    }

    #[must_use]
    pub const fn executable_build_artifact_digest(&self) -> ArtifactDigest {
        self.executable_build_artifact_digest
    }

    #[must_use]
    pub fn executable_path(&self) -> &Path {
        &self.executable_path
    }

    #[must_use]
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    #[must_use]
    pub fn cwd(&self) -> &Path {
        &self.cwd
    }

    #[must_use]
    pub const fn environment(&self) -> &ClosedEnvironmentV1 {
        &self.environment
    }

    #[must_use]
    pub const fn output_contract(&self) -> ExternalOutputContractV1 {
        self.output_contract
    }

    #[must_use]
    pub fn adapter_revision(&self) -> Option<&str> {
        self.adapter_revision.as_deref()
    }
}

impl fmt::Debug for ExecutableBuildV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutableBuildV1")
            .field("system_identity_present", &true)
            .field("executable_build_identity_present", &true)
            .field("absolute_executable_path_present", &true)
            .field("fixed_argument_count", &self.argv.len())
            .field("explicit_working_directory_present", &true)
            .field("environment", &self.environment)
            .field("output_contract", &self.output_contract)
            .field("adapter_revision_present", &self.adapter_revision.is_some())
            .field("uses_shell", &false)
            .finish()
    }
}

fn validate_absolute_utf8_path(path: &Path, error: HarnessError) -> Result<(), HarnessError> {
    if !path.is_absolute()
        || path
            .to_str()
            .is_none_or(|value| value.as_bytes().contains(&0))
    {
        return Err(error);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StdinArtifactClassV1 {
    PublicCase,
    HermeticSyntheticFixture,
}

impl StdinArtifactClassV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PublicCase => "public_case",
            Self::HermeticSyntheticFixture => "hermetic_synthetic_fixture",
        }
    }
}

impl fmt::Debug for StdinArtifactClassV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StdinArtifactClassV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Exact owned stdin bytes with a caller-declared artifact digest verified at
/// construction. No filesystem or ambient log lookup exists in this API.
#[derive(Clone, PartialEq, Eq)]
pub struct StdinArtifactV1 {
    class: StdinArtifactClassV1,
    artifact_digest: ArtifactDigest,
    bytes: Box<[u8]>,
}

impl StdinArtifactV1 {
    pub fn try_new(
        class: StdinArtifactClassV1,
        artifact_digest: ArtifactDigest,
        bytes: Vec<u8>,
    ) -> Result<Self, HarnessError> {
        if artifact_digest_for_bytes_v1(&bytes) != artifact_digest {
            return Err(HarnessError::StdinArtifactDigestMismatch);
        }
        Ok(Self {
            class,
            artifact_digest,
            bytes: bytes.into_boxed_slice(),
        })
    }

    #[must_use]
    pub const fn class(&self) -> StdinArtifactClassV1 {
        self.class
    }

    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for StdinArtifactV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StdinArtifactV1")
            .field("class", &self.class)
            .field("artifact_identity_present", &true)
            .field("byte_count", &self.bytes.len())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InvocationInputContractV1 {
    ByteExact,
    LegacyDrainRawTextKnownNormalization,
    LegacyDrainRawTextFullMembership,
}

impl InvocationInputContractV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ByteExact => "byte_exact",
            Self::LegacyDrainRawTextKnownNormalization => {
                "legacy_drain_raw_text_known_normalization"
            }
            Self::LegacyDrainRawTextFullMembership => "legacy_drain_raw_text_full_membership",
        }
    }
}

impl fmt::Debug for InvocationInputContractV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvocationInputContractV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Fail-closed V1 binding between one public case and its subprocess stdin.
/// Multi-source framing is deliberately unsupported until a canonical public
/// artifact contract defines ordering and separators.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PublicCaseStdinBindingV1 {
    SingleDeclaredSourceExactArtifact,
}

impl PublicCaseStdinBindingV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SingleDeclaredSourceExactArtifact => "single_declared_source_exact_artifact",
        }
    }
}

impl fmt::Debug for PublicCaseStdinBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicCaseStdinBindingV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Trust boundary used to resolve the public case admitted to a subprocess.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PublicCaseResolutionTrustV1 {
    CanonicalPublicCaseArtifactAndSourceExactLedger,
}

impl PublicCaseResolutionTrustV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::CanonicalPublicCaseArtifactAndSourceExactLedger => {
                "canonical_public_case_artifact_and_source_exact_ledger"
            }
        }
    }
}

impl fmt::Debug for PublicCaseResolutionTrustV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicCaseResolutionTrustV1")
            .field("code", &self.code())
            .finish()
    }
}

/// Checked public case input admitted before subprocess construction.
///
/// Construction derives the public case's canonical V1 bytes, verifies that
/// digest in the run manifest, checks exact single-source stdin bytes, and
/// joins every canonical source occurrence to one complete source-exact event.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicCaseInputBindingV1 {
    canonical_public_run_manifest_artifact: CanonicalPublicRunManifestArtifactV1,
    run_identity: BenchmarkRunIdentityV1,
    public_case_artifact_digest: ArtifactDigest,
    canonical_public_case_artifact: CanonicalPublicCaseArtifactV1,
    stdin: StdinArtifactV1,
    source_record_map: CanonicalPublicSourceRecordMapV1,
    source_binding: PublicCaseStdinBindingV1,
    resolution_trust: PublicCaseResolutionTrustV1,
}

impl PublicCaseInputBindingV1 {
    pub fn try_new_canonical(
        run_manifest: &EvidentrailBenchRunManifestV1,
        public_case: &EvidentrailBenchCaseSpecV1,
        stdin: StdinArtifactV1,
        ledger: &EventLedger,
    ) -> Result<Self, HarnessError> {
        let canonical_public_run_manifest_artifact =
            canonical_public_run_manifest_artifact_v1(run_manifest)?;
        let canonical_public_case_artifact = canonical_public_case_artifact_v1(public_case)?;
        let public_case_artifact_digest = canonical_public_case_artifact.artifact_digest();
        if run_manifest
            .public_case_artifact_digests()
            .binary_search(&public_case_artifact_digest)
            .is_err()
        {
            return Err(HarnessError::UnknownPublicCaseArtifact);
        }
        let [declared_source_artifact_digest] = public_case.source_artifact_digests() else {
            return Err(HarnessError::PublicCaseSourceCountUnsupported);
        };
        if *declared_source_artifact_digest != stdin.artifact_digest {
            return Err(HarnessError::PublicCaseStdinArtifactMismatch);
        }
        if public_case.plan_digest() != ledger.plan_digest() {
            return Err(HarnessError::PublicCasePlanLedgerMismatch);
        }
        let acquisition_class = match ledger.fetch_completion().completeness() {
            FetchCompleteness::Complete { .. } => ExpectedAcquisitionClassV1::Complete,
            FetchCompleteness::Partial { .. } => ExpectedAcquisitionClassV1::Partial,
            FetchCompleteness::Unknown { .. } => ExpectedAcquisitionClassV1::Unknown,
        };
        if public_case.expected_acquisition_class() != acquisition_class {
            return Err(HarnessError::PublicCaseAcquisitionClassMismatch);
        }
        let source_record_map = CanonicalPublicSourceRecordMapV1::try_new(&stdin, ledger)?;
        Ok(Self {
            canonical_public_run_manifest_artifact,
            run_identity: run_manifest.identity(),
            public_case_artifact_digest,
            canonical_public_case_artifact,
            stdin,
            source_record_map,
            source_binding: PublicCaseStdinBindingV1::SingleDeclaredSourceExactArtifact,
            resolution_trust:
                PublicCaseResolutionTrustV1::CanonicalPublicCaseArtifactAndSourceExactLedger,
        })
    }

    #[must_use]
    pub const fn canonical_public_run_manifest_artifact(
        &self,
    ) -> &CanonicalPublicRunManifestArtifactV1 {
        &self.canonical_public_run_manifest_artifact
    }

    #[must_use]
    pub const fn public_case_artifact_digest(&self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn stdin(&self) -> &StdinArtifactV1 {
        &self.stdin
    }

    #[must_use]
    pub const fn canonical_public_case_artifact(&self) -> &CanonicalPublicCaseArtifactV1 {
        &self.canonical_public_case_artifact
    }

    #[must_use]
    pub const fn source_record_map(&self) -> &CanonicalPublicSourceRecordMapV1 {
        &self.source_record_map
    }

    #[must_use]
    pub const fn source_binding(&self) -> PublicCaseStdinBindingV1 {
        self.source_binding
    }

    #[must_use]
    pub const fn resolution_trust(&self) -> PublicCaseResolutionTrustV1 {
        self.resolution_trust
    }
}

impl fmt::Debug for PublicCaseInputBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicCaseInputBindingV1")
            .field(
                "canonical_public_run_manifest_artifact",
                &self.canonical_public_run_manifest_artifact,
            )
            .field("run_identity", &self.run_identity)
            .field("public_case_binding_present", &true)
            .field(
                "canonical_public_case_artifact",
                &self.canonical_public_case_artifact,
            )
            .field("stdin", &self.stdin)
            .field("source_record_map", &self.source_record_map)
            .field("source_binding", &self.source_binding)
            .field("resolution_trust", &self.resolution_trust)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InvocationDigestV1([u8; 32]);

impl InvocationDigestV1 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for InvocationDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InvocationDigestV1(<redacted>)")
    }
}

/// Complete public-only subprocess request.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicSubprocessInvocationV1 {
    canonical_public_run_manifest_artifact: CanonicalPublicRunManifestArtifactV1,
    run_identity: BenchmarkRunIdentityV1,
    public_case_artifact_digest: ArtifactDigest,
    canonical_public_case_artifact: CanonicalPublicCaseArtifactV1,
    program: ExecutableBuildV1,
    stdin: StdinArtifactV1,
    source_record_map: CanonicalPublicSourceRecordMapV1,
    limits: HarnessLimitsV1,
    input_contract: InvocationInputContractV1,
    case_stdin_binding: PublicCaseStdinBindingV1,
    case_resolution_trust: PublicCaseResolutionTrustV1,
    digest: InvocationDigestV1,
}

impl PublicSubprocessInvocationV1 {
    pub fn try_new(
        run_manifest: &EvidentrailBenchRunManifestV1,
        case_input: PublicCaseInputBindingV1,
        program: ExecutableBuildV1,
        limits: HarnessLimitsV1,
        input_contract: InvocationInputContractV1,
    ) -> Result<Self, HarnessError> {
        if run_manifest
            .public_case_artifact_digests()
            .binary_search(&case_input.public_case_artifact_digest)
            .is_err()
        {
            return Err(HarnessError::UnknownPublicCaseArtifact);
        }
        if run_manifest.identity() != case_input.run_identity {
            return Err(HarnessError::CaseInputRunIdentityMismatch);
        }
        let canonical_public_run_manifest_artifact =
            canonical_public_run_manifest_artifact_v1(run_manifest)?;
        if canonical_public_run_manifest_artifact
            != case_input.canonical_public_run_manifest_artifact
        {
            return Err(HarnessError::CaseInputRunManifestArtifactMismatch);
        }
        if run_manifest.identity().system_artifact_digest() != program.system_artifact_digest {
            return Err(HarnessError::SystemArtifactMismatch);
        }
        if run_manifest.identity().build_artifact_digest()
            != program.executable_build_artifact_digest
        {
            return Err(HarnessError::BuildArtifactMismatch);
        }
        let stdin_length = u64::try_from(case_input.stdin.bytes.len())
            .map_err(|_| HarnessError::ArtifactLengthOverflow)?;
        if stdin_length > limits.stdin_bytes {
            return Err(HarnessError::StdinByteCapExceeded);
        }

        let PublicCaseInputBindingV1 {
            canonical_public_run_manifest_artifact,
            run_identity,
            public_case_artifact_digest,
            canonical_public_case_artifact,
            stdin,
            source_record_map,
            source_binding: case_stdin_binding,
            resolution_trust: case_resolution_trust,
        } = case_input;
        let digest = derive_invocation_digest_v1(
            &canonical_public_run_manifest_artifact,
            run_identity,
            public_case_artifact_digest,
            &canonical_public_case_artifact,
            &program,
            &stdin,
            &source_record_map,
            limits,
            input_contract,
            case_stdin_binding,
            case_resolution_trust,
        )?;
        Ok(Self {
            canonical_public_run_manifest_artifact,
            run_identity,
            public_case_artifact_digest,
            canonical_public_case_artifact,
            program,
            stdin,
            source_record_map,
            limits,
            input_contract,
            case_stdin_binding,
            case_resolution_trust,
            digest,
        })
    }

    #[must_use]
    pub const fn run_manifest_artifact_digest(&self) -> ArtifactDigest {
        self.canonical_public_run_manifest_artifact
            .artifact_digest()
    }

    #[must_use]
    pub const fn canonical_public_run_manifest_artifact(
        &self,
    ) -> &CanonicalPublicRunManifestArtifactV1 {
        &self.canonical_public_run_manifest_artifact
    }

    #[must_use]
    pub const fn run_identity(&self) -> BenchmarkRunIdentityV1 {
        self.run_identity
    }

    #[must_use]
    pub const fn public_case_artifact_digest(&self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn program(&self) -> &ExecutableBuildV1 {
        &self.program
    }

    #[must_use]
    pub const fn canonical_public_case_artifact(&self) -> &CanonicalPublicCaseArtifactV1 {
        &self.canonical_public_case_artifact
    }

    #[must_use]
    pub const fn stdin(&self) -> &StdinArtifactV1 {
        &self.stdin
    }

    #[must_use]
    pub const fn source_record_map(&self) -> &CanonicalPublicSourceRecordMapV1 {
        &self.source_record_map
    }

    #[must_use]
    pub const fn limits(&self) -> HarnessLimitsV1 {
        self.limits
    }

    #[must_use]
    pub const fn input_contract(&self) -> InvocationInputContractV1 {
        self.input_contract
    }

    #[must_use]
    pub const fn case_stdin_binding(&self) -> PublicCaseStdinBindingV1 {
        self.case_stdin_binding
    }

    #[must_use]
    pub const fn case_resolution_trust(&self) -> PublicCaseResolutionTrustV1 {
        self.case_resolution_trust
    }

    #[must_use]
    pub const fn digest(&self) -> InvocationDigestV1 {
        self.digest
    }
}

impl fmt::Debug for PublicSubprocessInvocationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicSubprocessInvocationV1")
            .field(
                "canonical_public_run_manifest_artifact",
                &self.canonical_public_run_manifest_artifact,
            )
            .field("run_identity", &self.run_identity)
            .field("public_case_binding_present", &true)
            .field(
                "canonical_public_case_artifact",
                &self.canonical_public_case_artifact,
            )
            .field("program", &self.program)
            .field("stdin", &self.stdin)
            .field("source_record_map", &self.source_record_map)
            .field("limits", &self.limits)
            .field("input_contract", &self.input_contract)
            .field("case_stdin_binding", &self.case_stdin_binding)
            .field("case_resolution_trust", &self.case_resolution_trust)
            .field("invocation_digest_present", &true)
            .field("contains_governed_labels", &false)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HarnessError {
    LimitExceedsHardBound { dimension: HarnessLimitDimensionV1 },
    LimitNotRepresentable { dimension: HarnessLimitDimensionV1 },
    ZeroWallDeadline,
    InvalidEnvironmentName,
    InvalidEnvironmentValue,
    DuplicateEnvironmentAllowlistName,
    DuplicateEnvironmentBinding,
    EnvironmentNameNotAllowlisted,
    InvalidExecutablePath,
    InvalidWorkingDirectory,
    InvalidArgument,
    InvalidAdapterRevision,
    StdinArtifactDigestMismatch,
    StdinByteCapExceeded,
    UnknownPublicCaseArtifact,
    SystemArtifactMismatch,
    BuildArtifactMismatch,
    ArtifactLengthOverflow,
    InvocationBindingOverflow,
    ArtifactNotRegularFile,
    ArtifactReadFailed,
    ExecutableArtifactDigestMismatch,
    ExecutableChangedDuringSpawn,
    WorkingDirectoryUnavailable,
    SpawnFailed,
    MissingChildPipe,
    ChildStatusFailed,
    ChildTerminationFailed,
    WorkerThreadFailed,
    UnsupportedExternalInput,
    InvalidSampleCap,
    FullMembershipEmptyInput,
    FullMembershipRecordCapExceeded,
    FullMembershipInputByteCapExceeded,
    FullMembershipInputNormalizationUnsupported,
    FullMembershipStdoutCapInsufficient,
    FullMembershipCandidateBudgetInsufficient,
    InputAccountingOverflow,
    OutputNormalizationUnsupported,
    OutputNotComplete,
    ProcessNotSuccessful,
    MeasurementBindingMismatch,
    PublicResultBindingMismatch,
    WallTimeOverflow,
    PublicCaseSourceCountUnsupported,
    PublicCaseStdinArtifactMismatch,
    CaseInputRunIdentityMismatch,
    CaseInputRunManifestArtifactMismatch,
    CanonicalPublicCaseArtifactTooLarge,
    CanonicalPublicRunManifestArtifactTooLarge,
    PublicCasePlanLedgerMismatch,
    PublicCaseAcquisitionClassMismatch,
    SourceRecordMapOverflow,
    SourceRecordCountExceedsHardBound,
    SourceRecordLedgerCountMismatch,
    SourceRecordLedgerNotSourceExact,
    SourceRecordLedgerFragment,
    SourceRecordLedgerEventMismatch,
    SourceRecordLedgerLaneMismatch,
    SourceRecordAcquisitionReceiptMismatch,
    SourceRecordMapInputMismatch,
}

impl HarnessError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::LimitExceedsHardBound { .. } => {
                "EVIDENTRAIL_BENCH_HARNESS_LIMIT_EXCEEDS_HARD_BOUND"
            }
            Self::LimitNotRepresentable { .. } => {
                "EVIDENTRAIL_BENCH_HARNESS_LIMIT_NOT_REPRESENTABLE"
            }
            Self::ZeroWallDeadline => "EVIDENTRAIL_BENCH_HARNESS_ZERO_WALL_DEADLINE",
            Self::InvalidEnvironmentName => "EVIDENTRAIL_BENCH_HARNESS_INVALID_ENVIRONMENT_NAME",
            Self::InvalidEnvironmentValue => "EVIDENTRAIL_BENCH_HARNESS_INVALID_ENVIRONMENT_VALUE",
            Self::DuplicateEnvironmentAllowlistName => {
                "EVIDENTRAIL_BENCH_HARNESS_DUPLICATE_ENVIRONMENT_ALLOWLIST_NAME"
            }
            Self::DuplicateEnvironmentBinding => {
                "EVIDENTRAIL_BENCH_HARNESS_DUPLICATE_ENVIRONMENT_BINDING"
            }
            Self::EnvironmentNameNotAllowlisted => {
                "EVIDENTRAIL_BENCH_HARNESS_ENVIRONMENT_NAME_NOT_ALLOWLISTED"
            }
            Self::InvalidExecutablePath => "EVIDENTRAIL_BENCH_HARNESS_INVALID_EXECUTABLE_PATH",
            Self::InvalidWorkingDirectory => "EVIDENTRAIL_BENCH_HARNESS_INVALID_WORKING_DIRECTORY",
            Self::InvalidArgument => "EVIDENTRAIL_BENCH_HARNESS_INVALID_ARGUMENT",
            Self::InvalidAdapterRevision => "EVIDENTRAIL_BENCH_HARNESS_INVALID_ADAPTER_REVISION",
            Self::StdinArtifactDigestMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_STDIN_ARTIFACT_DIGEST_MISMATCH"
            }
            Self::StdinByteCapExceeded => "EVIDENTRAIL_BENCH_HARNESS_STDIN_BYTE_CAP_EXCEEDED",
            Self::UnknownPublicCaseArtifact => {
                "EVIDENTRAIL_BENCH_HARNESS_UNKNOWN_PUBLIC_CASE_ARTIFACT"
            }
            Self::SystemArtifactMismatch => "EVIDENTRAIL_BENCH_HARNESS_SYSTEM_ARTIFACT_MISMATCH",
            Self::BuildArtifactMismatch => "EVIDENTRAIL_BENCH_HARNESS_BUILD_ARTIFACT_MISMATCH",
            Self::ArtifactLengthOverflow => "EVIDENTRAIL_BENCH_HARNESS_ARTIFACT_LENGTH_OVERFLOW",
            Self::InvocationBindingOverflow => {
                "EVIDENTRAIL_BENCH_HARNESS_INVOCATION_BINDING_OVERFLOW"
            }
            Self::ArtifactNotRegularFile => "EVIDENTRAIL_BENCH_HARNESS_ARTIFACT_NOT_REGULAR_FILE",
            Self::ArtifactReadFailed => "EVIDENTRAIL_BENCH_HARNESS_ARTIFACT_READ_FAILED",
            Self::ExecutableArtifactDigestMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_EXECUTABLE_ARTIFACT_DIGEST_MISMATCH"
            }
            Self::ExecutableChangedDuringSpawn => {
                "EVIDENTRAIL_BENCH_HARNESS_EXECUTABLE_CHANGED_DURING_SPAWN"
            }
            Self::WorkingDirectoryUnavailable => {
                "EVIDENTRAIL_BENCH_HARNESS_WORKING_DIRECTORY_UNAVAILABLE"
            }
            Self::SpawnFailed => "EVIDENTRAIL_BENCH_HARNESS_SPAWN_FAILED",
            Self::MissingChildPipe => "EVIDENTRAIL_BENCH_HARNESS_MISSING_CHILD_PIPE",
            Self::ChildStatusFailed => "EVIDENTRAIL_BENCH_HARNESS_CHILD_STATUS_FAILED",
            Self::ChildTerminationFailed => "EVIDENTRAIL_BENCH_HARNESS_CHILD_TERMINATION_FAILED",
            Self::WorkerThreadFailed => "EVIDENTRAIL_BENCH_HARNESS_WORKER_THREAD_FAILED",
            Self::UnsupportedExternalInput => {
                "EVIDENTRAIL_BENCH_HARNESS_UNSUPPORTED_EXTERNAL_INPUT"
            }
            Self::InvalidSampleCap => "EVIDENTRAIL_BENCH_HARNESS_INVALID_SAMPLE_CAP",
            Self::FullMembershipEmptyInput => {
                "EVIDENTRAIL_BENCH_HARNESS_FULL_MEMBERSHIP_EMPTY_INPUT"
            }
            Self::FullMembershipRecordCapExceeded => {
                "EVIDENTRAIL_BENCH_HARNESS_FULL_MEMBERSHIP_RECORD_CAP_EXCEEDED"
            }
            Self::FullMembershipInputByteCapExceeded => {
                "EVIDENTRAIL_BENCH_HARNESS_FULL_MEMBERSHIP_INPUT_BYTE_CAP_EXCEEDED"
            }
            Self::FullMembershipInputNormalizationUnsupported => {
                "EVIDENTRAIL_BENCH_HARNESS_FULL_MEMBERSHIP_INPUT_NORMALIZATION_UNSUPPORTED"
            }
            Self::FullMembershipStdoutCapInsufficient => {
                "EVIDENTRAIL_BENCH_HARNESS_FULL_MEMBERSHIP_STDOUT_CAP_INSUFFICIENT"
            }
            Self::FullMembershipCandidateBudgetInsufficient => {
                "EVIDENTRAIL_BENCH_HARNESS_FULL_MEMBERSHIP_CANDIDATE_BUDGET_INSUFFICIENT"
            }
            Self::InputAccountingOverflow => "EVIDENTRAIL_BENCH_HARNESS_INPUT_ACCOUNTING_OVERFLOW",
            Self::OutputNormalizationUnsupported => {
                "EVIDENTRAIL_BENCH_HARNESS_OUTPUT_NORMALIZATION_UNSUPPORTED"
            }
            Self::OutputNotComplete => "EVIDENTRAIL_BENCH_HARNESS_OUTPUT_NOT_COMPLETE",
            Self::ProcessNotSuccessful => "EVIDENTRAIL_BENCH_HARNESS_PROCESS_NOT_SUCCESSFUL",
            Self::MeasurementBindingMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_MEASUREMENT_BINDING_MISMATCH"
            }
            Self::PublicResultBindingMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_PUBLIC_RESULT_BINDING_MISMATCH"
            }
            Self::WallTimeOverflow => "EVIDENTRAIL_BENCH_HARNESS_WALL_TIME_OVERFLOW",
            Self::PublicCaseSourceCountUnsupported => {
                "EVIDENTRAIL_BENCH_HARNESS_PUBLIC_CASE_SOURCE_COUNT_UNSUPPORTED"
            }
            Self::PublicCaseStdinArtifactMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_PUBLIC_CASE_STDIN_ARTIFACT_MISMATCH"
            }
            Self::CaseInputRunIdentityMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_CASE_INPUT_RUN_IDENTITY_MISMATCH"
            }
            Self::CaseInputRunManifestArtifactMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_CASE_INPUT_RUN_MANIFEST_ARTIFACT_MISMATCH"
            }
            Self::CanonicalPublicCaseArtifactTooLarge => {
                "EVIDENTRAIL_BENCH_HARNESS_CANONICAL_PUBLIC_CASE_ARTIFACT_TOO_LARGE"
            }
            Self::CanonicalPublicRunManifestArtifactTooLarge => {
                "EVIDENTRAIL_BENCH_HARNESS_CANONICAL_PUBLIC_RUN_MANIFEST_ARTIFACT_TOO_LARGE"
            }
            Self::PublicCasePlanLedgerMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_PUBLIC_CASE_PLAN_LEDGER_MISMATCH"
            }
            Self::PublicCaseAcquisitionClassMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_PUBLIC_CASE_ACQUISITION_CLASS_MISMATCH"
            }
            Self::SourceRecordMapOverflow => "EVIDENTRAIL_BENCH_HARNESS_SOURCE_RECORD_MAP_OVERFLOW",
            Self::SourceRecordCountExceedsHardBound => {
                "EVIDENTRAIL_BENCH_HARNESS_SOURCE_RECORD_COUNT_EXCEEDS_HARD_BOUND"
            }
            Self::SourceRecordLedgerCountMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_SOURCE_RECORD_LEDGER_COUNT_MISMATCH"
            }
            Self::SourceRecordLedgerNotSourceExact => {
                "EVIDENTRAIL_BENCH_HARNESS_SOURCE_RECORD_LEDGER_NOT_SOURCE_EXACT"
            }
            Self::SourceRecordLedgerFragment => {
                "EVIDENTRAIL_BENCH_HARNESS_SOURCE_RECORD_LEDGER_FRAGMENT"
            }
            Self::SourceRecordLedgerEventMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_SOURCE_RECORD_LEDGER_EVENT_MISMATCH"
            }
            Self::SourceRecordLedgerLaneMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_SOURCE_RECORD_LEDGER_LANE_MISMATCH"
            }
            Self::SourceRecordAcquisitionReceiptMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_SOURCE_RECORD_ACQUISITION_RECEIPT_MISMATCH"
            }
            Self::SourceRecordMapInputMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_SOURCE_RECORD_MAP_INPUT_MISMATCH"
            }
        }
    }
}

impl fmt::Debug for HarnessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("HarnessError");
        debug.field("code", &self.code());
        match self {
            Self::LimitExceedsHardBound { dimension }
            | Self::LimitNotRepresentable { dimension } => {
                debug.field("dimension", &dimension.code());
            }
            _ => {}
        }
        debug.finish()
    }
}

impl fmt::Display for HarnessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for HarnessError {}

#[must_use]
pub fn artifact_digest_for_bytes_v1(bytes: &[u8]) -> ArtifactDigest {
    ArtifactDigest::from_bytes(Sha256::digest(bytes).into())
}

pub fn artifact_digest_for_file_v1(path: &Path) -> Result<ArtifactDigest, HarnessError> {
    let metadata = path
        .metadata()
        .map_err(|_| HarnessError::ArtifactReadFailed)?;
    if !metadata.is_file() {
        return Err(HarnessError::ArtifactNotRegularFile);
    }
    let mut file = File::open(path).map_err(|_| HarnessError::ArtifactReadFailed)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| HarnessError::ArtifactReadFailed)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

#[allow(clippy::too_many_arguments)]
fn derive_invocation_digest_v1(
    canonical_public_run_manifest_artifact: &CanonicalPublicRunManifestArtifactV1,
    run_identity: BenchmarkRunIdentityV1,
    public_case_artifact_digest: ArtifactDigest,
    canonical_public_case_artifact: &CanonicalPublicCaseArtifactV1,
    program: &ExecutableBuildV1,
    stdin: &StdinArtifactV1,
    source_record_map: &CanonicalPublicSourceRecordMapV1,
    limits: HarnessLimitsV1,
    input_contract: InvocationInputContractV1,
    case_stdin_binding: PublicCaseStdinBindingV1,
    case_resolution_trust: PublicCaseResolutionTrustV1,
) -> Result<InvocationDigestV1, HarnessError> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, INVOCATION_DOMAIN_V1)?;
    update_field(
        &mut hasher,
        canonical_public_run_manifest_artifact
            .artifact_digest()
            .as_bytes(),
    )?;
    update_u64(
        &mut hasher,
        u64::try_from(canonical_public_run_manifest_artifact.byte_count())
            .map_err(|_| HarnessError::InvocationBindingOverflow)?,
    )?;
    for digest in [
        run_identity.system_artifact_digest(),
        run_identity.build_artifact_digest(),
        run_identity.dataset_artifact_digest(),
    ] {
        update_field(&mut hasher, digest.as_bytes())?;
    }
    update_u64(&mut hasher, run_identity.seed())?;
    let budget = run_identity.budget();
    for value in [
        budget.unique_candidate_event_count(),
        budget.unique_candidate_source_bytes(),
        budget.canonical_candidate_tokens(),
        budget.wall_time_nanos(),
        budget.peak_memory_bytes(),
    ] {
        update_u64(&mut hasher, value)?;
    }
    update_field(&mut hasher, public_case_artifact_digest.as_bytes())?;
    update_u64(
        &mut hasher,
        u64::try_from(canonical_public_case_artifact.byte_count())
            .map_err(|_| HarnessError::InvocationBindingOverflow)?,
    )?;
    update_field(
        &mut hasher,
        source_record_map.map_artifact_digest().as_bytes(),
    )?;
    update_field(
        &mut hasher,
        source_record_map.acquisition_receipt_id().as_bytes(),
    )?;
    update_u64(
        &mut hasher,
        u64::try_from(source_record_map.records().len())
            .map_err(|_| HarnessError::InvocationBindingOverflow)?,
    )?;
    update_field(&mut hasher, program.system_artifact_digest.as_bytes())?;
    update_field(
        &mut hasher,
        program.executable_build_artifact_digest.as_bytes(),
    )?;
    update_field(
        &mut hasher,
        program
            .executable_path
            .to_str()
            .expect("constructor requires UTF-8 paths")
            .as_bytes(),
    )?;
    update_u64(
        &mut hasher,
        u64::try_from(program.argv.len()).map_err(|_| HarnessError::InvocationBindingOverflow)?,
    )?;
    for argument in &program.argv {
        update_field(&mut hasher, argument.as_bytes())?;
    }
    update_field(
        &mut hasher,
        program
            .cwd
            .to_str()
            .expect("constructor requires UTF-8 paths")
            .as_bytes(),
    )?;
    update_u64(
        &mut hasher,
        u64::try_from(program.environment.allowed_names.len())
            .map_err(|_| HarnessError::InvocationBindingOverflow)?,
    )?;
    for name in &program.environment.allowed_names {
        update_field(&mut hasher, name.as_bytes())?;
    }
    update_u64(
        &mut hasher,
        u64::try_from(program.environment.bindings.len())
            .map_err(|_| HarnessError::InvocationBindingOverflow)?,
    )?;
    for binding in &program.environment.bindings {
        update_field(&mut hasher, binding.name.as_bytes())?;
        update_field(&mut hasher, binding.value.as_bytes())?;
    }
    update_field(&mut hasher, program.output_contract.code().as_bytes())?;
    update_field(
        &mut hasher,
        program.adapter_revision.as_deref().unwrap_or("").as_bytes(),
    )?;
    update_field(&mut hasher, stdin.class.code().as_bytes())?;
    update_field(&mut hasher, stdin.artifact_digest.as_bytes())?;
    update_u64(
        &mut hasher,
        u64::try_from(stdin.bytes.len()).map_err(|_| HarnessError::ArtifactLengthOverflow)?,
    )?;
    for value in [
        limits.stdin_bytes,
        limits.stdout_bytes,
        limits.stderr_bytes,
        limits.wall_nanos,
    ] {
        update_u64(&mut hasher, value)?;
    }
    update_field(&mut hasher, input_contract.code().as_bytes())?;
    update_field(&mut hasher, case_stdin_binding.code().as_bytes())?;
    update_field(&mut hasher, case_resolution_trust.code().as_bytes())?;
    Ok(InvocationDigestV1(hasher.finalize().into()))
}

fn update_u64(hasher: &mut Sha256, value: u64) -> Result<(), HarnessError> {
    update_field(hasher, &value.to_le_bytes())
}

fn update_field(hasher: &mut Sha256, value: &[u8]) -> Result<(), HarnessError> {
    let length = u64::try_from(value.len()).map_err(|_| HarnessError::InvocationBindingOverflow)?;
    hasher.update(length.to_le_bytes());
    hasher.update(value);
    Ok(())
}
