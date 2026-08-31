use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use evidentrail_schema::{
    AdapterIdentity, BindingDigest, BindingId, BindingRefV1, IdentityProofKindV1,
    InternalPathPolicyDigest, LOCAL_FILE_ADAPTER_KIND_V1, LOCAL_FILE_ADAPTER_VERSION_V1,
    LocalFileArchitectureV1, LocalFileCertificationProfileDigest, LocalFileDeadlineModelV1,
    LocalFileFilesystemV1, LocalFileOperatingSystemV1, LocalFileOrderingV1, LocalFilePlanCapsV1,
    LocalFileQueryPlanMaterialV1, LocalFileRuntimeProfileV1, LocalFileSnapshotModeV1, PlanDigest,
    PlanId, PolicyDigest, RepositoryIdentityDigest, RetrievalId, SourceCursor,
    SourceIdentityDigest, SourceIdentityV1, SourceMember, UnixFileObjectIdV1, UnixFileSnapshotV1,
    UnixFileTypeV1, UnixLocalFileLocatorV1, UnixTimestampNanos,
    bounds::{JSON_SAFE_INTEGER_MAX, MAX_QUERY_PLAN_BYTES, MAX_UNIX_LOCAL_FILE_COMPONENTS},
};
use serde::{Deserialize, Serialize};

use crate::PlanVerificationError;
use crate::canonical::{canonical_json, domain_hash};

/// Exact contract discriminator for the V1 local-file query-plan body.
pub const LOCAL_FILE_PLAN_CONTRACT_V1: &str = "evidentrail.local_file_query_plan";
/// Domain for the integrity digest of canonical V1 local-file plan bytes.
pub const LOCAL_FILE_PLAN_DIGEST_DOMAIN_V1: &str = "evidentrail/local-file-query-plan-digest/v1";
/// Independent domain for the identity of canonical V1 local-file plan bytes.
pub const LOCAL_FILE_PLAN_ID_DOMAIN_V1: &str = "evidentrail/local-file-query-plan-id/v1";
/// Domain for the opaque envelope member derived from the sensitive locator.
pub const LOCAL_FILE_SOURCE_MEMBER_DOMAIN_V1: &str = "evidentrail/local-file-source-member/v1";
/// Domain for the local source identity derived from locator and snapshot facts.
pub const LOCAL_FILE_SOURCE_IDENTITY_DOMAIN_V1: &str = "evidentrail/local-file-source-identity/v1";

const LOCAL_FILE_PLAN_CONTRACT_VERSION_V1: u16 = 1;
const LOCAL_FILE_LOCATOR_CONTRACT_V1: &str = "evidentrail.unix_local_file_locator";
const LOCAL_FILE_LOCATOR_CONTRACT_VERSION_V1: u16 = 1;
const LOCAL_FILE_SOURCE_IDENTITY_CONTRACT_V1: &str = "evidentrail.local_file_source_identity";
const LOCAL_FILE_SOURCE_IDENTITY_CONTRACT_VERSION_V1: u16 = 1;
const LOCAL_FILE_METADATA_PROOF_KIND_V1: &str = "local_file_metadata";
const WHOLE_FILE_FIXED_HIGH_WATER_V1: &str = "whole_file_fixed_high_water_v1";
const SINGLE_FILE_BYTE_ORDER_V1: &str = "single_file_byte_order_v1";
const REGULAR_FILE_TYPE_V1: &str = "regular";
const BASE64URL_NOPAD_ENCODING: &str = "base64url-nopad";
const HASH_BYTES: usize = 32;
const HASH_HEX_BYTES: usize = HASH_BYTES * 2;

/// A local-file plan whose canonical wire bytes, semantic constructors, and
/// two domain-separated identities have all been checked.
///
/// This is intentionally not an executable capability. Its runtime profile is
/// a planned reference to a governed certification matrix, not evidence about
/// the live host or its exact OS build. V1 still has no approved live binding,
/// live profile/build membership record, internal-path registry lease, or
/// pre-first-byte opened-handle revalidation. Those checks remain
/// execution-boundary responsibilities and cannot be inferred from this type.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedLocalFilePlanV1 {
    material: LocalFileQueryPlanMaterialV1,
    plan_id: PlanId,
    plan_digest: PlanDigest,
    canonical_bytes: Vec<u8>,
}

impl VerifiedLocalFilePlanV1 {
    /// Constructor-validated semantic material recovered from the wire body.
    #[must_use]
    pub const fn material(&self) -> &LocalFileQueryPlanMaterialV1 {
        &self.material
    }

    /// Domain-separated identity derived from the canonical plan body.
    #[must_use]
    pub const fn plan_id(&self) -> PlanId {
        self.plan_id
    }

    /// Domain-separated integrity digest derived from the canonical plan body.
    #[must_use]
    pub const fn plan_digest(&self) -> PlanDigest {
        self.plan_digest
    }

    /// Exact RFC 8785 bytes that were verified.
    ///
    /// Plan bytes contain the sensitive root/member locator and must not be
    /// placed in diagnostics or telemetry.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

impl fmt::Debug for VerifiedLocalFilePlanV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedLocalFilePlanV1")
            .field("contract_version", &LOCAL_FILE_PLAN_CONTRACT_VERSION_V1)
            .field("canonical_bytes_len", &self.canonical_bytes.len())
            .field(
                "authorized_continuation_present",
                &self.material.authorized_continuation().is_some(),
            )
            .finish()
    }
}

/// Canonically encode trusted semantic material and pass it through the same
/// decoder and identity-verification path used for persisted plan bytes.
pub fn encode_local_file_plan_v1(
    material: &LocalFileQueryPlanMaterialV1,
) -> Result<VerifiedLocalFilePlanV1, PlanVerificationError> {
    preflight_material_size(material)?;
    let wire = LocalFilePlanWireV1::try_from(material)?;
    let canonical_bytes = canonical_json(&wire)?;
    check_document_size(&canonical_bytes)?;

    let plan_digest = derive_plan_digest(&canonical_bytes)?;
    let plan_id = derive_plan_id(&canonical_bytes)?;
    verify_local_file_plan_v1(&canonical_bytes, plan_id, plan_digest)
}

/// Strictly decode canonical V1 local-file plan bytes and verify the declared
/// typed identities before returning a non-executable verified wrapper.
///
/// The input size is checked before JSON decoding. Private DTOs reject unknown
/// and duplicate fields recursively. The accepted input must already be the
/// exact RFC 8785 representation; this function never normalizes untrusted
/// persisted bytes in place.
pub fn verify_local_file_plan_v1(
    canonical_bytes: &[u8],
    declared_plan_id: PlanId,
    declared_plan_digest: PlanDigest,
) -> Result<VerifiedLocalFilePlanV1, PlanVerificationError> {
    check_document_size(canonical_bytes)?;

    let wire: LocalFilePlanWireV1 = serde_json::from_slice(canonical_bytes)
        .map_err(|_| PlanVerificationError::MalformedDocument)?;
    wire.validate_header()?;

    let regenerated = canonical_json(&wire)?;
    if regenerated.len() > MAX_QUERY_PLAN_BYTES {
        return Err(PlanVerificationError::DocumentTooLarge);
    }
    if regenerated != canonical_bytes {
        return Err(PlanVerificationError::NonCanonicalDocument);
    }

    let material = LocalFileQueryPlanMaterialV1::try_from(wire)?;
    let derived_plan_digest = derive_plan_digest(canonical_bytes)?;
    if derived_plan_digest != declared_plan_digest {
        return Err(PlanVerificationError::PlanDigestMismatch);
    }

    let derived_plan_id = derive_plan_id(canonical_bytes)?;
    if derived_plan_id != declared_plan_id {
        return Err(PlanVerificationError::PlanIdMismatch);
    }

    Ok(VerifiedLocalFilePlanV1 {
        material,
        plan_id: derived_plan_id,
        plan_digest: derived_plan_digest,
        canonical_bytes: canonical_bytes.to_vec(),
    })
}

fn check_document_size(bytes: &[u8]) -> Result<(), PlanVerificationError> {
    if bytes.is_empty() {
        return Err(PlanVerificationError::EmptyDocument);
    }
    if bytes.len() > MAX_QUERY_PLAN_BYTES {
        return Err(PlanVerificationError::DocumentTooLarge);
    }
    Ok(())
}

fn preflight_material_size(
    material: &LocalFileQueryPlanMaterialV1,
) -> Result<(), PlanVerificationError> {
    let identity = material.source_identity();
    let mut variable_bytes = identity.adapter().kind().len();
    variable_bytes = variable_bytes
        .checked_add(identity.adapter().version().len())
        .and_then(|length| length.checked_add(material.locator().total_path_bytes()))
        .and_then(|length| length.checked_add(material.locator().relative_components().len()))
        .and_then(|length| length.checked_add(material.source_member().as_bytes().len()))
        .ok_or(PlanVerificationError::DocumentTooLarge)?;
    if let Some(cursor) = material.authorized_continuation() {
        variable_bytes = variable_bytes
            .checked_add(cursor.as_bytes().len())
            .ok_or(PlanVerificationError::DocumentTooLarge)?;
    }
    if variable_bytes > MAX_QUERY_PLAN_BYTES {
        return Err(PlanVerificationError::DocumentTooLarge);
    }
    Ok(())
}

fn derive_plan_digest(canonical_bytes: &[u8]) -> Result<PlanDigest, PlanVerificationError> {
    domain_hash(LOCAL_FILE_PLAN_DIGEST_DOMAIN_V1.as_bytes(), canonical_bytes)
        .map(PlanDigest::from_bytes)
}

fn derive_plan_id(canonical_bytes: &[u8]) -> Result<PlanId, PlanVerificationError> {
    domain_hash(LOCAL_FILE_PLAN_ID_DOMAIN_V1.as_bytes(), canonical_bytes).map(PlanId::from_bytes)
}

/// Derive the only local-file V1 envelope-member token from a sensitive
/// byte-exact locator. The returned 32-byte value is opaque and cannot be
/// reparsed as a path.
pub fn derive_local_file_source_member_v1(
    locator: &UnixLocalFileLocatorV1,
) -> Result<SourceMember, PlanVerificationError> {
    let body = canonical_json(&LocalFileLocatorIdentityWireV1::try_from(locator)?)?;
    let bytes = domain_hash(LOCAL_FILE_SOURCE_MEMBER_DOMAIN_V1.as_bytes(), &body)?;
    SourceMember::new(bytes).map_err(|_| PlanVerificationError::CanonicalizationFailed)
}

/// Derive the local-file V1 source digest from the pinned adapter/proof kind,
/// sensitive locator, runtime/certification profile, and every Unix snapshot
/// fact represented by V1.
///
/// The profile commits the intended macOS/APFS matrix but does not attest that
/// the current host or exact OS build belongs to it. That requires a separate
/// live runtime record and matrix-membership check at execution binding.
pub fn derive_local_file_source_identity_digest_v1(
    locator: &UnixLocalFileLocatorV1,
    snapshot: UnixFileSnapshotV1,
    runtime_profile: LocalFileRuntimeProfileV1,
) -> Result<SourceIdentityDigest, PlanVerificationError> {
    let material = LocalFileSourceIdentityMaterialWireV1 {
        adapter_kind: LOCAL_FILE_ADAPTER_KIND_V1.to_owned(),
        adapter_version: LOCAL_FILE_ADAPTER_VERSION_V1.to_owned(),
        contract: LOCAL_FILE_SOURCE_IDENTITY_CONTRACT_V1.to_owned(),
        contract_version: LOCAL_FILE_SOURCE_IDENTITY_CONTRACT_VERSION_V1,
        locator: UnixLocalFileLocatorWireV1::try_from(locator)?,
        proof_kind: LOCAL_FILE_METADATA_PROOF_KIND_V1.to_owned(),
        runtime_profile: LocalFileRuntimeProfileWireV1::from(runtime_profile),
        snapshot: UnixFileSnapshotWireV1::from(snapshot),
    };
    let body = canonical_json(&material)?;
    domain_hash(LOCAL_FILE_SOURCE_IDENTITY_DOMAIN_V1.as_bytes(), &body)
        .map(SourceIdentityDigest::from_bytes)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalFilePlanWireV1 {
    contract: String,
    contract_version: u16,
    retrieval_id: String,
    repository_identity: String,
    source_identity: SourceIdentityWireV1,
    source_member: BinaryValueWireV1,
    snapshot: UnixFileSnapshotWireV1,
    snapshot_mode: String,
    requested_ordering: String,
    declared_ordering: String,
    internal_path_policy_digest: String,
    locator: UnixLocalFileLocatorWireV1,
    runtime_profile: LocalFileRuntimeProfileWireV1,
    policy_version: u32,
    policy_digest: String,
    caps: LocalFileCapsWireV1,
    created_at_unix_nanos: String,
    execute_before_unix_nanos: String,
    authorized_continuation: RequiredNullable<BinaryValueWireV1>,
}

impl LocalFilePlanWireV1 {
    fn validate_header(&self) -> Result<(), PlanVerificationError> {
        if self.contract != LOCAL_FILE_PLAN_CONTRACT_V1 {
            return Err(PlanVerificationError::UnsupportedContract);
        }
        if self.contract_version != LOCAL_FILE_PLAN_CONTRACT_VERSION_V1 {
            return Err(PlanVerificationError::UnsupportedVersion);
        }
        Ok(())
    }
}

impl TryFrom<&LocalFileQueryPlanMaterialV1> for LocalFilePlanWireV1 {
    type Error = PlanVerificationError;

    fn try_from(material: &LocalFileQueryPlanMaterialV1) -> Result<Self, Self::Error> {
        let source_identity = material.source_identity();
        if source_identity.proof_kind() != IdentityProofKindV1::LocalFileMetadata {
            return Err(PlanVerificationError::UnsupportedSourceProof);
        }
        if derive_local_file_source_member_v1(material.locator())?.as_bytes()
            != material.source_member().as_bytes()
        {
            return Err(PlanVerificationError::SourceMemberMismatch);
        }
        if derive_local_file_source_identity_digest_v1(
            material.locator(),
            material.snapshot(),
            material.runtime_profile(),
        )? != source_identity.digest()
        {
            return Err(PlanVerificationError::SourceIdentityDigestMismatch);
        }

        Ok(Self {
            contract: LOCAL_FILE_PLAN_CONTRACT_V1.to_owned(),
            contract_version: LOCAL_FILE_PLAN_CONTRACT_VERSION_V1,
            retrieval_id: material.retrieval_id().to_string(),
            repository_identity: material.repository_identity().to_string(),
            source_identity: SourceIdentityWireV1::from(source_identity),
            source_member: BinaryValueWireV1::from_bytes(material.source_member().as_bytes())?,
            snapshot: UnixFileSnapshotWireV1::from(material.snapshot()),
            snapshot_mode: encode_snapshot_mode(material.snapshot_mode())?,
            requested_ordering: encode_ordering(material.requested_ordering())?,
            declared_ordering: encode_ordering(material.declared_ordering())?,
            internal_path_policy_digest: material.internal_path_policy_digest().to_string(),
            locator: UnixLocalFileLocatorWireV1::try_from(material.locator())?,
            runtime_profile: LocalFileRuntimeProfileWireV1::from(material.runtime_profile()),
            policy_version: material.policy_version(),
            policy_digest: material.policy_digest().to_string(),
            caps: LocalFileCapsWireV1::from(material.caps()),
            created_at_unix_nanos: material.created_at().get().to_string(),
            execute_before_unix_nanos: material.execute_before().get().to_string(),
            authorized_continuation: RequiredNullable::from_option(
                material
                    .authorized_continuation()
                    .map(|cursor| BinaryValueWireV1::from_bytes(cursor.as_bytes()))
                    .transpose()?,
            ),
        })
    }
}

impl TryFrom<LocalFilePlanWireV1> for LocalFileQueryPlanMaterialV1 {
    type Error = PlanVerificationError;

    fn try_from(wire: LocalFilePlanWireV1) -> Result<Self, Self::Error> {
        let retrieval_id = RetrievalId::from_bytes(parse_hash_token(&wire.retrieval_id, "ret_")?);
        let repository_identity = RepositoryIdentityDigest::from_bytes(parse_hash_token(
            &wire.repository_identity,
            "repo_sha256_",
        )?);
        let locator = UnixLocalFileLocatorV1::try_from(wire.locator)?;
        let source_member = SourceMember::new(wire.source_member.decode()?)
            .map_err(|_| PlanVerificationError::InvalidSemanticMaterial)?;
        if derive_local_file_source_member_v1(&locator)? != source_member {
            return Err(PlanVerificationError::SourceMemberMismatch);
        }
        let source_identity = SourceIdentityV1::try_from(wire.source_identity)?;
        let policy_digest =
            PolicyDigest::from_bytes(parse_hash_token(&wire.policy_digest, "policy_sha256_")?);
        let caps = LocalFilePlanCapsV1::new(
            wire.caps.source_bytes,
            wire.caps.records,
            wire.caps.per_record_bytes,
            wire.caps.wall_time_millis,
        )
        .map_err(|_| PlanVerificationError::InvalidSemanticMaterial)?;
        let runtime_profile = LocalFileRuntimeProfileV1::try_from(wire.runtime_profile)?;
        let snapshot = UnixFileSnapshotV1::try_from(wire.snapshot)?;
        if derive_local_file_source_identity_digest_v1(&locator, snapshot, runtime_profile)?
            != source_identity.digest()
        {
            return Err(PlanVerificationError::SourceIdentityDigestMismatch);
        }
        let snapshot_mode = parse_snapshot_mode(&wire.snapshot_mode)?;
        let requested_ordering = parse_ordering(&wire.requested_ordering)?;
        let declared_ordering = parse_ordering(&wire.declared_ordering)?;
        let internal_path_policy_digest = InternalPathPolicyDigest::from_bytes(parse_hash_token(
            &wire.internal_path_policy_digest,
            "internal_path_policy_sha256_",
        )?);
        let created_at = parse_timestamp(&wire.created_at_unix_nanos)?;
        let execute_before = parse_timestamp(&wire.execute_before_unix_nanos)?;
        let authorized_continuation = wire
            .authorized_continuation
            .into_option()
            .map(BinaryValueWireV1::decode)
            .transpose()?
            .map(SourceCursor::new)
            .transpose()
            .map_err(|_| PlanVerificationError::InvalidSemanticMaterial)?;

        Self::new(
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
            wire.policy_version,
            policy_digest,
            caps,
            created_at,
            execute_before,
            authorized_continuation,
        )
        .map_err(|_| PlanVerificationError::InvalidSemanticMaterial)
    }
}

#[derive(Serialize)]
struct LocalFileLocatorIdentityWireV1 {
    contract: String,
    contract_version: u16,
    locator: UnixLocalFileLocatorWireV1,
}

impl TryFrom<&UnixLocalFileLocatorV1> for LocalFileLocatorIdentityWireV1 {
    type Error = PlanVerificationError;

    fn try_from(locator: &UnixLocalFileLocatorV1) -> Result<Self, Self::Error> {
        Ok(Self {
            contract: LOCAL_FILE_LOCATOR_CONTRACT_V1.to_owned(),
            contract_version: LOCAL_FILE_LOCATOR_CONTRACT_VERSION_V1,
            locator: UnixLocalFileLocatorWireV1::try_from(locator)?,
        })
    }
}

#[derive(Serialize)]
struct LocalFileSourceIdentityMaterialWireV1 {
    adapter_kind: String,
    adapter_version: String,
    contract: String,
    contract_version: u16,
    locator: UnixLocalFileLocatorWireV1,
    proof_kind: String,
    runtime_profile: LocalFileRuntimeProfileWireV1,
    snapshot: UnixFileSnapshotWireV1,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalFileRuntimeProfileWireV1 {
    operating_system: String,
    filesystem: String,
    architecture: String,
    deadline_model: String,
    certification_profile_digest: String,
}

impl From<LocalFileRuntimeProfileV1> for LocalFileRuntimeProfileWireV1 {
    fn from(profile: LocalFileRuntimeProfileV1) -> Self {
        Self {
            operating_system: profile.operating_system().code().to_owned(),
            filesystem: profile.filesystem().code().to_owned(),
            architecture: profile.architecture().code().to_owned(),
            deadline_model: profile.deadline_model().code().to_owned(),
            certification_profile_digest: profile.certification_profile_digest().to_string(),
        }
    }
}

impl TryFrom<LocalFileRuntimeProfileWireV1> for LocalFileRuntimeProfileV1 {
    type Error = PlanVerificationError;

    fn try_from(wire: LocalFileRuntimeProfileWireV1) -> Result<Self, Self::Error> {
        let operating_system = if wire.operating_system == "macos" {
            LocalFileOperatingSystemV1::MacOs
        } else {
            return Err(PlanVerificationError::InvalidRuntimeProfile);
        };
        let filesystem = if wire.filesystem == "apfs" {
            LocalFileFilesystemV1::Apfs
        } else {
            return Err(PlanVerificationError::InvalidRuntimeProfile);
        };
        let architecture = match wire.architecture.as_str() {
            "aarch64" => LocalFileArchitectureV1::Aarch64,
            "x86_64" => LocalFileArchitectureV1::X86_64,
            _ => return Err(PlanVerificationError::InvalidRuntimeProfile),
        };
        let deadline_model = if wire.deadline_model == "cooperative_deadline_between_io_calls_v1" {
            LocalFileDeadlineModelV1::CooperativeBetweenIoCalls
        } else {
            return Err(PlanVerificationError::InvalidRuntimeProfile);
        };
        let certification_profile_digest =
            LocalFileCertificationProfileDigest::from_bytes(parse_hash_token(
                &wire.certification_profile_digest,
                "local_file_certification_profile_sha256_",
            )?);
        Self::new(
            operating_system,
            filesystem,
            architecture,
            deadline_model,
            certification_profile_digest,
        )
        .map_err(|_| PlanVerificationError::InvalidRuntimeProfile)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnixLocalFileLocatorWireV1 {
    root: BinaryValueWireV1,
    relative_components: Vec<BinaryValueWireV1>,
}

impl TryFrom<&UnixLocalFileLocatorV1> for UnixLocalFileLocatorWireV1 {
    type Error = PlanVerificationError;

    fn try_from(locator: &UnixLocalFileLocatorV1) -> Result<Self, Self::Error> {
        let relative_components = locator
            .relative_components()
            .iter()
            .map(|component| BinaryValueWireV1::from_bytes(component))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            root: BinaryValueWireV1::from_bytes(locator.root())?,
            relative_components,
        })
    }
}

impl TryFrom<UnixLocalFileLocatorWireV1> for UnixLocalFileLocatorV1 {
    type Error = PlanVerificationError;

    fn try_from(wire: UnixLocalFileLocatorWireV1) -> Result<Self, Self::Error> {
        if wire.relative_components.len() > MAX_UNIX_LOCAL_FILE_COMPONENTS {
            return Err(PlanVerificationError::InvalidLocator);
        }
        let root = wire.root.decode()?;
        let relative_components = wire
            .relative_components
            .into_iter()
            .map(BinaryValueWireV1::decode)
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(root, relative_components).map_err(|_| PlanVerificationError::InvalidLocator)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceIdentityWireV1 {
    adapter: AdapterIdentityWireV1,
    binding: BindingRefWireV1,
    digest: String,
    proof: SourceIdentityProofWireV1,
}

impl From<&SourceIdentityV1> for SourceIdentityWireV1 {
    fn from(identity: &SourceIdentityV1) -> Self {
        Self {
            adapter: AdapterIdentityWireV1 {
                kind: identity.adapter().kind().to_owned(),
                version: identity.adapter().version().to_owned(),
            },
            binding: BindingRefWireV1 {
                id: identity.binding().id().to_string(),
                version: identity.binding().version().get(),
                digest: identity.binding().digest().to_string(),
            },
            digest: identity.digest().to_string(),
            proof: SourceIdentityProofWireV1 {
                kind: LOCAL_FILE_METADATA_PROOF_KIND_V1.to_owned(),
                observed_at_unix_nanos: identity.proof_observed_at().get().to_string(),
                expires_at_unix_nanos: RequiredNullable::from_option(
                    identity
                        .proof_expires_at()
                        .map(|timestamp| timestamp.get().to_string()),
                ),
            },
        }
    }
}

impl TryFrom<SourceIdentityWireV1> for SourceIdentityV1 {
    type Error = PlanVerificationError;

    fn try_from(wire: SourceIdentityWireV1) -> Result<Self, Self::Error> {
        if wire.proof.kind != LOCAL_FILE_METADATA_PROOF_KIND_V1 {
            return Err(PlanVerificationError::UnsupportedSourceProof);
        }

        let adapter = AdapterIdentity::new(wire.adapter.kind, wire.adapter.version)
            .map_err(|_| PlanVerificationError::InvalidSemanticMaterial)?;
        let binding = BindingRefV1::new(
            BindingId::from_bytes(parse_hash_token(&wire.binding.id, "bind_")?),
            wire.binding.version,
            BindingDigest::from_bytes(parse_hash_token(&wire.binding.digest, "binding_sha256_")?),
        )
        .map_err(|_| PlanVerificationError::InvalidSemanticMaterial)?;
        let digest =
            SourceIdentityDigest::from_bytes(parse_hash_token(&wire.digest, "source_sha256_")?);
        let observed_at = parse_timestamp(&wire.proof.observed_at_unix_nanos)?;
        let expires_at = wire
            .proof
            .expires_at_unix_nanos
            .into_option()
            .map(|timestamp| parse_timestamp(&timestamp))
            .transpose()?;

        Self::new(
            adapter,
            binding,
            digest,
            IdentityProofKindV1::LocalFileMetadata,
            observed_at,
            expires_at,
        )
        .map_err(|_| PlanVerificationError::InvalidSemanticMaterial)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterIdentityWireV1 {
    kind: String,
    version: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingRefWireV1 {
    id: String,
    version: u32,
    digest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceIdentityProofWireV1 {
    kind: String,
    observed_at_unix_nanos: String,
    expires_at_unix_nanos: RequiredNullable<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalFileCapsWireV1 {
    source_bytes: u64,
    records: u64,
    per_record_bytes: u64,
    wall_time_millis: u64,
}

impl From<LocalFilePlanCapsV1> for LocalFileCapsWireV1 {
    fn from(caps: LocalFilePlanCapsV1) -> Self {
        Self {
            source_bytes: caps.source_bytes(),
            records: caps.records(),
            per_record_bytes: caps.per_record_bytes(),
            wall_time_millis: caps.wall_time_millis(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnixFileSnapshotWireV1 {
    root: UnixFileObjectIdWireV1,
    file: UnixFileObjectIdWireV1,
    file_type: String,
    mode: u32,
    link_count: String,
    size: String,
    modified_seconds: String,
    modified_nanoseconds: String,
    changed_seconds: String,
    changed_nanoseconds: String,
    start_offset: String,
    high_water_exclusive: String,
}

impl From<UnixFileSnapshotV1> for UnixFileSnapshotWireV1 {
    fn from(snapshot: UnixFileSnapshotV1) -> Self {
        Self {
            root: UnixFileObjectIdWireV1::from(snapshot.root()),
            file: UnixFileObjectIdWireV1::from(snapshot.file()),
            file_type: snapshot.file_type().code().to_owned(),
            mode: snapshot.mode(),
            link_count: snapshot.link_count().to_string(),
            size: snapshot.size().to_string(),
            modified_seconds: snapshot.modified_seconds().to_string(),
            modified_nanoseconds: snapshot.modified_nanoseconds().to_string(),
            changed_seconds: snapshot.changed_seconds().to_string(),
            changed_nanoseconds: snapshot.changed_nanoseconds().to_string(),
            start_offset: snapshot.start_offset().to_string(),
            high_water_exclusive: snapshot.high_water_exclusive().to_string(),
        }
    }
}

impl TryFrom<UnixFileSnapshotWireV1> for UnixFileSnapshotV1 {
    type Error = PlanVerificationError;

    fn try_from(wire: UnixFileSnapshotWireV1) -> Result<Self, Self::Error> {
        let file_type = if wire.file_type == REGULAR_FILE_TYPE_V1 {
            UnixFileTypeV1::Regular
        } else {
            return Err(PlanVerificationError::InvalidSemanticMaterial);
        };

        Self::new(
            UnixFileObjectIdV1::try_from(wire.root)?,
            UnixFileObjectIdV1::try_from(wire.file)?,
            file_type,
            wire.mode,
            parse_canonical_u64(&wire.link_count)?,
            parse_canonical_u64(&wire.size)?,
            parse_canonical_i64(&wire.modified_seconds)?,
            parse_canonical_i64(&wire.modified_nanoseconds)?,
            parse_canonical_i64(&wire.changed_seconds)?,
            parse_canonical_i64(&wire.changed_nanoseconds)?,
            parse_canonical_u64(&wire.start_offset)?,
            parse_canonical_u64(&wire.high_water_exclusive)?,
        )
        .map_err(|_| PlanVerificationError::InvalidSemanticMaterial)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnixFileObjectIdWireV1 {
    device: String,
    inode: String,
}

impl From<UnixFileObjectIdV1> for UnixFileObjectIdWireV1 {
    fn from(identity: UnixFileObjectIdV1) -> Self {
        Self {
            device: identity.device().to_string(),
            inode: identity.inode().to_string(),
        }
    }
}

impl TryFrom<UnixFileObjectIdWireV1> for UnixFileObjectIdV1 {
    type Error = PlanVerificationError;

    fn try_from(wire: UnixFileObjectIdWireV1) -> Result<Self, Self::Error> {
        Ok(Self::new(
            parse_canonical_u64(&wire.device)?,
            parse_canonical_u64(&wire.inode)?,
        ))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BinaryValueWireV1 {
    encoding: String,
    data: String,
    byte_length: u64,
}

impl BinaryValueWireV1 {
    fn from_bytes(bytes: &[u8]) -> Result<Self, PlanVerificationError> {
        let byte_length =
            u64::try_from(bytes.len()).map_err(|_| PlanVerificationError::InvalidBinaryValue)?;
        if byte_length > JSON_SAFE_INTEGER_MAX || bytes.len() > MAX_QUERY_PLAN_BYTES {
            return Err(PlanVerificationError::InvalidBinaryValue);
        }
        Ok(Self {
            encoding: BASE64URL_NOPAD_ENCODING.to_owned(),
            data: URL_SAFE_NO_PAD.encode(bytes),
            byte_length,
        })
    }

    fn decode(self) -> Result<Vec<u8>, PlanVerificationError> {
        if self.encoding != BASE64URL_NOPAD_ENCODING || self.byte_length > JSON_SAFE_INTEGER_MAX {
            return Err(PlanVerificationError::InvalidBinaryValue);
        }
        let expected_length = usize::try_from(self.byte_length)
            .map_err(|_| PlanVerificationError::InvalidBinaryValue)?;
        let decoded = URL_SAFE_NO_PAD
            .decode(self.data.as_bytes())
            .map_err(|_| PlanVerificationError::InvalidBinaryValue)?;
        if decoded.len() != expected_length || URL_SAFE_NO_PAD.encode(&decoded) != self.data {
            return Err(PlanVerificationError::InvalidBinaryValue);
        }
        Ok(decoded)
    }
}

/// Serde treats an absent `Option` field as `None`. An untagged value-or-null
/// enum keeps JSON `null` available without giving a missing field a default.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum RequiredNullable<T> {
    Value(T),
    Null,
}

impl<T> RequiredNullable<T> {
    fn from_option(value: Option<T>) -> Self {
        value.map_or(Self::Null, Self::Value)
    }

    fn into_option(self) -> Option<T> {
        match self {
            Self::Value(value) => Some(value),
            Self::Null => None,
        }
    }
}

fn parse_hash_token(token: &str, prefix: &str) -> Result<[u8; 32], PlanVerificationError> {
    let encoded = token
        .as_bytes()
        .strip_prefix(prefix.as_bytes())
        .ok_or(PlanVerificationError::InvalidHashToken)?;
    if encoded.len() != HASH_HEX_BYTES {
        return Err(PlanVerificationError::InvalidHashToken);
    }

    let mut result = [0_u8; HASH_BYTES];
    for (index, pair) in encoded.chunks_exact(2).enumerate() {
        let high = decode_lower_hex(pair[0]).ok_or(PlanVerificationError::InvalidHashToken)?;
        let low = decode_lower_hex(pair[1]).ok_or(PlanVerificationError::InvalidHashToken)?;
        result[index] = (high << 4) | low;
    }
    Ok(result)
}

const fn decode_lower_hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn encode_snapshot_mode(mode: LocalFileSnapshotModeV1) -> Result<String, PlanVerificationError> {
    if mode != LocalFileSnapshotModeV1::WholeFileFixedHighWater {
        return Err(PlanVerificationError::InvalidSemanticMaterial);
    }
    Ok(WHOLE_FILE_FIXED_HIGH_WATER_V1.to_owned())
}

fn parse_snapshot_mode(value: &str) -> Result<LocalFileSnapshotModeV1, PlanVerificationError> {
    if value != WHOLE_FILE_FIXED_HIGH_WATER_V1 {
        return Err(PlanVerificationError::InvalidSemanticMaterial);
    }
    Ok(LocalFileSnapshotModeV1::WholeFileFixedHighWater)
}

fn encode_ordering(ordering: LocalFileOrderingV1) -> Result<String, PlanVerificationError> {
    if ordering != LocalFileOrderingV1::SingleFileByteOrder {
        return Err(PlanVerificationError::InvalidSemanticMaterial);
    }
    Ok(SINGLE_FILE_BYTE_ORDER_V1.to_owned())
}

fn parse_ordering(value: &str) -> Result<LocalFileOrderingV1, PlanVerificationError> {
    if value != SINGLE_FILE_BYTE_ORDER_V1 {
        return Err(PlanVerificationError::InvalidSemanticMaterial);
    }
    Ok(LocalFileOrderingV1::SingleFileByteOrder)
}

fn parse_canonical_u64(value: &str) -> Result<u64, PlanVerificationError> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| PlanVerificationError::InvalidInteger)?;
    if parsed.to_string() != value {
        return Err(PlanVerificationError::InvalidInteger);
    }
    Ok(parsed)
}

fn parse_canonical_i64(value: &str) -> Result<i64, PlanVerificationError> {
    let parsed = value
        .parse::<i64>()
        .map_err(|_| PlanVerificationError::InvalidInteger)?;
    if parsed.to_string() != value {
        return Err(PlanVerificationError::InvalidInteger);
    }
    Ok(parsed)
}

fn parse_timestamp(value: &str) -> Result<UnixTimestampNanos, PlanVerificationError> {
    let parsed = value
        .parse::<i128>()
        .map_err(|_| PlanVerificationError::InvalidTimestamp)?;
    if parsed.to_string() != value {
        return Err(PlanVerificationError::InvalidTimestamp);
    }
    Ok(UnixTimestampNanos::new(parsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_tokens_require_the_exact_prefix_length_and_lowercase_hex() {
        assert_eq!(
            parse_hash_token(&format!("bind_{}", "ab".repeat(32)), "bind_"),
            Ok([0xab; 32])
        );
        assert_eq!(
            parse_hash_token(&format!("bind_{}", "AB".repeat(32)), "bind_"),
            Err(PlanVerificationError::InvalidHashToken)
        );
        assert_eq!(
            parse_hash_token(&format!("other_{}", "ab".repeat(32)), "bind_"),
            Err(PlanVerificationError::InvalidHashToken)
        );
    }

    #[test]
    fn timestamp_strings_have_one_canonical_decimal_spelling() {
        for value in ["00", "01", "+1", "-0", " 1", "1 "] {
            assert_eq!(
                parse_timestamp(value),
                Err(PlanVerificationError::InvalidTimestamp)
            );
        }
        assert_eq!(parse_timestamp("0").unwrap().get(), 0);
        assert_eq!(parse_timestamp("-1").unwrap().get(), -1);
        assert_eq!(
            parse_timestamp(&i128::MIN.to_string()).unwrap().get(),
            i128::MIN
        );
        assert_eq!(
            parse_timestamp(&i128::MAX.to_string()).unwrap().get(),
            i128::MAX
        );
    }

    #[test]
    fn unix_integer_strings_have_one_canonical_decimal_spelling() {
        for value in ["00", "01", "+1", "-0", "-1", " 1", "1 "] {
            assert_eq!(
                parse_canonical_u64(value),
                Err(PlanVerificationError::InvalidInteger)
            );
        }
        assert_eq!(parse_canonical_u64("0"), Ok(0));
        assert_eq!(parse_canonical_u64(&u64::MAX.to_string()), Ok(u64::MAX));
        assert_eq!(
            parse_canonical_u64("18446744073709551616"),
            Err(PlanVerificationError::InvalidInteger)
        );

        for value in ["00", "01", "+1", "-0", " 1", "1 "] {
            assert_eq!(
                parse_canonical_i64(value),
                Err(PlanVerificationError::InvalidInteger)
            );
        }
        assert_eq!(parse_canonical_i64("0"), Ok(0));
        assert_eq!(parse_canonical_i64("-1"), Ok(-1));
        assert_eq!(parse_canonical_i64(&i64::MIN.to_string()), Ok(i64::MIN));
        assert_eq!(parse_canonical_i64(&i64::MAX.to_string()), Ok(i64::MAX));
        assert_eq!(
            parse_canonical_i64("9223372036854775808"),
            Err(PlanVerificationError::InvalidInteger)
        );
    }

    #[test]
    fn locator_and_source_identity_derivations_match_frozen_canonical_material() {
        let locator =
            UnixLocalFileLocatorV1::new(b"/var/log".to_vec(), [b"app".to_vec(), vec![0xfb, 0xff]])
                .unwrap();
        let snapshot = UnixFileSnapshotV1::new(
            UnixFileObjectIdV1::new(u64::MAX, 9_007_199_254_740_992),
            UnixFileObjectIdV1::new(16_777_220, 1_234_567_890_123),
            UnixFileTypeV1::Regular,
            0o100_640,
            2,
            65_536,
            1_700_000_000,
            123_456_789,
            1_700_000_001,
            987_654_321,
            0,
            65_536,
        )
        .unwrap();
        let runtime_profile = LocalFileRuntimeProfileV1::new(
            LocalFileOperatingSystemV1::MacOs,
            LocalFileFilesystemV1::Apfs,
            LocalFileArchitectureV1::Aarch64,
            LocalFileDeadlineModelV1::CooperativeBetweenIoCalls,
            LocalFileCertificationProfileDigest::from_bytes([0x77; 32]),
        )
        .unwrap();

        let locator_body =
            canonical_json(&LocalFileLocatorIdentityWireV1::try_from(&locator).unwrap()).unwrap();
        assert_eq!(
            locator_body,
            include_str!("../tests/fixtures/local_file_plan_v1/locator_identity.json")
                .trim_end()
                .as_bytes()
        );
        let member = derive_local_file_source_member_v1(&locator).unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(member.as_bytes()),
            "hBFVWcuaWAZgWu2XBHvEHLCDc75m6v565KLIkF6nlOk"
        );

        let source_material = LocalFileSourceIdentityMaterialWireV1 {
            adapter_kind: LOCAL_FILE_ADAPTER_KIND_V1.to_owned(),
            adapter_version: LOCAL_FILE_ADAPTER_VERSION_V1.to_owned(),
            contract: LOCAL_FILE_SOURCE_IDENTITY_CONTRACT_V1.to_owned(),
            contract_version: LOCAL_FILE_SOURCE_IDENTITY_CONTRACT_VERSION_V1,
            locator: UnixLocalFileLocatorWireV1::try_from(&locator).unwrap(),
            proof_kind: LOCAL_FILE_METADATA_PROOF_KIND_V1.to_owned(),
            runtime_profile: LocalFileRuntimeProfileWireV1::from(runtime_profile),
            snapshot: UnixFileSnapshotWireV1::from(snapshot),
        };
        let source_body = canonical_json(&source_material).unwrap();
        assert_eq!(
            source_body,
            include_str!("../tests/fixtures/local_file_plan_v1/source_identity_material.json")
                .trim_end()
                .as_bytes()
        );
        let source_digest =
            derive_local_file_source_identity_digest_v1(&locator, snapshot, runtime_profile)
                .unwrap();
        assert_eq!(
            source_digest.to_string(),
            "source_sha256_ae4e66a4c71c6a3ba35ef6a1dd8f0ca962f9a6e30ea48f8691d73a2bb8280250"
        );
        assert_ne!(member.as_bytes(), source_digest.as_bytes());
    }

    #[test]
    fn binary_values_reject_noncanonical_base64_and_length_mismatches() {
        let canonical = BinaryValueWireV1::from_bytes(&[0, 1, 0xfe, 0xff]).unwrap();
        assert_eq!(canonical.data, "AAH-_w");
        assert_eq!(canonical.decode().unwrap(), [0, 1, 0xfe, 0xff]);

        for data in ["AAH+/w", "AAH-_w=="] {
            let invalid = BinaryValueWireV1 {
                encoding: BASE64URL_NOPAD_ENCODING.to_owned(),
                data: data.to_owned(),
                byte_length: 4,
            };
            assert_eq!(
                invalid.decode(),
                Err(PlanVerificationError::InvalidBinaryValue)
            );
        }

        let wrong_length = BinaryValueWireV1 {
            encoding: BASE64URL_NOPAD_ENCODING.to_owned(),
            data: "AAH-_w".to_owned(),
            byte_length: 3,
        };
        assert_eq!(
            wrong_length.decode(),
            Err(PlanVerificationError::InvalidBinaryValue)
        );
    }
}
