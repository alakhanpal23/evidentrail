use std::error::Error as StdError;
use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use evidentrail_schema::{
    AdapterIdentity, ApprovedLocalFileBindingMaterialV1, ApprovedLocalFileLocatorAuthorityV1,
    BindingDigest, BindingId, BindingRefV1, InternalPathPolicyDigest, LocalFileArchitectureV1,
    LocalFileCertificationProfileDigest, LocalFileDeadlineModelV1, LocalFileFilesystemV1,
    LocalFileOperatingSystemV1, LocalFileOrderingV1, LocalFilePlanCapsV1,
    LocalFileRuntimeProfileV1, LocalFileSnapshotModeV1, PlanId, PolicyDigest,
    RepositoryIdentityDigest, UnixFileObjectIdV1, UnixLocalFileLocatorV1, UnixTimestampNanos,
    bounds::{MAX_APPROVED_LOCAL_FILE_BINDING_BYTES, MAX_UNIX_LOCAL_FILE_COMPONENTS},
};
use serde::{Deserialize, Serialize};

use crate::VerifiedLocalFilePlanV1;
use crate::canonical::{canonical_json, domain_hash};

/// Exact contract discriminator for the V1 approved local-file binding.
pub const APPROVED_LOCAL_FILE_BINDING_CONTRACT_V1: &str = "evidentrail.approved_local_file_binding";
/// Domain for the derived digest of approved local-file binding material.
pub const APPROVED_LOCAL_FILE_BINDING_DIGEST_DOMAIN_V1: &str =
    "evidentrail/approved-local-file-binding-digest/v1";

const APPROVED_LOCAL_FILE_BINDING_CONTRACT_VERSION_V1: u16 = 1;
const BASE64URL_NOPAD_ENCODING: &str = "base64url-nopad";
const CERTIFICATION_PROFILE_DIGEST_PREFIX: &str = "local_file_certification_profile_sha256_";
const HASH_BYTES: usize = 32;
const HASH_HEX_BYTES: usize = HASH_BYTES * 2;

/// Strict canonical approved-binding artifact with a verified derived digest.
///
/// Canonical bytes contain the sensitive approved root. The wrapper proves
/// only document integrity and semantic construction. It does not attest that
/// the binding is currently valid or that the live root, host, filesystem,
/// registry, or opened handle matches it.
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovedLocalFileBindingV1 {
    material: ApprovedLocalFileBindingMaterialV1,
    binding_ref: BindingRefV1,
    canonical_bytes: Vec<u8>,
}

impl ApprovedLocalFileBindingV1 {
    #[must_use]
    pub const fn material(&self) -> &ApprovedLocalFileBindingMaterialV1 {
        &self.material
    }

    #[must_use]
    pub const fn binding_ref(&self) -> &BindingRefV1 {
        &self.binding_ref
    }

    /// Exact canonical artifact bytes. These contain the sensitive root path
    /// and must not enter ordinary diagnostics or telemetry.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

impl fmt::Debug for ApprovedLocalFileBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedLocalFileBindingV1")
            .field("material_present", &true)
            .field("binding_reference_present", &true)
            .finish()
    }
}

/// Non-executable proof that one verified plan document is a narrowing of one
/// exact, currently valid approved-binding document.
///
/// This marker does not prove a live registry lease, host certification-matrix
/// membership, binding revocation state outside the supplied document, or
/// opened-handle identity. It cannot be used as an execution capability.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedLocalFilePlanBindingNarrowingV1 {
    plan_id: PlanId,
    binding_ref: BindingRefV1,
    checked_at: UnixTimestampNanos,
}

impl VerifiedLocalFilePlanBindingNarrowingV1 {
    #[must_use]
    pub const fn plan_id(&self) -> PlanId {
        self.plan_id
    }

    #[must_use]
    pub const fn binding_ref(&self) -> &BindingRefV1 {
        &self.binding_ref
    }

    #[must_use]
    pub const fn checked_at(&self) -> UnixTimestampNanos {
        self.checked_at
    }
}

impl fmt::Debug for VerifiedLocalFilePlanBindingNarrowingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedLocalFilePlanBindingNarrowingV1")
            .field("plan_id_present", &true)
            .field("binding_reference_present", &true)
            .field("checked_at_present", &true)
            .finish()
    }
}

/// Canonically encode constructor-validated authority material, derive its
/// binding digest, and pass the bytes through the strict persisted verifier.
pub fn encode_approved_local_file_binding_v1(
    material: &ApprovedLocalFileBindingMaterialV1,
) -> Result<ApprovedLocalFileBindingV1, ApprovedBindingVerificationError> {
    let binding_digest = derive_approved_local_file_binding_digest_v1(material)?;
    let wire = ApprovedLocalFileBindingWireV1 {
        binding_digest: binding_digest.to_string(),
        contract: APPROVED_LOCAL_FILE_BINDING_CONTRACT_V1.to_owned(),
        contract_version: APPROVED_LOCAL_FILE_BINDING_CONTRACT_VERSION_V1,
        material: ApprovedLocalFileBindingMaterialWireV1::try_from(material)?,
    };
    let canonical_bytes = binding_canonical_json(&wire)?;
    check_binding_document_size(&canonical_bytes)?;
    verify_approved_local_file_binding_v1(&canonical_bytes)
}

/// Strictly decode and verify a self-contained approved local-file binding.
///
/// The input must already be its exact canonical representation. The declared
/// digest is independently recomputed over the same contract and semantic
/// material with only the derived digest field omitted.
pub fn verify_approved_local_file_binding_v1(
    canonical_bytes: &[u8],
) -> Result<ApprovedLocalFileBindingV1, ApprovedBindingVerificationError> {
    check_binding_document_size(canonical_bytes)?;
    let wire: ApprovedLocalFileBindingWireV1 = serde_json::from_slice(canonical_bytes)
        .map_err(|_| ApprovedBindingVerificationError::MalformedDocument)?;
    wire.validate_header()?;

    let regenerated = binding_canonical_json(&wire)?;
    if regenerated.len() > MAX_APPROVED_LOCAL_FILE_BINDING_BYTES {
        return Err(ApprovedBindingVerificationError::DocumentTooLarge);
    }
    if regenerated != canonical_bytes {
        return Err(ApprovedBindingVerificationError::NonCanonicalDocument);
    }

    let declared_digest =
        BindingDigest::from_bytes(parse_hash_token(&wire.binding_digest, "binding_sha256_")?);
    let material = ApprovedLocalFileBindingMaterialV1::try_from(wire.material)?;
    let derived_digest = derive_approved_local_file_binding_digest_v1(&material)?;
    if declared_digest != derived_digest {
        return Err(ApprovedBindingVerificationError::BindingDigestMismatch);
    }
    let binding_ref = BindingRefV1::new(
        material.binding_id(),
        material.binding_version().get(),
        derived_digest,
    )
    .map_err(|_| ApprovedBindingVerificationError::InvalidSemanticMaterial)?;

    Ok(ApprovedLocalFileBindingV1 {
        material,
        binding_ref,
        canonical_bytes: canonical_bytes.to_vec(),
    })
}

/// Derive the binding digest over the strict canonical digest-omitting
/// projection. This is public so approval code can present and persist the
/// exact typed reference without constructing an identity cycle.
pub fn derive_approved_local_file_binding_digest_v1(
    material: &ApprovedLocalFileBindingMaterialV1,
) -> Result<BindingDigest, ApprovedBindingVerificationError> {
    let digest_material = ApprovedLocalFileBindingDigestMaterialWireV1 {
        contract: APPROVED_LOCAL_FILE_BINDING_CONTRACT_V1.to_owned(),
        contract_version: APPROVED_LOCAL_FILE_BINDING_CONTRACT_VERSION_V1,
        material: ApprovedLocalFileBindingMaterialWireV1::try_from(material)?,
    };
    let canonical = binding_canonical_json(&digest_material)?;
    domain_hash(
        APPROVED_LOCAL_FILE_BINDING_DIGEST_DOMAIN_V1.as_bytes(),
        &canonical,
    )
    .map(BindingDigest::from_bytes)
    .map_err(|_| ApprovedBindingVerificationError::CanonicalizationFailed)
}

/// Verify that a plan is no broader than the exact supplied binding.
///
/// `checked_at` is a trusted wall-clock observation supplied by the caller.
/// The binding interval is `[valid_from, expires_at)`. Plan creation must be at
/// or after `valid_from`, and the plan's exclusive execution boundary may equal
/// but never exceed the binding's exclusive expiry.
pub fn verify_local_file_plan_binding_narrowing_v1(
    plan: &VerifiedLocalFilePlanV1,
    binding: &ApprovedLocalFileBindingV1,
    checked_at: UnixTimestampNanos,
) -> Result<VerifiedLocalFilePlanBindingNarrowingV1, LocalFilePlanBindingNarrowingError> {
    let authority = binding.material();
    if checked_at.get() < authority.valid_from().get() {
        return Err(LocalFilePlanBindingNarrowingError::BindingNotYetValid);
    }
    if checked_at.get() >= authority.expires_at().get() {
        return Err(LocalFilePlanBindingNarrowingError::BindingExpired);
    }

    let material = plan.material();
    let source_identity = material.source_identity();
    if source_identity.binding() != binding.binding_ref() {
        return Err(LocalFilePlanBindingNarrowingError::BindingReferenceMismatch);
    }
    if material.repository_identity() != authority.repository_identity() {
        return Err(LocalFilePlanBindingNarrowingError::RepositoryMismatch);
    }
    if source_identity.adapter() != authority.adapter() {
        return Err(LocalFilePlanBindingNarrowingError::AdapterMismatch);
    }
    if material.locator() != authority.approved_locator().locator()
        || material.snapshot().root() != authority.approved_locator().root_object_id()
    {
        return Err(LocalFilePlanBindingNarrowingError::LocatorAuthorityMismatch);
    }
    if material.policy_version() != authority.policy_version().get()
        || material.policy_digest() != authority.policy_digest()
    {
        return Err(LocalFilePlanBindingNarrowingError::PolicyMismatch);
    }
    if material.internal_path_policy_digest() != authority.internal_path_policy_digest() {
        return Err(LocalFilePlanBindingNarrowingError::InternalPathPolicyMismatch);
    }
    if material.runtime_profile() != authority.runtime_profile() {
        return Err(LocalFilePlanBindingNarrowingError::RuntimeProfileMismatch);
    }
    if material.snapshot_mode() != authority.snapshot_mode()
        || material.requested_ordering() != authority.ordering()
        || material.declared_ordering() != authority.ordering()
    {
        return Err(LocalFilePlanBindingNarrowingError::AcquisitionSemanticsMismatch);
    }
    if caps_widen(material.caps(), authority.maximum_caps()) {
        return Err(LocalFilePlanBindingNarrowingError::CapWidening);
    }
    if material.created_at().get() < authority.valid_from().get()
        || material.execute_before().get() > authority.expires_at().get()
    {
        return Err(LocalFilePlanBindingNarrowingError::TimeWidening);
    }

    Ok(VerifiedLocalFilePlanBindingNarrowingV1 {
        plan_id: plan.plan_id(),
        binding_ref: *binding.binding_ref(),
        checked_at,
    })
}

fn caps_widen(plan: LocalFilePlanCapsV1, maximum: LocalFilePlanCapsV1) -> bool {
    plan.source_bytes() > maximum.source_bytes()
        || plan.records() > maximum.records()
        || plan.per_record_bytes() > maximum.per_record_bytes()
        || plan.wall_time_millis() > maximum.wall_time_millis()
}

fn check_binding_document_size(bytes: &[u8]) -> Result<(), ApprovedBindingVerificationError> {
    if bytes.is_empty() {
        return Err(ApprovedBindingVerificationError::EmptyDocument);
    }
    if bytes.len() > MAX_APPROVED_LOCAL_FILE_BINDING_BYTES {
        return Err(ApprovedBindingVerificationError::DocumentTooLarge);
    }
    Ok(())
}

fn binding_canonical_json<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, ApprovedBindingVerificationError> {
    canonical_json(value).map_err(|_| ApprovedBindingVerificationError::CanonicalizationFailed)
}

fn parse_hash_token(
    token: &str,
    prefix: &str,
) -> Result<[u8; HASH_BYTES], ApprovedBindingVerificationError> {
    if token.len() != prefix.len() + HASH_HEX_BYTES || !token.starts_with(prefix) {
        return Err(ApprovedBindingVerificationError::InvalidHashToken);
    }
    let mut bytes = [0_u8; HASH_BYTES];
    let hex = &token.as_bytes()[prefix.len()..];
    for (index, pair) in hex.chunks_exact(2).enumerate() {
        let high = lowercase_hex_value(pair[0])?;
        let low = lowercase_hex_value(pair[1])?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

fn lowercase_hex_value(byte: u8) -> Result<u8, ApprovedBindingVerificationError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ApprovedBindingVerificationError::InvalidHashToken),
    }
}

fn parse_timestamp(value: &str) -> Result<UnixTimestampNanos, ApprovedBindingVerificationError> {
    let parsed = value
        .parse::<i128>()
        .map_err(|_| ApprovedBindingVerificationError::InvalidTimestamp)?;
    if parsed.to_string() != value {
        return Err(ApprovedBindingVerificationError::InvalidTimestamp);
    }
    Ok(UnixTimestampNanos::new(parsed))
}

fn parse_canonical_u64(value: &str) -> Result<u64, ApprovedBindingVerificationError> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| ApprovedBindingVerificationError::InvalidInteger)?;
    if parsed.to_string() != value {
        return Err(ApprovedBindingVerificationError::InvalidInteger);
    }
    Ok(parsed)
}

fn encode_snapshot_mode(
    mode: LocalFileSnapshotModeV1,
) -> Result<String, ApprovedBindingVerificationError> {
    if mode != LocalFileSnapshotModeV1::WholeFileFixedHighWater {
        return Err(ApprovedBindingVerificationError::InvalidSemanticMaterial);
    }
    Ok("whole_file_fixed_high_water_v1".to_owned())
}

fn parse_snapshot_mode(
    value: &str,
) -> Result<LocalFileSnapshotModeV1, ApprovedBindingVerificationError> {
    if value != "whole_file_fixed_high_water_v1" {
        return Err(ApprovedBindingVerificationError::InvalidSemanticMaterial);
    }
    Ok(LocalFileSnapshotModeV1::WholeFileFixedHighWater)
}

fn encode_ordering(
    ordering: LocalFileOrderingV1,
) -> Result<String, ApprovedBindingVerificationError> {
    if ordering != LocalFileOrderingV1::SingleFileByteOrder {
        return Err(ApprovedBindingVerificationError::InvalidSemanticMaterial);
    }
    Ok("single_file_byte_order_v1".to_owned())
}

fn parse_ordering(value: &str) -> Result<LocalFileOrderingV1, ApprovedBindingVerificationError> {
    if value != "single_file_byte_order_v1" {
        return Err(ApprovedBindingVerificationError::InvalidSemanticMaterial);
    }
    Ok(LocalFileOrderingV1::SingleFileByteOrder)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedLocalFileBindingWireV1 {
    binding_digest: String,
    contract: String,
    contract_version: u16,
    material: ApprovedLocalFileBindingMaterialWireV1,
}

impl ApprovedLocalFileBindingWireV1 {
    fn validate_header(&self) -> Result<(), ApprovedBindingVerificationError> {
        if self.contract != APPROVED_LOCAL_FILE_BINDING_CONTRACT_V1 {
            return Err(ApprovedBindingVerificationError::UnsupportedContract);
        }
        if self.contract_version != APPROVED_LOCAL_FILE_BINDING_CONTRACT_VERSION_V1 {
            return Err(ApprovedBindingVerificationError::UnsupportedVersion);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ApprovedLocalFileBindingDigestMaterialWireV1 {
    contract: String,
    contract_version: u16,
    material: ApprovedLocalFileBindingMaterialWireV1,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedLocalFileBindingMaterialWireV1 {
    adapter: AdapterIdentityWireV1,
    approved_locator: ApprovedLocalFileLocatorAuthorityWireV1,
    binding_id: String,
    binding_version: u32,
    expires_at_unix_nanos: String,
    internal_path_policy_digest: String,
    maximum_caps: LocalFileCapsWireV1,
    policy_digest: String,
    policy_version: u32,
    repository_identity: String,
    runtime_profile: LocalFileRuntimeProfileWireV1,
    snapshot_mode: String,
    ordering: String,
    valid_from_unix_nanos: String,
}

impl TryFrom<&ApprovedLocalFileBindingMaterialV1> for ApprovedLocalFileBindingMaterialWireV1 {
    type Error = ApprovedBindingVerificationError;

    fn try_from(material: &ApprovedLocalFileBindingMaterialV1) -> Result<Self, Self::Error> {
        Ok(Self {
            adapter: AdapterIdentityWireV1::from(material.adapter()),
            approved_locator: ApprovedLocalFileLocatorAuthorityWireV1::try_from(
                material.approved_locator(),
            )?,
            binding_id: material.binding_id().to_string(),
            binding_version: material.binding_version().get(),
            expires_at_unix_nanos: material.expires_at().get().to_string(),
            internal_path_policy_digest: material.internal_path_policy_digest().to_string(),
            maximum_caps: LocalFileCapsWireV1::from(material.maximum_caps()),
            policy_digest: material.policy_digest().to_string(),
            policy_version: material.policy_version().get(),
            repository_identity: material.repository_identity().to_string(),
            runtime_profile: LocalFileRuntimeProfileWireV1::from(material.runtime_profile()),
            snapshot_mode: encode_snapshot_mode(material.snapshot_mode())?,
            ordering: encode_ordering(material.ordering())?,
            valid_from_unix_nanos: material.valid_from().get().to_string(),
        })
    }
}

impl TryFrom<ApprovedLocalFileBindingMaterialWireV1> for ApprovedLocalFileBindingMaterialV1 {
    type Error = ApprovedBindingVerificationError;

    fn try_from(wire: ApprovedLocalFileBindingMaterialWireV1) -> Result<Self, Self::Error> {
        let binding_id = BindingId::from_bytes(parse_hash_token(&wire.binding_id, "bind_")?);
        let repository_identity = RepositoryIdentityDigest::from_bytes(parse_hash_token(
            &wire.repository_identity,
            "repo_sha256_",
        )?);
        let adapter = AdapterIdentity::try_from(wire.adapter)?;
        let approved_locator =
            ApprovedLocalFileLocatorAuthorityV1::try_from(wire.approved_locator)?;
        let policy_digest =
            PolicyDigest::from_bytes(parse_hash_token(&wire.policy_digest, "policy_sha256_")?);
        let internal_path_policy_digest = InternalPathPolicyDigest::from_bytes(parse_hash_token(
            &wire.internal_path_policy_digest,
            "internal_path_policy_sha256_",
        )?);
        let runtime_profile = LocalFileRuntimeProfileV1::try_from(wire.runtime_profile)?;
        let snapshot_mode = parse_snapshot_mode(&wire.snapshot_mode)?;
        let ordering = parse_ordering(&wire.ordering)?;
        let maximum_caps = LocalFilePlanCapsV1::try_from(wire.maximum_caps)?;
        let valid_from = parse_timestamp(&wire.valid_from_unix_nanos)?;
        let expires_at = parse_timestamp(&wire.expires_at_unix_nanos)?;

        Self::new(
            binding_id,
            wire.binding_version,
            repository_identity,
            adapter,
            approved_locator,
            wire.policy_version,
            policy_digest,
            internal_path_policy_digest,
            runtime_profile,
            snapshot_mode,
            ordering,
            maximum_caps,
            valid_from,
            expires_at,
        )
        .map_err(|_| ApprovedBindingVerificationError::InvalidSemanticMaterial)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterIdentityWireV1 {
    kind: String,
    version: String,
}

impl From<&AdapterIdentity> for AdapterIdentityWireV1 {
    fn from(identity: &AdapterIdentity) -> Self {
        Self {
            kind: identity.kind().to_owned(),
            version: identity.version().to_owned(),
        }
    }
}

impl TryFrom<AdapterIdentityWireV1> for AdapterIdentity {
    type Error = ApprovedBindingVerificationError;

    fn try_from(wire: AdapterIdentityWireV1) -> Result<Self, Self::Error> {
        Self::new(wire.kind, wire.version)
            .map_err(|_| ApprovedBindingVerificationError::UnsupportedAdapter)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedLocalFileLocatorAuthorityWireV1 {
    locator: UnixLocalFileLocatorWireV1,
    root_object_id: UnixFileObjectIdWireV1,
}

impl TryFrom<&ApprovedLocalFileLocatorAuthorityV1> for ApprovedLocalFileLocatorAuthorityWireV1 {
    type Error = ApprovedBindingVerificationError;

    fn try_from(authority: &ApprovedLocalFileLocatorAuthorityV1) -> Result<Self, Self::Error> {
        Ok(Self {
            locator: UnixLocalFileLocatorWireV1::try_from(authority.locator())?,
            root_object_id: UnixFileObjectIdWireV1::from(authority.root_object_id()),
        })
    }
}

impl TryFrom<ApprovedLocalFileLocatorAuthorityWireV1> for ApprovedLocalFileLocatorAuthorityV1 {
    type Error = ApprovedBindingVerificationError;

    fn try_from(wire: ApprovedLocalFileLocatorAuthorityWireV1) -> Result<Self, Self::Error> {
        let locator = UnixLocalFileLocatorV1::try_from(wire.locator)?;
        let root_object_id = UnixFileObjectIdV1::try_from(wire.root_object_id)?;
        Ok(Self::new(locator, root_object_id))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnixLocalFileLocatorWireV1 {
    relative_components: Vec<BinaryValueWireV1>,
    root: BinaryValueWireV1,
}

impl TryFrom<&UnixLocalFileLocatorV1> for UnixLocalFileLocatorWireV1 {
    type Error = ApprovedBindingVerificationError;

    fn try_from(locator: &UnixLocalFileLocatorV1) -> Result<Self, Self::Error> {
        let relative_components = locator
            .relative_components()
            .iter()
            .map(|component| BinaryValueWireV1::from_bytes(component))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            relative_components,
            root: BinaryValueWireV1::from_bytes(locator.root())?,
        })
    }
}

impl TryFrom<UnixLocalFileLocatorWireV1> for UnixLocalFileLocatorV1 {
    type Error = ApprovedBindingVerificationError;

    fn try_from(wire: UnixLocalFileLocatorWireV1) -> Result<Self, Self::Error> {
        if wire.relative_components.len() > MAX_UNIX_LOCAL_FILE_COMPONENTS {
            return Err(ApprovedBindingVerificationError::InvalidLocatorAuthority);
        }
        let root = wire.root.decode()?;
        let components = wire
            .relative_components
            .into_iter()
            .map(BinaryValueWireV1::decode)
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(root, components)
            .map_err(|_| ApprovedBindingVerificationError::InvalidLocatorAuthority)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BinaryValueWireV1 {
    byte_length: u64,
    data: String,
    encoding: String,
}

impl BinaryValueWireV1 {
    fn from_bytes(bytes: &[u8]) -> Result<Self, ApprovedBindingVerificationError> {
        let byte_length = u64::try_from(bytes.len())
            .map_err(|_| ApprovedBindingVerificationError::InvalidBinaryValue)?;
        Ok(Self {
            byte_length,
            data: URL_SAFE_NO_PAD.encode(bytes),
            encoding: BASE64URL_NOPAD_ENCODING.to_owned(),
        })
    }

    fn decode(self) -> Result<Vec<u8>, ApprovedBindingVerificationError> {
        if self.encoding != BASE64URL_NOPAD_ENCODING {
            return Err(ApprovedBindingVerificationError::InvalidBinaryValue);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(self.data.as_bytes())
            .map_err(|_| ApprovedBindingVerificationError::InvalidBinaryValue)?;
        if u64::try_from(decoded.len()).ok() != Some(self.byte_length)
            || URL_SAFE_NO_PAD.encode(&decoded) != self.data
        {
            return Err(ApprovedBindingVerificationError::InvalidBinaryValue);
        }
        Ok(decoded)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnixFileObjectIdWireV1 {
    device: String,
    inode: String,
}

impl From<UnixFileObjectIdV1> for UnixFileObjectIdWireV1 {
    fn from(value: UnixFileObjectIdV1) -> Self {
        Self {
            device: value.device().to_string(),
            inode: value.inode().to_string(),
        }
    }
}

impl TryFrom<UnixFileObjectIdWireV1> for UnixFileObjectIdV1 {
    type Error = ApprovedBindingVerificationError;

    fn try_from(wire: UnixFileObjectIdWireV1) -> Result<Self, Self::Error> {
        Ok(Self::new(
            parse_canonical_u64(&wire.device)?,
            parse_canonical_u64(&wire.inode)?,
        ))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalFileCapsWireV1 {
    per_record_bytes: u64,
    records: u64,
    source_bytes: u64,
    wall_time_millis: u64,
}

impl From<LocalFilePlanCapsV1> for LocalFileCapsWireV1 {
    fn from(caps: LocalFilePlanCapsV1) -> Self {
        Self {
            per_record_bytes: caps.per_record_bytes(),
            records: caps.records(),
            source_bytes: caps.source_bytes(),
            wall_time_millis: caps.wall_time_millis(),
        }
    }
}

impl TryFrom<LocalFileCapsWireV1> for LocalFilePlanCapsV1 {
    type Error = ApprovedBindingVerificationError;

    fn try_from(wire: LocalFileCapsWireV1) -> Result<Self, Self::Error> {
        Self::new(
            wire.source_bytes,
            wire.records,
            wire.per_record_bytes,
            wire.wall_time_millis,
        )
        .map_err(|_| ApprovedBindingVerificationError::InvalidSemanticMaterial)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalFileRuntimeProfileWireV1 {
    architecture: String,
    certification_profile_digest: String,
    deadline_model: String,
    filesystem: String,
    operating_system: String,
}

impl From<LocalFileRuntimeProfileV1> for LocalFileRuntimeProfileWireV1 {
    fn from(profile: LocalFileRuntimeProfileV1) -> Self {
        Self {
            architecture: profile.architecture().code().to_owned(),
            certification_profile_digest: profile.certification_profile_digest().to_string(),
            deadline_model: profile.deadline_model().code().to_owned(),
            filesystem: profile.filesystem().code().to_owned(),
            operating_system: profile.operating_system().code().to_owned(),
        }
    }
}

impl TryFrom<LocalFileRuntimeProfileWireV1> for LocalFileRuntimeProfileV1 {
    type Error = ApprovedBindingVerificationError;

    fn try_from(wire: LocalFileRuntimeProfileWireV1) -> Result<Self, Self::Error> {
        let operating_system = if wire.operating_system == "macos" {
            LocalFileOperatingSystemV1::MacOs
        } else {
            return Err(ApprovedBindingVerificationError::InvalidRuntimeProfile);
        };
        let filesystem = if wire.filesystem == "apfs" {
            LocalFileFilesystemV1::Apfs
        } else {
            return Err(ApprovedBindingVerificationError::InvalidRuntimeProfile);
        };
        let architecture = match wire.architecture.as_str() {
            "aarch64" => LocalFileArchitectureV1::Aarch64,
            "x86_64" => LocalFileArchitectureV1::X86_64,
            _ => return Err(ApprovedBindingVerificationError::InvalidRuntimeProfile),
        };
        let deadline_model = if wire.deadline_model == "cooperative_deadline_between_io_calls_v1" {
            LocalFileDeadlineModelV1::CooperativeBetweenIoCalls
        } else {
            return Err(ApprovedBindingVerificationError::InvalidRuntimeProfile);
        };
        let certification_profile_digest =
            LocalFileCertificationProfileDigest::from_bytes(parse_hash_token(
                &wire.certification_profile_digest,
                CERTIFICATION_PROFILE_DIGEST_PREFIX,
            )?);
        Self::new(
            operating_system,
            filesystem,
            architecture,
            deadline_model,
            certification_profile_digest,
        )
        .map_err(|_| ApprovedBindingVerificationError::InvalidRuntimeProfile)
    }
}

/// Contentless failures while encoding or verifying an approved binding.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ApprovedBindingVerificationError {
    EmptyDocument,
    DocumentTooLarge,
    MalformedDocument,
    UnsupportedContract,
    UnsupportedVersion,
    NonCanonicalDocument,
    UnsupportedAdapter,
    InvalidBinaryValue,
    InvalidHashToken,
    InvalidInteger,
    InvalidTimestamp,
    InvalidLocatorAuthority,
    InvalidRuntimeProfile,
    InvalidSemanticMaterial,
    BindingDigestMismatch,
    CanonicalizationFailed,
}

impl ApprovedBindingVerificationError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyDocument => "EVIDENTRAIL_WIRE_BINDING_EMPTY_DOCUMENT",
            Self::DocumentTooLarge => "EVIDENTRAIL_WIRE_BINDING_DOCUMENT_TOO_LARGE",
            Self::MalformedDocument => "EVIDENTRAIL_WIRE_BINDING_MALFORMED_DOCUMENT",
            Self::UnsupportedContract => "EVIDENTRAIL_WIRE_BINDING_UNSUPPORTED_CONTRACT",
            Self::UnsupportedVersion => "EVIDENTRAIL_WIRE_BINDING_UNSUPPORTED_VERSION",
            Self::NonCanonicalDocument => "EVIDENTRAIL_WIRE_BINDING_NONCANONICAL_DOCUMENT",
            Self::UnsupportedAdapter => "EVIDENTRAIL_WIRE_BINDING_UNSUPPORTED_ADAPTER",
            Self::InvalidBinaryValue => "EVIDENTRAIL_WIRE_BINDING_INVALID_BINARY_VALUE",
            Self::InvalidHashToken => "EVIDENTRAIL_WIRE_BINDING_INVALID_HASH_TOKEN",
            Self::InvalidInteger => "EVIDENTRAIL_WIRE_BINDING_INVALID_INTEGER",
            Self::InvalidTimestamp => "EVIDENTRAIL_WIRE_BINDING_INVALID_TIMESTAMP",
            Self::InvalidLocatorAuthority => "EVIDENTRAIL_WIRE_BINDING_INVALID_LOCATOR_AUTHORITY",
            Self::InvalidRuntimeProfile => "EVIDENTRAIL_WIRE_BINDING_INVALID_RUNTIME_PROFILE",
            Self::InvalidSemanticMaterial => "EVIDENTRAIL_WIRE_BINDING_INVALID_SEMANTIC_MATERIAL",
            Self::BindingDigestMismatch => "EVIDENTRAIL_WIRE_BINDING_DIGEST_MISMATCH",
            Self::CanonicalizationFailed => "EVIDENTRAIL_WIRE_BINDING_CANONICALIZATION_FAILED",
        }
    }
}

impl fmt::Debug for ApprovedBindingVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedBindingVerificationError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for ApprovedBindingVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ApprovedBindingVerificationError {}

/// Contentless failures proving plan authority is a binding narrowing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LocalFilePlanBindingNarrowingError {
    BindingNotYetValid,
    BindingExpired,
    BindingReferenceMismatch,
    RepositoryMismatch,
    AdapterMismatch,
    LocatorAuthorityMismatch,
    PolicyMismatch,
    InternalPathPolicyMismatch,
    RuntimeProfileMismatch,
    AcquisitionSemanticsMismatch,
    CapWidening,
    TimeWidening,
}

impl LocalFilePlanBindingNarrowingError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::BindingNotYetValid => "EVIDENTRAIL_PLAN_BINDING_NOT_YET_VALID",
            Self::BindingExpired => "EVIDENTRAIL_PLAN_BINDING_EXPIRED",
            Self::BindingReferenceMismatch => "EVIDENTRAIL_PLAN_BINDING_REFERENCE_MISMATCH",
            Self::RepositoryMismatch => "EVIDENTRAIL_PLAN_BINDING_REPOSITORY_MISMATCH",
            Self::AdapterMismatch => "EVIDENTRAIL_PLAN_BINDING_ADAPTER_MISMATCH",
            Self::LocatorAuthorityMismatch => "EVIDENTRAIL_PLAN_BINDING_LOCATOR_AUTHORITY_MISMATCH",
            Self::PolicyMismatch => "EVIDENTRAIL_PLAN_BINDING_POLICY_MISMATCH",
            Self::InternalPathPolicyMismatch => "EVIDENTRAIL_PLAN_BINDING_INTERNAL_POLICY_MISMATCH",
            Self::RuntimeProfileMismatch => "EVIDENTRAIL_PLAN_BINDING_RUNTIME_PROFILE_MISMATCH",
            Self::AcquisitionSemanticsMismatch => {
                "EVIDENTRAIL_PLAN_BINDING_ACQUISITION_SEMANTICS_MISMATCH"
            }
            Self::CapWidening => "EVIDENTRAIL_PLAN_BINDING_CAP_WIDENING",
            Self::TimeWidening => "EVIDENTRAIL_PLAN_BINDING_TIME_WIDENING",
        }
    }
}

impl fmt::Debug for LocalFilePlanBindingNarrowingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalFilePlanBindingNarrowingError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for LocalFilePlanBindingNarrowingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for LocalFilePlanBindingNarrowingError {}
