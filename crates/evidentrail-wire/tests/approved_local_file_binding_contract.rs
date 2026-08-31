use evidentrail_schema::{
    AdapterIdentity, ApprovedLocalFileBindingMaterialV1, ApprovedLocalFileLocatorAuthorityV1,
    BindingDigest, BindingId, BindingRefV1, IdentityProofKindV1, InternalPathPolicyDigest,
    LOCAL_FILE_ADAPTER_KIND_V1, LOCAL_FILE_ADAPTER_VERSION_V1, LocalFileArchitectureV1,
    LocalFileCertificationProfileDigest, LocalFileDeadlineModelV1, LocalFileFilesystemV1,
    LocalFileOperatingSystemV1, LocalFileOrderingV1, LocalFilePlanCapsV1,
    LocalFileQueryPlanMaterialV1, LocalFileRuntimeProfileV1, LocalFileSnapshotModeV1, PolicyDigest,
    RepositoryIdentityDigest, RetrievalId, SourceIdentityV1, UnixFileObjectIdV1,
    UnixFileSnapshotV1, UnixFileTypeV1, UnixLocalFileLocatorV1, UnixTimestampNanos,
    bounds::MAX_APPROVED_LOCAL_FILE_BINDING_BYTES,
};
use evidentrail_wire::{
    ApprovedBindingVerificationError, ApprovedLocalFileBindingV1,
    LocalFilePlanBindingNarrowingError, derive_approved_local_file_binding_digest_v1,
    derive_local_file_source_identity_digest_v1, derive_local_file_source_member_v1,
    encode_approved_local_file_binding_v1, encode_local_file_plan_v1,
    verify_approved_local_file_binding_v1, verify_local_file_plan_binding_narrowing_v1,
};
use sha2::{Digest, Sha256};

const GOLDEN: &str = include_str!("fixtures/approved_local_file_binding_v1/golden.json");
const DIGEST_MATERIAL: &str =
    include_str!("fixtures/approved_local_file_binding_v1/digest_material.json");
const EXPECTED_BINDING_DIGEST: &str =
    "binding_sha256_10b6736df02f318f05ca946f23342755b096140d1ea659de884177a5ec161ce0";

fn without_final_lf(fixture: &str) -> &[u8] {
    fixture.strip_suffix('\n').unwrap_or(fixture).as_bytes()
}

#[derive(Clone)]
struct BindingFixture {
    binding_id: [u8; 32],
    binding_version: u32,
    repository_identity: [u8; 32],
    adapter_kind: &'static str,
    adapter_version: &'static str,
    root: Vec<u8>,
    relative_components: Vec<Vec<u8>>,
    root_object: UnixFileObjectIdV1,
    policy_version: u32,
    policy_digest: [u8; 32],
    internal_path_policy_digest: [u8; 32],
    architecture: LocalFileArchitectureV1,
    certification_profile_digest: [u8; 32],
    maximum_caps: LocalFilePlanCapsV1,
    valid_from: i128,
    expires_at: i128,
}

impl BindingFixture {
    fn sample() -> Self {
        Self {
            binding_id: [0x11; 32],
            binding_version: 3,
            repository_identity: [0x33; 32],
            adapter_kind: LOCAL_FILE_ADAPTER_KIND_V1,
            adapter_version: LOCAL_FILE_ADAPTER_VERSION_V1,
            root: b"/var/log".to_vec(),
            relative_components: vec![b"app".to_vec(), vec![0xfb, 0xff]],
            root_object: UnixFileObjectIdV1::new(u64::MAX, 9_007_199_254_740_992),
            policy_version: 7,
            policy_digest: [0x44; 32],
            internal_path_policy_digest: [0x66; 32],
            architecture: LocalFileArchitectureV1::Aarch64,
            certification_profile_digest: [0x77; 32],
            maximum_caps: LocalFilePlanCapsV1::new(131_072, 2_000, 16_384, 60_000).unwrap(),
            valid_from: 1_699_999_999_000_000_000,
            expires_at: 1_700_000_060_000_000_000,
        }
    }

    fn runtime_profile(&self) -> LocalFileRuntimeProfileV1 {
        LocalFileRuntimeProfileV1::new(
            LocalFileOperatingSystemV1::MacOs,
            LocalFileFilesystemV1::Apfs,
            self.architecture,
            LocalFileDeadlineModelV1::CooperativeBetweenIoCalls,
            LocalFileCertificationProfileDigest::from_bytes(self.certification_profile_digest),
        )
        .unwrap()
    }

    fn material(&self) -> ApprovedLocalFileBindingMaterialV1 {
        ApprovedLocalFileBindingMaterialV1::new(
            BindingId::from_bytes(self.binding_id),
            self.binding_version,
            RepositoryIdentityDigest::from_bytes(self.repository_identity),
            AdapterIdentity::new(self.adapter_kind, self.adapter_version).unwrap(),
            ApprovedLocalFileLocatorAuthorityV1::new(
                UnixLocalFileLocatorV1::new(self.root.clone(), self.relative_components.clone())
                    .unwrap(),
                self.root_object,
            ),
            self.policy_version,
            PolicyDigest::from_bytes(self.policy_digest),
            InternalPathPolicyDigest::from_bytes(self.internal_path_policy_digest),
            self.runtime_profile(),
            LocalFileSnapshotModeV1::WholeFileFixedHighWater,
            LocalFileOrderingV1::SingleFileByteOrder,
            self.maximum_caps,
            UnixTimestampNanos::new(self.valid_from),
            UnixTimestampNanos::new(self.expires_at),
        )
        .unwrap()
    }
}

fn sample_binding() -> ApprovedLocalFileBindingV1 {
    encode_approved_local_file_binding_v1(&BindingFixture::sample().material()).unwrap()
}

#[derive(Clone)]
struct PlanFixture {
    binding_ref: BindingRefV1,
    repository_identity: [u8; 32],
    root: Vec<u8>,
    relative_components: Vec<Vec<u8>>,
    root_object: UnixFileObjectIdV1,
    policy_version: u32,
    policy_digest: [u8; 32],
    internal_path_policy_digest: [u8; 32],
    architecture: LocalFileArchitectureV1,
    certification_profile_digest: [u8; 32],
    caps: LocalFilePlanCapsV1,
    created_at: i128,
    execute_before: i128,
}

impl PlanFixture {
    fn for_binding(binding: &ApprovedLocalFileBindingV1) -> Self {
        let authority = binding.material();
        Self {
            binding_ref: *binding.binding_ref(),
            repository_identity: *authority.repository_identity().as_bytes(),
            root: authority.approved_locator().locator().root().to_vec(),
            relative_components: authority
                .approved_locator()
                .locator()
                .relative_components()
                .to_vec(),
            root_object: authority.approved_locator().root_object_id(),
            policy_version: authority.policy_version().get(),
            policy_digest: *authority.policy_digest().as_bytes(),
            internal_path_policy_digest: *authority.internal_path_policy_digest().as_bytes(),
            architecture: authority.runtime_profile().architecture(),
            certification_profile_digest: *authority
                .runtime_profile()
                .certification_profile_digest()
                .as_bytes(),
            caps: LocalFilePlanCapsV1::new(65_536, 1_000, 8_192, 30_000).unwrap(),
            created_at: 1_700_000_001_000_000_000,
            execute_before: 1_700_000_030_000_000_000,
        }
    }

    fn runtime_profile(&self) -> LocalFileRuntimeProfileV1 {
        LocalFileRuntimeProfileV1::new(
            LocalFileOperatingSystemV1::MacOs,
            LocalFileFilesystemV1::Apfs,
            self.architecture,
            LocalFileDeadlineModelV1::CooperativeBetweenIoCalls,
            LocalFileCertificationProfileDigest::from_bytes(self.certification_profile_digest),
        )
        .unwrap()
    }

    fn verified(&self) -> evidentrail_wire::VerifiedLocalFilePlanV1 {
        let locator =
            UnixLocalFileLocatorV1::new(self.root.clone(), self.relative_components.clone())
                .unwrap();
        let snapshot = UnixFileSnapshotV1::new(
            self.root_object,
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
        let runtime_profile = self.runtime_profile();
        let source_digest =
            derive_local_file_source_identity_digest_v1(&locator, snapshot, runtime_profile)
                .unwrap();
        let source_identity = SourceIdentityV1::new(
            AdapterIdentity::new(LOCAL_FILE_ADAPTER_KIND_V1, LOCAL_FILE_ADAPTER_VERSION_V1)
                .unwrap(),
            self.binding_ref,
            source_digest,
            IdentityProofKindV1::LocalFileMetadata,
            UnixTimestampNanos::new(self.created_at - 1),
            Some(UnixTimestampNanos::new(1_700_000_120_000_000_000)),
        )
        .unwrap();
        let source_member = derive_local_file_source_member_v1(&locator).unwrap();
        let material = LocalFileQueryPlanMaterialV1::new(
            RetrievalId::from_bytes([0x55; 32]),
            RepositoryIdentityDigest::from_bytes(self.repository_identity),
            source_identity,
            locator,
            runtime_profile,
            source_member,
            snapshot,
            LocalFileSnapshotModeV1::WholeFileFixedHighWater,
            LocalFileOrderingV1::SingleFileByteOrder,
            LocalFileOrderingV1::SingleFileByteOrder,
            InternalPathPolicyDigest::from_bytes(self.internal_path_policy_digest),
            self.policy_version,
            PolicyDigest::from_bytes(self.policy_digest),
            self.caps,
            UnixTimestampNanos::new(self.created_at),
            UnixTimestampNanos::new(self.execute_before),
            None,
        )
        .unwrap();
        encode_local_file_plan_v1(&material).unwrap()
    }
}

fn verify_mutation(document: &str, expected: ApprovedBindingVerificationError) {
    assert_ne!(document.trim_end(), GOLDEN.trim_end());
    assert_eq!(
        verify_approved_local_file_binding_v1(document.trim_end().as_bytes()),
        Err(expected)
    );
}

#[test]
fn binding_has_stable_canonical_bytes_and_independently_derived_digest() {
    let material = BindingFixture::sample().material();
    let binding = encode_approved_local_file_binding_v1(&material).unwrap();
    assert_eq!(binding.canonical_bytes(), without_final_lf(GOLDEN));
    assert_eq!(binding.material(), &material);
    assert_eq!(binding.binding_ref().id(), material.binding_id());
    assert_eq!(binding.binding_ref().version(), material.binding_version());
    assert_eq!(
        binding.binding_ref().digest().to_string(),
        EXPECTED_BINDING_DIGEST
    );
    assert_eq!(
        derive_approved_local_file_binding_digest_v1(&material)
            .unwrap()
            .to_string(),
        EXPECTED_BINDING_DIGEST
    );
    assert_eq!(DIGEST_MATERIAL.trim_end().len(), 1_490);
    let domain = b"evidentrail/approved-local-file-binding-digest/v1";
    let digest_body = DIGEST_MATERIAL.trim_end().as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(u64::try_from(domain.len()).unwrap().to_le_bytes());
    hasher.update(domain);
    hasher.update(u64::try_from(digest_body.len()).unwrap().to_le_bytes());
    hasher.update(digest_body);
    let independently_derived: [u8; 32] = hasher.finalize().into();
    assert_eq!(
        &independently_derived,
        binding.binding_ref().digest().as_bytes()
    );

    let decoded = verify_approved_local_file_binding_v1(without_final_lf(GOLDEN)).unwrap();
    assert_eq!(decoded, binding);
}

#[test]
fn strict_binding_dto_rejects_duplicates_unknown_fields_and_bad_binary() {
    for fixture in [
        include_str!(
            "fixtures/approved_local_file_binding_v1/adversarial/duplicate_top_level.json"
        ),
        include_str!("fixtures/approved_local_file_binding_v1/adversarial/duplicate_nested.json"),
        include_str!(
            "fixtures/approved_local_file_binding_v1/adversarial/unknown_nested_field.json"
        ),
    ] {
        assert_eq!(
            verify_approved_local_file_binding_v1(without_final_lf(fixture)),
            Err(ApprovedBindingVerificationError::MalformedDocument)
        );
    }

    let padded =
        include_str!("fixtures/approved_local_file_binding_v1/adversarial/padded_base64.json");
    assert_eq!(
        verify_approved_local_file_binding_v1(without_final_lf(padded)),
        Err(ApprovedBindingVerificationError::InvalidBinaryValue)
    );

    verify_mutation(
        &GOLDEN.replace("-_8", "+/8"),
        ApprovedBindingVerificationError::InvalidBinaryValue,
    );
    verify_mutation(
        &GOLDEN.replace(
            r#""relative_components":[{"byte_length":3,"data":"YXBw","encoding":"base64url-nopad"},{"byte_length":2,"data":"-_8","encoding":"base64url-nopad"}]"#,
            r#""relative_components":[]"#,
        ),
        ApprovedBindingVerificationError::InvalidLocatorAuthority,
    );
}

#[test]
fn binding_wire_fails_closed_on_noncanonical_invalid_and_tampered_documents() {
    let cases = [
        (
            GOLDEN.replace(
                r#""contract":"evidentrail.approved_local_file_binding""#,
                r#""contract":"evidentrail.other""#,
            ),
            ApprovedBindingVerificationError::UnsupportedContract,
        ),
        (
            GOLDEN.replace(r#""contract_version":1"#, r#""contract_version":2"#),
            ApprovedBindingVerificationError::UnsupportedVersion,
        ),
        (
            GOLDEN.replacen("binding_sha256_10", "binding_sha256_11", 1),
            ApprovedBindingVerificationError::BindingDigestMismatch,
        ),
        (
            GOLDEN.replace("bind_11", "bind_AA"),
            ApprovedBindingVerificationError::InvalidHashToken,
        ),
        (
            GOLDEN.replace(
                r#""device":"18446744073709551615""#,
                r#""device":"018446744073709551615""#,
            ),
            ApprovedBindingVerificationError::InvalidInteger,
        ),
        (
            GOLDEN.replace(
                r#""valid_from_unix_nanos":"1699999999000000000""#,
                r#""valid_from_unix_nanos":"01699999999000000000""#,
            ),
            ApprovedBindingVerificationError::InvalidTimestamp,
        ),
        (
            GOLDEN.replace(
                r#""root":{"byte_length":8,"data":"L3Zhci9sb2c","encoding":"base64url-nopad"}"#,
                r#""root":{"byte_length":7,"data":"dmFyL2xvZw","encoding":"base64url-nopad"}"#,
            ),
            ApprovedBindingVerificationError::InvalidLocatorAuthority,
        ),
        (
            GOLDEN.replace(r#""kind":"local-file""#, r#""kind":"other""#),
            ApprovedBindingVerificationError::InvalidSemanticMaterial,
        ),
        (
            GOLDEN.replace(r#""version":"1.0.0""#, r#""version":"1.0.1""#),
            ApprovedBindingVerificationError::InvalidSemanticMaterial,
        ),
        (
            GOLDEN.replace(r#""architecture":"aarch64""#, r#""architecture":"riscv64""#),
            ApprovedBindingVerificationError::InvalidRuntimeProfile,
        ),
        (
            GOLDEN.replace(
                r#""operating_system":"macos""#,
                r#""operating_system":"linux""#,
            ),
            ApprovedBindingVerificationError::InvalidRuntimeProfile,
        ),
        (
            GOLDEN.replace(r#""filesystem":"apfs""#, r#""filesystem":"ext4""#),
            ApprovedBindingVerificationError::InvalidRuntimeProfile,
        ),
        (
            GOLDEN.replace(
                r#""deadline_model":"cooperative_deadline_between_io_calls_v1""#,
                r#""deadline_model":"preemptive_v1""#,
            ),
            ApprovedBindingVerificationError::InvalidRuntimeProfile,
        ),
        (
            GOLDEN.replace(
                r#""snapshot_mode":"whole_file_fixed_high_water_v1""#,
                r#""snapshot_mode":"tail_v1""#,
            ),
            ApprovedBindingVerificationError::InvalidSemanticMaterial,
        ),
        (
            GOLDEN.replace(
                r#""ordering":"single_file_byte_order_v1""#,
                r#""ordering":"timestamp_v1""#,
            ),
            ApprovedBindingVerificationError::InvalidSemanticMaterial,
        ),
        (
            GOLDEN.replace(r#""source_bytes":131072"#, r#""source_bytes":0"#),
            ApprovedBindingVerificationError::InvalidSemanticMaterial,
        ),
        (
            GOLDEN.replace(r#""binding_version":3"#, r#""binding_version":0"#),
            ApprovedBindingVerificationError::InvalidSemanticMaterial,
        ),
        (
            GOLDEN.replace(r#""policy_version":7"#, r#""policy_version":0"#),
            ApprovedBindingVerificationError::InvalidSemanticMaterial,
        ),
        (
            GOLDEN.replace(
                r#""expires_at_unix_nanos":"1700000060000000000""#,
                r#""expires_at_unix_nanos":"1699999999000000000""#,
            ),
            ApprovedBindingVerificationError::InvalidSemanticMaterial,
        ),
    ];
    for (document, expected) in cases {
        verify_mutation(&document, expected);
    }

    let missing_required_digest = GOLDEN.replacen(
        &format!(r#""binding_digest":"{EXPECTED_BINDING_DIGEST}","#),
        "",
        1,
    );
    verify_mutation(
        &missing_required_digest,
        ApprovedBindingVerificationError::MalformedDocument,
    );

    let binding = sample_binding();
    assert_eq!(
        verify_approved_local_file_binding_v1(GOLDEN.as_bytes()),
        Err(ApprovedBindingVerificationError::NonCanonicalDocument)
    );
    assert_eq!(
        verify_approved_local_file_binding_v1(&[]),
        Err(ApprovedBindingVerificationError::EmptyDocument)
    );
    assert_eq!(
        verify_approved_local_file_binding_v1(&[0xff]),
        Err(ApprovedBindingVerificationError::MalformedDocument)
    );
    assert_eq!(
        verify_approved_local_file_binding_v1(&vec![
            b' ';
            MAX_APPROVED_LOCAL_FILE_BINDING_BYTES + 1
        ]),
        Err(ApprovedBindingVerificationError::DocumentTooLarge)
    );
    assert_eq!(
        binding.binding_ref().digest().to_string(),
        EXPECTED_BINDING_DIGEST
    );
}

#[test]
fn every_independently_mutable_binding_authority_field_changes_the_digest() {
    let base = BindingFixture::sample();
    let original = derive_approved_local_file_binding_digest_v1(&base.material()).unwrap();
    let mut variants = Vec::new();

    let mut value = base.clone();
    value.binding_id = [0x12; 32];
    variants.push(value);
    let mut value = base.clone();
    value.binding_version = 4;
    variants.push(value);
    let mut value = base.clone();
    value.repository_identity = [0x34; 32];
    variants.push(value);
    let mut value = base.clone();
    value.root = b"/var/log-2".to_vec();
    variants.push(value);
    let mut value = base.clone();
    value.relative_components = vec![b"app".to_vec(), b"other.log".to_vec()];
    variants.push(value);
    let mut value = base.clone();
    value.root_object = UnixFileObjectIdV1::new(u64::MAX - 1, 9_007_199_254_740_992);
    variants.push(value);
    let mut value = base.clone();
    value.root_object = UnixFileObjectIdV1::new(u64::MAX, 9_007_199_254_740_993);
    variants.push(value);
    let mut value = base.clone();
    value.policy_version = 8;
    variants.push(value);
    let mut value = base.clone();
    value.policy_digest = [0x45; 32];
    variants.push(value);
    let mut value = base.clone();
    value.internal_path_policy_digest = [0x67; 32];
    variants.push(value);
    let mut value = base.clone();
    value.architecture = LocalFileArchitectureV1::X86_64;
    variants.push(value);
    let mut value = base.clone();
    value.certification_profile_digest = [0x78; 32];
    variants.push(value);
    let mut value = base.clone();
    value.maximum_caps = LocalFilePlanCapsV1::new(131_073, 2_000, 16_384, 60_000).unwrap();
    variants.push(value);
    let mut value = base.clone();
    value.maximum_caps = LocalFilePlanCapsV1::new(131_072, 2_001, 16_384, 60_000).unwrap();
    variants.push(value);
    let mut value = base.clone();
    value.maximum_caps = LocalFilePlanCapsV1::new(131_072, 2_000, 16_385, 60_000).unwrap();
    variants.push(value);
    let mut value = base.clone();
    value.maximum_caps = LocalFilePlanCapsV1::new(131_072, 2_000, 16_384, 60_001).unwrap();
    variants.push(value);
    let mut value = base.clone();
    value.valid_from -= 1;
    variants.push(value);
    let mut value = base;
    value.expires_at += 1;
    variants.push(value);

    for variant in variants {
        assert_ne!(
            derive_approved_local_file_binding_digest_v1(&variant.material()).unwrap(),
            original
        );
    }
}

#[test]
fn plan_narrowing_accepts_the_exact_literal_member_smaller_caps_and_interval_boundaries() {
    let binding = sample_binding();
    let mut plan_fixture = PlanFixture::for_binding(&binding);
    plan_fixture.caps = binding.material().maximum_caps();
    plan_fixture.created_at = binding.material().valid_from().get();
    plan_fixture.execute_before = binding.material().expires_at().get();
    let plan = plan_fixture.verified();

    let proof = verify_local_file_plan_binding_narrowing_v1(
        &plan,
        &binding,
        UnixTimestampNanos::new(1_700_000_000_000_000_000),
    )
    .unwrap();
    assert_eq!(proof.plan_id(), plan.plan_id());
    assert_eq!(proof.binding_ref(), binding.binding_ref());
    assert_eq!(proof.checked_at().get(), 1_700_000_000_000_000_000);
}

#[test]
fn plan_narrowing_rejects_every_authority_change_or_widening() {
    let binding = sample_binding();
    let base = PlanFixture::for_binding(&binding);
    let checked_at = UnixTimestampNanos::new(1_700_000_000_000_000_000);
    let mut cases = Vec::new();

    let mut fixture = base.clone();
    fixture.binding_ref = BindingRefV1::new(
        BindingId::from_bytes([0x12; 32]),
        binding.binding_ref().version().get(),
        binding.binding_ref().digest(),
    )
    .unwrap();
    cases.push((
        fixture,
        LocalFilePlanBindingNarrowingError::BindingReferenceMismatch,
    ));

    let mut fixture = base.clone();
    fixture.binding_ref = BindingRefV1::new(
        binding.binding_ref().id(),
        binding.binding_ref().version().get() + 1,
        binding.binding_ref().digest(),
    )
    .unwrap();
    cases.push((
        fixture,
        LocalFilePlanBindingNarrowingError::BindingReferenceMismatch,
    ));

    let mut fixture = base.clone();
    fixture.binding_ref = BindingRefV1::new(
        binding.binding_ref().id(),
        binding.binding_ref().version().get(),
        BindingDigest::from_bytes([0; 32]),
    )
    .unwrap();
    cases.push((
        fixture,
        LocalFilePlanBindingNarrowingError::BindingReferenceMismatch,
    ));

    let mut fixture = base.clone();
    fixture.repository_identity = [0x34; 32];
    cases.push((
        fixture,
        LocalFilePlanBindingNarrowingError::RepositoryMismatch,
    ));

    let mut fixture = base.clone();
    fixture.root = b"/var/log-2".to_vec();
    cases.push((
        fixture,
        LocalFilePlanBindingNarrowingError::LocatorAuthorityMismatch,
    ));

    let mut fixture = base.clone();
    fixture.relative_components = vec![b"app".to_vec(), b"other.log".to_vec()];
    cases.push((
        fixture,
        LocalFilePlanBindingNarrowingError::LocatorAuthorityMismatch,
    ));

    let mut fixture = base.clone();
    fixture.root_object = UnixFileObjectIdV1::new(u64::MAX - 1, 9_007_199_254_740_992);
    cases.push((
        fixture,
        LocalFilePlanBindingNarrowingError::LocatorAuthorityMismatch,
    ));

    let mut fixture = base.clone();
    fixture.policy_version = 8;
    cases.push((fixture, LocalFilePlanBindingNarrowingError::PolicyMismatch));

    let mut fixture = base.clone();
    fixture.policy_digest = [0x45; 32];
    cases.push((fixture, LocalFilePlanBindingNarrowingError::PolicyMismatch));

    let mut fixture = base.clone();
    fixture.internal_path_policy_digest = [0x67; 32];
    cases.push((
        fixture,
        LocalFilePlanBindingNarrowingError::InternalPathPolicyMismatch,
    ));

    let mut fixture = base.clone();
    fixture.architecture = LocalFileArchitectureV1::X86_64;
    cases.push((
        fixture,
        LocalFilePlanBindingNarrowingError::RuntimeProfileMismatch,
    ));

    let mut fixture = base.clone();
    fixture.certification_profile_digest = [0x78; 32];
    cases.push((
        fixture,
        LocalFilePlanBindingNarrowingError::RuntimeProfileMismatch,
    ));

    for caps in [
        LocalFilePlanCapsV1::new(131_073, 2_000, 16_384, 60_000).unwrap(),
        LocalFilePlanCapsV1::new(131_072, 2_001, 16_384, 60_000).unwrap(),
        LocalFilePlanCapsV1::new(131_072, 2_000, 16_385, 60_000).unwrap(),
        LocalFilePlanCapsV1::new(131_072, 2_000, 16_384, 60_001).unwrap(),
    ] {
        let mut fixture = base.clone();
        fixture.caps = caps;
        cases.push((fixture, LocalFilePlanBindingNarrowingError::CapWidening));
    }

    let mut fixture = base.clone();
    fixture.created_at = binding.material().valid_from().get() - 1;
    fixture.execute_before = binding.material().valid_from().get() + 1;
    cases.push((fixture, LocalFilePlanBindingNarrowingError::TimeWidening));

    let mut fixture = base;
    fixture.execute_before = binding.material().expires_at().get() + 1;
    cases.push((fixture, LocalFilePlanBindingNarrowingError::TimeWidening));

    for (fixture, expected) in cases {
        let plan = fixture.verified();
        assert_eq!(
            verify_local_file_plan_binding_narrowing_v1(&plan, &binding, checked_at),
            Err(expected)
        );
    }

    let plan = PlanFixture::for_binding(&binding).verified();
    assert_eq!(
        verify_local_file_plan_binding_narrowing_v1(
            &plan,
            &binding,
            UnixTimestampNanos::new(binding.material().valid_from().get() - 1),
        ),
        Err(LocalFilePlanBindingNarrowingError::BindingNotYetValid)
    );
    assert_eq!(
        verify_local_file_plan_binding_narrowing_v1(
            &plan,
            &binding,
            binding.material().expires_at(),
        ),
        Err(LocalFilePlanBindingNarrowingError::BindingExpired)
    );
}

#[test]
fn binding_and_narrowing_diagnostics_are_contentless_and_non_executable() {
    let binding = sample_binding();
    let plan = PlanFixture::for_binding(&binding).verified();
    let proof = verify_local_file_plan_binding_narrowing_v1(
        &plan,
        &binding,
        UnixTimestampNanos::new(1_700_000_000_000_000_000),
    )
    .unwrap();

    for debug in [format!("{binding:?}"), format!("{proof:?}")] {
        for secret in [
            "/var/log",
            "L3Zhci9sb2c",
            "11111111",
            "33333333",
            "44444444",
            "66666666",
            "77777777",
            "b6ec2c85",
            "1700000000000000000",
        ] {
            assert!(!debug.contains(secret));
        }
    }

    let binding_errors = [
        ApprovedBindingVerificationError::EmptyDocument,
        ApprovedBindingVerificationError::DocumentTooLarge,
        ApprovedBindingVerificationError::MalformedDocument,
        ApprovedBindingVerificationError::UnsupportedContract,
        ApprovedBindingVerificationError::UnsupportedVersion,
        ApprovedBindingVerificationError::NonCanonicalDocument,
        ApprovedBindingVerificationError::UnsupportedAdapter,
        ApprovedBindingVerificationError::InvalidBinaryValue,
        ApprovedBindingVerificationError::InvalidHashToken,
        ApprovedBindingVerificationError::InvalidInteger,
        ApprovedBindingVerificationError::InvalidTimestamp,
        ApprovedBindingVerificationError::InvalidLocatorAuthority,
        ApprovedBindingVerificationError::InvalidRuntimeProfile,
        ApprovedBindingVerificationError::InvalidSemanticMaterial,
        ApprovedBindingVerificationError::BindingDigestMismatch,
        ApprovedBindingVerificationError::CanonicalizationFailed,
    ];
    for error in binding_errors {
        assert_eq!(error.to_string(), error.code());
        assert!(format!("{error:?}").contains(error.code()));
        assert!(!format!("{error:?}").contains("/var/log"));
    }

    let narrowing_errors = [
        LocalFilePlanBindingNarrowingError::BindingNotYetValid,
        LocalFilePlanBindingNarrowingError::BindingExpired,
        LocalFilePlanBindingNarrowingError::BindingReferenceMismatch,
        LocalFilePlanBindingNarrowingError::RepositoryMismatch,
        LocalFilePlanBindingNarrowingError::AdapterMismatch,
        LocalFilePlanBindingNarrowingError::LocatorAuthorityMismatch,
        LocalFilePlanBindingNarrowingError::PolicyMismatch,
        LocalFilePlanBindingNarrowingError::InternalPathPolicyMismatch,
        LocalFilePlanBindingNarrowingError::RuntimeProfileMismatch,
        LocalFilePlanBindingNarrowingError::AcquisitionSemanticsMismatch,
        LocalFilePlanBindingNarrowingError::CapWidening,
        LocalFilePlanBindingNarrowingError::TimeWidening,
    ];
    for error in narrowing_errors {
        assert_eq!(error.to_string(), error.code());
        assert!(format!("{error:?}").contains(error.code()));
        assert!(!format!("{error:?}").contains("/var/log"));
    }
}
