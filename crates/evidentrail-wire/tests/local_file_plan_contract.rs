use evidentrail_schema::{
    AdapterIdentity, BindingDigest, BindingId, BindingRefV1, IdentityProofKindV1,
    InternalPathPolicyDigest, LOCAL_FILE_ADAPTER_KIND_V1, LOCAL_FILE_ADAPTER_VERSION_V1,
    LocalFileArchitectureV1, LocalFileCertificationProfileDigest, LocalFileDeadlineModelV1,
    LocalFileFilesystemV1, LocalFileOperatingSystemV1, LocalFileOrderingV1, LocalFilePlanCapsV1,
    LocalFileQueryPlanMaterialV1, LocalFileRuntimeProfileV1, LocalFileSnapshotModeV1, PlanDigest,
    PlanId, PolicyDigest, RepositoryIdentityDigest, RetrievalId, SourceIdentityDigest,
    SourceIdentityV1, SourceMember, UnixFileObjectIdV1, UnixFileSnapshotV1, UnixFileTypeV1,
    UnixLocalFileLocatorV1, UnixTimestampNanos, bounds::MAX_QUERY_PLAN_BYTES,
};
use evidentrail_wire::{
    PlanVerificationError, derive_local_file_source_identity_digest_v1,
    derive_local_file_source_member_v1, encode_local_file_plan_v1, verify_local_file_plan_v1,
};

const GOLDEN: &str = include_str!("fixtures/local_file_plan_v1/golden.json");

fn without_final_lf(fixture: &str) -> &[u8] {
    fixture.strip_suffix('\n').unwrap_or(fixture).as_bytes()
}

fn sample_material() -> LocalFileQueryPlanMaterialV1 {
    sample_material_with_proof_expiry(Some(UnixTimestampNanos::new(1_700_000_060_000_000_000)))
}

fn sample_material_with_proof_expiry(
    proof_expires_at: Option<UnixTimestampNanos>,
) -> LocalFileQueryPlanMaterialV1 {
    sample_material_with_authority_overrides(proof_expires_at, None, None)
}

fn sample_locator() -> UnixLocalFileLocatorV1 {
    UnixLocalFileLocatorV1::new(b"/var/log".to_vec(), [b"app".to_vec(), vec![0xfb, 0xff]]).unwrap()
}

fn sample_snapshot() -> UnixFileSnapshotV1 {
    UnixFileSnapshotV1::new(
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
    .unwrap()
}

fn sample_runtime_profile(
    architecture: LocalFileArchitectureV1,
    digest_byte: u8,
) -> LocalFileRuntimeProfileV1 {
    LocalFileRuntimeProfileV1::new(
        LocalFileOperatingSystemV1::MacOs,
        LocalFileFilesystemV1::Apfs,
        architecture,
        LocalFileDeadlineModelV1::CooperativeBetweenIoCalls,
        LocalFileCertificationProfileDigest::from_bytes([digest_byte; 32]),
    )
    .unwrap()
}

fn sample_material_with_authority_overrides(
    proof_expires_at: Option<UnixTimestampNanos>,
    source_member_override: Option<[u8; 32]>,
    source_identity_digest_override: Option<SourceIdentityDigest>,
) -> LocalFileQueryPlanMaterialV1 {
    sample_material_for_authority(
        sample_locator(),
        sample_snapshot(),
        sample_runtime_profile(LocalFileArchitectureV1::Aarch64, 0x77),
        proof_expires_at,
        source_member_override,
        source_identity_digest_override,
    )
}

fn sample_material_for_authority(
    locator: UnixLocalFileLocatorV1,
    snapshot: UnixFileSnapshotV1,
    runtime_profile: LocalFileRuntimeProfileV1,
    proof_expires_at: Option<UnixTimestampNanos>,
    source_member_override: Option<[u8; 32]>,
    source_identity_digest_override: Option<SourceIdentityDigest>,
) -> LocalFileQueryPlanMaterialV1 {
    let source_member = source_member_override.map_or_else(
        || derive_local_file_source_member_v1(&locator).unwrap(),
        |bytes| SourceMember::new(bytes).unwrap(),
    );
    let source_identity_digest = source_identity_digest_override.unwrap_or_else(|| {
        derive_local_file_source_identity_digest_v1(&locator, snapshot, runtime_profile).unwrap()
    });
    let binding = BindingRefV1::new(
        BindingId::from_bytes([0x11; 32]),
        3,
        BindingDigest::from_bytes([0x22; 32]),
    )
    .unwrap();
    let identity = SourceIdentityV1::new(
        AdapterIdentity::new(LOCAL_FILE_ADAPTER_KIND_V1, LOCAL_FILE_ADAPTER_VERSION_V1).unwrap(),
        binding,
        source_identity_digest,
        IdentityProofKindV1::LocalFileMetadata,
        UnixTimestampNanos::new(1_700_000_000_000_000_000),
        proof_expires_at,
    )
    .unwrap();
    LocalFileQueryPlanMaterialV1::new(
        RetrievalId::from_bytes([0x55; 32]),
        RepositoryIdentityDigest::from_bytes([0x33; 32]),
        identity,
        locator,
        runtime_profile,
        source_member,
        snapshot,
        LocalFileSnapshotModeV1::WholeFileFixedHighWater,
        LocalFileOrderingV1::SingleFileByteOrder,
        LocalFileOrderingV1::SingleFileByteOrder,
        InternalPathPolicyDigest::from_bytes([0x66; 32]),
        7,
        PolicyDigest::from_bytes([0x44; 32]),
        LocalFilePlanCapsV1::new(65_536, 1_000, 8_192, 30_000).unwrap(),
        UnixTimestampNanos::new(1_700_000_001_000_000_000),
        UnixTimestampNanos::new(1_700_000_030_000_000_000),
        None,
    )
    .unwrap()
}

fn golden_verified() -> evidentrail_wire::VerifiedLocalFilePlanV1 {
    encode_local_file_plan_v1(&sample_material()).unwrap()
}

fn verify_golden_mutation(
    document: &str,
    expected: PlanVerificationError,
    verified: &evidentrail_wire::VerifiedLocalFilePlanV1,
) {
    assert_ne!(
        document.trim_end(),
        GOLDEN.trim_end(),
        "mutation must change the golden body"
    );
    assert_eq!(
        verify_local_file_plan_v1(
            document.trim_end().as_bytes(),
            verified.plan_id(),
            verified.plan_digest(),
        ),
        Err(expected)
    );
}

#[test]
fn local_plan_has_stable_canonical_bytes_and_domain_separated_ids() {
    let material = sample_material();
    let verified = encode_local_file_plan_v1(&material).unwrap();
    assert_eq!(verified.canonical_bytes(), without_final_lf(GOLDEN));
    assert_eq!(
        verified.plan_id().to_string(),
        "plan_78e3f1cc8a50dcc475a2f7326869d264cb8d15e6d298d5c516b6596d09ca0590"
    );
    assert_eq!(
        verified.plan_digest().to_string(),
        "plan_sha256_dadcf23266a01066f209c7a10b822e0be5bb3418cb345a08f20b984f14be8183"
    );
    assert_ne!(
        verified.plan_id().as_bytes(),
        verified.plan_digest().as_bytes()
    );
    assert_eq!(verified.material(), &material);

    let decoded = verify_local_file_plan_v1(
        without_final_lf(GOLDEN),
        verified.plan_id(),
        verified.plan_digest(),
    )
    .unwrap();
    assert_eq!(decoded, verified);
}

#[test]
fn strict_dtos_reject_duplicate_and_unknown_fields_recursively() {
    let verified = golden_verified();
    for fixture in [
        include_str!("fixtures/local_file_plan_v1/adversarial/duplicate_top_level.json"),
        include_str!("fixtures/local_file_plan_v1/adversarial/duplicate_nested.json"),
        include_str!("fixtures/local_file_plan_v1/adversarial/unknown_nested_field.json"),
    ] {
        assert_eq!(
            verify_local_file_plan_v1(
                without_final_lf(fixture),
                verified.plan_id(),
                verified.plan_digest(),
            ),
            Err(PlanVerificationError::MalformedDocument)
        );
    }
}

#[test]
fn optional_values_are_nullable_but_never_omittable() {
    let verified = golden_verified();
    let missing_continuation = without_final_lf(GOLDEN)
        .strip_prefix(br#"{"authorized_continuation":null,"#)
        .unwrap();
    let mut missing_document = b"{".to_vec();
    missing_document.extend_from_slice(missing_continuation);
    assert_eq!(
        verify_local_file_plan_v1(
            &missing_document,
            verified.plan_id(),
            verified.plan_digest(),
        ),
        Err(PlanVerificationError::MalformedDocument)
    );

    let missing_expiry = GOLDEN.replace(r#""expires_at_unix_nanos":"1700000060000000000","#, "");
    assert_eq!(
        verify_local_file_plan_v1(
            missing_expiry.trim_end().as_bytes(),
            verified.plan_id(),
            verified.plan_digest(),
        ),
        Err(PlanVerificationError::MalformedDocument)
    );

    let without_proof_expiry = sample_material_with_proof_expiry(None);
    let nullable = encode_local_file_plan_v1(&without_proof_expiry).unwrap();
    let nullable_body = std::str::from_utf8(nullable.canonical_bytes()).unwrap();
    assert!(nullable_body.starts_with(r#"{"authorized_continuation":null,"#));
    assert!(nullable_body.contains(r#""expires_at_unix_nanos":null"#));
    assert!(nullable.material().authorized_continuation().is_none());
    assert!(
        nullable
            .material()
            .source_identity()
            .proof_expires_at()
            .is_none()
    );

    let nonnull_continuation = GOLDEN.replace(
        r#""authorized_continuation":null"#,
        r#""authorized_continuation":{"byte_length":2,"data":"f4A","encoding":"base64url-nopad"}"#,
    );
    verify_golden_mutation(
        &nonnull_continuation,
        PlanVerificationError::InvalidSemanticMaterial,
        &verified,
    );
}

#[test]
fn binary_wire_values_require_url_safe_unpadded_canonical_base64() {
    let verified = golden_verified();
    let padded = include_str!("fixtures/local_file_plan_v1/adversarial/padded_base64.json");
    assert_eq!(
        verify_local_file_plan_v1(
            without_final_lf(padded),
            verified.plan_id(),
            verified.plan_digest(),
        ),
        Err(PlanVerificationError::InvalidBinaryValue)
    );

    let standard_alphabet = GOLDEN.replace("-_8", "+/8");
    verify_golden_mutation(
        &standard_alphabet,
        PlanVerificationError::InvalidBinaryValue,
        &verified,
    );

    let wrong_length = GOLDEN.replace(
        r#"{"byte_length":2,"data":"-_8""#,
        r#"{"byte_length":3,"data":"-_8""#,
    );
    verify_golden_mutation(
        &wrong_length,
        PlanVerificationError::InvalidBinaryValue,
        &verified,
    );
}

#[test]
fn contract_tokens_integer_spellings_and_pinned_semantics_fail_closed() {
    let verified = golden_verified();
    let one_component = r#"{"byte_length":1,"data":"eA","encoding":"base64url-nopad"}"#;
    let too_many_components = GOLDEN.replace(
        r#""relative_components":[{"byte_length":3,"data":"YXBw","encoding":"base64url-nopad"},{"byte_length":2,"data":"-_8","encoding":"base64url-nopad"}]"#,
        &format!(
            r#""relative_components":[{}]"#,
            vec![one_component; 257].join(",")
        ),
    );
    let cases = [
        (
            GOLDEN.replace(
                r#""contract":"evidentrail.local_file_query_plan""#,
                r#""contract":"evidentrail.other""#,
            ),
            PlanVerificationError::UnsupportedContract,
        ),
        (
            GOLDEN.replace(r#""contract_version":1"#, r#""contract_version":2"#),
            PlanVerificationError::UnsupportedVersion,
        ),
        (
            GOLDEN.replacen("bind_11", "bind_AA", 1),
            PlanVerificationError::InvalidHashToken,
        ),
        (
            GOLDEN.replace(
                r#""created_at_unix_nanos":"1700000001000000000""#,
                r#""created_at_unix_nanos":"01700000001000000000""#,
            ),
            PlanVerificationError::InvalidTimestamp,
        ),
        (
            GOLDEN.replace(
                r#""device":"18446744073709551615""#,
                r#""device":"018446744073709551615""#,
            ),
            PlanVerificationError::InvalidInteger,
        ),
        (
            GOLDEN.replace(
                r#""device":"18446744073709551615""#,
                r#""device":"18446744073709551616""#,
            ),
            PlanVerificationError::InvalidInteger,
        ),
        (
            GOLDEN.replace(
                r#""root":{"byte_length":8,"data":"L3Zhci9sb2c","encoding":"base64url-nopad"}"#,
                r#""root":{"byte_length":7,"data":"dmFyL2xvZw","encoding":"base64url-nopad"}"#,
            ),
            PlanVerificationError::InvalidLocator,
        ),
        (
            GOLDEN.replace(
                r#""relative_components":[{"byte_length":3,"data":"YXBw","encoding":"base64url-nopad"},{"byte_length":2,"data":"-_8","encoding":"base64url-nopad"}]"#,
                r#""relative_components":[]"#,
            ),
            PlanVerificationError::InvalidLocator,
        ),
        (
            GOLDEN.replace(
                r#"{"byte_length":3,"data":"YXBw","encoding":"base64url-nopad"}"#,
                r#"{"byte_length":1,"data":"Lg","encoding":"base64url-nopad"}"#,
            ),
            PlanVerificationError::InvalidLocator,
        ),
        (
            GOLDEN.replace(
                r#"{"byte_length":3,"data":"YXBw","encoding":"base64url-nopad"}"#,
                r#"{"byte_length":3,"data":"YS9i","encoding":"base64url-nopad"}"#,
            ),
            PlanVerificationError::InvalidLocator,
        ),
        (too_many_components, PlanVerificationError::InvalidLocator),
        (
            GOLDEN.replace(r#""kind":"local-file""#, r#""kind":"other""#),
            PlanVerificationError::InvalidSemanticMaterial,
        ),
        (
            GOLDEN.replace(r#""version":"1.0.0""#, r#""version":"1.0.1""#),
            PlanVerificationError::InvalidSemanticMaterial,
        ),
        (
            GOLDEN.replace(
                r#""kind":"local_file_metadata""#,
                r#""kind":"replay_manifest""#,
            ),
            PlanVerificationError::UnsupportedSourceProof,
        ),
        (
            GOLDEN.replace(
                r#""operating_system":"macos""#,
                r#""operating_system":"linux""#,
            ),
            PlanVerificationError::InvalidRuntimeProfile,
        ),
        (
            GOLDEN.replace(r#""filesystem":"apfs""#, r#""filesystem":"ext4""#),
            PlanVerificationError::InvalidRuntimeProfile,
        ),
        (
            GOLDEN.replace(r#""architecture":"aarch64""#, r#""architecture":"riscv64""#),
            PlanVerificationError::InvalidRuntimeProfile,
        ),
        (
            GOLDEN.replace(
                r#""deadline_model":"cooperative_deadline_between_io_calls_v1""#,
                r#""deadline_model":"preemptive_v1""#,
            ),
            PlanVerificationError::InvalidRuntimeProfile,
        ),
        (
            GOLDEN.replace(
                "local_file_certification_profile_sha256_",
                "certification_profile_sha256_",
            ),
            PlanVerificationError::InvalidHashToken,
        ),
        (
            GOLDEN.replace(
                r#""snapshot_mode":"whole_file_fixed_high_water_v1""#,
                r#""snapshot_mode":"tail_v1""#,
            ),
            PlanVerificationError::InvalidSemanticMaterial,
        ),
        (
            GOLDEN.replace(
                r#""requested_ordering":"single_file_byte_order_v1""#,
                r#""requested_ordering":"timestamp_v1""#,
            ),
            PlanVerificationError::InvalidSemanticMaterial,
        ),
        (
            GOLDEN.replace(
                r#""declared_ordering":"single_file_byte_order_v1""#,
                r#""declared_ordering":"timestamp_v1""#,
            ),
            PlanVerificationError::InvalidSemanticMaterial,
        ),
        (
            GOLDEN.replace(r#""file_type":"regular""#, r#""file_type":"symlink""#),
            PlanVerificationError::InvalidSemanticMaterial,
        ),
        (
            GOLDEN.replace(r#""link_count":"2""#, r#""link_count":"0""#),
            PlanVerificationError::InvalidSemanticMaterial,
        ),
        (
            GOLDEN.replace(
                r#""modified_nanoseconds":"123456789""#,
                r#""modified_nanoseconds":"1000000000""#,
            ),
            PlanVerificationError::InvalidSemanticMaterial,
        ),
        (
            GOLDEN.replace(r#""start_offset":"0""#, r#""start_offset":"1""#),
            PlanVerificationError::InvalidSemanticMaterial,
        ),
        (
            GOLDEN.replace(
                r#""high_water_exclusive":"65536""#,
                r#""high_water_exclusive":"65535""#,
            ),
            PlanVerificationError::InvalidSemanticMaterial,
        ),
        (
            GOLDEN.replace(r#""source_bytes":65536"#, r#""source_bytes":65535"#),
            PlanVerificationError::InvalidSemanticMaterial,
        ),
        (
            GOLDEN.replace(r#""wall_time_millis":30000"#, r#""wall_time_millis":0"#),
            PlanVerificationError::InvalidSemanticMaterial,
        ),
        (
            GOLDEN.replace(r#""policy_version":7"#, r#""policy_version":0"#),
            PlanVerificationError::InvalidSemanticMaterial,
        ),
        (
            GOLDEN.replace(
                r#""execute_before_unix_nanos":"1700000030000000000""#,
                r#""execute_before_unix_nanos":"1700000001000000000""#,
            ),
            PlanVerificationError::InvalidSemanticMaterial,
        ),
        (
            GOLDEN.replace(
                r#""expires_at_unix_nanos":"1700000060000000000""#,
                r#""expires_at_unix_nanos":"1700000029999999999""#,
            ),
            PlanVerificationError::InvalidSemanticMaterial,
        ),
    ];

    for (document, expected) in cases {
        verify_golden_mutation(&document, expected, &verified);
    }
}

#[test]
fn every_independently_variable_authority_and_cap_fact_is_plan_digest_committed() {
    let verified = golden_verified();
    let valid_mutations = [
        GOLDEN.replace(
            &format!("ret_{}", "55".repeat(32)),
            &format!("ret_{}", "56".repeat(32)),
        ),
        GOLDEN.replace(
            &format!("repo_sha256_{}", "33".repeat(32)),
            &format!("repo_sha256_{}", "34".repeat(32)),
        ),
        GOLDEN.replace(
            &format!("bind_{}", "11".repeat(32)),
            &format!("bind_{}", "12".repeat(32)),
        ),
        GOLDEN.replace(r#""version":3"#, r#""version":4"#),
        GOLDEN.replace(
            &format!("binding_sha256_{}", "22".repeat(32)),
            &format!("binding_sha256_{}", "23".repeat(32)),
        ),
        GOLDEN.replace("1700000000000000000", "1700000000000000001"),
        GOLDEN.replace("1700000060000000000", "1700000059999999999"),
        GOLDEN.replace(
            &format!("internal_path_policy_sha256_{}", "66".repeat(32)),
            &format!("internal_path_policy_sha256_{}", "67".repeat(32)),
        ),
        GOLDEN.replace(r#""policy_version":7"#, r#""policy_version":8"#),
        GOLDEN.replace(
            &format!("policy_sha256_{}", "44".repeat(32)),
            &format!("policy_sha256_{}", "45".repeat(32)),
        ),
        GOLDEN.replace(r#""source_bytes":65536"#, r#""source_bytes":65537"#),
        GOLDEN.replace(r#""records":1000"#, r#""records":1001"#),
        GOLDEN.replace(r#""per_record_bytes":8192"#, r#""per_record_bytes":8191"#),
        GOLDEN.replace(r#""wall_time_millis":30000"#, r#""wall_time_millis":30001"#),
        GOLDEN.replace("1700000001000000000", "1700000001000000001"),
        GOLDEN.replace("1700000030000000000", "1700000029999999999"),
    ];

    for document in valid_mutations {
        verify_golden_mutation(
            &document,
            PlanVerificationError::PlanDigestMismatch,
            &verified,
        );
    }
}

#[test]
fn every_admitted_runtime_profile_mutation_changes_source_and_plan_identities() {
    let original = golden_verified();
    let locator = sample_locator();
    let snapshot = sample_snapshot();
    let original_profile = sample_runtime_profile(LocalFileArchitectureV1::Aarch64, 0x77);
    let original_source_digest =
        derive_local_file_source_identity_digest_v1(&locator, snapshot, original_profile).unwrap();
    let source_member = derive_local_file_source_member_v1(&locator).unwrap();

    let variants = [
        sample_runtime_profile(LocalFileArchitectureV1::X86_64, 0x77),
        sample_runtime_profile(LocalFileArchitectureV1::Aarch64, 0x78),
    ];
    for variant in variants {
        let changed_source_digest =
            derive_local_file_source_identity_digest_v1(&locator, snapshot, variant).unwrap();
        assert_ne!(changed_source_digest, original_source_digest);

        let changed = encode_local_file_plan_v1(&sample_material_for_authority(
            locator.clone(),
            snapshot,
            variant,
            Some(UnixTimestampNanos::new(1_700_000_060_000_000_000)),
            None,
            None,
        ))
        .unwrap();
        assert_eq!(
            changed.material().source_identity().digest(),
            changed_source_digest
        );
        assert_eq!(
            changed.material().source_member().as_bytes(),
            source_member.as_bytes()
        );
        assert_ne!(changed.plan_id(), original.plan_id());
        assert_ne!(changed.plan_digest(), original.plan_digest());
    }

    let stale_source_identity_documents = [
        GOLDEN.replace(r#""architecture":"aarch64""#, r#""architecture":"x86_64""#),
        GOLDEN.replace(
            &format!(
                "local_file_certification_profile_sha256_{}",
                "77".repeat(32)
            ),
            &format!(
                "local_file_certification_profile_sha256_{}",
                "78".repeat(32)
            ),
        ),
    ];
    for document in stale_source_identity_documents {
        verify_golden_mutation(
            &document,
            PlanVerificationError::SourceIdentityDigestMismatch,
            &original,
        );
    }
}

#[test]
fn locator_member_and_every_snapshot_fact_are_cryptographically_bound() {
    let verified = golden_verified();
    let locator = sample_locator();
    let snapshot = sample_snapshot();
    let runtime_profile = sample_runtime_profile(LocalFileArchitectureV1::Aarch64, 0x77);
    let member = derive_local_file_source_member_v1(&locator).unwrap();
    let source_digest =
        derive_local_file_source_identity_digest_v1(&locator, snapshot, runtime_profile).unwrap();
    assert_eq!(member.as_bytes().len(), 32);
    assert_eq!(
        source_digest.to_string(),
        "source_sha256_ae4e66a4c71c6a3ba35ef6a1dd8f0ca962f9a6e30ea48f8691d73a2bb8280250"
    );
    assert_ne!(member.as_bytes(), source_digest.as_bytes());

    let locator_variants = [
        UnixLocalFileLocatorV1::new(b"/var/log-2".to_vec(), [b"app".to_vec(), vec![0xfb, 0xff]])
            .unwrap(),
        UnixLocalFileLocatorV1::new(b"/var/log".to_vec(), [b"app-2".to_vec(), vec![0xfb, 0xff]])
            .unwrap(),
        UnixLocalFileLocatorV1::new(b"/var/log".to_vec(), [b"app".to_vec(), vec![0xfa, 0xff]])
            .unwrap(),
    ];
    for changed_locator in locator_variants {
        assert_ne!(
            derive_local_file_source_member_v1(&changed_locator).unwrap(),
            member
        );
        assert_ne!(
            derive_local_file_source_identity_digest_v1(
                &changed_locator,
                snapshot,
                runtime_profile,
            )
            .unwrap(),
            source_digest
        );
        let changed_plan = encode_local_file_plan_v1(&sample_material_for_authority(
            changed_locator,
            snapshot,
            runtime_profile,
            Some(UnixTimestampNanos::new(1_700_000_060_000_000_000)),
            None,
            None,
        ))
        .unwrap();
        assert_ne!(changed_plan.plan_id(), verified.plan_id());
        assert_ne!(changed_plan.plan_digest(), verified.plan_digest());
    }

    let snapshot_with = |root,
                         file,
                         mode,
                         link_count,
                         size,
                         modified_seconds,
                         modified_nanoseconds,
                         changed_seconds,
                         changed_nanoseconds| {
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
        .unwrap()
    };
    let snapshot_variants = [
        snapshot_with(
            UnixFileObjectIdV1::new(u64::MAX - 1, 9_007_199_254_740_992),
            snapshot.file(),
            snapshot.mode(),
            snapshot.link_count(),
            snapshot.size(),
            snapshot.modified_seconds(),
            snapshot.modified_nanoseconds(),
            snapshot.changed_seconds(),
            snapshot.changed_nanoseconds(),
        ),
        snapshot_with(
            snapshot.root(),
            UnixFileObjectIdV1::new(16_777_221, 1_234_567_890_123),
            snapshot.mode(),
            snapshot.link_count(),
            snapshot.size(),
            snapshot.modified_seconds(),
            snapshot.modified_nanoseconds(),
            snapshot.changed_seconds(),
            snapshot.changed_nanoseconds(),
        ),
        snapshot_with(
            snapshot.root(),
            snapshot.file(),
            0o100_600,
            snapshot.link_count(),
            snapshot.size(),
            snapshot.modified_seconds(),
            snapshot.modified_nanoseconds(),
            snapshot.changed_seconds(),
            snapshot.changed_nanoseconds(),
        ),
        snapshot_with(
            snapshot.root(),
            snapshot.file(),
            snapshot.mode(),
            3,
            snapshot.size(),
            snapshot.modified_seconds(),
            snapshot.modified_nanoseconds(),
            snapshot.changed_seconds(),
            snapshot.changed_nanoseconds(),
        ),
        snapshot_with(
            snapshot.root(),
            snapshot.file(),
            snapshot.mode(),
            snapshot.link_count(),
            65_535,
            snapshot.modified_seconds(),
            snapshot.modified_nanoseconds(),
            snapshot.changed_seconds(),
            snapshot.changed_nanoseconds(),
        ),
        snapshot_with(
            snapshot.root(),
            snapshot.file(),
            snapshot.mode(),
            snapshot.link_count(),
            snapshot.size(),
            snapshot.modified_seconds() - 1,
            snapshot.modified_nanoseconds(),
            snapshot.changed_seconds(),
            snapshot.changed_nanoseconds(),
        ),
        snapshot_with(
            snapshot.root(),
            snapshot.file(),
            snapshot.mode(),
            snapshot.link_count(),
            snapshot.size(),
            snapshot.modified_seconds(),
            snapshot.modified_nanoseconds() - 1,
            snapshot.changed_seconds(),
            snapshot.changed_nanoseconds(),
        ),
        snapshot_with(
            snapshot.root(),
            snapshot.file(),
            snapshot.mode(),
            snapshot.link_count(),
            snapshot.size(),
            snapshot.modified_seconds(),
            snapshot.modified_nanoseconds(),
            snapshot.changed_seconds() + 1,
            snapshot.changed_nanoseconds(),
        ),
        snapshot_with(
            snapshot.root(),
            snapshot.file(),
            snapshot.mode(),
            snapshot.link_count(),
            snapshot.size(),
            snapshot.modified_seconds(),
            snapshot.modified_nanoseconds(),
            snapshot.changed_seconds(),
            snapshot.changed_nanoseconds() - 1,
        ),
    ];
    for variant in snapshot_variants {
        assert_ne!(
            derive_local_file_source_identity_digest_v1(&locator, variant, runtime_profile)
                .unwrap(),
            source_digest
        );
    }

    assert_eq!(
        encode_local_file_plan_v1(&sample_material_with_authority_overrides(
            Some(UnixTimestampNanos::new(1_700_000_060_000_000_000)),
            Some([0; 32]),
            None,
        )),
        Err(PlanVerificationError::SourceMemberMismatch)
    );
    assert_eq!(
        encode_local_file_plan_v1(&sample_material_with_authority_overrides(
            Some(UnixTimestampNanos::new(1_700_000_060_000_000_000)),
            None,
            Some(SourceIdentityDigest::from_bytes([0; 32])),
        )),
        Err(PlanVerificationError::SourceIdentityDigestMismatch)
    );

    let stale_locator_documents = [
        GOLDEN.replace("L3Zhci9sb2c", "L3Zhci9sb2Q"),
        GOLDEN.replace("YXBw", "YXBx"),
        GOLDEN.replace(
            "hBFVWcuaWAZgWu2XBHvEHLCDc75m6v565KLIkF6nlOk",
            "iBFVWcuaWAZgWu2XBHvEHLCDc75m6v565KLIkF6nlOk",
        ),
    ];
    for document in stale_locator_documents {
        verify_golden_mutation(
            &document,
            PlanVerificationError::SourceMemberMismatch,
            &verified,
        );
    }

    let stale_identity_documents = [
        GOLDEN.replace(
            "source_sha256_ae4e66a4c71c6a3ba35ef6a1dd8f0ca962f9a6e30ea48f8691d73a2bb8280250",
            "source_sha256_be4e66a4c71c6a3ba35ef6a1dd8f0ca962f9a6e30ea48f8691d73a2bb8280250",
        ),
        GOLDEN.replace("18446744073709551615", "18446744073709551614"),
        GOLDEN.replace("9007199254740992", "9007199254740993"),
        GOLDEN.replace("16777220", "16777221"),
        GOLDEN.replace("1234567890123", "1234567890124"),
        GOLDEN.replace(r#""mode":33184"#, r#""mode":33152"#),
        GOLDEN.replace(r#""link_count":"2""#, r#""link_count":"3""#),
        GOLDEN
            .replace(r#""size":"65536""#, r#""size":"65535""#)
            .replace(
                r#""high_water_exclusive":"65536""#,
                r#""high_water_exclusive":"65535""#,
            ),
        GOLDEN.replace(
            r#""modified_seconds":"1700000000""#,
            r#""modified_seconds":"1699999999""#,
        ),
        GOLDEN.replace(
            r#""modified_nanoseconds":"123456789""#,
            r#""modified_nanoseconds":"123456788""#,
        ),
        GOLDEN.replace(
            r#""changed_seconds":"1700000001""#,
            r#""changed_seconds":"1700000002""#,
        ),
        GOLDEN.replace(
            r#""changed_nanoseconds":"987654321""#,
            r#""changed_nanoseconds":"987654320""#,
        ),
    ];
    for document in stale_identity_documents {
        verify_golden_mutation(
            &document,
            PlanVerificationError::SourceIdentityDigestMismatch,
            &verified,
        );
    }
}

#[test]
fn persisted_input_must_already_be_canonical_and_within_the_plan_bound() {
    let verified = golden_verified();
    assert_eq!(
        verify_local_file_plan_v1(
            GOLDEN.as_bytes(),
            verified.plan_id(),
            verified.plan_digest(),
        ),
        Err(PlanVerificationError::NonCanonicalDocument)
    );
    assert_eq!(
        verify_local_file_plan_v1(&[], verified.plan_id(), verified.plan_digest()),
        Err(PlanVerificationError::EmptyDocument)
    );
    assert_eq!(
        verify_local_file_plan_v1(&[0xff], verified.plan_id(), verified.plan_digest()),
        Err(PlanVerificationError::MalformedDocument)
    );
    let oversized = vec![b' '; MAX_QUERY_PLAN_BYTES + 1];
    assert_eq!(
        verify_local_file_plan_v1(&oversized, verified.plan_id(), verified.plan_digest()),
        Err(PlanVerificationError::DocumentTooLarge)
    );
}

#[test]
fn both_declared_plan_identities_are_verified_independently() {
    let verified = golden_verified();
    assert_eq!(
        verify_local_file_plan_v1(
            verified.canonical_bytes(),
            verified.plan_id(),
            PlanDigest::from_bytes([0; 32]),
        ),
        Err(PlanVerificationError::PlanDigestMismatch)
    );
    assert_eq!(
        verify_local_file_plan_v1(
            verified.canonical_bytes(),
            PlanId::from_bytes([0; 32]),
            verified.plan_digest(),
        ),
        Err(PlanVerificationError::PlanIdMismatch)
    );
}

#[test]
fn debug_output_does_not_reveal_ids_hashes_snapshot_facts_or_plan_bytes() {
    let verified = golden_verified();
    let debug = format!("{verified:?}");
    for secret in [
        verified.plan_id().to_string(),
        verified.plan_digest().to_string(),
        verified.material().retrieval_id().to_string(),
        verified.material().repository_identity().to_string(),
        verified
            .material()
            .internal_path_policy_digest()
            .to_string(),
        "/var/log".to_owned(),
        "L3Zhci9sb2c".to_owned(),
        "YXBw".to_owned(),
        "-_8".to_owned(),
        "2p9hUuSP0rwnCLoSr3yFfqBe5CXThCquR2AJA1kvNyk".to_owned(),
        "source_sha256_".to_owned(),
        "local_file_certification_profile_sha256_".to_owned(),
        verified
            .material()
            .runtime_profile()
            .certification_profile_digest()
            .to_string(),
        "18446744073709551615".to_owned(),
        "1700000030000000000".to_owned(),
    ] {
        assert!(!debug.contains(&secret));
    }
    assert!(debug.contains("canonical_bytes_len"));
    assert!(debug.contains("authorized_continuation_present: false"));
}
