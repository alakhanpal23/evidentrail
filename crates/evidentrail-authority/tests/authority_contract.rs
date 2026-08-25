use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use evidentrail_authority::{
    BindingRegistryError, CanonicalUnixPathV1, InternalPathPolicyV1, InternalPathRegistryError,
    InternalPathRegistryV1, LiveApprovedBindingRegistryV1, RegistryAuthorizationError,
    authorize_local_file_plan_with_registries_v1,
};
use evidentrail_schema::{
    AdapterIdentity, ApprovedLocalFileBindingMaterialV1, ApprovedLocalFileLocatorAuthorityV1,
    BindingId, BindingRefV1, IdentityProofKindV1, InternalPathPolicyDigest,
    LOCAL_FILE_ADAPTER_KIND_V1, LOCAL_FILE_ADAPTER_VERSION_V1, LocalFileArchitectureV1,
    LocalFileCertificationProfileDigest, LocalFileDeadlineModelV1, LocalFileFilesystemV1,
    LocalFileOperatingSystemV1, LocalFileOrderingV1, LocalFilePlanCapsV1,
    LocalFileQueryPlanMaterialV1, LocalFileRuntimeProfileV1, LocalFileSnapshotModeV1, PolicyDigest,
    RepositoryIdentityDigest, RetrievalId, SourceIdentityV1, UnixFileObjectIdV1,
    UnixFileSnapshotV1, UnixFileTypeV1, UnixLocalFileLocatorV1, UnixTimestampNanos,
};
use evidentrail_wire::{
    ApprovedLocalFileBindingV1, VerifiedLocalFilePlanV1,
    derive_local_file_source_identity_digest_v1, derive_local_file_source_member_v1,
    encode_approved_local_file_binding_v1, encode_local_file_plan_v1,
};

const VALID_FROM: i128 = 1_700_000_000_000_000_000;
const EXPIRES_AT: i128 = 1_700_000_060_000_000_000;
const CHECKED_AT: i128 = 1_700_000_010_000_000_000;

fn canonical(path: &[u8]) -> CanonicalUnixPathV1 {
    CanonicalUnixPathV1::new(path.to_vec()).unwrap()
}

fn locator(root: &[u8], components: &[&[u8]]) -> UnixLocalFileLocatorV1 {
    UnixLocalFileLocatorV1::new(
        root.to_vec(),
        components
            .iter()
            .map(|component| component.to_vec())
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

fn runtime_profile() -> LocalFileRuntimeProfileV1 {
    LocalFileRuntimeProfileV1::new(
        LocalFileOperatingSystemV1::MacOs,
        LocalFileFilesystemV1::Apfs,
        LocalFileArchitectureV1::Aarch64,
        LocalFileDeadlineModelV1::CooperativeBetweenIoCalls,
        LocalFileCertificationProfileDigest::from_bytes([0x77; 32]),
    )
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn approved_binding(
    binding_byte: u8,
    version: u32,
    repository_byte: u8,
    internal_policy_digest: InternalPathPolicyDigest,
    valid_from: i128,
    expires_at: i128,
    maximum_caps: LocalFilePlanCapsV1,
) -> ApprovedLocalFileBindingV1 {
    let material = ApprovedLocalFileBindingMaterialV1::new(
        BindingId::from_bytes([binding_byte; 32]),
        version,
        RepositoryIdentityDigest::from_bytes([repository_byte; 32]),
        AdapterIdentity::new(LOCAL_FILE_ADAPTER_KIND_V1, LOCAL_FILE_ADAPTER_VERSION_V1).unwrap(),
        ApprovedLocalFileLocatorAuthorityV1::new(
            locator(b"/var/log", &[b"app", b"service.log"]),
            UnixFileObjectIdV1::new(10, 20),
        ),
        7,
        PolicyDigest::from_bytes([0x44; 32]),
        internal_policy_digest,
        runtime_profile(),
        LocalFileSnapshotModeV1::WholeFileFixedHighWater,
        LocalFileOrderingV1::SingleFileByteOrder,
        maximum_caps,
        UnixTimestampNanos::new(valid_from),
        UnixTimestampNanos::new(expires_at),
    )
    .unwrap();
    encode_approved_local_file_binding_v1(&material).unwrap()
}

fn standard_caps() -> LocalFilePlanCapsV1 {
    LocalFilePlanCapsV1::new(131_072, 2_000, 16_384, 60_000).unwrap()
}

fn plan_for(binding: &ApprovedLocalFileBindingV1) -> VerifiedLocalFilePlanV1 {
    let authority = binding.material();
    let locator = authority.approved_locator().locator().clone();
    let profile = authority.runtime_profile();
    let snapshot = UnixFileSnapshotV1::new(
        authority.approved_locator().root_object_id(),
        UnixFileObjectIdV1::new(30, 40),
        UnixFileTypeV1::Regular,
        0o100_640,
        1,
        65_536,
        1_700_000_001,
        123_456_789,
        1_700_000_002,
        987_654_321,
        0,
        65_536,
    )
    .unwrap();
    let source_identity = SourceIdentityV1::new(
        authority.adapter().clone(),
        *binding.binding_ref(),
        derive_local_file_source_identity_digest_v1(&locator, snapshot, profile).unwrap(),
        IdentityProofKindV1::LocalFileMetadata,
        authority.valid_from(),
        Some(authority.expires_at()),
    )
    .unwrap();
    let material = LocalFileQueryPlanMaterialV1::new(
        RetrievalId::from_bytes([0x55; 32]),
        authority.repository_identity(),
        source_identity,
        locator.clone(),
        profile,
        derive_local_file_source_member_v1(&locator).unwrap(),
        snapshot,
        authority.snapshot_mode(),
        authority.ordering(),
        authority.ordering(),
        authority.internal_path_policy_digest(),
        authority.policy_version().get(),
        authority.policy_digest(),
        LocalFilePlanCapsV1::new(65_536, 1_000, 8_192, 30_000).unwrap(),
        UnixTimestampNanos::new(VALID_FROM + 1),
        UnixTimestampNanos::new(EXPIRES_AT - 1),
        None,
    )
    .unwrap();
    encode_local_file_plan_v1(&material).unwrap()
}

fn public_policy() -> InternalPathPolicyV1 {
    InternalPathPolicyV1::new(
        [canonical(b"/Library/Application Support/Evidentrail")],
        [canonical(b"/private/var/evidentrail-alias")],
    )
    .unwrap()
}

#[test]
fn binding_registry_rejects_rollback_equal_version_changes_and_cross_repository_reuse() {
    let digest = public_policy().digest();
    let registry = LiveApprovedBindingRegistryV1::new();
    let version_one = approved_binding(
        0x11,
        1,
        0x33,
        digest,
        VALID_FROM,
        EXPIRES_AT,
        standard_caps(),
    );
    registry.install(version_one.clone()).unwrap();

    let cross_repository = approved_binding(
        0x11,
        2,
        0x34,
        digest,
        VALID_FROM,
        EXPIRES_AT,
        standard_caps(),
    );
    assert_eq!(
        registry.install(cross_repository).unwrap_err(),
        BindingRegistryError::RepositoryMismatch
    );

    let equal_version_different_digest = approved_binding(
        0x11,
        1,
        0x33,
        digest,
        VALID_FROM,
        EXPIRES_AT + 1,
        standard_caps(),
    );
    assert_ne!(
        equal_version_different_digest.binding_ref().digest(),
        version_one.binding_ref().digest()
    );
    assert_eq!(
        registry
            .replace(equal_version_different_digest)
            .unwrap_err(),
        BindingRegistryError::VersionNotAdvanced
    );

    let version_three = approved_binding(
        0x11,
        3,
        0x33,
        digest,
        VALID_FROM,
        EXPIRES_AT,
        standard_caps(),
    );
    registry.replace(version_three.clone()).unwrap();
    let rollback = approved_binding(
        0x11,
        2,
        0x33,
        digest,
        VALID_FROM,
        EXPIRES_AT,
        standard_caps(),
    );
    assert_eq!(
        registry.replace(rollback).unwrap_err(),
        BindingRegistryError::VersionNotAdvanced
    );
    assert_eq!(
        registry
            .read_lease(
                version_one.material().repository_identity(),
                version_one.binding_ref(),
                UnixTimestampNanos::new(CHECKED_AT),
            )
            .unwrap_err(),
        BindingRegistryError::BindingReferenceMismatch
    );

    registry
        .revoke(
            version_three.material().repository_identity(),
            version_three.binding_ref(),
        )
        .unwrap();
    assert_eq!(
        registry
            .read_lease(
                version_three.material().repository_identity(),
                version_three.binding_ref(),
                UnixTimestampNanos::new(CHECKED_AT),
            )
            .unwrap_err(),
        BindingRegistryError::BindingRevoked
    );

    let version_four = approved_binding(
        0x11,
        4,
        0x33,
        digest,
        VALID_FROM,
        EXPIRES_AT,
        standard_caps(),
    );
    registry.replace(version_four.clone()).unwrap();
    let lease = registry
        .read_lease(
            version_four.material().repository_identity(),
            version_four.binding_ref(),
            UnixTimestampNanos::new(CHECKED_AT),
        )
        .unwrap();
    assert_eq!(lease.binding_ref(), version_four.binding_ref());
}

#[test]
fn binding_read_lease_checks_exact_reference_repository_and_half_open_time() {
    let binding = approved_binding(
        0x11,
        1,
        0x33,
        public_policy().digest(),
        VALID_FROM,
        EXPIRES_AT,
        standard_caps(),
    );
    let registry = LiveApprovedBindingRegistryV1::new();
    registry.install(binding.clone()).unwrap();

    let start = registry
        .read_lease(
            binding.material().repository_identity(),
            binding.binding_ref(),
            UnixTimestampNanos::new(VALID_FROM),
        )
        .unwrap();
    drop(start);
    assert_eq!(
        registry
            .read_lease(
                binding.material().repository_identity(),
                binding.binding_ref(),
                UnixTimestampNanos::new(VALID_FROM - 1),
            )
            .unwrap_err(),
        BindingRegistryError::BindingNotYetValid
    );
    assert_eq!(
        registry
            .read_lease(
                binding.material().repository_identity(),
                binding.binding_ref(),
                UnixTimestampNanos::new(EXPIRES_AT),
            )
            .unwrap_err(),
        BindingRegistryError::BindingExpired
    );
    assert_eq!(
        registry
            .read_lease(
                RepositoryIdentityDigest::from_bytes([0x99; 32]),
                binding.binding_ref(),
                UnixTimestampNanos::new(CHECKED_AT),
            )
            .unwrap_err(),
        BindingRegistryError::RepositoryMismatch
    );
    let other_id = BindingRefV1::new(
        BindingId::from_bytes([0x12; 32]),
        binding.binding_ref().version().get(),
        binding.binding_ref().digest(),
    )
    .unwrap();
    assert_eq!(
        registry
            .read_lease(
                binding.material().repository_identity(),
                &other_id,
                UnixTimestampNanos::new(CHECKED_AT),
            )
            .unwrap_err(),
        BindingRegistryError::BindingNotFound
    );
}

#[test]
fn binding_read_lease_blocks_revoke_and_replace_until_drop_then_stale_refs_fail() {
    let digest = public_policy().digest();
    let version_one = approved_binding(
        0x11,
        1,
        0x33,
        digest,
        VALID_FROM,
        EXPIRES_AT,
        standard_caps(),
    );
    let registry = Arc::new(LiveApprovedBindingRegistryV1::new());
    registry.install(version_one.clone()).unwrap();

    let lease = registry
        .read_lease(
            version_one.material().repository_identity(),
            version_one.binding_ref(),
            UnixTimestampNanos::new(CHECKED_AT),
        )
        .unwrap();
    let writer_registry = Arc::clone(&registry);
    let repository_identity = version_one.material().repository_identity();
    let binding_ref = *version_one.binding_ref();
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let revoke_writer = thread::spawn(move || {
        started_tx.send(()).unwrap();
        writer_registry
            .revoke(repository_identity, &binding_ref)
            .unwrap();
        done_tx.send(()).unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
    drop(lease);
    done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    revoke_writer.join().unwrap();
    assert_eq!(
        registry
            .read_lease(
                version_one.material().repository_identity(),
                version_one.binding_ref(),
                UnixTimestampNanos::new(CHECKED_AT),
            )
            .unwrap_err(),
        BindingRegistryError::BindingRevoked
    );

    let version_two = approved_binding(
        0x11,
        2,
        0x33,
        digest,
        VALID_FROM,
        EXPIRES_AT,
        standard_caps(),
    );
    registry.replace(version_two.clone()).unwrap();
    let lease = registry
        .read_lease(
            version_two.material().repository_identity(),
            version_two.binding_ref(),
            UnixTimestampNanos::new(CHECKED_AT),
        )
        .unwrap();
    let version_three = approved_binding(
        0x11,
        3,
        0x33,
        digest,
        VALID_FROM,
        EXPIRES_AT,
        standard_caps(),
    );
    let writer_registry = Arc::clone(&registry);
    let visible_version_three = version_three.clone();
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let replace_writer = thread::spawn(move || {
        started_tx.send(()).unwrap();
        writer_registry.replace(version_three).unwrap();
        done_tx.send(()).unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
    drop(lease);
    done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    replace_writer.join().unwrap();
    assert_eq!(
        registry
            .read_lease(
                version_two.material().repository_identity(),
                version_two.binding_ref(),
                UnixTimestampNanos::new(CHECKED_AT),
            )
            .unwrap_err(),
        BindingRegistryError::BindingReferenceMismatch
    );
    registry
        .read_lease(
            visible_version_three.material().repository_identity(),
            visible_version_three.binding_ref(),
            UnixTimestampNanos::new(CHECKED_AT),
        )
        .unwrap();
}

#[test]
fn canonical_prefix_checks_resist_prefix_confusion_and_root_slash_is_universal() {
    let policy = InternalPathPolicyV1::new(
        [canonical(b"/var/log/evidentrail")],
        [canonical(b"/private/evidentrail-alias")],
    )
    .unwrap();
    let digest = policy.digest();
    let registry = InternalPathRegistryV1::new(policy);

    let confused = locator(b"/", &[b"var", b"log", b"evidentrail-other", b"file"]);
    registry.read_lease_for_locator(&confused, digest).unwrap();
    let reserved = locator(b"/var/log", &[b"evidentrail", b"file"]);
    assert_eq!(
        registry
            .read_lease_for_locator(&reserved, digest)
            .unwrap_err(),
        InternalPathRegistryError::CanonicalPathReserved
    );
    let alias = locator(b"/private", &[b"evidentrail-alias", b"file"]);
    assert_eq!(
        registry.read_lease_for_locator(&alias, digest).unwrap_err(),
        InternalPathRegistryError::CanonicalPathReserved
    );

    let root_policy = InternalPathPolicyV1::new([canonical(b"/")], []).unwrap();
    let root_digest = root_policy.digest();
    let root_registry = InternalPathRegistryV1::new(root_policy);
    assert_eq!(
        root_registry
            .read_lease_for_locator(&confused, root_digest)
            .unwrap_err(),
        InternalPathRegistryError::CanonicalPathReserved
    );
}

#[test]
fn active_identity_rejects_a_hard_link_outside_every_reserved_root() {
    let policy = public_policy();
    let digest = policy.digest();
    let registry = InternalPathRegistryV1::new(policy);
    let internal_identity = UnixFileObjectIdV1::new(500, 600);
    registry
        .register_active_identity(internal_identity)
        .unwrap();
    registry
        .register_active_identity(internal_identity)
        .unwrap();

    let outside = locator(b"/tmp", &[b"approved.log"]);
    let lease = registry.read_lease_for_locator(&outside, digest).unwrap();
    assert_eq!(
        lease.check_opened_identity(internal_identity).unwrap_err(),
        InternalPathRegistryError::OpenedIdentityReserved
    );
    lease
        .check_opened_identity(UnixFileObjectIdV1::new(500, 601))
        .unwrap();
    drop(lease);

    registry
        .unregister_active_identity(internal_identity)
        .unwrap();
    let lease = registry.read_lease_for_locator(&outside, digest).unwrap();
    assert_eq!(
        lease.check_opened_identity(internal_identity).unwrap_err(),
        InternalPathRegistryError::OpenedIdentityReserved
    );
    drop(lease);
    registry
        .unregister_active_identity(internal_identity)
        .unwrap();
    registry
        .read_lease_for_locator(&outside, digest)
        .unwrap()
        .check_opened_identity(internal_identity)
        .unwrap();
}

#[test]
fn policy_digest_is_order_stable_and_ignores_dynamic_identity_updates() {
    let first = InternalPathPolicyV1::new(
        [canonical(b"/z"), canonical(b"/a")],
        [canonical(b"/y"), canonical(b"/b")],
    )
    .unwrap();
    let reordered = InternalPathPolicyV1::new(
        [canonical(b"/a"), canonical(b"/z")],
        [canonical(b"/b"), canonical(b"/y")],
    )
    .unwrap();
    assert_eq!(first.digest(), reordered.digest());

    let changed = InternalPathPolicyV1::new(
        [canonical(b"/a"), canonical(b"/z")],
        [canonical(b"/b"), canonical(b"/different")],
    )
    .unwrap();
    assert_ne!(first.digest(), changed.digest());

    let expected_digest = first.digest();
    let registry = InternalPathRegistryV1::new(first);
    let identity = UnixFileObjectIdV1::new(91, 92);
    registry.register_active_identity(identity).unwrap();
    let lease = registry
        .read_lease_for_locator(&locator(b"/outside", &[b"file"]), expected_digest)
        .unwrap();
    assert_eq!(lease.policy_digest(), expected_digest);
    drop(lease);
    registry.unregister_active_identity(identity).unwrap();
    assert_eq!(
        registry
            .read_lease_for_locator(&locator(b"/outside", &[b"file"]), expected_digest,)
            .unwrap()
            .policy_digest(),
        expected_digest
    );
}

#[test]
fn internal_path_read_lease_blocks_policy_updates_until_both_checks_can_finish() {
    let policy = public_policy();
    let digest = policy.digest();
    let registry = Arc::new(InternalPathRegistryV1::new(policy));
    let lease = registry
        .read_lease_for_locator(&locator(b"/tmp", &[b"approved.log"]), digest)
        .unwrap();

    let writer_registry = Arc::clone(&registry);
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let writer = thread::spawn(move || {
        started_tx.send(()).unwrap();
        writer_registry
            .replace_policy(
                InternalPathPolicyV1::new([canonical(b"/new-internal-root")], []).unwrap(),
            )
            .unwrap();
        done_tx.send(()).unwrap();
    });

    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
    lease
        .check_opened_identity(UnixFileObjectIdV1::new(1, 2))
        .unwrap();
    drop(lease);
    done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    writer.join().unwrap();
}

#[test]
fn joined_token_requires_exact_live_binding_and_policy_but_remains_non_executable() {
    let policy = public_policy();
    let policy_digest = policy.digest();
    let internal_paths = InternalPathRegistryV1::new(policy);
    let binding = approved_binding(
        0x11,
        1,
        0x33,
        policy_digest,
        VALID_FROM,
        EXPIRES_AT,
        standard_caps(),
    );
    let plan = plan_for(&binding);
    let bindings = LiveApprovedBindingRegistryV1::new();
    bindings.install(binding.clone()).unwrap();

    assert_eq!(
        authorize_local_file_plan_with_registries_v1(
            &plan,
            &binding,
            &bindings,
            &internal_paths,
            UnixTimestampNanos::new(plan.material().created_at().get() - 1),
        )
        .unwrap_err(),
        RegistryAuthorizationError::PlanOutsideValidity
    );
    assert_eq!(
        authorize_local_file_plan_with_registries_v1(
            &plan,
            &binding,
            &bindings,
            &internal_paths,
            plan.material().execute_before(),
        )
        .unwrap_err(),
        RegistryAuthorizationError::PlanOutsideValidity
    );

    let token = authorize_local_file_plan_with_registries_v1(
        &plan,
        &binding,
        &bindings,
        &internal_paths,
        UnixTimestampNanos::new(CHECKED_AT),
    )
    .unwrap();
    assert_eq!(token.plan_id(), plan.plan_id());
    assert_eq!(token.binding_ref(), binding.binding_ref());
    assert_eq!(token.internal_path_policy_digest(), policy_digest);
    assert!(format!("{token:?}").contains("executable: false"));
    token
        .check_opened_identity_not_internal(plan.material().snapshot().file())
        .unwrap();
    drop(token);

    internal_paths
        .register_active_identity(plan.material().snapshot().file())
        .unwrap();
    let token = authorize_local_file_plan_with_registries_v1(
        &plan,
        &binding,
        &bindings,
        &internal_paths,
        UnixTimestampNanos::new(CHECKED_AT),
    )
    .unwrap();
    assert_eq!(
        token
            .check_opened_identity_not_internal(plan.material().snapshot().file())
            .unwrap_err(),
        RegistryAuthorizationError::OpenedIdentityReserved
    );
    drop(token);

    let unrelated_binding = approved_binding(
        0x12,
        1,
        0x33,
        policy_digest,
        VALID_FROM,
        EXPIRES_AT,
        standard_caps(),
    );
    assert_eq!(
        authorize_local_file_plan_with_registries_v1(
            &plan,
            &unrelated_binding,
            &bindings,
            &internal_paths,
            UnixTimestampNanos::new(CHECKED_AT),
        )
        .unwrap_err(),
        RegistryAuthorizationError::BindingArtifactMismatch
    );

    let wrong_policy = InternalPathPolicyV1::new([canonical(b"/different")], []).unwrap();
    let wrong_paths = InternalPathRegistryV1::new(wrong_policy);
    assert_eq!(
        authorize_local_file_plan_with_registries_v1(
            &plan,
            &binding,
            &bindings,
            &wrong_paths,
            UnixTimestampNanos::new(CHECKED_AT),
        )
        .unwrap_err(),
        RegistryAuthorizationError::InternalPathPolicyMismatch
    );

    bindings
        .revoke(
            binding.material().repository_identity(),
            binding.binding_ref(),
        )
        .unwrap();
    assert_eq!(
        authorize_local_file_plan_with_registries_v1(
            &plan,
            &binding,
            &bindings,
            &internal_paths,
            UnixTimestampNanos::new(CHECKED_AT),
        )
        .unwrap_err(),
        RegistryAuthorizationError::BindingRevoked
    );
}

#[test]
fn debug_and_errors_do_not_reveal_paths_object_ids_or_hashes() {
    let path = canonical(b"/secret/internal/telemetry");
    let policy = InternalPathPolicyV1::new([path.clone()], []).unwrap();
    let registry = InternalPathRegistryV1::new(policy.clone());
    let identity = UnixFileObjectIdV1::new(12_345, 67_890);
    registry.register_active_identity(identity).unwrap();
    let lease = registry
        .read_lease_for_locator(&locator(b"/outside", &[b"safe.log"]), policy.digest())
        .unwrap();
    let error = lease.check_opened_identity(identity).unwrap_err();

    for rendered in [
        format!("{path:?}"),
        format!("{policy:?}"),
        format!("{registry:?}"),
        format!("{lease:?}"),
        format!("{error:?}"),
        error.to_string(),
    ] {
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("telemetry"));
        assert!(!rendered.contains("12345"));
        assert!(!rendered.contains("67890"));
        assert!(!rendered.contains(&policy.digest().to_string()));
    }
}
