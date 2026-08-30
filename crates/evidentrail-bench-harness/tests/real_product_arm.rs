use evidentrail_bench_harness::{
    RealDurableQualificationAvailabilityV2, execute_real_durable_product_arm_v2,
    execute_real_memory_product_arm_v2, real_durable_qualification_availability_v2,
};
use evidentrail_core::UnixTimestampNanos;

#[cfg(unix)]
use evidentrail_cli::DurablePublishingMcpRetentionBackendV2;
#[cfg(unix)]
use evidentrail_product::DurableProductV2;
#[cfg(unix)]
use evidentrail_store::{DurableResultRepositoryV2, ProcessKeyAuthorityV2};

#[test]
fn real_memory_arm_is_deterministic_and_durable_qualification_fails_closed() {
    let input = b"request=fixture status=failed\r\ninvalid=\xff\0\n";
    let first = execute_real_memory_product_arm_v2(
        input,
        b"why did fixture fail?",
        100_000,
        [0x41; 32],
        UnixTimestampNanos::new(100),
    )
    .unwrap();
    let second = execute_real_memory_product_arm_v2(
        input,
        b"why did fixture fail?",
        100_000,
        [0x41; 32],
        UnixTimestampNanos::new(100),
    )
    .unwrap();
    assert_eq!(first.1, second.1);
    assert_eq!(first.1.source_record_count, 2);
    assert_eq!(first.1.source_byte_count, input.len() as u64);
    assert_eq!(
        real_durable_qualification_availability_v2(),
        RealDurableQualificationAvailabilityV2::MissingExternalTrustedAuthority
    );
}

#[cfg(unix)]
#[test]
fn real_memory_and_v2_durable_product_arms_have_identical_public_commitments() {
    let root =
        std::env::temp_dir().join(format!("evidentrail-t4-real-durable-arm-{}", std::process::id()));
    if root.exists() {
        std::fs::remove_dir_all(&root).unwrap();
    }
    let repository =
        DurableResultRepositoryV2::open(&root, ProcessKeyAuthorityV2::new(4).unwrap()).unwrap();
    let product = DurableProductV2::new(repository);
    let mut backend = DurablePublishingMcpRetentionBackendV2::new(product);
    let input = b"request=fixture status=failed\r\ninvalid=\xff\0\n";
    let now = UnixTimestampNanos::new(100);
    let memory = execute_real_memory_product_arm_v2(
        input,
        b"why did fixture fail?",
        100_000,
        [0x51; 32],
        now,
    )
    .unwrap();
    let durable = execute_real_durable_product_arm_v2(
        &mut backend,
        input,
        b"why did fixture fail?",
        100_000,
        [0x51; 32],
        now,
    )
    .unwrap();
    assert_eq!(memory.1, durable);
    drop(memory);
    drop(backend);
    std::fs::remove_dir_all(root).unwrap();
}
