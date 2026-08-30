#![cfg(target_os = "macos")]

use evidentrail_schema::ResultId;
use evidentrail_snapshot_format::{
    BuildContextDigestsV1, LifecycleDigestV1, LifecycleTransitionV1, OperationIdV1,
    ResultLifecycleStateV1, SealCommitmentsV1,
};
use evidentrail_store::{
    AuthorityDestroyOutcomeV2, KeyAuthorityErrorV2, KeyAuthorityV2, MacOsKeychainAuthorityV2,
};
use security_framework::passwords::{PasswordOptions, delete_generic_password_options};

fn operation(byte: u8) -> OperationIdV1 {
    OperationIdV1::from_bytes([byte; 16])
}

fn digest(byte: u8) -> LifecycleDigestV1 {
    LifecycleDigestV1::from_bytes([byte; 32])
}

#[test]
#[ignore = "requires a provisioned macOS data-protection Keychain entitlement"]
fn data_protection_keychain_survives_authority_reopen_and_deletes_key_first() {
    let namespace = format!("{}-production-contract", std::process::id());
    let result_id = ResultId::from_bytes([0xa7; 32]);
    let authority = MacOsKeychainAuthorityV2::isolated_for_tests(4, &namespace).unwrap();
    let _ = authority.destroy(result_id);

    let (open, transition) = authority
        .begin(result_id, 10, 10_000, operation(1), digest(1))
        .unwrap();
    assert_eq!(transition, LifecycleTransitionV1::Applied);
    assert_eq!(open.state(), ResultLifecycleStateV1::Open);
    let reserved = authority
        .reserve_nonce_range(result_id, operation(2), digest(2), 6)
        .unwrap();
    assert_eq!(reserved.first_counter(), 0);
    assert_eq!(
        authority
            .complete_nonce_reservation(result_id, operation(2), digest(2))
            .unwrap(),
        LifecycleTransitionV1::Applied
    );

    drop(authority);
    let reopened = MacOsKeychainAuthorityV2::isolated_for_tests(4, &namespace).unwrap();
    let retry = reopened
        .reserve_nonce_range(result_id, operation(2), digest(2), 6)
        .unwrap();
    assert_eq!(retry, reserved);
    assert_eq!(
        reopened
            .complete_nonce_reservation(result_id, operation(2), digest(2))
            .unwrap(),
        LifecycleTransitionV1::AlreadyApplied
    );
    let build = BuildContextDigestsV1::new(digest(3), digest(4), digest(5), digest(6), digest(7));
    reopened
        .commit_data(result_id, operation(3), digest(8), build)
        .unwrap();
    let commitments =
        SealCommitmentsV1::new(digest(9), digest(10), digest(11), digest(12), digest(13));
    reopened.seal(result_id, operation(4), commitments).unwrap();
    let generation = reopened
        .reserve_publication_generation(result_id, operation(5), digest(14))
        .unwrap();
    assert!(generation > 0);
    reopened
        .publish(result_id, operation(5), generation, digest(14))
        .unwrap();
    assert_eq!(
        reopened.snapshot(result_id).unwrap().state(),
        ResultLifecycleStateV1::Published
    );
    assert_eq!(reopened.list().unwrap().len(), 1);
    reopened
        .with_result_key(result_id, |record, _| {
            assert_eq!(record.state(), ResultLifecycleStateV1::Published);
            Ok(())
        })
        .unwrap();

    assert_eq!(
        reopened.destroy(result_id).unwrap(),
        AuthorityDestroyOutcomeV2::Destroyed
    );
    assert_eq!(
        reopened.snapshot(result_id),
        Err(KeyAuthorityErrorV2::NotFound)
    );

    let publication_service = format!("ai.evidentrail.snapshot-publication.v2.test.{namespace}");
    let mut options = PasswordOptions::new_generic_password(&publication_service, "global");
    options.set_access_synchronized(Some(false));
    options.use_protected_keychain();
    delete_generic_password_options(options).unwrap();
}
