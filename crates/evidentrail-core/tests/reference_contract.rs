use evidentrail_core::{
    BlockId, EventId, EvidenceReferenceConstructionError, EvidenceReferenceId,
    EvidenceReferenceUnavailable, EvidenceReferenceV1, EvidenceTargetRef, ExpansionRelationV1,
    MAX_EVIDENCE_REFERENCE_TARGETS, ResultId, UnixTimestampNanos,
};

fn result(seed: u8) -> ResultId {
    ResultId::from_bytes([seed; 32])
}

fn event(seed: u8) -> EvidenceTargetRef {
    EvidenceTargetRef::Event(EventId::from_bytes([seed; 32]))
}

fn block(seed: u8) -> EvidenceTargetRef {
    EvidenceTargetRef::Block(BlockId::from_bytes([seed; 32]))
}

fn issue(result_id: ResultId) -> EvidenceReferenceV1 {
    EvidenceReferenceV1::issue(
        result_id,
        [event(1), block(2)],
        [
            ExpansionRelationV1::GlobalBeforeAfter,
            ExpansionRelationV1::Exact,
            ExpansionRelationV1::SameLaneBeforeAfter,
        ],
        UnixTimestampNanos::new(100),
        UnixTimestampNanos::new(200),
    )
    .unwrap()
}

#[test]
fn reference_identity_is_result_bound_ordered_and_canonical() {
    let first = issue(result(3));
    let replay = EvidenceReferenceV1::issue(
        result(3),
        [event(1), block(2)],
        [
            ExpansionRelationV1::SameLaneBeforeAfter,
            ExpansionRelationV1::Exact,
            ExpansionRelationV1::GlobalBeforeAfter,
        ],
        UnixTimestampNanos::new(100),
        UnixTimestampNanos::new(200),
    )
    .unwrap();
    let reordered_targets = EvidenceReferenceV1::issue(
        result(3),
        [block(2), event(1)],
        [ExpansionRelationV1::Exact],
        UnixTimestampNanos::new(100),
        UnixTimestampNanos::new(200),
    )
    .unwrap();
    let other_result = issue(result(4));

    assert_eq!(first.id(), replay.id());
    assert_eq!(
        first.allowed_relations(),
        &[
            ExpansionRelationV1::Exact,
            ExpansionRelationV1::SameLaneBeforeAfter,
            ExpansionRelationV1::GlobalBeforeAfter,
        ]
    );
    assert_ne!(first.id(), reordered_targets.id());
    assert_ne!(first.id(), other_result.id());
}

#[test]
fn declared_identity_is_recomputed_before_construction() {
    let reference = issue(result(5));
    let verified = EvidenceReferenceV1::verify_declared(
        reference.id(),
        result(5),
        [event(1), block(2)],
        [
            ExpansionRelationV1::Exact,
            ExpansionRelationV1::SameLaneBeforeAfter,
            ExpansionRelationV1::GlobalBeforeAfter,
        ],
        UnixTimestampNanos::new(100),
        UnixTimestampNanos::new(200),
    )
    .unwrap();
    assert_eq!(reference, verified);

    assert_eq!(
        EvidenceReferenceV1::verify_declared(
            EvidenceReferenceId::from_bytes([0xff; 32]),
            result(5),
            [event(1), block(2)],
            [ExpansionRelationV1::Exact],
            UnixTimestampNanos::new(100),
            UnixTimestampNanos::new(200),
        ),
        Err(EvidenceReferenceConstructionError::DeclaredIdMismatch)
    );
}

#[test]
fn construction_rejects_ambiguous_or_unexpandable_material() {
    let issued_at = UnixTimestampNanos::new(100);
    let expires_at = UnixTimestampNanos::new(200);

    assert_eq!(
        EvidenceReferenceV1::issue(
            result(1),
            [],
            [ExpansionRelationV1::Exact],
            issued_at,
            expires_at,
        ),
        Err(EvidenceReferenceConstructionError::EmptyTargets)
    );
    assert_eq!(
        EvidenceReferenceV1::issue(
            result(1),
            [event(1), event(1)],
            [ExpansionRelationV1::Exact],
            issued_at,
            expires_at,
        ),
        Err(EvidenceReferenceConstructionError::DuplicateTarget)
    );
    assert_eq!(
        EvidenceReferenceV1::issue(result(1), [event(1)], [], issued_at, expires_at),
        Err(EvidenceReferenceConstructionError::EmptyRelations)
    );
    assert_eq!(
        EvidenceReferenceV1::issue(
            result(1),
            [event(1)],
            [ExpansionRelationV1::Exact, ExpansionRelationV1::Exact],
            issued_at,
            expires_at,
        ),
        Err(EvidenceReferenceConstructionError::DuplicateRelation)
    );
    assert_eq!(
        EvidenceReferenceV1::issue(
            result(1),
            [event(1)],
            [ExpansionRelationV1::GlobalBeforeAfter],
            issued_at,
            expires_at,
        ),
        Err(EvidenceReferenceConstructionError::ExactRelationRequired)
    );
    assert_eq!(
        EvidenceReferenceV1::issue(
            result(1),
            [event(1)],
            [ExpansionRelationV1::Exact],
            expires_at,
            expires_at,
        ),
        Err(EvidenceReferenceConstructionError::InvalidLifetime)
    );

    let too_many = (0..=MAX_EVIDENCE_REFERENCE_TARGETS)
        .map(|position| {
            let mut bytes = [0_u8; 32];
            bytes[..8].copy_from_slice(&u64::try_from(position).unwrap().to_le_bytes());
            EvidenceTargetRef::Event(EventId::from_bytes(bytes))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        EvidenceReferenceV1::issue(
            result(1),
            too_many,
            [ExpansionRelationV1::Exact],
            issued_at,
            expires_at,
        ),
        Err(EvidenceReferenceConstructionError::TooManyTargets)
    );
}

#[test]
fn authorization_is_exclusive_at_both_lifetime_and_result_boundaries() {
    let reference = issue(result(9));

    assert_eq!(
        reference.authorize(
            result(9),
            ExpansionRelationV1::Exact,
            UnixTimestampNanos::new(99),
        ),
        Err(EvidenceReferenceUnavailable)
    );
    assert_eq!(
        reference.authorize(
            result(9),
            ExpansionRelationV1::Exact,
            UnixTimestampNanos::new(100),
        ),
        Ok(())
    );
    assert_eq!(
        reference.authorize(
            result(9),
            ExpansionRelationV1::Exact,
            UnixTimestampNanos::new(199),
        ),
        Ok(())
    );
    for denied in [
        reference.authorize(
            result(9),
            ExpansionRelationV1::Exact,
            UnixTimestampNanos::new(200),
        ),
        reference.authorize(
            result(8),
            ExpansionRelationV1::Exact,
            UnixTimestampNanos::new(150),
        ),
        reference.authorize(
            result(9),
            ExpansionRelationV1::SameAttestedTrace,
            UnixTimestampNanos::new(150),
        ),
    ] {
        assert_eq!(denied, Err(EvidenceReferenceUnavailable));
    }
}

#[test]
fn reference_debug_and_public_denials_are_contentless() {
    let reference = issue(result(0xab));
    let result_token = reference.result_id().canonical_token();
    let reference_token = reference.id().to_string();
    let rendered = format!("{reference:?}");

    assert!(!rendered.contains(&result_token));
    assert!(!rendered.contains(&reference_token));
    assert_eq!(
        EvidenceReferenceUnavailable.to_string(),
        "EVIDENTRAIL_EVIDENCE_REFERENCE_UNAVAILABLE"
    );
    assert_eq!(
        format!("{EvidenceReferenceUnavailable:?}"),
        "EvidenceReferenceUnavailable"
    );
}
