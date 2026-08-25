use evidentrail_core::{
    AcquisitionOutcome, AcquisitionSequence, AdapterIdentity, DeterministicPolicy,
    EnvelopeOrdering, EnvelopeSink, EventId, ExactnessBasis, FetchIdentity, LaneKey, LaneSequence,
    LedgerBuilder, PlanDigest, PlanId, PolicyAuthorization, PolicyDigest,
    PreparedSinkAckExpectation, RawEnvelopeIdentityV1, RawEnvelopeV1, RecordBytes, RecordState,
    RetrievalId, SinkAck, SinkAckVerificationError, SourceIdentityDigest, SourceMember,
    SourceStream, TransformationReceiptId, expected_source_record_id, verify_sink_ack_binding,
};
use evidentrail_schema::bounds::MAX_AUTHORIZED_RECORD_BYTES;

fn retrieval(seed: u8) -> RetrievalId {
    RetrievalId::from_bytes([seed; 32])
}

fn identity(seed: u8) -> FetchIdentity {
    FetchIdentity::new(
        retrieval(seed),
        PlanId::from_bytes([seed.wrapping_add(1); 32]),
        PlanDigest::from_bytes([seed.wrapping_add(2); 32]),
        AdapterIdentity::new("CANARY_ADAPTER_PATH_/secret", "CANARY_ADAPTER_VERSION").unwrap(),
    )
}

fn envelope(identity: &FetchIdentity, sequence: u64, record: RecordBytes) -> RawEnvelopeV1 {
    RawEnvelopeV1::new(
        RawEnvelopeIdentityV1::new(
            identity.retrieval_id(),
            identity.plan_id(),
            identity.plan_digest(),
            identity.adapter().clone(),
            SourceIdentityDigest::from_bytes([9; 32]),
        ),
        EnvelopeOrdering::new(
            AcquisitionSequence::new(sequence),
            LaneKey::new(
                SourceMember::new(b"CANARY_MEMBER_/private/log".to_vec()).unwrap(),
                SourceStream::FileMember,
            ),
            LaneSequence::new(sequence),
        ),
        record,
        RecordState::Complete,
    )
}

fn source_exact_outcome() -> AcquisitionOutcome {
    AcquisitionOutcome::Persisted {
        event_id: EventId::from_bytes([10; 32]),
        exactness_basis: ExactnessBasis::SourceExact,
    }
}

fn post_policy_outcome() -> AcquisitionOutcome {
    AcquisitionOutcome::Persisted {
        event_id: EventId::from_bytes([11; 32]),
        exactness_basis: ExactnessBasis::PostPolicy {
            policy_digest: PolicyDigest::from_bytes([12; 32]),
            transformation_receipt_id: TransformationReceiptId::from_bytes([13; 32]),
        },
    }
}

fn omitted_outcome() -> AcquisitionOutcome {
    AcquisitionOutcome::OmittedByPolicy {
        policy_digest: PolicyDigest::from_bytes([14; 32]),
    }
}

fn acknowledgement(
    retrieval_id: RetrievalId,
    sequence: u64,
    source_record_id: evidentrail_core::SourceRecordId,
    authorized_byte_count: u64,
    outcome: AcquisitionOutcome,
) -> SinkAck {
    SinkAck::new(
        retrieval_id,
        source_record_id,
        AcquisitionSequence::new(sequence),
        authorized_byte_count,
        outcome,
    )
}

#[test]
fn source_exact_acknowledgement_binds_every_recomputable_dimension() {
    let identity = identity(1);
    let envelope = envelope(
        &identity,
        7,
        RecordBytes::framed(b"CANARY_PAYLOAD\0\xff".to_vec(), b"\r\n".to_vec()),
    );
    let source_record_id = expected_source_record_id(&envelope);
    let ack = acknowledgement(
        identity.retrieval_id(),
        7,
        source_record_id,
        u64::try_from(envelope.record().source_len()).unwrap(),
        source_exact_outcome(),
    );

    assert_eq!(verify_sink_ack_binding(&envelope, &ack), Ok(()));
    assert_eq!(
        PreparedSinkAckExpectation::from_envelope(&envelope).verify(&ack),
        Ok(())
    );
}

#[test]
fn prepared_expectation_is_compact_payload_free_and_contentless() {
    let identity = identity(42);
    let envelope = envelope(
        &identity,
        0,
        RecordBytes::whole(b"CANARY_PREPARED_PAYLOAD_AND_CURSOR".to_vec()),
    )
    .with_cursor(evidentrail_core::SourceCursor::new(b"CANARY_PREPARED_CURSOR".to_vec()).unwrap());
    let expectation = PreparedSinkAckExpectation::from_envelope(&envelope);
    let debug = format!("{expectation:?}");
    let expected_debug = format!(
        "PreparedSinkAckExpectation {{ source_byte_count: {} }}",
        envelope.record().source_len()
    );

    assert!(std::mem::size_of::<PreparedSinkAckExpectation>() <= 96);
    assert_eq!(debug, expected_debug);
    for canary in [
        "CANARY_PREPARED_PAYLOAD_AND_CURSOR",
        "CANARY_PREPARED_CURSOR",
        "CANARY_MEMBER",
        "CANARY_ADAPTER",
    ] {
        assert!(!debug.contains(canary));
    }
}

#[test]
fn each_identity_binding_dimension_fails_independently() {
    let identity = identity(2);
    let envelope = envelope(&identity, 4, RecordBytes::whole(b"CANARY_PAYLOAD".to_vec()));
    let expected = expected_source_record_id(&envelope);
    let valid_count = u64::try_from(envelope.record().source_len()).unwrap();

    let wrong_retrieval = acknowledgement(
        retrieval(99),
        4,
        expected,
        valid_count,
        source_exact_outcome(),
    );
    assert_eq!(
        verify_sink_ack_binding(&envelope, &wrong_retrieval),
        Err(SinkAckVerificationError::RetrievalMismatch)
    );

    let wrong_sequence = acknowledgement(
        identity.retrieval_id(),
        5,
        expected,
        valid_count,
        source_exact_outcome(),
    );
    assert_eq!(
        verify_sink_ack_binding(&envelope, &wrong_sequence),
        Err(SinkAckVerificationError::AcquisitionSequenceMismatch)
    );

    let wrong_source_record = acknowledgement(
        identity.retrieval_id(),
        4,
        evidentrail_core::SourceRecordId::from_bytes([99; 32]),
        valid_count,
        source_exact_outcome(),
    );
    assert_eq!(
        verify_sink_ack_binding(&envelope, &wrong_source_record),
        Err(SinkAckVerificationError::SourceRecordIdMismatch)
    );
}

#[test]
fn source_exact_and_omission_have_exact_byte_count_rules() {
    let identity = identity(3);
    let envelope = envelope(
        &identity,
        0,
        RecordBytes::framed(b"abc".to_vec(), b"\n".to_vec()),
    );
    let source_record_id = expected_source_record_id(&envelope);

    let wrong_source_exact_count = acknowledgement(
        identity.retrieval_id(),
        0,
        source_record_id,
        3,
        source_exact_outcome(),
    );
    assert_eq!(
        verify_sink_ack_binding(&envelope, &wrong_source_exact_count),
        Err(SinkAckVerificationError::AuthorizedByteCountMismatch)
    );

    let nonzero_omission = acknowledgement(
        identity.retrieval_id(),
        0,
        source_record_id,
        1,
        omitted_outcome(),
    );
    assert_eq!(
        verify_sink_ack_binding(&envelope, &nonzero_omission),
        Err(SinkAckVerificationError::AuthorizedByteCountMismatch)
    );

    let zero_omission = acknowledgement(
        identity.retrieval_id(),
        0,
        source_record_id,
        0,
        omitted_outcome(),
    );
    assert_eq!(verify_sink_ack_binding(&envelope, &zero_omission), Ok(()));
}

#[test]
fn post_policy_count_is_bounded_without_claiming_pre_policy_recomputation() {
    let identity = identity(4);
    let envelope = envelope(
        &identity,
        0,
        RecordBytes::whole(b"a much larger pre-policy secret".to_vec()),
    );
    let source_record_id = expected_source_record_id(&envelope);

    let transformed_count_differs_from_source = acknowledgement(
        identity.retrieval_id(),
        0,
        source_record_id,
        2,
        post_policy_outcome(),
    );
    assert_eq!(
        verify_sink_ack_binding(&envelope, &transformed_count_differs_from_source),
        Ok(())
    );

    let above_hard_maximum = acknowledgement(
        identity.retrieval_id(),
        0,
        source_record_id,
        u64::try_from(MAX_AUTHORIZED_RECORD_BYTES).unwrap() + 1,
        post_policy_outcome(),
    );
    assert_eq!(
        verify_sink_ack_binding(&envelope, &above_hard_maximum),
        Err(SinkAckVerificationError::AuthorizedByteCountMismatch)
    );
}

#[derive(Clone, Copy)]
struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

#[test]
fn ledger_builder_uses_the_public_authoritative_source_record_helper() {
    let identity = identity(5);
    let source_identity = SourceIdentityDigest::from_bytes([9; 32]);
    let envelope = envelope(&identity, 0, RecordBytes::whole(b"builder bytes".to_vec()));
    let expected = expected_source_record_id(&envelope);
    let mut builder = LedgerBuilder::new(identity, source_identity, SourceExactPolicy);

    let ack = builder.accept(envelope).unwrap();
    assert_eq!(ack.source_record_id(), expected);
}

#[test]
fn verification_errors_are_stable_and_contentless() {
    let errors = [
        (
            SinkAckVerificationError::RetrievalMismatch,
            "EVIDENTRAIL_SINK_ACK_RETRIEVAL_MISMATCH",
        ),
        (
            SinkAckVerificationError::AcquisitionSequenceMismatch,
            "EVIDENTRAIL_SINK_ACK_ACQUISITION_SEQUENCE_MISMATCH",
        ),
        (
            SinkAckVerificationError::SourceRecordIdMismatch,
            "EVIDENTRAIL_SINK_ACK_SOURCE_RECORD_ID_MISMATCH",
        ),
        (
            SinkAckVerificationError::AuthorizedByteCountMismatch,
            "EVIDENTRAIL_SINK_ACK_AUTHORIZED_BYTE_COUNT_MISMATCH",
        ),
    ];

    for (error, code) in errors {
        let debug = format!("{error:?}");
        let display = error.to_string();
        assert_eq!(error.code(), code);
        assert_eq!(display, code);
        assert_eq!(
            debug,
            format!("SinkAckVerificationError {{ code: {code:?} }}")
        );
        for canary in [
            "CANARY_PAYLOAD",
            "CANARY_MEMBER",
            "CANARY_ADAPTER",
            "/private/log",
            "0909",
        ] {
            assert!(!debug.contains(canary));
            assert!(!display.contains(canary));
        }
    }
}
