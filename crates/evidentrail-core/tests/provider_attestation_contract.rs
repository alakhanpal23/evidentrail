use evidentrail_core::{
    AcknowledgedCounts, AcquisitionOutcome, AcquisitionSequence, AdapterIdentity, AdapterOutcome,
    AttemptCounts, CompletenessProof, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink,
    FetchBoundaries, FetchCompleteness, FetchCompletion, FetchIdentity, FetchTiming, LaneKey,
    LaneSequence, LedgerBuilder, PolicyAuthorization, PolicyDigest,
    ProviderAttestationConstructionError, ProviderAttestationOriginV1,
    ProviderAttestationScopeDigestV1, ProviderAttestationValueV1, ProviderAttestationsV1,
    ProviderAttestedCorrelationV1, ProviderAttestedRelationKindV1, RawEnvelopeIdentityV1,
    RawEnvelopeV1, RecordBytes, RecordState, RetrievalId, SourceIdentityDigest, SourceMember,
    SourceStream, UnixTimestampNanos,
};
use evidentrail_schema::{PlanDigest, PlanId};

#[derive(Clone, Copy)]
struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

#[derive(Clone, Copy)]
struct OmitPolicy {
    policy_digest: PolicyDigest,
}

impl DeterministicPolicy for OmitPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::OmittedByPolicy {
            policy_digest: self.policy_digest,
        }
    }
}

fn correlation(
    scope: u8,
    kind: ProviderAttestedRelationKindV1,
    value: impl Into<Vec<u8>>,
) -> ProviderAttestedCorrelationV1 {
    ProviderAttestedCorrelationV1::new(
        ProviderAttestationScopeDigestV1::from_bytes([scope; 32]),
        kind,
        ProviderAttestationValueV1::new(value).unwrap(),
    )
}

fn ledger_with(
    seed: u8,
    payload: Vec<u8>,
    attestations: ProviderAttestationsV1,
) -> evidentrail_core::EventLedger {
    ledger_with_policy(seed, payload, attestations, SourceExactPolicy)
}

fn ledger_with_policy<P: DeterministicPolicy>(
    seed: u8,
    payload: Vec<u8>,
    attestations: ProviderAttestationsV1,
    policy: P,
) -> evidentrail_core::EventLedger {
    let retrieval_id = RetrievalId::from_bytes([seed; 32]);
    let plan_id = PlanId::from_bytes([seed.wrapping_add(1); 32]);
    let plan_digest = PlanDigest::from_bytes([seed.wrapping_add(2); 32]);
    let source_identity = SourceIdentityDigest::from_bytes([seed.wrapping_add(3); 32]);
    let adapter = AdapterIdentity::new("attested-replay", "v1").unwrap();
    let identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity =
        RawEnvelopeIdentityV1::new(retrieval_id, plan_id, plan_digest, adapter, source_identity);
    let payload_len = u64::try_from(payload.len()).unwrap();
    let envelope = RawEnvelopeV1::new(
        envelope_identity,
        EnvelopeOrdering::new(
            AcquisitionSequence::new(0),
            LaneKey::new(
                SourceMember::new(b"opaque-member".to_vec()).unwrap(),
                SourceStream::Stderr,
            ),
            LaneSequence::new(0),
        ),
        RecordBytes::whole(payload),
        RecordState::Complete,
    )
    .with_provider_attestations(attestations);
    let mut builder = LedgerBuilder::new(identity.clone(), source_identity, policy);
    builder.accept(envelope).unwrap();
    builder
        .seal(
            FetchCompletion::new(
                identity,
                FetchTiming::new(UnixTimestampNanos::new(1), UnixTimestampNanos::new(2)),
                AcknowledgedCounts::new(1, payload_len, payload_len),
                AttemptCounts::new(1, 1),
                AttemptCounts::default(),
                FetchBoundaries::default(),
                [],
                AdapterOutcome::Finished,
                [],
                FetchCompleteness::complete(CompletenessProof::ReplayManifestVerified),
            )
            .unwrap(),
        )
        .unwrap()
}

#[test]
fn native_attestations_preserve_arbitrary_bytes_and_replay_exactly() {
    let arbitrary = vec![0xff, 0, b'/', b'\n', b'\r', 0x80];
    let attestations = ProviderAttestationsV1::new([
        correlation(
            1,
            ProviderAttestedRelationKindV1::ServiceIdentity,
            b"service-a".to_vec(),
        ),
        correlation(
            1,
            ProviderAttestedRelationKindV1::TraceIdentity,
            arbitrary.clone(),
        ),
    ])
    .unwrap();
    let first = ledger_with(1, b"payload".to_vec(), attestations.clone());
    let replay = ledger_with(1, b"payload".to_vec(), attestations.clone());
    let first_event = &first.events()[0];
    let replay_event = &replay.events()[0];

    assert_eq!(first_event.id(), replay_event.id());
    assert_eq!(
        first_event.source_record_id(),
        replay_event.source_record_id()
    );
    assert_eq!(first_event.provider_attestations(), &attestations);
    assert_eq!(
        first_event.provider_attestations().entries()[0]
            .value()
            .as_bytes(),
        arbitrary,
    );
    assert!(
        first_event
            .provider_attestations()
            .entries()
            .iter()
            .all(|entry| entry.origin() == ProviderAttestationOriginV1::AdapterNativeField)
    );
}

#[test]
fn attestation_mutations_preserve_source_position_but_bind_persisted_event_identity() {
    let payload = b"same authorized payload".to_vec();
    let variants = [
        ProviderAttestationsV1::default(),
        ProviderAttestationsV1::new([correlation(
            1,
            ProviderAttestedRelationKindV1::TraceIdentity,
            b"same".to_vec(),
        )])
        .unwrap(),
        ProviderAttestationsV1::new([correlation(
            2,
            ProviderAttestedRelationKindV1::TraceIdentity,
            b"same".to_vec(),
        )])
        .unwrap(),
        ProviderAttestationsV1::new([correlation(
            1,
            ProviderAttestedRelationKindV1::RequestIdentity,
            b"same".to_vec(),
        )])
        .unwrap(),
        ProviderAttestationsV1::new([correlation(
            1,
            ProviderAttestedRelationKindV1::TraceIdentity,
            b"changed".to_vec(),
        )])
        .unwrap(),
    ];
    let ledgers = variants
        .into_iter()
        .map(|attestations| ledger_with(2, payload.clone(), attestations))
        .collect::<Vec<_>>();

    let content_hash = ledgers[0].events()[0].content_hash();
    assert!(
        ledgers
            .iter()
            .all(|ledger| ledger.events()[0].content_hash() == content_hash)
    );
    for (left_index, left) in ledgers.iter().enumerate() {
        for right in ledgers.iter().skip(left_index + 1) {
            assert_eq!(
                left.events()[0].source_record_id(),
                right.events()[0].source_record_id()
            );
            assert_ne!(left.events()[0].id(), right.events()[0].id());
        }
    }
}

#[test]
fn omitted_policy_receipts_never_commit_attestation_values() {
    let policy = OmitPolicy {
        policy_digest: PolicyDigest::from_bytes([0x91; 32]),
    };
    let first = ledger_with_policy(
        5,
        b"omitted payload".to_vec(),
        ProviderAttestationsV1::new([correlation(
            7,
            ProviderAttestedRelationKindV1::TraceIdentity,
            b"CANARY_OMITTED_TRACE_2c18".to_vec(),
        )])
        .unwrap(),
        policy,
    );
    let second = ledger_with_policy(
        5,
        b"omitted payload".to_vec(),
        ProviderAttestationsV1::new([correlation(
            8,
            ProviderAttestedRelationKindV1::RequestIdentity,
            b"different omitted identity".to_vec(),
        )])
        .unwrap(),
        policy,
    );

    assert!(first.events().is_empty());
    assert!(second.events().is_empty());
    assert_eq!(first.acquisition_receipt(), second.acquisition_receipt());
    assert_eq!(
        first.acquisition_receipt_id(),
        second.acquisition_receipt_id()
    );
    let entry = &first.acquisition_receipt().entries()[0];
    assert_eq!(
        entry.source_record_id(),
        second.acquisition_receipt().entries()[0].source_record_id()
    );
    assert!(matches!(
        entry.outcome(),
        AcquisitionOutcome::OmittedByPolicy { .. }
    ));
    assert_eq!(entry.outcome().persisted_event_id(), None);
}

#[test]
fn explicit_default_none_preserves_legacy_source_and_event_identities() {
    let implicit = ledger_with(6, b"payload".to_vec(), ProviderAttestationsV1::default());
    let explicit = ledger_with(
        6,
        b"payload".to_vec(),
        ProviderAttestationsV1::new(std::iter::empty()).unwrap(),
    );

    assert_eq!(
        implicit.events()[0].source_record_id(),
        explicit.events()[0].source_record_id()
    );
    assert_eq!(implicit.events()[0].id(), explicit.events()[0].id());
    assert_eq!(
        implicit.acquisition_receipt_id(),
        explicit.acquisition_receipt_id()
    );
}

#[test]
fn payload_lookalike_never_becomes_a_native_attestation() {
    const LOOKALIKE: &[u8] = b"trace_id=CANARY_PAYLOAD_TRACE_d26f";
    let unasserted = ledger_with(3, LOOKALIKE.to_vec(), ProviderAttestationsV1::default());
    assert!(unasserted.events()[0].provider_attestations().is_empty());

    let asserted = ledger_with(
        3,
        LOOKALIKE.to_vec(),
        ProviderAttestationsV1::new([correlation(
            3,
            ProviderAttestedRelationKindV1::TraceIdentity,
            b"CANARY_PAYLOAD_TRACE_d26f".to_vec(),
        )])
        .unwrap(),
    );
    assert_eq!(asserted.events()[0].provider_attestations().len(), 1);
    assert_ne!(unasserted.events()[0].id(), asserted.events()[0].id());
}

#[test]
fn namespace_is_part_of_canonical_equality_not_a_join_hint() {
    let first = correlation(
        0x41,
        ProviderAttestedRelationKindV1::SessionIdentity,
        b"shared-native-value".to_vec(),
    );
    let second = correlation(
        0x42,
        ProviderAttestedRelationKindV1::SessionIdentity,
        b"shared-native-value".to_vec(),
    );
    let attestations = ProviderAttestationsV1::new([second.clone(), first.clone()]).unwrap();
    assert_eq!(attestations.len(), 2);
    assert_ne!(first, second);
    assert_ne!(first.scope_digest(), second.scope_digest());
}

#[test]
fn debug_and_errors_expose_counts_and_codes_never_attestation_material() {
    const VALUE_CANARY: &str = "CANARY_ATTESTATION_VALUE_c52a";
    let attestations = ProviderAttestationsV1::new([correlation(
        0xab,
        ProviderAttestedRelationKindV1::ContainerIdentity,
        VALUE_CANARY.as_bytes().to_vec(),
    )])
    .unwrap();
    let ledger = ledger_with(4, b"payload".to_vec(), attestations.clone());
    let rendered = format!(
        "{attestations:?} {:?} {:?} {:?} {:?} {:?}",
        attestations.entries()[0],
        attestations.entries()[0].value(),
        attestations.entries()[0].scope_digest(),
        ledger.events()[0],
        ProviderAttestationConstructionError::EmptyValue,
    );
    assert!(!rendered.contains(VALUE_CANARY));
    assert!(!rendered.contains("ababab"));
    assert!(!rendered.contains("opaque-member"));
    assert!(rendered.contains("EVIDENTRAIL_SCHEMA_PROVIDER_ATTESTATION_EMPTY_VALUE"));
}
