#![cfg(feature = "internal-test-provider")]

use std::collections::BTreeSet;
#[cfg(unix)]
use std::fs::{self, DirBuilder};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};

use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    CompletenessProof, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, EventLedger,
    EvidenceReferenceV1, EvidenceTargetRef, ExpansionRelationV1, FetchBoundaries,
    FetchCompleteness, FetchCompletion, FetchIdentity, FetchPartialReason, FetchPartialReasons,
    FetchTiming, LaneKey, LaneSequence, LedgerBuilder, PlanDigest, PlanId, PolicyAuthorization,
    PolicyDigest, RawEnvelopeIdentityV1, RawEnvelopeV1, RecordBytes, RecordState, RetrievalId,
    SourceIdentityDigest, SourceMember, SourceStream, TransformationReceiptId, UnixTimestampNanos,
};
use evidentrail_evidence::Utf8ByteTokenizerV1;
use evidentrail_product::{
    AuthenticatedEncryptedRetentionErrorV1, AuthenticatedEncryptedRetentionV1,
    DeterministicProductDecisionV1, MemoryProductV1, ProductResultDecisionV1,
};
use evidentrail_schema::ResultId;
use evidentrail_snapshot_format::{
    EntropySourceFailureV1, EntropySourceV1, ExpectedCoreResultManifestContextV1,
};
use evidentrail_store::{
    AliasExpansionRequestV1, CreatingKeyContextV1, DEFAULT_RESULT_TTL_NANOS,
    EphemeralKeyProviderV1, EvidenceAliasV1, ExpansionLimitV1, ExpansionRequestV1,
    MemoryEncryptedCoreResultRepositoryV1, ResultStoreError,
};
#[cfg(unix)]
use evidentrail_store::{
    AuthenticatedFilesystemRecoveryDispositionV1, AuthenticatedFilesystemRestartCoordinatorV1,
    AuthenticatedFilesystemRestartErrorV1, FilesystemSealedBundleStoreV1,
};

#[derive(Clone, Copy)]
struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

#[derive(Clone)]
struct ReplacePolicy {
    authorized_record: RecordBytes,
}

impl DeterministicPolicy for ReplacePolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::PostPolicy {
            authorized_record: self.authorized_record.clone(),
            policy_digest: PolicyDigest::from_bytes([0xa1; 32]),
            transformation_receipt_id: TransformationReceiptId::from_bytes([0xa2; 32]),
        }
    }
}

struct CountingEntropy {
    next: u8,
}

impl CountingEntropy {
    const fn new() -> Self {
        Self { next: 1 }
    }
}

impl EntropySourceV1 for CountingEntropy {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropySourceFailureV1> {
        destination.fill(self.next);
        self.next = self.next.checked_add(1).unwrap();
        Ok(())
    }
}

type TestRetention = AuthenticatedEncryptedRetentionV1<EphemeralKeyProviderV1<CountingEntropy>>;

fn retention() -> TestRetention {
    let provider = EphemeralKeyProviderV1::new(CountingEntropy::new(), 16).unwrap();
    let repository = MemoryEncryptedCoreResultRepositoryV1::new(provider, 16).unwrap();
    AuthenticatedEncryptedRetentionV1::new(repository)
}

#[derive(Clone)]
struct FixtureRecord {
    member: Vec<u8>,
    stream: SourceStream,
    lane_sequence: u64,
    record: RecordBytes,
}

fn fixture(
    member: &[u8],
    stream: SourceStream,
    lane_sequence: u64,
    record: RecordBytes,
) -> FixtureRecord {
    FixtureRecord {
        member: member.to_vec(),
        stream,
        lane_sequence,
        record,
    }
}

fn result(seed: u8) -> ResultId {
    ResultId::from_bytes([0xd0_u8.wrapping_add(seed); 32])
}

fn ledger(seed: u8, completeness: FetchCompleteness, records: &[FixtureRecord]) -> EventLedger {
    ledger_with_policy(seed, completeness, records, SourceExactPolicy)
}

fn ledger_with_policy<P: DeterministicPolicy>(
    seed: u8,
    completeness: FetchCompleteness,
    records: &[FixtureRecord],
    policy: P,
) -> EventLedger {
    let retrieval_id = RetrievalId::from_bytes([seed; 32]);
    let plan_id = PlanId::from_bytes([seed.wrapping_add(1); 32]);
    let plan_digest = PlanDigest::from_bytes([seed.wrapping_add(2); 32]);
    let source_identity = SourceIdentityDigest::from_bytes([seed.wrapping_add(3); 32]);
    let adapter = AdapterIdentity::new("RETENTION_CANARY_ADAPTER", "v1").unwrap();
    let identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity =
        RawEnvelopeIdentityV1::new(retrieval_id, plan_id, plan_digest, adapter, source_identity);
    let mut builder = LedgerBuilder::new(identity.clone(), source_identity, policy);
    let mut members = BTreeSet::new();
    let mut payload_bytes = 0_u64;
    let mut source_bytes = 0_u64;
    for (position, fixture) in records.iter().enumerate() {
        let member = SourceMember::new(fixture.member.clone()).unwrap();
        members.insert(member.clone());
        payload_bytes = payload_bytes
            .checked_add(u64::try_from(fixture.record.payload_len()).unwrap())
            .unwrap();
        source_bytes = source_bytes
            .checked_add(u64::try_from(fixture.record.source_len()).unwrap())
            .unwrap();
        builder
            .accept(RawEnvelopeV1::new(
                envelope_identity.clone(),
                EnvelopeOrdering::new(
                    AcquisitionSequence::new(u64::try_from(position).unwrap()),
                    LaneKey::new(member, fixture.stream.clone()),
                    LaneSequence::new(fixture.lane_sequence),
                ),
                fixture.record.clone(),
                RecordState::Complete,
            ))
            .unwrap();
    }
    let member_count = u64::try_from(members.len()).unwrap();
    let record_count = u64::try_from(records.len()).unwrap();
    builder
        .seal(
            FetchCompletion::new(
                identity,
                FetchTiming::new(UnixTimestampNanos::new(1), UnixTimestampNanos::new(2)),
                AcknowledgedCounts::new(record_count, payload_bytes, source_bytes),
                AttemptCounts::new(member_count, member_count),
                AttemptCounts::default(),
                FetchBoundaries::default(),
                [],
                AdapterOutcome::Finished,
                [],
                completeness,
            )
            .unwrap(),
        )
        .unwrap()
}

fn complete_ledger(seed: u8, records: &[FixtureRecord]) -> EventLedger {
    ledger(
        seed,
        FetchCompleteness::complete(CompletenessProof::InMemoryFixtureExhausted),
        records,
    )
}

fn key_context(result_id: ResultId, now: UnixTimestampNanos) -> CreatingKeyContextV1 {
    CreatingKeyContextV1::new(
        result_id,
        i64::try_from(now.get()).unwrap(),
        i64::try_from(now.get() + DEFAULT_RESULT_TTL_NANOS).unwrap(),
    )
    .unwrap()
}

fn limit(max_events: usize, max_bytes: usize) -> ExpansionLimitV1 {
    ExpansionLimitV1::new(max_events, max_bytes, 0, 0).unwrap()
}

#[test]
fn finalized_passthrough_migrates_then_expands_exact_arbitrary_bytes() {
    let result_id = result(1);
    let now = UnixTimestampNanos::new(100);
    let exact_bytes = vec![0xff, 0, b'S', b'T', b'A', b'T', b'U', b'S', b'\r', b'\n'];
    let records = [fixture(
        b"CANARY_/private/retention.log",
        SourceStream::Stderr,
        0,
        RecordBytes::whole(exact_bytes.clone()),
    )];
    let mut product = MemoryProductV1::new();
    let decision = product
        .create_deterministic_result_v1(
            result_id,
            b"RETENTION_SECRET_QUESTION\xff",
            complete_ledger(1, &records),
            now,
            100_000,
        )
        .unwrap();
    let DeterministicProductDecisionV1::Passthrough(rendered) = decision else {
        panic!("small fixture must render passthrough");
    };
    let full_reference = rendered.references().next().unwrap().clone();
    let mut encrypted = retention();
    let publication = product
        .migrate_passthrough_to_authenticated_retention(
            &mut encrypted,
            &key_context(result_id, now),
            &rendered,
            now,
        )
        .unwrap();

    assert_eq!(publication.persisted_event_count(), 1);
    assert_eq!(publication.registered_reference_count(), 1);
    assert_eq!(publication.published_alias_count(), 1);
    assert_eq!(product.result_count(), 0);
    assert_eq!(encrypted.result_count(), 1);
    assert_eq!(
        product.expand(
            ExpansionRequestV1::new(
                result_id,
                full_reference.id(),
                ExpansionRelationV1::Exact,
                limit(1, 1024),
            ),
            now,
        ),
        Err(ResultStoreError::ReferenceUnavailable)
    );

    let opened = encrypted
        .expand_alias(
            AliasExpansionRequestV1::new(
                result_id,
                EvidenceAliasV1::new(result_id, 1).unwrap(),
                ExpansionRelationV1::Exact,
                limit(1, 1024),
            ),
            now,
        )
        .unwrap();
    assert_eq!(opened.events().len(), 1);
    assert_eq!(opened.events()[0].as_bytes(), exact_bytes);
    assert_eq!(
        opened.events()[0].event_id(),
        full_reference_target(&full_reference)
    );
    assert!(!opened.truncated());

    let debug = format!("{encrypted:?} {publication:?} {opened:?}");
    assert!(!debug.contains("RETENTION_SECRET"));
    assert!(!debug.contains("STATUS"));
    assert!(!debug.contains(&result_id.canonical_token()));

    encrypted
        .repository_for_test()
        .fail_next_ciphertext_cleanup_for_test()
        .unwrap();
    assert_eq!(
        encrypted.destroy(result_id).unwrap_err(),
        AuthenticatedEncryptedRetentionErrorV1::RepositoryFailed
    );
    assert_eq!(encrypted.result_count(), 0);
    assert_eq!(
        encrypted
            .expand_reference(
                ExpansionRequestV1::new(
                    result_id,
                    full_reference.id(),
                    ExpansionRelationV1::Exact,
                    limit(1, 1024),
                ),
                now,
            )
            .unwrap_err(),
        AuthenticatedEncryptedRetentionErrorV1::ReferenceUnavailable
    );
}

#[test]
fn post_policy_event_retains_only_authorized_bytes_and_exactness() {
    let result_id = result(6);
    let now = UnixTimestampNanos::new(600);
    let records = [fixture(
        b"policy",
        SourceStream::LogStream,
        0,
        RecordBytes::whole(b"SOURCE_SECRET_MUST_NOT_PERSIST".to_vec()),
    )];
    let authorized = RecordBytes::framed(
        vec![0xff, 0, b'R', b'E', b'D', b'A', b'C', b'T', b'E', b'D'],
        b"\r\n".to_vec(),
    );
    let source = ledger_with_policy(
        6,
        FetchCompleteness::complete(CompletenessProof::InMemoryFixtureExhausted),
        &records,
        ReplacePolicy {
            authorized_record: authorized.clone(),
        },
    );
    let expected_exactness = source.events()[0].exactness_basis();
    let mut product = MemoryProductV1::new();
    let decision = product
        .create_deterministic_result_v1(result_id, b"redacted", source, now, 100_000)
        .unwrap();
    let DeterministicProductDecisionV1::Passthrough(rendered) = decision else {
        panic!("small post-policy fixture must render passthrough");
    };
    let mut encrypted = retention();
    product
        .migrate_passthrough_to_authenticated_retention(
            &mut encrypted,
            &key_context(result_id, now),
            &rendered,
            now,
        )
        .unwrap();
    let opened = encrypted
        .expand_alias(
            AliasExpansionRequestV1::new(
                result_id,
                EvidenceAliasV1::new(result_id, 1).unwrap(),
                ExpansionRelationV1::Exact,
                limit(1, 1024),
            ),
            now,
        )
        .unwrap();
    assert_eq!(opened.events()[0].as_bytes(), authorized.exact_bytes());
    assert_eq!(opened.events()[0].exactness_basis(), expected_exactness);
    assert_ne!(
        opened.events()[0].as_bytes(),
        b"SOURCE_SECRET_MUST_NOT_PERSIST"
    );
}

#[test]
fn partial_empty_and_expiry_boundaries_remain_honest() {
    let partial = FetchCompleteness::partial(
        FetchPartialReasons::new(FetchPartialReason::SourceByteCap),
        None,
    );
    let result_id = result(2);
    let now = UnixTimestampNanos::new(200);
    let records = [fixture(
        b"partial",
        SourceStream::Stdout,
        0,
        RecordBytes::whole(b"partial-retained".to_vec()),
    )];
    let mut product = MemoryProductV1::new();
    let decision = product
        .create_deterministic_result_v1(
            result_id,
            b"partial",
            ledger(2, partial.clone(), &records),
            now,
            100_000,
        )
        .unwrap();
    let DeterministicProductDecisionV1::Passthrough(rendered) = decision else {
        panic!("small partial fixture must remain exact passthrough");
    };
    assert_eq!(rendered.artifact().brief().status().acquisition(), &partial);
    let mut encrypted = retention();
    product
        .migrate_passthrough_to_authenticated_retention(
            &mut encrypted,
            &key_context(result_id, now),
            &rendered,
            now,
        )
        .unwrap();
    let alias = EvidenceAliasV1::new(result_id, 1).unwrap();
    let request = |result_id, alias| {
        AliasExpansionRequestV1::new(result_id, alias, ExpansionRelationV1::Exact, limit(1, 1024))
    };
    assert_eq!(
        encrypted
            .expand_alias(request(result_id, alias), UnixTimestampNanos::new(199))
            .unwrap_err(),
        AuthenticatedEncryptedRetentionErrorV1::ReferenceUnavailable
    );
    assert_eq!(
        encrypted.cleanup_expired(UnixTimestampNanos::new(
            now.get() + DEFAULT_RESULT_TTL_NANOS
        )),
        1
    );
    assert_eq!(encrypted.result_count(), 0);
    assert_eq!(
        encrypted
            .expand_alias(
                request(result_id, alias),
                UnixTimestampNanos::new(now.get() + DEFAULT_RESULT_TTL_NANOS),
            )
            .unwrap_err(),
        AuthenticatedEncryptedRetentionErrorV1::ReferenceUnavailable
    );
    assert_eq!(
        encrypted
            .expand_alias(
                request(result_id, EvidenceAliasV1::new(result(3), 1).unwrap()),
                now,
            )
            .unwrap_err(),
        AuthenticatedEncryptedRetentionErrorV1::ReferenceUnavailable
    );

    let empty_id = result(3);
    let empty_now = UnixTimestampNanos::new(300);
    let mut empty_product = MemoryProductV1::new();
    let empty_decision = empty_product
        .create_deterministic_result_v1(
            empty_id,
            b"empty",
            complete_ledger(3, &[]),
            empty_now,
            100_000,
        )
        .unwrap();
    let DeterministicProductDecisionV1::Passthrough(empty_rendered) = empty_decision else {
        panic!("empty ledger must render passthrough");
    };
    let mut empty_encrypted = retention();
    let publication = empty_product
        .migrate_passthrough_to_authenticated_retention(
            &mut empty_encrypted,
            &key_context(empty_id, empty_now),
            &empty_rendered,
            empty_now,
        )
        .unwrap();
    assert_eq!(publication.persisted_event_count(), 0);
    assert_eq!(publication.published_alias_count(), 0);
    assert_eq!(empty_product.result_count(), 0);
}

#[test]
fn compiled_packet_is_atomic_and_precompile_full_references_survive() {
    let result_id = result(4);
    let now = UnixTimestampNanos::new(400);
    let compile_now = UnixTimestampNanos::new(450);
    let records = [
        fixture(
            b"app",
            SourceStream::Stderr,
            0,
            RecordBytes::framed(
                b"Traceback (most recent call last):".to_vec(),
                b"\n".to_vec(),
            ),
        ),
        fixture(
            b"app",
            SourceStream::Stderr,
            1,
            RecordBytes::framed(b"  File \"worker.py\", line 7".to_vec(), b"\n".to_vec()),
        ),
        fixture(
            b"app",
            SourceStream::Stderr,
            2,
            RecordBytes::framed(b"ValueError: timeout".to_vec(), b"\n".to_vec()),
        ),
        fixture(
            b"app",
            SourceStream::Stderr,
            3,
            RecordBytes::whole(vec![b'Z'; 50_000]),
        ),
    ];
    let source = complete_ledger(4, &records);
    let event_ids = source
        .events()
        .iter()
        .map(|event| event.id())
        .collect::<Vec<_>>();
    let full_large_reference = EvidenceReferenceV1::issue(
        result_id,
        [EvidenceTargetRef::Event(event_ids[3])],
        [
            ExpansionRelationV1::Exact,
            ExpansionRelationV1::SameLaneBeforeAfter,
            ExpansionRelationV1::GlobalBeforeAfter,
        ],
        now,
        UnixTimestampNanos::new(now.get() + DEFAULT_RESULT_TTL_NANOS),
    )
    .unwrap();
    let mut product = MemoryProductV1::new();
    let initial = product
        .create_result(
            result_id,
            b"timeout",
            source,
            now,
            20_000,
            &Utf8ByteTokenizerV1::new(),
        )
        .unwrap();
    let ProductResultDecisionV1::CompilationRequired(_) = initial else {
        panic!("oversized fixture must retain an exact passthrough miss");
    };
    let decision = product
        .resume_deterministic_result_v1(result_id, b"timeout", compile_now)
        .unwrap();
    let DeterministicProductDecisionV1::Compiled(compiled) = decision else {
        panic!("traceback plus oversized noise must compile");
    };
    let packet = compiled
        .artifact()
        .brief()
        .evidence()
        .iter()
        .find(|packet| packet.events().len() > 1)
        .expect("the intact traceback block must remain one packet");
    let expected_packet_bytes = packet
        .events()
        .iter()
        .map(|event| event.authorized_bytes().to_vec())
        .collect::<Vec<_>>();
    let packet_alias = u16::try_from(packet.ordinal() + 1).unwrap();

    let mut encrypted = retention();
    let publication = product
        .migrate_compiled_to_authenticated_retention(
            &mut encrypted,
            &key_context(result_id, now),
            &compiled,
            compile_now,
        )
        .unwrap();
    assert_eq!(publication.persisted_event_count(), records.len());
    assert!(publication.registered_reference_count() > publication.published_alias_count());
    assert_eq!(product.result_count(), 0);

    let packet_request = |limit| {
        AliasExpansionRequestV1::new(
            result_id,
            EvidenceAliasV1::new(result_id, packet_alias).unwrap(),
            ExpansionRelationV1::Exact,
            limit,
        )
    };
    assert_eq!(
        encrypted
            .expand_alias(packet_request(limit(1, 128 * 1024)), compile_now)
            .unwrap_err(),
        AuthenticatedEncryptedRetentionErrorV1::InsufficientExpansionBudget
    );
    assert_eq!(
        encrypted
            .expand_alias(packet_request(limit(8, 1)), compile_now)
            .unwrap_err(),
        AuthenticatedEncryptedRetentionErrorV1::InsufficientExpansionBudget
    );
    let opened = encrypted
        .expand_alias(packet_request(limit(8, 128 * 1024)), compile_now)
        .unwrap();
    assert_eq!(
        opened
            .events()
            .iter()
            .map(|event| event.as_bytes().to_vec())
            .collect::<Vec<_>>(),
        expected_packet_bytes
    );

    let retained_large = encrypted
        .expand_reference(
            ExpansionRequestV1::new(
                result_id,
                full_large_reference.id(),
                ExpansionRelationV1::Exact,
                limit(1, 64 * 1024),
            ),
            compile_now,
        )
        .unwrap();
    assert_eq!(retained_large.events()[0].as_bytes(), vec![b'Z'; 50_000]);
    assert_eq!(retained_large.events()[0].event_id(), event_ids[3]);

    let fabricated = EvidenceReferenceV1::issue(
        result_id,
        [
            EvidenceTargetRef::Event(event_ids[0]),
            EvidenceTargetRef::Event(event_ids[3]),
        ],
        [ExpansionRelationV1::Exact],
        now,
        UnixTimestampNanos::new(now.get() + DEFAULT_RESULT_TTL_NANOS),
    )
    .unwrap();
    assert_eq!(
        encrypted
            .expand_reference(
                ExpansionRequestV1::new(
                    result_id,
                    fabricated.id(),
                    ExpansionRelationV1::Exact,
                    limit(2, 64 * 1024),
                ),
                compile_now,
            )
            .unwrap_err(),
        AuthenticatedEncryptedRetentionErrorV1::ReferenceUnavailable
    );
    assert_eq!(
        encrypted
            .expand_reference(
                ExpansionRequestV1::new(
                    result_id,
                    full_large_reference.id(),
                    ExpansionRelationV1::GlobalBeforeAfter,
                    limit(8, 64 * 1024),
                ),
                compile_now,
            )
            .unwrap_err(),
        AuthenticatedEncryptedRetentionErrorV1::ReferenceUnavailable
    );
}

#[test]
fn publication_failure_leaves_plaintext_product_and_publishes_no_metadata() {
    let result_id = result(5);
    let now = UnixTimestampNanos::new(500);
    let records = [fixture(
        b"fault",
        SourceStream::Stderr,
        0,
        RecordBytes::whole(b"FAULT_CANARY_BYTES".to_vec()),
    )];
    let mut product = MemoryProductV1::new();
    let decision = product
        .create_deterministic_result_v1(
            result_id,
            b"fault",
            complete_ledger(5, &records),
            now,
            100_000,
        )
        .unwrap();
    let DeterministicProductDecisionV1::Passthrough(rendered) = decision else {
        panic!("small fixture must render passthrough");
    };
    let reference = rendered.references().next().unwrap().clone();
    let mut encrypted = retention();
    let wrong_created = CreatingKeyContextV1::new(
        result_id,
        i64::try_from(now.get() + 1).unwrap(),
        i64::try_from(now.get() + DEFAULT_RESULT_TTL_NANOS).unwrap(),
    )
    .unwrap();
    assert_eq!(
        product
            .migrate_passthrough_to_authenticated_retention(
                &mut encrypted,
                &wrong_created,
                &rendered,
                now,
            )
            .unwrap_err(),
        AuthenticatedEncryptedRetentionErrorV1::InvalidArtifactBinding
    );
    assert_eq!(product.result_count(), 1);
    assert_eq!(encrypted.result_count(), 0);
    encrypted
        .repository_for_test()
        .fail_next_publication_for_test()
        .unwrap();
    let error = product
        .migrate_passthrough_to_authenticated_retention(
            &mut encrypted,
            &key_context(result_id, now),
            &rendered,
            now,
        )
        .unwrap_err();
    assert_eq!(
        error,
        AuthenticatedEncryptedRetentionErrorV1::RepositoryFailed
    );
    assert_eq!(encrypted.result_count(), 0);
    assert_eq!(product.result_count(), 1);
    let plaintext = product
        .expand(
            ExpansionRequestV1::new(
                result_id,
                reference.id(),
                ExpansionRelationV1::Exact,
                limit(1, 1024),
            ),
            now,
        )
        .unwrap();
    assert_eq!(plaintext.events()[0].exact_bytes(), b"FAULT_CANARY_BYTES");
    assert_eq!(
        encrypted
            .expand_reference(
                ExpansionRequestV1::new(
                    result_id,
                    reference.id(),
                    ExpansionRelationV1::Exact,
                    limit(1, 1024),
                ),
                now,
            )
            .unwrap_err(),
        AuthenticatedEncryptedRetentionErrorV1::ReferenceUnavailable
    );
    let debug = format!("{error:?} {encrypted:?}");
    assert!(!debug.contains("FAULT_CANARY"));
    assert!(!debug.contains(&result_id.canonical_token()));
}

#[cfg(unix)]
static SYNTHETIC_RESTART_ROOT_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
struct SyntheticRestartRoot {
    path: PathBuf,
}

#[cfg(unix)]
impl SyntheticRestartRoot {
    fn new() -> Self {
        let base = fs::canonicalize(std::env::temp_dir()).unwrap();
        let ordinal = SYNTHETIC_RESTART_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!(
            "evidentrail-synthetic-product-restart-{}-{ordinal}",
            std::process::id()
        ));
        let mut builder = DirBuilder::new();
        builder.mode(0o700).create(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn store(&self) -> FilesystemSealedBundleStoreV1 {
        FilesystemSealedBundleStoreV1::open_existing_root(&self.path).unwrap()
    }
}

#[cfg(unix)]
impl Drop for SyntheticRestartRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
#[test]
fn finalized_product_restarts_from_ciphertext_after_plaintext_owners_are_dropped() {
    let root = SyntheticRestartRoot::new();
    let result_id = result(7);
    let now = UnixTimestampNanos::new(700);
    let exact_bytes = vec![
        0xff, 0, b'R', b'E', b'S', b'T', b'A', b'R', b'T', b'\r', b'\n',
    ];
    let records = [fixture(
        b"SYNTHETIC_RESTART_MEMBER",
        SourceStream::Stderr,
        0,
        RecordBytes::whole(exact_bytes.clone()),
    )];
    let source = complete_ledger(7, &records);
    let event_id = source.events()[0].id();
    let key_context = key_context(result_id, now);
    let expected = ExpectedCoreResultManifestContextV1::new(
        result_id,
        source.source_identity_digest(),
        source.acquisition_receipt_id(),
        key_context.created_unix_nanos(),
        key_context.expires_unix_nanos(),
    )
    .unwrap();

    let mut product = MemoryProductV1::new();
    let decision = product
        .create_deterministic_result_v1(
            result_id,
            b"SYNTHETIC_RESTART_QUESTION",
            source,
            now,
            100_000,
        )
        .unwrap();
    let DeterministicProductDecisionV1::Passthrough(rendered) = decision else {
        panic!("small synthetic fixture must render passthrough");
    };
    let displayed_reference_id = rendered.references().next().unwrap().id();

    let provider = Arc::new(EphemeralKeyProviderV1::new(CountingEntropy::new(), 16).unwrap());
    let repository = MemoryEncryptedCoreResultRepositoryV1::new(Arc::clone(&provider), 16).unwrap();
    let mut retention = AuthenticatedEncryptedRetentionV1::new(repository);
    product
        .migrate_passthrough_to_authenticated_retention(
            &mut retention,
            &key_context,
            &rendered,
            now,
        )
        .unwrap();
    assert_eq!(product.result_count(), 0);

    let publisher =
        AuthenticatedFilesystemRestartCoordinatorV1::new(root.store(), Arc::clone(&provider), 16)
            .unwrap();
    retention
        .publish_restart_bundle(&publisher, result_id, now)
        .unwrap();

    drop(rendered);
    drop(records);
    drop(product);
    drop(retention);
    drop(publisher);

    let restarted =
        AuthenticatedFilesystemRestartCoordinatorV1::new(root.store(), provider, 16).unwrap();
    let recovered = restarted
        .recover_exact_alias_result(expected, UnixTimestampNanos::new(701))
        .unwrap();
    assert_eq!(
        recovered.recovery_disposition(),
        AuthenticatedFilesystemRecoveryDispositionV1::Imported
    );
    assert_eq!(recovered.alias_count(), 1);
    let opened = recovered
        .expand_alias(
            AliasExpansionRequestV1::new(
                result_id,
                EvidenceAliasV1::new(result_id, 1).unwrap(),
                ExpansionRelationV1::Exact,
                limit(1, 1024),
            ),
            UnixTimestampNanos::new(702),
        )
        .unwrap();
    assert_eq!(opened.events()[0].as_bytes(), exact_bytes);
    assert_eq!(opened.events()[0].event_id(), event_id);
    assert_eq!(opened.reference_id(), displayed_reference_id);
    assert!(!opened.truncated());
    for forged in [
        AliasExpansionRequestV1::new(
            result_id,
            EvidenceAliasV1::new(result_id, 2).unwrap(),
            ExpansionRelationV1::Exact,
            limit(1, 1024),
        ),
        AliasExpansionRequestV1::new(
            result_id,
            EvidenceAliasV1::new(result_id, 1).unwrap(),
            ExpansionRelationV1::SameLaneBeforeAfter,
            limit(1, 1024),
        ),
        AliasExpansionRequestV1::new(
            result(8),
            EvidenceAliasV1::new(result(8), 1).unwrap(),
            ExpansionRelationV1::Exact,
            limit(1, 1024),
        ),
    ] {
        assert_eq!(
            recovered
                .expand_alias(forged, UnixTimestampNanos::new(703))
                .err(),
            Some(AuthenticatedFilesystemRestartErrorV1::AliasUnavailable)
        );
    }
    assert_eq!(
        recovered
            .expand_alias(
                AliasExpansionRequestV1::new(
                    result_id,
                    EvidenceAliasV1::new(result_id, 1).unwrap(),
                    ExpansionRelationV1::Exact,
                    limit(1, 1),
                ),
                UnixTimestampNanos::new(703),
            )
            .err(),
        Some(AuthenticatedFilesystemRestartErrorV1::InsufficientExpansionBudget)
    );
    assert_eq!(
        recovered
            .expand_alias(
                AliasExpansionRequestV1::new(
                    result_id,
                    EvidenceAliasV1::new(result_id, 1).unwrap(),
                    ExpansionRelationV1::Exact,
                    limit(1, 1024),
                ),
                UnixTimestampNanos::new(now.get() + DEFAULT_RESULT_TTL_NANOS),
            )
            .err(),
        Some(AuthenticatedFilesystemRestartErrorV1::AliasUnavailable)
    );
    assert!(!format!("{restarted:?} {recovered:?} {opened:?}").contains("SYNTHETIC_RESTART"));
    assert!(root.path().is_dir());
}

fn full_reference_target(reference: &EvidenceReferenceV1) -> evidentrail_core::EventId {
    let [EvidenceTargetRef::Event(event_id)] = reference.targets() else {
        panic!("fixture reference must target one event");
    };
    *event_id
}
