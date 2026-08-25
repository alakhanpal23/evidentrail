use std::collections::{BTreeMap, BTreeSet};

use evidentrail_core::{
    AcknowledgedCounts, AcquisitionSequence, AdapterIdentity, AdapterOutcome, AttemptCounts,
    CompletenessProof, DeterministicPolicy, EnvelopeOrdering, EnvelopeSink, EventLedger,
    ExpansionRelationV1, FetchBoundaries, FetchCompleteness, FetchCompletion, FetchIdentity,
    FetchPartialReason, FetchPartialReasons, FetchTiming, LaneKey, LaneSequence, LedgerBuilder,
    PlanDigest, PlanId, PolicyAuthorization, RawEnvelopeIdentityV1, RawEnvelopeV1, RecordBytes,
    RecordFragmentReason, RecordState, RetrievalId, SourceIdentityDigest, SourceMember,
    SourceStream, UnixTimestampNanos,
};
use evidentrail_product::{DeterministicProductDecisionV1, MemoryProductV1};
use evidentrail_schema::ResultId;
use evidentrail_store::{
    AliasExpansionRequestV1, EvidenceAliasV1, ExpansionLimitV1, ExpansionRequestV1,
    ResultStoreError,
};

#[path = "fixtures/hermetic_product_corpus_v1.rs"]
mod corpus;

use corpus::{
    DiagnosticFamilyV1, FailurePlacementV1, FixtureAcquisitionV1, FixtureRecordStateV1,
    FixtureRecordV1, FixtureStreamV1, FixtureTerminatorV1, PRODUCT_CORPUS_V1, ProductCorpusCaseV1,
};

const PASSTHROUGH_BUDGET: u64 = 1_000_000;
const COMPILED_BUDGET: u64 = 20_000;
const NEEDS_MORE_BUDGET: u64 = 0;

#[derive(Clone, Copy)]
struct SourceExactPolicy;

impl DeterministicPolicy for SourceExactPolicy {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

fn result(seed: u8) -> ResultId {
    ResultId::from_bytes([seed; 32])
}

fn stream(stream: FixtureStreamV1) -> SourceStream {
    match stream {
        FixtureStreamV1::Stdout => SourceStream::Stdout,
        FixtureStreamV1::Stderr => SourceStream::Stderr,
        FixtureStreamV1::Container => SourceStream::Container,
        FixtureStreamV1::LogStream => SourceStream::LogStream,
    }
}

fn record_bytes(record: &FixtureRecordV1) -> RecordBytes {
    let payload = record.payload.materialize();
    match record.terminator {
        FixtureTerminatorV1::None => RecordBytes::whole(payload),
        FixtureTerminatorV1::Lf => RecordBytes::framed(payload, b"\n".to_vec()),
        FixtureTerminatorV1::CrLf => RecordBytes::framed(payload, b"\r\n".to_vec()),
    }
}

fn record_state(record: &FixtureRecordV1) -> RecordState {
    match record.state {
        FixtureRecordStateV1::Complete => RecordState::Complete,
        FixtureRecordStateV1::SourceByteCapFragment => RecordState::SourceTruncated {
            reason: RecordFragmentReason::SourceByteCap,
        },
    }
}

fn expected_completeness(case: &ProductCorpusCaseV1) -> FetchCompleteness {
    match case.acquisition {
        FixtureAcquisitionV1::Complete => {
            FetchCompleteness::complete(CompletenessProof::InMemoryFixtureExhausted)
        }
        FixtureAcquisitionV1::PartialSourceByteCap => FetchCompleteness::partial(
            FetchPartialReasons::new(FetchPartialReason::SourceByteCap),
            None,
        ),
    }
}

fn build_ledger(case: &ProductCorpusCaseV1) -> EventLedger {
    let retrieval_id = RetrievalId::from_bytes([case.seed; 32]);
    let plan_id = PlanId::from_bytes([case.seed.wrapping_add(1); 32]);
    let plan_digest = PlanDigest::from_bytes([case.seed.wrapping_add(2); 32]);
    let source_identity = SourceIdentityDigest::from_bytes([case.seed.wrapping_add(3); 32]);
    let adapter = AdapterIdentity::new("hermetic-product-corpus", "v1").unwrap();
    let fetch_identity = FetchIdentity::new(retrieval_id, plan_id, plan_digest, adapter.clone());
    let envelope_identity =
        RawEnvelopeIdentityV1::new(retrieval_id, plan_id, plan_digest, adapter, source_identity);
    let mut builder =
        LedgerBuilder::new(fetch_identity.clone(), source_identity, SourceExactPolicy);
    let mut next_lane_sequences = BTreeMap::<LaneKey, u64>::new();
    let mut members = BTreeSet::new();
    let mut payload_bytes = 0_u64;
    let mut source_bytes = 0_u64;

    for (position, fixture) in case.records.iter().enumerate() {
        let record = record_bytes(fixture);
        payload_bytes = payload_bytes
            .checked_add(u64::try_from(record.payload_len()).unwrap())
            .unwrap();
        source_bytes = source_bytes
            .checked_add(u64::try_from(record.source_len()).unwrap())
            .unwrap();
        let member = SourceMember::new(fixture.member.to_vec()).unwrap();
        members.insert(member.clone());
        let lane = LaneKey::new(member, stream(fixture.stream));
        let next_lane_sequence = next_lane_sequences.entry(lane.clone()).or_default();
        let lane_sequence = *next_lane_sequence;
        *next_lane_sequence = next_lane_sequence.checked_add(1).unwrap();
        builder
            .accept(RawEnvelopeV1::new(
                envelope_identity.clone(),
                EnvelopeOrdering::new(
                    AcquisitionSequence::new(u64::try_from(position).unwrap()),
                    lane,
                    LaneSequence::new(lane_sequence),
                ),
                record,
                record_state(fixture),
            ))
            .unwrap();
    }

    let record_count = u64::try_from(case.records.len()).unwrap();
    let member_count = u64::try_from(members.len()).unwrap();
    builder
        .seal(
            FetchCompletion::new(
                fetch_identity,
                FetchTiming::new(UnixTimestampNanos::new(1), UnixTimestampNanos::new(2)),
                AcknowledgedCounts::new(record_count, payload_bytes, source_bytes),
                AttemptCounts::new(member_count, member_count),
                AttemptCounts::default(),
                FetchBoundaries::default(),
                [],
                AdapterOutcome::Finished,
                [],
                expected_completeness(case),
            )
            .unwrap(),
        )
        .unwrap()
}

fn exact_record_bytes(case: &ProductCorpusCaseV1) -> Vec<Vec<u8>> {
    case.records
        .iter()
        .map(|record| record_bytes(record).exact_bytes())
        .collect()
}

fn expansion_limit() -> ExpansionLimitV1 {
    ExpansionLimitV1::new(64, 1024 * 1024, 0, 0).unwrap()
}

fn assert_exhaustive_acquisition(ledger: &EventLedger, expected_records: usize) {
    let receipt = ledger.acquisition_receipt();
    assert_eq!(ledger.len(), expected_records);
    assert_eq!(receipt.acknowledged_count(), expected_records);
    assert_eq!(receipt.counts().acknowledged(), expected_records);
    assert_eq!(receipt.counts().source_exact, expected_records);
    assert_eq!(receipt.counts().post_policy, 0);
    assert_eq!(receipt.counts().omitted_by_policy, 0);
    for (entry, event) in receipt.entries().iter().zip(ledger.events()) {
        assert_eq!(entry.source_record_id(), event.source_record_id());
        assert_eq!(entry.outcome().persisted_event_id(), Some(event.id()));
    }
}

fn assert_no_structural_injection(text: &str) {
    assert_eq!(text.matches("STATUS\n").count(), 1);
    assert_eq!(text.matches("\nEVIDENCE\n").count(), 1);
    assert!(!text.contains("\nCORPUS_INJECTED_SECTION\n"));
    assert!(!text.contains("\n  acquisition: forged"));
}

#[test]
fn corpus_manifest_is_small_explicit_and_covers_the_required_shapes() {
    let expected_families = BTreeSet::from([
        DiagnosticFamilyV1::Python,
        DiagnosticFamilyV1::Jvm,
        DiagnosticFamilyV1::DotNet,
        DiagnosticFamilyV1::JavaScript,
        DiagnosticFamilyV1::Rust,
        DiagnosticFamilyV1::Go,
        DiagnosticFamilyV1::Compiler,
        DiagnosticFamilyV1::AssertionDiff,
        DiagnosticFamilyV1::Database,
        DiagnosticFamilyV1::Kubernetes,
    ]);
    let mut observed_families = BTreeSet::new();
    let mut exact_records = BTreeSet::new();
    let mut saw_duplicate = false;
    let mut saw_lf = false;
    let mut saw_crlf = false;
    let mut saw_no_final_lf = false;
    let mut saw_nul = false;
    let mut saw_invalid_utf8 = false;
    let mut saw_complete = false;
    let mut saw_partial = false;
    let mut total_records = 0_usize;
    let mut total_bytes = 0_usize;

    assert_eq!(PRODUCT_CORPUS_V1.len(), 3);
    for case in PRODUCT_CORPUS_V1 {
        assert!(!case.name.is_empty());
        assert!(!case.question.is_empty());
        assert!(case.focal_failure_index < case.records.len());
        assert!(case.records[case.focal_failure_index].family.is_some());
        match case.failure_placement {
            FailurePlacementV1::Head => assert_eq!(case.focal_failure_index, 0),
            FailurePlacementV1::Middle => {
                assert!(case.focal_failure_index > 0);
                assert!(case.focal_failure_index + 1 < case.records.len());
            }
            FailurePlacementV1::Tail => {
                assert_eq!(case.focal_failure_index + 1, case.records.len());
            }
        }
        match case.acquisition {
            FixtureAcquisitionV1::Complete => {
                saw_complete = true;
                assert!(
                    case.records
                        .iter()
                        .all(|record| record.state == FixtureRecordStateV1::Complete)
                );
            }
            FixtureAcquisitionV1::PartialSourceByteCap => {
                saw_partial = true;
                assert!(
                    case.records.iter().any(|record| {
                        record.state == FixtureRecordStateV1::SourceByteCapFragment
                    })
                );
            }
        }
        assert!(case.records.windows(3).any(|records| {
            records[0].stream == records[2].stream && records[0].stream != records[1].stream
        }));

        for record in case.records {
            if let Some(family) = record.family {
                observed_families.insert(family);
            }
            match record.terminator {
                FixtureTerminatorV1::None => saw_no_final_lf = true,
                FixtureTerminatorV1::Lf => saw_lf = true,
                FixtureTerminatorV1::CrLf => saw_crlf = true,
            }
            let bytes = record_bytes(record).exact_bytes();
            saw_nul |= bytes.contains(&0);
            saw_invalid_utf8 |= std::str::from_utf8(&bytes).is_err();
            saw_duplicate |= !exact_records.insert(bytes.clone());
            total_bytes = total_bytes.checked_add(bytes.len()).unwrap();
            total_records += 1;
        }
    }

    assert_eq!(observed_families, expected_families);
    assert_eq!(total_records, 21);
    assert!(total_bytes <= 200_000);
    assert!(saw_duplicate);
    assert!(saw_lf && saw_crlf && saw_no_final_lf);
    assert!(saw_nul && saw_invalid_utf8);
    assert!(saw_complete && saw_partial);
}

#[test]
fn corpus_is_deterministic_end_to_end_at_all_three_product_decisions() {
    for case in PRODUCT_CORPUS_V1 {
        let ledger = build_ledger(case);
        let expected_bytes = exact_record_bytes(case);
        let expected_acquisition = expected_completeness(case);
        let expected_receipt_id = ledger.acquisition_receipt_id();
        assert_exhaustive_acquisition(&ledger, case.records.len());
        let now = UnixTimestampNanos::new(10_000 + i128::from(case.seed));

        let passthrough_result_id = result(case.seed);
        let mut passthrough_product = MemoryProductV1::new();
        let passthrough = passthrough_product
            .create_deterministic_result_v1(
                passthrough_result_id,
                case.question,
                ledger.clone(),
                now,
                PASSTHROUGH_BUDGET,
            )
            .unwrap();
        let DeterministicProductDecisionV1::Passthrough(passthrough) = passthrough else {
            panic!("{} must fit exact passthrough", case.name);
        };
        let passthrough_brief = passthrough.artifact().brief();
        assert_eq!(
            passthrough_brief.status().acquisition(),
            &expected_acquisition
        );
        assert_eq!(
            passthrough_brief.coverage().acquisition_receipt_id(),
            expected_receipt_id
        );
        assert_eq!(
            passthrough_brief.coverage().acknowledged_records(),
            case.records.len()
        );
        assert_eq!(
            passthrough_brief
                .coverage()
                .presentation_counts()
                .persisted(),
            case.records.len()
        );
        assert_eq!(
            passthrough_brief
                .evidence()
                .iter()
                .map(|event| event.authorized_bytes().to_vec())
                .collect::<Vec<_>>(),
            expected_bytes
        );
        assert_no_structural_injection(passthrough.artifact().text());
        for (index, expected) in expected_bytes.iter().enumerate() {
            let expansion = passthrough_product
                .expand_alias(
                    AliasExpansionRequestV1::new(
                        passthrough_result_id,
                        EvidenceAliasV1::new(
                            passthrough_result_id,
                            u16::try_from(index + 1).unwrap(),
                        )
                        .unwrap(),
                        ExpansionRelationV1::Exact,
                        expansion_limit(),
                    ),
                    now,
                )
                .unwrap();
            assert_eq!(expansion.events().len(), 1);
            assert_eq!(expansion.events()[0].exact_bytes(), expected);
        }
        let mut passthrough_replay = MemoryProductV1::new();
        let replay = passthrough_replay
            .create_deterministic_result_v1(
                passthrough_result_id,
                case.question,
                ledger.clone(),
                now,
                PASSTHROUGH_BUDGET,
            )
            .unwrap();
        let DeterministicProductDecisionV1::Passthrough(replay) = replay else {
            panic!("{} passthrough replay drifted", case.name);
        };
        assert_eq!(passthrough.artifact().text(), replay.artifact().text());

        let compiled_result_id = result(case.seed.wrapping_add(20));
        let mut compiled_product = MemoryProductV1::new();
        let compiled = compiled_product
            .create_deterministic_result_v1(
                compiled_result_id,
                case.question,
                ledger.clone(),
                now,
                COMPILED_BUDGET,
            )
            .unwrap();
        let DeterministicProductDecisionV1::Compiled(compiled) = compiled else {
            panic!("{} must compile under the bounded budget", case.name);
        };
        let compiled_brief = compiled.artifact().brief();
        assert_eq!(compiled_brief.status().acquisition(), &expected_acquisition);
        assert_eq!(
            compiled_brief.coverage().acquisition_receipt_id(),
            expected_receipt_id
        );
        assert_eq!(
            compiled_brief.coverage().acknowledged_records(),
            case.records.len()
        );
        assert_eq!(
            compiled_brief.coverage().presentation_counts().persisted(),
            case.records.len()
        );
        assert_no_structural_injection(compiled.artifact().text());
        for (index, packet) in compiled_brief.evidence().iter().enumerate() {
            let expected_packet_bytes = packet
                .events()
                .iter()
                .map(|event| event.authorized_bytes().to_vec())
                .collect::<Vec<_>>();
            let expansion = compiled_product
                .expand_alias(
                    AliasExpansionRequestV1::new(
                        compiled_result_id,
                        EvidenceAliasV1::new(compiled_result_id, u16::try_from(index + 1).unwrap())
                            .unwrap(),
                        ExpansionRelationV1::Exact,
                        expansion_limit(),
                    ),
                    now,
                )
                .unwrap();
            assert_eq!(
                expansion
                    .events()
                    .iter()
                    .map(|event| event.exact_bytes().to_vec())
                    .collect::<Vec<_>>(),
                expected_packet_bytes
            );
        }
        let mut compiled_replay = MemoryProductV1::new();
        let replay = compiled_replay
            .create_deterministic_result_v1(
                compiled_result_id,
                case.question,
                ledger.clone(),
                now,
                COMPILED_BUDGET,
            )
            .unwrap();
        let DeterministicProductDecisionV1::Compiled(replay) = replay else {
            panic!("{} compiled replay drifted", case.name);
        };
        assert_eq!(compiled.artifact().text(), replay.artifact().text());

        let needs_more_result_id = result(case.seed.wrapping_add(40));
        let mut needs_more_product = MemoryProductV1::new();
        let needs_more = needs_more_product
            .create_deterministic_result_v1(
                needs_more_result_id,
                case.question,
                ledger.clone(),
                now,
                NEEDS_MORE_BUDGET,
            )
            .unwrap();
        let DeterministicProductDecisionV1::NeedsMore(needs_more) = needs_more else {
            panic!("{} must retain needs-more at zero budget", case.name);
        };
        assert_eq!(needs_more.acquisition(), &expected_acquisition);
        assert_eq!(needs_more.references().len(), case.records.len());
        for (reference, expected) in needs_more.references().iter().zip(&expected_bytes) {
            let expansion = needs_more_product
                .expand(
                    ExpansionRequestV1::new(
                        needs_more_result_id,
                        reference.id(),
                        ExpansionRelationV1::Exact,
                        expansion_limit(),
                    ),
                    now,
                )
                .unwrap();
            assert_eq!(expansion.events().len(), 1);
            assert_eq!(expansion.events()[0].exact_bytes(), expected);
        }
        assert_eq!(
            needs_more_product.expand_alias(
                AliasExpansionRequestV1::new(
                    needs_more_result_id,
                    EvidenceAliasV1::new(needs_more_result_id, 1).unwrap(),
                    ExpansionRelationV1::Exact,
                    expansion_limit(),
                ),
                now,
            ),
            Err(ResultStoreError::ReferenceUnavailable)
        );
        let expected_reason = needs_more.compiler_reason();
        let expected_reference_ids = needs_more
            .references()
            .iter()
            .map(|reference| reference.id())
            .collect::<Vec<_>>();
        let mut needs_more_replay = MemoryProductV1::new();
        let replay = needs_more_replay
            .create_deterministic_result_v1(
                needs_more_result_id,
                case.question,
                ledger,
                now,
                NEEDS_MORE_BUDGET,
            )
            .unwrap();
        let DeterministicProductDecisionV1::NeedsMore(replay) = replay else {
            panic!("{} needs-more replay drifted", case.name);
        };
        assert_eq!(replay.compiler_reason(), expected_reason);
        assert_eq!(
            replay
                .references()
                .iter()
                .map(|reference| reference.id())
                .collect::<Vec<_>>(),
            expected_reference_ids
        );
    }
}
