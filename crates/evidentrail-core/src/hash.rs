use evidentrail_schema::{
    AcquisitionOutcome, AcquisitionReceipt, AcquisitionReceiptId, BlockId, ContentHash, EventId,
    EvidenceReferenceId, ExactnessBasis, FramingPolicy, PresentationReceiptId,
    ProviderAttestationsV1, QuestionDigest, RawEnvelopeV1, RecordState, RetrievalId,
    SourceRecordId, SourceStream,
};
use sha2::{Digest, Sha256};

/// Hash only bytes that the policy boundary authorized for persistence.
pub(crate) fn authorized_content_hash(authorized: &[u8]) -> ContentHash {
    ContentHash::from_bytes(Sha256::digest(authorized).into())
}

/// Derive the canonical identity of exact, potentially non-UTF-8 question
/// bytes. The bytes are length-framed under a dedicated domain and are not
/// retained by this operation.
#[must_use]
pub fn derive_question_digest_v1(question_bytes: &[u8]) -> QuestionDigest {
    let mut hasher = domain_hasher(b"evidentrail/question/v1");
    update_field(&mut hasher, question_bytes);
    QuestionDigest::from_bytes(finish(hasher))
}

/// Derive a result-local source identity without observing payload bytes.
pub(crate) fn source_record_id(envelope: &RawEnvelopeV1) -> SourceRecordId {
    let mut hasher = domain_hasher(b"evidentrail/source-record/v1");
    update_field(&mut hasher, &envelope.contract_version().to_le_bytes());
    let identity = envelope.identity();
    update_field(&mut hasher, identity.retrieval_id().as_bytes());
    update_field(&mut hasher, identity.plan_id().as_bytes());
    update_field(&mut hasher, identity.plan_digest().as_bytes());
    update_field(&mut hasher, identity.adapter().kind().as_bytes());
    update_field(&mut hasher, identity.adapter().version().as_bytes());
    update_field(&mut hasher, identity.source_identity_digest().as_bytes());

    let ordering = envelope.ordering();
    update_field(
        &mut hasher,
        &ordering.acquisition_sequence().get().to_le_bytes(),
    );
    update_field(&mut hasher, ordering.lane().member().as_bytes());
    hash_stream(&mut hasher, ordering.lane().stream());
    update_field(&mut hasher, &ordering.lane_sequence().get().to_le_bytes());
    update_optional_field(
        &mut hasher,
        envelope.native_event_id().map(|value| value.as_bytes()),
    );
    update_optional_field(&mut hasher, envelope.cursor().map(|value| value.as_bytes()));
    hash_record_state(&mut hasher, envelope.state());
    SourceRecordId::from_bytes(finish(hasher))
}

fn hash_persisted_provider_attestations(
    hasher: &mut Sha256,
    attestations: &ProviderAttestationsV1,
) {
    // Preserve the original V2 event identity for the explicit default-none
    // path. Attestations are committed only after policy authorized a
    // persisted event; source-position and omitted receipt identities never
    // commit this material.
    if attestations.is_empty() {
        return;
    }
    update_field(
        hasher,
        b"evidentrail/authorized-event/provider-attestations/v1",
    );
    let count = u64::try_from(attestations.len())
        .expect("provider attestation representation bounds fit u64");
    update_field(hasher, &count.to_le_bytes());
    for attestation in attestations.entries() {
        update_field(hasher, attestation.scope_digest().as_bytes());
        update_field(hasher, attestation.relation_kind().code().as_bytes());
        update_field(hasher, attestation.origin().code().as_bytes());
        update_field(hasher, attestation.value().as_bytes());
    }
}

fn hash_stream(hasher: &mut Sha256, stream: &SourceStream) {
    update_field(hasher, stream.code().as_bytes());
    if let SourceStream::OtherVersioned { version, code } = stream {
        update_field(hasher, &version.to_le_bytes());
        update_field(hasher, &code.to_le_bytes());
    }
}

fn hash_record_state(hasher: &mut Sha256, state: RecordState) {
    update_field(hasher, state.code().as_bytes());
    match state {
        RecordState::Complete => {}
        RecordState::SourceTruncated { reason } | RecordState::AdapterFragment { reason } => {
            update_field(hasher, reason.code().as_bytes());
        }
    }
}

pub(crate) fn event_id(
    retrieval_id: RetrievalId,
    source_record_id: SourceRecordId,
    content_hash: ContentHash,
    exactness_basis: ExactnessBasis,
    provider_attestations: &ProviderAttestationsV1,
) -> EventId {
    let mut hasher = domain_hasher(b"evidentrail/authorized-event/v2");
    update_field(&mut hasher, retrieval_id.as_bytes());
    update_field(&mut hasher, source_record_id.as_bytes());
    update_field(&mut hasher, content_hash.as_bytes());
    update_field(&mut hasher, exactness_basis.code().as_bytes());
    if let ExactnessBasis::PostPolicy {
        policy_digest,
        transformation_receipt_id,
    } = exactness_basis
    {
        update_field(&mut hasher, policy_digest.as_bytes());
        update_field(&mut hasher, transformation_receipt_id.as_bytes());
    }
    hash_persisted_provider_attestations(&mut hasher, provider_attestations);
    EventId::from_bytes(finish(hasher))
}

/// Derive the canonical persisted identity for a source-exact envelope without
/// retaining it in an [`EventLedger`](crate::EventLedger).
///
/// Streaming acquisition uses this narrow helper to write exact bytes and
/// fixed-width metadata directly to a packed store. The ordinary
/// [`LedgerBuilder`](crate::LedgerBuilder) path derives the identical value.
#[must_use]
pub fn derive_source_exact_event_id_v1(envelope: &RawEnvelopeV1) -> EventId {
    event_id(
        envelope.identity().retrieval_id(),
        source_record_id(envelope),
        authorized_content_hash(&envelope.record().exact_bytes()),
        ExactnessBasis::SourceExact,
        envelope.provider_attestations(),
    )
}

pub(crate) fn block_id(
    retrieval_id: RetrievalId,
    member_ids: &[EventId],
    framing_policy: &FramingPolicy,
) -> BlockId {
    let mut hasher = domain_hasher(b"evidentrail/event-block/v1");
    update_field(&mut hasher, retrieval_id.as_bytes());
    let member_count =
        u64::try_from(member_ids.len()).expect("member counts fit into the u64 hash format");
    update_field(&mut hasher, &member_count.to_le_bytes());
    for member_id in member_ids {
        update_field(&mut hasher, member_id.as_bytes());
    }
    update_field(&mut hasher, framing_policy.policy());
    update_field(&mut hasher, framing_policy.version());
    BlockId::from_bytes(finish(hasher))
}

pub(crate) fn presentation_receipt_hasher(retrieval_id: RetrievalId) -> Sha256 {
    let mut hasher = domain_hasher(b"evidentrail/presentation-receipt/v1");
    update_field(&mut hasher, retrieval_id.as_bytes());
    hasher
}

pub(crate) fn acquisition_receipt_id(receipt: &AcquisitionReceipt) -> AcquisitionReceiptId {
    let mut hasher = domain_hasher(b"evidentrail/acquisition-receipt/v1");
    update_field(&mut hasher, receipt.retrieval_id().as_bytes());
    for entry in receipt.entries() {
        update_field(&mut hasher, entry.source_record_id().as_bytes());
        update_field(&mut hasher, entry.outcome().code().as_bytes());
        match entry.outcome() {
            AcquisitionOutcome::Persisted {
                event_id,
                exactness_basis,
            } => {
                update_field(&mut hasher, event_id.as_bytes());
                if let ExactnessBasis::PostPolicy {
                    policy_digest,
                    transformation_receipt_id,
                } = exactness_basis
                {
                    update_field(&mut hasher, policy_digest.as_bytes());
                    update_field(&mut hasher, transformation_receipt_id.as_bytes());
                }
            }
            AcquisitionOutcome::OmittedByPolicy { policy_digest } => {
                update_field(&mut hasher, policy_digest.as_bytes());
            }
        }
    }
    AcquisitionReceiptId::from_bytes(finish(hasher))
}

pub(crate) fn finish_presentation_receipt(hasher: Sha256) -> PresentationReceiptId {
    PresentationReceiptId::from_bytes(finish(hasher))
}

pub(crate) fn finish_evidence_reference(hasher: Sha256) -> EvidenceReferenceId {
    EvidenceReferenceId::from_bytes(finish(hasher))
}

pub(crate) fn domain_hasher(domain: &[u8]) -> Sha256 {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, domain);
    hasher
}

pub(crate) fn update_field(hasher: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).expect("field lengths fit into u64");
    hasher.update(length.to_le_bytes());
    hasher.update(value);
}

pub(crate) fn update_optional_field(hasher: &mut Sha256, value: Option<&[u8]>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            update_field(hasher, value);
        }
        None => {
            hasher.update([0]);
        }
    }
}

fn finish(hasher: Sha256) -> [u8; 32] {
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_provider_attestations_preserve_the_frozen_v2_event_identity() {
        let identity = event_id(
            RetrievalId::from_bytes([0x11; 32]),
            SourceRecordId::from_bytes([0x22; 32]),
            ContentHash::from_bytes([0x33; 32]),
            ExactnessBasis::SourceExact,
            &ProviderAttestationsV1::default(),
        );

        assert_eq!(
            identity.to_string(),
            "evt_53f9f1d4fec95a89d3ee5d3a3d861472a92705cb0db326439b8d72b0eca7b44c"
        );
    }

    #[test]
    fn question_digest_is_exact_deterministic_and_domain_separated() {
        let question = [0xff, 0x00, b'?', b'\n'];
        let digest = derive_question_digest_v1(&question);

        assert_eq!(digest, derive_question_digest_v1(&question));
        assert_ne!(digest, derive_question_digest_v1(&question[..3]));
        assert_eq!(
            digest.to_string(),
            "question_sha256_3bf950c7ed48f5aa5389b21b647355b7c7974e7d19cb723511aaae105d129533"
        );

        let mut other_domain = domain_hasher(b"evidentrail/question/v2");
        update_field(&mut other_domain, &question);
        assert_ne!(digest.as_bytes(), &finish(other_domain));
    }
}
