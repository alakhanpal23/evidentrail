use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;

use evidentrail_bench::{
    FrozenProducerProposalUniverseV1, ProducerProposalAcquisitionBindingV1,
    ProducerProposalErrorV1, ProducerProposalIdV1, ProducerProposalIdentityV1,
    ProducerProposalPacketV1,
};
use evidentrail_schema::{ArtifactDigest, EventId};
use sha2::{Digest as _, Sha256};

use crate::{
    LegacyDrainPatternRepresentedV1, PreparedConstrainedPinnedDrainMatchedCaseV1,
    canonical_public_case_artifact_v1, canonical_public_run_manifest_artifact_v1,
    legacy_drain_full_membership_adapter_artifact_digest_v1,
    legacy_drain_full_membership_normalizer_artifact_digest_v1,
};

const FIRST_PARTY_METHOD_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/first-party-production-proposal-method/v1\0";
const FIRST_PARTY_CONFIG_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/first-party-production-proposal-config/v1\0";
const FIRST_PARTY_PACKET_ID_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/first-party-production-proposal-id/v1\0";
const DRAIN_METHOD_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/drain-posthoc-occurrence-producer-method/v1\0";
const DRAIN_CONFIG_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/drain-posthoc-occurrence-producer-config/v1\0";
const DRAIN_RECEIPT_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/drain-posthoc-occurrence-producer-receipt/v1\0";
const DRAIN_PACKET_ID_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/drain-posthoc-group-proposal-id/v1\0";
const BOUND_UNIVERSE_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/bound-label-free-producer-universe/v1\0";
const CONSTRAINED_PAIR_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/constrained-producer-universe-pair/v1\0";

/// Provenance semantics of one label-free producer proposal universe.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProducerUniverseBasisV1 {
    /// The exact budget-independent proposal packets emitted by the production
    /// three-lane producer before selection.
    FirstPartyProductionPreSelection,
    /// A post-hoc upper bound reconstructed from the separately executed,
    /// fully sampled Drain instrumentation arm.
    DrainPostHocCompleteOccurrenceUpperBound,
}

impl ProducerUniverseBasisV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::FirstPartyProductionPreSelection => {
                "first_party_production_preselection_proposal_union"
            }
            Self::DrainPostHocCompleteOccurrenceUpperBound => {
                "drain_posthoc_complete_occurrence_membership_upper_bound"
            }
        }
    }
}

impl fmt::Debug for ProducerUniverseBasisV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProducerUniverseBasisV1")
            .field("code", &self.code())
            .finish()
    }
}

/// One public, label-free producer universe plus the exact public receipt from
/// which the harness admitted it.
///
/// Event membership is occurrence-aware. It is not a claim that the final
/// representation showed source-exact bytes, and it contains no governed
/// annotation, score, measurement, or resource cap.
#[derive(Clone, PartialEq, Eq)]
pub struct BoundLabelFreeProducerUniverseV1 {
    artifact_digest: ArtifactDigest,
    basis: ProducerUniverseBasisV1,
    source_receipt_artifact_digest: ArtifactDigest,
    universe: FrozenProducerProposalUniverseV1,
    complete_ledger_partition: bool,
}

impl BoundLabelFreeProducerUniverseV1 {
    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn basis(&self) -> ProducerUniverseBasisV1 {
        self.basis
    }

    #[must_use]
    pub const fn source_receipt_artifact_digest(&self) -> ArtifactDigest {
        self.source_receipt_artifact_digest
    }

    #[must_use]
    pub const fn universe(&self) -> &FrozenProducerProposalUniverseV1 {
        &self.universe
    }

    #[must_use]
    pub const fn complete_ledger_partition(&self) -> bool {
        self.complete_ledger_partition
    }

    #[must_use]
    pub const fn nonexhaustive_ledger_proposal_union(&self) -> bool {
        !self.complete_ledger_partition
    }

    #[must_use]
    pub const fn original_preselection_producer_api(&self) -> bool {
        matches!(
            self.basis,
            ProducerUniverseBasisV1::FirstPartyProductionPreSelection
        )
    }

    #[must_use]
    pub const fn posthoc_complete_occurrence_upper_bound(&self) -> bool {
        matches!(
            self.basis,
            ProducerUniverseBasisV1::DrainPostHocCompleteOccurrenceUpperBound
        )
    }

    #[must_use]
    pub const fn source_exact_representation_claim(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn representation_recall_scoreable(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn contains_hidden_annotations(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn contains_measurements_or_caps(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn contains_score_or_winner(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn contains_downstream_vds_outcome(&self) -> bool {
        false
    }
}

impl fmt::Debug for BoundLabelFreeProducerUniverseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundLabelFreeProducerUniverseV1")
            .field("basis", &self.basis)
            .field("receipt_binding_present", &true)
            .field("universe", &self.universe)
            .field("complete_ledger_partition", &self.complete_ledger_partition)
            .field("source_exact_representation_claim", &false)
            .field("representation_recall_scoreable", &false)
            .field("contains_hidden_annotations", &false)
            .field("contains_measurements_or_caps", &false)
            .field("contains_score_or_winner", &false)
            .field("contains_downstream_vds_outcome", &false)
            .finish()
    }
}

/// Same-case, same-acquisition, label-free producer material for the
/// constrained first-party and pinned-Drain arms.
///
/// The Drain side is explicitly a post-hoc complete-occurrence upper bound. It
/// does not prove an original pre-ranking Drain API, hosted Evidentrail behavior, or
/// source-exact visibility of pattern members.
#[derive(Clone, PartialEq, Eq)]
pub struct ConstrainedProducerUniverseBridgeV1 {
    artifact_digest: ArtifactDigest,
    public_case_artifact_digest: ArtifactDigest,
    acquisition_binding: ProducerProposalAcquisitionBindingV1,
    first_party: BoundLabelFreeProducerUniverseV1,
    drain: BoundLabelFreeProducerUniverseV1,
}

impl ConstrainedProducerUniverseBridgeV1 {
    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn public_case_artifact_digest(&self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn acquisition_binding(&self) -> ProducerProposalAcquisitionBindingV1 {
        self.acquisition_binding
    }

    #[must_use]
    pub const fn first_party(&self) -> &BoundLabelFreeProducerUniverseV1 {
        &self.first_party
    }

    #[must_use]
    pub const fn drain(&self) -> &BoundLabelFreeProducerUniverseV1 {
        &self.drain
    }

    #[must_use]
    pub const fn contains_hidden_annotations(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn contains_measurements_or_caps(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn contains_score_or_winner(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn contains_downstream_vds_outcome(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn hosted_evidentrail_behavior_claim(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn drain_original_preselection_api_claim(&self) -> bool {
        false
    }
}

impl fmt::Debug for ConstrainedProducerUniverseBridgeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConstrainedProducerUniverseBridgeV1")
            .field("public_case_binding_present", &true)
            .field("shared_acquisition_binding_present", &true)
            .field("first_party", &self.first_party)
            .field("drain", &self.drain)
            .field("contains_hidden_annotations", &false)
            .field("contains_measurements_or_caps", &false)
            .field("contains_score_or_winner", &false)
            .field("contains_downstream_vds_outcome", &false)
            .field("hosted_evidentrail_behavior_claim", &false)
            .field("drain_original_preselection_api_claim", &false)
            .finish()
    }
}

/// Freeze both label-free proposal universes from one already validated
/// constrained preparation.
///
/// This API intentionally accepts no annotation, diagnostic requirement,
/// label, measurement, resource cap, or winner policy.
pub fn freeze_constrained_producer_universes_v1(
    prepared_case: &PreparedConstrainedPinnedDrainMatchedCaseV1,
) -> Result<ConstrainedProducerUniverseBridgeV1, ConstrainedProducerUniverseBridgeErrorV1> {
    let canonical_case = canonical_public_case_artifact_v1(prepared_case.public_case())
        .map_err(|_| ConstrainedProducerUniverseBridgeErrorV1::PublicCaseBindingMismatch)?;
    if canonical_case.artifact_digest() != prepared_case.public_case_artifact_digest() {
        return Err(ConstrainedProducerUniverseBridgeErrorV1::PublicCaseBindingMismatch);
    }

    let first_party = freeze_first_party_universe_v1(prepared_case)?;
    let drain = freeze_drain_universe_v1(prepared_case)?;
    if first_party.universe.public_case_artifact_digest()
        != prepared_case.public_case_artifact_digest()
        || drain.universe.public_case_artifact_digest()
            != prepared_case.public_case_artifact_digest()
        || first_party.universe.acquisition_binding() != drain.universe.acquisition_binding()
    {
        return Err(ConstrainedProducerUniverseBridgeErrorV1::SharedAcquisitionMismatch);
    }
    let acquisition_binding = first_party.universe.acquisition_binding();
    let artifact_digest = derive_pair_digest_v1(
        prepared_case.public_case_artifact_digest(),
        first_party.artifact_digest,
        drain.artifact_digest,
        first_party.universe.digest().as_bytes(),
        drain.universe.digest().as_bytes(),
    )?;
    Ok(ConstrainedProducerUniverseBridgeV1 {
        artifact_digest,
        public_case_artifact_digest: prepared_case.public_case_artifact_digest(),
        acquisition_binding,
        first_party,
        drain,
    })
}

fn freeze_first_party_universe_v1(
    prepared_case: &PreparedConstrainedPinnedDrainMatchedCaseV1,
) -> Result<BoundLabelFreeProducerUniverseV1, ConstrainedProducerUniverseBridgeErrorV1> {
    let validated = prepared_case.proposal_audit();
    let audit = validated.audit();
    if audit.code() != "selected" || audit.reason().is_some() {
        return Err(ConstrainedProducerUniverseBridgeErrorV1::FirstPartyAuditNotSelected);
    }
    let prepared = audit
        .prepared()
        .ok_or(ConstrainedProducerUniverseBridgeErrorV1::FirstPartyAuditNotSelected)?;
    let receipt = audit
        .receipt()
        .ok_or(ConstrainedProducerUniverseBridgeErrorV1::FirstPartyAuditNotSelected)?;
    if prepared.receipt() != receipt
        || receipt.input() != audit.input()
        || receipt.input().question_digest() != prepared_case.public_case().question_digest()
        || receipt.input().retrieval_id() != prepared_case.ledger().retrieval_id()
        || receipt.input().plan_id() != prepared_case.ledger().plan_id()
        || receipt.input().plan_digest() != prepared_case.ledger().plan_digest()
        || receipt.input().source_identity_digest()
            != prepared_case.ledger().source_identity_digest()
        || receipt.input().acquisition_receipt_id()
            != prepared_case.ledger().acquisition_receipt_id()
        || receipt.accounting().proposal_packet_count() != validated.proposal_packet_count()
        || receipt.accounting().proposal_unique_member_event_count()
            != validated.proposal_unique_member_event_count()
        || receipt.accounting().proposal_member_source_bytes()
            != validated.proposal_member_source_bytes()
    {
        return Err(ConstrainedProducerUniverseBridgeErrorV1::FirstPartyAuditBindingMismatch);
    }

    let input = receipt.input();
    let method_artifact_digest = derive_digest_v1(
        FIRST_PARTY_METHOD_DOMAIN_V1,
        &[
            input.candidate_config_digest().as_bytes(),
            input.compiler_config_digest().as_bytes(),
        ],
    )?;
    let config_artifact_digest = derive_digest_v1(
        FIRST_PARTY_CONFIG_DOMAIN_V1,
        &[
            input.digest().as_bytes(),
            input.adapter_identity_digest().as_bytes(),
            input.candidate_config_digest().as_bytes(),
            input.compiler_config_digest().as_bytes(),
            input.renderer_digest().as_bytes(),
            input.tokenizer_digest().as_bytes(),
            input.tokenizer_bound_contract_digest().as_bytes(),
        ],
    )?;
    let producer = ProducerProposalIdentityV1::new(
        method_artifact_digest,
        config_artifact_digest,
        receipt.digest(),
    );
    let mut packets = Vec::with_capacity(prepared.proposal_packets().len());
    for packet in prepared.proposal_packets() {
        let opaque_id = derive_proposal_id_v1(
            FIRST_PARTY_PACKET_ID_DOMAIN_V1,
            &[
                method_artifact_digest.as_bytes(),
                config_artifact_digest.as_bytes(),
                receipt.digest().as_bytes(),
                packet.id().as_bytes(),
            ],
        )?;
        packets.push(
            ProducerProposalPacketV1::try_new(opaque_id, packet.event_ids().iter().copied())
                .map_err(ConstrainedProducerUniverseBridgeErrorV1::ProducerUniverse)?,
        );
    }
    let universe = FrozenProducerProposalUniverseV1::try_new(
        prepared_case.public_case_artifact_digest(),
        prepared_case.public_case(),
        prepared_case.ledger(),
        producer,
        packets,
    )
    .map_err(ConstrainedProducerUniverseBridgeErrorV1::ProducerUniverse)?;
    let accounting = universe.accounting();
    if accounting.proposal_packet_count() != validated.proposal_packet_count()
        || accounting.unique_member_event_count() != validated.proposal_unique_member_event_count()
        || accounting.unique_member_source_bytes() != validated.proposal_member_source_bytes()
        || accounting.unique_member_event_count()
            >= validated.exhaustive_unique_member_event_count()
        || validated.exhaustive_unique_member_event_count()
            != checked_count_v1(prepared_case.ledger().len())?
    {
        return Err(ConstrainedProducerUniverseBridgeErrorV1::FirstPartyAccountingMismatch);
    }
    bind_universe_v1(
        ProducerUniverseBasisV1::FirstPartyProductionPreSelection,
        validated.artifact_digest(),
        universe,
        false,
    )
}

fn freeze_drain_universe_v1(
    prepared_case: &PreparedConstrainedPinnedDrainMatchedCaseV1,
) -> Result<BoundLabelFreeProducerUniverseV1, ConstrainedProducerUniverseBridgeErrorV1> {
    let full = prepared_case.drain_full_membership();
    let invocation = prepared_case.drain_invocation();
    let canonical_run =
        canonical_public_run_manifest_artifact_v1(prepared_case.drain_manifest())
            .map_err(|_| ConstrainedProducerUniverseBridgeErrorV1::DrainArtifactBindingMismatch)?;
    let retained_map = prepared_case
        .first_party_case_input()
        .source_record_map()
        .legacy_drain_retained_records(prepared_case.first_party_case_input().stdin())
        .map_err(|_| ConstrainedProducerUniverseBridgeErrorV1::DrainArtifactBindingMismatch)?;
    if full.public_case_artifact_digest() != prepared_case.public_case_artifact_digest()
        || full.run_manifest_artifact_digest() != canonical_run.artifact_digest()
        || full.invocation_digest() != invocation.digest()
        || full.stdin_artifact_digest()
            != prepared_case
                .first_party_case_input()
                .stdin()
                .artifact_digest()
        || full.source_record_map_artifact_digest()
            != prepared_case
                .first_party_case_input()
                .source_record_map()
                .map_artifact_digest()
        || full.retained_record_map_artifact_digest() != retained_map.map_artifact_digest()
        || full.adapter_artifact_digest()
            != legacy_drain_full_membership_adapter_artifact_digest_v1()
        || full.normalizer_artifact_digest()
            != legacy_drain_full_membership_normalizer_artifact_digest_v1()
    {
        return Err(ConstrainedProducerUniverseBridgeErrorV1::DrainArtifactBindingMismatch);
    }

    let memberships = full
        .pattern_memberships()
        .iter()
        .map(|membership| DrainMembershipFactV1::from(*membership))
        .collect::<Vec<_>>();
    validate_drain_occurrences_v1(prepared_case, &retained_map, &memberships)?;
    let groups = group_drain_memberships_v1(&memberships)?;

    let run_identity = prepared_case.drain_manifest().identity();
    let adapter_revision = invocation.program().adapter_revision().unwrap_or("");
    let method_artifact_digest = derive_digest_v1(
        DRAIN_METHOD_DOMAIN_V1,
        &[
            prepared_case.drain_target_class().code().as_bytes(),
            run_identity.system_artifact_digest().as_bytes(),
            run_identity.build_artifact_digest().as_bytes(),
            invocation
                .program()
                .executable_build_artifact_digest()
                .as_bytes(),
            adapter_revision.as_bytes(),
            full.adapter_artifact_digest().as_bytes(),
        ],
    )?;
    let config_artifact_digest = derive_digest_v1(
        DRAIN_CONFIG_DOMAIN_V1,
        &[
            method_artifact_digest.as_bytes(),
            full.adapter_artifact_digest().as_bytes(),
            full.normalizer_artifact_digest().as_bytes(),
            full.invocation_digest().as_bytes(),
            full.run_manifest_artifact_digest().as_bytes(),
            full.source_record_map_artifact_digest().as_bytes(),
            full.retained_record_map_artifact_digest().as_bytes(),
            &full.sample_cap().to_le_bytes(),
        ],
    )?;
    let producer_receipt_artifact_digest = derive_digest_v1(
        DRAIN_RECEIPT_DOMAIN_V1,
        &[
            full.artifact_digest().as_bytes(),
            full.raw_stdout_artifact_digest().as_bytes(),
            full.raw_stderr_artifact_digest().as_bytes(),
            &full.raw_stdout_byte_count().to_le_bytes(),
            &full.raw_stderr_byte_count().to_le_bytes(),
        ],
    )?;
    let producer = ProducerProposalIdentityV1::new(
        method_artifact_digest,
        config_artifact_digest,
        producer_receipt_artifact_digest,
    );

    let mut packets = Vec::with_capacity(groups.len());
    for (group_id, group) in groups {
        let opaque_id = derive_proposal_id_v1(
            DRAIN_PACKET_ID_DOMAIN_V1,
            &[
                method_artifact_digest.as_bytes(),
                config_artifact_digest.as_bytes(),
                producer_receipt_artifact_digest.as_bytes(),
                &group_id.to_le_bytes(),
                group.pattern_artifact_digest.as_bytes(),
            ],
        )?;
        packets.push(
            ProducerProposalPacketV1::try_new(opaque_id, group.event_ids)
                .map_err(ConstrainedProducerUniverseBridgeErrorV1::ProducerUniverse)?,
        );
    }
    let universe = FrozenProducerProposalUniverseV1::try_new(
        prepared_case.public_case_artifact_digest(),
        prepared_case.public_case(),
        prepared_case.ledger(),
        producer,
        packets,
    )
    .map_err(ConstrainedProducerUniverseBridgeErrorV1::ProducerUniverse)?;
    let accounting = universe.accounting();
    if accounting.unique_member_event_count() != checked_count_v1(prepared_case.ledger().len())?
        || accounting.unique_member_source_bytes() != full.charged_candidate_source_bytes()
        || full.charged_candidate_event_count() != prepared_case.ledger().len()
        || full.sample_cap() != checked_count_v1(prepared_case.ledger().len())?
    {
        return Err(ConstrainedProducerUniverseBridgeErrorV1::DrainAccountingMismatch);
    }
    bind_universe_v1(
        ProducerUniverseBasisV1::DrainPostHocCompleteOccurrenceUpperBound,
        full.artifact_digest(),
        universe,
        true,
    )
}

fn validate_drain_occurrences_v1(
    prepared_case: &PreparedConstrainedPinnedDrainMatchedCaseV1,
    retained_map: &crate::LegacyDrainRetainedRecordMapV1,
    memberships: &[DrainMembershipFactV1],
) -> Result<(), ConstrainedProducerUniverseBridgeErrorV1> {
    let full = prepared_case.drain_full_membership();
    if retained_map.records().len() != prepared_case.ledger().len()
        || memberships.len() != retained_map.records().len()
        || full.transformed_samples().len() != memberships.len()
    {
        return Err(ConstrainedProducerUniverseBridgeErrorV1::DrainLedgerPartitionMismatch);
    }
    let mut by_retained_index = BTreeMap::new();
    for membership in memberships {
        if by_retained_index
            .insert(membership.retained_index, *membership)
            .is_some()
        {
            return Err(ConstrainedProducerUniverseBridgeErrorV1::DrainOccurrenceMismatch);
        }
    }
    let mut event_ids = BTreeSet::new();
    for (position, retained) in retained_map.records().iter().enumerate() {
        let retained_index = checked_count_v1(position)?;
        let membership = by_retained_index
            .get(&retained_index)
            .ok_or(ConstrainedProducerUniverseBridgeErrorV1::DrainOccurrenceMismatch)?;
        let transformed = full
            .transformed_samples()
            .get(position)
            .ok_or(ConstrainedProducerUniverseBridgeErrorV1::DrainOccurrenceMismatch)?;
        if membership.source_record_ordinal != retained.source_record_ordinal()
            || membership.event_id != retained.event_id()
            || transformed.retained_index() != retained_index
            || transformed.source_record_ordinal() != retained.source_record_ordinal()
            || transformed.event_id() != retained.event_id()
            || transformed.group_id() != membership.group_id
            || !event_ids.insert(membership.event_id)
        {
            return Err(ConstrainedProducerUniverseBridgeErrorV1::DrainOccurrenceMismatch);
        }
    }
    let ledger_ids = prepared_case
        .ledger()
        .events()
        .iter()
        .map(|event| event.id())
        .collect::<BTreeSet<_>>();
    if event_ids != ledger_ids {
        return Err(ConstrainedProducerUniverseBridgeErrorV1::DrainLedgerPartitionMismatch);
    }
    let exact_source_bytes =
        prepared_case
            .ledger()
            .events()
            .iter()
            .try_fold(0_u64, |total, event| {
                total
                    .checked_add(u64::try_from(event.raw().len()).map_err(|_| {
                        ConstrainedProducerUniverseBridgeErrorV1::AccountingOverflow
                    })?)
                    .ok_or(ConstrainedProducerUniverseBridgeErrorV1::AccountingOverflow)
            })?;
    if exact_source_bytes != full.charged_candidate_source_bytes() {
        return Err(ConstrainedProducerUniverseBridgeErrorV1::DrainAccountingMismatch);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct DrainMembershipFactV1 {
    retained_index: u64,
    source_record_ordinal: u64,
    event_id: EventId,
    group_id: u64,
    pattern_artifact_digest: ArtifactDigest,
}

impl From<LegacyDrainPatternRepresentedV1> for DrainMembershipFactV1 {
    fn from(membership: LegacyDrainPatternRepresentedV1) -> Self {
        Self {
            retained_index: membership.retained_index(),
            source_record_ordinal: membership.source_record_ordinal(),
            event_id: membership.event_id(),
            group_id: membership.group_id(),
            pattern_artifact_digest: membership.group_pattern_artifact_digest(),
        }
    }
}

struct DrainGroupV1 {
    pattern_artifact_digest: ArtifactDigest,
    event_ids: Vec<EventId>,
}

fn group_drain_memberships_v1(
    memberships: &[DrainMembershipFactV1],
) -> Result<BTreeMap<u64, DrainGroupV1>, ConstrainedProducerUniverseBridgeErrorV1> {
    let mut groups = BTreeMap::<u64, DrainGroupV1>::new();
    let mut seen_event_ids = BTreeSet::new();
    for membership in memberships {
        if !seen_event_ids.insert(membership.event_id) {
            return Err(ConstrainedProducerUniverseBridgeErrorV1::DrainOccurrenceMismatch);
        }
        match groups.get_mut(&membership.group_id) {
            Some(group) => {
                if group.pattern_artifact_digest != membership.pattern_artifact_digest {
                    return Err(
                        ConstrainedProducerUniverseBridgeErrorV1::DrainGroupPatternMismatch,
                    );
                }
                group.event_ids.push(membership.event_id);
            }
            None => {
                groups.insert(
                    membership.group_id,
                    DrainGroupV1 {
                        pattern_artifact_digest: membership.pattern_artifact_digest,
                        event_ids: vec![membership.event_id],
                    },
                );
            }
        }
    }
    if groups.is_empty() {
        return Err(ConstrainedProducerUniverseBridgeErrorV1::DrainLedgerPartitionMismatch);
    }
    Ok(groups)
}

fn bind_universe_v1(
    basis: ProducerUniverseBasisV1,
    source_receipt_artifact_digest: ArtifactDigest,
    universe: FrozenProducerProposalUniverseV1,
    complete_ledger_partition: bool,
) -> Result<BoundLabelFreeProducerUniverseV1, ConstrainedProducerUniverseBridgeErrorV1> {
    let artifact_digest = derive_bound_universe_digest_v1(
        basis,
        source_receipt_artifact_digest,
        universe.digest().as_bytes(),
        complete_ledger_partition,
    )?;
    Ok(BoundLabelFreeProducerUniverseV1 {
        artifact_digest,
        basis,
        source_receipt_artifact_digest,
        universe,
        complete_ledger_partition,
    })
}

fn derive_bound_universe_digest_v1(
    basis: ProducerUniverseBasisV1,
    source_receipt_artifact_digest: ArtifactDigest,
    universe_digest: &[u8],
    complete_ledger_partition: bool,
) -> Result<ArtifactDigest, ConstrainedProducerUniverseBridgeErrorV1> {
    derive_digest_v1(
        BOUND_UNIVERSE_DOMAIN_V1,
        &[
            basis.code().as_bytes(),
            source_receipt_artifact_digest.as_bytes(),
            universe_digest,
            &[u8::from(complete_ledger_partition)],
        ],
    )
}

fn derive_pair_digest_v1(
    public_case_artifact_digest: ArtifactDigest,
    first_party_bound_artifact_digest: ArtifactDigest,
    drain_bound_artifact_digest: ArtifactDigest,
    first_party_universe_digest: &[u8],
    drain_universe_digest: &[u8],
) -> Result<ArtifactDigest, ConstrainedProducerUniverseBridgeErrorV1> {
    derive_digest_v1(
        CONSTRAINED_PAIR_DOMAIN_V1,
        &[
            public_case_artifact_digest.as_bytes(),
            first_party_bound_artifact_digest.as_bytes(),
            drain_bound_artifact_digest.as_bytes(),
            first_party_universe_digest,
            drain_universe_digest,
        ],
    )
}

fn derive_proposal_id_v1(
    domain: &[u8],
    fields: &[&[u8]],
) -> Result<ProducerProposalIdV1, ConstrainedProducerUniverseBridgeErrorV1> {
    Ok(ProducerProposalIdV1::from_bytes(
        *derive_digest_v1(domain, fields)?.as_bytes(),
    ))
}

fn derive_digest_v1(
    domain: &[u8],
    fields: &[&[u8]],
) -> Result<ArtifactDigest, ConstrainedProducerUniverseBridgeErrorV1> {
    let mut hasher = Sha256::new();
    update_field_v1(&mut hasher, domain)?;
    for field in fields {
        update_field_v1(&mut hasher, field)?;
    }
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

fn update_field_v1(
    hasher: &mut Sha256,
    field: &[u8],
) -> Result<(), ConstrainedProducerUniverseBridgeErrorV1> {
    let length = u64::try_from(field.len())
        .map_err(|_| ConstrainedProducerUniverseBridgeErrorV1::DigestConstructionOverflow)?;
    hasher.update(length.to_le_bytes());
    hasher.update(field);
    Ok(())
}

fn checked_count_v1(count: usize) -> Result<u64, ConstrainedProducerUniverseBridgeErrorV1> {
    u64::try_from(count).map_err(|_| ConstrainedProducerUniverseBridgeErrorV1::AccountingOverflow)
}

/// Contentless public-construction failures for the label-free bridge.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConstrainedProducerUniverseBridgeErrorV1 {
    PublicCaseBindingMismatch,
    FirstPartyAuditNotSelected,
    FirstPartyAuditBindingMismatch,
    FirstPartyAccountingMismatch,
    DrainArtifactBindingMismatch,
    DrainOccurrenceMismatch,
    DrainGroupPatternMismatch,
    DrainLedgerPartitionMismatch,
    DrainAccountingMismatch,
    SharedAcquisitionMismatch,
    ProducerUniverse(ProducerProposalErrorV1),
    AccountingOverflow,
    DigestConstructionOverflow,
}

impl ConstrainedProducerUniverseBridgeErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PublicCaseBindingMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_PRODUCER_PUBLIC_CASE_BINDING_MISMATCH"
            }
            Self::FirstPartyAuditNotSelected => {
                "EVIDENTRAIL_BENCH_HARNESS_PRODUCER_FIRST_PARTY_AUDIT_NOT_SELECTED"
            }
            Self::FirstPartyAuditBindingMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_PRODUCER_FIRST_PARTY_AUDIT_BINDING_MISMATCH"
            }
            Self::FirstPartyAccountingMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_PRODUCER_FIRST_PARTY_ACCOUNTING_MISMATCH"
            }
            Self::DrainArtifactBindingMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_PRODUCER_DRAIN_ARTIFACT_BINDING_MISMATCH"
            }
            Self::DrainOccurrenceMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_PRODUCER_DRAIN_OCCURRENCE_MISMATCH"
            }
            Self::DrainGroupPatternMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_PRODUCER_DRAIN_GROUP_PATTERN_MISMATCH"
            }
            Self::DrainLedgerPartitionMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_PRODUCER_DRAIN_LEDGER_PARTITION_MISMATCH"
            }
            Self::DrainAccountingMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_PRODUCER_DRAIN_ACCOUNTING_MISMATCH"
            }
            Self::SharedAcquisitionMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_PRODUCER_SHARED_ACQUISITION_MISMATCH"
            }
            Self::ProducerUniverse(error) => error.code(),
            Self::AccountingOverflow => "EVIDENTRAIL_BENCH_HARNESS_PRODUCER_ACCOUNTING_OVERFLOW",
            Self::DigestConstructionOverflow => {
                "EVIDENTRAIL_BENCH_HARNESS_PRODUCER_DIGEST_CONSTRUCTION_OVERFLOW"
            }
        }
    }
}

impl fmt::Debug for ConstrainedProducerUniverseBridgeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConstrainedProducerUniverseBridgeErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for ConstrainedProducerUniverseBridgeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ConstrainedProducerUniverseBridgeErrorV1 {}

#[cfg(test)]
mod tests {
    use super::{
        ConstrainedProducerUniverseBridgeErrorV1, DRAIN_CONFIG_DOMAIN_V1, DRAIN_METHOD_DOMAIN_V1,
        DRAIN_PACKET_ID_DOMAIN_V1, DRAIN_RECEIPT_DOMAIN_V1, DrainMembershipFactV1,
        ProducerUniverseBasisV1, derive_bound_universe_digest_v1, derive_digest_v1,
        derive_pair_digest_v1, derive_proposal_id_v1, group_drain_memberships_v1,
    };
    use evidentrail_schema::{ArtifactDigest, EventId};

    fn fact(event: u8, group_id: u64, pattern: u8) -> DrainMembershipFactV1 {
        DrainMembershipFactV1 {
            retained_index: u64::from(event),
            source_record_ordinal: u64::from(event),
            event_id: EventId::from_bytes([event; 32]),
            group_id,
            pattern_artifact_digest: ArtifactDigest::from_bytes([pattern; 32]),
        }
    }

    #[test]
    fn drain_grouping_rejects_inconsistent_patterns_and_duplicate_occurrences() {
        assert!(matches!(
            group_drain_memberships_v1(&[fact(1, 7, 3), fact(2, 7, 4)]),
            Err(ConstrainedProducerUniverseBridgeErrorV1::DrainGroupPatternMismatch)
        ));
        assert!(matches!(
            group_drain_memberships_v1(&[fact(1, 7, 3), fact(1, 8, 4)]),
            Err(ConstrainedProducerUniverseBridgeErrorV1::DrainOccurrenceMismatch)
        ));
    }

    #[test]
    fn opaque_proposal_identity_is_deterministic_and_mutation_sensitive() {
        let receipt = ArtifactDigest::from_bytes([0x11; 32]);
        let pattern = ArtifactDigest::from_bytes([0x22; 32]);
        let baseline = derive_proposal_id_v1(
            DRAIN_PACKET_ID_DOMAIN_V1,
            &[receipt.as_bytes(), &7_u64.to_le_bytes(), pattern.as_bytes()],
        )
        .unwrap();
        let repeated = derive_proposal_id_v1(
            DRAIN_PACKET_ID_DOMAIN_V1,
            &[receipt.as_bytes(), &7_u64.to_le_bytes(), pattern.as_bytes()],
        )
        .unwrap();
        assert_eq!(baseline, repeated);
        for fields in [
            vec![
                ArtifactDigest::from_bytes([0x12; 32]).as_bytes().to_vec(),
                7_u64.to_le_bytes().to_vec(),
                pattern.as_bytes().to_vec(),
            ],
            vec![
                receipt.as_bytes().to_vec(),
                8_u64.to_le_bytes().to_vec(),
                pattern.as_bytes().to_vec(),
            ],
            vec![
                receipt.as_bytes().to_vec(),
                7_u64.to_le_bytes().to_vec(),
                ArtifactDigest::from_bytes([0x23; 32]).as_bytes().to_vec(),
            ],
        ] {
            let references = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
            assert_ne!(
                baseline,
                derive_proposal_id_v1(DRAIN_PACKET_ID_DOMAIN_V1, &references).unwrap()
            );
        }
    }

    #[test]
    fn producer_and_pair_digests_bind_receipts_config_and_membership() {
        for domain in [
            DRAIN_METHOD_DOMAIN_V1,
            DRAIN_CONFIG_DOMAIN_V1,
            DRAIN_RECEIPT_DOMAIN_V1,
        ] {
            let baseline = derive_digest_v1(domain, &[b"method", b"config", b"receipt"]).unwrap();
            assert_eq!(
                baseline,
                derive_digest_v1(domain, &[b"method", b"config", b"receipt"]).unwrap()
            );
            for changed in [
                [b"changed".as_slice(), b"config", b"receipt"],
                [b"method".as_slice(), b"changed", b"receipt"],
                [b"method".as_slice(), b"config", b"changed"],
            ] {
                assert_ne!(baseline, derive_digest_v1(domain, &changed).unwrap());
            }
        }

        let receipt = ArtifactDigest::from_bytes([0x31; 32]);
        let universe = [0x32; 32];
        let bound = derive_bound_universe_digest_v1(
            ProducerUniverseBasisV1::DrainPostHocCompleteOccurrenceUpperBound,
            receipt,
            &universe,
            true,
        )
        .unwrap();
        let changed_receipt_bound = derive_bound_universe_digest_v1(
            ProducerUniverseBasisV1::DrainPostHocCompleteOccurrenceUpperBound,
            ArtifactDigest::from_bytes([0x33; 32]),
            &universe,
            true,
        )
        .unwrap();
        let changed_membership_bound = derive_bound_universe_digest_v1(
            ProducerUniverseBasisV1::DrainPostHocCompleteOccurrenceUpperBound,
            receipt,
            &[0x34; 32],
            true,
        )
        .unwrap();
        assert_ne!(bound, changed_receipt_bound);
        assert_ne!(bound, changed_membership_bound);

        let case = ArtifactDigest::from_bytes([0x35; 32]);
        let first = ArtifactDigest::from_bytes([0x36; 32]);
        let pair = derive_pair_digest_v1(case, first, bound, &[0x37; 32], &universe).unwrap();
        assert_ne!(
            pair,
            derive_pair_digest_v1(case, first, changed_receipt_bound, &[0x37; 32], &universe)
                .unwrap()
        );
        assert_ne!(
            pair,
            derive_pair_digest_v1(case, first, bound, &[0x37; 32], &[0x38; 32]).unwrap()
        );
    }
}
