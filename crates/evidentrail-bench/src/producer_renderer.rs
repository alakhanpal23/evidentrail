use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_core::{EventId, EventLedger};
use evidentrail_schema::ArtifactDigest;
use sha2::{Digest as _, Sha256};

use crate::{
    FrozenProducerProposalUniverseDigestV1, FrozenProducerProposalUniverseV1,
    ProducerProposalAcquisitionBindingV1, ascii_byte_escape_v1_identity,
};

const PRODUCER_PROPOSAL_RENDERER_IDENTITY_DOMAIN_V1: &[u8] =
    b"evidentrail/bench/producer-proposal-renderer-identity/v1\0";
const PRODUCER_PROPOSAL_RENDERER_MANIFEST_V1: &[u8] = b"header=EVIDENTRAIL_PRODUCER_PROPOSAL_UNIVERSE_V1\0fixed-lf=true\0ascii=true\0hex=lowercase-fixed-64\0decimal=unsigned-no-leading-zero\0proposal-order=id-ascending\0member-order=event-id-ascending\0proposal-boundaries=explicit\0member-boundaries=explicit\0data=ascii_byte_escape_v1\0terminators=included-in-authorized-raw\0empty-universe=single-canonical-artifact\0";
const PRODUCER_PROPOSAL_RENDERER_CONTRACT_VERSION_V1: u64 = 1;

/// Absolute V1 ceiling for a canonical producer-proposal rendering.
pub const MAX_PRODUCER_PROPOSAL_RENDERED_BYTES_V1: usize = 16 * 1024 * 1024;

/// Closed identity of the canonical benchmark-neutral proposal renderer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProducerProposalRendererIdentityV1 {
    artifact_digest: ArtifactDigest,
    contract_version: u64,
}

impl ProducerProposalRendererIdentityV1 {
    #[must_use]
    pub const fn artifact_digest(self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn contract_version(self) -> u64 {
        self.contract_version
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        "canonical_producer_proposal_renderer_v1"
    }
}

impl fmt::Debug for ProducerProposalRendererIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProducerProposalRendererIdentityV1")
            .field("code", &self.code())
            .field("contract_version", &self.contract_version)
            .field("artifact_identity_present", &true)
            .finish()
    }
}

/// Identity of the exact V1 grammar and its pinned reversible byte encoding.
#[must_use]
pub fn canonical_producer_proposal_renderer_v1_identity() -> ProducerProposalRendererIdentityV1 {
    let byte_encoding = ascii_byte_escape_v1_identity();
    let mut hasher = Sha256::new();
    update_identity_field(&mut hasher, PRODUCER_PROPOSAL_RENDERER_IDENTITY_DOMAIN_V1);
    update_identity_field(&mut hasher, PRODUCER_PROPOSAL_RENDERER_MANIFEST_V1);
    update_identity_field(&mut hasher, byte_encoding.artifact_digest().as_bytes());
    update_identity_field(&mut hasher, &byte_encoding.contract_version().to_le_bytes());
    ProducerProposalRendererIdentityV1 {
        artifact_digest: ArtifactDigest::from_bytes(hasher.finalize().into()),
        contract_version: PRODUCER_PROPOSAL_RENDERER_CONTRACT_VERSION_V1,
    }
}

/// Caller-selected ceiling that can only narrow the immutable hard maximum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProducerProposalRenderLimitV1 {
    max_output_bytes: usize,
}

impl ProducerProposalRenderLimitV1 {
    pub fn try_new(max_output_bytes: usize) -> Result<Self, ProducerProposalRenderErrorV1> {
        if max_output_bytes == 0 {
            return Err(ProducerProposalRenderErrorV1::ZeroOutputLimit);
        }
        if max_output_bytes > MAX_PRODUCER_PROPOSAL_RENDERED_BYTES_V1 {
            return Err(ProducerProposalRenderErrorV1::OutputLimitExceedsHardMaximum);
        }
        Ok(Self { max_output_bytes })
    }

    #[must_use]
    pub const fn hard_maximum() -> Self {
        Self {
            max_output_bytes: MAX_PRODUCER_PROPOSAL_RENDERED_BYTES_V1,
        }
    }

    #[must_use]
    pub const fn max_output_bytes(self) -> usize {
        self.max_output_bytes
    }
}

/// Exact canonical ASCII artifact for one frozen proposal universe.
#[derive(PartialEq, Eq)]
pub struct CanonicalProducerProposalArtifactV1 {
    renderer: ProducerProposalRendererIdentityV1,
    universe_digest: FrozenProducerProposalUniverseDigestV1,
    acquisition_binding: ProducerProposalAcquisitionBindingV1,
    artifact_digest: ArtifactDigest,
    bytes: Vec<u8>,
    byte_count: u64,
    proposal_packet_count: u64,
    member_occurrence_count: u64,
    occurrence_source_bytes: u64,
    unique_member_event_count: u64,
    unique_member_source_bytes: u64,
}

impl CanonicalProducerProposalArtifactV1 {
    #[must_use]
    pub const fn renderer(&self) -> ProducerProposalRendererIdentityV1 {
        self.renderer
    }

    #[must_use]
    pub const fn universe_digest(&self) -> FrozenProducerProposalUniverseDigestV1 {
        self.universe_digest
    }

    #[must_use]
    pub const fn acquisition_binding(&self) -> ProducerProposalAcquisitionBindingV1 {
        self.acquisition_binding
    }

    /// Plain SHA-256 of [`Self::bytes`].
    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn byte_count(&self) -> u64 {
        self.byte_count
    }

    #[must_use]
    pub const fn proposal_packet_count(&self) -> u64 {
        self.proposal_packet_count
    }

    /// Proposal-member references, including repeated members across packets.
    #[must_use]
    pub const fn member_occurrence_count(&self) -> u64 {
        self.member_occurrence_count
    }

    /// Authorized raw bytes charged once for every proposal occurrence.
    #[must_use]
    pub const fn occurrence_source_bytes(&self) -> u64 {
        self.occurrence_source_bytes
    }

    #[must_use]
    pub const fn unique_member_event_count(&self) -> u64 {
        self.unique_member_event_count
    }

    #[must_use]
    pub const fn unique_member_source_bytes(&self) -> u64 {
        self.unique_member_source_bytes
    }

    pub(crate) fn has_valid_integrity(&self) -> bool {
        self.renderer == canonical_producer_proposal_renderer_v1_identity()
            && u64::try_from(self.bytes.len()) == Ok(self.byte_count)
            && self.artifact_digest.as_bytes() == &<[u8; 32]>::from(Sha256::digest(&self.bytes))
    }
}

impl fmt::Debug for CanonicalProducerProposalArtifactV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalProducerProposalArtifactV1")
            .field("renderer", &self.renderer)
            .field("universe_identity_present", &true)
            .field("acquisition_binding", &self.acquisition_binding)
            .field("artifact_identity_present", &true)
            .field("byte_count", &self.byte_count)
            .field("proposal_packet_count", &self.proposal_packet_count)
            .field("member_occurrence_count", &self.member_occurrence_count)
            .field("occurrence_source_bytes", &self.occurrence_source_bytes)
            .field("unique_member_event_count", &self.unique_member_event_count)
            .field(
                "unique_member_source_bytes",
                &self.unique_member_source_bytes,
            )
            .finish()
    }
}

/// Render the complete frozen proposal universe under a checked output bound.
///
/// The returned bytes contain no token count or measurement claim. A later
/// harness must tokenize this whole artifact exactly once.
pub fn render_canonical_producer_proposals_v1(
    ledger: &EventLedger,
    universe: &FrozenProducerProposalUniverseV1,
    limit: ProducerProposalRenderLimitV1,
) -> Result<CanonicalProducerProposalArtifactV1, ProducerProposalRenderErrorV1> {
    let acquisition_binding = ProducerProposalAcquisitionBindingV1::from_ledger(ledger);
    if universe.acquisition_binding() != acquisition_binding {
        return Err(ProducerProposalRenderErrorV1::AcquisitionBindingMismatch);
    }

    let accounting = validate_members_and_accounting(ledger, universe)?;
    let renderer = canonical_producer_proposal_renderer_v1_identity();
    let mut output = BoundedAscii::new(limit);
    output.push(b"EVIDENTRAIL_PRODUCER_PROPOSAL_UNIVERSE_V1\n")?;
    output.push(b"renderer_contract_version: 1\n")?;
    output.push(b"byte_encoding: ascii_byte_escape_v1\n")?;
    output.push_hex_field(b"universe_digest: ", universe.digest().as_bytes())?;
    output.push_hex_field(
        b"public_case_artifact_digest: ",
        universe.public_case_artifact_digest().as_bytes(),
    )?;
    output.push_hex_field(b"retrieval_id: ", universe.retrieval_id().as_bytes())?;
    output.push_hex_field(b"plan_id: ", universe.plan_id().as_bytes())?;
    output.push_hex_field(b"plan_digest: ", universe.plan_digest().as_bytes())?;
    output.push_hex_field(
        b"acquisition_receipt_id: ",
        universe.acquisition_receipt_id().as_bytes(),
    )?;
    output.push_hex_field(
        b"source_identity_digest: ",
        universe.source_identity_digest().as_bytes(),
    )?;
    output.push(b"acquisition_class: ")?;
    output.push(universe.acquisition_class().code().as_bytes())?;
    output.push(b"\n")?;
    output.push_hex_field(
        b"producer_method_artifact_digest: ",
        universe.producer().method_artifact_digest().as_bytes(),
    )?;
    output.push_hex_field(
        b"producer_config_artifact_digest: ",
        universe.producer().config_artifact_digest().as_bytes(),
    )?;
    output.push_hex_field(
        b"producer_receipt_artifact_digest: ",
        universe
            .producer()
            .producer_receipt_artifact_digest()
            .as_bytes(),
    )?;
    output.push_decimal_field(b"proposal_packet_count: ", accounting.proposal_packet_count)?;
    output.push_decimal_field(
        b"unique_member_event_count: ",
        accounting.unique_member_event_count,
    )?;
    output.push_decimal_field(
        b"unique_member_source_bytes: ",
        accounting.unique_member_source_bytes,
    )?;

    for proposal in universe.proposals() {
        output.push(b"BEGIN_PROPOSAL\n")?;
        output.push_hex_field(b"proposal_id: ", proposal.id().as_bytes())?;
        output.push_decimal_field(
            b"member_count: ",
            checked_u64(proposal.member_event_ids().len())?,
        )?;
        for event_id in proposal.member_event_ids() {
            let event = ledger
                .event(*event_id)
                .map_err(|_| ProducerProposalRenderErrorV1::UnknownMember { count: 1 })?;
            output.push(b"BEGIN_MEMBER\n")?;
            output.push_hex_field(b"event_id: ", event_id.as_bytes())?;
            output.push_decimal_field(b"source_byte_count: ", checked_u64(event.raw().len())?)?;
            output.push(b"data: ")?;
            output.push_escaped(event.raw())?;
            output.push(b"\nEND_MEMBER\n")?;
        }
        output.push(b"END_PROPOSAL\n")?;
    }
    output.push(b"END_EVIDENTRAIL_PRODUCER_PROPOSAL_UNIVERSE_V1\n")?;

    let bytes = output.finish();
    let byte_count = checked_u64(bytes.len())?;
    let artifact_digest = ArtifactDigest::from_bytes(Sha256::digest(&bytes).into());
    Ok(CanonicalProducerProposalArtifactV1 {
        renderer,
        universe_digest: universe.digest(),
        acquisition_binding,
        artifact_digest,
        bytes,
        byte_count,
        proposal_packet_count: accounting.proposal_packet_count,
        member_occurrence_count: accounting.member_occurrence_count,
        occurrence_source_bytes: accounting.occurrence_source_bytes,
        unique_member_event_count: accounting.unique_member_event_count,
        unique_member_source_bytes: accounting.unique_member_source_bytes,
    })
}

/// Contentless authority, accounting, allocation, and rendering failures.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProducerProposalRenderErrorV1 {
    ZeroOutputLimit,
    OutputLimitExceedsHardMaximum,
    AcquisitionBindingMismatch,
    UnknownMember { count: usize },
    ProposalAccountingMismatch,
    AccountingOverflow,
    OutputLimitExceeded,
    AllocationFailed,
}

impl ProducerProposalRenderErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ZeroOutputLimit => "EVIDENTRAIL_BENCH_PROPOSAL_RENDER_ZERO_OUTPUT_LIMIT",
            Self::OutputLimitExceedsHardMaximum => {
                "EVIDENTRAIL_BENCH_PROPOSAL_RENDER_LIMIT_EXCEEDS_HARD_MAXIMUM"
            }
            Self::AcquisitionBindingMismatch => {
                "EVIDENTRAIL_BENCH_PROPOSAL_RENDER_ACQUISITION_BINDING_MISMATCH"
            }
            Self::UnknownMember { .. } => "EVIDENTRAIL_BENCH_PROPOSAL_RENDER_UNKNOWN_MEMBER",
            Self::ProposalAccountingMismatch => {
                "EVIDENTRAIL_BENCH_PROPOSAL_RENDER_ACCOUNTING_MISMATCH"
            }
            Self::AccountingOverflow => "EVIDENTRAIL_BENCH_PROPOSAL_RENDER_ACCOUNTING_OVERFLOW",
            Self::OutputLimitExceeded => "EVIDENTRAIL_BENCH_PROPOSAL_RENDER_OUTPUT_LIMIT_EXCEEDED",
            Self::AllocationFailed => "EVIDENTRAIL_BENCH_PROPOSAL_RENDER_ALLOCATION_FAILED",
        }
    }
}

impl fmt::Debug for ProducerProposalRenderErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("ProducerProposalRenderErrorV1");
        debug.field("code", &self.code());
        if let Self::UnknownMember { count } = self {
            debug.field("count", count);
        }
        debug.finish()
    }
}

impl fmt::Display for ProducerProposalRenderErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ProducerProposalRenderErrorV1 {}

struct RenderAccounting {
    proposal_packet_count: u64,
    member_occurrence_count: u64,
    occurrence_source_bytes: u64,
    unique_member_event_count: u64,
    unique_member_source_bytes: u64,
}

fn validate_members_and_accounting(
    ledger: &EventLedger,
    universe: &FrozenProducerProposalUniverseV1,
) -> Result<RenderAccounting, ProducerProposalRenderErrorV1> {
    let mut unique_members = BTreeSet::<EventId>::new();
    let mut unknown_members = BTreeSet::<EventId>::new();
    let mut member_occurrence_count = 0_u64;
    let mut occurrence_source_bytes = 0_u64;
    for proposal in universe.proposals() {
        for event_id in proposal.member_event_ids() {
            member_occurrence_count = member_occurrence_count
                .checked_add(1)
                .ok_or(ProducerProposalRenderErrorV1::AccountingOverflow)?;
            unique_members.insert(*event_id);
            match ledger.event(*event_id) {
                Ok(event) => {
                    occurrence_source_bytes = occurrence_source_bytes
                        .checked_add(checked_u64(event.raw().len())?)
                        .ok_or(ProducerProposalRenderErrorV1::AccountingOverflow)?;
                }
                Err(_) => {
                    unknown_members.insert(*event_id);
                }
            }
        }
    }
    if !unknown_members.is_empty() {
        return Err(ProducerProposalRenderErrorV1::UnknownMember {
            count: unknown_members.len(),
        });
    }

    let proposal_packet_count = checked_u64(universe.proposals().len())?;
    let unique_member_event_count = checked_u64(unique_members.len())?;
    let mut unique_member_source_bytes = 0_u64;
    for event_id in unique_members {
        let event = ledger
            .event(event_id)
            .map_err(|_| ProducerProposalRenderErrorV1::UnknownMember { count: 1 })?;
        unique_member_source_bytes = unique_member_source_bytes
            .checked_add(checked_u64(event.raw().len())?)
            .ok_or(ProducerProposalRenderErrorV1::AccountingOverflow)?;
    }
    let frozen = universe.accounting();
    if proposal_packet_count != frozen.proposal_packet_count()
        || unique_member_event_count != frozen.unique_member_event_count()
        || unique_member_source_bytes != frozen.unique_member_source_bytes()
    {
        return Err(ProducerProposalRenderErrorV1::ProposalAccountingMismatch);
    }
    Ok(RenderAccounting {
        proposal_packet_count,
        member_occurrence_count,
        occurrence_source_bytes,
        unique_member_event_count,
        unique_member_source_bytes,
    })
}

struct BoundedAscii {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedAscii {
    fn new(limit: ProducerProposalRenderLimitV1) -> Self {
        Self {
            bytes: Vec::new(),
            limit: limit.max_output_bytes,
        }
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), ProducerProposalRenderErrorV1> {
        debug_assert!(bytes.is_ascii());
        self.reserve(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn push_decimal_field(
        &mut self,
        prefix: &[u8],
        value: u64,
    ) -> Result<(), ProducerProposalRenderErrorV1> {
        self.push(prefix)?;
        self.push(value.to_string().as_bytes())?;
        self.push(b"\n")
    }

    fn push_hex_field(
        &mut self,
        prefix: &[u8],
        bytes: &[u8; 32],
    ) -> Result<(), ProducerProposalRenderErrorV1> {
        self.push(prefix)?;
        self.reserve(64)?;
        for byte in bytes {
            self.bytes.push(lower_hex(byte >> 4));
            self.bytes.push(lower_hex(byte & 0x0f));
        }
        self.push(b"\n")
    }

    fn push_escaped(&mut self, raw: &[u8]) -> Result<(), ProducerProposalRenderErrorV1> {
        let mut encoded_length = 0_usize;
        for byte in raw {
            let width = match byte {
                b'\\' | b'\n' | b'\r' | b'\t' => 2,
                0x20..=0x7e => 1,
                _ => 4,
            };
            encoded_length = encoded_length
                .checked_add(width)
                .ok_or(ProducerProposalRenderErrorV1::AccountingOverflow)?;
        }
        self.reserve(encoded_length)?;
        for byte in raw {
            match byte {
                b'\\' => self.bytes.extend_from_slice(b"\\\\"),
                b'\n' => self.bytes.extend_from_slice(b"\\n"),
                b'\r' => self.bytes.extend_from_slice(b"\\r"),
                b'\t' => self.bytes.extend_from_slice(b"\\t"),
                0x20..=0x7e => self.bytes.push(*byte),
                _ => {
                    self.bytes.push(b'\\');
                    self.bytes.push(b'x');
                    self.bytes.push(lower_hex(byte >> 4));
                    self.bytes.push(lower_hex(byte & 0x0f));
                }
            }
        }
        Ok(())
    }

    fn reserve(&mut self, additional: usize) -> Result<(), ProducerProposalRenderErrorV1> {
        let required = self
            .bytes
            .len()
            .checked_add(additional)
            .ok_or(ProducerProposalRenderErrorV1::AccountingOverflow)?;
        if required > self.limit || required > MAX_PRODUCER_PROPOSAL_RENDERED_BYTES_V1 {
            return Err(ProducerProposalRenderErrorV1::OutputLimitExceeded);
        }
        self.bytes
            .try_reserve_exact(additional)
            .map_err(|_| ProducerProposalRenderErrorV1::AllocationFailed)
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

fn checked_u64(value: usize) -> Result<u64, ProducerProposalRenderErrorV1> {
    u64::try_from(value).map_err(|_| ProducerProposalRenderErrorV1::AccountingOverflow)
}

const fn lower_hex(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'a' + (value - 10),
    }
}

fn update_identity_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}
