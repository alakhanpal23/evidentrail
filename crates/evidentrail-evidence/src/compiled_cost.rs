use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use evidentrail_core::{EventId, EventLedger};
use evidentrail_schema::bounds::{
    JSON_SAFE_INTEGER_MAX, MAX_LOG_BRIEF_EVIDENCE_PACKETS, MAX_WIRE_OBJECT_BYTES,
};
use evidentrail_schema::{
    AcquisitionReceiptId, ArtifactDigest, PlanDigest, PresentationCounts, ResultId,
};
use evidentrail_select::{
    ComposableCostModelV1, ComposablePacketCostV1, MAX_PACKET_EVENTS_V1, MAX_SELECTION_PACKETS_V1,
    PacketIdV1, ProductionFacetKindV1, ReservedFixedOverheadV1, SelectionV1,
};
use sha2::{Digest, Sha256};

use super::compiled::{
    CompiledEventRenderV1, compiled_renderer_digest_v1, render_compiled_coverage_v1,
    render_compiled_header_v1, render_compiled_packet_v1,
};
use super::{BoundedText, PinnedTokenizer, TokenizerFailure};

const UTF8_BYTE_TOKENIZER_MANIFEST_V1: &[u8] = b"evidentrail-evidence/tokenizer/utf8-byte/v1\0token-unit=one-utf8-encoded-byte\0whole-render-only=true";
const ASCII_RENDER_TOKEN_BOUND_MANIFEST_V1: &[u8] = b"evidentrail-evidence/token-bound/ascii-render-bytes/v1\0precondition=render-is-ascii\0claim=whole-render-token-count-le-rendered-byte-count\0fragment-additivity=not-claimed";
const COMPILED_ASCII_BOUND_COST_MODEL_DOMAIN_V1: &[u8] =
    b"evidentrail/evidence/compiled-ascii-byte-bound-cost-model/v1\0";
const MAX_FORCING_CODE_V1: &str = "mandatory_validated_identifier";

/// Pinned tokenizer whose token unit is exactly one UTF-8 encoded byte.
///
/// The compiled V1 renderer emits ASCII only, so this tokenizer's whole-render
/// token count equals the rendered ASCII byte count. It is deliberately not a
/// BPE tokenizer and makes no fragment-additivity claim for other tokenizers.
#[derive(Default)]
pub struct Utf8ByteTokenizerV1 {
    whole_render_calls: AtomicU64,
}

impl Utf8ByteTokenizerV1 {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            whole_render_calls: AtomicU64::new(0),
        }
    }

    #[must_use]
    pub fn ascii_render_bound_contract(&self) -> AsciiRenderTokenBoundContractV1 {
        canonical_ascii_render_bound_contract_v1()
    }

    /// Process-local observation count for verifying that orchestration invokes
    /// this tokenizer only on complete rendered artifacts. It has no bearing on
    /// token values or artifact identity.
    #[must_use]
    pub fn whole_render_calls(&self) -> u64 {
        self.whole_render_calls.load(Ordering::Relaxed)
    }
}

impl PinnedTokenizer for Utf8ByteTokenizerV1 {
    fn digest(&self) -> ArtifactDigest {
        utf8_byte_tokenizer_digest_v1()
    }

    fn count_tokens(&self, complete_render: &str) -> Result<u64, TokenizerFailure> {
        self.whole_render_calls
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |calls| {
                calls.checked_add(1)
            })
            .map_err(|_| TokenizerFailure)?;
        u64::try_from(complete_render.len()).map_err(|_| TokenizerFailure)
    }
}

impl fmt::Debug for Utf8ByteTokenizerV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Utf8ByteTokenizerV1")
    }
}

/// Frozen executable-artifact identity for [`Utf8ByteTokenizerV1`].
#[must_use]
pub fn utf8_byte_tokenizer_digest_v1() -> ArtifactDigest {
    ArtifactDigest::from_bytes(Sha256::digest(UTF8_BYTE_TOKENIZER_MANIFEST_V1).into())
}

/// Closed V1 contract binding one tokenizer artifact to the conservative
/// whole-ASCII-render inequality `tokens <= UTF-8 bytes`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AsciiRenderTokenBoundContractV1 {
    tokenizer_digest: ArtifactDigest,
    contract_digest: ArtifactDigest,
}

impl AsciiRenderTokenBoundContractV1 {
    #[must_use]
    pub const fn tokenizer_digest(self) -> ArtifactDigest {
        self.tokenizer_digest
    }

    #[must_use]
    pub const fn contract_digest(self) -> ArtifactDigest {
        self.contract_digest
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        "ascii_whole_render_tokens_le_utf8_bytes_v1"
    }
}

impl fmt::Debug for AsciiRenderTokenBoundContractV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AsciiRenderTokenBoundContractV1")
            .field("code", &self.code())
            .finish()
    }
}

fn canonical_ascii_render_bound_contract_v1() -> AsciiRenderTokenBoundContractV1 {
    AsciiRenderTokenBoundContractV1 {
        tokenizer_digest: utf8_byte_tokenizer_digest_v1(),
        contract_digest: ArtifactDigest::from_bytes(
            Sha256::digest(ASCII_RENDER_TOKEN_BOUND_MANIFEST_V1).into(),
        ),
    }
}

fn compiled_ascii_bound_cost_model_v1(
    contract: AsciiRenderTokenBoundContractV1,
) -> ComposableCostModelV1 {
    let mut hasher = Sha256::new();
    hasher.update(COMPILED_ASCII_BOUND_COST_MODEL_DOMAIN_V1);
    update_digest_field(&mut hasher, compiled_renderer_digest_v1().as_bytes());
    update_digest_field(&mut hasher, contract.tokenizer_digest().as_bytes());
    update_digest_field(&mut hasher, contract.contract_digest().as_bytes());
    ComposableCostModelV1::new(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

fn update_digest_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(
        u64::try_from(bytes.len())
            .expect("digest field length fits u64")
            .to_le_bytes(),
    );
    hasher.update(bytes);
}

/// Canonical membership material used before an [`evidentrail_select::IntactPacketV1`]
/// can receive a renderer-derived cost.
#[derive(Clone, PartialEq, Eq)]
pub struct CompiledPacketMembershipV1 {
    packet_id: PacketIdV1,
    event_ids: Vec<EventId>,
}

impl CompiledPacketMembershipV1 {
    pub fn new(
        packet_id: PacketIdV1,
        event_ids: impl IntoIterator<Item = EventId>,
    ) -> Result<Self, CompiledCostCertificationError> {
        let mut event_ids = event_ids.into_iter().collect::<Vec<_>>();
        if event_ids.is_empty() {
            return Err(CompiledCostCertificationError::EmptyPacketMembership);
        }
        if event_ids.len() > MAX_PACKET_EVENTS_V1 {
            return Err(CompiledCostCertificationError::TooManyPacketEvents);
        }
        event_ids.sort_unstable();
        if event_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CompiledCostCertificationError::DuplicateEventInPacket);
        }
        Ok(Self {
            packet_id,
            event_ids,
        })
    }

    #[must_use]
    pub const fn packet_id(&self) -> PacketIdV1 {
        self.packet_id
    }

    #[must_use]
    pub fn event_ids(&self) -> &[EventId] {
        &self.event_ids
    }
}

impl fmt::Debug for CompiledPacketMembershipV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledPacketMembershipV1")
            .field("event_count", &self.event_ids.len())
            .finish()
    }
}

/// One packet's exact membership plus its conservative renderer-derived bound.
#[derive(Clone, PartialEq, Eq)]
pub struct CompiledPacketCostBoundV1 {
    packet_id: PacketIdV1,
    event_ids: Vec<EventId>,
    cost: ComposablePacketCostV1,
}

impl CompiledPacketCostBoundV1 {
    #[must_use]
    pub const fn packet_id(&self) -> PacketIdV1 {
        self.packet_id
    }

    #[must_use]
    pub fn event_ids(&self) -> &[EventId] {
        &self.event_ids
    }

    #[must_use]
    pub const fn cost(&self) -> ComposablePacketCostV1 {
        self.cost
    }
}

impl fmt::Debug for CompiledPacketCostBoundV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledPacketCostBoundV1")
            .field("event_count", &self.event_ids.len())
            .field("upper_bound_tokens", &self.cost.upper_bound_tokens())
            .finish()
    }
}

/// Ledger-, result-, renderer-, tokenizer-, and membership-bound additive
/// certificate. It can be independently checked against a selected subset.
#[derive(Clone, PartialEq, Eq)]
pub struct CompiledCostCertificationV1 {
    acquisition_receipt_id: AcquisitionReceiptId,
    plan_digest: PlanDigest,
    result_id: ResultId,
    tokenizer_bound: AsciiRenderTokenBoundContractV1,
    cost_model: ComposableCostModelV1,
    fixed_overhead: ReservedFixedOverheadV1,
    packet_bounds: Vec<CompiledPacketCostBoundV1>,
    universe_upper_bound: u64,
}

impl CompiledCostCertificationV1 {
    #[must_use]
    pub const fn tokenizer_bound(&self) -> AsciiRenderTokenBoundContractV1 {
        self.tokenizer_bound
    }

    #[must_use]
    pub const fn cost_model(&self) -> ComposableCostModelV1 {
        self.cost_model
    }

    #[must_use]
    pub const fn fixed_overhead(&self) -> ReservedFixedOverheadV1 {
        self.fixed_overhead
    }

    #[must_use]
    pub fn packet_bounds(&self) -> &[CompiledPacketCostBoundV1] {
        &self.packet_bounds
    }

    #[must_use]
    pub const fn universe_upper_bound(&self) -> u64 {
        self.universe_upper_bound
    }

    pub fn packet_cost(
        &self,
        packet_id: PacketIdV1,
        exact_event_ids: &[EventId],
    ) -> Result<ComposablePacketCostV1, CompiledCostCertificationError> {
        let entry = self
            .packet_bounds
            .binary_search_by_key(&packet_id, CompiledPacketCostBoundV1::packet_id)
            .ok()
            .and_then(|index| self.packet_bounds.get(index))
            .ok_or(CompiledCostCertificationError::UnknownPacketId)?;
        if entry.event_ids() != exact_event_ids {
            return Err(CompiledCostCertificationError::PacketMembershipMismatch);
        }
        Ok(entry.cost())
    }

    pub fn verify_selection(
        &self,
        ledger: &EventLedger,
        result_id: ResultId,
        selection: &SelectionV1,
        tokenizer: &Utf8ByteTokenizerV1,
    ) -> Result<(), CompiledCostCertificationError> {
        validate_supported_tokenizer(tokenizer, self.tokenizer_bound)?;
        if ledger.acquisition_receipt_id() != self.acquisition_receipt_id
            || ledger.plan_digest() != self.plan_digest
        {
            return Err(CompiledCostCertificationError::LedgerBindingMismatch);
        }
        if result_id != self.result_id {
            return Err(CompiledCostCertificationError::ResultBindingMismatch);
        }
        if selection.reserved_fixed_overhead() != self.fixed_overhead {
            return Err(CompiledCostCertificationError::FixedOverheadMismatch);
        }
        let mut selected_packet_ids = BTreeSet::new();
        for selected in selection.packets() {
            let packet = selected.packet();
            if !selected_packet_ids.insert(packet.id()) {
                return Err(CompiledCostCertificationError::DuplicatePacketId);
            }
            let expected = self.packet_cost(packet.id(), packet.event_ids())?;
            if packet.composable_token_upper_bound() != expected {
                return Err(CompiledCostCertificationError::PacketCostMismatch);
            }
        }
        Ok(())
    }
}

impl fmt::Debug for CompiledCostCertificationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledCostCertificationV1")
            .field("tokenizer_bound", &self.tokenizer_bound)
            .field("fixed_overhead", &self.fixed_overhead)
            .field("packet_count", &self.packet_bounds.len())
            .field("universe_upper_bound", &self.universe_upper_bound)
            .finish()
    }
}

/// Compute additive byte/token bounds from the exact V1 compiled renderer.
///
/// No tokenizer fragments are counted. The only token inequality used is the
/// explicit whole-ASCII-render contract, and final rendering still invokes the
/// pinned tokenizer exactly once over the complete artifact. The concrete
/// tokenizer parameter deliberately seals this certified path against a
/// caller-defined [`PinnedTokenizer`] that merely self-asserts the built-in
/// artifact digest.
pub fn certify_compiled_costs_v1(
    ledger: &EventLedger,
    result_id: ResultId,
    memberships: impl IntoIterator<Item = CompiledPacketMembershipV1>,
    tokenizer: &Utf8ByteTokenizerV1,
) -> Result<CompiledCostCertificationV1, CompiledCostCertificationError> {
    certify_compiled_costs_with_contract_v1(
        ledger,
        result_id,
        memberships,
        tokenizer,
        tokenizer.ascii_render_bound_contract(),
    )
}

fn certify_compiled_costs_with_contract_v1(
    ledger: &EventLedger,
    result_id: ResultId,
    memberships: impl IntoIterator<Item = CompiledPacketMembershipV1>,
    tokenizer: &Utf8ByteTokenizerV1,
    tokenizer_bound: AsciiRenderTokenBoundContractV1,
) -> Result<CompiledCostCertificationV1, CompiledCostCertificationError> {
    validate_supported_tokenizer(tokenizer, tokenizer_bound)?;
    let memberships = memberships.into_iter().collect::<Vec<_>>();
    if memberships.is_empty() {
        return Err(CompiledCostCertificationError::EmptyPacketSet);
    }
    if memberships.len() > MAX_SELECTION_PACKETS_V1 {
        return Err(CompiledCostCertificationError::TooManyPackets);
    }

    let mut packet_ids = BTreeSet::new();
    let mut selected_events = BTreeSet::new();
    for membership in &memberships {
        if !packet_ids.insert(membership.packet_id()) {
            return Err(CompiledCostCertificationError::DuplicatePacketId);
        }
        for event_id in membership.event_ids() {
            if !ledger.contains(*event_id) {
                return Err(CompiledCostCertificationError::UnknownEvent);
            }
            if !selected_events.insert(*event_id) {
                return Err(CompiledCostCertificationError::OverlappingEvent);
            }
        }
    }

    let cost_model = compiled_ascii_bound_cost_model_v1(tokenizer_bound);
    let fixed_overhead = fixed_render_bound(ledger, result_id, cost_model)?;
    let mut packet_bounds = Vec::with_capacity(memberships.len());
    let mut universe_upper_bound = fixed_overhead.upper_bound_tokens();
    for membership in memberships {
        let cost = packet_render_bound(ledger, &membership, cost_model)?;
        universe_upper_bound = universe_upper_bound
            .checked_add(cost.upper_bound_tokens())
            .ok_or(CompiledCostCertificationError::ArithmeticOverflow)?;
        if universe_upper_bound > JSON_SAFE_INTEGER_MAX {
            return Err(CompiledCostCertificationError::CostOutOfRange);
        }
        packet_bounds.push(CompiledPacketCostBoundV1 {
            packet_id: membership.packet_id,
            event_ids: membership.event_ids,
            cost,
        });
    }
    packet_bounds.sort_unstable_by_key(CompiledPacketCostBoundV1::packet_id);

    Ok(CompiledCostCertificationV1 {
        acquisition_receipt_id: ledger.acquisition_receipt_id(),
        plan_digest: ledger.plan_digest(),
        result_id,
        tokenizer_bound,
        cost_model,
        fixed_overhead,
        packet_bounds,
        universe_upper_bound,
    })
}

fn validate_supported_tokenizer(
    tokenizer: &Utf8ByteTokenizerV1,
    tokenizer_bound: AsciiRenderTokenBoundContractV1,
) -> Result<(), CompiledCostCertificationError> {
    let expected = canonical_ascii_render_bound_contract_v1();
    if tokenizer_bound != expected || tokenizer.digest() != expected.tokenizer_digest() {
        return Err(CompiledCostCertificationError::UnsupportedTokenizerBound);
    }
    Ok(())
}

fn fixed_render_bound(
    ledger: &EventLedger,
    result_id: ResultId,
    cost_model: ComposableCostModelV1,
) -> Result<ReservedFixedOverheadV1, CompiledCostCertificationError> {
    let mut text = BoundedText::new(MAX_WIRE_OBJECT_BYTES);
    render_compiled_header_v1(&mut text, ledger, result_id)
        .map_err(|_| CompiledCostCertificationError::FixedRenderLimitExceeded)?;
    render_compiled_coverage_v1(
        &mut text,
        ledger,
        PresentationCounts {
            shown_verbatim: ledger.len(),
            pattern_represented: 0,
            retained_raw: ledger.len(),
        },
    )
    .map_err(|_| CompiledCostCertificationError::FixedRenderLimitExceeded)?;
    let text = text.finish();
    if !text.is_ascii() {
        return Err(CompiledCostCertificationError::NonAsciiRendererInvariant);
    }
    let bytes = u64::try_from(text.len())
        .map_err(|_| CompiledCostCertificationError::ArithmeticOverflow)?;
    ReservedFixedOverheadV1::new(cost_model, bytes)
        .map_err(|_| CompiledCostCertificationError::CostOutOfRange)
}

fn packet_render_bound(
    ledger: &EventLedger,
    membership: &CompiledPacketMembershipV1,
    cost_model: ComposableCostModelV1,
) -> Result<ComposablePacketCostV1, CompiledCostCertificationError> {
    let member_set = membership
        .event_ids()
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let events = ledger
        .events()
        .iter()
        .filter(|event| member_set.contains(&event.id()))
        .map(|event| CompiledEventRenderV1 {
            exactness_code: event.exactness_basis().code(),
            stream_code: event.lane().stream().code(),
            authorized_bytes: event.raw(),
        })
        .collect::<Vec<_>>();
    if events.len() != membership.event_ids().len() {
        return Err(CompiledCostCertificationError::UnknownEvent);
    }

    let maximum_selected_ordinal = MAX_LOG_BRIEF_EVIDENCE_PACKETS
        .checked_sub(1)
        .ok_or(CompiledCostCertificationError::ArithmeticOverflow)?;
    let maximum_role_codes = ProductionFacetKindV1::ALL_V1
        .iter()
        .map(|kind| kind.code())
        .collect::<Vec<_>>();
    let mut text = BoundedText::new(MAX_WIRE_OBJECT_BYTES);
    render_compiled_packet_v1(
        &mut text,
        maximum_selected_ordinal,
        MAX_FORCING_CODE_V1,
        u64::MAX,
        u64::MAX,
        &maximum_role_codes,
        &events,
    )
    .map_err(|_| CompiledCostCertificationError::PacketRenderLimitExceeded)?;
    let text = text.finish();
    if !text.is_ascii() {
        return Err(CompiledCostCertificationError::NonAsciiRendererInvariant);
    }
    let bytes = u64::try_from(text.len())
        .map_err(|_| CompiledCostCertificationError::ArithmeticOverflow)?;
    ComposablePacketCostV1::new(cost_model, bytes)
        .map_err(|_| CompiledCostCertificationError::CostOutOfRange)
}

/// Stable contentless failure from membership validation or bound generation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CompiledCostCertificationError {
    EmptyPacketSet,
    TooManyPackets,
    EmptyPacketMembership,
    TooManyPacketEvents,
    DuplicateEventInPacket,
    DuplicatePacketId,
    UnknownPacketId,
    UnknownEvent,
    OverlappingEvent,
    PacketMembershipMismatch,
    PacketCostMismatch,
    FixedOverheadMismatch,
    LedgerBindingMismatch,
    ResultBindingMismatch,
    UnsupportedTokenizerBound,
    FixedRenderLimitExceeded,
    PacketRenderLimitExceeded,
    NonAsciiRendererInvariant,
    ArithmeticOverflow,
    CostOutOfRange,
}

impl CompiledCostCertificationError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyPacketSet => "EVIDENTRAIL_COMPILED_COST_EMPTY_PACKET_SET",
            Self::TooManyPackets => "EVIDENTRAIL_COMPILED_COST_TOO_MANY_PACKETS",
            Self::EmptyPacketMembership => "EVIDENTRAIL_COMPILED_COST_EMPTY_PACKET_MEMBERSHIP",
            Self::TooManyPacketEvents => "EVIDENTRAIL_COMPILED_COST_TOO_MANY_PACKET_EVENTS",
            Self::DuplicateEventInPacket => "EVIDENTRAIL_COMPILED_COST_DUPLICATE_EVENT_IN_PACKET",
            Self::DuplicatePacketId => "EVIDENTRAIL_COMPILED_COST_DUPLICATE_PACKET_ID",
            Self::UnknownPacketId => "EVIDENTRAIL_COMPILED_COST_UNKNOWN_PACKET_ID",
            Self::UnknownEvent => "EVIDENTRAIL_COMPILED_COST_UNKNOWN_EVENT",
            Self::OverlappingEvent => "EVIDENTRAIL_COMPILED_COST_OVERLAPPING_EVENT",
            Self::PacketMembershipMismatch => "EVIDENTRAIL_COMPILED_COST_PACKET_MEMBERSHIP_MISMATCH",
            Self::PacketCostMismatch => "EVIDENTRAIL_COMPILED_COST_PACKET_COST_MISMATCH",
            Self::FixedOverheadMismatch => "EVIDENTRAIL_COMPILED_COST_FIXED_OVERHEAD_MISMATCH",
            Self::LedgerBindingMismatch => "EVIDENTRAIL_COMPILED_COST_LEDGER_BINDING_MISMATCH",
            Self::ResultBindingMismatch => "EVIDENTRAIL_COMPILED_COST_RESULT_BINDING_MISMATCH",
            Self::UnsupportedTokenizerBound => "EVIDENTRAIL_COMPILED_COST_UNSUPPORTED_TOKENIZER_BOUND",
            Self::FixedRenderLimitExceeded => "EVIDENTRAIL_COMPILED_COST_FIXED_RENDER_LIMIT_EXCEEDED",
            Self::PacketRenderLimitExceeded => "EVIDENTRAIL_COMPILED_COST_PACKET_RENDER_LIMIT_EXCEEDED",
            Self::NonAsciiRendererInvariant => "EVIDENTRAIL_COMPILED_COST_NON_ASCII_RENDERER_INVARIANT",
            Self::ArithmeticOverflow => "EVIDENTRAIL_COMPILED_COST_ARITHMETIC_OVERFLOW",
            Self::CostOutOfRange => "EVIDENTRAIL_COMPILED_COST_OUT_OF_RANGE",
        }
    }
}

impl fmt::Debug for CompiledCostCertificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledCostCertificationError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for CompiledCostCertificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for CompiledCostCertificationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_bound_contract_is_rejected_inside_closed_compiler() {
        let tokenizer = Utf8ByteTokenizerV1::new();
        let unsupported = AsciiRenderTokenBoundContractV1 {
            tokenizer_digest: tokenizer.digest(),
            contract_digest: ArtifactDigest::from_bytes([0xff; 32]),
        };
        assert_eq!(
            validate_supported_tokenizer(&tokenizer, unsupported),
            Err(CompiledCostCertificationError::UnsupportedTokenizerBound),
        );
    }

    #[test]
    fn forcing_width_bound_covers_every_closed_v1_code() {
        for code in [
            "mandatory_validated_identifier",
            "density_greedy",
            "best_single",
        ] {
            assert!(code.len() <= MAX_FORCING_CODE_V1.len());
            assert!(code.is_ascii());
        }
    }

    #[test]
    fn role_bound_covers_the_complete_closed_v1_roster() {
        assert_eq!(ProductionFacetKindV1::ALL_V1.len(), 10);
        let codes = ProductionFacetKindV1::ALL_V1
            .iter()
            .map(|kind| kind.code())
            .collect::<BTreeSet<_>>();
        assert_eq!(codes.len(), ProductionFacetKindV1::ALL_V1.len());
        assert!(codes.iter().all(|code| code.is_ascii()));
    }
}
