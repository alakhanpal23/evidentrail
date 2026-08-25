use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::{ArtifactDigest, EventId, bounds::JSON_SAFE_INTEGER_MAX};
use sha2::{Digest, Sha256};

/// Integer scale used by V1 facet weights and packet affinities.
pub const AFFINITY_SCALE_V1: u32 = 1_000_000;
/// Versioned deterministic selection-objective policy identity.
pub const SELECTION_OBJECTIVE_POLICY_NAME_V1: &[u8] = b"evidentrail/selection/top-k-facility-coverage";
/// V2 introduces a two-packet saturation cardinality for provider relations.
pub const SELECTION_OBJECTIVE_POLICY_VERSION_V1: &[u8] = b"2";
/// Exact per-endpoint provider relation weight. Two distinct selected packets
/// together retain the former one-facet maximum contribution.
pub const PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1: u32 = AFFINITY_SCALE_V1 / 2;
/// Maximum closed saturation cardinality admitted by this objective version.
pub const MAX_FACET_SATURATION_CARDINALITY_V1: u8 = 2;
/// Maximum canonical packet count accepted by one selection problem.
pub const MAX_SELECTION_PACKETS_V1: usize = 4_096;
/// Maximum production facet count accepted by one selection problem.
pub const MAX_SELECTION_FACETS_V1: usize = 4_096;
/// Maximum event count carried by one intact packet.
pub const MAX_PACKET_EVENTS_V1: usize = 4_096;
/// Maximum unique event count across one canonical packet universe.
pub const MAX_SELECTION_EVENTS_V1: usize = 65_536;
/// Explicit V1 cap on identifier-forced mandatory packets.
pub const MAX_MANDATORY_PACKETS_V1: usize = 64;
/// Denominator of the optional-token slice available to packets whose current
/// positive marginal gain is exclusively source/service/time coverage.
///
/// The numerator is exactly one. Diagnostic, change, provider-attested, and
/// reconstruction-risk gain is not charged to this slice.
pub const COVERAGE_ONLY_OPTIONAL_BUDGET_DENOMINATOR_V1: u64 = 8;
/// Maximum canonical typed semantic key hashed into one facet identity.
pub const MAX_FACET_SEMANTIC_KEY_BYTES_V1: usize = 64 * 1024;

const ID_BYTES: usize = 32;

macro_rules! opaque_selection_id {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; ID_BYTES]);

        impl $name {
            #[must_use]
            pub const fn from_bytes(bytes: [u8; ID_BYTES]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; ID_BYTES] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

opaque_selection_id!(PacketIdV1);

/// Identity derived inside this crate from facet kind plus canonical typed key.
/// There is intentionally no public `from_bytes` constructor.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FacetIdV1([u8; ID_BYTES]);

impl FacetIdV1 {
    const fn from_derived_bytes(bytes: [u8; ID_BYTES]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ID_BYTES] {
        &self.0
    }
}

impl fmt::Debug for FacetIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FacetIdV1(<redacted>)")
    }
}

/// Closed list of runtime-authorized V1 facet families.
///
/// Evaluation labels, parser/group identities, reference-window scores,
/// anomaly scores, embeddings, and model outputs deliberately have no variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProductionFacetKindV1 {
    ValidatedQueryIdentifier,
    QueryTerm,
    FailureRole,
    OnsetRole,
    SourceCoverageStratum,
    ServiceCoverageStratum,
    TimeCoverageStratum,
    ValidatedTypedChange,
    ProviderAttestedGraphRelation,
    ReconstructionRiskCoverage,
}

/// Closed count of distinct selected packets that may contribute affinity to
/// one facet. There is no caller-selected cardinality.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FacetSaturationCardinalityV1 {
    One,
    Two,
}

impl FacetSaturationCardinalityV1 {
    #[must_use]
    pub const fn count(self) -> u8 {
        match self {
            Self::One => 1,
            Self::Two => 2,
        }
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::One => "top_one_distinct_packet",
            Self::Two => "top_two_distinct_packets",
        }
    }
}

impl ProductionFacetKindV1 {
    /// Complete closed V1 family roster in canonical code order.
    pub const ALL_V1: [Self; 10] = [
        Self::ValidatedQueryIdentifier,
        Self::QueryTerm,
        Self::FailureRole,
        Self::OnsetRole,
        Self::SourceCoverageStratum,
        Self::ServiceCoverageStratum,
        Self::TimeCoverageStratum,
        Self::ValidatedTypedChange,
        Self::ProviderAttestedGraphRelation,
        Self::ReconstructionRiskCoverage,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ValidatedQueryIdentifier => "validated_query_identifier",
            Self::QueryTerm => "query_term",
            Self::FailureRole => "failure_role",
            Self::OnsetRole => "onset_role",
            Self::SourceCoverageStratum => "source_coverage_stratum",
            Self::ServiceCoverageStratum => "service_coverage_stratum",
            Self::TimeCoverageStratum => "time_coverage_stratum",
            Self::ValidatedTypedChange => "validated_typed_change",
            Self::ProviderAttestedGraphRelation => "provider_attested_graph_relation",
            Self::ReconstructionRiskCoverage => "reconstruction_risk_coverage",
        }
    }

    /// Whether this family is a low-priority breadth sentinel when it is the
    /// only remaining source of positive marginal gain for a packet.
    #[must_use]
    pub const fn is_coverage_only(self) -> bool {
        matches!(
            self,
            Self::SourceCoverageStratum | Self::ServiceCoverageStratum | Self::TimeCoverageStratum
        )
    }

    /// Closed objective contract: provider-attested relation evidence can be
    /// supplied by two distinct selected packets; every other family remains
    /// ordinary max/top-one facility coverage.
    #[must_use]
    pub const fn saturation_cardinality(self) -> FacetSaturationCardinalityV1 {
        match self {
            Self::ProviderAttestedGraphRelation => FacetSaturationCardinalityV1::Two,
            Self::ValidatedQueryIdentifier
            | Self::QueryTerm
            | Self::FailureRole
            | Self::OnsetRole
            | Self::SourceCoverageStratum
            | Self::ServiceCoverageStratum
            | Self::TimeCoverageStratum
            | Self::ValidatedTypedChange
            | Self::ReconstructionRiskCoverage => FacetSaturationCardinalityV1::One,
        }
    }
}

/// Stable contentless facet-identity construction failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FacetConstructionError {
    EmptySemanticKey,
    SemanticKeyTooLarge,
    InvalidProviderRelationWeight,
}

impl FacetConstructionError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptySemanticKey => "EVIDENTRAIL_SELECT_EMPTY_FACET_SEMANTIC_KEY",
            Self::SemanticKeyTooLarge => "EVIDENTRAIL_SELECT_FACET_SEMANTIC_KEY_TOO_LARGE",
            Self::InvalidProviderRelationWeight => "EVIDENTRAIL_SELECT_INVALID_PROVIDER_RELATION_WEIGHT",
        }
    }
}

impl fmt::Debug for FacetConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FacetConstructionError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for FacetConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for FacetConstructionError {}

/// Stable contentless error for a fixed-point value outside `(0, 1]`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FixedPointConstructionError {
    Zero,
    AboveUnitScale,
}

impl FixedPointConstructionError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Zero => "EVIDENTRAIL_SELECT_FIXED_POINT_ZERO",
            Self::AboveUnitScale => "EVIDENTRAIL_SELECT_FIXED_POINT_ABOVE_UNIT_SCALE",
        }
    }
}

impl fmt::Debug for FixedPointConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixedPointConstructionError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for FixedPointConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for FixedPointConstructionError {}

/// Positive bounded facet weight. A missing facet supplies the mathematical
/// zero; material zero entries are rejected as noncanonical.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FacetWeightV1(u32);

impl FacetWeightV1 {
    pub const fn new(micros: u32) -> Result<Self, FixedPointConstructionError> {
        if micros == 0 {
            return Err(FixedPointConstructionError::Zero);
        }
        if micros > AFFINITY_SCALE_V1 {
            return Err(FixedPointConstructionError::AboveUnitScale);
        }
        Ok(Self(micros))
    }

    #[must_use]
    pub const fn micros(self) -> u32 {
        self.0
    }
}

impl fmt::Debug for FacetWeightV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("FacetWeightV1")
            .field(&self.0)
            .finish()
    }
}

/// Positive bounded packet-to-facet affinity. Absence represents exact zero.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AffinityV1(u32);

impl AffinityV1 {
    pub const fn new(micros: u32) -> Result<Self, FixedPointConstructionError> {
        if micros == 0 {
            return Err(FixedPointConstructionError::Zero);
        }
        if micros > AFFINITY_SCALE_V1 {
            return Err(FixedPointConstructionError::AboveUnitScale);
        }
        Ok(Self(micros))
    }

    #[must_use]
    pub const fn micros(self) -> u32 {
        self.0
    }
}

impl fmt::Debug for AffinityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("AffinityV1").field(&self.0).finish()
    }
}

/// Stable error for caller-declared composable bounds and total budgets.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TokenValueConstructionError {
    ZeroCost,
    AboveJsonSafeInteger,
}

impl TokenValueConstructionError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ZeroCost => "EVIDENTRAIL_SELECT_ZERO_COMPOSABLE_PACKET_COST",
            Self::AboveJsonSafeInteger => "EVIDENTRAIL_SELECT_TOKEN_VALUE_ABOVE_JSON_SAFE_INTEGER",
        }
    }
}

impl fmt::Debug for TokenValueConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenValueConstructionError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for TokenValueConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for TokenValueConstructionError {}

/// Identity declared for one renderer/tokenizer/cost-bound implementation.
///
/// Construction records an identity; it does not certify that any associated
/// numeric bound was derived correctly. A ledger- and renderer-aware compiler
/// must establish that separately.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ComposableCostModelV1 {
    artifact_digest: ArtifactDigest,
}

impl ComposableCostModelV1 {
    #[must_use]
    pub const fn new(artifact_digest: ArtifactDigest) -> Self {
        Self { artifact_digest }
    }

    #[must_use]
    pub const fn artifact_digest(self) -> ArtifactDigest {
        self.artifact_digest
    }
}

impl fmt::Debug for ComposableCostModelV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ComposableCostModelV1(<redacted>)")
    }
}

/// Positive caller-declared upper bound for rendering one intact packet under
/// a pinned composable cost model. Construction does not certify the number,
/// and this is never permission to treat independently counted BPE fragments
/// as additive across the final concatenated render.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ComposablePacketCostV1 {
    cost_model: ComposableCostModelV1,
    upper_bound_tokens: u64,
}

impl ComposablePacketCostV1 {
    pub const fn new(
        cost_model: ComposableCostModelV1,
        upper_bound_tokens: u64,
    ) -> Result<Self, TokenValueConstructionError> {
        if upper_bound_tokens == 0 {
            return Err(TokenValueConstructionError::ZeroCost);
        }
        if upper_bound_tokens > JSON_SAFE_INTEGER_MAX {
            return Err(TokenValueConstructionError::AboveJsonSafeInteger);
        }
        Ok(Self {
            cost_model,
            upper_bound_tokens,
        })
    }

    #[must_use]
    pub const fn cost_model(self) -> ComposableCostModelV1 {
        self.cost_model
    }

    #[must_use]
    pub const fn upper_bound_tokens(self) -> u64 {
        self.upper_bound_tokens
    }
}

impl fmt::Debug for ComposablePacketCostV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComposablePacketCostV1")
            .field("upper_bound_tokens", &self.upper_bound_tokens)
            .finish()
    }
}

/// Caller-declared fixed non-packet renderer space reserved before selection.
/// Zero is valid; construction does not certify the declared number.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReservedFixedOverheadV1 {
    cost_model: ComposableCostModelV1,
    upper_bound_tokens: u64,
}

impl ReservedFixedOverheadV1 {
    pub const fn new(
        cost_model: ComposableCostModelV1,
        upper_bound_tokens: u64,
    ) -> Result<Self, TokenValueConstructionError> {
        if upper_bound_tokens > JSON_SAFE_INTEGER_MAX {
            return Err(TokenValueConstructionError::AboveJsonSafeInteger);
        }
        Ok(Self {
            cost_model,
            upper_bound_tokens,
        })
    }

    #[must_use]
    pub const fn cost_model(self) -> ComposableCostModelV1 {
        self.cost_model
    }

    #[must_use]
    pub const fn upper_bound_tokens(self) -> u64 {
        self.upper_bound_tokens
    }
}

impl fmt::Debug for ReservedFixedOverheadV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReservedFixedOverheadV1")
            .field("upper_bound_tokens", &self.upper_bound_tokens)
            .finish()
    }
}

/// Total final-artifact token budget. Zero is a valid strict budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TotalTokenBudgetV1(u64);

impl TotalTokenBudgetV1 {
    pub const fn new(tokens: u64) -> Result<Self, TokenValueConstructionError> {
        if tokens > JSON_SAFE_INTEGER_MAX {
            return Err(TokenValueConstructionError::AboveJsonSafeInteger);
        }
        Ok(Self(tokens))
    }

    #[must_use]
    pub const fn tokens(self) -> u64 {
        self.0
    }
}

/// Exact numerator of the fixed-point facility-coverage objective. Its scale
/// is `AFFINITY_SCALE_V1²`; no lossy division is performed during selection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectiveGainV1(u64);

impl ObjectiveGainV1 {
    pub(crate) const fn from_numerator(numerator: u64) -> Self {
        Self(numerator)
    }

    #[must_use]
    pub const fn numerator(self) -> u64 {
        self.0
    }
}

/// One weighted production-computable coverage facet.
#[derive(Clone, PartialEq, Eq)]
pub struct ProductionFacetV1 {
    id: FacetIdV1,
    kind: ProductionFacetKindV1,
    weight: FacetWeightV1,
}

impl ProductionFacetV1 {
    /// Derive the semantic identity from a closed production kind and the
    /// caller's canonical typed binary key, then discard the key bytes.
    pub fn new(
        kind: ProductionFacetKindV1,
        canonical_semantic_key: &[u8],
        weight: FacetWeightV1,
    ) -> Result<Self, FacetConstructionError> {
        if canonical_semantic_key.is_empty() {
            return Err(FacetConstructionError::EmptySemanticKey);
        }
        if canonical_semantic_key.len() > MAX_FACET_SEMANTIC_KEY_BYTES_V1 {
            return Err(FacetConstructionError::SemanticKeyTooLarge);
        }
        if kind == ProductionFacetKindV1::ProviderAttestedGraphRelation
            && weight.micros() != PROVIDER_RELATION_ENDPOINT_WEIGHT_MICROS_V1
        {
            return Err(FacetConstructionError::InvalidProviderRelationWeight);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"evidentrail/select/facet/v1\0");
        update_hash_field(&mut hasher, kind.code().as_bytes());
        update_hash_field(&mut hasher, canonical_semantic_key);
        let id = FacetIdV1::from_derived_bytes(hasher.finalize().into());
        Ok(Self { id, kind, weight })
    }

    #[must_use]
    pub const fn id(&self) -> FacetIdV1 {
        self.id
    }

    #[must_use]
    pub const fn kind(&self) -> ProductionFacetKindV1 {
        self.kind
    }

    #[must_use]
    pub const fn weight(&self) -> FacetWeightV1 {
        self.weight
    }
}

impl fmt::Debug for ProductionFacetV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionFacetV1")
            .field("kind", &self.kind)
            .field("weight", &self.weight)
            .finish()
    }
}

/// One sparse, strictly positive packet affinity. Missing entries are zero.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FacetAffinityV1 {
    facet_id: FacetIdV1,
    affinity: AffinityV1,
}

impl FacetAffinityV1 {
    #[must_use]
    pub const fn new(facet_id: FacetIdV1, affinity: AffinityV1) -> Self {
        Self { facet_id, affinity }
    }

    #[must_use]
    pub const fn facet_id(self) -> FacetIdV1 {
        self.facet_id
    }

    #[must_use]
    pub const fn affinity(self) -> AffinityV1 {
        self.affinity
    }
}

impl fmt::Debug for FacetAffinityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FacetAffinityV1")
            .field("affinity", &self.affinity)
            .finish()
    }
}

/// Contentless packet-construction failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PacketConstructionError {
    EmptyEventSet,
    TooManyEvents,
    DuplicateEvent,
    EmptyAffinitySet,
    TooManyAffinities,
    DuplicateFacetAffinity,
}

impl PacketConstructionError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyEventSet => "EVIDENTRAIL_SELECT_EMPTY_PACKET_EVENT_SET",
            Self::TooManyEvents => "EVIDENTRAIL_SELECT_TOO_MANY_PACKET_EVENTS",
            Self::DuplicateEvent => "EVIDENTRAIL_SELECT_DUPLICATE_PACKET_EVENT",
            Self::EmptyAffinitySet => "EVIDENTRAIL_SELECT_EMPTY_PACKET_AFFINITY_SET",
            Self::TooManyAffinities => "EVIDENTRAIL_SELECT_TOO_MANY_PACKET_AFFINITIES",
            Self::DuplicateFacetAffinity => "EVIDENTRAIL_SELECT_DUPLICATE_PACKET_FACET_AFFINITY",
        }
    }
}

impl fmt::Debug for PacketConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PacketConstructionError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for PacketConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for PacketConstructionError {}

/// One indivisible candidate packet. Event and affinity order are canonicalized
/// at construction; no API exposes partial member selection.
#[derive(Clone, PartialEq, Eq)]
pub struct IntactPacketV1 {
    id: PacketIdV1,
    event_ids: Vec<EventId>,
    composable_token_upper_bound: ComposablePacketCostV1,
    affinities: Vec<FacetAffinityV1>,
}

impl IntactPacketV1 {
    pub fn new(
        id: PacketIdV1,
        event_ids: impl IntoIterator<Item = EventId>,
        composable_token_upper_bound: ComposablePacketCostV1,
        affinities: impl IntoIterator<Item = FacetAffinityV1>,
    ) -> Result<Self, PacketConstructionError> {
        let mut event_ids = event_ids.into_iter().collect::<Vec<_>>();
        if event_ids.is_empty() {
            return Err(PacketConstructionError::EmptyEventSet);
        }
        if event_ids.len() > MAX_PACKET_EVENTS_V1 {
            return Err(PacketConstructionError::TooManyEvents);
        }
        event_ids.sort_unstable();
        if event_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(PacketConstructionError::DuplicateEvent);
        }

        let mut affinities = affinities.into_iter().collect::<Vec<_>>();
        if affinities.is_empty() {
            return Err(PacketConstructionError::EmptyAffinitySet);
        }
        if affinities.len() > MAX_SELECTION_FACETS_V1 {
            return Err(PacketConstructionError::TooManyAffinities);
        }
        affinities.sort_unstable_by_key(|affinity| affinity.facet_id);
        if affinities
            .windows(2)
            .any(|pair| pair[0].facet_id == pair[1].facet_id)
        {
            return Err(PacketConstructionError::DuplicateFacetAffinity);
        }

        Ok(Self {
            id,
            event_ids,
            composable_token_upper_bound,
            affinities,
        })
    }

    #[must_use]
    pub const fn id(&self) -> PacketIdV1 {
        self.id
    }

    #[must_use]
    pub fn event_ids(&self) -> &[EventId] {
        &self.event_ids
    }

    #[must_use]
    pub const fn composable_token_upper_bound(&self) -> ComposablePacketCostV1 {
        self.composable_token_upper_bound
    }

    #[must_use]
    pub fn affinities(&self) -> &[FacetAffinityV1] {
        &self.affinities
    }

    pub(crate) fn affinity_for(&self, facet_id: FacetIdV1) -> Option<AffinityV1> {
        self.affinities
            .binary_search_by_key(&facet_id, |affinity| affinity.facet_id)
            .ok()
            .map(|index| self.affinities[index].affinity)
    }
}

impl fmt::Debug for IntactPacketV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IntactPacketV1")
            .field("event_count", &self.event_ids.len())
            .field(
                "composable_token_upper_bound",
                &self.composable_token_upper_bound,
            )
            .field("affinity_count", &self.affinities.len())
            .finish()
    }
}

/// Explicit mandatory membership justified only by a validated typed query
/// identifier facet. The problem constructor verifies the facet kind and that
/// the packet actually has a positive affinity to it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MandatoryPacketV1 {
    packet_id: PacketIdV1,
    validated_identifier_facet_id: FacetIdV1,
}

impl MandatoryPacketV1 {
    #[must_use]
    pub const fn validated_identifier(
        packet_id: PacketIdV1,
        validated_identifier_facet_id: FacetIdV1,
    ) -> Self {
        Self {
            packet_id,
            validated_identifier_facet_id,
        }
    }

    #[must_use]
    pub const fn packet_id(&self) -> PacketIdV1 {
        self.packet_id
    }

    #[must_use]
    pub const fn validated_identifier_facet_id(&self) -> FacetIdV1 {
        self.validated_identifier_facet_id
    }
}

impl fmt::Debug for MandatoryPacketV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MandatoryPacketV1 { reason: validated_query_identifier }")
    }
}

fn update_hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}
