use std::fmt;

use evidentrail_schema::ArtifactDigest;
use sha2::{Digest, Sha256};

use crate::proposal::{
    PreparedThreeLaneProposalUniverseV1, ThreeLaneProposalPreparationNeedsMoreV1,
    proposal_candidate_config_digest_v1, proposal_compiler_config_digest_v1,
};
use crate::types::CandidateLaneV1;

const THREE_LANE_ABLATION_METHOD_FAMILY_DOMAIN_V1: &[u8] =
    b"evidentrail/compile/three-lane-ablation-method-family/v1\0";
const THREE_LANE_ABLATION_CONFIG_DOMAIN_V1: &[u8] =
    b"evidentrail/compile/three-lane-ablation-config/v1\0";
const THREE_LANE_MASKED_CANDIDATE_CONFIG_DOMAIN_V1: &[u8] =
    b"evidentrail/compile/three-lane-masked-candidate-config/v1\0";

/// Closed leave-one-lane-out configurations for benchmark instrumentation.
///
/// The production path is always [`Self::Full`]. These masks are unavailable
/// unless the non-default `benchmark-instrumentation` feature is enabled.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ThreeLaneAblationMaskV1 {
    Full,
    WithoutLexical,
    WithoutCoverage,
    WithoutProvider,
}

impl ThreeLaneAblationMaskV1 {
    pub const ALL: [Self; 4] = [
        Self::Full,
        Self::WithoutLexical,
        Self::WithoutCoverage,
        Self::WithoutProvider,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::WithoutLexical => "without_lexical",
            Self::WithoutCoverage => "without_coverage",
            Self::WithoutProvider => "without_provider",
        }
    }

    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Self::Full => 0b111,
            Self::WithoutLexical => 0b110,
            Self::WithoutCoverage => 0b101,
            Self::WithoutProvider => 0b011,
        }
    }

    #[must_use]
    pub const fn includes(self, lane: CandidateLaneV1) -> bool {
        let bit = match lane {
            CandidateLaneV1::Lexical => 0b001,
            CandidateLaneV1::Coverage => 0b010,
            CandidateLaneV1::Provider => 0b100,
        };
        self.bits() & bit != 0
    }
}

impl fmt::Debug for ThreeLaneAblationMaskV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ThreeLaneAblationMaskV1")
            .field("code", &self.code())
            .finish()
    }
}

/// One method-family identity shared by all four configured producers.
#[must_use]
pub fn three_lane_ablation_method_family_digest_v1() -> ArtifactDigest {
    let mut hasher = Sha256::new();
    hasher.update(THREE_LANE_ABLATION_METHOD_FAMILY_DOMAIN_V1);
    update_field(
        &mut hasher,
        proposal_candidate_config_digest_v1().as_bytes(),
    );
    update_field(&mut hasher, proposal_compiler_config_digest_v1().as_bytes());
    ArtifactDigest::from_bytes(hasher.finalize().into())
}

/// Exact configured-producer identity. Unlike the shared method-family
/// identity, this commitment always includes the explicit mask byte.
#[must_use]
pub fn three_lane_ablation_config_digest_v1(mask: ThreeLaneAblationMaskV1) -> ArtifactDigest {
    let mut hasher = Sha256::new();
    hasher.update(THREE_LANE_ABLATION_CONFIG_DOMAIN_V1);
    hasher.update([mask.bits()]);
    update_field(&mut hasher, mask.code().as_bytes());
    update_field(
        &mut hasher,
        proposal_candidate_config_digest_v1().as_bytes(),
    );
    update_field(&mut hasher, proposal_compiler_config_digest_v1().as_bytes());
    ArtifactDigest::from_bytes(hasher.finalize().into())
}

pub(crate) fn masked_candidate_config_digest_v1(mask: ThreeLaneAblationMaskV1) -> ArtifactDigest {
    if mask == ThreeLaneAblationMaskV1::Full {
        return proposal_candidate_config_digest_v1();
    }
    let mut hasher = Sha256::new();
    hasher.update(THREE_LANE_MASKED_CANDIDATE_CONFIG_DOMAIN_V1);
    hasher.update([mask.bits()]);
    update_field(&mut hasher, mask.code().as_bytes());
    update_field(
        &mut hasher,
        proposal_candidate_config_digest_v1().as_bytes(),
    );
    ArtifactDigest::from_bytes(hasher.finalize().into())
}

/// One prepared, budget-independent configured producer.
#[derive(Clone, PartialEq, Eq)]
pub struct PreparedThreeLaneAblationV1 {
    mask: ThreeLaneAblationMaskV1,
    config_digest: ArtifactDigest,
    prepared: PreparedThreeLaneProposalUniverseV1,
}

impl PreparedThreeLaneAblationV1 {
    pub(crate) fn new(
        mask: ThreeLaneAblationMaskV1,
        prepared: PreparedThreeLaneProposalUniverseV1,
    ) -> Self {
        Self {
            mask,
            config_digest: three_lane_ablation_config_digest_v1(mask),
            prepared,
        }
    }

    #[must_use]
    pub const fn mask(&self) -> ThreeLaneAblationMaskV1 {
        self.mask
    }

    #[must_use]
    pub const fn config_digest(&self) -> ArtifactDigest {
        self.config_digest
    }

    #[must_use]
    /// Borrow the budget-independent proposal material for benchmark freezing.
    /// Non-Full receipts intentionally fail the production selector's ordinary
    /// Full-config binding check.
    pub const fn prepared(&self) -> &PreparedThreeLaneProposalUniverseV1 {
        &self.prepared
    }
}

impl fmt::Debug for PreparedThreeLaneAblationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedThreeLaneAblationV1")
            .field("mask", &self.mask)
            .field("configuration_identity_present", &true)
            .field(
                "proposal_packet_count",
                &self.prepared.proposal_packets().len(),
            )
            .finish()
    }
}

/// Exactly the four preregisterable V1 leave-one-lane-out configurations.
#[derive(Clone, PartialEq, Eq)]
pub struct PreparedThreeLaneAblationSetV1 {
    configurations: [PreparedThreeLaneAblationV1; 4],
}

impl PreparedThreeLaneAblationSetV1 {
    pub(crate) fn new(configurations: [PreparedThreeLaneAblationV1; 4]) -> Self {
        debug_assert!(
            configurations
                .iter()
                .zip(ThreeLaneAblationMaskV1::ALL)
                .all(|(configuration, expected)| configuration.mask == expected)
        );
        Self { configurations }
    }

    #[must_use]
    pub fn configurations(&self) -> &[PreparedThreeLaneAblationV1; 4] {
        &self.configurations
    }

    #[must_use]
    pub fn configuration(&self, mask: ThreeLaneAblationMaskV1) -> &PreparedThreeLaneAblationV1 {
        &self.configurations[match mask {
            ThreeLaneAblationMaskV1::Full => 0,
            ThreeLaneAblationMaskV1::WithoutLexical => 1,
            ThreeLaneAblationMaskV1::WithoutCoverage => 2,
            ThreeLaneAblationMaskV1::WithoutProvider => 3,
        }]
    }
}

impl fmt::Debug for PreparedThreeLaneAblationSetV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedThreeLaneAblationSetV1")
            .field("configuration_count", &self.configurations.len())
            .finish()
    }
}

/// Batch preparation is all-or-nothing: every lane must first produce one
/// validated ready universe before any configured output is frozen.
#[derive(Clone, PartialEq, Eq)]
pub enum ThreeLaneAblationPreparationDecisionV1 {
    Prepared(Box<PreparedThreeLaneAblationSetV1>),
    NeedsMore(Box<ThreeLaneProposalPreparationNeedsMoreV1>),
}

impl ThreeLaneAblationPreparationDecisionV1 {
    #[must_use]
    pub fn prepared(&self) -> Option<&PreparedThreeLaneAblationSetV1> {
        match self {
            Self::Prepared(prepared) => Some(prepared),
            Self::NeedsMore(_) => None,
        }
    }

    #[must_use]
    pub const fn needs_more(&self) -> Option<&ThreeLaneProposalPreparationNeedsMoreV1> {
        match self {
            Self::Prepared(_) => None,
            Self::NeedsMore(needs_more) => Some(needs_more),
        }
    }
}

impl fmt::Debug for ThreeLaneAblationPreparationDecisionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prepared(prepared) => formatter
                .debug_struct("ThreeLaneAblationPreparationDecisionV1")
                .field("state", &"prepared")
                .field("summary", prepared)
                .finish(),
            Self::NeedsMore(needs_more) => formatter
                .debug_struct("ThreeLaneAblationPreparationDecisionV1")
                .field("state", &"needs_more")
                .field("summary", needs_more)
                .finish(),
        }
    }
}

fn update_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(
        u64::try_from(bytes.len())
            .expect("bounded V1 identity field fits u64")
            .to_le_bytes(),
    );
    hasher.update(bytes);
}
