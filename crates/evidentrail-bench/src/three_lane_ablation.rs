use std::error::Error as StdError;
use std::fmt;

use evidentrail_compile::{
    PreparedThreeLaneAblationSetV1, ThreeLaneAblationMaskV1,
    three_lane_ablation_method_family_digest_v1,
};
use evidentrail_core::{EventLedger, QuestionDigest};
use evidentrail_schema::ArtifactDigest;

use crate::{
    EvidentrailBenchCaseSpecV1, FrozenProducerProposalUniverseV1, ProducerProposalErrorV1,
    ProducerProposalIdV1, ProducerProposalIdentityV1, ProducerProposalPacketV1,
};

/// One label-free frozen proposal universe at an exact lane mask.
#[derive(Clone, PartialEq, Eq)]
pub struct FrozenThreeLaneAblationV1 {
    mask: ThreeLaneAblationMaskV1,
    universe: FrozenProducerProposalUniverseV1,
}

impl FrozenThreeLaneAblationV1 {
    #[must_use]
    pub const fn mask(&self) -> ThreeLaneAblationMaskV1 {
        self.mask
    }

    #[must_use]
    pub const fn universe(&self) -> &FrozenProducerProposalUniverseV1 {
        &self.universe
    }
}

impl fmt::Debug for FrozenThreeLaneAblationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenThreeLaneAblationV1")
            .field("mask", &self.mask)
            .field("universe", &self.universe)
            .finish()
    }
}

/// The exact four configured-producer universes derived from one prepared,
/// label-free compiler batch.
#[derive(Clone, PartialEq, Eq)]
pub struct FrozenThreeLaneAblationSetV1 {
    method_family_digest: ArtifactDigest,
    question_digest: QuestionDigest,
    configurations: [FrozenThreeLaneAblationV1; 4],
}

impl FrozenThreeLaneAblationSetV1 {
    #[must_use]
    pub const fn method_family_digest(&self) -> ArtifactDigest {
        self.method_family_digest
    }

    #[must_use]
    pub const fn question_digest(&self) -> QuestionDigest {
        self.question_digest
    }

    #[must_use]
    pub fn configurations(&self) -> &[FrozenThreeLaneAblationV1; 4] {
        &self.configurations
    }

    #[must_use]
    pub fn configuration(&self, mask: ThreeLaneAblationMaskV1) -> &FrozenThreeLaneAblationV1 {
        &self.configurations[match mask {
            ThreeLaneAblationMaskV1::Full => 0,
            ThreeLaneAblationMaskV1::WithoutLexical => 1,
            ThreeLaneAblationMaskV1::WithoutCoverage => 2,
            ThreeLaneAblationMaskV1::WithoutProvider => 3,
        }]
    }

    /// This adapter accepts only public preparation artifacts; it neither
    /// receives nor proves temporal isolation from hidden annotations.
    #[must_use]
    pub const fn freeze_boundary_code(&self) -> &'static str {
        "label_free_preparation_input_process_order_not_attested"
    }
}

impl fmt::Debug for FrozenThreeLaneAblationSetV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrozenThreeLaneAblationSetV1")
            .field("method_family_identity_present", &true)
            .field("configuration_count", &self.configurations.len())
            .field("freeze_boundary", &self.freeze_boundary_code())
            .finish()
    }
}

/// Freeze already-prepared production/ablation outputs into benchmark-neutral
/// proposal universes. Preparation itself happens in the separate compiler
/// API whose signature contains no case budget, annotation, or measurement.
pub fn freeze_prepared_three_lane_ablations_v1(
    public_case_artifact_digest: ArtifactDigest,
    public_case: &EvidentrailBenchCaseSpecV1,
    ledger: &EventLedger,
    prepared: &PreparedThreeLaneAblationSetV1,
) -> Result<FrozenThreeLaneAblationSetV1, ThreeLaneAblationFreezeErrorV1> {
    let full_question_digest = prepared
        .configuration(ThreeLaneAblationMaskV1::Full)
        .prepared()
        .receipt()
        .input()
        .question_digest();
    if public_case.question_digest() != full_question_digest {
        return Err(ThreeLaneAblationFreezeErrorV1::QuestionBindingMismatch);
    }

    let method_family_digest = three_lane_ablation_method_family_digest_v1();
    let freeze = |mask| -> Result<FrozenThreeLaneAblationV1, ThreeLaneAblationFreezeErrorV1> {
        let configured = prepared.configuration(mask);
        let production_prepared = configured.prepared();
        let producer = ProducerProposalIdentityV1::new(
            method_family_digest,
            configured.config_digest(),
            production_prepared.receipt().digest(),
        );
        let packets = production_prepared
            .proposal_packets()
            .iter()
            .map(|packet| {
                ProducerProposalPacketV1::try_new(
                    ProducerProposalIdV1::from_bytes(*packet.id().as_bytes()),
                    packet.event_ids().iter().copied(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let universe = FrozenProducerProposalUniverseV1::try_new(
            public_case_artifact_digest,
            public_case,
            ledger,
            producer,
            packets,
        )?;
        Ok(FrozenThreeLaneAblationV1 { mask, universe })
    };

    Ok(FrozenThreeLaneAblationSetV1 {
        method_family_digest,
        question_digest: full_question_digest,
        configurations: [
            freeze(ThreeLaneAblationMaskV1::Full)?,
            freeze(ThreeLaneAblationMaskV1::WithoutLexical)?,
            freeze(ThreeLaneAblationMaskV1::WithoutCoverage)?,
            freeze(ThreeLaneAblationMaskV1::WithoutProvider)?,
        ],
    })
}

/// Contentless public-case or proposal-freeze failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ThreeLaneAblationFreezeErrorV1 {
    QuestionBindingMismatch,
    ProducerProposal(ProducerProposalErrorV1),
}

impl ThreeLaneAblationFreezeErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::QuestionBindingMismatch => "EVIDENTRAIL_BENCH_ABLATION_QUESTION_BINDING_MISMATCH",
            Self::ProducerProposal(_) => "EVIDENTRAIL_BENCH_ABLATION_PROPOSAL_FREEZE",
        }
    }
}

impl From<ProducerProposalErrorV1> for ThreeLaneAblationFreezeErrorV1 {
    fn from(error: ProducerProposalErrorV1) -> Self {
        Self::ProducerProposal(error)
    }
}

impl fmt::Debug for ThreeLaneAblationFreezeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ThreeLaneAblationFreezeErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for ThreeLaneAblationFreezeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for ThreeLaneAblationFreezeErrorV1 {}
