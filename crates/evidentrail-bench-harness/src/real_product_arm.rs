//! Binding to the real product compilation path used by qualification arms.

use evidentrail_cli::{
    McpRetentionBackendV1, McpRetentionModeV1, StdinBriefErrorV1, StdinBriefOutcomeV1,
    StdinBriefSessionV1, compile_explicit_stdin_retained_v1,
};
use evidentrail_core::UnixTimestampNanos;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const PUBLIC_ARTIFACT_DOMAIN_V2: &[u8] = b"evidentrail/qualification/real-product-artifact/v2";
const AUTHORIZED_BASIS_DOMAIN_V2: &[u8] = b"evidentrail/qualification/authorized-basis/v2";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealMemoryProductObservationV2 {
    pub public_artifact_commitment: [u8; 32],
    pub authorized_basis_commitment: [u8; 32],
    pub source_record_count: u64,
    pub source_byte_count: u64,
    pub evidence_alias_count: u64,
    pub rendered: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealDurableQualificationAvailabilityV2 {
    Ready,
    MissingExternalTrustedAuthority,
}

#[must_use]
pub const fn real_durable_qualification_availability_v2() -> RealDurableQualificationAvailabilityV2
{
    // The real V2 product path is wired, but storage currently exposes only
    // ProcessKeyAuthorityV2. It must never be promoted to a qualification root.
    RealDurableQualificationAvailabilityV2::MissingExternalTrustedAuthority
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RealProductArmErrorV2 {
    DurableBackendRequired,
    BackendFailed,
    OutcomeUnavailable,
}

pub fn execute_real_durable_product_arm_v2(
    backend: &mut impl McpRetentionBackendV1,
    input: &[u8],
    question: &[u8],
    token_budget: u64,
    result_randomness: [u8; 32],
    now: UnixTimestampNanos,
) -> Result<RealMemoryProductObservationV2, RealProductArmErrorV2> {
    if backend.mode() != McpRetentionModeV1::DurablePublishedV2 {
        return Err(RealProductArmErrorV2::DurableBackendRequired);
    }
    let outcome = backend
        .compile_logs(input, question, token_budget, result_randomness, now)
        .map_err(|_| RealProductArmErrorV2::BackendFailed)?
        .ok_or(RealProductArmErrorV2::OutcomeUnavailable)?;
    Ok(observe_outcome(&outcome, input))
}

pub fn execute_real_memory_product_arm_v2(
    input: &[u8],
    question: &[u8],
    token_budget: u64,
    result_randomness: [u8; 32],
    now: UnixTimestampNanos,
) -> Result<(StdinBriefSessionV1, RealMemoryProductObservationV2), StdinBriefErrorV1> {
    let session =
        compile_explicit_stdin_retained_v1(input, question, token_budget, result_randomness, now)?;
    let observation = observe_outcome(session.outcome(), input);
    Ok((session, observation))
}

fn observe_outcome(outcome: &StdinBriefOutcomeV1, input: &[u8]) -> RealMemoryProductObservationV2 {
    let mut public = Sha256::new();
    public.update(PUBLIC_ARTIFACT_DOMAIN_V2);
    public.update(outcome.code().as_bytes());
    public.update(outcome.result_id().as_bytes());
    public.update(outcome.expires_at().get().to_be_bytes());
    let (records, bytes, aliases, rendered) = match outcome {
        StdinBriefOutcomeV1::Rendered(value) => {
            public.update((value.text().len() as u64).to_be_bytes());
            public.update(value.text().as_bytes());
            public.update(value.evidence_alias_count().to_be_bytes());
            (
                value.source_record_count(),
                value.source_byte_count(),
                value.evidence_alias_count(),
                true,
            )
        }
        StdinBriefOutcomeV1::NeedsMore(value) => {
            public.update(value.reason().code().as_bytes());
            public.update(value.source_record_count().to_be_bytes());
            public.update(value.source_byte_count().to_be_bytes());
            (
                value.source_record_count(),
                value.source_byte_count(),
                0,
                false,
            )
        }
    };
    let mut basis = Sha256::new();
    basis.update(AUTHORIZED_BASIS_DOMAIN_V2);
    basis.update((input.len() as u64).to_be_bytes());
    basis.update(input);
    RealMemoryProductObservationV2 {
        public_artifact_commitment: public.finalize().into(),
        authorized_basis_commitment: basis.finalize().into(),
        source_record_count: records,
        source_byte_count: bytes,
        evidence_alias_count: aliases,
        rendered,
    }
}
