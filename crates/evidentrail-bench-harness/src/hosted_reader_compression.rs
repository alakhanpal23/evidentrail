use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::ArtifactDigest;
use sha2::{Digest, Sha256};

use crate::{HostedReaderJsonlResponseV1, ReaderCitationHandleV1, ReaderPublicInputV1};

pub const HOSTED_READER_COMPRESSION_CHECK_CONTRACT_VERSION_V1: u16 = 1;

const COMPRESSION_CHECK_DOMAIN_V1: &[u8] =
    b"evidentrail/bench-harness/hosted-reader-compression-check/v1";

/// Evidence that one pinned hosted reader produced the exact same structured
/// answer from a smaller representation and a smaller provider-reported
/// prompt. This is evaluation evidence only; it cannot mutate trusted evidence
/// or admit a representation into production by itself.
#[derive(Clone, PartialEq, Eq)]
pub struct HostedReaderCompressionCheckReceiptV1 {
    artifact_digest: ArtifactDigest,
    public_case_artifact_digest: ArtifactDigest,
    configuration_artifact_digest: ArtifactDigest,
    baseline_response_artifact_digest: ArtifactDigest,
    compressed_response_artifact_digest: ArtifactDigest,
    answer_artifact_digest: ArtifactDigest,
    baseline_method_bytes: u64,
    compressed_method_bytes: u64,
    saved_method_bytes: u64,
    baseline_prompt_tokens: u64,
    compressed_prompt_tokens: u64,
    saved_prompt_tokens: u64,
    prompt_reduction_micros: u64,
}

impl HostedReaderCompressionCheckReceiptV1 {
    #[must_use]
    pub const fn artifact_digest(&self) -> ArtifactDigest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn public_case_artifact_digest(&self) -> ArtifactDigest {
        self.public_case_artifact_digest
    }

    #[must_use]
    pub const fn configuration_artifact_digest(&self) -> ArtifactDigest {
        self.configuration_artifact_digest
    }

    #[must_use]
    pub const fn baseline_response_artifact_digest(&self) -> ArtifactDigest {
        self.baseline_response_artifact_digest
    }

    #[must_use]
    pub const fn compressed_response_artifact_digest(&self) -> ArtifactDigest {
        self.compressed_response_artifact_digest
    }

    #[must_use]
    pub const fn answer_artifact_digest(&self) -> ArtifactDigest {
        self.answer_artifact_digest
    }

    #[must_use]
    pub const fn baseline_method_bytes(&self) -> u64 {
        self.baseline_method_bytes
    }

    #[must_use]
    pub const fn compressed_method_bytes(&self) -> u64 {
        self.compressed_method_bytes
    }

    #[must_use]
    pub const fn saved_method_bytes(&self) -> u64 {
        self.saved_method_bytes
    }

    #[must_use]
    pub const fn baseline_prompt_tokens(&self) -> u64 {
        self.baseline_prompt_tokens
    }

    #[must_use]
    pub const fn compressed_prompt_tokens(&self) -> u64 {
        self.compressed_prompt_tokens
    }

    #[must_use]
    pub const fn saved_prompt_tokens(&self) -> u64 {
        self.saved_prompt_tokens
    }

    #[must_use]
    pub const fn prompt_reduction_micros(&self) -> u64 {
        self.prompt_reduction_micros
    }

    #[must_use]
    pub const fn answers_preserved(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn citation_semantics_preserved(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn provider_reported_token_counts(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn trusted_evidence_mutated(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn production_admission_authority(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn status_code(&self) -> &'static str {
        "passed_against_full_view_not_production_admission"
    }
}

impl fmt::Debug for HostedReaderCompressionCheckReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostedReaderCompressionCheckReceiptV1")
            .field("receipt_identity_present", &true)
            .field("public_case_binding_present", &true)
            .field("configuration_binding_present", &true)
            .field("response_bindings_present", &true)
            .field("answer_binding_present", &true)
            .field("baseline_method_bytes", &self.baseline_method_bytes)
            .field("compressed_method_bytes", &self.compressed_method_bytes)
            .field("saved_method_bytes", &self.saved_method_bytes)
            .field("baseline_prompt_tokens", &self.baseline_prompt_tokens)
            .field("compressed_prompt_tokens", &self.compressed_prompt_tokens)
            .field("saved_prompt_tokens", &self.saved_prompt_tokens)
            .field("prompt_reduction_micros", &self.prompt_reduction_micros)
            .field("answers_preserved", &true)
            .field("citation_semantics_preserved", &true)
            .field("provider_reported_token_counts", &true)
            .field("trusted_evidence_mutated", &false)
            .field("production_admission_authority", &false)
            .field("status_code", &self.status_code())
            .field("content_redacted", &true)
            .finish()
    }
}

pub fn check_hosted_reader_compression_v1(
    baseline_input: &ReaderPublicInputV1,
    baseline_response: &HostedReaderJsonlResponseV1,
    compressed_input: &ReaderPublicInputV1,
    compressed_response: &HostedReaderJsonlResponseV1,
) -> Result<HostedReaderCompressionCheckReceiptV1, HostedReaderCompressionCheckErrorV1> {
    if baseline_response.public_input_artifact_digest() != baseline_input.artifact_digest()
        || compressed_response.public_input_artifact_digest() != compressed_input.artifact_digest()
    {
        return Err(HostedReaderCompressionCheckErrorV1::ResponseInputBindingMismatch);
    }
    if baseline_input.public_case_artifact_digest()
        != compressed_input.public_case_artifact_digest()
        || baseline_input.question_digest() != compressed_input.question_digest()
        || baseline_input.context_artifact_digest() != compressed_input.context_artifact_digest()
    {
        return Err(HostedReaderCompressionCheckErrorV1::InputPairMismatch);
    }
    if baseline_response.configuration_artifact_digest()
        != compressed_response.configuration_artifact_digest()
    {
        return Err(HostedReaderCompressionCheckErrorV1::ConfigurationMismatch);
    }
    if baseline_response.provider_request_id_digest()
        == compressed_response.provider_request_id_digest()
    {
        return Err(HostedReaderCompressionCheckErrorV1::ProviderRequestReplay);
    }

    let baseline_method_bytes = checked_u64(baseline_input.method_artifact().bytes().len())?;
    let compressed_method_bytes = checked_u64(compressed_input.method_artifact().bytes().len())?;
    let Some(saved_method_bytes) = baseline_method_bytes.checked_sub(compressed_method_bytes)
    else {
        return Err(HostedReaderCompressionCheckErrorV1::MethodArtifactNotSmaller);
    };
    if saved_method_bytes == 0 {
        return Err(HostedReaderCompressionCheckErrorV1::MethodArtifactNotSmaller);
    }

    let baseline_prompt_tokens = baseline_response.usage().prompt_tokens();
    let compressed_prompt_tokens = compressed_response.usage().prompt_tokens();
    let Some(saved_prompt_tokens) = baseline_prompt_tokens.checked_sub(compressed_prompt_tokens)
    else {
        return Err(HostedReaderCompressionCheckErrorV1::PromptNotSmaller);
    };
    if saved_prompt_tokens == 0 {
        return Err(HostedReaderCompressionCheckErrorV1::PromptNotSmaller);
    }
    if baseline_response.answer_artifact_digest() != compressed_response.answer_artifact_digest()
        || baseline_response.answer_bytes() != compressed_response.answer_bytes()
        || !same_citation_semantics(
            baseline_input.method_artifact().citation_handles(),
            compressed_input.method_artifact().citation_handles(),
        )
    {
        return Err(HostedReaderCompressionCheckErrorV1::AnswerOrCitationMismatch);
    }

    let prompt_reduction_micros = u64::try_from(
        u128::from(saved_prompt_tokens)
            .checked_mul(1_000_000)
            .ok_or(HostedReaderCompressionCheckErrorV1::ArithmeticOverflow)?
            / u128::from(baseline_prompt_tokens),
    )
    .map_err(|_| HostedReaderCompressionCheckErrorV1::ArithmeticOverflow)?;
    let artifact_digest = derive_receipt_artifact_v1(
        baseline_input,
        baseline_response,
        compressed_input,
        compressed_response,
        baseline_method_bytes,
        compressed_method_bytes,
        saved_method_bytes,
        baseline_prompt_tokens,
        compressed_prompt_tokens,
        saved_prompt_tokens,
        prompt_reduction_micros,
    )?;
    Ok(HostedReaderCompressionCheckReceiptV1 {
        artifact_digest,
        public_case_artifact_digest: baseline_input.public_case_artifact_digest(),
        configuration_artifact_digest: baseline_response.configuration_artifact_digest(),
        baseline_response_artifact_digest: baseline_response.artifact_digest(),
        compressed_response_artifact_digest: compressed_response.artifact_digest(),
        answer_artifact_digest: baseline_response.answer_artifact_digest(),
        baseline_method_bytes,
        compressed_method_bytes,
        saved_method_bytes,
        baseline_prompt_tokens,
        compressed_prompt_tokens,
        saved_prompt_tokens,
        prompt_reduction_micros,
    })
}

fn same_citation_semantics(
    baseline: &[ReaderCitationHandleV1],
    compressed: &[ReaderCitationHandleV1],
) -> bool {
    baseline.len() == compressed.len()
        && baseline.iter().zip(compressed).all(|(left, right)| {
            left.handle() == right.handle() && left.targets() == right.targets()
        })
}

#[allow(clippy::too_many_arguments)]
fn derive_receipt_artifact_v1(
    baseline_input: &ReaderPublicInputV1,
    baseline_response: &HostedReaderJsonlResponseV1,
    compressed_input: &ReaderPublicInputV1,
    compressed_response: &HostedReaderJsonlResponseV1,
    baseline_method_bytes: u64,
    compressed_method_bytes: u64,
    saved_method_bytes: u64,
    baseline_prompt_tokens: u64,
    compressed_prompt_tokens: u64,
    saved_prompt_tokens: u64,
    prompt_reduction_micros: u64,
) -> Result<ArtifactDigest, HostedReaderCompressionCheckErrorV1> {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, COMPRESSION_CHECK_DOMAIN_V1)?;
    update_field(
        &mut hasher,
        &HOSTED_READER_COMPRESSION_CHECK_CONTRACT_VERSION_V1.to_le_bytes(),
    )?;
    for digest in [
        baseline_input.public_case_artifact_digest(),
        baseline_input.artifact_digest(),
        compressed_input.artifact_digest(),
        baseline_response.configuration_artifact_digest(),
        baseline_response.artifact_digest(),
        compressed_response.artifact_digest(),
        baseline_response.answer_artifact_digest(),
    ] {
        update_field(&mut hasher, digest.as_bytes())?;
    }
    for value in [
        baseline_method_bytes,
        compressed_method_bytes,
        saved_method_bytes,
        baseline_prompt_tokens,
        compressed_prompt_tokens,
        saved_prompt_tokens,
        prompt_reduction_micros,
    ] {
        update_field(&mut hasher, &value.to_le_bytes())?;
    }
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

fn update_field(
    hasher: &mut Sha256,
    bytes: &[u8],
) -> Result<(), HostedReaderCompressionCheckErrorV1> {
    let len = checked_u64(bytes.len())?;
    hasher.update(len.to_le_bytes());
    hasher.update(bytes);
    Ok(())
}

fn checked_u64(value: usize) -> Result<u64, HostedReaderCompressionCheckErrorV1> {
    u64::try_from(value).map_err(|_| HostedReaderCompressionCheckErrorV1::ArithmeticOverflow)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HostedReaderCompressionCheckErrorV1 {
    ResponseInputBindingMismatch,
    InputPairMismatch,
    ConfigurationMismatch,
    ProviderRequestReplay,
    MethodArtifactNotSmaller,
    PromptNotSmaller,
    AnswerOrCitationMismatch,
    ArithmeticOverflow,
}

impl HostedReaderCompressionCheckErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ResponseInputBindingMismatch => {
                "EVIDENTRAIL_BENCH_HOSTED_COMPRESSION_RESPONSE_INPUT_BINDING_MISMATCH"
            }
            Self::InputPairMismatch => "EVIDENTRAIL_BENCH_HOSTED_COMPRESSION_INPUT_PAIR_MISMATCH",
            Self::ConfigurationMismatch => {
                "EVIDENTRAIL_BENCH_HOSTED_COMPRESSION_CONFIGURATION_MISMATCH"
            }
            Self::ProviderRequestReplay => {
                "EVIDENTRAIL_BENCH_HOSTED_COMPRESSION_PROVIDER_REQUEST_REPLAY"
            }
            Self::MethodArtifactNotSmaller => {
                "EVIDENTRAIL_BENCH_HOSTED_COMPRESSION_METHOD_ARTIFACT_NOT_SMALLER"
            }
            Self::PromptNotSmaller => "EVIDENTRAIL_BENCH_HOSTED_COMPRESSION_PROMPT_NOT_SMALLER",
            Self::AnswerOrCitationMismatch => {
                "EVIDENTRAIL_BENCH_HOSTED_COMPRESSION_ANSWER_OR_CITATION_MISMATCH"
            }
            Self::ArithmeticOverflow => "EVIDENTRAIL_BENCH_HOSTED_COMPRESSION_ARITHMETIC_OVERFLOW",
        }
    }
}

impl fmt::Debug for HostedReaderCompressionCheckErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostedReaderCompressionCheckErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for HostedReaderCompressionCheckErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for HostedReaderCompressionCheckErrorV1 {}
