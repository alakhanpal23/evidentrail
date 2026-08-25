//! Frozen, annotation-free whole-event lexical baseline.
//!
//! This is a BM25F-style fixed-point comparator, not a learned ranker. It
//! derives both fields from authorized event bytes: the body field contains
//! every bounded ASCII token and the identifier field contains the lexical
//! subset with a digit or identifier connector. It never reads provider
//! attestations, hidden annotations, or decoded Unicode text.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;

use evidentrail_core::{EventId, EventLedger};
use evidentrail_schema::ArtifactDigest;
use sha2::{Digest as _, Sha256};

use crate::method::{
    BenchmarkMethod, MethodDescriptor, MethodError, MethodInput, MethodResult, SelectionReason,
    build_result, checked_cost_within_budget,
};

const CONFIG_DOMAIN_V1: &[u8] = b"evidentrail/bench/bm25f-whole-event/config/v1\0";
const TOKENIZER_CONTRACT_V1: &[u8] =
    b"ascii-lower-alnum-underscore-dot-hyphen/non-ascii-separator/drop-overlong/v1";
const SCORING_CONTRACT_V1: &[u8] =
    b"unique-query-terms/idf-rational/body+identifier-field/fixed-point-k1-b-length-normalization/v1";
const FIELD_CONTRACT_V1: &[u8] =
    b"body=all-tokens/identifier=token-has-digit-or-underscore-dot-hyphen/v1";
const TIE_CONTRACT_V1: &[u8] = b"score-desc/source-ordinal-asc/v1";
const BUDGET_CONTRACT_V1: &[u8] =
    b"positive-score-candidates/whole-event/skip-oversized/restore-source-order/v1";
const METHOD_NAME_V1: &[u8] = b"bm25f-whole-event";
const METHOD_VERSION_V1: &[u8] = b"1";

pub const BM25F_SCORE_SCALE_V1: u64 = 1_000_000;
pub const BM25F_K1_SCALED_V1: u64 = 1_200_000;
pub const BM25F_BODY_B_SCALED_V1: u64 = 750_000;
pub const BM25F_IDENTIFIER_B_SCALED_V1: u64 = 250_000;
pub const BM25F_BODY_WEIGHT_SCALED_V1: u64 = 1_000_000;
pub const BM25F_IDENTIFIER_WEIGHT_SCALED_V1: u64 = 2_000_000;
pub const BM25F_MAX_QUERY_BYTES_V1: usize = 16 * 1024;
pub const BM25F_MAX_EVENT_BYTES_V1: usize = 1024 * 1024;
pub const BM25F_MAX_QUERY_TOKENS_V1: usize = 128;
pub const BM25F_MAX_EVENT_TOKENS_V1: usize = 8 * 1024;
pub const BM25F_MAX_TOKEN_BYTES_V1: usize = 64;

/// Closed V1 configuration. There is no caller-tunable scoring surface.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bm25fConfigV1;

impl Bm25fConfigV1 {
    #[must_use]
    pub fn digest(self) -> ArtifactDigest {
        let mut hasher = Sha256::new();
        hasher.update(CONFIG_DOMAIN_V1);
        hash_field(&mut hasher, TOKENIZER_CONTRACT_V1);
        hash_field(&mut hasher, SCORING_CONTRACT_V1);
        hash_field(&mut hasher, FIELD_CONTRACT_V1);
        hash_field(&mut hasher, TIE_CONTRACT_V1);
        hash_field(&mut hasher, BUDGET_CONTRACT_V1);
        hash_field(&mut hasher, METHOD_NAME_V1);
        hash_field(&mut hasher, METHOD_VERSION_V1);
        for value in [
            BM25F_SCORE_SCALE_V1,
            BM25F_K1_SCALED_V1,
            BM25F_BODY_B_SCALED_V1,
            BM25F_IDENTIFIER_B_SCALED_V1,
            BM25F_BODY_WEIGHT_SCALED_V1,
            BM25F_IDENTIFIER_WEIGHT_SCALED_V1,
            u64::try_from(BM25F_MAX_QUERY_BYTES_V1).expect("bounded constant"),
            u64::try_from(BM25F_MAX_EVENT_BYTES_V1).expect("bounded constant"),
            u64::try_from(BM25F_MAX_QUERY_TOKENS_V1).expect("bounded constant"),
            u64::try_from(BM25F_MAX_EVENT_TOKENS_V1).expect("bounded constant"),
            u64::try_from(BM25F_MAX_TOKEN_BYTES_V1).expect("bounded constant"),
        ] {
            hasher.update(value.to_be_bytes());
        }
        ArtifactDigest::from_bytes(hasher.finalize().into())
    }

    #[must_use]
    pub const fn tokenizer_contract(self) -> &'static str {
        "ascii_lower_bounded_v1"
    }

    #[must_use]
    pub const fn scoring_contract(self) -> &'static str {
        "fixed_point_bm25f_style_v1"
    }

    #[must_use]
    pub const fn tie_contract(self) -> &'static str {
        "score_desc_source_ordinal_asc_v1"
    }
}

/// One contentless scoring failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bm25fErrorV1 {
    QueryByteBoundExceeded,
    EventByteBoundExceeded,
    QueryTokenBoundExceeded,
    EventTokenBoundExceeded,
    ArithmeticOverflow,
}

impl Bm25fErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::QueryByteBoundExceeded => "EVIDENTRAIL_BENCH_BM25F_QUERY_BYTE_BOUND",
            Self::EventByteBoundExceeded => "EVIDENTRAIL_BENCH_BM25F_EVENT_BYTE_BOUND",
            Self::QueryTokenBoundExceeded => "EVIDENTRAIL_BENCH_BM25F_QUERY_TOKEN_BOUND",
            Self::EventTokenBoundExceeded => "EVIDENTRAIL_BENCH_BM25F_EVENT_TOKEN_BOUND",
            Self::ArithmeticOverflow => "EVIDENTRAIL_BENCH_BM25F_ARITHMETIC",
        }
    }
}

impl fmt::Display for Bm25fErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for Bm25fErrorV1 {}

/// Public score audit. Event bytes and matched terms are deliberately absent.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Bm25fScoredEventV1 {
    event_id: EventId,
    source_ordinal: u64,
    score_scaled: u64,
    matched_unique_query_terms: usize,
}

impl Bm25fScoredEventV1 {
    #[must_use]
    pub const fn event_id(self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn score_scaled(self) -> u64 {
        self.score_scaled
    }

    #[must_use]
    pub const fn matched_unique_query_terms(self) -> usize {
        self.matched_unique_query_terms
    }
}

impl fmt::Debug for Bm25fScoredEventV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Bm25fScoredEventV1")
            .field("event_id_present", &true)
            .field("source_ordinal", &self.source_ordinal)
            .field("score_scaled", &self.score_scaled)
            .field(
                "matched_unique_query_terms",
                &self.matched_unique_query_terms,
            )
            .finish()
    }
}

/// Deterministic whole-event BM25F-style benchmark arm.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bm25fWholeEventV1 {
    config: Bm25fConfigV1,
}

impl Bm25fWholeEventV1 {
    pub const DESCRIPTOR: MethodDescriptor = MethodDescriptor::new("bm25f-whole-event", "1");

    #[must_use]
    pub const fn new(config: Bm25fConfigV1) -> Self {
        Self { config }
    }

    #[must_use]
    pub const fn config(self) -> Bm25fConfigV1 {
        self.config
    }

    pub fn rank(
        &self,
        ledger: &EventLedger,
        query: &[u8],
    ) -> Result<Vec<Bm25fScoredEventV1>, Bm25fErrorV1> {
        rank_documents(ledger, query)
    }
}

impl BenchmarkMethod for Bm25fWholeEventV1 {
    fn descriptor(&self) -> MethodDescriptor {
        Self::DESCRIPTOR
    }

    fn run(&self, input: MethodInput<'_>) -> Result<MethodResult, MethodError> {
        let ranked = self
            .rank(input.ledger(), input.query())
            .map_err(|_| MethodError::LexicalScoringFailure)?;
        let ordinal_by_id = input
            .ledger()
            .events()
            .iter()
            .enumerate()
            .map(|(ordinal, event)| (event.id(), ordinal))
            .collect::<BTreeMap<_, _>>();
        let candidate_ordinals = ranked
            .iter()
            .map(|scored| ordinal_by_id[&scored.event_id])
            .collect::<BTreeSet<_>>();
        let mut selected = BTreeMap::new();
        let mut selected_bytes = 0usize;
        let mut budget_excluded = 0usize;
        for scored in ranked {
            let ordinal = ordinal_by_id[&scored.event_id];
            let event_bytes = input.ledger().events()[ordinal].raw().len();
            let Some(new_cost) =
                checked_cost_within_budget(selected_bytes, event_bytes, input.budget())?
            else {
                budget_excluded = budget_excluded
                    .checked_add(1)
                    .ok_or(MethodError::SourceByteCostOverflow)?;
                continue;
            };
            selected_bytes = new_cost;
            selected.insert(ordinal, vec![SelectionReason::QueryTermMatch]);
        }
        build_result(
            self.descriptor(),
            input.ledger(),
            input.budget(),
            &candidate_ordinals,
            budget_excluded,
            selected,
        )
    }
}

#[derive(Clone)]
struct TokenizedDocument {
    event_id: EventId,
    source_ordinal: u64,
    body: BTreeMap<Vec<u8>, u64>,
    identifiers: BTreeMap<Vec<u8>, u64>,
    body_len: u64,
    identifier_len: u64,
}

fn rank_documents(
    ledger: &EventLedger,
    query: &[u8],
) -> Result<Vec<Bm25fScoredEventV1>, Bm25fErrorV1> {
    let query_tokens = tokenize(
        query,
        BM25F_MAX_QUERY_BYTES_V1,
        BM25F_MAX_QUERY_TOKENS_V1,
        true,
    )?;
    let query_terms = query_tokens.into_iter().collect::<BTreeSet<_>>();
    if query_terms.is_empty() || ledger.is_empty() {
        return Ok(Vec::new());
    }

    let documents = ledger
        .events()
        .iter()
        .map(|event| tokenized_document(event.id(), event.ordinal(), event.raw()))
        .collect::<Result<Vec<_>, _>>()?;
    let document_count = checked_u64(documents.len())?;
    let total_body_len = checked_sum(documents.iter().map(|document| document.body_len))?;
    let total_identifier_len =
        checked_sum(documents.iter().map(|document| document.identifier_len))?;

    let document_frequencies = query_terms
        .iter()
        .map(|term| {
            let frequency = documents
                .iter()
                .filter(|document| {
                    document.body.contains_key(term) || document.identifiers.contains_key(term)
                })
                .count();
            Ok((term.clone(), checked_u64(frequency)?))
        })
        .collect::<Result<BTreeMap<_, _>, Bm25fErrorV1>>()?;

    let mut ranked = Vec::new();
    for document in &documents {
        let mut score = 0u64;
        let mut matched = 0usize;
        for term in &query_terms {
            let body_tf = document.body.get(term).copied().unwrap_or(0);
            let identifier_tf = document.identifiers.get(term).copied().unwrap_or(0);
            if body_tf == 0 && identifier_tf == 0 {
                continue;
            }
            matched = matched
                .checked_add(1)
                .ok_or(Bm25fErrorV1::ArithmeticOverflow)?;
            let body_weighted_tf = normalized_weighted_tf(
                body_tf,
                document.body_len,
                total_body_len,
                document_count,
                BM25F_BODY_B_SCALED_V1,
                BM25F_BODY_WEIGHT_SCALED_V1,
            )?;
            let identifier_weighted_tf = normalized_weighted_tf(
                identifier_tf,
                document.identifier_len,
                total_identifier_len,
                document_count,
                BM25F_IDENTIFIER_B_SCALED_V1,
                BM25F_IDENTIFIER_WEIGHT_SCALED_V1,
            )?;
            let weighted_tf = body_weighted_tf
                .checked_add(identifier_weighted_tf)
                .ok_or(Bm25fErrorV1::ArithmeticOverflow)?;
            let saturation = checked_mul_div(
                weighted_tf,
                BM25F_K1_SCALED_V1
                    .checked_add(BM25F_SCORE_SCALE_V1)
                    .ok_or(Bm25fErrorV1::ArithmeticOverflow)?,
                weighted_tf
                    .checked_add(BM25F_K1_SCALED_V1)
                    .ok_or(Bm25fErrorV1::ArithmeticOverflow)?,
            )?;
            let df = document_frequencies[term];
            let idf = BM25F_SCORE_SCALE_V1
                .checked_add(checked_mul_div(
                    document_count
                        .checked_sub(df)
                        .ok_or(Bm25fErrorV1::ArithmeticOverflow)?,
                    BM25F_SCORE_SCALE_V1,
                    df.checked_add(1).ok_or(Bm25fErrorV1::ArithmeticOverflow)?,
                )?)
                .ok_or(Bm25fErrorV1::ArithmeticOverflow)?;
            let contribution = checked_mul_div(idf, saturation, BM25F_SCORE_SCALE_V1)?;
            score = score
                .checked_add(contribution)
                .ok_or(Bm25fErrorV1::ArithmeticOverflow)?;
        }
        if score != 0 {
            ranked.push(Bm25fScoredEventV1 {
                event_id: document.event_id,
                source_ordinal: document.source_ordinal,
                score_scaled: score,
                matched_unique_query_terms: matched,
            });
        }
    }
    ranked.sort_unstable_by(|left, right| {
        right
            .score_scaled
            .cmp(&left.score_scaled)
            .then_with(|| left.source_ordinal.cmp(&right.source_ordinal))
    });
    Ok(ranked)
}

fn tokenized_document(
    event_id: EventId,
    source_ordinal: u64,
    raw: &[u8],
) -> Result<TokenizedDocument, Bm25fErrorV1> {
    let tokens = tokenize(
        raw,
        BM25F_MAX_EVENT_BYTES_V1,
        BM25F_MAX_EVENT_TOKENS_V1,
        false,
    )?;
    let body_len = checked_u64(tokens.len())?;
    let mut body = BTreeMap::new();
    let mut identifiers = BTreeMap::new();
    let mut identifier_len = 0u64;
    for token in tokens {
        increment_frequency(&mut body, token.clone())?;
        if is_identifier_token(&token) {
            increment_frequency(&mut identifiers, token)?;
            identifier_len = identifier_len
                .checked_add(1)
                .ok_or(Bm25fErrorV1::ArithmeticOverflow)?;
        }
    }
    Ok(TokenizedDocument {
        event_id,
        source_ordinal,
        body,
        identifiers,
        body_len,
        identifier_len,
    })
}

fn tokenize(
    input: &[u8],
    max_input_bytes: usize,
    max_tokens: usize,
    query: bool,
) -> Result<Vec<Vec<u8>>, Bm25fErrorV1> {
    if input.len() > max_input_bytes {
        return Err(if query {
            Bm25fErrorV1::QueryByteBoundExceeded
        } else {
            Bm25fErrorV1::EventByteBoundExceeded
        });
    }
    let mut tokens = Vec::new();
    let mut current = Vec::new();
    let mut overlong = false;
    for byte in input.iter().copied().chain(std::iter::once(b' ')) {
        if is_token_byte(byte) {
            if current.len() < BM25F_MAX_TOKEN_BYTES_V1 {
                current.push(byte.to_ascii_lowercase());
            } else {
                overlong = true;
            }
            continue;
        }
        if !current.is_empty() && !overlong {
            if tokens.len() == max_tokens {
                return Err(if query {
                    Bm25fErrorV1::QueryTokenBoundExceeded
                } else {
                    Bm25fErrorV1::EventTokenBoundExceeded
                });
            }
            tokens.push(std::mem::take(&mut current));
        }
        current.clear();
        overlong = false;
    }
    Ok(tokens)
}

const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

fn is_identifier_token(token: &[u8]) -> bool {
    token
        .iter()
        .any(|byte| byte.is_ascii_digit() || matches!(*byte, b'_' | b'-' | b'.'))
}

fn increment_frequency(
    frequencies: &mut BTreeMap<Vec<u8>, u64>,
    token: Vec<u8>,
) -> Result<(), Bm25fErrorV1> {
    let count = frequencies.entry(token).or_default();
    *count = count
        .checked_add(1)
        .ok_or(Bm25fErrorV1::ArithmeticOverflow)?;
    Ok(())
}

fn normalized_weighted_tf(
    term_frequency: u64,
    document_length: u64,
    total_field_length: u64,
    document_count: u64,
    b_scaled: u64,
    weight_scaled: u64,
) -> Result<u64, Bm25fErrorV1> {
    if term_frequency == 0 {
        return Ok(0);
    }
    let length_component = if total_field_length == 0 {
        0
    } else {
        checked_mul3_div(
            b_scaled,
            document_length,
            document_count,
            total_field_length,
        )?
    };
    let normalization = BM25F_SCORE_SCALE_V1
        .checked_sub(b_scaled)
        .and_then(|base| base.checked_add(length_component))
        .ok_or(Bm25fErrorV1::ArithmeticOverflow)?;
    checked_mul3_div(
        term_frequency,
        weight_scaled,
        BM25F_SCORE_SCALE_V1,
        normalization,
    )
}

fn checked_mul_div(left: u64, right: u64, denominator: u64) -> Result<u64, Bm25fErrorV1> {
    if denominator == 0 {
        return Err(Bm25fErrorV1::ArithmeticOverflow);
    }
    let value = u128::from(left)
        .checked_mul(u128::from(right))
        .ok_or(Bm25fErrorV1::ArithmeticOverflow)?
        / u128::from(denominator);
    u64::try_from(value).map_err(|_| Bm25fErrorV1::ArithmeticOverflow)
}

fn checked_mul3_div(
    first: u64,
    second: u64,
    third: u64,
    denominator: u64,
) -> Result<u64, Bm25fErrorV1> {
    if denominator == 0 {
        return Err(Bm25fErrorV1::ArithmeticOverflow);
    }
    let value = u128::from(first)
        .checked_mul(u128::from(second))
        .and_then(|value| value.checked_mul(u128::from(third)))
        .ok_or(Bm25fErrorV1::ArithmeticOverflow)?
        / u128::from(denominator);
    u64::try_from(value).map_err(|_| Bm25fErrorV1::ArithmeticOverflow)
}

fn checked_sum(mut values: impl Iterator<Item = u64>) -> Result<u64, Bm25fErrorV1> {
    values.try_fold(0u64, |sum, value| {
        sum.checked_add(value)
            .ok_or(Bm25fErrorV1::ArithmeticOverflow)
    })
}

fn checked_u64(value: usize) -> Result<u64, Bm25fErrorV1> {
    u64::try_from(value).map_err(|_| Bm25fErrorV1::ArithmeticOverflow)
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(
        u64::try_from(value.len())
            .expect("bounded static contract")
            .to_be_bytes(),
    );
    hasher.update(value);
}
