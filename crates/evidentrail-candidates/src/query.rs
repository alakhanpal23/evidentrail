use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;

use evidentrail_core::{QuestionDigest, derive_question_digest_v1};

use crate::bounds::{
    MAX_QUERY_TERM_BYTES_V1, MAX_QUERY_TERMS_V1, MAX_QUERY_TOKENS_V1, MAX_QUESTION_BYTES_V1,
    MAX_VALIDATED_QUERY_IDENTIFIERS_V1, MIN_QUERY_TERM_BYTES_V1,
};
use crate::types::{CandidateNeedsMoreReasonV1, CandidateNeedsMoreV1};

/// Closed V1 identifier grammar. Shape alone never creates another kind.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValidatedIdentifierKindV1 {
    CanonicalUuid,
    TraceIdHex128,
    SpanIdHex64,
    RustCompilerErrorCode,
}

impl ValidatedIdentifierKindV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::CanonicalUuid => "canonical_uuid",
            Self::TraceIdHex128 => "trace_id_hex_128",
            Self::SpanIdHex64 => "span_id_hex_64",
            Self::RustCompilerErrorCode => "rust_compiler_error_code",
        }
    }
}

impl fmt::Debug for ValidatedIdentifierKindV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedIdentifierKindV1")
            .field("code", &self.code())
            .finish()
    }
}

/// One canonical lowercase ASCII free-text term. Debug never exposes it.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct QueryTermV1 {
    canonical_token: Vec<u8>,
}

impl QueryTermV1 {
    #[must_use]
    pub fn canonical_token(&self) -> &[u8] {
        &self.canonical_token
    }
}

impl fmt::Debug for QueryTermV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueryTermV1")
            .field("token_bytes", &self.canonical_token.len())
            .finish()
    }
}

/// One syntactically validated canonical identifier. Trace/span hex requires
/// an explicit type label in the question; UUIDs and Rust E-codes carry their
/// own closed syntax.
#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedQueryIdentifierV1 {
    kind: ValidatedIdentifierKindV1,
    canonical_token: Vec<u8>,
}

impl ValidatedQueryIdentifierV1 {
    #[must_use]
    pub const fn kind(&self) -> ValidatedIdentifierKindV1 {
        self.kind
    }

    #[must_use]
    pub fn canonical_token(&self) -> &[u8] {
        &self.canonical_token
    }

    pub(crate) fn canonical_semantic_key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(self.kind.code().len() + 1 + self.canonical_token.len());
        key.extend_from_slice(self.kind.code().as_bytes());
        key.push(0);
        key.extend_from_slice(&self.canonical_token);
        key
    }
}

impl fmt::Debug for ValidatedQueryIdentifierV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedQueryIdentifierV1")
            .field("kind", &self.kind)
            .field("token_bytes", &self.canonical_token.len())
            .finish()
    }
}

/// Bounded canonical query material. It retains no original question bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct PreprocessedQueryV1 {
    question_digest: QuestionDigest,
    terms: Vec<QueryTermV1>,
    identifiers: Vec<ValidatedQueryIdentifierV1>,
}

impl PreprocessedQueryV1 {
    #[must_use]
    pub const fn question_digest(&self) -> QuestionDigest {
        self.question_digest
    }

    #[must_use]
    pub fn terms(&self) -> &[QueryTermV1] {
        &self.terms
    }

    #[must_use]
    pub fn identifiers(&self) -> &[ValidatedQueryIdentifierV1] {
        &self.identifiers
    }
}

impl fmt::Debug for PreprocessedQueryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreprocessedQueryV1")
            .field("term_count", &self.terms.len())
            .field("identifier_count", &self.identifiers.len())
            .finish()
    }
}

/// Preprocess exact question bytes without UTF-8 decoding or lossy repair.
/// ASCII token order and case do not affect canonical term identities.
pub fn preprocess_query_v1(question: &[u8]) -> Result<PreprocessedQueryV1, CandidateNeedsMoreV1> {
    if question.len() > MAX_QUESTION_BYTES_V1 {
        return Err(CandidateNeedsMoreV1::new(
            CandidateNeedsMoreReasonV1::QuestionBytesCap,
        ));
    }

    let mut tokens = Vec::new();
    for_each_ascii_token(question, |token| {
        if tokens.len() >= MAX_QUERY_TOKENS_V1 {
            return false;
        }
        if token.len() > MAX_QUERY_TERM_BYTES_V1 {
            tokens.push(Vec::new());
            return false;
        }
        tokens.push(canonicalize_ascii(token));
        true
    });
    if tokens.last().is_some_and(Vec::is_empty) {
        return Err(CandidateNeedsMoreV1::new(
            CandidateNeedsMoreReasonV1::QueryTokenBytesCap,
        ));
    }
    if count_ascii_tokens_up_to(question, MAX_QUERY_TOKENS_V1 + 1) > MAX_QUERY_TOKENS_V1 {
        return Err(CandidateNeedsMoreV1::new(
            CandidateNeedsMoreReasonV1::QueryTokenCountCap,
        ));
    }

    let mut identifier_material = BTreeSet::new();
    for (position, token) in tokens.iter().enumerate() {
        let kind = if is_canonical_uuid(token) {
            Some(ValidatedIdentifierKindV1::CanonicalUuid)
        } else if is_rust_error_code(token) {
            Some(ValidatedIdentifierKindV1::RustCompilerErrorCode)
        } else if has_trace_label(&tokens, position) && is_trace_hex(token, 32) {
            Some(ValidatedIdentifierKindV1::TraceIdHex128)
        } else if has_span_label(&tokens, position) && is_trace_hex(token, 16) {
            Some(ValidatedIdentifierKindV1::SpanIdHex64)
        } else {
            None
        };
        if let Some(kind) = kind {
            identifier_material.insert((kind, token.clone()));
        }
    }
    if identifier_material.len() > MAX_VALIDATED_QUERY_IDENTIFIERS_V1 {
        return Err(CandidateNeedsMoreV1::new(
            CandidateNeedsMoreReasonV1::ValidatedIdentifierCountCap,
        ));
    }
    let identifier_tokens = identifier_material
        .iter()
        .map(|(_, token)| token.clone())
        .collect::<BTreeSet<_>>();

    let terms = tokens
        .into_iter()
        .filter(|token| token.len() >= MIN_QUERY_TERM_BYTES_V1)
        .filter(|token| !identifier_tokens.contains(token))
        .filter(|token| !is_stop_term(token) && !is_identifier_label(token))
        .collect::<BTreeSet<_>>();
    if terms.len() > MAX_QUERY_TERMS_V1 {
        return Err(CandidateNeedsMoreV1::new(
            CandidateNeedsMoreReasonV1::QueryTermCountCap,
        ));
    }

    let terms = terms
        .into_iter()
        .map(|canonical_token| QueryTermV1 { canonical_token })
        .collect();
    let mut identifiers = identifier_material
        .into_iter()
        .map(|(kind, canonical_token)| ValidatedQueryIdentifierV1 {
            kind,
            canonical_token,
        })
        .collect::<Vec<_>>();
    identifiers.sort_unstable_by(|left, right| {
        left.canonical_token
            .cmp(&right.canonical_token)
            .then_with(|| left.kind.cmp(&right.kind))
    });

    Ok(PreprocessedQueryV1 {
        question_digest: derive_question_digest_v1(question),
        terms,
        identifiers,
    })
}

/// Visit a bounded dual analysis of each ASCII compound: the intact compound
/// first, then its exact slash components, then exact dot/hyphen components.
/// This preserves path facets while allowing a typed identifier in a path to
/// match as a complete component. No component is produced by substring or
/// partial-prefix matching.
pub(crate) fn for_each_ascii_token(bytes: &[u8], mut visit: impl FnMut(&[u8]) -> bool) {
    let mut start = None;
    for (position, byte) in bytes.iter().copied().enumerate() {
        if is_token_byte(byte) {
            start.get_or_insert(position);
        } else if let Some(token_start) = start.take() {
            let token = trim_token_punctuation(&bytes[token_start..position]);
            if !token.is_empty() && !visit_compound_tokens(token, &mut visit) {
                return;
            }
        }
    }
    if let Some(token_start) = start {
        let token = trim_token_punctuation(&bytes[token_start..]);
        if !token.is_empty() {
            let _ = visit_compound_tokens(token, &mut visit);
        }
    }
}

fn visit_compound_tokens(token: &[u8], visit: &mut impl FnMut(&[u8]) -> bool) -> bool {
    if !visit(token) {
        return false;
    }
    for slash_component in token.split(|byte| *byte == b'/') {
        let slash_component = trim_token_punctuation(slash_component);
        if slash_component.is_empty() {
            continue;
        }
        if slash_component != token && !visit(slash_component) {
            return false;
        }
        // A canonical UUID must remain available as one typed value. Splitting
        // its hyphens would only create noisy free-text facets.
        if is_canonical_uuid(slash_component) {
            continue;
        }
        for component in slash_component.split(|byte| matches!(byte, b'.' | b'-')) {
            if component.is_empty() || component == slash_component || component == token {
                continue;
            }
            if !visit(component) {
                return false;
            }
        }
    }
    true
}

pub(crate) fn compare_canonical_to_raw(canonical: &[u8], raw: &[u8]) -> Ordering {
    canonical
        .iter()
        .copied()
        .cmp(raw.iter().map(u8::to_ascii_lowercase))
}

fn count_ascii_tokens_up_to(bytes: &[u8], limit: usize) -> usize {
    let mut count = 0usize;
    for_each_ascii_token(bytes, |_| {
        let Some(next) = count.checked_add(1) else {
            return false;
        };
        count = next;
        count < limit
    });
    count
}

fn canonicalize_ascii(token: &[u8]) -> Vec<u8> {
    token.iter().map(u8::to_ascii_lowercase).collect()
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/')
}

fn trim_token_punctuation(mut token: &[u8]) -> &[u8] {
    while token
        .first()
        .is_some_and(|byte| matches!(byte, b'.' | b'-'))
    {
        token = &token[1..];
    }
    while token.last().is_some_and(|byte| matches!(byte, b'.' | b'-')) {
        token = &token[..token.len() - 1];
    }
    token
}

fn is_canonical_uuid(token: &[u8]) -> bool {
    if token.len() != 36 {
        return false;
    }
    for (position, byte) in token.iter().copied().enumerate() {
        if matches!(position, 8 | 13 | 18 | 23) {
            if byte != b'-' {
                return false;
            }
        } else if !byte.is_ascii_hexdigit() {
            return false;
        }
    }
    matches!(token[14], b'1'..=b'8') && matches!(token[19], b'8' | b'9' | b'a' | b'b')
}

fn is_rust_error_code(token: &[u8]) -> bool {
    token.len() == 5
        && token[0] == b'e'
        && token[1..].iter().all(u8::is_ascii_digit)
        && token[1..] != *b"0000"
}

fn is_trace_hex(token: &[u8], expected_len: usize) -> bool {
    token.len() == expected_len
        && token.iter().all(u8::is_ascii_hexdigit)
        && token.iter().any(|byte| *byte != b'0')
}

fn is_trace_label(token: &[u8]) -> bool {
    matches!(
        token,
        b"trace" | b"trace_id" | b"trace-id" | b"trace.id" | b"traceid"
    )
}

fn is_span_label(token: &[u8]) -> bool {
    matches!(
        token,
        b"span" | b"span_id" | b"span-id" | b"span.id" | b"spanid"
    )
}

fn has_trace_label(tokens: &[Vec<u8>], value_position: usize) -> bool {
    value_position
        .checked_sub(1)
        .is_some_and(|position| is_trace_label(&tokens[position]))
        || value_position
            .checked_sub(2)
            .is_some_and(|position| tokens[position] == b"trace" && tokens[position + 1] == b"id")
}

fn has_span_label(tokens: &[Vec<u8>], value_position: usize) -> bool {
    value_position
        .checked_sub(1)
        .is_some_and(|position| is_span_label(&tokens[position]))
        || value_position
            .checked_sub(2)
            .is_some_and(|position| tokens[position] == b"span" && tokens[position + 1] == b"id")
}

fn is_identifier_label(token: &[u8]) -> bool {
    is_trace_label(token) || is_span_label(token)
}

fn is_stop_term(token: &[u8]) -> bool {
    matches!(
        token,
        b"an"
            | b"and"
            | b"are"
            | b"did"
            | b"do"
            | b"does"
            | b"for"
            | b"from"
            | b"how"
            | b"in"
            | b"is"
            | b"it"
            | b"log"
            | b"logs"
            | b"of"
            | b"on"
            | b"the"
            | b"to"
            | b"was"
            | b"were"
            | b"what"
            | b"when"
            | b"where"
            | b"why"
            | b"with"
    )
}
