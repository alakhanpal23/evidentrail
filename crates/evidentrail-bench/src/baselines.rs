use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use crate::method::{
    BenchmarkMethod, MethodDescriptor, MethodError, MethodInput, MethodResult, SelectionReason,
    build_result, checked_cost_within_budget,
};

/// Raw source-order prefix truncated only at whole-event boundaries.
#[derive(Clone, Copy, Debug, Default)]
pub struct RawChronological;

impl RawChronological {
    pub const DESCRIPTOR: MethodDescriptor = MethodDescriptor::new("raw-chronological", "1");
}

impl BenchmarkMethod for RawChronological {
    fn descriptor(&self) -> MethodDescriptor {
        Self::DESCRIPTOR
    }

    fn run(&self, input: MethodInput<'_>) -> Result<MethodResult, MethodError> {
        let ledger = input.ledger();
        let budget = input.budget();
        let mut selected = BTreeMap::new();
        let mut selected_bytes = 0usize;

        for (ordinal, event) in ledger.events().iter().enumerate() {
            let Some(new_cost) =
                checked_cost_within_budget(selected_bytes, event.raw().len(), budget)?
            else {
                break;
            };
            selected_bytes = new_cost;
            selected.insert(ordinal, vec![SelectionReason::Chronological]);
        }

        let budget_excluded = ledger.len() - selected.len();
        let candidates = (0..ledger.len()).collect::<BTreeSet<_>>();
        build_result(
            self.descriptor(),
            ledger,
            budget,
            &candidates,
            budget_excluded,
            selected,
        )
    }
}

/// Configuration for the query-term grep plus tail/head sentinel baseline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrepHeadTailConfig {
    head_events: usize,
    tail_events: usize,
}

impl GrepHeadTailConfig {
    #[must_use]
    pub const fn new(head_events: usize, tail_events: usize) -> Self {
        Self {
            head_events,
            tail_events,
        }
    }

    #[must_use]
    pub const fn head_events(self) -> usize {
        self.head_events
    }

    #[must_use]
    pub const fn tail_events(self) -> usize {
        self.tail_events
    }
}

impl Default for GrepHeadTailConfig {
    fn default() -> Self {
        Self::new(20, 200)
    }
}

/// Deterministic ASCII query-term grep, followed by tail and head sentinels.
///
/// The baseline retains an exact full-query match and identifier-like terms,
/// tokenizes ordinary ASCII terms, removes only a fixed stopword/short-noise
/// set, and orders candidates by full-query exactness, identifier exactness,
/// exact token matches, matched term count, and term specificity. Source
/// ordinal is the final tie-break. Query candidates receive budget priority,
/// then tail events, then head events. Selected output is always restored to
/// original source order. Oversized candidates are skipped whole so another
/// candidate can still fit; no event is sliced to fill the budget.
#[derive(Clone, Copy, Debug, Default)]
pub struct GrepHeadTail {
    config: GrepHeadTailConfig,
}

impl GrepHeadTail {
    pub const DESCRIPTOR: MethodDescriptor = MethodDescriptor::new("grep-head-tail", "1");

    #[must_use]
    pub const fn new(config: GrepHeadTailConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub const fn config(self) -> GrepHeadTailConfig {
        self.config
    }
}

impl BenchmarkMethod for GrepHeadTail {
    fn descriptor(&self) -> MethodDescriptor {
        Self::DESCRIPTOR
    }

    fn run(&self, input: MethodInput<'_>) -> Result<MethodResult, MethodError> {
        let ledger = input.ledger();
        let query = input.query();
        let budget = input.budget();
        let event_count = ledger.len();
        let head_end = self.config.head_events.min(event_count);
        let tail_start = event_count.saturating_sub(self.config.tail_events);

        let query_analysis = QueryAnalysis::new(query);
        let query_candidates = query_analysis.rank(ledger);
        let query_features = query_candidates
            .iter()
            .map(|candidate| (candidate.ordinal, candidate.features))
            .collect::<BTreeMap<_, _>>();

        let mut priority = Vec::new();
        priority.extend(query_candidates.iter().map(|candidate| candidate.ordinal));
        priority.extend(tail_start..event_count);
        priority.extend(0..head_end);

        let candidate_ordinals = priority.iter().copied().collect::<BTreeSet<_>>();
        let mut visited = BTreeSet::new();
        let mut selected = BTreeMap::new();
        let mut selected_bytes = 0usize;
        let mut budget_excluded = 0usize;

        for ordinal in priority {
            if !visited.insert(ordinal) {
                continue;
            }
            let event = &ledger.events()[ordinal];
            let Some(new_cost) =
                checked_cost_within_budget(selected_bytes, event.raw().len(), budget)?
            else {
                budget_excluded += 1;
                continue;
            };
            selected_bytes = new_cost;
            selected.insert(
                ordinal,
                selection_reasons(
                    ordinal,
                    event_count,
                    head_end,
                    tail_start,
                    query_features.get(&ordinal).copied(),
                ),
            );
        }

        build_result(
            self.descriptor(),
            ledger,
            budget,
            &candidate_ordinals,
            budget_excluded,
            selected,
        )
    }
}

/// Independent byte reservations for a four-view deterministic baseline.
///
/// The reservations must fit within the request's [`crate::ByteBudget`]. Any
/// bytes not spent during the reservation pass, plus any request budget not
/// reserved here, are redistributed by [`QuotaHybrid`] in a fixed round-robin
/// order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuotaHybridConfig {
    query_bytes: usize,
    head_bytes: usize,
    tail_bytes: usize,
    coverage_bytes: usize,
    head_events: usize,
    tail_events: usize,
    coverage_sentinels: usize,
}

impl QuotaHybridConfig {
    #[must_use]
    pub const fn new(
        query_bytes: usize,
        head_bytes: usize,
        tail_bytes: usize,
        coverage_bytes: usize,
        head_events: usize,
        tail_events: usize,
        coverage_sentinels: usize,
    ) -> Self {
        Self {
            query_bytes,
            head_bytes,
            tail_bytes,
            coverage_bytes,
            head_events,
            tail_events,
            coverage_sentinels,
        }
    }

    #[must_use]
    pub const fn query_bytes(self) -> usize {
        self.query_bytes
    }

    #[must_use]
    pub const fn head_bytes(self) -> usize {
        self.head_bytes
    }

    #[must_use]
    pub const fn tail_bytes(self) -> usize {
        self.tail_bytes
    }

    #[must_use]
    pub const fn coverage_bytes(self) -> usize {
        self.coverage_bytes
    }

    #[must_use]
    pub const fn head_events(self) -> usize {
        self.head_events
    }

    #[must_use]
    pub const fn tail_events(self) -> usize {
        self.tail_events
    }

    #[must_use]
    pub const fn coverage_sentinels(self) -> usize {
        self.coverage_sentinels
    }

    fn reserved_bytes(self) -> Result<usize, MethodError> {
        self.query_bytes
            .checked_add(self.head_bytes)
            .and_then(|sum| sum.checked_add(self.tail_bytes))
            .and_then(|sum| sum.checked_add(self.coverage_bytes))
            .ok_or(MethodError::SourceByteCostOverflow)
    }
}

/// Query/identifier retrieval with protected head, tail, and coverage quotas.
///
/// Each view first spends only its own byte reservation. An event already
/// selected by another view is free for the current view and still receives
/// every applicable selection reason. Remaining capacity is then redistributed
/// one candidate per view in the stable order query, head, tail, coverage.
/// Tail candidates run newest-first; output is restored to source order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuotaHybrid {
    config: QuotaHybridConfig,
}

impl QuotaHybrid {
    pub const DESCRIPTOR: MethodDescriptor = MethodDescriptor::new("quota-hybrid", "1");

    #[must_use]
    pub const fn new(config: QuotaHybridConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub const fn config(self) -> QuotaHybridConfig {
        self.config
    }
}

impl BenchmarkMethod for QuotaHybrid {
    fn descriptor(&self) -> MethodDescriptor {
        Self::DESCRIPTOR
    }

    fn run(&self, input: MethodInput<'_>) -> Result<MethodResult, MethodError> {
        let ledger = input.ledger();
        let budget = input.budget();
        if self.config.reserved_bytes()? > budget.bytes() {
            return Err(MethodError::ReservedQuotaExceedsBudget);
        }

        let event_count = ledger.len();
        let head_end = self.config.head_events.min(event_count);
        let tail_start = event_count.saturating_sub(self.config.tail_events);
        let query_candidates = QueryAnalysis::new(input.query()).rank(ledger);
        let query_features = query_candidates
            .iter()
            .map(|candidate| (candidate.ordinal, candidate.features))
            .collect::<BTreeMap<_, _>>();
        let query_ordinals = query_candidates
            .iter()
            .map(|candidate| candidate.ordinal)
            .collect::<Vec<_>>();
        let head_ordinals = (0..head_end).collect::<Vec<_>>();
        let tail_ordinals = (tail_start..event_count).rev().collect::<Vec<_>>();
        let coverage_ordinals = evenly_spaced_ordinals(event_count, self.config.coverage_sentinels);
        let lanes = [
            Lane::new(&query_ordinals, self.config.query_bytes),
            Lane::new(&head_ordinals, self.config.head_bytes),
            Lane::new(&tail_ordinals, self.config.tail_bytes),
            Lane::new(&coverage_ordinals, self.config.coverage_bytes),
        ];

        let candidate_ordinals = lanes
            .iter()
            .flat_map(|lane| lane.ordinals.iter().copied())
            .collect::<BTreeSet<_>>();
        let coverage_set = coverage_ordinals.iter().copied().collect::<BTreeSet<_>>();

        let mut selected_ordinals = BTreeSet::new();
        let mut selected_bytes = 0usize;
        for lane in &lanes {
            let mut lane_bytes = 0usize;
            for ordinal in lane.ordinals {
                if selected_ordinals.contains(ordinal) {
                    continue;
                }
                let event_bytes = ledger.events()[*ordinal].raw().len();
                let Some(new_lane_bytes) = checked_cost_within_budget(
                    lane_bytes,
                    event_bytes,
                    crate::ByteBudget::new(lane.byte_quota),
                )?
                else {
                    continue;
                };
                let Some(new_selected_bytes) =
                    checked_cost_within_budget(selected_bytes, event_bytes, budget)?
                else {
                    continue;
                };
                lane_bytes = new_lane_bytes;
                selected_bytes = new_selected_bytes;
                selected_ordinals.insert(*ordinal);
            }
        }

        let maximum_lane_len = lanes
            .iter()
            .map(|lane| lane.ordinals.len())
            .max()
            .unwrap_or(0);
        let mut redistribution_seen = BTreeSet::new();
        for position in 0..maximum_lane_len {
            for lane in &lanes {
                let Some(ordinal) = lane.ordinals.get(position).copied() else {
                    continue;
                };
                if selected_ordinals.contains(&ordinal) || !redistribution_seen.insert(ordinal) {
                    continue;
                }
                let event_bytes = ledger.events()[ordinal].raw().len();
                let Some(new_selected_bytes) =
                    checked_cost_within_budget(selected_bytes, event_bytes, budget)?
                else {
                    continue;
                };
                selected_bytes = new_selected_bytes;
                selected_ordinals.insert(ordinal);
            }
        }

        let selected = selected_ordinals
            .iter()
            .map(|ordinal| {
                let mut reasons = selection_reasons(
                    *ordinal,
                    event_count,
                    head_end,
                    tail_start,
                    query_features.get(ordinal).copied(),
                );
                if coverage_set.contains(ordinal) {
                    reasons.push(SelectionReason::CoverageSentinel);
                }
                (*ordinal, reasons)
            })
            .collect::<BTreeMap<_, _>>();
        let budget_excluded = candidate_ordinals.len() - selected.len();

        build_result(
            self.descriptor(),
            ledger,
            budget,
            &candidate_ordinals,
            budget_excluded,
            selected,
        )
    }
}

#[derive(Clone, Copy)]
struct Lane<'a> {
    ordinals: &'a [usize],
    byte_quota: usize,
}

impl<'a> Lane<'a> {
    const fn new(ordinals: &'a [usize], byte_quota: usize) -> Self {
        Self {
            ordinals,
            byte_quota,
        }
    }
}

fn evenly_spaced_ordinals(event_count: usize, requested: usize) -> Vec<usize> {
    let sentinel_count = requested.min(event_count);
    if sentinel_count == 0 {
        return Vec::new();
    }

    (0..sentinel_count)
        .map(|index| {
            let numerator = (2 * index as u128 + 1) * event_count as u128;
            let denominator = 2 * sentinel_count as u128;
            (numerator / denominator) as usize
        })
        .collect()
}

fn selection_reasons(
    ordinal: usize,
    event_count: usize,
    head_end: usize,
    tail_start: usize,
    query_features: Option<QueryMatchFeatures>,
) -> Vec<SelectionReason> {
    let mut reasons = Vec::with_capacity(5);
    if let Some(features) = query_features {
        if features.full_query_match {
            reasons.push(SelectionReason::FullQueryMatch);
        }
        if features.identifier_exact_matches != 0 {
            reasons.push(SelectionReason::IdentifierMatch);
        }
        if features.matched_terms != 0 {
            reasons.push(SelectionReason::QueryTermMatch);
        }
    }
    if ordinal < head_end {
        reasons.push(SelectionReason::HeadSentinel);
    }
    if ordinal >= tail_start && ordinal < event_count {
        reasons.push(SelectionReason::TailSentinel);
    }
    reasons
}

#[derive(Clone, PartialEq, Eq)]
struct QueryTerm {
    normalized: Vec<u8>,
    identifier_like: bool,
}

struct QueryAnalysis<'a> {
    full_query: &'a [u8],
    terms: Vec<QueryTerm>,
}

impl<'a> QueryAnalysis<'a> {
    fn new(query: &'a [u8]) -> Self {
        Self {
            full_query: trim_ascii_whitespace(query),
            terms: query_terms(query),
        }
    }

    fn rank(&self, ledger: &evidentrail_core::EventLedger) -> Vec<QueryCandidate> {
        let mut features = ledger
            .events()
            .iter()
            .enumerate()
            .map(|(ordinal, event)| self.match_event(ordinal, event.raw()))
            .collect::<Vec<_>>();

        let mut document_frequency = vec![0usize; self.terms.len()];
        for event in &features {
            for (term_index, matched) in event.matched_term_flags.iter().enumerate() {
                if *matched {
                    document_frequency[term_index] += 1;
                }
            }
        }

        let event_count = ledger.len();
        for event in &mut features {
            event.specificity = event
                .matched_term_flags
                .iter()
                .enumerate()
                .filter(|(_, matched)| **matched)
                .map(|(term_index, _)| {
                    term_specificity(
                        self.terms[term_index].normalized.len(),
                        document_frequency[term_index],
                        event_count,
                    )
                })
                .fold(0usize, usize::saturating_add);
        }

        let mut candidates = features
            .into_iter()
            .filter(|event| event.full_query_match || event.matched_terms != 0)
            .map(QueryCandidate::from)
            .collect::<Vec<_>>();
        candidates.sort_by_key(|candidate| (Reverse(candidate.score), candidate.ordinal));
        candidates
    }

    fn match_event(&self, ordinal: usize, event: &[u8]) -> EventQueryFeatures {
        let event_terms = ascii_tokens(event)
            .into_iter()
            .map(ascii_lowercase)
            .collect::<BTreeSet<_>>();
        let mut matched_term_flags = Vec::with_capacity(self.terms.len());
        let mut identifier_exact_matches = 0usize;
        let mut exact_term_matches = 0usize;

        for term in &self.terms {
            let exact = event_terms.contains(&term.normalized);
            let matched = exact || contains_ascii_case_insensitive(event, &term.normalized);
            matched_term_flags.push(matched);
            if exact {
                exact_term_matches += 1;
                if term.identifier_like {
                    identifier_exact_matches += 1;
                }
            }
        }

        EventQueryFeatures {
            ordinal,
            full_query_match: !self.full_query.is_empty()
                && contains_ascii_case_insensitive(event, self.full_query),
            identifier_exact_matches,
            exact_term_matches,
            matched_terms: matched_term_flags
                .iter()
                .filter(|matched| **matched)
                .count(),
            specificity: 0,
            matched_term_flags,
        }
    }
}

#[derive(Clone)]
struct EventQueryFeatures {
    ordinal: usize,
    full_query_match: bool,
    identifier_exact_matches: usize,
    exact_term_matches: usize,
    matched_terms: usize,
    specificity: usize,
    matched_term_flags: Vec<bool>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct QueryMatchFeatures {
    full_query_match: bool,
    identifier_exact_matches: usize,
    exact_term_matches: usize,
    matched_terms: usize,
    specificity: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct QueryScore {
    full_query_match: bool,
    identifier_exact_matches: usize,
    exact_term_matches: usize,
    matched_terms: usize,
    specificity: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct QueryCandidate {
    ordinal: usize,
    features: QueryMatchFeatures,
    score: QueryScore,
}

impl From<EventQueryFeatures> for QueryCandidate {
    fn from(features: EventQueryFeatures) -> Self {
        let match_features = QueryMatchFeatures {
            full_query_match: features.full_query_match,
            identifier_exact_matches: features.identifier_exact_matches,
            exact_term_matches: features.exact_term_matches,
            matched_terms: features.matched_terms,
            specificity: features.specificity,
        };
        Self {
            ordinal: features.ordinal,
            features: match_features,
            score: QueryScore {
                full_query_match: match_features.full_query_match,
                identifier_exact_matches: match_features.identifier_exact_matches,
                exact_term_matches: match_features.exact_term_matches,
                matched_terms: match_features.matched_terms,
                specificity: match_features.specificity,
            },
        }
    }
}

fn query_terms(query: &[u8]) -> Vec<QueryTerm> {
    let mut seen = BTreeSet::new();
    let mut terms = Vec::new();

    for raw in ascii_tokens(query) {
        let normalized = ascii_lowercase(raw.clone());
        let identifier_like = is_identifier_like(&raw);
        if is_stopword(&normalized) || (normalized.len() < 3 && !identifier_like) {
            continue;
        }
        if seen.insert(normalized.clone()) {
            terms.push(QueryTerm {
                normalized,
                identifier_like,
            });
        }
    }

    terms
}

fn ascii_tokens(input: &[u8]) -> Vec<Vec<u8>> {
    let mut tokens = Vec::new();
    let mut start = None;

    for (index, byte) in input.iter().copied().enumerate() {
        if is_term_byte(byte) {
            start.get_or_insert(index);
        } else if let Some(token_start) = start.take() {
            tokens.push(input[token_start..index].to_vec());
        }
    }
    if let Some(token_start) = start {
        tokens.push(input[token_start..].to_vec());
    }

    tokens
}

const fn is_term_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/' | b':')
}

fn ascii_lowercase(mut term: Vec<u8>) -> Vec<u8> {
    term.make_ascii_lowercase();
    term
}

fn is_identifier_like(term: &[u8]) -> bool {
    term.iter().any(u8::is_ascii_digit)
        || term
            .iter()
            .any(|byte| matches!(byte, b'_' | b'-' | b'.' | b'/' | b':'))
        || (term.len() >= 2
            && term.iter().any(u8::is_ascii_alphabetic)
            && term
                .iter()
                .filter(|byte| byte.is_ascii_alphabetic())
                .all(u8::is_ascii_uppercase))
}

fn is_stopword(term: &[u8]) -> bool {
    matches!(
        term,
        b"a" | b"an"
            | b"the"
            | b"is"
            | b"are"
            | b"was"
            | b"were"
            | b"what"
            | b"which"
            | b"who"
            | b"why"
            | b"how"
            | b"did"
            | b"does"
            | b"do"
            | b"to"
            | b"of"
            | b"for"
            | b"in"
            | b"on"
            | b"at"
            | b"by"
            | b"with"
            | b"from"
            | b"around"
            | b"cause"
            | b"caused"
    )
}

fn term_specificity(term_bytes: usize, document_frequency: usize, event_count: usize) -> usize {
    let rarity = event_count
        .saturating_add(1)
        .saturating_sub(document_frequency);
    term_bytes.saturating_mul(rarity.max(1))
}

fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }

    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

#[cfg(test)]
mod tests {
    use super::{contains_ascii_case_insensitive, query_terms};

    #[test]
    fn literal_byte_grep_is_ascii_case_insensitive_without_decoding() {
        assert!(contains_ascii_case_insensitive(
            b"\xffDATABASE Timeout\x00",
            b"database timeout"
        ));
        assert!(!contains_ascii_case_insensitive(
            b"database unavailable",
            b"database timeout"
        ));
        assert!(!contains_ascii_case_insensitive(b"anything", b""));
    }

    #[test]
    fn natural_question_terms_drop_only_fixed_noise_and_preserve_identifiers() {
        let terms = query_terms(b"What caused DB req-7 timeout around the deployment?");
        assert_eq!(
            terms
                .iter()
                .map(|term| term.normalized.as_slice())
                .collect::<Vec<_>>(),
            vec![b"db".as_slice(), b"req-7", b"timeout", b"deployment"]
        );
        assert!(terms[0].identifier_like);
        assert!(terms[1].identifier_like);
    }
}
