use evidentrail_core::{BlockId, BlockIndex, EventId};
use evidentrail_select::{
    AFFINITY_SCALE_V1, AffinityV1, FacetAffinityV1, FacetWeightV1, ProductionFacetKindV1,
    ProductionFacetV1,
};

use crate::bounds::{
    MAX_EMITTED_SIGNALS_V1, MAX_IDENTIFIER_BLOCK_FANOUT_V1, MAX_MANDATORY_BLOCKS_V1,
    MAX_PRIMARY_BLOCKS_V1, MAX_PRIMARY_BYTES_SCANNED_V1,
};
use crate::query::{
    PreprocessedQueryV1, compare_canonical_to_raw, for_each_ascii_token, preprocess_query_v1,
};
use crate::types::{
    CandidateBuildErrorV1, CandidateFacetV1, CandidateGenerationDecisionV1,
    CandidateNeedsMoreReasonV1, CandidateNeedsMoreV1, LexicalCandidateUniverseV1,
    MandatoryIdentifierReasonV1, PrimaryBlockCandidateV1, UniverseAccountingV1,
};

struct BlockStatistics {
    block_id: BlockId,
    ordered_event_ids: Vec<EventId>,
    exact_bytes: u64,
    document_tokens: u64,
    term_frequencies: Vec<u64>,
    identifier_matches: Vec<bool>,
}

/// Convenience entry point that preprocesses exact question bytes and then
/// annotates every reconciled primary block.
pub fn generate_lexical_candidates_v1(
    question: &[u8],
    blocks: &BlockIndex<'_>,
) -> Result<CandidateGenerationDecisionV1, CandidateBuildErrorV1> {
    let query = match preprocess_query_v1(question) {
        Ok(query) => query,
        Err(needs_more) => return Ok(CandidateGenerationDecisionV1::NeedsMore(needs_more)),
    };
    annotate_preprocessed_query_v1(&query, blocks)
}

/// Attach query facets to the exhaustive primary block universe. No alternate
/// packet membership can be supplied to or created by this function.
pub fn annotate_preprocessed_query_v1(
    query: &PreprocessedQueryV1,
    blocks: &BlockIndex<'_>,
) -> Result<CandidateGenerationDecisionV1, CandidateBuildErrorV1> {
    if blocks.len() > MAX_PRIMARY_BLOCKS_V1 {
        return Ok(needs_more(CandidateNeedsMoreReasonV1::PrimaryBlockCountCap));
    }

    let mut statistics = Vec::with_capacity(blocks.len());
    let mut scanned_bytes = 0u64;
    let mut scanned_tokens = 0u64;
    let mut term_document_frequencies = vec![0usize; query.terms().len()];
    let mut identifier_fanout = vec![0usize; query.identifiers().len()];

    for block in blocks.blocks() {
        let expansion = blocks
            .expand_block(block.id())
            .expect("reconciled block IDs remain resolvable");
        let mut exact_bytes = 0u64;
        let mut document_tokens = 0u64;
        let mut term_frequencies = vec![0u64; query.terms().len()];
        let mut identifier_matches = vec![false; query.identifiers().len()];
        let mut scan_arithmetic_exhausted = false;

        for event in expansion.events() {
            let event_bytes = match u64::try_from(event.raw().len()) {
                Ok(value) => value,
                Err(_) => {
                    return Ok(needs_more(CandidateNeedsMoreReasonV1::ArithmeticCapacity));
                }
            };
            exact_bytes =
                match with_authorized_event_scan(scanned_bytes, exact_bytes, event_bytes, || {
                    for_each_ascii_token(event.raw(), |token| {
                        let Some(next_document_tokens) = document_tokens.checked_add(1) else {
                            scan_arithmetic_exhausted = true;
                            return false;
                        };
                        document_tokens = next_document_tokens;
                        if let Ok(position) = query.terms().binary_search_by(|term| {
                            compare_canonical_to_raw(term.canonical_token(), token)
                        }) {
                            let Some(next_frequency) = term_frequencies[position].checked_add(1)
                            else {
                                scan_arithmetic_exhausted = true;
                                return false;
                            };
                            term_frequencies[position] = next_frequency;
                        }
                        if let Ok(position) = query.identifiers().binary_search_by(|identifier| {
                            compare_canonical_to_raw(identifier.canonical_token(), token)
                        }) {
                            identifier_matches[position] = true;
                        }
                        true
                    });
                }) {
                    Ok((next_exact_bytes, ())) => next_exact_bytes,
                    Err(reason) => return Ok(needs_more(reason)),
                };
            if scan_arithmetic_exhausted {
                return Ok(needs_more(CandidateNeedsMoreReasonV1::ArithmeticCapacity));
            }
        }
        scanned_bytes = match checked_scanned_bytes(scanned_bytes, exact_bytes) {
            Ok(value) => value,
            Err(reason) => return Ok(needs_more(reason)),
        };
        scanned_tokens = match scanned_tokens.checked_add(document_tokens) {
            Some(value) => value,
            None => return Ok(needs_more(CandidateNeedsMoreReasonV1::ArithmeticCapacity)),
        };
        for (position, frequency) in term_frequencies.iter().copied().enumerate() {
            if frequency > 0 {
                term_document_frequencies[position] =
                    match term_document_frequencies[position].checked_add(1) {
                        Some(value) => value,
                        None => {
                            return Ok(needs_more(CandidateNeedsMoreReasonV1::ArithmeticCapacity));
                        }
                    };
            }
        }
        for (position, matched) in identifier_matches.iter().copied().enumerate() {
            if matched {
                identifier_fanout[position] = match identifier_fanout[position].checked_add(1) {
                    Some(value) => value,
                    None => {
                        return Ok(needs_more(CandidateNeedsMoreReasonV1::ArithmeticCapacity));
                    }
                };
            }
        }
        statistics.push(BlockStatistics {
            block_id: block.id(),
            ordered_event_ids: block.member_ids().to_vec(),
            exact_bytes,
            document_tokens,
            term_frequencies,
            identifier_matches,
        });
    }

    if identifier_fanout
        .iter()
        .any(|fanout| *fanout > MAX_IDENTIFIER_BLOCK_FANOUT_V1)
    {
        return Ok(needs_more(
            CandidateNeedsMoreReasonV1::IdentifierBlockFanoutCap,
        ));
    }
    let mandatory_block_count = statistics
        .iter()
        .filter(|statistics| statistics.identifier_matches.iter().any(|matched| *matched))
        .count();
    if mandatory_block_count > MAX_MANDATORY_BLOCKS_V1 {
        return Ok(needs_more(
            CandidateNeedsMoreReasonV1::MandatoryBlockCountCap,
        ));
    }

    let block_count = u64::try_from(statistics.len())
        .map_err(|_| CandidateBuildErrorV1::FixedPointContractViolation)?;
    let mut candidate_facets = Vec::with_capacity(query.terms().len() + query.identifiers().len());
    let mut term_facet_ids = Vec::with_capacity(query.terms().len());
    for (term, document_frequency) in query
        .terms()
        .iter()
        .zip(term_document_frequencies.iter().copied())
    {
        let weight = idf_weight(
            block_count,
            u64::try_from(document_frequency)
                .map_err(|_| CandidateBuildErrorV1::FixedPointContractViolation)?,
        )?;
        let facet = ProductionFacetV1::new(
            ProductionFacetKindV1::QueryTerm,
            term.canonical_token(),
            weight,
        )
        .map_err(|_| CandidateBuildErrorV1::FacetContractViolation)?;
        term_facet_ids.push(facet.id());
        candidate_facets.push(CandidateFacetV1::QueryTerm(facet));
    }

    let full_weight = FacetWeightV1::new(AFFINITY_SCALE_V1)
        .map_err(|_| CandidateBuildErrorV1::FixedPointContractViolation)?;
    let mut identifier_facet_ids = Vec::with_capacity(query.identifiers().len());
    for identifier in query.identifiers() {
        let facet = ProductionFacetV1::new(
            ProductionFacetKindV1::ValidatedQueryIdentifier,
            &identifier.canonical_semantic_key(),
            full_weight,
        )
        .map_err(|_| CandidateBuildErrorV1::FacetContractViolation)?;
        identifier_facet_ids.push(facet.id());
        candidate_facets.push(CandidateFacetV1::ValidatedQueryIdentifier {
            facet,
            identifier_kind: identifier.kind(),
        });
    }
    candidate_facets.sort_unstable_by_key(|facet| facet.facet().id());

    let full_affinity = AffinityV1::new(AFFINITY_SCALE_V1)
        .map_err(|_| CandidateBuildErrorV1::FixedPointContractViolation)?;
    let mut primary_blocks = Vec::with_capacity(statistics.len());
    let mut emitted_signal_count = 0usize;
    for statistics in statistics {
        let mut affinities = Vec::new();
        let mut mandatory_reasons = Vec::new();
        for (position, frequency) in statistics.term_frequencies.iter().copied().enumerate() {
            if frequency == 0 {
                continue;
            }
            let affinity = bm25_affinity(
                frequency,
                statistics.document_tokens,
                scanned_tokens,
                block_count,
            )?;
            affinities.push(FacetAffinityV1::new(term_facet_ids[position], affinity));
            emitted_signal_count = match checked_signal_increment(emitted_signal_count) {
                Ok(value) => value,
                Err(reason) => return Ok(needs_more(reason)),
            };
        }
        for (position, matched) in statistics.identifier_matches.iter().copied().enumerate() {
            if !matched {
                continue;
            }
            affinities.push(FacetAffinityV1::new(
                identifier_facet_ids[position],
                full_affinity,
            ));
            mandatory_reasons.push(MandatoryIdentifierReasonV1::new(
                identifier_facet_ids[position],
                query.identifiers()[position].kind(),
            ));
            emitted_signal_count = match checked_signal_increment(emitted_signal_count) {
                Ok(value) => value,
                Err(reason) => return Ok(needs_more(reason)),
            };
            emitted_signal_count = match checked_signal_increment(emitted_signal_count) {
                Ok(value) => value,
                Err(reason) => return Ok(needs_more(reason)),
            };
        }
        affinities.sort_unstable_by_key(|affinity| affinity.facet_id());
        mandatory_reasons.sort_unstable_by_key(|reason| reason.facet_id());
        primary_blocks.push(PrimaryBlockCandidateV1::new(
            statistics.block_id,
            statistics.ordered_event_ids,
            affinities,
            mandatory_reasons,
            statistics.exact_bytes,
            statistics.document_tokens,
        ));
    }

    Ok(CandidateGenerationDecisionV1::Ready(
        LexicalCandidateUniverseV1::new(
            blocks.retrieval_id(),
            query.question_digest(),
            candidate_facets,
            primary_blocks,
            UniverseAccountingV1 {
                scanned_bytes,
                scanned_tokens,
                emitted_signal_count,
                mandatory_block_count,
            },
        ),
    ))
}

fn checked_signal_increment(current: usize) -> Result<usize, CandidateNeedsMoreReasonV1> {
    let next = current
        .checked_add(1)
        .ok_or(CandidateNeedsMoreReasonV1::ArithmeticCapacity)?;
    if next > MAX_EMITTED_SIGNALS_V1 {
        return Err(CandidateNeedsMoreReasonV1::EmittedSignalCountCap);
    }
    Ok(next)
}

fn checked_scanned_bytes(current: u64, additional: u64) -> Result<u64, CandidateNeedsMoreReasonV1> {
    let next = current
        .checked_add(additional)
        .ok_or(CandidateNeedsMoreReasonV1::ArithmeticCapacity)?;
    if next > MAX_PRIMARY_BYTES_SCANNED_V1 {
        return Err(CandidateNeedsMoreReasonV1::PrimaryBytesScannedCap);
    }
    Ok(next)
}

/// Run content inspection only after the complete next event fits inside the
/// remaining global scan budget. The returned block byte count is committed
/// only when the scan closure completes.
fn with_authorized_event_scan<T>(
    already_scanned: u64,
    current_block_bytes: u64,
    event_bytes: u64,
    scan: impl FnOnce() -> T,
) -> Result<(u64, T), CandidateNeedsMoreReasonV1> {
    let next_block_bytes = current_block_bytes
        .checked_add(event_bytes)
        .ok_or(CandidateNeedsMoreReasonV1::ArithmeticCapacity)?;
    let _ = checked_scanned_bytes(already_scanned, next_block_bytes)?;
    Ok((next_block_bytes, scan()))
}

fn needs_more(reason: CandidateNeedsMoreReasonV1) -> CandidateGenerationDecisionV1 {
    CandidateGenerationDecisionV1::NeedsMore(CandidateNeedsMoreV1::new(reason))
}

fn idf_weight(
    block_count: u64,
    document_frequency: u64,
) -> Result<FacetWeightV1, CandidateBuildErrorV1> {
    // This is a frozen linear bounded rarity weight, not BM25's logarithmic
    // inverse-document-frequency function: (N - df + 1) / (N + 1).
    let numerator = u128::from(AFFINITY_SCALE_V1)
        .checked_mul(u128::from(
            block_count
                .checked_sub(document_frequency)
                .and_then(|value| value.checked_add(1))
                .ok_or(CandidateBuildErrorV1::FixedPointContractViolation)?,
        ))
        .ok_or(CandidateBuildErrorV1::FixedPointContractViolation)?;
    let denominator = u128::from(
        block_count
            .checked_add(1)
            .ok_or(CandidateBuildErrorV1::FixedPointContractViolation)?,
    );
    let micros = u32::try_from(numerator / denominator)
        .map_err(|_| CandidateBuildErrorV1::FixedPointContractViolation)?;
    FacetWeightV1::new(micros).map_err(|_| CandidateBuildErrorV1::FixedPointContractViolation)
}

/// Normalized BM25-style term-frequency saturation using k1=6/5 and b=3/4.
/// The exact rational form avoids floats and average-length rounding:
/// `tf / (tf + 0.3 + 0.9 * dl / avg_dl)`.
fn bm25_affinity(
    term_frequency: u64,
    document_tokens: u64,
    total_document_tokens: u64,
    block_count: u64,
) -> Result<AffinityV1, CandidateBuildErrorV1> {
    if term_frequency == 0 || total_document_tokens == 0 || block_count == 0 {
        return Err(CandidateBuildErrorV1::FixedPointContractViolation);
    }
    let total = u128::from(total_document_tokens);
    let frequency = u128::from(term_frequency);
    let document = u128::from(document_tokens);
    let blocks = u128::from(block_count);
    let base = 10u128
        .checked_mul(total)
        .and_then(|value| value.checked_mul(frequency))
        .ok_or(CandidateBuildErrorV1::FixedPointContractViolation)?;
    let numerator = base
        .checked_mul(u128::from(AFFINITY_SCALE_V1))
        .ok_or(CandidateBuildErrorV1::FixedPointContractViolation)?;
    let denominator = base
        .checked_add(
            3u128
                .checked_mul(total)
                .ok_or(CandidateBuildErrorV1::FixedPointContractViolation)?,
        )
        .and_then(|value| {
            9u128
                .checked_mul(document)
                .and_then(|component| component.checked_mul(blocks))
                .and_then(|component| value.checked_add(component))
        })
        .ok_or(CandidateBuildErrorV1::FixedPointContractViolation)?;
    let micros = u32::try_from(numerator / denominator)
        .map_err(|_| CandidateBuildErrorV1::FixedPointContractViolation)?;
    AffinityV1::new(micros).map_err(|_| CandidateBuildErrorV1::FixedPointContractViolation)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[test]
    fn resource_counters_accept_exact_caps_and_fail_before_overrun() {
        assert_eq!(
            checked_scanned_bytes(0, MAX_PRIMARY_BYTES_SCANNED_V1),
            Ok(MAX_PRIMARY_BYTES_SCANNED_V1)
        );
        assert_eq!(
            checked_scanned_bytes(MAX_PRIMARY_BYTES_SCANNED_V1, 1),
            Err(CandidateNeedsMoreReasonV1::PrimaryBytesScannedCap)
        );
        assert_eq!(
            checked_scanned_bytes(u64::MAX, 1),
            Err(CandidateNeedsMoreReasonV1::ArithmeticCapacity)
        );
        assert_eq!(
            checked_signal_increment(MAX_EMITTED_SIGNALS_V1 - 1),
            Ok(MAX_EMITTED_SIGNALS_V1)
        );
        assert_eq!(
            checked_signal_increment(MAX_EMITTED_SIGNALS_V1),
            Err(CandidateNeedsMoreReasonV1::EmittedSignalCountCap)
        );

        let content_visited = Cell::new(false);
        let result = with_authorized_event_scan(MAX_PRIMARY_BYTES_SCANNED_V1, 0, 1, || {
            content_visited.set(true)
        });
        assert_eq!(
            result,
            Err(CandidateNeedsMoreReasonV1::PrimaryBytesScannedCap)
        );
        assert!(!content_visited.get());
    }

    #[test]
    fn fixed_point_math_is_bounded_monotone_and_checked() {
        let rare = idf_weight(100, 1).unwrap();
        let common = idf_weight(100, 90).unwrap();
        assert!(rare > common);
        assert!(rare.micros() <= AFFINITY_SCALE_V1);

        let once = bm25_affinity(1, 10, 100, 10).unwrap();
        let repeated = bm25_affinity(2, 10, 100, 10).unwrap();
        let longer = bm25_affinity(1, 20, 100, 10).unwrap();
        assert!(repeated > once);
        assert!(once > longer);
        assert!(repeated.micros() <= AFFINITY_SCALE_V1);
        assert!(bm25_affinity(0, 10, 100, 10).is_err());
    }
}
