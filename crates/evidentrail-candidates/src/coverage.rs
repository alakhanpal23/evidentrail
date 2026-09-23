use std::collections::{BTreeMap, BTreeSet};

use evidentrail_core::{BlockConfidence, BlockId, BlockIndex, BlockState, LaneKey, LaneSequence};
use evidentrail_select::{
    AFFINITY_SCALE_V1, AffinityV1, FacetAffinityV1, FacetIdV1, FacetWeightV1,
    ProductionFacetKindV1, ProductionFacetV1,
};

use crate::bounds::{
    MAX_COVERAGE_ANALYSIS_TOKENS_V1, MAX_COVERAGE_OUTPUT_AFFINITIES_V1,
    MAX_COVERAGE_OUTPUT_FACETS_V1, MAX_COVERAGE_OUTPUT_SENTINELS_V1,
    MAX_COVERAGE_SIGNAL_OBSERVATIONS_V1, MAX_COVERAGE_SOURCE_LANES_V1, MAX_PRIMARY_BLOCKS_V1,
    MAX_PRIMARY_BYTES_SCANNED_V1, MAX_RECONSTRUCTION_RISK_REPRESENTATIVES_PER_KIND_V1,
    MAX_TIME_COVERAGE_STRATA_V1,
};
use crate::coverage_types::{
    BREADTH_COVERAGE_FACET_WEIGHT_DENOMINATOR_V1, CoverageAccountingPartsV1, CoverageAccountingV1,
    CoverageBlockAnnotationV1, CoverageCandidateUniverseV1, CoverageFacetRoleV1, CoverageFacetV1,
    CoverageGenerationDecisionV1, CoverageSentinelKindV1, CoverageSentinelV1, FailureBlockFactV1,
    FailureSignalCountV1, FailureSignalKindV1, OnsetBoundaryFactV1, OnsetBoundaryRoleV1,
    OnsetSignalCountV1, OnsetSignalKindV1, ReconstructionRiskKindV1, SourceCoverageStratumKindV1,
};
use crate::query::for_each_ascii_token;
use crate::types::{CandidateBuildErrorV1, CandidateNeedsMoreReasonV1, CandidateNeedsMoreV1};

struct BlockFacts {
    block_id: BlockId,
    ordinal: u64,
    lane: LaneKey,
    first_lane_sequence: LaneSequence,
    state: BlockState,
    confidence: BlockConfidence,
    has_fragment: bool,
}

struct WorkAnnotation {
    block_id: BlockId,
    failure_counts: BTreeMap<FailureSignalKindV1, u32>,
    onset_counts: BTreeMap<OnsetSignalKindV1, u32>,
    failure_lane_position: Option<(u32, u32)>,
    onset_boundaries: BTreeSet<OnsetBoundaryFactV1>,
    reconstruction_risks: BTreeSet<ReconstructionRiskKindV1>,
    sentinels: BTreeMap<(CoverageSentinelKindV1, FacetIdV1), CoverageSentinelV1>,
    affinities: BTreeMap<FacetIdV1, FacetAffinityV1>,
}

impl WorkAnnotation {
    fn new(block_id: BlockId) -> Self {
        Self {
            block_id,
            failure_counts: BTreeMap::new(),
            onset_counts: BTreeMap::new(),
            failure_lane_position: None,
            onset_boundaries: BTreeSet::new(),
            reconstruction_risks: BTreeSet::new(),
            sentinels: BTreeMap::new(),
            affinities: BTreeMap::new(),
        }
    }
}

struct OutputEmitter {
    facets: BTreeMap<FacetIdV1, CoverageFacetV1>,
    affinity_count: usize,
    sentinel_count: usize,
    full_weight: FacetWeightV1,
    breadth_weight: FacetWeightV1,
    full_affinity: AffinityV1,
}

impl OutputEmitter {
    fn new() -> Result<Self, CandidateBuildErrorV1> {
        Ok(Self {
            facets: BTreeMap::new(),
            affinity_count: 0,
            sentinel_count: 0,
            full_weight: FacetWeightV1::new(AFFINITY_SCALE_V1)
                .map_err(|_| CandidateBuildErrorV1::FixedPointContractViolation)?,
            breadth_weight: FacetWeightV1::new(
                AFFINITY_SCALE_V1 / BREADTH_COVERAGE_FACET_WEIGHT_DENOMINATOR_V1,
            )
            .map_err(|_| CandidateBuildErrorV1::FixedPointContractViolation)?,
            full_affinity: AffinityV1::new(AFFINITY_SCALE_V1)
                .map_err(|_| CandidateBuildErrorV1::FixedPointContractViolation)?,
        })
    }

    fn register_facet(
        &mut self,
        role: CoverageFacetRoleV1,
        lane_anchor: Option<BlockId>,
    ) -> Result<FacetIdV1, GenerationFailure> {
        let kind = production_kind(role);
        let key = semantic_key(role, lane_anchor);
        let weight = if kind.is_coverage_only() {
            self.breadth_weight
        } else {
            self.full_weight
        };
        let facet = ProductionFacetV1::new(kind, &key, weight)
            .map_err(|_| CandidateBuildErrorV1::FacetContractViolation)?;
        let id = facet.id();
        if let Some(existing) = self.facets.get(&id) {
            if existing.role() != role {
                return Err(CandidateBuildErrorV1::FacetContractViolation.into());
            }
            return Ok(id);
        }
        if self.facets.len() >= MAX_COVERAGE_OUTPUT_FACETS_V1 {
            return Err(CandidateNeedsMoreReasonV1::CoverageFacetOutputCap.into());
        }
        self.facets.insert(id, CoverageFacetV1::new(facet, role));
        Ok(id)
    }

    fn add_affinity(
        &mut self,
        annotation: &mut WorkAnnotation,
        facet_id: FacetIdV1,
    ) -> Result<(), GenerationFailure> {
        if annotation.affinities.contains_key(&facet_id) {
            return Ok(());
        }
        self.affinity_count = checked_bounded_increment(
            self.affinity_count,
            MAX_COVERAGE_OUTPUT_AFFINITIES_V1,
            CandidateNeedsMoreReasonV1::CoverageAffinityOutputCap,
        )?;
        annotation
            .affinities
            .insert(facet_id, FacetAffinityV1::new(facet_id, self.full_affinity));
        Ok(())
    }

    fn add_sentinel(
        &mut self,
        annotation: &mut WorkAnnotation,
        kind: CoverageSentinelKindV1,
        facet_id: FacetIdV1,
    ) -> Result<(), GenerationFailure> {
        if annotation.sentinels.contains_key(&(kind, facet_id)) {
            return Ok(());
        }
        self.sentinel_count = checked_bounded_increment(
            self.sentinel_count,
            MAX_COVERAGE_OUTPUT_SENTINELS_V1,
            CandidateNeedsMoreReasonV1::CoverageSentinelOutputCap,
        )?;
        annotation
            .sentinels
            .insert((kind, facet_id), CoverageSentinelV1::new(kind, facet_id));
        self.add_affinity(annotation, facet_id)
    }
}

enum GenerationFailure {
    NeedsMore(CandidateNeedsMoreReasonV1),
    Build(CandidateBuildErrorV1),
}

impl From<CandidateNeedsMoreReasonV1> for GenerationFailure {
    fn from(reason: CandidateNeedsMoreReasonV1) -> Self {
        Self::NeedsMore(reason)
    }
}

impl From<CandidateBuildErrorV1> for GenerationFailure {
    fn from(error: CandidateBuildErrorV1) -> Self {
        Self::Build(error)
    }
}

/// Generate deterministic complete-failure, transparent onset, and raw-
/// coverage annotations over the existing exhaustive primary block partition.
/// The output cannot add, overlap, split, suppress, or make a block mandatory.
pub fn generate_failure_coverage_candidates_v1(
    blocks: &BlockIndex<'_>,
) -> Result<CoverageGenerationDecisionV1, CandidateBuildErrorV1> {
    match build_failure_coverage_candidates_v1(blocks) {
        Ok(universe) => Ok(CoverageGenerationDecisionV1::Ready(universe)),
        Err(GenerationFailure::NeedsMore(reason)) => Ok(CoverageGenerationDecisionV1::NeedsMore(
            CandidateNeedsMoreV1::new(reason),
        )),
        Err(GenerationFailure::Build(error)) => Err(error),
    }
}

fn build_failure_coverage_candidates_v1(
    blocks: &BlockIndex<'_>,
) -> Result<CoverageCandidateUniverseV1, GenerationFailure> {
    if blocks.len() > MAX_PRIMARY_BLOCKS_V1 {
        return Err(CandidateNeedsMoreReasonV1::PrimaryBlockCountCap.into());
    }

    let mut facts = Vec::with_capacity(blocks.len());
    let mut work = Vec::with_capacity(blocks.len());
    let mut scanned_bytes = 0u64;
    let mut scanned_analysis_tokens = 0u64;
    let mut failure_signal_observations = 0usize;
    let mut onset_signal_observations = 0usize;

    for block in blocks.blocks() {
        let expansion = blocks
            .expand_block(block.id())
            .map_err(|_| CandidateBuildErrorV1::BlockIndexContractViolation)?;
        let first_lane_sequence = *block
            .member_lane_sequences()
            .first()
            .ok_or(CandidateBuildErrorV1::BlockIndexContractViolation)?;
        let mut annotation = WorkAnnotation::new(block.id());
        let mut has_fragment = false;

        for event in expansion.events() {
            let event_bytes = u64::try_from(event.raw().len())
                .map_err(|_| CandidateNeedsMoreReasonV1::ArithmeticCapacity)?;
            scanned_bytes = checked_scanned_bytes(scanned_bytes, event_bytes)?;
            has_fragment |= !event.record_state().is_complete();
            let mut scan_failure = None;
            // An absence report is not an observed failure. Keep this scoped
            // to the immediately preceding token in the same source record;
            // a later, real failure on that record must still be counted.
            let mut previous_negates_failure = false;
            for_each_ascii_token(event.raw(), |token| {
                match checked_bounded_u64_increment(
                    scanned_analysis_tokens,
                    MAX_COVERAGE_ANALYSIS_TOKENS_V1,
                    CandidateNeedsMoreReasonV1::CoverageAnalysisTokenCap,
                ) {
                    Ok(next) => scanned_analysis_tokens = next,
                    Err(error) => {
                        scan_failure = Some(error);
                        return false;
                    }
                }

                if let Some(kind) =
                    classify_failure_signal(token).filter(|_| !previous_negates_failure)
                {
                    match checked_signal_observation_increment(
                        failure_signal_observations,
                        onset_signal_observations,
                    ) {
                        Ok(next) => failure_signal_observations = next,
                        Err(error) => {
                            scan_failure = Some(error);
                            return false;
                        }
                    }
                    if increment_signal_count(&mut annotation.failure_counts, kind).is_err() {
                        scan_failure = Some(CandidateNeedsMoreReasonV1::ArithmeticCapacity);
                        return false;
                    }
                }
                if let Some(kind) = classify_onset_signal(token) {
                    match checked_signal_observation_increment(
                        onset_signal_observations,
                        failure_signal_observations,
                    ) {
                        Ok(next) => onset_signal_observations = next,
                        Err(error) => {
                            scan_failure = Some(error);
                            return false;
                        }
                    }
                    if increment_signal_count(&mut annotation.onset_counts, kind).is_err() {
                        scan_failure = Some(CandidateNeedsMoreReasonV1::ArithmeticCapacity);
                        return false;
                    }
                }
                previous_negates_failure = ascii_eq(token, b"no")
                    || ascii_eq(token, b"without")
                    || ascii_eq(token, b"zero");
                true
            });
            if let Some(reason) = scan_failure {
                return Err(reason.into());
            }
        }

        facts.push(BlockFacts {
            block_id: block.id(),
            ordinal: block.ordinal(),
            lane: block.lane().clone(),
            first_lane_sequence,
            state: block.state(),
            confidence: block.confidence(),
            has_fragment,
        });
        work.push(annotation);
    }

    let mut lanes = BTreeMap::<LaneKey, Vec<usize>>::new();
    for (position, block) in facts.iter().enumerate() {
        lanes.entry(block.lane.clone()).or_default().push(position);
    }
    if lanes.len() > MAX_COVERAGE_SOURCE_LANES_V1 {
        return Err(CandidateNeedsMoreReasonV1::CoverageSourceLaneCap.into());
    }
    for positions in lanes.values_mut() {
        positions.sort_unstable_by(|left, right| {
            facts[*left]
                .first_lane_sequence
                .cmp(&facts[*right].first_lane_sequence)
                .then_with(|| facts[*left].block_id.cmp(&facts[*right].block_id))
        });
    }

    let mut emitter = OutputEmitter::new()?;
    annotate_failure_and_explicit_onset(&facts, &mut work, &mut emitter)?;
    annotate_lane_boundaries_and_source_coverage(&facts, &lanes, &mut work, &mut emitter)?;
    annotate_retrieval_and_time_coverage(&facts, &mut work, &mut emitter)?;
    let reconstruction_risk_accounting =
        annotate_reconstruction_risk(&facts, &mut work, &mut emitter)?;

    let source_lane_count = lanes.len();
    let emitted_facet_count = emitter.facets.len();
    let emitted_affinity_count = emitter.affinity_count;
    let emitted_sentinel_count = emitter.sentinel_count;
    let facets = emitter.facets.into_values().collect::<Vec<_>>();
    let mut annotations = work
        .into_iter()
        .map(finalize_annotation)
        .collect::<Result<Vec<_>, _>>()?;
    annotations.sort_unstable_by_key(CoverageBlockAnnotationV1::block_id);

    Ok(CoverageCandidateUniverseV1::new(
        blocks.retrieval_id(),
        facets,
        annotations,
        CoverageAccountingV1::new(CoverageAccountingPartsV1 {
            scanned_bytes,
            scanned_analysis_tokens,
            failure_signal_observations,
            onset_signal_observations,
            reconstruction_risk_fact_count: reconstruction_risk_accounting.fact_count,
            reconstruction_risk_representative_count: reconstruction_risk_accounting
                .representative_count,
            source_lane_count,
            emitted_facet_count,
            emitted_affinity_count,
            emitted_sentinel_count,
        }),
    ))
}

fn annotate_failure_and_explicit_onset(
    _facts: &[BlockFacts],
    work: &mut [WorkAnnotation],
    emitter: &mut OutputEmitter,
) -> Result<(), GenerationFailure> {
    for annotation in work {
        let failure_kinds = annotation
            .failure_counts
            .keys()
            .copied()
            .collect::<Vec<_>>();
        for kind in failure_kinds {
            let facet_id = emitter.register_facet(CoverageFacetRoleV1::Failure(kind), None)?;
            emitter.add_affinity(annotation, facet_id)?;
        }
        let onset_kinds = annotation.onset_counts.keys().copied().collect::<Vec<_>>();
        for kind in onset_kinds {
            let facet_id =
                emitter.register_facet(CoverageFacetRoleV1::ExplicitOnset(kind), None)?;
            emitter.add_affinity(annotation, facet_id)?;
        }
    }
    Ok(())
}

fn annotate_lane_boundaries_and_source_coverage(
    facts: &[BlockFacts],
    lanes: &BTreeMap<LaneKey, Vec<usize>>,
    work: &mut [WorkAnnotation],
    emitter: &mut OutputEmitter,
) -> Result<(), GenerationFailure> {
    for positions in lanes.values() {
        let Some(first_position) = positions.first().copied() else {
            return Err(CandidateBuildErrorV1::BlockIndexContractViolation.into());
        };
        let last_position = *positions
            .last()
            .ok_or(CandidateBuildErrorV1::BlockIndexContractViolation)?;
        let lane_anchor = facts[first_position].block_id;

        add_source_sentinel(
            &mut work[first_position],
            SourceCoverageStratumKindV1::SourceStreamHead,
            Some(lane_anchor),
            emitter,
        )?;
        add_source_sentinel(
            &mut work[last_position],
            SourceCoverageStratumKindV1::SourceStreamTail,
            Some(lane_anchor),
            emitter,
        )?;

        let failure_positions = positions
            .iter()
            .copied()
            .filter(|position| !work[*position].failure_counts.is_empty())
            .collect::<Vec<_>>();
        let failure_block_count = u32::try_from(failure_positions.len())
            .map_err(|_| CandidateNeedsMoreReasonV1::ArithmeticCapacity)?;
        for (ordinal, position) in failure_positions.iter().copied().enumerate() {
            let ordinal = u32::try_from(ordinal)
                .map_err(|_| CandidateNeedsMoreReasonV1::ArithmeticCapacity)?;
            work[position].failure_lane_position = Some((ordinal, failure_block_count));
        }
        if let Some(boundary_position) = failure_positions.first().copied() {
            add_onset_boundary(
                positions,
                boundary_position,
                lane_anchor,
                (
                    OnsetBoundaryRoleV1::FirstFailureInLane,
                    OnsetBoundaryRoleV1::LastAvailableBeforeFirstFailure,
                ),
                facts,
                work,
                emitter,
            )?;
        }

        if let Some(boundary_position) = positions
            .iter()
            .copied()
            .find(|position| !work[*position].onset_counts.is_empty())
        {
            add_onset_boundary(
                positions,
                boundary_position,
                lane_anchor,
                (
                    OnsetBoundaryRoleV1::FirstExplicitOnsetInLane,
                    OnsetBoundaryRoleV1::LastAvailableBeforeFirstExplicitOnset,
                ),
                facts,
                work,
                emitter,
            )?;
        }
    }
    Ok(())
}

fn add_onset_boundary(
    lane_positions: &[usize],
    boundary_position: usize,
    lane_anchor: BlockId,
    roles: (OnsetBoundaryRoleV1, OnsetBoundaryRoleV1),
    facts: &[BlockFacts],
    work: &mut [WorkAnnotation],
    emitter: &mut OutputEmitter,
) -> Result<(), GenerationFailure> {
    let (boundary_role, context_role) = roles;
    let boundary_block_id = facts[boundary_position].block_id;
    let facet_id = emitter.register_facet(
        CoverageFacetRoleV1::OnsetBoundary(boundary_role),
        Some(lane_anchor),
    )?;
    work[boundary_position]
        .onset_boundaries
        .insert(OnsetBoundaryFactV1::new(boundary_role, boundary_block_id));
    emitter.add_affinity(&mut work[boundary_position], facet_id)?;

    let boundary_lane_position = lane_positions
        .iter()
        .position(|position| *position == boundary_position)
        .ok_or(CandidateBuildErrorV1::BlockIndexContractViolation)?;
    let Some(context_lane_position) = boundary_lane_position.checked_sub(1) else {
        return Ok(());
    };
    let context_position = lane_positions[context_lane_position];
    let context_facet_id = emitter.register_facet(
        CoverageFacetRoleV1::OnsetBoundary(context_role),
        Some(lane_anchor),
    )?;
    work[context_position]
        .onset_boundaries
        .insert(OnsetBoundaryFactV1::new(context_role, boundary_block_id));
    emitter.add_affinity(&mut work[context_position], context_facet_id)
}

fn annotate_retrieval_and_time_coverage(
    facts: &[BlockFacts],
    work: &mut [WorkAnnotation],
    emitter: &mut OutputEmitter,
) -> Result<(), GenerationFailure> {
    let Some(first) = work.first_mut() else {
        return Ok(());
    };
    add_source_sentinel(
        first,
        SourceCoverageStratumKindV1::RetrievalHead,
        None,
        emitter,
    )?;
    let last = work
        .last_mut()
        .ok_or(CandidateBuildErrorV1::BlockIndexContractViolation)?;
    add_source_sentinel(
        last,
        SourceCoverageStratumKindV1::RetrievalTail,
        None,
        emitter,
    )?;

    let stratum_count = facts.len().min(MAX_TIME_COVERAGE_STRATA_V1);
    let stratum_count_u8 = u8::try_from(stratum_count)
        .map_err(|_| CandidateBuildErrorV1::FixedPointContractViolation)?;
    for index in 0..stratum_count {
        let position = index
            .checked_mul(facts.len())
            .and_then(|value| value.checked_div(stratum_count))
            .ok_or(CandidateNeedsMoreReasonV1::ArithmeticCapacity)?;
        let index_u8 =
            u8::try_from(index).map_err(|_| CandidateBuildErrorV1::FixedPointContractViolation)?;
        let role = CoverageFacetRoleV1::AcquisitionOrderStratum {
            index: index_u8,
            count: stratum_count_u8,
        };
        let facet_id = emitter.register_facet(role, None)?;
        let sentinel = CoverageSentinelKindV1::AcquisitionOrderStratum {
            index: index_u8,
            count: stratum_count_u8,
        };
        emitter.add_sentinel(&mut work[position], sentinel, facet_id)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ReconstructionRiskOccurrence {
    ordinal: u64,
    block_id: BlockId,
    work_position: usize,
}

#[derive(Clone, Copy, Default)]
struct ReconstructionRiskAccountingParts {
    fact_count: usize,
    representative_count: usize,
}

fn annotate_reconstruction_risk(
    facts: &[BlockFacts],
    work: &mut [WorkAnnotation],
    emitter: &mut OutputEmitter,
) -> Result<ReconstructionRiskAccountingParts, GenerationFailure> {
    let mut occurrences = BTreeMap::<ReconstructionRiskKindV1, Vec<_>>::new();
    let mut fact_count = 0usize;
    for (work_position, (fact, annotation)) in facts.iter().zip(work.iter_mut()).enumerate() {
        let mut risks = BTreeSet::new();
        match fact.confidence {
            BlockConfidence::Medium => {
                risks.insert(ReconstructionRiskKindV1::MediumConfidence);
            }
            BlockConfidence::Low => {
                risks.insert(ReconstructionRiskKindV1::LowConfidence);
            }
            BlockConfidence::Unknown => {
                risks.insert(ReconstructionRiskKindV1::UnknownConfidence);
            }
            BlockConfidence::Certain | BlockConfidence::High => {}
        }
        match fact.state {
            BlockState::Ambiguous => {
                risks.insert(ReconstructionRiskKindV1::AmbiguousBoundary);
            }
            BlockState::FallbackSingleton => {
                risks.insert(ReconstructionRiskKindV1::FallbackSingleton);
            }
            BlockState::ProviderAtomic | BlockState::Reconstructed => {}
        }
        if fact.has_fragment {
            risks.insert(ReconstructionRiskKindV1::Fragment);
        }

        fact_count = fact_count
            .checked_add(risks.len())
            .ok_or(CandidateNeedsMoreReasonV1::ArithmeticCapacity)?;
        annotation.reconstruction_risks = risks.clone();
        for risk in risks {
            occurrences
                .entry(risk)
                .or_default()
                .push(ReconstructionRiskOccurrence {
                    ordinal: fact.ordinal,
                    block_id: fact.block_id,
                    work_position,
                });
        }
    }

    let mut representative_count = 0usize;
    for (risk, risk_occurrences) in &mut occurrences {
        risk_occurrences.sort_unstable_by(|left, right| {
            left.ordinal
                .cmp(&right.ordinal)
                .then_with(|| left.block_id.cmp(&right.block_id))
        });
        let representative_offsets = canonical_stratified_offsets(
            risk_occurrences.len(),
            MAX_RECONSTRUCTION_RISK_REPRESENTATIVES_PER_KIND_V1,
        )?;
        let facet_id =
            emitter.register_facet(CoverageFacetRoleV1::ReconstructionRisk(*risk), None)?;
        for offset in representative_offsets {
            let occurrence = risk_occurrences[offset];
            emitter.add_sentinel(
                &mut work[occurrence.work_position],
                CoverageSentinelKindV1::ReconstructionRisk(*risk),
                facet_id,
            )?;
            representative_count = representative_count
                .checked_add(1)
                .ok_or(CandidateNeedsMoreReasonV1::ArithmeticCapacity)?;
        }
    }

    Ok(ReconstructionRiskAccountingParts {
        fact_count,
        representative_count,
    })
}

/// Select canonical head/tail and evenly spaced interior occurrences. For the
/// frozen odd V1 cap, the center representative is the lower middle. Inputs
/// are only canonical occurrence order and count; no payload or hidden label
/// participates in selection.
fn canonical_stratified_offsets(
    occurrence_count: usize,
    representative_cap: usize,
) -> Result<Vec<usize>, GenerationFailure> {
    if occurrence_count == 0 || representative_cap == 0 {
        return Ok(Vec::new());
    }
    if occurrence_count <= representative_cap {
        return Ok((0..occurrence_count).collect());
    }
    if representative_cap < 3 {
        return Err(CandidateBuildErrorV1::FixedPointContractViolation.into());
    }

    let last_occurrence = occurrence_count - 1;
    let last_stratum = representative_cap - 1;
    (0..representative_cap)
        .map(|stratum| {
            stratum
                .checked_mul(last_occurrence)
                .and_then(|numerator| numerator.checked_div(last_stratum))
                .ok_or(CandidateNeedsMoreReasonV1::ArithmeticCapacity.into())
        })
        .collect()
}

fn add_source_sentinel(
    annotation: &mut WorkAnnotation,
    kind: SourceCoverageStratumKindV1,
    lane_anchor: Option<BlockId>,
    emitter: &mut OutputEmitter,
) -> Result<(), GenerationFailure> {
    let facet_id = emitter.register_facet(CoverageFacetRoleV1::Source(kind), lane_anchor)?;
    emitter.add_sentinel(annotation, CoverageSentinelKindV1::Source(kind), facet_id)
}

fn finalize_annotation(
    annotation: WorkAnnotation,
) -> Result<CoverageBlockAnnotationV1, GenerationFailure> {
    let failure = match annotation.failure_lane_position {
        Some((ordinal, count)) => {
            let mut occurrence_total = 0u32;
            let signals = annotation
                .failure_counts
                .into_iter()
                .map(|(kind, occurrence_count)| {
                    occurrence_total = occurrence_total
                        .checked_add(occurrence_count)
                        .ok_or(CandidateNeedsMoreReasonV1::ArithmeticCapacity)?;
                    Ok(FailureSignalCountV1::new(kind, occurrence_count))
                })
                .collect::<Result<Vec<_>, GenerationFailure>>()?;
            Some(FailureBlockFactV1::new(
                signals,
                occurrence_total,
                ordinal,
                count,
            ))
        }
        None => {
            if !annotation.failure_counts.is_empty() {
                return Err(CandidateBuildErrorV1::BlockIndexContractViolation.into());
            }
            None
        }
    };
    let onset_signals = annotation
        .onset_counts
        .into_iter()
        .map(|(kind, count)| OnsetSignalCountV1::new(kind, count))
        .collect();
    Ok(CoverageBlockAnnotationV1::new(
        annotation.block_id,
        failure,
        onset_signals,
        annotation.onset_boundaries.into_iter().collect(),
        annotation.reconstruction_risks.into_iter().collect(),
        annotation.sentinels.into_values().collect(),
        annotation.affinities.into_values().collect(),
    ))
}

fn checked_signal_observation_increment(
    current_family: usize,
    other_family: usize,
) -> Result<usize, CandidateNeedsMoreReasonV1> {
    let current_total = current_family
        .checked_add(other_family)
        .ok_or(CandidateNeedsMoreReasonV1::ArithmeticCapacity)?;
    if current_total >= MAX_COVERAGE_SIGNAL_OBSERVATIONS_V1 {
        return Err(CandidateNeedsMoreReasonV1::CoverageSignalObservationCap);
    }
    current_family
        .checked_add(1)
        .ok_or(CandidateNeedsMoreReasonV1::ArithmeticCapacity)
}

fn checked_bounded_increment(
    current: usize,
    maximum: usize,
    cap_reason: CandidateNeedsMoreReasonV1,
) -> Result<usize, CandidateNeedsMoreReasonV1> {
    let next = current
        .checked_add(1)
        .ok_or(CandidateNeedsMoreReasonV1::ArithmeticCapacity)?;
    if next > maximum {
        return Err(cap_reason);
    }
    Ok(next)
}

fn checked_bounded_u64_increment(
    current: u64,
    maximum: u64,
    cap_reason: CandidateNeedsMoreReasonV1,
) -> Result<u64, CandidateNeedsMoreReasonV1> {
    let next = current
        .checked_add(1)
        .ok_or(CandidateNeedsMoreReasonV1::ArithmeticCapacity)?;
    if next > maximum {
        return Err(cap_reason);
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

fn increment_signal_count<K: Ord + Copy>(counts: &mut BTreeMap<K, u32>, kind: K) -> Result<(), ()> {
    let current = counts.get(&kind).copied().unwrap_or(0);
    let next = current.checked_add(1).ok_or(())?;
    counts.insert(kind, next);
    Ok(())
}

fn classify_failure_signal(token: &[u8]) -> Option<FailureSignalKindV1> {
    if ascii_eq(token, b"error") {
        Some(FailureSignalKindV1::Error)
    } else if ascii_eq(token, b"fatal") {
        Some(FailureSignalKindV1::Fatal)
    } else if ascii_eq(token, b"critical") {
        Some(FailureSignalKindV1::Critical)
    } else if ascii_eq(token, b"panic")
        || ascii_eq(token, b"panicked")
        || ascii_eq(token, b"panicking")
    {
        Some(FailureSignalKindV1::Panic)
    } else if ascii_eq(token, b"assert")
        || ascii_eq(token, b"assertion")
        || ascii_eq(token, b"assertionerror")
    {
        Some(FailureSignalKindV1::Assertion)
    } else if ascii_eq(token, b"exception") || is_exception_class_token(token) {
        Some(FailureSignalKindV1::Exception)
    } else if is_rust_compiler_error_code(token) {
        Some(FailureSignalKindV1::CompilerError)
    } else if ascii_eq(token, b"crash")
        || ascii_eq(token, b"crashed")
        || ascii_eq(token, b"crashing")
    {
        Some(FailureSignalKindV1::Crash)
    } else if ascii_eq(token, b"fail") || ascii_eq(token, b"failed") || ascii_eq(token, b"failure")
    {
        Some(FailureSignalKindV1::Failure)
    } else {
        None
    }
}

fn classify_onset_signal(token: &[u8]) -> Option<OnsetSignalKindV1> {
    if ascii_eq(token, b"deploy")
        || ascii_eq(token, b"deployed")
        || ascii_eq(token, b"deployment")
        || ascii_eq(token, b"redeployed")
    {
        Some(OnsetSignalKindV1::Deployment)
    } else if ascii_eq(token, b"restart")
        || ascii_eq(token, b"restarted")
        || ascii_eq(token, b"restarting")
    {
        Some(OnsetSignalKindV1::Restart)
    } else if ascii_eq(token, b"migration")
        || ascii_eq(token, b"migrate")
        || ascii_eq(token, b"migrated")
        || ascii_eq(token, b"migrating")
    {
        Some(OnsetSignalKindV1::Migration)
    } else if ascii_eq(token, b"reconfigured")
        || ascii_eq(token, b"configuration-change")
        || ascii_eq(token, b"configuration_changed")
        || ascii_eq(token, b"config-reload")
        || ascii_eq(token, b"config_reloaded")
    {
        Some(OnsetSignalKindV1::ConfigurationChange)
    } else if ascii_eq(token, b"feature-flag-enabled")
        || ascii_eq(token, b"feature-flag-disabled")
        || ascii_eq(token, b"feature_flag_enabled")
        || ascii_eq(token, b"feature_flag_disabled")
        || ascii_eq(token, b"feature.flag.enabled")
        || ascii_eq(token, b"feature.flag.disabled")
    {
        Some(OnsetSignalKindV1::FeatureFlagChange)
    } else {
        None
    }
}

fn is_exception_class_token(token: &[u8]) -> bool {
    let suffix = if token.ends_with(b"Exception") {
        b"Exception".as_slice()
    } else if token.ends_with(b"Error") {
        b"Error".as_slice()
    } else {
        return false;
    };
    let Some(prefix_length) = token.len().checked_sub(suffix.len()) else {
        return false;
    };
    prefix_length > 0
        && token[..prefix_length]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        && token[..prefix_length].iter().any(u8::is_ascii_uppercase)
}

fn is_rust_compiler_error_code(token: &[u8]) -> bool {
    token.len() == 5
        && matches!(token[0], b'E' | b'e')
        && token[1..].iter().all(u8::is_ascii_digit)
        && token[1..] != *b"0000"
}

fn ascii_eq(left: &[u8], right_lowercase: &[u8]) -> bool {
    left.len() == right_lowercase.len()
        && left
            .iter()
            .zip(right_lowercase)
            .all(|(left, right)| left.to_ascii_lowercase() == *right)
}

fn production_kind(role: CoverageFacetRoleV1) -> ProductionFacetKindV1 {
    match role {
        CoverageFacetRoleV1::Failure(_) => ProductionFacetKindV1::FailureRole,
        CoverageFacetRoleV1::ExplicitOnset(_) | CoverageFacetRoleV1::OnsetBoundary(_) => {
            ProductionFacetKindV1::OnsetRole
        }
        CoverageFacetRoleV1::Source(_) => ProductionFacetKindV1::SourceCoverageStratum,
        CoverageFacetRoleV1::AcquisitionOrderStratum { .. } => {
            ProductionFacetKindV1::TimeCoverageStratum
        }
        CoverageFacetRoleV1::ReconstructionRisk(_) => {
            ProductionFacetKindV1::ReconstructionRiskCoverage
        }
    }
}

fn semantic_key(role: CoverageFacetRoleV1, lane_anchor: Option<BlockId>) -> Vec<u8> {
    let mut key = Vec::with_capacity(96);
    append_key_part(&mut key, b"evidentrail/failure-onset-raw-coverage/v1");
    match role {
        CoverageFacetRoleV1::Failure(kind) => {
            append_key_part(&mut key, b"failure");
            append_key_part(&mut key, kind.code().as_bytes());
        }
        CoverageFacetRoleV1::ExplicitOnset(kind) => {
            append_key_part(&mut key, b"explicit_onset");
            append_key_part(&mut key, kind.code().as_bytes());
        }
        CoverageFacetRoleV1::OnsetBoundary(role) => {
            append_key_part(&mut key, b"onset_boundary");
            append_key_part(&mut key, role.code().as_bytes());
        }
        CoverageFacetRoleV1::Source(kind) => {
            append_key_part(&mut key, b"source");
            append_key_part(&mut key, kind.code().as_bytes());
        }
        CoverageFacetRoleV1::AcquisitionOrderStratum { index, count } => {
            append_key_part(&mut key, b"acquisition_order_stratum");
            append_key_part(&mut key, &[index]);
            append_key_part(&mut key, &[count]);
        }
        CoverageFacetRoleV1::ReconstructionRisk(kind) => {
            append_key_part(&mut key, b"reconstruction_risk");
            append_key_part(&mut key, kind.code().as_bytes());
        }
    }
    if let Some(anchor) = lane_anchor {
        append_key_part(&mut key, anchor.as_bytes());
    }
    key
}

fn append_key_part(key: &mut Vec<u8>, part: &[u8]) {
    let length = u64::try_from(part.len()).expect("facet key parts fit in u64");
    key.extend_from_slice(&length.to_be_bytes());
    key.extend_from_slice(part);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_counter_accepts_its_exact_cap_and_rejects_the_next_value() {
        for (maximum, reason) in [
            (
                MAX_COVERAGE_OUTPUT_FACETS_V1,
                CandidateNeedsMoreReasonV1::CoverageFacetOutputCap,
            ),
            (
                MAX_COVERAGE_OUTPUT_AFFINITIES_V1,
                CandidateNeedsMoreReasonV1::CoverageAffinityOutputCap,
            ),
            (
                MAX_COVERAGE_OUTPUT_SENTINELS_V1,
                CandidateNeedsMoreReasonV1::CoverageSentinelOutputCap,
            ),
            (
                MAX_COVERAGE_SOURCE_LANES_V1,
                CandidateNeedsMoreReasonV1::CoverageSourceLaneCap,
            ),
        ] {
            assert_eq!(
                checked_bounded_increment(maximum - 1, maximum, reason),
                Ok(maximum)
            );
            assert_eq!(
                checked_bounded_increment(maximum, maximum, reason),
                Err(reason)
            );
        }
        assert_eq!(
            checked_bounded_u64_increment(
                MAX_COVERAGE_ANALYSIS_TOKENS_V1 - 1,
                MAX_COVERAGE_ANALYSIS_TOKENS_V1,
                CandidateNeedsMoreReasonV1::CoverageAnalysisTokenCap,
            ),
            Ok(MAX_COVERAGE_ANALYSIS_TOKENS_V1)
        );
        assert_eq!(
            checked_bounded_u64_increment(
                MAX_COVERAGE_ANALYSIS_TOKENS_V1,
                MAX_COVERAGE_ANALYSIS_TOKENS_V1,
                CandidateNeedsMoreReasonV1::CoverageAnalysisTokenCap,
            ),
            Err(CandidateNeedsMoreReasonV1::CoverageAnalysisTokenCap)
        );
        assert_eq!(
            checked_signal_observation_increment(MAX_COVERAGE_SIGNAL_OBSERVATIONS_V1 - 1, 0,),
            Ok(MAX_COVERAGE_SIGNAL_OBSERVATIONS_V1)
        );
        assert_eq!(
            checked_signal_observation_increment(MAX_COVERAGE_SIGNAL_OBSERVATIONS_V1, 0),
            Err(CandidateNeedsMoreReasonV1::CoverageSignalObservationCap)
        );
        assert_eq!(
            checked_scanned_bytes(0, MAX_PRIMARY_BYTES_SCANNED_V1),
            Ok(MAX_PRIMARY_BYTES_SCANNED_V1)
        );
        assert_eq!(
            checked_scanned_bytes(MAX_PRIMARY_BYTES_SCANNED_V1, 1),
            Err(CandidateNeedsMoreReasonV1::PrimaryBytesScannedCap)
        );
    }

    #[test]
    fn byte_signal_grammars_are_exact_nonsubstring_and_case_bounded() {
        assert_eq!(
            classify_failure_signal(b"ERROR"),
            Some(FailureSignalKindV1::Error)
        );
        assert_eq!(
            classify_failure_signal(b"ValueError"),
            Some(FailureSignalKindV1::Exception)
        );
        assert_eq!(classify_failure_signal(b"terror"), None);
        assert_eq!(classify_failure_signal(b"errorish"), None);
        assert_eq!(
            classify_onset_signal(b"FEATURE_FLAG_ENABLED"),
            Some(OnsetSignalKindV1::FeatureFlagChange)
        );
        assert_eq!(classify_onset_signal(b"redeploymentish"), None);
    }
}
