use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;

use evidentrail_bench::{
    CandidateRendererIdentityV1, EvidentrailBenchCaseSpecV1, EvidentrailBenchRunManifestV1,
    EvidenceRepresentationClaimV1, FrozenExternalRepresentationSubmissionV1,
    MeasuredCandidateResources, MeasurementEnvironmentV1, MeasurementHarnessIdentityV1,
    MethodDescriptor, RenderedCandidateArtifactV1, TokenizerIdentityV1,
    ascii_byte_escape_v1_identity, derive_reversible_encoded_representation_artifact_digest_v1,
};
use evidentrail_core::{EventId, EventLedger};
use evidentrail_evidence::{
    COMPILED_TEXT_RENDERER_CONTRACT_VERSION_V1, OwnedRenderedCompiledBriefV1,
    OwnedRenderedPassthroughBriefV1, PASSTHROUGH_TEXT_RENDERER_CONTRACT_VERSION_V1,
    RenderedCompiledBriefV1, RenderedPassthroughBriefV1, compiled_renderer_digest_v1,
    passthrough_renderer_digest_v1,
};
use evidentrail_schema::{ArtifactDigest, QuestionDigest};

use crate::{
    PublicCaseInputBindingV1, artifact_digest_for_bytes_v1, canonical_public_case_artifact_v1,
    canonical_public_run_manifest_artifact_v1,
};

const PASSTHROUGH_DATA_MARKER_V1: &[u8] = b"\n    data_encoding: ascii_byte_escape_v1\n    data: ";
const COMPILED_DATA_MARKER_V1: &[u8] = b"\n      data_encoding: ascii_byte_escape_v1\n      data: ";
const FIRST_PARTY_LOG_BRIEF_BRIDGE_MANIFEST_V1: &[u8] = b"evidentrail/bench-harness/first-party-log-brief-reversible-bridge/v1\0typed-rendered-brief-required=true\0structured-event-order=true\0data-encoding=ascii-byte-escape-v1\0proof-range=canonical-field-prefix-plus-half-open-encoded-data\0displayed-representation-bytes=complete-render\0input-universe-charge=separate\0proposal-union-accounting=not-provided\0hidden-labels=none";

/// Inherent exhaustive input-universe charge, separate from selected candidate
/// resources and from externally observed render/runtime dimensions.
///
/// Duplicate payload occurrences are charged independently because this is an
/// occurrence count over the sealed ledger, not a content-deduplicated size.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FirstPartyInputUniverseChargeV1 {
    event_count: u64,
    source_bytes: u64,
}

impl FirstPartyInputUniverseChargeV1 {
    #[must_use]
    pub const fn event_count(self) -> u64 {
        self.event_count
    }

    #[must_use]
    pub const fn source_bytes(self) -> u64 {
        self.source_bytes
    }
}

impl fmt::Debug for FirstPartyInputUniverseChargeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirstPartyInputUniverseChargeV1")
            .field("event_count", &self.event_count)
            .field("source_bytes", &self.source_bytes)
            .finish()
    }
}

/// Frozen first-party representation plus separately reported input-universe
/// accounting.
///
/// The generic candidate envelope inside `submission` accounts for evidence
/// actually displayed by this final renderer. It is not a pre-ranking
/// candidate-generator proposal union. Likewise, the universe charge records
/// exhaustive input processing but does not substitute for proposal-recall or
/// proposal-cost accounting.
#[derive(Clone, PartialEq, Eq)]
pub struct FirstPartyLogBriefRepresentationReceiptV1 {
    submission: FrozenExternalRepresentationSubmissionV1,
    input_universe_charge: FirstPartyInputUniverseChargeV1,
}

impl FirstPartyLogBriefRepresentationReceiptV1 {
    #[must_use]
    pub const fn submission(&self) -> &FrozenExternalRepresentationSubmissionV1 {
        &self.submission
    }

    #[must_use]
    pub const fn input_universe_charge(&self) -> FirstPartyInputUniverseChargeV1 {
        self.input_universe_charge
    }
}

impl fmt::Debug for FirstPartyLogBriefRepresentationReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirstPartyLogBriefRepresentationReceiptV1")
            .field("submission", &self.submission)
            .field("input_universe_charge", &self.input_universe_charge)
            .field("contains_governed_labels", &false)
            .finish()
    }
}

/// Fixed benchmark method identity for canonical first-party passthrough text.
#[must_use]
pub const fn log_brief_passthrough_method_descriptor_v1() -> MethodDescriptor {
    MethodDescriptor::new("evidentrail-log-brief-passthrough", "1")
}

/// Fixed benchmark method identity for canonical first-party compiled text.
#[must_use]
pub const fn log_brief_compiled_method_descriptor_v1() -> MethodDescriptor {
    MethodDescriptor::new("evidentrail-log-brief-compiled", "1")
}

/// Freeze a canonical typed passthrough Log Brief as byte-proven reversible
/// evidence. The typed renderer output, structured event order, renderer and
/// tokenizer identities, and complete rendered artifact are all cross-checked
/// before the generic governed submission can be constructed.
#[allow(clippy::too_many_arguments)]
pub fn freeze_passthrough_log_brief_representation_v1(
    run_manifest: &EvidentrailBenchRunManifestV1,
    public_case_artifact_digest: ArtifactDigest,
    ledger: &EventLedger,
    rendered: &RenderedPassthroughBriefV1<'_>,
    tokenizer: TokenizerIdentityV1,
    measurement_harness: MeasurementHarnessIdentityV1,
    externally_observed: MeasuredCandidateResources,
) -> Result<FirstPartyLogBriefRepresentationReceiptV1, FirstPartyLogBriefBridgeErrorV1> {
    let brief = rendered.brief();
    let renderer_digest = passthrough_renderer_digest_v1();
    if brief.plan_digest() != ledger.plan_digest()
        || brief.budget().renderer_digest() != renderer_digest
        || brief.budget().total_rendered_bytes()
            != u64::try_from(rendered.text().len())
                .map_err(|_| FirstPartyLogBriefBridgeErrorV1::AccountingOverflow)?
    {
        return Err(FirstPartyLogBriefBridgeErrorV1::StructuredBriefMismatch);
    }
    if brief.budget().tokenizer_digest() != tokenizer.artifact_digest() {
        return Err(FirstPartyLogBriefBridgeErrorV1::TokenizerBindingMismatch);
    }
    if brief.budget().total_rendered_tokens() != externally_observed.canonical_candidate_tokens() {
        return Err(FirstPartyLogBriefBridgeErrorV1::MeasurementBindingMismatch);
    }
    let event_ids = brief
        .evidence()
        .iter()
        .map(|evidence| evidence.event_id())
        .collect::<Vec<_>>();
    freeze_typed_log_brief(
        run_manifest,
        public_case_artifact_digest,
        ledger,
        log_brief_passthrough_method_descriptor_v1(),
        renderer_digest,
        u64::from(PASSTHROUGH_TEXT_RENDERER_CONTRACT_VERSION_V1),
        rendered.text().as_bytes(),
        PASSTHROUGH_DATA_MARKER_V1,
        event_ids,
        tokenizer,
        measurement_harness,
        externally_observed,
    )
}

/// Owned-artifact variant for the product lifecycle after
/// `RenderedPassthroughBriefV1::into_owned`. No reconstruction from text is
/// accepted: the owned structured evidence order is still required.
#[allow(clippy::too_many_arguments)]
pub fn freeze_owned_passthrough_log_brief_representation_v1(
    run_manifest: &EvidentrailBenchRunManifestV1,
    public_case_artifact_digest: ArtifactDigest,
    ledger: &EventLedger,
    rendered: &OwnedRenderedPassthroughBriefV1,
    tokenizer: TokenizerIdentityV1,
    measurement_harness: MeasurementHarnessIdentityV1,
    externally_observed: MeasuredCandidateResources,
) -> Result<FirstPartyLogBriefRepresentationReceiptV1, FirstPartyLogBriefBridgeErrorV1> {
    let brief = rendered.brief();
    let renderer_digest = passthrough_renderer_digest_v1();
    if brief.plan_digest() != ledger.plan_digest()
        || brief.budget().renderer_digest() != renderer_digest
        || brief.budget().total_rendered_bytes()
            != u64::try_from(rendered.text().len())
                .map_err(|_| FirstPartyLogBriefBridgeErrorV1::AccountingOverflow)?
    {
        return Err(FirstPartyLogBriefBridgeErrorV1::StructuredBriefMismatch);
    }
    if brief.budget().tokenizer_digest() != tokenizer.artifact_digest() {
        return Err(FirstPartyLogBriefBridgeErrorV1::TokenizerBindingMismatch);
    }
    if brief.budget().total_rendered_tokens() != externally_observed.canonical_candidate_tokens() {
        return Err(FirstPartyLogBriefBridgeErrorV1::MeasurementBindingMismatch);
    }
    let event_ids = brief
        .evidence()
        .iter()
        .map(|evidence| evidence.event_id())
        .collect::<Vec<_>>();
    freeze_typed_log_brief(
        run_manifest,
        public_case_artifact_digest,
        ledger,
        log_brief_passthrough_method_descriptor_v1(),
        renderer_digest,
        u64::from(PASSTHROUGH_TEXT_RENDERER_CONTRACT_VERSION_V1),
        rendered.text().as_bytes(),
        PASSTHROUGH_DATA_MARKER_V1,
        event_ids,
        tokenizer,
        measurement_harness,
        externally_observed,
    )
}

/// Case-bound owned passthrough bridge for actual product output.
///
/// In addition to the renderer proof, this validates the exact canonical
/// public case/input binding, question digest, and the selected run budget
/// point before freezing the representation.
#[allow(clippy::too_many_arguments)]
pub fn freeze_bound_owned_passthrough_log_brief_representation_v1(
    run_manifest: &EvidentrailBenchRunManifestV1,
    public_case: &EvidentrailBenchCaseSpecV1,
    case_input: &PublicCaseInputBindingV1,
    ledger: &EventLedger,
    rendered: &OwnedRenderedPassthroughBriefV1,
    tokenizer: TokenizerIdentityV1,
    measurement_harness: MeasurementHarnessIdentityV1,
    externally_observed: MeasuredCandidateResources,
) -> Result<FirstPartyLogBriefRepresentationReceiptV1, FirstPartyLogBriefBridgeErrorV1> {
    validate_bound_product_case(
        run_manifest,
        public_case,
        case_input,
        ledger,
        rendered.brief().question_digest(),
        rendered.brief().budget().total_token_limit(),
    )?;
    freeze_owned_passthrough_log_brief_representation_v1(
        run_manifest,
        case_input.public_case_artifact_digest(),
        ledger,
        rendered,
        tokenizer,
        measurement_harness,
        externally_observed,
    )
}

/// Freeze a canonical typed compiled Log Brief as byte-proven reversible
/// evidence. Only displayed packet members become claims; retained-raw events
/// are not fabricated into the candidate set.
#[allow(clippy::too_many_arguments)]
pub fn freeze_compiled_log_brief_representation_v1(
    run_manifest: &EvidentrailBenchRunManifestV1,
    public_case_artifact_digest: ArtifactDigest,
    ledger: &EventLedger,
    rendered: &RenderedCompiledBriefV1<'_>,
    tokenizer: TokenizerIdentityV1,
    measurement_harness: MeasurementHarnessIdentityV1,
    externally_observed: MeasuredCandidateResources,
) -> Result<FirstPartyLogBriefRepresentationReceiptV1, FirstPartyLogBriefBridgeErrorV1> {
    let brief = rendered.brief();
    let renderer_digest = compiled_renderer_digest_v1();
    if brief.plan_digest() != ledger.plan_digest()
        || brief.cost().renderer_digest() != renderer_digest
        || brief.cost().total_rendered_bytes()
            != u64::try_from(rendered.text().len())
                .map_err(|_| FirstPartyLogBriefBridgeErrorV1::AccountingOverflow)?
    {
        return Err(FirstPartyLogBriefBridgeErrorV1::StructuredBriefMismatch);
    }
    if brief.cost().tokenizer_digest() != tokenizer.artifact_digest() {
        return Err(FirstPartyLogBriefBridgeErrorV1::TokenizerBindingMismatch);
    }
    if brief.cost().total_rendered_tokens() != externally_observed.canonical_candidate_tokens() {
        return Err(FirstPartyLogBriefBridgeErrorV1::MeasurementBindingMismatch);
    }
    let event_ids = brief
        .evidence()
        .iter()
        .flat_map(|packet| packet.events().iter().map(|event| event.event_id()))
        .collect::<Vec<_>>();
    freeze_typed_log_brief(
        run_manifest,
        public_case_artifact_digest,
        ledger,
        log_brief_compiled_method_descriptor_v1(),
        renderer_digest,
        u64::from(COMPILED_TEXT_RENDERER_CONTRACT_VERSION_V1),
        rendered.text().as_bytes(),
        COMPILED_DATA_MARKER_V1,
        event_ids,
        tokenizer,
        measurement_harness,
        externally_observed,
    )
}

/// Owned-artifact variant for the product lifecycle after
/// `RenderedCompiledBriefV1::into_owned`.
#[allow(clippy::too_many_arguments)]
pub fn freeze_owned_compiled_log_brief_representation_v1(
    run_manifest: &EvidentrailBenchRunManifestV1,
    public_case_artifact_digest: ArtifactDigest,
    ledger: &EventLedger,
    rendered: &OwnedRenderedCompiledBriefV1,
    tokenizer: TokenizerIdentityV1,
    measurement_harness: MeasurementHarnessIdentityV1,
    externally_observed: MeasuredCandidateResources,
) -> Result<FirstPartyLogBriefRepresentationReceiptV1, FirstPartyLogBriefBridgeErrorV1> {
    let brief = rendered.brief();
    let renderer_digest = compiled_renderer_digest_v1();
    if brief.plan_digest() != ledger.plan_digest()
        || brief.cost().renderer_digest() != renderer_digest
        || brief.cost().total_rendered_bytes()
            != u64::try_from(rendered.text().len())
                .map_err(|_| FirstPartyLogBriefBridgeErrorV1::AccountingOverflow)?
    {
        return Err(FirstPartyLogBriefBridgeErrorV1::StructuredBriefMismatch);
    }
    if brief.cost().tokenizer_digest() != tokenizer.artifact_digest() {
        return Err(FirstPartyLogBriefBridgeErrorV1::TokenizerBindingMismatch);
    }
    if brief.cost().total_rendered_tokens() != externally_observed.canonical_candidate_tokens() {
        return Err(FirstPartyLogBriefBridgeErrorV1::MeasurementBindingMismatch);
    }
    let event_ids = brief
        .evidence()
        .iter()
        .flat_map(|packet| packet.events().iter().map(|event| event.event_id()))
        .collect::<Vec<_>>();
    freeze_typed_log_brief(
        run_manifest,
        public_case_artifact_digest,
        ledger,
        log_brief_compiled_method_descriptor_v1(),
        renderer_digest,
        u64::from(COMPILED_TEXT_RENDERER_CONTRACT_VERSION_V1),
        rendered.text().as_bytes(),
        COMPILED_DATA_MARKER_V1,
        event_ids,
        tokenizer,
        measurement_harness,
        externally_observed,
    )
}

/// Case-bound owned compiled bridge for actual product output.
#[allow(clippy::too_many_arguments)]
pub fn freeze_bound_owned_compiled_log_brief_representation_v1(
    run_manifest: &EvidentrailBenchRunManifestV1,
    public_case: &EvidentrailBenchCaseSpecV1,
    case_input: &PublicCaseInputBindingV1,
    ledger: &EventLedger,
    rendered: &OwnedRenderedCompiledBriefV1,
    tokenizer: TokenizerIdentityV1,
    measurement_harness: MeasurementHarnessIdentityV1,
    externally_observed: MeasuredCandidateResources,
) -> Result<FirstPartyLogBriefRepresentationReceiptV1, FirstPartyLogBriefBridgeErrorV1> {
    validate_bound_product_case(
        run_manifest,
        public_case,
        case_input,
        ledger,
        rendered.brief().question_digest(),
        rendered.brief().cost().total_token_budget(),
    )?;
    freeze_owned_compiled_log_brief_representation_v1(
        run_manifest,
        case_input.public_case_artifact_digest(),
        ledger,
        rendered,
        tokenizer,
        measurement_harness,
        externally_observed,
    )
}

fn validate_bound_product_case(
    run_manifest: &EvidentrailBenchRunManifestV1,
    public_case: &EvidentrailBenchCaseSpecV1,
    case_input: &PublicCaseInputBindingV1,
    ledger: &EventLedger,
    rendered_question_digest: QuestionDigest,
    product_token_budget: u64,
) -> Result<(), FirstPartyLogBriefBridgeErrorV1> {
    let canonical_case = canonical_public_case_artifact_v1(public_case)
        .map_err(|_| FirstPartyLogBriefBridgeErrorV1::PublicCaseBindingMismatch)?;
    let canonical_run = canonical_public_run_manifest_artifact_v1(run_manifest)
        .map_err(|_| FirstPartyLogBriefBridgeErrorV1::RunManifestBindingMismatch)?;
    if canonical_case.artifact_digest() != case_input.public_case_artifact_digest()
        || canonical_run.artifact_digest()
            != case_input
                .canonical_public_run_manifest_artifact()
                .artifact_digest()
        || case_input.source_record_map().acquisition_receipt_id()
            != ledger.acquisition_receipt_id()
        || case_input.source_record_map().records().len() != ledger.events().len()
        || case_input
            .source_record_map()
            .records()
            .iter()
            .zip(ledger.events())
            .any(|(record, event)| {
                record.event_id() != event.id()
                    || record.source_record_id() != event.source_record_id()
            })
    {
        return Err(FirstPartyLogBriefBridgeErrorV1::PublicCaseBindingMismatch);
    }
    if public_case.question_digest() != rendered_question_digest
        || public_case.plan_digest() != ledger.plan_digest()
    {
        return Err(FirstPartyLogBriefBridgeErrorV1::QuestionOrPlanBindingMismatch);
    }
    let run_budget = run_manifest.identity().budget();
    if product_token_budget != run_budget.canonical_candidate_tokens()
        || !public_case.budget_points().contains(&run_budget.cap())
    {
        return Err(FirstPartyLogBriefBridgeErrorV1::ProductBudgetBindingMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn freeze_typed_log_brief(
    run_manifest: &EvidentrailBenchRunManifestV1,
    public_case_artifact_digest: ArtifactDigest,
    ledger: &EventLedger,
    method: MethodDescriptor,
    renderer_digest: ArtifactDigest,
    renderer_contract_version: u64,
    rendered_bytes: &[u8],
    marker: &[u8],
    event_ids: Vec<EventId>,
    tokenizer: TokenizerIdentityV1,
    measurement_harness: MeasurementHarnessIdentityV1,
    externally_observed: MeasuredCandidateResources,
) -> Result<FirstPartyLogBriefRepresentationReceiptV1, FirstPartyLogBriefBridgeErrorV1> {
    if event_ids.is_empty() {
        if ledger.events().is_empty() {
            return Err(FirstPartyLogBriefBridgeErrorV1::EmptyLedgerUnsupported);
        }
        return Err(FirstPartyLogBriefBridgeErrorV1::EmptyDisplayedEvidence);
    }
    if event_ids.iter().copied().collect::<BTreeSet<_>>().len() != event_ids.len() {
        return Err(FirstPartyLogBriefBridgeErrorV1::DuplicateDisplayedEvent);
    }
    let ranges = locate_canonical_data_ranges(rendered_bytes, marker, event_ids.len())?;
    let encoding = ascii_byte_escape_v1_identity();
    let claims = event_ids
        .into_iter()
        .zip(ranges)
        .map(|(event_id, (context_start, start, end))| {
            let encoded = &rendered_bytes[start..end];
            let context_start = u64::try_from(context_start)
                .map_err(|_| FirstPartyLogBriefBridgeErrorV1::AccountingOverflow)?;
            let start = u64::try_from(start)
                .map_err(|_| FirstPartyLogBriefBridgeErrorV1::AccountingOverflow)?;
            let end = u64::try_from(end)
                .map_err(|_| FirstPartyLogBriefBridgeErrorV1::AccountingOverflow)?;
            let digest =
                derive_reversible_encoded_representation_artifact_digest_v1(encoding, encoded)
                    .map_err(|_| {
                        FirstPartyLogBriefBridgeErrorV1::RepresentationConstructionFailed
                    })?;
            Ok(
                EvidenceRepresentationClaimV1::source_exact_reversible_encoding(
                    event_id,
                    encoding,
                    digest,
                    context_start,
                    start,
                    end,
                ),
            )
        })
        .collect::<Result<Vec<_>, FirstPartyLogBriefBridgeErrorV1>>()?;
    let rendered_candidate = RenderedCandidateArtifactV1::try_new(
        artifact_digest_for_bytes_v1(rendered_bytes),
        u64::try_from(rendered_bytes.len())
            .map_err(|_| FirstPartyLogBriefBridgeErrorV1::AccountingOverflow)?,
    )
    .map_err(|_| FirstPartyLogBriefBridgeErrorV1::RepresentationConstructionFailed)?;
    let renderer = CandidateRendererIdentityV1::try_new(renderer_digest, renderer_contract_version)
        .map_err(|_| FirstPartyLogBriefBridgeErrorV1::RendererBindingMismatch)?;
    let canonical_run = canonical_public_run_manifest_artifact_v1(run_manifest)
        .map_err(|_| FirstPartyLogBriefBridgeErrorV1::RunManifestBindingMismatch)?;
    let submission = FrozenExternalRepresentationSubmissionV1::try_new_self_asserted(
        canonical_run.artifact_digest(),
        run_manifest,
        public_case_artifact_digest,
        method,
        ledger,
        artifact_digest_for_bytes_v1(FIRST_PARTY_LOG_BRIEF_BRIDGE_MANIFEST_V1),
        encoding.artifact_digest(),
        MeasurementEnvironmentV1::new(tokenizer, renderer, measurement_harness),
        rendered_candidate,
        rendered_bytes,
        externally_observed,
        claims,
    )
    .map_err(|_| FirstPartyLogBriefBridgeErrorV1::RepresentationConstructionFailed)?;
    Ok(FirstPartyLogBriefRepresentationReceiptV1 {
        submission,
        input_universe_charge: input_universe_charge(ledger)?,
    })
}

fn locate_canonical_data_ranges(
    rendered: &[u8],
    marker: &[u8],
    expected_count: usize,
) -> Result<Vec<(usize, usize, usize)>, FirstPartyLogBriefBridgeErrorV1> {
    let mut ranges = Vec::with_capacity(expected_count);
    let mut cursor = 0_usize;
    for _ in 0..expected_count {
        let relative = rendered
            .get(cursor..)
            .and_then(|remaining| {
                remaining
                    .windows(marker.len())
                    .position(|window| window == marker)
            })
            .ok_or(FirstPartyLogBriefBridgeErrorV1::RenderedGrammarMismatch)?;
        let context_start = cursor
            .checked_add(relative)
            .ok_or(FirstPartyLogBriefBridgeErrorV1::AccountingOverflow)?;
        let start = context_start
            .checked_add(marker.len())
            .ok_or(FirstPartyLogBriefBridgeErrorV1::AccountingOverflow)?;
        let length = rendered
            .get(start..)
            .and_then(|remaining| remaining.iter().position(|byte| *byte == b'\n'))
            .ok_or(FirstPartyLogBriefBridgeErrorV1::RenderedGrammarMismatch)?;
        let end = start
            .checked_add(length)
            .ok_or(FirstPartyLogBriefBridgeErrorV1::AccountingOverflow)?;
        ranges.push((context_start, start, end));
        cursor = end
            .checked_add(1)
            .ok_or(FirstPartyLogBriefBridgeErrorV1::AccountingOverflow)?;
    }
    if rendered.get(cursor..).is_some_and(|remaining| {
        remaining
            .windows(marker.len())
            .any(|window| window == marker)
    }) {
        return Err(FirstPartyLogBriefBridgeErrorV1::RenderedGrammarMismatch);
    }
    Ok(ranges)
}

fn input_universe_charge(
    ledger: &EventLedger,
) -> Result<FirstPartyInputUniverseChargeV1, FirstPartyLogBriefBridgeErrorV1> {
    let event_count = u64::try_from(ledger.events().len())
        .map_err(|_| FirstPartyLogBriefBridgeErrorV1::AccountingOverflow)?;
    let source_bytes = ledger.events().iter().try_fold(0_u64, |total, event| {
        let event_bytes = u64::try_from(event.raw().len())
            .map_err(|_| FirstPartyLogBriefBridgeErrorV1::AccountingOverflow)?;
        total
            .checked_add(event_bytes)
            .ok_or(FirstPartyLogBriefBridgeErrorV1::AccountingOverflow)
    })?;
    Ok(FirstPartyInputUniverseChargeV1 {
        event_count,
        source_bytes,
    })
}

/// Contentless failures at the typed first-party renderer bridge.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FirstPartyLogBriefBridgeErrorV1 {
    RunManifestBindingMismatch,
    PublicCaseBindingMismatch,
    QuestionOrPlanBindingMismatch,
    ProductBudgetBindingMismatch,
    RendererBindingMismatch,
    TokenizerBindingMismatch,
    MeasurementBindingMismatch,
    StructuredBriefMismatch,
    RenderedGrammarMismatch,
    EmptyLedgerUnsupported,
    EmptyDisplayedEvidence,
    DuplicateDisplayedEvent,
    RepresentationConstructionFailed,
    AccountingOverflow,
}

impl FirstPartyLogBriefBridgeErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::RunManifestBindingMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_LOG_BRIEF_RUN_MANIFEST_BINDING_MISMATCH"
            }
            Self::PublicCaseBindingMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_LOG_BRIEF_PUBLIC_CASE_BINDING_MISMATCH"
            }
            Self::QuestionOrPlanBindingMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_LOG_BRIEF_QUESTION_OR_PLAN_BINDING_MISMATCH"
            }
            Self::ProductBudgetBindingMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_LOG_BRIEF_PRODUCT_BUDGET_BINDING_MISMATCH"
            }
            Self::RendererBindingMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_LOG_BRIEF_RENDERER_BINDING_MISMATCH"
            }
            Self::TokenizerBindingMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_LOG_BRIEF_TOKENIZER_BINDING_MISMATCH"
            }
            Self::MeasurementBindingMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_LOG_BRIEF_MEASUREMENT_BINDING_MISMATCH"
            }
            Self::StructuredBriefMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_LOG_BRIEF_STRUCTURED_BRIEF_MISMATCH"
            }
            Self::RenderedGrammarMismatch => {
                "EVIDENTRAIL_BENCH_HARNESS_LOG_BRIEF_RENDERED_GRAMMAR_MISMATCH"
            }
            Self::EmptyLedgerUnsupported => {
                "EVIDENTRAIL_BENCH_HARNESS_LOG_BRIEF_EMPTY_LEDGER_UNSUPPORTED"
            }
            Self::EmptyDisplayedEvidence => {
                "EVIDENTRAIL_BENCH_HARNESS_LOG_BRIEF_EMPTY_DISPLAYED_EVIDENCE"
            }
            Self::DuplicateDisplayedEvent => {
                "EVIDENTRAIL_BENCH_HARNESS_LOG_BRIEF_DUPLICATE_DISPLAYED_EVENT"
            }
            Self::RepresentationConstructionFailed => {
                "EVIDENTRAIL_BENCH_HARNESS_LOG_BRIEF_REPRESENTATION_CONSTRUCTION_FAILED"
            }
            Self::AccountingOverflow => "EVIDENTRAIL_BENCH_HARNESS_LOG_BRIEF_ACCOUNTING_OVERFLOW",
        }
    }
}

impl fmt::Debug for FirstPartyLogBriefBridgeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirstPartyLogBriefBridgeErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for FirstPartyLogBriefBridgeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for FirstPartyLogBriefBridgeErrorV1 {}
