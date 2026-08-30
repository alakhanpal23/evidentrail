#[cfg(feature = "product")]
use evidentrail_schema::bounds::MAX_EXPANSION_REQUEST_BYTES;
#[cfg(feature = "local-file")]
use evidentrail_schema::bounds::MAX_QUERY_PLAN_BYTES;
use evidentrail_schema::bounds::MAX_WIRE_OBJECT_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationClassV1 {
    HistoricalEvidence,
    ReissueRequired,
    ReplanRequired,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityDomainV1 {
    None,
    Binding,
    Plan,
    TransformationReceipt,
    Event,
    Block,
    AcquisitionReceipt,
    PresentationReceipt,
    EvidenceReference,
    ResultScoped,
    Artifact,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContractDescriptorV1 {
    name: &'static str,
    supported_version: u16,
    maximum_bytes: usize,
    schema_path: &'static str,
    migration_class: MigrationClassV1,
    identity_domain: IdentityDomainV1,
}

impl ContractDescriptorV1 {
    const fn new(
        name: &'static str,
        maximum_bytes: usize,
        schema_path: &'static str,
        migration_class: MigrationClassV1,
        identity_domain: IdentityDomainV1,
    ) -> Self {
        Self {
            name,
            supported_version: 1,
            maximum_bytes,
            schema_path,
            migration_class,
            identity_domain,
        }
    }
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }
    #[must_use]
    pub const fn supported_version(self) -> u16 {
        self.supported_version
    }
    #[must_use]
    pub const fn maximum_bytes(self) -> usize {
        self.maximum_bytes
    }
    #[must_use]
    pub const fn schema_path(self) -> &'static str {
        self.schema_path
    }
    #[must_use]
    pub const fn migration_class(self) -> MigrationClassV1 {
        self.migration_class
    }
    #[must_use]
    pub const fn identity_domain(self) -> IdentityDomainV1 {
        self.identity_domain
    }
}

const fn d(
    name: &'static str,
    maximum_bytes: usize,
    schema_path: &'static str,
    migration_class: MigrationClassV1,
    identity_domain: IdentityDomainV1,
) -> ContractDescriptorV1 {
    ContractDescriptorV1::new(
        name,
        maximum_bytes,
        schema_path,
        migration_class,
        identity_domain,
    )
}

/// Every contract compiled into this feature selection, in lexical order.
#[must_use]
pub fn contract_registry_v1() -> Vec<ContractDescriptorV1> {
    let mut registry = Vec::new();
    #[cfg(feature = "local-file")]
    registry.extend([
        d(
            "evidentrail.approved_local_file_binding",
            MAX_WIRE_OBJECT_BYTES,
            "schemas/evidentrail/v1/approved_local_file_binding.schema.json",
            MigrationClassV1::None,
            IdentityDomainV1::Binding,
        ),
        d(
            "evidentrail.local_file_query_plan",
            MAX_QUERY_PLAN_BYTES,
            "schemas/evidentrail/v1/local_file_query_plan.schema.json",
            MigrationClassV1::ReplanRequired,
            IdentityDomainV1::Plan,
        ),
    ]);
    #[cfg(feature = "ledger")]
    registry.extend([
        d(
            "evidentrail.acquisition_receipt",
            MAX_WIRE_OBJECT_BYTES,
            "schemas/evidentrail/v1/acquisition_receipt.schema.json",
            MigrationClassV1::HistoricalEvidence,
            IdentityDomainV1::AcquisitionReceipt,
        ),
        d(
            "evidentrail.acquisition_receipt_chunk",
            MAX_WIRE_OBJECT_BYTES,
            "schemas/evidentrail/v1/acquisition_receipt_chunk.schema.json",
            MigrationClassV1::HistoricalEvidence,
            IdentityDomainV1::Artifact,
        ),
        d(
            "evidentrail.event_block_record",
            MAX_WIRE_OBJECT_BYTES,
            "schemas/evidentrail/v1/event_block_record.schema.json",
            MigrationClassV1::HistoricalEvidence,
            IdentityDomainV1::Block,
        ),
        d(
            "evidentrail.event_record",
            MAX_WIRE_OBJECT_BYTES,
            "schemas/evidentrail/v1/event_record.schema.json",
            MigrationClassV1::HistoricalEvidence,
            IdentityDomainV1::Event,
        ),
        d(
            "evidentrail.fetch_completion",
            MAX_WIRE_OBJECT_BYTES,
            "schemas/evidentrail/v1/fetch_completion.schema.json",
            MigrationClassV1::HistoricalEvidence,
            IdentityDomainV1::Artifact,
        ),
        d(
            "evidentrail.presentation_receipt",
            MAX_WIRE_OBJECT_BYTES,
            "schemas/evidentrail/v1/presentation_receipt.schema.json",
            MigrationClassV1::HistoricalEvidence,
            IdentityDomainV1::PresentationReceipt,
        ),
        d(
            "evidentrail.presentation_receipt_chunk",
            MAX_WIRE_OBJECT_BYTES,
            "schemas/evidentrail/v1/presentation_receipt_chunk.schema.json",
            MigrationClassV1::HistoricalEvidence,
            IdentityDomainV1::Artifact,
        ),
        d(
            "evidentrail.transformation_receipt",
            MAX_WIRE_OBJECT_BYTES,
            "schemas/evidentrail/v1/transformation_receipt.schema.json",
            MigrationClassV1::HistoricalEvidence,
            IdentityDomainV1::TransformationReceipt,
        ),
    ]);
    #[cfg(feature = "product")]
    registry.extend([
        d(
            "evidentrail.evidence_reference",
            MAX_WIRE_OBJECT_BYTES,
            "schemas/evidentrail/v1/evidence_reference.schema.json",
            MigrationClassV1::HistoricalEvidence,
            IdentityDomainV1::EvidenceReference,
        ),
        d(
            "evidentrail.expansion_request",
            MAX_EXPANSION_REQUEST_BYTES,
            "schemas/evidentrail/v1/expansion_request.schema.json",
            MigrationClassV1::ReissueRequired,
            IdentityDomainV1::ResultScoped,
        ),
        d(
            "evidentrail.expansion_response",
            MAX_WIRE_OBJECT_BYTES,
            "schemas/evidentrail/v1/expansion_response.schema.json",
            MigrationClassV1::HistoricalEvidence,
            IdentityDomainV1::ResultScoped,
        ),
        d(
            "evidentrail.log_brief",
            MAX_WIRE_OBJECT_BYTES,
            "schemas/evidentrail/v1/log_brief.schema.json",
            MigrationClassV1::HistoricalEvidence,
            IdentityDomainV1::Artifact,
        ),
        d(
            "evidentrail.result_status",
            MAX_WIRE_OBJECT_BYTES,
            "schemas/evidentrail/v1/result_status.schema.json",
            MigrationClassV1::HistoricalEvidence,
            IdentityDomainV1::ResultScoped,
        ),
    ]);
    #[cfg(feature = "bench")]
    registry.extend([
        d(
            "evidentrail.bench.annotation_manifest",
            MAX_WIRE_OBJECT_BYTES,
            "schemas/evidentrail/v1/bench_annotation_manifest.schema.json",
            MigrationClassV1::None,
            IdentityDomainV1::Artifact,
        ),
        d(
            "evidentrail.bench.case_manifest",
            MAX_WIRE_OBJECT_BYTES,
            "schemas/evidentrail/v1/bench_case_manifest.schema.json",
            MigrationClassV1::None,
            IdentityDomainV1::Artifact,
        ),
        d(
            "evidentrail.bench.hidden_evaluation_manifest",
            MAX_WIRE_OBJECT_BYTES,
            "schemas/evidentrail/v1/bench_hidden_evaluation_manifest.schema.json",
            MigrationClassV1::None,
            IdentityDomainV1::Artifact,
        ),
        d(
            "evidentrail.bench.run_manifest",
            MAX_WIRE_OBJECT_BYTES,
            "schemas/evidentrail/v1/bench_run_manifest.schema.json",
            MigrationClassV1::None,
            IdentityDomainV1::Artifact,
        ),
    ]);
    registry.sort_unstable_by_key(|entry| entry.name);
    registry
}

/// V1 is the first release. No synthetic V0 migration exists.
#[must_use]
pub const fn migration_registry_v1() -> &'static [(u16, u16)] {
    &[]
}
