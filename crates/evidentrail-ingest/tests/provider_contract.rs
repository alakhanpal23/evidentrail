use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use evidentrail_core::{DeterministicPolicy, LedgerBuilder, PolicyAuthorization};
use evidentrail_ingest::{
    CLOUDWATCH_ADAPTER_KIND_V1, CLOUDWATCH_ADAPTER_VERSION_V1, CancellationToken,
    CloudWatchAdapterV1, CloudWatchCapsV1, CloudWatchEventV1, CloudWatchFilterRequestV1,
    CloudWatchPageV1, CloudWatchPlanV1, CloudWatchTransportErrorV1, CloudWatchTransportV1,
    ExecutionContext, KUBERNETES_ADAPTER_KIND_V1, KUBERNETES_ADAPTER_VERSION_V1,
    KubernetesAdapterV1, KubernetesCapsV1, KubernetesContainerInstanceKindV1,
    KubernetesContainerInstanceV1, KubernetesContainerObservationV1, KubernetesLogRecordV1,
    KubernetesLogRequestV1, KubernetesLogResponseV1, KubernetesLogStreamV1, KubernetesPlanV1,
    KubernetesTransportErrorV1, KubernetesTransportV1, SingleEnvelopeSourceAdapterV1,
    SourceAdapter,
};
use evidentrail_schema::{
    AdapterIdentity, AdapterOutcome, FetchCompleteness, FetchIdentity, FetchPartialReason,
    FetchUnknownReason, PlanDigest, PlanId, RawEnvelopeV1, RetrievalId, SourceIdentityDigest,
};

#[derive(Clone, Copy)]
struct SourceExact;

impl DeterministicPolicy for SourceExact {
    fn authorize(&self, _envelope: &RawEnvelopeV1) -> PolicyAuthorization {
        PolicyAuthorization::SourceExact
    }
}

fn execution_context(kind: &str, version: &str, seed: u8) -> ExecutionContext {
    ExecutionContext::new(
        FetchIdentity::new(
            RetrievalId::from_bytes([seed; 32]),
            PlanId::from_bytes([seed.wrapping_add(1); 32]),
            PlanDigest::from_bytes([seed.wrapping_add(2); 32]),
            AdapterIdentity::new(kind, version).unwrap(),
        ),
        SourceIdentityDigest::from_bytes([seed.wrapping_add(3); 32]),
    )
}

fn cloudwatch_plan(caps: CloudWatchCapsV1) -> CloudWatchPlanV1 {
    CloudWatchPlanV1::new(
        b"ACCOUNT_CANARY".to_vec(),
        b"REGION_CANARY".to_vec(),
        b"GROUP_CANARY".to_vec(),
        [b"STREAM_CANARY".to_vec()],
        Some(10),
        Some(20),
        Some(b"FILTER_CANARY".to_vec()),
        caps,
    )
    .unwrap()
}

fn cloudwatch_event(id: &[u8], timestamp: i64, message: &[u8]) -> CloudWatchEventV1 {
    CloudWatchEventV1 {
        log_stream: b"STREAM_CANARY".to_vec(),
        event_id: id.to_vec(),
        event_timestamp_millis: timestamp,
        ingestion_timestamp_millis: timestamp + 1,
        message: message.to_vec(),
    }
}

struct ScriptedCloudWatch {
    pages: Mutex<VecDeque<Result<CloudWatchPageV1, CloudWatchTransportErrorV1>>>,
    tokens: Mutex<Vec<Option<Vec<u8>>>>,
}

impl ScriptedCloudWatch {
    fn new(
        pages: impl IntoIterator<Item = Result<CloudWatchPageV1, CloudWatchTransportErrorV1>>,
    ) -> Self {
        Self {
            pages: Mutex::new(pages.into_iter().collect()),
            tokens: Mutex::new(Vec::new()),
        }
    }
}

impl CloudWatchTransportV1 for ScriptedCloudWatch {
    fn filter_log_events(
        &self,
        request: &CloudWatchFilterRequestV1,
    ) -> Result<CloudWatchPageV1, CloudWatchTransportErrorV1> {
        assert!(!request.plan().account().is_empty());
        assert!(!request.plan().region().is_empty());
        assert!(!request.plan().log_group().is_empty());
        assert!(!request.plan().log_streams().is_empty());
        assert!(request.plan().caps().max_pages() > 0);
        self.tokens
            .lock()
            .unwrap()
            .push(request.next_token().map(<[u8]>::to_vec));
        self.pages.lock().unwrap().pop_front().unwrap()
    }
}

#[test]
fn cloudwatch_continues_empty_pages_orders_canonically_and_never_claims_complete() {
    let transport = ScriptedCloudWatch::new([
        Ok(CloudWatchPageV1::new(
            Vec::new(),
            Some(b"TOKEN_CANARY".to_vec()),
        )),
        Ok(CloudWatchPageV1::new(
            vec![
                cloudwatch_event(b"event-b", 12, b"second"),
                cloudwatch_event(b"event-a", 11, b"first"),
            ],
            None,
        )),
    ]);
    let adapter = SingleEnvelopeSourceAdapterV1::new(CloudWatchAdapterV1::new(
        cloudwatch_plan(CloudWatchCapsV1::new(100, 10_000, 10, 1_000).unwrap()),
        transport,
    ));
    let context = execution_context(
        CLOUDWATCH_ADAPTER_KIND_V1,
        CLOUDWATCH_ADAPTER_VERSION_V1,
        10,
    );
    let mut ledger = LedgerBuilder::new(
        context.fetch_identity().clone(),
        context.source_identity_digest(),
        SourceExact,
    );
    let completion = adapter.execute(&context, &mut ledger).unwrap();
    let ledger = ledger.seal(completion).unwrap();

    assert_eq!(ledger.events().len(), 2);
    assert_eq!(ledger.events()[0].raw(), b"first");
    assert_eq!(ledger.events()[1].raw(), b"second");
    assert_eq!(ledger.fetch_completion().page_counts().attempted(), 2);
    assert_eq!(ledger.fetch_completion().page_counts().completed(), 2);
    assert_eq!(
        ledger.fetch_completion().completeness(),
        &FetchCompleteness::unknown(FetchUnknownReason::EventuallyConsistentWindow)
    );
}

#[test]
fn cloudwatch_deduplicates_only_identical_native_delivery_and_conflicts_on_changed_bytes() {
    let duplicate = cloudwatch_event(b"same-id", 11, b"same-bytes");
    let transport = ScriptedCloudWatch::new([
        Ok(CloudWatchPageV1::new(
            vec![duplicate.clone()],
            Some(b"next".to_vec()),
        )),
        Ok(CloudWatchPageV1::new(vec![duplicate], None)),
    ]);
    let adapter = SingleEnvelopeSourceAdapterV1::new(CloudWatchAdapterV1::new(
        cloudwatch_plan(CloudWatchCapsV1::new(100, 10_000, 10, 1_000).unwrap()),
        transport,
    ));
    let context = execution_context(
        CLOUDWATCH_ADAPTER_KIND_V1,
        CLOUDWATCH_ADAPTER_VERSION_V1,
        11,
    );
    let mut ledger = LedgerBuilder::new(
        context.fetch_identity().clone(),
        context.source_identity_digest(),
        SourceExact,
    );
    let completion = adapter.execute(&context, &mut ledger).unwrap();
    let ledger = ledger.seal(completion).unwrap();
    assert_eq!(ledger.events().len(), 1);

    let transport = ScriptedCloudWatch::new([Ok(CloudWatchPageV1::new(
        vec![
            cloudwatch_event(b"same-id", 11, b"first"),
            cloudwatch_event(b"same-id", 11, b"changed"),
        ],
        None,
    ))]);
    let adapter = SingleEnvelopeSourceAdapterV1::new(CloudWatchAdapterV1::new(
        cloudwatch_plan(CloudWatchCapsV1::new(100, 10_000, 10, 1_000).unwrap()),
        transport,
    ));
    let context = execution_context(
        CLOUDWATCH_ADAPTER_KIND_V1,
        CLOUDWATCH_ADAPTER_VERSION_V1,
        12,
    );
    let mut ledger = LedgerBuilder::new(
        context.fetch_identity().clone(),
        context.source_identity_digest(),
        SourceExact,
    );
    let completion = adapter.execute(&context, &mut ledger).unwrap();
    assert_eq!(completion.adapter_outcome(), AdapterOutcome::AdapterStopped);
    let FetchCompleteness::Partial { reasons, .. } = completion.completeness() else {
        panic!("identity conflict must be partial")
    };
    assert!(matches!(
        reasons.first(),
        FetchPartialReason::OtherVersioned { version: 1, .. }
    ));
}

#[test]
fn cloudwatch_repeated_tokens_caps_permissions_and_cancellation_are_partial() {
    let cases = [
        ScriptedCloudWatch::new([
            Ok(CloudWatchPageV1::new(Vec::new(), Some(b"repeat".to_vec()))),
            Ok(CloudWatchPageV1::new(Vec::new(), Some(b"repeat".to_vec()))),
        ]),
        ScriptedCloudWatch::new([Err(CloudWatchTransportErrorV1::PermissionDenied)]),
    ];
    for (offset, transport) in cases.into_iter().enumerate() {
        let adapter = SingleEnvelopeSourceAdapterV1::new(CloudWatchAdapterV1::new(
            cloudwatch_plan(CloudWatchCapsV1::new(100, 10_000, 10, 1_000).unwrap()),
            transport,
        ));
        let context = execution_context(
            CLOUDWATCH_ADAPTER_KIND_V1,
            CLOUDWATCH_ADAPTER_VERSION_V1,
            20 + offset as u8,
        );
        let mut ledger = LedgerBuilder::new(
            context.fetch_identity().clone(),
            context.source_identity_digest(),
            SourceExact,
        );
        let completion = adapter.execute(&context, &mut ledger).unwrap();
        assert!(matches!(
            completion.completeness(),
            FetchCompleteness::Partial { .. }
        ));
    }

    let transport = ScriptedCloudWatch::new([Ok(CloudWatchPageV1::new(
        vec![
            cloudwatch_event(b"one", 1, b"1"),
            cloudwatch_event(b"two", 2, b"2"),
        ],
        None,
    ))]);
    let adapter = SingleEnvelopeSourceAdapterV1::new(CloudWatchAdapterV1::new(
        cloudwatch_plan(CloudWatchCapsV1::new(1, 10_000, 10, 1_000).unwrap()),
        transport,
    ));
    let context = execution_context(
        CLOUDWATCH_ADAPTER_KIND_V1,
        CLOUDWATCH_ADAPTER_VERSION_V1,
        23,
    );
    let mut ledger = LedgerBuilder::new(
        context.fetch_identity().clone(),
        context.source_identity_digest(),
        SourceExact,
    );
    let completion = adapter.execute(&context, &mut ledger).unwrap();
    assert!(matches!(
        completion.completeness(),
        FetchCompleteness::Partial { .. }
    ));

    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let transport = ScriptedCloudWatch::new([]);
    let adapter = SingleEnvelopeSourceAdapterV1::new(CloudWatchAdapterV1::new(
        cloudwatch_plan(CloudWatchCapsV1::new(1, 10_000, 10, 1_000).unwrap()),
        transport,
    ));
    let context = execution_context(
        CLOUDWATCH_ADAPTER_KIND_V1,
        CLOUDWATCH_ADAPTER_VERSION_V1,
        24,
    );
    let mut ledger = LedgerBuilder::new(
        context.fetch_identity().clone(),
        context.source_identity_digest(),
        SourceExact,
    );
    let completion = adapter
        .execute_with_cancellation(&context, &mut ledger, &cancellation)
        .unwrap();
    assert_eq!(completion.adapter_outcome(), AdapterOutcome::Cancelled);
}

fn kube_member(
    instance: KubernetesContainerInstanceKindV1,
    restart: u32,
) -> KubernetesContainerInstanceV1 {
    KubernetesContainerInstanceV1::new(
        b"CLUSTER_CANARY".to_vec(),
        b"NAMESPACE_CANARY".to_vec(),
        b"POD_UID_CANARY".to_vec(),
        b"CONTAINER_CANARY".to_vec(),
        format!("CONTAINER_ID_{restart}").into_bytes(),
        restart,
        instance,
    )
    .unwrap()
}

struct ScriptedKubernetes {
    responses: Mutex<VecDeque<Result<KubernetesLogResponseV1, KubernetesTransportErrorV1>>>,
    observations:
        Mutex<VecDeque<Result<KubernetesContainerObservationV1, KubernetesTransportErrorV1>>>,
    requests: Mutex<Vec<KubernetesLogRequestV1>>,
}

impl KubernetesTransportV1 for ScriptedKubernetes {
    fn read_logs(
        &self,
        member: &KubernetesContainerInstanceV1,
        request: KubernetesLogRequestV1,
    ) -> Result<KubernetesLogResponseV1, KubernetesTransportErrorV1> {
        assert!(!member.cluster_identity().is_empty());
        assert!(!member.namespace().is_empty());
        assert!(!member.pod_uid().is_empty());
        assert!(!member.container().is_empty());
        assert!(!member.container_id().is_empty());
        assert!(request.timestamps());
        assert!(!request.insecure_skip_tls_verify_backend());
        self.requests.lock().unwrap().push(request);
        self.responses.lock().unwrap().pop_front().unwrap()
    }

    fn revalidate(
        &self,
        _member: &KubernetesContainerInstanceV1,
    ) -> Result<KubernetesContainerObservationV1, KubernetesTransportErrorV1> {
        self.observations.lock().unwrap().pop_front().unwrap()
    }
}

fn kube_record(timestamp: i128, payload: &[u8]) -> KubernetesLogRecordV1 {
    KubernetesLogRecordV1 {
        stream: KubernetesLogStreamV1::Stdout,
        provider_timestamp: Some(timestamp.to_string().into_bytes()),
        parsed_timestamp_nanos: Some(timestamp),
        payload: payload.to_vec(),
        terminator: b"\n".to_vec(),
    }
}

fn observation(
    member: &KubernetesContainerInstanceV1,
    restart: u32,
) -> KubernetesContainerObservationV1 {
    let _ = member;
    KubernetesContainerObservationV1 {
        pod_uid: b"POD_UID_CANARY".to_vec(),
        container_id: format!("CONTAINER_ID_{restart}").into_bytes(),
        restart_count: restart,
    }
}

#[test]
fn kubernetes_freezes_current_and_previous_orders_records_and_remains_unknown() {
    let previous = kube_member(KubernetesContainerInstanceKindV1::Previous, 0);
    let current = kube_member(KubernetesContainerInstanceKindV1::Current, 1);
    let transport = ScriptedKubernetes {
        responses: Mutex::new(VecDeque::from([
            Ok(KubernetesLogResponseV1::new(
                vec![kube_record(20, b"later")],
                false,
                false,
                false,
                false,
            )),
            Ok(KubernetesLogResponseV1::new(
                vec![kube_record(10, b"earlier")],
                false,
                false,
                false,
                false,
            )),
        ])),
        observations: Mutex::new(VecDeque::from([
            Ok(observation(&previous, 0)),
            Ok(observation(&current, 1)),
        ])),
        requests: Mutex::new(Vec::new()),
    };
    let plan = KubernetesPlanV1::new(
        [previous, current],
        KubernetesCapsV1::new(100, 10_000, 10, 1_000).unwrap(),
    )
    .unwrap();
    let adapter = SingleEnvelopeSourceAdapterV1::new(KubernetesAdapterV1::new(plan, transport));
    let context = execution_context(
        KUBERNETES_ADAPTER_KIND_V1,
        KUBERNETES_ADAPTER_VERSION_V1,
        30,
    );
    let mut ledger = LedgerBuilder::new(
        context.fetch_identity().clone(),
        context.source_identity_digest(),
        SourceExact,
    );
    let completion = adapter.execute(&context, &mut ledger).unwrap();
    let ledger = ledger.seal(completion).unwrap();
    assert_eq!(ledger.events()[0].raw(), b"earlier\n");
    assert_eq!(ledger.events()[1].raw(), b"later\n");
    assert!(matches!(
        ledger.fetch_completion().completeness(),
        FetchCompleteness::Unknown {
            reason: FetchUnknownReason::ProviderHasNoCompletenessProof
        }
    ));
}

#[test]
fn kubernetes_restart_rotation_truncation_and_previous_access_are_partial() {
    let previous = kube_member(KubernetesContainerInstanceKindV1::Previous, 0);
    let current = kube_member(KubernetesContainerInstanceKindV1::Current, 1);
    let transport = ScriptedKubernetes {
        responses: Mutex::new(VecDeque::from([
            Err(KubernetesTransportErrorV1::PreviousInstanceUnavailable),
            Ok(KubernetesLogResponseV1::new(
                vec![kube_record(10, b"partial")],
                true,
                true,
                true,
                true,
            )),
        ])),
        observations: Mutex::new(VecDeque::from([
            Err(KubernetesTransportErrorV1::PreviousInstanceUnavailable),
            Ok(observation(&current, 2)),
        ])),
        requests: Mutex::new(Vec::new()),
    };
    let plan = KubernetesPlanV1::new(
        [previous, current],
        KubernetesCapsV1::new(100, 10_000, 10, 1_000).unwrap(),
    )
    .unwrap();
    let adapter = SingleEnvelopeSourceAdapterV1::new(KubernetesAdapterV1::new(plan, transport));
    let context = execution_context(
        KUBERNETES_ADAPTER_KIND_V1,
        KUBERNETES_ADAPTER_VERSION_V1,
        31,
    );
    let mut ledger = LedgerBuilder::new(
        context.fetch_identity().clone(),
        context.source_identity_digest(),
        SourceExact,
    );
    let completion = adapter.execute(&context, &mut ledger).unwrap();
    let FetchCompleteness::Partial { reasons, .. } = completion.completeness() else {
        panic!("known omissions must be partial")
    };
    let codes = reasons
        .iter()
        .map(FetchPartialReason::code)
        .collect::<Vec<_>>();
    assert!(codes.contains(&"source_disappeared"));
    assert!(codes.contains(&"provider_cap"));
    assert!(codes.contains(&"record_truncated"));
    assert!(codes.contains(&"source_changed"));
    assert!(codes.contains(&"provider_truncation"));
}

#[test]
fn provider_diagnostics_do_not_expose_scopes_tokens_or_payloads() {
    let plan = cloudwatch_plan(CloudWatchCapsV1::new(10, 100, 10, 100).unwrap());
    let request_debug = format!("{:?}", capture_request(plan));
    assert!(!request_debug.contains("ACCOUNT_CANARY"));
    assert!(!request_debug.contains("TOKEN_CANARY"));
    let event_debug = format!(
        "{:?}",
        cloudwatch_event(b"EVENT_CANARY", 1, b"PAYLOAD_CANARY")
    );
    assert!(!event_debug.contains("EVENT_CANARY"));
    assert!(!event_debug.contains("PAYLOAD_CANARY"));
}

fn capture_request(plan: CloudWatchPlanV1) -> CloudWatchFilterRequestV1 {
    struct Capture(Arc<Mutex<Option<CloudWatchFilterRequestV1>>>);
    impl CloudWatchTransportV1 for Capture {
        fn filter_log_events(
            &self,
            request: &CloudWatchFilterRequestV1,
        ) -> Result<CloudWatchPageV1, CloudWatchTransportErrorV1> {
            *self.0.lock().unwrap() = Some(request.clone());
            Ok(CloudWatchPageV1::new(Vec::new(), None))
        }
    }
    let observed = Arc::new(Mutex::new(None));
    let capture = Capture(Arc::clone(&observed));
    let adapter = SingleEnvelopeSourceAdapterV1::new(CloudWatchAdapterV1::new(plan, capture));
    let context = execution_context(
        CLOUDWATCH_ADAPTER_KIND_V1,
        CLOUDWATCH_ADAPTER_VERSION_V1,
        99,
    );
    let mut ledger = LedgerBuilder::new(
        context.fetch_identity().clone(),
        context.source_identity_digest(),
        SourceExact,
    );
    adapter.execute(&context, &mut ledger).unwrap();
    observed.lock().unwrap().take().unwrap()
}
