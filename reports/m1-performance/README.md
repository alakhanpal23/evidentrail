# M1 measurement status

Status: **harness implemented; local engineering study measured; production qualification pending**.

The checked-in code now provides:

- the frozen memory-baseline contract;
- lazy local-file, CloudWatch, and Kubernetes fixture families at 10K/100K/1M scales;
- balanced randomized throughput execution with five warmups/30 pairs and latency execution with ten warmups/200 pairs;
- paired BCa one-sided 95% bounds with 20,000 resamples and non-relaxable throughput, p95 latency, RSS, and random-access gates;
- storage-overhead reporting, semantic/public-artifact equality, exact authorized-basis reconciliation, outcome counters, and worst-slice identities; and
- JSON-serializable raw runs and suite reports.

No production hardware-performance claim is asserted here. The real memory and V2 durable product paths and macOS Keychain authority are bound. Qualification still fails closed until the executable has an Apple-provisioned data-protection Keychain entitlement and the signed binary runs the dedicated-host warm and clean-boot protocol. Synthetic statistical observations are used only to prove gate logic; they are not benchmark results.

The [August 30 local engineering study](LOCAL_ENGINEERING_STUDY_2026-08-30.md)
contains non-certifying measurements from a developer Mac. It found and drove
fixes for the >512-record compilation handoff, durable multi-batch frame
capacity, and multi-shard EventId ordering. The repository component completed
one million events, but the public full-product input remains capped at 100,000
records / 16 MiB and the large provider-shaped product cases honestly return
`needs_more`. The report records those limitations rather than promoting its
numbers to release claims.

The runbook and metric definitions are in [`docs/M1_PERFORMANCE_PROTOCOL.md`](../../docs/M1_PERFORMANCE_PROTOCOL.md).
