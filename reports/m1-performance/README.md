# M1 measurement status

Status: **harness implemented; production measurements pending integrated M1 arms**.

The checked-in code now provides:

- the frozen memory-baseline contract;
- lazy local-file, CloudWatch, and Kubernetes fixture families at 10K/100K/1M scales;
- balanced randomized throughput execution with five warmups/30 pairs and latency execution with ten warmups/200 pairs;
- paired BCa one-sided 95% bounds with 20,000 resamples and non-relaxable throughput, p95 latency, RSS, and random-access gates;
- storage-overhead reporting, semantic/public-artifact equality, exact authorized-basis reconciliation, outcome counters, and worst-slice identities; and
- JSON-serializable raw runs and suite reports.

No hardware performance number is asserted here. The real memory and V2 durable product paths are bound; the latter can run reduced conformance smoke tests. V2 storage currently exposes only `ProcessKeyAuthorityV2`, so the qualification availability check fails closed. A Keychain-backed external authority must land before reference-host measurements are meaningful. Synthetic statistical observations are used only to prove gate logic; they are not benchmark results.

The runbook and metric definitions are in [`docs/M1_PERFORMANCE_PROTOCOL.md`](../../docs/M1_PERFORMANCE_PROTOCOL.md).
