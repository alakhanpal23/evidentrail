# Native Streaming Product V3 validation

> Historical, superseded observation: these measurements used the experimental
> one-object-per-page layout. The V4 checkpoint-packed `.v3p` revision must be
> measured again before any performance gate can pass. This file is retained as
> raw engineering history and is not evidence about the current layout.

**Date:** August 30, 2026
**Status:** Release blocked

The native packed architecture passes correctness, disk-only restart, header
AAD, V3 fault-injection, multi-lane atomic partition, 1M RSS, expansion scaling,
and 1M storage-amplification point gates. It fails the throughput and 10K
overhead screens, so the preregistered expensive paired phase was not run.

| Scale | Memory | Durable | Throughput ratio | Memory RSS | Durable RSS | Storage/source | Durable expansion p95 |
|---|---:|---:|---:|---:|---:|---:|---:|
| 10K | 0.213 s | 0.419 s | 0.509 | 45.2 MiB | 47.8 MiB | 2.419x | 3.855 ms |
| 100K | 1.057 s | 2.236 s | 0.473 | 75.1 MiB | 111.7 MiB | 2.401x | 3.868 ms |
| 1M | 9.447 s | 26.606 s | 0.355 | 412.8 MiB | 383.7 MiB | 2.386x | 3.946 ms |

These are randomized-order, release-mode point observations on the local macOS
host using the process conformance authority. They are engineering evidence,
not signed-Keychain or cold-boot certification. The 1M durable RSS is below the
512 MiB target and 1 GiB ceiling; durable RSS does not regress versus memory;
storage is below 2.5x; and the 100K-to-1M expansion p95 scaling ratio is 1.020.

The blockers are concrete:

- 100K and 1M durable/memory throughput are below the required 0.90 lower bound.
- 10K durable overhead is about 206 ms, above the 20 ms ceiling.
- No independently adjudicated external corpus is present, so accuracy
  certification is unavailable.
- Final Keychain/APFS cold-boot qualification needs an approved signed binary
  and provisioned rebootable Mac.

Raw observations, including all 200 expansion timings per arm, are in
[`native-v3-study.json`](native-v3-study.json). The runner at
[`run_frozen_paired_study.py`](run_frozen_paired_study.py) performs five
warmups and 30 paired observations with 20,000-resample paired BCa intervals
only after all point screens pass.
