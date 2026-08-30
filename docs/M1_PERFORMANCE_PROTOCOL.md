# M1 performance and accuracy protocol

## Scope

`evidentrail-bench-harness::performance_trials` is the Terminal 4 measurement boundary for M1. It does not choose candidates, compile a Log Brief, or implement repository behavior. A caller injects the memory-only and durable product arms; the harness supplies the exact fixture identity, preregistered arm order, timing phase, scale, provider shape, and cache state.

The protocol measures the product episode from authorized-basis ingestion through semantic product completion. Fixture construction, executable startup, and report serialization are outside the timed interval. Both arms must include equivalent work. The durable interval includes every required file and directory sync and external-authority transition through `PUBLISHED`.

## Frozen baseline

Before a durable comparison, execute the memory-only product against the exact fixture and build context and recompute:

- the commitment to public status, Log Brief, references, acquisition/transformation/presentation receipts, and expansion handles;
- the independent authorized-basis commitment;
- protected-block, required-evidence, citation, diagnosis, fix, and honest-abstention outcomes; and
- all reconciliation-failure counts.

`freeze_memory_baseline_v1` rejects a baseline with any reconciliation or accuracy failure. Its commitment binds the generative fixture identity, build context, and every semantic counter. `M1PairedRunConfigV1::validate` detects a changed fixture, corrupted baseline commitment, fewer than five warmups, fewer than 30 measured observations, or fewer than 2,000 bootstrap resamples.

The callback must compute semantic commitments from the bytes returned by the actual product arm. A label or mode name is not evidence of equality. The runner rejects either arm unless its semantic observation exactly equals the frozen memory baseline.

## Trial matrix

The complete matrix is 18 slices:

| Dimension | Values |
| --- | --- |
| Provider shape | local file, CloudWatch, Kubernetes |
| Scale | 10K, 100K, 1M records |
| Cache state | cold, warm |

Each throughput slice runs at least five warmups followed by 30 measured pairs. Each latency slice runs at least ten warmups followed by 200 measured pairs. Arm order is balanced and deterministically shuffled from the recorded randomization seed. Both arms in a pair receive the same generative fixture commitment and record count.

Cold qualification means one arm per clean dedicated-host boot. The byte-identical fixture copy is staged and synced before reboot; its commitment is rechecked after boot. The paired arm runs only after another reboot, and boot commitments cannot be reused within the run. A fresh process or repository root without a reboot is a reduced smoke test, not a cold qualification observation.

The checked-in `stage-cold-boot-arm-v2.sh` creates a private, create-only staged copy and state record. After the operator reboots, `verify-cold-boot-arm-v2.sh` rejects an unchanged boot identity or fixture digest before emitting the arm receipt. Neither script initiates a reboot.

Warm means that executable code and ordinary process infrastructure are warm, but each timed create uses a fresh ResultId and performs the full requested lifecycle. Warm expansion may reuse the already published result. A warm create must not reuse a prior result's semantic product.

## Provider-shaped fixtures

`ProviderFixtureStreamV1` generates records lazily, including at 1M scale. The generator is versioned by its commitment domain and binds provider, scale, and seed. Every record contains separate acquisition ordinal, provider-native identity, source member, canonical order key, payload, and terminator.

The corpus includes invalid UTF-8, NUL, CRLF, blank records, unterminated records, and duplicate payloads with distinct native identities. Provider timestamps reverse within synthetic 128-record pages so acquisition order cannot accidentally stand in for canonical order. Kubernetes records cross restart-count boundaries at large scales.

Nominal local-file trials report `Complete`. Nominal CloudWatch and Kubernetes trials must report `Unknown`; the harness rejects a `Complete` claim because ordinary provider traversal does not prove an immutable snapshot. Partial/cap/failure conformance remains in the source-adapter test suites rather than the performance hot path.

## Observations

Each arm returns:

- episode elapsed nanoseconds, records, and authorized source bytes;
- direct process peak RSS bytes;
- total repository bytes after publication (`0` for memory-only);
- the semantic observation described above; and
- optional exact-expansion latency, total result records, returned authenticated frame count, and returned plaintext bytes.

The durable and memory observations must agree on authorized source bytes and expansion shape. RSS must be measured with the same observer semantics for both arms. Storage overhead is reported as durable repository bytes divided by authorized source bytes; it does not alter selection or any public artifact.

## Statistical gates

Production qualification uses a paired bias-corrected and accelerated (BCa) bootstrap with 20,000 resamples and recorded seeds. Throughput uses a one-sided lower 95% non-inferiority bound; latency and RSS use one-sided upper 95% bounds. Ordinary CI may use the smaller deterministic V1 smoke protocol, but its output is never qualification evidence.

- At 100K and 1M, the lower confidence bound for durable/memory throughput must be at least `0.90`.
- At 100K and 1M, the upper confidence bound for durable p95 latency regression must be at most `10%`.
- At 10K, the upper confidence bound for absolute durable p95 overhead must be at most `20 ms`.
- The upper confidence bound for paired RSS regression must be at most `15%`, and every durable observation must stay under the configured hard cap.
- Expansion comparisons require identical returned frame count and bytes at result sizes separated by at least 10x. The upper confidence bound for the larger/smaller p95 ratio must be at most `1.10`.

An incomplete provider/scale/cache matrix, a missing expansion comparison, an underpowered slice, a noisy interval that crosses its threshold, any non-nominal/unknown thermal state, detected frequency throttling, a semantic mismatch, or an exactness failure makes the suite fail. `ProcessKeyAuthorityV2` is conformance-only and is rejected by the environment gate; production qualification requires the external trusted-root authority. Durability and exactness thresholds are not adjustable by this benchmark.

## Report production

Serialize `M1PerformanceSuiteReportV1` with `serde_json` only after all raw `M1PairedRunV1` observations are retained. Keep the raw run artifact, executable/build commitments, host and filesystem description, RSS-observer identity, compiler/renderer/tokenizer/policy commitments, cold-cache policy, and repository byte-accounting method beside the summary.

Benchmark results are self-asserted reproducibility evidence, not independent attestation. A release claim requires review of the raw observations and environment, not only `overall: "pass"`.
