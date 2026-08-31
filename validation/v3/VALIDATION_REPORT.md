# Streaming Product V3 readiness validation

> Superseded again by the V4 checkpoint-packed `.v3p` implementation. The
> results below describe older layouts and remain only as fail-closed historical
> records. All performance, storage, and platform slices must be rerun; no prior
> pass is carried forward.

> Historical V2-adapter baseline. The native V3 rerun is recorded in
> [NATIVE_V3_VALIDATION.md](NATIVE_V3_VALIDATION.md) and
> [native-v3-study.json](native-v3-study.json). Do not treat the measurements
> below as the current architecture.

## Technical summary

**Overall assessment: Needs revision.** The V3 CLI must remain gated. Exact
streaming behavior and the synthetic 1M boundary corpus pass, but the current
durable backend is still the V2 frame adapter and the measured resource and
performance screens fail by wide margins.

At 1M records (92,536,266 source bytes), memory peaked at 2,304.9 MiB and
durable peaked at 2,577.7 MiB. Both exceed the 1 GiB hard ceiling. Durable
throughput was 0.147x memory, versus the required lower bound of 0.90, and
durable storage amplification was 7.23x, versus the 2.5x engineering target.

## Measured gates fail before statistical certification

| Scale | Memory elapsed | Durable elapsed | Durable/memory throughput | Memory RSS | Durable RSS | Durable storage/source | Durable expansion p95 |
|---|---:|---:|---:|---:|---:|---:|---:|
| 10K | 219.7 ms | 436.9 ms | 0.503 | 36.8 MiB | 43.3 MiB | 7.37x | 19.94 ms |
| 100K | 1.294 s | 4.112 s | 0.315 | 235.3 MiB | 291.5 MiB | 7.30x | 38.70 ms |
| 1M | 20.925 s | 141.979 s | 0.147 | 2,304.9 MiB | 2,577.7 MiB | 7.23x | 29.69 ms |

These are one paired full-product observation per scale, plus 10 expansion
warmups and 200 measured expansion reads per arm and scale. Because the point
measurements already fail the frozen thresholds materially, the expensive
30-pair throughput and 200-pair full-product latency certification was not
represented as complete or used to claim confidence intervals.

The 100K-to-1M durable expansion p95 ratio is 0.767 in this run, so the local
expansion-scaling screen passes. It is not a release certificate because the
host, authority, and sampling protocol are non-certifying.

## Durability tests validate V2 machinery, not the missing V3 format

Nine V2 repository contracts passed, including deterministic crash hooks,
exact retry, create-only publication, recovery, corruption rejection,
publication-generation rollback defense, and authority-first cleanup. Four V3
retained-store adapter contracts also passed.

Those passes do not satisfy the V3 page/checkpoint gate. The current durable
backend still stores each event through `DurableResultRepositoryV2`; it has no
independent V3 page header, packed page index, checkpoint file, authenticated
V3 format dispatcher, or V3-specific page/checkpoint fault boundaries.

## Corpus coverage passes locally but remains non-adjudicated

The existing two-test hermetic product corpus and seven governed executable
incident tests passed. A new resource-heavy 1M-record corpus also passed: exact
required evidence at record 0, record 500,000, and record 999,999 was retained
in the rendered brief.

The 1M fixture is synthetic and locally labeled. No independently adjudicated
public incident corpus was supplied or discovered in the repository, so no
broad real-world accuracy claim is justified.

## Method and definitions

- The real `compile_explicit_stream_v3` path consumed a generated `Read`
  stream, so the probe did not pre-materialize the source input.
- Peak RSS is the Linux cgroup `memory.peak` value for a fresh container with a
  7 GiB limit; it includes the small container/runtime baseline.
- Stored bytes are the complete durable repository tree before destruction.
- Throughput ratio is durable records/second divided by memory records/second.
- Expansion p95 is the nearest-rank p95 after 10 warmups and 200 reads of the
  same middle event.
- The authority was `ProcessKeyAuthorityV2`, so all results are engineering
  evidence rather than signed-Keychain qualification.

## Required next work

1. Replace the V2 adapter with the independent encrypted packed-page and
   checkpoint repository before rerunning durability or storage gates.
2. Remove the full `EventLedger`/store duplication or introduce a packed
   analysis representation; 1M memory is more than twice the hard ceiling.
3. Re-run the complete randomized 5/30 throughput and 10/200 latency protocols
   with 20,000-resample paired BCa intervals only after point screens pass.
4. Fault-inject every new V3 page, checkpoint, nonce, commit, seal, publish,
   recovery, rollback, and destruction boundary.
5. Provide an independently adjudicated public incident corpus and its frozen
   annotations before claiming real-world diagnostic accuracy.

## Further questions

- Which independently adjudicated corpus is approved for release gating?
- Which dedicated signed macOS host will own final Keychain and APFS
  certification?
