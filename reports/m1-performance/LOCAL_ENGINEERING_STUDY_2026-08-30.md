# Local performance engineering study — 2026-08-30

Status: **measured engineering evidence; not production qualification**.

This study exercised release-built Evidentrail code on a developer Mac to find real
scale failures and establish local performance ranges. It is not admissible M1
qualification because the host was not designated as the dedicated reference
host, the durable product used `ProcessKeyAuthorityV2`, and no clean boot was
performed.

## Environment and method

- Host: Apple `Mac17,8`, 24 GiB RAM, APFS, macOS build `25F71`.
- Rust toolchain: 1.88.0, release profile.
- Host admission: `dedicated_reference_host=false`.
- Durable authority: `process_conformance_only`.
- Warm throughput samples: five warmups followed by 30 alternating-order
  memory/durable pairs.
- Rendered 512-record latency samples: ten warmups followed by 200 pairs.
- Confidence intervals: paired BCa 95% intervals with 20,000 resamples and a
  fixed `20260830` resampling seed.
- Peak RSS: direct process `/usr/bin/time -l`; child-tree RSS is not claimed.
- Real input: a private frozen copy of `/var/log/install.log`, 7,331 records and
  910,945 bytes, SHA-256
  `37d3c378218b659ba71fa13171ddf83ee92a388410b02deebf79b103dd441644`.
  Raw bytes were neither printed nor committed.

The repeatable local probe is
`crates/evidentrail-bench-harness/examples/local_product_performance.rs`. Its JSON
marks every observation `qualification_eligible=false`; repository-only runs
also mark `component_only=true`.

## Full-product observations

| Corpus | Outcome | Memory median | Durable median | Durable/memory throughput, paired BCa 95% | Median durable overhead | Peak RSS p95, memory / durable |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Generated, 512 records / 45,730 bytes | rendered, 9 aliases | 119,070 records/s | 15,344 records/s | 0.122–0.130 | 29.0 ms | 10.4 / 11.7 MiB |
| Private real-log slice, 512 records / 58,125 bytes | rendered, 15 aliases | 108,100 records/s | 15,352 records/s | 0.138–0.143 | 28.6 ms | 10.8 / 12.0 MiB |
| Private real log, 7,331 records / 910,945 bytes | honest `needs_more` | 116,905 records/s | 37,857 records/s | 0.293–0.332 | 130.0 ms | 34.1 / 44.5 MiB |
| Generated, 10,000 records / 905,306 bytes | honest `needs_more` | 122,717 records/s | 38,642 records/s | 0.307–0.316 | 177.8 ms | 44.1 / 54.6 MiB |
| Generated, 100,000 records / 9,153,344 bytes | honest `needs_more` | 108,128 records/s | 27,061 records/s | 0.245–0.264 | 2,760.0 ms | 357.4 / 415.8 MiB |
| Generated, 1,000,000 records | rejected before product execution | not measured | not measured | not measured | not measured | not measured |

All completed memory/durable pairs had identical public-artifact and
authorized-basis commitments. Every measured rendered alias expansion returned
source-exact bytes. On the generated rendered corpus, memory/durable expansion
p95 was 1.21 microseconds / 0.935 milliseconds; on the real-log slice it was
1.79 microseconds / 0.936 milliseconds.

The 10K, 100K, and full real-log inputs exceed the compiler's bounded 4,096
primary-block analysis universe for this provider shape, so `needs_more` is the
honest product result. These observations measure acquisition, deterministic
analysis, and—on the durable arm—encryption, synchronization, authenticated
index construction, and authority-first cleanup. They do **not** demonstrate
diagnostic accuracy or retained expansion at those scales.

The full product cannot accept one million stdin records: the public boundary
is 100,000 records and 16 MiB. The generated one-million-record input was
rejected as `EVIDENTRAIL_CLI_INPUT_TOO_LARGE`. Consequently, there is no honest 1M
full-product performance result.

## Durable repository component observations

These single lifecycle observations isolate the repository's complete
begin/batch/data/seal/publish path and 200 exact indexed reads. They are not a
memory/durable product comparison.

| Records | Source | Lifecycle | Throughput | Peak RSS | Stored | Stored/source | Exact expansion p95 |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10,000 | 767,750 B | 0.176 s | 56,976 records/s | 24.9 MiB | 6.53 MB | 8.51× | 10.10 ms |
| 100,000 | 7,777,780 B | 2.917 s | 34,283 records/s | 112.0 MiB | 65.40 MB | 8.41× | 29.16 ms |
| 1,000,000 | 78,778,542 B | 139.421 s | 7,173 records/s | 858.6 MiB | 654.95 MB | 8.31× | 28.76 ms |

The 100K-to-1M p95 expansion-latency ratio is 0.986, satisfying the intended
near-constant lookup check over that 10× interval in this local component run.
The 10K result uses one index shard and is materially faster; 10K-to-100K is
2.89×. The 1M memory and storage figures are therefore repository-component
evidence only, not full-product claims.

## Defects found and fixed

The real scale runs exposed three defects that small conformance fixtures did
not reach:

1. More than 512 passthrough evidence events caused a generic product failure
   instead of entering compilation. Oversized passthrough now returns the typed
   `evidence_packet_limit_exceeded` compilation handoff.
2. Durable product batches filled the repository's event-only frame capacity
   and then added one semantic receipt. Product batches now reserve that frame,
   with a multi-batch regression test.
3. Multi-shard event indexes were chunked before global EventId ordering,
   causing authenticated directory decode failure above 16,384 events. Entries
   are now globally sorted before sharding, with a 16,385-event regression test.

## Gate interpretation

- Correctness parity and source-exact expansion passed for every rendered pair.
- Local durable throughput is far below the 0.90 ratio target at every measured
  full-product size.
- The 10K RSS ratio is 1.239 and the 100K ratio is 1.163, both above the 1.15
  target on this host.
- The repository completed one million events, but peak RSS was 858.6 MiB and
  stored bytes were 654.95 MB; no approved hard cap has been certified here.
- Full-product 1M, diagnostic quality at the large `needs_more` sizes, signed
  Keychain overhead, and true cold-boot performance remain unproven.

Fresh processes were used, but the operating-system cache remained warm. A
true cold observation requires one staged arm per actual clean boot and was not
attempted because rebooting the user's machine is disruptive and this host is
not admitted for qualification.
