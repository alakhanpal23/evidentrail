# Pinned paired-reader smoke

The local open-engine checkout is accepted only when `/opt/evidentrail-bench/legacy-drain`
is clean and its exact HEAD is
`5a84fb050e074b15474fdb264c9e97faaa66c9f5`. The longer spelling ending in
`...f5e` is not a Git object in that checkout.

Run the opt-in smoke from `/opt/evidentrail-bench/evidentrail`:

```sh
cargo test -p evidentrail-bench-harness --test pinned_paired_reader_smoke pinned_actual_constrained_pair_runs_deterministic_reader -- --ignored --exact --nocapture --test-threads=1
```

The test uses only the committed synthetic constrained case, the actual pinned
`legacy-drain` executable, the workspace's real first-party product helper, and
the deterministic fixture reader. It checks the external checkout before and
after execution. It records producer/normalizer receipts, separate reader input
and message artifacts, identical reader configuration and caps, two-trial
answer repeatability, governed dimensions, wall time, and direct-process peak
RSS.

Drain pattern membership is never promoted to source-exact citations. The
smoke makes no scalar, winner, fairness, comparative quality, hosted Evidentrail, or
hosted-reader claim and performs no network request.

## Observed checkpoint — 2026-08-24

The command above completed successfully with the checkout clean before and
after. Self-asserted local reproducibility identities from that run were:

- pinned Drain executable SHA-256:
  `40a83db59cf20246381363eddb2d27c56a386d9e4dcf32ac8115f55b9445d220`
- public case:
  `72c50a900d1b3cc33258914517f63059cf485e630698c05feef61403bc1073cc`
- first-party producer receipt:
  `0ad894f894cd9b80f8a3e04c19d92d52f6732f2760e221b033900a8653c072ac`
- Drain full-membership normalization receipt:
  `693fb7302511b7e8fdf516e4ff79054a5328e0f485a996e53d548eab1c3507a6`
- finalized first-party/Drain product receipt:
  `48bcb0311b10d9d025fe1fcd69fe13814cd7e7030551fded84fe68cb8a74f9ec`
- paired reader input:
  `dffbb1532476de4b5a1b582b58bedac649dd20f2c0f610b513d2c5b045af8125`
- first-party / Drain reader-method bindings:
  `f97d415625b2eb376b95f61622f6371708be5f78ffea6d4494d24d5b429f0279` /
  `0fbc3769f7d704d6c9333a622f8b7e5f00023f18b48f3c3dfb09c12104d928a7`
- hosted model-message template:
  `f9557a9d9aa679d1c10d5a24f94b08ba98c8f756d4b24c47fe1d9bf0399ca3ff`
- first-party / Drain model-message artifacts:
  `aa1800e77140f5a18a24c7d9f35dda2bcea9c63f6c5ae45fdc8a4fc113f232d0` /
  `c4fe1e6e4b5a2df3cf18dc49ec86dec2c88d588bddc9a34c59b1ee0cab90b743`
- deterministic reader configuration:
  `377cfcde3cd334dddaec814bd0019c9fef77d6f77ef5b44853bada9474a551ad`
- two-trial paired repeatability receipt:
  `c24c285b743e002bb8da085797c2210a4e314a88d485ef163c88ba73e2fe10f8`
- governed paired receipt:
  `ba63ec05d946abb49487e6c43492534cb2d957a85c273164d9d94fd5067e5f05`

Both deterministic-reader answers had artifact digest
`392ecde9480b94ac902af2eee2e5b1db979a0376f832488d987e1f0911e73930`.
The first-party arm observed 29,018 prompt-byte tokens, 308 answer-byte tokens,
448,272,042 wall nanoseconds, and 1,982,464 bytes direct-process peak RSS. The
Drain arm observed 360,361 prompt-byte tokens, 308 answer-byte tokens,
448,614,958 wall nanoseconds, and 2,310,144 bytes direct-process peak RSS.
These timing and RSS observations are run-specific, self-asserted local facts,
not independent attestation, child-tree RSS, cold-start claims, or product
performance conclusions.

The governed fixture-reader dimensions recorded two valid and zero invalid
first-party citations, versus zero valid and two invalid Drain citations. That
is a contract check reflecting Drain's deliberately empty source-exact
citation catalog, not a comparative product-quality result.
