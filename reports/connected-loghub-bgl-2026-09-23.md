# Connected retrieval on LogHub BGL sample (local, 2026-09-23)

The [LogHub BGL sample](https://github.com/logpai/loghub/blob/master/BGL/README.md)
contains real BlueGene/L system logs. Its first column labels alert versus
non-alert lines. The opt-in test downloads `BGL_2k.log` at upstream commit
`dd61d0952749ee7963bde24220d1be5ede023033` and verifies SHA-256
`2a819ea540909db682005c9cf948387a40729b5c2e9f19d430e29ce704825496`.
The source file is not redistributed here.

The test ingests all 2,000 original lines into an encrypted source corpus and
asks for failures reading the control-stream message prefix. Two `APPREAD`
alert lines at source positions 8 and 9 are the frozen required evidence.
At the same 4,096-byte raw-log budget, connected retrieval with a deterministic
first-advertised-ID selector returned the first alert as an exact source line.
Its group reports three occurrences; bounded expansion from that selected
line returned the adjacent second alert with its original bytes. A
12-newest-group baseline returned neither required line (0/2). The connected
candidate pool contained 47 groups and the selector emitted 16 exact source
lines. The other selected lines were not labeled as irrelevant, so this run
does not establish precision or useful-answer rate.

The first run produced 2,000 groups from 2,000 lines: a concrete compression
gap. After adding a narrowly recognized BGL preamble and normalizing numeric
network ports within fingerprints, the parser produced 1,374 groups while
preserving all original bytes. Grouping can hide a specific repeated line from
the compact pack; expansion is needed to inspect that line. This is a single
cherry-picked task on a 2,000-line sample, with no live model, provider
sync, downstream coding agent, or full alert-label evaluation. It supports
source-byte fidelity and candidate reachability for these two labeled lines;
it does not establish broad relevance accuracy. The alert labels mark log
categories, not a verified coding-agent fix or causal diagnosis.

Run `bash scripts/eval-loghub-bgl.sh` from the repository root. The script
fetches the pinned upstream sample into a temporary directory; the test
checks its hash before ingesting it.
