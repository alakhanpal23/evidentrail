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

## Twelve-category retrieval proxy

The same pinned 2,000-line corpus contains 143 alert-labeled lines in 12
categories. A second local probe queries each category with a phrase taken
from one of its messages. At a 4,096-byte raw-log budget and a 12-group
selection limit, both a first-advertised-ID selector and a deterministic
critical/error selector returned at least one exact original line from all
12 target categories. A 12-newest-group baseline covered 1 of 12. Across the
12 queries, 147 of 189 lines returned by the first-ID selector and 138 of 179
returned by the critical/error selector carried a different alert label.
Those are **off-label lines**, not proven irrelevant lines: different categories
can describe the same incident. One query reported a truncated candidate
pool. The probe confirms reachability for these message-derived tasks while
exposing substantial output noise under a small log budget. It does not
measure a model's choices, independent user tasks, answer usefulness, or
downstream fixes. The earlier severity baseline considered only `error` and
missed BGL's `FATAL` lines, which the parser classifies as `critical`; the
corrected baseline includes both roles.
The group-card excerpt cap increased from 160 to 256 characters after the
probe showed that the shorter excerpt hid the decisive suffixes of two BGL
alerts. Tests verify those suffixes are now visible to a selector. The 12-way
deterministic results above do not measure whether a model uses that extra
context, and the larger excerpt may increase model cost. Long records now use
bounded head and tail fragments with an explicit omission marker, so a
diagnostic suffix beyond the first 512 bytes can still be seen without
loading the full record into the ranking prompt. Final log output continues
to resolve exact original bytes by source ID.

Run `bash scripts/eval-loghub-bgl.sh` from the repository root. The script
fetches the pinned upstream sample into a temporary directory; the test
checks its hash before ingesting it.
