# Connected-log repair study — 24 September 2026

**Decision: retain the current product route and do not promote a model.**
On eleven held-out, executable BugsInPy repairs, the current connected route
produced 7 verified fixes versus 6 with no logs, 5 with first-ID logs, and 4
with severity logs. The GPT-6 Luna challenger also produced 7. The current
route helped on three cases that no-logs missed but hurt on two that no-logs
fixed (one-sided exact paired p = 0.5). The challenger gained one and lost
one relative to current (p = 0.75). Neither passes the preregistered review
gate, and this Codex CLI study bridge does not qualify a production adapter.

## Protocol

We screened 79 historical BugsInPy bugs from five projects in a pinned Python
3.9 environment. Twenty-six had executable controls: the same hidden test
failed on buggy source and passed on fixed source. Each trial used an isolated
buggy source tree, the same task, Codex CLI 0.156.1 GPT-6 Sol at low effort,
the same workspace/edit restrictions, and a 1,024-byte exact raw-log cap.
Agents did not receive fixed source or the hidden test files. The verifier
mounted hidden tests only in disposable copies, checked frozen tree and log
hashes, rejected edits outside allowed source files, and reran buggy, fixed,
and agent-edited controls. The scorer independently reran that verifier
before accepting the [contentless receipts](per-case-results.jsonl).

The [original case lock](locked-cases.json) and [pack lock](pack-lock.json)
were committed before original repair trials. PySnooper 2 was used in a
pre-lock agent-runner pilot, so it is reported as development only. Two
untouched Black bugs were selected by next eligible numeric ID and frozen in
[supplemental case](supplemental-cases.json) and
[pack](supplement-pack-lock.json) commits before their repair trials. Their
selection occurred after the first two original outcomes were visible; this
limits confirmatory interpretation even though no route was tuned on them.
The held-out set has three projects and six fault families. There were 60
total repair arms: 55 held-out and five development. All 60 completed under
the protocol. An audit of completed command events found no prohibited test
run, package install, network command, or external-path read. All selected
records matched exact source IDs and bytes and stayed within the cap.

## Verified repairs

✓ means the independent hidden regression passed; — means it failed. The
development row is excluded from every score.

| Case | Split | No logs | First ID | Severity | Current | Challenger |
|---|---|:---:|:---:|:---:|:---:|:---:|
| black-4 | held out | — | — | — | — | — |
| black-5 | held out | ✓ | — | — | ✓ | — |
| black-7 | held out | ✓ | — | — | — | — |
| black-11 | held out | ✓ | — | — | — | ✓ |
| thefuck-1 | held out | ✓ | ✓ | ✓ | ✓ | ✓ |
| thefuck-25 | held out | — | ✓ | ✓ | ✓ | ✓ |
| thefuck-26 | held out | — | — | — | ✓ | ✓ |
| fastapi-1 | held out | — | ✓ | — | ✓ | ✓ |
| fastapi-2 | held out | ✓ | ✓ | ✓ | ✓ | ✓ |
| black-8 | held out | — | — | — | — | — |
| black-9 | held out | ✓ | ✓ | ✓ | ✓ | ✓ |
| PySnooper-2 | development | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Held-out total** | **11** | **6** | **5** | **4** | **7** | **7** |

Against no logs, current had three unique fixes and two unique failures;
challenger had the same 3:2 split. Against first-ID, current had two unique
fixes and no unique failures (p = 0.25). Against severity it had three unique
fixes and no unique failures (p = 0.125). None reaches the frozen 0.01 paired
gate. Current and challenger each made 22 counted CLI invocations across
held-out cases (11 repair, 11 selector); deterministic arms made 11 repair
invocations. These are **not** internal model-call counts.

| Arm | p95 end-to-end latency | Repair input tokens | Cached input tokens | Repair output tokens |
|---|---:|---:|---:|---:|
| No logs | 94.1 s | 1,825,868 | 1,636,480 | 15,552 |
| First ID | 43.2 s | 1,328,869 | 1,166,976 | 10,000 |
| Severity | 80.7 s | 1,773,229 | 1,629,440 | 14,430 |
| Current | 76.4 s | 1,440,261 | 1,259,776 | 11,427 |
| Challenger | 87.7 s | 1,478,099 | 1,319,680 | 11,926 |

Latency includes log selection and repair. The challenger p95 was about 15%
slower than current, within the provisional 25% latency limit, but it did not
fix more bugs. Selector token usage and a reliable dollar price were not
available from these Codex CLI runs, so the monetary cost guardrail cannot
be evaluated. The repair token counts above are workload context, not a cost
claim. Cases ran in fixed arm order, and the supplemental process overlapped
the original process, so latency differences are descriptive rather than a
controlled performance comparison.

## What the failures showed

Black 7 is a concrete retrieval miss: the original failing log included the
assertion difference, but current and challenger selected traceback
locations and omitted that difference. The no-logs agent repaired the hidden
regression; all four log-fed agents failed. Conversely, on The Fuck 26,
current and challenger surfaced command-specific failure lines and both
repaired the regression while no-logs, first-ID, and severity failed. The
project therefore has a measurable opportunity in preserving diagnostic
payload near failure summaries, but this held-out set must not be used to
tune and then requalify a new route.

The source logs here came from failing tests, not live Datadog/AWS/Sentry
incidents. A passing targeted regression is a verified repair signal, not
proof the patch passes the full project suite or is production safe. The
selection bridge used Evidentrail's encrypted corpus, group cards, candidate
paging, budget enforcement, and exact record resolution, with Codex CLI for
the selector. It is not the production OpenAI API adapter. These limits and
the small, partly amended held-out set rule out a default-model change.

The [study manifest](study-manifest.json),
[source-exact artifacts](artifacts/), [score](score.json), and
[reproduction commands](README.md) make the protocol and outcome inspectable.
Agent traces, source trees, hidden tests, and patches are kept outside the
repository to avoid contaminating future repair evaluations.
