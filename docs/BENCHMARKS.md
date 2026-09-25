# Evidentrail benchmark ledger

The [README](../README.md#benchmarks) shows the headline measurements. This ledger indexes the completed connected-log experiments and distinguishes verified repairs, retrieval proxies, and local performance observations. Values from different cohorts or product paths are **not** pooled. No listed experiment establishes a production repair advantage or a live-provider latency guarantee.

## Verified coding-agent repairs

| Study | Cohort and matched conditions | Results | Decision |
| --- | --- | --- | --- |
| [Six-arm frozen learning study](../reports/learning-repair-2026-09-24/REPORT.md) | 12 held-out executable BugsInPy bugs from 3 projects; 1 KiB exact-log cap; same GPT-6 Sol repair agent; 72 independently checked edits | Current **7** fixes, no logs **7**, first-ID **8**, severity **7**, GPT-6 Luna memory on **4**, memory off **5**. Current p95 end-to-end **48.1 s**; memory-on **72.6 s**. | No current-route improvement over simple baselines and no memory benefit. Keep learning in shadow. |
| [Earlier five-arm study](../reports/repair-study-2026-09-24/REPORT.md) | 11 different held-out BugsInPy bugs from 3 projects; 1 KiB exact-log cap; same GPT-6 Sol repair agent; 55 held-out trials | Current **7** fixes, no logs **6**, first-ID **5**, severity **4**, GPT-6 Luna challenger **7**. Current p95 end-to-end **76.4 s**. | Paired improvement missed the frozen gate. Fixed arm order and a partly amended cohort limit interpretation. |
| [Single tqdm probe](../reports/connected-real-repair-tqdm-2026-09-24.md) | One real BugsInPy bug, bounded two-edit local-model reader | **0** verified fixes in every arm for both tested readers; first-ID/model packs did retain the offending line. | Exploratory development data, not held-out evidence. |

These studies use failing-test logs, not live provider incidents. A passing hidden regression is a verified signal for that bug, not proof of a safe production patch. The six-arm report's dollar amounts are list-price estimates; missing provider-metered costs close the promotion gate.

## Log selection and reduction

| Probe | Corpus and task | Observed result | Interpretation |
| --- | --- | --- | --- |
| [LogHub BGL](../reports/connected-loghub-bgl-2026-09-23.md) | Pinned real 2,000-line sample; one message-derived task; 4 KiB output | **1,374** template groups; **16** exact lines returned. The first required alert was in the pack; its adjacent alert was recovered by expansion. | **31.3% fewer groups**, **99.2% fewer lines presented** for that task. Original lines are retained. These are not byte-storage savings or broad recall. |
| [BGL 12-category proxy](../reports/connected-loghub-bgl-2026-09-23.md) | 12 message-derived tasks on same sample | First-ID and severity each hit **12 of 12** target categories; 12-newest hit **1**. First-ID returned **147 off-label of 189** lines; severity **138 of 179**. | Off-label does not mean irrelevant. One candidate pool truncated. |
| [BGL actual local model](../reports/connected-loghub-bgl-model-eval.md) | Qwen2.5-Coder 7B, same 12 tasks and 4 KiB cap | **12 of 12** category hits, **107 off-label of 149** lines; **494.4 s** across sequential queries; slowest **157.5 s**. | Narrow noise proxy improved over deterministic arms, but too slow and too task-derived to qualify a default. A revised prompt was tested and reverted. |
| [RCAEval Sock Shop labels](../reports/connected-rcaeval-labeled-2026-09-24.md) | Seven full log histories, **596,494** rows per case; generic task; 32 KiB per case | First-ID repeated-severe path found **7 of 7** labeled templates and **3** exact published lines. Qwen2.5-Coder 7B found **3** templates and **1** exact line in its first local run. | A matching template is weaker than an exact line and neither proves a useful answer or repair. Model run took **370.7 s** across 28 selector calls. |
| [RCAEval parser grouping](../reports/connected-rcaeval-labeled-2026-09-24.md) | Same seven pinned Sock Shop histories before/after a parser change | Indexed groups fell from **379,858** to **353,222** (**7.0% fewer**). | Source bytes stayed intact; measured deterministic line and template recall did not improve. |
| [RCAEval Online Boutique](../reports/connected-rcaeval-re3-2026-09-23.md) | Three code-fault histories, **205,659** rows total; generic task; 32 KiB per case | After diversity safeguard, first-ID included the labeled service in **3 of 3** cases; Qwen3 14B and Qwen2.5-Coder 7B each in **1**, GPT-OSS 20B in **2**. | Service presence and post-injection timing are proxies, not causal line labels. The GPT-OSS email query took **212.6 s**. |
| [Executable fault streams](../reports/connected-executable-2026-09-24.md) | Three synthetic 183-line streams; 7 KiB cap | First-ID and Qwen2.5-Coder 7B each retained precursor plus symptom in **3 of 3**; severity and recent-only in **0**. | Candidate pools were only 4–6 groups, so this does not test difficult ranking. A bounded synthetic workspace-edit probe got **3 of 3** verified edits for every log arm versus **2** without logs; no selection-specific win. |
| [Frozen graph/noise fixture](../reports/connected-retrieval-v2.md) | Six synthetic cases, including 300–800 newer error groups; 4 KiB cap | First-ID and severity retained the required clue in all **6** cases; recent-only missed all **6**. | Deterministic selector and synthetic clues; hard candidate caps still permit misses. [Archived v1](../reports/connected-retrieval-v1.md) records the earlier 3-case fixture. |
| [Shadow-learning replay](../reports/learning-route-shadow-2026-09-24.md) | Six synthetic development cases; 4 KiB cap | Current route selected **7 of 7** labeled records; lexical **6**, severity **7**, recent **0**. | Retrieval mechanism test only; no independently labeled held-out repairs or learning benefit from this replay. |

## Connected-corpus scale

The [local connected scale exercise](../reports/connected-scale-local-2026-09-23.md) inserted distinct synthetic records and template groups into the encrypted corpus. Each query had three planted error clues at the start, middle, and end, a 4 KiB raw-log cap, and a deterministic selector. Every selected clue was verified against original bytes and repeat count.

| Records / groups | Ingest | Indexed query | Wording-mismatch fallback | Exact planted clues |
| ---: | ---: | ---: | ---: | ---: |
| 100,000 / 100,000 | **12.536 s** | **21 ms** | **27 ms** | **3 of 3** in both |
| 1,000,000 / 1,000,000 | **191.762 s** | **351 ms** | **270 ms** | **3 of 3** in both |

These are single debug-build observations on an Apple M5 Pro with 24 GiB RAM. The query times exclude ingest, provider sync, and model inference; the fixture has only three severe clues and does not test concurrent users or a noisy error storm. They are not p50/p95 latency measurements. The fallback happened to run faster than the indexed query in this run; neither should be described as universally faster.

## Earlier repository-component scale

An [older local performance study](../reports/m1-performance/LOCAL_ENGINEERING_STUDY_2026-08-30.md) exercised the durable repository component with **1 million** generated events: **139.421 s** lifecycle, **7,173 records/s**, **858.6 MiB** peak RSS, **654.95 MB** stored for **78.78 MB** source, and **28.76 ms** p95 for exact indexed expansion reads. This was **component-only**, on a different path and fixture from the connected-corpus test above. The old full-product stdin path rejected a million-record input at its 100,000-record/16 MiB public boundary; the component result is not a full-product 1M claim.

The earlier `analyze`/`brief` diagnosis experiments are tracked separately in the [RCAEval selection probes](../reports/rcaeval-selection/README.md) and [log-only abstention pilot](../reports/independent-log-abstention/README.md). They use different inputs and outputs from the connected log-pack product and must not be combined with its retrieval or repair scores.
