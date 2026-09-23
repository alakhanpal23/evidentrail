# Independent log-only abstention pilot

This pilot uses the 18 pinned cases in
[`PhyByte/LLM-SRE-Bench`'s `multimodal_rca.json`](https://github.com/PhyByte/LLM-SRE-Bench/blob/89db617170f3b2fe560d31f3790cf2678d5d82be/datasets/data/multimodal_rca.json),
derived by its authors from Nezha microservice incidents. We pass only each
case's 30 exact log strings to `evidentrail analyze`. The source's metrics and
traces are already pre-aggregated, so this run does **not** validate
Evidentrail's raw metric or span parsers. The dataset SHA-256, Evidentrail
revision, executable SHA-256, and clean-worktree flag are recorded in each
artifact header. The JSONL files contain case IDs and aggregate outcomes, no
raw logs or model explanations.

The set has 12 labeled incident cases, five labeled `unknown` (the available
signals do not identify a culprit), and one healthy `none` case. Six incident
cases are labeled as having informative logs. One of those six nevertheless
has no emitted log line from its labeled culprit, so top-service scoring is
particularly limited. Logs alone cannot reveal the injected CPU or network
fault in many cases. A correct abstention on a metric-only incident is useful,
even though it does not count as a top-service hit here.

| Log-only outcome | Original prompt `d87c8f1` | Causal-limit prompt `3c3d0c3` |
| --- | ---: | ---: |
| Complete cases / product errors | 18 / 0 | 18 / 0 |
| Top-service hits among 6 log-informative incidents | 2 | 2 |
| Abstentions among 6 log-informative incidents | 3 | 3 |
| Abstentions among 6 log-uninformative incidents | 4 | 3 |
| Abstentions among 5 unresolvable incidents | 2 | 4 |
| Abstentions on the healthy case | 1 | 1 |

The revised prompt asks the LLM to treat caller failures, repeated warnings,
and errors across several services as possible symptoms, and to abstain when
the logs cannot distinguish candidates. It reduced wrong guesses on the five
unresolvable cases from three to one, but increased guesses on the six
log-uninformative cases from two to three. Across all 18 cases, the original
prompt made two correct and six wrong top-service attributions; the revised
prompt made two correct and five wrong. These are **development results**, not
held-out evidence of an accuracy improvement: the prompt was adjusted after
inspecting the original run on this same set. Exact source-citation checks
reject fabricated citations but cannot establish that a cited error is the
root cause. Both runs return partial reports and preserve `needs_more_evidence`
when appropriate.

Reproduce from the respective commits with a local `qwen3:14b` model and a
32K Ollama context. The probe fetches and SHA-checks the pinned public JSON
unless `--dataset` points to an identical local copy:

```sh
cargo build -p evidentrail-cli --bin evidentrail
cp target/debug/evidentrail /tmp/evidentrail-fixed
EVIDENTRAIL_ANALYZE_LOCAL_MODEL=qwen3:14b \
  python3 scripts/independent-log-abstention-probe.py \
  --binary /tmp/evidentrail-fixed --live-model > independent-log-live.jsonl
```

The fixed executable copy prevents a rebuild during evaluation from mixing
product versions. [`selection-d87c8f1.jsonl`](selection-d87c8f1.jsonl)
records the model-free parsing pass;
[`qwen3-d87c8f1.jsonl`](qwen3-d87c8f1.jsonl) and
[`qwen3-3c3d0c3.jsonl`](qwen3-3c3d0c3.jsonl) are the paired local-model runs.
