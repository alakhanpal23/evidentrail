# Connected log selection on labeled RCAEval RE3-SS cases

This opt-in probe uses seven [RCAEval Sock Shop code-fault cases](https://huggingface.co/datasets/phamquiluan/RCAEval) with a published `root_cause.txt` line that occurs exactly once in the corresponding `logs.parquet` message and service columns. It ingests all 596,494 log rows into one source-bound encrypted corpus per case. The query is the same generic task for every case: “Investigate service errors and failed requests.” The selector sees no fault label, root-cause line, service name, or incident time. Each arm has a 32 KiB raw-log output budget. The original [dataset card](https://huggingface.co/datasets/phamquiluan/RCAEval/blob/afeacb11bcc94dadfd1c8f483ee4377b2b8b614e/README.md) says eight RE3-SS cases have root-cause files; the eighth, `re3ss_front-end_f2_2`, is excluded because its published root-cause message is absent from that case's logs.

| Selection arm | Exact labeled line | Same parsed service/message template | Labeled service present | Returned lines, total |
| --- | ---: | ---: | ---: | ---: |
| First advertised IDs | 0/7 | 0/7 | 7/7 | 138 |
| Severity-only IDs | 0/7 | 0/7 | 3/7 | 141 |
| Twelve recent representatives | 0/7 | 0/7 | — | 84 |

Both deterministic selectors resolve every returned line to its exact encrypted source record. The recent baseline is scored for the labeled line, but was not scored for service/template coverage. No arm hit the byte ceiling. First-ID and severity selection each made 17 selector calls across seven cases. Neither had a reported candidate-pool or service-directory truncation in the final run, although intermediate pages pruned 360 candidate groups across cases. These counts show that service membership is too weak a proxy for useful log selection in this setting.

The version-5 parser recognizes complete Spring Boot log preambles and seven-field HTTP access lines. It groups variable trace IDs, threads, request latency, and response size without altering the original source bytes. In an exploratory before/after run on the same seven pinned corpora, total indexed groups fell from 379,858 to 353,222 (7.0%). The line and template recall did not improve in the measured deterministic arms. A tested attempt to add severity samples to sparse lexical results also missed the labeled template while increasing candidate truncation and selector calls; that retrieval change was removed.

Reproduce with `python3 -m pip install pyarrow==21.0.0`, then `python3 scripts/eval-rcaeval-connected.py --labeled > /tmp/evidentrail-rcaeval-labeled.txt 2>&1` and `python3 scripts/score-rcaeval-connected-labeled.py /tmp/evidentrail-rcaeval-labeled.txt`. The harness pins the dataset revision and SHA-256 of the case index, seven Parquet files, and seven root-cause files. It checks the unique label match before evaluation, keeps raw telemetry in a temporary directory, and prints only counts and metadata.

This is a hard, ambiguous task: a generic query over full history gives the selector no incident time or specific symptom, and the published line is not a complete set of all useful lines. Template matching is a second proxy, not a repair outcome. A local Ollama endpoint and hosted-model key were unavailable for this run, so model-guided selection, matched-budget downstream coding-agent fixes, and live provider operation remain unqualified.
