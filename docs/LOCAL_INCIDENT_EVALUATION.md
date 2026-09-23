# Local incident evaluation

Use this runner for a frozen, reviewer-labeled set of historical incidents that
you are approved to inspect. Keep the manifest and telemetry outside the public
repository. The script uses an installed Ollama model on `127.0.0.1:11434` and
removes `OPENAI_API_KEY` from the child process environment. It prints only
file-independent case digests, per-case scores, and aggregate counts; it never
prints source lines, questions, model explanations, or local paths.

Write a JSON manifest like this in a private local directory:

```json
{
  "schema_version": 1,
  "cases": [
    {
      "id": "reviewed-incident-001",
      "question": "What caused the checkout failures?",
      "expected_status": "incident",
      "expected_service": "checkoutservice",
      "expected_fault_type": "disk",
      "logs": "reviewed-incident-001.log"
    },
    {
      "id": "reviewed-unknown-001",
      "question": "What caused the checkout failures?",
      "expected_status": "unknown",
      "logs": "reviewed-unknown-001.log"
    }
  ]
}
```

Paths are relative to the manifest directory unless absolute. Each case needs
explicit `logs` or `metrics`. Optional inputs are `topology`, `traces`, and
`metrics` paired with integer Unix `incident_time`. For confirmed incidents,
`expected_service` is required and `expected_fault_type` is optional. Fault
types are `cpu`, `mem`, `disk`, `delay`, `loss`, `socket`, `other`, or `unknown`.
Use `unknown` or `healthy` only when the reviewer has established that no
specific cause should be named from the provided evidence. Freeze labels and
case selection before inference; avoid using the same cases to tune prompts and
claim validation.

```sh
cargo build --release -p evidentrail-cli --bin evidentrail
OLLAMA_CONTEXT_LENGTH=32768 ollama serve
EVIDENTRAIL_ANALYZE_LOCAL_MODEL=qwen3:14b \
  python3 scripts/evaluate-local-incidents.py \
  --manifest /private/path/incident-manifest.json \
  --binary target/release/evidentrail \
  > /private/path/incident-scores.jsonl
```

Run Ollama in a separate terminal before the evaluator. The first JSONL line
records manifest and binary SHA-256 hashes plus the model; subsequent lines
record hashed case identifiers; the last line is an aggregate summary. Product
errors and timeouts remain in the denominator. `confirmed_service_hits` uses
all confirmed incidents; `confirmed_joint_hits` uses all cases with a confirmed
fault label. Abstentions and false attributions on `unknown`/`healthy` cases
show whether the model can decline to diagnose. The runner does not score the
quality of a fix, semantic entailment of a citation, or downstream utility.
Those require independent reviewer judgment and matched-budget comparisons
against truncation, grep/tail, and retrieval baselines.
