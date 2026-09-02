# Evidentrail

**Compression you can cross-examine.**

Evidentrail turns a large diagnostic log and a debugging question into a
budget-bounded evidence brief for coding agents. It reduces context without
turning source evidence into an unverifiable summary: every selected event
keeps its original bytes, every citation can be expanded, and every incomplete
result says so.

```text
explicit log bytes + question + budget
                │
                ▼
     deterministic evidence compiler
       frame → retrieve → select → certify
                │
                ▼
 cited Log Brief + coverage receipt + exact expansion
```

## The product

Large logs create a bad tradeoff for an agent: send everything and waste the
context window, truncate and miss the cause, or summarize and lose the proof.
Evidentrail introduces a fourth option—a compact evidence layer between raw
telemetry and the reasoning model.

Give it logs such as CI output, compiler failures, service incidents, or
Kubernetes events. Ask a concrete question. Evidentrail returns the smallest
useful set it can certify under the supplied budget, with exact `E<n>` handles
back to the retained source.

| Capability | Product behavior |
|---|---|
| Exact when small | If the authorized input already fits, it passes through unchanged. |
| Evidence selection | It combines exact identifiers, failure/onset roles, source coverage, and authorized correlations. |
| Honest incompleteness | If mandatory evidence cannot fit, it returns `needs_more` instead of a confident-looking partial answer. |
| Byte fidelity | Invalid UTF-8, duplicate events, record boundaries, and multiline stacks remain reversible. |
| Exact follow-up | Every advertised `E<n>` reference expands to bounded original source events. |
| Agent-ready output | A compact brief carries evidence, roles, coverage, receipts, and expansion instructions together. |
| Local by default | Deterministic compilation performs no hosted model call and needs no credential. |

Evidentrail is an evidence compiler, not a root-cause chatbot. It does not
invent a diagnosis, paraphrase a failure, or treat generated text as source
truth. The downstream agent reasons; Evidentrail controls what evidence reaches
that reasoning step and preserves the path back to the bytes.

## Quick start

Evidentrail is a Rust workspace and requires Rust 1.85 or newer.

```sh
cargo build --release -p evidentrail-cli --bin evidentrail

target/release/evidentrail brief \
  --question "Why did request REQ-7 fail?" \
  --token-budget 20000 < app.log
```

The default is memory-only, deterministic, and offline. Questions can also be
read from a file so they do not appear in the process argument list:

```sh
target/release/evidentrail brief \
  --question-file question.txt \
  --token-budget 20000 < app.log
```

A compiled result is deliberately inspectable:

```text
STATUS
  result: result_…
  acquisition: COMPLETE
  selection: COMPILED

EVIDENCE
  [E1]
    expand: E1 exact
    roles: query_term,failure_role,onset_role
    event_1:
      exactness: source_exact
      data: ERROR request REQ-7 upstream timed out\n

COVERAGE
  shown_verbatim: 1
  retained_raw: …
```

The result-scoped alias is not a decorative citation. In a retained product or
MCP session, `E1` is an exact, bounded retrieval capability for the underlying
event bytes.

## How it works

1. **Acquire explicitly.** The caller supplies the byte stream. The product
   does not crawl a repository, discover files, or inspect ambient logs.
2. **Frame reversibly.** Records, malformed bytes, duplicates, and multiline
   failures are represented without destroying source fidelity.
3. **Build independent evidence lanes.** Exact query matches, failure context,
   raw coverage, and narrowly authorized provider relations contribute
   candidates with explicit provenance.
4. **Preserve mandatory evidence.** Feasibility is checked before optional
   evidence or any hosted ranking can influence selection.
5. **Pack to the real render budget.** A deterministic, diversity-aware
   selector chooses intact evidence packets using certified composable costs.
6. **Render and receipt.** The brief exposes what was shown, what remains
   retained, and how each source-exact citation can be expanded.

The same authorized input, question, policy, and budget produce the same
deterministic result.

## Optional hosted ranking

Hosted ranking is an explicit, memory-only beta. It can reorder a bounded set
of intact optional evidence blocks; it cannot edit evidence, create citations,
remove mandatory evidence, decide completeness, or generate the final answer.

The preferred mode uses deterministic selective escalation:

```sh
read -rs 'OPENAI_API_KEY?Paste OpenAI API key: '; export OPENAI_API_KEY; echo

target/release/evidentrail brief \
  --question "Why did request REQ-7 fail?" \
  --token-budget 20000 \
  --llm-rank-if-contended < approved.log
```

`--llm-rank-if-contended` calls only when deterministic packing excluded at
least one model-visible optional block—an auditable opportunity for ranking to
change membership. It is not a model-confidence claim. `--llm-rank` retains
the unconditional evaluation path.

Both modes make at most one call, never retry within the request, and fall back
to the already-computed deterministic result on missing credentials, timeout,
provider failure, policy denial, or invalid structured output. Set
`EVIDENTRAIL_HOSTED_RANKING_SHADOW=1` to exercise an explicitly requested
hosted path while always publishing deterministic bytes. The kill switch is
`EVIDENTRAIL_HOSTED_RANKING_DISABLED=1`.

The current hosted candidate is **not qualified for product admission**. Its
approved synthetic characterization returned valid rankings but took
1.501–2.236 seconds end to end, exceeding the unchanged 800 ms provider
deadline. No hosted accuracy improvement has yet been established. See the
[hosted ranking contract](docs/HOSTED_EVIDENCE_RANKING.md) and
[selective-ranking release gates](docs/SELECTIVE_HOSTED_RANKING_RELEASE_PLAN.md).

## MCP for agent tool loops

Run the process-resident MCP server:

```sh
target/release/evidentrail serve-mcp
```

It exposes two tools:

- `evidentrail_logs` compiles explicitly supplied, bounded log bytes.
- `evidentrail_expand` resolves an advertised result-scoped alias without
  rereading or widening the original source.

`ranking_mode` defaults to `deterministic`. The only hosted alternatives are
`hosted` and `hosted_if_contended`; both require request-level opt-in.
Process-resident results expire after 30 minutes or when the server exits.

## Trust boundary

The contracts are intentionally stricter than ordinary retrieval pipelines:

- Input logs and all returned evidence are marked as untrusted data.
- Candidate blocks are intact and use reversible byte escaping.
- Mandatory evidence and budget feasibility are resolved before hosted egress.
- A hosted response must be a complete permutation of submitted opaque IDs.
- Unknown, duplicate, missing, malformed, or foreign IDs invalidate the whole
  proposal.
- Diagnostics are contentless: configuration digests, timing, token/cost
  counters, validation outcome, and fallback reason—not prompts or responses.
- Durable retention is encrypted and fails closed when its external authority
  is unavailable.

Read the [threat model](docs/THREAT_MODEL.md),
[Log Brief contract](docs/LOG_BRIEF_CONTRACT.md), and
[local data policy](docs/LOCAL_DATA_POLICY.md) for the normative boundary.

## What is proven today

The deterministic product has unit, property, integration, golden, executable
incident, and byte-integrity coverage across the workspace. Frozen hermetic
corpora exercise exact recall, abstention, adversarial bytes, mandatory
feasibility, expansion, and downstream diagnosis contracts. The streaming V3
path has validation fixtures up to 1,000,000 records / 1 GiB behind its rollout
gate.

Those results are engineering evidence, not a population-level claim about all
production incidents. Hosted ranking still requires a passing frozen
multi-provider benchmark and approved realistic shadow operation. Current
claims and open gaps are maintained in
[implementation status](docs/IMPLEMENTATION_STATUS.md) and the
[product roadmap](docs/PRODUCT_ROADMAP.md).

Approved historical incidents can be evaluated with the memory-only,
contentless-reporting
[`evidentrail-production-shadow`](docs/PRODUCTION_SHADOW_PILOT.md) runner. It is
deterministic by default and can exercise the real pinned OpenAI ranking path
only through explicit manifest- and case-level egress approval. Real incident
material must remain outside this repository and ordinary CI.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

The workspace keeps acquisition, framing, evidence construction, selection,
rendering, wire contracts, encrypted retention, product orchestration, CLI/MCP,
and benchmarking in separate crates. The core compiler remains network- and
credential-free.

## License

Licensed under either [Apache 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at
your option.
