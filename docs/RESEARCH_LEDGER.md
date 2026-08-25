# Evidentrail Research Ledger

**Cutoff:** 2026-08-24
**Purpose:** Evidence ledger for the greenfield diagnostic-evidence compiler described in `GREENFIELD_EXECUTION_PROGRAM.md` and evaluated by `EVIDENTRAILBENCH_PROTOCOL.md`.

## Scope and evidence policy

This is a **systematic ledger of relevant sources**, not a claim that we found literally every paper ever published on log parsing, compression, anomaly detection, diagnosis, or context selection. The search was intentionally bounded to methods that can change Evidentrail's architecture, evaluation, or training plan. Every literature citation below is an original paper, an author-maintained repository, or an official dataset/benchmark record. Surveys, vendor summaries, and secondary blog posts are excluded. Current competitor-product evidence is maintained separately in the source-linked [`EVIDENTRAIL_COMPETITIVE_TEARDOWN.md`](EVIDENTRAIL_COMPETITIVE_TEARDOWN.md).

Evidence labels mean:

- **Peer reviewed:** a venue or publisher record was verified.
- **Preprint:** the result has an author manuscript but, as of the cutoff, no peer-reviewed record was verified here.
- **Artifact/dataset:** an author or institutional repository, benchmark site, or archival dataset record was verified.

“Demonstrates” means what the cited work itself establishes or evaluates; it does not imply independent replication. Author-reported comparisons are not treated as product claims. “Adopt” means incorporate the underlying requirement or mechanism after our own tests. “Adapt” means borrow a constrained idea. “Benchmark” means include as a comparator. “Watch” means insufficient maturity or reproducibility for a product dependency. “Reject” means exclude from the stated product layer—not that the research is valueless. Titles were cross-checked against the linked primary records, and every URL in this ledger was resolution-tested on the cutoff date (some publisher DOI endpoints reject automated clients while remaining valid DOI records).

## Design conclusions supported by the ledger

The literature supports a product that is more disciplined than a single parser, compressor, anomaly model, or LLM summarizer:

1. **Keep the immutable authorized ledger as truth.** Every acknowledged envelope records exactly one policy outcome: `SourceExact`, `PostPolicy` with a transformation receipt, or `OmittedByPolicy` with no payload. Exact expansion is always relative to the declared retained basis; only `SourceExact` permits a source-byte claim. Parsing and compression methods optimize different proxies, and none of the reviewed work proves that its omissions preserve every fact needed for incident diagnosis.
2. **Reconstruct atomic events before grouping.** Within an authorized retained basis, multiline records, stack traces, wrapped messages, and source-specific boundaries must survive as indivisible evidence units.
3. **Ship exactly three active MVP evidence lanes:** (1) lexical plus validated typed identifiers, (2) complete failures plus transparent onset/change signals plus raw-coverage sentinels, and (3) provider-attested bounded correlations. Drain/tree, n-gram, grouping-derived selection, reference-window contrast, learned anomaly, embedding, and LLM-ranker lanes remain disabled experiments until each passes held-out unique-yield, leave-one-lane-out recall, incompatible-overmerge, and recall-cost gates. **Agreement between proposers is not validation.**
4. **Separate storage compression from diagnostic compression.** Lossless archival codecs reduce retained bytes. A diagnostic brief selects basis-exact blocks under a context budget. They need different objectives and tests.
5. **Select basis-exact blocks with a deterministic, inspectable objective.** Nonnegative facility-style coverage is a useful starting point, but approximation claims apply only when their mathematical assumptions and algorithm are actually implemented.
6. **Treat anomaly as a proposal, never a causal label.** Novelty, sequence surprise, count shifts, and change points can surface candidates; none alone establishes root cause.
7. **Make every conclusion traceable to stable evidence IDs.** Diagnose, retrieval, citation correctness, citation completeness, and abstention must be scored separately.
8. **Treat logs as hostile input.** Log text has no authority to change policies, call tools, expand scope, or construct commands. The trusted data plane must remain separate from any neural reader.
9. **Train an LLM only after the deterministic product and benchmark gates exist.** The model can learn ranking, evidence roles, and synthesis; it cannot become the ledger, permission boundary, or sole judge.

### Competitor evidence implication

Public Evidentrail is not accurately described as only template compression: its hosted surface advertises action-aware reduction, local encrypted retrieval of omitted content, analytics, and workspace policy. The open `legacy-drain` artifact is a distinct Drain-style grouping/rendering engine; its public parser benchmark attributes default grouping behavior to Drain3 while distinguishing rendering gains. The `legacy-drain` agent-serving report also shows a conditional result—worse than raw at the reported 300-line setting and better than the truncated raw arm at 3,000 lines—under a private case set and one reader setup; it does not establish current hosted-service performance.

The implementation consequences are testable and narrow:

- exact passthrough is mandatory whenever the complete authorized result fits;
- pinned current hosted Evidentrail and pinned `legacy-drain` are separate benchmark arms and can never substitute for one another;
- current hosted-product claims remain hypotheses until matched evaluation under the same inputs, outputs, reader/tool loop, and total cost;
- no greenfield component imports, wraps, forks, or depends at runtime on either competitor implementation.

---

## 1. Log parsing, event reconstruction, and grouping

### Drain

- **Source:** [“Drain: An Online Log Parsing Approach with Fixed Depth Tree” (ICWS 2017, DOI)](https://doi.org/10.1109/ICWS.2017.13); [author manuscript](https://pinjiahe.github.io/files/pdf/research/ICWS17.pdf). **Peer reviewed.**
- **Demonstrates:** A bounded-depth tree can route streaming log messages to template clusters without pairwise comparison against every cluster. Its chief product-relevant property is predictable online proposal behavior.
- **Limitations:** It is a line-oriented template parser, not an event reconstructor, provenance system, evidence selector, or diagnostic evaluator. A wrong template assignment can collapse a rare difference if the downstream system treats the template as truth.
- **Evidentrail decision — DISABLED MVP EXPERIMENT + BENCHMARK:** Include canonical Drain as a speed/quality baseline, but do not activate a tree-derived evidence lane. Admission requires held-out unique required-evidence yield per unit cost, positive leave-one-lane-out contribution, and zero known incompatible overmerges. Its cluster ID can never replace authorized retained content or an atomic event ID, and agreement with another proposer is not validation.

### Spell

- **Source:** [“Spell: Streaming Parsing of System Event Logs” (ICDM 2016, DOI)](https://doi.org/10.1109/ICDM.2016.0103); [author manuscript](https://users.cs.utah.edu/~lifeifei/papers/spell.pdf). **Peer reviewed.**
- **Demonstrates:** Longest-common-subsequence matching can incrementally form templates in a streaming setting without an offline vocabulary.
- **Limitations:** LCS similarity can be costly as clusters grow and is sensitive to tokenization. The work evaluates template extraction rather than exact incident evidence preservation or root-cause diagnosis.
- **Evidentrail decision — DISABLED MVP EXPERIMENT + BENCHMARK:** Retain Spell as a structurally different parser comparator. It supplies neither an active v1 lane nor validation for another proposer; it must pass the same held-out unique-yield, overmerge, recall-cost, and leave-one-lane-out gates before admission.

### Logram

- **Source:** [“Logram: Efficient Log Parsing Using n-Gram Dictionaries” (IEEE TSE, DOI)](https://doi.org/10.1109/TSE.2020.3007554); [author preprint](https://arxiv.org/abs/2001.03038). **Peer reviewed.**
- **Demonstrates:** Frequencies of token bigrams and trigrams can identify stable and variable parts without a parsing tree, giving an efficient alternative proposal mechanism.
- **Limitations:** Corpus frequencies can shift with deployment mix and time. Frequent tokens are not necessarily diagnostically important, and rare tokens are not necessarily variables.
- **Evidentrail decision — DISABLED MVP EXPERIMENT + BENCHMARK:** Prototype an n-gram/anchor proposer only behind a feature gate with time-bounded statistics and drift telemetry. It is not one of the three active lanes and may be admitted only after held-out unique-yield, incompatible-overmerge, recall-cost, and leave-one-lane-out ablations pass. Frequency can never erase authorized retained content, and agreement with Drain is not validation.

### Hue

- **Source:** [“Hue: A User-Adaptive Parser for Hybrid Logs”](https://arxiv.org/abs/2308.07085); [author repository](https://github.com/logpai/hybridlogparser). **Preprint + artifact.**
- **Demonstrates:** Hybrid logs require explicit handling of single-line and multiline structures, and parser feedback can be represented as merge/reject decisions rather than a one-shot immutable guess.
- **Limitations:** The reported evaluation is scoped to a small set of hybrid datasets, and user feedback does not itself create a deterministic boundary rule. Template output still is not exact evidence identity.
- **Evidentrail decision — ADOPT THE REQUIREMENT, NOT THE DEPENDENCY:** Atomic reconstruction is a first-class stage feeding the three active lanes, not a fourth evidence lane. Use bounded, source-aware state machines with fixtures for stack traces and continuations, plus an explicit “uncertain boundary” state. Feedback changes versioned rules, never the authorized retained basis.

### Loghub-2.0 and large-scale parser evaluation

- **Source:** [“A Large-Scale Evaluation for Log Parsing Techniques: How Far Are We?” (ISSTA 2024, DOI)](https://doi.org/10.1145/3650212.3652123); [author preprint](https://arxiv.org/abs/2308.10828); [official repository](https://github.com/logpai/loghub-2.0); [archived dataset](https://zenodo.org/records/8275861). **Peer reviewed + artifact/dataset.**
- **Demonstrates:** Parser conclusions can change at realistic corpus scale and when evaluation includes template-level and rare-template behavior rather than only message-level grouping. The official corpus contains 14 systems and large per-system samples.
- **Limitations:** The benchmark measures parsing, not diagnostic sufficiency. Its systems and ground truth are still a finite historical sample, and later corrections show that parser labels themselves can be contestable.
- **Evidentrail decision — ADOPT AS A COMPONENT TRACK:** Pin the exact dataset revision and checksums. Report message-, template-, and rare-template behavior, runtime, peak memory, and deterministic repeatability. Never translate parser accuracy into an end-to-end diagnosis claim.

### Corrected public log-parsing ground truths

- **Source:** [“Corrected versions of LogHub, LogHub 2.0, LoFi, and Hybrid log parsing datasets” (Zenodo record, 2026)](https://zenodo.org/records/20752471). **Dataset.**
- **Demonstrates:** Public parsing labels can contain overlapping templates and ambiguous wildcard semantics; corrected labels distinguish one-word from multiword wildcards and revise several established datasets.
- **Limitations:** A later correction is an alternative curated ground truth, not proof that every remaining boundary is uniquely correct. Results against it are not directly interchangeable with results against the original labels.
- **Evidentrail decision — ADOPT FOR SENSITIVITY TESTING:** Preserve both original and corrected revisions. Publish which revision generated each result, measure conclusion changes, and manually audit disagreements that touch protected or rare events.

### PMSS label-free parser evaluation

- **Source:** [“A Story About Cohesion and Separation: Label-Free Metric for Log Parser Evaluation” (SANER 2026, DOI)](https://doi.org/10.1109/SANER67736.2026.00079); [author preprint](https://arxiv.org/abs/2512.21811); [official repository](https://github.com/mooselab/Label-Free-Metric-for-Log-Parser-Evaluation). **Peer reviewed + artifact.**
- **Demonstrates:** Parser clusters can be assessed without curated templates by combining within-cluster cohesion and between-cluster separation; the work also documents that ground-truth revisions can change parser rankings.
- **Limitations:** A cluster-geometry score is an indirect proxy and was not shown to replace labeled evaluation or downstream diagnosis testing. High separation does not prove preservation of causal evidence.
- **Evidentrail decision — DISABLED GROUPING-EXPERIMENT MONITOR:** Track PMSS-like cohesion/separation only when evaluating a feature-gated grouper. It is not an active v1 lane, release gate, truth label, or substitute for incident-level evidence recall.

### Deterministic parser preprocessing

- **Source:** [“Preprocessing is All You Need: Boosting the Performance of Log Parsers with a General Preprocessing Framework” (SANER 2025, DOI)](https://doi.org/10.1109/SANER64311.2025.00036); [author preprint](https://arxiv.org/abs/2412.05254). **Peer reviewed.**
- **Demonstrates:** Reusable deterministic transformations before parsing can materially alter the performance of otherwise unchanged parsers.
- **Limitations:** Masking can also remove the very identifiers, numbers, paths, or values needed for diagnosis. Improvements are parser- and benchmark-dependent.
- **Evidentrail decision — ADAPT REVERSIBLY WITHIN ACTIVE LANES:** Preprocessing may create derived features for lexical/typed-ID and failure/onset processing only. Each masked token retains offsets and a reversible pointer to its authorized retained basis; the ledger and protected evidence blocks remain untouched, and preprocessing cannot silently create another evidence lane.

### LILAC

- **Source:** [“LILAC: Log Parsing using LLMs with Adaptive Parsing Cache” (FSE 2024, DOI)](https://doi.org/10.1145/3643733); [author preprint](https://arxiv.org/abs/2310.01796). **Peer reviewed.**
- **Demonstrates:** Hierarchical sampling, demonstrations, and an adaptive cache can reduce repeated LLM parsing work and improve consistency across similar messages.
- **Limitations:** The parser depends on model behavior, prompting, cache state, and potentially an external API. Its evaluation target is template parsing, not provenance, exact expansion, or diagnosis.
- **Evidentrail decision — DISABLED FROM THE TRUSTED DATA PLANE; OFF-PATH BENCHMARK:** Do not put an LLM between ingestion and the authorized ledger. LILAC is not an active MVP lane; use it only as a later learned-parser baseline after deterministic admission gates, with cache invalidation and model-version pinning.

### DivLog

- **Source:** [“DivLog: Log Parsing with Prompt Enhanced In-Context Learning” (ICSE 2024, DOI)](https://doi.org/10.1145/3597503.3639155); [author/university publication record](https://ink.library.smu.edu.sg/sis_research/10674/). **Peer reviewed.**
- **Demonstrates:** Diversity-maximizing offline example selection plus per-message retrieval can make in-context LLM parsing more effective than using a fixed demonstration set.
- **Limitations:** Candidate examples require labels, the result depends on a proprietary model/prompt and a small retrieved set, and the evaluated output is a template rather than evidence-preserving diagnosis.
- **Evidentrail decision — OFF-PATH DATA-CURATION ADAPTATION; DISABLED PARSER BENCHMARK:** Use diversity coverage to choose offline labeling and evaluation examples. Prompted parsing is not an active MVP lane and never enters the authorized ingestion path.

### LogBatcher

- **Source:** [“Demonstration-Free: Towards More Practical Log Parsing with Large Language Models” (ASE 2024, DOI)](https://doi.org/10.1145/3691620.3694994); [updated author manuscript, titled “Stronger, Cheaper and Demonstration-Free Log Parsing with LLMs”](https://arxiv.org/abs/2406.06156); [author repository](https://github.com/LogIntelligence/LogBatcher). **Peer reviewed + artifact.**
- **Demonstrates:** Partitioning, diversity-aware batching, and caching can reduce redundant LLM calls without requiring labeled in-context demonstrations for each target dataset.
- **Limitations:** Results remain model-, prompt-, partition-, and cache-dependent. The unit is still normally a log message and the output is a template, not an auditable diagnostic brief.
- **Evidentrail decision — OFF-PATH SAMPLING ADAPTATION:** Reuse diversity selection for test-case construction and, later, training batches. V1 remains limited to the three active lanes; LogBatcher is a disabled learned-parser ablation.

### LibreLog

- **Source:** [“LibreLog: Accurate and Efficient Unsupervised Log Parsing Using Open-Source Large Language Models” (ICSE 2025, DOI)](https://doi.org/10.1109/ICSE55347.2025.00103); [author preprint](https://arxiv.org/abs/2408.01585); [official repository](https://github.com/zeyang919/LibreLog). **Peer reviewed + artifact.**
- **Demonstrates:** An open-weight local model can be combined with grouping, diverse retrieval, self-reflection, and memory to perform unsupervised log-template parsing without a hosted proprietary model.
- **Limitations:** Local execution does not make outputs deterministic or integrity-preserving. Compute, model version, memory state, and prompt still influence results, and parsing metrics do not establish diagnostic utility.
- **Evidentrail decision — DISABLED BENCHMARK / FUTURE TRAINING REFERENCE:** Evaluate it under pinned weights and offline execution only after deterministic gates pass. It is not an active MVP lane and never receives authority over event boundaries, retention, or evidence identity.

### UNLEASH

- **Source:** [“Unleashing the True Potential of Semantic-Based Log Parsing with Pre-Trained Language Models” (ICSE 2025, DOI)](https://doi.org/10.1109/ICSE55347.2025.00174); [official repository](https://github.com/LogIntelligence/UNLEASH); [author manuscript record](https://orbilu.uni.lu/handle/10993/67305). **Peer reviewed + artifact.**
- **Demonstrates:** Entropy-based example selection, contrastive training, and optimized inference can make a smaller pretrained language model useful for semantic log parsing.
- **Limitations:** The method still requires learned parameters and representative samples, is sensitive to domain shift, and is evaluated for parsing rather than incident evidence selection.
- **Evidentrail decision — DISABLED FUTURE ABLATION:** Test as a learned grouping/ranking experiment only after the three deterministic active lanes and gates are stable. Admission requires held-out unique evidence yield per cost and overmerge/recall ablations; even then, it may add candidates but cannot veto protected blocks or raw-coverage sentinels.

### LUNAR

- **Source:** [“No More Labelled Examples? An Unsupervised Log Parser with LLMs” (FSE 2025, DOI)](https://doi.org/10.1145/3729377); [official repository](https://github.com/logpai/LUNAR); [author manuscript](https://zbchern.github.io/papers/fse25b.pdf). **Peer reviewed + artifact.**
- **Demonstrates:** Contrastive examples exposing commonality and variability can guide an LLM parser without manually labeled target examples.
- **Limitations:** It remains an LLM template parser whose behavior depends on the model and prompts. Template correctness is not sufficient for incident diagnosis, and revised public ground truths complicate direct cross-paper comparisons.
- **Evidentrail decision — OFF-PATH CONTRASTIVE TEST; DISABLED PARSER BENCHMARK:** Use minimally different event pairs to stress grouping experiments and later learned models. LUNAR is not an active MVP lane or trusted ingestion dependency.

### PIPLUP

- **Source:** [“Plug it and Play on Logs: A configuration-free statistic-based log parser” (Empirical Software Engineering, DOI)](https://doi.org/10.1007/s10664-026-10870-y); [author preprint](https://arxiv.org/abs/2508.09366). **Peer reviewed.**
- **Demonstrates:** A statistic-based, configuration-free parser can avoid the common assumption that fixed token positions always represent constants, while remaining suitable for local CPU execution.
- **Limitations:** Its objective is still template recovery. Claims of broad generalization rest on the evaluated open datasets and do not prove behavior on every proprietary source grammar.
- **Evidentrail decision — STRONG NON-LLM BASELINE; DISABLED AS A LANE:** Compare it with canonical Drain/Logram and Evidentrail's exact-key/token-shape grouping experiments. Borrow source-agnostic statistical cues only in feature-gated tests; activation still requires held-out unique-yield, overmerge, recall-cost, and leave-one-lane-out evidence.

### MicLog

- **Source:** [“MicLog: Towards Accurate and Efficient LLM-based Log Parsing via Progressive Meta In-Context Learning” (AAAI 2026)](https://ojs.aaai.org/index.php/AAAI/article/view/37123); [DOI](https://doi.org/10.1609/aaai.v40i2.37123); [author preprint](https://arxiv.org/abs/2601.07005). **Peer reviewed.**
- **Demonstrates:** Progressive meta in-context learning combines clustered sample selection, retrieval, and multilevel caching to specialize a smaller model for log parsing.
- **Limitations:** Training still uses log/template supervision, and outcomes depend on trained weights, retrieval, and cache state. The task ends at template parsing.
- **Evidentrail decision — DISABLED FUTURE TRAINING REFERENCE:** Use its curriculum, retrieval, and cache ablations only when designing the optional later Evidentrail model. MicLog is not an active MVP lane or part of the deterministic critical path.

**Parsing synthesis.** No reviewed parser supplies the full product invariant. V1 reconstructs atomic blocks over the authorized retained ledger, may annotate exact provider event keys and conservative token-shape fingerprints, and keeps Drain/tree, n-gram, other grouping-derived selection, and learned parsing disabled. A parser can become an evidence proposer only after held-out unique-yield, incompatible-overmerge, recall-cost, and leave-one-lane-out gates pass. Proposer agreement is never treated as validation. Parsing remains separately evaluated from evidence recall and diagnosis.

---

## 2. Lossless storage compression

### LogReducer

- **Source:** [“On the Feasibility of Parser-based Log Compression in Large-Scale Cloud Systems” (FAST 2021)](https://www.usenix.org/conference/fast21/presentation/wei). **Peer reviewed; official proceedings page includes the paper and slides.**
- **Demonstrates:** Parser-derived structure can support lossless encoding of timestamps, repeated fields, numeric sequences, and correlated variables in large log corpora.
- **Limitations:** Compression ratio and throughput are storage objectives. Parser or type mistakes add implementation risk, and the work does not test whether a selected subset is sufficient for diagnosis.
- **Evidentrail decision — POST-MVP OPTIONAL ARCHIVE CODEC:** Reuse typed delta and correlation transforms only behind byte-for-byte retained-basis round-trip tests, corruption tests, versioned schemas, and a verbatim fallback. This is not an evidence lane; never optimize the diagnostic brief for archive compression ratio.

### LogBlock

- **Source:** [“Improving State-of-the-Art Compression Techniques for Log Management Tools” (IEEE TSE, DOI)](https://doi.org/10.1109/TSE.2021.3069958); [official replication repository](https://github.com/SAILResearch/suppmaterial-21-kundi-logblock). **Peer reviewed + artifact.**
- **Demonstrates:** Header separation, columnar/transposed organization, delta transforms, dictionaries, and prefix handling can improve general-purpose compression of small log blocks.
- **Limitations:** Results depend on block size, log format, and the downstream compressor. The method does not rank diagnostic evidence and its optimal physical block need not match a semantic incident block.
- **Evidentrail decision — POST-MVP STORAGE EXPERIMENT:** Evaluate its transforms for packed immutable segments after the evidence MVP. Keep physical storage blocks independent from atomic event and evidence-selection boundaries.

### Denum

- **Source:** [“Unlocking the Power of Numbers: Log Compression via Numeric Token Parsing” (ASE 2024, DOI)](https://doi.org/10.1145/3691620.3695474); [author preprint](https://arxiv.org/abs/2408.05760); [author repository](https://github.com/gaiusyu/Denum). **Peer reviewed + artifact.**
- **Demonstrates:** Separating numeric tokens from surrounding text and applying type-appropriate/delta encodings can expose redundancy that byte-oriented compression misses.
- **Limitations:** A numeric-looking token may be an opaque identifier rather than a measurement or sequence. A type error can make a representation misleading even if a decoder can reproduce bytes.
- **Evidentrail decision — POST-MVP CODEC ADOPTION ONLY AFTER TYPE PROOF:** The active typed-ID lane may validate identifier classes, but numeric archive transforms are separate and later. They require source-schema evidence or a conservative classifier with an opaque fallback; IDs, hashes, ports, versions, and status codes remain categorical unless explicitly declared otherwise.

### LogShrink

- **Source:** [“LogShrink: Effective Log Compression by Leveraging Commonality and Variability of Log Data” (ICSE 2024, DOI)](https://doi.org/10.1145/3597503.3608129); [author preprint](https://arxiv.org/abs/2309.09479); [official repository](https://github.com/IntelligentDDS/LogShrink). **Peer reviewed + artifact.**
- **Demonstrates:** Longest-common-subsequence and entropy analyses can separate common and variable material before lossless compression, with clustering-based sampling used to control analyzer cost.
- **Limitations:** Its target is archive compression, and sampled/common material is not a diagnostic-importance signal. Its analysis and format assumptions still require exact decompression and cross-source tests.
- **Evidentrail decision — POST-MVP CODEC BENCHMARK / OFF-PATH DIVERSITY TESTS:** Include it in later storage experiments and borrow commonality/variability pairs for feature-gated grouper stress tests. It is not an evidence lane, and its entropy or sampling decision cannot omit incident evidence.

### DeLog

- **Source:** [“DeLog: An Efficient Log Compression Framework with Pattern Signature Synthesis”](https://arxiv.org/abs/2601.15084); [author repository](https://github.com/gaiusyu/Delog). **Preprint + artifact.**
- **Demonstrates:** Pattern signatures can group streams for compression even when higher parser accuracy does not translate directly into a better compression ratio. The artifact includes compression and recovery workflows.
- **Limitations:** The work is a preprint; private production datasets are not available for independent reproduction. The repository uses a different subtitle (“Pattern-based Grouping”) and notes that new variable types may require custom recovery handling.
- **Evidentrail decision — WATCH + POST-MVP CODEC BENCHMARK:** Test round-trip fidelity, corruption isolation, memory, and random-access cost on public and synthetic corpora after the evidence MVP. Do not adopt its signatures as evidence truth or its compression objective as a selection score.

### LogPrism

- **Source:** [“LogPrism: Unifying Structure and Variable Encoding for Effective Log Compression”](https://arxiv.org/abs/2601.17482). **Preprint.**
- **Demonstrates:** The paper proposes a unified redundancy structure intended to capture both log templates and relations among variables instead of compressing those streams independently.
- **Limitations:** As of the cutoff, this ledger could not verify a usable author-linked implementation artifact. The result is preprint evidence about storage compression, not evidence selection or root-cause diagnosis.
- **Evidentrail decision — WATCH, NOT MVP:** Revisit when a reproducible artifact and stable paper record exist. We may later test the conceptual hypothesis—joint structure/variable co-occurrence can aid an archive codec—without creating a product dependency, active evidence lane, or product claim.

**Storage synthesis.** A post-MVP archive layer may use specialized, lossless transforms, but the acceptance criterion is exact round trip relative to each event's declared authorized basis under versioning and corruption tests. The evidence compiler operates on stable event identities and retained-basis spans; it is never allowed to equate “compresses well” with “safe to omit.”

---

## 3. Anomaly, sequence, and change signals

### DeepLog

- **Source:** [“DeepLog: Anomaly Detection and Diagnosis from System Logs through Deep Learning” (CCS 2017, DOI)](https://doi.org/10.1145/3133956.3134015). **Peer reviewed.**
- **Demonstrates:** A recurrent model of normal log-key sequences can propose deviations and support workflow-level investigation.
- **Limitations:** The method inherits parser and session/window assumptions, requires representative training data, and conflates novelty with possible fault evidence. Its datasets and model architecture predate modern distributed telemetry practice.
- **Evidentrail decision — DISABLED ANOMALY EXPERIMENT + BENCHMARK:** Keep DeepLog as a historical baseline. Sequence-surprise output is not an active MVP lane and may be admitted only after held-out unique-yield, recall-cost, leave-one-lane-out, and protected-slice tests. It never establishes root cause.

### LogAnomaly

- **Source:** [“LogAnomaly: Unsupervised Detection of Sequential and Quantitative Anomalies in Unstructured Logs” (IJCAI 2019, DOI)](https://doi.org/10.24963/ijcai.2019/658); [official proceedings PDF](https://www.ijcai.org/proceedings/2019/0658.pdf). **Peer reviewed.**
- **Demonstrates:** Sequential patterns and event-count patterns provide complementary anomaly signals, and semantic representations can approximate unseen templates.
- **Limitations:** Evaluation covers a limited set of systems. Approximation of unseen templates may merge a novel rare failure with a familiar event, and anomaly classification does not establish cause.
- **Evidentrail decision — DISABLED ANOMALY EXPERIMENT:** Evaluate sequential/quantitative deltas off-path. The active failure/onset/raw-coverage lane may use transparent bounded count and onset facts, but LogAnomaly-style semantic approximation and anomaly selection remain disabled until held-out unique-yield and recall-cost ablations pass; raw-coverage sentinels protect unseen events.

### LogBERT

- **Source:** [“LogBERT: Log Anomaly Detection via BERT” (IJCNN 2021, DOI)](https://doi.org/10.1109/IJCNN52387.2021.9534113); [author preprint](https://arxiv.org/abs/2103.04475); [official repository](https://github.com/HelenGuohx/logbert). **Peer reviewed + artifact.**
- **Demonstrates:** Bidirectional self-supervision over log-event sequences can learn an anomaly detector without labeled faults.
- **Limitations:** Results depend on parsing, session/window construction, training distribution, and thresholds. A binary anomaly endpoint gives neither exact evidence completeness nor a causal diagnosis.
- **Evidentrail decision — DISABLED FUTURE LEARNED BASELINE:** Compare against it only after the active lanes are stable. Admission requires held-out unique-yield and leave-one-lane-out recall under the full cost vector; its score can never remove mandatory, protected, or raw-coverage candidates.

### LogFormer

- **Source:** [“LogFormer: A Pre-train and Tuning Pipeline for Log Anomaly Detection” (AAAI 2024)](https://ojs.aaai.org/index.php/AAAI/article/view/27764); [DOI](https://doi.org/10.1609/aaai.v38i1.27764). **Peer reviewed.**
- **Demonstrates:** Pretraining plus parameter-efficient adaptation can transfer a log anomaly model across systems while retaining parameter information in the representation.
- **Limitations:** Cross-domain adaptation still needs representative data and validation, and the evaluated endpoint remains anomaly detection rather than evidence-grounded diagnosis.
- **Evidentrail decision — DISABLED FUTURE CROSS-DOMAIN BASELINE:** Test off-path as an optional learned-anomaly proposer, not an MVP lane. Independently preserve typed parameter fields and retained-basis spans so model attention is never the only route to a value; require the same unique-yield, overmerge/recall, and cost gates before admission.

### Parsing quality versus anomaly quality

- **Source:** [“Impact of Log Parsing on Deep Learning-Based Anomaly Detection” (Empirical Software Engineering, DOI)](https://doi.org/10.1007/s10664-024-10533-w); [author preprint](https://arxiv.org/abs/2305.15897). **Peer reviewed.**
- **Demonstrates:** Across the evaluated parser/detector combinations, conventional parsing accuracy was not a reliable proxy for anomaly-detection performance; the distinguishability induced by parsed sequences mattered.
- **Limitations:** The empirical scope is a finite set of public datasets, parsers, and anomaly models. The study does not show that parsing quality is irrelevant to exact evidence retrieval or diagnosis.
- **Evidentrail decision — ADOPT THE METRIC SEPARATION:** Report parsing, candidate recall, packed-evidence recall, anomaly quality, diagnosis, citation, latency, and cost independently. No component proxy may stand in for the product outcome.

### BARO

- **Source:** [“BARO: Robust Root Cause Analysis for Microservices via Multivariate Bayesian Online Change Point Detection” (FSE 2024, DOI)](https://doi.org/10.1145/3660805); [author preprint](https://arxiv.org/abs/2405.09330); [official repository](https://github.com/phamquiluan/baro). **Peer reviewed + artifact.**
- **Demonstrates:** Multivariate Bayesian online change-point detection plus robust nonparametric scoring can rank anomalous service metrics under noisy microservice fault experiments.
- **Limitations:** It is primarily metrics-based, evaluated under controlled fault injection, and outputs rankings rather than exact causal log evidence. Temporal proximity is not causality.
- **Evidentrail decision — ADAPT ONLY TRANSPARENT ONSET/CHANGE PRIMITIVES:** The active failure/onset/raw-coverage lane may use bounded, inspectable count/rate and typed-value changes with pre/post context. BARO's multivariate RCA ranker remains a disabled anomaly experiment until held-out unique-yield and recall-cost ablations pass. All outputs are “change evidence,” never “root cause.”

### Onion

- **Source:** [“Onion: Identifying Incident-indicating Logs for Cloud Systems” (ESEC/FSE 2021, DOI)](https://doi.org/10.1145/3468264.3473919); [official Microsoft Research record](https://www.microsoft.com/en-us/research/publication/onion-identifying-incident-indicating-logs-for-cloud-systems/). **Peer reviewed.**
- **Demonstrates:** Incident-aware representations, progressive clustering, and contrast analysis between log cliques can localize incident-indicating logs using consistency, impact, and bilateral-difference criteria. The paper also reports application in a Microsoft cloud setting.
- **Limitations:** Its learned/engineered representation and incident labels reflect the studied services, and “incident-indicating” is still not equivalent to a complete causal explanation. Clustering can hide unique events if it becomes an exclusion gate.
- **Evidentrail decision — DISABLED REFERENCE-WINDOW EXPERIMENT + BENCHMARK:** Onion motivates a reference/contrast study, but reference-derived selection is not an active MVP lane. Admit it only after pre-content reference eligibility, placebo/multi-control sensitivity, held-out unique-yield, leave-one-lane-out recall, incompatible-overmerge, and full-cost gates pass. It may add candidates but never erase raw-coverage sentinels.

**Anomaly synthesis.** V1 exposes only transparent onset/change facts inside the active complete-failure/onset/raw-coverage lane. Group-derived rarity, reference contrasts, sequence-surprise models, embeddings, and learned anomaly lanes are disabled experiments. They are evaluated on held-out unique candidate yield, leave-one-lane-out recall, protected-slice behavior, incompatible-overmerge where applicable, and the full candidate-cost vector; none receives omission or causal authority.

---

## 4. Evidence and context compression for language models

### RECOMP

- **Source:** [“RECOMP: Improving Retrieval-Augmented LMs with Compression and Selective Augmentation” (ICLR 2024)](https://proceedings.iclr.cc/paper_files/paper/2024/file/bda88ed2892f5e61c9a9bf215c566913-Paper-Conference.pdf); [author preprint](https://arxiv.org/abs/2310.04408); [official repository](https://github.com/carriex/recomp). **Peer reviewed + artifact.**
- **Demonstrates:** A compressor can be trained against downstream reader utility rather than lexical similarity, with extractive and abstractive variants and the ability to decline augmentation when retrieved context is unhelpful.
- **Limitations:** The source units are natural-language passages and the tasks are language-model benchmarks. Abstractive compression can alter facts; sentence extraction does not preserve log event boundaries, IDs, stack traces, or exact expansion.
- **Evidentrail decision — FUTURE TRAINING OBJECTIVE; REJECT ABSTRACTION IN THE TRUSTED ARTIFACT:** RECOMP does not create an active MVP lane. Train later rankers against downstream evidence/diagnosis utility and allow abstention only after the three active lanes establish frozen candidates and gates. The production brief selects intact blocks exact to their authorized retained basis; any generated synopsis is visibly secondary and cites those blocks.

### LLMLingua-2

- **Source:** [“LLMLingua-2: Data Distillation for Efficient and Faithful Task-Agnostic Prompt Compression” (ACL Findings 2024)](https://aclanthology.org/2024.findings-acl.57/); [author preprint](https://arxiv.org/abs/2403.12968); [official Microsoft repository](https://github.com/microsoft/LLMLingua). **Peer reviewed + artifact.**
- **Demonstrates:** A bidirectional token classifier distilled from synthetic compression supervision can perform extractive, task-agnostic prompt compression efficiently.
- **Limitations:** Token deletion can break paths, identifiers, exception chains, code, JSON, and log grammar even when the remaining prose looks fluent. The evaluated tasks do not establish byte fidelity, atomic event preservation, or incident evidence recall.
- **Evidentrail decision — MANDATORY BASELINE; REJECT TOKEN DELETION FOR PROTECTED EVIDENCE:** Compare token budget and downstream diagnosis against it. It may later supply off-path token-importance features, but selected blocks exact to their authorized retained basis and required fields are indivisible; it is not an active lane.

### LoFI

- **Source:** [“Demystifying and Extracting Fault-indicating Information from Logs for Failure Diagnosis” (ISSRE 2024, DOI)](https://doi.org/10.1109/ISSRE62328.2024.00055); [author preprint](https://arxiv.org/abs/2409.13561); [official repository and released data](https://github.com/Jun-jie-Huang/LoFI). **Peer reviewed + artifact/dataset.**
- **Demonstrates:** A coarse semantic filter followed by prompt-tuned extraction can label fault-indicating descriptions and parameters, turning a broad anomaly session into finer evidence roles. The paper evaluates a fault-injected Spark benchmark and an industrial dataset.
- **Limitations:** The role taxonomy, severe-level seed, semantic similarity, and tuned model can miss quiet precursors or novel fault forms. The industrial distribution is not public in full, and role extraction is not a complete causal diagnosis.
- **Evidentrail decision — ADOPT THE LABEL SCHEMA; DISABLED MODEL BASELINE:** Add description, entity/parameter, symptom, cause, consequence, and fix-evidence roles to offline annotation. LoFI remains an off-path learned selector/extractor baseline and is not an MVP lane; admission requires held-out unique-yield and full-cost ablations. Its output can never delete blocks before protected/raw-coverage gates.

### LogSieve

- **Source:** [“LogSieve: Task-Aware CI Log Reduction for Sustainable LLM-Based Analysis” (MSR 2026, DOI)](https://doi.org/10.1145/3793302.3793380); [author preprint](https://arxiv.org/abs/2601.20148); [author manuscript](https://safwathassan.com/publications/LogSieve_MSR.pdf). **Peer reviewed.**
- **Demonstrates:** CI-line relevance can be modeled explicitly before LLM inference, and reduced logs can be evaluated on token/line savings together with semantic and downstream failure-analysis measures rather than storage ratio alone.
- **Limitations:** The study is confined to GitHub Actions logs from open-source Android projects. Similarity and category/explanation scores do not prove requirement-level evidence completeness, and independent line classification can sever multiline or causal context.
- **Evidentrail decision — MANDATORY CI BASELINE / ADAPT THE TASK LABELS:** Reproduce the released method on family-held-out cases. Replace independent line deletion with atomic-block selection, explicit protected categories, exact evidence IDs, omission audits, and downstream diagnosis/citation scoring.

### Long-context position effects

- **Source:** [“Lost in the Middle: How Language Models Use Long Contexts” (TACL 2024)](https://aclanthology.org/2024.tacl-1.9/); [DOI](https://doi.org/10.1162/tacl_a_00638). **Peer reviewed.**
- **Demonstrates:** In the evaluated retrieval and question-answering settings, model performance depends on where relevant information appears in a long context; merely increasing context length does not guarantee reliable use of all evidence.
- **Limitations:** The experiments are not log-diagnosis trials, and model/context implementations continue to evolve. Position effects are a risk to test, not a universal fixed curve.
- **Evidentrail decision — ADOPT POSITIONAL TESTS:** Put the strongest evidence and compact incident map first, keep exact source order within blocks, and evaluate multiple orderings and distractor loads. A larger window does not relax evidence-budget discipline.

**Context-compression synthesis.** Natural-language compression research validates downstream-utility objectives and selective context, but not destructive mutation of machine evidence. Evidentrail's trusted output is an extractive, block-addressable dossier whose expansion is exact relative to each retained authorization basis. Any LLM-written summary is a convenience layer with citations and an explicit abstention path, not an active evidence lane.

---

## 5. CI, root-cause, and interactive operations benchmarks

### LogDx-CI

- **Source:** [“LogDx-CI: Benchmarking Log Reduction Tools for LLM Root-Cause Diagnosis”](https://arxiv.org/abs/2605.28876); [official benchmark site](https://logdx-bench.github.io/); [official repository](https://github.com/eyuansu62/LogDx). **Preprint + artifact.**
- **Demonstrates:** Log reduction can be evaluated by downstream root-cause diagnosis and token use, in both single-shot and iterative/tool-assisted settings, rather than by compression ratio alone. It also establishes simple filtering/tail-style methods as serious baselines.
- **Limitations:** The current benchmark release is small (the repository documents 35 cases), uses AI-assisted drafting plus single-author verification for ground truth, covers a limited model set, and documents exclusions. Some reducer design choices were iterated on the benchmark, which creates overfitting risk.
- **Evidentrail decision — ADOPT AS ONE PUBLIC CI TRACK:** Reproduce pinned versions of raw, grep/filter, tail, and published reducer baselines. Add requirement-level evidence labels, independent adjudication, prompt/model version pins, and family-held-out splits. Never make its leaderboard the sole product claim.

### RCAEval

- **Source:** [“RCAEval: A Benchmark for Root Cause Analysis of Microservice Systems with Telemetry Data” (WWW Companion 2025, DOI)](https://doi.org/10.1145/3701716.3715290); [author preprint](https://arxiv.org/abs/2412.17015); [official repository](https://github.com/phamquiluan/RCAEval); [archived dataset](https://zenodo.org/records/14590730). **Peer reviewed + artifact/dataset.**
- **Demonstrates:** Logs, metrics, and traces from repeatable microservice fault injections can support standardized RCA baselines and ranked-root-cause evaluation. The current official repository enumerates 735 cases across its included datasets.
- **Limitations:** Injected faults in a finite set of benchmark systems do not reproduce every production incident. Root-cause localization is narrower than producing a complete, evidence-cited diagnosis and safe fix, and closely related trials can leak across naive random splits.
- **Evidentrail decision — ADOPT AS A SEPARATE MULTI-TELEMETRY TRACK:** Split by system, fault family, and injection campaign; keep variants together. Measure candidate/evidence recall and ranked localization, but do not pool these scores with CI failures or real incidents.

### AIOpsLab

- **Source:** [“AIOpsLab: A Holistic Framework for Evaluating AI Agents for Enabling Autonomous Cloud” (MLSys 2025, official Microsoft Research record)](https://www.microsoft.com/en-us/research/publication/aiopslab-a-holistic-framework-for-evaluating-ai-agents-for-enabling-autonomous-cloud/); [author preprint](https://arxiv.org/abs/2501.06706); [official repository](https://github.com/microsoft/AIOpsLab). **Peer reviewed + artifact.**
- **Demonstrates:** A benchmark can deploy microservices, generate workloads and faults, collect telemetry, expose tools to an agent, and evaluate interactive operational tasks in a controlled environment.
- **Limitations:** A lab Kubernetes environment and its task library are not the full production distribution. Interactive agents are nondeterministic, and remediation success mixes diagnosis quality with tool policy and action execution.
- **Evidentrail decision — ADOPT AS A HERMETIC TOOL-LOOP TRACK:** Run Evidentrail read-only as the evidence layer. Score diagnosis and cited evidence before scoring any remediation agent; tool permissions and action safety remain separate systems.

**Benchmark synthesis.** No single public suite is the product benchmark. EvidentrailBench must retain distinct tracks for parser components (Loghub-2.0), CI diagnosis (LogDx-CI), injected multi-telemetry RCA (RCAEval), interactive lab incidents (AIOpsLab), synthetic invariants/adversaries, and blinded real incidents. Scores are reported by track and failure family, not collapsed into one flattering aggregate.

---

## 6. Neuro-symbolic log diagnosis

### Log-Insight

- **Source:** [“Log-Insight: Automating Microservice Incident Diagnosis via Neuro-Symbolic Log Analysis”](https://arxiv.org/abs/2607.08529). **Preprint.**
- **Demonstrates:** A staged pipeline can perform log sampling, schema extraction, knowledge-base construction, entropy/pattern analysis, incident-versus-reference skew analysis, and only then use an LLM to synthesize a diagnosis from a compact evidence report. The paper reports a production deployment study.
- **Limitations:** The reported incident evaluation is small (11 historical incidents with repeated runs) and from one organizational setting. Fixed thresholds, two-pass sampling, character caps, success/error classification, and raw-sample fallbacks can omit evidence or bind behavior to local conventions. No independently reusable benchmark artifact was verified in this ledger.
- **Evidentrail decision — ADOPT THE SYMBOLIC-BEFORE-NEURAL SHAPE; KEEP EXTRA LANES DISABLED:** V1 produces a transparent dossier from the three active lanes with exact event IDs, validated typed identifiers, complete failure/onset context, raw-coverage sentinels, provider-attested correlations, and uncertainty before optional synthesis. Log-Insight-style template/pattern and incident/reference features remain disabled experiments until held-out unique-yield and full-cost ablations pass. Reject fixed universal thresholds, destructive first-pass sampling, and uncited raw-to-LLM fallback; include a faithful Log-Insight-like baseline where disclosed details permit reproduction.

**Neuro-symbolic synthesis.** Log-Insight is close to the desired product shape but is not the foundation. Evidentrail starts from immutable blocks exact to the authorized retained basis, the three active MVP lanes, deterministic budgeted selection, explicit acquisition/presentation receipts, and adversarial invariants. The LLM sees the dossier and may explain it; it does not decide which bytes were authorized, retained, transformed, or omitted.

---

## 7. Prompt injection and authority separation

### LogJack

- **Source:** [“LogJack: Indirect Prompt Injection Through Cloud Logs Against LLM Debugging Agents”](https://arxiv.org/abs/2604.15368); [author repository](https://github.com/HarshShah1997/logjack). **Preprint + artifact.**
- **Demonstrates:** Adversarial strings embedded in realistic cloud-log fields can influence tool-using debugging agents, and log formatting can frustrate input-only filtering. The released benchmark contains 42 payloads across five cloud-log categories.
- **Limitations:** The work is a preprint with hand-constructed payloads and a simulated/intercepted tool environment; its labels and model snapshot are not a complete threat model. It evaluates attacks rather than proving a defense.
- **Evidentrail decision — ADOPT THE ADVERSARIAL SUITE AND HARD BOUNDARY:** All source text is tainted data. It cannot set instructions, policies, authorization scope, executable arguments, URLs, or tool calls. The evidence compiler has no action authority; displays escape control characters; generated diagnoses quote through stable IDs; and tests include encoded, fragmented, multiline, and cross-event attacks. Prompt wording and regex filters are defense-in-depth only.

### CaMeL

- **Source:** [“Defeating Prompt Injections by Design”](https://arxiv.org/abs/2503.18813); [official Google Research repository](https://github.com/google-research/camel-prompt-injection). **Preprint + artifact.**
- **Demonstrates:** Separating trusted control flow from untrusted data flow and enforcing capabilities can prevent injected data from directly determining sensitive tool operations in an agent architecture.
- **Limitations:** The repository explicitly presents a research implementation rather than a production system; supported program/task patterns and capability policies constrain utility, and implementation defects remain possible.
- **Evidentrail decision — ADAPT AT INTEGRATION BOUNDARIES:** Preserve taint labels and capability checks if Evidentrail later feeds an action agent. The v1 safety rule is simpler and stronger: Evidentrail compiles evidence and has no mutation or remediation tools.

**Security synthesis.** “The prompt says to ignore instructions in logs” is not a security boundary. The enforceable boundary is architectural: untrusted evidence cannot flow into authority-bearing fields, and the evidence product itself cannot act.

---

## 8. Grounding, evidence selection, and evaluation

### Submodular coverage for summarization

- **Source:** [“A Class of Submodular Functions for Document Summarization” (ACL 2011)](https://aclanthology.org/P11-1052/). **Peer reviewed.**
- **Demonstrates:** Monotone submodular functions can encode representativeness and diversity, enabling efficient greedy construction of extractive summaries under suitable constraints.
- **Limitations:** The work targets documents and summary quality proxies, not exact incident blocks, protected evidence, typed facets, or diagnostic completeness. A function is not submodular merely because it contains a “coverage” term.
- **Evidentrail decision — ADOPT WITH PROPERTY TESTS:** For MVP, define nonnegative production-computable top-k facility coverage only over facets emitted by the three active lanes: source/time, lexical and validated typed IDs, complete failure/onset/raw coverage, and provider-attested bounded correlations. Provider-attested relations admit the two best affinities from distinct selected packets at one-half endpoint weight; every other facet remains top-one. This measured refinement fixes an oracle-feasible objective-saturation residual without adding a non-submodular complement bonus; it is frozen in [`ADR 0005`](adr/0005-provider-relation-top-two-coverage.md). Group-, reference-, anomaly-, embedding-, and LLM-derived facets remain disabled with their lanes. Freeze features, cardinalities, and weights per benchmark run; verify normalization, monotonicity, diminishing returns, deterministic tie-breaking, disjoint member accounting, and exact cost accounting on generated cases.

### Monotone submodular maximization under a knapsack budget

- **Source:** [“A Note on Maximizing a Submodular Set Function Subject to a Knapsack Constraint” (Operations Research Letters 2004, DOI)](https://doi.org/10.1016/S0167-6377%2803%2900062-2). **Peer reviewed.**
- **Demonstrates:** For a nonnegative monotone submodular objective with one knapsack constraint, a partial-enumeration algorithm attains the classical \(1-1/e\) approximation guarantee.
- **Limitations:** The guarantee depends on the stated objective and algorithm; the cited construction is computationally heavier than plain density greedy. A “greedy plus best singleton” implementation must not inherit a guarantee it did not implement.
- **Evidentrail decision — ADOPT THE DISCIPLINE, NOT AN UNIMPLEMENTED CLAIM:** Ship deterministic marginal-gain-per-cost greedy plus best-singleton as the transparent baseline. Benchmark bounded seed enumeration. Claim an approximation factor only if the implemented algorithm and all assumptions match the proof; otherwise report empirical regret against exact solutions on small cases.

### ALCE citation evaluation

- **Source:** [“Enabling Large Language Models to Generate Text with Citations” (EMNLP 2023)](https://aclanthology.org/2023.emnlp-main.398/); [official repository](https://github.com/princeton-nlp/ALCE). **Peer reviewed + artifact.**
- **Demonstrates:** Citation quality should be evaluated separately from response fluency and correctness, including whether cited material supports claims and whether claims have sufficient citation coverage.
- **Limitations:** ALCE is built around open-domain question answering and textual documents. Automatic entailment/citation metrics are imperfect and do not establish source-byte identity or operational correctness.
- **Evidentrail decision — ADOPT SEPARATE CITATION DIMENSIONS:** Every factual diagnostic claim resolves to stable event/block IDs. Score diagnosis correctness, citation entailment, citation completeness, invalid-ID rate, and unsupported-claim rate separately, with deterministic and human checks where appropriate.

### RAGChecker

- **Source:** [“RAGChecker: A Fine-grained Framework for Diagnosing Retrieval-Augmented Generation”](https://arxiv.org/abs/2408.08067); [official Amazon Science repository](https://github.com/amazon-science/RAGChecker). **Paper + artifact.**
- **Demonstrates:** Retrieval and generation failures can be decomposed into claim-level diagnostics instead of hidden inside one answer score, separating context coverage/precision from use and hallucination behavior.
- **Limitations:** Its model-based claim and entailment metrics target question answering and require reference answers. They are not a substitute for deterministic event IDs, byte spans, or incident-specific required-evidence labels.
- **Evidentrail decision — ADAPT THE DECOMPOSITION:** Measure candidate recall, packed-context recall, context precision, evidence utilization, citation correctness/completeness, and unsupported synthesis separately. Deterministic required-event and required-block annotations remain primary where available.

### Position and selective-context cross-checks

- **Sources:** [RECOMP](https://arxiv.org/abs/2310.04408), [LLMLingua-2](https://aclanthology.org/2024.findings-acl.57/), and [Lost in the Middle](https://aclanthology.org/2024.tacl-1.9/).
- **Demonstrates:** Context value is task-dependent, irrelevant context can be withheld, and relevant material may be underused depending on position; context length alone is not an evaluation.
- **Limitations:** These are natural-language LM studies rather than exact log-evidence benchmarks.
- **Evidentrail decision — ADOPT AS EVAL STRESSORS:** Sweep budgets, distractor density, order, duplicate volume, and reader model. Report a Pareto surface for evidence recall, diagnosis quality, tokens, latency, and determinism instead of a single compression percentage.

---

## 9. Architecture and benchmark traceability

### Canonical method-admission map

The controlling gate definitions are in the implementation plan's [canonical method-admission matrix](GREENFIELD_EXECUTION_PROGRAM.md#canonical-method-admission-matrix): `T` is the non-negotiable trust/contract gate; `U` requires statistically positive held-out lane-unique yield and leave-one-lane-out recall contribution plus product non-inferiority, a Pareto win, slice floors, and resource caps; `G` adds zero incompatible overmerge and full grouping accounting; `R` adds eligible-reference, placebo, multi-control, and partial-acquisition rules; `M` adds split isolation, frozen training provenance, versioning, calibration/variance, privacy/licensing/deletion, and adaptive-injection tests. `X1` starts after deterministic Wave 2 freezes, `X2` starts only after the separate LLM-training boundary, and `P1` requires a separate post-MVP charter.

This table mirrors the plan; the plan controls if the two ever drift.

| Method family | Status | Why | Exact admission gate | Code phase |
| --- | --- | --- | --- | --- |
| Policy sink, authorized ledger, exactness bases, three receipts | **Active v1** | Defines retained truth and every loss boundary | `T` plus crash/cancel/partial receipt reconciliation | W0–W1 |
| Source-aware atomic blocks | **Active v1** | Protects diagnostic structures from splitting | `T` plus golden framing, ambiguity, and cap fixtures | W1–W2 |
| Reversible deterministic preprocessing for active-lane features | **Active v1** | Helps typed extraction and retrieval without mutating evidence | `T`; retained-basis offset map, mask/unmask metamorphic tests, opaque fallback, intact protected blocks, no new lane | W1–W2 |
| Exact event-key and token-shape annotations only | **Active v1** | Deterministic metadata without omission power | `T`; annotation cannot change candidates, mandatory status, or retained bytes | W2 |
| Evidence lane 1 — lexical + validated typed identifiers | **Active v1** | Cheap question-directed evidence lane | `T`; active-v1 `R_macro(K) >= R0`, typed-ID false-mandatory and slice floors | W2 |
| Evidence lane 2 — complete failures + transparent onset/change + raw coverage | **Active v1** | Complete failure context and blind-spot protection | `T`; active-v1 `R_macro(K) >= R0`, complete-block/onset/strata/partial tests | W2 |
| Evidence lane 3 — provider-attested bounded correlations | **Active v1** | Provenance-bearing symptom/precursor relations | `T`; namespace/hop/degree/cost, payload-ID non-authority, and clock tests | W2 |
| Feasible small-window exact passthrough | **Active v1** | Complete authorized context dominates reduction when it fits | `T`; passthrough always selected when feasible and matches the complete-authorized-input task outcome | W1–W2 |
| Disjoint monotone top-k packer + deterministic brief/expansion | **Active v1** | Auditable complementary selection under budget; provider relations retain two endpoints while other facets saturate at one | `T`; objective property tests, exact-small-instance regret, closed-cardinality/version binding, honest guarantee boundary | W2 |
| Structural taint/authority separation + read-only expansion | **Active v1** | Enforceable security boundary, unlike prompt filtering | `T`; encoded/fragmented/multiline/cross-event suite has zero Evidentrail-owned authority path | W0–W3 |
| Evaluation infrastructure — Loghub-2.0/corrections, LogDx-CI, RCAEval, AIOpsLab tracks | **Active v1** | Keeps component, CI, injected RCA, interactive, and hidden-real claims separate | Pinned versions/checksums, held-out families/systems, no runtime gold, per-track/worst-slice reports | W1–W4 |
| Evaluation infrastructure — ALCE/RAGChecker grounding, position tests, LogJack attacks | **Active v1** | Separates citation, utilization, ordering, and hostile-input failures | Stable IDs, citation dimensions, order/distractor sweeps, adaptive-injection intervals | W1–W4 |
| Separate benchmark arms — pinned current Evidentrail hosted service and pinned `legacy-drain` | **Active v1** | Hosted product claims are broader than and not proven by the open engine | Separate version/commit/config/model/budget/provenance; matched costs; hosted arm only when permitted; never pool/substitute | W1–W4 |
| Drain, Spell, Logram, PIPLUP, other non-neural groupers | **Evaluation-only challenger** | Parser metrics are not diagnostic utility; overmerge is destructive | `G` independently per proposer; proposer agreement gives no credit | X1/W4 |
| LILAC, DivLog, LogBatcher, LibreLog, UNLEASH, LUNAR, MicLog | **Evaluation-only challenger** | Potential parsing gains add model/cache/privacy/drift risk | `G + M` independently per pinned implementation | X2/W4 |
| Onion/Log-Insight reference and group-skew selection | **Evaluation-only challenger** | Potentially useful contrast rests on weak reference/production evidence | `R`; no inherited fixed thresholds or destructive sampling | X1/W4 |
| DeepLog, LogAnomaly, LogBERT, LogFormer, BARO ranker | **Evaluation-only challenger** | Surprise/change is not causality; evaluated domains are limited | `U`; add `M` when learned | X1 or X2/W4 |
| LoFI, LogSieve classifier, RECOMP-style extractive ranker | **Evaluation-only challenger** | Task-aware selection is promising but not proven complete across incidents | `U + M`; intact blocks and ID/score/role/uncertainty-only output | X2/W4 |
| Trusted-evidence mutation — LLMLingua token deletion, RECOMP abstraction, uncited neural summaries | **Rejected** | Mutates machine evidence and breaks basis-exact expansion | No protected/trusted-block admission; external baseline or secondary cited synopsis only | W1/W4 adapter only |
| V1 evidence-path use of LogReducer, LogBlock, Denum, LogShrink, DeLog, LogPrism codecs | **Rejected** | Storage ratio does not establish diagnostic sufficiency | No evidence admission; `P1` requires basis-exact round trip, corruption, version, and random-access proof | P1 only |
| Old Evidentrail and `legacy-drain` runtime reuse | **Rejected** | Would make the product a wrapper around the prior implementation or open grouping engine | No runtime admission; isolated subprocess baseline only | W1/W4 adapter only |
| Generic observability/store/dashboard/replay | **Rejected** | Expands scope beyond bounded evidence compilation | Separate product charter required | Never in this program |
| Autonomous RCA/remediation/log-derived actions | **Rejected** | Conflates evidence, diagnosis, and authority | No admission; Evidentrail remains read-only | Never |
| Prompt filtering as the security boundary | **Rejected** | Filtering cannot enforce authority separation | No admission; structural taint/capability separation must satisfy `T` | Never |

### Release traceability

| Evidence-backed requirement | Primary support | Evidentrail implementation consequence | Release gate |
|---|---|---|---|
| Atomic single-/multiline events precede grouping | Hue; failures implied by line-oriented parsers | Versioned source adapters, bounded continuation state, uncertain-boundary state, retained-basis byte spans | Multiline/stack-trace golden fixtures; zero unexplained mutation relative to declared basis; deterministic IDs |
| Complete authorized input is the small-window winner | Current Evidentrail public agent-serving report, source-linked in [`EVIDENTRAIL_COMPETITIVE_TEARDOWN.md`](EVIDENTRAIL_COMPETITIVE_TEARDOWN.md) | Bypass packing reduction and emit exact passthrough whenever the complete authorized bounded input fits | Feasible small-window cases select passthrough and match the complete-authorized-input task outcome |
| Current hosted Evidentrail and `legacy-drain` are distinct comparators | Current product, SDK, repository, and public reports, source-linked in [`EVIDENTRAIL_COMPETITIVE_TEARDOWN.md`](EVIDENTRAIL_COMPETITIVE_TEARDOWN.md) | Pin separate hosted and open-engine arms; never pool, substitute, or infer one from the other | Matched inputs, output budget, reader/tool loop, total cost, version/config, and provenance; hosted arm only when permitted |
| V1 has exactly three active evidence lanes | Parsing/anomaly limitations across this ledger; LogJack authority risk | Lexical + validated typed IDs; complete failures + transparent onset/change + raw-coverage sentinels; provider-attested bounded correlations | Per-lane cost, unique yield, leave-one-lane-out recall, protected-slice recall, deterministic recomputation |
| Group/parser-derived selection is disabled by default | Drain, Spell, Logram, Loghub-2.0, corrected datasets, PMSS | Exact provider event keys and conservative token-shape fingerprints may annotate blocks; tree/n-gram/other groupers are feature-gated experiments | Held-out unique yield, leave-one-lane-out recall, full recall-cost vector, zero known incompatible overmerge; proposer agreement gives no credit |
| No destructive preprocessing | Preprocessing framework; LLMLingua-2 limitations | Reversible active-lane features with offsets; protected blocks indivisible | Basis-exact expansion and metamorphic mask/unmask tests |
| Archive compression is not diagnostic compression | LogReducer, LogBlock, Denum, LogShrink, DeLog, LogPrism | Optional post-MVP lossless codec behind ledger API; brief selection has a separate objective | Byte-for-byte round trip against declared retained basis, corruption isolation, version compatibility; no diagnosis KPI inferred from ratio |
| Reference and anomaly lanes are disabled by default | DeepLog, LogAnomaly, LogBERT, LogFormer, BARO, Onion | Only transparent bounded onset/change facts are active; learned anomaly, sequence-surprise, group-rarity, and reference contrast are feature-gated | Held-out lane-unique yield, leave-one-lane-out recall, protected-slice behavior, full cost; no causal wording from signal alone |
| Parsing quality is not a downstream proxy | Impact-of-parsing study; LogDx-CI | Component and outcome evaluations remain separate | No release based on parser score alone |
| Evidence packer is deterministic and inspectable | Lin & Bilmes; Sviridenko | Frozen nonnegative top-k facility objective, exact costs, protected constraints, deterministic ties; provider relations use two half-weight distinct-packet slots and all other facets one | Objective property tests; distinct-packet/top-two/third-zero gates; exact-optimum regret on small cases; repeatability |
| Output claims are grounded | ALCE; RAGChecker | Stable evidence IDs, claim-to-evidence map, visible uncertainty/abstention | Citation correctness/completeness, invalid IDs, unsupported claims |
| Context relevance, ordering, and budget are experimental variables | RECOMP; LLMLingua-2; LoFI; LogSieve; Lost in the Middle | Strongest evidence/map early; intact blocks; explicit budget receipt | Budget/order/distractor sweeps, omission audits, and Pareto curves |
| Public benchmarks cover distinct distributions | Loghub-2.0, LogDx-CI, RCAEval, AIOpsLab | Separate component, CI, injected RCA, interactive, synthetic, and blinded-real tracks | Per-track and per-family reports; family-held-out splits; no pooled vanity score |
| Symbolic evidence precedes neural synthesis | Log-Insight; RECOMP | Deterministic dossier first, optional cited synthesis second | Dossier evaluated without an LLM; synthesis cannot alter selected IDs |
| Logs are adversarial data, never instructions | LogJack; CaMeL | Taint/authority separation, no tools in compiler, escaped display, capability checks downstream | Injection suite with encoded, fragmented, multiline, and cross-event payloads; zero unauthorized action path |

## 10. Explicitly rejected shortcuts

- **One universal parser as ground truth:** rejected because parser families fail differently and public labels themselves change.
- **Template frequency as importance:** rejected because frequent boilerplate and rare causal events invert that assumption.
- **Compression ratio as product success:** rejected because storage redundancy and diagnostic sufficiency are different objectives.
- **Anomaly score as root cause:** rejected because novelty and temporal change are evidence proposals, not causal proof.
- **Token-level deletion inside protected logs:** rejected because it can corrupt syntax, identifiers, and basis-exact expansion.
- **LLM summary as the only retained artifact:** rejected because it is not lossless, reproducible evidence.
- **Gold incident labels in the production selector:** rejected as leakage. Gold is allowed only in offline scoring and learning.
- **A single benchmark or a single reader model:** rejected because distributions, position effects, and tool loops differ.
- **Treating hosted Evidentrail and `legacy-drain` as one comparator:** rejected because their public surfaces and evidentiary scopes differ.
- **Automatic approximation claims for ordinary greedy:** rejected unless the implemented objective, constraints, and algorithm satisfy the cited theorem.
- **Prompt filters as the security boundary:** rejected because untrusted logs must be structurally separated from authority.

## 11. Product and training sequence implied by the evidence

1. **Ship the deterministic evidence compiler:** policy-aware authorized ingestion, immutable ledger, atomic reconstruction, exactly three active evidence lanes, protected-block rules, deterministic disjoint budgeted packing, basis-exact expansion, and acquisition/presentation receipts.
2. **Pass invariant and benchmark gates:** synthetic losslessness/adversarial tests, Loghub-2.0 parsing track, LogDx-CI, RCAEval, AIOpsLab, and blinded real incidents. Establish strong raw, grep/filter, tail, parser-only, LogSieve, LoFI/Onion-style selection, token-compression, and Log-Insight-like baselines.
3. **Collect training records from the product:** candidate blocks, production-computable features, selection receipts, expert evidence-role labels, counterfactual omissions, diagnosis/citation outcomes, and hard negatives. Keep incident families and organizations isolated across splits.
4. **Train the narrowest model that can add value:** first a candidate/ranking model; then an optional evidence-role classifier; only then a cited diagnosis model. Optimize downstream evidence and diagnosis utility with explicit abstention, inspired by RECOMP, while preserving intact blocks.
5. **Consider learned lanes only after admission gates pass:** grouping, reference, anomaly, embedding, and LLM rankers remain disabled until each independently adds held-out unique required-evidence yield per unit cost, improves leave-one-lane-out recall, and passes protected-slice and incompatible-overmerge gates where applicable. Proposer agreement is not evidence of correctness. An admitted model remains additive and cannot change the ledger, authorization outcomes, protected inclusions, tool authority, or deterministic fallback; every learned release is pinned, shadow-tested, calibrated, and reversible.

## Bottom line

The defensible moat is not “a better parser” or “an LLM that summarizes logs.” It is the combination of a policy-aware authorized ledger with declared exactness bases, source-aware atomic reconstruction, three deliberately narrow active evidence lanes, deterministic disjoint budgeted selection, basis-exact traceability through stable IDs and receipts, adversarial authority separation, and an evaluation program that ties each omitted or included block to downstream incident outcomes. Grouping, reference, anomaly, embedding, and learned-ranker proposals are options, not shipped complexity, until they earn admission on held-out evidence and cost. Learned models may later improve ranking and explanation on top of that substrate; they cannot replace it. Generic observability, replay, autonomous RCA/remediation, and old-Evidentrail runtime reuse are separate or rejected products—not later phases hidden inside this plan.
