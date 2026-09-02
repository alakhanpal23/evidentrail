# Evidentrail threat model

**Status:** Normative for the deterministic greenfield product  
**Last updated:** August 24, 2026  
**Applies to:** CLI, MCP server, source adapters, local result ledger, Log Brief rendering, exact expansion, diagnostics, telemetry, and EvidentrailBench

## Security objective

Evidentrail reads operational data that commonly contains credentials, personal data, customer identifiers, internal topology, source paths, and attacker-controlled text. Its security objective is:

> Turn an explicitly approved, bounded log acquisition into exact local evidence without giving log content authority, widening the approved source scope, or retaining or exporting content invisibly.

The product is secure only when the evidence contract and the access contract hold together. Exact evidence is not useful if acquisition escapes its approved boundary; a read-only query is not sufficient if raw content leaks through diagnostics or benchmark artifacts.

The following principles are mandatory:

1. Log content is untrusted data, never an instruction or policy input.
2. A source binding is a capability that later requests may narrow but never widen.
3. Exact source bytes are captured before parsing and remain local by default.
4. Persistent raw snapshots are authenticated-encrypted and short-lived; plaintext fallback is forbidden.
5. Provider commands use reviewed executable-and-argument templates, never a shell.
6. Every content egress has its own explicit consent; telemetry consent is not content or training consent.
7. Security failures are explicit `partial`, `needs_input`, or errors. Evidentrail must not fail open to produce a cleaner Log Brief.

## System and data flow

```text
user or coding agent
  -> QueryIntent
  -> approved repository/source binding
  -> bounded QueryPlan
  -> source adapter or reviewed local command preset
  -> exact RawEnvelope stream
  -> encrypted local result snapshot + immutable ledger
  -> framing, parsing, grouping, candidate generation, packing
  -> structured Log Brief containing typed untrusted evidence
  -> local exact expansion

separate paths:
  -> allowlisted contentless diagnostics
  -> optional contentless telemetry, only with telemetry consent
  -> benchmark or training export, only with its own explicit consent
```

Raw content must not enter the diagnostic or telemetry paths. Expansion reads the bounded local snapshot; it does not silently requery a provider.

## Protected assets

### Highest sensitivity

- exact log bytes and provider stderr;
- post-policy evidence blocks and reconstructed stacks;
- questions, alerts, search terms, filenames, paths, and query predicates;
- credentials, session material, provider CLI configuration, and OS-keychain keys;
- local result encryption keys and key envelopes;
- private benchmark cases, annotations, root causes, fixes, and held-out labels;
- consented training examples and outcome labels.

Derived templates, typed fields, hashes, embeddings, summaries, and model features remain content. They can reveal the original system and must not be reclassified as harmless telemetry.

### Sensitive operational metadata

- account, cluster, tenant, namespace, repository, service, host, and container identity;
- repository-to-service bindings;
- exact timestamps and incident windows;
- source cursors and stable provider event IDs;
- result IDs and expansion references.

### Contentless operational metadata

Only a strict allowlist can enter diagnostics or telemetry: component and schema versions, source kind, coarse status, numeric counts and byte totals, configured caps, elapsed timings, partial-reason codes, evidence-lane counts, rendered token counts, and error codes. Free-form strings are not contentless.

## Actors and attacker capabilities

The model considers:

- a malicious application or tenant that can write arbitrary log messages;
- a compromised dependency that writes prompt-injection text into logs;
- a malicious or accidentally broad file path, glob, symlink, rotated file, archive, or named pipe;
- a coding agent that supplies malformed, adversarial, or scope-widening tool arguments;
- a local unprivileged process racing file resolution, replacing files, or reading permissive cache files;
- a provider returning malformed data, untrusted stderr, duplicates, pagination anomalies, or partial results;
- a user accidentally approving the wrong cloud account, cluster, namespace, or repository binding;
- a benchmark contributor attempting to leak private cases through fixtures, reports, or CI artifacts;
- dependency or build-system compromise.

## Assumptions and residual limits

- The signed-in operating-system user and OS keychain are trusted for the duration of a query.
- Provider authentication and authorization remain enforced by the provider. Evidentrail must not copy provider credentials into its own cloud.
- An attacker with root, kernel access, the same user's live-process memory, or control of the provider CLI can observe data during use. Disk encryption and TTL do not defend against that attacker.
- Secure physical erasure is not reliable on SSDs. Cryptographic erasure by destroying per-result keys is the primary deletion mechanism.
- Evidentrail can mark and isolate untrusted evidence but cannot guarantee that every downstream coding agent will ignore a convincing instruction in a log. Destructive or privileged actions require authorization independent of Evidentrail and the log content.
- Availability is bounded by explicit row, byte, decompression, event, memory, process, and wall-time limits. Evidentrail may return partial evidence instead of exhausting the machine.

## Trust boundaries

### TB-1: User or agent request to approved binding

The request is untrusted. The stored binding is the authority. A request may reduce time, service, environment, resource, severity, or output budget. It may not add a provider, account, cluster, namespace, repository, service, file root, command, or permission.

Any widening produces `needs_input` and a human-readable diff. Reusing an approval from a different repository, tenant, or provider identity is forbidden. The effective provider identity is rechecked immediately before execution so a changed AWS profile or Kubernetes context cannot turn an old plan into access to another account.

### TB-2: Query planner to source adapter

Adapters accept typed `QueryPlan` values, not raw provider arguments. The executable plan and its sanitized display are distinct objects. Secrets and credential-bearing environment variables never appear in the display, diagnostics, or result.

Provider-side semantic filters such as `error`, anomaly terms, or generated keywords cannot be the only acquisition path unless the user explicitly requested that exact filter and the query plan plus `FetchCompletion` preserve that scope limitation. Safe pushdowns are limited to approved identity, exact scope, explicit identifiers, and bounded time.

### TB-3: Local command execution

Agent-accessible commands use an approved command preset:

- resolve an executable to an approved absolute path;
- build an argv array from typed fields;
- call the process API directly with no shell, interpolation, command substitution, or response file;
- reject unknown flags, positional arguments, subcommands, and path escapes;
- use an allowlisted environment and never log environment values;
- set an approved working directory;
- close stdin and nonessential inherited file descriptors;
- prohibit `sudo`, privilege escalation, interactive prompts, and arbitrary plugins;
- capture stdout and stderr as separate untrusted content streams;
- enforce row, byte, wall-time, and decompression limits;
- place the child in a killable process group and reap the full group on cancellation or timeout.

Examples of agent-safe presets include `kubectl logs`, CloudWatch log reads, `docker logs`, `journalctl`, macOS `log show`, and GitHub Actions log reads after their exact arguments are reviewed. A human-invoked advanced wrapper may run a user-specified command only as an explicit local action; it must not be callable through the normal MCP path and does not convert the command into a Evidentrail-approved read-only preset.

Log content, provider output, and expansion results can never contribute executable names, arguments, environment values, paths, or subsequent query scope.

### TB-4: Filesystem to raw snapshot

Evidentrail never crawls a home directory or auto-enrolls a discovered log. The user approves an explicit path, resolved glob, or root. Before a file read:

1. canonicalize the approved root and proposed target;
2. require the target to remain within the root;
3. reject devices, sockets, named pipes, and other special files in the file adapter;
4. open without following a final symlink where supported;
5. verify the opened handle with `fstat`, including device, inode, file type, size, and modification time;
6. snapshot a bounded byte range from that handle;
7. verify identity and size again after the read.

If a symlink target changes, an inode rotates, a file truncates, a writer races the snapshot, or the ending high-water mark cannot be verified, the result is `partial`. Evidentrail does not switch to a replacement file invisibly. Resolved globs and rotation members are listed in the query plan and capped before content is read.

Compressed inputs have independent compressed-byte, expanded-byte, entry-count, nesting, and expansion-ratio limits. An archive entry may not escape the approved root or create a file. Decoding happens as a bounded stream.

### TB-5: Raw content to evidence compiler

Exact bytes are immutable. Parsing creates derived objects that reference ledger spans. Invalid UTF-8, malformed JSON, and parser failures remain addressable raw records.

All parsers and framers must tolerate arbitrary bytes and enforce maximum record length, block length, stack depth, field count, nesting depth, and parse time. A malformed multiline record cannot absorb an unbounded window. Parser panics, allocation failures, or timeouts produce partial status and preserve the already captured ledger.

### TB-6: Log evidence to coding agent

Every evidence payload is serialized in a typed field with source identity and an explicit untrusted-evidence label. Markdown is a deterministic view of the same structured object. Logs are never concatenated into a system message or parsed as tool calls.

Instruction-like text is retained because it may itself be incident evidence. It can be flagged without rewriting it. Fixed control fields, policy, query scope, expansion authorization, and command arguments are constructed outside the evidence channel.

The deterministic engine and optional hosted ranker have no tool authority. The hosted ranker may return only a complete permutation of request-local opaque block aliases. It may not emit provider syntax, commands, prose that becomes policy, mandatory authority, citations, or a new acquisition scope. Unknown, duplicate, missing, malformed, and foreign aliases invalidate the entire response and trigger deterministic fallback.

Hosted egress is separately bounded after deterministic feasibility: no more
than 32 optional blocks and 40 KiB of combined escaped question/evidence are
eligible. The provider envelope is independently bounded and must contain one
completed, non-refusal structured output. Internal shadow mode still requires
explicit hosted opt-in and always publishes deterministic bytes. Operational
records use a closed contentless schema and never include prompt, response,
credential, provider request ID, raw alias, question, or source bytes.

### TB-7: Local snapshot and expansion

Each persisted result uses a fresh random data-encryption key and an authenticated encryption algorithm from a reviewed library. Nonces are unique per encrypted object. Result ID, schema version, object type, and sequence are authenticated associated data.

The data-encryption key is wrapped by a key-encryption key held in the OS keychain. Keys are never stored beside ciphertext, printed, included in crash reports, or passed on the command line. If the keychain is unavailable, Evidentrail uses an explicitly selected memory-only mode or fails closed; it never writes plaintext.

Cache directories are user-only and files are created with restrictive permissions. Writes use a ciphertext temporary file, flush, and atomic rename. A crash can leave ciphertext or an incomplete ciphertext temporary file, but never an intentional plaintext staging file.

Expansion requires the result ID plus a reference belonging to that result. Cross-result and expired references fail. Expansion checks the original binding and policy snapshot but reads only the local result; a missing record must not trigger a provider fetch.

Default expiry is 30 minutes from creation. Expansion does not silently extend expiry. A periodic sweeper and startup recovery remove expired key envelopes, ciphertext, stale locks, and incomplete temporary files. Crypto-erasure precedes best-effort file removal.

### TB-8: Diagnostics, telemetry, and support bundles

Diagnostics use an allowlist of typed contentless events, not general-purpose string logging. Source content types must not implement a diagnostic formatter that exposes payloads. Provider stderr and parser excerpts are content and cannot be logged as error strings.

Panic handlers, tracing spans, debug formatting, filenames, metrics labels, process titles, and support bundles must obey the same rule. High-cardinality IDs, questions, paths, account names, and query predicates are excluded unless transformed into a documented local-only pseudonymous identifier.

Security canary tests inject unique source, question, path, credential, and provider-stderr strings and scan:

- diagnostic files;
- console diagnostics;
- telemetry queues and request bodies;
- process arguments and environment snapshots used by tests;
- panic output and crash artifacts;
- filenames and cache indexes;
- support bundles;
- CI logs and artifacts.

The release requirement is zero canary occurrences outside the encrypted content store and expected user-facing evidence output.

### TB-9: Telemetry, content, benchmark, and training consent

The following controls are independent and default off unless the local product function explicitly requires local encrypted retention for expansion:

1. contentless product telemetry;
2. remote content retention or export;
3. contribution to product evaluation or a benchmark;
4. contribution to model training.

Enabling one cannot enable or imply another. Organization policy may disable or cap any category. Consent is versioned, scoped, revocable, and recorded without placing content in telemetry.

### TB-10: EvidentrailBench and private incident data

Public datasets are pinned by license, version, checksum, and acquisition script. Private incidents and labels are stored outside the source repository and normal CI. Private cases use least-privilege access, encryption at rest and in transit, an approved retention schedule, and case-level provenance and consent.

Test annotations remain hidden from implementation owners where practical. Reports contain aggregate metrics and opaque case IDs by default. Raw snippets, questions, diagnoses, paths, and citations are content and require an approved private report destination.

A third-party reader or judge may receive a private case only when that provider and data path are separately approved. Benchmark consent does not permit training. Revocation removes future access, exports, derived content where feasible, and key material according to the local data policy.

## Threats and required defenses

| Threat | Required defense | Failure behavior |
| --- | --- | --- |
| Log-borne prompt injection | Typed untrusted evidence; no log-derived policy, command, or tool call; injection suite | Preserve and flag evidence; never execute it |
| Shell or argument injection | Absolute approved executable, typed argv, direct process API, allowlisted environment | Reject plan before spawn |
| Provider scope widening | Capability intersection, human diff and approval, execution-time identity check | `needs_input` or scope error |
| Symlink/path escape | Canonical approved root, handle verification, no-follow semantics, bounded resolved manifest | Reject target or mark race partial |
| Rotation/truncation race | Open-handle snapshot, before/after identity and high-water checks | Keep captured bytes; mark partial |
| Archive/decompression bomb | Compressed and expanded caps, entry and ratio limits, streaming decode | Stop and mark partial |
| Malformed input DoS | Per-record/block/parser limits, bounded allocation and time | Preserve raw; degrade to partial/raw lane |
| Snapshot disclosure | AEAD per result, keychain-wrapped keys, user-only permissions, short TTL | Memory-only or fail closed |
| Crash residue | Ciphertext-only staging, startup recovery, periodic sweeper, crypto-erasure | Remove stale key/ciphertext artifacts |
| Cross-result expansion | Result-bound references and authenticated associated data | Reject reference |
| Diagnostic leakage | Typed allowlist, canary scan, no free-form provider errors | Block release on any occurrence |
| Consent confusion | Four independent versioned controls, default off for egress | No export or use |
| Private benchmark leakage | External encrypted store, restricted CI, aggregate reports, access audit | Quarantine run and revoke artifact |
| Dependency compromise | Locked dependencies, provenance review, vulnerability/license scanning, reproducible release inputs | Block build or release |

## Concrete security verification gates

These gates are required before a component or release is considered safe. Test names may differ, but the behavior is normative.

### Access and command gates

- **SEC-001 — No shell:** metacharacters, substitutions, newlines, quotes, response-file syntax, and shell flags remain literal argv values or are rejected. No agent path invokes a shell.
- **SEC-002 — Executable pinning:** path replacement between planning and execution is detected; unapproved executable paths and plugins are rejected.
- **SEC-003 — Environment minimization:** only documented environment names reach the child, and no environment value reaches diagnostics.
- **SEC-004 — Scope monotonicity:** property tests show every accepted override is a subset of the approved binding. Cross-repository and cross-tenant binding reuse fails.
- **SEC-005 — Identity revalidation:** changed AWS account, Kubernetes context, provider project, or local root fails before content acquisition.
- **SEC-006 — Cancellation:** timeout and cancellation terminate and reap the process group within the configured grace period; no descendant continues writing.

### Filesystem and snapshot gates

- **SEC-007 — Path containment:** traversal, symlink-swap, nested symlink, case-normalization, and resolved-glob tests cannot read outside an approved root.
- **SEC-008 — File-type safety:** device files, sockets, and named pipes are rejected by the file adapter.
- **SEC-009 — Rotation integrity:** rename, truncate, replace, and append races either snapshot the originally opened bounded bytes or produce prominent partial status.
- **SEC-010 — Bounded decoding:** huge lines, deep JSON, malformed encodings, and multiline absorption stop at declared limits without loss of already captured records. If compressed sources later graduate from unsupported, gzip/archive bombs must pass the same gate plus a versioned derived-exact transformation contract.
- **SEC-011 — Ciphertext only:** a unique canary placed in raw evidence does not occur in cache files, indexes, temporary files, swap-like application spill files, or filenames as plaintext.
- **SEC-012 — Key failure:** unavailable or locked keychain causes memory-only behavior or a hard error; no plaintext snapshot is created.
- **SEC-013 — Permissions:** cache, binding, diagnostic, and key-envelope paths have user-only permissions on every supported OS.
- **SEC-014 — Expiry and recovery:** simulated process crashes at every write phase leave no plaintext; startup and periodic cleanup crypto-erase expired results and remove incomplete ciphertext artifacts.
- **SEC-015 — Expansion isolation:** forged, expired, cross-result, and modified references fail authentication and never trigger a provider requery.

### Content-boundary gates

- **SEC-016 — Diagnostic canaries:** source, question, path, credential, provider-stderr, and annotation canaries have zero occurrences in diagnostics, telemetry, panic output, support bundles, or CI artifacts.
- **SEC-017 — Evidentrail prompt-injection invariant:** for every evidence byte string, Evidentrail performs zero log-derived command/tool execution, binding/policy mutation, provider-scope widening, executable/argv/environment/path construction, content egress, implicit requery, or suppression of coverage warnings. The ranker emits only result-local IDs, bounded scores, typed roles, and uncertainty; expansion is read-only and result-scoped.
- **SEC-018 — Benign instruction text:** benign command examples remain evidence and are not silently deleted; benign-overblock rate is reported beside unsafe-action rate.
- **SEC-019 — Declared transformations:** every redaction or reversible tokenization has an auditable transformation record; unmarked evidence mutation is zero.
- **SEC-020 — Parser failure retention:** malformed and invalid persisted records remain addressable in the raw lane and reconcile in the presentation receipt; policy-omitted source records reconcile separately in the acquisition receipt.

### Consent and private-data gates

- **SEC-021 — Consent independence:** every combination of telemetry, remote content, evaluation, and training controls is tested. No control mutates another.
- **SEC-022 — Revocation:** revoked export/evaluation/training permission prevents new use and schedules associated keys and retained artifacts for deletion.
- **SEC-023 — Benchmark isolation:** private case bytes and labels never appear in the product repository, public CI, public reports, or unapproved reader-model requests.
- **SEC-024 — Report sanitation:** benchmark and support outputs contain aggregate metrics and opaque IDs unless an explicitly approved private-content destination is selected.
- **SEC-025 — Self-ingestion isolation:** active Evidentrail snapshot, key-envelope, diagnostic, telemetry-queue, and support-bundle directories are rejected as file sources and excluded from resolved globs. Copying an intentionally selected diagnostic artifact outside those directories is a separate explicit acquisition.

### Release criteria

A release is blocked by:

- any unauthorized command execution or scope expansion;
- any plaintext persistent raw snapshot;
- any diagnostic or telemetry canary leak;
- any cross-result expansion;
- any unmarked evidence mutation;
- any private benchmark content in public or normal CI artifacts;
- any violation of the Evidentrail-owned prompt-injection invariant;
- any failure to mark a capped, raced, timed-out, or permission-limited acquisition as partial.

Security results are reported per source and operating system. A pass on synthetic fixtures does not waive adapter-specific sandbox testing.

For supported host-agent integrations, log-derived fields carry machine-readable untrusted-data provenance and the host independently authorizes every side effect. Adaptive injection suites report attack-success confidence intervals, benign-task success/overblock, and read-only expansion success for each pinned agent, prompt, tool set, and policy. Destructive or privileged actions require confirmation or corroboration independent of log text. This is an empirical integration claim, not a universal Evidentrail invariant; untested hosts receive no safe-agent claim.

## Review triggers

This threat model must be reviewed before adding:

- a new source adapter or executable preset;
- a hosted content path or remote ranker;
- a learned parser or evidence model;
- automatic repository changes or remediation;
- shared team bindings or multi-tenant execution;
- a new benchmark-data provider or external judge;
- retention longer than the documented local TTL;
- a new diagnostic, telemetry, crash, or support-bundle field.
