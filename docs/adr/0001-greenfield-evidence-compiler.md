# ADR 0001: Build a greenfield diagnostic evidence compiler

**Status:** Accepted  
**Date:** August 24, 2026

## Context

The existing Evidentrail implementation and public `legacy-drain` repository primarily perform deterministic log templating. Their input and output contracts do not provide immutable raw bytes, complete source provenance, multiline block identity, exact expansion, question-conditioned evidence selection, provider completeness, or reconciled loss accounting.

The product objective is verified debugging success under a total episode budget, not template compression ratio. Building the product around the old parser would make its lossy record model and grouping assumptions foundational and force later trust features to reconstruct information that has already disappeared.

## Decision

Build the product independently in `/opt/evidentrail-bench/evidentrail` as a greenfield Rust workspace.

- Do not link, vendor, copy, wrap, or call `legacy-drain` in the product runtime.
- Implement a new immutable authorized byte ledger, source-aware framing, conservative structural grouping, multi-view candidate system, evidence graph, constrained packer, three-layer coverage accounting, and basis-exact local expansion.
- Keep the old Evidentrail implementation, `legacy-drain`, Drain, and related methods as pinned external EvidentrailBench baselines.
- Reuse published ideas only through independently implemented, tested algorithms and properly attributed design documentation.
- Preserve one future ranker interface, but do not add an LLM or learned ranker until deterministic and benchmark gates pass.

## Consequences

Benefits:

- exactness, privacy, and coverage are architectural properties rather than patches;
- the benchmark can establish genuine improvement over old Evidentrail;
- grouping is one derived view rather than the product's truth;
- local logs, provider logs, and future training labels share stable event identity;
- the deterministic product remains useful without a proprietary model.

Costs:

- more initial implementation than wrapping the existing templater;
- new grouping and ingestion paths require independent validation;
- old Evidentrail behavior must be maintained as a subprocess/container benchmark adapter;
- no performance claim is allowed until the new pipeline passes EvidentrailBench.

## Revisit condition

This decision may be revisited only if a component can be reused without weakening the immutable event contract, source isolation, coverage algebra, or external-baseline independence. Convenience or connector speed alone is not sufficient.
