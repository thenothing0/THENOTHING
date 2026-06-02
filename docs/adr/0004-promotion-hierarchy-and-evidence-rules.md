# ADR 0004 — Promotion hierarchy and evidence rules

- **Status:** Accepted (Phase A)
- **Date:** 2026-06-02

## Context

Knowledge is only valuable if it is trustworthy. The spec defines a strict hierarchy
`Observation → Intel → Hypothesis → Finding → Pattern → Chain` and forbids skipping validation.
Without enforcement, confidence inflation and "hypothesis presented as finding" creep in — exactly
the failure modes the operator's memory and `wiki/SCHEMA.md` warn against.

## Decision

`hydra/knowledge/promotion.py` is the **only sanctioned way knowledge moves up a level**, and it
hard-codes the rules (no caller can bypass them):

- **No stage skipping** — a page may promote only to the immediate next stage.
- **Forbidden transitions raise regardless of evidence** — notably `Hypothesis → Pattern`,
  `Hypothesis → Chain`, and `Observation/Intel → Finding`. Validation is mandatory; a hypothesis
  must become a *finding* before it can ever inform a pattern or chain.
- **Evidence is mandatory** for every promotion.
- **Two-Signal rule** for `Finding`, `Pattern`, `Chain` — ≥ 2 independent signals required
  (`hydra/knowledge/confidence.py`).
- **Scope gate** — promotion to `Finding` requires in-scope; out-of-scope knowledge may remain
  `Intel` but must never become a finding.

Confidence is dynamic: source-weighted by the Two-Signal rule (1 source → low, 2 → medium,
≥3 → high), **decays with age**, and **drops on contradiction**.

## Consequences

- "Novel ≠ severe" and "possibility ≠ proof" are structurally enforced, not just documented.
- The MCP `kb_promote` tool returns a clear rejection (never silently promotes) on violation.
- Phase C (pattern/chain discovery) is built *on top of* this library, so automated discovery
  inherits the same guarantees and cannot manufacture unvalidated patterns/chains.
- These rules are encoded as golden scenarios (`promotion_legality`) so a regression fails CI.
