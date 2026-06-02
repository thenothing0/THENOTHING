---
type: hypothesis
aliases: []
tags: []
target: "[[<program-or-blank>]]"   # the program this would be tested against, if specific
confidence: low | medium | high     # how likely this holds, given current evidence
status: open | validating | confirmed | refuted
created: YYYY-MM-DD
updated: YYYY-MM-DD
---
# <One-line hypothesis as a falsifiable claim>

> A **hypothesis is not a finding.** It is a future investigation candidate generated from
> intel/patterns. It must be falsifiable and carry a confidence label. See `SCHEMA.md`
> evidence discipline and `[[public-api-key-pitfall]]` before promoting one to a finding.

## Hypothesis
The claim, stated so it can be proven *false*. ("Endpoint X on target Y exposes Z because W.")

## Supporting evidence
What makes this plausible — cite the wiki pages / `output/` artifacts / disclosed reports it
derives from. Quote/paraphrase only real sources, never invented output.
- [[intel-or-pattern-or-finding]] — why it points here.

## Confidence
`low | medium | high` and *why*. What raises it (a second independent signal) and what would
lower it. Repeated supporting observations increase confidence; contradictions decrease it.

## Validation plan
Concrete, scope-checked steps to confirm or refute. Name the MCP `hydra-security` tools /
techniques to run. **Verify scope in `../scope.txt` before any active step.**
1.
2.

## What would falsify this
The observation that kills the hypothesis. If seen, set `status: refuted` and record the lesson
back into the relevant `[[pattern]]`/`[[technique]]`.

## Related
- Techniques: [[...]] · Patterns: [[...]] · Promotes to: [[finding-if-confirmed]]
