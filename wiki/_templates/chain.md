---
type: chain
aliases: []
tags: []
target: "[[<program>]]"
severity: P1 | P2 | P3
nodes: []     # ordered [[finding]] links
created: YYYY-MM-DD
updated: YYYY-MM-DD
---
# <Chain Name>

> One-line: the end-to-end attack the chain achieves and the severity it reaches.

## Chain
`[[finding-a]]` → `[[finding-b]]` → `[[finding-c]]`

Each hop: what it provides and what it unlocks next. Only chain **confirmed** components
(no speculative "if XSS existed..." links — see chaining anti-patterns in memory).

## End-to-end PoC
Concrete walk-through (e.g. ~10-line browser PoC for cross-origin chains).

## Why the chain > sum of parts
Severity elevation justification (don't double-count standalone severities).

## Related
- Pattern: [[...]] · Target: [[...]]
