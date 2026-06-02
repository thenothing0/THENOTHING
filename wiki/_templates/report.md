---
type: report
aliases: []
tags: []
source: <url-or-path to the disclosed report / writeup>
target: "[[<program-or-target>]]"
vuln_class: <idor | ssrf | authz-bypass | business-logic | ...>
asset_type: <web | api | mobile | cloud | ...>
date: YYYY-MM-DD
severity: P1 | P2 | P3 | P4 | P5
learning_score: 1   # 1-10; high = creative/authz-bypass/biz-logic/chains/escalation; low = dupes/trivial
created: YYYY-MM-DD
updated: YYYY-MM-DD
---
# <report title>

> One-line: what this disclosed report teaches us (the reusable lesson, not a copy).

## Distilled intelligence
- **Root cause:** ...
- **Trust-boundary failure:** ...
- **Exploitation sequence:** ...
- **Escalation / impact:** ...
- **Severity reasoning:** ...
- **Attacker assumptions:** ...

## Why the learning_score
- <one line justifying the 1-10 score>

## Related
- Techniques: [[...]] · Patterns: [[...]] · Chains: [[...]] · Intel: [[...]]
