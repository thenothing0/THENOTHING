---
type: finding
aliases: []
tags: []
target: "[[<program>]]"
host: <hostname>
scope_status: in-scope
status: suspected | confirmed | submitted | accepted | rejected | na | duplicate
severity: P1 | P2 | P3 | P4 | P5
report: ""        # path to full report in ../output/<program>/, once written
reward: ""
created: YYYY-MM-DD
updated: YYYY-MM-DD
---
# <Finding Title>

> One-line: the bug and its impact.

## Summary
What it is, where, and why it matters.

## Evidence / PoC
Reproduction steps + quoted evidence from `../output/...`. Two independent signals before
marking `confirmed`.

## Impact (maximized but honest)
Worst realistic scenario, financial/compliance angle (PCI DSS / GDPR / SOC2), users affected.

## Honest assessment — what limits the impact
Address the obvious counterarguments before a triager does.

## Techniques used
- [[...]]

## Chaining
- Part of [[chain-...]] / combines with [[finding-...]].

## Status / triage
- Submitted: YYYY-MM-DD · Response: · **Why rejected (if N/A):** feed lesson into [[pattern]].
