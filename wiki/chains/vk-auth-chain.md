---
type: chain
aliases: ["VK auth chain", "validatePhone chain"]
tags: [vk, sms, enumeration, account-takeover]
target: "[[vk]]"
nodes: ["auth.restore", "auth.validatePhone", "auth.confirm"]
created: 2026-06-01
updated: 2026-06-01
---
# VK Auth Method Chain: Enumerate → SMS → Brute Code

## Entry point
`auth.restore?phone=<target>` — unauthenticated. Different error codes reveal if phone is registered with VK.

## Pivot
`auth.validatePhone?phone=<target>` — unauthenticated. Sends 6-digit SMS code to confirmed VK user. See [[vk-r6-sms-abuse-live]].

## Escalation
`auth.confirm?phone=<target>&code=<brute>` — attempt code verification. Rate-limited per IP (error 29) but distributable across rotating IPs. 6-digit code = 1M combinations.

## Final impact
If code confirmed → access to account recovery flow → potential full account takeover.

## Current status
- Entry (auth.restore): confirmed working, landed Informative (R7)
- Pivot (auth.validatePhone): confirmed working, in vendor review (R6)
- Escalation (auth.confirm): rate-limited per IP, not fully tested with distributed IPs

## Feasibility assessment
- Entry + pivot: **confirmed, trivial**
- Full chain to ATO: **theoretical** — auth.confirm rate limit is the gating factor. Feasible with botnet/proxy rotation but not demonstrated.

## Limitations
- auth.confirm rate limit makes brute force slow without distributed infrastructure
- 6-digit code with 60-second window is a narrow attack window per attempt
- VK may have additional server-side detection (attempt counting across IPs)

## Pattern links
- [[per-target-vs-mass-rate-limit]]
