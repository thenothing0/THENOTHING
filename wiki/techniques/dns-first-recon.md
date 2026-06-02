---
type: technique
aliases: ["DNS-first", "subdomain enumeration"]
tags: [recon, dns, highest-roi]
created: 2026-05-30
updated: 2026-05-30
---
# DNS-First Recon

> The highest-ROI technique. Run subdomain enum on **every** in-scope domain before any
> active probing — every subsequent finding hangs off a host discovered here.

## When to use
First step of every engagement, before active probing.

## Procedure
1. `subfinder_scan` on **all** in-scope domains (MCP `hydra-security`). Then `amass_enum` for depth.
2. `httpx_probe` the results for live services.
3. Parse subdomains for high-signal patterns:
   - `-prd`/`-prod` (production), `-dev`/`-staging` (lower environments)
   - `secret-origin-*` (CDN-bypass origins) → [[waf-gap-chain]]
   - `internal*` (internal APIs), `admin.*` (admin panels), `api.*`, `payments.*`
4. Note team names, environments, tech choices, developer usernames leaked in names.

## What "a hit" looks like
A live host that the main domain's WAF/controls don't cover (subsidiary, API, origin, internal).

## Evidence it works (real hits)
- [[tripadvisor]] — tamg.cloud (5,286 subs), viator.com (3,622), tapayments.com (128) enums were the foundation for **6+ reports**.

## Applies to
- [[tripadvisor]], [[vk]] — every target.

## Pitfalls / false positives
- Verify each discovered host against `../scope.txt` before probing → set `scope_status`.

## Related
- Techniques: [[response-header-forensics]] (next step) · Patterns: [[waf-gap-chain]] · Skill: `/recon`
