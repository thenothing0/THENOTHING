---
type: intel
tags:
- intel
- auto
- report-derived
target: '[[rocketchat]]'
created: '2026-06-26'
updated: '2026-06-26'
sources:
- https://hackerone.com/reports/3383079
learning_score: 8
---

# Rocket.Chat SSRF via oEmbed Redirect Validation Bypass (HackerOne 3383079) — actionable intelligence

> Distilled from report [[rocket-chat-ssrf-via-oembed-redirect-validation-bypass-hackerone-3383079]]. What to *reuse*, not an archive copy.

- **Vuln class:** ssrf
- **Target / asset type:** api / api
- **Root cause to look for:** allowlist/SSRF guard applied only to the initial URL, not to redirect targets ("time-of-check vs time-of-fetch"). Redirect following defeats first-hop validation.
- **Trust boundary to probe:** unknown
- **Learning score:** 8/10

## Reusable exploitation sequence
1. Rocket.Chat's oEmbed/link-preview fetches posted URLs server-side to render a preview.
2. Direct internal URLs may be blocked, but the destination of an HTTP redirect was NOT re-validated. The attacker posts a public shortener / attacker-controlled URL that 30x-redirects to an internal host.
3. The server follows the redirect and fetches the internal address, rendering the response — confirming SSRF. The reporter noted the same primitive reaches cloud metadata (e.g. AWS IMDS 169.254.169.254) and internal services.

## Provenance
- Source: https://hackerone.com/reports/3383079
- Report page: [[rocket-chat-ssrf-via-oembed-redirect-validation-bypass-hackerone-3383079]]
- Target: [[rocketchat]]

## Patterns (discovered)
- [[ssrf-pattern]]
