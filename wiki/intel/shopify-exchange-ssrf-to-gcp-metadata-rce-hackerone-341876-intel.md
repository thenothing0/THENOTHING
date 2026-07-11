---
type: intel
tags:
- intel
- auto
- report-derived
target: '[[shopify]]'
created: '2026-06-26'
updated: '2026-06-26'
sources:
- https://hackerone.com/reports/341876
learning_score: 9
---

# Shopify Exchange SSRF to GCP Metadata RCE (HackerOne 341876) — actionable intelligence

> Distilled from report [[shopify-exchange-ssrf-to-gcp-metadata-rce-hackerone-341876]]. What to *reuse*, not an archive copy.

- **Vuln class:** ssrf
- **Target / asset type:** api / api
- **Root cause to look for:** server-side URL fetcher with no allowlist / no egress restriction to link-local metadata IP, combined with GCP's legacy v1beta1 metadata path not enforcing the anti-SSRF header.
- **Trust boundary to probe:** unknown
- **Learning score:** 9/10

## Reusable exploitation sequence
1. The Exchange store-screenshot feature fetched attacker-supplied URLs server-side (classic URL-fetch SSRF sink).
2. GCP instance metadata normally requires the request header "Metadata-Flavor: Google", which a basic SSRF cannot set. Reading GCP docs, the researcher found the legacy endpoint http://metadata.google.internal/computeMetadata/v1beta1/ still served metadata WITHOUT the Metadata-Flavor header — a built-in header-requirement bypass.
3. Via v1beta1 the SSRF retrieved the instance service-account token and project metadata, then escalated to remote code execution on the instance.
4. Researcher stopped at confirmed RCE; Shopify disabled the vulnerable service the same night.

## Provenance
- Source: https://hackerone.com/reports/341876
- Report page: [[shopify-exchange-ssrf-to-gcp-metadata-rce-hackerone-341876]]
- Target: [[shopify]]

## Patterns (discovered)
- [[rce-pattern]]
