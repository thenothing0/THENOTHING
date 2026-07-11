---
type: intel
tags:
- intel
- auto
- report-derived
target: '[[methodology]]'
created: '2026-06-26'
updated: '2026-06-26'
sources:
- https://0xpatrik.com/subdomain-takeover-basics/
learning_score: 4
---

# Subdomain Takeover: Basics (Patrik Hudak) — CNAME/NS/MX/A Dangling DNS Methodology — actionable intelligence

> Distilled from report [[subdomain-takeover-basics-patrik-hudak-cname-ns-mx-a-dangling-dns-methodology]]. What to *reuse*, not an archive copy.

- **Vuln class:** xss
- **Target / asset type:** api / api
- **Root cause to look for:** unknown
- **Trust boundary to probe:** unknown
- **Learning score:** 4/10

## Reusable exploitation sequence
1. Enumerate subdomains and their DNS records (CNAME, NS, MX, A).
2. For each CNAME: resolve the canonical name; test whether its base domain is available for registration (not NXDOMAIN-protected, not reserved TLD).
3. For CloudFront: attempt to add the source subdomain as an alternate domain to a newly created distribution; success without error indicates takeover.
4. For NS records: test if at least one NS canonical base is registrable.
5. For MX: registering the mail-domain canonical gives email-receipt control.
6. Register the canonical domain and recreate higher-level DNS records to gain full control of the source subdomain.
7. CloudFront: CNAME → *.cloudfront.net; error response on alternate-domain registration indicates unclaimed.
8. S3: regional endpoint CNAME; bucket registration possible.
9. Heroku: *.herokuapp.com CNAME.
10. GitHub Pages: *.github.io CNAME.

## Provenance
- Source: https://0xpatrik.com/subdomain-takeover-basics/
- Report page: [[subdomain-takeover-basics-patrik-hudak-cname-ns-mx-a-dangling-dns-methodology]]
- Target: [[methodology]]

## Patterns (discovered)
- [[xss-pattern]]
