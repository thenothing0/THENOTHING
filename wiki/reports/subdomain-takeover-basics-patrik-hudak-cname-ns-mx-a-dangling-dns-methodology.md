---
type: report
tags:
- report
- auto
target: '[[methodology]]'
severity: low
created: '2026-06-26'
updated: '2026-06-26'
source: https://0xpatrik.com/subdomain-takeover-basics/
vuln_class: xss
asset_type: api
learning_score: 4
learning_score_rationale: base 4 (mid class 'xss') · +2 chain · -2 trivial
unresolved_references:
- xss
---

# Subdomain Takeover: Basics (Patrik Hudak) — CNAME/NS/MX/A Dangling DNS Methodology

> Reusable lesson distilled from a disclosed report — see the intel page [[subdomain-takeover-basics-patrik-hudak-cname-ns-mx-a-dangling-dns-methodology-intel]].

## Distilled intelligence
- **Root cause:** unknown  
  <sub>provenance: not found</sub>
- **Trust-boundary failure:** unknown  
  <sub>provenance: not found</sub>
- **Exploitation sequence:** Enumerate subdomains and their DNS records (CNAME, NS, MX, A)., For each CNAME: resolve the canonical name; test whether its base domain is available for registration (not NXDOMAIN-protected, not reserved TLD)., For CloudFront: attempt to add the source subdomain as an alternate domain to a newly created distribution; success without error indicates takeover., For NS records: test if at least one NS canonical base is registrable., For MX: registering the mail-domain canonical gives email-receipt control., Register the canonical domain and recreate higher-level DNS records to gain full control of the source subdomain., CloudFront: CNAME → *.cloudfront.net; error response on alternate-domain registration indicates unclaimed., S3: regional endpoint CNAME; bucket registration possible., Heroku: *.herokuapp.com CNAME., GitHub Pages: *.github.io CNAME.  
  <sub>provenance: research_ingestion methodology steps</sub>
- **Escalation / impact:** unknown  
  <sub>provenance: not found</sub>
- **Impact:** unknown  
  <sub>provenance: not found</sub>
- **Severity reasoning:** unknown  
  <sub>provenance: no explicit severity statement</sub>
- **Attacker assumptions:** unknown  
  <sub>provenance: not found</sub>

## Why the learning_score
- **4/10** — base 4 (mid class 'xss') · +2 chain · -2 trivial
- signals: chain, trivial

## Unresolved references (recorded, not created)
- `xss` — no page exists (Phase C may create it)

## Related
- Intel: [[subdomain-takeover-basics-patrik-hudak-cname-ns-mx-a-dangling-dns-methodology-intel]] · Target: [[methodology]]
