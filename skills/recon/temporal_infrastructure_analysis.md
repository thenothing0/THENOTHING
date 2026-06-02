# Skill: Temporal Infrastructure Analysis (Churn, Dangling Records)

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `temporal_infrastructure_analysis` |
| **version** | `1.0.0` |
| **category** | Recon / OSINT |
| **correlates_with** | Subdomain takeover, DNS history, cert lifetimes |

## Objective
Identify **time-dependent** weaknesses: **dangling** DNS to deleted SaaS, **expired** certs with weak rollback, **stale** NS delegations, and **historical** IPs leaking origin. Combine **passive** historical data with minimal active confirmation.

## Scope Rules
- Takeover **proof** only on assets **in scope** and with program permission (some programs ban takeover PoCs).

## Trigger Conditions
- CNAME to `github.io`, `herokuapp`, `azurewebsites.net`, etc. with 404/fingerprint mismatch.
- DNS history shows migration from self-hosted to CDN.

## Technology Fingerprints
- SecurityTrails-like history (use whatever passive API program allows), CT logs over time.

## Recon Methodology
1. Snapshot current DNS; compare to **historical** records.
2. Identify **CNAME chains** ending at generic PaaS.
3. Check **HTTP** fingerprint vs expected SaaS landing page.
4. Note **cert** notAfter windows for maintenance risk (informational unless exploitable).

## MCP Tool Orchestration Logic
- `httpx_probe`, `whatweb_detect`, `gau_urls` for historical URL paths.
- `subfinder`/`amass` for broadnames that may be stale.

## Reasoning Heuristics
- **NXDOMAIN** at leaf but parent still delegated → possible hijack window.
- **TXT** records leaking infra (`google-site-verification` mapping to old owner).

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Subdomain takeover on SaaS |
| H2 | Stale MX records |
| H3 | Historical IP exposing admin without CDN shield |

## Validation Workflow
- **Safe** HTTP probe; **do not** claim takeover without explicit PoC policy compliance.

## False-Positive Reduction
- **Intentional** parking pages vs vulnerable dangling records.

## Stealth + OPSEC Guidance
- Low-frequency historical API calls; cache results.

## Replay Procedures
- Timestamped DNS/HTTP evidence table.

## Evidence Requirements
- Before/after DNS + HTTP body hash diff.

## Reporting Methodology
- Remove dangling records, monitor CT+DNS drift, use CAA.

## Confidence Scoring Logic
- Clear dangling CNAME to claimable SaaS: **high** pending takeover policy.

## Adaptive Branching Logic
- **Email** security (SPF/DMARC) temporal issues → separate deliverable if in scope.

## Related Exploit Chains
- `skills/recon/subdomain_intelligence.md`

## Safety Boundaries
No claiming third-party brand assets.

## Output Artifact Requirements
`output/<target_slug>/recon/temporal/` — `dns_timeline.csv`, `http_fingerprints.md`
