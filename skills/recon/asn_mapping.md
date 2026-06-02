# Skill: ASN Mapping & Network Block Reasoning

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `asn_mapping` |
| **version** | `1.0.0` |
| **category** | Recon / OSINT |
| **correlates_with** | IP ranges, BGP, cloud egress, WAF ranges |

## Objective
Map organization **ASN** → **netblocks** → **live services** to avoid random internet scanning and to **justify** host relevance. Use only **public** routing data and program-approved correlation.

## Scope Rules
- Do not scan **unrelated** netblocks inferred from ASN if program restricts to named domains.

## Trigger Conditions
- Large scope “**ASxxxx** + domains”; incident response style asset recovery.

## Technology Fingerprints
- WHOIS/RDAP, BGP looking glasses, cloud BYOIP.

## Recon Methodology
1. Identify ASN(s) linked to target org (public records).
2. Expand to prefixes; intersect with **known** in-scope domains’ A records.
3. Flag **orphan** IPs that still host org TLS certs (CT).

## MCP Tool Orchestration Logic
- `httpx_probe` on enumerated IPs derived from scoped domains (not full internet sweep).
- `nmap_scan` **only** if program allows and rate-limited.

## Reasoning Heuristics
- **Shared ASN** hosting many tenants—narrow by cert SAN and HTML branding.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Forgotten service on edge IP |
| H2 | VPN concentrator mis-banners |

## Validation Workflow
- Cross-check IP with **TLS cert** CN/SAN and **reverse DNS**.

## False-Positive Reduction
- CDN anycast IPs ≠ org-owned service content.

## Stealth + OPSEC Guidance
- Avoid aggressive `nmap` on sensitive networks; prefer TLS/cert hints.

## Replay Procedures
- Document ASN → prefix → IP evidence chain.

## Evidence Requirements
- Table with citations to public data sources.

## Reporting Methodology
- Clear list of **in-scope** IPs/hostnames worth testing further.

## Confidence Scoring Logic
- High when cert + content + org linkage align.

## Adaptive Branching Logic
- If **IPv6** present → parallel resolution branch.

## Related Exploit Chains
- `skills/recon/subdomain_intelligence.md`

## Safety Boundaries
No bulk scanning of national infrastructure.

## Output Artifact Requirements
`output/<target_slug>/recon/asn/` — `prefixes.csv`, `rationale.md`
