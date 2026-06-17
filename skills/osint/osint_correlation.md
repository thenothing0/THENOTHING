# Skill: OSINT Correlation

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `osint_correlation` |
| **version** | `1.0.0` |
| **category** | OSINT / Recon |
| **correlates_with** | Subdomain discovery, historical URLs, leaked secrets, asset graph |

## Objective
From a domain-only seed, build the external asset graph and surface starting points: subdomains,
historical/archived URLs, exposed code/secrets, and infrastructure — fused into Two-Signal asset
intelligence the rest of the pipeline can act on.

## Scope Rules
- Passive-first; only act on assets confirmed in-scope.
- No intrusive scanning of third-party/supplier infra.

## Trigger Conditions
- `domain_only`, `program_recon_allowed`; a new program with a root domain.

## Technology Fingerprints
- N/A (discovery stage) — output feeds fingerprinting.

## Recon Methodology
1. Passive subdomain enumeration + DNS resolution.
2. Historical URL mining (archives) for parameters and dead/forgotten endpoints.
3. Fuse multi-source signals into asset intelligence; record provenance.

## MCP Tool Orchestration Logic
- `subfinder_scan` / `amass_enum` / `dnsx_resolve` — subdomains + resolution.
- `gau_urls` — historical/archived URLs (params, old endpoints).
- `httpx_probe` — which assets are live.
- `recon_fuse` — multi-source fusion → wiki asset intelligence (Two-Signal confidence).
- `kb_recall` — pull prior knowledge before planning.

## Reasoning Heuristics
- Forgotten subdomains / decommissioned services are high-yield (takeover, stale apps).
- Archived URLs reveal parameters not present in the current site.
- Two independent sources agreeing raises asset confidence.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|------------|
| H1 | Dangling subdomain → takeover |
| H2 | Archived param → injection surface |
| H3 | Exposed code/secret → access |

## Validation Workflow
1. Confirm an asset resolves + is in-scope before any active testing.
2. Promote to active skills (`web`, `api`) only after scope confirmation.

## False-Positive Reduction
- Wildcard DNS inflates subdomain counts — verify distinct content.
- Archived URLs may be long dead — probe before scanning.

## Stealth + OPSEC Guidance
- Prefer passive sources; rate-limit; rotate politely; respect program recon rules.

## Replay Procedures
- Persist the asset graph + source provenance in the wiki via `recon_fuse`.

## Evidence Requirements
- Source-attributed asset list, confidence bands, in-scope determination.

## Confidence Scoring Logic
- Two independent sources: high; single passive hit: candidate.

## Adaptive Branching Logic
- Live web asset → `skills/web/web_attack_surface_reasoning.md`; cloud host → `skills/<cloud>/*`.

## Related Exploit Chains
- `skills/recon/cloud_asset_discovery.md`

## Safety Boundaries
Passive-first; never test out-of-scope or supplier assets.

## Output Artifact Requirements
`output/<target_slug>/osint/` — `assets.json`, `subdomains.txt`, `archive_urls.txt`
