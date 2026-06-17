# Skill: Azure-Specific Attack Surface & Escalation

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `azure_attack_surface` |
| **version** | `1.0.0` |
| **category** | Cloud / Azure |
| **correlates_with** | SSRF→IMDS/Managed Identity, Blob exposure, Entra ID, App Service |

## Objective
Find Azure-hosted assets and pursue Azure-specific escalations: **SSRF → IMDS / Managed Identity**
token theft, exposed **Blob** containers, App Service misconfig, and Entra ID (OIDC) issues — PoC-only.

## Scope Rules
- In-scope tenant/resources only; PoC-only token/listing proof.

## Trigger Conditions
- `azurewebsites`, `managed_identity`; `*.azurewebsites.net`, `*.blob.core.windows.net`, `login.microsoftonline.com`.

## Technology Fingerprints
- App Service, Functions, Blob Storage, Azure Front Door, Entra ID (Azure AD), APIM.

## Recon Methodology
1. Map Azure service hosts.
2. Find SSRF sinks reaching `169.254.169.254/metadata/identity` (requires `Metadata: true` header).
3. Probe Blob containers for anonymous list/read.

## MCP Tool Orchestration Logic
- `httpx_probe` / `whatweb_detect` — identify Azure services.
- `attack_scan vuln_class=ssrf` / `attack_oob_test vuln_class=ssrf` — IMDS/Managed-Identity reach.
- `attack_oauth` — Entra ID OIDC redirect/scope checks.
- `nuclei_scan` — Azure misconfig templates.

## Reasoning Heuristics
- Azure IMDS requires the `Metadata: true` header — SSRF must control headers or hit a helpful proxy.
- Managed Identity token → Graph/ARM access within granted role (PoC-only).
- Anonymous Blob containers leak data; SAS tokens in URLs leak access.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|------------|
| H1 | SSRF → IMDS → Managed Identity token |
| H2 | Public Blob container with sensitive objects |
| H3 | Entra ID OIDC redirect_uri/scope abuse |
| H4 | Dangling `*.azurewebsites.net` → takeover |

## Validation Workflow
1. Confirm a metadata/identity-token response (two signals); reverify.
2. For Blob, demonstrate anonymous read of a sensitive object (minimal).

## False-Positive Reduction
- SSRF without header control often can't reach Azure IMDS — verify, don't assume.
- A SAS-protected container is not "public".

## Stealth + OPSEC Guidance
- Minimal reads; no bulk container enumeration/download.

## Replay Procedures
- Save the SSRF request (with headers), redacted token, container policy.

## Evidence Requirements
- Token/identity proof (redacted), remediation (block IMDS via SSRF, container ACLs, scoped roles).

## Confidence Scoring Logic
- Managed-Identity token retrieved: critical; public Blob: per-data sensitivity.

## Adaptive Branching Logic
- Token obtained → cloud IAM branch (PoC depth); OIDC → `skills/oauth/oauth_oidc_abuse_patterns.md`.

## Related Exploit Chains
- `skills/ssrf/chained_ssrf.md`, `skills/cloud/iam_abuse.md`

## Safety Boundaries
PoC-only; no bulk exfiltration; no token use beyond identity proof.

## Output Artifact Requirements
`output/<target_slug>/azure/` — `services.json`, `ssrf_imds.md`, `blob_findings.csv`
