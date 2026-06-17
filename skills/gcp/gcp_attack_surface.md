# Skill: GCP-Specific Attack Surface & Escalation

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `gcp_attack_surface` |
| **version** | `1.0.0` |
| **category** | Cloud / GCP |
| **correlates_with** | SSRF→metadata, GCS exposure, service-account tokens, Cloud Run/Functions |

## Objective
Find GCP-hosted assets and pursue GCP-specific escalations: **SSRF → metadata** service-account token
theft, exposed **GCS** buckets, and Cloud Run/Functions/App Engine misconfig — PoC-only.

## Scope Rules
- In-scope project/resources only; PoC-only token/listing proof.

## Trigger Conditions
- `appspot`, `run_app`, `gcp_metadata`; `*.appspot.com`, `*.run.app`, `storage.googleapis.com`.

## Technology Fingerprints
- App Engine, Cloud Run, Cloud Functions, GCS, Apigee, Firebase, Identity Platform.

## Recon Methodology
1. Map GCP service hosts.
2. Find SSRF sinks reaching `metadata.google.internal/computeMetadata/v1/` (needs `Metadata-Flavor: Google`).
3. Probe GCS buckets for public list/read.

## MCP Tool Orchestration Logic
- `httpx_probe` / `whatweb_detect` — identify GCP services.
- `attack_scan vuln_class=ssrf` / `attack_oob_test vuln_class=ssrf` — metadata reach + token endpoint.
- `nuclei_scan` — GCP misconfig templates.

## Reasoning Heuristics
- GCP metadata requires `Metadata-Flavor: Google` — SSRF must control headers or hit a permissive proxy.
- `…/instance/service-accounts/default/token` → OAuth token within granted scopes (PoC-only).
- `allUsers`/`allAuthenticatedUsers` IAM bindings make GCS objects public.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|------------|
| H1 | SSRF → metadata → service-account token |
| H2 | Public GCS bucket/object |
| H3 | Cloud Run/Functions misconfig (unauth invoke) |
| H4 | Firebase rules world-readable/writable |

## Validation Workflow
1. Confirm a metadata/token response (two signals); reverify.
2. For GCS, demonstrate public read of a sensitive object (minimal).

## False-Positive Reduction
- SSRF lacking header control usually can't reach GCP metadata — verify.
- Public bucket of intentionally-public assets is not a finding.

## Stealth + OPSEC Guidance
- Minimal reads; no bulk bucket enumeration/download.

## Replay Procedures
- Save the SSRF request (with headers), redacted token, IAM/bucket policy.

## Evidence Requirements
- Token proof (redacted), remediation (header-safe SSRF egress controls, IAM bindings, scopes).

## Confidence Scoring Logic
- Service-account token retrieved: critical; public GCS: per-data sensitivity.

## Adaptive Branching Logic
- Token obtained → cloud IAM branch (PoC depth); Firebase → data-rules branch.

## Related Exploit Chains
- `skills/ssrf/chained_ssrf.md`, `skills/cloud/iam_abuse.md`

## Safety Boundaries
PoC-only; no bulk exfiltration; no token use beyond scope/identity proof.

## Output Artifact Requirements
`output/<target_slug>/gcp/` — `services.json`, `ssrf_metadata.md`, `gcs_findings.csv`
