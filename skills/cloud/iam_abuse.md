# Skill: IAM Policy & Identity Misconfiguration (Multi-Cloud Patterns)

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `iam_abuse` |
| **version** | `1.0.0` |
| **category** | Cloud / Identity |
| **correlates_with** | OIDC from CI, workload identity, key rotation gaps |

## Objective
Evaluate **identity plane** misconfigurations across AWS/Azure/GCP patterns: **overbroad federated trust**, **static keys in CI logs**, **assumable roles from internet**, and **missing MFA** on break-glass—but only where **you are authorized** to review those directories.

## Scope Rules
- No password spraying on cloud consoles.
- Respect **customer** data handling; identity artifacts are **secrets**.

## Trigger Conditions
- Terraform/GitHub Actions OIDC trust `sub` too broad.
- `az login` / `gcloud` hints in leaked pipelines.

## Technology Fingerprints
- GitHub OIDC → AWS `sts:AssumeRoleWithWebIdentity`, Azure managed identities, GCP WIF.

## Recon Methodology
1. Scan **IaC** in repos (if in scope) for trust policies.
2. Map **CI** roles to deployment targets.
3. Cross-check **human** vs **machine** roles separation.

## MCP Tool Orchestration Logic
- `katana_crawl` / `gau_urls` for exposed `.tfstate` or CI artifacts (if allowed).
- `nuclei_scan` for leaked cloud cred templates.

## Reasoning Heuristics
- **Wildcard `sub`** in OIDC trust is a frequent critical.
- **Long-lived keys** on CI runners → escalation if runner compromised.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | OIDC trust too broad |
| H2 | CI role can modify prod deployment |
| H3 | Service account key exposed in container image |

## Validation Workflow
- Policy diff proof in **lab** clone; for prod, **read-only** policy review with customer.

## False-Positive Reduction
- **Reader** roles on telemetry ≠ IAM abuse.

## Stealth + OPSEC Guidance
- Redact all credentials; use secure channels for customer policy files.

## Replay Procedures
- IaC snippet + explanation of trust expansion.

## Evidence Requirements
- Minimal trust policy JSON + attack narrative.

## Reporting Methodology
- Tighten OIDC subjects, use permission boundaries, keyless where possible.

## Confidence Scoring Logic
- OIDC wildcard with path to prod deploy: **0.9+**.

## Adaptive Branching Logic
- **Multi-cloud** hybrid identity → map sync errors.

## Related Exploit Chains
- `skills/cloud/cicd_exposure.md`

## Safety Boundaries
No live role assumption in customer prod without approval.

## Output Artifact Requirements
`output/<target_slug>/iam/` — `findings.md`, `snippets_redacted/`
