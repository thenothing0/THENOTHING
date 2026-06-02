# Skill: IAM Abuse (Multi-Cloud Identity Plane)

## Metadata
| **id** | `cloud_iam_abuse` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/iam/` |

## Objective
Review federated trust (GitHub OIDC, Azure AD, GCP WIF), long-lived keys in CI, and machine-role blast radius—authorized environments only.

## Trigger Conditions
`.github/workflows`, Terraform `trust_policy`, leaked `AWS_` keys patterns in repos.

## Technology Fingerprints
OIDC `sub` claims, managed identities, workload identity.

## Reasoning Heuristics
Wildcard `sub` in OIDC trust is high-signal; correlate CI role to prod deploy paths.

## Exploit Hypotheses
OIDC trust too broad; CI role modifies prod; SA keys in images.

## MCP Orchestration Logic
`katana_crawl` / `gau_urls` for state/IaC leaks (if in scope) → `nuclei_scan` for known patterns.

## Stealth Guidance
Treat identity artifacts as secrets; coordinated disclosure for customer-owned repos.

## Validation Workflow
Policy diff + blast radius; lab assume-role only with approval.

## Evidence Requirements
Redacted trust policy + narrative.

## Adaptive Branching
K8s service accounts → `kubernetes/k8s_attack_paths.md`.

## Confidence Scoring
0.9 OIDC wildcard with prod path; informational if read-only telemetry role.

## Replay Logic
IaC file path + commit SHA references.

## Reporting Guidance
Tighten OIDC subjects, remove long-lived keys, permission boundaries, periodic access review.
