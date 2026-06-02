# Skill: AWS Privilege Escalation (Reasoning)

## Metadata
| **id** | `cloud_aws_privesc` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/aws/` |

## Objective
Within **authorized** AWS accounts, map IAM and resource policies for escalation paths (`sts:AssumeRole`, `iam:PassRole`, dangerous `lambda:*`, S3/KMS policy trusts).

## Trigger Conditions
Overbroad policies; exposed keys in repos (separate OSINT); SSRF-to-metadata (cross-skill, scope gated).

## Technology Fingerprints
IAM, Organizations SCP, Lambda roles, EKS IRSA, OIDC from CI.

## Reasoning Heuristics
Graph principals and trust edges; separate read-only discovery roles from dangerous combos; validate with policy simulator in **lab** when possible.

## Exploit Hypotheses
Role chain to admin; PassRole + Lambda code path; metadata credential pivot (ROE).

## MCP Orchestration Logic
`httpx_probe` / `nuclei_scan` for **misconfig signals** on exposed endpoints; cloud CLI proofs stay in private client reports—summarize in `evidence/` without secrets.

## Stealth Guidance
Redact ARNs/tokens from workspace; no posting credentials.

## Validation Workflow
Customer-approved policy excerpts + lab reproduction of effect class.

## Evidence Requirements
Redacted policy JSON, graph description, blast radius narrative.

## Adaptive Branching
CI OIDC hints → `cloud/cicd_exposure.md` (if added) or `kubernetes/k8s_attack_paths.md` for IRSA.

## Confidence Scoring
0.95 demonstrable escalation in authorized account; 0.45 theory-only.

## Replay Logic
Simulator commands documented externally; link summary in `replay/notes.md`.

## Reporting Guidance
Least privilege, permission boundaries, SCPs, keyless CI, remove wildcard `Action`.
