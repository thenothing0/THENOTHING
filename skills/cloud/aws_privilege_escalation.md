# Skill: AWS Privilege Escalation & IAM Abuse Reasoning

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `aws_privilege_escalation` |
| **version** | `1.0.0` |
| **category** | Cloud / AWS |
| **correlates_with** | SSRF metadata, CI OIDC, Lambda over-permission, S3 policy |

## Objective
Within **explicitly authorized** AWS accounts or programs that permit cloud review, map **IAM** and **resource policies** for **escalation paths** (role assumption chains, `iam:PassRole`, `lambda:UpdateFunctionCode`, `sts:AssumeRole` wildcards). **No** testing on third-party accounts.

## Scope Rules
- Valid only for **your** lab account or **client-authorized** assessment.
- Never attempt **cross-account** access without written ARN scope.

## Trigger Conditions
- Exposed access keys in repos, overly broad `Action: "*"`, trust policies `Principal: *`.
- SSRF to IMDS (pair with SSRF skill) when in scope.

## Technology Fingerprints
- IAM, Organizations SCP, S3 bucket policies, KMS grants, Lambda execution roles, EKS IRSA.

## Recon Methodology
1. Inventory principals (users, roles, OIDC providers) and **trust** relationships.
2. Map **high-risk** actions attached to low-trust principals.
3. Check **PassRole** + `lambda:CreateFunction` style combos from literature—validate in **lab**.

## MCP Tool Orchestration Logic
- `httpx_probe` / `nuclei_scan` for **exposed** cloud endpoints and misconfigs (signals).
- Cloud CLI work is often **outside** MCP—document commands privately per ROE.

**Branching:** If only **static keys in JS** → pivot secret handling + rotation, not live escalation.

## Reasoning Heuristics
- **Separation of duties**: developers with `iam:*` on prod roles.
- **Resource-based** policies on S3/KMS that trust unexpected principals.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | AssumeRole chain to admin |
| H2 | PassRole to Lambda then code update |
| H3 | Overprivileged instance profile reachable via SSRF |

## Validation Workflow
1. **Simulate** policy evaluation with AWS policy simulator in **lab** account.
2. For findings on targets, attach **minimal** repro showing effective access expansion.

## False-Positive Reduction
- **Read-only** discovery roles expected by design.

## Stealth + OPSEC Guidance
- Never post ARNs/tokens publicly; scrub `output/`.

## Replay Procedures
- Policy JSON excerpts (redacted account ids if required by client).

## Evidence Requirements
- IAM graph narrative + blast radius + remediation: least privilege, SCP, permission boundaries.

## Confidence Scoring Logic
- Demonstrable role assumption to higher privilege in-scope: **0.95**; theoretical policy text only: **0.45**.

## Adaptive Branching Logic
- **EKS IRSA** service account annotations → pod → cloud token branch.

## Related Exploit Chains
- `skills/ssrf/chained_ssrf.md`
- `skills/cloud/cicd_exposure.md`

## Safety Boundaries
No unauthorized access to AWS infrastructure.

## Output Artifact Requirements
`output/<target_slug>/aws/` — `graph_notes.md`, `policy_snippets_redacted.json`
