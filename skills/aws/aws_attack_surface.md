# Skill: AWS-Specific Attack Surface & Escalation

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `aws_attack_surface` |
| **version** | `1.0.0` |
| **category** | Cloud / AWS |
| **correlates_with** | SSRF→IMDS, S3 exposure, IAM abuse, presigned URLs, subdomain takeover |

## Objective
Identify AWS-hosted assets and pursue cloud-specific escalations: **SSRF→IMDS** credential theft
(IMDSv1), exposed/misconfigured **S3**, leaked IAM keys, and dangling resources — PoC-only.

## Scope Rules
- Only assets owned by the in-scope program; cloud accounts you're authorized to test.
- No data exfiltration beyond a minimal credential/listing proof.

## Trigger Conditions
- `x_amz_headers`, `s3_host_style`; `*.amazonaws.com`, `X-Amz-*`, S3 vhost/path style.

## Technology Fingerprints
- S3, CloudFront, API Gateway, ELB, EC2 metadata `169.254.169.254`, Cognito.

## Recon Methodology
1. Map AWS service hosts from DNS/headers.
2. Find SSRF sinks that could reach `169.254.169.254/latest/meta-data/`.
3. Probe S3 buckets for list/read/write misconfig (in-scope buckets only).

## MCP Tool Orchestration Logic
- `httpx_probe` / `whatweb_detect` — identify AWS services.
- `attack_scan vuln_class=ssrf` / `attack_oob_test vuln_class=ssrf` — SSRF to IMDS / OOB callback.
- `nuclei_scan` — AWS misconfig/exposure templates.

## Reasoning Heuristics
- SSRF + IMDSv1 → temporary IAM creds → escalate within granted permissions (PoC-only).
- S3 path/vhost confusion and public ACLs are classic.
- IMDSv2 (token-required) blunts naive SSRF — note the version.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|------------|
| H1 | SSRF → IMDS → IAM creds (`ssrf_imds_takeover`) |
| H2 | Public/listable S3 with sensitive objects |
| H3 | Leaked AKIA key grants API access (validate read-only) |
| H4 | Dangling S3/CloudFront → subdomain takeover |

## Validation Workflow
1. Confirm SSRF reaches metadata (OOB/IMDS response) — two signals.
2. For keys, a single read-only `sts get-caller-identity`-equivalent proof; reverify.

## False-Positive Reduction
- A 169.254 connect that times out ≠ creds — require an actual metadata response.
- Public bucket of public assets (by design) is not a finding.

## Stealth + OPSEC Guidance
- Minimal metadata reads; never enumerate/download buckets wholesale.

## Replay Procedures
- Save the SSRF request, the (redacted) metadata response, bucket policy snippet.

## Evidence Requirements
- Metadata/creds proof (redacted), remediation (IMDSv2, bucket policy, key rotation).

## Confidence Scoring Logic
- Retrieved creds via SSRF: critical/**0.95**; public bucket listing: per-data sensitivity.

## Adaptive Branching Logic
- Creds obtained → `skills/cloud/iam_abuse.md` / `aws_privilege_escalation.md` (PoC depth).

## Related Exploit Chains
- `skills/ssrf/chained_ssrf.md`, `skills/exploit_chains/exploit_chain_composition.md`

## Safety Boundaries
PoC-only; no bulk exfiltration; no use of creds beyond identity proof.

## Output Artifact Requirements
`output/<target_slug>/aws/` — `services.json`, `ssrf_imds.md`, `s3_findings.csv`
