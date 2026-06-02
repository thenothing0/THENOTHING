# Skill: Cloud Asset Discovery from OSINT & Config Clues

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `cloud_asset_discovery` |
| **version** | `1.0.0` |
| **category** | Recon / Cloud OSINT |
| **correlates_with** | S3 buckets, Azure blobs, GCP buckets, cert SANs |

## Objective
Enumerate **cloud-hosted** assets tied to the target using **DNS**, **CT**, **search**, and **config leaks**—without hammering object storage with aggressive bruteforce unless program allows.

## Scope Rules
- Bucket bruteforce may be **out of scope**—read program.
- Do not access **private** objects even if URL guessable (legal/ethical line).

## Trigger Conditions
- `*.s3.amazonaws.com`, `*.blob.core.windows.net`, `storage.googleapis.com` in CT/DNS.
- Terraform `bucket =` strings in repos.

## Technology Fingerprints
- AWS S3/GCP GCS/Azure Blob naming patterns; CloudFront distributions.

## Recon Methodology
1. Extract **bucket names** from passive sources first.
2. **HEAD/GET** public objects only; note `ListBucketResult` exposure vs single object.
3. Map **cloud** front domains back to app flows.

## MCP Tool Orchestration Logic
- `httpx_probe` for existence checks (gentle).
- `nuclei_scan` cloud exposure templates if allowed.

## Reasoning Heuristics
- **Similar naming** (`company-backup`, `company-dev`) from primary domain tokens.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Public list ACL |
| H2 | Authenticated object with predictable key |
| H3 | Mislinked CDN origin exposing bucket |

## Validation Workflow
- Screenshot/listing proof for **public** misconfig; for auth issues, stop at metadata.

## False-Positive Reduction
- **Intentional** public static site buckets.

## Stealth + OPSEC Guidance
- Low QPS object checks; backoff 403 patterns.

## Replay Procedures
- URLs + response headers (`Server`, `x-amz`).

## Evidence Requirements
- Minimal listing snippet; impact statement.

## Reporting Methodology
- Block public access, bucket policies, SCP, inventory auditing.

## Confidence Scoring Logic
- PII in public bucket: **critical**; empty dev bucket: informational.

## Adaptive Branching Logic
- **Multi-region** replication configs → expand search tokens.

## Related Exploit Chains
- `skills/cloud/aws_privilege_escalation.md`

## Safety Boundaries
No downloading sensitive datasets.

## Output Artifact Requirements
`output/<target_slug>/recon/cloud_assets/` — `buckets.csv`, `evidence_headers.txt`
