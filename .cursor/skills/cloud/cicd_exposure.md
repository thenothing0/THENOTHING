# Skill: CI/CD Exposure

## Metadata
| **id** | `cloud_cicd_exposure` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/cicd/` |

## Objective
Find dangerous GitHub Actions/GitLab CI patterns (`pull_request_target`, excessive `GITHUB_TOKEN`, cache poisoning), exposed Jenkins, and OIDC trust that is too broad—**read-only** proof first.

## Trigger Conditions
Public workflows, fork PR workflows, public Jenkins `/script`, build artifacts with secrets.

## Technology Fingerprints
GitHub Actions, GitLab, Buildkite, Argo CD.

## Reasoning Heuristics
`pull_request_target` + untrusted checkout = high risk pattern; OIDC `sub` wildcard to cloud deploy role = critical.

## Exploit Hypotheses
Fork PR secret exfil; cache poisoned dependency install; OIDC trust hijack.

## MCP Orchestration Logic
`katana_crawl` / `httpx_probe` for exposed UIs → `nuclei_scan` CI exposure templates.

## Stealth Guidance
Do not run malicious workflows on org repos without authorization; prefer static YAML analysis.

## Validation Workflow
YAML line references + blast radius; harmless fork test only on **your** fixture repo if required.

## Evidence Requirements
Workflow commit SHAs, redacted secret patterns (hashes), impact narrative.

## Adaptive Branching
OIDC → `cloud/iam_abuse.md`.

## Confidence Scoring
0.9 demonstrable secret exposure vector; pattern-only = policy severity.

## Replay Logic
Permalinks to lines in workflow YAML.

## Reporting Guidance
Least permissions, environment protections, OIDC tightening, secret scanning, cache keying.
