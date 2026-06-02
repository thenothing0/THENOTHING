# Skill: CI/CD Exposure & Pipeline Abuse

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `cicd_exposure` |
| **version** | `1.0.0` |
| **category** | Cloud / CI/CD |
| **correlates_with** | GitHub Actions, GitLab CI, Jenkins, OIDC, secrets in logs |

## Objective
Find **pipeline secrets** exposure, **fork PR** attacks on Actions, **unprotected** Jenkins script consoles, and **OIDC** trust misconfigurations—prioritize **read-only** proof (workflow YAML, public artifact) before any execution class demo.

## Scope Rules
- **Fork PR workflows** testing may violate GitHub rules and program policy—read carefully.
- Do not run malicious workflows on **org** repos without authorization.

## Trigger Conditions
- `.github/workflows/*.yml` with `pull_request_target`, `GITHUB_TOKEN` with `contents: write`, cache poisoning of build.
- Public Jenkins with `/script`.

## Technology Fingerprints
- GitHub Actions, GitLab pipelines, CircleCI, Buildkite, Argo CD.

## Recon Methodology
1. Enumerate workflows and **permissions** blocks.
2. Check **artifact** and **cache** keys for injection.
3. Map **OIDC** roles to cloud deploy per `iam_abuse` skill.

## MCP Tool Orchestration Logic
- `katana_crawl` / `httpx_probe` for exposed CI UIs.
- `nuclei_scan` for Jenkins/GitLab exposures.

## Reasoning Heuristics
- `pull_request_target` + checkout of **untrusted** code is high risk pattern.
- **Cache** keys missing hash of lockfile → supply chain cache poison path.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Fork PR secret exfil |
| H2 | Writable `GITHUB_TOKEN` escalation |
| H3 | OIDC subject too broad |
| H4 | Public artifact with `.npmrc` token |

## Validation Workflow
1. Static YAML proof of dangerous pattern.
2. If allowed, **minimal** harmless workflow proof on fork of **your** test repo.

## False-Positive Reduction
- **Private** repos with required reviews may mitigate—state assumptions.

## Stealth + OPSEC Guidance
- Do not print secrets into issues; use coordinated disclosure.

## Replay Procedures
- Links to workflow commit SHAs + line numbers.

## Evidence Requirements
- YAML excerpts + explanation of blast radius.

## Reporting Methodology
- `permissions` minimal, environment protection rules, OIDC tightening, secret scanning.

## Confidence Scoring Logic
- Demonstrable secret access from fork: **critical** if program allows that test vector.

## Adaptive Branching Logic
- **Self-hosted runners** labels → runner hijack branch.

## Related Exploit Chains
- `skills/cloud/iam_abuse.md`

## Safety Boundaries
No supply-chain malware; no org-wide pipeline takeover.

## Output Artifact Requirements
`output/<target_slug>/cicd/` — `workflow_refs.md`, `yaml_snippets/`
