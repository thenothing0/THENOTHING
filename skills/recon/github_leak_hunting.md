# Skill: GitHub & Code-Host Leak Hunting

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `github_leak_hunting` |
| **version** | `1.0.0` |
| **category** | Recon / OSINT |
| **correlates_with** | CI keys, `.env`, Terraform, internal URLs |

## Objective
Discover **accidental exposures** in public (or authorized internal) repos: secrets, **endpoints**, **IAM** hints, and **pivot** artifacts. Operate under **GitHub ToS** and program rules; prefer **read-only** search APIs.

## Scope Rules
- Only repos **in scope** (org name, keywords per brief). No downloading private repos without authorization.
- If you find **live secrets**, rotate via coordinated disclosure—do not use them.

## Trigger Conditions
- Program mentions GitHub org; leaks in historical commits; forked repos.

## Technology Fingerprints
- GitHub/GitLab/Bitbucket search; `gitleaks`-class patterns mentally.

## Recon Methodology
1. Construct **queries** (`org:`, `filename:.env`, `extension:tf`).
2. Review **commit history** for deleted secrets (still reachable).
3. Correlate endpoints with **subdomain** graph.

## MCP Tool Orchestration Logic
- `httpx_probe` on URLs found in code.
- `katana_crawl` / `gau_urls` for related endpoints.
- Manual GitHub UI/API—document queries in `output/`.

## Reasoning Heuristics
- **Forks** may expose secrets removed upstream.
- **LFS** and **release assets** often forgotten.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Long-lived cloud key in repo |
| H2 | Internal admin URL in README |
| H3 | Mobile app signing keys |

## Validation Workflow
- **TruffleHog**-style confirmation in isolated env; never paste secrets into tickets raw.

## False-Positive Reduction
- **Sample** keys in docs; revoked keys—verify with safe `sts get-caller-identity` only if allowed.

## Stealth + OPSEC Guidance
- Do not star/watch in ways that alert competitors; use program channels.

## Replay Procedures
- Commit SHA + file path + redacted snippet hash.

## Evidence Requirements
- Redacted proof + rotation guidance.

## Reporting Methodology
- Secret scanning in CI, pre-commit hooks, vault, GitHub org rules.

## Confidence Scoring Logic
- Verified active secret: **critical**; historical only: depends on revocation.

## Adaptive Branching Logic
- **Monorepo** vs microrepo explosion → prioritize services in scope.

## Related Exploit Chains
- `skills/cloud/cicd_exposure.md`

## Safety Boundaries
No extortion; legal compliance for data handling.

## Output Artifact Requirements
`output/<target_slug>/recon/github/` — `queries.md`, `hits_redacted.csv`
