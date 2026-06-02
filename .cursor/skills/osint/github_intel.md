# Skill: OSINT — GitHub & Code-Host Intel

## Metadata
| **id** | `osint_github_intel` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/recon/osint/` |

## Objective
Discover leaks and pivot artifacts in **in-scope** repos: endpoints, keys, internal URLs, Terraform—read-only search compliant with host ToS and program rules.

## Trigger Conditions
Program lists GitHub org; subdomain hints; dependency footprints.

## Technology Fingerprints
GitHub/GitLab search; gitleaks-style patterns (manual).

## Reasoning Heuristics
Forks may retain deleted secrets; historical commits; release assets; LFS objects.

## Exploit Hypotheses
Live cloud keys; kubeconfigs; CI secrets.

## MCP Orchestration Logic
`httpx_probe` on URLs from code; `gau_urls` for related endpoints; avoid automated secret exfil beyond proof.

## Stealth Guidance
Do not star/fork in noisy ways; coordinate disclosure; rotate keys via customer.

## Validation Workflow
Verify key **class** safely where program allows; otherwise hash + metadata only.

## Evidence Requirements
`queries.md`, `hits_redacted.csv`, commit SHAs.

## Adaptive Branching
CI files → `cloud/cicd_exposure.md`.

## Confidence Scoring
0.95 confirmed active secret (with rotation path); sample keys in docs = low.

## Replay Logic
Search query string + permalink to line.

## Reporting Guidance
Secret scanning, branch protection, org rules, vault, pre-commit hooks.
