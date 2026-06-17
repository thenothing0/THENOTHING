# Skill: CI/CD Exposure Reasoning

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `cicd_pipeline_exposure` |
| **version** | `1.0.0` |
| **category** | CI/CD / Supply chain |
| **correlates_with** | Leaked secrets, exposed build configs, artifact registries, SSRF |

## Objective
Surface exposed CI/CD assets — public pipeline configs, build logs, runner endpoints, and leaked
tokens — that reveal secrets or enable supply-chain footholds, PoC-only.

## Scope Rules
- In-scope CI/CD assets only; read-only; validate secrets read-only.
- No pipeline execution / no injecting build steps.

## Trigger Conditions
- `github_actions`, `jenkins`, `gitlab_ci`; `.github/workflows`, `Jenkinsfile`, `.gitlab-ci.yml`, runner URLs.

## Technology Fingerprints
- GitHub Actions, GitLab CI, Jenkins, CircleCI, Argo, Drone, TeamCity.

## Recon Methodology
1. Locate exposed pipeline configs and build logs (web + JS + repos).
2. Check Jenkins/CI dashboards for unauth access (`/script`, `/api`, build histories).
3. Extract secrets/tokens from logs/configs; map to cloud/registry access.

## MCP Tool Orchestration Logic
- `httpx_probe` — CI dashboards/runner endpoints + auth posture.
- `nuclei_scan` — exposed-Jenkins/GitLab/CI templates.
- `attack_js_extract` / `gau_urls` — leaked configs, tokens, build artifacts in history.

## Reasoning Heuristics
- Public build logs leak secrets (env dumps, registry creds, cloud keys).
- Unauth Jenkins `/script` (Groovy console) = RCE-class exposure.
- Pipeline configs reveal deploy targets and trust relationships.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|------------|
| H1 | Public build log leaks a valid secret |
| H2 | Unauth Jenkins/CI console |
| H3 | Pipeline config exposes deploy creds/targets |

## Validation Workflow
1. Demonstrate the exposure (unauth read / leaked secret) minimally.
2. Validate the secret read-only; reverify; map blast radius.

## False-Positive Reduction
- Masked/rotated secrets in logs — confirm validity.
- A login-gated CI dashboard is not "exposed".

## Stealth + OPSEC Guidance
- Read-only; never trigger builds or inject steps; no console command execution beyond identity proof.

## Replay Procedures
- Save the exposed config/log path and the redacted secret location.

## Evidence Requirements
- Exposure proof + validated-secret proof (redacted), remediation (secret hygiene, auth, log masking).

## Confidence Scoring Logic
- Valid secret / unauth console: high/critical; config exposure only: medium.

## Adaptive Branching Logic
- Cloud/registry creds found → `skills/<cloud>/*` / `skills/containers/container_image_supply_surface.md`.

## Related Exploit Chains
- `skills/cloud/cicd_exposure.md`, `skills/exploit_chains/exploit_chain_composition.md`

## Safety Boundaries
No pipeline execution / build injection; PoC-only secret validation.

## Output Artifact Requirements
`output/<target_slug>/cicd/` — `exposed_configs.md`, `secrets_redacted.json`
