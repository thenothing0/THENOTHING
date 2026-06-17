# Skill: Container & Image Supply Surface

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `container_image_supply_surface` |
| **version** | `1.0.0` |
| **category** | Cloud-native / Containers |
| **correlates_with** | Exposed registries, leaked image secrets, K8s exposure, CI/CD |

## Objective
Find exposed container **registries** and analyze **images** for baked-in secrets, sensitive layers, and
misconfigurations that lead to access — feeding the Kubernetes and cloud skills.

## Scope Rules
- In-scope registries/images only; pull is read-only; no pushes.
- Validate any discovered secret read-only.

## Trigger Conditions
- `docker_registry`, `k8s_manifest`; `/v2/_catalog`, `*.dkr.ecr.*`, `gcr.io`, `ghcr.io`, registry ports.

## Technology Fingerprints
- Docker Registry v2, Harbor, ECR/GCR/ACR, GHCR, Quay.

## Recon Methodology
1. Probe `/v2/` and `/v2/_catalog` for anonymous catalog/list access.
2. Pull in-scope image manifests/layers; scan layers for secrets/config.
3. Map images back to running workloads (K8s).

## MCP Tool Orchestration Logic
- `httpx_probe` — registry `/v2/` reachability + auth posture.
- `nuclei_scan` — exposed-registry / misconfig templates.
- `attack_js_extract` — secrets in image-bundled JS/config artifacts.

## Reasoning Heuristics
- Anonymous `/v2/_catalog` → full image inventory → targeted secret hunting.
- Secrets baked into layers/ENV are common (API keys, cloud creds, .npmrc).
- Image tags reveal internal naming/versions for further recon.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|------------|
| H1 | Anonymous registry catalog/list |
| H2 | Baked-in secret in an image layer (validate read-only) |
| H3 | Internal image leaks build/config intelligence |

## Validation Workflow
1. Demonstrate anonymous catalog/manifest read (minimal).
2. Validate a discovered secret read-only; reverify downstream access.

## False-Positive Reduction
- A public base image's contents are not a finding — focus on the org's own images.
- Expired/rotated secrets in old layers — confirm validity before reporting.

## Stealth + OPSEC Guidance
- Pull selectively; do not mass-download large images/layers.

## Replay Procedures
- Save the catalog response, the layer path, and the redacted secret location.

## Evidence Requirements
- Anonymous access proof and/or validated-secret proof (redacted), remediation.

## Confidence Scoring Logic
- Valid secret granting access: high; anonymous catalog only: medium/info.

## Adaptive Branching Logic
- Cloud creds found → relevant `skills/<cloud>/*`; running workloads → `skills/kubernetes/*`.

## Related Exploit Chains
- `skills/cloud/cicd_exposure.md`, `skills/cloud/container_escape.md`

## Safety Boundaries
Read-only pulls; no registry pushes; PoC-only secret validation.

## Output Artifact Requirements
`output/<target_slug>/containers/` — `catalog.json`, `image_secrets_redacted.json`
