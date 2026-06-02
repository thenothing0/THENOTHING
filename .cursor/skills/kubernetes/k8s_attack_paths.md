# Skill: Kubernetes Attack Paths

## Metadata
| **id** | `kubernetes_attack_paths` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/k8s/` |

## Objective
Assess RBAC, anonymous API access, dangerous pod securityContext, exposed dashboards, and secret mounting—**authorized clusters only**; avoid destructive actions.

## Trigger Conditions
Exposed API, kubeconfig in repos, cluster-admin bindings to default SA, hostPath/privileged pods.

## Technology Fingerprints
EKS/GKE/AKS, ingress controllers, cert-manager, Helm releases.

## Reasoning Heuristics
Map **cluster-admin** edges to **default** SAs; check `system:authenticated` bindings; CRD controllers running as cluster-admin.

## Exploit Hypotheses
Anonymous secret read; `pods/exec` to sensitive workloads; metadata exfil from pods (scope).

## MCP Orchestration Logic
`httpx_probe` / `nmap_scan` (if allowed) for API/dashboard exposure → `nuclei_scan` k8s templates.

## Stealth Guidance
Read-only API verbs first; coordinate with blue team if production.

## Validation Workflow
`kubectl auth can-i` style evidence if tooling permitted; else static manifest proof.

## Evidence Requirements
Redacted RBAC YAML references, exposure proof, impact path.

## Adaptive Branching
Container breakout primitives → document link to `cloud` container hardening reviews.

## Confidence Scoring
0.95 anonymous secret read if confirmed; static misconfig without exposure = medium policy finding.

## Replay Logic
Redacted command transcript in `replay/`.

## Reporting Guidance
RBAC least privilege, disable anonymous auth, PSA, network policies, OPA/Gatekeeper, secret hygiene.
