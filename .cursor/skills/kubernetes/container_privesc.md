# Skill: Container Privilege Escalation (Reasoning)

## Metadata
| **id** | `kubernetes_container_privesc` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/containers/` |

## Objective
From manifests and (authorized) runtime checks, identify docker.sock mounts, `privileged`, dangerous caps, hostPath to sensitive paths, and outdated runc/kernel risk classes.

## Trigger Conditions
Helm values, docker-compose in repo, CI build logs leaking pod specs.

## Technology Fingerprints
containerd/runc, gVisor/Kata, AppArmor/seccomp profiles.

## Reasoning Heuristics
`docker.sock` in app workload ≈ critical if reachable; distinguish CI isolated builders from prod workload specs.

## Exploit Hypotheses
Host escape via socket; privileged breakout; hostPath shadowing.

## MCP Orchestration Logic
Repo static analysis + `nuclei_scan` for exposed Docker APIs (scope gated).

## Stealth Guidance
Lab-only dynamic escape proofs; no host harm.

## Validation Workflow
Manifest evidence + lab repro note; no prod exploitation without ROE.

## Evidence Requirements
YAML snippets, risk rationale, kernel/runc version matrix if collected.

## Adaptive Branching
K8s misconfig skill for cluster-admin SA mounted into risky pods.

## Confidence Scoring
0.95 reachable docker.sock in prod app namespace; theoretical cap = lower.

## Replay Logic
Manifest file paths + commit SHAs.

## Reporting Guidance
Drop caps, no socket mounts, readOnlyRootFilesystem, seccomp/apparmor, runtime security.
