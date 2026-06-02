# Skill: Container Escape & Host Boundary Reasoning

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `container_escape` |
| **version** | `1.0.0` |
| **category** | Cloud / Containers |
| **correlates_with** | docker.sock mounts, privileged, caps, kernel CVEs |

## Objective
Assess **workload isolation** failures: **`docker.sock`**, **`privileged`**, dangerous **capabilities**, **hostPath** to `/`, **shared PID/network** namespaces, and **outdated** kernels—only in **lab** clusters or with **explicit** client approval on non-prod.

## Scope Rules
- Host escape attempts on **production** are often forbidden—confirm.
- No destructive host filesystem tests.

## Trigger Conditions
- Pod specs in CI logs, Helm charts, docker-compose in repos.

## Technology Fingerprints
- containerd, runc, gVisor, kata, AppArmor/Seccomp profiles.

## Recon Methodology
1. Static review of manifests for **dangerous** fields.
2. If dynamic allowed, enumerate **capabilities** and **mounts** from inside **test** pod.

## MCP Tool Orchestration Logic
- Repo scanning via local tools; MCP `nuclei_scan` for exposed Docker APIs.

## Reasoning Heuristics
- **`docker.sock`** in user workload is near-critical if reachable.
- **CAP_SYS_ADMIN** + specific kernel ranges → literature-based risk scoring.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | docker.sock → host root |
| H2 | privileged breakout |
| H3 | hostPath shadowing |

## Validation Workflow
- **Lab** reproduction only unless approved; document kernel version matrix.

## False-Positive Reduction
- **CI** `docker.sock` on isolated builder may be accepted architecture—ask.

## Stealth + OPSEC Guidance
- Do not exfiltrate host SSH keys; use benign proof files in lab.

## Replay Procedures
- Manifest snippet + lab pod logs.

## Evidence Requirements
- Policy vs actual `securityContext` diff.

## Reporting Methodology
- Drop caps, readOnlyRootFilesystem, seccomp/apparmor, no socket mounts, runtime security.

## Confidence Scoring Logic
- docker.sock reachable from app container in prod: **0.95** if proven.

## Adaptive Branching Logic
- **Windows** containers → different escape class.

## Related Exploit Chains
- `skills/cloud/kubernetes_misconfigurations.md`

## Safety Boundaries
No real host compromise outside lab.

## Output Artifact Requirements
`output/<target_slug>/containers/` — `manifest_findings.md`
