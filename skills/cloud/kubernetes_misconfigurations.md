# Skill: Kubernetes Misconfigurations & RBAC

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `kubernetes_misconfigurations` |
| **version** | `1.0.0` |
| **category** | Cloud / Kubernetes |
| **correlates_with** | Exposed dashboards, anonymous API, CRDs, network policies |

## Objective
Identify **K8s** attack surface: **anonymous** API access, **overprivileged** service accounts, **hostPath** mounts, **`privileged`** pods, **exposed** dashboards, and **RBAC** bindings that allow **secrets** or **exec**—only on clusters you are authorized to test.

## Scope Rules
- Kubernetes testing can be **destructive**—follow ROE; no `delete` on prod namespaces without approval.
- Do not pivot to **cloud provider** APIs outside scope.

## Trigger Conditions
- Exposed API servers (`kubectl` works anonymously), kubeconfig in repos, dashboard URLs.

## Technology Fingerprints
- EKS, GKE, AKS, self-managed; ingress controllers; cert-manager.

## Recon Methodology
1. Version and **anonymous** auth flags (from allowed recon).
2. Enumerate **Roles/ClusterRoles** bindings to `system:authenticated`.
3. Check **default** service account automount in sensitive namespaces.

## MCP Tool Orchestration Logic
- `nmap_scan` / `httpx_probe` for API/dashboard exposure (if permitted).
- `nuclei_scan` for k8s misconfig templates.

**Branching:** If only **internal** kube API from compromised pod—clarify **entry** prerequisite.

## Reasoning Heuristics
- **`cluster-admin`** to **default** SA in user namespace is a common mis- pattern.
- **CRD** controllers may run as cluster-admin—supply chain angle.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Anonymous API read secrets |
| H2 | SA token escape to cloud metadata |
| H3 | `pods/exec` on system components |

## Validation Workflow
- `kubectl auth can-i` style checks if tooling allowed; else policy JSON proof.

## False-Positive Reduction
- **Intended** public ingress to app ≠ API server exposure.

## Stealth + OPSEC Guidance
- Read-only API calls; audit logs exist—coordinate with blue team.

## Replay Procedures
- Redacted `kubectl` commands or policy excerpts.

## Evidence Requirements
- RBAC YAML references; impact path.

## Reporting Methodology
- RBAC least privilege, disable anonymous auth, network policies, PSA, OPA/Gatekeeper.

## Confidence Scoring Logic
- Anonymous secret read: **critical** if confirmed.

## Adaptive Branching Logic
- **Helm** release secrets naming patterns → secret discovery branch.

## Related Exploit Chains
- `skills/cloud/container_escape.md`

## Safety Boundaries
No cluster-wide DoS; no crypto-mining pods.

## Output Artifact Requirements
`output/<target_slug>/k8s/` — `rbac_notes.md`, `exposure_evidence.txt`
