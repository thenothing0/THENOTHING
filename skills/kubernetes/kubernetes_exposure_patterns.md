# Skill: Kubernetes Exposure Patterns

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `kubernetes_exposure_patterns` |
| **version** | `1.0.0` |
| **category** | Cloud-native / Kubernetes |
| **correlates_with** | Exposed API server, dashboard, kubelet, etcd, SSRF, leaked kubeconfig |

## Objective
Find exposed Kubernetes control/data-plane surfaces — unauth **API server**, **dashboard**, **kubelet**
(10250), **etcd** (2379) — and misconfigurations that yield cluster information or workload access,
PoC-only.

## Scope Rules
- In-scope clusters/hosts only; read-only enumeration; no workload disruption.

## Trigger Conditions
- `k8s_api`, `dashboard`, `kubeconfig_leak`; ports 6443/8443/10250/2379, `/api/v1`, dashboard paths.

## Technology Fingerprints
- kube-apiserver, Kubernetes Dashboard, kubelet, etcd, Rancher, OpenShift, ingress-nginx.

## Recon Methodology
1. Port-scan for control-plane/data-plane services on in-scope hosts.
2. Probe API server `/version`, `/api`, `/apis` unauthenticated.
3. Check dashboard auth and kubelet read endpoints; hunt leaked kubeconfig in JS/repos.

## MCP Tool Orchestration Logic
- `nmap_scan` — 6443/8443/10250/2379/2380 exposure.
- `httpx_probe` — API server/dashboard reachability + auth posture.
- `nuclei_scan` — k8s exposure/misconfig templates.
- `attack_js_extract` — leaked kubeconfig/tokens in bundles.

## Reasoning Heuristics
- Anonymous `system:anonymous` with list verbs → cluster recon → escalation.
- Read-only kubelet (10250) `/pods` leaks workloads/secrets mounts.
- A leaked kubeconfig/SA token is full or scoped cluster access (PoC-only).

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|------------|
| H1 | Unauth API server allows resource listing |
| H2 | Exposed dashboard without auth |
| H3 | Kubelet read endpoints leak pod/secret info |
| H4 | Leaked kubeconfig/token grants access |

## Validation Workflow
1. Demonstrate an unauthenticated read (e.g. namespace/pod list) — minimal.
2. For tokens, prove identity (`whoami`-equivalent), not mass actions; reverify.

## False-Positive Reduction
- A 401/403 from the API server is correct behavior, not a finding.
- An exposed port behind mTLS is not unauthenticated.

## Stealth + OPSEC Guidance
- Read-only; no `kubectl exec`/delete/scale; no workload disruption.

## Replay Procedures
- Save the unauth request/response and the (redacted) kubeconfig path.

## Evidence Requirements
- The unauthenticated read proof, remediation (RBAC, anonymous-auth off, network policy).

## Confidence Scoring Logic
- Unauth cluster read / valid token: high/critical; exposed-but-authed surface: info/medium.

## Adaptive Branching Logic
- Container/registry exposure → `skills/containers/container_image_supply_surface.md`.

## Related Exploit Chains
- `skills/cloud/kubernetes_misconfigurations.md`, `skills/cloud/container_escape.md`

## Safety Boundaries
Read-only enumeration; no workload changes; PoC depth only.

## Output Artifact Requirements
`output/<target_slug>/k8s/` — `exposure.json`, `unauth_reads.md`
