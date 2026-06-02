# Skill: HTTP Request Smuggling & Desync Reasoning

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `http_request_smuggling` |
| **version** | `1.0.0` |
| **category** | Web / HTTP protocol abuse |
| **correlates_with** | Reverse proxies, CDNs, WAFs, connection reuse |

## Objective
Reason about **frontend/backend desynchronization** (CL.TE, TE.CL, TE.TE) and **pipeline** risks. Confirm with **time-safe** techniques and program approval—smuggling tests can be **high impact** and disruptive.

## Scope Rules
- Obtain **explicit** authorization; many programs prohibit or tightly scope smuggling.
- Prefer **lab** replay of captured stacks; avoid production connection poisoning.
- Stop immediately on elevated 502/503 storms or origin instability.

## Trigger Conditions
- HTTP/1.1 hop-by-hop with multiple proxies (CDN → origin).
- `Transfer-Encoding` + `Content-Length` both present (implementation quirks).
- Custom headers from CDN vendors suggesting pipeline reuse.

## Technology Fingerprints
- **Proxies:** nginx, Apache, HAProxy, Envoy, CloudFront, Cloudflare, Akamai (vendor-specific behaviors).
- **HTTP/2** downgrades and **H2C** upgrade paths.

## Recon Methodology
1. Map **full chain** from client to origin (headers stripped/added).
2. Time **CL vs TE** parsing using **harmless** desync probes (researcher-tuned, not destructive).
3. Correlate with **timeout** patterns and **retry** semantics.
4. Document HTTP version per hop.

## MCP Tool Orchestration Logic
- `httpx_probe` — HTTP version, TLS, header echo where visible.
- `nuclei_scan` — smuggling templates **only if** program allows.
- Manual tooling often required beyond MCP—**do not** fake MCP output.

**Branching:** If program disallows → document **theoretical** risk with architecture review only.

## Reasoning Heuristics
- Treat ambiguous parsing as **graph** of possibilities, not one payload.
- Prefer **timing** + **collaborator** (if allowed) over blind tunneling.
- Link to **ACL bypass** only with in-scope proof.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | CL.TE request splitting |
| H2 | TE.CL obfuscation |
| H3 | H2 downgrade smuggling |
| H4 | Cache poisoning via desync (tie to cache skill) |

## Validation Workflow
1. Minimal desync probe with safety caps.
2. Observe **stable** differential vs control.
3. Second independent repro; capture TCP/TLS notes.

## False-Positive Reduction
- Random 502s from flaky origin ≠ smuggling.
- WAF anomalies without backend split ≠ confirmed.

## Stealth + OPSEC Guidance
- Extreme throttling; maintenance windows if program specifies; alert ops if coordinated disclosure requires.

## Replay Procedures
- Raw socket or trusted repro script; version-locked.

## Evidence Requirements
- Diagram of hop chain + minimal repro + impact scoped to program assets.

## Reporting Methodology
- Clear **disruption risk**; remediation: patch proxy versions, disable ambiguous TE, strict HTTP/2.

## Confidence Scoring Logic
- Single odd response: low; reproducible split with controlled second request: high (if allowed).

## Adaptive Branching Logic
- **CDN present** → vendor-specific research branch.
- **HTTP/2 only** → downgrade surface analysis.

## Related Exploit Chains
- `skills/cache_poisoning/web_cache_poisoning.md`

## Safety Boundaries
Do not weaponize for traffic hijacking outside scope; no customer session theft demos without approval.

## Output Artifact Requirements
`output/<target_slug>/smuggling/` — `architecture.md`, `repro_notes.md`, `ethics_approval.txt` (if applicable)
