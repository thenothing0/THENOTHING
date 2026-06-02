# Skill: SSTI

## Metadata
| **id** | `web_ssti` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/ssti/` |

## Objective
Detect evaluated template expressions with **safe** proofs (`7*7`), then escalate hypotheses only under ROE.

## Trigger Conditions
Template-like delimiters echoed; PDF/email customization; template engine errors.

## Technology Fingerprints
Jinja2, Twig, Freemarker, Velocity, Thymeleaf, Pebble, ERB.

## Reasoning Heuristics
Separate client template from server evaluation; engine fingerprint guides next safe probes.

## Exploit Hypotheses
**H1** math evaluation; **H2** sandbox escape read; **H3** RCE gadget (ROE-gated).

## MCP Orchestration Logic
`httpx_probe` → `ffuf_fuzz` (gentle) → `nuclei_scan` (SSTI) → manual confirmation.

## Stealth Guidance
Single-shot probes on high-traffic prod until signal; then pause for approval.

## Validation Workflow
Safe eval proof → replay → escalate only if allowed.

## Evidence Requirements
Request/response, engine rationale, redacted errors.

## Adaptive Branching
If only client Vue/React → pivot `browser/dom_reasoning.md`.

## Confidence Scoring
0.85+ with clear evaluation; echo-only <0.45.

## Replay Logic
Exact encoding and `Content-Type` documented.

## Reporting Guidance
Remove user input from template context, sandbox, upgrade engine, safe APIs.
