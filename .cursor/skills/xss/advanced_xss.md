# Skill: Advanced XSS (Cursor path)

## Metadata
| **id** | `advanced_xss` |
| **version** | `1.0.0` |
| **see_also** | `.cursor/skills/web/xss.md` |
| **output_root** | `output/<target>/evidence/xss/` |

## Objective
Same mission as `web/xss.md`: validated XSS hunting with CSP and DOM awareness; this file is the **shortcut path** referenced in examples (`@.cursor/skills/xss/advanced_xss.md`).

## Trigger Conditions
Reflection, DOM sinks, unsafe HTML APIs, post-auth rendering differences.

## Technology Fingerprints
React/Next/Vue/Angular; RSC/SSR boundaries; CSP variants.

## Reasoning Heuristics
Correlate reflection context with sink; second-order stored flows; partial encoders.

## Exploit Hypotheses
Reflected, stored, DOM, CSP-gadget-assisted XSS.

## MCP Orchestration Logic
`katana_crawl` → `httpx_probe` → `wafw00f_detect` → `ffuf_fuzz` (narrow) → `nuclei_scan` → optional dalfox/gxss if MCP exposes them.

## Stealth Guidance
Adaptive pacing; WAF-aware payload classes; backoff on blocks.

## Validation Workflow
Execution proof → replay → screenshot/HAR → control case.

## Evidence Requirements
Store under `evidence/` and `screenshots/` per `.cursor/rules/output-artifacts.mdc`.

## Adaptive Branching
CSP strict → pair with `web/csp_bypass.md`; heavy SPA → `browser/dom_reasoning.md`.

## Confidence Scoring
Submission ≥0.8 with execution + replay.

## Replay Logic
Minimal repro script in `replay/`.

## Reporting Guidance
Impact, parameter/sink, CSP, remediation (encode, CSP, Trusted Types).
