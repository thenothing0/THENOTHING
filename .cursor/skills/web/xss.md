# Skill: XSS (Reflected, Stored, DOM)

## Metadata
| **id** | `web_xss` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/xss/` |

## Objective
Find and **validate** XSS with context-aware reasoning (HTML, attribute, JS, URL, SVG) and framework-specific sinks.

## Trigger Conditions
Reflection in responses; DOM sinks in JS bundles; weak/absent CSP on sensitive routes.

## Technology Fingerprints
React, Next.js, Vue, Angular, HTMX, server templates adjacent to SPA.

## Reasoning Heuristics
- Map **source → sink**; separate reflection from **execution**.  
- Infer **partial** sanitization and parser differentials.  
- Consider **second-order** stored JSON rendered as HTML later.

## Exploit Hypotheses
**H1** reflected HTML; **H2** DOM via hash/query; **H3** stored in user-visible content; **H4** CSP gadget chain.

## MCP Orchestration Logic
`katana_crawl` → `httpx_probe` → `whatweb_detect` / `wafw00f_detect` → targeted `ffuf_fuzz` (throttled) → `nuclei_scan` (XSS tags) → external `dalfox`/`gxss` **only if** present on MCP.

## Stealth Guidance
Adaptive pacing; avoid burst identical payloads; respect WAF after fingerprint.

## Validation Workflow
Minimal PoC → replay → screenshot/HAR → control parameter case → severity gate.

## Evidence Requirements
HAR (redacted), screenshot, CSP snapshot, replay script in `replay/`.

## Adaptive Branching
WAF strict → DOM/CSP branch; SPA-heavy → prioritize `browser/dom_reasoning.md`.

## Confidence Scoring
≥0.8 for submission with execution proof; 0.4–0.7 = suspected reflection only.

## Replay Logic
Store curl/httpie or MCP-captured request exactly; note cookies/session.

## Reporting Guidance
Impact, affected parameter/sink, repro, remediation (context encoding, CSP, Trusted Types).
