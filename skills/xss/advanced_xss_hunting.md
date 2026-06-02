# Skill: Advanced XSS Hunting

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `advanced_xss_hunting` |
| **version** | `1.0.0` |
| **category** | Web / Injection / Client execution |
| **operator_mode** | Validation-first; authorized scope only |
| **correlates_with** | DOM sinks, CSP policy, auth cookies, GraphQL errors |

## Objective
Identify **high-confidence** reflected, stored, and DOM-based XSS using contextual reasoning—not payload spam. Prioritize hypotheses where **reflection**, **sink**, and **execution context** align, then prove execution with replayable evidence within program rules.

## Scope Rules
- Operate only on hosts, parameters, and actions explicitly **in scope** (program brief or written client approval).
- Do not deploy persistent payloads against production users without **explicit** ROE; prefer self-owned accounts and labs.
- Stop if responses indicate **session fixation on third parties**, **CSAM-adjacent content**, or **out-of-scope** user data.
- All active probing must respect **rate limits** and **WAF/program** constraints.

## Trigger Conditions
- Parameters or headers reflected in HTML, JSON-to-HTML bridges, or error pages.
- DOM sinks identified (e.g. `innerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, URL → script assignment).
- Client templates rendering user-controlled fragments (React `dangerouslySetInnerHTML`, Vue `v-html`).
- Weak or absent **CSP** on sensitive routes, or CSP that still allows script gadgets.
- Post-auth surfaces where **role/context** changes reflection behavior.

## Technology Fingerprints
- **Frameworks:** React, Next.js, Vue, Angular, Svelte, HTMX, Alpine.
- **Transports:** Server-rendered HTML, SPA hydration, RSC/SSR boundaries, WebSockets delivering HTML snippets.
- **Defenses:** CSP nonces/hashes, Trusted Types, DOMPurify hooks, WAF HTML entity rewriting.

## Recon Methodology
1. **Map surface** — Crawl for forms, query params, fragments, WebSocket subprotocols, and API responses consumed by the DOM.
2. **Classify reflection** — Separate HTML context, attribute context, JS string context, URL context, CSS context.
3. **Trace sources → sinks** — For DOM XSS, follow `location`, `postMessage`, `localStorage`, query/hash into sinks.
4. **CSP inventory** — Parse `Content-Security-Policy` / `Report-Only`; note `unsafe-inline`, `strict-dynamic`, JSONP endpoints, allowed domains.
5. **Differential behavior** — Compare authenticated vs anonymous, mobile vs desktop, and edge vs origin.

## MCP Tool Orchestration Logic
| Phase | Tools (via MCP `hydra-security` names) | Logic |
|--------|----------------------------------------|--------|
| Surface | `katana_crawl`, `httpx_probe`, `gau_urls` | Build URL/parameter inventory; prefer passive depth first. |
| Live probe | `httpx_probe`, `whatweb_detect` | Confirm live hosts, TLS, redirects; avoid hammering dead assets. |
| Directed fuzz | `ffuf_fuzz` (tuned rate), `dalfox` / `gxss` **if exposed on your MCP** | Use only after WAF fingerprint; narrow to high-value params. |
| Scan sanity | `nuclei_scan` (tagged templates) | Treat as **signals** only—never sole proof. |
| WAF | `wafw00f_detect` | Adjust payload classes and pacing. |

**Branching:** If `wafw00f` reports strict WAF → reduce `ffuf`/`dalfox` concurrency; pivot to DOM + CSP gadget paths and encoding bypass research *within* validation rules.

## Reasoning Heuristics
- **Correlate** reflection location with sink type: attribute breakout ≠ HTML body breakout.
- Infer **partial sanitization** (strip tags but leave attributes, or allow `svg`/`math`).
- Treat **framework-specific** escaping: React text nodes vs attributes; Vue compiler vs runtime.
- Consider **second-order** XSS: stored JSON later rendered as HTML.
- Weight **CSP** as a down-rater for *probability of exploit* but not for *severity of design flaw*—report unsafe patterns even if CSP blocks today.

## Attack-Path Hypotheses
| ID | Hypothesis | Falsification |
|----|----------------|---------------|
| H1 | Reflected HTML/attribute injection executes | Encoding/context prevents closure; CSP blocks without gadget path |
| H2 | DOM XSS via hash/query → sink | Strict parser + no sink or Trusted Types enforce |
| H3 | Stored XSS in user-visible content | Output encoding at render; CSP + nonce |
| H4 | CSP bypass via JSONP, allowed CDN, or strict-dynamic chain | No reachable gadget; nonce binds correctly |
| H5 | Template/client pivot (SSTI vs XSS confusion) | Server returns literal; no template evaluation |

## Validation Workflow
1. **Minimal PoC** — Smallest payload proving execution (`alert`, `print`, `postMessage` to self).
2. **Replay** — Same steps from clean session/incognito; capture HAR.
3. **Screenshot / video** — Show execution context (URL, account role).
4. **Control case** — Nearby parameter or sibling route that does **not** execute.
5. **Impact upgrade check** — Cookie `HttpOnly`? Sensitive actions without CSRF? (chain only if in scope.)

## False-Positive Reduction
- Reject **scanner-only** hits without manual replay.
- Ignore **self-XSS** unless program counts it and impact exists.
- Distinguish **MIME sniff** / **download** quirks from XSS.
- Require **JavaScript execution** proof—not merely reflected angle brackets.

## Stealth + OPSEC Guidance
- **Stealth:** Adaptive pacing, jitter delays, backoff on 429/403 spikes; prefer passive URL sources before active fuzz.
- **OPSEC:** Do not embed real credentials in PoCs; use throwaway accounts; redact third-party PII from evidence bundles.

## Replay Procedures
1. Document exact URL, method, body, and headers (copy from Burp-style export or MCP-saved artifact).
2. Replay with **same** `User-Agent`/`Accept-Language` if behavior differs.
3. If time-sensitive, note clock/token TTL and attach renewal steps.

## Evidence Requirements
- Raw HTTP request + response (or HAR).
- Screenshot or short clip of execution.
- CSP header snapshot at time of test.
- One-paragraph **root cause** (which sink, which source).

## Reporting Methodology
- **Title:** clear vulnerability class + affected component.
- **Impact:** concrete attacker capability (session, account actions, data read).
- **Affected parameter / sink:** precise.
- **Reproduction:** numbered steps, non-destructive.
- **Remediation:** encode by context, CSP + Trusted Types, framework-safe APIs.

## Confidence Scoring Logic
- Start at **0.5**.
- **+0.15** independent replay success; **+0.1** screenshot; **+0.1** second context confirmed (e.g. different browser).
- **−0.2** if only reflection without execution; **−0.15** if CSP clearly blocks and no gadget path documented.
- **Report threshold:** ≥ **0.80** for submission-grade; 0.55–0.79 as “suspected” internally.

## Adaptive Branching Logic
- **WAF strict** → DOM/CSP branch; reduce scanner noise.
- **Heavy SPA** → prioritize `katana` + JS bundle review (manual) over blind `ffuf`.
- **Auth-only reflection** → pivot to stored/second-order and IDOR+XSS chain **if** scope allows object reference testing.

## Related Exploit Chains
- `skills/csp/csp_bypass_reasoning.md`
- `skills/cors/cors_exploitation.md`
- `skills/api/graphql_introspection_abuse.md` (errors reflecting in UI)

## Safety Boundaries
No phishing of real users, no malware distribution, no crypto-mining payloads, no access to out-of-scope systems—even as “impact demo.”

## Output Artifact Requirements
Store under `output/<target_slug>/xss/`:
- `evidence.har` (sanitized)
- `screenshots/`
- `notes.md` (hypothesis log with confidence deltas)
- `replay_curl.sh` or equivalent minimal repro
