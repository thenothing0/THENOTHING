# Skill: Server-Side Template Injection (SSTI)

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `ssti_hunting` |
| **version** | `1.0.0` |
| **category** | Web / Code injection |
| **correlates_with** | XSS confusion, log injection, email/PDF templates |

## Objective
Detect template engines evaluating user input and **classify** engine family without jumping to destructive RCE chains. Build a **validation-first** proof (math/string probes) then escalate hypotheses only within ROE.

## Scope Rules
- Escalation to RCE payloads only when program **explicitly** allows; otherwise stop at **safe** evaluation proof (e.g. `7*7`).
- Sandbox destructive filesystem/exec probes in **lab** or **explicit** dev environments.

## Trigger Conditions
- Echo of template-like syntax: `{{`, `${`, `<%`, `#{`, `*{`.
- PDF/email/report customization fields.
- Error messages naming Jinja2, Twig, Freemarker, Velocity, Thymeleaf, Pebble, ERB.

## Technology Fingerprints
- **Python:** Jinja2, Django templates, Tornado.
- **Java:** Freemarker, Velocity, Thymeleaf, Pebble.
- **PHP:** Twig, Smarty, Blade (usually not SSTI but verify).
- **Node:** Handlebars (limited), Nunjucks, EJS.

## Recon Methodology
1. Map inputs that flow into **rendered documents** (not JSON APIs only).
2. Polyglot probes to detect evaluation vs reflection.
3. Identify **autoescape** and **sandbox** hints from docs/errors.
4. Separate **client template** (Vue) from **server template**.

## MCP Tool Orchestration Logic
- `httpx_probe` — baseline behavior and status codes.
- `ffuf_fuzz` — parameter discovery with **gentle** wordlist; throttle.
- `nuclei_scan` — SSTI templates as **signals**.
- `whatweb_detect` — stack hints.

**Branching:** High traffic production → **single-shot** probes then stop on positive signal pending approval.

## Reasoning Heuristics
- Math evaluation (`{{7*7}}` → `49`) is stronger than echo of braces.
- If only **client-side** rendering, down-rank SSTI; pivot XSS.
- Engine fingerprint guides **safe** next probes.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Evaluating SSTI with safe math |
| H2 | Sandboxed but info disclosure via globals |
| H3 | RCE gadget chain (ROE-gated) |
| H4 | SSTI → SSRF via template helpers |

## Validation Workflow
1. Safe evaluation proof.
2. Independent replay from second session.
3. If escalating, **snapshot** before/after and isolate blast radius.

## False-Positive Reduction
- WAF may strip `{{`—try encoding/alternate syntax.
- JSON string echo ≠ template evaluation.

## Stealth + OPSEC Guidance
- Minimal payloads; avoid log-poisoning noise; backoff on 500 storms.

## Replay Procedures
- Document exact body encoding and `Content-Type`.

## Evidence Requirements
- Request/response showing evaluation.
- Engine guess + why alternatives ruled out.

## Reporting Methodology
- Distinguish **confirmed SSTI** vs **suspected**; remediation: no user input in template context, sandbox, static templates.

## Confidence Scoring Logic
- Safe math proof: **0.85+**; ambiguous echo: ≤0.45.

## Adaptive Branching Logic
- PDF pipeline → focus file upload + render path.
- API returns raw template errors → increase priority.

## Related Exploit Chains
- `skills/xss/advanced_xss_hunting.md`
- `skills/deserialization/insecure_deserialization_web.md`

## Safety Boundaries
No production RCE without authorization; no data destruction.

## Output Artifact Requirements
`output/<target_slug>/ssti/` — `probes.log`, `replay.sh`, `engine_rationale.md`
