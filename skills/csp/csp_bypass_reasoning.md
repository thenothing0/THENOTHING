# Skill: CSP Bypass & Policy Weakness Reasoning

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `csp_bypass_reasoning` |
| **version** | `1.0.0` |
| **category** | Web / Browser policy |
| **correlates_with** | XSS, JSONP, Angular templates, strict-dynamic chains |

## Objective
Analyze **Content-Security-Policy** for **bypass paths** that turn an XSS primitive into execution, or for **policy design flaws** that materially weaken defense-in-depth. Report **policy text**, **bypass chain**, and **severity** separate from underlying XSS.

## Scope Rules
- CSP testing must stay on **in-scope** origins; do not load attacker scripts on unrelated domains.
- Respect **bug bounty** rules on “self-XSS + gadget” combinations.

## Trigger Conditions
- CSP headers present but allow `unsafe-inline`, wildcards, or broad `https:`.
- `strict-dynamic` with **nonce** gaps; **`base-uri`** missing; **`object-src`** `none` missing.
- Third-party script endpoints whitelisted (analytics, CDNs).

## Technology Fingerprints
- React/Next inline hydration; Angular `ng-app`; old jQuery JSONP.
- Browser extensions not in scope—note only.

## Recon Methodology
1. Collect CSP for **all** routes (login vs app vs API docs).
2. Build **allowlist graph**: scripts, frames, connects, styles.
3. Search for **gadgets**: JSONP, Angular CSP bypass patterns, open redirect to script host.
4. Test **nonce reuse** across navigation (SPA routers).

## MCP Tool Orchestration Logic
- `httpx_probe` — header collection per path.
- `katana_crawl` — route diversity for CSP variants.
- Manual analysis dominates—document in `notes.md`.

**Branching:** If **`script-src` nonced** and no XSS → down-rank; if XSS exists → map bypass.

## Reasoning Heuristics
- **`base-uri`** missing + relative script injection paths.
- **`uploads` same origin** + MIME sniff risk + CSP allows same-origin JS.
- **`strict-dynamic`** + import maps / modulepreload quirks (browser-specific).

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | JSONP endpoint in allowlist |
| H2 | Angular CSP bypass template |
| H3 | `data:` / `blob:` where allowed |
| H4 | Redirect chain loads allowed CDN with attacker-controlled path |

## Validation Workflow
1. Prove XSS or injection primitive **or** policy flaw standalone if program values defense gaps.
2. Demonstrate execution **with** CSP active (screenshot console).
3. Attempt **minimal** bypass chain; avoid heavy gadget chains if disallowed.

## False-Positive Reduction
- `unsafe-inline` alone is a finding but pair with **what XSS entry** exists.
- Report-only CSP ≠ enforcement.

## Stealth + OPSEC Guidance
- Console PoCs only; no public hosting of malware.

## Replay Procedures
- Save CSP header + exact URL + payload.

## Evidence Requirements
- CSP string; bypass chain diagram; execution proof.

## Reporting Methodology
- Remediation: tighten `script-src`, add `base-uri`, remove JSONP, adopt nonces + hashes correctly.

## Confidence Scoring Logic
- XSS + working bypass: **0.9**; theoretical gadget only: **≤0.55**.

## Adaptive Branching Logic
- **Multiple CSP variants** across CDN vs origin → matrix each.

## Related Exploit Chains
- `skills/xss/advanced_xss_hunting.md`

## Safety Boundaries
No serving exploits to other users; lab-only for chain stress tests.

## Output Artifact Requirements
`output/<target_slug>/csp/` — `policies/`, `bypass_chain.md`, `evidence.png`
