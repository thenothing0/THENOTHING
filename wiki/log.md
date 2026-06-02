# Wiki Log

> Append-only chronological record. One entry per ingest / query / lint.
> Prefix format: `## [YYYY-MM-DD] <op> | <summary>` so `grep "^## \[" log.md | tail` works.

## [2026-05-30] init | Wiki bootstrapped
Adapted the LLM Wiki pattern (`../CLAUDE1.md`) to bug-bounty research. Created `SCHEMA.md`,
`index.md`, `log.md`, and `_templates/` (target, technique, asset, pattern, finding, intel,
chain). Seeded from operator memory + `output/` + `scope.txt`:
- Targets: [[tripadvisor]], [[vk]]
- Techniques: [[dns-first-recon]], [[response-header-forensics]], [[cors-probing]],
  [[403-waf-bypass]], [[progressive-auth-probing]]
- Patterns: [[waf-gap-chain]], [[public-api-key-pitfall]], [[severity-calibration]]
- Intel: [[vk-disclosed-reports]]

Next suggested actions: promote individual Tripadvisor reports (REPORT_01 CDE WAF bypass,
REPORT_09 Bókun mega-report) into `finding` pages and build a [[waf-gap-chain]] chain page;
ingest the VK recon dump from `../output/vk_scan/` to populate [[vk]] assets.

## [2026-05-30] ingest | REPORT_9_BOKUN_PLATFORM_MISCONFIG.md → 5 pages
Source: `../output/tripadvisor/REPORT_9_BOKUN_PLATFORM_MISCONFIG.md` (P2, 12 sub-findings).
Created [[tripadvisor-bokun-platform-misconfig]] (finding) and [[bokun-platform-compromise]]
(chain, 6-step). Cross-linked into [[tripadvisor]] (findings table + next-actions),
[[waf-gap-chain]] (examples), and [[index]]. Confirmed it is *not* a [[public-api-key-pitfall]]
case — value rests on the $147K/mo abuse + systemic WAF gap, not key secrecy.

## [2026-05-30] ingest | REPORT_1_CDE_WAF_BYPASS.md + estate-wide chain → 6 pages
Source: `../output/tripadvisor/REPORT_1_CDE_WAF_BYPASS.md` (P2, CWE-693). Created
[[tripadvisor-cde-waf-bypass]] (finding). Built [[tripadvisor-estate-waf-gap]] — the systemic
WAF-gap chain across **3 subsidiaries/clouds**: CDE/tamg.cloud (REPORT_01), Bókun (REPORT_09),
Viator api.viator.com (REPORT_12, cited inline pending promotion to [[tripadvisor-viator-api-wafgap]]).
Cross-linked into [[tripadvisor]], [[waf-gap-chain]], [[index]]. Read REPORT_12 as supporting
evidence for the 3rd node. Open: promote REPORT_12; audit adjacent CDE hosts.

## [2026-05-30] schema | Added Reader Contract
Per operator: agents that read the wiki must *store and understand* it, not skim. Added the
"Reader contract" section to [[SCHEMA]].

## [2026-06-01] ingest | VK triage outcomes → 6 new wiki pages
VK reports triaged by Solimonka. Re-validated R1, R2, R6 with live testing.

**Intel pages created:**
- [[vk-r2-oauth-redirect-fix]]: OAuth redirect_uri reflection fixed by VK. Key lesson: two-endpoint OAuth split (UI vs code issuer).
- [[vk-r6-sms-abuse-live]]: auth.validatePhone still live. Mapped CAPTCHA behavior (2 free per phone/IP, then CAPTCHA; no limit on unique phones).

**Pattern pages created:**
- [[two-endpoint-oauth-split]]: OAuth UI reflecting redirect_uri ≠ exploitable if code issuer validates separately. High false-positive risk.
- [[per-target-vs-mass-rate-limit]]: Per-phone CAPTCHA/rate-limit doesn't prevent mass-targeting unique resources. Applies broadly.

**Technique page created:**
- [[unauthenticated-sms-send]]: Reusable playbook for testing phone validation endpoints. Workflow, impact arguments, cross-target applicability.

**Chain page created:**
- [[vk-auth-chain]]: auth.restore (enum) → auth.validatePhone (SMS) → auth.confirm (brute). Entry+pivot confirmed, escalation theoretical.

Updated [[index]] with all 6 new pages. Updated [[vk]] target status in index.

## [2026-06-01] schema | Added `hypothesis` node type
Closed the gap against the Report Intelligence System spec (hypothesis generation). Created
`hypotheses/` dir + `_templates/hypothesis.md` (falsifiable claim, supporting evidence,
confidence, validation plan, what-would-falsify). Registered `hypothesis` in [[SCHEMA]]
(page-types table, frontmatter keys `confidence`/`status`, new **Hypothesize** operation) and
added a Hypotheses section to [[index]]. No reports processed yet — scaffolding only. Next:
seed hypotheses from [[vk-disclosed-reports]] and the existing patterns via the Hypothesize op.
