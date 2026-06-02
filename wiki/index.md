# Wiki Index

> Content catalog of the bug-bounty research wiki. Read this first to locate pages, then
> drill in. Updated on every ingest. See `SCHEMA.md` for conventions.

## Targets (hub)
| Page | Platform | Status | Summary |
|------|----------|--------|---------|
| [[tripadvisor]] | Bugcrowd | Active — APK + recon done, 14 reports | Travel platform + subsidiaries (Viator, Bókun, tamg.cloud, tapayments). WAF-gap & infra-disclosure goldmine. |
| [[vk]] | Standoff 365 | Active — R6 in vendor review, R2 fixed, R1/R3/R7 closed | VKontakte. Privacy-bypass/IDOR + 2FA bypass are the high-reward recurring classes. |

## Techniques (hub)
| Page | Class | Best evidence |
|------|-------|---------------|
| [[dns-first-recon]] | Recon | Foundation for 6+ Tripadvisor reports |
| [[response-header-forensics]] | Recon / info-disclosure | 3-4 findings per target; internal IP extraction |
| [[cors-probing]] | Web | 4 Tripadvisor reports; DataDome vendor bug |
| [[403-waf-bypass]] | Access / WAF | Systematic path/method/header/host/encoding |
| [[progressive-auth-probing]] | API / auth | GraphQL SigV4, Viator exp-api-key disclosures |
| [[unauthenticated-sms-send]] | API abuse / SMS | VK auth.validatePhone — 2 free SMS per phone, mass-targetable |

## Patterns
| Page | Type | Examples |
|------|------|----------|
| [[waf-gap-chain]] | Chaining / severity | tamg.cloud CDE, Bókun, Viator |
| [[public-api-key-pitfall]] | Severity / anti-pattern | Tripadvisor `adf6d1b8-...` (N/A lesson) |
| [[severity-calibration]] | Severity rubric | What elevates P4→P2 |
| [[two-endpoint-oauth-split]] | OAuth false positive | VK id.vk.com vs oauth.vk.com — UI reflection ≠ code theft |
| [[per-target-vs-mass-rate-limit]] | Rate limit bypass | Per-phone CAPTCHA doesn't prevent mass-targeting unique phones |

## Intel (disclosed-report analysis)
| Page | Target | Takeaway |
|------|--------|----------|
| [[vk-disclosed-reports]] | VK | 172 HackerOne reports → ranked attack paths |
| [[vk-r2-oauth-redirect-fix]] | VK | OAuth redirect_uri reflection — fixed by VK. Lesson: two-endpoint split |
| [[vk-r6-sms-abuse-live]] | VK | auth.validatePhone unauthenticated SMS — live, CAPTCHA behavior mapped |

## Findings (our own)
| Page | Target | Severity | Status |
|------|--------|----------|--------|
| [[tripadvisor-cde-waf-bypass]] | [[tripadvisor]] | P2 | submitted (REPORT_01) |
| [[tripadvisor-bokun-platform-misconfig]] | [[tripadvisor]] | P2 | submitted (REPORT_09) |

_VK submissions tracked inside [[vk]]; remaining Tripadvisor reports in `../output/tripadvisor/`._

## Chains
| Page | Target | Severity | Built from |
|------|--------|----------|-----------|
| [[tripadvisor-estate-waf-gap]] | [[tripadvisor]] | P2 | CDE + Bókun + Viator WAF gaps (systemic) |
| [[bokun-platform-compromise]] | [[tripadvisor]] | P2 | [[tripadvisor-bokun-platform-misconfig]] |
| [[vk-auth-chain]] | [[vk]] | High (theoretical) | auth.restore → auth.validatePhone → auth.confirm (enumerate → SMS → brute code) |

## Hypotheses (future investigation candidates)
| Page | Target | Confidence | Status |
|------|--------|------------|--------|
_None seeded yet — generate from intel/patterns via the **Hypothesize** op (see `SCHEMA.md`). A hypothesis is not a finding; it promotes to one only when confirmed._

## Assets (dedicated pages)
_None promoted yet — assets currently live as tables in [[tripadvisor]] and [[vk]]._
