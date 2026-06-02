---
type: target
aliases: ["VKontakte", "VK", "vk.com", "vk.ru"]
tags: [social, api, idor, privacy-bypass, 2fa]
platform: standoff365
scope_status: in-scope
created: 2026-05-30
updated: 2026-05-30
---
# VKontakte (VK)

> Russian social platform on [[standoff365]]. Accepts English; operator registered as a
> foreign (Egyptian) researcher. **Highest reward-to-accessibility ratio is API-method IDOR
> / privacy bypass** — VK's #1 recurring bug class historically.

## Program facts
- **Platform / URL:** Standoff 365 — `bugbounty.standoff365.com/en-US/programs/vkontakte_vk/`
- **720 valid reports**, accepts English.
- **Reward tiers (₽):**
  | Class | VK ID | VKcom | Others |
  |-------|-------|-------|--------|
  | Server RCE | 3,600,000 | 2,000,000 | 1,200,000 |
  | Privacy Bypass | 3,000,000 | 2,000,000 | 1,000,000 |
  | SQLi | 1,500,000 | 1,200,000 | 900,000 |
  | IDOR | 1,200,000 | 600,000 | 300,000 |
  | SSRF | 600,000 (all) | | |
  | XSS | 60,000 (all) | | |

## Pre-hunt intel
→ [[vk-disclosed-reports]] (172 HackerOne reports analyzed). Ranked attack paths:
1. **IDOR on VK API methods** — highest probability; 20+ historical privacy bypasses paid $300–$5,000.
2. **2FA bypass** — recurring weakness; test `auth.restore`, session persistence, race conditions.
3. **SSRF via link preview / share bots / webhook callbacks**.
4. **Mobile app exploitation** — Android code exec paid $3,000.
5. **Stored XSS in messages/products** — $500–$1,000.

## Attack surface
### Assets / hosts (from recon — see `../output/vk_scan/`)
| Host | Type | Notes | Status |
|------|------|-------|--------|
| dev.vk.com/method | API method catalog | **1000+ methods** — fuzz for auth bypass / IDOR | in-scope |
| internal.api.vk.ru | Internal API | exposed publicly (Report 1, High) | in-scope |
| cashout.vk.ru | Financial platform | info disclosure (Report 3, Medium) | in-scope |
| pu.vk.com | Media/upload | Blind XXE confirmed historically ($500) | in-scope |
| VK ID (OAuth) | Auth | deleted-apps + arbitrary `redirect_uri` (Report 2) | in-scope |

### Auth flows (where it's weak)
- **2FA** historically weak — `auth.restore`, session persistence, race conditions.
- **VK ID OAuth** — deleted apps still resolve; `redirect_uri` validation gaps.
- **Unauthenticated API methods** — `auth.validatePhone` (SMS send), `auth.restore` (phone enum).

## Findings — 5 reports submitted 2026-05-29 (awaiting triage)
| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | internal.api.vk.ru public internal API | High | submitted |
| 2 | VK ID OAuth deleted apps + arbitrary redirect_uri | Medium | submitted |
| 3 | cashout.vk.ru financial platform info disclosure | Medium | submitted |
| 6 | `auth.validatePhone` unauthenticated SMS send | High | submitted |
| 7 | `auth.restore` phone enumeration | Medium | submitted |

_Reports 4 (cookie security) and 5 (infra fingerprint) NOT submitted — too low severity._

## Techniques to apply
- API-method IDOR fuzzing across dev.vk.com/method (1000+ methods) — highest priority.
- 2FA bypass testing → see [[progressive-auth-probing]].
- SSRF probing on link previews / share bots.
- Crafted media uploads (FFmpeg LFI paid $1,000; XXE on pu.vk.com).

## Open threads / next actions
- [ ] Track triage on the 5 submitted reports. If accepted → escalate with **authenticated** testing (authed IDOR untested). If rejected → analyze + adjust.
- [ ] Begin systematic API-method IDOR sweep (highest reward path, not yet done).
- [ ] Ingest `../output/vk_scan/` fully to populate asset table with concrete hosts.
