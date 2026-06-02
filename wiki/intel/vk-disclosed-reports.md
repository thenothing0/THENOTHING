---
type: intel
aliases: ["VK intel", "VK pre-hunt research"]
tags: [vk, pre-hunt, hackerone]
target: "[[vk]]"
created: 2026-05-30
updated: 2026-05-30
sources: ["172 HackerOne disclosed VK reports"]
---
# VKontakte — Disclosed Report Analysis

> Pre-hunt research deliverable for [[vk]]. Built from 172 HackerOne disclosed reports.
> (Per the operator's standing rule: study disclosed reports before scanning a new target.)

## Sources reviewed
- 172 HackerOne disclosed VK reports. Re-pull via github.com/reddelexc/hackerone-reports,
  `site:medium.com vk vulnerability`, GitHub writeup collections.

## What pays most
| Class | Reward signal | Frequency |
|-------|---------------|-----------|
| Privacy bypass (view private photos/videos/posts) | $300–$5,000 historically; tier up to ₽3M | **#1 recurring** (20+ paid) |
| 2FA bypass | $1,000+ each | 3 separate bypasses — recurring weakness |
| SSRF (link preview / share bot) | ₽600,000 tier | confirmed historically |
| Mobile (Android) code exec | $3,000 | repeat |
| Stored XSS (messages/products) | $500–$1,000 | regular |
| Media-processing LFI/XXE (FFmpeg, pu.vk.com) | $500–$1,000 | confirmed (LFI $1k, blind XXE $500) |

## Recurring weakness patterns
1. **IDOR across the 1000+ VK API methods** (dev.vk.com/method) — privacy bypass is the dominant class.
2. **Weak 2FA** — `auth.restore`, session persistence, race conditions.
3. **SSRF surface** — link previews, share bots, webhook callbacks, app URLs.
4. **Media pipeline** — crafted uploads → FFmpeg LFI / XXE.

## Ranked attack paths (probability × reward)
1. API-method IDOR / privacy bypass (highest probability + highest reward).
2. 2FA bypass.
3. SSRF via link preview/bots.
4. Mobile app exploitation.
5. Stored XSS in messages/products.

## Feeds into
- [[vk]] attack plan. Apply [[progressive-auth-probing]] to the method catalog and auth endpoints.
