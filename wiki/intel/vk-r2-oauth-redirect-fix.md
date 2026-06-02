---
type: intel
aliases: ["VK OAuth redirect fix"]
tags: [vk, oauth, redirect_uri, fixed]
target: "[[vk]]"
created: 2026-06-01
updated: 2026-06-01
sources: ["own testing", "VK triage response (Solimonka)"]
---
# VK ID OAuth redirect_uri Reflection — Fixed

## Summary
`id.vk.com/authorize` rendered login forms for deleted `client_id`s and reflected attacker-controlled `redirect_uri` into page state as `"outer":{"host":"evil.com"}`. Fixed by VK on or before 2026-06-01.

## Vulnerability class
OAuth misconfiguration / phishing vector (not code theft)

## Root cause
Deleted applications retained OAuth configuration. The UI layer (`id.vk.com`) embedded `redirect_uri` into JS init state without validation.

## Key finding: two-endpoint split
- `id.vk.com/authorize` = **UI page** (renders form, reflects redirect_uri)
- `oauth.vk.com/authorize` = **code issuer** (strictly validates redirect_uri → HTTP 401)
- Code theft was never achievable — the code-issuing layer was always secure

## Lessons learned
- [[two-endpoint-oauth-split]]: reflecting redirect_uri in UI ≠ exploitable if code issuer validates separately. Always test the token/code endpoint, not just the login page.
- Original report's "SAFE apps" (IDs 2685278, 6121396, 7913379) were a **methodology error** — they returned `{"error":"not found"}`, not validation. Grepping for `evil.com` in a 21-byte error page produces a false negative that looks like "validation."
- Triager asked for screenshot/video proof before evaluating. See [[proof-requirement-pattern]].

## Technique links
- [[progressive-auth-probing]]

## Pattern links
- [[two-endpoint-oauth-split]] (new — to create)
