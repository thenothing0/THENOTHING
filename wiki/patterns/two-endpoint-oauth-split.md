---
type: pattern
aliases: ["OAuth UI vs code issuer", "two-endpoint OAuth"]
tags: [oauth, redirect_uri, phishing, validation]
created: 2026-06-01
updated: 2026-06-01
---
# Two-Endpoint OAuth Split

## Pattern
OAuth implementations sometimes split the UI layer (login page) from the code-issuing layer (token endpoint). The UI may reflect attacker-controlled `redirect_uri` into page state without validation, while the code endpoint validates strictly. This creates a false positive: the UI looks exploitable but no authorization code is ever delivered to the attacker.

## Indicators
- Login form renders with attacker `redirect_uri` embedded in JS state
- But the page returns HTTP 200 (no `Location` redirect header)
- Separate endpoint (e.g., `oauth.vk.com` vs `id.vk.com`) issues codes and rejects mismatched URIs

## Validation method
1. Check if the **UI page** actually redirects (follow `Location` headers) — not just renders
2. Test the **code-issuing endpoint** directly with the attacker `redirect_uri`
3. Complete the full authenticated flow and observe where the `code` parameter lands
4. If code issuer returns `redirect_uri is incorrect`, the UI reflection is cosmetic only

## Observed instances
- [[vk-r2-oauth-redirect-fix]]: `id.vk.com` reflected redirect_uri, `oauth.vk.com` validated → phishing only, no code theft

## Risk of false positive
**High.** Grepping page source for the reflected `redirect_uri` shows the host embedded in `"outer":{}`, which looks like a hit. But without testing the actual code delivery, it's an overclaim.

## Severity impact
- With code delivery: **High/Critical** (account takeover)
- Without code delivery: **Medium at best** (phishing fidelity on legitimate domain)
- Most programs will rate the UI-only case as Informative or Low

## Cross-target applicability
Any OAuth provider with separate UI and token endpoints. Common in large platforms (Google, Microsoft, VK) where the login page is a SPA separate from the authorization server.
