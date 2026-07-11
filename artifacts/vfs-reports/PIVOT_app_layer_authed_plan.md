# VFS Global — App-Layer (Paid-Tier) Pivot: Authenticated Test Plan

**Status:** ready to execute the moment an authenticated session is provided.
**Why this exists:** the DNS-hygiene reports (01/02/03) are ~$0 reputation filings. VFS pays for app-layer impact — facial-verification tampering (≈$2k), visa-applicant PII / IDOR (≤$1.5k / High-Crit), payment & auth/access-control bypass (≤$700). This plan aims the recon already done at those reward themes.

---

## 0. The blocker, stated plainly

From the current egress, with no account, the app layer is fully walled — **and these are auth gates, not IP blocks**:

| Host | Unauth response | Meaning |
|------|-----------------|---------|
| `visa.vfsglobal.com` (all paths) | `403 {"code":"403204"}` | app-level block of unauth/edge requests |
| `lift-api.vfsglobal.com` (all paths incl. `/health`, `/swagger`, `/.well-known`) | `403 {"code":"403205"}` | API gateway rejecting unauthenticated clients |
| `x-api.vfsglobal.com`, `orghierarchyapi-uat.vfsglobal.com` | do not resolve (cert SANs only) | internal / dead |
| `vfsevisa.com`, `onevasco.com` APIs | Cloudflare WAF "you have been blocked" | egress-reputation blocked |
| `web.archive.org` | unreachable from this egress | no historical-URL harvest |

`403205` returning uniformly for *every* path (including `/health`) is the signature of "present a valid bearer/session or you get nothing." **A token from a self-registered session is expected to unlock it.** That single input turns this whole plan live.

---

## 1. What I need from you (one-time capture)

Self-register **two** test applicant accounts (`A` and `B`) in the **same country + visa type** (so they share the same API surface and object-id space — required for IDOR/BOLA). Then, from your browser DevTools → Network (or Burp), capture and paste me:

1. **`A`'s and `B`'s bearer tokens** (the `Authorization: Bearer …` value, or the session cookie if cookie-based).
2. **One working authenticated request that returns A's own data** — full: method, URL (host+path), all headers (esp. `Origin`, `Referer`, any `x-correlation-id` / `x-vfs-*` / country/route headers), and body. This reveals the real endpoint shapes and the object-id parameter names.
3. **A's and B's own object identifiers** as the app shows them (application ID / booking ID / reference number / applicant ID / order ID).
4. (For the facial-verification theme) **the reschedule flow's network calls** up to and including the facial-verification step.
5. (For the payment theme) **the payment-initiation request** (the call that creates the order / sets the amount).

That's it. With #1–#3 I can start BOLA immediately; #4/#5 unlock the higher-value themes.

> Egress note: if `lift-api`/`bolt2` still return `403205` to *my* egress even with a valid token (i.e. the gate also checks IP/Origin server-side), I'll hand you exact Burp/curl repro steps to run from your (working) session and you feed me the responses — I do the analysis & write-ups. Either way the testing is surgical.

---

## 2. Targets by reward theme ("map all, then decide" — ordered by yield)

### A. Visa-applicant PII via IDOR / BOLA — *primary, ≤$1.5k / High-Crit*
The broadest, highest-probability surface. Booking/application/document endpoints almost always key on a guessable/enumerable object id.
- **Method:** authenticate as A and B; take a request that returns **A's** record; replay it **with A's token but B's object-id** (and vice-versa). If A can read B's application/booking/documents/personal data → BOLA.
- **Object-id params to swap:** `applicationId`, `bookingId`, `appointmentId`, `applicantId`, `referenceNumber`/`refNo`, `orderId`, `vafNumber`, `gwfRef`, any numeric/sequential id or base64-wrapped id in the path or body.
- **Also test:** mass-assignment (add `role`/`isAdmin`/`status` to a profile PATCH), excessive-data-exposure (does the object response include fields the UI hides — passport no., DOB, full address?).
- **Tools:** `attack_access_control` (dual-identity same-resource diff with `owner_markers` = strings unique to A's private data), `attack_api` (`check=bola` enumerating B's ids with A's session; `check=mass_assignment`; `check=excessive_data_exposure`).
- **Impact proof discipline:** prove access to **one** foreign record's identifying field — do **not** bulk-dump PII (non-negotiable; see `feedback_impact_proof`). One cross-account read + screenshot is the finding.

### B. Facial-verification tampering on rescheduling — *highest single payout ≈$2k*
- **Walk the reschedule flow once** (capture #4) to find the facial-verification call(s).
- **Tests:** replay another applicant's verification token/result; skip the step (call the post-verify endpoint directly); tamper the verdict field (`verified=true` / `livenessScore`/`matchStatus`); reuse A's passed verification on B's booking. Two-signal: the server must *accept* the tampered/absent verification AND let the reschedule proceed.
- **Tools:** `attack_api` (BFLA/sequence), `shell_exec` curl replay of the captured calls with modified bodies, `attack_stored` if a verification artifact is persisted and reused.

### C. Auth / access-control & token bypass — *≤$700, often chains into A*
- **JWT:** run `attack_jwt` on A's token — `alg:none`, weak-HMAC recovery, `kid` injection, RS/HS confusion; forge B's `sub`/`applicantId` and replay.
- **OAuth/OIDC:** if login is OAuth (`attack_oauth` on the authorize endpoint) — `redirect_uri` validation, missing `state`/PKCE, token leakage. (Note: the dangling-CNAME subdomains are **not** trusted in CORS — `lift-api` ACAO is static-pinned to `https://visa.vfsglobal.com` — so subdomain-trust escalation is already ruled out.)
- **BFLA / privilege:** low-priv applicant calling agent/admin/dispatch functions (`attack_privesc`, `attack_api check=bfla`) — relevant given the `bolt2-ukdc-{admin,dispatch,reports}api` naming.

### D. Payment-flow tampering — *≤$700*
- Capture #5; test amount/currency tampering, status-callback forgery (mark unpaid order paid), and re-use of another applicant's payment reference. PoC-only — never move real money; prove the *acceptance* of a tampered parameter, not a completed fraudulent transaction.

---

## 3. Execution order (once session material is in hand)

1. `authorize_target(exploitation)` on the exact API host — confirm ALLOW (deny-by-default gate).
2. `attack_login` (or import the captured tokens) → establish sessions A and B.
3. **BOLA sweep first** (theme A) — fastest path to a paid finding; `attack_access_control` + `attack_api`.
4. In parallel: `attack_jwt` on the token (offline, no traffic) — cheap, high-leverage.
5. If BOLA dry → facial-verification (B) and payment (D) with the captured flows.
6. Every confirmed bug: **two independent signals**, `attack_reverify` for a replayable PoC bundle, screenshot/recording attached (never text-only), `attack_triage` for program severity + dup check, then `attack_report` (YesWeHack template).

## 4. Guardrails (non-negotiable)
- PoC-only; minimal proof; **no bulk PII exfiltration**, no destructive/DoS, no social-eng.
- Two-signal before any severity claim; honest "suspected vs confirmed" split.
- Stay in `*.vfsglobal.com` scope; re-`authorize_target` per host before active testing.

## 5. Recon state feeding this plan
- API hosts mapped: `lift-api.vfsglobal.com` (live, 403205 auth-gated), `bolt2-ukdc-*` fleet (booking/admin/dispatch/reports APIs), `cdapi`, `atlantis-abs-uk`. New from crt.sh: `x-api`, `orghierarchyapi-uat` (don't resolve — internal/dead). 84 distinct `vfsglobal.com` hosts catalogued.
- Confirmed safe/ruled-out: `lift-api` CORS static-pinned to `visa` (no reflection); only `Domain=.vfsglobal.com` cookie is `__cf_bm` (CF bot-mgmt, non-auth); no CloudFront subdomain-takeover (all live-edge hosts claimed).
