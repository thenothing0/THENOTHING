# DNS Hygiene: Dangling & Dead CloudFront CNAMEs on `*.vfsglobal.com` (no subdomain takeover)

**Program:** VFS Global (YesWeHack)
**Assets:** 26 in-scope `*.vfsglobal.com` / `*.vfsevisa.com` hosts CNAMEing to `*.cloudfront.net` (23 dead + 3 live-edge, all swept)
**Class:** DNS misconfiguration / dangling CNAME — dead or unmaintained CloudFront aliases (**CWE-16: Configuration**)
**Severity (proposed):** Informational (Low at most)

> **Changelog (this revision).** This report consolidates the earlier reports 03 + 04 and corrects two methodology errors made along the way:
> 1. An early framing treated "the `dXXXX.cloudfront.net` target has **no** A record" as a takeover signal. **Inverted.** A non-resolving `dXXXX` means no visitor ever reaches a CloudFront edge — the *least* exploitable state, not the most.
> 2. A later framing then elevated three hosts (`notify`, `bolt2londonapiuat`, `bolt2-ukdc-mastersapi-prod`) to "takeover candidates" because they returned CloudFront's `403 "The request could not be satisfied"`. **Also wrong, once the full body is read.** That `<H2>` line appears on *every* CloudFront 403; it is not a discriminator. The decisive signal is the **sub-message** beneath it — and all three return `Request blocked.` (an AWS WAF block on a **claimed, live** distribution), not `Bad request.` (the CNAMEError that marks a free, claimable alias). **There are no subdomain-takeover candidates on this scope.**

---

## 1. Executive Summary

Every `*.vfsglobal.com` / `*.vfsevisa.com` host that `CNAME`s to `*.cloudfront.net` was swept. **23** point at CloudFront distribution names (`dXXXX.cloudfront.net`) that no longer resolve (zero A records, `curl 000`) — dead/decommissioned endpoints. **3** point at distributions that still resolve and returned `403 "The request could not be satisfied"`; reading the **full** error body, each carries a **claimed/live** signal — an AWS-WAF `Request blocked.`, a live JSON API `404`, or an ALB `503` (the sub-state varies by egress/moment) — and **never** the `Bad request.` CNAMEError, i.e. they are **claimed, live hosts** that simply rejected an unauthenticated `GET`, not orphaned aliases. **No subdomain-takeover candidate exists here.** This is reported as an Informational DNS-hygiene observation: the 23 dangling/dead CNAMEs should be cleaned up. The takeover angle on this scope came up dry — a legitimate, defensible result.

---

## 2. Methodology — the correct CloudFront takeover discriminator

CloudFront's generic 403 page **always** contains `<H2>The request could not be satisfied.</H2>`. That line alone tells you nothing about takeover-ability. Two independent signals together are required:

**(a) Edge reachability — is `dXXXX.cloudfront.net` live?**
A visitor's traffic must reach a CloudFront shared edge for any hijack to be possible. That requires the `dXXXX` CNAME target to publish **live A records**. A `dXXXX` with no A record (`curl 000`) is a dead DNS path — not takeover-able. (`*.cloudfront.net` returns `NOERROR` for *any* label, so only the A-record presence — not the DNS status — distinguishes a real distribution from a never-existed one; a bogus-label control proves this.)

**(b) Alias state — the 403 SUB-MESSAGE (the real discriminator):**

| Body beneath "could not be satisfied" | Meaning | Takeover-able? |
|---|---|---|
| `Bad request.` (`x-cache: Error from cloudfront`) | **CNAMEError** — no distribution claims this alias | **YES** — `associate-alias` would succeed |
| `Request blocked.` | **AWS WAF** block — a distribution *does* serve this host (a WebACL ran) | No — alias is claimed |
| JSON / app HTML / `awselb` 503 | Live origin / custom error page | No — alias is claimed |
| App content (e.g. `<title>VFS UKVI Admin</title>`, S3 `REPLICA`) | Claimed distribution serving its own app | No |

**Clean rule:** *takeover candidate ⇔ live `dXXXX` A-records **AND** body = `Bad request.` (CNAMEError).* `CNAMEAlreadyExists` is **not** a generic blocker — it fires only when the alias is already claimed, which is exactly the condition a `Bad request.` CNAMEError tells you is **absent**.

Applying this rule to every CloudFront-fronted host on the scope yields **an empty candidate set**.

---

## 3. Dead-path hosts (23) — dangling CNAME to a non-resolving distribution

`dXXXX.cloudfront.net` publishes **zero** A records → `curl 000`. Verified live 2026-06-24.

| # | Host | CloudFront target (`dXXXX`, no A record) |
|---|------|------------------------------------------|
| 1 | `bolt2-ukdc-adminapi-prod.vfsglobal.com` | `d174qqghn9gc24.cloudfront.net` |
| 2 | `bolt2-ukdc-applicationapi-prod.vfsglobal.com` | `d10g5mqjnu49iu.cloudfront.net` |
| 3 | `bolt2-ukdc-dispatchapi-prod.vfsglobal.com` | `d2cvre4u8uoey3.cloudfront.net` |
| 4 | `bolt2-ukdc-reportsapi-prod.vfsglobal.com` | `d2pjppi5serj0u.cloudfront.net` |
| 5 | `boltdashboard.vfsglobal.com` | `d2pwphm54e4vuy.cloudfront.net` |
| 6 | `boltdashboardapi.vfsglobal.com` | `d18j64fjfjmeui.cloudfront.net` |
| 7 | `delhid2d.vfsglobal.com` | `dvei4du1qqt1m.cloudfront.net` |
| 8 | `delhid2dapi.vfsglobal.com` | `dvtmhz9f5caj.cloudfront.net` |
| 9 | `delhid2dportal.vfsglobal.com` | `d3lwm5dhft083l.cloudfront.net` |
| 10 | `orbitfrankfurtuiprod.vfsglobal.com` | `d851ddph9pqsw.cloudfront.net` |
| 11 | `orbitgfrankfurtextuiprod.vfsglobal.com` | `dl9jmlfsmowmd.cloudfront.net` |
| 12 | `bolt21boltfilesffuat.vfsglobal.com` | `d7mqts9dp65s9.cloudfront.net` |
| 13 | `bolt21missionffuat.vfsglobal.com` | `drzxr72n1ylb4.cloudfront.net` |
| 14 | `bolt21missionlondondev.vfsglobal.com` | `dqx3ncklddmc4.cloudfront.net` |
| 15 | `inferdemo.vfsglobal.com` | `d1ds9rgd2v6bs8.cloudfront.net` |
| 16 | `lift-api-uat.vfsglobal.com` | `d2i8r1lg4u6qco.cloudfront.net` |
| 17 | `r121.vfsglobal.com` | `d1oslg9uxtbe0x.cloudfront.net` |
| 18 | `row2cache.vfsglobal.com` | `d2lgigdkozkisb.cloudfront.net` |
| 19 | `testssl.vfsglobal.com` | `d20buf7y6o5jf5.cloudfront.net` |
| 20 | `visaorigincdn2.vfsglobal.com` | `dvpd93qbsngwx.cloudfront.net` |
| 21 | `visapreprod.vfsglobal.com` | `drxvcw86vk5i4.cloudfront.net` |
| 22 | `staging-app.vfsevisa.com` | `d3ckpwrastc6n3.cloudfront.net` |
| 23 | `staging-ops.vfsevisa.com` | `d13laebjc4c7ew.cloudfront.net` |

---

## 4. Live-edge hosts swept (3) — all claimed, no orphaned alias

`dXXXX` resolves to a live shared edge (`108.159.120.x`), but the full body shows a **claimed/live** distribution, not a CNAMEError. None is takeover-able. Verified live 2026-06-24 — **each host returns a claimed/live signal (an AWS-WAF `Request blocked.`, a live JSON API `404`, or an ALB `503`), and never `Bad request.` (CNAMEError).** The exact sub-state varies by egress and moment — which is itself consistent with a claimed, live distribution — so a triager who reproduces a different sub-state (e.g. the JSON `404` instead of the WAF block) is seeing the same conclusion, not a contradiction.

| Host | CloudFront target (live A) | Observed response(s) | Sub-message | Verdict |
|---|---|---|---|---|
| `notify.vfsglobal.com` | `dh724wso4cqtu.cloudfront.net` | `403` CloudFront | **`Request blocked.`** (AWS WAF) | Claimed (WAF) |
| `bolt2londonapiuat.vfsglobal.com` | `dxkvwtv8yz4dp.cloudfront.net` | `403` CloudFront / also seen `404` `{"success":false,"message":"Method not found."}` | **`Request blocked.`** / live JSON API | Claimed (live API) |
| `bolt2-ukdc-mastersapi-prod.vfsglobal.com` | `d20gux613julxe.cloudfront.net` | `403` CloudFront / also seen `503` `server: awselb/2.0` | **`Request blocked.`** / live ALB | Claimed (live ALB) |
| *(contrast)* `atlantisuat-absadmin.vfsglobal.com` | `d1ku6sg1wzv7ke.cloudfront.net` | `403` serving VFS Angular SPA, S3 `x-amz-replication-status: REPLICA` | app HTML (`<title>VFS UKVI Admin</title>`) | Claimed (live app) |

> **Egress/moment caveat:** a WAF/`503`/`404` is one egress IP at one moment. The status varies, but across repeated probes every one of these stays a *claimed/live* signal — none ever returns the `Bad request.` CNAMEError. If a future sweep from any egress shows a live-edge host returning `Bad request.`, **that** would be a genuine takeover candidate worth seeking authorization for; none here is that today.

---

## 5. Proof of Concept & Detection Method

```bash
# (a) Edge reachability — does the dXXXX target resolve?
dig +short notify.vfsglobal.com CNAME            # dh724wso4cqtu.cloudfront.net.
dig +short dh724wso4cqtu.cloudfront.net A        # 108.159.120.8/.23/.60/.91  (live edge)

dig +short bolt2-ukdc-adminapi-prod.vfsglobal.com CNAME   # d174qqghn9gc24.cloudfront.net.
dig +short d174qqghn9gc24.cloudfront.net A                 # (empty — dead, no A record)

# (b) The decisive sub-message — read the FULL body, not just the <H2>
curl -sk https://notify.vfsglobal.com/ | grep -oE 'Bad request\.|Request blocked\.'
#   Request blocked.        <-- AWS WAF on a CLAIMED distribution (NOT takeover-able)
# A genuine candidate would instead print:
#   Bad request.            <-- CNAMEError: no distribution claims the alias

# control — *.cloudfront.net answers NOERROR for any label; only real distributions publish A
dig +noall +answer A dZZZbogus99999xyz.cloudfront.net @8.8.8.8   # NOERROR, zero A records
```

**Attach to submission:** a terminal screenshot showing, for 2–3 dead hosts, the `dig` chain + empty `A` answer + `curl 000`; and for one live-edge host, the `curl ... | grep` returning `Request blocked.` (proving it is claimed, not a CNAMEError). Per YesWeHack policy this report must not be text-only.

---

## 6. Honest Assessment

**CONFIRMED**
- 23 in-scope hosts publish dangling CNAMEs to dead CloudFront distributions (`dXXXX` no A record → `curl 000`). DNS-hygiene defect; decommissioned/never-provisioned endpoints.
- The 3 live-edge hosts are **claimed and live** (AWS WAF `Request blocked.` / live JSON API / live ALB), confirmed by full-body reads across repeated probes.

**NOT FOUND**
- **No subdomain-takeover candidate.** No CloudFront-fronted host on this scope returns the `Bad request.` CNAMEError that marks a free, claimable alias. The `associate-alias` confirmation test is therefore **moot** — there is nothing to test against, and standing up a distribution was never authorized regardless.

**Mechanism (stated correctly):** takeover needs both a live edge (so traffic arrives) *and* an unclaimed alias (CNAMEError `Bad request.`). The 23 fail the first condition (dead edge); the 3 fail the second (claimed — WAF/live origin). `CNAMEAlreadyExists` would block a claim on the 3 precisely *because* they are already claimed — not as a generic barrier.

**Impact bounding (had any host been claimable — it isn't):** impact would still be Low. The only `Domain=.vfsglobal.com` cookie observed is `__cf_bm` (Cloudflare bot-management, `HttpOnly; Secure`, non-auth); `lift-api.vfsglobal.com` CORS is statically pinned to `https://visa.vfsglobal.com` and does not reflect arbitrary Origins; OAuth `.well-known/openid-configuration` returns `403` (no subdomain trust established); and the cert ceiling caps any CloudFront alias-claim to HTTP/TLS-warning serving (so `Secure` cookies are uncapturable). These were verified and independently confirm no escalation path even hypothetically.

---

## 7. Remediation

1. **Delete the 23 dangling CNAMEs** pointing at dead `dXXXX.cloudfront.net` distributions (CNAME-first; nothing else needs touching — there is no live resource behind them).
2. **Reconcile DNS against live CloudFront inventory** (`aws cloudfront list-distributions`); remove or re-point any record whose target distribution no longer exists. The 3 live hosts are fine as-is (claimed); no takeover remediation is required for them.
3. **Enforce decommissioning order:** remove the DNS CNAME *before* deleting a CloudFront distribution, so dangling windows never open. Add the §5 `dig`+`curl` drift check as a recurring hygiene scan, keyed on the correct discriminator (`Bad request.` CNAMEError + live `dXXXX`).
4. **Enforce HSTS `includeSubDomains` + preload** on `vfsglobal.com` to bound any future dangling-subdomain worst case to a TLS-warning page.

---

## 8. Suggestions for Next Iteration

- **Treat the takeover angle as closed (dry) for this scope** unless a future sweep surfaces a live-edge host returning the `Bad request.` CNAMEError. The correct discriminator is now in hand to catch one instantly if it appears.
- **Submit this as a single Informational "DNS hygiene" report.** On a heavily-farmed, high-dup-risk scope, that is the credible, accurate framing; a "takeover candidates" pitch would N/A on first `curl` and cost credibility where the rest of the work is sharp.
- Reports 01 (Azure `asuid`-protected dangling CNAME, Low/Info) and 02 (`omanpostsql*` internal-IP, Info — VDP or fold in) remain as separately scoped.
