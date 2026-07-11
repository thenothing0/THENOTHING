# Good Chop Public Reactivation URL Check

Date: 2026-07-08

Tested URL:

```text
https://www.goodchop.com/settings/plan/reactivate?c=BCS100X4C
```

Method:

```text
Unauthenticated GET without the pasted JWT or browser cookies.
```

Result:

```text
HTTP/2 403
final_url=https://www.goodchop.com/settings/plan/reactivate?c=BCS100X4C
redirects=0
content_type=text/html; charset=UTF-8
body_size=5679 bytes
```

Relevant response headers:

```text
server: cloudflare
cf-mitigated: challenge
content-type: text/html; charset=UTF-8
x-frame-options: SAMEORIGIN
x-content-type-options: nosniff
```

Page title:

```text
Just a moment...
```

Observed links/URLs in response:

```text
https://challenges.cloudflare.com
/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1?ray=a17b1220ea97a55f
/settings/plan/reactivate?c=BCS100X4C&__cf_chl_tk=<cloudflare_challenge_token>
/settings/plan/reactivate?c=BCS100X4C&__cf_chl_f_tk=<cloudflare_challenge_token>
/settings/plan/reactivate?c=BCS100X4C&__cf_chl_rt_tk=<cloudflare_challenge_token>
```

Interpretation:

```text
The public unauthenticated request did not reach Good Chop application content.
Cloudflare returned a managed challenge before the reactivation page loaded.
No account data, checkout data, or reactivation state was visible in this response.
```

Browser-side result provided by tester:

```text
HTTP/2 200 OK
content-type: text/html; charset=utf-8
cache-control: private, no-cache, no-store, max-age=0, must-revalidate
server: cloudflare
x-matched-path: /whitelabel/settings/plan/[action]
x-powered-by: Next.js
x-vercel-cache: MISS
cf-cache-status: BYPASS
```

Sanitized interpretation of tester-provided response:

```text
The browser-side request passed Cloudflare and reached the Good Chop/HelloFresh
Next.js application route for /settings/plan/reactivate. The provided snippet
only shows page shell, fonts, and global CSS. It does not by itself show PII,
account-specific state, authenticated API data, or successful reactivation.
```

Additional unauthenticated coupon-route check:

```text
https://www.goodchop.com/settings/plan/reactivate?c=WNG300
```

Result:

```text
HTTP/2 403
final_url=https://www.goodchop.com/settings/plan/reactivate?c=WNG300
redirects=0
content_type=text/html; charset=UTF-8
body_size=5670 bytes
server: cloudflare
cf-mitigated: challenge
page_title=Just a moment...
```

Interpretation:

```text
The unauthenticated curl request with c=WNG300 was also stopped by a
Cloudflare managed challenge before Good Chop application content loaded.
No coupon validity, account-specific state, or reactivation impact can be
determined from this response alone.
```

Authenticated account request provided by tester:

```text
GET /settings/account HTTP/2
Host: www.goodchop.com
Referer: https://www.goodchop.com/settings/orders
```

Sanitized authentication indicators:

```text
apiV2Auth cookie present
access_token present: JWT, RS256, issuer=https://goodchop-live.eu.auth0.com/
refresh_token present
authenticated email claim: mrdracula@intigriti.me
customer_uuid claim: 5dbd97b4-4432-4108-bf41-1ec9bc436f30
country claim: mr
hf_i cookie present: 100187931
```

Token timing:

```text
iat=1783472976 -> Wed Jul 8 01:09:36 UTC 2026
exp=1783474776 -> Wed Jul 8 01:39:36 UTC 2026
access token lifetime: 1800 seconds
refresh_expires_in: 5184000 seconds
```

Interpretation:

```text
This request is authenticated. A 200 response from /settings/account with this
cookie set would not prove an authorization bypass by itself. The relevant
comparison is whether /settings/account or its API calls expose account data
when apiV2Auth is removed, expired, replaced with another test account's token,
or tampered while keeping the original signature.
```

Tester observation: cf_clearance removed

```text
Cookie removed: cf_clearance
Observed result: 403
```

Interpretation:

```text
cf_clearance is Cloudflare challenge-clearance state. A different response after
removing it shows the request is affected by edge/bot-mitigation state, but it
does not by itself demonstrate application authentication or authorization
impact. The next useful comparison is the full sanitized 404 response headers,
especially whether it includes cf-mitigated, x-matched-path, x-vercel-id, or a
Cloudflare challenge/error page body.
```
