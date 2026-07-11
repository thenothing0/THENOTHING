# Attack-Surface Findings — `bcrc.io` (domain)

_Generated 2026-07-07T22:49:01Z by TheN0thing v11.0_

## Executive Summary

**Risk score:** 100 / 100 (**critical**)  ·  **Total findings:** 166

| Severity | Count |
|----------|------:|
| critical | 1 |
| high | 12 |
| medium | 14 |
| low | 30 |
| info | 109 |

## Findings by Severity

### [CRITICAL] GitHub code mentions 'bcrc.io' near 'aws access key id' (4 hits)
- **Asset:** `github:bcrc.io`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] Kibana status
- **Asset:** `http://trk.bcrc.io/api/status`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Kibana status at http://trk.bcrc.io/api/status (HTTP 200)


### [HIGH] Consul ui
- **Asset:** `http://trk.bcrc.io/v1/catalog/services`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Consul ui at http://trk.bcrc.io/v1/catalog/services (HTTP 200)


### [HIGH] Docker API images
- **Asset:** `https://trk.bcrc.io/images/json`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker API images at https://trk.bcrc.io/images/json (HTTP 200)


### [HIGH] Docker registry root
- **Asset:** `https://trk.bcrc.io/v2/`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker registry root at https://trk.bcrc.io/v2/ (HTTP 200)


### [HIGH] DMARC record missing
- **Asset:** `bcrc.io`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

No DMARC policy; spoofed mail is neither quarantined nor rejected

_References:_ https://datatracker.ietf.org/doc/html/rfc7489

**Remediation:** Publish _dmarc.bcrc.io with p=quarantine or p=reject


### [HIGH] Google API Key exposed
- **Asset:** `http://dev-lnk.bcrc.io`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://dev-lnk.bcrc.io

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `https://dev-lnk.bcrc.io`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in https://dev-lnk.bcrc.io

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Publicly readable cloud bucket (s3)
- **Asset:** `https://s3.amazonaws.com/dev-static/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/com-bucket/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Google API Key exposed
- **Asset:** `https://trk.bcrc.io`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in https://trk.bcrc.io

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] GitHub code mentions 'bcrc.io' near 'api key' (6 hits)
- **Asset:** `github:bcrc.io`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'bcrc.io' near 'secret' (3 hits)
- **Asset:** `github:bcrc.io`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [MEDIUM] Legacy TLSv1.0 supported
- **Asset:** `trk.bcrc.io:443`
- **Category:** tls  ·  **Confidence:** confirmed  ·  **Detection:** tls

Server negotiates deprecated TLSv1.0

_References:_ https://datatracker.ietf.org/doc/html/rfc8996

**Remediation:** Disable TLS 1.0 and TLS 1.1


### [MEDIUM] Legacy TLSv1.1 supported
- **Asset:** `trk.bcrc.io:443`
- **Category:** tls  ·  **Confidence:** confirmed  ·  **Detection:** tls

Server negotiates deprecated TLSv1.1

_References:_ https://datatracker.ietf.org/doc/html/rfc8996

**Remediation:** Disable TLS 1.0 and TLS 1.1


### [MEDIUM] Internal hostname/IP leaked in JavaScript
- **Asset:** `http:///code.jquery.com/ui/1.11.4/jquery-ui.js`
- **Category:** js  ·  **Confidence:** firm  ·  **Detection:** jsanalysis

Client-served JS references internal infrastructure

**Remediation:** Remove internal references from client bundles


### [MEDIUM] Internal hostname/IP leaked in JavaScript
- **Asset:** `https:///code.jquery.com/ui/1.11.4/jquery-ui.js`
- **Category:** js  ·  **Confidence:** firm  ·  **Detection:** jsanalysis

Client-served JS references internal infrastructure

**Remediation:** Remove internal references from client bundles


### [MEDIUM] Candidate: ssti pattern in URL
- **Asset:** `https://bugs.webkit.org/show_bug.cgi?id=136851`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssti' gf pattern — manual verification candidate

**Remediation:** Manually test for ssti on the highlighted parameter


### [MEDIUM] Candidate: ssti pattern in URL
- **Asset:** `https://bugs.webkit.org/show_bug.cgi?id=29084`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssti' gf pattern — manual verification candidate

**Remediation:** Manually test for ssti on the highlighted parameter


### [MEDIUM] Candidate: ssti pattern in URL
- **Asset:** `https://bugs.webkit.org/show_bug.cgi?id=47182`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssti' gf pattern — manual verification candidate

**Remediation:** Manually test for ssti on the highlighted parameter


### [MEDIUM] Candidate: ssti pattern in URL
- **Asset:** `https://bugzilla.mozilla.org/show_bug.cgi?id=491668`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssti' gf pattern — manual verification candidate

**Remediation:** Manually test for ssti on the highlighted parameter


### [MEDIUM] Candidate: ssti pattern in URL
- **Asset:** `https://bugzilla.mozilla.org/show_bug.cgi?id=561664`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssti' gf pattern — manual verification candidate

**Remediation:** Manually test for ssti on the highlighted parameter


### [MEDIUM] Candidate: ssti pattern in URL
- **Asset:** `https://bugzilla.mozilla.org/show_bug.cgi?id=649285`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssti' gf pattern — manual verification candidate

**Remediation:** Manually test for ssti on the highlighted parameter


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@bcrc/app`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@bcrc/app' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@bcrc/core`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@bcrc/core' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@bcrc/ui`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@bcrc/ui' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@bcrc/utils`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@bcrc/utils' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [LOW] Env example
- **Asset:** `http://dev-lnk.bcrc.io/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at http://dev-lnk.bcrc.io/.env.example (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `http://dev-lnk.bcrc.io/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at http://dev-lnk.bcrc.io/health (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `http://lnk.bcrc.io/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at http://lnk.bcrc.io/health (HTTP 200)


### [LOW] Env example
- **Asset:** `https://dev-lnk.bcrc.io/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at https://dev-lnk.bcrc.io/.env.example (HTTP 200)


### [LOW] Composer json
- **Asset:** `https://dev-lnk.bcrc.io/composer.json`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Composer json at https://dev-lnk.bcrc.io/composer.json (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `https://dev-lnk.bcrc.io/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at https://dev-lnk.bcrc.io/health (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `https://lnk.bcrc.io/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at https://lnk.bcrc.io/health (HTTP 200)


### [LOW] Env example
- **Asset:** `https://trk.bcrc.io/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at https://trk.bcrc.io/.env.example (HTTP 200)


### [LOW] DNSSEC not enabled
- **Asset:** `bcrc.io`
- **Category:** dns  ·  **Confidence:** firm  ·  **Detection:** emailsec

Zone is not DNSSEC-signed; DNS answers can be spoofed/tampered

_References:_ https://www.cloudflare.com/dns/dnssec/

**Remediation:** Enable DNSSEC signing at the registrar/DNS provider


### [LOW] MTA-STS not deployed
- **Asset:** `bcrc.io`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

No MTA-STS policy; inbound-mail TLS can be stripped (downgrade)

_References:_ https://datatracker.ietf.org/doc/html/rfc8461

**Remediation:** Publish an MTA-STS policy and _mta-sts TXT record


### [LOW] SPF not hard-fail
- **Asset:** `bcrc.io`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

SPF ends in ~all/?all rather than -all; spoofed mail may still pass

**Remediation:** Use -all once senders are enumerated


### [LOW] No DKIM selector found
- **Asset:** `bcrc.io`
- **Category:** email  ·  **Confidence:** tentative  ·  **Detection:** emailsec

No DKIM key found at common selectors; outbound mail may be unsigned

**Remediation:** Publish a DKIM key and sign outbound mail


### [LOW] Candidate: idor pattern in URL
- **Asset:** `https://bugs.webkit.org/show_bug.cgi?id=136851`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'idor' gf pattern — manual verification candidate

**Remediation:** Manually test for idor on the highlighted parameter


### [LOW] Candidate: sqli pattern in URL
- **Asset:** `https://bugs.webkit.org/show_bug.cgi?id=136851`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'sqli' gf pattern — manual verification candidate

**Remediation:** Manually test for sqli on the highlighted parameter


### [LOW] Candidate: xss pattern in URL
- **Asset:** `https://bugs.webkit.org/show_bug.cgi?id=136851`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'xss' gf pattern — manual verification candidate

**Remediation:** Manually test for xss on the highlighted parameter


### [LOW] Candidate: idor pattern in URL
- **Asset:** `https://bugs.webkit.org/show_bug.cgi?id=29084`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'idor' gf pattern — manual verification candidate

**Remediation:** Manually test for idor on the highlighted parameter


### [LOW] Candidate: sqli pattern in URL
- **Asset:** `https://bugs.webkit.org/show_bug.cgi?id=29084`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'sqli' gf pattern — manual verification candidate

**Remediation:** Manually test for sqli on the highlighted parameter


### [LOW] Candidate: xss pattern in URL
- **Asset:** `https://bugs.webkit.org/show_bug.cgi?id=29084`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'xss' gf pattern — manual verification candidate

**Remediation:** Manually test for xss on the highlighted parameter


### [LOW] Candidate: idor pattern in URL
- **Asset:** `https://bugs.webkit.org/show_bug.cgi?id=47182`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'idor' gf pattern — manual verification candidate

**Remediation:** Manually test for idor on the highlighted parameter


### [LOW] Candidate: sqli pattern in URL
- **Asset:** `https://bugs.webkit.org/show_bug.cgi?id=47182`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'sqli' gf pattern — manual verification candidate

**Remediation:** Manually test for sqli on the highlighted parameter


### [LOW] Candidate: xss pattern in URL
- **Asset:** `https://bugs.webkit.org/show_bug.cgi?id=47182`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'xss' gf pattern — manual verification candidate

**Remediation:** Manually test for xss on the highlighted parameter


### [LOW] Candidate: idor pattern in URL
- **Asset:** `https://bugzilla.mozilla.org/show_bug.cgi?id=491668`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'idor' gf pattern — manual verification candidate

**Remediation:** Manually test for idor on the highlighted parameter


### [LOW] Candidate: sqli pattern in URL
- **Asset:** `https://bugzilla.mozilla.org/show_bug.cgi?id=491668`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'sqli' gf pattern — manual verification candidate

**Remediation:** Manually test for sqli on the highlighted parameter


### [LOW] Candidate: xss pattern in URL
- **Asset:** `https://bugzilla.mozilla.org/show_bug.cgi?id=491668`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'xss' gf pattern — manual verification candidate

**Remediation:** Manually test for xss on the highlighted parameter


### [LOW] Candidate: idor pattern in URL
- **Asset:** `https://bugzilla.mozilla.org/show_bug.cgi?id=561664`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'idor' gf pattern — manual verification candidate

**Remediation:** Manually test for idor on the highlighted parameter


### [LOW] Candidate: sqli pattern in URL
- **Asset:** `https://bugzilla.mozilla.org/show_bug.cgi?id=561664`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'sqli' gf pattern — manual verification candidate

**Remediation:** Manually test for sqli on the highlighted parameter


### [LOW] Candidate: xss pattern in URL
- **Asset:** `https://bugzilla.mozilla.org/show_bug.cgi?id=561664`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'xss' gf pattern — manual verification candidate

**Remediation:** Manually test for xss on the highlighted parameter


### [LOW] Candidate: idor pattern in URL
- **Asset:** `https://bugzilla.mozilla.org/show_bug.cgi?id=649285`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'idor' gf pattern — manual verification candidate

**Remediation:** Manually test for idor on the highlighted parameter


### [LOW] Candidate: sqli pattern in URL
- **Asset:** `https://bugzilla.mozilla.org/show_bug.cgi?id=649285`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'sqli' gf pattern — manual verification candidate

**Remediation:** Manually test for sqli on the highlighted parameter


### [LOW] Candidate: xss pattern in URL
- **Asset:** `https://bugzilla.mozilla.org/show_bug.cgi?id=649285`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'xss' gf pattern — manual verification candidate

**Remediation:** Manually test for xss on the highlighted parameter


### [INFO] API root hint
- **Asset:** `https://trk.bcrc.io/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at https://trk.bcrc.io/api (HTTP 200)


### [INFO] API v1 root
- **Asset:** `https://trk.bcrc.io/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at https://trk.bcrc.io/api/v1 (HTTP 200)


### [INFO] Reverse DNS reveals related host
- **Asset:** `108.156.60.115`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 108.156.60.115 resolves to server-108-156-60-115.ams1.r.cloudfront.net (outside bcrc.io)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `108.156.60.19`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 108.156.60.19 resolves to server-108-156-60-19.ams1.r.cloudfront.net (outside bcrc.io)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `18.172.153.31`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 18.172.153.31 resolves to server-18-172-153-31.lhr50.r.cloudfront.net (outside bcrc.io)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `18.172.153.57`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 18.172.153.57 resolves to server-18-172-153-57.lhr50.r.cloudfront.net (outside bcrc.io)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `3.5.165.104`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 3.5.165.104 resolves to s3-website.ap-southeast-2.amazonaws.com (outside bcrc.io)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `34.234.48.164`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 34.234.48.164 resolves to ec2-34-234-48-164.compute-1.amazonaws.com (outside bcrc.io)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Virtual host on 108.156.60.115
- **Asset:** `dev-lnk.bcrc.io`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'dev-lnk.bcrc.io' served distinct content on 108.156.60.115 (HTTP 301)


### [INFO] Virtual host on 108.156.60.19
- **Asset:** `dev-lnk.bcrc.io`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'dev-lnk.bcrc.io' served distinct content on 108.156.60.19 (HTTP 301)


### [INFO] Virtual host on 18.172.153.31
- **Asset:** `dev-lnk.bcrc.io`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'dev-lnk.bcrc.io' served distinct content on 18.172.153.31 (HTTP 301)


### [INFO] Virtual host on 18.172.153.57
- **Asset:** `dev-lnk.bcrc.io`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'dev-lnk.bcrc.io' served distinct content on 18.172.153.57 (HTTP 301)


### [INFO] Candidate: interestingEXT pattern in URL
- **Asset:** `http://weblogs.java.net/blog/driscoll/archive/2009/09/08/eval-javascript-global-context`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingEXT' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingEXT on the highlighted parameter


### [INFO] Candidate: interestingEXT pattern in URL
- **Asset:** `https://bugs.webkit.org/show_bug.cgi?id=136851`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingEXT' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingEXT on the highlighted parameter


### [INFO] Candidate: interestingparams pattern in URL
- **Asset:** `https://bugs.webkit.org/show_bug.cgi?id=136851`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingparams' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingparams on the highlighted parameter


### [INFO] Candidate: interestingEXT pattern in URL
- **Asset:** `https://bugs.webkit.org/show_bug.cgi?id=29084`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingEXT' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingEXT on the highlighted parameter


### [INFO] Candidate: interestingparams pattern in URL
- **Asset:** `https://bugs.webkit.org/show_bug.cgi?id=29084`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingparams' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingparams on the highlighted parameter


### [INFO] Candidate: interestingEXT pattern in URL
- **Asset:** `https://bugs.webkit.org/show_bug.cgi?id=47182`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingEXT' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingEXT on the highlighted parameter


### [INFO] Candidate: interestingparams pattern in URL
- **Asset:** `https://bugs.webkit.org/show_bug.cgi?id=47182`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingparams' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingparams on the highlighted parameter


### [INFO] Candidate: interestingEXT pattern in URL
- **Asset:** `https://bugzilla.mozilla.org/show_bug.cgi?id=491668`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingEXT' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingEXT on the highlighted parameter


### [INFO] Candidate: interestingparams pattern in URL
- **Asset:** `https://bugzilla.mozilla.org/show_bug.cgi?id=491668`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingparams' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingparams on the highlighted parameter


### [INFO] Candidate: interestingEXT pattern in URL
- **Asset:** `https://bugzilla.mozilla.org/show_bug.cgi?id=561664`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingEXT' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingEXT on the highlighted parameter


### [INFO] Candidate: interestingparams pattern in URL
- **Asset:** `https://bugzilla.mozilla.org/show_bug.cgi?id=561664`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingparams' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingparams on the highlighted parameter


### [INFO] Candidate: interestingEXT pattern in URL
- **Asset:** `https://bugzilla.mozilla.org/show_bug.cgi?id=649285`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingEXT' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingEXT on the highlighted parameter


### [INFO] Candidate: interestingparams pattern in URL
- **Asset:** `https://bugzilla.mozilla.org/show_bug.cgi?id=649285`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingparams' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingparams on the highlighted parameter


### [INFO] Cloud bucket exists (azure)
- **Asset:** `https://dev.blob.core.windows.net/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/com-backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/com-data/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/com-img/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/com-media/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/com-public/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/com-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/com-web/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/com.backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/com.backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/com.bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/com.files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/com.media/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/com.public/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/com/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev-app/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev-assets/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev-cdn/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev-dev/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev-images/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev-img/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev-public/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev.app/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev.assets/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev.backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev.logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev.media/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev.staging/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev.storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev.test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev.web/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/inbound-bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/inbound-cdn/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/inbound-dev/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/inbound-images/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/inbound-prod/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/lnk-files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/lnk-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/lnk/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/smtp-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/smtp.backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/smtp/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/trk-assets/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/trk-static/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/trk.logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/west-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/west-bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/west-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/west/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/amazonaws/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/com-assets/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/com-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/com-data/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/com-public/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/dev-app/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/dev-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/dev-cdn/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/dev-data/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/dev-files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/dev-images/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/dev-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/dev-private/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/dev-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/dev-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/dev-uploads/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/inbound-assets/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/inbound-files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/inbound-media/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/inbound-static/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/inbound-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/smtp-dev/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/smtp-prod/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/smtp/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/trk-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/trk-web/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/trk/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/west/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Virtual host on 108.156.60.115
- **Asset:** `lnk.bcrc.io`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'lnk.bcrc.io' served distinct content on 108.156.60.115 (HTTP 301)


### [INFO] Virtual host on 108.156.60.19
- **Asset:** `lnk.bcrc.io`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'lnk.bcrc.io' served distinct content on 108.156.60.19 (HTTP 301)


### [INFO] Virtual host on 18.172.153.31
- **Asset:** `lnk.bcrc.io`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'lnk.bcrc.io' served distinct content on 18.172.153.31 (HTTP 301)


### [INFO] Virtual host on 18.172.153.57
- **Asset:** `lnk.bcrc.io`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'lnk.bcrc.io' served distinct content on 18.172.153.57 (HTTP 301)


## Prioritized Recommendations

- [CRITICAL] Review and rotate any leaked secrets; request GitHub takedown if applicable
- [HIGH] Publish _dmarc.bcrc.io with p=quarantine or p=reject
- [HIGH] Restrict the bucket ACL/policy
- [HIGH] Rotate/revoke the credential and remove it from client-served content
- [MEDIUM] Disable TLS 1.0 and TLS 1.1
- [MEDIUM] Manually test for ssti on the highlighted parameter
- [MEDIUM] Publish/claim the scope, or pin an internal registry + scope config
- [MEDIUM] Remove internal references from client bundles
- [LOW] Enable DNSSEC signing at the registrar/DNS provider
- [LOW] Manually test for idor on the highlighted parameter
- [LOW] Manually test for sqli on the highlighted parameter
- [LOW] Manually test for xss on the highlighted parameter
- [LOW] Publish a DKIM key and sign outbound mail
- [LOW] Publish an MTA-STS policy and _mta-sts TXT record
- [LOW] Use -all once senders are enumerated
- [INFO] Manually test for interestingEXT on the highlighted parameter
- [INFO] Manually test for interestingparams on the highlighted parameter
- [INFO] Review whether the pointed-to host is in scope
