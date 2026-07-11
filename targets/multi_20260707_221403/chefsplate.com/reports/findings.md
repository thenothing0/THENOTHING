# Attack-Surface Findings — `chefsplate.com` (domain)

_Generated 2026-07-08T02:11:47Z by TheN0thing v11.0_

## Executive Summary

**Risk score:** 100 / 100 (**critical**)  ·  **Total findings:** 201

| Severity | Count |
|----------|------:|
| critical | 1 |
| high | 20 |
| medium | 8 |
| low | 10 |
| info | 162 |

## Findings by Severity

### [CRITICAL] Infostealer-exposed credentials
- **Asset:** `chefsplate.com`
- **Category:** breach  ·  **Confidence:** firm  ·  **Detection:** breach

HudsonRock reports credentials from info-stealer logs (employees: 2, users: 1678, total: 1683)

_References:_ https://www.hudsonrock.com/threat-intelligence-cybercrime-tools

**Remediation:** Force password resets; investigate infected endpoints; enforce MFA


### [HIGH] Google API Key exposed
- **Asset:** `http://easy.chefsplate.com`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://easy.chefsplate.com

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://easy.chefsplate.com:2095`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://easy.chefsplate.com:2095

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://eat.chefsplate.com:2086`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://eat.chefsplate.com:2086

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `https://chefsplate.com`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in https://chefsplate.com

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `https://easy.chefsplate.com:2096`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in https://easy.chefsplate.com:2096

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `https://eat.chefsplate.com`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in https://eat.chefsplate.com

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `https://links.chefsplate.com`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in https://links.chefsplate.com

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/admin-app/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/admin-prod/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/admin-uploads/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/alpha-assets/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/alpha-web/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/api-files/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/api-img/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/api-media/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/api-static/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/api-web/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] GitHub code mentions 'chefsplate.com' near 'api key' (57 hits)
- **Asset:** `github:chefsplate.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'chefsplate.com' near 'password' (12 hits)
- **Asset:** `github:chefsplate.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'chefsplate.com' near 'secret' (48 hits)
- **Asset:** `github:chefsplate.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [MEDIUM] SPF record missing
- **Asset:** `chefsplate.com`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

No SPF record published; sender spoofing is easier

_References:_ https://datatracker.ietf.org/doc/html/rfc7208

**Remediation:** Publish an SPF record that ends in -all


### [MEDIUM] Third-party CNAME (takeover candidate)
- **Asset:** `content.crm.chefsplate.com`
- **Category:** takeover  ·  **Confidence:** tentative  ·  **Detection:** normalize

content.crm.chefsplate.com -> dw7bgrz9bvfqm.cloudfront.net.

**Remediation:** Verify the pointed-to service is claimed by you


### [MEDIUM] Third-party CNAME (takeover candidate)
- **Asset:** `live-vercel.chefsplate.com`
- **Category:** takeover  ·  **Confidence:** tentative  ·  **Detection:** normalize

live-vercel.chefsplate.com -> live-vercel.chefsplate.com.cdn.cloudflare.net.

**Remediation:** Verify the pointed-to service is claimed by you


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@chefsplate/app`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@chefsplate/app' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@chefsplate/core`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@chefsplate/core' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@chefsplate/ui`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@chefsplate/ui' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@chefsplate/utils`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@chefsplate/utils' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Third-party CNAME (takeover candidate)
- **Asset:** `staging-vercel.chefsplate.com`
- **Category:** takeover  ·  **Confidence:** tentative  ·  **Detection:** normalize

staging-vercel.chefsplate.com -> staging-vercel.chefsplate.com.cdn.cloudflare.net.

**Remediation:** Verify the pointed-to service is claimed by you


### [LOW] SOAP WSDL
- **Asset:** `http://eat.chefsplate.com:2086/?wsdl`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

SOAP WSDL at http://eat.chefsplate.com:2086/?wsdl (HTTP 200)


### [LOW] DNSSEC not enabled
- **Asset:** `chefsplate.com`
- **Category:** dns  ·  **Confidence:** firm  ·  **Detection:** emailsec

Zone is not DNSSEC-signed; DNS answers can be spoofed/tampered

_References:_ https://www.cloudflare.com/dns/dnssec/

**Remediation:** Enable DNSSEC signing at the registrar/DNS provider


### [LOW] MTA-STS not deployed
- **Asset:** `chefsplate.com`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

No MTA-STS policy; inbound-mail TLS can be stripped (downgrade)

_References:_ https://datatracker.ietf.org/doc/html/rfc8461

**Remediation:** Publish an MTA-STS policy and _mta-sts TXT record


### [LOW] JWT Token exposed
- **Asset:** `http://easy.chefsplate.com`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'JWT Token' matched in http://easy.chefsplate.com

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [LOW] JWT Token exposed
- **Asset:** `http://easy.chefsplate.com:2095`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'JWT Token' matched in http://easy.chefsplate.com:2095

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [LOW] JWT Token exposed
- **Asset:** `http://eat.chefsplate.com:2086`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'JWT Token' matched in http://eat.chefsplate.com:2086

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [LOW] JWT Token exposed
- **Asset:** `https://chefsplate.com`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'JWT Token' matched in https://chefsplate.com

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [LOW] JWT Token exposed
- **Asset:** `https://easy.chefsplate.com:2096`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'JWT Token' matched in https://easy.chefsplate.com:2096

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [LOW] JWT Token exposed
- **Asset:** `https://eat.chefsplate.com`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'JWT Token' matched in https://eat.chefsplate.com

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [LOW] JWT Token exposed
- **Asset:** `https://links.chefsplate.com`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'JWT Token' matched in https://links.chefsplate.com

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [INFO] Robots txt
- **Asset:** `http://easy.chefsplate.com/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at http://easy.chefsplate.com/robots.txt (HTTP 200)


### [INFO] Sitemap xml
- **Asset:** `http://easy.chefsplate.com/sitemap.xml`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Sitemap xml at http://easy.chefsplate.com/sitemap.xml (HTTP 200)


### [INFO] Robots txt
- **Asset:** `http://easy.chefsplate.com:2095/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at http://easy.chefsplate.com:2095/robots.txt (HTTP 200)


### [INFO] Sitemap xml
- **Asset:** `http://easy.chefsplate.com:2095/sitemap.xml`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Sitemap xml at http://easy.chefsplate.com:2095/sitemap.xml (HTTP 200)


### [INFO] Robots txt
- **Asset:** `http://eat.chefsplate.com:2086/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at http://eat.chefsplate.com:2086/robots.txt (HTTP 200)


### [INFO] Robots txt
- **Asset:** `https://chefsplate.com/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at https://chefsplate.com/robots.txt (HTTP 200)


### [INFO] Sitemap xml
- **Asset:** `https://chefsplate.com/sitemap.xml`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Sitemap xml at https://chefsplate.com/sitemap.xml (HTTP 200)


### [INFO] Robots txt
- **Asset:** `https://eat.chefsplate.com/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at https://eat.chefsplate.com/robots.txt (HTTP 200)


### [INFO] Robots txt
- **Asset:** `https://links.chefsplate.com/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at https://links.chefsplate.com/robots.txt (HTTP 200)


### [INFO] Google Workspace in use
- **Asset:** `chefsplate.com`
- **Category:** identity  ·  **Confidence:** firm  ·  **Detection:** identity

MX records point to Google Workspace


### [INFO] IPv6 attack surface present
- **Asset:** `chefsplate.com`
- **Category:** dns  ·  **Confidence:** firm  ·  **Detection:** netintel

45 IPv6 (AAAA) address(es) discovered across hosts

**Remediation:** Ensure IPv6 endpoints are covered by the same controls as IPv4


### [INFO] Android app identified
- **Asset:** `play:com.chefsplate.ChefsPlate`
- **Category:** mobile  ·  **Confidence:** firm  ·  **Detection:** mobile

Google Play app 'com.chefsplate.ChefsPlate' appears associated with the target


### [INFO] Reverse DNS reveals related host
- **Asset:** `161.71.33.242`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 161.71.33.242 resolves to reply.s50.exacttarget.com (outside chefsplate.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `3.164.230.29`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 3.164.230.29 resolves to server-3-164-230-29.arn53.r.cloudfront.net (outside chefsplate.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `3.164.230.66`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 3.164.230.66 resolves to server-3-164-230-66.arn53.r.cloudfront.net (outside chefsplate.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `34.111.99.212`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 34.111.99.212 resolves to 212.99.111.34.bc.googleusercontent.com (outside chefsplate.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `34.160.169.32`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 34.160.169.32 resolves to 32.169.160.34.bc.googleusercontent.com (outside chefsplate.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `52.209.242.51`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 52.209.242.51 resolves to ec2-52-209-242-51.eu-west-1.compute.amazonaws.com (outside chefsplate.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `54.240.174.54`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 54.240.174.54 resolves to server-54-240-174-54.osl50.r.cloudfront.net (outside chefsplate.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-app.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-app.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-auth.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-auth.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-backup.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-backup.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-bak.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-bak.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-beta.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-beta.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-cd.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-cd.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-ci.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-ci.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-confluence.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-confluence.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-corp.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-corp.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-demo.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-demo.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-dev.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-dev.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-development.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-development.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-ftp.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-ftp.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-gateway.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-gateway.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-git.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-git.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-gitlab.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-gitlab.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-grafana.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-grafana.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-gw.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-gw.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-jenkins.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-jenkins.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-portal.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-portal.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-test.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-test.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-testing.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-testing.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-uat.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-uat.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-v1.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-v1.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-v2.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-v2.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-v3.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-v3.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-vpn.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-vpn.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active-web.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-web.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active.alpha.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.alpha.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active.api.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.api.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active.api2.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.api2.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active.app.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.app.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active.apps.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.apps.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active.backup.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.backup.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active.bak.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.bak.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active.cd.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.cd.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active.ci.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.ci.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active.confluence.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.confluence.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active.ftp.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.ftp.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active.production.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.production.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active.qa.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.qa.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active.sandbox.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.sandbox.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active.smtp.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.smtp.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active.sso.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.sso.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active.stage.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.stage.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active.staging.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.staging.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active.status.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.status.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active.stg.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.stg.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Virtual host on 104.18.32.2
- **Asset:** `active.testing.chefsplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.testing.chefsplate.com' served distinct content on 104.18.32.2 (HTTP 301)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/active-app/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/active-archive/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/active-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/active-backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/active-bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/active-data/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/active-files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/active-images/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/active-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/active-media/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/active-public/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/active-staging/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/active-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/active-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/active/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/admin-archive/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/admin-assets/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/admin-dev/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/admin-files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/admin-img/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/admin-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/admin-media/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/admin-private/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/admin-public/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/admin-staging/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/admin-uploads/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/admin.app/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/admin.storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alpha-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alpha-dev/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alpha-images/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alpha-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alpha-media/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alpha-prod/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alpha-public/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alpha-staging/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alpha-static/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alpha-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alpha-web/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alpha.backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alpha.images/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alpha.media/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alpha.test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alt3/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api-app/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api-assets/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api-backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api-bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api-data/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api-files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api-images/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api-media/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api-prod/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api-staging/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api-static/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api.bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api.staging/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api.storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api2-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api2-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/active-bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/active-data/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/active-files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/active/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/admin-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/admin-backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/admin-dev/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/admin-files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/admin-images/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/admin-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/admin-media/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/admin-static/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/admin-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alpha-data/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alpha-dev/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alpha-files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alpha-images/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alpha-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alpha-staging/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alpha-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alpha-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alpha/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alt1/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/api-archive/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/api-backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/api-data/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/api-dev/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/api-private/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/api-prod/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/api-public/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/api-staging/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/api-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/api-uploads/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


## Prioritized Recommendations

- [CRITICAL] Force password resets; investigate infected endpoints; enforce MFA
- [HIGH] Restrict the bucket ACL/policy
- [HIGH] Review and rotate any leaked secrets; request GitHub takedown if applicable
- [HIGH] Rotate/revoke the credential and remove it from client-served content
- [MEDIUM] Publish an SPF record that ends in -all
- [MEDIUM] Publish/claim the scope, or pin an internal registry + scope config
- [MEDIUM] Verify the pointed-to service is claimed by you
- [LOW] Enable DNSSEC signing at the registrar/DNS provider
- [LOW] Publish an MTA-STS policy and _mta-sts TXT record
- [INFO] Ensure IPv6 endpoints are covered by the same controls as IPv4
- [INFO] Review whether the pointed-to host is in scope
