# Attack-Surface Findings — `goodchop.com` (domain)

_Generated 2026-07-08T06:51:22Z by TheN0thing v11.0_

## Executive Summary

**Risk score:** 100 / 100 (**critical**)  ·  **Total findings:** 334

| Severity | Count |
|----------|------:|
| critical | 2 |
| high | 27 |
| medium | 12 |
| low | 14 |
| info | 279 |

## Findings by Severity

### [CRITICAL] GitHub code mentions 'goodchop.com' near 'BEGIN RSA PRIVATE KEY' (1 hits)
- **Asset:** `github:goodchop.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [CRITICAL] GitHub code mentions 'goodchop.com' near 'aws access key id' (28 hits)
- **Asset:** `github:goodchop.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] Backup zip exposed
- **Asset:** `http://track.goodchop.com:2082/backup.zip`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Backup zip exposed at http://track.goodchop.com:2082/backup.zip (HTTP 200)


### [HIGH] Infostealer-exposed credentials
- **Asset:** `goodchop.com`
- **Category:** breach  ·  **Confidence:** firm  ·  **Detection:** breach

HudsonRock reports credentials from info-stealer logs (employees: 0, users: 526, total: 526)

_References:_ https://www.hudsonrock.com/threat-intelligence-cybercrime-tools

**Remediation:** Force password resets; investigate infected endpoints; enforce MFA


### [HIGH] Google API Key exposed
- **Asset:** `http://track.goodchop.com:2082`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://track.goodchop.com:2082

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `https://links.goodchop.com`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in https://links.goodchop.com

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Publicly readable cloud bucket (s3)
- **Asset:** `https://s3.amazonaws.com/account-assets/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (s3)
- **Asset:** `https://s3.amazonaws.com/account-media/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (s3)
- **Asset:** `https://s3.amazonaws.com/account-static/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (s3)
- **Asset:** `https://s3.amazonaws.com/admin-data/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (s3)
- **Asset:** `https://s3.amazonaws.com/ads-app/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


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
- **Asset:** `https://storage.googleapis.com/admin-public/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/admin-uploads/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/ads-images/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/ads-img/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/ads-public/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/alpha-app/`
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
- **Asset:** `https://storage.googleapis.com/api-backup/`
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
- **Asset:** `https://storage.googleapis.com/api-web/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] GitHub code mentions 'goodchop.com' near '.env' (10 hits)
- **Asset:** `github:goodchop.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'goodchop.com' near 'api key' (52 hits)
- **Asset:** `github:goodchop.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'goodchop.com' near 'password' (14 hits)
- **Asset:** `github:goodchop.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'goodchop.com' near 'secret' (28 hits)
- **Asset:** `github:goodchop.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [MEDIUM] GraphiQL UI
- **Asset:** `http://track.goodchop.com:2082/graphiql`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

GraphiQL UI at http://track.goodchop.com:2082/graphiql (HTTP 200)


### [MEDIUM] GraphQL present
- **Asset:** `http://track.goodchop.com:2082/graphql`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

GraphQL present at http://track.goodchop.com:2082/graphql (HTTP 200)


### [MEDIUM] Swagger UI
- **Asset:** `http://track.goodchop.com:2082/swagger-ui.html`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

Swagger UI at http://track.goodchop.com:2082/swagger-ui.html (HTTP 200)


### [MEDIUM] SPF record missing
- **Asset:** `goodchop.com`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

No SPF record published; sender spoofing is easier

_References:_ https://datatracker.ietf.org/doc/html/rfc7208

**Remediation:** Publish an SPF record that ends in -all


### [MEDIUM] Third-party CNAME (takeover candidate)
- **Asset:** `account.goodchop.com`
- **Category:** takeover  ·  **Confidence:** tentative  ·  **Detection:** normalize

account.goodchop.com -> shops.myshopify.com.

**Remediation:** Verify the pointed-to service is claimed by you


### [MEDIUM] Third-party CNAME (takeover candidate)
- **Asset:** `live-vercel.goodchop.com`
- **Category:** takeover  ·  **Confidence:** tentative  ·  **Detection:** normalize

live-vercel.goodchop.com -> live-vercel.goodchop.com.cdn.cloudflare.net.

**Remediation:** Verify the pointed-to service is claimed by you


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@goodchop/app`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@goodchop/app' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@goodchop/core`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@goodchop/core' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@goodchop/ui`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@goodchop/ui' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@goodchop/utils`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@goodchop/utils' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Third-party CNAME (takeover candidate)
- **Asset:** `shop.goodchop.com`
- **Category:** takeover  ·  **Confidence:** tentative  ·  **Detection:** normalize

shop.goodchop.com -> shops.myshopify.com.

**Remediation:** Verify the pointed-to service is claimed by you


### [MEDIUM] Third-party CNAME (takeover candidate)
- **Asset:** `staging-vercel.goodchop.com`
- **Category:** takeover  ·  **Confidence:** tentative  ·  **Detection:** normalize

staging-vercel.goodchop.com -> staging-vercel.goodchop.com.cdn.cloudflare.net.

**Remediation:** Verify the pointed-to service is claimed by you


### [LOW] Env example
- **Asset:** `http://track.goodchop.com:2082/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at http://track.goodchop.com:2082/.env.example (HTTP 200)


### [LOW] SOAP WSDL
- **Asset:** `http://track.goodchop.com:2082/?wsdl`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

SOAP WSDL at http://track.goodchop.com:2082/?wsdl (HTTP 200)


### [LOW] Dockerfile exposed
- **Asset:** `http://track.goodchop.com:2082/Dockerfile`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Dockerfile exposed at http://track.goodchop.com:2082/Dockerfile (HTTP 200)


### [LOW] Admin panel
- **Asset:** `http://track.goodchop.com:2082/admin`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin panel at http://track.goodchop.com:2082/admin (HTTP 200)


### [LOW] Adminer
- **Asset:** `http://track.goodchop.com:2082/adminer.php`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Adminer at http://track.goodchop.com:2082/adminer.php (HTTP 200)


### [LOW] WADL present
- **Asset:** `http://track.goodchop.com:2082/application.wadl`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

WADL present at http://track.goodchop.com:2082/application.wadl (HTTP 200)


### [LOW] Composer json
- **Asset:** `http://track.goodchop.com:2082/composer.json`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Composer json at http://track.goodchop.com:2082/composer.json (HTTP 200)


### [LOW] Docker compose
- **Asset:** `http://track.goodchop.com:2082/docker-compose.yml`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Docker compose at http://track.goodchop.com:2082/docker-compose.yml (HTTP 200)


### [LOW] Package json
- **Asset:** `http://track.goodchop.com:2082/package.json`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Package json at http://track.goodchop.com:2082/package.json (HTTP 200)


### [LOW] WP json
- **Asset:** `http://track.goodchop.com:2082/wp-json/`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

WP json at http://track.goodchop.com:2082/wp-json/ (HTTP 200)


### [LOW] DNSSEC not enabled
- **Asset:** `goodchop.com`
- **Category:** dns  ·  **Confidence:** firm  ·  **Detection:** emailsec

Zone is not DNSSEC-signed; DNS answers can be spoofed/tampered

_References:_ https://www.cloudflare.com/dns/dnssec/

**Remediation:** Enable DNSSEC signing at the registrar/DNS provider


### [LOW] MTA-STS not deployed
- **Asset:** `goodchop.com`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

No MTA-STS policy; inbound-mail TLS can be stripped (downgrade)

_References:_ https://datatracker.ietf.org/doc/html/rfc8461

**Remediation:** Publish an MTA-STS policy and _mta-sts TXT record


### [LOW] JWT Token exposed
- **Asset:** `http://track.goodchop.com:2082`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'JWT Token' matched in http://track.goodchop.com:2082

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [LOW] JWT Token exposed
- **Asset:** `https://links.goodchop.com`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'JWT Token' matched in https://links.goodchop.com

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [INFO] Well known openid
- **Asset:** `http://account.goodchop.com/.well-known/openid-configuration`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Well known openid at http://account.goodchop.com/.well-known/openid-configuration (HTTP 200)


### [INFO] Robots txt
- **Asset:** `http://click.link.goodchop.com/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at http://click.link.goodchop.com/robots.txt (HTTP 200)


### [INFO] Robots txt
- **Asset:** `http://shop.goodchop.com/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at http://shop.goodchop.com/robots.txt (HTTP 200)


### [INFO] Changelog
- **Asset:** `http://track.goodchop.com:2082/CHANGELOG.md`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Changelog at http://track.goodchop.com:2082/CHANGELOG.md (HTTP 200)


### [INFO] API root hint
- **Asset:** `http://track.goodchop.com:2082/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at http://track.goodchop.com:2082/api (HTTP 200)


### [INFO] Robots txt
- **Asset:** `http://view.link.goodchop.com/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at http://view.link.goodchop.com/robots.txt (HTTP 200)


### [INFO] Well known openid
- **Asset:** `https://account.goodchop.com/.well-known/openid-configuration`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Well known openid at https://account.goodchop.com/.well-known/openid-configuration (HTTP 200)


### [INFO] Robots txt
- **Asset:** `https://account.goodchop.com/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at https://account.goodchop.com/robots.txt (HTTP 200)


### [INFO] Robots txt
- **Asset:** `https://links.goodchop.com/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at https://links.goodchop.com/robots.txt (HTTP 200)


### [INFO] BIMI record present
- **Asset:** `goodchop.com`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

Domain publishes a BIMI record (brand indicator)


### [INFO] Google Workspace in use
- **Asset:** `goodchop.com`
- **Category:** identity  ·  **Confidence:** firm  ·  **Detection:** identity

MX records point to Google Workspace


### [INFO] IPv6 attack surface present
- **Asset:** `goodchop.com`
- **Category:** dns  ·  **Confidence:** firm  ·  **Detection:** netintel

55 IPv6 (AAAA) address(es) discovered across hosts

**Remediation:** Ensure IPv6 endpoints are covered by the same controls as IPv4


### [INFO] Reverse DNS reveals related host
- **Asset:** `161.71.33.242`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 161.71.33.242 resolves to reply.s50.exacttarget.com (outside goodchop.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `23.227.38.74`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 23.227.38.74 resolves to shops.myshopify.com (outside goodchop.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `34.111.99.212`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 34.111.99.212 resolves to 212.99.111.34.bc.googleusercontent.com (outside goodchop.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `34.242.102.67`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 34.242.102.67 resolves to ec2-34-242-102-67.eu-west-1.compute.amazonaws.com (outside goodchop.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `34.248.159.121`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 34.248.159.121 resolves to ec2-34-248-159-121.eu-west-1.compute.amazonaws.com (outside goodchop.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `34.248.200.201`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 34.248.200.201 resolves to ec2-34-248-200-201.eu-west-1.compute.amazonaws.com (outside goodchop.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `52.209.242.51`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 52.209.242.51 resolves to ec2-52-209-242-51.eu-west-1.compute.amazonaws.com (outside goodchop.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `52.211.114.94`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 52.211.114.94 resolves to ec2-52-211-114-94.eu-west-1.compute.amazonaws.com (outside goodchop.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `52.51.199.159`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 52.51.199.159 resolves to ec2-52-51-199-159.eu-west-1.compute.amazonaws.com (outside goodchop.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `54.240.174.55`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 54.240.174.55 resolves to server-54-240-174-55.osl50.r.cloudfront.net (outside goodchop.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `63.35.200.242`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 63.35.200.242 resolves to ec2-63-35-200-242.eu-west-1.compute.amazonaws.com (outside goodchop.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-app.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-app.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-apps.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-apps.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-auth.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-auth.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-backup.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-backup.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-bak.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-bak.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-beta.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-beta.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-cd.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-cd.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-ci.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-ci.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-confluence.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-confluence.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-corp.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-corp.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-demo.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-demo.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-dev.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-dev.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-development.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-development.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-ftp.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-ftp.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-gateway.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-gateway.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-git.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-git.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-gitlab.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-gitlab.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-grafana.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-grafana.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-int.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-int.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-internal.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-internal.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-qa.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-qa.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-status.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-status.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-stg.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-stg.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-test.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-test.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-testing.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-testing.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-uat.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-uat.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-v1.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-v1.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-v2.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-v2.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-v3.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-v3.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-vpn.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-vpn.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a-web.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-web.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a.admin.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.admin.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a.alpha.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.alpha.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a.api.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.api.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a.api2.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.api2.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a.app.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.app.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a.apps.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.apps.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a.auth.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.auth.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a.bak.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.bak.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a.ci.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.ci.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a.preprod.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.preprod.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a.prod.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.prod.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a.production.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.production.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a.qa.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.qa.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a.sandbox.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.sandbox.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a.smtp.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.smtp.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a.sso.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.sso.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a.stage.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.stage.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Virtual host on 104.18.43.247
- **Asset:** `a.staging.goodchop.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.staging.goodchop.com' served distinct content on 104.18.43.247 (HTTP 301)


### [INFO] Cloud bucket exists (azure)
- **Asset:** `https://account.blob.core.windows.net/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/account-app/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/account-archive/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/account-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/account-bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/account-data/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/account-files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/account-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/account-prod/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/account-public/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/account-staging/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/account-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/account-web/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/account.app/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/account.assets/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/account.data/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/account.dev/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/account.logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/account.test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/account/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/admin-app/`
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
- **Asset:** `https://s3.amazonaws.com/admin-backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/admin-bucket/`
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
- **Asset:** `https://s3.amazonaws.com/admin-images/`
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
- **Asset:** `https://s3.amazonaws.com/admin-prod/`
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
- **Asset:** `https://s3.amazonaws.com/admin-static/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/admin-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/admin-uploads/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/admin-web/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/admin.app/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/admin.backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/admin.bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/admin.storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/admin/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ads-archive/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ads-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ads-bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ads-cdn/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ads-data/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ads-dev/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ads-files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ads-images/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ads-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ads-prod/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ads-public/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ads-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ads-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ads.backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ads.bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ads.files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ads.images/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ads.test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ads/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alpha-assets/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alpha-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alpha-backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alpha-bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alpha-dev/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alpha-files/`
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
- **Asset:** `https://s3.amazonaws.com/alpha-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alpha-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alpha-uploads/`
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
- **Asset:** `https://s3.amazonaws.com/alpha.data/`
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
- **Asset:** `https://s3.amazonaws.com/alpha/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/analytics-assets/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/analytics-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/analytics-bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/analytics-data/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/analytics-files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/analytics-images/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/analytics-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/analytics-private/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/analytics-static/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/analytics-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/analytics-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/analytics-web/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/analytics.assets/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/analytics.dev/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/analytics.images/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/analytics.logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/analytics/`
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
- **Asset:** `https://s3.amazonaws.com/api-dev/`
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
- **Asset:** `https://s3.amazonaws.com/api-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api.data/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api.logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api.staging/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api.static/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api.storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api2-bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api2-files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api2-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api2/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/account-archive/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/account-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/account-backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/account-bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/account-data/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/account-dev/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/account-files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/account-images/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/account-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/account-prod/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/account-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/account-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/account/`
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
- **Asset:** `https://storage.googleapis.com/admin-bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/admin-data/`
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
- **Asset:** `https://storage.googleapis.com/admin-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/admin-web/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/admin/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/ads-archive/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/ads-assets/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/ads-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/ads-bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/ads-cdn/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/ads-data/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/ads-dev/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/ads-media/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/ads-private/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/ads-staging/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/ads-static/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/ads-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/ads-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/ads/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alpha-backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alpha-bucket/`
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
- **Asset:** `https://storage.googleapis.com/alpha-prod/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alpha-public/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alpha-staging/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alpha-static/`
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
- **Asset:** `https://storage.googleapis.com/alpha-uploads/`
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
- **Asset:** `https://storage.googleapis.com/analytics-app/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/analytics-archive/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/analytics-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/analytics-backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/analytics-bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/analytics-cdn/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/analytics-dev/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/analytics-files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/analytics-images/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/analytics-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/analytics-staging/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/analytics-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/analytics-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/analytics/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/api-archive/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/api-assets/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/api-backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/api-bucket/`
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
- **Asset:** `https://storage.googleapis.com/api-images/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/api-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/api-prod/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/api-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/api/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/api2/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


## Prioritized Recommendations

- [CRITICAL] Review and rotate any leaked secrets; request GitHub takedown if applicable
- [HIGH] Force password resets; investigate infected endpoints; enforce MFA
- [HIGH] Restrict the bucket ACL/policy
- [HIGH] Rotate/revoke the credential and remove it from client-served content
- [MEDIUM] Publish an SPF record that ends in -all
- [MEDIUM] Publish/claim the scope, or pin an internal registry + scope config
- [MEDIUM] Verify the pointed-to service is claimed by you
- [LOW] Enable DNSSEC signing at the registrar/DNS provider
- [LOW] Publish an MTA-STS policy and _mta-sts TXT record
- [INFO] Ensure IPv6 endpoints are covered by the same controls as IPv4
- [INFO] Review whether the pointed-to host is in scope
