# Attack-Surface Findings — `everyplate.com.au` (domain)

_Generated 2026-07-08T03:57:48Z by TheN0thing v11.0_

## Executive Summary

**Risk score:** 100 / 100 (**critical**)  ·  **Total findings:** 306

| Severity | Count |
|----------|------:|
| critical | 4 |
| high | 28 |
| medium | 10 |
| low | 13 |
| info | 251 |

## Findings by Severity

### [CRITICAL] Docker cfg exposed
- **Asset:** `http://bob.everyplate.com.au/.dockercfg`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Docker cfg exposed at http://bob.everyplate.com.au/.dockercfg (HTTP 200)


### [CRITICAL] Infostealer-exposed credentials
- **Asset:** `everyplate.com.au`
- **Category:** breach  ·  **Confidence:** firm  ·  **Detection:** breach

HudsonRock reports credentials from info-stealer logs (employees: 3, users: 533, total: 537)

_References:_ https://www.hudsonrock.com/threat-intelligence-cybercrime-tools

**Remediation:** Force password resets; investigate infected endpoints; enforce MFA


### [CRITICAL] GitHub code mentions 'everyplate.com.au' near 'BEGIN RSA PRIVATE KEY' (11 hits)
- **Asset:** `github:everyplate.com.au`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [CRITICAL] GitHub code mentions 'everyplate.com.au' near 'aws access key id' (147 hits)
- **Asset:** `github:everyplate.com.au`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] Docker API images
- **Asset:** `http://bob.everyplate.com.au/images/json`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker API images at http://bob.everyplate.com.au/images/json (HTTP 200)


### [HIGH] Consul ui
- **Asset:** `http://bob.everyplate.com.au/v1/catalog/services`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Consul ui at http://bob.everyplate.com.au/v1/catalog/services (HTTP 200)


### [HIGH] Docker registry root
- **Asset:** `http://bob.everyplate.com.au/v2/`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker registry root at http://bob.everyplate.com.au/v2/ (HTTP 200)


### [HIGH] SVN entries exposed
- **Asset:** `https://flex.everyplate.com.au/.svn/entries`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

SVN entries exposed at https://flex.everyplate.com.au/.svn/entries (HTTP 200)


### [HIGH] Elasticsearch cat
- **Asset:** `https://flex.everyplate.com.au/_cat/indices`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Elasticsearch cat at https://flex.everyplate.com.au/_cat/indices (HTTP 200)


### [HIGH] Kibana status
- **Asset:** `https://flex.everyplate.com.au/api/status`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Kibana status at https://flex.everyplate.com.au/api/status (HTTP 200)


### [HIGH] Docker API images
- **Asset:** `https://flex.everyplate.com.au/images/json`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker API images at https://flex.everyplate.com.au/images/json (HTTP 200)


### [HIGH] Consul ui
- **Asset:** `https://flex.everyplate.com.au/v1/catalog/services`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Consul ui at https://flex.everyplate.com.au/v1/catalog/services (HTTP 200)


### [HIGH] Google API Key exposed
- **Asset:** `http://everyplate.com.au`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://everyplate.com.au

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Publicly readable cloud bucket (s3)
- **Asset:** `https://s3.amazonaws.com/admin-data/`
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
- **Asset:** `https://storage.googleapis.com/alerts-assets/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/alerts-data/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/alerts-storage/`
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
- **Asset:** `https://storage.googleapis.com/api-web/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/app-public/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] GitHub code mentions 'everyplate.com.au' near '.env' (27 hits)
- **Asset:** `github:everyplate.com.au`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'everyplate.com.au' near 'api key' (167 hits)
- **Asset:** `github:everyplate.com.au`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'everyplate.com.au' near 'password' (3 hits)
- **Asset:** `github:everyplate.com.au`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'everyplate.com.au' near 'secret' (151 hits)
- **Asset:** `github:everyplate.com.au`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [MEDIUM] VMware Horizon
- **Asset:** `http://bob.everyplate.com.au/portal/webclient/`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

VMware Horizon at http://bob.everyplate.com.au/portal/webclient/ (HTTP 200)


### [MEDIUM] SonarQube status
- **Asset:** `https://flex.everyplate.com.au/api/system/status`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

SonarQube status at https://flex.everyplate.com.au/api/system/status (HTTP 200)


### [MEDIUM] Third-party CNAME (takeover candidate)
- **Asset:** `flex.everyplate.com.au`
- **Category:** takeover  ·  **Confidence:** tentative  ·  **Detection:** normalize

flex.everyplate.com.au -> dznc3ygsd930e.cloudfront.net.

**Remediation:** Verify the pointed-to service is claimed by you


### [MEDIUM] Third-party CNAME (takeover candidate)
- **Asset:** `live-vercel.everyplate.com.au`
- **Category:** takeover  ·  **Confidence:** tentative  ·  **Detection:** normalize

live-vercel.everyplate.com.au -> live-vercel.everyplate.com.au.cdn.cloudflare.net.

**Remediation:** Verify the pointed-to service is claimed by you


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@everyplate/app`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@everyplate/app' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@everyplate/core`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@everyplate/core' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@everyplate/ui`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@everyplate/ui' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@everyplate/utils`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@everyplate/utils' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Third-party CNAME (takeover candidate)
- **Asset:** `staging-vercel.everyplate.com.au`
- **Category:** takeover  ·  **Confidence:** tentative  ·  **Detection:** normalize

staging-vercel.everyplate.com.au -> staging-vercel.everyplate.com.au.cdn.cloudflare.net.

**Remediation:** Verify the pointed-to service is claimed by you


### [MEDIUM] Third-party CNAME (takeover candidate)
- **Asset:** `stg-flex.everyplate.com.au`
- **Category:** takeover  ·  **Confidence:** tentative  ·  **Detection:** normalize

stg-flex.everyplate.com.au -> d1xrgj4thhbyx.cloudfront.net.

**Remediation:** Verify the pointed-to service is claimed by you


### [LOW] Admin panel
- **Asset:** `http://bob.everyplate.com.au/admin`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin panel at http://bob.everyplate.com.au/admin (HTTP 200)


### [LOW] Admin login
- **Asset:** `http://bob.everyplate.com.au/admin/login`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin login at http://bob.everyplate.com.au/admin/login (HTTP 200)


### [LOW] Docker compose
- **Asset:** `http://bob.everyplate.com.au/docker-compose.yml`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Docker compose at http://bob.everyplate.com.au/docker-compose.yml (HTTP 200)


### [LOW] Env example
- **Asset:** `https://flex.everyplate.com.au/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at https://flex.everyplate.com.au/.env.example (HTTP 200)


### [LOW] Dockerfile exposed
- **Asset:** `https://flex.everyplate.com.au/Dockerfile`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Dockerfile exposed at https://flex.everyplate.com.au/Dockerfile (HTTP 200)


### [LOW] Admin panel
- **Asset:** `https://flex.everyplate.com.au/admin`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin panel at https://flex.everyplate.com.au/admin (HTTP 200)


### [LOW] Admin login
- **Asset:** `https://flex.everyplate.com.au/admin/login`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin login at https://flex.everyplate.com.au/admin/login (HTTP 200)


### [LOW] Composer json
- **Asset:** `https://flex.everyplate.com.au/composer.json`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Composer json at https://flex.everyplate.com.au/composer.json (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `https://flex.everyplate.com.au/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at https://flex.everyplate.com.au/health (HTTP 200)


### [LOW] DNSSEC not enabled
- **Asset:** `everyplate.com.au`
- **Category:** dns  ·  **Confidence:** firm  ·  **Detection:** emailsec

Zone is not DNSSEC-signed; DNS answers can be spoofed/tampered

_References:_ https://www.cloudflare.com/dns/dnssec/

**Remediation:** Enable DNSSEC signing at the registrar/DNS provider


### [LOW] MTA-STS not deployed
- **Asset:** `everyplate.com.au`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

No MTA-STS policy; inbound-mail TLS can be stripped (downgrade)

_References:_ https://datatracker.ietf.org/doc/html/rfc8461

**Remediation:** Publish an MTA-STS policy and _mta-sts TXT record


### [LOW] SPF not hard-fail
- **Asset:** `everyplate.com.au`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

SPF ends in ~all/?all rather than -all; spoofed mail may still pass

**Remediation:** Use -all once senders are enumerated


### [LOW] JWT Token exposed
- **Asset:** `http://everyplate.com.au`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'JWT Token' matched in http://everyplate.com.au

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [INFO] Robots txt
- **Asset:** `http://bob.everyplate.com.au/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at http://bob.everyplate.com.au/robots.txt (HTTP 200)


### [INFO] Robots txt
- **Asset:** `http://click.link.everyplate.com.au/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at http://click.link.everyplate.com.au/robots.txt (HTTP 200)


### [INFO] Robots txt
- **Asset:** `http://everyplate.com.au/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at http://everyplate.com.au/robots.txt (HTTP 200)


### [INFO] API v1 root
- **Asset:** `https://flex.everyplate.com.au/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at https://flex.everyplate.com.au/api/v1 (HTTP 200)


### [INFO] API v2 root
- **Asset:** `https://flex.everyplate.com.au/api/v2`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v2 root at https://flex.everyplate.com.au/api/v2 (HTTP 200)


### [INFO] BIMI record present
- **Asset:** `everyplate.com.au`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

Domain publishes a BIMI record (brand indicator)


### [INFO] Google Workspace in use
- **Asset:** `everyplate.com.au`
- **Category:** identity  ·  **Confidence:** firm  ·  **Detection:** identity

MX records point to Google Workspace


### [INFO] IPv6 attack surface present
- **Asset:** `everyplate.com.au`
- **Category:** dns  ·  **Confidence:** firm  ·  **Detection:** netintel

66 IPv6 (AAAA) address(es) discovered across hosts

**Remediation:** Ensure IPv6 endpoints are covered by the same controls as IPv4


### [INFO] Android app identified
- **Asset:** `play:com.everyplate.android`
- **Category:** mobile  ·  **Confidence:** firm  ·  **Detection:** mobile

Google Play app 'com.everyplate.android' appears associated with the target


### [INFO] Reverse DNS reveals related host
- **Asset:** `161.71.33.242`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 161.71.33.242 resolves to reply.s50.exacttarget.com (outside everyplate.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `18.158.228.216`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 18.158.228.216 resolves to ec2-18-158-228-216.eu-central-1.compute.amazonaws.com (outside everyplate.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `205.201.133.57`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 205.201.133.57 resolves to mail57.atl11.rsgsv.net (outside everyplate.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `3.164.230.66`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 3.164.230.66 resolves to server-3-164-230-66.arn53.r.cloudfront.net (outside everyplate.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `3.167.2.48`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 3.167.2.48 resolves to server-3-167-2-48.osl50.r.cloudfront.net (outside everyplate.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `3.211.161.173`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 3.211.161.173 resolves to ec2-3-211-161-173.compute-1.amazonaws.com (outside everyplate.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `3.79.130.38`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 3.79.130.38 resolves to ec2-3-79-130-38.eu-central-1.compute.amazonaws.com (outside everyplate.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `34.227.209.168`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 34.227.209.168 resolves to ec2-34-227-209-168.compute-1.amazonaws.com (outside everyplate.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `34.242.102.67`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 34.242.102.67 resolves to ec2-34-242-102-67.eu-west-1.compute.amazonaws.com (outside everyplate.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `34.248.159.121`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 34.248.159.121 resolves to ec2-34-248-159-121.eu-west-1.compute.amazonaws.com (outside everyplate.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `46.51.200.92`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 46.51.200.92 resolves to ec2-46-51-200-92.eu-west-1.compute.amazonaws.com (outside everyplate.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `52.209.242.51`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 52.209.242.51 resolves to ec2-52-209-242-51.eu-west-1.compute.amazonaws.com (outside everyplate.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `52.21.142.91`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 52.21.142.91 resolves to ec2-52-21-142-91.compute-1.amazonaws.com (outside everyplate.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `54.216.50.79`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 54.216.50.79 resolves to ec2-54-216-50-79.eu-west-1.compute.amazonaws.com (outside everyplate.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `63.35.200.242`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 63.35.200.242 resolves to ec2-63-35-200-242.eu-west-1.compute.amazonaws.com (outside everyplate.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `99.84.152.97`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 99.84.152.97 resolves to server-99-84-152-97.fra56.r.cloudfront.net (outside everyplate.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-app.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-app.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-apps.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-apps.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-auth.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-auth.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-backup.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-backup.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-bak.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-bak.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-beta.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-beta.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-cd.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-cd.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-ci.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-ci.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-confluence.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-confluence.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-corp.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-corp.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-demo.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-demo.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-dev.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-dev.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-development.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-development.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-ftp.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-ftp.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-gateway.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-gateway.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-git.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-git.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-int.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-int.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-internal.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-internal.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-testing.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-testing.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-uat.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-uat.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-v1.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-v1.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-v2.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-v2.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-v3.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-v3.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-vpn.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-vpn.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active-web.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active-web.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.admin.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.admin.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.alpha.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.alpha.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.api.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.api.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.api2.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.api2.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.app.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.app.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.backup.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.backup.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.bak.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.bak.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.beta.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.beta.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.confluence.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.confluence.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.demo.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.demo.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.development.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.development.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.ftp.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.ftp.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.jenkins.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.jenkins.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.qa.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.qa.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.sandbox.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.sandbox.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.smtp.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.smtp.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.sso.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.sso.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.stage.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.stage.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.status.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.status.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.stg.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.stg.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.test.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.test.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.testing.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.testing.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.v1.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.v1.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


### [INFO] Virtual host on 104.18.36.122
- **Asset:** `active.v3.everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.v3.everyplate.com.au' served distinct content on 104.18.36.122 (HTTP 301)


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
- **Asset:** `https://s3.amazonaws.com/active.files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/active.media/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/active/`
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
- **Asset:** `https://s3.amazonaws.com/alerts-archive/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alerts-assets/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alerts-bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alerts-data/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alerts-files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alerts-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alerts-staging/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alerts-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alerts.assets/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alerts/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alpha-assets/`
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
- **Asset:** `https://s3.amazonaws.com/api-backups/`
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
- **Asset:** `https://s3.amazonaws.com/api-img/`
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
- **Asset:** `https://s3.amazonaws.com/api-web/`
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
- **Asset:** `https://s3.amazonaws.com/api/`
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


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/api2/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/app-assets/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/app-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/app-backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/app-cdn/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/app-data/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/app-files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/app-prod/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/app-public/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/app-static/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/app-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/app/`
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
- **Asset:** `https://storage.googleapis.com/active-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/active-test/`
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
- **Asset:** `https://storage.googleapis.com/alerts-archive/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alerts-bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alerts-dev/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alerts-images/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alerts-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alerts-media/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alerts-staging/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alerts-static/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alerts-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alerts/`
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
- **Asset:** `https://storage.googleapis.com/api-data/`
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
- **Asset:** `https://storage.googleapis.com/api-private/`
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
- **Asset:** `https://storage.googleapis.com/api-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/api-uploads/`
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


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/app-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/app-backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/app-cdn/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/app-data/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/app-img/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/app-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/app-media/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/app-private/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/app-prod/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/app-staging/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/app-static/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/app-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/app-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/app-uploads/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/app/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


## Prioritized Recommendations

- [CRITICAL] Force password resets; investigate infected endpoints; enforce MFA
- [CRITICAL] Review and rotate any leaked secrets; request GitHub takedown if applicable
- [HIGH] Restrict the bucket ACL/policy
- [HIGH] Rotate/revoke the credential and remove it from client-served content
- [MEDIUM] Publish/claim the scope, or pin an internal registry + scope config
- [MEDIUM] Verify the pointed-to service is claimed by you
- [LOW] Enable DNSSEC signing at the registrar/DNS provider
- [LOW] Publish an MTA-STS policy and _mta-sts TXT record
- [LOW] Use -all once senders are enumerated
- [INFO] Ensure IPv6 endpoints are covered by the same controls as IPv4
- [INFO] Review whether the pointed-to host is in scope
