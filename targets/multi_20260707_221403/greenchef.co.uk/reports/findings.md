# Attack-Surface Findings — `greenchef.co.uk` (domain)

_Generated 2026-07-08T07:38:22Z by TheN0thing v11.0_

## Executive Summary

**Risk score:** 100 / 100 (**critical**)  ·  **Total findings:** 180

| Severity | Count |
|----------|------:|
| critical | 3 |
| high | 13 |
| medium | 6 |
| low | 7 |
| info | 151 |

## Findings by Severity

### [CRITICAL] Infostealer-exposed credentials
- **Asset:** `greenchef.co.uk`
- **Category:** breach  ·  **Confidence:** firm  ·  **Detection:** breach

HudsonRock reports credentials from info-stealer logs (employees: 1, users: 231, total: 232)

_References:_ https://www.hudsonrock.com/threat-intelligence-cybercrime-tools

**Remediation:** Force password resets; investigate infected endpoints; enforce MFA


### [CRITICAL] GitHub code mentions 'greenchef.co.uk' near 'BEGIN RSA PRIVATE KEY' (3 hits)
- **Asset:** `github:greenchef.co.uk`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [CRITICAL] GitHub code mentions 'greenchef.co.uk' near 'aws access key id' (12 hits)
- **Asset:** `github:greenchef.co.uk`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] Google API Key exposed
- **Asset:** `http://greenchef.co.uk`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://greenchef.co.uk

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `https://greenchef.co.uk`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in https://greenchef.co.uk

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Publicly readable cloud bucket (s3)
- **Asset:** `https://s3.amazonaws.com/ads-app/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (s3)
- **Asset:** `https://s3.amazonaws.com/bob-staging/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/ads-images/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/ads-public/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/bob-bucket/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/cdn-public/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/cdn-web/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] GitHub code mentions 'greenchef.co.uk' near '.env' (3 hits)
- **Asset:** `github:greenchef.co.uk`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'greenchef.co.uk' near 'api key' (20 hits)
- **Asset:** `github:greenchef.co.uk`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'greenchef.co.uk' near 'password' (4 hits)
- **Asset:** `github:greenchef.co.uk`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'greenchef.co.uk' near 'secret' (11 hits)
- **Asset:** `github:greenchef.co.uk`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [MEDIUM] Third-party CNAME (takeover candidate)
- **Asset:** `live-vercel.greenchef.co.uk`
- **Category:** takeover  ·  **Confidence:** tentative  ·  **Detection:** normalize

live-vercel.greenchef.co.uk -> live-vercel.greenchef.co.uk.cdn.cloudflare.net.

**Remediation:** Verify the pointed-to service is claimed by you


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@greenchef/app`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@greenchef/app' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@greenchef/core`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@greenchef/core' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@greenchef/ui`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@greenchef/ui' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@greenchef/utils`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@greenchef/utils' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Third-party CNAME (takeover candidate)
- **Asset:** `staging-vercel.greenchef.co.uk`
- **Category:** takeover  ·  **Confidence:** tentative  ·  **Detection:** normalize

staging-vercel.greenchef.co.uk -> staging-vercel.greenchef.co.uk.cdn.cloudflare.net.

**Remediation:** Verify the pointed-to service is claimed by you


### [LOW] SOAP WSDL
- **Asset:** `http://greenchef.co.uk/?wsdl`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

SOAP WSDL at http://greenchef.co.uk/?wsdl (HTTP 200)


### [LOW] SOAP WSDL
- **Asset:** `https://greenchef.co.uk/?wsdl`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

SOAP WSDL at https://greenchef.co.uk/?wsdl (HTTP 200)


### [LOW] DNSSEC not enabled
- **Asset:** `greenchef.co.uk`
- **Category:** dns  ·  **Confidence:** firm  ·  **Detection:** emailsec

Zone is not DNSSEC-signed; DNS answers can be spoofed/tampered

_References:_ https://www.cloudflare.com/dns/dnssec/

**Remediation:** Enable DNSSEC signing at the registrar/DNS provider


### [LOW] MTA-STS not deployed
- **Asset:** `greenchef.co.uk`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

No MTA-STS policy; inbound-mail TLS can be stripped (downgrade)

_References:_ https://datatracker.ietf.org/doc/html/rfc8461

**Remediation:** Publish an MTA-STS policy and _mta-sts TXT record


### [LOW] SPF not hard-fail
- **Asset:** `greenchef.co.uk`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

SPF ends in ~all/?all rather than -all; spoofed mail may still pass

**Remediation:** Use -all once senders are enumerated


### [LOW] JWT Token exposed
- **Asset:** `http://greenchef.co.uk`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'JWT Token' matched in http://greenchef.co.uk

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [LOW] JWT Token exposed
- **Asset:** `https://greenchef.co.uk`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'JWT Token' matched in https://greenchef.co.uk

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [INFO] Robots txt
- **Asset:** `http://greenchef.co.uk/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at http://greenchef.co.uk/robots.txt (HTTP 200)


### [INFO] Sitemap xml
- **Asset:** `http://greenchef.co.uk/sitemap.xml`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Sitemap xml at http://greenchef.co.uk/sitemap.xml (HTTP 200)


### [INFO] Robots txt
- **Asset:** `https://greenchef.co.uk/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at https://greenchef.co.uk/robots.txt (HTTP 200)


### [INFO] Sitemap xml
- **Asset:** `https://greenchef.co.uk/sitemap.xml`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Sitemap xml at https://greenchef.co.uk/sitemap.xml (HTTP 200)


### [INFO] BIMI record present
- **Asset:** `greenchef.co.uk`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

Domain publishes a BIMI record (brand indicator)


### [INFO] Google Workspace in use
- **Asset:** `greenchef.co.uk`
- **Category:** identity  ·  **Confidence:** firm  ·  **Detection:** identity

MX records point to Google Workspace


### [INFO] IPv6 attack surface present
- **Asset:** `greenchef.co.uk`
- **Category:** dns  ·  **Confidence:** firm  ·  **Detection:** netintel

48 IPv6 (AAAA) address(es) discovered across hosts

**Remediation:** Ensure IPv6 endpoints are covered by the same controls as IPv4


### [INFO] Android app identified
- **Asset:** `play:com.greenchef.GreenChef`
- **Category:** mobile  ·  **Confidence:** firm  ·  **Detection:** mobile

Google Play app 'com.greenchef.GreenChef' appears associated with the target


### [INFO] Android app identified
- **Asset:** `play:com.greenchef.app`
- **Category:** mobile  ·  **Confidence:** firm  ·  **Detection:** mobile

Google Play app 'com.greenchef.app' appears associated with the target


### [INFO] Reverse DNS reveals related host
- **Asset:** `161.71.33.242`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 161.71.33.242 resolves to reply.s50.exacttarget.com (outside greenchef.co.uk)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `18.158.228.216`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 18.158.228.216 resolves to ec2-18-158-228-216.eu-central-1.compute.amazonaws.com (outside greenchef.co.uk)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `205.201.133.57`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 205.201.133.57 resolves to mail57.atl11.rsgsv.net (outside greenchef.co.uk)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `3.211.161.173`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 3.211.161.173 resolves to ec2-3-211-161-173.compute-1.amazonaws.com (outside greenchef.co.uk)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `3.79.130.38`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 3.79.130.38 resolves to ec2-3-79-130-38.eu-central-1.compute.amazonaws.com (outside greenchef.co.uk)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `34.227.209.168`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 34.227.209.168 resolves to ec2-34-227-209-168.compute-1.amazonaws.com (outside greenchef.co.uk)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `34.242.102.67`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 34.242.102.67 resolves to ec2-34-242-102-67.eu-west-1.compute.amazonaws.com (outside greenchef.co.uk)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `34.248.159.121`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 34.248.159.121 resolves to ec2-34-248-159-121.eu-west-1.compute.amazonaws.com (outside greenchef.co.uk)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `46.51.200.92`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 46.51.200.92 resolves to ec2-46-51-200-92.eu-west-1.compute.amazonaws.com (outside greenchef.co.uk)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `52.209.242.51`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 52.209.242.51 resolves to ec2-52-209-242-51.eu-west-1.compute.amazonaws.com (outside greenchef.co.uk)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `52.21.142.91`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 52.21.142.91 resolves to ec2-52-21-142-91.compute-1.amazonaws.com (outside greenchef.co.uk)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `54.216.50.79`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 54.216.50.79 resolves to ec2-54-216-50-79.eu-west-1.compute.amazonaws.com (outside greenchef.co.uk)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `63.35.200.242`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 63.35.200.242 resolves to ec2-63-35-200-242.eu-west-1.compute.amazonaws.com (outside greenchef.co.uk)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `a.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `active.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'active.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `ads.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'ads.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `bob-staging-cdn.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'bob-staging-cdn.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 403)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `bob.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'bob.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `click.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'click.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `click.link.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'click.link.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `cloud.link.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'cloud.link.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `downloads.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'downloads.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `friends.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'friends.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `help.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'help.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


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
- **Asset:** `https://s3.amazonaws.com/ads-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ads-cdn/`
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
- **Asset:** `https://s3.amazonaws.com/ads-public/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ads-storage/`
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
- **Asset:** `https://s3.amazonaws.com/ads/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alt3/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/bob-archive/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/bob-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/bob-backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/bob-data/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/bob-images/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/bob-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/bob-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/bob.bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/bob.logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/bob.test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/cdn-app/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/cdn-assets/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/cdn-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/cdn-backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/cdn-data/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/cdn-images/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/cdn-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/cdn-media/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/cdn-public/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/cdn-staging/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/cdn-static/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/cdn-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/cdn-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/cdn-uploads/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/cdn/`
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
- **Asset:** `https://storage.googleapis.com/ads-staging/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/ads-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alt1/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/bob-data/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/bob-files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/bob-private/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/bob-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/bob/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/cdn-app/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/cdn-archive/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/cdn-assets/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/cdn-bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/cdn-dev/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/cdn-files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/cdn-images/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/cdn-private/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/cdn-prod/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/cdn-staging/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/cdn-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `hub.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'hub.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `image.link.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'image.link.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `invoice.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'invoice.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `link.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'link.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `live-vercel.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'live-vercel.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `m.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'm.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `mail.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'mail.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `mail.zendesk.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'mail.zendesk.com' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `media.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'media.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `mobile.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'mobile.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 403)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `mta.link.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'mta.link.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `mta10.link.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'mta10.link.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `mta2.link.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'mta2.link.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `mta3.link.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'mta3.link.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `mta4.link.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'mta4.link.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `mta5.link.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'mta5.link.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `mta6.link.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'mta6.link.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `mta7.link.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'mta7.link.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `mta8.link.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'mta8.link.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `mta9.link.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'mta9.link.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `n.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'n.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `newsletter.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'newsletter.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `prometheus.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'prometheus.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `refer.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'refer.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `s3.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 's3.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `stage.mobile.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'stage.mobile.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 403)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `staging-vercel.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'staging-vercel.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `static-staging-cdn.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'static-staging-cdn.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 403)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `static.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'static.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `t.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 't.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `tms.hft.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'tms.hft.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `track-staging-cdn.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'track-staging-cdn.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 403)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `track.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'track.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `view.link.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'view.link.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `w.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'w.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `wd.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'wd.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `welcome.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'welcome.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 301)


### [INFO] Virtual host on 104.18.39.184
- **Asset:** `www-staging-cdn.greenchef.co.uk`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'www-staging-cdn.greenchef.co.uk' served distinct content on 104.18.39.184 (HTTP 403)


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
