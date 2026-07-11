# Attack-Surface Findings — `becoolcouriers.com.au` (domain)

_Generated 2026-07-07T23:36:59Z by TheN0thing v11.0_

## Executive Summary

**Risk score:** 100 / 100 (**critical**)  ·  **Total findings:** 327

| Severity | Count |
|----------|------:|
| critical | 2 |
| high | 56 |
| medium | 31 |
| low | 47 |
| info | 191 |

## Findings by Severity

### [CRITICAL] GitHub code mentions 'becoolcouriers.com.au' near 'BEGIN RSA PRIVATE KEY' (5 hits)
- **Asset:** `github:becoolcouriers.com.au`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [CRITICAL] GitHub code mentions 'becoolcouriers.com.au' near 'aws access key id' (10 hits)
- **Asset:** `github:becoolcouriers.com.au`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] Elasticsearch cat
- **Asset:** `http://107.21.108.229/_cat/indices`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Elasticsearch cat at http://107.21.108.229/_cat/indices (HTTP 200)


### [HIGH] Kibana status
- **Asset:** `http://107.21.108.229/api/status`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Kibana status at http://107.21.108.229/api/status (HTTP 200)


### [HIGH] Docker registry root
- **Asset:** `http://107.21.108.229/v2/`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker registry root at http://107.21.108.229/v2/ (HTTP 200)


### [HIGH] Elasticsearch cat
- **Asset:** `http://3.230.124.158/_cat/indices`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Elasticsearch cat at http://3.230.124.158/_cat/indices (HTTP 200)


### [HIGH] Kibana status
- **Asset:** `http://3.230.124.158/api/status`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Kibana status at http://3.230.124.158/api/status (HTTP 200)


### [HIGH] Docker API images
- **Asset:** `http://3.230.124.158/images/json`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker API images at http://3.230.124.158/images/json (HTTP 200)


### [HIGH] Elasticsearch cat
- **Asset:** `http://34.234.48.164/_cat/indices`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Elasticsearch cat at http://34.234.48.164/_cat/indices (HTTP 200)


### [HIGH] Kibana status
- **Asset:** `http://34.234.48.164/api/status`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Kibana status at http://34.234.48.164/api/status (HTTP 200)


### [HIGH] Elasticsearch cat
- **Asset:** `http://44.218.228.250/_cat/indices`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Elasticsearch cat at http://44.218.228.250/_cat/indices (HTTP 200)


### [HIGH] Kibana status
- **Asset:** `http://44.218.228.250/api/status`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Kibana status at http://44.218.228.250/api/status (HTTP 200)


### [HIGH] Consul ui
- **Asset:** `http://44.218.228.250/v1/catalog/services`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Consul ui at http://44.218.228.250/v1/catalog/services (HTTP 200)


### [HIGH] Docker registry root
- **Asset:** `http://44.218.228.250/v2/`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker registry root at http://44.218.228.250/v2/ (HTTP 200)


### [HIGH] Consul ui
- **Asset:** `http://portal.becoolcouriers.com.au/v1/catalog/services`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Consul ui at http://portal.becoolcouriers.com.au/v1/catalog/services (HTTP 200)


### [HIGH] Elasticsearch cat
- **Asset:** `https://107.21.108.229/_cat/indices`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Elasticsearch cat at https://107.21.108.229/_cat/indices (HTTP 200)


### [HIGH] Docker API images
- **Asset:** `https://107.21.108.229/images/json`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker API images at https://107.21.108.229/images/json (HTTP 200)


### [HIGH] Consul ui
- **Asset:** `https://107.21.108.229/v1/catalog/services`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Consul ui at https://107.21.108.229/v1/catalog/services (HTTP 200)


### [HIGH] Docker registry root
- **Asset:** `https://107.21.108.229/v2/`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker registry root at https://107.21.108.229/v2/ (HTTP 200)


### [HIGH] Elasticsearch cat
- **Asset:** `https://3.230.124.158/_cat/indices`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Elasticsearch cat at https://3.230.124.158/_cat/indices (HTTP 200)


### [HIGH] Kibana status
- **Asset:** `https://3.230.124.158/api/status`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Kibana status at https://3.230.124.158/api/status (HTTP 200)


### [HIGH] Docker API images
- **Asset:** `https://3.230.124.158/images/json`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker API images at https://3.230.124.158/images/json (HTTP 200)


### [HIGH] Consul ui
- **Asset:** `https://3.230.124.158/v1/catalog/services`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Consul ui at https://3.230.124.158/v1/catalog/services (HTTP 200)


### [HIGH] Docker registry root
- **Asset:** `https://3.230.124.158/v2/`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker registry root at https://3.230.124.158/v2/ (HTTP 200)


### [HIGH] Elasticsearch cat
- **Asset:** `https://34.234.48.164/_cat/indices`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Elasticsearch cat at https://34.234.48.164/_cat/indices (HTTP 200)


### [HIGH] Kibana status
- **Asset:** `https://34.234.48.164/api/status`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Kibana status at https://34.234.48.164/api/status (HTTP 200)


### [HIGH] Docker API images
- **Asset:** `https://34.234.48.164/images/json`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker API images at https://34.234.48.164/images/json (HTTP 200)


### [HIGH] Consul ui
- **Asset:** `https://34.234.48.164/v1/catalog/services`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Consul ui at https://34.234.48.164/v1/catalog/services (HTTP 200)


### [HIGH] Docker registry root
- **Asset:** `https://34.234.48.164/v2/`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker registry root at https://34.234.48.164/v2/ (HTTP 200)


### [HIGH] Elasticsearch cat
- **Asset:** `https://44.218.228.250/_cat/indices`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Elasticsearch cat at https://44.218.228.250/_cat/indices (HTTP 200)


### [HIGH] Kibana status
- **Asset:** `https://44.218.228.250/api/status`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Kibana status at https://44.218.228.250/api/status (HTTP 200)


### [HIGH] Consul ui
- **Asset:** `https://44.218.228.250/v1/catalog/services`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Consul ui at https://44.218.228.250/v1/catalog/services (HTTP 200)


### [HIGH] Docker registry root
- **Asset:** `https://44.218.228.250/v2/`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker registry root at https://44.218.228.250/v2/ (HTTP 200)


### [HIGH] Infostealer-exposed credentials
- **Asset:** `becoolcouriers.com.au`
- **Category:** breach  ·  **Confidence:** firm  ·  **Detection:** breach

HudsonRock reports credentials from info-stealer logs (employees: 0, users: 11, total: 12)

_References:_ https://www.hudsonrock.com/threat-intelligence-cybercrime-tools

**Remediation:** Force password resets; investigate infected endpoints; enforce MFA


### [HIGH] Google API Key exposed
- **Asset:** `http://107.21.108.229`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://107.21.108.229

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://3.230.124.158`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://3.230.124.158

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://34.234.48.164`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://34.234.48.164

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://44.218.228.250`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://44.218.228.250

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `https://107.21.108.229`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in https://107.21.108.229

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `https://3.230.124.158`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in https://3.230.124.158

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `https://34.234.48.164`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in https://34.234.48.164

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `https://44.218.228.250`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in https://44.218.228.250

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Publicly readable cloud bucket (s3)
- **Asset:** `https://s3.amazonaws.com/com-images/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/api-app/`
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
- **Asset:** `https://storage.googleapis.com/com-prod/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/dev-assets/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/dev-media/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/internal-cdn/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/intranet-bucket/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/intranet-media/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/mail-app/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/mail-images/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/mail-img/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] GitHub code mentions 'becoolcouriers.com.au' near '.env' (2 hits)
- **Asset:** `github:becoolcouriers.com.au`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'becoolcouriers.com.au' near 'api key' (14 hits)
- **Asset:** `github:becoolcouriers.com.au`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'becoolcouriers.com.au' near 'secret' (11 hits)
- **Asset:** `github:becoolcouriers.com.au`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [MEDIUM] Legacy TLSv1.0 supported
- **Asset:** `107.21.108.229:443`
- **Category:** tls  ·  **Confidence:** confirmed  ·  **Detection:** tls

Server negotiates deprecated TLSv1.0

_References:_ https://datatracker.ietf.org/doc/html/rfc8996

**Remediation:** Disable TLS 1.0 and TLS 1.1


### [MEDIUM] Legacy TLSv1.1 supported
- **Asset:** `107.21.108.229:443`
- **Category:** tls  ·  **Confidence:** confirmed  ·  **Detection:** tls

Server negotiates deprecated TLSv1.1

_References:_ https://datatracker.ietf.org/doc/html/rfc8996

**Remediation:** Disable TLS 1.0 and TLS 1.1


### [MEDIUM] Legacy TLSv1.0 supported
- **Asset:** `3.104.100.8:443`
- **Category:** tls  ·  **Confidence:** confirmed  ·  **Detection:** tls

Server negotiates deprecated TLSv1.0

_References:_ https://datatracker.ietf.org/doc/html/rfc8996

**Remediation:** Disable TLS 1.0 and TLS 1.1


### [MEDIUM] Legacy TLSv1.1 supported
- **Asset:** `3.104.100.8:443`
- **Category:** tls  ·  **Confidence:** confirmed  ·  **Detection:** tls

Server negotiates deprecated TLSv1.1

_References:_ https://datatracker.ietf.org/doc/html/rfc8996

**Remediation:** Disable TLS 1.0 and TLS 1.1


### [MEDIUM] Legacy TLSv1.0 supported
- **Asset:** `3.230.124.158:443`
- **Category:** tls  ·  **Confidence:** confirmed  ·  **Detection:** tls

Server negotiates deprecated TLSv1.0

_References:_ https://datatracker.ietf.org/doc/html/rfc8996

**Remediation:** Disable TLS 1.0 and TLS 1.1


### [MEDIUM] Legacy TLSv1.1 supported
- **Asset:** `3.230.124.158:443`
- **Category:** tls  ·  **Confidence:** confirmed  ·  **Detection:** tls

Server negotiates deprecated TLSv1.1

_References:_ https://datatracker.ietf.org/doc/html/rfc8996

**Remediation:** Disable TLS 1.0 and TLS 1.1


### [MEDIUM] Legacy TLSv1.0 supported
- **Asset:** `3.27.101.70:443`
- **Category:** tls  ·  **Confidence:** confirmed  ·  **Detection:** tls

Server negotiates deprecated TLSv1.0

_References:_ https://datatracker.ietf.org/doc/html/rfc8996

**Remediation:** Disable TLS 1.0 and TLS 1.1


### [MEDIUM] Legacy TLSv1.1 supported
- **Asset:** `3.27.101.70:443`
- **Category:** tls  ·  **Confidence:** confirmed  ·  **Detection:** tls

Server negotiates deprecated TLSv1.1

_References:_ https://datatracker.ietf.org/doc/html/rfc8996

**Remediation:** Disable TLS 1.0 and TLS 1.1


### [MEDIUM] Legacy TLSv1.0 supported
- **Asset:** `34.234.48.164:443`
- **Category:** tls  ·  **Confidence:** confirmed  ·  **Detection:** tls

Server negotiates deprecated TLSv1.0

_References:_ https://datatracker.ietf.org/doc/html/rfc8996

**Remediation:** Disable TLS 1.0 and TLS 1.1


### [MEDIUM] Legacy TLSv1.1 supported
- **Asset:** `34.234.48.164:443`
- **Category:** tls  ·  **Confidence:** confirmed  ·  **Detection:** tls

Server negotiates deprecated TLSv1.1

_References:_ https://datatracker.ietf.org/doc/html/rfc8996

**Remediation:** Disable TLS 1.0 and TLS 1.1


### [MEDIUM] Legacy TLSv1.0 supported
- **Asset:** `44.218.228.250:443`
- **Category:** tls  ·  **Confidence:** confirmed  ·  **Detection:** tls

Server negotiates deprecated TLSv1.0

_References:_ https://datatracker.ietf.org/doc/html/rfc8996

**Remediation:** Disable TLS 1.0 and TLS 1.1


### [MEDIUM] Legacy TLSv1.1 supported
- **Asset:** `44.218.228.250:443`
- **Category:** tls  ·  **Confidence:** confirmed  ·  **Detection:** tls

Server negotiates deprecated TLSv1.1

_References:_ https://datatracker.ietf.org/doc/html/rfc8996

**Remediation:** Disable TLS 1.0 and TLS 1.1


### [MEDIUM] SonarQube status
- **Asset:** `http://107.21.108.229/api/system/status`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

SonarQube status at http://107.21.108.229/api/system/status (HTTP 200)


### [MEDIUM] SonarQube status
- **Asset:** `http://3.230.124.158/api/system/status`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

SonarQube status at http://3.230.124.158/api/system/status (HTTP 200)


### [MEDIUM] Swagger UI docs
- **Asset:** `https://3.104.100.8/swagger/index.html`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

Swagger UI docs at https://3.104.100.8/swagger/index.html (HTTP 200)


### [MEDIUM] SonarQube status
- **Asset:** `https://3.230.124.158/api/system/status`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

SonarQube status at https://3.230.124.158/api/system/status (HTTP 200)


### [MEDIUM] Swagger UI docs
- **Asset:** `https://3.27.101.70/swagger/index.html`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

Swagger UI docs at https://3.27.101.70/swagger/index.html (HTTP 200)


### [MEDIUM] SonarQube status
- **Asset:** `https://44.218.228.250/api/system/status`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

SonarQube status at https://44.218.228.250/api/system/status (HTTP 200)


### [MEDIUM] Legacy TLSv1.1 supported
- **Asset:** `portalv2.becoolcouriers.com.au:443`
- **Category:** tls  ·  **Confidence:** confirmed  ·  **Detection:** tls

Server negotiates deprecated TLSv1.1

_References:_ https://datatracker.ietf.org/doc/html/rfc8996

**Remediation:** Disable TLS 1.0 and TLS 1.1


### [MEDIUM] DMARC policy is p=none
- **Asset:** `becoolcouriers.com.au`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

DMARC is monitor-only; spoofed mail is still delivered

**Remediation:** Progress to p=quarantine then p=reject


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
- **Asset:** `npm:@becoolcouriers/app`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@becoolcouriers/app' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@becoolcouriers/core`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@becoolcouriers/core' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@becoolcouriers/ui`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@becoolcouriers/ui' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@becoolcouriers/utils`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@becoolcouriers/utils' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [LOW] Exchange Autodiscover
- **Asset:** `http://107.21.108.229/autodiscover/autodiscover.xml`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Exchange Autodiscover at http://107.21.108.229/autodiscover/autodiscover.xml (HTTP 200)


### [LOW] Composer json
- **Asset:** `http://107.21.108.229/composer.json`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Composer json at http://107.21.108.229/composer.json (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `http://107.21.108.229/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at http://107.21.108.229/health (HTTP 200)


### [LOW] Exchange Autodiscover
- **Asset:** `http://3.230.124.158/autodiscover/autodiscover.xml`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Exchange Autodiscover at http://3.230.124.158/autodiscover/autodiscover.xml (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `http://3.230.124.158/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at http://3.230.124.158/health (HTTP 200)


### [LOW] Env example
- **Asset:** `http://34.234.48.164/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at http://34.234.48.164/.env.example (HTTP 200)


### [LOW] Exchange Autodiscover
- **Asset:** `http://34.234.48.164/autodiscover/autodiscover.xml`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Exchange Autodiscover at http://34.234.48.164/autodiscover/autodiscover.xml (HTTP 200)


### [LOW] Composer json
- **Asset:** `http://34.234.48.164/composer.json`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Composer json at http://34.234.48.164/composer.json (HTTP 200)


### [LOW] Exchange Autodiscover
- **Asset:** `http://44.218.228.250/autodiscover/autodiscover.xml`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Exchange Autodiscover at http://44.218.228.250/autodiscover/autodiscover.xml (HTTP 200)


### [LOW] Composer json
- **Asset:** `http://44.218.228.250/composer.json`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Composer json at http://44.218.228.250/composer.json (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `http://44.218.228.250/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at http://44.218.228.250/health (HTTP 200)


### [LOW] Env example
- **Asset:** `http://portal.becoolcouriers.com.au/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at http://portal.becoolcouriers.com.au/.env.example (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `http://portal.becoolcouriers.com.au/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at http://portal.becoolcouriers.com.au/health (HTTP 200)


### [LOW] Env example
- **Asset:** `https://107.21.108.229/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at https://107.21.108.229/.env.example (HTTP 200)


### [LOW] Composer json
- **Asset:** `https://107.21.108.229/composer.json`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Composer json at https://107.21.108.229/composer.json (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `https://107.21.108.229/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at https://107.21.108.229/health (HTTP 200)


### [LOW] Env example
- **Asset:** `https://3.230.124.158/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at https://3.230.124.158/.env.example (HTTP 200)


### [LOW] Composer json
- **Asset:** `https://3.230.124.158/composer.json`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Composer json at https://3.230.124.158/composer.json (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `https://3.230.124.158/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at https://3.230.124.158/health (HTTP 200)


### [LOW] Exchange Autodiscover
- **Asset:** `https://34.234.48.164/autodiscover/autodiscover.xml`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Exchange Autodiscover at https://34.234.48.164/autodiscover/autodiscover.xml (HTTP 200)


### [LOW] Composer json
- **Asset:** `https://34.234.48.164/composer.json`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Composer json at https://34.234.48.164/composer.json (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `https://34.234.48.164/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at https://34.234.48.164/health (HTTP 200)


### [LOW] Env example
- **Asset:** `https://44.218.228.250/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at https://44.218.228.250/.env.example (HTTP 200)


### [LOW] Composer json
- **Asset:** `https://44.218.228.250/composer.json`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Composer json at https://44.218.228.250/composer.json (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `https://44.218.228.250/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at https://44.218.228.250/health (HTTP 200)


### [LOW] DNSSEC not enabled
- **Asset:** `becoolcouriers.com.au`
- **Category:** dns  ·  **Confidence:** firm  ·  **Detection:** emailsec

Zone is not DNSSEC-signed; DNS answers can be spoofed/tampered

_References:_ https://www.cloudflare.com/dns/dnssec/

**Remediation:** Enable DNSSEC signing at the registrar/DNS provider


### [LOW] MTA-STS not deployed
- **Asset:** `becoolcouriers.com.au`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

No MTA-STS policy; inbound-mail TLS can be stripped (downgrade)

_References:_ https://datatracker.ietf.org/doc/html/rfc8461

**Remediation:** Publish an MTA-STS policy and _mta-sts TXT record


### [LOW] SPF not hard-fail
- **Asset:** `becoolcouriers.com.au`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

SPF ends in ~all/?all rather than -all; spoofed mail may still pass

**Remediation:** Use -all once senders are enumerated


### [LOW] No DKIM selector found
- **Asset:** `becoolcouriers.com.au`
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
- **Asset:** `http://107.21.108.229/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at http://107.21.108.229/api (HTTP 200)


### [INFO] API v1 root
- **Asset:** `http://107.21.108.229/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at http://107.21.108.229/api/v1 (HTTP 200)


### [INFO] API v2 root
- **Asset:** `http://107.21.108.229/api/v2`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v2 root at http://107.21.108.229/api/v2 (HTTP 200)


### [INFO] API root hint
- **Asset:** `http://3.230.124.158/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at http://3.230.124.158/api (HTTP 200)


### [INFO] API v2 root
- **Asset:** `http://3.230.124.158/api/v2`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v2 root at http://3.230.124.158/api/v2 (HTTP 200)


### [INFO] API root hint
- **Asset:** `http://34.234.48.164/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at http://34.234.48.164/api (HTTP 200)


### [INFO] API v1 root
- **Asset:** `http://34.234.48.164/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at http://34.234.48.164/api/v1 (HTTP 200)


### [INFO] API root hint
- **Asset:** `http://44.218.228.250/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at http://44.218.228.250/api (HTTP 200)


### [INFO] API v1 root
- **Asset:** `http://44.218.228.250/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at http://44.218.228.250/api/v1 (HTTP 200)


### [INFO] API root hint
- **Asset:** `http://portal.becoolcouriers.com.au/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at http://portal.becoolcouriers.com.au/api (HTTP 200)


### [INFO] API v1 root
- **Asset:** `http://portal.becoolcouriers.com.au/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at http://portal.becoolcouriers.com.au/api/v1 (HTTP 200)


### [INFO] API v2 root
- **Asset:** `http://portal.becoolcouriers.com.au/api/v2`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v2 root at http://portal.becoolcouriers.com.au/api/v2 (HTTP 200)


### [INFO] API root hint
- **Asset:** `https://107.21.108.229/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at https://107.21.108.229/api (HTTP 200)


### [INFO] API v2 root
- **Asset:** `https://107.21.108.229/api/v2`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v2 root at https://107.21.108.229/api/v2 (HTTP 200)


### [INFO] API v1 root
- **Asset:** `https://3.230.124.158/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at https://3.230.124.158/api/v1 (HTTP 200)


### [INFO] API v2 root
- **Asset:** `https://3.230.124.158/api/v2`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v2 root at https://3.230.124.158/api/v2 (HTTP 200)


### [INFO] API root hint
- **Asset:** `https://34.234.48.164/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at https://34.234.48.164/api (HTTP 200)


### [INFO] API v1 root
- **Asset:** `https://34.234.48.164/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at https://34.234.48.164/api/v1 (HTTP 200)


### [INFO] API v2 root
- **Asset:** `https://34.234.48.164/api/v2`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v2 root at https://34.234.48.164/api/v2 (HTTP 200)


### [INFO] API root hint
- **Asset:** `https://44.218.228.250/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at https://44.218.228.250/api (HTTP 200)


### [INFO] API v1 root
- **Asset:** `https://44.218.228.250/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at https://44.218.228.250/api/v1 (HTTP 200)


### [INFO] API v1 root
- **Asset:** `https://portalv2.becoolcouriers.com.au/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at https://portalv2.becoolcouriers.com.au/api/v1 (HTTP 200)


### [INFO] API v2 root
- **Asset:** `https://portalv2.becoolcouriers.com.au/api/v2`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v2 root at https://portalv2.becoolcouriers.com.au/api/v2 (HTTP 200)


### [INFO] Google Workspace in use
- **Asset:** `becoolcouriers.com.au`
- **Category:** identity  ·  **Confidence:** firm  ·  **Detection:** identity

MX records point to Google Workspace


### [INFO] IPv6 attack surface present
- **Asset:** `becoolcouriers.com.au`
- **Category:** dns  ·  **Confidence:** firm  ·  **Detection:** netintel

2 IPv6 (AAAA) address(es) discovered across hosts

**Remediation:** Ensure IPv6 endpoints are covered by the same controls as IPv4


### [INFO] Reverse DNS reveals related host
- **Asset:** `107.21.108.229`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 107.21.108.229 resolves to ec2-107-21-108-229.compute-1.amazonaws.com (outside becoolcouriers.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `143.204.130.68`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 143.204.130.68 resolves to server-143-204-130-68.iah50.r.cloudfront.net (outside becoolcouriers.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `143.204.130.83`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 143.204.130.83 resolves to server-143-204-130-83.iah50.r.cloudfront.net (outside becoolcouriers.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `143.204.130.88`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 143.204.130.88 resolves to server-143-204-130-88.iah50.r.cloudfront.net (outside becoolcouriers.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `143.204.130.92`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 143.204.130.92 resolves to server-143-204-130-92.iah50.r.cloudfront.net (outside becoolcouriers.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `184.168.221.15`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 184.168.221.15 resolves to 15.221.168.184.host.secureserver.net (outside becoolcouriers.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `3.104.100.8`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 3.104.100.8 resolves to ec2-3-104-100-8.ap-southeast-2.compute.amazonaws.com (outside becoolcouriers.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `3.230.124.158`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 3.230.124.158 resolves to ec2-3-230-124-158.compute-1.amazonaws.com (outside becoolcouriers.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `3.27.101.70`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 3.27.101.70 resolves to ec2-3-27-101-70.ap-southeast-2.compute.amazonaws.com (outside becoolcouriers.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `34.234.48.164`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 34.234.48.164 resolves to ec2-34-234-48-164.compute-1.amazonaws.com (outside becoolcouriers.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `52.222.177.57`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 52.222.177.57 resolves to server-52-222-177-57.lhr95.r.cloudfront.net (outside becoolcouriers.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `52.222.177.97`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 52.222.177.97 resolves to server-52-222-177-97.lhr95.r.cloudfront.net (outside becoolcouriers.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `52.84.50.110`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 52.84.50.110 resolves to server-52-84-50-110.osl50.r.cloudfront.net (outside becoolcouriers.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `52.84.50.38`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 52.84.50.38 resolves to server-52-84-50-38.osl50.r.cloudfront.net (outside becoolcouriers.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `52.84.50.70`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 52.84.50.70 resolves to server-52-84-50-70.osl50.r.cloudfront.net (outside becoolcouriers.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `54.209.191.217`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 54.209.191.217 resolves to ec2-54-209-191-217.compute-1.amazonaws.com (outside becoolcouriers.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `54.79.43.92`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 54.79.43.92 resolves to ec2-54-79-43-92.ap-southeast-2.compute.amazonaws.com (outside becoolcouriers.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `98.89.169.226`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 98.89.169.226 resolves to ec2-98-89-169-226.compute-1.amazonaws.com (outside becoolcouriers.com.au)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Virtual host on 143.204.130.68
- **Asset:** `api.becoolcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'api.becoolcouriers.com.au' served distinct content on 143.204.130.68 (HTTP 301)


### [INFO] Virtual host on 143.204.130.83
- **Asset:** `api.becoolcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'api.becoolcouriers.com.au' served distinct content on 143.204.130.83 (HTTP 301)


### [INFO] Virtual host on 143.204.130.88
- **Asset:** `api.becoolcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'api.becoolcouriers.com.au' served distinct content on 143.204.130.88 (HTTP 301)


### [INFO] Virtual host on 143.204.130.92
- **Asset:** `api.becoolcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'api.becoolcouriers.com.au' served distinct content on 143.204.130.92 (HTTP 301)


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
- **Asset:** `https://s3.amazonaws.com/api-test/`
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
- **Asset:** `https://s3.amazonaws.com/api.storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/becoolcouriers/`
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
- **Asset:** `https://s3.amazonaws.com/com-public/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/com-web/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/com.logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/com.media/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev-archive/`
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
- **Asset:** `https://s3.amazonaws.com/dev-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev-private/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev-uploads/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev-web/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev.app/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/dev.images/`
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
- **Asset:** `https://s3.amazonaws.com/dev.public/`
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
- **Asset:** `https://s3.amazonaws.com/internal-app/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/internal-assets/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/internal-bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/internal-cdn/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/internal-data/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/internal-img/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/internal-prod/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/internal-uploads/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/internal.assets/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/intranet-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/intranet-backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/intranet-dev/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/intranet-prod/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/intranet-public/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/intranet-staging/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/intranet-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/intranet.media/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/intranet.uploads/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/intranet/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mail-app/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mail-archive/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mail-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mail-backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mail-cdn/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mail-data/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mail-files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mail-img/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mail-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mail-media/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mail-prod/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mail-public/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mail-staging/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mail-static/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mail-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mail.bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mail.data/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mail.web/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mobi-app/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mobi-assets/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mobi-files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mobi-images/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mobi-prod/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mobi-public/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/mobi-uploads/`
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
- **Asset:** `https://storage.googleapis.com/api-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/api/`
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
- **Asset:** `https://storage.googleapis.com/com-media/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/com-static/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/dev-app/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/dev-backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/dev-cdn/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/dev-files/`
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
- **Asset:** `https://storage.googleapis.com/dev-public/`
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
- **Asset:** `https://storage.googleapis.com/dev/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/internal-archive/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/internal-backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/internal-bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/internal-dev/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/internal-public/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/internal-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/internal-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/internal-uploads/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/internal/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/intranet-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/intranet-prod/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/intranet-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/intranet-uploads/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/mail-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/mail-backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/mail-cdn/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/mail-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/mail-prod/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/mail-uploads/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/mobi-assets/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/mobi/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Virtual host on 142.251.143.147
- **Asset:** `intranet.becoolcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'intranet.becoolcouriers.com.au' served distinct content on 142.251.143.147 (HTTP 301)


### [INFO] Virtual host on 143.204.130.68
- **Asset:** `portal.becoolcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'portal.becoolcouriers.com.au' served distinct content on 143.204.130.68 (HTTP 301)


### [INFO] Virtual host on 143.204.130.83
- **Asset:** `portal.becoolcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'portal.becoolcouriers.com.au' served distinct content on 143.204.130.83 (HTTP 301)


### [INFO] Virtual host on 143.204.130.88
- **Asset:** `portal.becoolcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'portal.becoolcouriers.com.au' served distinct content on 143.204.130.88 (HTTP 301)


### [INFO] Virtual host on 143.204.130.92
- **Asset:** `portal.becoolcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'portal.becoolcouriers.com.au' served distinct content on 143.204.130.92 (HTTP 301)


### [INFO] Virtual host on 143.204.130.68
- **Asset:** `portalv2-dev.becoolcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'portalv2-dev.becoolcouriers.com.au' served distinct content on 143.204.130.68 (HTTP 301)


### [INFO] Virtual host on 143.204.130.83
- **Asset:** `portalv2-dev.becoolcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'portalv2-dev.becoolcouriers.com.au' served distinct content on 143.204.130.83 (HTTP 301)


### [INFO] Virtual host on 143.204.130.88
- **Asset:** `portalv2-dev.becoolcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'portalv2-dev.becoolcouriers.com.au' served distinct content on 143.204.130.88 (HTTP 301)


### [INFO] Virtual host on 143.204.130.92
- **Asset:** `portalv2-dev.becoolcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'portalv2-dev.becoolcouriers.com.au' served distinct content on 143.204.130.92 (HTTP 301)


### [INFO] Virtual host on 143.204.130.68
- **Asset:** `portalv2.becoolcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'portalv2.becoolcouriers.com.au' served distinct content on 143.204.130.68 (HTTP 301)


### [INFO] Virtual host on 143.204.130.83
- **Asset:** `portalv2.becoolcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'portalv2.becoolcouriers.com.au' served distinct content on 143.204.130.83 (HTTP 301)


### [INFO] Virtual host on 143.204.130.88
- **Asset:** `portalv2.becoolcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'portalv2.becoolcouriers.com.au' served distinct content on 143.204.130.88 (HTTP 301)


### [INFO] Virtual host on 143.204.130.92
- **Asset:** `portalv2.becoolcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'portalv2.becoolcouriers.com.au' served distinct content on 143.204.130.92 (HTTP 301)


## Prioritized Recommendations

- [CRITICAL] Review and rotate any leaked secrets; request GitHub takedown if applicable
- [HIGH] Force password resets; investigate infected endpoints; enforce MFA
- [HIGH] Restrict the bucket ACL/policy
- [HIGH] Rotate/revoke the credential and remove it from client-served content
- [MEDIUM] Disable TLS 1.0 and TLS 1.1
- [MEDIUM] Manually test for ssti on the highlighted parameter
- [MEDIUM] Progress to p=quarantine then p=reject
- [MEDIUM] Publish/claim the scope, or pin an internal registry + scope config
- [MEDIUM] Remove internal references from client bundles
- [LOW] Enable DNSSEC signing at the registrar/DNS provider
- [LOW] Manually test for idor on the highlighted parameter
- [LOW] Manually test for sqli on the highlighted parameter
- [LOW] Manually test for xss on the highlighted parameter
- [LOW] Publish a DKIM key and sign outbound mail
- [LOW] Publish an MTA-STS policy and _mta-sts TXT record
- [LOW] Use -all once senders are enumerated
- [INFO] Ensure IPv6 endpoints are covered by the same controls as IPv4
- [INFO] Manually test for interestingEXT on the highlighted parameter
- [INFO] Manually test for interestingparams on the highlighted parameter
- [INFO] Review whether the pointed-to host is in scope
