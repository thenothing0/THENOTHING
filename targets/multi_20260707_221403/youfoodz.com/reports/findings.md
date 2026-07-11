# Attack-Surface Findings — `youfoodz.com` (domain)

_Generated 2026-07-08T10:02:42Z by TheN0thing v11.0_

## Executive Summary

**Risk score:** 100 / 100 (**critical**)  ·  **Total findings:** 346

| Severity | Count |
|----------|------:|
| critical | 3 |
| high | 44 |
| medium | 64 |
| low | 104 |
| info | 131 |

## Findings by Severity

### [CRITICAL] Docker cfg exposed
- **Asset:** `https://bob.youfoodz.com/.dockercfg`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Docker cfg exposed at https://bob.youfoodz.com/.dockercfg (HTTP 200)


### [CRITICAL] GitHub code mentions 'youfoodz.com' near 'BEGIN RSA PRIVATE KEY' (56 hits)
- **Asset:** `github:youfoodz.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [CRITICAL] GitHub code mentions 'youfoodz.com' near 'aws access key id' (106 hits)
- **Asset:** `github:youfoodz.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] Docker API images
- **Asset:** `http://pages.e.youfoodz.com/images/json`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker API images at http://pages.e.youfoodz.com/images/json (HTTP 200)


### [HIGH] Docker API images
- **Asset:** `https://bob.youfoodz.com/images/json`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker API images at https://bob.youfoodz.com/images/json (HTTP 200)


### [HIGH] Consul ui
- **Asset:** `https://bob.youfoodz.com/v1/catalog/services`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Consul ui at https://bob.youfoodz.com/v1/catalog/services (HTTP 200)


### [HIGH] Docker registry root
- **Asset:** `https://bob.youfoodz.com/v2/`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker registry root at https://bob.youfoodz.com/v2/ (HTTP 200)


### [HIGH] Google API Key exposed
- **Asset:** `http://links.youfoodz.com:2086`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://links.youfoodz.com:2086

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://www.youfoodz.com/cart.js`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://www.youfoodz.com/cart.js

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://www.youfoodz.com/cart.js?_=1484818005613`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://www.youfoodz.com/cart.js?_=1484818005613

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://www.youfoodz.com/cart.js?_=1484818379091`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://www.youfoodz.com/cart.js?_=1484818379091

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://www.youfoodz.com/cart.js?_=1492067135511`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://www.youfoodz.com/cart.js?_=1492067135511

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://www.youfoodz.com/js/contentslider.js`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://www.youfoodz.com/js/contentslider.js

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://www.youfoodz.com/js/dropdown.js`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://www.youfoodz.com/js/dropdown.js

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://www.youfoodz.com/js/jqzoom.pack.1.0.1.js`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://www.youfoodz.com/js/jqzoom.pack.1.0.1.js

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://www.youfoodz.com/js/shopajaxsearch.js`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://www.youfoodz.com/js/shopajaxsearch.js

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://www.youfoodz.com/js/stocknotification.js`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://www.youfoodz.com/js/stocknotification.js

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://www.youfoodz.com/js/vs350.js`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://www.youfoodz.com/js/vs350.js

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://www.youfoodz.com/templates/template_spa700/js/easySlider1.7.js`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://www.youfoodz.com/templates/template_spa700/js/easySlider1.7.js

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://www.youfoodz.com/templates/template_spa700/js/libs/jquery-1.7.1.min.js`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://www.youfoodz.com/templates/template_spa700/js/libs/jquery-1.7.1.min.js

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://www.youfoodz.com/templates/template_spa700/js/libs/jquery.easing.1.3.js`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://www.youfoodz.com/templates/template_spa700/js/libs/jquery.easing.1.3.js

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://www.youfoodz.com/templates/template_spa700/js/libs/jquery.jcarousel.min.js`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://www.youfoodz.com/templates/template_spa700/js/libs/jquery.jcarousel.min.js

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://www.youfoodz.com/templates/template_spa700/js/libs/modernizr-1.7.min.js`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://www.youfoodz.com/templates/template_spa700/js/libs/modernizr-1.7.min.js

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://www.youfoodz.com/templates/template_spa700/js/main.js`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://www.youfoodz.com/templates/template_spa700/js/main.js

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://www.youfoodz.com/templates/template_spa700/js/plugins.js`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://www.youfoodz.com/templates/template_spa700/js/plugins.js

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://www.youfoodz.com/templates/template_spa700/js/script.js`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://www.youfoodz.com/templates/template_spa700/js/script.js

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://www.youfoodz.com/templates/template_spa700/js/vendor/modernizr-2.6.2.min.js`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://www.youfoodz.com/templates/template_spa700/js/vendor/modernizr-2.6.2.min.js

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://www.youfoodz.com:80/js/vendor/jquery-1.9.1.min.js`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://www.youfoodz.com:80/js/vendor/jquery-1.9.1.min.js

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://youfoodz.com/templates/template_spa700/js/main.js?sid=8252ee5a2773732965aa36e5e2dcb25b`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://youfoodz.com/templates/template_spa700/js/main.js?sid=8252ee5a2773732965aa36e5e2dcb25b

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://youfoodz.com/templates/template_spa700/js/plugins.js?sid=729a8b55abbca516f9c0bbc7cf6254f7`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://youfoodz.com/templates/template_spa700/js/plugins.js?sid=729a8b55abbca516f9c0bbc7cf6254f7

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://youfoodz.com/templates/template_spa700/js/vendor/modernizr-2.6.2.min.js?sid=0c7125415980f2d699a0f0bb84142bf0`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://youfoodz.com/templates/template_spa700/js/vendor/modernizr-2.6.2.min.js?sid=0c7125415980f2d699a0f0bb84142bf0

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/add-assets/`
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


### [HIGH] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/cancellation/referrals.cdp.test.key`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [HIGH] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/checkout/referrals.cdp.test.key`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [HIGH] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/gift/register/referrals.cdp.test.key`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [HIGH] Infostealer-exposed credentials
- **Asset:** `youfoodz.com`
- **Category:** breach  ·  **Confidence:** firm  ·  **Detection:** breach

HudsonRock reports credentials from info-stealer logs (employees: 0, users: 901, total: 907)

_References:_ https://www.hudsonrock.com/threat-intelligence-cybercrime-tools

**Remediation:** Force password resets; investigate infected endpoints; enforce MFA


### [HIGH] GitHub code mentions 'youfoodz.com' near '.env' (36 hits)
- **Asset:** `github:youfoodz.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'youfoodz.com' near 'api key' (144 hits)
- **Asset:** `github:youfoodz.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'youfoodz.com' near 'mysql password' (2 hits)
- **Asset:** `github:youfoodz.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'youfoodz.com' near 'password' (28 hits)
- **Asset:** `github:youfoodz.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'youfoodz.com' near 'secret' (113 hits)
- **Asset:** `github:youfoodz.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [MEDIUM] VMware Horizon
- **Asset:** `https://bob.youfoodz.com/portal/webclient/`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

VMware Horizon at https://bob.youfoodz.com/portal/webclient/ (HTTP 200)


### [MEDIUM] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/.well-known/assetlinks.json`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [MEDIUM] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/apple-app-site-association/chefsplate.json`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [MEDIUM] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/apple-app-site-association/everyplate.json`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [MEDIUM] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/apple-app-site-association/factor.json`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [MEDIUM] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/apple-app-site-association/greenchef.json`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [MEDIUM] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/apple-app-site-association/youfoodz.json`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [MEDIUM] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/assetlinks/chefsplate.json`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [MEDIUM] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/assetlinks/everyplate.json`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [MEDIUM] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/assetlinks/factor.json`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [MEDIUM] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/assetlinks/greenchef.json`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [MEDIUM] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/assetlinks/youfoodz.json`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [MEDIUM] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/assets/releases/web-infra/t9n/7.98.12393/youfoodz/en-AU/contact.json`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [MEDIUM] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/assets/releases/web-infra/t9n/7.98.12393/youfoodz/en-AU/self-report.json`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [MEDIUM] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/assets/releases/web-infra/t9n/7.98.28649/youfoodz/en-AU/account-area.my-deliveries.json`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [MEDIUM] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/cancellation/factor-app-communication.json`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [MEDIUM] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/checkout/factor-app-communication.json`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [MEDIUM] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/gift/register/factor-app-communication.json`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [MEDIUM] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/manifest.json`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [MEDIUM] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/manifests/ao.json`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [MEDIUM] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/manifests/cf.json`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [MEDIUM] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/manifests/cg.json`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [MEDIUM] Archived sensitive file still live
- **Asset:** `https://www.youfoodz.com/manifests/ck.json`
- **Category:** wayback  ·  **Confidence:** firm  ·  **Detection:** wayback

A historically-archived sensitive file is still accessible today (HTTP 200)

**Remediation:** Remove the file from the web root / restrict access


### [MEDIUM] SPF record missing
- **Asset:** `youfoodz.com`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

No SPF record published; sender spoofing is easier

_References:_ https://datatracker.ietf.org/doc/html/rfc7208

**Remediation:** Publish an SPF record that ends in -all


### [MEDIUM] Candidate: ssti pattern in URL
- **Asset:** `http://www.youfoodz.com/shopreviewspro.asp?id=213`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssti' gf pattern — manual verification candidate

**Remediation:** Manually test for ssti on the highlighted parameter


### [MEDIUM] Candidate: ssti pattern in URL
- **Asset:** `http://www.youfoodz.com/shoptellfriendpro.asp?id=213`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssti' gf pattern — manual verification candidate

**Remediation:** Manually test for ssti on the highlighted parameter


### [MEDIUM] Candidate: ssti pattern in URL
- **Asset:** `http://www.youfoodz.com:80/?utm_source=february&utm_medium=content&utm_content=balicomp&utm_campaign=urbanlist`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssti' gf pattern — manual verification candidate

**Remediation:** Manually test for ssti on the highlighted parameter


### [MEDIUM] Candidate: ssti pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/all/products/balinese-chicken-cashew-noodles?utm_source=february&utm_medium=content&utm_content=balicomp&utm_campaign=urbanlist`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssti' gf pattern — manual verification candidate

**Remediation:** Manually test for ssti on the highlighted parameter


### [MEDIUM] Candidate: ssti pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/all?utm_source=Facebook-ads&utm_medium=Alleygroup&utm_content=Prospecting`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssti' gf pattern — manual verification candidate

**Remediation:** Manually test for ssti on the highlighted parameter


### [MEDIUM] Candidate: ssti pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/breakfast/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssti' gf pattern — manual verification candidate

**Remediation:** Manually test for ssti on the highlighted parameter


### [MEDIUM] Candidate: ssti pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/drinks/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssti' gf pattern — manual verification candidate

**Remediation:** Manually test for ssti on the highlighted parameter


### [MEDIUM] Candidate: ssti pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/relaxed-lunch-dinner/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssti' gf pattern — manual verification candidate

**Remediation:** Manually test for ssti on the highlighted parameter


### [MEDIUM] Candidate: ssti pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?id=1&cat=Main+Meals`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssti' gf pattern — manual verification candidate

**Remediation:** Manually test for ssti on the highlighted parameter


### [MEDIUM] Candidate: ssti pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?id=2&cat=Salads`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssti' gf pattern — manual verification candidate

**Remediation:** Manually test for ssti on the highlighted parameter


### [MEDIUM] Candidate: ssti pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?id=3&cat=Snacks+%26amp%3B+Deserts`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssti' gf pattern — manual verification candidate

**Remediation:** Manually test for ssti on the highlighted parameter


### [MEDIUM] Candidate: ssti pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?id=3&cat=Snacks+%26amp%3B+Desserts`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssti' gf pattern — manual verification candidate

**Remediation:** Manually test for ssti on the highlighted parameter


### [MEDIUM] Candidate: ssti pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?id=4&cat=Fit+Meals`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssti' gf pattern — manual verification candidate

**Remediation:** Manually test for ssti on the highlighted parameter


### [MEDIUM] Candidate: ssti pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?id=5&cat=Breakfast`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssti' gf pattern — manual verification candidate

**Remediation:** Manually test for ssti on the highlighted parameter


### [MEDIUM] Candidate: ssti pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?id=6&cat=Pre%2DSet+Menu`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssti' gf pattern — manual verification candidate

**Remediation:** Manually test for ssti on the highlighted parameter


### [MEDIUM] Candidate: rce pattern in URL
- **Asset:** `https://www.youfoodz.com/?%3Forigin=%2Fcontact-page%2Fself-report&action=agent&option=chat&reason=ingredients-in-my-order`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'rce' gf pattern — manual verification candidate

**Remediation:** Manually test for rce on the highlighted parameter


### [MEDIUM] Candidate: rce pattern in URL
- **Asset:** `https://www.youfoodz.com/?action=agent&option=chat&origin=%2Fcontact-page%2Fself-report`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'rce' gf pattern — manual verification candidate

**Remediation:** Manually test for rce on the highlighted parameter


### [MEDIUM] Candidate: rce pattern in URL
- **Asset:** `https://www.youfoodz.com/about/FAQ?%22%27x=,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,&addBase=o8&ajax=o8&bookings=o8&bulk_edit=o8&categorie=o8&categoryID=o8&cni=o8&core=o8&dbk=o8&deact=o8&gpsflag3=o8&help=o8&information_item_access=o8&ipproto=o8&mail_joined_ltml=o8&methodpayload=o8&myname=o8&newPlaylistTitle=o8&newvalue=o8&noRedirect=o8&oracle=o8&postal_code=o8&profiler=o8&que=o8&receipt=o8&relation=o8&relay=o8&replaceWith=o8&res=o8&screen=o8&searchText=o8&sortColumn=o8&stay=o8&tdel_username=o8&templateid=o8&tnm=o8&usa=o8&useR=o8&userdata=o8&vbseo_redirect=o8&vouchers=o8&wy=o8&xlb=o8&xmldump=o8`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'rce' gf pattern — manual verification candidate

**Remediation:** Manually test for rce on the highlighted parameter


### [MEDIUM] Candidate: rce pattern in URL
- **Asset:** `https://www.youfoodz.com/about/FAQ?Desserts=gc&InvId=gc&LMI_PAYMENT_NO=gc&VBSEO_POSTID_URI=gc&admin_chat=gc&allss=gc&attachmentId=gc&autoredirect=gc&balance=gc&blogtype=gc&bsz=gc&cc=gc&completed=gc&country=gc&dbpassword=gc&ddx=gc&dw=gc&exemplar=gc&getupdatestatus=gc&hide_last_info=gc&hsn=gc&king=gc&lower=gc&managerlanguage=gc&massdefacedir=gc&msg_title=gc&nnr=gc&o=,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,&originalPath=gc&phpsettings=gc&pipi=gc&placa=gc&popuptitle=gc&post_subject=gc&prog=gc&qp=gc&redirect_on=gc&redirect_url=gc&removeheader=gc&reportsent=gc&reserveAlert=gc&revoke=gc&rok=gc&search_cat=gc&search_query=gc&searchfield=gc&serv=gc&sfilename=gc&size=gc&snc=gc&stopbtn=gc&tagcloudview=gc&txtCommand=gc&uploaddir=gc&usf=gc&validator=gc&venue=gc&viewonline=gc&vmd=gc&vz=gc&wa=gc&yz=gc`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'rce' gf pattern — manual verification candidate

**Remediation:** Manually test for rce on the highlighted parameter


### [MEDIUM] Candidate: rce pattern in URL
- **Asset:** `https://www.youfoodz.com/about/FAQ?Desserts=gc&InvId=gc&VBSEO_POSTID_URI=gc&admin_chat=gc&allss=gc&attachmentId=gc&autoredirect=gc&balance=gc&blogtype=gc&bsz=gc&cc=gc&completed=gc&country=gc&dbpassword=gc&ddx=gc&dw=gc&exemplar=gc&getupdatestatus=gc&hide_last_info=gc&hsn=gc&ipn=gc&king=gc&lower=gc&managerlanguage=gc&massdefacedir=gc&msg_title=gc&nnr=gc&o=,,,,,,,,,,,,,,,,,&originalPath=gc&phpsettings=gc&pipi=gc&placa=gc&popuptitle=gc&post_subject=gc&prog=gc&qp=gc&redirect_on=gc&redirect_url=gc&removeheader=gc&reportsent=gc&reserveAlert=gc&revoke=gc&rok=gc&search_cat=gc&search_query=gc&searchfield=gc&serv=gc&sfilename=gc&size=gc&snc=gc&stopbtn=gc&tagcloudview=gc&txtCommand=gc&uploaddir=gc&usf=gc&validator=gc&venue=gc&viewonline=gc&vmd=gc&vz=gc&wa=gc&yz=gc`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'rce' gf pattern — manual verification candidate

**Remediation:** Manually test for rce on the highlighted parameter


### [MEDIUM] Candidate: rce pattern in URL
- **Asset:** `https://www.youfoodz.com/about/delivery-areas?%22%27x=,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,&addBase=o8&ajax=o8&bookings=o8&bulk_edit=o8&categorie=o8&categoryID=o8&cni=o8&core=o8&dbk=o8&deact=o8&gpsflag3=o8&help=o8&information_item_access=o8&ipproto=o8&mail_joined_ltml=o8&methodpayload=o8&myname=o8&newPlaylistTitle=o8&newvalue=o8&noRedirect=o8&oracle=o8&postal_code=o8&profiler=o8&que=o8&receipt=o8&relation=o8&relay=o8&replaceWith=o8&res=o8&screen=o8&searchText=o8&sortColumn=o8&stay=o8&tdel_username=o8&templateid=o8&tnm=o8&usa=o8&useR=o8&userdata=o8&vbseo_redirect=o8&vouchers=o8&wy=o8&xlb=o8&xmldump=o8`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'rce' gf pattern — manual verification candidate

**Remediation:** Manually test for rce on the highlighted parameter


### [MEDIUM] Candidate: rce pattern in URL
- **Asset:** `https://www.youfoodz.com/about/delivery-areas?Desserts=gc&InvId=gc&LMI_PAYMENT_NO=gc&VBSEO_POSTID_URI=gc&admin_chat=gc&allss=gc&attachmentId=gc&autoredirect=gc&balance=gc&blogtype=gc&bsz=gc&cc=gc&completed=gc&country=gc&dbpassword=gc&ddx=gc&dw=gc&exemplar=gc&getupdatestatus=gc&hide_last_info=gc&hsn=gc&king=gc&lower=gc&managerlanguage=gc&massdefacedir=gc&msg_title=gc&nnr=gc&o=,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,&originalPath=gc&phpsettings=gc&pipi=gc&placa=gc&popuptitle=gc&post_subject=gc&prog=gc&qp=gc&redirect_on=gc&redirect_url=gc&removeheader=gc&reportsent=gc&reserveAlert=gc&revoke=gc&rok=gc&search_cat=gc&search_query=gc&searchfield=gc&serv=gc&sfilename=gc&size=gc&snc=gc&stopbtn=gc&tagcloudview=gc&txtCommand=gc&uploaddir=gc&usf=gc&validator=gc&venue=gc&viewonline=gc&vmd=gc&vz=gc&wa=gc&yz=gc`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'rce' gf pattern — manual verification candidate

**Remediation:** Manually test for rce on the highlighted parameter


### [MEDIUM] Candidate: rce pattern in URL
- **Asset:** `https://www.youfoodz.com/about/delivery-areas?Desserts=gc&InvId=gc&VBSEO_POSTID_URI=gc&admin_chat=gc&allss=gc&attachmentId=gc&autoredirect=gc&balance=gc&blogtype=gc&bsz=gc&cc=gc&completed=gc&country=gc&dbpassword=gc&ddx=gc&dw=gc&exemplar=gc&getupdatestatus=gc&hide_last_info=gc&hsn=gc&ipn=gc&king=gc&lower=gc&managerlanguage=gc&massdefacedir=gc&msg_title=gc&nnr=gc&o=,,,,,,,,,,,,,,,,,&originalPath=gc&phpsettings=gc&pipi=gc&placa=gc&popuptitle=gc&post_subject=gc&prog=gc&qp=gc&redirect_on=gc&redirect_url=gc&removeheader=gc&reportsent=gc&reserveAlert=gc&revoke=gc&rok=gc&search_cat=gc&search_query=gc&searchfield=gc&serv=gc&sfilename=gc&size=gc&snc=gc&stopbtn=gc&tagcloudview=gc&txtCommand=gc&uploaddir=gc&usf=gc&validator=gc&venue=gc&viewonline=gc&vmd=gc&vz=gc&wa=gc&yz=gc`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'rce' gf pattern — manual verification candidate

**Remediation:** Manually test for rce on the highlighted parameter


### [MEDIUM] Candidate: rce pattern in URL
- **Asset:** `https://www.youfoodz.com/about/how-it-works?%22%27x=,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,&addBase=o8&ajax=o8&bookings=o8&bulk_edit=o8&categorie=o8&categoryID=o8&cni=o8&core=o8&dbk=o8&deact=o8&gpsflag3=o8&help=o8&information_item_access=o8&ipproto=o8&mail_joined_ltml=o8&methodpayload=o8&myname=o8&newPlaylistTitle=o8&newvalue=o8&noRedirect=o8&oracle=o8&postal_code=o8&profiler=o8&que=o8&receipt=o8&relation=o8&relay=o8&replaceWith=o8&res=o8&screen=o8&searchText=o8&sortColumn=o8&stay=o8&tdel_username=o8&templateid=o8&tnm=o8&usa=o8&useR=o8&userdata=o8&vbseo_redirect=o8&vouchers=o8&wy=o8&xlb=o8&xmldump=o8`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'rce' gf pattern — manual verification candidate

**Remediation:** Manually test for rce on the highlighted parameter


### [MEDIUM] Candidate: rce pattern in URL
- **Asset:** `https://www.youfoodz.com/about/how-it-works?Desserts=gc&InvId=gc&LMI_PAYMENT_NO=gc&VBSEO_POSTID_URI=gc&admin_chat=gc&allss=gc&attachmentId=gc&autoredirect=gc&balance=gc&blogtype=gc&bsz=gc&cc=gc&completed=gc&country=gc&dbpassword=gc&ddx=gc&dw=gc&exemplar=gc&getupdatestatus=gc&hide_last_info=gc&hsn=gc&king=gc&lower=gc&managerlanguage=gc&massdefacedir=gc&msg_title=gc&nnr=gc&o=,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,&originalPath=gc&phpsettings=gc&pipi=gc&placa=gc&popuptitle=gc&post_subject=gc&prog=gc&qp=gc&redirect_on=gc&redirect_url=gc&removeheader=gc&reportsent=gc&reserveAlert=gc&revoke=gc&rok=gc&search_cat=gc&search_query=gc&searchfield=gc&serv=gc&sfilename=gc&size=gc&snc=gc&stopbtn=gc&tagcloudview=gc&txtCommand=gc&uploaddir=gc&usf=gc&validator=gc&venue=gc&viewonline=gc&vmd=gc&vz=gc&wa=gc&yz=gc`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'rce' gf pattern — manual verification candidate

**Remediation:** Manually test for rce on the highlighted parameter


### [MEDIUM] Candidate: rce pattern in URL
- **Asset:** `https://www.youfoodz.com/about/how-it-works?Desserts=gc&InvId=gc&VBSEO_POSTID_URI=gc&admin_chat=gc&allss=gc&attachmentId=gc&autoredirect=gc&balance=gc&blogtype=gc&bsz=gc&cc=gc&completed=gc&country=gc&dbpassword=gc&ddx=gc&dw=gc&exemplar=gc&getupdatestatus=gc&hide_last_info=gc&hsn=gc&ipn=gc&king=gc&lower=gc&managerlanguage=gc&massdefacedir=gc&msg_title=gc&nnr=gc&o=,,,,,,,,,,,,,,,,,&originalPath=gc&phpsettings=gc&pipi=gc&placa=gc&popuptitle=gc&post_subject=gc&prog=gc&qp=gc&redirect_on=gc&redirect_url=gc&removeheader=gc&reportsent=gc&reserveAlert=gc&revoke=gc&rok=gc&search_cat=gc&search_query=gc&searchfield=gc&serv=gc&sfilename=gc&size=gc&snc=gc&stopbtn=gc&tagcloudview=gc&txtCommand=gc&uploaddir=gc&usf=gc&validator=gc&venue=gc&viewonline=gc&vmd=gc&vz=gc&wa=gc&yz=gc`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'rce' gf pattern — manual verification candidate

**Remediation:** Manually test for rce on the highlighted parameter


### [MEDIUM] Candidate: rce pattern in URL
- **Asset:** `https://www.youfoodz.com/about/how-to-cancel-youfoodz?%22%27x=,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,&addBase=o8&ajax=o8&bookings=o8&bulk_edit=o8&categorie=o8&categoryID=o8&cni=o8&core=o8&dbk=o8&deact=o8&gpsflag3=o8&help=o8&information_item_access=o8&ipproto=o8&mail_joined_ltml=o8&methodpayload=o8&myname=o8&newPlaylistTitle=o8&newvalue=o8&noRedirect=o8&oracle=o8&postal_code=o8&profiler=o8&que=o8&receipt=o8&relation=o8&relay=o8&replaceWith=o8&res=o8&screen=o8&searchText=o8&sortColumn=o8&stay=o8&tdel_username=o8&templateid=o8&tnm=o8&usa=o8&useR=o8&userdata=o8&vbseo_redirect=o8&vouchers=o8&wy=o8&xlb=o8&xmldump=o8`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'rce' gf pattern — manual verification candidate

**Remediation:** Manually test for rce on the highlighted parameter


### [MEDIUM] Candidate: rce pattern in URL
- **Asset:** `https://www.youfoodz.com/about/how-to-cancel-youfoodz?Desserts=gc&InvId=gc&LMI_PAYMENT_NO=gc&VBSEO_POSTID_URI=gc&admin_chat=gc&allss=gc&attachmentId=gc&autoredirect=gc&balance=gc&blogtype=gc&bsz=gc&cc=gc&completed=gc&country=gc&dbpassword=gc&ddx=gc&dw=gc&exemplar=gc&getupdatestatus=gc&hide_last_info=gc&hsn=gc&king=gc&lower=gc&managerlanguage=gc&massdefacedir=gc&msg_title=gc&nnr=gc&o=,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,&originalPath=gc&phpsettings=gc&pipi=gc&placa=gc&popuptitle=gc&post_subject=gc&prog=gc&qp=gc&redirect_on=gc&redirect_url=gc&removeheader=gc&reportsent=gc&reserveAlert=gc&revoke=gc&rok=gc&search_cat=gc&search_query=gc&searchfield=gc&serv=gc&sfilename=gc&size=gc&snc=gc&stopbtn=gc&tagcloudview=gc&txtCommand=gc&uploaddir=gc&usf=gc&validator=gc&venue=gc&viewonline=gc&vmd=gc&vz=gc&wa=gc&yz=gc`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'rce' gf pattern — manual verification candidate

**Remediation:** Manually test for rce on the highlighted parameter


### [MEDIUM] Candidate: rce pattern in URL
- **Asset:** `https://www.youfoodz.com/about/how-to-cancel-youfoodz?Desserts=gc&InvId=gc&VBSEO_POSTID_URI=gc&admin_chat=gc&allss=gc&attachmentId=gc&autoredirect=gc&balance=gc&blogtype=gc&bsz=gc&cc=gc&completed=gc&country=gc&dbpassword=gc&ddx=gc&dw=gc&exemplar=gc&getupdatestatus=gc&hide_last_info=gc&hsn=gc&ipn=gc&king=gc&lower=gc&managerlanguage=gc&massdefacedir=gc&msg_title=gc&nnr=gc&o=,,,,,,,,,,,,,,,,,&originalPath=gc&phpsettings=gc&pipi=gc&placa=gc&popuptitle=gc&post_subject=gc&prog=gc&qp=gc&redirect_on=gc&redirect_url=gc&removeheader=gc&reportsent=gc&reserveAlert=gc&revoke=gc&rok=gc&search_cat=gc&search_query=gc&searchfield=gc&serv=gc&sfilename=gc&size=gc&snc=gc&stopbtn=gc&tagcloudview=gc&txtCommand=gc&uploaddir=gc&usf=gc&validator=gc&venue=gc&viewonline=gc&vmd=gc&vz=gc&wa=gc&yz=gc`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'rce' gf pattern — manual verification candidate

**Remediation:** Manually test for rce on the highlighted parameter


### [MEDIUM] Candidate: rce pattern in URL
- **Asset:** `https://www.youfoodz.com/about/menus-and-plans?%22%27x=,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,&addBase=o8&ajax=o8&bookings=o8&bulk_edit=o8&categorie=o8&categoryID=o8&cni=o8&core=o8&dbk=o8&deact=o8&gpsflag3=o8&help=o8&information_item_access=o8&ipproto=o8&mail_joined_ltml=o8&methodpayload=o8&myname=o8&newPlaylistTitle=o8&newvalue=o8&noRedirect=o8&oracle=o8&postal_code=o8&profiler=o8&que=o8&receipt=o8&relation=o8&relay=o8&replaceWith=o8&res=o8&screen=o8&searchText=o8&sortColumn=o8&stay=o8&tdel_username=o8&templateid=o8&tnm=o8&usa=o8&useR=o8&userdata=o8&vbseo_redirect=o8&vouchers=o8&wy=o8&xlb=o8&xmldump=o8`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'rce' gf pattern — manual verification candidate

**Remediation:** Manually test for rce on the highlighted parameter


### [MEDIUM] Third-party CNAME (takeover candidate)
- **Asset:** `live-vercel.youfoodz.com`
- **Category:** takeover  ·  **Confidence:** tentative  ·  **Detection:** normalize

live-vercel.youfoodz.com -> live-vercel.youfoodz.com.cdn.cloudflare.net.

**Remediation:** Verify the pointed-to service is claimed by you


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@youfoodz/app`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@youfoodz/app' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@youfoodz/core`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@youfoodz/core' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@youfoodz/ui`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@youfoodz/ui' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@youfoodz/utils`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@youfoodz/utils' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Third-party CNAME (takeover candidate)
- **Asset:** `partnerships.youfoodz.com`
- **Category:** takeover  ·  **Confidence:** tentative  ·  **Detection:** normalize

partnerships.youfoodz.com -> dpnkow9o4nx98.cloudfront.net.

**Remediation:** Verify the pointed-to service is claimed by you


### [MEDIUM] Third-party CNAME (takeover candidate)
- **Asset:** `shopify-dandomain-controllererpsychotechnics.fresh.youfoodz.com`
- **Category:** takeover  ·  **Confidence:** tentative  ·  **Detection:** normalize

shopify-dandomain-controllererpsychotechnics.fresh.youfoodz.com -> c69ee047def545f018e34bf38f44f283.7d7d3772d2769c8c044b0e3010684195.pfkqlkldb6o55k55c555.comodoca.com.

**Remediation:** Verify the pointed-to service is claimed by you


### [MEDIUM] Third-party CNAME (takeover candidate)
- **Asset:** `staging-vercel.youfoodz.com`
- **Category:** takeover  ·  **Confidence:** tentative  ·  **Detection:** normalize

staging-vercel.youfoodz.com -> staging-vercel.youfoodz.com.cdn.cloudflare.net.

**Remediation:** Verify the pointed-to service is claimed by you


### [MEDIUM] Third-party CNAME (takeover candidate)
- **Asset:** `support.youfoodz.com`
- **Category:** takeover  ·  **Confidence:** tentative  ·  **Detection:** normalize

support.youfoodz.com -> youfoodzsupport.zendesk.com.

**Remediation:** Verify the pointed-to service is claimed by you


### [MEDIUM] Third-party CNAME (takeover candidate)
- **Asset:** `www.care.youfoodz.com`
- **Category:** takeover  ·  **Confidence:** tentative  ·  **Detection:** normalize

www.care.youfoodz.com -> shops.myshopify.com.

**Remediation:** Verify the pointed-to service is claimed by you


### [LOW] Env example
- **Asset:** `https://bob.youfoodz.com/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at https://bob.youfoodz.com/.env.example (HTTP 200)


### [LOW] Admin panel
- **Asset:** `https://bob.youfoodz.com/admin`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin panel at https://bob.youfoodz.com/admin (HTTP 200)


### [LOW] Admin login
- **Asset:** `https://bob.youfoodz.com/admin/login`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin login at https://bob.youfoodz.com/admin/login (HTTP 200)


### [LOW] Docker compose
- **Asset:** `https://bob.youfoodz.com/docker-compose.yml`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Docker compose at https://bob.youfoodz.com/docker-compose.yml (HTTP 200)


### [LOW] JWT Token exposed
- **Asset:** `http://links.youfoodz.com:2086`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'JWT Token' matched in http://links.youfoodz.com:2086

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [LOW] DNSSEC not enabled
- **Asset:** `youfoodz.com`
- **Category:** dns  ·  **Confidence:** firm  ·  **Detection:** emailsec

Zone is not DNSSEC-signed; DNS answers can be spoofed/tampered

_References:_ https://www.cloudflare.com/dns/dnssec/

**Remediation:** Enable DNSSEC signing at the registrar/DNS provider


### [LOW] MTA-STS not deployed
- **Asset:** `youfoodz.com`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

No MTA-STS policy; inbound-mail TLS can be stripped (downgrade)

_References:_ https://datatracker.ietf.org/doc/html/rfc8461

**Remediation:** Publish an MTA-STS policy and _mta-sts TXT record


### [LOW] Candidate: idor pattern in URL
- **Asset:** `http://www.youfoodz.com/shopreviewspro.asp?id=213`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'idor' gf pattern — manual verification candidate

**Remediation:** Manually test for idor on the highlighted parameter


### [LOW] Candidate: sqli pattern in URL
- **Asset:** `http://www.youfoodz.com/shopreviewspro.asp?id=213`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'sqli' gf pattern — manual verification candidate

**Remediation:** Manually test for sqli on the highlighted parameter


### [LOW] Candidate: xss pattern in URL
- **Asset:** `http://www.youfoodz.com/shopreviewspro.asp?id=213`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'xss' gf pattern — manual verification candidate

**Remediation:** Manually test for xss on the highlighted parameter


### [LOW] Candidate: idor pattern in URL
- **Asset:** `http://www.youfoodz.com/shoptellfriendpro.asp?id=213`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'idor' gf pattern — manual verification candidate

**Remediation:** Manually test for idor on the highlighted parameter


### [LOW] Candidate: sqli pattern in URL
- **Asset:** `http://www.youfoodz.com/shoptellfriendpro.asp?id=213`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'sqli' gf pattern — manual verification candidate

**Remediation:** Manually test for sqli on the highlighted parameter


### [LOW] Candidate: xss pattern in URL
- **Asset:** `http://www.youfoodz.com/shoptellfriendpro.asp?id=213`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'xss' gf pattern — manual verification candidate

**Remediation:** Manually test for xss on the highlighted parameter


### [LOW] Candidate: lfi pattern in URL
- **Asset:** `http://www.youfoodz.com:80/?utm_source=february&utm_medium=content&utm_content=balicomp&utm_campaign=urbanlist`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'lfi' gf pattern — manual verification candidate

**Remediation:** Manually test for lfi on the highlighted parameter


### [LOW] Candidate: lfi pattern in URL
- **Asset:** `http://www.youfoodz.com:80/blogs/blog?page=2`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'lfi' gf pattern — manual verification candidate

**Remediation:** Manually test for lfi on the highlighted parameter


### [LOW] Candidate: redirect pattern in URL
- **Asset:** `http://www.youfoodz.com:80/blogs/blog?page=2`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'redirect' gf pattern — manual verification candidate

**Remediation:** Manually test for redirect on the highlighted parameter


### [LOW] Candidate: ssrf pattern in URL
- **Asset:** `http://www.youfoodz.com:80/blogs/blog?page=2`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssrf' gf pattern — manual verification candidate

**Remediation:** Manually test for ssrf on the highlighted parameter


### [LOW] Candidate: xss pattern in URL
- **Asset:** `http://www.youfoodz.com:80/blogs/blog?page=2`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'xss' gf pattern — manual verification candidate

**Remediation:** Manually test for xss on the highlighted parameter


### [LOW] Candidate: lfi pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/all/products/balinese-chicken-cashew-noodles?utm_source=february&utm_medium=content&utm_content=balicomp&utm_campaign=urbanlist`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'lfi' gf pattern — manual verification candidate

**Remediation:** Manually test for lfi on the highlighted parameter


### [LOW] Candidate: lfi pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/all?page=1`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'lfi' gf pattern — manual verification candidate

**Remediation:** Manually test for lfi on the highlighted parameter


### [LOW] Candidate: redirect pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/all?page=1`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'redirect' gf pattern — manual verification candidate

**Remediation:** Manually test for redirect on the highlighted parameter


### [LOW] Candidate: ssrf pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/all?page=1`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssrf' gf pattern — manual verification candidate

**Remediation:** Manually test for ssrf on the highlighted parameter


### [LOW] Candidate: xss pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/all?page=1`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'xss' gf pattern — manual verification candidate

**Remediation:** Manually test for xss on the highlighted parameter


### [LOW] Candidate: lfi pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/all?utm_source=Facebook-ads&utm_medium=Alleygroup&utm_content=Prospecting`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'lfi' gf pattern — manual verification candidate

**Remediation:** Manually test for lfi on the highlighted parameter


### [LOW] Candidate: lfi pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/breakfast/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'lfi' gf pattern — manual verification candidate

**Remediation:** Manually test for lfi on the highlighted parameter


### [LOW] Candidate: redirect pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/breakfast/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'redirect' gf pattern — manual verification candidate

**Remediation:** Manually test for redirect on the highlighted parameter


### [LOW] Candidate: sqli pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/breakfast/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'sqli' gf pattern — manual verification candidate

**Remediation:** Manually test for sqli on the highlighted parameter


### [LOW] Candidate: ssrf pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/breakfast/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssrf' gf pattern — manual verification candidate

**Remediation:** Manually test for ssrf on the highlighted parameter


### [LOW] Candidate: xss pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/breakfast/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'xss' gf pattern — manual verification candidate

**Remediation:** Manually test for xss on the highlighted parameter


### [LOW] Candidate: lfi pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/drinks/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'lfi' gf pattern — manual verification candidate

**Remediation:** Manually test for lfi on the highlighted parameter


### [LOW] Candidate: redirect pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/drinks/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'redirect' gf pattern — manual verification candidate

**Remediation:** Manually test for redirect on the highlighted parameter


### [LOW] Candidate: sqli pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/drinks/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'sqli' gf pattern — manual verification candidate

**Remediation:** Manually test for sqli on the highlighted parameter


### [LOW] Candidate: ssrf pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/drinks/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssrf' gf pattern — manual verification candidate

**Remediation:** Manually test for ssrf on the highlighted parameter


### [LOW] Candidate: xss pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/drinks/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'xss' gf pattern — manual verification candidate

**Remediation:** Manually test for xss on the highlighted parameter


### [LOW] Candidate: lfi pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/relaxed-lunch-dinner/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'lfi' gf pattern — manual verification candidate

**Remediation:** Manually test for lfi on the highlighted parameter


### [LOW] Candidate: redirect pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/relaxed-lunch-dinner/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'redirect' gf pattern — manual verification candidate

**Remediation:** Manually test for redirect on the highlighted parameter


### [LOW] Candidate: sqli pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/relaxed-lunch-dinner/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'sqli' gf pattern — manual verification candidate

**Remediation:** Manually test for sqli on the highlighted parameter


### [LOW] Candidate: ssrf pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/relaxed-lunch-dinner/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssrf' gf pattern — manual verification candidate

**Remediation:** Manually test for ssrf on the highlighted parameter


### [LOW] Candidate: xss pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/relaxed-lunch-dinner/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'xss' gf pattern — manual verification candidate

**Remediation:** Manually test for xss on the highlighted parameter


### [LOW] Candidate: lfi pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/www.youfoodz.com/collections/all?page=1`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'lfi' gf pattern — manual verification candidate

**Remediation:** Manually test for lfi on the highlighted parameter


### [LOW] Candidate: redirect pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/www.youfoodz.com/collections/all?page=1`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'redirect' gf pattern — manual verification candidate

**Remediation:** Manually test for redirect on the highlighted parameter


### [LOW] Candidate: ssrf pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/www.youfoodz.com/collections/all?page=1`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssrf' gf pattern — manual verification candidate

**Remediation:** Manually test for ssrf on the highlighted parameter


### [LOW] Candidate: xss pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/www.youfoodz.com/collections/all?page=1`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'xss' gf pattern — manual verification candidate

**Remediation:** Manually test for xss on the highlighted parameter


### [LOW] Candidate: lfi pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/www.youfoodz.com/collections/all?page=2`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'lfi' gf pattern — manual verification candidate

**Remediation:** Manually test for lfi on the highlighted parameter


### [LOW] Candidate: redirect pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/www.youfoodz.com/collections/all?page=2`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'redirect' gf pattern — manual verification candidate

**Remediation:** Manually test for redirect on the highlighted parameter


### [LOW] Candidate: ssrf pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/www.youfoodz.com/collections/all?page=2`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssrf' gf pattern — manual verification candidate

**Remediation:** Manually test for ssrf on the highlighted parameter


### [LOW] Candidate: xss pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/www.youfoodz.com/collections/all?page=2`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'xss' gf pattern — manual verification candidate

**Remediation:** Manually test for xss on the highlighted parameter


### [LOW] Candidate: lfi pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopblogs.asp?type=Healthy%20Fish%20and%20Chips%20Recipe`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'lfi' gf pattern — manual verification candidate

**Remediation:** Manually test for lfi on the highlighted parameter


### [LOW] Candidate: xss pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopblogs.asp?type=Healthy%20Fish%20and%20Chips%20Recipe`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'xss' gf pattern — manual verification candidate

**Remediation:** Manually test for xss on the highlighted parameter


### [LOW] Candidate: lfi pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopblogs.asp?type=Healthy%20Fruity%20Icy%20Poles`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'lfi' gf pattern — manual verification candidate

**Remediation:** Manually test for lfi on the highlighted parameter


### [LOW] Candidate: xss pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopblogs.asp?type=Healthy%20Fruity%20Icy%20Poles`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'xss' gf pattern — manual verification candidate

**Remediation:** Manually test for xss on the highlighted parameter


### [LOW] Candidate: lfi pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopblogs.asp?type=Healthy+Fruity+Icy+Poles`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'lfi' gf pattern — manual verification candidate

**Remediation:** Manually test for lfi on the highlighted parameter


### [LOW] Candidate: xss pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopblogs.asp?type=Healthy+Fruity+Icy+Poles`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'xss' gf pattern — manual verification candidate

**Remediation:** Manually test for xss on the highlighted parameter


### [LOW] Candidate: lfi pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopblogs.asp?type=Recent+Posts`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'lfi' gf pattern — manual verification candidate

**Remediation:** Manually test for lfi on the highlighted parameter


### [LOW] Candidate: xss pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopblogs.asp?type=Recent+Posts`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'xss' gf pattern — manual verification candidate

**Remediation:** Manually test for xss on the highlighted parameter


### [LOW] Candidate: lfi pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopblogs.asp?type=first`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'lfi' gf pattern — manual verification candidate

**Remediation:** Manually test for lfi on the highlighted parameter


### [LOW] Candidate: xss pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopblogs.asp?type=first`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'xss' gf pattern — manual verification candidate

**Remediation:** Manually test for xss on the highlighted parameter


### [LOW] Candidate: xss pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopblogslistings.asp?month=1/2012`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'xss' gf pattern — manual verification candidate

**Remediation:** Manually test for xss on the highlighted parameter


### [LOW] Candidate: idor pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?id=1&cat=Main+Meals`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'idor' gf pattern — manual verification candidate

**Remediation:** Manually test for idor on the highlighted parameter


### [LOW] Candidate: sqli pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?id=1&cat=Main+Meals`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'sqli' gf pattern — manual verification candidate

**Remediation:** Manually test for sqli on the highlighted parameter


### [LOW] Candidate: idor pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?id=2&cat=Salads`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'idor' gf pattern — manual verification candidate

**Remediation:** Manually test for idor on the highlighted parameter


### [LOW] Candidate: sqli pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?id=2&cat=Salads`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'sqli' gf pattern — manual verification candidate

**Remediation:** Manually test for sqli on the highlighted parameter


### [LOW] Candidate: idor pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?id=3&cat=Snacks+%26amp%3B+Deserts`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'idor' gf pattern — manual verification candidate

**Remediation:** Manually test for idor on the highlighted parameter


### [LOW] Candidate: sqli pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?id=3&cat=Snacks+%26amp%3B+Deserts`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'sqli' gf pattern — manual verification candidate

**Remediation:** Manually test for sqli on the highlighted parameter


### [LOW] Candidate: idor pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?id=3&cat=Snacks+%26amp%3B+Desserts`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'idor' gf pattern — manual verification candidate

**Remediation:** Manually test for idor on the highlighted parameter


### [LOW] Candidate: sqli pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?id=3&cat=Snacks+%26amp%3B+Desserts`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'sqli' gf pattern — manual verification candidate

**Remediation:** Manually test for sqli on the highlighted parameter


### [LOW] Candidate: idor pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?id=4&cat=Fit+Meals`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'idor' gf pattern — manual verification candidate

**Remediation:** Manually test for idor on the highlighted parameter


### [LOW] Candidate: sqli pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?id=4&cat=Fit+Meals`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'sqli' gf pattern — manual verification candidate

**Remediation:** Manually test for sqli on the highlighted parameter


### [LOW] Candidate: idor pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?id=5&cat=Breakfast`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'idor' gf pattern — manual verification candidate

**Remediation:** Manually test for idor on the highlighted parameter


### [LOW] Candidate: sqli pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?id=5&cat=Breakfast`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'sqli' gf pattern — manual verification candidate

**Remediation:** Manually test for sqli on the highlighted parameter


### [LOW] Candidate: idor pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?id=6&cat=Pre%2DSet+Menu`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'idor' gf pattern — manual verification candidate

**Remediation:** Manually test for idor on the highlighted parameter


### [LOW] Candidate: sqli pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?id=6&cat=Pre%2DSet+Menu`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'sqli' gf pattern — manual verification candidate

**Remediation:** Manually test for sqli on the highlighted parameter


### [LOW] Candidate: idor pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?search=yes&bc=no&catalogid=174`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'idor' gf pattern — manual verification candidate

**Remediation:** Manually test for idor on the highlighted parameter


### [LOW] Candidate: sqli pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?search=yes&bc=no&catalogid=174`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'sqli' gf pattern — manual verification candidate

**Remediation:** Manually test for sqli on the highlighted parameter


### [LOW] Candidate: idor pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?search=yes&bc=no&catalogid=47`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'idor' gf pattern — manual verification candidate

**Remediation:** Manually test for idor on the highlighted parameter


### [LOW] Candidate: sqli pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?search=yes&bc=no&catalogid=47`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'sqli' gf pattern — manual verification candidate

**Remediation:** Manually test for sqli on the highlighted parameter


### [LOW] Candidate: idor pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?search=yes&bc=no&catalogid=51`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'idor' gf pattern — manual verification candidate

**Remediation:** Manually test for idor on the highlighted parameter


### [LOW] Candidate: sqli pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?search=yes&bc=no&catalogid=51`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'sqli' gf pattern — manual verification candidate

**Remediation:** Manually test for sqli on the highlighted parameter


### [LOW] Candidate: idor pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?search=yes&bc=no&catalogid=62`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'idor' gf pattern — manual verification candidate

**Remediation:** Manually test for idor on the highlighted parameter


### [LOW] Candidate: idor pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?search=yes&bc=no&catalogid=69`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'idor' gf pattern — manual verification candidate

**Remediation:** Manually test for idor on the highlighted parameter


### [LOW] Candidate: idor pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopexd.asp?id=210`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'idor' gf pattern — manual verification candidate

**Remediation:** Manually test for idor on the highlighted parameter


### [LOW] Candidate: redirect pattern in URL
- **Asset:** `http://youfoodz.com:80/collections/all.oembed?page=2`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'redirect' gf pattern — manual verification candidate

**Remediation:** Manually test for redirect on the highlighted parameter


### [LOW] Candidate: ssrf pattern in URL
- **Asset:** `http://youfoodz.com:80/collections/all.oembed?page=2`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssrf' gf pattern — manual verification candidate

**Remediation:** Manually test for ssrf on the highlighted parameter


### [LOW] Candidate: redirect pattern in URL
- **Asset:** `http://youfoodz.com:80/collections/all/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'redirect' gf pattern — manual verification candidate

**Remediation:** Manually test for redirect on the highlighted parameter


### [LOW] Candidate: ssrf pattern in URL
- **Asset:** `http://youfoodz.com:80/collections/all/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssrf' gf pattern — manual verification candidate

**Remediation:** Manually test for ssrf on the highlighted parameter


### [LOW] Candidate: redirect pattern in URL
- **Asset:** `http://youfoodz.com:80/collections/all?page=2`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'redirect' gf pattern — manual verification candidate

**Remediation:** Manually test for redirect on the highlighted parameter


### [LOW] Candidate: ssrf pattern in URL
- **Asset:** `http://youfoodz.com:80/collections/all?page=2`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssrf' gf pattern — manual verification candidate

**Remediation:** Manually test for ssrf on the highlighted parameter


### [LOW] Candidate: redirect pattern in URL
- **Asset:** `http://youfoodz.com:80/collections/mains/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'redirect' gf pattern — manual verification candidate

**Remediation:** Manually test for redirect on the highlighted parameter


### [LOW] Candidate: ssrf pattern in URL
- **Asset:** `http://youfoodz.com:80/collections/mains/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssrf' gf pattern — manual verification candidate

**Remediation:** Manually test for ssrf on the highlighted parameter


### [LOW] Candidate: redirect pattern in URL
- **Asset:** `http://youfoodz.com:80/collections/naked-protein-powder/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'redirect' gf pattern — manual verification candidate

**Remediation:** Manually test for redirect on the highlighted parameter


### [LOW] Candidate: ssrf pattern in URL
- **Asset:** `http://youfoodz.com:80/collections/naked-protein-powder/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssrf' gf pattern — manual verification candidate

**Remediation:** Manually test for ssrf on the highlighted parameter


### [LOW] Candidate: redirect pattern in URL
- **Asset:** `http://youfoodz.com:80/collections/snacks/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'redirect' gf pattern — manual verification candidate

**Remediation:** Manually test for redirect on the highlighted parameter


### [LOW] Candidate: ssrf pattern in URL
- **Asset:** `http://youfoodz.com:80/collections/snacks/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssrf' gf pattern — manual verification candidate

**Remediation:** Manually test for ssrf on the highlighted parameter


### [LOW] Candidate: redirect pattern in URL
- **Asset:** `http://youfoodz.com:80/collections/youfoodz.com/collections/all?page=2`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'redirect' gf pattern — manual verification candidate

**Remediation:** Manually test for redirect on the highlighted parameter


### [LOW] Candidate: ssrf pattern in URL
- **Asset:** `http://youfoodz.com:80/collections/youfoodz.com/collections/all?page=2`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssrf' gf pattern — manual verification candidate

**Remediation:** Manually test for ssrf on the highlighted parameter


### [LOW] Candidate: img-traversal pattern in URL
- **Asset:** `https://www.youfoodz.com/_next/data/0.7953.0/whitelabel/login.json?r=%2Fsettings%2Fgifts-and-offers`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'img-traversal' gf pattern — manual verification candidate

**Remediation:** Manually test for img-traversal on the highlighted parameter


### [LOW] Candidate: redirect pattern in URL
- **Asset:** `https://www.youfoodz.com/about/FAQ?%22%27x=,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,&addBase=o8&ajax=o8&bookings=o8&bulk_edit=o8&categorie=o8&categoryID=o8&cni=o8&core=o8&dbk=o8&deact=o8&gpsflag3=o8&help=o8&information_item_access=o8&ipproto=o8&mail_joined_ltml=o8&methodpayload=o8&myname=o8&newPlaylistTitle=o8&newvalue=o8&noRedirect=o8&oracle=o8&postal_code=o8&profiler=o8&que=o8&receipt=o8&relation=o8&relay=o8&replaceWith=o8&res=o8&screen=o8&searchText=o8&sortColumn=o8&stay=o8&tdel_username=o8&templateid=o8&tnm=o8&usa=o8&useR=o8&userdata=o8&vbseo_redirect=o8&vouchers=o8&wy=o8&xlb=o8&xmldump=o8`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'redirect' gf pattern — manual verification candidate

**Remediation:** Manually test for redirect on the highlighted parameter


### [LOW] Candidate: ssrf pattern in URL
- **Asset:** `https://www.youfoodz.com/about/FAQ?%22%27x=,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,&addBase=o8&ajax=o8&bookings=o8&bulk_edit=o8&categorie=o8&categoryID=o8&cni=o8&core=o8&dbk=o8&deact=o8&gpsflag3=o8&help=o8&information_item_access=o8&ipproto=o8&mail_joined_ltml=o8&methodpayload=o8&myname=o8&newPlaylistTitle=o8&newvalue=o8&noRedirect=o8&oracle=o8&postal_code=o8&profiler=o8&que=o8&receipt=o8&relation=o8&relay=o8&replaceWith=o8&res=o8&screen=o8&searchText=o8&sortColumn=o8&stay=o8&tdel_username=o8&templateid=o8&tnm=o8&usa=o8&useR=o8&userdata=o8&vbseo_redirect=o8&vouchers=o8&wy=o8&xlb=o8&xmldump=o8`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'ssrf' gf pattern — manual verification candidate

**Remediation:** Manually test for ssrf on the highlighted parameter


### [LOW] Candidate: img-traversal pattern in URL
- **Asset:** `https://www.youfoodz.com/faq?categoryId=3kS9mMsDfr3XOAMS1jpGCy`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'img-traversal' gf pattern — manual verification candidate

**Remediation:** Manually test for img-traversal on the highlighted parameter


### [LOW] Candidate: img-traversal pattern in URL
- **Asset:** `https://www.youfoodz.com/faq?questionId=21LyXX5966YGU5VNkrYvO1?categoryId=3kS9mMsDfr3XOAMS1jpGCy`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'img-traversal' gf pattern — manual verification candidate

**Remediation:** Manually test for img-traversal on the highlighted parameter


### [LOW] Candidate: img-traversal pattern in URL
- **Asset:** `https://www.youfoodz.com/faq?questionId=2q1RjJ1e4yecLHDhykBQm4?categoryId=3kS9mMsDfr3XOAMS1jpGCy`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'img-traversal' gf pattern — manual verification candidate

**Remediation:** Manually test for img-traversal on the highlighted parameter


### [LOW] Candidate: img-traversal pattern in URL
- **Asset:** `https://www.youfoodz.com/faq?questionId=4f7OXJWhpEDSLwPdp8KXT2?categoryId=3kS9mMsDfr3XOAMS1jpGCy`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'img-traversal' gf pattern — manual verification candidate

**Remediation:** Manually test for img-traversal on the highlighted parameter


### [LOW] Candidate: img-traversal pattern in URL
- **Asset:** `https://www.youfoodz.com/faq?questionId=7tWVaCUUzGImm8LqUk39oa?categoryId=3kS9mMsDfr3XOAMS1jpGCy`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'img-traversal' gf pattern — manual verification candidate

**Remediation:** Manually test for img-traversal on the highlighted parameter


### [LOW] Candidate: img-traversal pattern in URL
- **Asset:** `https://www.youfoodz.com/login?r=%2Fsettings%2Fgifts-and-offers`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'img-traversal' gf pattern — manual verification candidate

**Remediation:** Manually test for img-traversal on the highlighted parameter


### [INFO] Robots txt
- **Asset:** `http://34.102.150.6/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at http://34.102.150.6/robots.txt (HTTP 200)


### [INFO] Robots txt
- **Asset:** `http://click.link.youfoodz.com/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at http://click.link.youfoodz.com/robots.txt (HTTP 200)


### [INFO] Robots txt
- **Asset:** `http://commsclick.youfoodz.com/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at http://commsclick.youfoodz.com/robots.txt (HTTP 200)


### [INFO] Robots txt
- **Asset:** `http://links.youfoodz.com:2086/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at http://links.youfoodz.com:2086/robots.txt (HTTP 200)


### [INFO] Robots txt
- **Asset:** `https://bob.youfoodz.com/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at https://bob.youfoodz.com/robots.txt (HTTP 200)


### [INFO] Robots txt
- **Asset:** `https://image.e.youfoodz.com/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at https://image.e.youfoodz.com/robots.txt (HTTP 200)


### [INFO] Google Workspace in use
- **Asset:** `youfoodz.com`
- **Category:** identity  ·  **Confidence:** firm  ·  **Detection:** identity

MX records point to Google Workspace


### [INFO] IPv6 attack surface present
- **Asset:** `youfoodz.com`
- **Category:** dns  ·  **Confidence:** firm  ·  **Detection:** netintel

62 IPv6 (AAAA) address(es) discovered across hosts

**Remediation:** Ensure IPv6 endpoints are covered by the same controls as IPv4


### [INFO] Reverse DNS reveals related host
- **Asset:** `108.156.152.123`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 108.156.152.123 resolves to server-108-156-152-123.atl58.r.cloudfront.net (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `108.156.152.50`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 108.156.152.50 resolves to server-108-156-152-50.atl58.r.cloudfront.net (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `108.156.152.52`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 108.156.152.52 resolves to server-108-156-152-52.atl58.r.cloudfront.net (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `108.156.152.58`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 108.156.152.58 resolves to server-108-156-152-58.atl58.r.cloudfront.net (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `13.111.18.25`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 13.111.18.25 resolves to pages.s10.exacttarget.com (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `13.111.18.27`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 13.111.18.27 resolves to ej27.mta.exacttarget.com (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `13.226.209.13`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 13.226.209.13 resolves to server-13-226-209-13.iad61.r.cloudfront.net (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `13.226.209.56`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 13.226.209.56 resolves to server-13-226-209-56.iad61.r.cloudfront.net (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `13.226.209.59`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 13.226.209.59 resolves to server-13-226-209-59.iad61.r.cloudfront.net (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `13.226.209.79`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 13.226.209.79 resolves to server-13-226-209-79.iad61.r.cloudfront.net (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `13.227.146.107`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 13.227.146.107 resolves to server-13-227-146-107.waw51.r.cloudfront.net (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `13.227.146.122`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 13.227.146.122 resolves to server-13-227-146-122.waw51.r.cloudfront.net (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `13.227.146.25`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 13.227.146.25 resolves to server-13-227-146-25.waw51.r.cloudfront.net (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `13.227.146.89`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 13.227.146.89 resolves to server-13-227-146-89.waw51.r.cloudfront.net (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `13.35.20.22`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 13.35.20.22 resolves to server-13-35-20-22.ccu50.r.cloudfront.net (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `13.35.20.48`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 13.35.20.48 resolves to server-13-35-20-48.ccu50.r.cloudfront.net (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `13.35.20.68`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 13.35.20.68 resolves to server-13-35-20-68.ccu50.r.cloudfront.net (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `13.35.20.83`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 13.35.20.83 resolves to server-13-35-20-83.ccu50.r.cloudfront.net (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `143.204.238.82`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 143.204.238.82 resolves to server-143-204-238-82.arn53.r.cloudfront.net (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `161.71.33.242`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 161.71.33.242 resolves to reply.s50.exacttarget.com (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `23.210.231.226`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 23.210.231.226 resolves to a23-210-231-226.deploy.static.akamaitechnologies.com (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `23.227.38.65`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 23.227.38.65 resolves to myshopify.com (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `34.102.150.6`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 34.102.150.6 resolves to 6.150.102.34.bc.googleusercontent.com (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `34.111.99.212`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 34.111.99.212 resolves to 212.99.111.34.bc.googleusercontent.com (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `34.242.102.67`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 34.242.102.67 resolves to ec2-34-242-102-67.eu-west-1.compute.amazonaws.com (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `52.209.242.51`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 52.209.242.51 resolves to ec2-52-209-242-51.eu-west-1.compute.amazonaws.com (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `54.200.143.224`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 54.200.143.224 resolves to ec2-54-200-143-224.us-west-2.compute.amazonaws.com (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `63.35.200.242`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 63.35.200.242 resolves to ec2-63-35-200-242.eu-west-1.compute.amazonaws.com (outside youfoodz.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `a.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `addondomain.add.ukd.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'addondomain.add.ukd.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `amaunet.autodandomain-7lererfig-lab.com-okta-olinkserver.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'amaunet.autodandomain-7lererfig-lab.com-okta-olinkserver.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `api.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'api.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `assets.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'assets.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `authy.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'authy.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `autodandomain-7lererfig-lab.com-okta-olinkserver.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'autodandomain-7lererfig-lab.com-okta-olinkserver.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `autodandomain-7lererfig-lab.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'autodandomain-7lererfig-lab.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `autodandomain-controllererfig-lab-setup.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'autodandomain-controllererfig-lab-setup.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `autodandomain-controllererfig-lab-speakup.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'autodandomain-controllererfig-lab-speakup.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `autodandomainlererfig.com.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'autodandomainlererfig.com.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `b.ns.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'b.ns.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `banners.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'banners.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `beta.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'beta.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `black.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'black.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `blog.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'blog.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `bob-staging-cdn.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'bob-staging-cdn.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 403)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `bob.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'bob.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `care.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'care.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `casper.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'casper.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `cfjump.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'cfjump.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `checkrelay.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'checkrelay.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `click.e.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'click.e.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `click.link.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'click.link.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `cloud.e.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'cloud.e.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `cloud.link.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'cloud.link.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `commsclick.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'commsclick.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `devel.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'devel.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `e.fresh.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'e.fresh.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `e.info.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'e.info.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `e.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'e.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `email.deals.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'email.deals.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `email.gh-mail.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'email.gh-mail.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `email.newsletter.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'email.newsletter.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `email.u.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'email.u.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `email.updates.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'email.updates.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `f.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'f.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `fd.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'fd.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `fiona.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'fiona.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `fornax.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'fornax.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `forum.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'forum.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `frases-citas.wtfisanaddondomain.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'frases-citas.wtfisanaddondomain.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `go.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'go.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `gov.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'gov.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `hhe.testwebautodandomain.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'hhe.testwebautodandomain.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `hpdmsala.wtfisanaddondomain.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'hpdmsala.wtfisanaddondomain.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Candidate: interestingEXT pattern in URL
- **Asset:** `http://www.youfoodz.com/js/jqzoom.pack.1.0.1.js`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingEXT' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingEXT on the highlighted parameter


### [INFO] Candidate: interestingEXT pattern in URL
- **Asset:** `http://www.youfoodz.com/robots.txt`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingEXT' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingEXT on the highlighted parameter


### [INFO] Candidate: interestingparams pattern in URL
- **Asset:** `http://www.youfoodz.com/shopreviewspro.asp?id=213`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingparams' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingparams on the highlighted parameter


### [INFO] Candidate: interestingparams pattern in URL
- **Asset:** `http://www.youfoodz.com/shoptellfriendpro.asp?id=213`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingparams' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingparams on the highlighted parameter


### [INFO] Candidate: interestingparams pattern in URL
- **Asset:** `http://www.youfoodz.com:80/?utm_source=february&utm_medium=content&utm_content=balicomp&utm_campaign=urbanlist`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingparams' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingparams on the highlighted parameter


### [INFO] Candidate: interestingparams pattern in URL
- **Asset:** `http://www.youfoodz.com:80/blogs/blog?page=2`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingparams' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingparams on the highlighted parameter


### [INFO] Candidate: interestingparams pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/all/products/balinese-chicken-cashew-noodles?utm_source=february&utm_medium=content&utm_content=balicomp&utm_campaign=urbanlist`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingparams' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingparams on the highlighted parameter


### [INFO] Candidate: interestingparams pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/all?page=1`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingparams' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingparams on the highlighted parameter


### [INFO] Candidate: interestingparams pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/all?utm_source=Facebook-ads&utm_medium=Alleygroup&utm_content=Prospecting`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingparams' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingparams on the highlighted parameter


### [INFO] Candidate: interestingparams pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/breakfast/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingparams' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingparams on the highlighted parameter


### [INFO] Candidate: interestingparams pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/drinks/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingparams' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingparams on the highlighted parameter


### [INFO] Candidate: interestingparams pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/relaxed-lunch-dinner/?view=list`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingparams' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingparams on the highlighted parameter


### [INFO] Candidate: interestingparams pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/www.youfoodz.com/collections/all?page=1`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingparams' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingparams on the highlighted parameter


### [INFO] Candidate: interestingparams pattern in URL
- **Asset:** `http://www.youfoodz.com:80/collections/www.youfoodz.com/collections/all?page=2`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingparams' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingparams on the highlighted parameter


### [INFO] Candidate: interestingparams pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?id=1&cat=Main+Meals`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingparams' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingparams on the highlighted parameter


### [INFO] Candidate: interestingparams pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?id=2&cat=Salads`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingparams' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingparams on the highlighted parameter


### [INFO] Candidate: interestingparams pattern in URL
- **Asset:** `http://www.youfoodz.com:80/shopdisplayproducts.asp?id=3&cat=Snacks+%26amp%3B+Deserts`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingparams' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingparams on the highlighted parameter


### [INFO] Candidate: interestingEXT pattern in URL
- **Asset:** `http://youfoodz.com/ads.txt`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingEXT' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingEXT on the highlighted parameter


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/add-bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/add-images/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/add-prod/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/add/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/alt1/`
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
- **Asset:** `https://storage.googleapis.com/api-images/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/api-logs/`
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


### [INFO] Candidate: interestingEXT pattern in URL
- **Asset:** `https://www.youfoodz.com/.well-known/ai-plugin.json`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingEXT' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingEXT on the highlighted parameter


### [INFO] Candidate: interestingEXT pattern in URL
- **Asset:** `https://www.youfoodz.com/.well-known/assetlinks.json`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingEXT' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingEXT on the highlighted parameter


### [INFO] Candidate: interestingEXT pattern in URL
- **Asset:** `https://www.youfoodz.com/.well-known/dnt-policy.txt`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingEXT' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingEXT on the highlighted parameter


### [INFO] Candidate: interestingEXT pattern in URL
- **Asset:** `https://www.youfoodz.com/.well-known/gpc.json`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingEXT' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingEXT on the highlighted parameter


### [INFO] Candidate: interestingEXT pattern in URL
- **Asset:** `https://www.youfoodz.com/_next/data/0.7953.0/whitelabel/login.json?r=%2Fmy-deliveries`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingEXT' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingEXT on the highlighted parameter


### [INFO] Candidate: interestingEXT pattern in URL
- **Asset:** `https://www.youfoodz.com/_next/data/0.7953.0/whitelabel/login.json?r=%2Fmy-deliveries%2F2022-W40%3Fcrmcid%3D434781%26locale%3Den-AU`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingEXT' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingEXT on the highlighted parameter


### [INFO] Candidate: interestingEXT pattern in URL
- **Asset:** `https://www.youfoodz.com/_next/data/0.7953.0/whitelabel/login.json?r=%2Fmy-deliveries%2F2022-W41`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingEXT' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingEXT on the highlighted parameter


### [INFO] Candidate: interestingEXT pattern in URL
- **Asset:** `https://www.youfoodz.com/_next/data/0.7953.0/whitelabel/login.json?r=%2Fmy-deliveries%2F2022-W42`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingEXT' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingEXT on the highlighted parameter


### [INFO] Candidate: interestingEXT pattern in URL
- **Asset:** `https://www.youfoodz.com/_next/data/0.7953.0/whitelabel/login.json?r=%2Fsettings%2Fgifts-and-offers`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingEXT' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingEXT on the highlighted parameter


### [INFO] Candidate: interestingEXT pattern in URL
- **Asset:** `https://www.youfoodz.com/_next/data/0.7953.0/whitelabel/login.json?r=%2Fsubscription-loading`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingEXT' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingEXT on the highlighted parameter


### [INFO] Candidate: interestingEXT pattern in URL
- **Asset:** `https://www.youfoodz.com/_next/data/0.7953.0/whitelabel/plans.json?r=%2Fcheckout%2Fdelivery`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingEXT' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingEXT on the highlighted parameter


### [INFO] Candidate: interestingEXT pattern in URL
- **Asset:** `https://www.youfoodz.com/_next/data/0.7953.0/whitelabel/plans.json?r=%2Fcheckout%3Fr%3D%252Fsignup%252FYE-CB-12-1-0`
- **Category:** vuln-indicator  ·  **Confidence:** tentative  ·  **Detection:** gfpatterns

URL matches the 'interestingEXT' gf pattern — manual verification candidate

**Remediation:** Manually test for interestingEXT on the highlighted parameter


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `hungry.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'hungry.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `image.e.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'image.e.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `image.link.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'image.link.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


### [INFO] Virtual host on 104.18.37.232
- **Asset:** `imap.youfoodz.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'imap.youfoodz.com' served distinct content on 104.18.37.232 (HTTP 301)


## Prioritized Recommendations

- [CRITICAL] Review and rotate any leaked secrets; request GitHub takedown if applicable
- [HIGH] Force password resets; investigate infected endpoints; enforce MFA
- [HIGH] Remove the file from the web root / restrict access
- [HIGH] Restrict the bucket ACL/policy
- [HIGH] Rotate/revoke the credential and remove it from client-served content
- [MEDIUM] Manually test for rce on the highlighted parameter
- [MEDIUM] Manually test for ssti on the highlighted parameter
- [MEDIUM] Publish an SPF record that ends in -all
- [MEDIUM] Publish/claim the scope, or pin an internal registry + scope config
- [MEDIUM] Verify the pointed-to service is claimed by you
- [LOW] Enable DNSSEC signing at the registrar/DNS provider
- [LOW] Manually test for idor on the highlighted parameter
- [LOW] Manually test for img-traversal on the highlighted parameter
- [LOW] Manually test for lfi on the highlighted parameter
- [LOW] Manually test for redirect on the highlighted parameter
- [LOW] Manually test for sqli on the highlighted parameter
- [LOW] Manually test for ssrf on the highlighted parameter
- [LOW] Manually test for xss on the highlighted parameter
- [LOW] Publish an MTA-STS policy and _mta-sts TXT record
- [INFO] Ensure IPv6 endpoints are covered by the same controls as IPv4
- [INFO] Manually test for interestingEXT on the highlighted parameter
- [INFO] Manually test for interestingparams on the highlighted parameter
- [INFO] Review whether the pointed-to host is in scope
