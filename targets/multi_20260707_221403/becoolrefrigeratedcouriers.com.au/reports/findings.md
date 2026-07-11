# Attack-Surface Findings — `becoolrefrigeratedcouriers.com.au` (domain)

_Generated 2026-07-08T01:16:54Z by TheN0thing v11.0_

## Executive Summary

**Risk score:** 100 / 100 (**critical**)  ·  **Total findings:** 192

| Severity | Count |
|----------|------:|
| critical | 2 |
| high | 7 |
| medium | 17 |
| low | 78 |
| info | 88 |

## Findings by Severity

### [CRITICAL] GitHub code mentions 'becoolrefrigeratedcouriers.com.au' near 'BEGIN RSA PRIVATE KEY' (5 hits)
- **Asset:** `github:becoolrefrigeratedcouriers.com.au`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [CRITICAL] GitHub code mentions 'becoolrefrigeratedcouriers.com.au' near 'aws access key id' (9 hits)
- **Asset:** `github:becoolrefrigeratedcouriers.com.au`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] DMARC record missing
- **Asset:** `becoolrefrigeratedcouriers.com.au`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

No DMARC policy; spoofed mail is neither quarantined nor rejected

_References:_ https://datatracker.ietf.org/doc/html/rfc7489

**Remediation:** Publish _dmarc.becoolrefrigeratedcouriers.com.au with p=quarantine or p=reject


### [HIGH] Infostealer-exposed credentials
- **Asset:** `becoolrefrigeratedcouriers.com.au`
- **Category:** breach  ·  **Confidence:** firm  ·  **Detection:** breach

HudsonRock reports credentials from info-stealer logs (employees: 0, users: 0, total: 2)

_References:_ https://www.hudsonrock.com/threat-intelligence-cybercrime-tools

**Remediation:** Force password resets; investigate infected endpoints; enforce MFA


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/autoconfig-bucket/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/com-bucket/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] Publicly readable cloud bucket (gcp)
- **Asset:** `https://storage.googleapis.com/ftp-data/`
- **Category:** cloud  ·  **Confidence:** firm  ·  **Detection:** normalize

Bucket is world-readable

**Remediation:** Restrict the bucket ACL/policy


### [HIGH] GitHub code mentions 'becoolrefrigeratedcouriers.com.au' near 'api key' (12 hits)
- **Asset:** `github:becoolrefrigeratedcouriers.com.au`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'becoolrefrigeratedcouriers.com.au' near 'secret' (7 hits)
- **Asset:** `github:becoolrefrigeratedcouriers.com.au`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [MEDIUM] GraphQL console
- **Asset:** `http://43.250.142.36:2083/graphql/console`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

GraphQL console at http://43.250.142.36:2083/graphql/console (HTTP 200)


### [MEDIUM] GraphQL console
- **Asset:** `http://43.250.142.36:2096/graphql/console`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

GraphQL console at http://43.250.142.36:2096/graphql/console (HTTP 200)


### [MEDIUM] GraphQL console
- **Asset:** `http://autoconfig.becoolrefrigeratedcouriers.com.au:2083/graphql/console`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

GraphQL console at http://autoconfig.becoolrefrigeratedcouriers.com.au:2083/graphql/console (HTTP 200)


### [MEDIUM] GraphQL console
- **Asset:** `http://autoconfig.becoolrefrigeratedcouriers.com.au:2096/graphql/console`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

GraphQL console at http://autoconfig.becoolrefrigeratedcouriers.com.au:2096/graphql/console (HTTP 200)


### [MEDIUM] GraphQL console
- **Asset:** `http://autodiscover.becoolrefrigeratedcouriers.com.au:2083/graphql/console`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

GraphQL console at http://autodiscover.becoolrefrigeratedcouriers.com.au:2083/graphql/console (HTTP 200)


### [MEDIUM] GraphQL console
- **Asset:** `http://autodiscover.becoolrefrigeratedcouriers.com.au:2096/graphql/console`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

GraphQL console at http://autodiscover.becoolrefrigeratedcouriers.com.au:2096/graphql/console (HTTP 200)


### [MEDIUM] GraphQL console
- **Asset:** `http://becoolrefrigeratedcouriers.com.au:2083/graphql/console`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

GraphQL console at http://becoolrefrigeratedcouriers.com.au:2083/graphql/console (HTTP 200)


### [MEDIUM] GraphQL console
- **Asset:** `http://becoolrefrigeratedcouriers.com.au:2096/graphql/console`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

GraphQL console at http://becoolrefrigeratedcouriers.com.au:2096/graphql/console (HTTP 200)


### [MEDIUM] GraphQL console
- **Asset:** `http://cpanel.becoolrefrigeratedcouriers.com.au:2083/graphql/console`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

GraphQL console at http://cpanel.becoolrefrigeratedcouriers.com.au:2083/graphql/console (HTTP 200)


### [MEDIUM] GraphQL console
- **Asset:** `http://cpanel.becoolrefrigeratedcouriers.com.au:2096/graphql/console`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

GraphQL console at http://cpanel.becoolrefrigeratedcouriers.com.au:2096/graphql/console (HTTP 200)


### [MEDIUM] GraphQL console
- **Asset:** `http://cpcalendars.becoolrefrigeratedcouriers.com.au:2083/graphql/console`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

GraphQL console at http://cpcalendars.becoolrefrigeratedcouriers.com.au:2083/graphql/console (HTTP 200)


### [MEDIUM] GraphQL console
- **Asset:** `http://ftp.becoolrefrigeratedcouriers.com.au:2096/graphql/console`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

GraphQL console at http://ftp.becoolrefrigeratedcouriers.com.au:2096/graphql/console (HTTP 200)


### [MEDIUM] GraphQL console
- **Asset:** `http://test.becoolrefrigeratedcouriers.com.au:2083/graphql/console`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

GraphQL console at http://test.becoolrefrigeratedcouriers.com.au:2083/graphql/console (HTTP 200)


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@becoolrefrigeratedcouriers/app`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@becoolrefrigeratedcouriers/app' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@becoolrefrigeratedcouriers/core`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@becoolrefrigeratedcouriers/core' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@becoolrefrigeratedcouriers/ui`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@becoolrefrigeratedcouriers/ui' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [MEDIUM] Unclaimed scoped npm package (dependency-confusion risk)
- **Asset:** `npm:@becoolrefrigeratedcouriers/utils`
- **Category:** supplychain  ·  **Confidence:** tentative  ·  **Detection:** pkgintel

Scoped package '@becoolrefrigeratedcouriers/utils' is referenced but not published to public npm — an attacker could publish it

_References:_ https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

**Remediation:** Publish/claim the scope, or pin an internal registry + scope config


### [LOW] Env example
- **Asset:** `http://43.250.142.36:2083/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at http://43.250.142.36:2083/.env.example (HTTP 200)


### [LOW] Admin panel
- **Asset:** `http://43.250.142.36:2083/admin`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin panel at http://43.250.142.36:2083/admin (HTTP 200)


### [LOW] Admin login
- **Asset:** `http://43.250.142.36:2083/admin/login`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin login at http://43.250.142.36:2083/admin/login (HTTP 200)


### [LOW] WADL present
- **Asset:** `http://43.250.142.36:2083/application.wadl`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

WADL present at http://43.250.142.36:2083/application.wadl (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `http://43.250.142.36:2083/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at http://43.250.142.36:2083/health (HTTP 200)


### [LOW] Env example
- **Asset:** `http://43.250.142.36:2096/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at http://43.250.142.36:2096/.env.example (HTTP 200)


### [LOW] Admin panel
- **Asset:** `http://43.250.142.36:2096/admin`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin panel at http://43.250.142.36:2096/admin (HTTP 200)


### [LOW] Admin login
- **Asset:** `http://43.250.142.36:2096/admin/login`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin login at http://43.250.142.36:2096/admin/login (HTTP 200)


### [LOW] Joomla admin
- **Asset:** `http://43.250.142.36:2096/administrator/`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Joomla admin at http://43.250.142.36:2096/administrator/ (HTTP 200)


### [LOW] WADL present
- **Asset:** `http://43.250.142.36:2096/application.wadl`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

WADL present at http://43.250.142.36:2096/application.wadl (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `http://43.250.142.36:2096/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at http://43.250.142.36:2096/health (HTTP 200)


### [LOW] Env example
- **Asset:** `http://autoconfig.becoolrefrigeratedcouriers.com.au/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at http://autoconfig.becoolrefrigeratedcouriers.com.au/.env.example (HTTP 200)


### [LOW] Admin panel
- **Asset:** `http://autoconfig.becoolrefrigeratedcouriers.com.au/admin`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin panel at http://autoconfig.becoolrefrigeratedcouriers.com.au/admin (HTTP 200)


### [LOW] Admin login
- **Asset:** `http://autoconfig.becoolrefrigeratedcouriers.com.au/admin/login`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin login at http://autoconfig.becoolrefrigeratedcouriers.com.au/admin/login (HTTP 200)


### [LOW] Admin panel
- **Asset:** `http://autoconfig.becoolrefrigeratedcouriers.com.au:2083/admin`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin panel at http://autoconfig.becoolrefrigeratedcouriers.com.au:2083/admin (HTTP 200)


### [LOW] Admin login
- **Asset:** `http://autoconfig.becoolrefrigeratedcouriers.com.au:2083/admin/login`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin login at http://autoconfig.becoolrefrigeratedcouriers.com.au:2083/admin/login (HTTP 200)


### [LOW] Joomla admin
- **Asset:** `http://autoconfig.becoolrefrigeratedcouriers.com.au:2083/administrator/`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Joomla admin at http://autoconfig.becoolrefrigeratedcouriers.com.au:2083/administrator/ (HTTP 200)


### [LOW] WADL present
- **Asset:** `http://autoconfig.becoolrefrigeratedcouriers.com.au:2083/application.wadl`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

WADL present at http://autoconfig.becoolrefrigeratedcouriers.com.au:2083/application.wadl (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `http://autoconfig.becoolrefrigeratedcouriers.com.au:2083/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at http://autoconfig.becoolrefrigeratedcouriers.com.au:2083/health (HTTP 200)


### [LOW] Admin panel
- **Asset:** `http://autoconfig.becoolrefrigeratedcouriers.com.au:2096/admin`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin panel at http://autoconfig.becoolrefrigeratedcouriers.com.au:2096/admin (HTTP 200)


### [LOW] Admin login
- **Asset:** `http://autoconfig.becoolrefrigeratedcouriers.com.au:2096/admin/login`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin login at http://autoconfig.becoolrefrigeratedcouriers.com.au:2096/admin/login (HTTP 200)


### [LOW] Joomla admin
- **Asset:** `http://autoconfig.becoolrefrigeratedcouriers.com.au:2096/administrator/`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Joomla admin at http://autoconfig.becoolrefrigeratedcouriers.com.au:2096/administrator/ (HTTP 200)


### [LOW] WADL present
- **Asset:** `http://autoconfig.becoolrefrigeratedcouriers.com.au:2096/application.wadl`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

WADL present at http://autoconfig.becoolrefrigeratedcouriers.com.au:2096/application.wadl (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `http://autoconfig.becoolrefrigeratedcouriers.com.au:2096/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at http://autoconfig.becoolrefrigeratedcouriers.com.au:2096/health (HTTP 200)


### [LOW] Env example
- **Asset:** `http://autodiscover.becoolrefrigeratedcouriers.com.au:2083/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at http://autodiscover.becoolrefrigeratedcouriers.com.au:2083/.env.example (HTTP 200)


### [LOW] Admin panel
- **Asset:** `http://autodiscover.becoolrefrigeratedcouriers.com.au:2083/admin`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin panel at http://autodiscover.becoolrefrigeratedcouriers.com.au:2083/admin (HTTP 200)


### [LOW] Admin login
- **Asset:** `http://autodiscover.becoolrefrigeratedcouriers.com.au:2083/admin/login`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin login at http://autodiscover.becoolrefrigeratedcouriers.com.au:2083/admin/login (HTTP 200)


### [LOW] Joomla admin
- **Asset:** `http://autodiscover.becoolrefrigeratedcouriers.com.au:2083/administrator/`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Joomla admin at http://autodiscover.becoolrefrigeratedcouriers.com.au:2083/administrator/ (HTTP 200)


### [LOW] WADL present
- **Asset:** `http://autodiscover.becoolrefrigeratedcouriers.com.au:2083/application.wadl`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

WADL present at http://autodiscover.becoolrefrigeratedcouriers.com.au:2083/application.wadl (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `http://autodiscover.becoolrefrigeratedcouriers.com.au:2083/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at http://autodiscover.becoolrefrigeratedcouriers.com.au:2083/health (HTTP 200)


### [LOW] Env example
- **Asset:** `http://autodiscover.becoolrefrigeratedcouriers.com.au:2096/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at http://autodiscover.becoolrefrigeratedcouriers.com.au:2096/.env.example (HTTP 200)


### [LOW] Admin panel
- **Asset:** `http://autodiscover.becoolrefrigeratedcouriers.com.au:2096/admin`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin panel at http://autodiscover.becoolrefrigeratedcouriers.com.au:2096/admin (HTTP 200)


### [LOW] Admin login
- **Asset:** `http://autodiscover.becoolrefrigeratedcouriers.com.au:2096/admin/login`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin login at http://autodiscover.becoolrefrigeratedcouriers.com.au:2096/admin/login (HTTP 200)


### [LOW] Joomla admin
- **Asset:** `http://autodiscover.becoolrefrigeratedcouriers.com.au:2096/administrator/`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Joomla admin at http://autodiscover.becoolrefrigeratedcouriers.com.au:2096/administrator/ (HTTP 200)


### [LOW] WADL present
- **Asset:** `http://autodiscover.becoolrefrigeratedcouriers.com.au:2096/application.wadl`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

WADL present at http://autodiscover.becoolrefrigeratedcouriers.com.au:2096/application.wadl (HTTP 200)


### [LOW] Admin panel
- **Asset:** `http://becoolrefrigeratedcouriers.com.au/admin`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin panel at http://becoolrefrigeratedcouriers.com.au/admin (HTTP 200)


### [LOW] WP admin
- **Asset:** `http://becoolrefrigeratedcouriers.com.au/wp-admin/`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

WP admin at http://becoolrefrigeratedcouriers.com.au/wp-admin/ (HTTP 200)


### [LOW] WP json
- **Asset:** `http://becoolrefrigeratedcouriers.com.au/wp-json/`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

WP json at http://becoolrefrigeratedcouriers.com.au/wp-json/ (HTTP 200)


### [LOW] Joomla admin
- **Asset:** `http://becoolrefrigeratedcouriers.com.au:2083/administrator/`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Joomla admin at http://becoolrefrigeratedcouriers.com.au:2083/administrator/ (HTTP 200)


### [LOW] WADL present
- **Asset:** `http://becoolrefrigeratedcouriers.com.au:2083/application.wadl`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

WADL present at http://becoolrefrigeratedcouriers.com.au:2083/application.wadl (HTTP 200)


### [LOW] Env example
- **Asset:** `http://becoolrefrigeratedcouriers.com.au:2096/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at http://becoolrefrigeratedcouriers.com.au:2096/.env.example (HTTP 200)


### [LOW] Admin login
- **Asset:** `http://becoolrefrigeratedcouriers.com.au:2096/admin/login`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin login at http://becoolrefrigeratedcouriers.com.au:2096/admin/login (HTTP 200)


### [LOW] Joomla admin
- **Asset:** `http://becoolrefrigeratedcouriers.com.au:2096/administrator/`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Joomla admin at http://becoolrefrigeratedcouriers.com.au:2096/administrator/ (HTTP 200)


### [LOW] WADL present
- **Asset:** `http://becoolrefrigeratedcouriers.com.au:2096/application.wadl`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

WADL present at http://becoolrefrigeratedcouriers.com.au:2096/application.wadl (HTTP 200)


### [LOW] Admin login
- **Asset:** `http://cpanel.becoolrefrigeratedcouriers.com.au:2083/admin/login`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin login at http://cpanel.becoolrefrigeratedcouriers.com.au:2083/admin/login (HTTP 200)


### [LOW] WADL present
- **Asset:** `http://cpanel.becoolrefrigeratedcouriers.com.au:2083/application.wadl`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

WADL present at http://cpanel.becoolrefrigeratedcouriers.com.au:2083/application.wadl (HTTP 200)


### [LOW] Env example
- **Asset:** `http://cpanel.becoolrefrigeratedcouriers.com.au:2096/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at http://cpanel.becoolrefrigeratedcouriers.com.au:2096/.env.example (HTTP 200)


### [LOW] Joomla admin
- **Asset:** `http://cpanel.becoolrefrigeratedcouriers.com.au:2096/administrator/`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Joomla admin at http://cpanel.becoolrefrigeratedcouriers.com.au:2096/administrator/ (HTTP 200)


### [LOW] WADL present
- **Asset:** `http://cpanel.becoolrefrigeratedcouriers.com.au:2096/application.wadl`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

WADL present at http://cpanel.becoolrefrigeratedcouriers.com.au:2096/application.wadl (HTTP 200)


### [LOW] WADL present
- **Asset:** `http://cpcalendars.becoolrefrigeratedcouriers.com.au:2083/application.wadl`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

WADL present at http://cpcalendars.becoolrefrigeratedcouriers.com.au:2083/application.wadl (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `http://cpcalendars.becoolrefrigeratedcouriers.com.au:2083/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at http://cpcalendars.becoolrefrigeratedcouriers.com.au:2083/health (HTTP 200)


### [LOW] Admin panel
- **Asset:** `http://cpcalendars.becoolrefrigeratedcouriers.com.au:2096/admin`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin panel at http://cpcalendars.becoolrefrigeratedcouriers.com.au:2096/admin (HTTP 200)


### [LOW] Admin login
- **Asset:** `http://cpcalendars.becoolrefrigeratedcouriers.com.au:2096/admin/login`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin login at http://cpcalendars.becoolrefrigeratedcouriers.com.au:2096/admin/login (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `http://cpcalendars.becoolrefrigeratedcouriers.com.au:2096/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at http://cpcalendars.becoolrefrigeratedcouriers.com.au:2096/health (HTTP 200)


### [LOW] Admin login
- **Asset:** `http://cpcontacts.becoolrefrigeratedcouriers.com.au:2083/admin/login`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin login at http://cpcontacts.becoolrefrigeratedcouriers.com.au:2083/admin/login (HTTP 200)


### [LOW] Env example
- **Asset:** `http://cpcontacts.becoolrefrigeratedcouriers.com.au:2096/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at http://cpcontacts.becoolrefrigeratedcouriers.com.au:2096/.env.example (HTTP 200)


### [LOW] Admin panel
- **Asset:** `http://cpcontacts.becoolrefrigeratedcouriers.com.au:2096/admin`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin panel at http://cpcontacts.becoolrefrigeratedcouriers.com.au:2096/admin (HTTP 200)


### [LOW] Joomla admin
- **Asset:** `http://cpcontacts.becoolrefrigeratedcouriers.com.au:2096/administrator/`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Joomla admin at http://cpcontacts.becoolrefrigeratedcouriers.com.au:2096/administrator/ (HTTP 200)


### [LOW] WADL present
- **Asset:** `http://cpcontacts.becoolrefrigeratedcouriers.com.au:2096/application.wadl`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

WADL present at http://cpcontacts.becoolrefrigeratedcouriers.com.au:2096/application.wadl (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `http://cpcontacts.becoolrefrigeratedcouriers.com.au:2096/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at http://cpcontacts.becoolrefrigeratedcouriers.com.au:2096/health (HTTP 200)


### [LOW] Env example
- **Asset:** `http://ftp.becoolrefrigeratedcouriers.com.au:2083/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at http://ftp.becoolrefrigeratedcouriers.com.au:2083/.env.example (HTTP 200)


### [LOW] Admin panel
- **Asset:** `http://ftp.becoolrefrigeratedcouriers.com.au:2083/admin`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin panel at http://ftp.becoolrefrigeratedcouriers.com.au:2083/admin (HTTP 200)


### [LOW] Joomla admin
- **Asset:** `http://ftp.becoolrefrigeratedcouriers.com.au:2083/administrator/`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Joomla admin at http://ftp.becoolrefrigeratedcouriers.com.au:2083/administrator/ (HTTP 200)


### [LOW] WADL present
- **Asset:** `http://ftp.becoolrefrigeratedcouriers.com.au:2083/application.wadl`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

WADL present at http://ftp.becoolrefrigeratedcouriers.com.au:2083/application.wadl (HTTP 200)


### [LOW] Env example
- **Asset:** `http://ftp.becoolrefrigeratedcouriers.com.au:2096/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at http://ftp.becoolrefrigeratedcouriers.com.au:2096/.env.example (HTTP 200)


### [LOW] WADL present
- **Asset:** `http://ftp.becoolrefrigeratedcouriers.com.au:2096/application.wadl`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

WADL present at http://ftp.becoolrefrigeratedcouriers.com.au:2096/application.wadl (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `http://ftp.becoolrefrigeratedcouriers.com.au:2096/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at http://ftp.becoolrefrigeratedcouriers.com.au:2096/health (HTTP 200)


### [LOW] WP json
- **Asset:** `http://staging.becoolrefrigeratedcouriers.com.au/wp-json/`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

WP json at http://staging.becoolrefrigeratedcouriers.com.au/wp-json/ (HTTP 200)


### [LOW] Admin panel
- **Asset:** `http://test.becoolrefrigeratedcouriers.com.au:2083/admin`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin panel at http://test.becoolrefrigeratedcouriers.com.au:2083/admin (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `http://test.becoolrefrigeratedcouriers.com.au:2083/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at http://test.becoolrefrigeratedcouriers.com.au:2083/health (HTTP 200)


### [LOW] Admin panel
- **Asset:** `https://autoconfig.becoolrefrigeratedcouriers.com.au/admin`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin panel at https://autoconfig.becoolrefrigeratedcouriers.com.au/admin (HTTP 200)


### [LOW] Admin login
- **Asset:** `https://autoconfig.becoolrefrigeratedcouriers.com.au/admin/login`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin login at https://autoconfig.becoolrefrigeratedcouriers.com.au/admin/login (HTTP 200)


### [LOW] WP admin
- **Asset:** `https://becoolrefrigeratedcouriers.com.au/wp-admin/`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

WP admin at https://becoolrefrigeratedcouriers.com.au/wp-admin/ (HTTP 200)


### [LOW] WP json
- **Asset:** `https://becoolrefrigeratedcouriers.com.au/wp-json/`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

WP json at https://becoolrefrigeratedcouriers.com.au/wp-json/ (HTTP 200)


### [LOW] DNSSEC not enabled
- **Asset:** `becoolrefrigeratedcouriers.com.au`
- **Category:** dns  ·  **Confidence:** firm  ·  **Detection:** emailsec

Zone is not DNSSEC-signed; DNS answers can be spoofed/tampered

_References:_ https://www.cloudflare.com/dns/dnssec/

**Remediation:** Enable DNSSEC signing at the registrar/DNS provider


### [LOW] MTA-STS not deployed
- **Asset:** `becoolrefrigeratedcouriers.com.au`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

No MTA-STS policy; inbound-mail TLS can be stripped (downgrade)

_References:_ https://datatracker.ietf.org/doc/html/rfc8461

**Remediation:** Publish an MTA-STS policy and _mta-sts TXT record


### [LOW] SPF not hard-fail
- **Asset:** `becoolrefrigeratedcouriers.com.au`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

SPF ends in ~all/?all rather than -all; spoofed mail may still pass

**Remediation:** Use -all once senders are enumerated


### [LOW] No DKIM selector found
- **Asset:** `becoolrefrigeratedcouriers.com.au`
- **Category:** email  ·  **Confidence:** tentative  ·  **Detection:** emailsec

No DKIM key found at common selectors; outbound mail may be unsigned

**Remediation:** Publish a DKIM key and sign outbound mail


### [INFO] API root hint
- **Asset:** `http://43.250.142.36:2083/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at http://43.250.142.36:2083/api (HTTP 200)


### [INFO] API v1 root
- **Asset:** `http://43.250.142.36:2083/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at http://43.250.142.36:2083/api/v1 (HTTP 200)


### [INFO] API v2 root
- **Asset:** `http://43.250.142.36:2083/api/v2`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v2 root at http://43.250.142.36:2083/api/v2 (HTTP 200)


### [INFO] API root hint
- **Asset:** `http://43.250.142.36:2096/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at http://43.250.142.36:2096/api (HTTP 200)


### [INFO] API v1 root
- **Asset:** `http://43.250.142.36:2096/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at http://43.250.142.36:2096/api/v1 (HTTP 200)


### [INFO] API v2 root
- **Asset:** `http://43.250.142.36:2096/api/v2`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v2 root at http://43.250.142.36:2096/api/v2 (HTTP 200)


### [INFO] API root hint
- **Asset:** `http://autoconfig.becoolrefrigeratedcouriers.com.au:2083/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at http://autoconfig.becoolrefrigeratedcouriers.com.au:2083/api (HTTP 200)


### [INFO] API v1 root
- **Asset:** `http://autoconfig.becoolrefrigeratedcouriers.com.au:2083/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at http://autoconfig.becoolrefrigeratedcouriers.com.au:2083/api/v1 (HTTP 200)


### [INFO] API v2 root
- **Asset:** `http://autoconfig.becoolrefrigeratedcouriers.com.au:2083/api/v2`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v2 root at http://autoconfig.becoolrefrigeratedcouriers.com.au:2083/api/v2 (HTTP 200)


### [INFO] API root hint
- **Asset:** `http://autoconfig.becoolrefrigeratedcouriers.com.au:2096/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at http://autoconfig.becoolrefrigeratedcouriers.com.au:2096/api (HTTP 200)


### [INFO] API v1 root
- **Asset:** `http://autoconfig.becoolrefrigeratedcouriers.com.au:2096/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at http://autoconfig.becoolrefrigeratedcouriers.com.au:2096/api/v1 (HTTP 200)


### [INFO] API v2 root
- **Asset:** `http://autoconfig.becoolrefrigeratedcouriers.com.au:2096/api/v2`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v2 root at http://autoconfig.becoolrefrigeratedcouriers.com.au:2096/api/v2 (HTTP 200)


### [INFO] API root hint
- **Asset:** `http://autodiscover.becoolrefrigeratedcouriers.com.au:2083/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at http://autodiscover.becoolrefrigeratedcouriers.com.au:2083/api (HTTP 200)


### [INFO] API v1 root
- **Asset:** `http://autodiscover.becoolrefrigeratedcouriers.com.au:2083/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at http://autodiscover.becoolrefrigeratedcouriers.com.au:2083/api/v1 (HTTP 200)


### [INFO] API v2 root
- **Asset:** `http://autodiscover.becoolrefrigeratedcouriers.com.au:2083/api/v2`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v2 root at http://autodiscover.becoolrefrigeratedcouriers.com.au:2083/api/v2 (HTTP 200)


### [INFO] API root hint
- **Asset:** `http://autodiscover.becoolrefrigeratedcouriers.com.au:2096/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at http://autodiscover.becoolrefrigeratedcouriers.com.au:2096/api (HTTP 200)


### [INFO] API v1 root
- **Asset:** `http://autodiscover.becoolrefrigeratedcouriers.com.au:2096/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at http://autodiscover.becoolrefrigeratedcouriers.com.au:2096/api/v1 (HTTP 200)


### [INFO] API v2 root
- **Asset:** `http://autodiscover.becoolrefrigeratedcouriers.com.au:2096/api/v2`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v2 root at http://autodiscover.becoolrefrigeratedcouriers.com.au:2096/api/v2 (HTTP 200)


### [INFO] API root hint
- **Asset:** `http://becoolrefrigeratedcouriers.com.au:2083/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at http://becoolrefrigeratedcouriers.com.au:2083/api (HTTP 200)


### [INFO] API root hint
- **Asset:** `http://becoolrefrigeratedcouriers.com.au:2096/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at http://becoolrefrigeratedcouriers.com.au:2096/api (HTTP 200)


### [INFO] API v1 root
- **Asset:** `http://becoolrefrigeratedcouriers.com.au:2096/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at http://becoolrefrigeratedcouriers.com.au:2096/api/v1 (HTTP 200)


### [INFO] API v2 root
- **Asset:** `http://becoolrefrigeratedcouriers.com.au:2096/api/v2`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v2 root at http://becoolrefrigeratedcouriers.com.au:2096/api/v2 (HTTP 200)


### [INFO] API root hint
- **Asset:** `http://cpcalendars.becoolrefrigeratedcouriers.com.au:2083/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at http://cpcalendars.becoolrefrigeratedcouriers.com.au:2083/api (HTTP 200)


### [INFO] API v1 root
- **Asset:** `http://cpcalendars.becoolrefrigeratedcouriers.com.au:2083/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at http://cpcalendars.becoolrefrigeratedcouriers.com.au:2083/api/v1 (HTTP 200)


### [INFO] API v2 root
- **Asset:** `http://cpcalendars.becoolrefrigeratedcouriers.com.au:2083/api/v2`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v2 root at http://cpcalendars.becoolrefrigeratedcouriers.com.au:2083/api/v2 (HTTP 200)


### [INFO] API root hint
- **Asset:** `http://cpcalendars.becoolrefrigeratedcouriers.com.au:2096/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at http://cpcalendars.becoolrefrigeratedcouriers.com.au:2096/api (HTTP 200)


### [INFO] API v1 root
- **Asset:** `http://cpcontacts.becoolrefrigeratedcouriers.com.au:2083/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at http://cpcontacts.becoolrefrigeratedcouriers.com.au:2083/api/v1 (HTTP 200)


### [INFO] API v2 root
- **Asset:** `http://cpcontacts.becoolrefrigeratedcouriers.com.au:2083/api/v2`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v2 root at http://cpcontacts.becoolrefrigeratedcouriers.com.au:2083/api/v2 (HTTP 200)


### [INFO] API v2 root
- **Asset:** `http://cpcontacts.becoolrefrigeratedcouriers.com.au:2096/api/v2`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v2 root at http://cpcontacts.becoolrefrigeratedcouriers.com.au:2096/api/v2 (HTTP 200)


### [INFO] API root hint
- **Asset:** `http://ftp.becoolrefrigeratedcouriers.com.au:2083/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at http://ftp.becoolrefrigeratedcouriers.com.au:2083/api (HTTP 200)


### [INFO] API v1 root
- **Asset:** `http://ftp.becoolrefrigeratedcouriers.com.au:2083/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at http://ftp.becoolrefrigeratedcouriers.com.au:2083/api/v1 (HTTP 200)


### [INFO] API root hint
- **Asset:** `http://ftp.becoolrefrigeratedcouriers.com.au:2096/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at http://ftp.becoolrefrigeratedcouriers.com.au:2096/api (HTTP 200)


### [INFO] API v1 root
- **Asset:** `http://ftp.becoolrefrigeratedcouriers.com.au:2096/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at http://ftp.becoolrefrigeratedcouriers.com.au:2096/api/v1 (HTTP 200)


### [INFO] API v2 root
- **Asset:** `http://ftp.becoolrefrigeratedcouriers.com.au:2096/api/v2`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v2 root at http://ftp.becoolrefrigeratedcouriers.com.au:2096/api/v2 (HTTP 200)


### [INFO] Sitemap xml
- **Asset:** `http://staging.becoolrefrigeratedcouriers.com.au/sitemap.xml`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Sitemap xml at http://staging.becoolrefrigeratedcouriers.com.au/sitemap.xml (HTTP 200)


### [INFO] API root hint
- **Asset:** `http://test.becoolrefrigeratedcouriers.com.au:2083/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at http://test.becoolrefrigeratedcouriers.com.au:2083/api (HTTP 200)


### [INFO] API v1 root
- **Asset:** `http://test.becoolrefrigeratedcouriers.com.au:2083/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at http://test.becoolrefrigeratedcouriers.com.au:2083/api/v1 (HTTP 200)


### [INFO] API v2 root
- **Asset:** `http://test.becoolrefrigeratedcouriers.com.au:2083/api/v2`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v2 root at http://test.becoolrefrigeratedcouriers.com.au:2083/api/v2 (HTTP 200)


### [INFO] Sitemap xml
- **Asset:** `https://becoolrefrigeratedcouriers.com.au/sitemap.xml`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Sitemap xml at https://becoolrefrigeratedcouriers.com.au/sitemap.xml (HTTP 200)


### [INFO] IPv6 attack surface present
- **Asset:** `becoolrefrigeratedcouriers.com.au`
- **Category:** dns  ·  **Confidence:** firm  ·  **Detection:** netintel

13 IPv6 (AAAA) address(es) discovered across hosts

**Remediation:** Ensure IPv6 endpoints are covered by the same controls as IPv4


### [INFO] Virtual host on 43.250.142.36
- **Asset:** `autoconfig.becoolrefrigeratedcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'autoconfig.becoolrefrigeratedcouriers.com.au' served distinct content on 43.250.142.36 (HTTP 200)


### [INFO] Virtual host on 43.250.142.36
- **Asset:** `autodiscover.becoolrefrigeratedcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'autodiscover.becoolrefrigeratedcouriers.com.au' served distinct content on 43.250.142.36 (HTTP 302)


### [INFO] Virtual host on 43.250.142.36
- **Asset:** `becoolrefrigeratedcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'becoolrefrigeratedcouriers.com.au' served distinct content on 43.250.142.36 (HTTP 301)


### [INFO] Virtual host on 43.250.142.36
- **Asset:** `cpanel.becoolrefrigeratedcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'cpanel.becoolrefrigeratedcouriers.com.au' served distinct content on 43.250.142.36 (HTTP 301)


### [INFO] Virtual host on 43.250.142.36
- **Asset:** `cpcalendars.becoolrefrigeratedcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'cpcalendars.becoolrefrigeratedcouriers.com.au' served distinct content on 43.250.142.36 (HTTP 302)


### [INFO] Virtual host on 43.250.142.36
- **Asset:** `cpcontacts.becoolrefrigeratedcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'cpcontacts.becoolrefrigeratedcouriers.com.au' served distinct content on 43.250.142.36 (HTTP 302)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/com-archive/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/com-backups/`
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
- **Asset:** `https://s3.amazonaws.com/com.backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/com/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/cpanel-backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ftp-archive/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ftp-assets/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ftp-dev/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ftp-files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ftp-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ftp-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ftp.backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ftp.backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ftp/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ipv6-bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/ipv6-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/autoconfig/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/com-assets/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/com-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/cpanel/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/ftp-archive/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/ftp-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/ftp-images/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/ftp-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/ftp-staging/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/ftp-storage/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/ftp-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/ftp-uploads/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/ipv6/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Virtual host on 43.250.142.36
- **Asset:** `ipv6.becoolrefrigeratedcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'ipv6.becoolrefrigeratedcouriers.com.au' served distinct content on 43.250.142.36 (HTTP 301)


### [INFO] Virtual host on 43.250.142.36
- **Asset:** `mail.becoolrefrigeratedcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'mail.becoolrefrigeratedcouriers.com.au' served distinct content on 43.250.142.36 (HTTP 301)


### [INFO] Virtual host on 43.250.142.36
- **Asset:** `new.becoolrefrigeratedcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'new.becoolrefrigeratedcouriers.com.au' served distinct content on 43.250.142.36 (HTTP 200)


### [INFO] Virtual host on 43.250.142.36
- **Asset:** `staging.becoolrefrigeratedcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'staging.becoolrefrigeratedcouriers.com.au' served distinct content on 43.250.142.36 (HTTP 301)


### [INFO] Virtual host on 43.250.142.36
- **Asset:** `test.becoolrefrigeratedcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'test.becoolrefrigeratedcouriers.com.au' served distinct content on 43.250.142.36 (HTTP 200)


### [INFO] Virtual host on 43.250.142.36
- **Asset:** `webdisk.becoolrefrigeratedcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'webdisk.becoolrefrigeratedcouriers.com.au' served distinct content on 43.250.142.36 (HTTP 302)


### [INFO] Virtual host on 43.250.142.36
- **Asset:** `webmail.becoolrefrigeratedcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'webmail.becoolrefrigeratedcouriers.com.au' served distinct content on 43.250.142.36 (HTTP 301)


### [INFO] Virtual host on 43.250.142.36
- **Asset:** `www.becoolrefrigeratedcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'www.becoolrefrigeratedcouriers.com.au' served distinct content on 43.250.142.36 (HTTP 301)


### [INFO] Virtual host on 43.250.142.36
- **Asset:** `www.new.becoolrefrigeratedcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'www.new.becoolrefrigeratedcouriers.com.au' served distinct content on 43.250.142.36 (HTTP 200)


### [INFO] Virtual host on 43.250.142.36
- **Asset:** `www.staging.becoolrefrigeratedcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'www.staging.becoolrefrigeratedcouriers.com.au' served distinct content on 43.250.142.36 (HTTP 301)


### [INFO] Virtual host on 43.250.142.36
- **Asset:** `www.test.becoolrefrigeratedcouriers.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'www.test.becoolrefrigeratedcouriers.com.au' served distinct content on 43.250.142.36 (HTTP 200)


## Prioritized Recommendations

- [CRITICAL] Review and rotate any leaked secrets; request GitHub takedown if applicable
- [HIGH] Force password resets; investigate infected endpoints; enforce MFA
- [HIGH] Publish _dmarc.becoolrefrigeratedcouriers.com.au with p=quarantine or p=reject
- [HIGH] Restrict the bucket ACL/policy
- [MEDIUM] Publish/claim the scope, or pin an internal registry + scope config
- [LOW] Enable DNSSEC signing at the registrar/DNS provider
- [LOW] Publish a DKIM key and sign outbound mail
- [LOW] Publish an MTA-STS policy and _mta-sts TXT record
- [LOW] Use -all once senders are enumerated
- [INFO] Ensure IPv6 endpoints are covered by the same controls as IPv4
