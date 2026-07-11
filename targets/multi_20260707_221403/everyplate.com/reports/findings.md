# Attack-Surface Findings — `everyplate.com` (domain)

_Generated 2026-07-08T02:54:20Z by TheN0thing v11.0_

## Executive Summary

**Risk score:** 100 / 100 (**critical**)  ·  **Total findings:** 238

| Severity | Count |
|----------|------:|
| critical | 2 |
| high | 43 |
| medium | 31 |
| low | 30 |
| info | 132 |

## Findings by Severity

### [CRITICAL] GitHub code mentions 'everyplate.com' near 'BEGIN RSA PRIVATE KEY' (80 hits)
- **Asset:** `github:everyplate.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [CRITICAL] GitHub code mentions 'everyplate.com' near 'aws access key id' (381 hits)
- **Asset:** `github:everyplate.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] Elasticsearch cat
- **Asset:** `http://get.everyplate.com:2086/_cat/indices`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Elasticsearch cat at http://get.everyplate.com:2086/_cat/indices (HTTP 200)


### [HIGH] Actuator configprops
- **Asset:** `http://get.everyplate.com:2086/actuator/configprops`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Actuator configprops at http://get.everyplate.com:2086/actuator/configprops (HTTP 200)


### [HIGH] Kubernetes apis
- **Asset:** `http://get.everyplate.com:2086/apis`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Kubernetes apis at http://get.everyplate.com:2086/apis (HTTP 200)


### [HIGH] Backup zip exposed
- **Asset:** `http://get.everyplate.com:2086/backup.zip`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Backup zip exposed at http://get.everyplate.com:2086/backup.zip (HTTP 200)


### [HIGH] Docker API images
- **Asset:** `http://get.everyplate.com:2086/images/json`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker API images at http://get.everyplate.com:2086/images/json (HTTP 200)


### [HIGH] OpenAPI json
- **Asset:** `http://get.everyplate.com:2086/openapi.json`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

OpenAPI json at http://get.everyplate.com:2086/openapi.json (HTTP 200)


### [HIGH] Consul ui
- **Asset:** `http://get.everyplate.com:2086/v1/catalog/services`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Consul ui at http://get.everyplate.com:2086/v1/catalog/services (HTTP 200)


### [HIGH] Docker registry root
- **Asset:** `http://get.everyplate.com:2086/v2/`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker registry root at http://get.everyplate.com:2086/v2/ (HTTP 200)


### [HIGH] OpenAPI v2 spec
- **Asset:** `http://get.everyplate.com:2086/v2/api-docs`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

OpenAPI v2 spec at http://get.everyplate.com:2086/v2/api-docs (HTTP 200)


### [HIGH] OpenAPI v3 spec
- **Asset:** `http://get.everyplate.com:2086/v3/api-docs`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

OpenAPI v3 spec at http://get.everyplate.com:2086/v3/api-docs (HTTP 200)


### [HIGH] Kubernetes API
- **Asset:** `http://get.everyplate.com:2086/version`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Kubernetes API at http://get.everyplate.com:2086/version (HTTP 200)


### [HIGH] Elasticsearch cat
- **Asset:** `http://lp.everyplate.com:2082/_cat/indices`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Elasticsearch cat at http://lp.everyplate.com:2082/_cat/indices (HTTP 200)


### [HIGH] Actuator configprops
- **Asset:** `http://lp.everyplate.com:2082/actuator/configprops`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Actuator configprops at http://lp.everyplate.com:2082/actuator/configprops (HTTP 200)


### [HIGH] Elasticsearch cat
- **Asset:** `https://lp.everyplate.com:2083/_cat/indices`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Elasticsearch cat at https://lp.everyplate.com:2083/_cat/indices (HTTP 200)


### [HIGH] Actuator configprops
- **Asset:** `https://lp.everyplate.com:2083/actuator/configprops`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Actuator configprops at https://lp.everyplate.com:2083/actuator/configprops (HTTP 200)


### [HIGH] OpenAPI json api
- **Asset:** `https://lp.everyplate.com:2083/api/openapi.json`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

OpenAPI json api at https://lp.everyplate.com:2083/api/openapi.json (HTTP 200)


### [HIGH] Kibana status
- **Asset:** `https://lp.everyplate.com:2083/api/status`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Kibana status at https://lp.everyplate.com:2083/api/status (HTTP 200)


### [HIGH] Kubernetes apis
- **Asset:** `https://lp.everyplate.com:2083/apis`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Kubernetes apis at https://lp.everyplate.com:2083/apis (HTTP 200)


### [HIGH] Backup zip exposed
- **Asset:** `https://lp.everyplate.com:2083/backup.zip`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Backup zip exposed at https://lp.everyplate.com:2083/backup.zip (HTTP 200)


### [HIGH] Docker API images
- **Asset:** `https://lp.everyplate.com:2083/images/json`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker API images at https://lp.everyplate.com:2083/images/json (HTTP 200)


### [HIGH] OpenAPI json
- **Asset:** `https://lp.everyplate.com:2083/openapi.json`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

OpenAPI json at https://lp.everyplate.com:2083/openapi.json (HTTP 200)


### [HIGH] Consul ui
- **Asset:** `https://lp.everyplate.com:2083/v1/catalog/services`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Consul ui at https://lp.everyplate.com:2083/v1/catalog/services (HTTP 200)


### [HIGH] Docker registry root
- **Asset:** `https://lp.everyplate.com:2083/v2/`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker registry root at https://lp.everyplate.com:2083/v2/ (HTTP 200)


### [HIGH] OpenAPI v2 spec
- **Asset:** `https://lp.everyplate.com:2083/v2/api-docs`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

OpenAPI v2 spec at https://lp.everyplate.com:2083/v2/api-docs (HTTP 200)


### [HIGH] OpenAPI v3 spec
- **Asset:** `https://lp.everyplate.com:2083/v3/api-docs`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

OpenAPI v3 spec at https://lp.everyplate.com:2083/v3/api-docs (HTTP 200)


### [HIGH] Kubernetes API
- **Asset:** `https://lp.everyplate.com:2083/version`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Kubernetes API at https://lp.everyplate.com:2083/version (HTTP 200)


### [HIGH] Kubernetes apis
- **Asset:** `https://mail05.recalls.everyplate.com:8888/apis`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Kubernetes apis at https://mail05.recalls.everyplate.com:8888/apis (HTTP 401)


### [HIGH] Docker registry root
- **Asset:** `https://mail05.recalls.everyplate.com:8888/v2/`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker registry root at https://mail05.recalls.everyplate.com:8888/v2/ (HTTP 401)


### [HIGH] Infostealer-exposed credentials
- **Asset:** `everyplate.com`
- **Category:** breach  ·  **Confidence:** firm  ·  **Detection:** breach

HudsonRock reports credentials from info-stealer logs (employees: 0, users: 3080, total: 3080)

_References:_ https://www.hudsonrock.com/threat-intelligence-cybercrime-tools

**Remediation:** Force password resets; investigate infected endpoints; enforce MFA


### [HIGH] Google API Key exposed
- **Asset:** `http://everyplate.com`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://everyplate.com

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://links.everyplate.com`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://links.everyplate.com

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `http://links.everyplate.com:2095`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://links.everyplate.com:2095

**Remediation:** Rotate/revoke the credential and remove it from client-served content


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


### [HIGH] GitHub code mentions 'everyplate.com' near '.env' (206 hits)
- **Asset:** `github:everyplate.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'everyplate.com' near 'api key' (477 hits)
- **Asset:** `github:everyplate.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'everyplate.com' near 'mysql password' (7 hits)
- **Asset:** `github:everyplate.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'everyplate.com' near 'password' (217 hits)
- **Asset:** `github:everyplate.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'everyplate.com' near 'secret' (297 hits)
- **Asset:** `github:everyplate.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [MEDIUM] Legacy TLSv1.0 supported
- **Asset:** `cdn-live.everyplate.com:443`
- **Category:** tls  ·  **Confidence:** confirmed  ·  **Detection:** tls

Server negotiates deprecated TLSv1.0

_References:_ https://datatracker.ietf.org/doc/html/rfc8996

**Remediation:** Disable TLS 1.0 and TLS 1.1


### [MEDIUM] Legacy TLSv1.1 supported
- **Asset:** `cdn-live.everyplate.com:443`
- **Category:** tls  ·  **Confidence:** confirmed  ·  **Detection:** tls

Server negotiates deprecated TLSv1.1

_References:_ https://datatracker.ietf.org/doc/html/rfc8996

**Remediation:** Disable TLS 1.0 and TLS 1.1


### [MEDIUM] Legacy TLSv1.0 supported
- **Asset:** `cdn.everyplate.com:443`
- **Category:** tls  ·  **Confidence:** confirmed  ·  **Detection:** tls

Server negotiates deprecated TLSv1.0

_References:_ https://datatracker.ietf.org/doc/html/rfc8996

**Remediation:** Disable TLS 1.0 and TLS 1.1


### [MEDIUM] Legacy TLSv1.1 supported
- **Asset:** `cdn.everyplate.com:443`
- **Category:** tls  ·  **Confidence:** confirmed  ·  **Detection:** tls

Server negotiates deprecated TLSv1.1

_References:_ https://datatracker.ietf.org/doc/html/rfc8996

**Remediation:** Disable TLS 1.0 and TLS 1.1


### [MEDIUM] ArgoCD api
- **Asset:** `http://get.everyplate.com:2086/api/v1/applications`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

ArgoCD api at http://get.everyplate.com:2086/api/v1/applications (HTTP 200)


### [MEDIUM] Open backup dir
- **Asset:** `http://get.everyplate.com:2086/backup`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Open backup dir at http://get.everyplate.com:2086/backup (HTTP 200)


### [MEDIUM] Citrix logon
- **Asset:** `http://get.everyplate.com:2086/citrix/`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Citrix logon at http://get.everyplate.com:2086/citrix/ (HTTP 200)


### [MEDIUM] Exchange ECP
- **Asset:** `http://get.everyplate.com:2086/ecp/`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Exchange ECP at http://get.everyplate.com:2086/ecp/ (HTTP 200)


### [MEDIUM] Exchange OWA
- **Asset:** `http://get.everyplate.com:2086/owa/`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Exchange OWA at http://get.everyplate.com:2086/owa/ (HTTP 200)


### [MEDIUM] VMware Horizon
- **Asset:** `http://get.everyplate.com:2086/portal/webclient/`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

VMware Horizon at http://get.everyplate.com:2086/portal/webclient/ (HTTP 200)


### [MEDIUM] SonarQube status
- **Asset:** `http://lp.everyplate.com:2082/api/system/status`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

SonarQube status at http://lp.everyplate.com:2082/api/system/status (HTTP 200)


### [MEDIUM] ArgoCD api
- **Asset:** `http://lp.everyplate.com:2082/api/v1/applications`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

ArgoCD api at http://lp.everyplate.com:2082/api/v1/applications (HTTP 200)


### [MEDIUM] GraphQL present
- **Asset:** `http://lp.everyplate.com:2082/graphql`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

GraphQL present at http://lp.everyplate.com:2082/graphql (HTTP 200)


### [MEDIUM] GraphQL api
- **Asset:** `https://lp.everyplate.com:2083/api/graphql`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

GraphQL api at https://lp.everyplate.com:2083/api/graphql (HTTP 200)


### [MEDIUM] SonarQube status
- **Asset:** `https://lp.everyplate.com:2083/api/system/status`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

SonarQube status at https://lp.everyplate.com:2083/api/system/status (HTTP 200)


### [MEDIUM] ArgoCD api
- **Asset:** `https://lp.everyplate.com:2083/api/v1/applications`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

ArgoCD api at https://lp.everyplate.com:2083/api/v1/applications (HTTP 200)


### [MEDIUM] Citrix logon
- **Asset:** `https://lp.everyplate.com:2083/citrix/`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Citrix logon at https://lp.everyplate.com:2083/citrix/ (HTTP 200)


### [MEDIUM] GraphQL endpoint
- **Asset:** `https://lp.everyplate.com:2083/graphql`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

GraphQL endpoint at https://lp.everyplate.com:2083/graphql (HTTP 200)


### [MEDIUM] GraphQL present
- **Asset:** `https://lp.everyplate.com:2083/graphql`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

GraphQL present at https://lp.everyplate.com:2083/graphql (HTTP 200)


### [MEDIUM] GraphQL console
- **Asset:** `https://lp.everyplate.com:2083/graphql/console`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

GraphQL console at https://lp.everyplate.com:2083/graphql/console (HTTP 200)


### [MEDIUM] VMware Horizon
- **Asset:** `https://lp.everyplate.com:2083/portal/webclient/`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

VMware Horizon at https://lp.everyplate.com:2083/portal/webclient/ (HTTP 200)


### [MEDIUM] GraphQL v1
- **Asset:** `https://lp.everyplate.com:2083/v1/graphql`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

GraphQL v1 at https://lp.everyplate.com:2083/v1/graphql (HTTP 200)


### [MEDIUM] SPF record missing
- **Asset:** `everyplate.com`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

No SPF record published; sender spoofing is easier

_References:_ https://datatracker.ietf.org/doc/html/rfc7208

**Remediation:** Publish an SPF record that ends in -all


### [MEDIUM] Internal hostname/IP leaked in JavaScript
- **Asset:** `http:///g.fastcdn.co/js/Cradle.c9144221d5b5d6147353.js`
- **Category:** js  ·  **Confidence:** firm  ·  **Detection:** jsanalysis

Client-served JS references internal infrastructure

**Remediation:** Remove internal references from client bundles


### [MEDIUM] Third-party CNAME (takeover candidate)
- **Asset:** `join.everyplate.com`
- **Category:** takeover  ·  **Confidence:** tentative  ·  **Detection:** normalize

join.everyplate.com -> d3c17743tgwo8l.cloudfront.net.

**Remediation:** Verify the pointed-to service is claimed by you


### [MEDIUM] Third-party CNAME (takeover candidate)
- **Asset:** `live-vercel.everyplate.com`
- **Category:** takeover  ·  **Confidence:** tentative  ·  **Detection:** normalize

live-vercel.everyplate.com -> live-vercel.everyplate.com.cdn.cloudflare.net.

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
- **Asset:** `staging-vercel.everyplate.com`
- **Category:** takeover  ·  **Confidence:** tentative  ·  **Detection:** normalize

staging-vercel.everyplate.com -> staging-vercel.everyplate.com.cdn.cloudflare.net.

**Remediation:** Verify the pointed-to service is claimed by you


### [LOW] SOAP WSDL
- **Asset:** `http://everyplate.com/?wsdl`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

SOAP WSDL at http://everyplate.com/?wsdl (HTTP 200)


### [LOW] Env example
- **Asset:** `http://get.everyplate.com:2086/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at http://get.everyplate.com:2086/.env.example (HTTP 200)


### [LOW] Admin panel
- **Asset:** `http://get.everyplate.com:2086/admin`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin panel at http://get.everyplate.com:2086/admin (HTTP 200)


### [LOW] Admin login
- **Asset:** `http://get.everyplate.com:2086/admin/login`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin login at http://get.everyplate.com:2086/admin/login (HTTP 200)


### [LOW] Joomla admin
- **Asset:** `http://get.everyplate.com:2086/administrator/`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Joomla admin at http://get.everyplate.com:2086/administrator/ (HTTP 200)


### [LOW] Composer json
- **Asset:** `http://get.everyplate.com:2086/composer.json`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Composer json at http://get.everyplate.com:2086/composer.json (HTTP 200)


### [LOW] Debug endpoint
- **Asset:** `http://get.everyplate.com:2086/debug`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Debug endpoint at http://get.everyplate.com:2086/debug (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `http://get.everyplate.com:2086/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at http://get.everyplate.com:2086/health (HTTP 200)


### [LOW] WP json
- **Asset:** `http://get.everyplate.com:2086/wp-json/`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

WP json at http://get.everyplate.com:2086/wp-json/ (HTTP 200)


### [LOW] DS Store exposed
- **Asset:** `http://join.everyplate.com/.DS_Store`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

DS Store exposed at http://join.everyplate.com/.DS_Store (HTTP 200)


### [LOW] Package json
- **Asset:** `http://join.everyplate.com/package.json`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Package json at http://join.everyplate.com/package.json (HTTP 200)


### [LOW] Admin panel
- **Asset:** `http://lp.everyplate.com:2082/admin`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin panel at http://lp.everyplate.com:2082/admin (HTTP 200)


### [LOW] Admin login
- **Asset:** `http://lp.everyplate.com:2082/admin/login`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin login at http://lp.everyplate.com:2082/admin/login (HTTP 200)


### [LOW] Env example
- **Asset:** `https://lp.everyplate.com:2083/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at https://lp.everyplate.com:2083/.env.example (HTTP 200)


### [LOW] Dockerfile exposed
- **Asset:** `https://lp.everyplate.com:2083/Dockerfile`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Dockerfile exposed at https://lp.everyplate.com:2083/Dockerfile (HTTP 200)


### [LOW] Joomla admin
- **Asset:** `https://lp.everyplate.com:2083/administrator/`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Joomla admin at https://lp.everyplate.com:2083/administrator/ (HTTP 200)


### [LOW] WADL present
- **Asset:** `https://lp.everyplate.com:2083/application.wadl`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

WADL present at https://lp.everyplate.com:2083/application.wadl (HTTP 200)


### [LOW] Exchange Autodiscover
- **Asset:** `https://lp.everyplate.com:2083/autodiscover/autodiscover.xml`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Exchange Autodiscover at https://lp.everyplate.com:2083/autodiscover/autodiscover.xml (HTTP 200)


### [LOW] Composer json
- **Asset:** `https://lp.everyplate.com:2083/composer.json`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Composer json at https://lp.everyplate.com:2083/composer.json (HTTP 200)


### [LOW] Debug endpoint
- **Asset:** `https://lp.everyplate.com:2083/debug`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Debug endpoint at https://lp.everyplate.com:2083/debug (HTTP 200)


### [LOW] Docker compose
- **Asset:** `https://lp.everyplate.com:2083/docker-compose.yml`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Docker compose at https://lp.everyplate.com:2083/docker-compose.yml (HTTP 200)


### [LOW] Health endpoint
- **Asset:** `https://lp.everyplate.com:2083/health`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Health endpoint at https://lp.everyplate.com:2083/health (HTTP 200)


### [LOW] Package json
- **Asset:** `https://lp.everyplate.com:2083/package.json`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Package json at https://lp.everyplate.com:2083/package.json (HTTP 200)


### [LOW] WP json
- **Asset:** `https://lp.everyplate.com:2083/wp-json/`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

WP json at https://lp.everyplate.com:2083/wp-json/ (HTTP 200)


### [LOW] Admin login
- **Asset:** `https://mail05.recalls.everyplate.com:8888/admin/login`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin login at https://mail05.recalls.everyplate.com:8888/admin/login (HTTP 401)


### [LOW] DNSSEC not enabled
- **Asset:** `everyplate.com`
- **Category:** dns  ·  **Confidence:** firm  ·  **Detection:** emailsec

Zone is not DNSSEC-signed; DNS answers can be spoofed/tampered

_References:_ https://www.cloudflare.com/dns/dnssec/

**Remediation:** Enable DNSSEC signing at the registrar/DNS provider


### [LOW] MTA-STS not deployed
- **Asset:** `everyplate.com`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

No MTA-STS policy; inbound-mail TLS can be stripped (downgrade)

_References:_ https://datatracker.ietf.org/doc/html/rfc8461

**Remediation:** Publish an MTA-STS policy and _mta-sts TXT record


### [LOW] JWT Token exposed
- **Asset:** `http://everyplate.com`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'JWT Token' matched in http://everyplate.com

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [LOW] JWT Token exposed
- **Asset:** `http://links.everyplate.com`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'JWT Token' matched in http://links.everyplate.com

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [LOW] JWT Token exposed
- **Asset:** `http://links.everyplate.com:2095`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'JWT Token' matched in http://links.everyplate.com:2095

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [INFO] Robots txt
- **Asset:** `http://everyplate.com/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at http://everyplate.com/robots.txt (HTTP 200)


### [INFO] Changelog
- **Asset:** `http://get.everyplate.com:2086/CHANGELOG.md`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Changelog at http://get.everyplate.com:2086/CHANGELOG.md (HTTP 200)


### [INFO] API root hint
- **Asset:** `http://get.everyplate.com:2086/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at http://get.everyplate.com:2086/api (HTTP 200)


### [INFO] API v1 root
- **Asset:** `http://get.everyplate.com:2086/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at http://get.everyplate.com:2086/api/v1 (HTTP 200)


### [INFO] Well known openid
- **Asset:** `https://lp.everyplate.com:2083/.well-known/openid-configuration`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Well known openid at https://lp.everyplate.com:2083/.well-known/openid-configuration (HTTP 200)


### [INFO] Changelog
- **Asset:** `https://lp.everyplate.com:2083/CHANGELOG.md`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Changelog at https://lp.everyplate.com:2083/CHANGELOG.md (HTTP 200)


### [INFO] API root hint
- **Asset:** `https://lp.everyplate.com:2083/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at https://lp.everyplate.com:2083/api (HTTP 200)


### [INFO] API v1 root
- **Asset:** `https://lp.everyplate.com:2083/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at https://lp.everyplate.com:2083/api/v1 (HTTP 200)


### [INFO] API v2 root
- **Asset:** `https://lp.everyplate.com:2083/api/v2`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v2 root at https://lp.everyplate.com:2083/api/v2 (HTTP 200)


### [INFO] Google Workspace in use
- **Asset:** `everyplate.com`
- **Category:** identity  ·  **Confidence:** firm  ·  **Detection:** identity

MX records point to Google Workspace


### [INFO] IPv6 attack surface present
- **Asset:** `everyplate.com`
- **Category:** dns  ·  **Confidence:** firm  ·  **Detection:** netintel

85 IPv6 (AAAA) address(es) discovered across hosts

**Remediation:** Ensure IPv6 endpoints are covered by the same controls as IPv4


### [INFO] Android app identified
- **Asset:** `play:com.everyplate.android`
- **Category:** mobile  ·  **Confidence:** firm  ·  **Detection:** mobile

Google Play app 'com.everyplate.android' appears associated with the target


### [INFO] Reverse DNS reveals related host
- **Asset:** `18.66.122.116`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 18.66.122.116 resolves to server-18-66-122-116.fra60.r.cloudfront.net (outside everyplate.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `3.167.2.59`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 3.167.2.59 resolves to server-3-167-2-59.osl50.r.cloudfront.net (outside everyplate.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `34.111.99.212`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 34.111.99.212 resolves to 212.99.111.34.bc.googleusercontent.com (outside everyplate.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `52.209.242.51`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 52.209.242.51 resolves to ec2-52-209-242-51.eu-west-1.compute.amazonaws.com (outside everyplate.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `54.240.174.54`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 54.240.174.54 resolves to server-54-240-174-54.osl50.r.cloudfront.net (outside everyplate.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `65.9.46.60`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 65.9.46.60 resolves to server-65-9-46-60.arn52.r.cloudfront.net (outside everyplate.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `65.9.62.71`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 65.9.62.71 resolves to server-65-9-62-71.arn56.r.cloudfront.net (outside everyplate.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `66.18.4.228`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 66.18.4.228 resolves to ns01.belltowertech.com (outside everyplate.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `99.84.152.100`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 99.84.152.100 resolves to server-99-84-152-100.fra56.r.cloudfront.net (outside everyplate.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `a.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `alerts.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'alerts.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `alpha.hft.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'alpha.hft.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `bob-staging-cdn.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'bob-staging-cdn.everyplate.com' served distinct content on 104.17.74.24 (HTTP 403)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `bob-staging.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'bob-staging.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `bob.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'bob.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `c.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'c.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `cdn-live.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'cdn-live.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `cdn.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'cdn.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `click-live.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'click-live.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `click.link.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'click.link.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `cloud.link.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'cloud.link.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `deals.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'deals.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `dns.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'dns.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `edge.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'edge.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `email.deals.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'email.deals.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `email.g.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'email.g.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `email.u.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'email.u.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `email.updates.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'email.updates.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `everyplate.com.au`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'everyplate.com.au' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `g.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'g.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `gateway.hft.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'gateway.hft.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `get-preprod.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'get-preprod.everyplate.com' served distinct content on 104.17.74.24 (HTTP 403)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `get.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'get.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `h.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'h.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `hft.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'hft.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


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
- **Asset:** `https://s3.amazonaws.com/alerts-dev/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alerts-files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/alerts-images/`
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


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `image.link.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'image.link.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `images.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'images.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `info.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'info.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `int.hft.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'int.hft.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `invoice.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'invoice.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `join.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'join.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `link.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'link.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `links.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'links.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `live-vercel.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'live-vercel.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `lp-preprod.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'lp-preprod.everyplate.com' served distinct content on 104.17.74.24 (HTTP 403)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `lp-staging.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'lp-staging.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `lp.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'lp.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `mail.hft.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'mail.hft.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `mail05.recalls.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'mail05.recalls.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `mail06.recalls.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'mail06.recalls.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `mail1.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'mail1.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `media.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'media.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `mi.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'mi.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `mobile.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'mobile.everyplate.com' served distinct content on 104.17.74.24 (HTTP 403)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `mta.link.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'mta.link.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `mta2.link.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'mta2.link.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `mta3.link.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'mta3.link.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


### [INFO] Virtual host on 104.17.74.24
- **Asset:** `mta4.link.everyplate.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'mta4.link.everyplate.com' served distinct content on 104.17.74.24 (HTTP 301)


## Prioritized Recommendations

- [CRITICAL] Review and rotate any leaked secrets; request GitHub takedown if applicable
- [HIGH] Force password resets; investigate infected endpoints; enforce MFA
- [HIGH] Restrict the bucket ACL/policy
- [HIGH] Rotate/revoke the credential and remove it from client-served content
- [MEDIUM] Disable TLS 1.0 and TLS 1.1
- [MEDIUM] Publish an SPF record that ends in -all
- [MEDIUM] Publish/claim the scope, or pin an internal registry + scope config
- [MEDIUM] Remove internal references from client bundles
- [MEDIUM] Verify the pointed-to service is claimed by you
- [LOW] Enable DNSSEC signing at the registrar/DNS provider
- [LOW] Publish an MTA-STS policy and _mta-sts TXT record
- [INFO] Ensure IPv6 endpoints are covered by the same controls as IPv4
- [INFO] Review whether the pointed-to host is in scope
