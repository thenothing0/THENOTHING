# Attack-Surface Findings — `greenchef.com` (domain)

_Generated 2026-07-08T08:55:40Z by TheN0thing v11.0_

## Executive Summary

**Risk score:** 100 / 100 (**critical**)  ·  **Total findings:** 358

| Severity | Count |
|----------|------:|
| critical | 6 |
| high | 39 |
| medium | 22 |
| low | 29 |
| info | 262 |

## Findings by Severity

### [CRITICAL] Docker cfg exposed
- **Asset:** `http://bob.greenchef.com:2086/.dockercfg`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Docker cfg exposed at http://bob.greenchef.com:2086/.dockercfg (HTTP 200)


### [CRITICAL] Docker cfg exposed
- **Asset:** `https://lp.greenchef.com/.dockercfg`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Docker cfg exposed at https://lp.greenchef.com/.dockercfg (HTTP 200)


### [CRITICAL] Dotenv exposed
- **Asset:** `https://lp.greenchef.com/.env`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Dotenv exposed at https://lp.greenchef.com/.env (HTTP 200)


### [CRITICAL] Infostealer-exposed credentials
- **Asset:** `greenchef.com`
- **Category:** breach  ·  **Confidence:** firm  ·  **Detection:** breach

HudsonRock reports credentials from info-stealer logs (employees: 1, users: 1196, total: 1200)

_References:_ https://www.hudsonrock.com/threat-intelligence-cybercrime-tools

**Remediation:** Force password resets; investigate infected endpoints; enforce MFA


### [CRITICAL] GitHub code mentions 'greenchef.com' near 'BEGIN RSA PRIVATE KEY' (99 hits)
- **Asset:** `github:greenchef.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [CRITICAL] GitHub code mentions 'greenchef.com' near 'aws access key id' (177 hits)
- **Asset:** `github:greenchef.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] Docker API images
- **Asset:** `http://bob.greenchef.com:2086/images/json`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker API images at http://bob.greenchef.com:2086/images/json (HTTP 200)


### [HIGH] Kubernetes apis
- **Asset:** `http://track.greenchef.com:2086/apis`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Kubernetes apis at http://track.greenchef.com:2086/apis (HTTP 200)


### [HIGH] Backup zip exposed
- **Asset:** `http://track.greenchef.com:2086/backup.zip`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Backup zip exposed at http://track.greenchef.com:2086/backup.zip (HTTP 200)


### [HIGH] Docker registry root
- **Asset:** `http://track.greenchef.com:2086/v2/`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker registry root at http://track.greenchef.com:2086/v2/ (HTTP 200)


### [HIGH] SVN entries exposed
- **Asset:** `https://lp.greenchef.com/.svn/entries`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

SVN entries exposed at https://lp.greenchef.com/.svn/entries (HTTP 200)


### [HIGH] Elasticsearch cat
- **Asset:** `https://lp.greenchef.com/_cat/indices`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Elasticsearch cat at https://lp.greenchef.com/_cat/indices (HTTP 200)


### [HIGH] Actuator configprops
- **Asset:** `https://lp.greenchef.com/actuator/configprops`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Actuator configprops at https://lp.greenchef.com/actuator/configprops (HTTP 200)


### [HIGH] Kibana status
- **Asset:** `https://lp.greenchef.com/api/status`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Kibana status at https://lp.greenchef.com/api/status (HTTP 200)


### [HIGH] Kubernetes apis
- **Asset:** `https://lp.greenchef.com/apis`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Kubernetes apis at https://lp.greenchef.com/apis (HTTP 200)


### [HIGH] Backup zip exposed
- **Asset:** `https://lp.greenchef.com/backup.zip`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Backup zip exposed at https://lp.greenchef.com/backup.zip (HTTP 200)


### [HIGH] Config php backup
- **Asset:** `https://lp.greenchef.com/config.php.bak`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Config php backup at https://lp.greenchef.com/config.php.bak (HTTP 200)


### [HIGH] Swagger json
- **Asset:** `https://lp.greenchef.com/swagger.json`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

Swagger json at https://lp.greenchef.com/swagger.json (HTTP 200)


### [HIGH] Consul ui
- **Asset:** `https://lp.greenchef.com/v1/catalog/services`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Consul ui at https://lp.greenchef.com/v1/catalog/services (HTTP 200)


### [HIGH] Docker registry root
- **Asset:** `https://lp.greenchef.com/v2/`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

Docker registry root at https://lp.greenchef.com/v2/ (HTTP 200)


### [HIGH] Google API Key exposed
- **Asset:** `http://track.greenchef.com:2086`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in http://track.greenchef.com:2086

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `https://greenchef.com`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in https://greenchef.com

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `https://hellofresh.com`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in https://hellofresh.com

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `https://links.greenchef.com`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in https://links.greenchef.com

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [HIGH] Google API Key exposed
- **Asset:** `https://lp.greenchef.com`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'Google API Key' matched in https://lp.greenchef.com

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


### [HIGH] GitHub code mentions 'greenchef.com' near '.env' (64 hits)
- **Asset:** `github:greenchef.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'greenchef.com' near 'api key' (382 hits)
- **Asset:** `github:greenchef.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'greenchef.com' near 'mysql password' (11 hits)
- **Asset:** `github:greenchef.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'greenchef.com' near 'password' (68 hits)
- **Asset:** `github:greenchef.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [HIGH] GitHub code mentions 'greenchef.com' near 'secret' (233 hits)
- **Asset:** `github:greenchef.com`
- **Category:** exposure  ·  **Confidence:** tentative  ·  **Detection:** githubdork

Public GitHub code matches the target domain alongside a secret/config indicator — review for leaked credentials

_References:_ https://docs.github.com/search-github/searching-on-github/searching-code

**Remediation:** Review and rotate any leaked secrets; request GitHub takedown if applicable


### [MEDIUM] VMware Horizon
- **Asset:** `http://bob.greenchef.com:2086/portal/webclient/`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

VMware Horizon at http://bob.greenchef.com:2086/portal/webclient/ (HTTP 200)


### [MEDIUM] Open backup dir
- **Asset:** `http://track.greenchef.com:2086/backup`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Open backup dir at http://track.greenchef.com:2086/backup (HTTP 200)


### [MEDIUM] GraphiQL UI
- **Asset:** `http://track.greenchef.com:2086/graphiql`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

GraphiQL UI at http://track.greenchef.com:2086/graphiql (HTTP 200)


### [MEDIUM] GraphQL endpoint
- **Asset:** `http://track.greenchef.com:2086/graphql`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

GraphQL endpoint at http://track.greenchef.com:2086/graphql (HTTP 200)


### [MEDIUM] GraphQL present
- **Asset:** `http://track.greenchef.com:2086/graphql`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

GraphQL present at http://track.greenchef.com:2086/graphql (HTTP 200)


### [MEDIUM] GraphQL api
- **Asset:** `https://lp.greenchef.com/api/graphql`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

GraphQL api at https://lp.greenchef.com/api/graphql (HTTP 200)


### [MEDIUM] SonarQube status
- **Asset:** `https://lp.greenchef.com/api/system/status`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

SonarQube status at https://lp.greenchef.com/api/system/status (HTTP 200)


### [MEDIUM] ArgoCD api
- **Asset:** `https://lp.greenchef.com/api/v1/applications`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

ArgoCD api at https://lp.greenchef.com/api/v1/applications (HTTP 200)


### [MEDIUM] GraphQL endpoint
- **Asset:** `https://lp.greenchef.com/graphql`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

GraphQL endpoint at https://lp.greenchef.com/graphql (HTTP 200)


### [MEDIUM] GraphQL present
- **Asset:** `https://lp.greenchef.com/graphql`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

GraphQL present at https://lp.greenchef.com/graphql (HTTP 200)


### [MEDIUM] GraphQL console
- **Asset:** `https://lp.greenchef.com/graphql/console`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

GraphQL console at https://lp.greenchef.com/graphql/console (HTTP 200)


### [MEDIUM] VMware Horizon
- **Asset:** `https://lp.greenchef.com/portal/webclient/`
- **Category:** vendor  ·  **Confidence:** confirmed  ·  **Detection:** vendor

VMware Horizon at https://lp.greenchef.com/portal/webclient/ (HTTP 200)


### [MEDIUM] GraphQL v1
- **Asset:** `https://lp.greenchef.com/v1/graphql`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

GraphQL v1 at https://lp.greenchef.com/v1/graphql (HTTP 200)


### [MEDIUM] Legacy TLSv1.0 supported
- **Asset:** `tms.hft.greenchef.com:443`
- **Category:** tls  ·  **Confidence:** confirmed  ·  **Detection:** tls

Server negotiates deprecated TLSv1.0

_References:_ https://datatracker.ietf.org/doc/html/rfc8996

**Remediation:** Disable TLS 1.0 and TLS 1.1


### [MEDIUM] Legacy TLSv1.1 supported
- **Asset:** `tms.hft.greenchef.com:443`
- **Category:** tls  ·  **Confidence:** confirmed  ·  **Detection:** tls

Server negotiates deprecated TLSv1.1

_References:_ https://datatracker.ietf.org/doc/html/rfc8996

**Remediation:** Disable TLS 1.0 and TLS 1.1


### [MEDIUM] SPF record missing
- **Asset:** `greenchef.com`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

No SPF record published; sender spoofing is easier

_References:_ https://datatracker.ietf.org/doc/html/rfc7208

**Remediation:** Publish an SPF record that ends in -all


### [MEDIUM] Third-party CNAME (takeover candidate)
- **Asset:** `live-vercel.greenchef.com`
- **Category:** takeover  ·  **Confidence:** tentative  ·  **Detection:** normalize

live-vercel.greenchef.com -> live-vercel.greenchef.com.cdn.cloudflare.net.

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
- **Asset:** `staging-vercel.greenchef.com`
- **Category:** takeover  ·  **Confidence:** tentative  ·  **Detection:** normalize

staging-vercel.greenchef.com -> staging-vercel.greenchef.com.cdn.cloudflare.net.

**Remediation:** Verify the pointed-to service is claimed by you


### [LOW] Env example
- **Asset:** `http://bob.greenchef.com:2086/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at http://bob.greenchef.com:2086/.env.example (HTTP 200)


### [LOW] Admin panel
- **Asset:** `http://bob.greenchef.com:2086/admin`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin panel at http://bob.greenchef.com:2086/admin (HTTP 200)


### [LOW] Admin login
- **Asset:** `http://bob.greenchef.com:2086/admin/login`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin login at http://bob.greenchef.com:2086/admin/login (HTTP 200)


### [LOW] Docker compose
- **Asset:** `http://bob.greenchef.com:2086/docker-compose.yml`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Docker compose at http://bob.greenchef.com:2086/docker-compose.yml (HTTP 200)


### [LOW] SOAP WSDL
- **Asset:** `http://track.greenchef.com:2086/?wsdl`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

SOAP WSDL at http://track.greenchef.com:2086/?wsdl (HTTP 200)


### [LOW] Dockerfile exposed
- **Asset:** `http://track.greenchef.com:2086/Dockerfile`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Dockerfile exposed at http://track.greenchef.com:2086/Dockerfile (HTTP 200)


### [LOW] Admin panel
- **Asset:** `http://track.greenchef.com:2086/admin`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin panel at http://track.greenchef.com:2086/admin (HTTP 200)


### [LOW] Joomla admin
- **Asset:** `http://track.greenchef.com:2086/administrator/`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Joomla admin at http://track.greenchef.com:2086/administrator/ (HTTP 200)


### [LOW] WADL present
- **Asset:** `http://track.greenchef.com:2086/application.wadl`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

WADL present at http://track.greenchef.com:2086/application.wadl (HTTP 200)


### [LOW] Composer json
- **Asset:** `http://track.greenchef.com:2086/composer.json`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Composer json at http://track.greenchef.com:2086/composer.json (HTTP 200)


### [LOW] Debug endpoint
- **Asset:** `http://track.greenchef.com:2086/debug`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Debug endpoint at http://track.greenchef.com:2086/debug (HTTP 200)


### [LOW] Docker compose
- **Asset:** `http://track.greenchef.com:2086/docker-compose.yml`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Docker compose at http://track.greenchef.com:2086/docker-compose.yml (HTTP 200)


### [LOW] Package json
- **Asset:** `http://track.greenchef.com:2086/package.json`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Package json at http://track.greenchef.com:2086/package.json (HTTP 200)


### [LOW] phpMyAdmin
- **Asset:** `http://track.greenchef.com:2086/phpmyadmin`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

phpMyAdmin at http://track.greenchef.com:2086/phpmyadmin (HTTP 200)


### [LOW] Env example
- **Asset:** `https://lp.greenchef.com/.env.example`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Env example at https://lp.greenchef.com/.env.example (HTTP 200)


### [LOW] Dockerfile exposed
- **Asset:** `https://lp.greenchef.com/Dockerfile`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Dockerfile exposed at https://lp.greenchef.com/Dockerfile (HTTP 200)


### [LOW] Admin panel
- **Asset:** `https://lp.greenchef.com/admin`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin panel at https://lp.greenchef.com/admin (HTTP 200)


### [LOW] Admin login
- **Asset:** `https://lp.greenchef.com/admin/login`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Admin login at https://lp.greenchef.com/admin/login (HTTP 200)


### [LOW] WADL present
- **Asset:** `https://lp.greenchef.com/application.wadl`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

WADL present at https://lp.greenchef.com/application.wadl (HTTP 200)


### [LOW] Docker compose
- **Asset:** `https://lp.greenchef.com/docker-compose.yml`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Docker compose at https://lp.greenchef.com/docker-compose.yml (HTTP 200)


### [LOW] Package json
- **Asset:** `https://lp.greenchef.com/package.json`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Package json at https://lp.greenchef.com/package.json (HTTP 200)


### [LOW] Web config
- **Asset:** `https://lp.greenchef.com/web.config`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Web config at https://lp.greenchef.com/web.config (HTTP 200)


### [LOW] DNSSEC not enabled
- **Asset:** `greenchef.com`
- **Category:** dns  ·  **Confidence:** firm  ·  **Detection:** emailsec

Zone is not DNSSEC-signed; DNS answers can be spoofed/tampered

_References:_ https://www.cloudflare.com/dns/dnssec/

**Remediation:** Enable DNSSEC signing at the registrar/DNS provider


### [LOW] MTA-STS not deployed
- **Asset:** `greenchef.com`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

No MTA-STS policy; inbound-mail TLS can be stripped (downgrade)

_References:_ https://datatracker.ietf.org/doc/html/rfc8461

**Remediation:** Publish an MTA-STS policy and _mta-sts TXT record


### [LOW] JWT Token exposed
- **Asset:** `http://track.greenchef.com:2086`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'JWT Token' matched in http://track.greenchef.com:2086

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [LOW] JWT Token exposed
- **Asset:** `https://greenchef.com`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'JWT Token' matched in https://greenchef.com

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [LOW] JWT Token exposed
- **Asset:** `https://hellofresh.com`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'JWT Token' matched in https://hellofresh.com

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [LOW] JWT Token exposed
- **Asset:** `https://links.greenchef.com`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'JWT Token' matched in https://links.greenchef.com

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [LOW] JWT Token exposed
- **Asset:** `https://lp.greenchef.com`
- **Category:** secret  ·  **Confidence:** firm  ·  **Detection:** secrets

Pattern 'JWT Token' matched in https://lp.greenchef.com

**Remediation:** Rotate/revoke the credential and remove it from client-served content


### [INFO] Robots txt
- **Asset:** `http://34.117.183.115/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at http://34.117.183.115/robots.txt (HTTP 200)


### [INFO] Robots txt
- **Asset:** `http://bob.greenchef.com:2086/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at http://bob.greenchef.com:2086/robots.txt (HTTP 200)


### [INFO] Robots txt
- **Asset:** `http://click.link.greenchef.com/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at http://click.link.greenchef.com/robots.txt (HTTP 200)


### [INFO] Robots txt
- **Asset:** `http://tms.hft.greenchef.com/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at http://tms.hft.greenchef.com/robots.txt (HTTP 200)


### [INFO] Changelog
- **Asset:** `http://track.greenchef.com:2086/CHANGELOG.md`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Changelog at http://track.greenchef.com:2086/CHANGELOG.md (HTTP 200)


### [INFO] API root hint
- **Asset:** `http://track.greenchef.com:2086/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at http://track.greenchef.com:2086/api (HTTP 200)


### [INFO] Robots txt
- **Asset:** `https://greenchef.com/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at https://greenchef.com/robots.txt (HTTP 200)


### [INFO] Sitemap xml
- **Asset:** `https://greenchef.com/sitemap.xml`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

Sitemap xml at https://greenchef.com/sitemap.xml (HTTP 200)


### [INFO] Robots txt
- **Asset:** `https://hellofresh.com/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at https://hellofresh.com/robots.txt (HTTP 200)


### [INFO] Robots txt
- **Asset:** `https://links.greenchef.com/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at https://links.greenchef.com/robots.txt (HTTP 200)


### [INFO] API root hint
- **Asset:** `https://lp.greenchef.com/api`
- **Category:** api  ·  **Confidence:** confirmed  ·  **Detection:** api

API root hint at https://lp.greenchef.com/api (HTTP 200)


### [INFO] API v1 root
- **Asset:** `https://lp.greenchef.com/api/v1`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v1 root at https://lp.greenchef.com/api/v1 (HTTP 200)


### [INFO] API v2 root
- **Asset:** `https://lp.greenchef.com/api/v2`
- **Category:** content  ·  **Confidence:** confirmed  ·  **Detection:** content

API v2 root at https://lp.greenchef.com/api/v2 (HTTP 200)


### [INFO] Robots txt
- **Asset:** `https://mi.greenchef.com/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at https://mi.greenchef.com/robots.txt (HTTP 200)


### [INFO] Robots txt
- **Asset:** `https://tms.hft.greenchef.com/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at https://tms.hft.greenchef.com/robots.txt (HTTP 200)


### [INFO] Robots txt
- **Asset:** `https://view.link.greenchef.com/robots.txt`
- **Category:** exposure  ·  **Confidence:** confirmed  ·  **Detection:** exposure

Robots txt at https://view.link.greenchef.com/robots.txt (HTTP 200)


### [INFO] BIMI record present
- **Asset:** `greenchef.com`
- **Category:** email  ·  **Confidence:** firm  ·  **Detection:** emailsec

Domain publishes a BIMI record (brand indicator)


### [INFO] Google Workspace in use
- **Asset:** `greenchef.com`
- **Category:** identity  ·  **Confidence:** firm  ·  **Detection:** identity

MX records point to Google Workspace


### [INFO] IPv6 attack surface present
- **Asset:** `greenchef.com`
- **Category:** dns  ·  **Confidence:** firm  ·  **Detection:** netintel

47 IPv6 (AAAA) address(es) discovered across hosts

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
- **Asset:** `108.138.51.100`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 108.138.51.100 resolves to server-108-138-51-100.waw51.r.cloudfront.net (outside greenchef.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `108.138.51.38`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 108.138.51.38 resolves to server-108-138-51-38.waw51.r.cloudfront.net (outside greenchef.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `108.138.51.85`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 108.138.51.85 resolves to server-108-138-51-85.waw51.r.cloudfront.net (outside greenchef.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `108.138.51.89`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 108.138.51.89 resolves to server-108-138-51-89.waw51.r.cloudfront.net (outside greenchef.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `13.35.107.108`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 13.35.107.108 resolves to server-13-35-107-108.phl51.r.cloudfront.net (outside greenchef.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `13.35.107.111`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 13.35.107.111 resolves to server-13-35-107-111.phl51.r.cloudfront.net (outside greenchef.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `13.35.107.19`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 13.35.107.19 resolves to server-13-35-107-19.phl51.r.cloudfront.net (outside greenchef.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `13.35.107.72`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 13.35.107.72 resolves to server-13-35-107-72.phl51.r.cloudfront.net (outside greenchef.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `143.204.238.123`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 143.204.238.123 resolves to server-143-204-238-123.arn53.r.cloudfront.net (outside greenchef.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `161.71.33.242`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 161.71.33.242 resolves to reply.s50.exacttarget.com (outside greenchef.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `3.174.18.113`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 3.174.18.113 resolves to server-3-174-18-113.cph50.r.cloudfront.net (outside greenchef.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `3.174.18.3`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 3.174.18.3 resolves to server-3-174-18-3.cph50.r.cloudfront.net (outside greenchef.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `3.174.18.34`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 3.174.18.34 resolves to server-3-174-18-34.cph50.r.cloudfront.net (outside greenchef.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `3.174.230.102`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 3.174.230.102 resolves to server-3-174-230-102.waw51.r.cloudfront.net (outside greenchef.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `34.111.99.212`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 34.111.99.212 resolves to 212.99.111.34.bc.googleusercontent.com (outside greenchef.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `34.117.183.115`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 34.117.183.115 resolves to 115.183.117.34.bc.googleusercontent.com (outside greenchef.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `34.248.200.201`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 34.248.200.201 resolves to ec2-34-248-200-201.eu-west-1.compute.amazonaws.com (outside greenchef.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `44.231.149.160`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 44.231.149.160 resolves to ec2-44-231-149-160.us-west-2.compute.amazonaws.com (outside greenchef.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `52.211.114.94`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 52.211.114.94 resolves to ec2-52-211-114-94.eu-west-1.compute.amazonaws.com (outside greenchef.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `52.51.199.159`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 52.51.199.159 resolves to ec2-52-51-199-159.eu-west-1.compute.amazonaws.com (outside greenchef.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `63.35.200.242`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 63.35.200.242 resolves to ec2-63-35-200-242.eu-west-1.compute.amazonaws.com (outside greenchef.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `65.9.175.49`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 65.9.175.49 resolves to server-65-9-175-49.fra60.r.cloudfront.net (outside greenchef.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `65.9.175.99`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 65.9.175.99 resolves to server-65-9-175-99.fra60.r.cloudfront.net (outside greenchef.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Reverse DNS reveals related host
- **Asset:** `66.18.4.231`
- **Category:** dns  ·  **Confidence:** tentative  ·  **Detection:** netintel

PTR for 66.18.4.231 resolves to host231.belltowertech.com (outside greenchef.com)

**Remediation:** Review whether the pointed-to host is in scope


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-api.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-api.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-apps.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-apps.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-auth.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-auth.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-backup.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-backup.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-bak.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-bak.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-beta.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-beta.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-cd.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-cd.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-ci.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-ci.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-confluence.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-confluence.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-corp.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-corp.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-demo.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-demo.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-dev.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-dev.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-development.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-development.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-ftp.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-ftp.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-gateway.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-gateway.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-git.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-git.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-gitlab.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-gitlab.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-grafana.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-grafana.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-gw.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-gw.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-int.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-int.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-status.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-status.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-stg.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-stg.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-test.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-test.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-testing.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-testing.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-uat.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-uat.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-v1.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-v1.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-v2.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-v2.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-v3.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-v3.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-vpn.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-vpn.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a-web.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a-web.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a.admin.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.admin.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a.alpha.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.alpha.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a.api.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.api.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a.api2.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.api2.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a.app.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.app.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a.apps.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.apps.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a.auth.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.auth.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a.backup.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.backup.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a.cd.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.cd.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a.ci.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.ci.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a.portal.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.portal.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a.prod.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.prod.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a.production.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.production.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a.qa.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.qa.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a.sandbox.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.sandbox.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a.smtp.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.smtp.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a.sso.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.sso.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a.stage.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.stage.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


### [INFO] Virtual host on 104.18.35.137
- **Asset:** `a.staging.greenchef.com`
- **Category:** misc  ·  **Confidence:** tentative  ·  **Detection:** normalize

Host header 'a.staging.greenchef.com' served distinct content on 104.18.35.137 (HTTP 301)


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
- **Asset:** `https://s3.amazonaws.com/alt3/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/analytics-backup/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/analytics-backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/analytics-bucket/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/analytics-cdn/`
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
- **Asset:** `https://s3.amazonaws.com/analytics-web/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (s3)
- **Asset:** `https://s3.amazonaws.com/analytics/`
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
- **Asset:** `https://storage.googleapis.com/analytics-backups/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/analytics-cdn/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/analytics-files/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/analytics-logs/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/analytics-prod/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/analytics-staging/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/analytics-test/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/analytics-uploads/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


### [INFO] Cloud bucket exists (gcp)
- **Asset:** `https://storage.googleapis.com/analytics/`
- **Category:** cloud  ·  **Confidence:** tentative  ·  **Detection:** normalize

Bucket exists (access denied)


## Prioritized Recommendations

- [CRITICAL] Force password resets; investigate infected endpoints; enforce MFA
- [CRITICAL] Review and rotate any leaked secrets; request GitHub takedown if applicable
- [HIGH] Restrict the bucket ACL/policy
- [HIGH] Rotate/revoke the credential and remove it from client-served content
- [MEDIUM] Disable TLS 1.0 and TLS 1.1
- [MEDIUM] Publish an SPF record that ends in -all
- [MEDIUM] Publish/claim the scope, or pin an internal registry + scope config
- [MEDIUM] Verify the pointed-to service is claimed by you
- [LOW] Enable DNSSEC signing at the registrar/DNS provider
- [LOW] Publish an MTA-STS policy and _mta-sts TXT record
- [INFO] Ensure IPv6 endpoints are covered by the same controls as IPv4
- [INFO] Review whether the pointed-to host is in scope
