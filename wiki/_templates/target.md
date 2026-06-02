---
type: target
aliases: []
tags: []
platform: bugcrowd | standoff365 | hackerone | private
created: YYYY-MM-DD
updated: YYYY-MM-DD
---
# <Program Name>

> One-line description of the program and what makes it interesting.

## Program facts
- **Platform / URL:**
- **Scope reference:** `../scope.txt` (verify before every action)
- **Reward range / tiers:**
- **Notes:** accepts English? auth testing allowed? rate limits?

## Pre-hunt intel
Link the disclosed-report analysis that informed the plan → [[<target>-disclosed-reports]].
Ranked attack paths (highest probability/reward first):
1.
2.

## Attack surface
### Assets / subdomains
| Host | Type | Tech / WAF | Notes | Status |
|------|------|-----------|-------|--------|
| | | | | in/out-of-scope |

### Tech stack & infra map
- Servers/versions, WAF/CDN, cloud (S3/Firebase/K8s), internal IP ranges.

### Auth flows
- How auth works; where it's weak.

## Credential / token inventory
| Credential | Source (file:line / host) | Type | Public-by-design? | Notes |
|-----------|---------------------------|------|-------------------|-------|

## Findings
| Finding | Severity | Status | Report |
|---------|----------|--------|--------|
| [[...]] | | suspected/submitted | `../output/<prog>/...` |

## Techniques that work / don't here
- **Works:** [[...]]
- **Doesn't (WAF/scope):** ...

## Open threads / next actions
- [ ]
