# THENOTHING — Cursor Skills (Agent)

This directory holds **Cursor-native** operational skills for Agent mode. Reference files with `@.cursor/skills/...` from chat.

## Layout

| Folder | Focus |
|--------|--------|
| `recon/` | Passive-first inventory |
| `web/` | Core web vuln classes |
| `xss/` | Example shortcut (`advanced_xss.md`) |
| `api/` | REST auth, JWT, OAuth, IDOR, mass assignment |
| `graphql/` | GraphQL surface + authz |
| `cloud/` | AWS privesc, IAM, CI/CD |
| `kubernetes/` | Cluster attack paths + container hardening |
| `business_logic/` | Race, workflow, tenant, payments, coupons |
| `ai_security/` | Prompt, MCP, RAG, tools, agents |
| `browser/` | DOM, WS, tokens, client-side auth |
| `osint/` | GitHub/code-host intel |
| `exploit_chains/` | Meta composer |
| `stealth/` | Adaptive operational pacing |
| `validation/` | FP triage |

## Rules integration

Project rules in `.cursor/rules/*.mdc` enforce: **scope**, **reasoning-first**, **validation-first**, **stealth**, **MCP + output artifacts**.

## Repo-wide skills

The repository also ships `skills/**/*.md` and `skills/**/SKILL.yaml` for Claude Code / Hydra loaders—keep **wording** aligned when updating methodologies.
