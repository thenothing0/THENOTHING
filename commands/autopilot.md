---
description: Full autonomous mode (recon, hunt, chain, validate, report)
argument-hint: <target-domain-or-slug>
allowed-tools: [Bash, Read, Write, mcp__hydra-security__check_tools, mcp__hydra-security__subfinder_scan, mcp__hydra-security__amass_enum, mcp__hydra-security__httpx_probe, mcp__hydra-security__katana_crawl, mcp__hydra-security__gau_urls, mcp__hydra-security__whatweb_detect, mcp__hydra-security__wafw00f_detect, mcp__hydra-security__nmap_scan, mcp__hydra-security__nuclei_scan, mcp__hydra-security__nuclei_scan_list, mcp__hydra-security__ffuf_fuzz, mcp__hydra-security__save_finding, mcp__hydra-security__get_findings, mcp__hydra-security__generate_report]
---

## Target

The user invoked this command with: $ARGUMENTS

Derive a **target slug** (filesystem-safe): primary domain, program handle, or explicit folder name under `output/<slug>/`.

## Instructions

Run the complete THENOTHING pipeline end-to-end on the target.

### Phase 0: Scope and authorization

1. **Stop if scope is unknown:** Read `output/<slug>/memory/scope_notes.md` when present. If missing or says the program/asset list is not confirmed, instruct the user to run `/scope <platform> <handle>` (or paste an authoritative target list) before any intrusive MCP.
2. **Host allowlist:** Prefer seeds from `/tmp/scope_targets.txt` (on Windows, `%TEMP%\scope_targets.txt`). Only enumerate and scan assets that are **in scope** per those notes; do not expand to neighbors or guessed subdomains without explicit scope.
3. **Program rules:** Honor bounty ROE (no unapproved DoS, no other users’ data, etc.). **Scope and ROE beat autopilot** if anything conflicts.

### Phase 1: Reconnaissance

Passive-first; backoff on 429/403 and WAF signals. Log pacing decisions in `output/<slug>/memory/` when non-default.

1. `check_tools` to verify availability
2. `subfinder_scan` + `amass_enum` (passive) for subdomains **scoped to in-scope roots**
3. `httpx_probe` on candidate hosts
4. `katana_crawl` on top live hosts (depth=3, js_crawl=true)
5. `gau_urls` for historical URLs
6. `whatweb_detect` on main domain + interesting subdomains
7. `wafw00f_detect` for WAF
8. `nmap_scan` on key hosts (only where scope allows port scanning)
9. Save live hosts to `/tmp/recon_live_hosts.txt` and mirror a copy under `output/<slug>/recon/recon_live_hosts.txt`

### Phase 2: Vulnerability Hunting

1. `nuclei_scan` severity="medium,high,critical" on scoped live hosts
2. Targeted nuclei scans based on tech stack
3. `ffuf_fuzz` on interesting endpoints (throttled; avoid spray on out-of-scope hosts)
4. `nuclei_scan` tags="cve,exposure,misconfiguration"
5. If APIs: tags="api,graphql"

### Phase 3: Chain Building

Analyze findings for chains:

- Info Disclosure + Auth Bypass → Account Takeover
- Open Redirect + OAuth → Token Theft
- SSRF + Cloud Metadata → Key Extraction
- XSS + CSRF → Privileged Actions

Stop each chain at the **scope boundary**; do not pivot to out-of-scope systems.

### Phase 4: Validation

1. Re-run or manually replay to confirm reproducibility; **second signal** where practical before High/Critical
2. Filter false positives (generic errors, banner-only versions, WAF replacement pages)
3. Assess real-world exploitability; place evidence under `output/<slug>/evidence/`
4. `save_finding` for each **validated** finding with evidence

### Phase 5: Reporting

1. Compile validated findings only; label suspected items as **hypothesis** with next validation step
2. `generate_report` for structured output under `reports/` or `output/<slug>/` per project convention
3. Present final summary

### Output

```
## HYDRA Autopilot: [target]
### Executive Summary
### Findings by Severity
- Critical: [n] | High: [n] | Medium: [n] | Low: [n]
### Top Findings
### Attack Chains
### Remediation Priority
### Report File: [path]
```
