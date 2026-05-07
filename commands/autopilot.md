---
description: Full autonomous mode (recon, hunt, chain, validate, report)
argument-hint: <target-domain>
allowed-tools: [Bash, Read, Write, mcp__hydra-security__check_tools, mcp__hydra-security__subfinder_scan, mcp__hydra-security__amass_enum, mcp__hydra-security__httpx_probe, mcp__hydra-security__katana_crawl, mcp__hydra-security__gau_urls, mcp__hydra-security__whatweb_detect, mcp__hydra-security__wafw00f_detect, mcp__hydra-security__nmap_scan, mcp__hydra-security__nuclei_scan, mcp__hydra-security__nuclei_scan_list, mcp__hydra-security__ffuf_fuzz, mcp__hydra-security__save_finding, mcp__hydra-security__get_findings, mcp__hydra-security__generate_report]
---

## Target

The user invoked this command with: $ARGUMENTS

## Instructions

Run the complete HYDRA pipeline end-to-end on the target.

### Phase 1: Reconnaissance
1. `check_tools` to verify availability
2. `subfinder_scan` + `amass_enum` (passive) for subdomains
3. `httpx_probe` on all subdomains
4. `katana_crawl` on top live hosts (depth=3, js_crawl=true)
5. `gau_urls` for historical URLs
6. `whatweb_detect` on main domain + interesting subdomains
7. `wafw00f_detect` for WAF
8. `nmap_scan` on key hosts
9. Save live hosts to `/tmp/recon_live_hosts.txt`

### Phase 2: Vulnerability Hunting
1. `nuclei_scan` severity="medium,high,critical" on all live hosts
2. Targeted nuclei scans based on tech stack
3. `ffuf_fuzz` on interesting endpoints
4. `nuclei_scan` tags="cve,exposure,misconfiguration"
5. If APIs: tags="api,graphql"

### Phase 3: Chain Building
Analyze findings for chains:
- Info Disclosure + Auth Bypass → Account Takeover
- Open Redirect + OAuth → Token Theft
- SSRF + Cloud Metadata → Key Extraction
- XSS + CSRF → Privileged Actions

### Phase 4: Validation
1. Re-run scans to confirm reproducibility
2. Filter false positives
3. Assess real-world exploitability
4. `save_finding` for each validated finding

### Phase 5: Reporting
1. Compile validated findings
2. `generate_report` for structured output
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
