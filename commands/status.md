---
description: Show current HYDRA scan status and findings
allowed-tools: [Bash, Read, mcp__hydra-security__get_findings, mcp__hydra-security__check_tools]
---

## Instructions

Display the current state of all HYDRA operations.

### Step 1: Check Findings
`get_findings` to see what's been discovered.

### Step 2: Check Recon Data Files
Check existence and line count of:
- `/tmp/scope_targets.txt` — loaded scope
- `/tmp/recon_live_hosts.txt` — live hosts
- `/tmp/recon_endpoints.txt` — endpoints
- `/tmp/subdomains_subfinder.txt` — subdomains
- `/tmp/live_hosts.txt` — probed hosts
- `/tmp/gau_urls.txt` — historical URLs
- `/tmp/nuclei_results.txt` — vuln results
- `/tmp/katana_urls.txt` — crawled URLs

### Step 3: Tool Availability
Run `check_tools`.

### Step 4: Reports
Check `reports/` directory for generated reports.

### Output

```
## HYDRA Status
### Scope
- Target: [loaded or "none — use /scope"]
### Recon Data
| Data | Status | Count |
|------|--------|-------|
| Subdomains | [found/missing] | [n] |
| Live hosts | [found/missing] | [n] |
| Endpoints | [found/missing] | [n] |
| Historical URLs | [found/missing] | [n] |
### Findings
- Total: [n] | Critical: [n] | High: [n] | Medium: [n] | Low: [n]
### Tools
- Available: [n]/[total] | Missing: [list]
### Reports
- Generated: [n] | Latest: [path]
### Suggested Next Step
[what to run next based on current state]
```
