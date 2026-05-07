# Show Scan Status

Display the current state of HYDRA scanning operations.

## Instructions

Check and report the current status of all HYDRA operations:

### Step 1: Check Saved Findings
Use `get_findings` to see what's been discovered so far.

### Step 2: Check Recon Data
Look for these files and report their contents/status:
- `/tmp/scope_targets.txt` — loaded scope targets
- `/tmp/recon_live_hosts.txt` — discovered live hosts
- `/tmp/recon_endpoints.txt` — discovered endpoints
- `/tmp/subdomains_subfinder.txt` — subdomain results
- `/tmp/live_hosts.txt` — probed hosts
- `/tmp/gau_urls.txt` — historical URLs
- `/tmp/nuclei_results.txt` — vulnerability scan results
- `/tmp/katana_urls.txt` — crawled URLs

For each file that exists, report the line count and a brief summary.

### Step 3: Check Tool Availability
Run `check_tools` to show which tools are ready.

### Step 4: Check Reports
Look in the project's `reports/` directory for generated reports.

### Output

```
## HYDRA Status

### Scope
- Target: [loaded target or "none loaded — use /scope"]
- Scope file: [exists/missing]

### Recon Data
| Data | Status | Count |
|------|--------|-------|
| Subdomains | [found/missing] | [n] |
| Live hosts | [found/missing] | [n] |
| Endpoints | [found/missing] | [n] |
| Historical URLs | [found/missing] | [n] |
| Crawled URLs | [found/missing] | [n] |

### Findings
- Total saved: [count]
- Critical: [n] | High: [n] | Medium: [n] | Low: [n]

### Tools
- Available: [n]/[total]
- Missing: [list any missing tools]

### Reports
- Generated: [count]
- Latest: [path or "none"]

### Suggested Next Step
[what the user should run next based on current state]
```
