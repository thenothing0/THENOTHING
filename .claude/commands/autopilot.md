# Full Autonomous Mode

Run the complete HYDRA pipeline: recon, hunt, chain, validate, and report.

$ARGUMENTS — the target domain (e.g., "example.com")

## Instructions

You are running full autonomous mode on: $ARGUMENTS

Execute the entire bug bounty methodology end-to-end without stopping. Work through each phase sequentially, using results from each phase to inform the next.

### Phase 1: Reconnaissance
1. Run `check_tools` to verify tool availability
2. Run `subfinder_scan` and `amass_enum` (passive) for subdomain enumeration
3. Run `httpx_probe` on all discovered subdomains
4. Run `katana_crawl` on top live hosts (depth=3, js_crawl=true)
5. Run `gau_urls` for historical URL discovery
6. Run `whatweb_detect` on main domain and interesting subdomains
7. Run `wafw00f_detect` to check for WAF
8. Run `nmap_scan` on key hosts

Save live hosts to `/tmp/recon_live_hosts.txt`.

### Phase 2: Vulnerability Hunting
1. Run `nuclei_scan` with `severity="medium,high,critical"` on all live hosts
2. Run targeted nuclei scans based on detected tech stack
3. Run `ffuf_fuzz` on interesting endpoints
4. Run `nuclei_scan` with `tags="cve,exposure,misconfiguration"`
5. If APIs found: `nuclei_scan` with `tags="api,graphql"`

### Phase 3: Chain Building
For each finding, analyze:
1. Can this finding be combined with others for greater impact?
2. Does an info-disclosure enable exploitation of another vuln?
3. Can an open redirect be chained with SSRF or OAuth bypass?
4. Do multiple low-severity findings combine into a high-severity chain?

Document chains as:
```
Chain: [Name]
Step 1: [Finding A] → enables →
Step 2: [Finding B] → leads to →
Impact: [Combined impact]
```

### Phase 4: Validation
For each finding and chain:
1. Verify the finding is reproducible (re-run the specific scan)
2. Confirm it's not a false positive (check response content)
3. Assess real-world exploitability
4. Determine actual impact vs theoretical impact
5. Use `save_finding` for each validated finding

### Phase 5: Reporting
1. Compile all validated findings
2. Use `generate_report` to create the structured report
3. Present a final summary with:
   - Executive summary (1 paragraph)
   - Finding count by severity
   - Top 3 most impactful findings
   - Attack chains discovered
   - Remediation priority list

### Output

Present a progress update after each phase completes, then the final report at the end.

```
## HYDRA Autopilot Report: [target]
### Scan Duration: [time]

### Executive Summary
[1 paragraph overview]

### Findings by Severity
- Critical: [count]
- High: [count]
- Medium: [count]
- Low: [count]
- Info: [count]

### Top Findings
[top 3-5 findings with details]

### Attack Chains
[documented chains]

### Remediation Priority
1. [most urgent fix]
2. [next priority]
...

### Report File
[path to generated report]
```
