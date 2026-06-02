# Autonomous Vulnerability Hunting

Hunt for vulnerabilities on a target. Supports targeting specific vulnerability classes.

$ARGUMENTS — target and optional flags (e.g., "example.com" or "example.com --xss")

## Instructions

Parse the arguments:
- First argument: target domain or URL
- Optional flags: --xss, --sqli, --ssrf, --idor, --lfi, --rce, --misconfig, --cve

If no flag is provided, run a broad vulnerability hunt. If a flag is provided, focus on that specific class.

### Pre-checks
1. Check if recon data exists in `/tmp/recon_live_hosts.txt` — if yes, use those targets
2. If no recon data, run a quick `httpx_probe` on the target first
3. Run `wafw00f_detect` to check for WAF — adjust rate limits accordingly (WAF present = rate_limit 50)

### Broad Hunt (no specific flag)

1. **Nuclei Broad Scan**
   - Run `nuclei_scan` on each live host with `severity="medium,high,critical"`
   - Use default templates for broad coverage

2. **Tag-Specific Scans** based on detected tech stack:
   - WordPress: `tags="wordpress"`
   - Apache/Nginx: `tags="apache"` or `tags="nginx"`
   - Login pages: `tags="default-login"`
   - API endpoints: `tags="api,graphql,swagger"`
   - Always: `tags="cve,exposure,misconfiguration"`

3. **Directory Fuzzing**
   - Run `ffuf_fuzz` on main targets for hidden content
   - Look for: admin panels, backup files, .git, config files

4. **Analysis** — filter false positives, assess impact, identify chains

### Targeted Hunt (--xss)
- Run `nuclei_scan` with `tags="xss"`
- Crawl with `katana_crawl` (js_crawl=true) to find reflection points
- Fuzz parameters with `ffuf_fuzz` in parameter mode
- Check for DOM XSS patterns in discovered JS files

### Targeted Hunt (--sqli)
- Run `nuclei_scan` with `tags="sqli"`
- Identify endpoints with database-backed parameters
- Fuzz parameters looking for SQL error responses

### Targeted Hunt (--ssrf)
- Run `nuclei_scan` with `tags="ssrf"`
- Look for URL parameters, redirect endpoints, webhook configs
- Check for internal service access patterns

### Targeted Hunt (--idor)
- Identify endpoints with numeric/UUID identifiers
- Look for sequential IDs in API responses
- Check authorization on object references

### Targeted Hunt (--lfi)
- Run `nuclei_scan` with `tags="lfi"`
- Look for file path parameters
- Fuzz with path traversal patterns

### Targeted Hunt (--rce)
- Run `nuclei_scan` with `tags="rce"`
- Check for command injection points
- Look for deserialization endpoints

### Targeted Hunt (--misconfig)
- Run `nuclei_scan` with `tags="misconfiguration,exposure"`
- Check for exposed panels, debug endpoints, default credentials

### Targeted Hunt (--cve)
- Run `nuclei_scan` with `tags="cve"` and detected version info
- Cross-reference detected software versions with known CVEs

### For ALL hunts:

**Save findings:** Use `save_finding` for each validated vulnerability.

**Output format:**
```
## Hunt Results: [target]
### Mode: [broad / specific class]
### WAF: [detected / none]

### Findings ([count])

#### [Severity] — [Title]
- URL: [affected URL]
- Type: [vulnerability type]
- Evidence: [tool output snippet]
- Impact: [what an attacker could do]

### False Positives Filtered: [count]
### Next Steps: [suggested follow-up actions]
```
