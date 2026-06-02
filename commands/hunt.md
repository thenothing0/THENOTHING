---
description: Autonomous vulnerability hunting (supports --xss, --sqli, --ssrf, etc.)
argument-hint: <target> [--xss|--sqli|--ssrf|--idor|--lfi|--rce|--misconfig|--cve]
allowed-tools: [Bash, Read, Write, mcp__hydra-security__nuclei_scan, mcp__hydra-security__nuclei_scan_list, mcp__hydra-security__ffuf_fuzz, mcp__hydra-security__katana_crawl, mcp__hydra-security__httpx_probe, mcp__hydra-security__wafw00f_detect, mcp__hydra-security__save_finding, mcp__hydra-security__get_findings]
---

## Arguments

The user invoked this command with: $ARGUMENTS

Parse: first arg = target, optional flags = vulnerability class filter.

## Instructions

### Pre-checks
1. Check `/tmp/recon_live_hosts.txt` for existing recon data
2. If none, run `httpx_probe` on the target
3. Run `wafw00f_detect` — if WAF present, use rate_limit=50

### Broad Hunt (no flag)
1. `nuclei_scan` with `severity="medium,high,critical"` on live hosts
2. Tech-specific scans: wordpress, apache, nginx, api, graphql, cve, exposure, misconfiguration
3. `ffuf_fuzz` on main targets for hidden content
4. Filter false positives, assess impact

### --xss
- `nuclei_scan` with `tags="xss"`
- `katana_crawl` (js_crawl=true) for reflection points
- `ffuf_fuzz` parameter mode on interesting endpoints

### --sqli
- `nuclei_scan` with `tags="sqli"`
- Identify database-backed parameters
- Fuzz for SQL error responses

### --ssrf
- `nuclei_scan` with `tags="ssrf"`
- Look for URL params, redirects, webhooks

### --idor
- Identify endpoints with numeric/UUID IDs
- Check authorization on object references

### --lfi
- `nuclei_scan` with `tags="lfi"`
- Fuzz file path parameters

### --rce
- `nuclei_scan` with `tags="rce"`
- Check command injection points, deserialization

### --misconfig
- `nuclei_scan` with `tags="misconfiguration,exposure"`
- Exposed panels, debug endpoints, default creds

### --cve
- `nuclei_scan` with `tags="cve"` + version info

### For ALL hunts:
Use `save_finding` for each validated vulnerability.

Output:
```
## Hunt Results: [target]
### Mode: [broad / specific class]
### WAF: [detected / none]
### Findings ([count])
#### [Severity] — [Title]
- URL: ...
- Evidence: ...
- Impact: ...
### False Positives Filtered: [count]
### Next Steps: [suggestions]
```
