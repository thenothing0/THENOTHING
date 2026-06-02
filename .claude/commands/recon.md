# Full Reconnaissance Pipeline

Run comprehensive reconnaissance on a target domain.

$ARGUMENTS — the target domain (e.g., "example.com")

## Instructions

You are performing full reconnaissance on the target: $ARGUMENTS

Follow this pipeline in order:

### Phase 1: Tool Check
Run `check_tools` to verify available security tools.

### Phase 2: Subdomain Enumeration
1. Run `subfinder_scan` on the target domain
2. Run `amass_enum` with `passive=true`
3. Merge and deduplicate all discovered subdomains

### Phase 3: HTTP Probing
1. Take all unique subdomains and run `httpx_probe` with `status_code=true`, `title=true`, `tech_detect=true`
2. Note alive subdomains, their status codes, and titles
3. Flag interesting codes: 403 (bypass potential), 401 (auth), 302 (redirects)

### Phase 4: Endpoint Discovery
1. Run `katana_crawl` on the top 10 most interesting live hosts (depth=3, js_crawl=true)
2. Run `gau_urls` on the main domain for historical URLs
3. Look for: API endpoints, admin panels, file uploads, login pages

### Phase 5: Technology Fingerprinting
1. Run `whatweb_detect` on the main domain and key subdomains
2. Run `wafw00f_detect` to identify WAF presence
3. Note the full tech stack

### Phase 6: Port Scanning
1. Run `nmap_scan` with `scan_type="service"` on the most interesting hosts
2. Look for non-standard ports and exposed services

### Output

Present results as:

```
## Recon Summary: [target]

### Subdomains: [count] discovered, [count] alive
| Subdomain | Status | Title | Tech |
|-----------|--------|-------|------|

### Interesting Endpoints
[list endpoints worth investigating]

### Technology Stack
[detected technologies per host]

### WAF Detection
[WAF status and product if detected]

### Port Scan Results
[open ports and services on key hosts]

### Attack Surface Notes
[observations, interesting findings, suggested next steps]
```

Save all live hosts to `/tmp/recon_live_hosts.txt` and interesting endpoints to `/tmp/recon_endpoints.txt` for use by other commands.
