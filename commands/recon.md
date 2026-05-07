---
description: Full reconnaissance pipeline on a target domain
argument-hint: <target-domain>
allowed-tools: [Bash, Read, Write, mcp__hydra-security__check_tools, mcp__hydra-security__subfinder_scan, mcp__hydra-security__amass_enum, mcp__hydra-security__httpx_probe, mcp__hydra-security__katana_crawl, mcp__hydra-security__gau_urls, mcp__hydra-security__whatweb_detect, mcp__hydra-security__wafw00f_detect, mcp__hydra-security__nmap_scan, mcp__hydra-security__full_recon]
---

## Target

The user invoked this command with: $ARGUMENTS

## Instructions

Run comprehensive reconnaissance on the target domain.

### Phase 1: Tool Check
Run `check_tools` to verify available security tools.

### Phase 2: Subdomain Enumeration
1. Run `subfinder_scan` on the target
2. Run `amass_enum` with `passive=true`
3. Merge and deduplicate results

### Phase 3: HTTP Probing
1. Run `httpx_probe` on all subdomains with `status_code=true`, `title=true`, `tech_detect=true`
2. Flag: 403 (bypass potential), 401 (auth), 302 (redirects)

### Phase 4: Endpoint Discovery
1. Run `katana_crawl` on top 10 live hosts (depth=3, js_crawl=true)
2. Run `gau_urls` for historical URLs
3. Look for: APIs, admin panels, uploads, logins

### Phase 5: Fingerprinting
1. Run `whatweb_detect` on main domain + key subdomains
2. Run `wafw00f_detect` for WAF detection

### Phase 6: Port Scanning
1. Run `nmap_scan` with `scan_type="service"` on interesting hosts

### Output

```
## Recon Summary: [target]
### Subdomains: [count] discovered, [count] alive
| Subdomain | Status | Title | Tech |
|-----------|--------|-------|------|
### Interesting Endpoints
### Technology Stack
### WAF Detection
### Port Scan Results
### Attack Surface Notes
```

Save live hosts to `/tmp/recon_live_hosts.txt` and endpoints to `/tmp/recon_endpoints.txt`.
