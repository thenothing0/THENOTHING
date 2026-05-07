---
description: Validate all findings with evidence and filter false positives
allowed-tools: [Bash, Read, mcp__hydra-security__get_findings, mcp__hydra-security__nuclei_scan, mcp__hydra-security__httpx_probe, mcp__hydra-security__save_finding]
---

## Instructions

Validate vulnerability findings — confirm they're real, reproducible, and evidenced.

### Step 1: Load Findings
1. `get_findings` to retrieve saved findings
2. If none, tell user to run `/hunt` first

### Step 2: For Each Finding

**Reproducibility:** Re-run the specific scan/template that found it.

**False Positive Indicators:**
- Generic error pages triggering matches
- Version detection without actual vuln
- WAF/CDN responses misidentified
- Informational headers not exploitable
- Custom 404 pages matching patterns

**Evidence Collection:**
- Exact HTTP request triggering the vuln
- Response proving the finding
- Tool output as proof

**Impact Assessment:**
- What data is at risk?
- What actions can attacker perform?
- How many users affected?
- Trivial or complex exploitation?

### Step 3: Classify Each Finding
- **VALIDATED** — confirmed, evidenced, reproducible
- **LIKELY VALID** — strong indicators, can't fully confirm
- **FALSE POSITIVE** — not real, explain why
- **NEEDS MANUAL** — requires manual testing

### Step 4: Update Knowledge Base
`save_finding` for validated findings with evidence.

### Output
```
## Validation Results
### Summary
- Reviewed: [n] | Validated: [n] | False Positives: [n] | Needs Manual: [n]
### Validated Findings
| # | Title | Severity | Evidence |
### False Positives Removed
| # | Finding | Reason |
### Needs Manual Testing
| # | Finding | What to test |
```
