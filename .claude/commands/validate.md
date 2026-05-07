# Validate Findings

Validate all discovered findings with evidence and filter false positives.

## Instructions

You are validating vulnerability findings to ensure they are real, reproducible, and properly evidenced before reporting.

### Step 1: Load Findings
1. Use `get_findings` to retrieve all saved findings
2. Also check for any recent scan output that hasn't been saved yet

If no findings exist, inform the user to run `/hunt` first.

### Step 2: Validation Process

For each finding, perform:

**2a. Reproducibility Check**
- Re-run the specific scan that found the vulnerability
- Use `nuclei_scan` with the specific template if it was a nuclei finding
- Use `httpx_probe` to confirm the host is still alive
- Confirm the finding appears consistently

**2b. False Positive Analysis**

Common false positive indicators:
- Generic error pages triggering template matches
- Version detection without actual vulnerability
- WAF/CDN responses being misidentified
- Informational headers that aren't exploitable
- Honeypot or decoy responses
- Custom 404 pages matching patterns

**2c. Evidence Collection**

For each validated finding, collect:
- The exact HTTP request that triggers the vulnerability
- The response showing the vulnerability
- The specific tool output proving the finding
- Any additional context (affected parameter, payload used)

**2d. Impact Assessment**

Evaluate real-world impact:
- What data is actually at risk?
- What actions can an attacker perform?
- How many users are affected?
- Is exploitation trivial or complex?
- Are there mitigating factors?

### Step 3: Classification

Mark each finding as:
- **VALIDATED** — confirmed real, has evidence, reproducible
- **LIKELY VALID** — strong indicators but can't fully confirm without auth/interaction
- **FALSE POSITIVE** — not a real vulnerability, explain why
- **NEEDS MANUAL** — requires manual testing to confirm (e.g., blind XSS, race conditions)

### Step 4: Update Knowledge Base

- Use `save_finding` to update validated findings with evidence
- Remove or note false positives

### Output

```
## Validation Results

### Summary
- Total findings reviewed: [count]
- Validated: [count]
- Likely valid: [count]
- False positives: [count]
- Needs manual testing: [count]

### Validated Findings
| # | Title | Severity | Evidence |
|---|-------|----------|----------|

### False Positives Removed
| # | Original Finding | Reason |
|---|-----------------|--------|

### Needs Manual Testing
| # | Finding | What to test |
|---|---------|-------------|

### Confidence Assessment
[overall confidence in the findings set]
```
