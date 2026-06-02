---
description: Build exploit chains from discovered findings
allowed-tools: [Read, mcp__hydra-security__get_findings]
---

## Instructions

Analyze discovered vulnerabilities and build exploit chains.

### Step 1: Load Findings
1. `get_findings` to retrieve all saved findings
2. Check `/tmp/nuclei_results.txt` for unsaved results
3. If nothing found, tell user to run `/hunt` first

### Step 2: Chain Analysis

Common chain patterns:
- Info Disclosure + Auth Bypass → Account Takeover
- Open Redirect + OAuth → Token Theft
- SSRF + Cloud Metadata → AWS/GCP Key Extraction
- XSS + CSRF → Privileged Action Execution
- IDOR + PII Exposure → Mass Data Exfiltration
- Subdomain Takeover + Cookie Scope → Session Hijack
- Path Traversal + Config Read → Credential Theft → RCE
- SQL Injection + Admin Panel → Full Compromise
- Misconfigured CORS + Sensitive Endpoint → Data Theft
- Version Disclosure + Known CVE → Exploitation

Evaluate: same target? one enables another? severity escalation? realistic?

### Step 3: Document Each Chain

```
## Chain: [Name]
**Combined Severity:** [elevated severity]
### Attack Flow
Step 1: [Finding A] → enables →
Step 2: [Finding B] → leads to →
Impact: [combined impact]
### Prerequisites
[conditions required]
```

### Step 4: Severity Reassessment
- Two Lows → Medium
- Low + Medium → High
- Any chain → RCE/Account Takeover = Critical

### Output
```
## Exploit Chain Analysis
### Chains Discovered: [count]
[chain details]
### Standalone Findings
### Recommendations
```
