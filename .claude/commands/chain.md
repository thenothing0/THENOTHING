# Build Exploit Chains

Analyze current findings and build exploit chains from related vulnerabilities.

## Instructions

You are analyzing discovered vulnerabilities to find exploit chains — combinations of findings that together produce greater impact than any single finding alone.

### Step 1: Load Findings
1. Use `get_findings` to retrieve all saved findings
2. If no findings in the knowledge base, check `/tmp/nuclei_results.txt` or recent scan output
3. If no findings at all, inform the user to run `/hunt` or `/recon` first

### Step 2: Chain Analysis

For each finding, evaluate potential chains:

**Common Chain Patterns:**
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

**Chain Evaluation Criteria:**
- Are the findings on the same target or related infrastructure?
- Does one finding enable or amplify another?
- Does the chain increase severity beyond individual findings?
- Is the chain realistic and reproducible?

### Step 3: Document Chains

For each valid chain:

```
## Chain: [Descriptive Name]
**Combined Severity:** [severity of the chain as a whole]
**Individual Findings:** [list of findings in the chain]

### Attack Flow
Step 1: [First vulnerability] — [what it gives the attacker]
  ↓
Step 2: [Second vulnerability] — [how step 1 enables this]
  ↓
Step 3: [Result] — [final impact]

### Impact
[What an attacker achieves through the full chain]

### Prerequisites
[What conditions must be true for this chain to work]
```

### Step 4: Severity Reassessment

Chains often elevate severity:
- Two Lows → Medium
- Low + Medium → High
- Medium + Medium → High
- Any chain leading to RCE/Account Takeover → Critical

### Output

```
## Exploit Chain Analysis

### Chains Discovered: [count]

[chain details for each]

### Standalone Findings (no chain potential)
[findings that don't combine with others]

### Recommendations
[which chains to prioritize for reporting]
```
