---
description: Generate submission-ready bug bounty report
allowed-tools: [Read, Write, mcp__hydra-security__get_findings, mcp__hydra-security__generate_report]
---

## Instructions

Generate a professional bug bounty report from validated findings.

### Step 1: Gather Findings
`get_findings` — if none, tell user to run `/hunt` and `/validate` first.

### Step 2: For Each Finding

```markdown
## [Severity] — [Title]

### Summary
[1-2 sentences]

### Vulnerability Details
- **Type:** [CWE ID and name]
- **Severity:** [Critical/High/Medium/Low]
- **CVSS 3.1:** [score]
- **Affected URL:** [exact URL]
- **Parameter:** [vector]

### Steps to Reproduce
1. [exact steps anyone can follow]

### Evidence
[tool output, request/response]

### Impact
[what attacker achieves — data at risk, users affected]

### Remediation
[actionable fixes]

### References
- [CWE link]
- [OWASP ref]
```

### Step 3: Generate Report File
Use `generate_report` with all findings.

### Step 4: Quality Check
- Clear titles (not template IDs)
- Accurate severity + CVSS
- Complete repro steps
- Real evidence (never fabricated)
- Specific impact
- Actionable remediation

### Output
```
## Report Summary
- Total: [n] | Critical: [n] | High: [n] | Medium: [n] | Low: [n]
- Report saved to: [path]
- Ready for submission: [yes/no]
```
