# Generate Bug Bounty Report

Generate a submission-ready bug bounty report from validated findings.

## Instructions

You are generating a professional bug bounty report suitable for submission to HackerOne, Bugcrowd, or Intigriti.

### Step 1: Gather Findings
1. Use `get_findings` to retrieve all validated findings from the knowledge base
2. If no findings saved, inform the user to run `/hunt` and `/validate` first

### Step 2: For Each Finding, Write a Report Section

Use this exact template per finding:

```markdown
## [Severity] — [Vulnerability Title]

### Summary
[1-2 sentence summary of the vulnerability and its impact]

### Vulnerability Details
- **Type:** [CWE ID and name]
- **Severity:** [Critical / High / Medium / Low]
- **CVSS 3.1:** [calculated score]
- **Affected URL:** [exact URL]
- **Parameter/Input:** [specific vector]

### Steps to Reproduce
1. [Exact step-by-step instructions]
2. [Include payloads, headers, parameters]
3. [Anyone should be able to follow these]

### Evidence
[Tool output, HTTP request/response pairs, or relevant scan results]

### Impact
[Specific description of what an attacker could achieve.
Mention: data at risk, affected users, business impact.]

### Remediation
[Actionable fix recommendations:
- Code changes
- Configuration updates
- Security controls to implement]

### References
- [CWE link]
- [OWASP reference]
- [CVE if applicable]
```

### Step 3: Generate Report File
1. Use `generate_report` with all findings to create the consolidated report
2. Save to the reports directory

### Step 4: Quality Check

Before presenting, verify:
- Clear, descriptive titles (not template IDs)
- Accurate severity with CVSS justification
- Complete reproduction steps
- Real evidence from tool output (never fabricated)
- Specific and realistic impact statements
- Actionable remediation

### Output

Present the full report, then:

```
## Report Summary
- Total findings: [count]
- Critical: [count] | High: [count] | Medium: [count] | Low: [count]
- Report saved to: [path]
- Ready for submission: [yes/no + any issues]
```
