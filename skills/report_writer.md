# Skill: Bug Bounty Report Writer

You are writing a professional bug bounty report suitable for submission
to HackerOne, Bugcrowd, or Intigriti.

## File Output Rule — CRITICAL

For EVERY finding, you MUST create a SEPARATE file named:
  vuln_[SEVERITY]_[SHORT_TITLE].md
  Examples:
    vuln_critical_sqli_login.md
    vuln_high_xss_search.md
    vuln_medium_idor_profile.md

Do NOT combine multiple vulnerabilities into one file.
Each file is self-contained and independently submittable.

---

## File Template (use for EVERY finding)

---
# [SEVERITY] — [Vulnerability Title]

## 1. Summary
[2-3 sentences: what is it, where is it, what can an attacker do.]

## 2. Vulnerability Details
| Field         | Value                                      |
|---------------|--------------------------------------------|
| Type          | CWE-XXX: Name                              |
| Severity      | Critical / High / Medium / Low             |
| CVSS 3.1      | X.X (Vector: CVSS:3.1/AV:.../...)          |
| Affected URL  | https://target.com/path/to/endpoint        |
| Method        | GET / POST / PUT / DELETE                  |
| Parameter     | Exact parameter name or input vector       |
| Auth Required | Yes / No                                   |

## 3. Environment Setup

### Tools Required
- [Tool name + version, e.g. Burp Suite Community 2024.x]
- [curl / Python 3.x / sqlmap / etc.]

### Prerequisites
- Account type needed (if any): [guest / low-priv user / admin]
- Any cookies/tokens to grab first: [explain how]

## 4. Steps to Reproduce

### Step 1 — [Action Name]
Navigate to:
  https://target.com/vulnerable/endpoint

Explanation: [why this step matters]

### Step 2 — [Action Name]
Intercept the request with Burp Suite (or use curl):

```http
POST /api/endpoint HTTP/1.1
Host: target.com
Content-Type: application/json
Cookie: session=YOUR_SESSION_TOKEN

{"param": "PAYLOAD_HERE"}
```

### Step 3 — Inject Payload
Replace `PAYLOAD_HERE` with the following:

**Payload:**
```
[EXACT PAYLOAD — no placeholders, the real thing]
```

**Why this payload works:** [Brief technical explanation]

### Step 4 — Observe the Result
Expected vulnerable response:
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"result": "EVIDENCE_OF_EXPLOITATION"}
```

## 5. Proof of Concept (PoC)

### Option A — curl one-liner
```bash
curl -i -s -k -X POST \
  -H "Content-Type: application/json" \
  -H "Cookie: session=SESSION_TOKEN" \
  -d '{"param":"PAYLOAD"}' \
  "https://target.com/api/endpoint"
```

### Option B — Python script
```python
import requests

TARGET = "https://target.com/api/endpoint"
SESSION = "YOUR_SESSION_TOKEN"

payload = {
    "param": "REAL_PAYLOAD_HERE"
}

headers = {
    "Cookie": f"session={SESSION}",
    "Content-Type": "application/json"
}

r = requests.post(TARGET, json=payload, headers=headers)
print(f"[*] Status: {r.status_code}")
print(f"[*] Response: {r.text[:500]}")

# Confirm exploitation
if "INDICATOR_OF_SUCCESS" in r.text:
    print("[+] VULNERABLE — exploitation confirmed!")
else:
    print("[-] Not vulnerable or needs adjustment")
```

### Option C — Burp Suite Repeater
1. Capture the original request
2. Send to Repeater (Ctrl+R)
3. Modify parameter as shown in Step 3
4. Click Send
5. Observe response in right panel

### Expected Output / Screenshot Description
```
[Paste actual tool output here — never fabricate.
Include: HTTP status code, relevant response body,
any error messages, or data disclosure.]
```

## 6. Impact

### What an attacker can achieve:
- [Specific action 1, e.g., "Read any user's private messages"]
- [Specific action 2, e.g., "Bypass authentication completely"]
- [Specific action 3, e.g., "Execute arbitrary SQL on the database"]

### Affected parties:
- Users affected: [All users / Authenticated users / Admins only]
- Data at risk: [PII / credentials / financial data / etc.]
- Business impact: [Reputational / financial / legal / operational]

### CVSS Justification
- Attack Vector (AV): Network — exploitable remotely
- Attack Complexity (AC): Low — no special conditions
- Privileges Required (PR): None / Low / High
- User Interaction (UI): None / Required
- Scope (S): Unchanged / Changed
- Confidentiality (C): High / Low / None
- Integrity (I): High / Low / None
- Availability (A): High / Low / None

## 7. Remediation

### Immediate Fix
[Most critical code/config change to stop exploitation right now]

### Code Example (Vulnerable vs Fixed)

**Vulnerable:**
```[language]
// Bad code — showing the problem
```

**Fixed:**
```[language]
// Correct code — showing the solution
```

### Additional Hardening
- [ ] [Security control 1]
- [ ] [Security control 2]
- [ ] [Security control 3]

### Testing After Fix
```bash
# Run this command to verify the fix worked:
[command or test case]
```

## 8. References
- CWE: https://cwe.mitre.org/data/definitions/XXX.html
- OWASP: https://owasp.org/www-community/attacks/[attack-name]
- PortSwigger: https://portswigger.net/web-security/[topic]
- CVE (if applicable): https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXX

---

## Quality Checklist (verify before saving file)

- [ ] File named correctly: vuln_[severity]_[title].md
- [ ] Title is clear and descriptive
- [ ] CVSS score calculated and justified
- [ ] Payloads are real (not placeholders)
- [ ] At least 2 PoC options provided (curl + Python preferred)
- [ ] Steps reproducible by someone who didn't discover the bug
- [ ] Evidence is real output (never fabricated)
- [ ] Impact is specific — mentions data types and affected users
- [ ] Remediation includes before/after code example
- [ ] Not a duplicate (check with `get_findings`)

---

## Workflow After Writing

1. `save_finding` — persist the finding to the database
2. Write the file: `vuln_[severity]_[title].md`
3. `generate_report` — create consolidated summary report
4. Present each file path to the user for review
