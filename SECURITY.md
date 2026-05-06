# Security Policy

## ⚠️ Responsible Use

HYDRA is designed **exclusively** for authorized security testing within approved bug bounty program scopes. 

**Unauthorized use of this tool against systems you do not have explicit permission to test is illegal and unethical.**

## 🔒 Scope Enforcement

HYDRA includes mandatory scope enforcement at three levels:
1. **Scope Intelligence Layer** — Blocks out-of-scope targets before any scan
2. **MCP Tool Server** — Validates every tool execution against scope policy
3. **Coordinator** — Blocks entire scan phases for unauthorized targets

These safety mechanisms should **never** be bypassed or disabled.

## 🐛 Reporting Security Vulnerabilities

If you discover a security vulnerability in HYDRA itself:

1. **Do NOT** open a public issue
2. Email: security@hydra-security.dev (replace with your actual email)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours and work with you on a coordinated disclosure.

## 📋 Supported Versions

| Version | Supported |
|---------|-----------|
| 3.x     | ✅ Active |
| 2.x     | ⚠️ Critical fixes only |
| < 2.0   | ❌ End of life |

## ⚖️ Legal Notice

Users of HYDRA are solely responsible for ensuring compliance with:
- Applicable laws and regulations
- Bug bounty program terms and conditions
- Target organization's security testing policies
- Rate limiting and responsible testing practices
