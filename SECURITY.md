# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Active support |
| < 1.0   | Not supported |

## Reporting a vulnerability

If you discover a security vulnerability in HYDRA itself (not in a target you're testing), please report it responsibly:

1. **GitHub Security Advisories** (preferred): Go to [Security Advisories](https://github.com/thenothing-sec/hydra/security/advisories) and create a new draft advisory.
2. **Email**: Contact the maintainers directly (see the repository for contact details).

Please **do not** open a public GitHub issue for security vulnerabilities.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

### Response timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 7 days
- **Fix or mitigation**: within 30 days for critical issues

## Scope enforcement

HYDRA enforces deny-by-default authorization at multiple levels:

1. **Authorization gate** — `authorize_target` must be called before any active action. Only targets covered by a registered bug bounty program are permitted.
2. **MCP tool server** — every tool execution validates scope policy.
3. **Four absolute prohibitions** — DoS, destructive actions, data exfiltration, and social engineering are never permitted, even against in-scope targets.
4. **Catastrophic command denylist** — `shell_exec` blocks dangerous system commands regardless of operator mode.
5. **Secret redaction** — evidence storage automatically redacts credentials and secrets.
6. **Poison-gate quarantine** — cross-session learning quarantines target-derived steering text.

These safety mechanisms must never be bypassed or disabled.

## Responsible use

HYDRA is designed exclusively for authorized security testing within approved bug bounty program scopes or explicit written authorization.

Unauthorized use against systems you do not have permission to test is illegal and unethical. Users are solely responsible for compliance with applicable laws, program terms, and responsible testing practices.
