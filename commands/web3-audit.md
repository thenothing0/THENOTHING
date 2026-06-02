---
description: Smart contract security audit (Solidity/Vyper)
argument-hint: <contract-file.sol>
allowed-tools: [Bash, Read, Write]
---

## Arguments

The user invoked this command with: $ARGUMENTS

## Instructions

Perform a security audit on the specified smart contract file(s).

### Step 1: Load Contract
1. Read the specified file(s)
2. If directory given, find all .sol/.vy files
3. Identify purpose, dependencies, inheritance

### Step 2: Check Vulnerability Classes

**Critical:** Reentrancy, unprotected selfdestruct/delegatecall, arbitrary external calls, uninitialized storage, tx.origin auth

**High:** Flash loan vectors, oracle manipulation, missing access control, integer overflow (pre-0.8), unchecked return values, front-running

**Medium:** Centralization risks, missing events, floating pragma, gas griefing, DoS via unbounded loops, timestamp dependence

**Low:** Missing zero-address checks, dead code, naming conventions, missing NatSpec, gas optimization

### Step 3: DeFi Checks (if applicable)
- Infinite approvals, slippage protection, liquidity manipulation
- Governance attacks, ERC20/ERC721 compliance

### Step 4: Report

```markdown
## Web3 Audit: [contract]
### Overview
- File: [path] | Solidity: [version] | LoC: [count]
### Findings
#### [Severity] — [Title]
- **Location:** [file:line]
- **Code:** [snippet]
- **Issue:** [explanation]
- **Fix:** [corrected code]
### Summary
| Severity | Count |
|----------|-------|
### Recommendations
```
