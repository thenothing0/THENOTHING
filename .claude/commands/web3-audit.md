# Web3 Smart Contract Security Audit

Perform a security audit on a Solidity/Vyper smart contract.

$ARGUMENTS — path to the contract file or directory (e.g., "contracts/Vault.sol")

## Instructions

You are performing a security audit on: $ARGUMENTS

### Step 1: Load the Contract
1. Read the specified file(s)
2. If a directory is given, find all .sol and .vy files recursively
3. Identify the contract's purpose, dependencies, and inheritance chain

### Step 2: Static Analysis

Check for these vulnerability classes:

**Critical**
- Reentrancy: external calls before state updates
- Unprotected selfdestruct/delegatecall
- Arbitrary external call targets
- Uninitialized storage pointers
- tx.origin authentication

**High**
- Flash loan attack vectors
- Oracle manipulation (single-source price feeds)
- Missing access control on sensitive functions
- Integer overflow/underflow (pre-0.8.0)
- Unchecked return values on external calls
- Front-running / sandwich attack exposure

**Medium**
- Centralization risks (owner can rug)
- Missing event emissions on state changes
- Floating pragma versions
- Gas griefing vectors
- Denial of service via unbounded loops
- Timestamp dependence

**Low**
- Missing zero-address checks
- Redundant code / dead code
- Non-standard naming conventions
- Missing NatSpec documentation
- Suboptimal gas usage

### Step 3: DeFi-Specific Checks (if applicable)
- Token approval patterns (infinite approvals)
- Slippage protection
- Liquidity manipulation vectors
- Governance attack vectors (flash loan + vote)
- ERC20/ERC721 compliance

### Step 4: Report

```markdown
## Web3 Security Audit: [contract name]

### Contract Overview
- **File:** [path]
- **Solidity Version:** [version]
- **Purpose:** [what the contract does]
- **Dependencies:** [imported contracts/libraries]
- **Lines of Code:** [count]

### Findings

#### [Severity] — [Title]
- **Location:** [file:line_number]
- **Code:**
  ```solidity
  [vulnerable code snippet]
  ```
- **Issue:** [explanation]
- **Impact:** [what could go wrong]
- **Fix:**
  ```solidity
  [corrected code]
  ```

### Summary
| Severity | Count |
|----------|-------|
| Critical | [n]   |
| High     | [n]   |
| Medium   | [n]   |
| Low      | [n]   |

### Recommendations
[prioritized list of fixes]
```

### Notes
- Only audit contracts you have permission to review
- Never deploy or interact with mainnet contracts
- Flag any upgradeable proxy patterns for special attention
- Check for known vulnerable dependency versions (OpenZeppelin, etc.)
