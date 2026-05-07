---
description: Load bug bounty scope from platform (hackerone, bugcrowd)
argument-hint: <platform> <program_handle>
allowed-tools: [Bash, Read, Write, WebFetch]
---

## Arguments

The user invoked this command with: $ARGUMENTS

Parse the arguments as: <platform> <program_handle>
- First word = platform (hackerone or bugcrowd)
- Second word = program handle

## Instructions

Fetch and display the in-scope assets for the specified bug bounty program.

### For HackerOne programs:

1. Query the HackerOne GraphQL API:

```bash
curl -s https://hackerone.com/graphql -X POST \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -A 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' \
  -d '{"operationName":"PolicySearchStructuredScopes","variables":{"handle":"PROGRAM_HANDLE","eligibleForBounty":null,"eligibleForSubmission":null,"asmTagIds":[],"first":100},"query":"query PolicySearchStructuredScopes($handle:String!,$eligibleForBounty:Boolean,$eligibleForSubmission:Boolean,$asmTagIds:[Int],$first:Int){team(handle:$handle){structured_scopes_search(eligible_for_bounty:$eligibleForBounty,eligible_for_submission:$eligibleForSubmission,asm_tag_ids:$asmTagIds,first:$first){edges{node{...on StructuredScopeDocument{id,identifier,asset_type,availability_requirement,confidentiality_requirement,eligible_for_bounty,eligible_for_submission,instruction,integrity_requirement}}}}}}"}'
```

Replace PROGRAM_HANDLE with the actual handle from arguments.

2. If GraphQL fails, fall back to: `curl -s -L -A "Mozilla/5.0..." "https://hackerone.com/<handle>"`

3. Display scope as:
```
## Scope: <handle> (<platform>)
### In-Scope (Bounty Eligible)
| Asset | Type | Instructions |
|-------|------|--------------|
### In-Scope (No Bounty)
| Asset | Type | Instructions |
|-------|------|--------------|
### Out of Scope
```

4. Save in-scope domains to `/tmp/scope_targets.txt`
5. Summarize: total assets, bounty-eligible count, interesting targets

### For Bugcrowd:
Fetch `https://bugcrowd.com/<handle>` and extract scope.

### Errors:
- Missing args → show usage: `/scope <platform> <program_handle>`
- Not found → say so clearly
- Auth required → suggest manual check
