# Fetch Bug Bounty Scope

Fetch and display the in-scope assets for a bug bounty program.

## Usage

/scope <platform> <program_handle>

Supported platforms: hackerone, bugcrowd

## Arguments

$ARGUMENTS — expects: <platform> <program_handle>
Example: hackerone coupang_tw

## Instructions

You are fetching the bug bounty program scope for the given target.

### For HackerOne programs:

1. Use curl to query the HackerOne GraphQL API for structured scopes:

```bash
curl -s https://hackerone.com/graphql -X POST \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -A 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' \
  -d '{"operationName":"PolicySearchStructuredScopes","variables":{"handle":"<PROGRAM_HANDLE>","eligibleForBounty":null,"eligibleForSubmission":null,"asmTagIds":[],"first":100},"query":"query PolicySearchStructuredScopes($handle:String!,$eligibleForBounty:Boolean,$eligibleForSubmission:Boolean,$asmTagIds:[Int],$first:Int){team(handle:$handle){structured_scopes_search(eligible_for_bounty:$eligibleForBounty,eligible_for_submission:$eligibleForSubmission,asm_tag_ids:$asmTagIds,first:$first){edges{node{...on StructuredScopeDocument{id,identifier,asset_type,availability_requirement,confidentiality_requirement,eligible_for_bounty,eligible_for_submission,instruction,integrity_requirement}}}}}}"}'
```

2. If the GraphQL query fails or returns empty, fall back to fetching the program page:

```bash
curl -s -L -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" "https://hackerone.com/<PROGRAM_HANDLE>"
```

3. Parse and display the scope in this format:

```
## Scope: <program_handle> (<platform>)

### In-Scope Assets (Eligible for Bounty)
| Asset | Type | Instructions |
|-------|------|--------------|
| *.example.com | URL | ... |

### In-Scope Assets (Not Eligible for Bounty)
| Asset | Type | Instructions |
|-------|------|--------------|

### Out of Scope
[list any out-of-scope items mentioned]
```

4. After displaying the scope, save the in-scope domains/URLs to `/tmp/scope_targets.txt` (one per line) so they can be used by recon tools.

5. Summarize: total assets in scope, how many are bounty-eligible, and suggest which targets look most interesting for testing.

### For Bugcrowd programs:

1. Fetch the program page from `https://bugcrowd.com/<PROGRAM_HANDLE>` and extract scope information.
2. Display in the same table format as above.

### Error handling:

- If the program is not found, say so clearly.
- If the API requires authentication, note that and suggest the user check the program page manually.
- If arguments are missing, show usage: `/scope <platform> <program_handle>`
