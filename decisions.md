# Technical Decisions

## Methodology
- **MCP-first execution**: all recon/scans through hydra-security MCP tools, not ad-hoc shell commands
- **Validation-first reporting**: scanner output = hypothesis. Require 2 independent signals before claiming a vuln
- **Honest assessment in every report**: explicit "what this IS" / "what this is NOT" sections prevent overclaiming
- **Pre-hunt research**: study disclosed reports on target's platform before any scanning
- **Differential testing**: prove impact by comparing (e.g., internal vs public API), not just "it exists"

## Reporting
- **Always attach visual proof**: screenshot/video with every submission on every platform. Prepare proof BEFORE writing the report
- **Chain to impact**: bare info-disclosure/enumeration rarely pays. Only submit when you can show business impact or chain to higher severity
- **Withdraw overclaims**: if re-testing disproves a claim, retract it immediately. Credibility > volume

## Target Selection
- **VK via Standoff 365**: high payouts (RCE ₽3.6M, Privacy ₽3M). Focus on auth/API abuse, not info-disclosure
- **Tripadvisor via Bugcrowd**: 4-tier scope. CDE payment APIs highest payout ($5K). Subsidiaries (Bokun, Viator) are softer targets
- **Ozon via Standoff 365**: ₽21M total paid, avg ₽60K. Scoped, not started. High potential
- **Tesla via Bugcrowd**: passive recon only so far. Heavy security posture, low-yield without deep investment

## Architecture
- **THENOTHING v7.1**: 22 cognitive subsystems, 9-phase reasoning loop. MCP server with 22 tools
- **Wiki knowledge base**: LLM-maintained at `wiki/`, schema at `wiki/SCHEMA.md`. Ingest/query/lint pattern
- **Memory system**: persistent file-based at `.claude/projects/.../memory/`. Indexed via `MEMORY.md`
- **Output structure**: `output/<target>/` with `REPORT_*.md` files per finding

## Lessons (decisions from failures)
- **Public API keys ≠ vuln**: Tripadvisor key `adf6d1b8-...` is public by design. Only data exposed THROUGH a key matters
- **Two-endpoint OAuth**: UI page reflecting redirect_uri ≠ exploitable if the code-issuing endpoint validates separately (VK R2)
- **"Internal" hostnames**: being reachable ≠ vulnerability without differential access (VK R1)
- **CAPTCHA awareness**: always test rate-limiting behavior before claiming "no rate limit" (VK R6)
