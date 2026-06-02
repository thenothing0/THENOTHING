# IDOR chained to privilege escalation and full account takeover

A high-value disclosure against an API. Technique reference: [[idor]].
See also [[ghost-technique]] (not yet in the wiki).

## Root cause
The API trusted a client-supplied `user_id` parameter without performing any
server-side authorization check, so any authenticated user could act as another.

## Trust boundary
The authorization decision was effectively made client-side; the backend never
re-validated object ownership.

## Impact
Full account takeover of any user. We then escalated privilege to an admin role,
giving complete tenant compromise.

## Attacker assumptions
The attacker only needs a low-privilege authenticated session.

This was a chained exploit: an IDOR pivoted into privilege escalation. Steps:
1. Enumerate `user_id` values via the `/users` endpoint
2. Replay the profile request with a victim `user_id` (IDOR)
3. Use the leaked session token to escalate privilege to admin

CVSS 9.1 (critical) — remote, unauthenticated impact after the initial foothold.
