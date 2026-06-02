# Missing X-Frame-Options header on marketing page

## Impact
The marketing site does not set the `X-Frame-Options` response header. This is an
informational, low-impact observation and is a duplicate of an already reported,
already known issue. Trivial to remediate.

## Notes
No authentication, no data exposure, no escalation. Minor hardening item only.
