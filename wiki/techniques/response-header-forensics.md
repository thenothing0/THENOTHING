---
type: technique
aliases: ["header analysis", "x-unique-id", "internal IP extraction"]
tags: [recon, info-disclosure, headers]
created: 2026-05-30
updated: 2026-05-30
---
# Response Header Forensics

> Headers are consistently under-secured because they're invisible to most users.
> Yields 3-4 findings per target: internal IPs, LB pools, trace contexts, version leaks.

## When to use
On every live host, immediately after [[dns-first-recon]].

## Procedure
Capture full headers: `curl -sk -D- <URL>` (route through proxychains4/Tor if needed). Check:
- `x-unique-id` — hex-encoded internal IPs. Format `XXXXXXXX:PORT_..._TIMESTAMP_RANDOM`;
  decode bytes 0-3 of the server portion as hex octets. Send 3-5 requests to map the LB pool.
- `x-forwarded-for` (sometimes echoed), HTML comments (`<!-- ip-10-75-128-89.eu-west-1... -->`).
- `server` / `x-ta-timing` / `server-timing` / `traceresponse` — version & tracing leaks.
- `set-cookie` — audit HttpOnly / Secure / SameSite / Domain (build a 4-flag table).
- `access-control-allow-origin` + `-credentials` → hand off to [[cors-probing]].
- `x-amz-*` — AWS metadata / S3 backing.

## What "a hit" looks like
A decodable internal IP (10.40.x.x / 10.75.x.x), an LB pool, a precise server version, or a
session cookie missing HttpOnly.

## Severity & framing
Individually P4; chain into infra-map + cookie-table + CORS for P3, compliance for P2. See [[severity-calibration]].

## Evidence it works (real hits)
- [[tripadvisor]] — decoded 4 internal Viator IPs; Jetty/Tomcat/nginx version inventory; 10-cookie flag audit table.

## Pitfalls / false positives
- Internal IP behind a VPC limits impact — state that honestly in the report.

## Related
- Techniques: [[cors-probing]], [[progressive-auth-probing]] · Patterns: [[severity-calibration]]
