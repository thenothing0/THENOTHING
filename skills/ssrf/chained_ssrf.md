# Skill: Chained SSRF Methodology

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `chained_ssrf` |
| **version** | `1.0.0` |
| **category** | Web / Server-side request abuse |
| **correlates_with** | Open redirects, cloud metadata, internal port scan, cache layers |

## Objective
Find and validate **server-side request forgery** and **request routing abuse** where the application fetches attacker-influenced URLs. Reason about **second-hop** impact (metadata, internal APIs, cache) and prove reachability with **minimal** internal touch—only where explicitly in scope.

## Scope Rules
- Never target **out-of-scope** internal networks, third-party SaaS, or government/critical infra without written authorization.
- Cloud metadata probes (`169.254.169.254`, etc.) are **high sensitivity**—document intent, get program approval, and prefer **read-only** proof.
- Respect **safe harbor** and program bans on “internal network access” categories.

## Trigger Conditions
- URL parameters: `url`, `uri`, `path`, `dest`, `redirect`, `webhook`, `fetch`, `import`, `load`, `avatar`, `pdf`, `preview`.
- Features: SSR proxies, PDF generators, image optimizers, webhook testers, “health check” fetchers.
- GraphQL/file resolvers that pull remote resources.

## Technology Fingerprints
- **Cloud:** AWS, GCP, Azure (metadata headers, IMDSv2 behavior).
- **Stacks:** Java `HttpURLConnection`, Node `axios`/`fetch`, Python `requests`, PHP `file_get_contents`, Go `http.Client`.
- **Defenses:** URL blocklists, DNS rebinding mitigations, egress proxies, signed URL requirements.

## Recon Methodology
1. Inventory every **outbound fetch** feature from crawl + code hints (error messages, OpenAPI).
2. Classify **parser vs resolver** (SSRF vs open redirect vs DNS pinning issues).
3. Map **URL parser differential** (IPv6, `@`, unicode, scheme smuggling).
4. Identify **blind** signals: timing, DNS callback correlation (only if program allows OAST).
5. Layer **cache/CDN** behavior if responses might be stored or coalesced.

## MCP Tool Orchestration Logic
| Phase | Tools | Logic |
|--------|--------|--------|
| Surface | `katana_crawl`, `httpx_probe`, `gau_urls` | Find URL-like params and API fields. |
| Fingerprint | `whatweb_detect`, `wafw00f_detect` | Adjust aggressiveness. |
| Templates | `nuclei_scan` (SSRF tags) | Hypothesis generation, not final proof. |
| Manual/OAST | Program-approved callback only | Blind confirmation path. |

**Branching:** If **no OAST** allowed → rely on timing/error differential and in-scope collaborator endpoints only.

## Reasoning Heuristics
- Prefer **parser confusion** over brute IP lists when WAF blocks literals.
- Ask: does the server follow **302** to internal? Split **DNS vs HTTP** phase.
- Correlate **response length/timing** with `127.0.0.1` vs dead IP—careful with rate.
- For **cloud**, reason IMDSv2 vs v1; headers like `Metadata-Flavor: Google`.

## Attack-Path Hypotheses
| ID | Hypothesis | Notes |
|----|----------------|-------|
| H1 | Basic URL to internal service | Filter bypass needed |
| H2 | Metadata credential exposure | Often critical; confirm redaction rules |
| H3 | Protocol smuggle (`gopher`/`dict` disabled) | Stack-dependent |
| H4 | SSRF → cache poisoning / header injection | Multi-hop chain |
| H5 | Blind SSRF + internal API chaining | Map graph only in-scope |

## Validation Workflow
1. Prove **server** initiated request (collaborator hit, timing, or unique error).
2. **Minimize** data read from internal—metadata snippets per program rules.
3. Replay with **control** URL proving absence of behavior.
4. Document **defense** expectations (blocklist, SSRF proxy).

## False-Positive Reduction
- Open redirect alone ≠ SSRF; prove **server-side** fetch.
- Outbound 200 to public URL with reflected body ≠ SSRF.
- Scanner “SSRF” on static marketing sites—discard without parser proof.

## Stealth + OPSEC Guidance
- Low QPS; avoid sweeping internal ranges.
- Do not exfiltrate **secrets** to external paste bins—keep in vault + report channel.

## Replay Procedures
- Curl repro of the triggering request; redact tokens.
- If multi-step, include token refresh and ordering.

## Evidence Requirements
- Request proving SSRF primitive.
- Proof of server-side initiation (callback log or differential).
- Impact narrative tied to **in-scope** assets.

## Reporting Methodology
- Clear boundary: what was accessed vs only probed.
- Remediation: disable raw URL fetch, allowlist hosts, network egress controls, metadata hardening.

## Confidence Scoring Logic
- Base 0.45; +0.25 confirmed server fetch; +0.15 limited internal read in-scope; −0.2 if only redirect without fetch proof.
- Submission-grade ≥ **0.80** when impact and server initiation are both solid.

## Adaptive Branching Logic
- **WAF/CDN** → parser/encoding branches; reduce IP sweep.
- **Blind-only** → timing + OAST if permitted.
- **GraphQL** → batch resolver abuse path if introspection or field errors suggest fetches.

## Related Exploit Chains
- `skills/cloud/aws_privilege_escalation.md` (metadata path)
- `skills/cache_poisoning/web_cache_poisoning.md`

## Safety Boundaries
No lateral movement outside scope; no destructive internal calls; no dumping full cloud identity—minimal proof only.

## Output Artifact Requirements
`output/<target_slug>/ssrf/` — `requests.txt`, `callback_log.txt` (if any), `impact.md`, `confidence.md`
