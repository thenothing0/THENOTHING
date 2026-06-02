# Skill: SQL Injection Hypothesis Engine

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `sql_injection_methodology` |
| **version** | `1.0.0` |
| **category** | Web / Database injection |
| **correlates_with** | ORM misuse, search filters, reporting exports, GraphQL resolvers |

## Objective
Treat SQLi as a **hypothesis graph**: error-based, boolean, time-based, stacked queries, second-order. Prioritize **evidence** (differentiable responses) over noisy scanning; align depth with **program rules** (many programs restrict `sqlmap`).

## Scope Rules
- No bulk data exfiltration; **column/row proof** only unless program permits.
- Avoid destructive statements (`DROP`, `DELETE`) always.
- Rate-limit; some programs ban automated SQLi tools—**follow program**.

## Trigger Conditions
- SQL errors in HTML/JSON, ODBC/JDBC traces.
- Numeric/string parameters driving `ORDER BY`, `WHERE`, `LIMIT`, reporting filters.
- Features: search, sort columns, export CSV, legacy admin panels.

## Technology Fingerprints
- DB errors: MySQL, Postgres, MSSQL, Oracle, SQLite.
- ORMs: Hibernate, Sequelize, Django ORM raw SQL hints.

## Recon Methodology
1. Parameter inventory + reflection of **syntax** characters.
2. Error oracle establishment (`'`, `"`, `)`, comment tokens).
3. Boolean differential design (length/body/hash stable comparisons).
4. Time-based as last resort (noisy; document baseline jitter).
5. Second-order: stored input executed later in query.

## MCP Tool Orchestration Logic
- `httpx_probe` — tech + status baseline.
- `nuclei_scan` — SQLi templates (signals).
- `sqlmap` **only if** MCP exposes it **and** program allows—else manual Burp-style.
- `ffuf_fuzz` — parameter names, throttled.

**Branching:** If WAF blocks quotes → pivot encoding, HPP, JSON/XML wrappers.

## Reasoning Heuristics
- Correlate **single quote** delta with **consistent** error class.
- Prefer **two** boolean states over one timing spike.
- ORM often → **parameter binding** elsewhere but raw fragments in `ORDER BY`.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Error-based disclosure |
| H2 | Boolean blind |
| H3 | Time-based blind |
| H4 | Second-order via stored profile/search |
| H5 | JSON SQLi / GraphQL → SQL layer |

## Validation Workflow
1. Minimal syntactic proof.
2. Controlled boolean pair.
3. Replay from clean state.
4. If time-based: baseline distribution + statistical threshold.

## False-Positive Reduction
- Scraping **static** SQL strings from JS ≠ SQLi.
- WAF replacement pages causing length changes—control with benign params.

## Stealth + OPSEC Guidance
- Slow timing probes; avoid long `SLEEP` storms; respect business hours if program asks.

## Replay Procedures
- Store raw requests; annotate which hypothesis each request tests.

## Evidence Requirements
- Error snippet or boolean pair diff; no unnecessary table dumps.

## Reporting Methodology
- Parameter + query context; ORM vs raw SQL; parameterized fix; least privilege.

## Confidence Scoring Logic
- Error with clear SQL grammar: **0.9**; single ambiguous 500: **≤0.4**.

## Adaptive Branching Logic
- **API-only** → JSON bodies, array params, `sort=` injection.
- **Search** → `MATCH`/fulltext dialect specifics.

## Related Exploit Chains
- `skills/api/graphql_introspection_abuse.md`
- `skills/ssrf/chained_ssrf.md` (DB via cloud misconfig is separate chain)

## Safety Boundaries
No destructive queries; no PII exfiltration beyond proof row.

## Output Artifact Requirements
`output/<target_slug>/sqli/` — `hypothesis_matrix.md`, `pairs/`, `replay.md`
