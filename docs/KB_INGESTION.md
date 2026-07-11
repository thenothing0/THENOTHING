# Token-Efficient Report Ingestion — scaling the Knowledge OS to 1000 reports

This is the production pipeline for growing the disclosed-report knowledge base (`wiki/reports/`,
`wiki/intel/`, `wiki/patterns/`, `wiki/chains/`) from public HackerOne reports and high-quality
writeups **without burning the context window**.

## The core idea: keep documents out of the orchestrator

Every expensive operation (fetch a page, read its body, call `ingest_report` and read its large
echo) happens **inside a per-document Haiku subagent whose context is discarded**. Only a ~6-field
result object returns. So the main reasoning context does **not** grow with the corpus — report
#1000 costs the orchestrator the same as report #1.

```
 SEEDS ──▶ [dedup marker]──▶ [Haiku subagent: fetch · extract · ingest_report · mark] ──▶ {slug,vc,ls}
 (args)     fs, 0 LLM         isolated context, thrown away after                          compact
                                                          │
                                       ...one per URL, ~10–16 in parallel...
                                                          ▼
                              [1 driver agent] discover_patterns + discover_chains + confirm_candidate
                                              deterministic Python · compact summary out
```

## Components

| File | Role |
|---|---|
| `scripts/ingest_reports.workflow.js` | **Deep tier.** Fetch + schema-extract + `ingest_report` per URL in isolated Haiku subagents, then deterministic pattern/chain synthesis. Resumable via filesystem dedup markers. |
| `scripts/harvest_seeds.workflow.js` | Build `artifacts/seeds.jsonl` from the reddelexc HackerOne catalog CSV (+ extra indexes), tier-tagged `deep` vs `metadata`. Heavy parsing stays in one shell agent. |
| `scripts/ingest_metadata.workflow.js` | **Metadata tier.** Batched CSV-derived records → `ingest_report` (no fetch). Each subagent handles ~25 records. ~10× cheaper than deep tier. Same dedup markers. |
| `scripts/batch_metadata.workflow.js` | **Orchestrator.** Reads `seeds.jsonl`, filters metadata-tier, chunks, and calls `ingest-metadata` per chunk. One-liner to bank hundreds. |
| `artifacts/ingested/<sha1(url)>.done` | One marker file per ingested URL → idempotent, resumable batches. |

## Two-tier corpus (how you actually reach 1000)

Reaching 1000 with *deep* extraction on every doc is neither necessary nor affordable, and most
HackerOne report pages are JS-rendered (WebFetch returns only a shell — see Constraints). So:

- **Tier A — deep (~200–400 docs).** Genuinely fetchable writeups: Medium, `*.github.io`,
  security blogs, PortSwigger, HackTricks, infosecwriteups. Full methodology/payload/ATT&CK/
  detection extraction. This is where reusable *pattern* knowledge comes from.
- **Tier B — metadata (~600–800 docs).** The reddelexc `data.csv` catalog of disclosed H1
  reports: title + program + bounty + severity + weakness. Ingested as thin, **traceable**
  records with **no per-doc fetch**. Cheap, fast, and exactly what powers cross-report
  *statistics* (which classes/programs recur, bounty distributions) and the `discover_patterns`
  signal counts. Promote any Tier-B record to Tier-A later by feeding its URL through the deep
  pipeline (the marker makes that incremental).

1000 = a few hundred deep + the rest metadata. Both tiers land in the same `reports/`+`intel/`
structure and feed the same synthesis engine.

## Run it

```text
# 1a) Harvest seeds via workflow (writes artifacts/seeds.jsonl)
Workflow({ scriptPath: "scripts/harvest_seeds.workflow.js", args: { topN: 1000 } })
# 1b) OR harvest manually via bash+python (no LLM tokens — see scripts/harvest_seeds.workflow.js header for logic):
#     curl the CSV, sort by bounty, write seeds.jsonl — the workflow just automates this.

# 2) TIER B — Bank metadata records cheaply (no page fetch, ~10x cheaper than deep):
#    One-liner orchestrator (reads seeds.jsonl, chunks, ingests):
Workflow({ scriptPath: "scripts/batch_metadata.workflow.js", args: { limit: 200 } })
#    Or direct (pass records yourself):
Workflow({ scriptPath: "scripts/ingest_metadata.workflow.js",
           args: { seeds: [ {url,title,program,vuln_class,bounty,upvotes}, ... ], limit: 100 } })

# 3) TIER A — Deep-ingest fetchable writeup URLs (full extraction):
Workflow({ scriptPath: "scripts/ingest_reports.workflow.js",
           args: { seeds: [ "https://medium.com/...", ... ], model: "haiku", limit: 100 } })
```

Synthesis (`discover_patterns`/`discover_chains` → `confirm_candidate`) runs at the end of each
deep batch, and can also be run standalone any time — it is deterministic and re-detects existing
patterns as `strengthen_existing` (idempotent merge, no duplicates).

## Batching, resume, budget

- **Batch size 50–100 per invocation.** Concurrency is capped at ~10–16 subagents; the lifetime
  agent cap is 1000 per workflow run, so never put 1000 in a single `seeds`. ~10–20 batch
  invocations (or a scheduled loop) reach 1000.
- **Resume is free.** Re-running a batch re-pays nothing for already-marked URLs. Crash/stop mid-
  way → just re-invoke.
- **Budget guard.** Pass a turn budget (`+Nk`) and the workflow's `budget.remaining()` can gate
  how many seeds a single invocation processes; or cap with `args.limit`.

### Token math (deep tier) — MEASURED

A 6-seed validation batch (4 ingested, 2 failed) cost **544k subagent tokens across 7 agents** —
but the **orchestrator received only a ~300-token summary**. That is the whole point: the cost is
real, but it is paid in **cheap Haiku tokens inside disposable subagents**, and the main reasoning
context stays flat regardless of corpus size.

| | Naive (docs in main context) | This pipeline |
|---|---|---|
| Per deep doc | full page on the big model, **accumulates** every page + echo | ~90k **Haiku** tokens (fetch + `ingest_report` echo + extraction) in a **disposable** subagent |
| Orchestrator growth | linear in corpus → eventually overflows | ~flat — only `{slug,vc,ls}` per doc returns |
| Synthesis | full candidate JSON echoed each call | one compact summary |

Deep tier is **not free** (~90k Haiku tokens/doc) — it is *cheap and non-accumulating*. ~200 deep
docs ≈ ~18M Haiku tokens, fully parallel. **This is why Tier B matters:** metadata records skip the
fetch + echo entirely and are ~an order of magnitude cheaper, so the bulk of the 1000 should be
metadata, with deep extraction reserved for high-value fetchable writeups.

## Constraints (honest)

- **HackerOne report pages are not WebFetch-able** — they render via React and return only the
  string "HackerOne". Deep extraction therefore works on writeup *mirrors* (Medium/blogs/GitHub),
  not raw `hackerone.com/reports/*`. Those raw URLs go to **Tier B (metadata)**. (To deep-ingest
  H1 bodies you need the authenticated hacktivity GraphQL API or a logged-in fetch — out of scope
  for WebFetch; wire it in as an alternate fetch strategy if you have credentials.)
- **Never fabricate.** A subagent that gets an empty/blocked body returns `status:"failed"` — it
  does not invent payloads. Failures are logged, not hidden.
- **Classifier noise.** `ingest_report`'s auto vuln-class tagger is keyword-based and can mislabel
  (e.g. an OAuth catalog mentioning "XSS" → `xss`; a PortSwigger XXE page → `ssrf`). When a class
  should cluster but doesn't, the fix is at ingest time (clearer title/text, or extend the
  `tag_technique_vocab`), not by editing the wiki page after the fact — the synthesis signature is
  derived from the ingest-time store. For deterministic classes, set the extractor to put the
  class first in the title/text, or post-process with a fixed class allowlist.
- **Dedup keys on the URL marker, not the title.** `ingest_report` derives its slug from the
  *title*, so re-ingesting the same source under a drifted title creates a DUPLICATE page (observed:
  the Authentik writeup landed under two slugs when the Haiku title differed from the original). The
  `artifacts/ingested/<sha1(url)>.done` marker prevents this on re-runs — but only if every prior
  ingest created a marker. **Seed markers for any pages ingested outside this pipeline**, keep
  titles stable, and merge stragglers with `confirm_candidate` / manual edit.
