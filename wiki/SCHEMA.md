# Bug Bounty Research Wiki — Schema & Conventions

> This is the **configuration layer**. It tells any LLM session how this wiki is
> structured and how to ingest sources, answer queries, and maintain the wiki.
> Read this file first before touching any other wiki page. Co-evolve it as the
> workflow improves.

This wiki adapts the "LLM Wiki" pattern (see `../CLAUDE1.md`) to offensive-security
research. It is the **synthesis layer** between raw engagement data and the operator.
It is *not* a dumping ground for scan output — that stays in `output/`.

---

## The three layers

| Layer | Where | Who owns it | Mutability |
|-------|-------|-------------|------------|
| **Raw sources** | `../output/<program>/`, `../scope.txt`, APK extractions, disclosed reports, recon dumps | The operator + tools | Immutable — read, never edit |
| **The wiki** | `wiki/` (this dir) | The LLM | Created & maintained by the LLM |
| **The schema** | this file | LLM + operator together | Co-evolved |

The LLM **never edits raw sources**. It reads `output/`, scan logs, APK strings, and
disclosed reports, then *compiles* the knowledge into interlinked wiki pages.

---

## Reader contract (READ THIS — non-negotiable)

**Any agent that reads this wiki must STORE and UNDERSTAND it — not skim it.** This wiki only
compounds if the robots reading it actually internalize and carry the knowledge forward.

At the **start of every session** that touches bug-bounty work, the reading agent must:

1. **Store it.** Load this `SCHEMA.md`, then `index.md`, then the pages relevant to the current
   target/task, into working context. Treat the wiki as **authoritative working knowledge** for
   the session — the same standing as operator memory and `CLAUDE.md`, not an optional reference.
2. **Understand it.** Synthesize what was read — *why* a technique works, *what* a target's weak
   spots are, *which* lessons (e.g. [[public-api-key-pitfall]]) forbid certain framings — before
   acting. If a page contradicts a plan, the plan changes. Do not act against recorded lessons.
3. **Keep it in sync (write-back).** When the session produces or learns something durable, write
   it back per the operations below, and reconcile with operator memory (`.claude/.../memory/`)
   so the two never drift. Knowledge gained that is not written down is considered lost.
4. **Verify before relying.** A page reflects what was true when written. If it names a host,
   endpoint, key, or version you're about to act on, re-confirm it still holds (scope, liveness)
   before trusting it — then update the page if reality changed.

A session that reads the wiki and neither internalizes nor updates it has failed the contract.

### Relationship to the other memory systems
- **`output/<program>/`** — raw artifacts and the full markdown bug-bounty reports the
  operator submits. The wiki *links to* these, it does not duplicate them.
- **`.claude/.../memory/`** — cross-session operator preferences and durable lessons
  (methodology, rejections). The wiki *embodies* those lessons as reusable technique and
  pattern pages, and links back conceptually. When a lesson is target-specific it lives in
  the wiki; when it's about how the operator wants work done it stays in memory.
- **Skills (`hydra/skills/`, `skills/`)** — executable methodology. Technique pages here
  are the *human-readable knowledge*; skills are the *automation*. Cross-reference both.

---

## Page types (node types)

Every page has a `type` in its frontmatter. Each type lives in its own directory and has a
template in `_templates/`. **Targets and techniques are the two co-equal hubs** — most links
flow into or out of one of them.

| `type` | Dir | What it is | Hub? |
|--------|-----|------------|------|
| `target` | `targets/` | A program/scope dossier (Tripadvisor, VK). Living picture of one engagement. | **Hub** |
| `technique` | `techniques/` | A reusable attack playbook (403 bypass, CORS probing, DNS-first recon). Target-agnostic. | **Hub** |
| `asset` | `assets/` | A notable host/API/subdomain/mobile-app worth its own page (big attack surface). Small assets stay as table rows inside a target page. | |
| `pattern` | `patterns/` | A cross-target vulnerability or *chaining* pattern, and severity-calibration knowledge (WAF-gap chain, public-API-key pitfall). | |
| `finding` | `findings/` | One of *our own* findings — suspected → confirmed → submitted → resolved. Links to the `output/` report. | |
| `intel` | `intel/` | Analysis of *external* disclosed reports / writeups (the pre-hunt research deliverable). What pays, recurring weaknesses, exclusions. | |
| `chain` | `chains/` | A multi-hop exploit chain built from confirmed findings (SSRF→Admin→RCE). | |
| `hypothesis` | `hypotheses/` | A falsifiable investigation candidate generated from intel/patterns — *not* a finding. Carries a confidence label and a validation plan; promotes to a `finding` only when confirmed. | |
| `observation` | `observations/` | The lowest tier: a raw, untrusted observation extracted from evidence. Promotes to `intel` once contextualized. (Phase A) | |
| `report` | `reports/` | Metadata + distilled lesson for one *external* disclosed report/writeup, carrying a `learning_score` (1-10). Distinct from `intel` (which is cross-report analysis). (Phase A) | |

---

## Machine tooling (Offensive Knowledge OS — Phase A)

The wiki is still **canonical and human-authored**, but it is now also **machine-operable**:

- `hydra.knowledge.wiki_store` parses/writes these pages (preserving unknown frontmatter); the
  `hydra.knowledge.schema` enums are the single contract for `type`, promotion `stage`, and `confidence`.
- `hydra.knowledge.graph_index` builds a **derived, rebuildable** graph from `[[wikilinks]]` (never authoritative —
  throw it away and rebuild any time). Queries: neighbors, shortest_path, attack_paths, related_{findings,patterns,chains}, orphans, dangling_links.
- `hydra.knowledge.promotion` enforces the hierarchy `observation→intel→hypothesis→finding→pattern→chain`:
  no stage-skipping, evidence mandatory, Two-Signal required for finding/pattern/chain, in-scope required for finding.
  `hypothesis→pattern` and `hypothesis→chain` are **forbidden** (validation is mandatory).
- `hydra.recon_fusion` turns multi-source recon into **Asset Intelligence** (`assets/` pages) with source-weighted,
  Two-Signal confidence; `hydra.capabilities` declares capability→source mappings (offline-first execution policy).
- MCP tools: `capability_list`, `capability_sources`, `recon_fuse`, `kb_recall`, `kb_lint`, `kb_promote`,
  `kb_rebuild_index`, `asset_lookup`, `graph_neighbors`, `graph_path`.

New frontmatter keys these tools may add: `stage`, `confidence`, `sources` (list of stable source ids),
`first_seen`/`last_seen`, `asset_type`, and on reports `learning_score`. Hand-authored keys are never dropped.

---

## Frontmatter conventions (YAML — powers Obsidian Dataview & graph)

Every page starts with frontmatter. Use only the keys relevant to the type.

```yaml
---
type: target | technique | asset | pattern | finding | intel | chain | hypothesis
aliases: []                 # alternate names for [[wikilinks]] resolution
tags: [recon, api, idor]    # freeform; lowercase-kebab
created: 2026-05-30
updated: 2026-05-30
# --- target / asset ---
platform: bugcrowd | standoff365 | hackerone | private
scope_status: in-scope | out-of-scope | unknown
# --- asset ---
target: "[[tripadvisor]]"   # parent program
host: api.viator.com
# --- finding ---
status: suspected | confirmed | submitted | accepted | rejected | na | duplicate
severity: P1 | P2 | P3 | P4 | P5   # Bugcrowd VRT, or critical/high/medium/low/info
report: "../output/tripadvisor/REPORT_09.md"   # path to the full report, if written
reward: ""                  # currency + amount once resolved
# --- chain ---
nodes: ["[[finding-x]]", "[[finding-y]]"]
# --- hypothesis ---
confidence: low | medium | high            # likelihood given current evidence
status: open | validating | confirmed | refuted
---
```

**Dates are absolute** (`2026-05-30`), never relative. Today's date comes from session context.

---

## Linking discipline (the whole point)

- Use **Obsidian `[[wikilinks]]`** everywhere: `[[tripadvisor]]`, `[[403-waf-bypass]]`.
  A link whose target doesn't exist yet is fine — it's a TODO marking a page worth creating.
- **Link liberally and bidirectionally in spirit.** A `finding` links its `target`, the
  `technique(s)` used, and any `pattern`/`chain` it belongs to. A `target` links its assets,
  findings, and the intel that informed it.
- Every **technique** page should link the findings/reports where it actually produced a hit
  (evidence that it works), and the targets it applies to.
- Every **pattern** page should link ≥2 findings/targets that exhibit it (a pattern needs
  examples).
- Keep an **orphan check** in mind: no page should have zero inbound links after lint.

---

## Evidence & honesty discipline (non-negotiable — inherited from CLAUDE.md)

This wiki is offensive-research knowledge; the same rigor as reporting applies.

1. **Never invent tool output.** Quote/paraphrase only from actual `output/` artifacts or
   real MCP responses. Cite the source path.
2. **Label confidence.** A `finding` is `suspected` until two independent signals confirm it
   (`confirmed`). Hypotheses get a **Hypothesis** heading and a "what would falsify this" line.
3. **Scope first.** Before adding any asset/finding, verify it against `../scope.txt` and set
   `scope_status`. Never create finding pages for out-of-scope hosts.
4. **Public-key pitfall.** A client-side/public API key is *never itself* a finding — only the
   sensitive data/functionality reachable *through* it is. See `[[public-api-key-pitfall]]`.
   Do not frame public keys as "broken access control."
5. **Rejection memory.** When a finding is marked N/A/rejected, update its page with `status`
   and a **Why rejected** note, and feed the lesson into the relevant `pattern`/`technique`
   page so the mistake isn't repeated.

---

## Operations

### Ingest (a new source → wiki)
Trigger: operator drops recon output / an APK extraction / a disclosed-report set / a finished
report into `output/` (or points at one) and says "ingest this."

1. **Read** the source. Identify which target it belongs to (or create the target page).
2. **Discuss** the 2-5 key takeaways with the operator before writing.
3. **Update the target dossier** — assets discovered, tech stack, WAF map, auth flows,
   credential inventory, attack-surface notes.
4. **Create/promote pages**: significant new asset → `asset` page; a confirmed/suspected vuln →
   `finding` page; a recurring observation → strengthen a `technique` or `pattern` page.
5. **Cross-link** everything per the linking discipline.
6. **Update `index.md`** (add/adjust catalog entries).
7. **Append to `log.md`** (`## [YYYY-MM-DD] ingest | <source> → <pages touched>`).

A single rich source (e.g. a full recon dump) may touch 8-15 pages. That's expected.

### Query (ask the wiki)
1. Read `index.md` first to locate relevant pages, then drill into them (and follow links).
2. Synthesize an answer **with citations to wiki pages and `output/` paths**.
3. **File good answers back** as a new page (usually a `pattern`, `chain`, or `intel` page) so
   the exploration compounds. Don't let a useful synthesis evaporate into chat.
4. Append a `query` line to `log.md` if the answer produced or changed a page.

### Hypothesize (intel → future investigation candidates)
Trigger: after ingesting a disclosed report / intel page, or on request. Knowledge should not
just be recorded — it should generate *next moves*.

1. Read the source intel/pattern. Ask the cross-target question: *can this technique/pattern
   apply to one of our in-scope targets?*
2. For each plausible answer, create a `hypotheses/` page from `_templates/hypothesis.md`:
   a falsifiable claim, the supporting evidence (cited), a **confidence** label, and a
   **scope-checked validation plan** (which MCP tools/techniques to run).
3. A hypothesis is **not a finding** — keep `status: open` until validated. Confirmed → promote
   to a `finding` page; refuted → record the lesson back into the relevant `pattern`/`technique`.
4. Cross-link to the intel/pattern it came from and the target it would test against.
5. Append a `hypothesize` entry to `log.md`.

### Lint (health-check)
Run periodically or on request. Look for:
- **Contradictions** between pages (e.g. two targets claim different WAF on a shared host).
- **Stale claims** a newer source superseded (decommissioned host now returning 200, etc.).
- **Orphans** — pages with no inbound `[[links]]`.
- **Missing pages** — concepts/assets referenced by `[[link]]` but never written.
- **Confidence drift** — `suspected` findings that have sat unconfirmed; `submitted` findings
  with no triage update.
- **Scope drift** — assets whose `scope_status` is `unknown` or may have changed.
- Suggest new questions to investigate and new sources to pull. Append a `lint` log entry.

---

## Naming & style

- Filenames: `lowercase-kebab-case.md`. Targets by short program name (`vk.md`,
  `tripadvisor.md`). Findings: `<target>-<short-slug>.md` (`vk-auth-validatephone-sms.md`).
- Keep pages **tight and skimmable** — tables for inventories (assets, cookies, WAF coverage,
  CORS behavior), prose only for reasoning. Triager-style clarity.
- One concept per page. If a target page grows huge, split big assets into `asset/` pages.
- Severity uses Bugcrowd VRT (`P1`–`P5`) for Bugcrowd targets; note reward tiers inline for
  Standoff 365 (₽ amounts) since they're program-specific.

---

## Quick map for a new session

1. Read this `SCHEMA.md`.
2. Read `index.md` for what exists.
3. Skim recent `log.md` entries for what happened lately.
4. Then ingest / query / lint as asked.
