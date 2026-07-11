// ingest_reports.workflow.js — token-efficient bulk ingestion for the hydra-security Knowledge OS.
//
// WHY THIS IS CHEAP:
//   - Every heavy step (fetch the page, read its full body, call ingest_report and read its
//     large echo) happens INSIDE a per-document Haiku subagent whose context is thrown away.
//     Only a ~6-field result object ever returns to the orchestrator, so the main context does
//     NOT grow with the corpus — doc #1000 costs the same orchestrator tokens as doc #1.
//   - A filesystem dedup marker (one tiny file per URL) makes the whole thing RESUMABLE and
//     idempotent: re-running a batch re-pays nothing for URLs already ingested.
//   - Pattern/chain synthesis is deterministic Python (discover_patterns/confirm_candidate);
//     one cheap agent drives it and returns a compact summary, never the raw candidate JSON.
//
// USAGE (from the Workflow tool):
//   Workflow({ scriptPath: ".../scripts/ingest_reports.workflow.js",
//              args: { seeds: ["https://...","https://..."], model: "haiku", limit: 100 } })
//   Re-invoke with the next batch of seeds to grow toward 1000; done URLs auto-skip.
//
// args:
//   seeds  : string[]  REQUIRED — writeup URLs to ingest (fetchable HTML/markdown).
//   model  : string    extraction model for the per-doc map step (default "haiku").
//   limit  : number    cap how many seeds this invocation processes (default: all).
//   synth  : boolean   run pattern/chain synthesis after ingest (default true).

export const meta = {
  name: 'ingest-reports',
  description: 'Token-efficient bulk ingestion of public security writeups into the Knowledge OS: filesystem dedup gate -> per-doc fetch+extract+ingest in isolated Haiku subagents -> deterministic pattern/chain synthesis. Only compact results reach the orchestrator.',
  whenToUse: 'Grow the disclosed-report knowledge base from a list of fetchable writeup URLs; re-run batches to scale to 1000.',
  phases: [
    { title: 'Ingest', detail: 'one Haiku subagent per URL: dedup-marker, fetch, schema extract, ingest_report, mark', model: 'haiku' },
    { title: 'Synthesize', detail: 'discover_patterns + discover_chains, confirm strong candidates' }
  ]
}

// ---- inputs ---------------------------------------------------------------
const allSeeds = Array.isArray(args && args.seeds) ? args.seeds
               : (Array.isArray(args) ? args : [])
const model = (args && args.model) || 'haiku'
const doSynth = !(args && args.synth === false)
const limit = (args && Number(args.limit)) || allSeeds.length
const seeds = allSeeds.slice(0, limit)

if (!seeds.length) { log('no seeds provided — pass args.seeds = [urls]'); return { error: 'no_seeds' } }
log(seeds.length + ' seed URL(s); extract model=' + model + (doSynth ? '; +synthesis' : ''))

// ---- compact result schemas (bound subagent output) -----------------------
const INGEST_RESULT = {
  type: 'object', additionalProperties: false,
  properties: {
    url: { type: 'string' },
    status: { type: 'string', enum: ['ok', 'skipped', 'failed'] },
    slug: { type: 'string' },
    vuln_class: { type: 'string' },
    learning_score: { type: 'number' },
    reason: { type: 'string' }
  },
  required: ['url', 'status']
}

const SYNTH_RESULT = {
  type: 'object', additionalProperties: false,
  properties: {
    patterns: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false,
        properties: {
          slug: { type: 'string' },
          confidence: { type: 'string' },
          sources: { type: 'number' },
          action: { type: 'string' }   // create_new | strengthen_existing
        },
        required: ['slug']
      }
    },
    chains: {
      type: 'array',
      items: { type: 'object', additionalProperties: false, properties: { slug: { type: 'string' } }, required: ['slug'] }
    },
    notes: { type: 'string' }
  },
  required: ['patterns']
}

// ---- per-document map step (runs in an isolated, disposable subagent) ------
const ingestPrompt = (url) => [
  'You ingest exactly ONE public security writeup into the hydra-security Knowledge OS.',
  'Be terse. NEVER echo the page body back in your final answer — return only the result object.',
  '',
  'TARGET URL: ' + url,
  '',
  'STEP 1 — dedup marker (skip work already done). Run bash:',
  '  h=$(printf %s ' + JSON.stringify(url) + ' | sha1sum | cut -c1-16); m="artifacts/ingested/$h.done"; if test -f "$m"; then echo ALREADY_DONE; else echo NEW; fi',
  '  If it prints ALREADY_DONE -> return {"url":"'+url+'","status":"skipped"} and STOP.',
  '',
  'STEP 2 — fetch (WebFetch) asking ONLY for: title; program/target; vulnerability class;',
  '  step-by-step exploitation methodology; exact payloads/endpoints; root cause; impact;',
  '  MITRE ATT&CK technique IDs; detection opportunities; remediation.',
  '  If the page is JS-rendered / a blocked shell / empty (e.g. body is just a site name) OR the',
  '  fetch errors, return {"url":"'+url+'","status":"failed","reason":"unfetchable"} and STOP.',
  '  Never invent content not present in the page.',
  '',
  'STEP 3 — ingest. Call the hydra-security MCP tool ingest_report with:',
  '  text = the structured extraction from step 2 (root cause, methodology steps, payloads,',
  '         impact, ATT&CK, detection, remediation, lesson);',
  '  source_url = ' + JSON.stringify(url) + ';',
  '  title = a concise descriptive title (include the platform + report id if the URL has one);',
  '  target = the program/product slug (lowercase-kebab) or "methodology" for general writeups.',
  '',
  'STEP 4 — mark done. Run bash:',
  '  mkdir -p artifacts/ingested && touch "$m"',
  '',
  'STEP 5 — return {"url","status":"ok","slug":<ingest slug>,"vuln_class":<ingest vuln_class>,',
  '  "learning_score":<ingest learning_score>}.'
].join('\n')

phase('Ingest')
const results = await pipeline(
  seeds,
  (url, _orig, i) => agent(ingestPrompt(url), {
    model, schema: INGEST_RESULT, effort: 'low',
    label: 'ingest#' + (i + 1), phase: 'Ingest'
  })
)

const ok = results.filter(r => r && r.status === 'ok')
const skipped = results.filter(r => r && r.status === 'skipped')
const failed = results.filter(r => !r || r.status === 'failed')
log('ingested=' + ok.length + '  skipped=' + skipped.length + '  failed=' + failed.length)

// ---- reduce step: deterministic synthesis, one cheap driver agent ---------
let synthesis = null
if (doSynth && ok.length) {
  phase('Synthesize')
  synthesis = await agent([
    'Synthesize cross-report knowledge in the hydra-security Knowledge OS. Be terse; do NOT echo raw candidate JSON.',
    '1) Call discover_patterns with min_support=2 and discover_chains with min_support=2.',
    '2) For every candidate that is confidence "high" or "medium" AND has >=2 independent sources,',
    '   call confirm_candidate(candidate_type, candidate_id) to materialize/merge it.',
    '3) Return a compact summary per the schema: each confirmed pattern (slug, confidence, source count,',
    '   create_new|strengthen_existing) and chain (slug), plus a one-line notes field.'
  ].join('\n'), { model: 'sonnet', effort: 'low', schema: SYNTH_RESULT, phase: 'Synthesize' })
}

return {
  seeds: seeds.length,
  ingested: ok.length,
  skipped: skipped.length,
  failed: failed.length,
  ok: ok.map(r => ({ slug: r.slug, vuln_class: r.vuln_class, learning_score: r.learning_score })),
  failures: failed.map(r => (r && r.url) || 'unknown'),
  synthesis
}
