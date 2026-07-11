// ingest_metadata.workflow.js — Tier B: cheap metadata-only ingestion (no page fetch).
//
// Takes CSV-derived seed records (title/program/vuln_class/severity/bounty/url) and ingests each
// as a thin, traceable report+intel page via ingest_report. NO WebFetch — the text is synthesized
// from the structured fields. ~10x cheaper than deep tier because there's no page body to process.
//
// This is what banks 600–800 reports cheaply. Each record still feeds discover_patterns signal
// counts, cross-report statistics, and can be PROMOTED to deep tier later by running its URL
// through ingest_reports.workflow.js (the dedup marker makes that incremental).
//
// args:
//   seeds    : object[] REQUIRED — array of {url, title, program, vuln_class, bounty, upvotes}
//   limit    : number   cap how many seeds to process (default: all)
//   synth    : boolean  run pattern/chain synthesis after ingest (default true)
//   batchSize: number   seeds per subagent (default 25 — each agent ingests multiple records)

export const meta = {
  name: 'ingest-metadata',
  description: 'Tier B bulk metadata ingestion: CSV-derived report records -> ingest_report (no fetch) -> pattern/chain synthesis. ~10x cheaper than deep tier.',
  whenToUse: 'Bank hundreds of HackerOne report metadata records cheaply to power cross-report statistics and pattern signal counts.',
  phases: [
    { title: 'Ingest', detail: 'batched metadata records -> ingest_report (no fetch)', model: 'haiku' },
    { title: 'Synthesize', detail: 'discover_patterns + discover_chains on the enlarged corpus' }
  ]
}

const allSeeds = Array.isArray(args && args.seeds) ? args.seeds : []
const limitN = (args && Number(args.limit)) || allSeeds.length
const doSynth = !(args && args.synth === false)
const batchSize = (args && Number(args.batchSize)) || 25
const seeds = allSeeds.slice(0, limitN)

if (!seeds.length) { log('no seeds — pass args.seeds = [{url,title,program,...}]'); return { error: 'no_seeds' } }
log(seeds.length + ' metadata seed(s), batchSize=' + batchSize + (doSynth ? ', +synthesis' : ''))

const BATCH_RESULT = {
  type: 'object', additionalProperties: false,
  properties: {
    ingested: { type: 'number' },
    skipped: { type: 'number' },
    failed: { type: 'number' },
    slugs: { type: 'array', items: { type: 'string' } },
    errors: { type: 'array', items: { type: 'string' } }
  },
  required: ['ingested', 'skipped', 'failed']
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
          action: { type: 'string' }
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

// Split seeds into batches — each subagent handles multiple records to reduce agent overhead
const batches = []
for (let i = 0; i < seeds.length; i += batchSize) {
  batches.push(seeds.slice(i, i + batchSize))
}
log(batches.length + ' batch(es) of up to ' + batchSize + ' records each')

// Build the prompt for a batch of metadata records
const batchPrompt = (batch) => {
  const records = batch.map((s, i) => {
    const vc = s.vuln_class || 'unknown'
    const bounty = s.bounty || 0
    const program = s.program || 'unknown'
    const title = s.title || 'Untitled'
    const url = s.url || ''
    const upvotes = s.upvotes || 0
    return `RECORD ${i+1}:\n  url: ${url}\n  title: ${title}\n  program: ${program}\n  vuln_class: ${vc}\n  bounty: $${bounty}\n  upvotes: ${upvotes}`
  }).join('\n\n')

  return [
    'You ingest METADATA-ONLY report records into the hydra-security Knowledge OS.',
    'Each record is a disclosed HackerOne report — NO page fetch needed.',
    'Be TERSE. Never echo large outputs back.',
    '',
    'For EACH record below:',
    '',
    '1) DEDUP CHECK — run bash:',
    '   h=$(printf "%s" "<url>" | sha1sum | cut -c1-16); m="artifacts/ingested/$h.done"',
    '   if test -f "$m"; then skip this record (count as skipped). else continue.',
    '',
    '2) INGEST — call the hydra-security MCP tool ingest_report with:',
    '   title = the record title',
    '   source_url = the record url',
    '   target = the program name (lowercase-kebab)',
    '   text = a compact structured summary like:',
    '     "Disclosed HackerOne report. Program: <program>. Vulnerability class: <vuln_class>.',
    '      Bounty: $<bounty>. Upvotes: <upvotes>. Title: <title>.',
    '      This is a metadata-tier record from the HackerOne disclosed reports catalog.',
    '      Promote to deep-tier by fetching the full writeup for detailed methodology extraction."',
    '',
    '3) MARK DONE — run bash: mkdir -p artifacts/ingested && touch "$m"',
    '',
    '4) After processing ALL records, return the result object:',
    '   ingested = count of successfully ingested records',
    '   skipped = count of already-done records',
    '   failed = count of errors',
    '   slugs = array of created slug strings',
    '   errors = array of error descriptions (if any)',
    '',
    '--- RECORDS TO PROCESS ---',
    '',
    records
  ].join('\n')
}

phase('Ingest')
const results = await pipeline(
  batches,
  (batch, _orig, i) => agent(batchPrompt(batch), {
    model: 'haiku', schema: BATCH_RESULT, effort: 'low',
    label: 'meta-batch#' + (i + 1) + ' (' + batch.length + ')', phase: 'Ingest'
  })
)

// Aggregate
let totalIngested = 0, totalSkipped = 0, totalFailed = 0
const allSlugs = [], allErrors = []
for (const r of results) {
  if (!r) { totalFailed += batchSize; continue }
  totalIngested += (r.ingested || 0)
  totalSkipped += (r.skipped || 0)
  totalFailed += (r.failed || 0)
  if (r.slugs) allSlugs.push(...r.slugs)
  if (r.errors) allErrors.push(...r.errors)
}
log('metadata ingest done: ingested=' + totalIngested + ' skipped=' + totalSkipped + ' failed=' + totalFailed)

// Synthesis
let synthesis = null
if (doSynth && totalIngested > 0) {
  phase('Synthesize')
  synthesis = await agent([
    'Synthesize cross-report knowledge in the hydra-security Knowledge OS. Be terse.',
    '1) Call discover_patterns with min_support=2 and discover_chains with min_support=2.',
    '2) For every candidate with confidence "high" or "medium" AND >=2 independent sources,',
    '   call confirm_candidate(candidate_type, candidate_id) to materialize/merge it.',
    '3) Return a compact summary per the schema.'
  ].join('\n'), { model: 'sonnet', effort: 'low', schema: SYNTH_RESULT, phase: 'Synthesize' })
}

return {
  seeds: seeds.length,
  ingested: totalIngested,
  skipped: totalSkipped,
  failed: totalFailed,
  slugs_sample: allSlugs.slice(0, 20),
  errors: allErrors.slice(0, 10),
  synthesis
}
