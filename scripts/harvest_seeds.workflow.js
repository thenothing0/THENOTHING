// harvest_seeds.workflow.js — build a deduped seed list for KB ingestion, cheaply.
//
// Pulls curated public-report indexes (default: the reddelexc/hackerone-reports data.csv, a
// community catalog of thousands of disclosed H1 reports with title/program/bounty/severity/
// weakness) plus any extra fetchable index URLs you pass, normalizes them to seed records, tags
// each with a TIER, dedups, and writes artifacts/seeds.jsonl. The big CSV + parsing live inside
// ONE shell-driven agent; only a compact summary returns to the orchestrator.
//
// TIER tagging (drives how ingest treats each record):
//   deep     -> fetchable writeup domains (medium.com, *.github.io, infosecwriteups, blog.*,
//               portswigger, hacktricks, *.substack, personal blogs) -> full fetch+extract.
//   metadata -> hackerone.com/reports/* (JS-rendered, not WebFetch-able) -> ingest title+
//               program+bounty+severity+weakness as a thin, traceable record (no fetch).
//
// args:
//   topN      : number  keep the top-N reports by bounty/popularity (default 1000).
//   csvUrl    : string   override the catalog CSV (default reddelexc data.csv on raw.githubusercontent).
//   extra     : string[] extra fetchable INDEX/list URLs to scrape for writeup links (optional).
//   out       : string   output path (default artifacts/seeds.jsonl).

export const meta = {
  name: 'harvest-seeds',
  description: 'Harvest and dedup a seed list of public security reports (HackerOne catalog CSV + extra indexes) into artifacts/seeds.jsonl, tier-tagged deep vs metadata. Heavy parsing stays in one shell agent; only a summary returns.',
  whenToUse: 'Before bulk ingestion, to assemble up to ~1000 seed report URLs without loading them into context.',
  phases: [{ title: 'Harvest', detail: 'curl the catalog, sort/dedup/tier, write seeds.jsonl' }]
}

const topN = (args && Number(args.topN)) || 1000
const csvUrl = (args && args.csvUrl) || 'https://raw.githubusercontent.com/reddelexc/hackerone-reports/master/data.csv'
const extra = Array.isArray(args && args.extra) ? args.extra : []
const out = (args && args.out) || 'artifacts/seeds.jsonl'

const SUMMARY = {
  type: 'object', additionalProperties: false,
  properties: {
    harvested: { type: 'number' },
    deep: { type: 'number' },
    metadata: { type: 'number' },
    by_class: { type: 'string' },     // compact "ssrf:42, idor:88, ..." string, not a big object
    out: { type: 'string' },
    sample: { type: 'array', items: { type: 'string' } }  // first ~5 urls
  },
  required: ['harvested', 'out']
}

phase('Harvest')
const summary = await agent([
  'Build a deduped, tier-tagged seed list for KB ingestion. Be terse; do NOT echo the CSV or URL lists back.',
  '',
  '1) Fetch the catalog CSV with shell (curl -s ' + JSON.stringify(csvUrl) + '). It has columns including a report URL,',
  '   title, program/handle, bounty, upvotes, and weakness/vuln-type.',
  '2) Parse with shell/python: sort by bounty (then upvotes) descending, keep the top ' + topN + ' rows.',
  '3) For each kept row emit one JSON object per line: {"url","title","program","vuln_class","severity","bounty","tier"}.',
  '   tier="metadata" when url host is hackerone.com; tier="deep" for any other (fetchable) host.',
  extra.length ? ('4) Also scrape these extra fetchable index URLs for writeup links and add them as tier="deep" rows: ' + extra.join(', ') + '.') : '4) (no extra indexes)',
  '5) Dedup by url. Write all lines to ' + JSON.stringify(out) + ' (mkdir -p its dir first).',
  '6) Return the compact summary: total harvested, count of deep vs metadata, a short "by_class" string',
  '   (e.g. "ssrf:40, idor:120, xss:200"), the out path, and the first 5 urls as sample.'
].join('\n'), { model: 'haiku', effort: 'low', schema: SUMMARY, phase: 'Harvest' })

return summary
