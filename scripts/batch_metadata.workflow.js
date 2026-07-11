// batch_metadata.workflow.js — Orchestrator: reads seeds.jsonl, feeds metadata batches to ingest_metadata.
//
// One-liner to bank metadata records:
//   Workflow({ scriptPath: "scripts/batch_metadata.workflow.js", args: { limit: 200 } })
//
// Reads artifacts/seeds.jsonl, filters to metadata-tier, chunks into sub-batches, and calls
// ingest_metadata as a child workflow for each chunk. Resume-safe via the dedup markers.
//
// args:
//   limit      : number  total records to process this run (default 200)
//   chunkSize  : number  records per child workflow invocation (default 100)
//   seedsFile  : string  path to seeds.jsonl (default artifacts/seeds.jsonl)
//   synth      : boolean run synthesis (default: only on last chunk)

export const meta = {
  name: 'batch-metadata',
  description: 'Read seeds.jsonl and feed metadata-tier records to ingest_metadata in chunks. One-liner to bank hundreds of reports.',
  phases: [
    { title: 'Load', detail: 'read seeds.jsonl, filter metadata tier, chunk' },
    { title: 'Ingest', detail: 'child workflow per chunk' }
  ]
}

const limitN = (args && Number(args.limit)) || 200
const chunkSize = (args && Number(args.chunkSize)) || 100
const seedsFile = (args && args.seedsFile) || 'artifacts/seeds.jsonl'
const synthFlag = args && args.synth

phase('Load')
const loader = await agent([
  'Read the file ' + JSON.stringify(seedsFile) + ' and return a JSON array of the first ' + limitN + ' objects',
  'where tier == "metadata". Each line is a JSON object. Return ONLY the array, nothing else.',
  'If the file does not exist or is empty, return an empty array [].',
  'Use bash: head -' + (limitN + 50) + ' ' + JSON.stringify(seedsFile) + ' to read it.',
  'Parse each line as JSON, filter tier=="metadata", take the first ' + limitN + ', return as array.'
].join('\n'), {
  model: 'haiku', effort: 'low', phase: 'Load', label: 'load-seeds',
  schema: {
    type: 'object', additionalProperties: false,
    properties: {
      seeds: {
        type: 'array',
        items: {
          type: 'object', additionalProperties: false,
          properties: {
            url: { type: 'string' },
            title: { type: 'string' },
            program: { type: 'string' },
            vuln_class: { type: 'string' },
            bounty: { type: 'number' },
            upvotes: { type: 'number' }
          },
          required: ['url', 'title']
        }
      },
      total: { type: 'number' }
    },
    required: ['seeds', 'total']
  }
})

if (!loader || !loader.seeds || !loader.seeds.length) {
  log('No metadata seeds found in ' + seedsFile)
  return { error: 'no_seeds', file: seedsFile }
}

const seeds = loader.seeds
log('Loaded ' + seeds.length + ' metadata seeds')

// Chunk and run child workflows
const chunks = []
for (let i = 0; i < seeds.length; i += chunkSize) {
  chunks.push(seeds.slice(i, i + chunkSize))
}

phase('Ingest')
log(chunks.length + ' chunk(s) of up to ' + chunkSize)

const results = await pipeline(
  chunks,
  (chunk, _orig, i) => {
    const isLast = i === chunks.length - 1
    const doSynth = synthFlag !== undefined ? synthFlag : isLast
    return workflow('ingest-metadata', {
      seeds: chunk,
      limit: chunk.length,
      synth: doSynth,
      batchSize: 25
    })
  }
)

// Aggregate
let totalIngested = 0, totalSkipped = 0, totalFailed = 0
for (const r of results) {
  if (!r) continue
  totalIngested += (r.ingested || 0)
  totalSkipped += (r.skipped || 0)
  totalFailed += (r.failed || 0)
}

return {
  loaded: seeds.length,
  chunks: chunks.length,
  ingested: totalIngested,
  skipped: totalSkipped,
  failed: totalFailed,
  synthesis: results[results.length - 1] && results[results.length - 1].synthesis
}
