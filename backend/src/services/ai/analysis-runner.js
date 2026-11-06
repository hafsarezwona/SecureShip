import { env } from '../../config/env.js'
import { adminClient } from '../../lib/supabase.js'
import { normalizeScannerFinding, extractEvidenceReferences } from './context-sanitizer.js'
import { analysisDigest, readFindingSourceContext } from './source-context.js'
import { analyzeVulnerability } from './vulnerability-analyzer.js'
import { AI_PROMPT_VERSION, VulnerabilityAnalysisSchema } from './vulnerability-schema.js'
import { getFindingForUser, persistFindingAnalysis } from './finding-analysis-store.js'

const inFlight = new Map()

function readCache(value, digest) {
  if (!value || value._meta?.digest !== digest) return null
  const response = Object.fromEntries(Object.entries(value).filter(([key]) => key !== '_meta'))
  const parsed = VulnerabilityAnalysisSchema.safeParse(response)
  return parsed.success ? parsed.data : null
}

export async function analyzeFinding({ database, userId, findingId, admin = adminClient() }) {
  if (!env.AI_API_KEY) throw new Error('AI_NOT_CONFIGURED')
  const finding = await getFindingForUser({ db: database, findingId, userId })
  if (!finding) return null

  const [{ data: scan, error: scanError }, { data: job, error: jobError }] = await Promise.all([
    database.from('scans').select('id,project_id,user_id,source_file_path').eq('id', finding.scan_id).eq('user_id', userId).maybeSingle(),
    database.from('scan_jobs').select('request_hash').eq('scan_id', finding.scan_id).eq('user_id', userId).maybeSingle(),
  ])
  if (scanError) throw scanError
  if (jobError) throw jobError
  if (!scan || !job) throw new Error('SCAN_SOURCE_NOT_AVAILABLE')

  const digest = analysisDigest({ finding, sourceHash: job.request_hash, model: env.OPENAI_MODEL, promptVersion: AI_PROMPT_VERSION, userId })
  const cached = readCache(finding.ai_explanation, digest)
  if (cached) return { analysis: cached, cached: true }
  const pending = inFlight.get(digest)
  if (pending) return { analysis: await pending, cached: true }

  const operation = (async () => {
    const normalizedFinding = normalizeScannerFinding(finding)
    const source = await readFindingSourceContext({ userDb: database, userId, finding: { ...finding, source_hash: job.request_hash }, sourcePath: scan.source_file_path })
    const result = await analyzeVulnerability({
      finding: normalizedFinding,
      context: source.context,
      trustedReferences: extractEvidenceReferences(normalizedFinding.scannerEvidence),
    })
    const persisted = { ...result, _meta: { digest, model: env.OPENAI_MODEL, prompt_version: AI_PROMPT_VERSION, analyzed_at: new Date().toISOString() } }
    const updated = await persistFindingAnalysis({ admin, findingId: finding.id, userId, scanId: finding.scan_id, analysis: persisted })
    if (!updated) throw new Error('FINDING_OWNERSHIP_CHANGED')
    return result
  })()
  inFlight.set(digest, operation)
  operation.finally(() => { if (inFlight.get(digest) === operation) inFlight.delete(digest) }).catch(() => {})
  return { analysis: await operation, cached: false }
}

async function mapPool(items, limit, operation) {
  let cursor = 0
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor++
      await operation(items[index])
    }
  })
  await Promise.all(runners)
}

const activeScans = new Set()

export async function analyzeScanFindings({ scanId, userId, database = adminClient(), admin = database }) {
  if (!env.AI_API_KEY) return { analyzed: 0, failed: 0 }
  if (activeScans.has(scanId)) return { analyzed: 0, failed: 0, alreadyRunning: true }
  activeScans.add(scanId)
  let analyzed = 0
  let failed = 0
  try {
    const { data: findings, error } = await database.from('findings').select('id').eq('scan_id', scanId).eq('user_id', userId).limit(1000)
    if (error) throw error
    await mapPool(findings || [], 2, async ({ id }) => {
      try {
        const result = await analyzeFinding({ database, userId, findingId: id, admin })
        if (result && !result.cached) analyzed += 1
      } catch (error) {
        failed += 1
        console.error('Finding analysis failed:', error?.code || error?.name || 'UnknownError')
      }
    })
    return { analyzed, failed }
  } finally { activeScans.delete(scanId) }
}

