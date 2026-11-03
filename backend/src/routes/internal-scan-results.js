import { Router } from 'express'
import { timingSafeEqual } from 'node:crypto'
import { z } from 'zod'
import { env } from '../config/env.js'
import { adminClient } from '../lib/supabase.js'

const router = Router()
const severity = z.enum(['critical', 'high', 'medium', 'low', 'info', 'unknown'])
const findingSchema = z.object({
  scanner: z.enum(['semgrep', 'trivy']),
  ruleId: z.string().min(1).max(180),
  title: z.string().min(1).max(240),
  severity,
  cweId: z.string().max(40).nullable().optional(),
  filePath: z.string().min(1).max(1024),
  lineStart: z.number().int().positive().nullable().optional(),
  lineEnd: z.number().int().positive().nullable().optional(),
  description: z.string().max(4000).optional(),
  fingerprint: z.string().regex(/^[a-f0-9]{64}$/i),
}).strict()
const resultSchema = z.object({
  scannerVersions: z.object({ semgrep: z.string().max(80), trivy: z.string().max(80) }).strict(),
  findings: z.array(findingSchema).max(1000),
}).strict()
const idSchema = z.string().uuid()

function validSecret(requestSecret) {
  if (!env.N8N_INTERNAL_SECRET || typeof requestSecret !== 'string') return false
  const expected = Buffer.from(env.N8N_INTERNAL_SECRET)
  const provided = Buffer.from(requestSecret)
  return expected.length === provided.length && timingSafeEqual(expected, provided)
}

function safePath(filePath) {
  return !filePath.includes('\\') && !filePath.includes('\0') && !filePath.startsWith('/') && !/^[a-z]:/i.test(filePath) && !filePath.split('/').some(part => !part || part === '.' || part === '..')
}

router.post('/:scanId/results', async (req, res, next) => {
  if (!validSecret(req.get('x-secureship-secret'))) return res.status(401).json({ error: { message: 'Invalid internal credential.' } })
  if (!idSchema.safeParse(req.params.scanId).success) return res.status(404).json({ error: { message: 'Scan not found.' } })
  const result = resultSchema.safeParse(req.body)
  if (!result.success || result.data.findings.some(finding => !safePath(finding.filePath))) {
    return res.status(400).json({ error: { message: 'The scanner result payload is invalid.' } })
  }

  try {
    const client = adminClient()
    const { data: scan, error: scanError } = await client.from('scans').select('id,project_id,user_id,status').eq('id', req.params.scanId).maybeSingle()
    if (scanError) throw scanError
    if (!scan) return res.status(404).json({ error: { message: 'Scan not found.' } })
    if (scan.status === 'completed') return res.status(200).json({ scanId: scan.id, status: 'completed', reused: true })
    if (!['queued', 'scanning', 'analyzing'].includes(scan.status)) return res.status(409).json({ error: { message: 'This scan cannot accept results in its current state.' } })

    const rows = result.data.findings.map(finding => ({
      scan_id: scan.id,
      project_id: scan.project_id,
      user_id: scan.user_id,
      scanner: finding.scanner,
      rule_id: finding.ruleId,
      title: finding.title,
      severity: finding.severity,
      cwe_id: finding.cweId || null,
      file_path: finding.filePath,
      line_start: finding.lineStart || null,
      line_end: finding.lineEnd || null,
      description: finding.description || '',
      // Never persist source excerpts, scanner matches, credentials, or raw evidence.
      evidence_redacted: {},
      fingerprint: finding.fingerprint.toLowerCase(),
    }))

    for (let offset = 0; offset < rows.length; offset += 100) {
      const batch = rows.slice(offset, offset + 100)
      const { error } = await client.from('findings').upsert(batch, { onConflict: 'scan_id,fingerprint' })
      if (error) throw error
    }
    const { error: scanUpdateError } = await client.from('scans').update({ status: 'completed', scanner_versions: result.data.scannerVersions, completed_at: new Date().toISOString(), error_message: null }).eq('id', scan.id)
    if (scanUpdateError) throw scanUpdateError
    const { error: jobUpdateError } = await client.from('scan_jobs').update({ status: 'completed', completed_at: new Date().toISOString(), error_message: null }).eq('scan_id', scan.id)
    if (jobUpdateError) throw jobUpdateError
    res.status(200).json({ scanId: scan.id, status: 'completed', findingCount: rows.length })
  } catch (error) { next(error) }
})

router.post('/:scanId/failure', async (req, res, next) => {
  if (!validSecret(req.get('x-secureship-secret'))) return res.status(401).json({ error: { message: 'Invalid internal credential.' } })
  if (!idSchema.safeParse(req.params.scanId).success) return res.status(404).json({ error: { message: 'Scan not found.' } })
  try {
    const client = adminClient()
    const { data: scan, error } = await client.from('scans').select('id,status').eq('id', req.params.scanId).maybeSingle()
    if (error) throw error
    if (!scan) return res.status(404).json({ error: { message: 'Scan not found.' } })
    if (scan.status === 'completed') return res.status(409).json({ error: { message: 'A completed scan cannot be marked failed.' } })
    const completedAt = new Date().toISOString()
    const publicError = 'The isolated scanner could not complete this scan.'
    const [scanUpdate, jobUpdate] = await Promise.all([
      client.from('scans').update({ status: 'failed', error_message: publicError, completed_at: completedAt }).eq('id', scan.id),
      client.from('scan_jobs').update({ status: 'failed', error_message: publicError, completed_at: completedAt }).eq('scan_id', scan.id),
    ])
    if (scanUpdate.error) throw scanUpdate.error
    if (jobUpdate.error) throw jobUpdate.error
    res.status(200).json({ scanId: scan.id, status: 'failed' })
  } catch (error) { next(error) }
})

export default router
