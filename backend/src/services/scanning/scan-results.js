import { z } from 'zod'

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

export const scanResultSchema = z.object({
  scanId: z.string().uuid(),
  scannerVersions: z.object({ semgrep: z.string().max(80), trivy: z.string().max(80) }).strict(),
  findings: z.array(findingSchema).max(1000),
}).strict()

function safePath(filePath) {
  return !filePath.includes('\\') && !filePath.includes('\0') && !filePath.startsWith('/') && !/^[a-z]:/i.test(filePath) && !filePath.split('/').some(part => !part || part === '.' || part === '..')
}

export function normalizeScanResult(input, expectedScanId) {
  const result = scanResultSchema.parse(input)
  if (expectedScanId && result.scanId !== expectedScanId) throw new Error('Scanner response scan ID did not match the request.')
  if (result.findings.some(finding => !safePath(finding.filePath) || (finding.lineStart && finding.lineEnd && finding.lineEnd < finding.lineStart))) throw new Error('Invalid scanner finding path or line range.')
  return result
}

export async function persistScanResult({ admin, scan, result }) {
  const rows = result.findings.map(finding => ({
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
    evidence_redacted: {},
    fingerprint: finding.fingerprint.toLowerCase(),
  }))

  for (let offset = 0; offset < rows.length; offset += 100) {
    const { error } = await admin.from('findings').upsert(rows.slice(offset, offset + 100), { onConflict: 'scan_id,fingerprint' })
    if (error) throw error
  }
  return rows.length
}
