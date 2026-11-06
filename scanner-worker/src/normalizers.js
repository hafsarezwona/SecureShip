import crypto from 'node:crypto'
import path from 'node:path'

function severity(value) {
  const normalized = String(value || '').toLowerCase()
  const normalizedSemgrep = { error: 'high', warning: 'medium', info: 'low' }[normalized]
  const result = normalizedSemgrep || normalized
  return ['critical', 'high', 'medium', 'low', 'info'].includes(result) ? result : 'unknown'
}

function safeRelativePath(value) {
  const normalized = String(value || '').replaceAll('\\', '/')
  if (!normalized || normalized.startsWith('/') || /^[a-z]:/i.test(normalized) || normalized.split('/').some(part => !part || part === '.' || part === '..')) return null
  return normalized.slice(0, 1024)
}

function fingerprint(scanner, ruleId, filePath, line) {
  return crypto.createHash('sha256').update(`${scanner}\0${ruleId}\0${filePath}\0${line || 0}`).digest('hex')
}

export function semgrepFindings(report, root) {
  return (report.results || []).flatMap(result => {
    const filePath = safeRelativePath(path.relative(root, path.resolve(root, result.path || '')))
    if (!filePath) return []
    const ruleId = String(result.check_id || 'semgrep.unknown').slice(0, 180)
    const metadata = result.extra?.metadata || {}
    const cwe = Array.isArray(metadata.cwe) ? metadata.cwe[0] : metadata.cwe
    return [{ scanner: 'semgrep', ruleId, title: String(metadata.name || ruleId).slice(0, 240), severity: severity(result.extra?.severity), cweId: cwe ? String(cwe).slice(0, 40) : null, filePath, lineStart: result.start?.line || null, lineEnd: result.end?.line || null, description: String(result.extra?.message || 'Static analysis rule matched.').slice(0, 4000), fingerprint: fingerprint('semgrep', ruleId, filePath, result.start?.line) }]
  })
}

export function trivyFindings(report, root) {
  const findings = []
  for (const result of report.Results || []) {
    const filePath = safeRelativePath(path.relative(root, path.resolve(root, result.Target || '')))
    if (!filePath) continue
    for (const vulnerability of result.Vulnerabilities || []) {
      const ruleId = String(vulnerability.VulnerabilityID || 'TRIVY-VULN').slice(0, 180)
      const title = String(vulnerability.Title || ruleId).slice(0, 240)
      findings.push({ scanner: 'trivy', ruleId, title, severity: severity(vulnerability.Severity), cweId: Array.isArray(vulnerability.CweIDs) ? String(vulnerability.CweIDs[0] || '').slice(0, 40) || null : null, filePath, lineStart: null, lineEnd: null, description: String(vulnerability.Description || 'Dependency vulnerability detected.').slice(0, 4000), fingerprint: fingerprint('trivy', ruleId, filePath, 0) })
    }
    for (const secretFinding of result.Secrets || []) {
      const ruleId = String(secretFinding.RuleID || 'TRIVY-SECRET').slice(0, 180)
      const line = Number.isInteger(secretFinding.StartLine) ? secretFinding.StartLine : null
      findings.push({ scanner: 'trivy', ruleId, title: 'Potential hardcoded secret', severity: severity(secretFinding.Severity), cweId: null, filePath, lineStart: line, lineEnd: line, description: 'A secret detection rule matched. Source content has been withheld.', fingerprint: fingerprint('trivy', ruleId, filePath, line) })
    }
  }
  return findings
}
