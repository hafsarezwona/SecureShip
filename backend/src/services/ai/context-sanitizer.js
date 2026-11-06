import { FindingForAnalysisSchema } from './vulnerability-schema.js'

const MAX_CONTEXT_CHARS = 12_000
const MAX_CONTEXT_LINES = 48
const SECRET_PATH_COMPONENT = /^(?:(?:\.?env|[^/]+\.env)(?:\..*)?|secrets?(?:\..*)?|credentials?(?:\..*)?|id_(?:rsa|ed25519)|[^/]+\.(?:pem|key|p12|pfx|keystore))$/i
const REDACTION_PATTERNS = [
  [/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/gi, '[REDACTED PRIVATE KEY]'],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi, 'Bearer [REDACTED]'],
  [/\bBasic\s+[A-Za-z0-9+/=]{8,}/gi, 'Basic [REDACTED]'],
  [/\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{30,})\b/g, '[REDACTED TOKEN]'],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, '[REDACTED JWT]'],
  [/((?:api[_-]?key|access[_-]?key|client[_-]?secret|password|passwd|secret|token|private[_-]?key)\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)/gi, '$1[REDACTED]'],
  [/(:\/\/)[^\s/:@]+:[^\s/@]+@/g, '$1[REDACTED]@'],
]

export function sanitizeUntrustedText(value, maxChars = MAX_CONTEXT_CHARS) {
  let text = String(value ?? '').replace(/\p{Cc}(?![\r\n\t])/gu, '')
  for (const [pattern, replacement] of REDACTION_PATTERNS) text = text.replace(pattern, replacement)
  return text.slice(0, maxChars)
}

export function normalizeScannerFinding(row) {
  const cweId = String(row.cwe_id || '').trim()
  return FindingForAnalysisSchema.parse({
    scanner: row.scanner,
    title: sanitizeUntrustedText(row.title, 240).trim(),
    ruleId: sanitizeUntrustedText(row.rule_id, 180).trim(),
    scannerSeverity: row.severity,
    cweId: /^CWE-\d{1,6}$/i.test(cweId) ? cweId.toUpperCase() : null,
    owaspCategory: row.owasp_category ? sanitizeUntrustedText(row.owasp_category, 120).trim() : null,
    filePath: sanitizeUntrustedText(row.file_path, 1024).trim(),
    lineStart: row.line_start || null,
    lineEnd: row.line_end || null,
    scannerEvidence: sanitizeUntrustedText(row.description || '', 4000).trim(),
  })
}

export function isSensitiveSourcePath(filePath) {
  const normalized = String(filePath || '').replaceAll('\\', '/')
  const parts = normalized.split('/')
  return normalized.startsWith('/') || /^[a-z]:/i.test(normalized) || parts.some(part => !part || part === '.' || part === '..' || SECRET_PATH_COMPONENT.test(part))
}

export function sanitizeCodeContext({ filePath, source, lineStart, lineEnd }) {
  if (isSensitiveSourcePath(filePath) || typeof source !== 'string' || source.includes('\0')) return ''
  const lines = source.split(/\r?\n/)
  const start = Number.isInteger(lineStart) && lineStart > 0 ? lineStart : 1
  const end = Number.isInteger(lineEnd) && lineEnd >= start ? lineEnd : start
  const first = Math.max(1, start - 20)
  const last = Math.min(lines.length, Math.max(end, start) + 20, first + MAX_CONTEXT_LINES - 1)
  const selected = lines.slice(first - 1, last).map((line, index) => `${first + index}: ${line.slice(0, 600)}`).join('\n')
  return sanitizeUntrustedText(selected, MAX_CONTEXT_CHARS)
}

export function extractEvidenceReferences(text) {
  return [...new Set((String(text || '').match(/https:\/\/[^\s)\]}>,"']+/gi) || []).map(url => url.replace(/[.]+$/, '').slice(0, 500)))]
}
