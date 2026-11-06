import assert from 'node:assert/strict'
import test from 'node:test'
import { createRequireUser } from '../src/middleware/auth.js'
import { normalizeScannerFinding, sanitizeCodeContext, sanitizeUntrustedText, isSensitiveSourcePath } from '../src/services/ai/context-sanitizer.js'
import { createVulnerabilityAnalyzer, InvalidAnalysisResponseError } from '../src/services/ai/vulnerability-analyzer.js'
import { getFindingForUser, persistFindingAnalysis } from '../src/services/ai/finding-analysis-store.js'

const validAnalysis = {
  vulnerability_summary: 'Untrusted input may reach a dynamic query.',
  technical_explanation: 'The scanner reported a query construction pattern; surrounding control flow was not proven.',
  root_cause: 'The query may combine user controlled data with SQL syntax.',
  attack_scenario: 'An attacker could submit crafted input if this path is reachable.',
  business_impact: 'Potential unauthorized data access or modification.',
  severity_assessment: 'high',
  severity_justification: 'The rule severity is high and exploitability depends on runtime validation.',
  confidence_score: 0.72,
  remediation_guidance: 'Use parameterized queries and verify the value is treated only as data.',
  recommended_secure_code: '',
  references: ['https://docs.example/security'],
  false_positive_assessment: { likelihood: 'medium', rationale: 'The excerpt does not show the complete call path.' },
}

const scannerRow = overrides => ({
  scanner: 'semgrep', title: 'Potential SQL injection', rule_id: 'javascript.express.security.audit.sqli', severity: 'high',
  cwe_id: 'CWE-89', owasp_category: null, file_path: 'src/routes/orders.js', line_start: 12, line_end: 14,
  description: 'A rule matched. https://docs.example/security', ...overrides,
})

function responseRecorder() {
  return { statusCode: 200, status(code) { this.statusCode = code; return this }, json(body) { this.body = body; return this } }
}

test('normalizes Semgrep and Trivy findings and rejects invalid scanner fields', () => {
  const semgrep = normalizeScannerFinding(scannerRow())
  const trivy = normalizeScannerFinding(scannerRow({ scanner: 'trivy', rule_id: 'CVE-2025-12345', cwe_id: null, severity: 'critical' }))
  assert.equal(semgrep.scannerSeverity, 'high')
  assert.equal(semgrep.cweId, 'CWE-89')
  assert.equal(trivy.scanner, 'trivy')
  assert.equal(trivy.scannerSeverity, 'critical')
  assert.throws(() => normalizeScannerFinding(scannerRow({ scanner: 'unknown' })))
})

test('sanitizes secrets and excludes environment and credential files from source context', () => {
  const source = "const api_key = 'sk-proj-ABCDEFGHIJKLMNOPQRSTUV';\nconst authToken = 'ghp_123456789012345678901234567890123456';\nrunQuery(input)"
  const context = sanitizeCodeContext({ filePath: 'src/routes/orders.js', source, lineStart: 3 })
  assert.match(context, /\[REDACTED\]/)
  assert.doesNotMatch(context, /sk-proj-|ghp_/)
  assert.equal(sanitizeCodeContext({ filePath: 'config/dev.env', source, lineStart: 1 }), '')
  assert.equal(isSensitiveSourcePath('secrets/prod.json'), true)
  assert.equal(isSensitiveSourcePath('../src/app.js'), true)
  assert.doesNotMatch(sanitizeUntrustedText('Authorization: Bearer abcdefghijklmnop'), /abcdefghijklmnop/)
})

test('uses structured mocked OpenAI output, preserves evidence severity, and drops unverified references', async () => {
  let request
  let requestOptions
  const analyze = createVulnerabilityAnalyzer({ model: 'gpt-6-luna', client: { responses: { parse: async (args, options) => { request = args; requestOptions = options; return { output_parsed: validAnalysis } } } } })
  const result = await analyze({ finding: normalizeScannerFinding(scannerRow()), context: '12: query($1)', trustedReferences: [] })
  assert.equal(request.model, 'gpt-6-luna')
  assert.equal(request.store, false)
  assert.equal(request.text.format.schema.properties.references.items.format, undefined)
  assert.equal(request.tools, undefined)
  assert.match(request.instructions, /untrusted data/)
  assert.equal(result.severity_assessment, 'high')
  assert.deepEqual(result.references, [])
  assert.equal(request.signal, undefined)
  assert.ok(requestOptions.signal instanceof AbortSignal)
})

test('supports missing source context and rejects invalid model output without a paid API call', async () => {
  let captured
  const analyze = createVulnerabilityAnalyzer({ client: { responses: { parse: async args => { captured = args; return { output_parsed: validAnalysis } } } } })
  await analyze({ finding: normalizeScannerFinding(scannerRow()), context: '' })
  assert.match(captured.input, /"source_context":null/)

  const invalid = createVulnerabilityAnalyzer({ client: { responses: { parse: async () => ({ output_parsed: { ...validAnalysis, confidence_score: 4 } }) } } })
  await assert.rejects(invalid({ finding: normalizeScannerFinding(scannerRow()) }), InvalidAnalysisResponseError)
})

test('propagates API timeouts while passing a bounded abort signal to the SDK', async () => {
  let signal
  const timeout = Object.assign(new Error('timeout'), { name: 'APIConnectionTimeoutError' })
  const analyze = createVulnerabilityAnalyzer({ client: { responses: { parse: async (_args, options) => { signal = options.signal; throw timeout } } }, timeoutMs: 15 })
  await assert.rejects(analyze({ finding: normalizeScannerFinding(scannerRow()) }), error => error === timeout)
  assert.ok(signal instanceof AbortSignal)
})

test('authentication rejects missing and invalid bearer tokens before calling next', async () => {
  let authCalls = 0
  const middleware = createRequireUser({ authClient: { auth: { getUser: async token => { authCalls += 1; return { data: {}, error: token === 'invalid' ? new Error('invalid') : null } } } }, createUserClient: () => ({}) })
  for (const authorization of [undefined, 'Bearer invalid']) {
    const req = { get: () => authorization }
    const res = responseRecorder()
    let nextCalled = false
    await middleware(req, res, () => { nextCalled = true })
    assert.equal(res.statusCode, 401)
    assert.equal(nextCalled, false)
  }
  assert.equal(authCalls, 1)
})

test('finding reads are owner scoped and persistence repeats owner and scan filters', async () => {
  const ownedFinding = { id: 'f-1', user_id: 'user-a', scan_id: 'scan-a' }
  const db = {
    from: () => {
      const filters = {}
      const query = {
        select() { return this },
        eq(key, value) { filters[key] = value; return this },
        maybeSingle: async () => ({ data: filters.user_id === ownedFinding.user_id ? ownedFinding : null, error: null }),
      }
      return query
    },
  }
  assert.equal(await getFindingForUser({ db, findingId: 'f-1', userId: 'user-a' }), ownedFinding)
  assert.equal(await getFindingForUser({ db, findingId: 'f-1', userId: 'user-b' }), null)

  let written
  const admin = {
    from: table => {
      assert.equal(table, 'findings')
      const filters = {}
      const query = {
        update(value) { written = value; return this },
        eq(key, value) { filters[key] = value; return this },
        select() { return this },
        maybeSingle: async () => ({ data: filters.user_id === 'user-a' && filters.scan_id === 'scan-a' ? { id: 'f-1' } : null, error: null }),
      }
      return query
    },
  }
  assert.equal(await persistFindingAnalysis({ admin, findingId: 'f-1', userId: 'user-a', scanId: 'scan-a', analysis: { business_impact: 'impact', remediation_guidance: 'fix' } }), true)
  assert.equal(written.business_impact, 'impact')
  assert.equal(await persistFindingAnalysis({ admin, findingId: 'f-1', userId: 'user-b', scanId: 'scan-a', analysis: validAnalysis }), false)
})
