import assert from 'node:assert/strict'
import test from 'node:test'
import { semgrepFindings, trivyFindings } from '../src/normalizers.js'

test('normalizes Semgrep findings with stable ids and relative paths', () => {
  const [finding] = semgrepFindings({ results: [{
    check_id: 'javascript.express.security.audit.sqli', path: '/workspace/src/orders.js', start: { line: 12 }, end: { line: 14 },
    extra: { severity: 'ERROR', message: 'Possible unsafe query.', metadata: { name: 'SQL injection', cwe: ['CWE-89'] } },
  }] }, '/workspace')
  assert.equal(finding.scanner, 'semgrep')
  assert.equal(finding.filePath, 'src/orders.js')
  assert.equal(finding.severity, 'high')
  assert.equal(finding.cweId, 'CWE-89')
  assert.equal(finding.lineStart, 12)
  assert.match(finding.fingerprint, /^[a-f0-9]{64}$/)
  assert.equal(semgrepFindings({ results: [{ path: '/outside/secret.js' }] }, '/workspace').length, 0)
})

test('normalizes Trivy dependency and secret findings without returning secret matches', () => {
  const [dependency, secret] = trivyFindings({ Results: [{
    Target: '/workspace/package-lock.json',
    Vulnerabilities: [{ VulnerabilityID: 'CVE-2025-12345', Title: 'Package vulnerability', Severity: 'HIGH', CweIDs: ['CWE-79'], Description: 'Upgrade the affected dependency.' }],
    Secrets: [{ RuleID: 'generic-api-key', Severity: 'CRITICAL', StartLine: 9, Match: 'sk-proj-do-not-leak' }],
  }] }, '/workspace')
  assert.equal(dependency.scanner, 'trivy')
  assert.equal(dependency.filePath, 'package-lock.json')
  assert.equal(dependency.severity, 'high')
  assert.equal(dependency.ruleId, 'CVE-2025-12345')
  assert.equal(secret.title, 'Potential hardcoded secret')
  assert.doesNotMatch(JSON.stringify(secret), /sk-proj-do-not-leak/)
})
