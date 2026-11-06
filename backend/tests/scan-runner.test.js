import assert from 'node:assert/strict'
import test from 'node:test'
import { normalizeScanResult, persistScanResult } from '../src/services/scanning/scan-results.js'
import { downloadPrivateArchive, invokeScannerWorker, isScannerWorkerReady } from '../src/services/scanning/worker-client.js'

const scannerVersions = { semgrep: '1.0.0', trivy: '1.0.0' }
const scanId = '15fd8392-0dd7-4fe8-ac1b-b15613f2ec73'
const finding = {
  scanner: 'semgrep', ruleId: 'secureship.javascript.dynamic-code-evaluation', title: 'Dynamic evaluation', severity: 'high',
  cweId: 'CWE-95', filePath: 'src/app.js', lineStart: 4, lineEnd: 4, description: 'Dynamic evaluation can execute attacker controlled input.', fingerprint: 'a'.repeat(64),
}

test('validates scanner output and rejects traversal paths and unknown fields', () => {
  const response = { scanId, scannerVersions, findings: [finding] }
  assert.equal(normalizeScanResult(response, scanId).findings.length, 1)
  assert.throws(() => normalizeScanResult(response, 'ea30f991-f874-4622-8ea3-64ed996d3788'), /scan ID did not match/)
  assert.throws(() => normalizeScanResult({ ...response, findings: [{ ...finding, filePath: '../outside.js' }] }, scanId))
  assert.throws(() => normalizeScanResult({ ...response, findings: [{ ...finding, evidence: 'untrusted extra' }] }, scanId))
})

test('persists normalized Semgrep and Trivy results in bounded batches without source evidence', async () => {
  let persisted
  const admin = { from(table) { assert.equal(table, 'findings'); return { upsert: async (rows, options) => { persisted = { rows, options }; return { error: null } } } } }
  const scan = { id: scanId, project_id: 'project-1', user_id: 'owner-1' }
  const result = normalizeScanResult({ scanId, scannerVersions, findings: [finding, { ...finding, scanner: 'trivy', ruleId: 'CVE-2025-1234', fingerprint: 'b'.repeat(64) }] }, scanId)
  assert.equal(await persistScanResult({ admin, scan, result }), 2)
  assert.equal(persisted.rows.length, 2)
  assert.equal(persisted.options.onConflict, 'scan_id,fingerprint')
  assert.equal(persisted.rows[0].user_id, 'owner-1')
  assert.deepEqual(persisted.rows[0].evidence_redacted, {})
})

test('downloads only the scan owner archive and streams it to the authenticated worker', async () => {
  const archive = Buffer.alloc(24, 0x41)
  let requestedUrl
  const admin = {
    storage: {
      from(bucket) {
        assert.equal(bucket, 'secure-source')
        return {
          async createSignedUrl(path) {
            assert.equal(path, 'owner-1/project-1/scan-1.zip')
            return { data: { signedUrl: 'https://storage.example/signed' }, error: null }
          },
        }
      },
    },
  }
  const downloaded = await downloadPrivateArchive({
    admin, sourcePath: 'owner-1/project-1/scan-1.zip', userId: 'owner-1', projectId: 'project-1', scanId: 'scan-1',
    fetchImpl: async url => { requestedUrl = url; return new Response(archive, { headers: { 'content-length': String(archive.length) } }) },
  })
  assert.equal(requestedUrl, 'https://storage.example/signed')
  assert.deepEqual(downloaded, archive)
  await assert.rejects(downloadPrivateArchive({ admin, sourcePath: 'owner-2/project-1/scan-1.zip', userId: 'owner-1', projectId: 'project-1', scanId: 'scan-1' }))

  let call
  const payload = { scanId, scannerVersions, findings: [] }
  const response = await invokeScannerWorker({
    archive, scanId: 'scan-1', sourceHash: 'c'.repeat(64), workerUrl: 'http://scanner-worker:4100/', workerSecret: 'test-worker-secret',
    fetchImpl: async (...args) => { call = args; return Response.json(payload) },
  })
  assert.equal(call[0], 'http://scanner-worker:4100/scan')
  assert.equal(call[1].headers['x-secureship-secret'], 'test-worker-secret')
  assert.equal(call[1].headers['x-source-sha256'], 'c'.repeat(64))
  assert.deepEqual(response, payload)
})

test('worker readiness checks report reachable and unavailable workers without exposing settings', async () => {
  assert.equal(await isScannerWorkerReady({ workerUrl: 'http://scanner-worker:4100', fetchImpl: async () => Response.json({ status: 'ok' }) }), true)
  assert.equal(await isScannerWorkerReady({ workerUrl: 'http://scanner-worker:4100', fetchImpl: async () => new Response('', { status: 503 }) }), false)
  assert.equal(await isScannerWorkerReady({ workerUrl: 'http://scanner-worker:4100', fetchImpl: async () => { throw new Error('connection failure') } }), false)
})
