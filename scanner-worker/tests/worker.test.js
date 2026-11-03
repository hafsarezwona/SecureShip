import { after, before, test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer } from 'node:net'

let worker
let baseUrl

before(async () => {
  const probe = createServer()
  await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve))
  const { port } = probe.address()
  await new Promise((resolve, reject) => probe.close(error => error ? reject(error) : resolve()))
  baseUrl = `http://127.0.0.1:${port}`
  worker = spawn(process.execPath, ['src/server.js'], {
    cwd: new URL('..', import.meta.url),
    env: { ...process.env, PORT: String(port), WORKER_API_SECRET: 'worker-test-secret' },
    stdio: 'ignore',
  })
  const startedAt = Date.now()
  while (Date.now() - startedAt < 5000) {
    try {
      const response = await fetch(`${baseUrl}/health`)
      if (response.ok) return
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 50))
  }
  throw new Error('Scanner worker did not start for tests.')
})

after(() => worker?.kill())

test('worker reports configured health without exposing credentials', async () => {
  const response = await fetch(`${baseUrl}/health`)
  assert.equal(response.status, 200)
  assert.deepEqual(await response.json(), { status: 'ok' })
})

test('scan endpoint rejects missing internal credentials', async () => {
  const response = await fetch(`${baseUrl}/scan`, { method: 'POST', headers: { 'content-type': 'application/zip' }, body: 'not a zip' })
  assert.equal(response.status, 401)
})

test('scan endpoint rejects invalid authenticated metadata before processing a body', async () => {
  const response = await fetch(`${baseUrl}/scan`, {
    method: 'POST',
    headers: { 'content-type': 'application/zip', 'x-secureship-secret': 'worker-test-secret', 'x-scan-id': 'bad-id', 'x-source-sha256': 'bad-hash' },
    body: 'not a zip',
  })
  assert.equal(response.status, 400)
})
