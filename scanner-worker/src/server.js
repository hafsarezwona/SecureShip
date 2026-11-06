import crypto from 'node:crypto'
import { spawn } from 'node:child_process'
import { createWriteStream } from 'node:fs'
import { mkdir, mkdtemp, rm } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { Transform } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import express from 'express'
import { archiveLimits, extractZip, inspectZip } from '@secureship/archive'
import { semgrepFindings, trivyFindings } from './normalizers.js'

const port = Number(process.env.PORT || 4100)
const secret = process.env.WORKER_API_SECRET || ''
const tempDirectory = process.env.SCAN_TEMP_DIRECTORY || path.join(os.tmpdir(), 'secureship')
const maxArchiveSize = Number(process.env.MAX_ARCHIVE_SIZE || 25 * 1024 * 1024)
const limits = archiveLimits({
  MAX_ARCHIVE_SIZE: maxArchiveSize,
  MAX_EXTRACTED_SIZE: Number(process.env.MAX_EXTRACTED_SIZE || 250 * 1024 * 1024),
  MAX_ARCHIVE_FILES: Number(process.env.MAX_ARCHIVE_FILES || 5000),
  MAX_COMPRESSION_RATIO: Number(process.env.MAX_COMPRESSION_RATIO || 100),
})
const app = express()
app.disable('x-powered-by')
app.get('/health', (_req, res) => res.status(secret ? 200 : 503).json({ status: secret ? 'ok' : 'not_configured' }))

function authorized(value) {
  if (!secret || typeof value !== 'string') return false
  const expected = Buffer.from(secret)
  const received = Buffer.from(value)
  return expected.length === received.length && crypto.timingSafeEqual(expected, received)
}

function execute(command, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, env: { PATH: process.env.PATH, HOME: '/tmp', TRIVY_CACHE_DIR: process.env.TRIVY_CACHE_DIR || '/var/lib/trivy', SEMGREP_SEND_METRICS: 'off' }, shell: false, stdio: ['ignore', 'pipe', 'ignore'] })
    let stdout = ''
    const maxOutput = 32 * 1024 * 1024
    child.stdout.on('data', chunk => { stdout += chunk.toString(); if (stdout.length > maxOutput) child.kill('SIGKILL') })
    const timer = setTimeout(() => child.kill('SIGKILL'), 180_000)
    child.once('error', error => { clearTimeout(timer); reject(error) })
    child.once('close', code => {
      clearTimeout(timer)
      if (code !== 0) return reject(new Error(`${path.basename(command)} exited with code ${code}.`))
      try { resolve(JSON.parse(stdout)) } catch { reject(new Error(`${path.basename(command)} returned invalid JSON.`)) }
    })
  })
}

async function getVersions() {
  const [semgrep, trivy] = await Promise.all([
    execute('semgrep', ['--version'], process.cwd()).then(report => String(report.version || 'unknown')).catch(async () => runVersion('semgrep', ['--version'])),
    runVersion('trivy', ['--version']),
  ])
  return { semgrep, trivy }
}

function runVersion(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { env: { PATH: process.env.PATH, HOME: '/tmp', TRIVY_CACHE_DIR: process.env.TRIVY_CACHE_DIR || '/var/lib/trivy', SEMGREP_SEND_METRICS: 'off' }, shell: false })
    let output = ''
    child.stdout.on('data', chunk => { output += chunk.toString() })
    child.once('error', reject)
    child.once('close', code => code === 0 ? resolve(output.trim().split(/\s+/).pop()) : reject(new Error(`${command} version check failed.`)))
  })
}

app.post('/scan', async (req, res) => {
  if (!authorized(req.get('x-secureship-secret'))) return res.status(401).json({ error: 'Invalid internal credential.' })
  const scanId = req.get('x-scan-id')
  const sourceHash = req.get('x-source-sha256')
  if (!/^[0-9a-f-]{36}$/i.test(scanId || '') || !/^[0-9a-f]{64}$/i.test(sourceHash || '') || req.get('content-type')?.split(';')[0] !== 'application/zip') {
    return res.status(400).json({ error: 'Invalid scan request.' })
  }
  const contentLength = Number(req.get('content-length'))
  if (!Number.isSafeInteger(contentLength) || contentLength < 22 || contentLength > maxArchiveSize) return res.status(413).json({ error: 'Archive size is outside the configured limit.' })

  let jobDirectory
  try {
    await mkdir(tempDirectory, { recursive: true, mode: 0o700 })
    jobDirectory = await mkdtemp(path.join(tempDirectory, 'scan-'))
    const archivePath = path.join(jobDirectory, 'source.zip')
    const hash = crypto.createHash('sha256')
    let received = 0
    const guard = new Transform({ transform(chunk, _encoding, callback) {
      received += chunk.length
      if (received > maxArchiveSize) return callback(new Error('Archive exceeds the configured limit.'))
      hash.update(chunk)
      callback(null, chunk)
    } })
    await pipeline(req, guard, createWriteStream(archivePath, { flags: 'wx', mode: 0o600 }))
    if (received !== contentLength || hash.digest('hex') !== sourceHash.toLowerCase()) throw new Error('Uploaded archive size or digest did not match the authenticated request metadata.')
    await inspectZip(archivePath, limits)
    const sourcePath = path.join(jobDirectory, 'source')
    await extractZip(archivePath, sourcePath, limits)
    const [semgrepReport, trivyReport, scannerVersions] = await Promise.all([
      execute('semgrep', ['scan', '--config', '/app/rules/semgrep.yml', '--json', '--metrics=off', '--quiet', sourcePath], sourcePath),
      execute('trivy', ['fs', '--format', 'json', '--scanners', 'vuln,secret', '--skip-db-update', '--skip-java-db-update', '--no-progress', '--cache-dir', process.env.TRIVY_CACHE_DIR || '/var/lib/trivy', sourcePath], sourcePath),
      getVersions(),
    ])
    const findings = [...semgrepFindings(semgrepReport, sourcePath), ...trivyFindings(trivyReport, sourcePath)].slice(0, 1000)
    res.json({ scanId, scannerVersions, findings })
  } catch (error) {
    console.error('Scan failed:', error?.message || 'Unknown scanner error')
    if (!res.headersSent) res.status(422).json({ error: 'The archive could not be scanned. Check the worker logs for the failed scanner.' })
  } finally {
    if (jobDirectory) await rm(jobDirectory, { recursive: true, force: true }).catch(() => {})
  }
})

app.listen(port, '0.0.0.0', () => console.log(`SecureShip isolated scanner listening on ${port}`))
