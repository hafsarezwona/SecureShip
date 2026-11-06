import crypto from 'node:crypto'
import { createWriteStream } from 'node:fs'
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { Transform, Readable } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { archiveLimits, extractZip, inspectZip } from '@secureship/archive'
import { env } from '../../config/env.js'
import { sanitizeCodeContext, isSensitiveSourcePath } from './context-sanitizer.js'

const MAX_CONTEXT_FILE_BYTES = 256 * 1024

export class SourceContextUnavailableError extends Error {
  constructor() { super('The private scan source could not be read safely.'); this.name = 'SourceContextUnavailableError' }
}

function resolveFindingFile(root, filePath) {
  if (isSensitiveSourcePath(filePath)) return null
  const resolvedRoot = path.resolve(root)
  const candidate = path.resolve(resolvedRoot, filePath)
  const relative = path.relative(resolvedRoot, candidate)
  if (!relative || relative.startsWith(`..${path.sep}`) || relative === '..' || path.isAbsolute(relative)) return null
  return candidate
}

async function downloadArchive(userDb, sourcePath, destination) {
  const { data, error } = await userDb.storage.from(env.SUPABASE_STORAGE_BUCKET).createSignedUrl(sourcePath, 60)
  if (error || !data?.signedUrl) throw new SourceContextUnavailableError()
  const url = data.signedUrl.startsWith('http') ? data.signedUrl : `${env.SUPABASE_URL.replace(/\/$/, '')}/storage/v1${data.signedUrl}`
  let response
  try { response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(15_000) }) }
  catch { throw new SourceContextUnavailableError() }
  if (!response.ok || !response.body) throw new SourceContextUnavailableError()
  const announcedLength = Number(response.headers.get('content-length'))
  if (Number.isFinite(announcedLength) && announcedLength > env.MAX_ARCHIVE_SIZE) throw new SourceContextUnavailableError()
  let bytes = 0
  const guard = new Transform({ transform(chunk, _encoding, callback) {
    bytes += chunk.length
    if (bytes > env.MAX_ARCHIVE_SIZE) return callback(new SourceContextUnavailableError())
    callback(null, chunk)
  } })
  try { await pipeline(Readable.fromWeb(response.body), guard, createWriteStream(destination, { flags: 'wx', mode: 0o600 })) }
  catch { throw new SourceContextUnavailableError() }
}

export async function readFindingSourceContext({ userDb, userId, finding, sourcePath }) {
  const expectedPath = `${userId}/${finding.project_id}/${finding.scan_id}.zip`
  const requestHash = typeof finding.source_hash === 'string' && /^[a-f0-9]{64}$/i.test(finding.source_hash) ? finding.source_hash.toLowerCase() : null
  if (!sourcePath || sourcePath !== expectedPath || !requestHash || isSensitiveSourcePath(finding.file_path)) {
    return { context: '', sourceHash: requestHash }
  }

  const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), 'secureship-ai-context-'))
  try {
    const archivePath = path.join(temporaryDirectory, 'source.zip')
    await downloadArchive(userDb, sourcePath, archivePath)
    const limits = archiveLimits(env)
    await inspectZip(archivePath, limits)
    const root = await extractZip(archivePath, path.join(temporaryDirectory, 'source'), limits)
    const target = resolveFindingFile(root, finding.file_path)
    if (!target) return { context: '', sourceHash: requestHash }
    let fileInfo
    try { fileInfo = await stat(target) } catch { return { context: '', sourceHash: requestHash } }
    if (!fileInfo.isFile() || fileInfo.size > MAX_CONTEXT_FILE_BYTES) return { context: '', sourceHash: requestHash }
    const source = await readFile(target, 'utf8')
    return { context: sanitizeCodeContext({ filePath: finding.file_path, source, lineStart: finding.line_start, lineEnd: finding.line_end }), sourceHash: requestHash }
  } catch (error) {
    if (error instanceof SourceContextUnavailableError) throw error
    throw new SourceContextUnavailableError()
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true }).catch(() => console.error('AI context temporary cleanup failed'))
  }
}

export function analysisDigest({ finding, sourceHash, model, promptVersion, userId }) {
  const digest = crypto.createHash('sha256')
  digest.update(JSON.stringify({
    fingerprint: finding.fingerprint,
    scanner: finding.scanner,
    ruleId: finding.rule_id,
    title: finding.title,
    severity: finding.severity,
    cweId: finding.cwe_id,
    owaspCategory: finding.owasp_category,
    filePath: finding.file_path,
    lineStart: finding.line_start,
    lineEnd: finding.line_end,
    scannerEvidence: finding.description,
    sourceHash,
    model,
    promptVersion,
    userId,
  }))
  return digest.digest('hex')
}
