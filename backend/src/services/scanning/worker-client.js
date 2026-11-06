import { env } from '../../config/env.js'

const MAX_WORKER_RESPONSE_BYTES = 8 * 1024 * 1024

export async function isScannerWorkerReady({ workerUrl = env.WORKER_INTERNAL_URL, fetchImpl = fetch } = {}) {
  if (!workerUrl) return false
  try {
    const response = await fetchImpl(`${workerUrl.replace(/\/$/, '')}/health`, { redirect: 'error', signal: AbortSignal.timeout(1500) })
    if (!response.ok) return false
    const health = await response.json()
    return health.status === 'ok'
  } catch { return false }
}

async function readBoundedResponse(response) {
  const announcedSize = Number(response.headers.get('content-length'))
  if (Number.isFinite(announcedSize) && announcedSize > MAX_WORKER_RESPONSE_BYTES) throw new Error('Scanner response exceeded the configured limit.')
  if (!response.body) throw new Error('Scanner returned an empty response.')
  const reader = response.body.getReader()
  const chunks = []
  let size = 0
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    size += value.byteLength
    if (size > MAX_WORKER_RESPONSE_BYTES) {
      await reader.cancel().catch(() => {})
      throw new Error('Scanner response exceeded the configured limit.')
    }
    chunks.push(Buffer.from(value))
  }
  return Buffer.concat(chunks, size).toString('utf8')
}

export async function downloadPrivateArchive({ admin, sourcePath, userId, projectId, scanId, sourceUrlBase = env.SUPABASE_URL, bucket = env.SUPABASE_STORAGE_BUCKET, fetchImpl = fetch }) {
  const expectedPath = `${userId}/${projectId}/${scanId}.zip`
  if (sourcePath !== expectedPath) throw new Error('Scan source path did not match its owner and scan.')
  const { data, error } = await admin.storage.from(bucket).createSignedUrl(sourcePath, 60)
  if (error || !data?.signedUrl) throw new Error('A temporary private source URL could not be created.')
  const url = data.signedUrl.startsWith('http') ? data.signedUrl : `${sourceUrlBase.replace(/\/$/, '')}/storage/v1${data.signedUrl}`
  const response = await fetchImpl(url, { redirect: 'error', signal: AbortSignal.timeout(30_000) })
  const announcedSize = Number(response.headers.get('content-length'))
  if (!response.ok || !Number.isFinite(announcedSize) || announcedSize < 22 || announcedSize > env.MAX_ARCHIVE_SIZE) {
    await response.body?.cancel().catch(() => {})
    throw new Error('Private source archive was unavailable or outside configured size limits.')
  }
  const reader = response.body?.getReader()
  if (!reader) throw new Error('Private source archive had no response body.')
  const chunks = []
  let size = 0
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    size += value.byteLength
    if (size > env.MAX_ARCHIVE_SIZE) {
      await reader.cancel().catch(() => {})
      throw new Error('Private source archive exceeded configured size limits.')
    }
    chunks.push(Buffer.from(value))
  }
  const bytes = Buffer.concat(chunks, size)
  if (bytes.length !== announcedSize || bytes.length > env.MAX_ARCHIVE_SIZE) throw new Error('Private source archive size did not match its metadata.')
  return bytes
}

export async function invokeScannerWorker({ archive, scanId, sourceHash, workerUrl = env.WORKER_INTERNAL_URL, workerSecret = env.WORKER_API_SECRET, fetchImpl = fetch }) {
  const response = await fetchImpl(`${workerUrl.replace(/\/$/, '')}/scan`, {
    method: 'POST',
    headers: {
      'content-type': 'application/zip',
      'content-length': String(archive.length),
      'x-secureship-secret': workerSecret,
      'x-scan-id': scanId,
      'x-source-sha256': sourceHash,
    },
    body: archive,
    signal: AbortSignal.timeout(5 * 60_000),
    redirect: 'error',
  })
  const text = await readBoundedResponse(response)
  if (!response.ok) throw new Error(`Scanner worker returned status ${response.status}.`)
  try { return JSON.parse(text) } catch { throw new Error('Scanner worker returned invalid JSON.') }
}
