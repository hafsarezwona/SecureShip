import crypto from 'node:crypto'
import { env } from '../../config/env.js'
import { adminClient } from '../../lib/supabase.js'
import { analyzeScanFindings } from '../ai/analysis-runner.js'
import { normalizeScanResult, persistScanResult } from './scan-results.js'
import { downloadPrivateArchive, invokeScannerWorker, isScannerWorkerReady } from './worker-client.js'

const LEASE_MS = 10 * 60_000
const MAX_QUEUED_JOBS = 100
const MAX_ACTIVE_JOBS = 1
const jobQueue = []
const jobPromises = new Map()
const activeJobs = new Set()

function genericFailure(error) {
  return error?.name === 'TimeoutError' || error?.name === 'AbortError'
    ? 'The isolated scanner timed out.'
    : 'The isolated scanner could not complete this scan.'
}

async function claimJob(admin, scanId, userId, now = new Date()) {
  const { data: job, error } = await admin.from('scan_jobs').select('status,started_at').eq('scan_id', scanId).eq('user_id', userId).maybeSingle()
  if (error) throw error
  if (!job) return null
  const staleBefore = new Date(now.getTime() - LEASE_MS).toISOString()
  const isQueued = job.status === 'queued'
  const isStale = job.status === 'running' && (!job.started_at || job.started_at < staleBefore)
  if (!isQueued && !isStale) return null

  const token = crypto.randomUUID()
  let query = admin.from('scan_jobs').update({ status: 'running', worker_job_id: token, started_at: now.toISOString(), completed_at: null, error_message: null })
    .eq('scan_id', scanId).eq('user_id', userId).eq('status', job.status)
  if (isStale) query = job.started_at ? query.eq('started_at', job.started_at) : query.is('started_at', null)
  const { data, error: claimError } = await query.select('scan_id').maybeSingle()
  if (claimError) throw claimError
  return data ? token : null
}

async function finishJob(admin, { scanId, userId, token, status, errorMessage = null }) {
  const completedAt = new Date().toISOString()
  const { data, error: jobError } = await admin.from('scan_jobs')
    .update({ status: status === 'completed' ? 'completed' : 'failed', completed_at: completedAt, error_message: errorMessage })
    .eq('scan_id', scanId).eq('user_id', userId).eq('worker_job_id', token).select('scan_id').maybeSingle()
  if (jobError) throw jobError
  if (!data) return false
  const { error: scanError } = await admin.from('scans').update({ status, completed_at: completedAt, error_message: errorMessage }).eq('id', scanId).eq('user_id', userId)
  if (scanError) throw scanError
  return true
}

async function executeScanJob({ scanId, userId, admin }) {
  let token
  let heartbeat
  try {
    token = await claimJob(admin, scanId, userId)
    if (!token) return { alreadyRunning: true }
    heartbeat = setInterval(() => {
      admin.from('scan_jobs').update({ started_at: new Date().toISOString() }).eq('scan_id', scanId).eq('user_id', userId).eq('worker_job_id', token)
        .then(({ error }) => { if (error) console.error('Scan job lease refresh failed') })
        .catch(() => console.error('Scan job lease refresh failed'))
    }, 60_000)
    heartbeat.unref?.()
    const [{ data: scan, error: scanError }, { data: job, error: jobError }] = await Promise.all([
      admin.from('scans').select('id,project_id,user_id,workspace_id,status,source_file_path,scanner_versions').eq('id', scanId).eq('user_id', userId).maybeSingle(),
      admin.from('scan_jobs').select('request_hash,worker_job_id').eq('scan_id', scanId).eq('user_id', userId).maybeSingle(),
    ])
    if (scanError) throw scanError
    if (jobError) throw jobError
    if (!scan || !job || job.worker_job_id !== token) throw new Error('Scan job ownership could not be verified.')

    if (scan.status !== 'analyzing') {
      if (!await isScannerWorkerReady()) {
        const [scanReset, jobReset] = await Promise.all([
          admin.from('scans').update({ status: 'queued', started_at: null, completed_at: null }).eq('id', scanId).eq('user_id', userId),
          admin.from('scan_jobs').update({ status: 'queued', worker_job_id: null, started_at: null, completed_at: null }).eq('scan_id', scanId).eq('user_id', userId).eq('worker_job_id', token),
        ])
        if (scanReset.error) throw scanReset.error
        if (jobReset.error) throw jobReset.error
        return { workerUnavailable: true }
      }
      const { error: updateError } = await admin.from('scans').update({ status: 'scanning', started_at: new Date().toISOString(), error_message: null }).eq('id', scanId).eq('user_id', userId)
      if (updateError) throw updateError
      const archive = await downloadPrivateArchive({ admin, sourcePath: scan.source_file_path, userId, projectId: scan.project_id, scanId })
      const digest = crypto.createHash('sha256').update(archive).digest('hex')
      if (digest !== job.request_hash) throw new Error('Private source archive digest did not match the scan job.')
      const result = normalizeScanResult(await invokeScannerWorker({ archive, scanId, sourceHash: job.request_hash }), scanId)
      await persistScanResult({ admin, scan, result })
      const { error } = await admin.from('scans').update({ status: env.AI_API_KEY && result.findings.length ? 'analyzing' : 'scanning', scanner_versions: result.scannerVersions }).eq('id', scanId).eq('user_id', userId)
      if (error) throw error
    }

    const { data: entitlement, error: entitlementError } = await admin.from('workspace_subscriptions').select('plan,status,current_period_end').eq('workspace_id', scan.workspace_id).maybeSingle()
    if (entitlementError) throw entitlementError
    const premium = entitlement?.plan === 'premium' && entitlement.status === 'active'
      && (!entitlement.current_period_end || new Date(entitlement.current_period_end).getTime() > Date.now())
    if (premium && env.AI_API_KEY) await analyzeScanFindings({ scanId, userId, database: admin, admin })
    if (!await finishJob(admin, { scanId, userId, token, status: 'completed' })) return { stale: true }
    return { completed: true }
  } catch (error) {
    console.error('Scan job failed:', error?.code || error?.name || 'UnknownError')
    if (token) await finishJob(admin, { scanId, userId, token, status: 'failed', errorMessage: genericFailure(error) }).catch(() => console.error('Scan failure status update failed'))
    return { completed: false }
  } finally { if (heartbeat) clearInterval(heartbeat) }
}

function drainQueue() {
  while (activeJobs.size < MAX_ACTIVE_JOBS && jobQueue.length) {
    const job = jobQueue.shift()
    activeJobs.add(job.scanId)
    executeScanJob(job).then(job.resolve, job.reject).finally(() => {
      activeJobs.delete(job.scanId)
      jobPromises.delete(job.scanId)
      drainQueue()
    })
  }
}

export function runScanJob({ scanId, userId, admin = adminClient() }) {
  const pending = jobPromises.get(scanId)
  if (pending) return pending
  if (jobQueue.length + activeJobs.size >= MAX_QUEUED_JOBS) return Promise.resolve({ queued: true })
  const promise = new Promise((resolve, reject) => jobQueue.push({ scanId, userId, admin, resolve, reject }))
  jobPromises.set(scanId, promise)
  drainQueue()
  return promise
}

export async function recoverPendingScanJobs() {
  let admin
  try { admin = adminClient() } catch { return }
  const { data: scans, error } = await admin.from('scans').select('id,user_id').in('status', ['queued', 'scanning', 'analyzing']).order('created_at', { ascending: true }).limit(100)
  if (error) return
  await Promise.all((scans || []).map(({ id, user_id }) => runScanJob({ scanId: id, userId: user_id, admin })))
}
