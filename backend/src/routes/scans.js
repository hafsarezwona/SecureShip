import { Router } from 'express'
import crypto, { randomUUID } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { mkdir, stat, unlink } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import multer from 'multer'
import { z } from 'zod'
import { env, hasScanOrchestrator } from '../config/env.js'
import { adminClient } from '../lib/supabase.js'
import { requireUser } from '../middleware/auth.js'
import { archiveLimits, ArchiveValidationError, inspectZip } from '@secureship/archive'

const router = Router()
const tempDirectory = env.SCAN_TEMP_DIRECTORY || os.tmpdir()
const storage = multer.diskStorage({
  destination: (_req, _file, callback) => mkdir(tempDirectory, { recursive: true }).then(() => callback(null, tempDirectory), callback),
  filename: (_req, _file, callback) => callback(null, `secureship-${randomUUID()}.zip`),
})
const upload = multer({ storage, limits: { fileSize: env.MAX_ARCHIVE_SIZE, files: 1, fields: 1, parts: 2 } })
const idSchema = z.string().uuid()

async function hashFile(filePath) {
  const hash = crypto.createHash('sha256')
  for await (const chunk of createReadStream(filePath)) hash.update(chunk)
  return hash.digest('hex')
}

async function uploadPrivateFile(accessToken, filePath, objectPath) {
  const base = env.SUPABASE_URL.replace(/\/$/, '')
  const encodedPath = objectPath.split('/').map(encodeURIComponent).join('/')
  const fileInfo = await stat(filePath)
  const response = await fetch(`${base}/storage/v1/object/${encodeURIComponent(env.SUPABASE_STORAGE_BUCKET)}/${encodedPath}`, {
    method: 'POST',
    headers: { apikey: env.SUPABASE_ANON_KEY, Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/zip', 'Content-Length': String(fileInfo.size), 'x-upsert': 'false' },
    body: createReadStream(filePath),
    duplex: 'half',
    signal: AbortSignal.timeout(30000),
  })
  if (!response.ok) throw new Error('Private source storage rejected the upload.')
}

async function removePrivateFile(client, objectPath) {
  if (!objectPath) return
  await client.storage.from(env.SUPABASE_STORAGE_BUCKET).remove([objectPath]).catch(() => {})
}

router.use(requireUser)

router.get('/', async (req, res, next) => {
  const { data, error } = await req.db.from('scans').select('id,project_id,status,started_at,completed_at,created_at,projects(name)').order('created_at', { ascending: false }).limit(100)
  if (error) return next(error)
  res.json({ scans: data.map(scan => ({ ...scan, project_name: scan.projects?.name || 'Project' })) })
})

router.get('/:scanId/status', async (req, res, next) => {
  if (!idSchema.safeParse(req.params.scanId).success) return res.status(404).json({ error: { message: 'Scan not found.' } })
  const { data, error } = await req.db.from('scans').select('id,status,started_at,completed_at,error_message,created_at').eq('id', req.params.scanId).maybeSingle()
  if (error) return next(error)
  if (!data) return res.status(404).json({ error: { message: 'Scan not found.' } })
  res.json({ scan: data })
})

router.post('/', (req, res, next) => {
  if (!hasScanOrchestrator) return res.status(503).json({ error: { message: 'Secure scanning is not configured. Set up private storage, the isolated worker, and the authenticated n8n workflow first.' } })
  upload.single('file')(req, res, error => {
    if (error) {
      if (error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: { message: 'The ZIP exceeds the configured compressed upload limit.' } })
      return next(error)
    }
    next()
  })
}, async (req, res, next) => {
  let objectPath
  let scanId
  let admin
  try {
    if (!req.file) return res.status(400).json({ error: { message: 'Select a ZIP archive to scan.' } })
    const projectId = idSchema.safeParse(req.body.projectId)
    if (!projectId.success) return res.status(400).json({ error: { message: 'Choose a valid project.' } })
    const idempotencyKey = z.string().uuid().safeParse(req.get('idempotency-key'))
    if (!idempotencyKey.success) return res.status(400).json({ error: { message: 'A valid Idempotency-Key is required.' } })

    const accessToken = req.get('authorization').replace(/^Bearer\s+/i, '')
    const { data: project, error: projectError } = await req.db.from('projects').select('id,name,primary_language,framework').eq('id', projectId.data).maybeSingle()
    if (projectError) return next(projectError)
    if (!project) return res.status(404).json({ error: { message: 'Project not found.' } })

    const metadata = await inspectZip(req.file.path, archiveLimits(env))
    const requestHash = await hashFile(req.file.path)
    admin = adminClient()
    const { data: existing, error: lookupError } = await admin.from('scan_jobs').select('scan_id,request_hash,status').eq('user_id', req.user.id).eq('idempotency_key', idempotencyKey.data).maybeSingle()
    if (lookupError) return next(lookupError)
    if (existing) {
      if (existing.request_hash !== requestHash) return res.status(409).json({ error: { message: 'This Idempotency-Key was already used for a different ZIP.' } })
      return res.status(200).json({ scanId: existing.scan_id, status: existing.status, reused: true })
    }

    scanId = randomUUID()
    objectPath = `${req.user.id}/${projectId.data}/${scanId}.zip`
    await uploadPrivateFile(accessToken, req.file.path, objectPath)
    const { error: scanError } = await admin.from('scans').insert({ id: scanId, project_id: projectId.data, user_id: req.user.id, status: 'queued', source_file_path: objectPath })
    if (scanError) throw new Error('The scan record could not be created.')
    const { error: jobError } = await admin.from('scan_jobs').insert({ scan_id: scanId, user_id: req.user.id, status: 'queued', idempotency_key: idempotencyKey.data, request_hash: requestHash })
    if (jobError) throw new Error('The scan job could not be created.')

    const { data: signed, error: signedError } = await req.db.storage.from(env.SUPABASE_STORAGE_BUCKET).createSignedUrl(objectPath, 60)
    if (signedError || !signed?.signedUrl) throw new Error('A temporary private source URL could not be created.')
    const signedUrl = signed.signedUrl.startsWith('http') ? signed.signedUrl : `${env.SUPABASE_URL.replace(/\/$/, '')}/storage/v1${signed.signedUrl}`
    const webhook = await fetch(env.N8N_SCAN_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${env.N8N_INTERNAL_SECRET}`, 'Idempotency-Key': idempotencyKey.data },
      body: JSON.stringify({ scanId, project: { id: project.id, name: project.name, language: project.primary_language, framework: project.framework }, source: { url: signedUrl, fileName: 'source.zip', size: req.file.size, sha256: requestHash }, archive: metadata }),
      signal: AbortSignal.timeout(10000),
    })
    if (!webhook.ok) throw new Error('The scan orchestrator did not accept the job.')
    await Promise.all([
      admin.from('scans').update({ status: 'scanning', started_at: new Date().toISOString() }).eq('id', scanId),
      admin.from('scan_jobs').update({ status: 'running', started_at: new Date().toISOString() }).eq('scan_id', scanId),
    ])
    res.status(202).json({ scanId, status: 'scanning', archive: { entryCount: metadata.entryCount, fileCount: metadata.fileCount } })
  } catch (error) {
    if (error instanceof ArchiveValidationError) return res.status(400).json({ error: { message: error.message } })
    if (scanId && admin) {
      await Promise.all([
        admin.from('scans').update({ status: 'failed', source_file_path: null, error_message: 'Scan setup failed before scanning started.', completed_at: new Date().toISOString() }).eq('id', scanId),
        admin.from('scan_jobs').update({ status: 'failed', error_message: 'Scan setup failed before scanning started.', completed_at: new Date().toISOString() }).eq('scan_id', scanId),
        removePrivateFile(admin, objectPath),
      ])
      return res.status(502).json({ error: { message: 'The scan could not be started. The failed attempt is recorded for review.', scanId } })
    }
    next(error)
  } finally {
    if (req.file?.path) await unlink(req.file.path).catch(() => {})
  }
})

export default router
