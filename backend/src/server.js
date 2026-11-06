import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import { env, hasAI, hasScanner, hasSupabase } from './config/env.js'
import { adminClient } from './lib/supabase.js'
import { requireUser } from './middleware/auth.js'
import { apiErrorHandler } from './middleware/error-handler.js'
import projects from './routes/projects.js'
import dashboard from './routes/dashboard.js'
import findings from './routes/findings.js'
import scans from './routes/scans.js'
import aiAnalysis from './routes/ai-analysis.js'
import billing from './routes/billing.js'
import { recoverPendingScanJobs } from './services/scanning/scan-runner.js'
import { isScannerWorkerReady } from './services/scanning/worker-client.js'

const app = express()
const allowedOrigins = env.WEB_ORIGIN.split(',').map(origin => origin.trim()).filter(Boolean)
let databaseSchemaCache = { checkedAt: 0, ready: false }

async function isDatabaseSchemaReady() {
  if (Date.now() - databaseSchemaCache.checkedAt < 30_000) return databaseSchemaCache.ready
  let ready = false
  try {
    const admin = adminClient()
    const [{ error: projectError }, { error: billingError }] = await Promise.all([
      admin.from('projects').select('id').limit(0),
      admin.from('workspace_subscriptions').select('workspace_id').limit(0),
    ])
    ready = !projectError && !billingError
  } catch {}
  databaseSchemaCache = { checkedAt: Date.now(), ready }
  return ready
}

app.disable('x-powered-by')
app.use(helmet())
app.use(cors({ origin: allowedOrigins, credentials: true, methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'] }))
app.use(express.json({ limit: '64kb' }))
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 120, standardHeaders: 'draft-8', legacyHeaders: false }))

app.get('/health', async (_req, res) => res.json({ status: 'ok', services: { supabase: hasSupabase, databaseSchema: hasSupabase ? await isDatabaseSchemaReady() : false, scannerWorker: await isScannerWorkerReady(), ai: hasAI } }))
app.post('/api/billing/webhook', express.urlencoded({ extended: false, limit: '16kb' }))
app.get('/api/profile', requireUser, (req, res) => res.json({ profile: { id: req.user.id, email: req.user.email, full_name: req.user.user_metadata?.full_name || null } }))
app.use('/api/projects', projects)
app.use('/api/dashboard', dashboard)
app.use('/api/findings', aiAnalysis)
app.use('/api/billing', billing)
app.use('/api/findings', findings)
app.use('/api/scans', scans)

app.use((_req, res) => res.status(404).json({ error: { message: 'Route not found.' } }))
app.use(apiErrorHandler)

app.listen(env.PORT, () => {
  console.log(`SecureShip API listening on port ${env.PORT}`)
  if (hasScanner) {
    const recoveryTimer = setInterval(() => recoverPendingScanJobs().catch(() => console.error('Pending scan recovery failed')), 60_000)
    recoveryTimer.unref()
    setTimeout(() => recoverPendingScanJobs().catch(() => console.error('Pending scan recovery failed')), 0).unref()
  }
})
