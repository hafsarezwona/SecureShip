import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import { env, hasScanOrchestrator, hasSupabase } from './config/env.js'
import { requireUser } from './middleware/auth.js'
import projects from './routes/projects.js'
import dashboard from './routes/dashboard.js'
import findings from './routes/findings.js'
import scans from './routes/scans.js'
import internalScanResults from './routes/internal-scan-results.js'

const app = express()
const allowedOrigins = env.WEB_ORIGIN.split(',').map(origin => origin.trim()).filter(Boolean)

app.disable('x-powered-by')
app.use(helmet())
app.use(cors({ origin: allowedOrigins, credentials: true, methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'] }))
app.use('/api/internal', express.json({ limit: '2mb' }))
app.use(express.json({ limit: '64kb' }))
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 120, standardHeaders: 'draft-8', legacyHeaders: false }))

app.get('/health', (_req, res) => res.json({ status: 'ok', services: { supabase: hasSupabase, scanOrchestrator: hasScanOrchestrator, scannerWorker: Boolean(env.WORKER_INTERNAL_URL && env.WORKER_API_SECRET), ai: Boolean(process.env.AI_API_KEY) } }))
app.get('/api/profile', requireUser, (req, res) => res.json({ profile: { id: req.user.id, email: req.user.email, full_name: req.user.user_metadata?.full_name || null } }))
app.use('/api/projects', projects)
app.use('/api/dashboard', dashboard)
app.use('/api/findings', findings)
app.use('/api/scans', scans)
app.use('/api/internal/scans', internalScanResults)

app.use((_req, res) => res.status(404).json({ error: { message: 'Route not found.' } }))
app.use((error, _req, res, _next) => {
  console.error('API request failed:', error?.code || error?.name || 'UnknownError')
  res.status(500).json({ error: { message: 'The request could not be completed.' } })
})

app.listen(env.PORT, () => console.log(`SecureShip API listening on port ${env.PORT}`))
