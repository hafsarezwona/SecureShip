import { Router } from 'express'
import rateLimit from 'express-rate-limit'
import { z } from 'zod'
import { env } from '../config/env.js'
import { requireUser } from '../middleware/auth.js'
import { AnalysisCapacityError, AnalyzerUnavailableError, InvalidAnalysisResponseError } from '../services/ai/vulnerability-analyzer.js'
import { analyzeFinding } from '../services/ai/analysis-runner.js'
import { getBillingStatus, getWorkspaceForUser } from '../services/billing.js'

const router = Router()
const idSchema = z.string().uuid()
const analysisLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 20,
  keyGenerator: req => req.user.id,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  handler: (_req, res) => res.status(429).json({ error: { message: 'AI analysis limit reached. Try again later.' } }),
})

router.post('/:findingId/analyze', requireUser, analysisLimit, async (req, res) => {
  if (!idSchema.safeParse(req.params.findingId).success) return res.status(404).json({ error: { message: 'Finding not found.' } })
  if (!env.AI_API_KEY) return res.status(503).json({ error: { message: 'OpenAI analysis is not configured on the API.' } })
  try {
    const workspace = await getWorkspaceForUser(req.db, req.user.id)
    if (!workspace) return res.status(403).json({ error: { message: 'No workspace is assigned to this account.' } })
    const billing = await getBillingStatus({ db: req.db, workspaceId: workspace.workspace_id })
    if (!billing.entitlements.aiAnalysis) return res.status(403).json({ error: { message: 'AI finding analysis requires the Premium plan.' } })
    const result = await analyzeFinding({ database: req.db, userId: req.user.id, findingId: req.params.findingId })
    if (!result) return res.status(404).json({ error: { message: 'Finding not found.' } })
    res.json(result)
  } catch (error) {
    if (error instanceof AnalyzerUnavailableError) return res.status(503).json({ error: { message: error.message } })
    if (error instanceof AnalysisCapacityError) return res.status(503).json({ error: { message: error.message } })
    if (error instanceof InvalidAnalysisResponseError) return res.status(502).json({ error: { message: error.message } })
    if (error?.status === 429) return res.status(429).json({ error: { message: 'OpenAI rate limit reached. Retry shortly.' } })
    if (error?.name === 'APIConnectionTimeoutError' || error?.name === 'AbortError' || error?.name === 'TimeoutError') return res.status(504).json({ error: { message: 'OpenAI analysis timed out. Retry shortly.' } })
    if (error?.name === 'SourceContextUnavailableError' || error?.message === 'SCAN_SOURCE_NOT_AVAILABLE') return res.status(502).json({ error: { message: 'The private scan source could not be read safely.' } })
    if (error?.message === 'AI_NOT_CONFIGURED') return res.status(503).json({ error: { message: 'OpenAI analysis is not configured on the API.' } })
    if (error?.message === 'Trusted server-side database access is not configured.') return res.status(503).json({ error: { message: 'AI analysis persistence is not configured on the API.' } })
    console.error('AI analysis failed:', error?.code || error?.name || 'UnknownError')
    res.status(502).json({ error: { message: 'AI analysis could not be completed. Scanner findings remain unchanged.' } })
  }
})

export default router
