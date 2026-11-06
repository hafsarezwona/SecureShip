import { Router } from 'express'
import { z } from 'zod'
import { adminClient } from '../lib/supabase.js'
import { requireUser } from '../middleware/auth.js'
import { env } from '../config/env.js'
import { billingConfigured, cancelSubscription, createCheckout, getBillingStatus, getWorkspaceForUser, markPaymentFailed, processPaymentNotification } from '../services/billing.js'

const router = Router()

router.get('/', requireUser, async (req, res, next) => {
  try {
    const workspace = await getWorkspaceForUser(req.db, req.user.id)
    if (!workspace) return res.status(403).json({ error: { message: 'No workspace is assigned to this account.' } })
    res.json({ ...(await getBillingStatus({ db: req.db, usageDb: adminClient(), workspaceId: workspace.workspace_id })), role: workspace.role, paymentConfigured: billingConfigured() })
  } catch (error) { next(error) }
})

router.post('/checkout', requireUser, async (req, res, next) => {
  try {
    const workspace = await getWorkspaceForUser(req.db, req.user.id)
    if (!workspace) return res.status(403).json({ error: { message: 'No workspace is assigned to this account.' } })
    if (!['owner', 'admin'].includes(workspace.role)) return res.status(403).json({ error: { message: 'Only workspace owners and admins can manage billing.' } })
    const admin = adminClient()
    const status = await getBillingStatus({ db: req.db, usageDb: admin, workspaceId: workspace.workspace_id })
    if (status.entitlements.premium) return res.status(409).json({ error: { message: 'This workspace already has Premium.' } })
    const origins = env.WEB_ORIGIN.split(',').map(origin => origin.trim()).filter(Boolean)
    const webOrigin = origins.includes(req.get('origin')) ? req.get('origin') : origins[0]
    const result = await createCheckout({ admin, workspaceId: workspace.workspace_id, userId: req.user.id, email: req.user.email, webOrigin })
    res.json(result)
  } catch (error) {
    if (error.code === '23505') return res.status(409).json({ error: { message: 'A checkout is already in progress for this workspace.' } })
    if (error.message === 'BILLING_NOT_CONFIGURED') return res.status(503).json({ error: { message: 'Payment checkout is not configured. Set the SSLCOMMERZ backend environment values.' } })
    if (error.message === 'CHECKOUT_ALREADY_PENDING') return res.status(409).json({ error: { message: 'A checkout is already in progress for this workspace. Finish it or try again in an hour.' } })
    if (error.message === 'CHECKOUT_CREATION_FAILED') return res.status(502).json({ error: { message: 'The payment provider could not start checkout. Try again shortly.' } })
    next(error)
  }
})

router.post('/cancel', requireUser, async (req, res, next) => {
  try {
    const workspace = await getWorkspaceForUser(req.db, req.user.id)
    if (!workspace) return res.status(403).json({ error: { message: 'No workspace is assigned to this account.' } })
    if (!['owner', 'admin'].includes(workspace.role)) return res.status(403).json({ error: { message: 'Only workspace owners and admins can manage billing.' } })
    const canceled = await cancelSubscription({ admin: adminClient(), workspaceId: workspace.workspace_id })
    if (!canceled) return res.status(409).json({ error: { message: 'No active Premium subscription can be canceled.' } })
    res.json({ canceled: true })
  } catch (error) { next(error) }
})

router.post('/webhook', async (req, res) => {
  const payload = req.body || {}
  const tranId = z.string().min(1).max(40).safeParse(payload.tran_id)
  if (!tranId.success) return res.status(400).send('Invalid transaction.')
  try {
    const admin = adminClient()
    if (['FAILED', 'CANCELLED', 'EXPIRED', 'UNATTEMPTED'].includes(payload.status)) {
      const failed = await markPaymentFailed({ admin, tranId: tranId.data })
      return res.status(failed ? 200 : 400).send(failed ? 'Failure confirmed.' : 'Failure not confirmed.')
    }
    const accepted = await processPaymentNotification({ admin, payload })
    res.status(accepted ? 200 : 400).send(accepted ? 'Validated.' : 'Not validated.')
  } catch (error) {
    console.error('Payment webhook processing failed:', error?.code || error?.name || 'UnknownError')
    res.status(503).send('Payment validation temporarily unavailable.')
  }
})

export default router
