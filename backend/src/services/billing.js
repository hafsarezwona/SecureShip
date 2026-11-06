import { env } from '../config/env.js'

const FREE_SCAN_LIMIT = 3
const MONTHLY_MS = 30 * 24 * 60 * 60 * 1000

export function billingConfigured() {
  return Boolean(env.SSLCOMMERZ_STORE_ID && env.SSLCOMMERZ_STORE_PASSWORD && env.BILLING_API_PUBLIC_URL)
}

export async function getWorkspaceForUser(db, userId) {
  const { data, error } = await db.from('workspace_members').select('workspace_id,role').eq('user_id', userId).order('created_at').limit(1).maybeSingle()
  if (error) throw error
  return data
}

export async function getBillingStatus({ db, usageDb = db, workspaceId }) {
  const [{ data: subscription, error }, { count, error: countError }] = await Promise.all([
    db.from('workspace_subscriptions').select('plan,status,current_period_start,current_period_end,cancel_at_period_end').eq('workspace_id', workspaceId).maybeSingle(),
    usageDb.from('scans').select('id', { count: 'exact', head: true }).eq('workspace_id', workspaceId).gte('created_at', new Date(Date.now() - MONTHLY_MS).toISOString()),
  ])
  if (error) throw error
  if (countError) throw countError
  const premium = subscription?.plan === 'premium' && subscription.status === 'active'
    && (!subscription.current_period_end || new Date(subscription.current_period_end).getTime() > Date.now())
  const expired = subscription?.plan === 'premium' && subscription.current_period_end && new Date(subscription.current_period_end).getTime() <= Date.now()
  const visibleSubscription = expired ? { ...subscription, plan: 'free', status: 'expired' } : subscription
  return {
    subscription: visibleSubscription || { plan: 'free', status: 'active', cancel_at_period_end: false },
    usage: { scansThisPeriod: count || 0, scanLimit: premium ? null : FREE_SCAN_LIMIT },
    plans: [
      { id: 'free', name: 'Free', price: 0, currency: 'BDT', interval: 'month', features: ['3 scans per month', 'Scanner findings', 'Personal workspace'] },
      { id: 'premium', name: 'Premium', price: env.PREMIUM_PRICE_BDT, currency: 'BDT', interval: 'month', features: ['Unlimited scans', 'AI finding analysis', 'Workspace subscription'] },
    ],
    entitlements: { premium, aiAnalysis: premium, scanLimit: premium ? null : FREE_SCAN_LIMIT },
  }
}

export async function createCheckout({ admin, workspaceId, userId, email, webOrigin, fetchImpl = fetch }) {
  if (!billingConfigured()) throw new Error('BILLING_NOT_CONFIGURED')
  const { error: expireError } = await admin.from('payment_orders').update({ status: 'failed' }).eq('workspace_id', workspaceId).eq('status', 'pending').lt('created_at', new Date(Date.now() - 60 * 60_000).toISOString())
  if (expireError) throw expireError
  const { data: pending, error: pendingError } = await admin.from('payment_orders').select('id').eq('workspace_id', workspaceId).eq('status', 'pending').limit(1).maybeSingle()
  if (pendingError) throw pendingError
  if (pending) throw new Error('CHECKOUT_ALREADY_PENDING')
  const tranId = `ss-${cryptoRandomId()}`
  const { error: insertError } = await admin.from('payment_orders').insert({ workspace_id: workspaceId, created_by: userId, tran_id: tranId, amount: env.PREMIUM_PRICE_BDT })
  if (insertError) throw insertError
  const endpoint = env.SSLCOMMERZ_SANDBOX ? 'https://sandbox.sslcommerz.com/gwprocess/v4/api.php' : 'https://securepay.sslcommerz.com/gwprocess/v4/api.php'
  const params = new URLSearchParams({
    store_id: env.SSLCOMMERZ_STORE_ID, store_passwd: env.SSLCOMMERZ_STORE_PASSWORD,
    total_amount: env.PREMIUM_PRICE_BDT.toFixed(2), currency: 'BDT', tran_id: tranId,
    success_url: `${webOrigin}/app/settings?payment=processing`, fail_url: `${webOrigin}/app/settings?payment=failed`, cancel_url: `${webOrigin}/app/settings?payment=canceled`,
    ipn_url: `${env.BILLING_API_PUBLIC_URL.replace(/\/$/, '')}/api/billing/webhook`,
    cus_name: 'SecureShip customer', cus_email: email || 'customer@secureship.local', cus_add1: 'Not provided', cus_city: 'Dhaka', cus_country: 'Bangladesh', cus_phone: '01700000000',
    shipping_method: 'NO', product_name: 'SecureShip Premium monthly subscription', product_category: 'software', product_profile: 'non-physical-goods',
  })
  const response = await fetchImpl(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: params, signal: AbortSignal.timeout(15000) })
  const body = await response.json().catch(() => ({}))
  const checkoutUrl = URL.canParse(body.GatewayPageURL || '') ? new URL(body.GatewayPageURL) : null
  const expectedHost = env.SSLCOMMERZ_SANDBOX ? 'sandbox.sslcommerz.com' : 'securepay.sslcommerz.com'
  if (!response.ok || body.status !== 'SUCCESS' || checkoutUrl?.hostname !== expectedHost || checkoutUrl.protocol !== 'https:') {
    await admin.from('payment_orders').update({ status: 'failed' }).eq('tran_id', tranId)
    throw new Error('CHECKOUT_CREATION_FAILED')
  }
  return { checkoutUrl: checkoutUrl.href }
}

export async function processPaymentNotification({ admin, payload, fetchImpl = fetch }) {
  const tranId = payload?.tran_id
  const valId = payload?.val_id
  if (typeof tranId !== 'string' || typeof valId !== 'string' || !billingConfigured()) return false
  const { data: order, error } = await admin.from('payment_orders').select('id,workspace_id,amount,currency,status').eq('tran_id', tranId).maybeSingle()
  if (error) throw error
  if (!order) return false
  if (order.status === 'paid') return true
  const base = env.SSLCOMMERZ_SANDBOX ? 'https://sandbox.sslcommerz.com' : 'https://securepay.sslcommerz.com'
  const url = new URL(`${base}/validator/api/validationserverAPI.php`)
  url.search = new URLSearchParams({ val_id: valId, store_id: env.SSLCOMMERZ_STORE_ID, store_passwd: env.SSLCOMMERZ_STORE_PASSWORD, format: 'json' }).toString()
  const response = await fetchImpl(url, { signal: AbortSignal.timeout(15000) })
  const verified = await response.json().catch(() => ({}))
  if (!response.ok || !['VALID', 'VALIDATED'].includes(verified.status) || verified.tran_id !== tranId || verified.val_id !== valId || verified.currency !== order.currency
    || Number(verified.amount) !== Number(order.amount) || Number(verified.risk_level) !== 0) {
    await admin.from('payment_orders').update({ status: 'failed' }).eq('id', order.id).neq('status', 'paid')
    return false
  }
  const { data, error: completionError } = await admin.rpc('complete_payment_order', { p_tran_id: tranId, p_val_id: valId })
  if (completionError) throw completionError
  return data === true
}

export async function cancelSubscription({ admin, workspaceId }) {
  const { data, error } = await admin.rpc('cancel_workspace_subscription', { p_workspace_id: workspaceId })
  if (error) throw error
  return data === true
}

export async function markPaymentFailed({ admin, tranId, fetchImpl = fetch }) {
  if (typeof tranId !== 'string' || !billingConfigured()) return false
  const { data: order, error: lookupError } = await admin.from('payment_orders').select('amount,currency,status').eq('tran_id', tranId).maybeSingle()
  if (lookupError) throw lookupError
  if (!order || order.status !== 'pending') return false
  const base = env.SSLCOMMERZ_SANDBOX ? 'https://sandbox.sslcommerz.com' : 'https://securepay.sslcommerz.com'
  const url = new URL(`${base}/validator/api/merchantTransIDvalidationAPI.php`)
  url.search = new URLSearchParams({ tran_id: tranId, store_id: env.SSLCOMMERZ_STORE_ID, store_passwd: env.SSLCOMMERZ_STORE_PASSWORD, v: '1', format: 'json' }).toString()
  const response = await fetchImpl(url, { signal: AbortSignal.timeout(15000) })
  const result = await response.json().catch(() => ({}))
  const attempts = Array.isArray(result.element) ? result.element.filter(item => item.tran_id === tranId && item.currency === order.currency && Number(item.amount) === Number(order.amount)) : []
  if (!response.ok || result.APIConnect !== 'DONE' || attempts.length === 0 || !attempts.every(item => ['FAILED', 'CANCELLED', 'EXPIRED', 'UNATTEMPTED'].includes(item.status))) return false
  const { error } = await admin.rpc('fail_payment_order', { p_tran_id: tranId })
  if (error) throw error
  return true
}

function cryptoRandomId() {
  return globalThis.crypto.randomUUID().replaceAll('-', '')
}
