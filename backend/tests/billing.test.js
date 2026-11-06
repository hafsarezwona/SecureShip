import assert from 'node:assert/strict'
import test from 'node:test'

process.env.SSLCOMMERZ_STORE_ID = 'sandbox-store'
process.env.SSLCOMMERZ_STORE_PASSWORD = 'sandbox-password'
process.env.SSLCOMMERZ_SANDBOX = 'true'
process.env.BILLING_API_PUBLIC_URL = 'https://api.example.test'
process.env.PREMIUM_PRICE_BDT = '1000'

const { getBillingStatus, processPaymentNotification } = await import('../src/services/billing.js')

test('free workspace reports scan usage and backend entitlements', async () => {
  const db = { from(table) {
    const query = { select(_columns, options) { query.countQuery = options?.count === 'exact'; return query }, eq() { return query }, gte() { return query }, maybeSingle: async () => ({ data: { plan: 'free', status: 'active' }, error: null }), then(resolve) { resolve({ count: 3, error: null }) } }
    if (table === 'workspace_subscriptions') return query
    if (table === 'scans') return query
    throw new Error(`Unexpected table ${table}`)
  } }
  const status = await getBillingStatus({ db, workspaceId: 'workspace-id' })
  assert.equal(status.usage.scansThisPeriod, 3)
  assert.equal(status.entitlements.premium, false)
  assert.equal(status.entitlements.scanLimit, 3)
})

test('verified matching provider transaction activates through the atomic database function', async () => {
  const calls = []
  const admin = {
    from(table) {
      assert.equal(table, 'payment_orders')
      return { select() { return this }, eq() { return this }, maybeSingle: async () => ({ data: { id: 'order-id', workspace_id: 'workspace-id', amount: 1000, currency: 'BDT', status: 'pending' }, error: null }) }
    },
    async rpc(name, args) { calls.push({ name, args }); return { data: true, error: null } },
  }
  const accepted = await processPaymentNotification({ admin, payload: { tran_id: 'ss-test', val_id: 'val-test' }, fetchImpl: async () => new Response(JSON.stringify({ status: 'VALID', tran_id: 'ss-test', val_id: 'val-test', currency: 'BDT', amount: '1000.00', risk_level: '0' }), { status: 200 }) })
  assert.equal(accepted, true)
  assert.deepEqual(calls, [{ name: 'complete_payment_order', args: { p_tran_id: 'ss-test', p_val_id: 'val-test' } }])
})

test('mismatched provider evidence cannot activate Premium', async () => {
  let called = false
  const admin = {
    from() { return { select() { return this }, eq() { return this }, maybeSingle: async () => ({ data: { id: 'order-id', workspace_id: 'workspace-id', amount: 1000, currency: 'BDT', status: 'pending' }, error: null }), update() { return { eq() { return { neq: async () => ({ error: null }) } } } } } },
    async rpc() { called = true; return { data: true, error: null } },
  }
  const accepted = await processPaymentNotification({ admin, payload: { tran_id: 'ss-test', val_id: 'val-test' }, fetchImpl: async () => new Response(JSON.stringify({ status: 'VALID', tran_id: 'ss-test', val_id: 'val-test', currency: 'BDT', amount: '1.00', risk_level: '0' }), { status: 200 }) })
  assert.equal(accepted, false)
  assert.equal(called, false)
})
