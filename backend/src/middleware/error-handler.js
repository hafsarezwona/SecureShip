const SCHEMA_ERROR_CODES = new Set(['PGRST205', 'PGRST204', '42P01', '42703'])
const MIGRATION_MESSAGE = 'SecureShip database tables are missing or out of date. Apply supabase/migrations/202611040001_initial_schema.sql to the Supabase project configured for this backend.'

export function apiErrorHandler(error, _req, res, _next) {
  const code = error?.code || error?.name || 'UnknownError'
  console.error('API request failed:', code)
  if (SCHEMA_ERROR_CODES.has(error?.code)) return res.status(503).json({ error: { message: MIGRATION_MESSAGE } })
  return res.status(500).json({ error: { message: 'The request could not be completed.' } })
}
