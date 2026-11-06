import { supabaseAuth, userClient } from '../lib/supabase.js'

export function createRequireUser({ authClient = supabaseAuth, createUserClient = userClient } = {}) {
  return async function requireUser(req, res, next) {
    if (!authClient) return res.status(503).json({ error: { message: 'Supabase authentication is not configured.' } })
    const token = req.get('authorization')?.match(/^Bearer\s+(.+)$/i)?.[1]
    if (!token) return res.status(401).json({ error: { message: 'A valid access token is required.' } })
    try {
      const { data, error } = await authClient.auth.getUser(token)
      if (error || !data.user) return res.status(401).json({ error: { message: 'The access token is invalid or expired.' } })
      req.user = data.user
      req.db = createUserClient(token)
      next()
    } catch {
      res.status(401).json({ error: { message: 'The access token could not be verified.' } })
    }
  }
}

export const requireUser = createRequireUser()
