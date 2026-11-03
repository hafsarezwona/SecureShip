import { createClient } from '@supabase/supabase-js'
import { env, hasSupabase } from '../config/env.js'

export const supabaseAuth = hasSupabase
  ? createClient(env.SUPABASE_URL, env.SUPABASE_ANON_KEY, { auth: { autoRefreshToken: false, persistSession: false } })
  : null

export function userClient(accessToken) {
  if (!hasSupabase) throw new Error('Supabase is not configured on the backend.')
  return createClient(env.SUPABASE_URL, env.SUPABASE_ANON_KEY, {
    auth: { autoRefreshToken: false, persistSession: false },
    global: { headers: { Authorization: `Bearer ${accessToken}` } },
  })
}

export function adminClient() {
  if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) throw new Error('Trusted server-side database access is not configured.')
  return createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, { auth: { autoRefreshToken: false, persistSession: false } })
}
