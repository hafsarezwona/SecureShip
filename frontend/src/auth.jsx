import { useEffect, useMemo, useState } from 'react'
import { AuthContext } from './auth-context.jsx'
import { supabase } from './services/supabase.js'

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [ready, setReady] = useState(!supabase)

  useEffect(() => {
    if (!supabase) return undefined
    let alive = true
    supabase.auth.getSession().then(({ data, error }) => {
      if (!alive) return
      if (!error) setUser(data.session?.user ?? null)
      setReady(true)
    }).catch(() => { if (alive) setReady(true) })
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => setUser(session?.user ?? null))
    const handleExpiredSession = () => setUser(null)
    window.addEventListener('secureship:auth-expired', handleExpiredSession)
    return () => { alive = false; subscription.unsubscribe(); window.removeEventListener('secureship:auth-expired', handleExpiredSession) }
  }, [])

  const value = useMemo(() => ({
    user,
    ready,
    configured: Boolean(supabase),
    signIn: async ({ email, password }) => {
      const { data, error } = await supabase.auth.signInWithPassword({ email, password })
      if (error) throw error
      setUser(data.user)
      return data
    },
    signUp: async ({ email, password, name }) => {
      const { data, error } = await supabase.auth.signUp({ email, password, options: { data: { full_name: name } } })
      if (error) throw error
      if (data.session) setUser(data.user)
      return data
    },
    resetPassword: async email => {
      const { error } = await supabase.auth.resetPasswordForEmail(email)
      if (error) throw error
    },
    signOut: async () => {
      if (!supabase) return
      const { error } = await supabase.auth.signOut()
      if (error) throw error
      setUser(null)
    },
  }), [user, ready])

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

