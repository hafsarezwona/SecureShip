import { supabase } from './supabase.js'

const baseUrl = import.meta.env.VITE_API_BASE_URL

async function getSession() {
  if (!supabase) return null
  const { data, error } = await supabase.auth.getSession()
  if (error) throw error
  return data.session
}

async function refreshSession() {
  if (!supabase) return null
  const { data, error } = await supabase.auth.refreshSession()
  if (error || !data.session) {
    if (error?.status >= 400) {
      await supabase.auth.signOut({ scope: 'local' }).catch(() => {})
      window.dispatchEvent(new Event('secureship:auth-expired'))
      return null
    }
    throw new Error('Your session could not be refreshed. Check your connection and try again.')
  }
  return data.session
}

async function fetchWithAuth(url, options) {
  const session = await getSession()
  const headers = new Headers(options.headers || {})
  if (session?.access_token) headers.set('Authorization', `Bearer ${session.access_token}`)
  else headers.delete('Authorization')
  let response = await fetch(url, { ...options, headers })
  if (response.status !== 401 || !session) return response

  const refreshedSession = await refreshSession()
  if (!refreshedSession) return response
  headers.set('Authorization', `Bearer ${refreshedSession.access_token}`)
  response = await fetch(url, { ...options, headers })
  if (response.status === 401) {
    await supabase.auth.signOut({ scope: 'local' }).catch(() => {})
    window.dispatchEvent(new Event('secureship:auth-expired'))
  }
  return response
}

async function request(path, options = {}) {
  if (!baseUrl) throw new Error('SecureShip API is not configured. Set VITE_API_BASE_URL in frontend/.env.local.')
  const headers = new Headers(options.headers || {})
  if (!(options.body instanceof FormData)) headers.set('Content-Type', 'application/json')
  let response
  try { response = await fetchWithAuth(new URL(path, baseUrl), { ...options, headers }) }
  catch { throw new Error('Could not reach the SecureShip API. Check that the backend is running and VITE_API_BASE_URL is correct.') }
  const body = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(body.error?.scanId ? `${body.error.message} (Scan ID: ${body.error.scanId})` : body.error?.message || body.message || `Request failed (${response.status}).`)
  return body
}

export const api = {
  get: path => request(path),
  post: (path, value) => request(path, { method: 'POST', body: value instanceof FormData ? value : JSON.stringify(value) }),
  patch: (path, value) => request(path, { method: 'PATCH', body: JSON.stringify(value) }),
  delete: path => request(path, { method: 'DELETE' }),
  upload: async (path, { projectId, file, idempotencyKey, onProgress }) => {
    if (!baseUrl) throw new Error('SecureShip API is not configured. Set VITE_API_BASE_URL in frontend/.env.local.')
    const sendUpload = session => new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest()
      xhr.open('POST', new URL(path, baseUrl))
      xhr.timeout = 60000
      xhr.setRequestHeader('Idempotency-Key', idempotencyKey)
      if (session?.access_token) xhr.setRequestHeader('Authorization', `Bearer ${session.access_token}`)
      xhr.upload.addEventListener('progress', event => { if (event.lengthComputable) onProgress?.(Math.min(96, Math.round(event.loaded / event.total * 96))) })
      xhr.addEventListener('load', () => {
        const body = (() => { try { return JSON.parse(xhr.responseText) } catch { return {} } })()
        resolve({ status: xhr.status, body })
      })
      xhr.addEventListener('error', () => reject(new Error('Could not reach the SecureShip API. Check that the backend is running and VITE_API_BASE_URL is correct.')))
      xhr.addEventListener('timeout', () => reject(new Error('The upload timed out. Check the connection and retry.')))
      const body = new FormData()
      body.append('projectId', projectId)
      body.append('file', file)
      xhr.send(body)
    })
    let session = await getSession()
    let result = await sendUpload(session)
    if (result.status === 401 && session) {
      session = await refreshSession()
      if (session) result = await sendUpload(session)
    }
    if (result.status === 401 && session) {
      await supabase.auth.signOut({ scope: 'local' }).catch(() => {})
      window.dispatchEvent(new Event('secureship:auth-expired'))
    }
    if (result.status < 200 || result.status >= 300) throw new Error(result.body.error?.scanId ? `${result.body.error.message} (Scan ID: ${result.body.error.scanId})` : result.body.error?.message || result.body.message || `Upload failed (${result.status}).`)
    return result.body
  },
}
