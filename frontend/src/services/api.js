import { supabase } from './supabase.js'

const baseUrl = import.meta.env.VITE_API_BASE_URL

async function request(path, options = {}) {
  if (!baseUrl) throw new Error('SecureShip API is not configured. Set VITE_API_BASE_URL in frontend/.env.local.')
  const { data: { session } = {} } = await supabase?.auth.getSession() ?? {}
  const headers = new Headers(options.headers || {})
  if (session?.access_token) headers.set('Authorization', `Bearer ${session.access_token}`)
  if (!(options.body instanceof FormData)) headers.set('Content-Type', 'application/json')
  let response
  try { response = await fetch(new URL(path, baseUrl), { ...options, headers }) }
  catch { throw new Error('Could not reach the SecureShip API. Check that the backend is running and VITE_API_BASE_URL is correct.') }
  const body = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(body.error?.message || body.message || `Request failed (${response.status}).`)
  return body
}

export const api = {
  get: path => request(path),
  post: (path, value) => request(path, { method: 'POST', body: value instanceof FormData ? value : JSON.stringify(value) }),
  patch: (path, value) => request(path, { method: 'PATCH', body: JSON.stringify(value) }),
  delete: path => request(path, { method: 'DELETE' }),
  upload: async (path, { projectId, file, idempotencyKey, onProgress }) => {
    if (!baseUrl) throw new Error('SecureShip API is not configured. Set VITE_API_BASE_URL in frontend/.env.local.')
    const { data: { session } = {} } = await supabase?.auth.getSession() ?? {}
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest()
      xhr.open('POST', new URL(path, baseUrl))
      xhr.timeout = 60000
      xhr.setRequestHeader('Idempotency-Key', idempotencyKey)
      if (session?.access_token) xhr.setRequestHeader('Authorization', `Bearer ${session.access_token}`)
      xhr.upload.addEventListener('progress', event => { if (event.lengthComputable) onProgress?.(Math.min(96, Math.round(event.loaded / event.total * 96))) })
      xhr.addEventListener('load', () => {
        const body = (() => { try { return JSON.parse(xhr.responseText) } catch { return {} } })()
        if (xhr.status >= 200 && xhr.status < 300) resolve(body)
        else reject(new Error(body.error?.message || body.message || `Upload failed (${xhr.status}).`))
      })
      xhr.addEventListener('error', () => reject(new Error('Could not reach the SecureShip API. Check that the backend is running and VITE_API_BASE_URL is correct.')))
      xhr.addEventListener('timeout', () => reject(new Error('The upload timed out. Check the connection and retry.')))
      const body = new FormData()
      body.append('projectId', projectId)
      body.append('file', file)
      xhr.send(body)
    })
  },
}
