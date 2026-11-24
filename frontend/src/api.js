const base = import.meta.env.VITE_API_URL || ''
const token = () => localStorage.getItem('pulse_token')

export async function request(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...options.headers }
  if (token()) headers.Authorization = `Bearer ${token()}`
  const response = await fetch(`${base}/api${path}`, { ...options, headers })
  const body = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(body.error || 'Something went wrong. Please try again.')
  return body
}

export function socketURL(path) {
  const url = new URL(`${base}/ws/${path}`, window.location.origin)
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
  return url.toString()
}
