const BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

async function req<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options,
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`API ${res.status}: ${text}`)
  }
  return res.json()
}

// ---- Events ----
export const getEvents = (params: Record<string, string | number | undefined> = {}) => {
  const qs = Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== '')
    .map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`)
    .join('&')
  return req<any>(`/api/events${qs ? '?' + qs : ''}`)
}

export const getEvent = (line: number) => req<any>(`/api/events/${line}`)

// ---- Exceptions ----
export const getExceptions = (params: Record<string, string | number | undefined> = {}) => {
  const qs = Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== '')
    .map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`)
    .join('&')
  return req<any>(`/api/exceptions${qs ? '?' + qs : ''}`)
}

export const approveException = (id: number) =>
  req<any>(`/api/exceptions/${id}/approve`, { method: 'POST' })

export const rejectException = (id: number, reason?: string) =>
  req<any>(`/api/exceptions/${id}/reject`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  })

// ---- Deploy ----
export const getPending = () => req<any>('/api/deploy/pending')

export const deployExceptions = (ids?: number[]) =>
  req<any>('/api/deploy', {
    method: 'POST',
    body: JSON.stringify({ ids }),
  })

export const rollbackException = (id: number) =>
  req<any>(`/api/deploy/${id}`, { method: 'DELETE' })

export const downloadFalsePositivesExcel = (status?: string) => {
  const qs = status ? `?status=${encodeURIComponent(status)}` : ''
  window.open(`${BASE}/api/exceptions/export/false-positives${qs}`, '_blank')
}

// ---- Analytics ----
export const getSummary = () => req<any>('/api/analytics/summary')
export const getTopRules = () => req<any>('/api/analytics/top-rules')
export const getTopUris = () => req<any>('/api/analytics/top-uris')
export const getTimeline = (params: Record<string, string> = {}) => {
  const qs = Object.entries(params)
    .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
    .join('&')
  return req<any>(`/api/analytics/timeline${qs ? '?' + qs : ''}`)
}
