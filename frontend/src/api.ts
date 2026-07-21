// Same-origin /api when served via waf-tuner-frontend nginx proxy.
const BASE =
  import.meta.env.VITE_API_URL !== undefined && import.meta.env.VITE_API_URL !== ''
    ? import.meta.env.VITE_API_URL
    : typeof window !== 'undefined' && window.location.port === '3000'
      ? ''
      : `http://${typeof window !== 'undefined' ? window.location.hostname : 'localhost'}:8000`

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

// ---- Application context ----
export const getApplicationProfiles = () => req<any>('/api/application-profiles')

export const createApplicationProfile = (body: any) =>
  req<any>('/api/application-profiles', {
    method: 'POST',
    body: JSON.stringify(body),
  })

export const createApplicationProfileVersion = (id: number, body: any) =>
  req<any>(`/api/application-profiles/${id}`, {
    method: 'PUT',
    body: JSON.stringify(body),
  })

// ---- Deduplicated cases ----
export const getCases = (params: Record<string, string | number | undefined> = {}) => {
  const qs = Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== '')
    .map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`)
    .join('&')
  return req<any>(`/api/cases${qs ? '?' + qs : ''}`)
}

export const getCase = (id: number) => req<any>(`/api/cases/${id}`)

export const reanalyzeCase = (id: number) =>
  req<any>(`/api/cases/${id}/reanalyze`, { method: 'POST' })

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

// ---- Settings ----
export type IngestStatus = {
  modsec_audit_log: string
  explicitly_configured: boolean
  configured: boolean
  exists: boolean
  size_bytes: number
  readable: boolean
  source: string
  config_file?: string
  message?: string
  ok?: boolean
}

export type AppModeInfo = {
  config_writes_enabled: boolean
  deploy_enabled: boolean
  engine_mode_control_enabled: boolean
  description: string
  service?: string
  ingest?: IngestStatus
  audit_log_contract?: {
    format?: string
    type?: string
    required_fields?: string[]
    recommended_directives?: string[]
    notes?: string[]
    example_snippet?: string
  }
  env?: Record<string, string>
}

export const getAppMode = () => req<AppModeInfo>('/api/settings/product')
export const getIngestSettings = () => req<IngestStatus>('/api/settings/ingest')
export const setIngestAuditLog = (modsec_audit_log: string) =>
  req<IngestStatus>('/api/settings/ingest', {
    method: 'PUT',
    body: JSON.stringify({ modsec_audit_log }),
  })
