import { useEffect, useState } from 'react'
import {
  getAppMode,
  getIngestSettings,
  setIngestAuditLog,
  type AppModeInfo,
  type IngestStatus,
} from '../api'

const LAB_DEFAULT_PATH = '/shared/modsec/audit.log'

export default function Settings() {
  const [appMode, setAppMode] = useState<AppModeInfo | null>(null)
  const [ingest, setIngest] = useState<IngestStatus | null>(null)
  const [auditPath, setAuditPath] = useState(LAB_DEFAULT_PATH)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const load = async () => {
    setLoading(true)
    setError(null)
    try {
      const [modeInfo, ingestInfo] = await Promise.all([getAppMode(), getIngestSettings()])
      setAppMode(modeInfo)
      setIngest(ingestInfo)
      if (ingestInfo?.modsec_audit_log) setAuditPath(ingestInfo.modsec_audit_log)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  const saveAuditPath = async () => {
    if (busy || !auditPath.trim()) return
    setBusy(true)
    setError(null)
    setMessage(null)
    try {
      const result = await setIngestAuditLog(auditPath.trim())
      setIngest(result)
      setMessage(result.message || 'Audit log path saved.')
      await load()
    } catch (e: any) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  const copySnippet = async () => {
    const snippet = appMode?.audit_log_contract?.example_snippet || ''
    if (!snippet) return
    try {
      await navigator.clipboard.writeText(snippet)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      setError('Could not copy to clipboard')
    }
  }

  const contract = appMode?.audit_log_contract

  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h1 className="text-xl font-bold">Settings</h1>
        <p className="text-xs muted mt-1 leading-relaxed">
          Configure the ModSecurity audit log path. Copy proposed exclusions from
          Exceptions into your own Nginx/Apache config. Edit <span className="font-mono">lab-data/.env</span>{' '}
          for LLM keys, then restart the backend container.
        </p>
      </div>

      {loading && <p className="muted text-sm">Loading…</p>}
      {error && <div className="alert-error">{error}</div>}
      {message && (
        <div className="border-l-2 border-emerald-600 bg-emerald-50 text-emerald-800 dark:bg-emerald-950/30 dark:text-emerald-300 px-3 py-2 text-xs">
          {message}
        </div>
      )}

      <section className="card space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <p className="section-label">ModSecurity audit log</p>
            <p className="text-xs muted mt-0.5">JSON Serial path as seen by waf-tuner-backend</p>
          </div>
          <button type="button" className="btn-ghost text-xs" onClick={load} disabled={busy}>
            ↻ Refresh
          </button>
        </div>
        <input
          className="input-field w-full font-mono text-xs"
          value={auditPath}
          onChange={(e) => setAuditPath(e.target.value)}
          spellCheck={false}
        />
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            className="btn-success text-xs"
            disabled={busy || !auditPath.trim()}
            onClick={saveAuditPath}
          >
            {busy ? 'Saving…' : 'Save path'}
          </button>
          <button type="button" className="btn-ghost text-xs" onClick={() => setAuditPath(LAB_DEFAULT_PATH)}>
            Lab default
          </button>
        </div>
        {ingest && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs border-t border-stone-200 dark:border-zinc-800 pt-3">
            <div>
              <span className="muted">Exists</span>
              <p className="font-mono">{ingest.exists ? 'yes' : 'no'}</p>
            </div>
            <div>
              <span className="muted">Readable</span>
              <p className="font-mono">{ingest.readable ? 'yes' : 'no'}</p>
            </div>
            <div>
              <span className="muted">Size</span>
              <p className="font-mono">{ingest.size_bytes ?? 0} B</p>
            </div>
            <div>
              <span className="muted">Source</span>
              <p className="font-mono">{ingest.source}</p>
            </div>
          </div>
        )}
      </section>

      {appMode && (
        <section className="card space-y-3">
          <p className="section-label">Product</p>
          <p className="text-xs muted leading-relaxed">{appMode.description}</p>
          {appMode.env && (
            <div className="text-xs space-y-1 border-t border-stone-200 dark:border-zinc-800 pt-3">
              {Object.entries(appMode.env).map(([k, v]) => (
                <p key={k} className="font-mono break-all">
                  <span className="text-amber-500">{k}</span>={v || '—'}
                </p>
              ))}
            </div>
          )}
        </section>
      )}

      {contract && (
        <section className="card space-y-3">
          <div className="flex justify-between items-center">
            <p className="section-label">Audit log contract</p>
            {contract.example_snippet && (
              <button type="button" className="btn-ghost text-xs" onClick={copySnippet}>
                {copied ? '✓ Copied' : 'Copy snippet'}
              </button>
            )}
          </div>
          {contract.example_snippet && (
            <pre className="mono-block text-xs whitespace-pre-wrap">{contract.example_snippet}</pre>
          )}
        </section>
      )}
    </div>
  )
}
