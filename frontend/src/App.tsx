import { useEffect, useState } from 'react'
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import { ThemeProvider, useTheme } from './theme'
import {
  getAppMode,
  getIngestSettings,
  setIngestAuditLog,
  type AppModeInfo,
  type IngestStatus,
} from './api'
import Analytics from './pages/Analytics'
import Events from './pages/Events'
import Exceptions from './pages/Exceptions'
import ApplicationProfiles from './pages/ApplicationProfiles'
import Cases from './pages/Cases'
import Settings from './pages/Settings'

const LAB_DEFAULT_PATH = '/shared/modsec/audit.log'

function NavItem({ to, label }: { to: string; label: string }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        `px-4 py-2 text-sm transition-colors rounded ${
          isActive
            ? 'text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-zinc-800'
            : 'muted hover:text-inherit'
        }`
      }
    >
      {label}
    </NavLink>
  )
}

function SetupGate({
  ingest,
  onSaved,
}: {
  ingest: IngestStatus
  onSaved: (s: IngestStatus) => void
}) {
  const [path, setPath] = useState(ingest.modsec_audit_log || LAB_DEFAULT_PATH)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const save = async () => {
    setBusy(true)
    setError(null)
    try {
      onSaved(await setIngestAuditLog(path.trim()))
    } catch (e: any) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="card max-w-lg w-full space-y-4">
        <div>
          <p className="text-amber-700 dark:text-amber-400 text-xs font-semibold uppercase tracking-wide">
            WAF Tuner · setup
          </p>
          <h1 className="text-xl font-bold mt-1">ModSecurity audit log path</h1>
          <p className="text-xs muted mt-2 leading-relaxed">
            Point the backend at your ModSecurity <strong>JSON Serial</strong> audit log. Lab default
            is fine for docker compose.
          </p>
        </div>
        <div>
          <label className="text-xs muted block mb-1" htmlFor="setup-path">
            Path inside waf-tuner-backend
          </label>
          <input
            id="setup-path"
            className="input-field w-full font-mono text-xs"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            spellCheck={false}
          />
        </div>
        <button type="button" className="btn-ghost text-xs" onClick={() => setPath(LAB_DEFAULT_PATH)}>
          Use lab default ({LAB_DEFAULT_PATH})
        </button>
        {error && <div className="alert-error text-xs">{error}</div>}
        <button
          type="button"
          className="btn-success text-sm"
          disabled={busy || !path.trim()}
          onClick={save}
        >
          {busy ? 'Saving…' : 'Save & continue'}
        </button>
      </div>
    </div>
  )
}

function Shell() {
  const { theme, toggle } = useTheme()
  const [mode, setMode] = useState<AppModeInfo | null>(null)
  const [ingest, setIngest] = useState<IngestStatus | null>(null)
  const [bootError, setBootError] = useState<string | null>(null)
  const [ready, setReady] = useState(false)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const [modeInfo, ingestInfo] = await Promise.all([
          getAppMode(),
          getIngestSettings().catch(() => null),
        ])
        if (cancelled) return
        setMode(modeInfo)
        setIngest(ingestInfo || modeInfo.ingest || null)
      } catch (e: any) {
        if (!cancelled) setBootError(e.message || 'Backend unreachable')
      } finally {
        if (!cancelled) setReady(true)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  const needsSetup =
    ready && !bootError && ingest != null && !ingest.explicitly_configured && !ingest.exists

  if (!ready) {
    return (
      <div className="min-h-screen flex items-center justify-center muted text-sm">
        Connecting to waf-tuner backend…
      </div>
    )
  }

  if (bootError) {
    return (
      <div className="min-h-screen flex items-center justify-center px-4">
        <div className="card max-w-md space-y-2">
          <h1 className="font-bold text-lg">Backend unreachable</h1>
          <p className="text-xs text-red-700 dark:text-red-400">{bootError}</p>
        </div>
      </div>
    )
  }

  if (needsSetup && ingest) {
    return <SetupGate ingest={ingest} onSaved={setIngest} />
  }

  return (
    <BrowserRouter>
      {/* Fixed viewport shell: page itself does not grow; children scroll internally */}
      <div className="h-dvh flex flex-col overflow-hidden">
        <header className="surface-header flex-shrink-0 z-50 backdrop-blur">
          <div className="max-w-screen-xl mx-auto px-6 flex items-center h-14 gap-2 flex-wrap">
            <span className="text-amber-700 dark:text-amber-400 font-bold tracking-tight mr-2">⚡ WAF Tuner</span>
            {ingest && !ingest.exists && (
              <span className="text-[10px] text-amber-600" title={ingest.modsec_audit_log}>
                log missing
              </span>
            )}
            <NavItem to="/" label="Analytics" />
            <NavItem to="/events" label="Events" />
            <NavItem to="/cases" label="Cases" />
            <NavItem to="/exceptions" label="Exceptions" />
            <NavItem to="/profiles" label="Application Context" />
            <NavItem to="/settings" label="Settings" />
            <button type="button" onClick={toggle} className="btn-ghost text-xs ml-auto">
              {theme === 'dark' ? '☀ Light' : '☾ Dark'}
            </button>
          </div>
        </header>

        <main className="flex-1 min-h-0 overflow-y-auto">
          <div className="max-w-screen-xl mx-auto w-full h-full px-6 py-4">
            <Routes>
              <Route path="/" element={<Analytics />} />
              <Route path="/events" element={<Events />} />
              <Route path="/cases" element={<Cases />} />
              <Route path="/cases/:caseId" element={<Cases />} />
              <Route path="/exceptions" element={<Exceptions />} />
              <Route path="/profiles" element={<ApplicationProfiles />} />
              <Route path="/settings" element={<Settings />} />
            </Routes>
          </div>
        </main>

        <footer className="flex-shrink-0 border-t border-stone-200 dark:border-zinc-900 py-2 text-center text-xs muted">
          WAF Tuner · copy exclusion rules · never writes edge config
          {mode?.service ? ` · ${mode.service}` : ''}
        </footer>
      </div>
    </BrowserRouter>
  )
}

export default function App() {
  return (
    <ThemeProvider>
      <Shell />
    </ThemeProvider>
  )
}
