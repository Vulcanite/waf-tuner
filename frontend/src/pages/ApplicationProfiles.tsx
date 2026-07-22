import { FormEvent, useEffect, useMemo, useState } from 'react'
import {
  createApplicationProfile,
  createApplicationProfileVersion,
  getApplicationProfiles,
} from '../api'

type Profile = {
  id: number
  name: string
  version: number
  active: boolean
  host_patterns: string[]
  context: Record<string, unknown>
  routes: Array<Record<string, unknown>>
  source_metadata: Record<string, unknown>
}

const EMPTY_CONTEXT = JSON.stringify({
  languages: [],
  frameworks: [],
  data_stores: [],
  downstream_services: [],
  authentication: [],
}, null, 2)

const EMPTY_ROUTES = JSON.stringify([
  {
    path: '/search',
    methods: ['GET'],
    content_types: ['text/plain'],
    dependencies: [],
    notes: 'Facts are advisory and should be verified by an operator.',
  },
], null, 2)

export default function ApplicationProfiles() {
  const [profiles, setProfiles] = useState<Profile[]>([])
  const [editing, setEditing] = useState<Profile | null>(null)
  const [name, setName] = useState('')
  const [hosts, setHosts] = useState('')
  const [context, setContext] = useState(EMPTY_CONTEXT)
  const [routes, setRoutes] = useState(EMPTY_ROUTES)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const activeCount = useMemo(() => profiles.filter((profile) => profile.active).length, [profiles])

  const load = async () => {
    setLoading(true)
    try {
      const data = await getApplicationProfiles()
      setProfiles(data.items)
    } catch (err: any) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const editProfile = (profile: Profile) => {
    setEditing(profile)
    setName(profile.name)
    setHosts(profile.host_patterns.join(', '))
    setContext(JSON.stringify(profile.context, null, 2))
    setRoutes(JSON.stringify(profile.routes, null, 2))
    setError(null)
    setMessage(null)
  }

  const reset = () => {
    setEditing(null)
    setName('')
    setHosts('')
    setContext(EMPTY_CONTEXT)
    setRoutes(EMPTY_ROUTES)
  }

  const save = async (event: FormEvent) => {
    event.preventDefault()
    setSaving(true)
    setError(null)
    setMessage(null)
    try {
      const body = {
        name: name.trim(),
        host_patterns: hosts.split(',').map((host) => host.trim()).filter(Boolean),
        context: JSON.parse(context),
        routes: JSON.parse(routes),
        source_metadata: { type: 'manual', verified: true },
      }
      if (editing) {
        await createApplicationProfileVersion(editing.id, body)
        setMessage(`Created ${body.name} version ${editing.version + 1}. Existing analyses are now stale.`)
      } else {
        await createApplicationProfile(body)
        setMessage(`Created application profile ${body.name}.`)
      }
      reset()
      await load()
    } catch (err: any) {
      setError(err instanceof SyntaxError ? `Invalid JSON: ${err.message}` : err.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4 border-b border-stone-200 dark:border-zinc-800 pb-5">
        <div>
          <p className="text-[10px] uppercase tracking-[0.28em] text-amber-700 dark:text-amber-400">Analysis context</p>
          <h1 className="mt-1 text-xl font-bold heading-text">Application profiles</h1>
          <p className="mt-2 max-w-3xl text-sm leading-relaxed muted">
            Versioned facts enrich AI review. They never disable CRS signatures or bypass inspection.
          </p>
        </div>
        <div className="surface-subtle border px-4 py-2 text-right">
          <div className="text-lg font-semibold heading-text">{activeCount}</div>
          <div className="text-[10px] uppercase tracking-widest muted">active profiles</div>
        </div>
      </header>

      <div className="grid gap-6 lg:grid-cols-[0.82fr_1.18fr]">
        <section aria-labelledby="profile-list-heading" className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 id="profile-list-heading" className="text-sm font-semibold heading-text">Known applications</h2>
            <button onClick={load} className="btn-ghost text-xs">↻ Refresh</button>
          </div>
          {loading ? (
            <div className="card py-12 text-center text-sm muted">Loading profiles…</div>
          ) : profiles.length === 0 ? (
            <div className="border border-dashed border-stone-300 dark:border-zinc-800 px-5 py-12 text-center text-sm muted">
              No application context configured.
            </div>
          ) : profiles.map((profile) => (
            <article key={profile.id} className={`border p-4 ${profile.active ? 'border-amber-400 bg-amber-50 dark:border-amber-900/70 dark:bg-zinc-900' : 'border-stone-200 bg-stone-100 dark:border-zinc-900 dark:bg-zinc-950/40 opacity-60'}`}>
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-semibold heading-text">{profile.name}</h3>
                    <span className="text-[10px] muted">v{profile.version}</span>
                    {profile.active && <span className="badge-pending">active</span>}
                  </div>
                  <p className="mt-2 text-xs muted">{profile.host_patterns.join(', ') || 'all hosts'}</p>
                  <p className="mt-1 text-xs muted">{profile.routes.length} route definition(s)</p>
                </div>
                {profile.active && (
                  <button onClick={() => editProfile(profile)} className="btn-ghost text-xs">New version</button>
                )}
              </div>
            </article>
          ))}
        </section>

        <section aria-labelledby="profile-editor-heading" className="card p-5">
          <div className="mb-5 flex items-center justify-between">
            <div>
              <p className="text-[10px] uppercase tracking-[0.24em] muted">{editing ? 'Immutable revision' : 'New inventory'}</p>
              <h2 id="profile-editor-heading" className="mt-1 text-sm font-semibold heading-text">
                {editing ? `Create ${editing.name} v${editing.version + 1}` : 'Define application context'}
              </h2>
            </div>
            {editing && <button onClick={reset} className="btn-ghost text-xs">Cancel</button>}
          </div>

          <form onSubmit={save} className="space-y-4">
            <label className="block text-xs muted">
              Application name
              <input required disabled={Boolean(editing)} value={name} onChange={(event) => setName(event.target.value)} className="input-field mt-1 w-full py-2 outline-none focus:border-amber-600 disabled:opacity-50" />
            </label>
            <label className="block text-xs muted">
              Host patterns <span className="muted">— comma separated, wildcards allowed</span>
              <input value={hosts} onChange={(event) => setHosts(event.target.value)} placeholder="app.example.com, *.internal.example" className="input-field mt-1 w-full py-2 outline-none focus:border-amber-600" />
            </label>
            <div className="grid gap-4 xl:grid-cols-2">
              <label className="block text-xs muted">
                Application facts (JSON)
                <textarea required value={context} onChange={(event) => setContext(event.target.value)} rows={15} spellCheck={false} className="input-field mt-1 w-full resize-y p-3 font-mono text-xs leading-relaxed outline-none focus:border-amber-600" />
              </label>
              <label className="block text-xs muted">
                Route facts (JSON)
                <textarea required value={routes} onChange={(event) => setRoutes(event.target.value)} rows={15} spellCheck={false} className="input-field mt-1 w-full resize-y p-3 font-mono text-xs leading-relaxed outline-none focus:border-amber-600" />
              </label>
            </div>
            <div aria-live="polite" className="min-h-5 text-xs">
              {error && <span className="text-red-700 dark:text-red-400">{error}</span>}
              {message && <span className="text-emerald-700 dark:text-emerald-400">{message}</span>}
            </div>
            <button disabled={saving} className="btn-primary w-full py-2.5">
              {saving ? 'Saving immutable version…' : editing ? 'Create new version' : 'Create profile'}
            </button>
          </form>
        </section>
      </div>
    </div>
  )
}
