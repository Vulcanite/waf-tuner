import { useEffect, useState } from 'react'
import { getPending, deployExceptions, rollbackException } from '../api'

interface PendingItem {
  id: number
  transaction_id: string
  verdict: string
  proposed_rule: string | null
  proposed_rule_scope: { uri?: string; rule_id?: string; parameter?: string } | null
  confidence: number
}

interface DeployLog {
  ts: string
  ids: number[]
  deployed: number[]
  failed: number[]
  nginx_reloaded: boolean
}

export default function Deploy() {
  const [pending, setPending] = useState<PendingItem[]>([])
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [log, setLog] = useState<DeployLog[]>([])
  const [loading, setLoading] = useState(true)
  const [deploying, setDeploying] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<any | null>(null)

  const load = async () => {
    setLoading(true)
    try {
      const data = await getPending()
      setPending(data.items)
      // Select all by default
      setSelected(new Set(data.items.map((i: PendingItem) => i.id)))
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const toggleSelect = (id: number) => {
    setSelected((prev) => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  const handleDeploy = async () => {
    if (selected.size === 0) return
    setDeploying(true)
    setResult(null)
    setError(null)
    try {
      const ids = Array.from(selected)
      const res = await deployExceptions(ids)
      setResult(res)
      setLog((prev) => [
        { ts: new Date().toISOString(), ids, ...res },
        ...prev,
      ])
      await load()
    } catch (e: any) {
      setError(e.message)
    } finally {
      setDeploying(false)
    }
  }

  const handleRollback = async (id: number) => {
    try {
      await rollbackException(id)
      await load()
    } catch (e: any) {
      setError(e.message)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-zinc-100">Deploy Panel</h1>
        <button onClick={load} className="btn-ghost text-xs">↻ Refresh</button>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-800 rounded-lg px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {result && (
        <div className={`rounded-lg px-4 py-3 text-sm border ${
          result.nginx_reloaded
            ? 'bg-emerald-900/30 border-emerald-800 text-emerald-300'
            : 'bg-amber-900/30 border-amber-800 text-amber-300'
        }`}>
          {result.deployed.length > 0 && (
            <p>✓ {result.deployed.length} rule(s) deployed (IDs: {result.deployed.join(', ')})</p>
          )}
          {result.failed.length > 0 && (
            <p>✗ {result.failed.length} failed (IDs: {result.failed.join(', ')})</p>
          )}
          <p>{result.nginx_reloaded ? '✓ nginx reloaded successfully' : '⚠ nginx reload failed'}</p>
        </div>
      )}

      {/* Pending exceptions checklist */}
      {loading ? (
        <div className="text-zinc-500 text-center py-12">Loading…</div>
      ) : pending.length === 0 ? (
        <div className="card text-center text-zinc-600 py-12">
          No approved exceptions waiting for deployment.
          <br />
          <span className="text-zinc-700 text-xs">Approve exceptions on the Exceptions page first.</span>
        </div>
      ) : (
        <div className="space-y-3">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-zinc-400">{selected.size} of {pending.length} selected</span>
            <div className="flex gap-2">
              <button onClick={() => setSelected(new Set(pending.map((i) => i.id)))} className="btn-ghost text-xs">
                Select all
              </button>
              <button onClick={() => setSelected(new Set())} className="btn-ghost text-xs">
                Deselect all
              </button>
            </div>
          </div>

          {pending.map((item) => (
            <div
              key={item.id}
              className={`card cursor-pointer transition-colors ${
                selected.has(item.id) ? 'border-amber-700 bg-zinc-900' : 'border-zinc-800 opacity-60'
              }`}
              onClick={() => toggleSelect(item.id)}
            >
              <div className="flex items-start gap-3">
                <input
                  type="checkbox"
                  checked={selected.has(item.id)}
                  onChange={() => toggleSelect(item.id)}
                  onClick={(e) => e.stopPropagation()}
                  className="mt-1 accent-amber-500"
                />
                <div className="flex-1 space-y-2">
                  <div className="flex flex-wrap gap-3 text-xs text-zinc-500">
                    <span className="text-zinc-400 font-medium">#{item.id}</span>
                    {item.proposed_rule_scope?.uri && (
                      <span><span className="text-zinc-500">URI:</span> <span className="text-zinc-300">{item.proposed_rule_scope.uri}</span></span>
                    )}
                    {item.proposed_rule_scope?.rule_id && (
                      <span><span className="text-zinc-500">rule:</span> <span className="text-amber-400">{item.proposed_rule_scope.rule_id}</span></span>
                    )}
                    <span>{Math.round(item.confidence * 100)}% confidence</span>
                  </div>
                  <p className="text-sm text-zinc-300">{item.verdict}</p>
                  {item.proposed_rule && (
                    <div className="mono-block text-emerald-300 text-xs">{item.proposed_rule}</div>
                  )}
                </div>
              </div>
            </div>
          ))}

          <div className="pt-2">
            <button
              onClick={handleDeploy}
              disabled={selected.size === 0 || deploying}
              className="btn-primary w-full py-2.5 text-sm"
            >
              {deploying ? 'Deploying…' : `Deploy ${selected.size} selected exception${selected.size !== 1 ? 's' : ''}`}
            </button>
          </div>
        </div>
      )}

      {/* Deployment log */}
      {log.length > 0 && (
        <div className="space-y-2">
          <h2 className="text-sm font-semibold text-zinc-400">Deployment Log</h2>
          <div className="rounded-lg border border-zinc-800 overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-zinc-800 bg-zinc-900/80">
                  <th className="text-left px-4 py-2 text-zinc-500">Timestamp</th>
                  <th className="text-left px-3 py-2 text-zinc-500">Deployed</th>
                  <th className="text-left px-3 py-2 text-zinc-500">Failed</th>
                  <th className="text-left px-3 py-2 text-zinc-500">Nginx</th>
                </tr>
              </thead>
              <tbody>
                {log.map((entry, i) => (
                  <tr key={i} className="border-b border-zinc-900">
                    <td className="px-4 py-2 text-zinc-400">{new Date(entry.ts).toLocaleString()}</td>
                    <td className="px-3 py-2 text-emerald-400">{entry.deployed.join(', ') || '—'}</td>
                    <td className="px-3 py-2 text-red-400">{entry.failed.join(', ') || '—'}</td>
                    <td className="px-3 py-2">
                      <span className={entry.nginx_reloaded ? 'text-emerald-400' : 'text-red-400'}>
                        {entry.nginx_reloaded ? '✓ ok' : '✗ failed'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
