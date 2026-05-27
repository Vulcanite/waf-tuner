import { useEffect, useState } from 'react'
import { getEvents } from '../api'

const STATUS_BADGE: Record<string, string> = {
  pending: 'badge-pending',
  approved: 'badge-approved',
  deployed: 'badge-deployed',
  rejected: 'badge-rejected',
  stale: 'badge-stale',
}

function ScoreBadge({ score }: { score: number }) {
  const color =
    score >= 10 ? 'text-red-400' : score >= 5 ? 'text-amber-400' : 'text-zinc-400'
  return <span className={`font-bold ${color}`}>{score}</span>
}

function ExpandedRow({ event }: { event: any }) {
  return (
    <tr className="bg-zinc-900/60">
      <td colSpan={7} className="px-6 py-4 space-y-3">
        <div>
          <p className="text-xs text-zinc-500 uppercase tracking-widest mb-1">Matches</p>
          <div className="space-y-1">
            {event.matches?.map((m: any, i: number) => (
              <div key={i} className="mono-block text-zinc-300">
                <span className="text-amber-400">[{m.rule_id}]</span> {m.rule_message}
                {m.matched_data && (
                  <div className="text-zinc-500 mt-0.5">{m.matched_data}</div>
                )}
              </div>
            ))}
          </div>
        </div>
        {event.raw_request?.body && (
          <div>
            <p className="text-xs text-zinc-500 uppercase tracking-widest mb-1">Request Body</p>
            <div className="mono-block text-zinc-400">{JSON.stringify(event.raw_request.body)}</div>
          </div>
        )}
      </td>
    </tr>
  )
}

export default function Events() {
  const [events, setEvents] = useState<any[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Filters
  const [ruleId, setRuleId] = useState('')
  const [uri, setUri] = useState('')
  const [minScore, setMinScore] = useState('')

  const limit = 50

  const load = async () => {
    setLoading(true)
    try {
      const data = await getEvents({
        page,
        limit,
        rule_id: ruleId || undefined,
        uri: uri || undefined,
        min_score: minScore ? Number(minScore) : undefined,
      })
      setEvents(data.items)
      setTotal(data.total)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [page, ruleId, uri, minScore])

  const toggleExpand = (txnId: string) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      next.has(txnId) ? next.delete(txnId) : next.add(txnId)
      return next
    })
  }

  const totalPages = Math.ceil(total / limit)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-zinc-100">Events</h1>
        <span className="text-zinc-500 text-sm">{total.toLocaleString()} total</span>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-end">
        <div className="flex flex-col gap-1">
          <label className="text-xs text-zinc-500">Rule ID</label>
          <input
            value={ruleId}
            onChange={(e) => { setRuleId(e.target.value); setPage(1) }}
            placeholder="e.g. 942100"
            className="bg-zinc-900 border border-zinc-700 rounded px-3 py-1.5 text-sm text-zinc-100 w-32 focus:outline-none focus:border-amber-600"
          />
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-xs text-zinc-500">URI contains</label>
          <input
            value={uri}
            onChange={(e) => { setUri(e.target.value); setPage(1) }}
            placeholder="e.g. /search"
            className="bg-zinc-900 border border-zinc-700 rounded px-3 py-1.5 text-sm text-zinc-100 w-40 focus:outline-none focus:border-amber-600"
          />
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-xs text-zinc-500">Min Score</label>
          <input
            value={minScore}
            onChange={(e) => { setMinScore(e.target.value); setPage(1) }}
            placeholder="e.g. 5"
            type="number"
            className="bg-zinc-900 border border-zinc-700 rounded px-3 py-1.5 text-sm text-zinc-100 w-24 focus:outline-none focus:border-amber-600"
          />
        </div>
        <button onClick={() => { setRuleId(''); setUri(''); setMinScore(''); setPage(1) }} className="btn-ghost text-xs self-end">
          Clear
        </button>
        <button onClick={load} className="btn-ghost text-xs self-end">↻ Refresh</button>
      </div>

      {error && <div className="text-red-400 text-sm">{error}</div>}

      <div className="overflow-x-auto rounded-lg border border-zinc-800">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-zinc-800 bg-zinc-900/80">
              <th className="text-left px-4 py-3 text-zinc-500 font-medium">Timestamp</th>
              <th className="text-left px-3 py-3 text-zinc-500 font-medium">Method</th>
              <th className="text-left px-3 py-3 text-zinc-500 font-medium">URI</th>
              <th className="text-left px-3 py-3 text-zinc-500 font-medium">Rule IDs</th>
              <th className="text-left px-3 py-3 text-zinc-500 font-medium">Score</th>
              <th className="text-left px-3 py-3 text-zinc-500 font-medium">Status</th>
              <th className="px-3 py-3" />
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={7} className="text-center text-zinc-500 py-12">Loading…</td>
              </tr>
            ) : events.length === 0 ? (
              <tr>
                <td colSpan={7} className="text-center text-zinc-600 py-12">No events yet. Run traffic generator to populate.</td>
              </tr>
            ) : (
              events.map((e, i) => (
                <>
                  <tr
                    key={e.transaction_id || i}
                    className="border-b border-zinc-900 hover:bg-zinc-900/40 cursor-pointer transition-colors"
                    onClick={() => toggleExpand(e.transaction_id)}
                  >
                    <td className="px-4 py-2.5 text-zinc-400">
                      {e.timestamp ? new Date(e.timestamp).toLocaleString() : '—'}
                    </td>
                    <td className="px-3 py-2.5">
                      <span className="text-amber-400">{e.method}</span>
                    </td>
                    <td className="px-3 py-2.5 text-zinc-300 max-w-xs truncate">{e.uri}</td>
                    <td className="px-3 py-2.5">
                      <div className="flex flex-wrap gap-1">
                        {e.matches?.slice(0, 3).map((m: any) => (
                          <span key={m.rule_id} className="bg-zinc-800 text-zinc-300 px-1.5 py-0.5 rounded text-xs">
                            {m.rule_id}
                          </span>
                        ))}
                        {e.matches?.length > 3 && (
                          <span className="text-zinc-500">+{e.matches.length - 3}</span>
                        )}
                      </div>
                    </td>
                    <td className="px-3 py-2.5">
                      <ScoreBadge score={e.anomaly_score ?? 0} />
                    </td>
                    <td className="px-3 py-2.5">
                      {e.draft_status ? (
                        <span className={STATUS_BADGE[e.draft_status] || 'badge'}>{e.draft_status}</span>
                      ) : (
                        <span className="text-zinc-600">—</span>
                      )}
                    </td>
                    <td className="px-3 py-2.5 text-zinc-600">
                      {expanded.has(e.transaction_id) ? '▲' : '▼'}
                    </td>
                  </tr>
                  {expanded.has(e.transaction_id) && (
                    <ExpandedRow key={`exp-${e.transaction_id}`} event={e} />
                  )}
                </>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center gap-3 justify-end text-sm">
          <button
            disabled={page <= 1}
            onClick={() => setPage((p) => p - 1)}
            className="btn-ghost disabled:opacity-30"
          >
            ← Prev
          </button>
          <span className="text-zinc-500">
            Page {page} / {totalPages}
          </span>
          <button
            disabled={page >= totalPages}
            onClick={() => setPage((p) => p + 1)}
            className="btn-ghost disabled:opacity-30"
          >
            Next →
          </button>
        </div>
      )}
    </div>
  )
}
