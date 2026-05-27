import { useEffect, useState } from 'react'
import { getExceptions, approveException, rejectException, downloadFalsePositivesExcel } from '../api'

const TABS = [
  { key: 'pending', label: 'Pending Review' },
  { key: 'approved', label: 'Approved (queued)' },
  { key: 'deployed', label: 'Deployed' },
  { key: 'rejected', label: 'Rejected' },
  { key: 'stale', label: 'Stale' },
]

function confidenceBorder(confidence: number) {
  if (confidence >= 0.85) return 'border-l-4 border-l-emerald-500'
  if (confidence >= 0.60) return 'border-l-4 border-l-amber-500'
  return 'border-l-4 border-l-zinc-600'
}

function confidenceLabel(confidence: number) {
  if (confidence >= 0.85) return 'text-emerald-400'
  if (confidence >= 0.60) return 'text-amber-400'
  return 'text-zinc-500'
}

function CRSBlock({ raw }: { raw: string | null }) {
  const [open, setOpen] = useState(false)
  if (!raw) return null
  return (
    <div>
      <button
        onClick={() => setOpen((o) => !o)}
        className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors flex items-center gap-1 mb-1"
      >
        {open ? '▼' : '▶'} CRS Rule (raw SecRule)
      </button>
      {open && (
        <div className="mono-block text-zinc-400 text-xs">{raw}</div>
      )}
    </div>
  )
}

function ExceptionCard({
  draft,
  onAction,
}: {
  draft: any
  onAction: () => void
}) {
  const [rejectReason, setRejectReason] = useState('')
  const [showReject, setShowReject] = useState(false)
  const [busy, setBusy] = useState(false)

  const doApprove = async () => {
    setBusy(true)
    try { await approveException(draft.id) } finally { setBusy(false); onAction() }
  }

  const doReject = async () => {
    setBusy(true)
    try { await rejectException(draft.id, rejectReason) } finally { setBusy(false); onAction() }
  }

  const scope = draft.proposed_rule_scope || {}
  const event = draft.event_summary

  return (
    <div className={`card ${confidenceBorder(draft.confidence)} space-y-3`}>
      {/* Verdict — prominent */}
      <p className="text-sm text-zinc-100 leading-relaxed font-medium">{draft.verdict}</p>

      {/* Meta row */}
      <div className="flex flex-wrap gap-3 text-xs text-zinc-500">
        <span>
          <span className="text-zinc-400">rule</span>{' '}
          <span className="text-amber-400">{scope.rule_id || draft.proposed_rule_scope?.rule_id}</span>
        </span>
        {event && (
          <>
            <span>
              <span className="text-zinc-400">{event.method}</span>{' '}
              <span className="text-zinc-300">{event.uri}</span>
            </span>
            {event.timestamp && (
              <span>{new Date(event.timestamp).toLocaleString()}</span>
            )}
          </>
        )}
        <span className={`font-semibold ${confidenceLabel(draft.confidence)}`}>
          {Math.round(draft.confidence * 100)}% confidence
        </span>
        <span
          className={`badge badge-${draft.classification === 'false_positive' ? 'deployed' : draft.classification === 'true_positive' ? 'rejected' : 'pending'}`}
        >
          {draft.classification}
        </span>
      </div>

      {/* Matched data */}
      {event?.matches && (
        <div className="space-y-1">
          {event.matches.slice(0, 2).map((m: any, i: number) => (
            <div key={i} className="mono-block text-xs text-zinc-400">
              <span className="text-amber-500">[{m.rule_id}]</span> {m.matched_data || m.rule_message}
            </div>
          ))}
        </div>
      )}

      {/* CRS rule expandable */}
      <CRSBlock raw={draft.crs_rule_raw} />

      {/* Proposed rule */}
      {draft.proposed_rule && (
        <div>
          <p className="text-xs text-zinc-500 mb-1">Proposed exception rule</p>
          <div className="mono-block text-emerald-300 text-xs">{draft.proposed_rule}</div>
        </div>
      )}

      {/* Actions */}
      {draft.status === 'pending' && (
        <div className="flex flex-wrap gap-2 items-center pt-1">
          <button onClick={doApprove} disabled={busy} className="btn-success text-xs">
            ✓ Approve
          </button>
          <button
            onClick={() => setShowReject((s) => !s)}
            disabled={busy}
            className="btn-danger text-xs"
          >
            ✗ Reject
          </button>
          {showReject && (
            <>
              <input
                value={rejectReason}
                onChange={(e) => setRejectReason(e.target.value)}
                placeholder="Reason (optional)"
                className="bg-zinc-800 border border-zinc-700 rounded px-2 py-1 text-xs text-zinc-100 focus:outline-none focus:border-amber-600 flex-1 min-w-32"
              />
              <button onClick={doReject} disabled={busy} className="btn-danger text-xs">
                Confirm reject
              </button>
            </>
          )}
        </div>
      )}

      {draft.status === 'approved' && (
        <div className="flex items-center gap-2">
          <span className="badge-approved badge">Awaiting deployment</span>
        </div>
      )}

      {draft.status === 'deployed' && (
        <div className="flex flex-wrap gap-4 text-xs text-zinc-500">
          {draft.deployed_at && <span>Deployed: {new Date(draft.deployed_at).toLocaleString()}</span>}
          {draft.last_seen_at && <span>Last seen: {new Date(draft.last_seen_at).toLocaleString()}</span>}
        </div>
      )}

      {draft.status === 'rejected' && draft.rejection_reason && (
        <div className="text-xs text-red-400">Reason: {draft.rejection_reason}</div>
      )}

      {draft.status === 'stale' && draft.last_seen_at && (
        <div className="text-xs text-zinc-500">
          Last seen: {new Date(draft.last_seen_at).toLocaleString()} ·{' '}
          <span className="text-amber-400">Review for cleanup</span>
        </div>
      )}
    </div>
  )
}

const CLASSIFICATIONS = [
  { key: '', label: 'All' },
  { key: 'false_positive', label: 'False Positive' },
  { key: 'true_positive', label: 'True Positive' },
  { key: 'uncertain', label: 'Uncertain' },
]

export default function Exceptions() {
  const [tab, setTab] = useState('pending')
  const [classification, setClassification] = useState('')
  const [drafts, setDrafts] = useState<any[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const limit = 20

  const load = async () => {
    setLoading(true)
    try {
      const data = await getExceptions({
        status: tab,
        page,
        limit,
        ...(classification ? { classification } : {}),
      })
      setDrafts(data.items)
      setTotal(data.total)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [tab, page, classification])

  const handleTabChange = (key: string) => { setTab(key); setPage(1) }
  const handleClassification = (key: string) => { setClassification(key); setPage(1) }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-zinc-100">Exceptions</h1>
        <div className="flex items-center gap-2">
          <button
            onClick={() => downloadFalsePositivesExcel(tab !== 'pending' ? tab : undefined)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded border border-zinc-700 text-zinc-400 hover:text-emerald-400 hover:border-emerald-700 transition-colors"
            title="Download all false positives as Excel"
          >
            ↓ Export FP Excel
          </button>
          <button onClick={load} className="btn-ghost text-xs">↻ Refresh</button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-zinc-800">
        {TABS.map((t) => (
          <button
            key={t.key}
            onClick={() => handleTabChange(t.key)}
            className={`px-4 py-2 text-sm transition-colors border-b-2 ${
              tab === t.key
                ? 'text-amber-400 border-amber-500'
                : 'text-zinc-500 border-transparent hover:text-zinc-300'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Classification filter */}
      <div className="flex items-center gap-2">
        <span className="text-xs text-zinc-500">Filter:</span>
        {CLASSIFICATIONS.map((c) => {
          const active = classification === c.key
          const colorMap: Record<string, string> = {
            false_positive: active
              ? 'bg-emerald-900 text-emerald-300 border-emerald-600'
              : 'text-zinc-500 border-zinc-700 hover:text-emerald-400 hover:border-emerald-700',
            true_positive: active
              ? 'bg-red-950 text-red-300 border-red-700'
              : 'text-zinc-500 border-zinc-700 hover:text-red-400 hover:border-red-700',
            uncertain: active
              ? 'bg-zinc-700 text-zinc-200 border-zinc-500'
              : 'text-zinc-500 border-zinc-700 hover:text-zinc-300',
            '': active
              ? 'bg-zinc-700 text-zinc-100 border-zinc-500'
              : 'text-zinc-500 border-zinc-700 hover:text-zinc-300',
          }
          return (
            <button
              key={c.key}
              onClick={() => handleClassification(c.key)}
              className={`px-3 py-1 text-xs rounded border transition-colors ${colorMap[c.key]}`}
            >
              {c.label}
            </button>
          )
        })}
        {classification && (
          <span className="text-xs text-zinc-600 ml-1">
            — {total} result{total !== 1 ? 's' : ''}
          </span>
        )}
      </div>

      {error && <div className="text-red-400 text-sm">{error}</div>}

      {loading ? (
        <div className="text-zinc-500 text-center py-12">Loading…</div>
      ) : drafts.length === 0 ? (
        <div className="text-zinc-600 text-center py-12">
          No {tab} exceptions.{tab === 'pending' ? ' Run the agent worker to generate drafts.' : ''}
        </div>
      ) : (
        <div className="space-y-4">
          {drafts.map((d) => (
            <ExceptionCard key={d.id} draft={d} onAction={load} />
          ))}
        </div>
      )}

      {Math.ceil(total / limit) > 1 && (
        <div className="flex items-center gap-3 justify-end text-sm">
          <button disabled={page <= 1} onClick={() => setPage((p) => p - 1)} className="btn-ghost">← Prev</button>
          <span className="text-zinc-500">Page {page} / {Math.ceil(total / limit)}</span>
          <button disabled={page >= Math.ceil(total / limit)} onClick={() => setPage((p) => p + 1)} className="btn-ghost">Next →</button>
        </div>
      )}
    </div>
  )
}
