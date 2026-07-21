import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { getCases, getCase, reanalyzeCase } from '../api'

export default function Cases() {
  const { caseId: caseIdParam } = useParams()
  const navigate = useNavigate()
  const [items, setItems] = useState<any[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [state, setState] = useState('')
  const [ruleId, setRuleId] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<any | null>(null)
  const [busyId, setBusyId] = useState<number | null>(null)
  const limit = 30

  const load = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await getCases({
        page,
        limit,
        state: state || undefined,
        rule_id: ruleId || undefined,
      })
      setItems(data.items || [])
      setTotal(data.total || 0)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  const openDetail = async (id: number, updateUrl = true) => {
    try {
      const detail = await getCase(id)
      setSelected(detail)
      if (updateUrl) navigate(`/cases/${id}`, { replace: false })
    } catch (e: any) {
      setError(e.message)
      setSelected(null)
    }
  }

  useEffect(() => {
    load()
  }, [page, state, ruleId])

  // Deep-link: /cases/26 opens that case in the detail pane
  useEffect(() => {
    if (!caseIdParam) return
    const id = Number(caseIdParam)
    if (!Number.isFinite(id) || id <= 0) return
    if (selected?.id === id) return
    openDetail(id, false)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caseIdParam])

  const doReanalyze = async (id: number) => {
    setBusyId(id)
    try {
      await reanalyzeCase(id)
      await load()
      await openDetail(id, false)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setBusyId(null)
    }
  }

  const totalPages = Math.max(1, Math.ceil(total / limit))

  const revisions = selected?.revisions || []
  const successful = revisions.filter(
    (r: any) => r.state === 'complete' && r.classification
  )
  const failed = revisions.filter(
    (r: any) => r.state === 'retryable_error' || r.state === 'failed' || r.state === 'analyzing'
  )
  const latest = successful[0] || revisions[0]

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <h1 className="text-xl font-bold">Cases</h1>
          <p className="text-xs muted mt-1 max-w-2xl leading-relaxed">
            A <strong>case</strong> is one unique signature match pattern (path + rule + parameter +
            payload fingerprint). The AI analyzes each case once; repeats only increase the count.
            Use this page to inspect analysis history and re-run the model.
          </p>
        </div>
        <span className="muted text-sm">{total.toLocaleString()} total</span>
      </div>

      <div className="flex flex-wrap gap-3 items-end">
        <div>
          <label className="section-label">State</label>
          <select
            value={state}
            onChange={(e) => {
              setPage(1)
              setState(e.target.value)
            }}
            className="input-field"
          >
            <option value="">All</option>
            <option value="queued">queued</option>
            <option value="analyzing">analyzing</option>
            <option value="complete">complete</option>
            <option value="retryable_error">retryable_error</option>
            <option value="failed">failed</option>
          </select>
        </div>
        <div>
          <label className="section-label">Rule ID</label>
          <input
            value={ruleId}
            onChange={(e) => {
              setPage(1)
              setRuleId(e.target.value)
            }}
            placeholder="942100"
            className="input-field w-32"
          />
        </div>
      </div>

      {error && <div className="text-red-400 text-sm">{error}</div>}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="table-wrap">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-stone-200 dark:border-zinc-800 text-left muted">
                <th className="px-3 py-2">Case</th>
                <th className="px-3 py-2">Path</th>
                <th className="px-3 py-2">Rule</th>
                <th className="px-3 py-2">Zone</th>
                <th className="px-3 py-2">n</th>
                <th className="px-3 py-2">State</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr>
                  <td colSpan={6} className="px-3 py-8 text-center muted">
                    Loading…
                  </td>
                </tr>
              )}
              {!loading && items.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-3 py-8 text-center muted">
                    No cases yet
                  </td>
                </tr>
              )}
              {items.map((c) => (
                <tr
                  key={c.id}
                  onClick={() => openDetail(c.id)}
                  className={`row-hover ${selected?.id === c.id ? 'bg-amber-500/10' : ''}`}
                >
                  <td className="px-3 py-2 text-amber-500 font-semibold">#{c.id}</td>
                  <td className="px-3 py-2 max-w-[10rem] truncate">
                    {c.method} {c.path}
                  </td>
                  <td className="px-3 py-2 text-amber-500">{c.rule_id}</td>
                  <td className="px-3 py-2 muted text-xs">
                    {c.collection || '—'}
                    {c.parameter ? `:${c.parameter}` : ''}
                  </td>
                  <td className="px-3 py-2">{c.occurrence_count}</td>
                  <td className="px-3 py-2">
                    <span
                      className={
                        c.state === 'failed'
                          ? 'badge-rejected'
                          : c.state === 'complete'
                            ? 'badge-deployed'
                            : c.state === 'queued'
                              ? 'badge-pending'
                              : 'badge-stale'
                      }
                    >
                      {c.state}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="flex justify-between items-center px-3 py-2 text-xs muted">
            <button
              className="btn-ghost"
              disabled={page <= 1}
              onClick={() => setPage((p) => p - 1)}
            >
              Prev
            </button>
            <span>
              {page} / {totalPages}
            </span>
            <button
              className="btn-ghost"
              disabled={page >= totalPages}
              onClick={() => setPage((p) => p + 1)}
            >
              Next
            </button>
          </div>
        </div>

        <div className="card space-y-3 min-h-[20rem]">
          {!selected && (
            <p className="muted text-sm">
              Select a case (or open <span className="font-mono">/cases/&lt;id&gt;</span>) to inspect
              analysis results and re-queue the model.
            </p>
          )}
          {selected && (
            <>
              <div className="flex justify-between gap-2 items-start">
                <div>
                  <p className="text-amber-500 font-semibold text-lg">Case #{selected.id}</p>
                  <p className="text-sm">
                    {selected.method} {selected.path}
                  </p>
                  <p className="text-xs muted mt-1">
                    rule {selected.rule_id} · {selected.collection || '—'}
                    {selected.parameter ? `:${selected.parameter}` : ''} · seen{' '}
                    {selected.occurrence_count}× · state{' '}
                    <span className="text-amber-500">{selected.state}</span>
                  </p>
                </div>
                <button
                  className="btn-primary text-xs"
                  disabled={busyId === selected.id || selected.state === 'analyzing'}
                  onClick={() => doReanalyze(selected.id)}
                >
                  {busyId === selected.id ? '…' : 'Reanalyze'}
                </button>
              </div>
              {selected.last_error && selected.state !== 'complete' && (
                <div className="alert-error">{selected.last_error}</div>
              )}
              <div>
                <p className="section-label">Matched data</p>
                <div className="mono-block text-xs">{selected.matched_data || '—'}</div>
              </div>

              {latest && latest.state === 'complete' && (
                <div>
                  <p className="section-label">Latest analysis</p>
                  <div className="border border-stone-200 dark:border-zinc-800 rounded p-3 text-xs space-y-2">
                    <div className="flex gap-2 flex-wrap items-center">
                      <span className="badge-stale">revision #{latest.id}</span>
                      {latest.classification && (
                        <span className="text-amber-500 font-semibold">
                          {latest.classification}
                        </span>
                      )}
                      {latest.confidence != null && (
                        <span>{Math.round(latest.confidence * 100)}%</span>
                      )}
                      <span className="muted">{latest.validation_status}</span>
                      {latest.model && <span className="muted">{latest.model}</span>}
                    </div>
                    {latest.verdict && <p className="leading-relaxed">{latest.verdict}</p>}
                    {latest.normalized_rule && (
                      <div className="mono-block rule-ok">{latest.normalized_rule}</div>
                    )}
                  </div>
                </div>
              )}

              {failed.length > 0 && (
                <details>
                  <summary className="text-xs muted cursor-pointer">
                    Earlier failed attempts ({failed.length}) — retries / timeouts / truncated model
                    output
                  </summary>
                  <div className="space-y-2 max-h-48 overflow-y-auto mt-2">
                    {failed.map((r: any) => (
                      <div
                        key={r.id}
                        className="border border-stone-200 dark:border-zinc-800 rounded p-2 text-xs space-y-1"
                      >
                        <div className="flex gap-2 flex-wrap">
                          <span className="badge-stale">#{r.id}</span>
                          <span>{r.state}</span>
                        </div>
                        {(r.validation_error || r.last_error) && (
                          <p className="text-red-400">{r.validation_error || r.last_error}</p>
                        )}
                      </div>
                    ))}
                  </div>
                </details>
              )}

              {!revisions.length && <p className="muted text-xs">No revisions yet</p>}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
