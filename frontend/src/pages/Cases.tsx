import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { getCases, getCase, reanalyzeCase } from '../api'
import Explanation from '../Explanation'

const ACTIVE_STATES = new Set(['queued', 'analyzing', 'retryable_error'])

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
    setError(null)
    try {
      const detail = await getCase(id)
      setSelected(detail)
      if (updateUrl) navigate(`/cases/${id}`, { replace: false })
    } catch (e: any) {
      setError(e.message)
      setSelected(null)
      // Invalid deep-link: fall back to list without looping
      if (caseIdParam && String(id) === String(caseIdParam)) {
        navigate('/cases', { replace: true })
      }
    }
  }

  useEffect(() => {
    load()
  }, [page, state, ruleId])

  // Deep-link / click: always load full case detail by id (not limited to current page).
  useEffect(() => {
    if (!caseIdParam) return
    const id = Number(caseIdParam)
    if (!Number.isFinite(id) || id <= 0) return
    if (selected?.id === id) return
    void openDetail(id, false)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caseIdParam])

  // If user clears filters/page, keep deep-linked selection; only clear when leaving /cases/:id
  // and the selected row is not the active URL target.
  useEffect(() => {
    if (!selected || loading) return
    if (caseIdParam && Number(caseIdParam) === selected.id) return
    if (caseIdParam) return // waiting for deep-link load
    // On plain /cases list, drop selection if filters hide it (optional UX)
    if (!items.some((item) => item.id === selected.id)) {
      setSelected(null)
    }
  }, [items, loading, selected?.id, caseIdParam])

  const activeCaseId = ACTIVE_STATES.has(selected?.state) ? selected.id : null
  const retryAt = selected?.next_retry_at
  useEffect(() => {
    if (!activeCaseId || (caseIdParam && Number(caseIdParam) !== activeCaseId)) return
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout>
    const poll = async () => {
      try {
        const detail = await getCase(activeCaseId, {}, controller.signal)
        if (controller.signal.aborted) return
        setSelected((current: any) => current?.id === activeCaseId ? detail : current)
        setItems((rows) => rows.map((row) => row.id === activeCaseId ? { ...row, state: detail.state } : row))
        if (!ACTIVE_STATES.has(detail.state)) return
      } catch (err: any) {
        if (controller.signal.aborted) return
        setError(err.message)
      }
      timer = setTimeout(poll, 1500)
    }
    const wait = retryAt ? Date.parse(retryAt) - Date.now() : 1500
    timer = setTimeout(poll, Math.max(1500, Math.min(15000, wait || 0)))
    return () => { clearTimeout(timer); controller.abort() }
  }, [activeCaseId, caseIdParam, retryAt])

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
  const latest = revisions[0]
  const previous = revisions.slice(1)

  const loadOlder = async () => {
    const id = selected.id
    try {
      const detail = await getCase(id, { before_revision: selected.next_revision })
      setSelected((current: any) => current?.id === id
        ? { ...current, revisions: [...current.revisions, ...detail.revisions], next_revision: detail.next_revision }
        : current)
    } catch (err: any) {
      setError(err.message)
    }
  }

  // Fill the app main area; page shell does not scroll — only table + detail panes do.
  return (
    <div className="flex flex-col gap-3 h-full min-h-0 overflow-hidden">
      <div className="flex-shrink-0 flex items-center justify-between flex-wrap gap-2">
        <div>
          <h1 className="text-xl font-bold">Cases</h1>
        </div>
        <span className="muted text-sm">{total.toLocaleString()} total</span>
      </div>

      <div className="flex-shrink-0 flex flex-wrap gap-4 items-end">
        <div className="flex flex-col gap-2">
          <label htmlFor="cases-state" className="section-label !mb-0">
            State
          </label>
          <select
            id="cases-state"
            value={state}
            onChange={(e) => {
              setPage(1)
              setState(e.target.value)
            }}
            className="input-field min-w-[10rem]"
          >
            <option value="">All states</option>
            <option value="queued">queued</option>
            <option value="analyzing">analyzing</option>
            <option value="complete">complete</option>
            <option value="retryable_error">retryable_error</option>
            <option value="failed">failed</option>
            <option value="stale">stale</option>
          </select>
        </div>
        <div className="flex flex-col gap-2">
          <label htmlFor="cases-rule-id" className="section-label !mb-0">
            Rule ID
          </label>
          <input
            id="cases-rule-id"
            value={ruleId}
            onChange={(e) => {
              setPage(1)
              setRuleId(e.target.value.trim())
            }}
            placeholder="filter"
            className="input-field w-36"
            inputMode="numeric"
            autoComplete="off"
          />
        </div>
        {(state || ruleId) && (
          <button
            type="button"
            className="btn-ghost text-xs"
            onClick={() => {
              setPage(1)
              setState('')
              setRuleId('')
            }}
          >
            Clear filters
          </button>
        )}
      </div>

      {error && (
        <div className="flex-shrink-0 text-red-700 dark:text-red-400 text-sm">{error}</div>
      )}

      {!loading && total === 0 && (state || ruleId) && (
        <div className="flex-shrink-0 border-l-2 border-amber-600/60 bg-amber-500/5 px-3 py-2 text-xs leading-relaxed">
          No cases match these filters
          {state ? (
            <>
              {' '}
              (state=<span className="font-mono">{state}</span>)
            </>
          ) : null}
          {ruleId ? (
            <>
              {' '}
              (rule=<span className="font-mono">{ruleId}</span>)
            </>
          ) : null}
          . Try{' '}
          <button
            type="button"
            className="text-amber-600 dark:text-amber-400 underline"
            onClick={() => {
              setPage(1)
              setState('')
              setRuleId('')
            }}
          >
            Clear filters
          </button>
          .
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 flex-1 min-h-0">
        {/* Left: table scrolls, pagination fixed */}
        <div className="table-wrap flex flex-col min-h-0 h-full overflow-hidden">
          <div className="flex-1 min-h-0 overflow-y-auto overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 z-10 bg-stone-50 dark:bg-zinc-900">
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
                      {state || ruleId
                        ? 'No cases match these filters'
                        : 'No cases yet — run traffic or the incident matrix'}
                    </td>
                  </tr>
                )}
                {items.map((c) => (
                  <tr
                    key={c.id}
                    onClick={() => {
                      void openDetail(c.id, true)
                    }}
                    className={`row-hover cursor-pointer ${selected?.id === c.id ? 'bg-amber-500/10' : ''}`}
                  >
                    <td className="px-3 py-2 text-amber-700 dark:text-amber-400 font-semibold">
                      #{c.id}
                    </td>
                    <td className="px-3 py-2 max-w-[10rem] truncate">
                      {c.method} {c.path}
                    </td>
                    <td className="px-3 py-2 text-amber-700 dark:text-amber-400">{c.rule_id}</td>
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
                              ? 'badge-complete'
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
          </div>
          <div className="flex-shrink-0 flex justify-between items-center px-3 py-2 text-xs muted border-t border-stone-200 dark:border-zinc-800">
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

        {/* Right: fixed panel height; content scrolls inside */}
        <div className="card flex flex-col min-h-0 h-full overflow-hidden p-0">
          <div className="flex-1 min-h-0 overflow-y-auto p-4 space-y-3">
            {!selected && (
              <p className="muted text-sm">
                Select a case (or open <span className="font-mono">/cases/&lt;id&gt;</span>) to
                inspect analysis results and re-queue the model.
              </p>
            )}
            {selected && (
              <>
                <div className="flex justify-between gap-2 items-start">
                  <div>
                    <p className="text-amber-700 dark:text-amber-400 font-semibold text-lg">
                      Case #{selected.id}
                    </p>
                    <p className="text-sm">
                      {selected.method} {selected.application_host || ''}{selected.path}
                    </p>
                    <p className="text-xs muted mt-1">
                      rule {selected.rule_id} · {selected.collection || '—'}
                      {selected.parameter ? `:${selected.parameter}` : ''} · seen{' '}
                      {selected.occurrence_count}× · state{' '}
                      <span className="text-amber-700 dark:text-amber-400">{selected.state}</span>
                    </p>
                  </div>
                  <button
                    className="btn-primary text-xs shrink-0"
                    disabled={busyId === selected.id || selected.state === 'analyzing' || selected.evidence_expired}
                    onClick={() => doReanalyze(selected.id)}
                  >
                    {busyId === selected.id ? '…' : 'Reanalyze'}
                  </button>
                </div>
                {selected.next_retry_at && (
                  <p className="text-xs muted" aria-live="polite">
                    {selected.budget_deferred ? 'Waiting for inference budget' : 'Retry scheduled'} ·{' '}
                    <time dateTime={selected.next_retry_at}>{new Date(selected.next_retry_at).toLocaleString()}</time>
                  </p>
                )}
                {selected.last_error && selected.state !== 'complete' && (
                  <div className="alert-error">{selected.last_error}</div>
                )}
                <div>
                  <p className="section-label">Matched data</p>
                  <div className="mono-block text-xs">{selected.evidence_expired ? 'Audit evidence expired' : selected.matched_data || '—'}</div>
                </div>

                {latest && (
                  <div>
                    <p className="section-label">Latest analysis</p>
                    <div className="border border-stone-200 dark:border-zinc-800 rounded p-3 text-xs space-y-2">
                      <div className="flex gap-2 flex-wrap items-center">
                        <span className="badge-stale">revision #{latest.id}</span>
                        <span>{latest.state}</span>
                        {latest.error_code && <span>{latest.error_code}</span>}
                        {latest.classification && (
                          <span className="text-amber-700 dark:text-amber-400 font-semibold">
                            {latest.classification}
                          </span>
                        )}
                        {latest.confidence != null && (
                          <span>model score {Math.round(latest.confidence * 100)}%</span>
                        )}
                        <span className="muted">{latest.validation_status}</span>
                        {latest.model && <span className="muted">{latest.model}</span>}
                      </div>
                      {latest.verdict && <p className="leading-relaxed">{latest.verdict}</p>}
                      {latest.classification && <Explanation source={latest} />}
                      {latest.validation_error && <p className="muted">{latest.validation_error}</p>}
                      {latest.normalized_rule && selected.state === 'complete' && (
                        <div className="mono-block rule-ok">{latest.normalized_rule}</div>
                      )}
                    </div>
                  </div>
                )}

                {(previous.length > 0 || selected.next_revision) && (
                  <details>
                    <summary className="text-xs muted cursor-pointer">
                      Earlier revisions ({previous.length})
                    </summary>
                    <div className="space-y-2 mt-2">
                      {previous.map((r: any) => (
                        <div
                          key={r.id}
                          className="border border-stone-200 dark:border-zinc-800 rounded p-2 text-xs space-y-1"
                        >
                          <div className="flex gap-2 flex-wrap">
                            <span className="badge-stale">#{r.id}</span>
                            <span>{r.state}</span>
                            {r.classification && <span>{r.classification}</span>}
                            {r.error_code && (
                              <span
                                className={
                                  r.error_code === 'budget_exhausted'
                                    ? 'badge-pending'
                                    : 'badge-rejected'
                                }
                              >
                                {r.error_code}
                              </span>
                            )}
                          </div>
                          {r.verdict && <p>{r.verdict}</p>}
                          {r.classification && <Explanation source={r} />}
                          {(r.validation_error || r.last_error) && (
                            <p className="text-red-700 dark:text-red-400">
                              {r.validation_error || r.last_error}
                            </p>
                          )}
                        </div>
                      ))}
                      {selected.next_revision && <button type="button" className="btn-ghost text-xs" onClick={loadOlder}>Load older revisions</button>}
                    </div>
                  </details>
                )}

                {!revisions.length && <p className="muted text-xs">No revisions yet</p>}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
