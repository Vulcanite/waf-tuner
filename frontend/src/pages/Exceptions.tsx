import { useEffect, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import {
  getExceptions,
  approveException,
  rejectException,
  downloadFalsePositivesExcel,
} from '../api'

const TABS = [
  { key: 'pending', label: 'Pending Review' },
  { key: 'approved', label: 'Reviewed / ready to copy' },
  { key: 'rejected', label: 'Rejected' },
]

function confidenceBorder(confidence: number) {
  if (confidence >= 0.85) return 'border-l-4 border-l-emerald-500'
  if (confidence >= 0.6) return 'border-l-4 border-l-amber-500'
  return 'border-l-4 border-l-zinc-500'
}

function ExpandableBlock({
  label,
  children,
  defaultOpen = false,
}: {
  label: string
  children: ReactNode
  defaultOpen?: boolean
}) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="text-xs muted hover:opacity-80 flex items-center gap-1 mb-1"
      >
        {open ? '▼' : '▶'} {label}
      </button>
      {open && children}
    </div>
  )
}

function operatorKind(name: string | undefined): string {
  if (!name) return 'unknown operator'
  const n = name.toLowerCase()
  if (n === '@rx') return 'regular expression (@rx)'
  if (n === '@detectsqli') return 'libinjection SQLi (@detectSQLi)'
  if (n === '@detectxss') return 'libinjection XSS (@detectXSS)'
  if (n.startsWith('@pm')) return `phrase match (${name})`
  if (n === '@streq') return 'string equality (@streq)'
  if (n === '@beginswith') return 'prefix match (@beginsWith)'
  if (n === '@contains') return 'contains (@contains)'
  return name
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
  const [actionError, setActionError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const copyRule = async () => {
    if (!draft.proposed_rule) return
    try {
      await navigator.clipboard.writeText(draft.proposed_rule)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      setActionError('Could not copy rule to clipboard')
    }
  }

  const zone = draft.zone || draft.proposed_rule_scope || {}
  const sig = draft.signature || {}
  const match = draft.this_match || {}
  const event = draft.event_summary || {}
  const evidence = draft.evidence || null
  const ruleId = zone.rule_id || sig.rule_id
  const collection = zone.collection || '—'
  const parameter = zone.parameter || '—'
  const path = zone.uri || '—'

  const doApprove = async () => {
    setBusy(true)
    setActionError(null)
    try {
      await approveException(draft.id)
      onAction()
    } catch (e: any) {
      setActionError(e.message)
    } finally {
      setBusy(false)
    }
  }

  const doReject = async () => {
    setBusy(true)
    setActionError(null)
    try {
      await rejectException(draft.id, rejectReason)
      onAction()
    } catch (e: any) {
      setActionError(e.message)
    } finally {
      setBusy(false)
    }
  }

  const canApprove =
    draft.status === 'pending' &&
    draft.classification === 'false_positive' &&
    draft.validation_status === 'valid' &&
    !!draft.proposed_rule

  return (
    <div className={`card ${confidenceBorder(draft.confidence)} space-y-4`}>
      {/* 1. Decision summary */}
      <section>
        <p className="section-label">Decision</p>
        <p className="text-sm leading-relaxed font-medium">{draft.verdict}</p>
        <div className="flex flex-wrap gap-2 mt-2 text-xs items-center">
          <span
            className={`badge badge-${
              draft.classification === 'false_positive'
                ? 'deployed'
                : draft.classification === 'true_positive'
                  ? 'rejected'
                  : 'pending'
            }`}
          >
            {draft.classification}
          </span>
          <span className="text-amber-500 font-semibold">
            {Math.round((draft.confidence || 0) * 100)}% confidence
          </span>
          <span className="muted">{draft.status}</span>
          {event.anomaly_score != null && (
            <span className="muted" title="Computed anomaly score for this transaction (other rules may still fire)">
              txn anomaly {event.anomaly_score}
            </span>
          )}
        </div>
        {(draft.context_factors || []).length > 0 && (
          <ul className="mt-2 text-xs muted list-disc pl-4">
            {draft.context_factors.slice(0, 5).map((f: string, i: number) => (
              <li key={i}>{f}</li>
            ))}
          </ul>
        )}
        {(draft.uncertainty_factors || []).length > 0 && (
          <details className="mt-2">
            <summary className="text-xs muted cursor-pointer">Uncertainty factors</summary>
            <ul className="mt-1 text-xs muted list-disc pl-4">
              {draft.uncertainty_factors.slice(0, 6).map((f: string, i: number) => (
                <li key={i}>{f}</li>
              ))}
            </ul>
          </details>
        )}
      </section>

      {/* 2. Signature — human first, raw operator collapsed */}
      <section>
        <p className="section-label">Matched signature (CRS)</p>
        <div className="text-sm space-y-2">
          <p>
            <span className="text-amber-500 font-semibold">[{ruleId || '—'}]</span>{' '}
            {sig.message || match.rule_message || '—'}
          </p>
          <div className="flex flex-wrap gap-3 text-xs">
            {sig.paranoia_level != null && (
              <span className="badge-stale">PL{sig.paranoia_level}</span>
            )}
            {sig.severity && <span className="badge-stale">{sig.severity}</span>}
            {sig.phase != null && <span className="badge-stale">phase {sig.phase}</span>}
            {sig.chain && <span className="badge-stale">chained</span>}
          </div>
          <div className="text-xs space-y-1">
            <p>
              <span className="muted">Detection: </span>
              <span className="font-medium">{operatorKind(sig.operator_name || (sig.operator || '').split(/\s+/)[0])}</span>
            </p>
            {sig.targets?.length > 0 && (
              <p>
                <span className="muted">CRS targets: </span>
                <span className="font-mono text-amber-500">{sig.targets.join(' | ')}</span>
              </p>
            )}
          </div>
          {sig.tags?.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {sig.tags.slice(0, 10).map((t: string) => (
                <span key={t} className="badge-stale">
                  {t}
                </span>
              ))}
            </div>
          )}
          {(sig.operator || draft.crs_rule_raw) && (
            <div className="space-y-1 mt-1">
              {sig.operator && (
                <ExpandableBlock label="Full operator pattern (advanced)">
                  <div className="mono-block text-xs break-all whitespace-pre-wrap">
                    {sig.operator}
                  </div>
                  {sig.operator_summary && sig.operator.length > 120 && (
                    <p className="text-xs muted mt-1">
                      Long patterns are collapsed by default so the card stays readable.
                    </p>
                  )}
                </ExpandableBlock>
              )}
              <ExpandableBlock label="Raw CRS SecRule">
                <div className="mono-block text-xs break-all whitespace-pre-wrap">
                  {draft.crs_rule_raw || '—'}
                </div>
              </ExpandableBlock>
            </div>
          )}
        </div>
      </section>

      {/* 3. Zone */}
      <section>
        <p className="section-label">Match target (zone)</p>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
          <div>
            <span className="muted">method</span>
            <p className="font-semibold">{zone.method || event.method || '—'}</p>
          </div>
          <div>
            <span className="muted">path</span>
            <p className="font-semibold break-all">{path}</p>
          </div>
          <div>
            <span className="muted">collection</span>
            <p className="font-semibold text-amber-500">{collection}</p>
          </div>
          <div>
            <span className="muted">parameter</span>
            <p className="font-semibold text-amber-500">{parameter}</p>
          </div>
        </div>
        {event.uri && event.uri !== zone.uri && (
          <p className="text-xs muted mt-1">Full request URI: {event.uri}</p>
        )}
      </section>

      {/* 4. Evidence — snippet vs full value */}
      <section>
        <p className="section-label">Matched evidence</p>
        {evidence?.snippet || match.matched_data ? (
          <div className="space-y-2">
            <div>
              <p className="text-xs muted mb-0.5">
                What CRS matched (snippet — may be truncated by ModSecurity)
              </p>
              <div className="mono-block text-xs">
                {evidence?.snippet || match.matched_data || '—'}
              </div>
            </div>
            {evidence?.variable && (
              <p className="text-xs muted">
                Inspected variable:{' '}
                <span className="text-amber-500 font-mono">{evidence.variable}</span>
              </p>
            )}
            {evidence?.full_value != null && evidence.full_value !== evidence.snippet && (
              <div>
                <p className="text-xs muted mb-0.5">Full value of that variable (as logged)</p>
                <div className="mono-block text-xs">{evidence.full_value}</div>
              </div>
            )}
            {evidence?.raw && evidence.raw !== evidence.snippet && (
              <ExpandableBlock label="Raw matched_data line">
                <div className="mono-block text-xs">{evidence.raw}</div>
              </ExpandableBlock>
            )}
          </div>
        ) : (
          <div className="mono-block text-xs muted">—</div>
        )}
        {event.raw_request?.body != null && event.raw_request.body !== '' && (
          <div className="mt-2">
            <ExpandableBlock label="Request body (as logged)">
              <div className="mono-block text-xs">
                {typeof event.raw_request.body === 'string'
                  ? event.raw_request.body
                  : JSON.stringify(event.raw_request.body, null, 2)}
              </div>
            </ExpandableBlock>
          </div>
        )}
      </section>

      {/* 5. Exclusion + risk note */}
      <section>
        <p className="section-label">Proposed exclusion (system-built)</p>
        <div className="flex flex-wrap items-center gap-2 text-xs mb-2">
          <span className="muted">Validation</span>
          <span
            className={
              draft.validation_status === 'valid'
                ? 'badge-deployed'
                : draft.validation_status === 'not_applicable' ||
                    draft.validation_status === 'not_requested'
                  ? 'badge-stale'
                  : 'badge-rejected'
            }
          >
            {draft.validation_status || 'unknown'}
          </span>
          {draft.rule_placement && (
            <span className="muted">
              placement: {String(draft.rule_placement).replace(/_/g, ' ')}
            </span>
          )}
        </div>
        {draft.validation_error && (
          <div className="alert-error mb-2">{draft.validation_error}</div>
        )}
        {draft.proposed_rule ? (
          <>
            <div className="mono-block rule-ok text-xs break-all whitespace-pre-wrap">
              {draft.proposed_rule}
            </div>
            <div className="flex flex-wrap gap-2 mt-2">
              <button type="button" className="btn-ghost text-xs" onClick={copyRule}>
                {copied ? '✓ Copied' : '⎘ Copy SecRule'}
              </button>
            </div>
            <p className="text-xs muted mt-2 leading-relaxed border-l-2 border-amber-600/60 pl-2">
              Copy this rule into your ModSecurity exceptions include (Nginx or Apache). It disables{' '}
              <span className="text-amber-500 font-mono">rule {ruleId}</span> only for{' '}
              <span className="text-amber-500 font-mono">
                {collection}
                {parameter !== '—' ? `:${parameter}` : ''}
              </span>{' '}
              on path <span className="text-amber-500 font-mono">{path}</span>. This app does not
              write edge config.
            </p>
          </>
        ) : (
          <p className="text-xs muted">
            No approvable exclusion. The platform only ships policy-validated, system-built rules.
          </p>
        )}
      </section>

      {/* 6. Links / actions */}
      <div className="flex flex-wrap gap-2 items-center pt-1 border-t border-stone-200 dark:border-zinc-800">
        {draft.analysis_case_id && (
          <Link
            to={`/cases/${draft.analysis_case_id}`}
            className="text-xs text-amber-500 hover:underline font-medium"
            title="Open this analysis case"
          >
            Related case #{draft.analysis_case_id} →
          </Link>
        )}
        {draft.status === 'pending' && (
          <>
            <button
              type="button"
              onClick={doApprove}
              disabled={busy || !canApprove}
              title={
                !canApprove
                  ? 'Requires false_positive + validation_status=valid + proposed rule'
                  : `Mark reviewed / ready to copy for rule ${ruleId}`
              }
              className="btn-success text-xs"
            >
              ✓ Mark ready to copy
            </button>
            <button
              type="button"
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
                  className="input-field flex-1 min-w-32 text-xs"
                />
                <button type="button" onClick={doReject} disabled={busy} className="btn-danger text-xs">
                  Confirm reject
                </button>
              </>
            )}
          </>
        )}
        {draft.status === 'approved' && (
          <span className="badge-approved badge">Ready to copy into your config</span>
        )}
        {draft.status === 'rejected' && draft.rejection_reason && (
          <span className="text-xs text-red-400">Reason: {draft.rejection_reason}</span>
        )}
      </div>
      {actionError && (
        <div aria-live="polite" className="text-xs text-red-400">
          {actionError}
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
      setError(null)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    setPage(1)
  }, [tab, classification])

  useEffect(() => {
    load()
  }, [tab, classification, page])

  const totalPages = Math.max(1, Math.ceil(total / limit))

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <h1 className="text-xl font-bold">Exceptions</h1>
          <p className="text-xs muted mt-1">
            Review classifications, copy exclusion SecRules into your own Nginx/Apache
            config. This app never writes edge configuration.
          </p>
        </div>
        <button
          type="button"
          className="btn-ghost text-xs"
          onClick={() => downloadFalsePositivesExcel(tab === 'pending' ? undefined : tab)}
        >
          Export FPs (Excel)
        </button>
      </div>

      <div className="border-l-2 border-amber-600/60 bg-amber-500/5 px-3 py-2 text-xs leading-relaxed">
        <strong className="text-amber-500">Copy-paste workflow</strong> — paste rules under your
        ModSecurity exceptions include, run <span className="font-mono">nginx -t</span> / Apache
        configtest, then reload. See Settings for the audit log contract.
      </div>

      <div className="flex flex-wrap gap-2 border-b border-stone-200 dark:border-zinc-800 pb-2">
        {TABS.map((t) => (
          <button
            key={t.key}
            type="button"
            onClick={() => setTab(t.key)}
            className={`px-3 py-1.5 text-sm rounded ${
              tab === t.key ? 'bg-amber-500/20 text-amber-500' : 'muted'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="flex gap-2 flex-wrap">
        {CLASSIFICATIONS.map((c) => (
          <button
            key={c.key || 'all'}
            type="button"
            onClick={() => setClassification(c.key)}
            className={`text-xs px-2 py-1 rounded border ${
              classification === c.key
                ? 'border-amber-500 text-amber-500'
                : 'border-stone-300 dark:border-zinc-700 muted'
            }`}
          >
            {c.label}
          </button>
        ))}
      </div>

      {error && <div className="text-red-400 text-sm">{error}</div>}
      {loading && <p className="muted text-sm">Loading…</p>}
      {!loading && drafts.length === 0 && (
        <p className="muted text-sm">No drafts in this view.</p>
      )}

      <div className="space-y-4">
        {drafts.map((d) => (
          <ExceptionCard key={d.id} draft={d} onAction={load} />
        ))}
      </div>

      {totalPages > 1 && (
        <div className="flex justify-between text-xs muted">
          <button
            type="button"
            className="btn-ghost"
            disabled={page <= 1}
            onClick={() => setPage((p) => p - 1)}
          >
            Prev
          </button>
          <span>
            {page} / {totalPages} · {total} total
          </span>
          <button
            type="button"
            className="btn-ghost"
            disabled={page >= totalPages}
            onClick={() => setPage((p) => p + 1)}
          >
            Next
          </button>
        </div>
      )}
    </div>
  )
}
