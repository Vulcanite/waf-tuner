import { useEffect, useState } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  LineChart, Line, CartesianGrid,
} from 'recharts'
import {
  getAnalysisHealth, getSummary, getTopRules, getTopUris, getTimeline,
  type AnalysisHealth,
} from '../api'

interface Summary {
  total_events: number
  total_drafts: number
  pending_review: number
  approved: number
  ready_to_copy?: number
  rejected: number
}

const tick = { fill: 'var(--chart-text)', fontSize: 10 }
const tooltipStyle = {
  background: 'var(--chart-tooltip-bg)',
  border: '1px solid var(--chart-tooltip-border)',
  borderRadius: 6,
  color: 'var(--chart-tooltip-label)',
}

function StatCard({ label, value, accent }: { label: string; value: number; accent?: boolean }) {
  return (
    <div className={`card flex flex-col gap-1 ${accent ? 'border-amber-600' : ''}`}>
      <span className="section-label">{label}</span>
      <span className={`text-3xl font-bold ${accent ? 'text-amber-600 dark:text-amber-400' : 'heading-text'}`}>
        {value.toLocaleString()}
      </span>
    </div>
  )
}

function HealthPanel({ health }: { health: AnalysisHealth }) {
  const valid = health.valid_output_rate == null ? '—' : `${Math.round(health.valid_output_rate * 100)}%`
  const repair = health.repair_rate == null ? '—' : `${Math.round(health.repair_rate * 100)}%`
  return (
    <section className="card space-y-3" aria-labelledby="analysis-health-heading">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h2 id="analysis-health-heading" className="text-sm font-semibold heading-text">Analysis health</h2>
          <p className="text-xs muted mt-1">{health.model} · {health.prompt_version}</p>
        </div>
        <span className={health.paused_by_budget ? 'badge-rejected' : 'badge-complete'}>
          {health.paused_by_budget ? 'paused by budget' : 'workers available'}
        </span>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-6 gap-3 text-xs">
        <div><p className="muted">Workers</p><p className="font-semibold text-lg">{health.worker_count}</p></div>
        <div><p className="muted">Requests / hour</p><p className="font-semibold text-lg">{health.hourly_requests_used}/{health.hourly_budget}</p></div>
        <div><p className="muted">Active attempts</p><p className="font-semibold text-lg">{health.active_attempts}</p></div>
        <div><p className="muted">Valid output</p><p className="font-semibold text-lg">{valid}</p></div>
        <div><p className="muted">Repair rate</p><p className="font-semibold text-lg">{repair}</p></div>
        <div><p className="muted">Structured output</p><p className="font-semibold text-lg">{health.structured_output ? 'on' : 'off'}</p></div>
      </div>
      <div className="grid md:grid-cols-3 gap-3 text-xs border-t border-stone-200 dark:border-zinc-800 pt-3">
        <div><p className="muted">Cases</p><p className="break-words">{Object.entries(health.cases_by_state).map(([k, v]) => `${k} ${v}`).join(' · ') || 'none'}</p></div>
        <div><p className="muted">Analysis errors</p><p className="break-words">{Object.entries(health.revisions_by_error_code).map(([k, v]) => `${k} ${v}`).join(' · ') || 'none'}</p></div>
        <div><p className="muted">Last success</p><p>{health.last_successful_completion ? new Date(health.last_successful_completion).toLocaleString() : 'none'}</p></div>
      </div>
    </section>
  )
}

export default function Analytics() {
  const [summary, setSummary] = useState<Summary | null>(null)
  const [health, setHealth] = useState<AnalysisHealth | null>(null)
  const [topRules, setTopRules] = useState<any[]>([])
  const [topUris, setTopUris] = useState<any[]>([])
  const [timeline, setTimeline] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = async () => {
    try {
      setLoading(true)
      const [s, h, r, u, t] = await Promise.all([
        getSummary(), getAnalysisHealth(), getTopRules(), getTopUris(), getTimeline({ interval: 'hour' }),
      ])
      setSummary(s); setHealth(h); setTopRules(r); setTopUris(u); setTimeline(t); setError(null)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])
  if (loading) return <div className="muted py-12 text-center">Loading analytics…</div>
  if (error) return <div className="text-red-700 dark:text-red-400 py-12 text-center">Error: {error}</div>

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold heading-text">Analytics</h1>
        <button onClick={load} className="btn-ghost text-xs">↻ Refresh</button>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-3">
        <StatCard label="Total Events" value={summary?.total_events ?? 0} accent />
        <StatCard label="Total Drafts" value={summary?.total_drafts ?? 0} />
        <StatCard label="Pending" value={summary?.pending_review ?? 0} />
        <StatCard label="Ready to copy" value={summary?.ready_to_copy ?? summary?.approved ?? 0} />
        <StatCard label="Rejected" value={summary?.rejected ?? 0} />
      </div>
      {health && <HealthPanel health={health} />}
      <div className="card">
        <h2 className="text-sm font-semibold heading-text mb-4">Event volume (last 24h)</h2>
        {timeline.length === 0 ? <div className="muted text-sm text-center py-8">No data yet</div> : (
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={timeline}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" />
              <XAxis dataKey="time" tick={tick} tickFormatter={(v) => v.slice(11, 16) || v.slice(5, 10)} />
              <YAxis tick={tick} />
              <Tooltip contentStyle={tooltipStyle} labelStyle={{ color: 'var(--chart-tooltip-label)' }} />
              <Line type="monotone" dataKey="count" stroke="#d97706" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="card">
          <h2 className="text-sm font-semibold heading-text mb-4">Top 10 firing rules</h2>
          {topRules.length === 0 ? <div className="muted text-sm text-center py-8">No data yet</div> : (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={topRules} layout="vertical">
                <XAxis type="number" tick={tick} />
                <YAxis type="category" dataKey="rule_id" tick={tick} width={64} />
                <Tooltip contentStyle={tooltipStyle} labelStyle={{ color: 'var(--chart-tooltip-label)' }} formatter={(v: any, _n: any, p: any) => [v, p.payload.rule_message || 'count']} />
                <Bar dataKey="count" fill="#d97706" radius={[0, 3, 3, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
        <div className="card">
          <h2 className="text-sm font-semibold heading-text mb-4">Top 10 URIs by event count</h2>
          {topUris.length === 0 ? <div className="muted text-sm text-center py-8">No data yet</div> : (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={topUris} layout="vertical">
                <XAxis type="number" tick={tick} />
                <YAxis type="category" dataKey="uri" tick={tick} width={150} tickFormatter={(v: string) => v.length > 20 ? `${v.slice(0, 18)}…` : v} />
                <Tooltip contentStyle={tooltipStyle} labelStyle={{ color: 'var(--chart-tooltip-label)' }} />
                <Bar dataKey="count" fill="#b45309" radius={[0, 3, 3, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  )
}
