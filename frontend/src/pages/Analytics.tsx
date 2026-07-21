import { useEffect, useState } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  LineChart, Line, CartesianGrid,
} from 'recharts'
import { getSummary, getTopRules, getTopUris, getTimeline } from '../api'

interface Summary {
  total_events: number
  total_drafts: number
  pending_review: number
  approved: number
  ready_to_copy?: number
  rejected: number
}

function StatCard({ label, value, accent }: { label: string; value: number; accent?: boolean }) {
  return (
    <div className={`card flex flex-col gap-1 ${accent ? 'border-amber-700' : ''}`}>
      <span className="text-xs text-zinc-500 uppercase tracking-widest">{label}</span>
      <span className={`text-3xl font-bold ${accent ? 'text-amber-400' : 'text-zinc-100'}`}>
        {value.toLocaleString()}
      </span>
    </div>
  )
}

const CHART_STYLE = {
  fill: '#f59e0b',
  stroke: '#f59e0b',
  background: 'transparent',
}

export default function Analytics() {
  const [summary, setSummary] = useState<Summary | null>(null)
  const [topRules, setTopRules] = useState<any[]>([])
  const [topUris, setTopUris] = useState<any[]>([])
  const [timeline, setTimeline] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = async () => {
    try {
      setLoading(true)
      const [s, r, u, t] = await Promise.all([
        getSummary(),
        getTopRules(),
        getTopUris(),
        getTimeline({ interval: 'hour' }),
      ])
      setSummary(s)
      setTopRules(r)
      setTopUris(u)
      setTimeline(t)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  if (loading) return <div className="text-zinc-500 py-12 text-center">Loading analytics…</div>
  if (error) return <div className="text-red-400 py-12 text-center">Error: {error}</div>

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-zinc-100">Analytics</h1>
        <button onClick={load} className="btn-ghost text-xs">↻ Refresh</button>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-3">
        <StatCard label="Total Events" value={summary?.total_events ?? 0} accent />
        <StatCard label="Total Drafts" value={summary?.total_drafts ?? 0} />
        <StatCard label="Pending" value={summary?.pending_review ?? 0} />
        <StatCard label="Ready to copy" value={summary?.ready_to_copy ?? summary?.approved ?? 0} />
        <StatCard label="Rejected" value={summary?.rejected ?? 0} />
      </div>

      {/* Timeline */}
      <div className="card">
        <h2 className="text-sm font-semibold text-zinc-300 mb-4">Event Volume (last 24h)</h2>
        {timeline.length === 0 ? (
          <div className="text-zinc-500 text-sm text-center py-8">No data yet</div>
        ) : (
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={timeline}>
              <CartesianGrid strokeDasharray="3 3" stroke="#3f3f46" />
              <XAxis
                dataKey="time"
                tick={{ fill: '#71717a', fontSize: 10 }}
                tickFormatter={(v) => v.slice(11, 16) || v.slice(5, 10)}
              />
              <YAxis tick={{ fill: '#71717a', fontSize: 10 }} />
              <Tooltip
                contentStyle={{ background: '#18181b', border: '1px solid #3f3f46', borderRadius: 6 }}
                labelStyle={{ color: '#a1a1aa' }}
                itemStyle={{ color: '#f59e0b' }}
              />
              <Line
                type="monotone"
                dataKey="count"
                stroke="#f59e0b"
                strokeWidth={2}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Top rules */}
        <div className="card">
          <h2 className="text-sm font-semibold text-zinc-300 mb-4">Top 10 Firing Rules</h2>
          {topRules.length === 0 ? (
            <div className="text-zinc-500 text-sm text-center py-8">No data yet</div>
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={topRules} layout="vertical">
                <XAxis type="number" tick={{ fill: '#71717a', fontSize: 10 }} />
                <YAxis
                  type="category"
                  dataKey="rule_id"
                  tick={{ fill: '#a1a1aa', fontSize: 10 }}
                  width={60}
                />
                <Tooltip
                  contentStyle={{ background: '#18181b', border: '1px solid #3f3f46', borderRadius: 6 }}
                  labelStyle={{ color: '#a1a1aa' }}
                  itemStyle={{ color: '#f59e0b' }}
                  formatter={(v: any, n: any, p: any) => [v, p.payload.rule_message || 'count']}
                />
                <Bar dataKey="count" fill="#f59e0b" radius={[0, 3, 3, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Top URIs */}
        <div className="card">
          <h2 className="text-sm font-semibold text-zinc-300 mb-4">Top 10 URIs by Event Count</h2>
          {topUris.length === 0 ? (
            <div className="text-zinc-500 text-sm text-center py-8">No data yet</div>
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={topUris} layout="vertical">
                <XAxis type="number" tick={{ fill: '#71717a', fontSize: 10 }} />
                <YAxis
                  type="category"
                  dataKey="uri"
                  tick={{ fill: '#a1a1aa', fontSize: 10 }}
                  width={80}
                />
                <Tooltip
                  contentStyle={{ background: '#18181b', border: '1px solid #3f3f46', borderRadius: 6 }}
                  labelStyle={{ color: '#a1a1aa' }}
                  itemStyle={{ color: '#f59e0b' }}
                />
                <Bar dataKey="count" fill="#d97706" radius={[0, 3, 3, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  )
}
