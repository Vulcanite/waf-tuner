// The model's structured explanation of one verdict. Revisions and drafts made before the
// explanation fields existed (prompt offpath-v7 and older) have nulls, shown as missing.
const FIELDS = [
  ['rule_looks_for', 'Rule looks for'],
  ['payload_is', 'Payload is'],
  ['why', 'Why'],
] as const

export default function Explanation({ source }: { source: Record<string, any> }) {
  return (
    <dl className="mt-2 text-xs space-y-1">
      {FIELDS.map(([key, label]) => (
        <div key={key}>
          <dt className="inline font-semibold">{label}: </dt>
          <dd className="inline">
            {typeof source[key] === 'string' && source[key].trim() ? source[key] : <span className="muted">missing</span>}
          </dd>
        </div>
      ))}
    </dl>
  )
}
