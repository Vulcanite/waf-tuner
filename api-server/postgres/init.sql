-- WAF Exception Agent — Postgres schema
-- exception_drafts table only; events are stored in events.jsonl

CREATE TABLE IF NOT EXISTS exception_drafts (
    id                  SERIAL PRIMARY KEY,
    transaction_id      TEXT NOT NULL,
    event_line          INTEGER NOT NULL,
    classification      TEXT NOT NULL,          -- 'false_positive' | 'true_positive' | 'uncertain'
    confidence          REAL NOT NULL,           -- 0.0 to 1.0
    verdict             TEXT NOT NULL,           -- fused confidence + reasoning sentence
    crs_rule_raw        TEXT,                    -- raw SecRule directive from CRS index
    proposed_rule       TEXT,                    -- ModSecurity SecRule exception string
    proposed_rule_scope JSONB,                   -- {uri, parameter, rule_id}
    status              TEXT NOT NULL DEFAULT 'pending',  -- 'pending'|'approved'|'rejected'|'deployed'|'stale'
    rejection_reason    TEXT,
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    reviewed_at         TIMESTAMPTZ,
    deployed_at         TIMESTAMPTZ,
    last_seen_at        TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS exception_drafts_status_idx ON exception_drafts(status);
CREATE INDEX IF NOT EXISTS exception_drafts_transaction_id_idx ON exception_drafts(transaction_id);
