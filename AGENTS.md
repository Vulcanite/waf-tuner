# WAF Exception Agent — Implementation Plan
> Agentic coding reference document. Follow phases sequentially. Do not proceed to the next phase until all acceptance criteria for the current phase are met.

---

## Project Overview

A containerized system that sits on top of Nginx + ModSecurity, observes WAF events, runs an LLM agent to classify false positives and draft exception rules, and presents them to a human operator for approval and deployment via a web portal. Approved exceptions are batched and explicitly deployed by the operator — the portal writes the ModSecurity conf and triggers nginx reload.

---

## Repository Structure

```
waf-exception-agent/
├── docker-compose.yml
├── .env.example
├── nginx/
│   ├── Dockerfile
│   ├── nginx.conf
│   ├── modsecurity/
│   │   ├── modsecurity.conf
│   │   ├── crs-setup.conf
│   │   └── exceptions/          # agent-generated exception rules land here
├── target-app/
│   ├── Dockerfile
│   └── app.py                   # Flask app with realistic endpoints
├── api-server/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py                  # FastAPI entrypoint
│   ├── db/
│   │   ├── models.py            # exception_drafts table only
│   │   └── migrations/
│   ├── data/
│   │   ├── events.jsonl         # append-only event store (shared volume)
│   │   └── tracker.json         # offset tracker: {"last_offset": 0}
│   ├── services/
│   │   ├── log_tailer.py        # tails modsec audit log -> events.jsonl
│   │   ├── offset_tracker.py    # reads/writes tracker.json (byte offset)
│   │   ├── crs_index.py         # parses CRS .conf files -> in-memory rule index
│   │   ├── agent.py             # LLM agent logic
│   │   └── rule_writer.py       # writes approved exceptions to modsec conf
│   └── routers/
│       ├── events.py            # serves events from events.jsonl
│       ├── exceptions.py
│       ├── deploy.py            # deployment endpoints
│       └── analytics.py
├── portal/
│   ├── Dockerfile
│   ├── package.json
│   └── src/
│       ├── App.tsx
│       ├── pages/
│       │   ├── Events.tsx
│       │   ├── Exceptions.tsx
│       │   ├── Deploy.tsx       # deployment panel
│       │   └── Analytics.tsx
│       └── components/
├── traffic-generator/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── locustfile.py
└── postgres/
    └── init.sql                 # exception_drafts table only
```

---

## Environment Variables

Create `.env` from `.env.example`. All services read from this file.

```env
POSTGRES_USER=waf
POSTGRES_PASSWORD=waf
POSTGRES_DB=wafdb
POSTGRES_HOST=postgres
POSTGRES_PORT=5432

ANTHROPIC_API_KEY=sk-ant-...

MODSEC_AUDIT_LOG=/var/log/modsec/audit.log
EVENTS_JSONL_PATH=/app/data/events.jsonl
TRACKER_PATH=/app/data/tracker.json
MODSEC_EXCEPTIONS_DIR=/etc/nginx/modsecurity/exceptions/
CRS_RULES_DIR=/etc/nginx/modsecurity/crs/rules/
NGINX_CONTAINER_NAME=nginx

TARGET_APP_HOST=target-app
TARGET_APP_PORT=5000
```

---

## Phase 1 — Infrastructure Scaffold

**Goal:** All containers running. Traffic flows from traffic-generator → nginx → target-app. ModSecurity logs events as JSON to a shared volume. api-server can read from that volume.

### 1.1 docker-compose.yml

Define the following services:

```yaml
services:
  postgres:
  nginx:
  target-app:
  api-server:
  portal:
  traffic-generator:
```

**Networks:** All services on a single bridge network `waf-net`.

**Volumes:**
- `modsec-logs`: shared between `nginx` and `api-server`. nginx writes ModSecurity audit log here, api-server reads it.
- `waf-data`: shared between `api-server` and `nginx`. api-server writes `events.jsonl`, `tracker.json`, and approved exception `.conf` files here. nginx reads the exceptions directory from this volume.
- `crs-rules`: named volume populated by the nginx container's entrypoint script (copies `/etc/nginx/modsecurity/crs/rules/` into the volume on startup). Mounted read-only into `api-server` for CRS index parsing. **Note:** Docker named volumes cannot mount directly from another container's filesystem — the nginx entrypoint must explicitly copy the rules into this shared volume.
- `postgres-data`: persistent postgres storage.

**Special mounts:**
- api-server requires `/var/run/docker.sock:/var/run/docker.sock` (read-only) to trigger nginx config reload via the Docker SDK. This is a security-sensitive mount — acceptable for PoC but should be replaced with a signal-based approach in production.

**Health checks & startup ordering:**
- postgres: `pg_isready -U waf` — api-server depends on `postgres` with `condition: service_healthy`.
- nginx: `curl -f http://localhost:80/` — api-server and traffic-generator depend on nginx being healthy.
- api-server: `curl -f http://localhost:8000/health` — portal depends on api-server being healthy.

**Port mappings (host:container):**
- nginx: `8080:80`
- portal: `3000:3000`
- api-server: `8000:8000`
- target-app: internal only (no host port)
- traffic-generator: internal only
- postgres: `5432:5432`

### 1.2 Nginx + ModSecurity Container

Base image: `owasp/modsecurity-crs:nginx-alpine-202406`

**modsecurity.conf key settings:**
```
SecRuleEngine DetectionOnly
SecAuditEngine On
SecAuditLog /var/log/modsec/audit.log
SecAuditLogFormat JSON
SecAuditLogParts ABCFHIJKZ
SecRequestBodyAccess On
SecResponseBodyAccess On
```

**crs-setup.conf key settings:**
```
SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"
SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.paranoia_level=2"
SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=10,setvar:tx.outbound_anomaly_score_threshold=4"
```

**nginx.conf:** Reverse proxy all traffic to `target-app:5000`. Include ModSecurity. Include all `.conf` files in the exceptions directory from the `waf-data` volume.

### 1.3 Target Application

Flask app (`target-app/app.py`) with the following endpoints. These are designed to generate realistic false positives against OWASP CRS PL2:

```
GET  /                          # homepage
GET  /search?q=<query>          # search — triggers SQLi FP on queries like "select all items"
POST /login                     # form login — triggers FP on passwords with special chars
POST /comment                   # rich text submission — triggers XSS FP on markdown
POST /upload                    # file upload — triggers FP on binary content
GET  /api/users                 # JSON API endpoint
POST /api/data                  # JSON POST with nested payload
```

Each endpoint returns a simple JSON or HTML response. No auth required.

### 1.4 Postgres Schema

`postgres/init.sql` — exception_drafts table only. Events are stored in `events.jsonl`, not Postgres.

```sql
CREATE TABLE exception_drafts (
    id SERIAL PRIMARY KEY,
    transaction_id TEXT NOT NULL,        -- links back to event in events.jsonl
    event_line INTEGER NOT NULL,         -- line number in events.jsonl for direct lookup
    classification TEXT NOT NULL,        -- 'false_positive' | 'true_positive' | 'uncertain'
    confidence REAL NOT NULL,            -- 0.0 to 1.0 (used for card border color, filtering)
    verdict TEXT NOT NULL,               -- fused sentence: "We are 98% sure this is a false
                                         --   positive because the parameter is 'blog_content'
                                         --   and it matched SQL keyword 'union' inside a
                                         --   natural English paragraph."
    crs_rule_raw TEXT,                   -- raw SecRule directive from CRS index, for audit trail
    proposed_rule TEXT,                  -- ModSecurity SecRule exception string, null if uncertain/TP
    proposed_rule_scope JSONB,           -- {uri, parameter, rule_id}
    status TEXT NOT NULL DEFAULT 'pending', -- 'pending' | 'approved' | 'rejected' | 'deployed' | 'stale'
    rejection_reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    reviewed_at TIMESTAMPTZ,
    deployed_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ             -- updated when matching traffic is observed post-deployment
);

CREATE INDEX ON exception_drafts(status);
CREATE INDEX ON exception_drafts(transaction_id);
```

### 1.5 api-server Bootstrap

FastAPI app. On startup:
1. Run `init.sql` idempotently against Postgres.
2. Ensure `events.jsonl` and `tracker.json` exist on the `waf-data` volume (create if absent).
3. **Parse CRS rules directory and build in-memory rule index** (see Phase 1.5).
4. Start the log tailer as a background asyncio task.
5. Start the agent worker as a background asyncio task.
6. Start the stale checker as a background asyncio task.

**Phase 1 acceptance criteria:**
- [ ] `docker-compose up` starts all six containers without errors.
- [ ] Curling `localhost:8080/search?q=select+all` produces a log entry in the shared volume `audit.log`.
- [ ] `audit.log` entries are valid JSON.
- [ ] `events.jsonl` and `tracker.json` are created on startup.
- [ ] api-server connects to postgres without errors.
- [ ] api-server logs the count of CRS rules loaded at startup (e.g. "CRS index built: 172 rules").

---

## Phase 1.5 — CRS Rule Index

**Goal:** Build an in-memory index of all OWASP CRS rules at api-server startup, keyed by rule ID, so the agent has access to the full rule definition — not just the log message — when classifying each event. This is critical: classifying a false positive purely from the matched payload without understanding the rule's operator and targets produces inaccurate results.

### CRS Index Service (`api-server/services/crs_index.py`)

The CRS ships its rules as plain `.conf` files in the rules directory. Each `SecRule` directive spans one or more lines (continuation via `\`). The index parser reads all `.conf` files from `CRS_RULES_DIR`, extracts every `SecRule` block, and builds a dict keyed by rule ID.

**Parsed rule structure:**

```python
@dataclass
class CRSRule:
    rule_id: str
    raw: str              # full raw SecRule directive, exactly as written in the .conf file
    targets: list[str]    # e.g. ["ARGS", "REQUEST_BODY"]
    operator: str         # e.g. "@detectSQLi", "@rx (?i:union)", "@pmFromFile"
    message: str          # msg: value from the action list
    tags: list[str]       # all tag: values, e.g. ["attack-sqli", "paranoia-level/1", "OWASP_CRS"]
    paranoia_level: int   # extracted from paranoia-level/N tag, or 0 if absent
    phase: int            # phase:N from the action list
    severity: str         # severity: value, e.g. "CRITICAL", "WARNING"
    chain: bool           # True if rule uses 'chain' action (has a chained SecRule)
```

**Parser implementation:**

```python
import os
import re
from dataclasses import dataclass, field

CRS_INDEX: dict[str, CRSRule] = {}

def build_crs_index(rules_dir: str) -> dict[str, CRSRule]:
    index = {}
    for filename in sorted(os.listdir(rules_dir)):
        if not filename.endswith(".conf"):
            continue
        filepath = os.path.join(rules_dir, filename)
        with open(filepath, "r", errors="replace") as f:
            content = f.read()

        # Join continuation lines (lines ending with \)
        content = re.sub(r"\\\n\s*", " ", content)

        # Extract all SecRule blocks
        for match in re.finditer(
            r'SecRule\s+(\S+)\s+"([^"]+)"\s+"([^"]+)"',
            content,
            re.MULTILINE
        ):
            targets_raw, operator_raw, actions_raw = match.groups()
            raw = match.group(0)

            # Extract rule id
            id_match = re.search(r'\bid:(\d+)', actions_raw)
            if not id_match:
                continue
            rule_id = id_match.group(1)

            # Extract msg
            msg_match = re.search(r"msg:'([^']+)'", actions_raw)
            message = msg_match.group(1) if msg_match else ""

            # Extract tags
            tags = re.findall(r"tag:'([^']+)'", actions_raw)

            # Extract paranoia level from tags
            pl = 0
            for tag in tags:
                pl_match = re.match(r"paranoia-level/(\d+)", tag)
                if pl_match:
                    pl = int(pl_match.group(1))
                    break

            # Extract phase
            phase_match = re.search(r'\bphase:(\d+)', actions_raw)
            phase = int(phase_match.group(1)) if phase_match else 2

            # Extract severity
            sev_match = re.search(r'\bseverity:\'?(\w+)\'?', actions_raw)
            severity = sev_match.group(1) if sev_match else ""

            chain = "chain" in actions_raw
            
            # If the rule uses a chain, seek subsequent SecRules in the .conf block to capture complete chained context
            # (In production, group all sequential chained SecRules together and append them to 'raw')
            targets = [t.strip() for t in targets_raw.split("|")]
            operator = operator_raw.strip()

            index[rule_id] = CRSRule(
                rule_id=rule_id,
                raw=raw,
                targets=targets,
                operator=operator,
                message=message,
                tags=tags,
                paranoia_level=pl,
                phase=phase,
                severity=severity,
                chain=chain,
            )

    return index


def get_rule(rule_id: str) -> CRSRule | None:
    return CRS_INDEX.get(rule_id)
```

Call `CRS_INDEX = build_crs_index(CRS_RULES_DIR)` at api-server startup. The index is a module-level singleton — all services import `get_rule()` directly.

**What the index enables for the agent:**

| Without CRS index | With CRS index |
|---|---|
| "rule 942100 fired on `/search?q=select all`" | "rule 942100 uses `@detectSQLi` on `ARGS`, tagged `paranoia-level/1`, severity CRITICAL. The libinjection parser flagged `select` as a SQL token in an expression context." |
| Agent guesses based on rule message alone | Agent reasons from operator logic + targets + paranoia level |
| High false positive misclassification rate on ambiguous payloads | Paranoia level is a strong prior: PL3/PL4 rules flag far more false positives by design |

**Phase 1.5 acceptance criteria:**
- [ ] On api-server startup, `CRS_INDEX` is populated with at least 100 rules.
- [ ] `get_rule("942100")` returns a `CRSRule` with non-empty `operator`, `tags`, and `paranoia_level`.
- [ ] Rules with `paranoia-level/3` and `paranoia-level/4` tags are correctly parsed.
- [ ] Chained rules (`chain` action) are flagged with `chain=True`.
- [ ] Parser does not crash on malformed or comment-only `.conf` files.
- [ ] Startup log line confirms rule count: `"CRS index built: N rules from M files"`.

---

## Phase 2 — Log Ingestion Pipeline

**Goal:** ModSecurity JSON audit log events are parsed and appended to `events.jsonl` in real time. The line tracker stays in sync.

### 2.1 Log Tailer (`api-server/services/log_tailer.py`)

Background service that runs continuously. Reads the ModSecurity JSON audit log from the `modsec-logs` volume and appends parsed events to `events.jsonl` on the `waf-data` volume.

**ModSecurity JSON audit log format (relevant fields):**
```json
{
  "transaction": {
    "id": "abc123",
    "time": "2025-01-01T00:00:00Z",
    "client_ip": "172.18.0.1",
    "request": {
      "method": "GET",
      "uri": "/search?q=select+all",
      "headers": {},
      "body": ""
    },
    "messages": [
      {
        "ruleId": "942100",
        "message": "SQL Injection Attack Detected via libinjection",
        "data": "Matched Data: select found within ARGS:q"
      }
    ],
    "response": {
      "status": 200
    }
  }
}
```

**Parsing logic:**
- One JSON object per ModSecurity audit log entry (one transaction per blob).
- Emit one JSONL line per transaction, clustering all rule matches (messages) inside a single transaction object. This prevents transaction fragmentation and preserves the complete request context for the AI Agent.
- Each JSONL line written to `events.jsonl`:

```json
{
  "transaction_id": "abc123",
  "timestamp": "2025-01-01T00:00:00Z",
  "client_ip": "172.18.0.1",
  "method": "GET",
  "uri": "/search?q=select+all",
  "anomaly_score": 5,
  "raw_request": { "headers": {}, "body": "" },
  "matches": [
    {
      "rule_id": "942100",
      "rule_message": "SQL Injection Attack Detected via libinjection",
      "matched_data": "Matched Data: select found within ARGS:q"
    }
  ]
}
```

- Skip duplicate `transaction_id` entries by referencing a small, fixed-size in-memory cache of recent transactions.
- On parse error, log the raw line and continue — never crash the tailer.
- **Anomaly score extraction:** The ModSecurity JSON audit log does not include a top-level anomaly score. Compute it by summing severity scores of all matched rules in the transaction (CRITICAL=5, ERROR=4, WARNING=3, NOTICE=2). Alternatively, extract `TX:anomaly_score` from the audit log’s `part H` (trailer) if present.
- After appending to `events.jsonl`, check if the new event's URI matches any `deployed` exception’s `proposed_rule_scope.uri` in Postgres. If so, update `last_seen_at` on that draft. **Note:** Once an exception is deployed, `ctl:ruleRemoveTargetById` prevents the target rule from firing on the excluded parameter, so `last_seen_at` tracks whether the *URI itself* is still receiving traffic — not whether the specific rule is still firing. This is the correct signal for stale detection: if the URI stops receiving traffic entirely, the exception is likely stale.

### 2.2 Offset Tracker (`api-server/services/offset_tracker.py`)

`tracker.json` contains a single JSON object:

```json
{
  "last_offset": 0
}
```

- `last_offset` is the byte offset in `events.jsonl` marking the end of the last line the agent has successfully processed. The agent seeks to this offset on the next cycle, achieving O(1) startup regardless of file size.
- The tracker is updated atomically: write to `tracker.tmp`, then rename to `tracker.json`.
- Provide three functions:
  - `get_last_offset() -> int` — reads and returns `last_offset` from tracker.json.
  - `set_last_offset(n: int)` — atomically writes updated tracker.json.
  - `count_lines_to_offset(path: str, offset: int) -> int` — counts newlines from byte 0 to `offset` and returns the 0-based line number. Used when inserting drafts into Postgres (which stores `event_line` for the API).

**Phase 2 acceptance criteria:**
- [ ] After running traffic, `events.jsonl` is populated with one JSON object per line.
- [ ] Each line has non-null `transaction_id`, `uri`, `matched_data`, and a non-empty `matches` array.
- [ ] Duplicate `transaction_id` entries are not written twice.
- [ ] `tracker.json` exists and contains `{"last_offset": 0}` on first startup.
- [ ] Tailer recovers automatically if the ModSecurity audit log is temporarily missing.

---

## Phase 3 — Traffic Generation

**Goal:** Populate `events.jsonl` with a realistic distribution of ModSecurity events including both false positives and true positives.

### 3.1 Locust Scenarios (`traffic-generator/locustfile.py`)

Define the following user classes:

**NormalUser (weight: 70)**
Simulates legitimate application traffic that triggers false positives:
```python
# Scenarios:
- GET /search?q=select all products from category shoes
- GET /search?q=drop down menu navigation
- POST /comment with body containing markdown: **bold** and <em>italic</em>
- POST /login with password: P@ssw0rd!#$
- POST /upload with a small PNG file
- GET /api/users
- POST /api/data with nested JSON containing special characters
```

**AttackUser (weight: 10)**
Simulates actual attack traffic for true positives:
```python
# Scenarios:
- GET /search?q=1' OR '1'='1
- POST /login with body: username=admin'--&password=x
- GET /search?q=<script>alert(1)</script>
- POST /api/data with body: {"key": "'; DROP TABLE users; --"}
```

**ScannerUser (weight: 20)**
Simulates automated scanner noise:
```python
# Scenarios:
- GET /.env
- GET /wp-admin
- GET /phpmyadmin
- Various path traversal attempts: ../../etc/passwd
```

**Run config:** 50 concurrent users, ramp up over 30 seconds, run for 5 minutes. Target `http://nginx:80`.

**Phase 3 acceptance criteria:**
- [ ] After one Locust run, at least 200 lines are in `events.jsonl`.
- [ ] At least 5 distinct `rule_id` values are present.
- [ ] Events from NormalUser scenarios are present (verifiable by URI and matched_data).
- [ ] Events from AttackUser scenarios are present.

---

## Phase 4 — LLM Agent

**Goal:** Agent reads unprocessed lines from `events.jsonl` using the line tracker, classifies each event, and writes drafts to Postgres.

### 4.1 Agent Worker Loop (`api-server/services/agent.py`)

Runs as a background asyncio task every 30 seconds. Uses byte offset-based seeking instead of iterating through the entire file from line 0. A single transaction can trigger multiple CRS rules — the agent iterates over `event["matches"]` and creates one draft per match, with deduplication:

```python
async def agent_worker():
    while True:
        last_offset = get_last_offset()
        new_events, next_offset = read_jsonl_from_offset(
            EVENTS_JSONL_PATH,
            start_offset=last_offset,
            limit=10
        )
        if not new_events:
            await asyncio.sleep(30)
            continue
        for event, event_offset in new_events:
            event_line = count_lines_to_offset(EVENTS_JSONL_PATH, event_offset)
            # Process each rule match in the transaction independently
            for match in event.get("matches", []):
                # Deduplication: skip if a pending/approved/deployed draft already
                # exists for this exact scope (uri + parameter + rule_id)
                scope = extract_scope(event, match)
                if await db.draft_exists_for_scope(scope):
                    continue
                draft = await analyze_match(event, match, event_line)
                if draft:
                    await db.insert_draft(draft)
            set_last_offset(event_offset)
        await asyncio.sleep(30)
```

**`read_jsonl_from_offset` implementation:**
```python
def read_jsonl_from_offset(path: str, start_offset: int, limit: int) -> tuple[list[tuple[dict, int]], int]:
    results = []
    current_offset = start_offset
    with open(path, "r") as f:
        f.seek(start_offset)
        for _ in range(limit):
            line = f.readline()
            if not line:
                break
            current_offset = f.tell()
            try:
                results.append((json.loads(line.strip()), current_offset))
            except json.JSONDecodeError:
                continue   # skip malformed lines
    return results, current_offset
```

### 4.2 Agent Analysis (`analyze_match`)

The agent processes each rule match independently. A single transaction may trigger multiple rules — each match gets its own LLM call and its own draft row. This preserves a 1:1 mapping between drafts and rule exceptions.

**Deduplication helper:**
```python
def extract_scope(event: dict, match: dict) -> dict:
    """Extract the (uri, parameter, rule_id) scope for dedup lookup."""
    param = None
    md = match.get("matched_data", "")
    # Parse parameter name from matched_data,
    # e.g. "Matched Data: select found within ARGS:q" -> "q"
    if "within ARGS:" in md:
        param = md.split("within ARGS:")[-1].strip()
    elif "within REQUEST_BODY" in md:
        param = "REQUEST_BODY"
    return {"uri": event["uri"], "parameter": param, "rule_id": match["rule_id"]}
```

**`db.draft_exists_for_scope` query:**
```sql
SELECT EXISTS(
    SELECT 1 FROM exception_drafts
    WHERE status IN ('pending', 'approved', 'deployed')
      AND proposed_rule_scope->>'uri' = :uri
      AND proposed_rule_scope->>'parameter' = :parameter
      AND proposed_rule_scope->>'rule_id' = :rule_id
)
```

**Context object passed to the LLM — enriched with CRS rule:**
```python
crs_rule = get_rule(match["rule_id"])   # from crs_index module

context = {
    "uri": event["uri"],
    "method": event["method"],
    "rule_id": match["rule_id"],
    "rule_message": match["rule_message"],
    "matched_data": match["matched_data"],
    "anomaly_score": event["anomaly_score"],
    "raw_request": event.get("raw_request", {}),
    # Provide all matches in the transaction for cross-rule context
    "other_matches_in_transaction": [
        m for m in event.get("matches", []) if m["rule_id"] != match["rule_id"]
    ],
    # CRS rule enrichment — critical for accurate classification
    "crs_rule": {
        "raw": crs_rule.raw,
        "targets": crs_rule.targets,
        "operator": crs_rule.operator,
        "tags": crs_rule.tags,
        "paranoia_level": crs_rule.paranoia_level,
        "severity": crs_rule.severity,
        "chain": crs_rule.chain,
    } if crs_rule else None,
}
```

**System prompt:**
```
You are a WAF security analyst specializing in ModSecurity and OWASP CRS rule tuning.

You will receive a ModSecurity security event enriched with the full CRS rule definition
that triggered it. Use the rule's operator, targets, paranoia level, and tags — not just
the matched payload — to determine whether this is a false positive or a true positive.

Key reasoning guidance:
- The operator tells you exactly what the rule is detecting: @detectSQLi uses libinjection,
  @rx uses a regex pattern, @pmFromFile matches against a phrase list. Reason from the
  operator logic, not just the surface appearance of the payload.
- Paranoia level is a strong prior. PL3 and PL4 rules are intentionally aggressive and
  produce far more false positives than PL1/PL2. A PL4 rule firing on a blog post field
  is almost certainly a false positive.
- The targets list tells you which part of the request was inspected. A rule targeting
  ARGS firing on a parameter named 'blog_content', 'search_query', or 'comment_body'
  is a strong signal toward false positive. A rule targeting REQUEST_COOKIES or
  REQUEST_HEADERS firing on unusual content is stronger toward true positive.
- Chained rules require ALL conditions in the chain to match — a chain match is a
  stronger signal toward true positive than a single-rule match.

Respond ONLY with a JSON object in this exact format — no preamble, no markdown fences:

{
  "classification": "false_positive" | "true_positive" | "uncertain",
  "confidence": <float 0.0 to 1.0>,
  "verdict": "We are {confidence_pct}% sure this is a [false positive / true positive /
              uncertain case] because the parameter is '{parameter}' and {specific reason
              referencing the matched_data, the rule operator, and the paranoia level}.
              Example: We are 96% sure this is a false positive because the parameter is
              'search_query' and the @detectSQLi operator flagged the word 'select' inside
              a natural English sentence — a known libinjection false positive pattern on
              PL1 search endpoints.",
  "proposed_rule": "<ModSecurity SecRule exception string, or null>",
  "proposed_rule_scope": {
    "uri": "<exact URI pattern>",
    "parameter": "<specific parameter name, or null>",
    "rule_id": "<rule ID to suppress>"
  }
}

Rules for proposed_rule:
- Only generate a proposed_rule if classification is false_positive AND confidence >= 0.75.
- Scope as tightly as possible: specific URI + specific parameter + specific rule ID.
- Use target-specific rule exclusions. Do NOT use ruleRemoveById (which disables the rule entirely for the request). Use ruleRemoveTargetById to bypass the check ONLY on the triggered parameter.
- Example of a correctly scoped exception bypassing rule 942100 ONLY on parameter 'q' under the '/search' URI path:
  SecRule REQUEST_URI "@beginsWith /search" \
    "id:1000001,phase:2,pass,nolog,ctl:ruleRemoveTargetById=942100;ARGS:q"
- Never suppress entire rule categories, disable rule IDs globally for a URI, or use overly broad URI patterns like /.
- Set proposed_rule to null for true_positive or uncertain classifications.
```

**User prompt:**
```
Analyze this ModSecurity event. Pay close attention to the crs_rule field — the operator
and paranoia_level are the most important signals for determining false positive vs true
positive. Do not rely solely on the appearance of the matched_data.

{json.dumps(context, indent=2)}
```

**Response handling:**
- Parse the JSON response.
- If classification is `false_positive` and confidence < 0.75, downgrade to `uncertain` and set proposed_rule to null.
- If `crs_rule` was null (rule not found in index), prepend a note to the verdict: "CRS rule definition not found in index — classification based on payload and rule message only. "
- If JSON parsing fails, insert an `uncertain` draft with verdict "Agent response could not be parsed." and proposed_rule null.
- Store `crs_rule.raw` in the `crs_rule_raw` column of `exception_drafts` for audit trail.
- Insert one row into `exception_drafts` with the `event_line` field set to the line number in `events.jsonl`.

**Anthropic API call:**
```python
import anthropic

client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1000,
    system=SYSTEM_PROMPT,
    messages=[{"role": "user", "content": user_prompt}]
)
raw = response.content[0].text
```

**Phase 4 acceptance criteria:**
- [ ] After one agent cycle, `exception_drafts` rows appear in Postgres.
- [ ] `tracker.json` `last_offset` advances after each cycle.
- [ ] Agent never re-processes events already tracked.
- [ ] A transaction triggering 3 rules produces 3 separate drafts (one per match).
- [ ] Deduplication prevents duplicate drafts: a second transaction matching the same (uri, parameter, rule_id) scope as a pending/approved draft does not generate a new LLM call.
- [ ] Each draft has a non-null `verdict` field containing a complete fused sentence with confidence percentage embedded.
- [ ] Each draft has a non-null `crs_rule_raw` field when the rule was found in the CRS index.
- [ ] Drafts for attack events (SQLi, XSS payloads) are `true_positive` or `uncertain` — never `false_positive`.
- [ ] Drafts for NormalUser events are `false_positive` with a proposed_rule the majority of the time.
- [ ] PL3/PL4 tagged rules firing on content fields (blog_content, comment, search) are classified `false_positive` with confidence ≥ 0.80.
- [ ] proposed_rule strings are valid ModSecurity syntax (test by manually loading them in the nginx container).
- [ ] Agent worker recovers from Anthropic API errors without crashing.
- [ ] `event_line` in each draft correctly identifies the source line in `events.jsonl`.

---

## Phase 5 — API Endpoints

**Goal:** Portal can query all data it needs. api-server exposes clean REST endpoints.

### 5.1 Events Router (`routers/events.py`)

Events are served by reading directly from `events.jsonl`. No database query.

```
GET /api/events
    Query params: page, limit, rule_id, uri, min_score, max_score, date_from, date_to
    Implementation: read events.jsonl into memory (or stream), filter, paginate.
    Returns: {total, page, limit, items: [...events with draft_status field]}

GET /api/events/{line}
    Path param: line number in events.jsonl (integer)
    Returns: single event JSON object + linked exception_draft if exists
```

**draft_status enrichment:** For each event returned, look up `exception_drafts` by `transaction_id` and include `draft_status` (null if no draft exists).

**Analytics computed from events.jsonl:**
- `top_rules`: count occurrences of each `rule_id` across all lines.
- `top_uris`: count occurrences of each `uri`.
- `timeline`: bucket events by hour or day using the `timestamp` field.
- These are computed by a full scan of `events.jsonl` — acceptable for PoC scale. **Cache** these results in-memory with a 60-second TTL to avoid redundant scans on repeated requests.

### 5.2 Exceptions Router (`routers/exceptions.py`)

```
GET /api/exceptions
    Query params: status (pending|approved|rejected|deployed|stale), page, limit
    Returns: paginated list of exception drafts with linked event summary
             (event summary fetched from events.jsonl using event_line)

GET /api/exceptions/{id}
    Returns: full draft detail + full event JSON from events.jsonl

POST /api/exceptions/{id}/approve
    Body: {} (no body needed)
    Action: sets status=approved, reviewed_at=now()
    Note: does NOT deploy yet. Deployment is a separate explicit action.
    Returns: updated draft

POST /api/exceptions/{id}/reject
    Body: {"reason": "string"}
    Action: sets status=rejected, rejection_reason, reviewed_at=now()
    Returns: updated draft
```

### 5.3 Deploy Router (`routers/deploy.py`)

Deployment is a separate, explicit operator action. Approved exceptions queue up until the operator chooses to deploy.

```
GET /api/deploy/pending
    Returns: list of all approved-but-not-yet-deployed exception drafts with their
             proposed_rule and proposed_rule_scope

POST /api/deploy
    Body: {"ids": [1, 2, 3]}   -- list of exception_draft ids to deploy, or omit for all approved
    Action:
      1. For each draft id, call rule_writer.write_exception(draft).
      2. Trigger a single nginx reload after all rules are written.
      3. Mark each draft status=deployed, deployed_at=now().
    Returns: {deployed: [ids], failed: [ids], nginx_reloaded: bool}

DELETE /api/deploy/{id}
    Action: deletes the exception .conf file for this draft, triggers nginx reload,
            sets status=approved (rolls back to approved state).
    Returns: updated draft
```

### 5.4 Analytics Router (`routers/analytics.py`)

```
GET /api/analytics/summary
    Returns:
    {
      "total_events": int,           -- total lines in events.jsonl
      "total_drafts": int,
      "pending_review": int,
      "approved": int,               -- approved but not yet deployed
      "deployed": int,
      "rejected": int,
      "stale": int
    }

GET /api/analytics/top-rules
    Returns: top 10 rule_ids by event count with rule_message

GET /api/analytics/top-uris
    Returns: top 10 URIs by event count

GET /api/analytics/timeline
    Query params: interval (hour|day), date_from, date_to
    Returns: event count bucketed by interval
```

### 5.5 Rule Writer (`services/rule_writer.py`)

Called by the deploy router — never called directly on approval.

```python
def write_exception(draft: ExceptionDraft) -> None:
    # 1. Sanitize URI for use in filename
    safe_uri = draft.proposed_rule_scope["uri"].replace("/", "_").strip("_")
    filename = f"exception_{draft.id}_{safe_uri}.conf"
    filepath = os.path.join(MODSEC_EXCEPTIONS_DIR, filename)

    # 2. Write the proposed_rule to the exceptions directory
    with open(filepath, "w") as f:
        f.write(f"# Exception {draft.id} — generated by WAF agent\n")
        f.write(f"# Rule: {draft.proposed_rule_scope['rule_id']}\n")
        f.write(f"# URI: {draft.proposed_rule_scope['uri']}\n")
        f.write(f"# Deployed: {datetime.utcnow().isoformat()}\n\n")
        f.write(draft.proposed_rule + "\n")

def validate_exception(draft: ExceptionDraft) -> bool:
    """Write the .conf file, then run nginx -t to validate. Delete on failure."""
    write_exception(draft)
    import docker
    client = docker.from_env()
    container = client.containers.get(os.environ.get("NGINX_CONTAINER_NAME", "nginx"))
    result = container.exec_run("nginx -t")
    if result.exit_code != 0:
        delete_exception(draft)  # remove invalid file
        return False
    return True

def reload_nginx() -> bool:
    # Since api-server and nginx run in separate containers, we trigger config validation
    # and configuration reload on the nginx container using the Docker SDK:
    import docker
    try:
        client = docker.from_env()
        container = client.containers.get(os.environ.get("NGINX_CONTAINER_NAME", "nginx"))
        
        # 1. Run configuration test before reloading
        test_result = container.exec_run("nginx -t")
        if test_result.exit_code != 0:
            print(f"Nginx config check failed: {test_result.output.decode('utf-8')}")
            return False
            
        # 2. Trigger configuration reload
        reload_result = container.exec_run("nginx -s reload")
        return reload_result.exit_code == 0
    except Exception as e:
        print(f"Failed to reload Nginx container: {e}")
        return False

def delete_exception(draft: ExceptionDraft) -> None:
    safe_uri = draft.proposed_rule_scope["uri"].replace("/", "_").strip("_")
    filename = f"exception_{draft.id}_{safe_uri}.conf"
    filepath = os.path.join(MODSEC_EXCEPTIONS_DIR, filename)
    if os.path.exists(filepath):
        os.remove(filepath)
```

**Phase 5 acceptance criteria:**
- [ ] `GET /api/events` returns paginated results filtered from `events.jsonl`.
- [ ] `GET /api/analytics/summary` returns correct counts.
- [ ] `POST /api/exceptions/{id}/approve` sets status to `approved` — does not write any file.
- [ ] `POST /api/deploy` validates each `.conf` file with `nginx -t` before finalizing — invalid files are deleted and included in the `failed` list.
- [ ] `POST /api/deploy` triggers one nginx reload for the batch after all valid rules are written.
- [ ] After deploy, curling the URI that originally triggered the false positive no longer generates a new `events.jsonl` line for that rule. **Note:** The exception rule's phase must match the target CRS rule's phase. Exception rules using `ctl:ruleRemoveTargetById` in `phase:2` will suppress `phase:2` CRS rules; `phase:1` rules require a separate `phase:1` exception.
- [ ] `DELETE /api/deploy/{id}` removes the `.conf` file, reloads nginx, resets status to `approved`.

---

## Phase 6 — Portal

**Goal:** A clean, functional web portal for observing events, reviewing agent drafts, deploying exceptions, and monitoring analytics.

### Design Direction

Dark theme. Security tooling aesthetic — terminal-inspired but polished. Monospace font for payloads and rule strings. Accent color: amber/orange (signals caution). No gradients. High information density on the events table, more spacious on the exception review cards and deploy panel.

### 6.1 Pages

**Events Page (`/events`)**
- Filterable table: Timestamp, Method, URI, Rule ID, Rule Message, Anomaly Score, Draft Status
- Row click expands inline to show `matched_data` and raw request body
- Filter bar: rule_id dropdown, URI text search, score range, date range
- Status badge per row: no draft / pending / approved / deployed / rejected

**Exceptions Page (`/exceptions`)**
- Tab bar: Pending Review | Approved (queued) | Deployed | Rejected | Stale
- Each exception shown as a card with border color keyed to confidence (green ≥ 85%, amber 60–85%, gray < 60%):
  - Event summary: method, URI, rule_id, matched_data, paranoia level from CRS index
  - **Verdict sentence** — displayed prominently at the top of the card in slightly larger text. This is the fused confidence + reasoning string e.g. "We are 96% sure this is a false positive because the parameter is 'search_query' and the @detectSQLi operator flagged 'select' in a natural English sentence — a known libinjection false positive on PL1 search endpoints." The raw confidence float is NOT shown separately.
  - CRS rule block (monospace, collapsed by default, expandable) — shows the raw `SecRule` directive from `crs_rule_raw`
  - Proposed rule block (monospace) — the generated exception SecRule
  - **Pending:** Approve button (green) + Reject button (red) with optional reason input
  - **Approved (queued):** "Awaiting deployment" badge — shows up in Deploy panel
  - **Deployed:** deployed timestamp, last_seen_at timestamp
  - **Stale:** days since last seen, prompt to review

**Deploy Panel (`/deploy`)**
- Lists all approved-but-not-deployed exceptions as a checklist
- Operator selects which to include (all selected by default)
- Shows the proposed rule for each in a monospace block
- Single "Deploy selected" button — calls `POST /api/deploy` with selected ids
- On success: shows count of rules written, confirms nginx reloaded
- Deployed exceptions can be rolled back individually via a Rollback button (`DELETE /api/deploy/{id}`)
- Deployment log: table of past deploy actions with timestamp, ids deployed, nginx reload status

**Analytics Page (`/`)**
- Summary stat cards: Total Events, Pending Review, Approved (queued), Deployed, Stale
- Bar chart: Top 10 firing rules
- Bar chart: Top 10 URIs by event count
- Line chart: Event volume over time (last 24h by default)

### 6.2 Technical Stack

- React + TypeScript
- Tailwind CSS for layout and spacing
- Recharts for analytics charts
- No component library — build raw with Tailwind
- Fetch from api-server at `http://localhost:8000`
- No auth (PoC scope)
- React Router for page navigation

**Phase 6 acceptance criteria:**
- [ ] Events page loads and shows paginated events read from `events.jsonl`.
- [ ] Filtering by rule_id and URI works.
- [ ] Exceptions page shows pending drafts with verdict sentence at the top of each card.
- [ ] Card border color reflects confidence level (green / amber / gray).
- [ ] CRS rule block is present on each card, collapsed by default, expandable.
- [ ] Approve action sets status to `approved` — draft appears in Deploy panel.
- [ ] Reject action moves draft to Rejected tab.
- [ ] Deploy panel lists all approved-queued exceptions.
- [ ] "Deploy selected" triggers `POST /api/deploy`, writes `.conf` files, reloads nginx.
- [ ] Deployed exceptions show in Deployed tab with timestamp.
- [ ] Rollback removes the `.conf` file and resets status to `approved`.
- [ ] Analytics page shows correct summary counts and charts.

---

## Phase 7 — Stale Exception Detection

**Goal:** Deployed exceptions that are no longer seeing matching traffic are automatically flagged.

### 7.1 Stale Detection Worker

Background asyncio task running once per day:

```python
async def stale_checker():
    while True:
        deployed = await db.fetch_deployed_exceptions()
        for exc in deployed:
            if exc.last_seen_at is None:
                continue
            days_since_seen = (datetime.utcnow() - exc.last_seen_at).days
            if days_since_seen >= 90:
                await db.set_status(exc.id, "stale")
        await asyncio.sleep(86400)
```

### 7.2 Last Seen Updater

In the log tailer, after appending a new event to `events.jsonl`, check the event's URI against all `deployed` exception `proposed_rule_scope.uri` values in Postgres. If a match exists, update `last_seen_at` on that draft to now.

**Important clarification:** Once deployed, `ctl:ruleRemoveTargetById` prevents the excluded rule from firing on the excluded parameter. Therefore, `last_seen_at` does NOT track whether the specific rule is still firing — it tracks whether the *URI itself* is still receiving any WAF-logged traffic. This is the correct signal: if the URI stops appearing in the audit log entirely (e.g., the endpoint was removed from the application), the exception is stale and should be reviewed for cleanup.

**Phase 7 acceptance criteria:**
- [ ] `last_seen_at` on deployed exceptions updates when matching traffic is observed.
- [ ] Exceptions with `last_seen_at` older than 90 days are marked `stale`.
- [ ] Stale exceptions appear in the Stale tab with days-since-last-seen displayed.

---

## Non-Goals (PoC Scope)

- No authentication or multi-user support
- No HTTPS
- No AWS WAF or Azure WAF integration (ModSecurity only)
- No automatic deployment without operator action
- No GNN or ML-based classification (LLM agent only)
- No production hardening (rate limiting, input validation, etc.)
- No `events.jsonl` rotation or archival (single append-only file for PoC)

---

## Demo Script

After all phases complete, the following sequence should be demonstrable end to end:

1. `docker-compose up`
2. Open portal at `localhost:3000` — Analytics shows zero events.
3. `docker-compose run traffic-generator` — runs Locust for 2 minutes.
4. Refresh Analytics — event counts populate, charts show top rules.
5. Navigate to Events — events visible with rule IDs and matched payloads (read from `events.jsonl`).
6. Navigate to Exceptions → Pending Review — agent-generated drafts visible.
7. Find a false positive draft (e.g. search query triggering rule 942100).
8. Read the verdict sentence at the top of the card — verify it references the parameter name, the operator (@detectSQLi), and the paranoia level. Verify the CRS rule block shows the raw SecRule when expanded.
9. Click Approve — draft moves to Approved (queued).
10. Navigate to Deploy panel — approved exception appears in the checklist.
11. Click "Deploy selected" — portal confirms rules written and nginx reloaded.
12. Run `curl "localhost:8080/search?q=select all products"` — request passes, no new line in `events.jsonl`.
13. Navigate to Exceptions → Deployed tab — exception shows deployed timestamp.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

When the user types `/graphify`, invoke the `skill` tool with `skill: "graphify"` before doing anything else.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- Dirty graphify-out/ files are expected after hooks or incremental updates; dirty graph files are not a reason to skip graphify. Only skip graphify if the task is about stale or incorrect graph output, or the user explicitly says not to use it.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
