# Changelog

All notable changes to this project are documented here.

## [0.1.0] - Unreleased

Initial lab/evaluation release of the observe-and-recommend workflow:

- Ingest ModSecurity JSON audit data and group alerts into review cases.
- Run bounded, off-path LLM classification and system-build parameter-scoped exception drafts.
- Require a matching application route profile (`REQUIRE_APPLICATION_CONTEXT`, on by default; set `false` to disable), deterministic validation, and human approval before a rule is available to copy.
- Seed a `default-lab` route profile (DVWA routes plus a `/*` catch-all) when no profiles exist, so the lab produces copyable rules under the default; disable with `SEED_DEFAULT_PROFILE=false`.
- Merge reanalysis into the active pending draft for a scope (upgrade missing context → valid rule; never rewrite approved drafts).
- Retire approve-time rule-ID conflicts as `stale` (no half-pending rows).
- Opt-in CORS via `CORS_ALLOW_ORIGINS` (empty default for same-origin Compose UI proxy).
- Backend runtime: **Python 3.13** (CI + container image).
- Redaction: `matched_data` from cookie and auth-header matches is removed before inference (it previously carried session IDs such as `PHPSESSID`), and more secret field names (`pass`, `otp`, `pin`, `cvv`, card numbers) are redacted.
- Exclusions are built only for plain parameter names; names such as `/.*/` that ModSecurity would read as a regex target are refused.
- Audit-log ingest reads in 8 MB steps and skips entries that cannot be parsed (database errors are retried 3 times) instead of stalling on them.
- False-positive export is CSV, with formula-like cells neutralized.
- Model output cut off at the token cap is refused (no parse, no repair) and the case fails with a clear error. The cap is now `LLM_MAX_OUTPUT_TOKEN` (default 20000; it limits only what the model writes, reasoning included). The eval applies the same rules as the backend, including the 0.90 false-positive threshold.
- Thinking controls are sent as the `thinking` and `reasoning_effort` request fields, for any OpenAI-compatible model that supports them: `LLM_THINKING` (`enabled` by default, `disabled`, or `off` to send nothing) and `LLM_REASONING_EFFORT` (default `high`, sent only when thinking is enabled). They replace the OpenRouter-style `LLM_REASONING_ENABLED`.
- Audit ingest keeps a record waiting on any storage fault (locked, full or damaged database) and skips it only for invalid data. Startup errors are retried, and `/health` returns 503 with `ingest: stopped` or `retrying` when ingestion is not running.
- `REQUEST_URI` matches send the redacted query string to the model and include it in the case fingerprint, so different URI payloads no longer share one case.
- A missing HTTP method is no longer recorded as `GET`; such alerts cannot produce an approvable exclusion.
- Each alert records the CRS ruleset active when it arrived and is analysed against that rule. If the rule has changed since, the exclusion is withheld.
- Eval no longer escalates a repaired verdict, matching the backend.
- A detection whose HTTP method was not logged now counts as overlapping any method when approving or invalidating exclusions.
- Each CRS rule has a signature covering its text and the `.data` files it reads. A draft is withheld when the current rule is missing or its signature differs from the rule that fired, and a changed rule opens a new case.
- The ruleset pin is taken once per record and survives retries. Alerts whose timestamp is not later than the current snapshot's publish time are marked as having an uncertain ruleset, and their drafts are withheld. Older verdicts are marked stale by an evidence-policy version in the analysis generation.
- `/health` also reports `retrying` during runtime storage faults. `REQUEST_URI_RAW` keeps the query's original encoding.
- Eval uses the same pinned rule lookup as the worker, and fails when fewer than `--min-attack-detection` (default 0.5, `EVAL_MIN_ATTACK_DETECTION`) of attacks are classified `true_positive`.
- Removed: the model-SecLang parser and no-op engine check (`RULE_VALIDATION_MODE`), the SQLite migration block and Postgres URL handling, `raw_proposed_rule`, the `AI_*`/`API_*` setting aliases (use `LLM_*`), the unused nginx include hook, and the `openpyxl` dependency.
- v0.1 surface cleanup: SQLite checks in `verify_installation.sh`; remove no-op ingest helper, unused `mode_public_info` alias, unwired OpenAPI/SBOM import routes, unused `deployed_at` model field, and dead imports.
- Bare-metal lab E2E: `scripts/e2e_baremetal.sh` runs unit tests + host uvicorn + synthetic (or external) audit ingest without Docker.
- Never authenticate users, write edge configuration, or reload a WAF; loopback Compose is the supported default.
- Sanitize inference evidence, while disclosing that selected evidence may leave the host for the configured provider.
- Retain raw audit events and provider responses locally until operators remove their data.
- A match on a request header or cookie now sends that one header's or cookie's value to the model (for example `Referer`, `X-Forwarded-For` or a `prefs` cookie), so payloads there are no longer left `uncertain`. Credential and session names (`Authorization`, `Cookie`, names containing `sess`, `sid`, `token`, `auth`, `jwt`, `csrf`, ...) stay hidden, and cookie matches are fingerprinted by the matched cookie's value.
- Removed the write-only `events.jsonl` mirror (`EVENTS_JSONL_PATH`, `EVENTS_JSONL_MAX_BYTES`, `EVENTS_FSYNC`). Raw events live only in SQLite, and event line numbers continue from the highest stored line. The data directory is now `DATA_DIR` (default `/shared`); if you set `EVENTS_JSONL_PATH` to another directory, set `DATA_DIR` to that directory so the database, cursor and fingerprint key are found.
- `CF_AIG_GATEWAY_ID` is removed; send the header with `LLM_EXTRA_HEADERS` instead. The placeholder-key check (`sk-...`) is gone too: an unconfigured key now fails at the provider with an authentication error.
- Verdicts include `applies_to_stack` (`yes`/`no`/`unknown`): whether the detected technique would work on the profiled stack. It is recorded in the revision's `model_settings` only; no gate uses it, and the stack is never a reason to call an attack a false positive. Outputs without it read as `unknown`.

Known limitations include model/provider variability, classification errors, a single backend process per SQLite data directory, no automatic retention service, and no multi-version CRS compatibility guarantee.

Before release, maintainers must enable GitHub private vulnerability reporting, attach a passing model-evaluation report, verify CI and Compose E2E, replace `Unreleased` with the release date, and publish tag `v0.1.0`.
