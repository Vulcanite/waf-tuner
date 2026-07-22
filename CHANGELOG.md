# Changelog

All notable changes to this project are documented here.

## [0.1.0] - Unreleased

Initial lab/evaluation release of the observe-and-recommend workflow:

- Ingest ModSecurity JSON audit data and group alerts into review cases.
- Run bounded, off-path LLM classification and system-build parameter-scoped exception drafts.
- Require application context, deterministic validation, and human approval before a rule is available to copy.
- Merge reanalysis into the active pending draft for a scope (upgrade missing context → valid rule; never rewrite approved drafts).
- Retire approve-time rule-ID conflicts as `stale` (no half-pending rows).
- Opt-in CORS via `CORS_ALLOW_ORIGINS` (empty default for same-origin Compose UI proxy).
- Backend runtime: **Python 3.13** (CI + container image).
- v0.1 surface cleanup: SQLite checks in `verify_installation.sh`; remove no-op ingest helper, unused `mode_public_info` alias, unwired OpenAPI/SBOM import routes, unused `deployed_at` model field, and dead imports.
- Bare-metal lab E2E: `scripts/e2e_baremetal.sh` runs unit tests + host uvicorn + synthetic (or external) audit ingest without Docker.
- Never authenticate users, write edge configuration, or reload a WAF; loopback Compose is the supported default.
- Sanitize inference evidence, while disclosing that selected evidence may leave the host for the configured provider.
- Retain raw audit events and provider responses locally until operators remove their data.

Known limitations include model/provider variability, classification errors, a single backend process per SQLite data directory, no automatic retention service, and no multi-version CRS compatibility guarantee.

Before release, maintainers must enable GitHub private vulnerability reporting, attach a passing model-evaluation report, verify CI and Compose E2E, replace `Unreleased` with the release date, and publish tag `v0.1.0`.
