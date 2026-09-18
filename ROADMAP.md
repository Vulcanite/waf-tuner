# Roadmap

These items are intentionally not in the current tree. They are the growth path after the eval corpus and recorded CI job land.

## Coraza audit-log format support

ModSecurity JSON Serial is the only ingest contract today, which keeps the lab honest but leaves Coraza operators outside the product. Adding a Coraza-shaped parser (same incident fingerprint, different envelope) would broaden the user base considerably without changing the classify-then-build trust boundary. The work is format mapping and tests against a checked-in Coraza sample, not a rewrite of grouping or exception construction.

## Staged deploy with human-gated reload

Approved exclusions still leave the repo as copy-paste. A staging include, reload, and one-click rollback would make the last mile less error-prone while remaining operator-gated: the process would write only to a designated exceptions file and never to the live CRS tree. Rollback is the feature that makes this safe enough to offer; without it, automatic reloads do not belong here.

## Rule drift detection

An approved exclusion is a claim about a specific evidence pattern. If later traffic for the same rule ID and parameter no longer matches that pattern, the exclusion should be flagged rather than silently covering a new payload. Drift checks can run off the existing fingerprint and matched-data fields already stored on each case.

## Minimal authentication

v0.1 is loopback-only and unauthenticated by design. A single shared token or basic auth in front of the API would let someone run it on a private network without pretending it is multi-tenant SaaS. Bind-address and TLS termination should stay with the operator's reverse proxy; the app only needs to reject unauthenticated mutating routes.

## Standing multi-model eval matrix

The recorded eval job now publishes a per-CRS-rule-ID confusion matrix for whatever recordings are committed. Making that report a release artifact—re-run against oracle plus at least one live model on each tagged version—turns the 200+ fixture corpus into ongoing evidence instead of a one-off dump. Live runs stay off pull-request CI so API keys never enter GitHub Actions.
