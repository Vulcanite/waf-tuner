# Limits and data handling

## What the verdict tells you

- The model judges individual payload matches. Rate, behaviour, bots, DDoS, and attack campaigns are outside the current scope.
- Confidence is a model-reported score. The default false-positive threshold is `0.90`. A score of 0.90 carries no calibrated probability of correctness.
- A false-positive verdict describes the observed request. A rule exclusion affects future requests in the same scope. The operator decides whether that change is acceptable.
- Integrate with ModSecurity v3 JSON Serial logs and the CRS rules your WAF uses. Chained rules can receive verdicts and require manual tuning.

## Model egress and local storage

The configured endpoint receives redacted, bounded evidence. This can include a matched query, form or JSON value, a non-credential-looking header or cookie value, and selected route and profile facts. Redaction is best effort. Use an endpoint appropriate for the sensitivity of your logs, including a private or self-hosted endpoint when that fits your deployment.

SQLite stores audit evidence, inference context, verdicts, and drafts. Optional audit retention expires stored audit evidence for settled cases. Optional inference artifact retention clears provider response excerpts. Prompt context and verdicts remain in SQLite. Rotate the ModSecurity source log separately, and manage access and retention for backups and exports.

Evidence expiry stales pending drafts. A previously approved rule can remain copyable and exportable when the rule, profile, and conflict checks still pass.

## Deployment boundary

Run one backend process per SQLite data directory. The UI and API are unauthenticated and the Compose lab binds them to loopback. For remote access, put both behind an authenticated TLS reverse proxy and keep the backend private. Manage the edge configuration and reloads through your existing process.
