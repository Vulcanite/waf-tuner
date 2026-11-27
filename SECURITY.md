# Security policy

## Supported versions

Only the latest `0.1.x` release is supported, on a best-effort lab basis. WAF Tuner is not production-certified and has no built-in authentication.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for this repository. Do not include live credentials, unsanitized audit logs, or customer traffic in a public issue. Maintainers must enable private vulnerability reporting in repository settings before the `v0.1.0` release.

## Security model and known risks

- **Prompt and log injection:** audit evidence is untrusted. Instructions embedded in paths, headers, bodies, matched data, rules, or application context must not override the classifier contract.
- **Classification errors:** model scores are not calibrated probabilities. By default, a copyable false-positive exclusion requires a matching application route profile with parameter semantics, a high threshold, deterministic validation, and human review. Configure operator-owned profiles for your applications.
- **Unsafe exclusions:** overly broad or conflicting exclusions can weaken a WAF. WAF Tuner creates parameter-scoped drafts only and never applies them.
- **API exposure:** the v0.1 API is unauthenticated. Compose binds to loopback; remote access requires an authenticated TLS reverse proxy with the API kept private.
- **Sensitive audit data:** URLs, headers, bodies, matched data, application context, and raw provider responses may contain secrets or personal data. Redaction reduces risk but cannot guarantee perfect detection.
- **LLM egress:** sanitized evidence is transmitted to the configured provider. Review the provider, model, retention terms, and redaction settings before using real traffic.
- **TLS verification:** keep provider certificate verification enabled. `LLM_VERIFY_SSL=false` is a temporary lab-only escape hatch for self-signed endpoints and permits machine-in-the-middle attacks.
- **Local retention:** protect the workspace, rotate the ModSecurity source log with your WAF, and set retention for backups and exports separately. `AUDIT_EVIDENCE_RETENTION_DAYS` expires raw SQLite audit evidence for settled cases. Pending drafts that depend on expired evidence become stale. Already approved rules can stay copyable and exportable when the remaining current-context checks pass. `INFERENCE_ARTIFACT_RETENTION_DAYS` ages out provider response excerpts. Sanitized prompt context, verdicts, and attempt metadata remain. The default for each limit is `0` (keep).
- **Single-process storage:** one backend process may own a SQLite data directory. Sharing it across backend processes is unsupported.

The project never places LLM inference on the request path and never writes or reloads edge configuration.
