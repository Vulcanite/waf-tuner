# Security policy

## Supported versions

Only the latest `0.1.x` release is supported, on a best-effort lab basis. WAF Tuner is not production-certified and has no built-in authentication.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for this repository. Do not include live credentials, unsanitized audit logs, or customer traffic in a public issue. Maintainers must enable private vulnerability reporting in repository settings before the `v0.1.0` release.

## Security model and known risks

- **Prompt and log injection:** audit evidence is untrusted. Instructions embedded in paths, headers, bodies, matched data, rules, or application context must not override the classifier contract.
- **Classification errors:** model scores are not calibrated probabilities. A copyable false-positive exclusion requires a matching application route profile, a high threshold, deterministic validation, and human review. The route-profile check is on by default (`REQUIRE_APPLICATION_CONTEXT=true`) and can be turned off with `REQUIRE_APPLICATION_CONTEXT=false`. The seeded `default-lab` profile includes a `/*` catch-all that satisfies this check for every path; replace it with real route profiles before using real traffic.
- **Unsafe exclusions:** overly broad or conflicting exclusions can weaken a WAF. WAF Tuner creates parameter-scoped drafts only and never applies them.
- **API exposure:** the v0.1 API is unauthenticated. Compose binds to loopback; remote access requires an authenticated TLS reverse proxy with the API kept private.
- **Sensitive audit data:** URLs, headers, bodies, matched data, application context, and raw provider responses may contain secrets or personal data. Redaction reduces risk but cannot guarantee perfect detection.
- **LLM egress:** sanitized evidence is transmitted to the configured provider. Review the provider, model, retention terms, and redaction settings before using real traffic.
- **TLS verification:** keep provider certificate verification enabled. `LLM_VERIFY_SSL=false` is a temporary lab-only escape hatch for self-signed endpoints and permits machine-in-the-middle attacks.
- **Local retention:** raw events and complete provider responses persist in local files and SQLite until the operator deletes them. Protect and back up the data directory according to its sensitivity.
- **Single-process storage:** one backend process may own a SQLite data directory. Sharing it across backend processes is unsupported.

The project never places LLM inference on the request path and never writes or reloads edge configuration.
