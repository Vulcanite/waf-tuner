# Roadmap

## Next: Coraza

[Coraza](https://coraza.io) is OWASP's WAF engine, written in Go and compatible with ModSecurity's rule language and OWASP CRS. Trustwave ended its support for ModSecurity in 2024 and handed the project to OWASP, and many new self-hosted deployments now start with Coraza instead: as a Caddy module, an Envoy or HAProxy filter, or embedded in a Go service.

WAF Tuner's analysis, profiles and exclusion builder do not depend on the engine. What does: the audit-log reader and the exact names of inspected targets. The Coraza port will:

1. Read Coraza's audit log and map its records into the same events and matches.
2. Check that the rule index, target names and the `ctl:ruleRemoveTargetById` exclusions behave the same on Coraza, end to end, before calling it supported.
3. Run the lab and the benchmark on Coraza next to ModSecurity.

## Then

- **Run the model on the WordPress and Nextcloud benchmark**, and compare its verdicts with the official CRS plugins.
- **Measure exclusion collateral.** Replay the attack set against the exclusions WAF Tuner would draft, and report what they let through, next to what the plugins let through.
- **Self-hosted model results**, with token counts, beside a hosted model.
- **Show the exact evidence in review.** Display the field value and the profile fact the model saw next to its explanation, and flag approved rules that later evidence undermines.

## Later

- Authentication for the UI and API, for installations beyond a loopback lab.
- A deployment workflow with explicit approval and tested rollback. Today, rule placement and reloads stay with you.
