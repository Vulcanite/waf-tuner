---
title: Why WAF Tuner
---

# Why WAF Tuner

## The problem

Running your own WAF with ModSecurity and the OWASP Core Rule Set (CRS) is a good alternative to a managed WAF. You keep your traffic, your rules and your costs. The hard part is tuning.

CRS is built from signatures. A signature matches a pattern, not a meaning. So a product review that says *"I'd call it 'select' quality"* trips a SQL injection rule, a support ticket containing `console.log(window.cart)` trips three more, and a Markdown comment trips the XSS rules. At the paranoia levels that catch real attacks, these false positives arrive in hundreds. Each one has to be read, understood and either excluded or left alone. Many teams lower the paranoia level, write broad exclusions, or switch the WAF to detection-only and stop looking. All three throw away protection.

## The idea

Most false positives are easy for a person to recognise once they see three things together: what the rule looks for, what the value actually is, and what the application expects in that field. A language model can do that reading, if you give it the same three things.

WAF Tuner does exactly that, and nothing more:

1. It reads the ModSecurity audit log **offline**. Your WAF keeps serving traffic exactly as before.
2. For each CRS match it gives a model the rule, the matched value (redacted and bounded) and your **application profile**: the language, framework, database, routes and what each parameter means.
3. The model returns a verdict, `false_positive`, `true_positive` or `uncertain`, and must explain it: what the rule looks for, what the payload is, and why they differ.
4. For a false positive, the **server** builds one narrow exclusion from its own template: one rule, one field, one route, one host and method. The model never writes rule text. Missing evidence, conflicting verdicts on the same input, or a changed ruleset withhold the draft.
5. **You** review the evidence and the rule, approve it, and deploy it through your own process.

## Principles

- **Off the request path.** Inference never delays or decides a live request.
- **Any model.** Any OpenAI-compatible endpoint works, including a model you host yourself, so request data can stay on your network.
- **Payload judgement, not traffic analysis.** An attack that could not work on your stack is still an attack. Rates, bots and campaigns are out of scope.
- **The server owns the rule, a human owns the decision.** WAF Tuner never edits or reloads your WAF.
- **Honest about limits.** An exclusion lets later values in that field past that rule, attacks included. WAF Tuner keeps exclusions narrow and explains each one so you can judge that trade. See [Limits](./limits.md).

## Who it is for

Teams and individuals who already run, or want to run, ModSecurity with OWASP CRS in front of their own applications, and who would rather tune it with evidence than turn it down.

Next: [run the lab](./quick-start.md), or read [how it works](./architecture.mdx).
