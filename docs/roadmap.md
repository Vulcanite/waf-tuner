# Future work

## Coraza ingestion

Add a Coraza audit-log adapter and verify that recorded targets, CRS rule context, and the exclusion builder agree end to end before declaring engine support.

## Better operator review

Show the exact sanitized field and application fact the model received alongside its explanation. Flag when later evidence undermines a rule someone already approved, so the operator can revisit any corresponding deployed configuration.

## Deployment and access

Improve readiness reporting and access controls for installations that outgrow a loopback lab. A future deployment workflow would need explicit operator approval and a tested rollback. The current workflow leaves rule placement and reloads with the operator.
