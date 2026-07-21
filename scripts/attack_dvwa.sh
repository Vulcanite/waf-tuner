#!/usr/bin/env bash
# Alias entrypoint: generate ModSecurity events via DVWA behind the lab WAF.
# Same as run_incident_matrix.sh (kept as a clear name for operators).
exec "$(dirname "$0")/run_incident_matrix.sh" "$@"
