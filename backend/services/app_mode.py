"""Product posture exposed to API/UI (observe + recommend; no edge writes)."""
from __future__ import annotations

import os


def product_info() -> dict:
    from services.runtime_config import audit_log_status

    return {
        "config_writes_enabled": False,
        "deploy_enabled": False,
        "engine_mode_control_enabled": False,
        "description": (
            "Read ModSecurity JSON audit logs (Nginx or Apache), classify FP/TP, "
            "and generate exclusion SecRules for you to copy into your own WAF config. "
            "This application never writes edge configuration."
        ),
        "service": "waf-tuner-backend",
        "audit_log_contract": {
            "format": "JSON",
            "type": "Serial",
            "required_fields": [
                "transaction.id (or unique_id)",
                "transaction.request.method",
                "transaction.request.uri",
                "transaction.messages[] with ruleId/rule_id (or details.ruleId/details.id)",
            ],
            "recommended_directives": [
                "SecAuditEngine On",
                "SecAuditLog <path>",
                "SecAuditLogFormat JSON",
                "SecAuditLogType Serial",
                "SecAuditLogParts ABCFHIJKZ",
            ],
            "notes": [
                "Works with ModSecurity on Nginx or Apache when the audit log is JSON Serial.",
                "Transactions with no rule messages are skipped.",
                "For DetectionOnly FP tuning on HTTP 200, consider SecAuditLogRelevantStatus \".*\".",
                "Set CRS_RULES_DIR to the WAF's rules for signature evidence and copyable exclusions.",
            ],
            "example_snippet": (
                "SecAuditEngine On\n"
                "SecAuditLog /var/log/modsec/audit.log\n"
                "SecAuditLogFormat JSON\n"
                "SecAuditLogType Serial\n"
                "SecAuditLogParts ABCFHIJKZ\n"
                "# Optional for DetectionOnly false-positive capture on 200 responses:\n"
                "# SecAuditLogRelevantStatus \".*\"\n"
            ),
        },
        "env": {
            "MODSEC_AUDIT_LOG": os.environ.get("MODSEC_AUDIT_LOG", ""),
            "CRS_RULES_DIR": os.environ.get("CRS_RULES_DIR", ""),
            "DATABASE_PATH": os.environ.get(
                "DATABASE_PATH", ""
            ),
            "LLM_MODEL": os.environ.get("LLM_MODEL", ""),
            "LLM_API_BASE_URL": os.environ.get("LLM_API_BASE_URL", ""),
        },
        "ingest": audit_log_status(),
    }
