"""
Security Event Logger with Sensitive Data Redaction.
Ensures tokens, passwords, cookies, and secret credentials are never exposed in log outputs.
"""

import json
import logging
import sys
from typing import Any

# Sensitive headers and keys to automatically redact
REDACTED_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "token",
    "password",
    "secret",
    "passwd",
    "access_token",
    "refresh_token",
    "private_key",
}

REDACTION_MASK = "[REDACTED]"


def redact_sensitive_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively redacts sensitive keys from dictionaries."""
    sanitized = {}
    for key, value in data.items():
        lower_key = str(key).lower()
        if any(sensitive in lower_key for sensitive in REDACTED_KEYS):
            sanitized[key] = REDACTION_MASK
        elif isinstance(value, dict):
            sanitized[key] = redact_sensitive_dict(value)
        elif isinstance(value, list):
            sanitized[key] = [
                redact_sensitive_dict(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            sanitized[key] = value
    return sanitized


class SecurityEventLogger:
    """Structured JSON Logger for security audit logs."""

    def __init__(self, name: str = "ai_waf.security"):
        self.logger = logging.getLogger(name)
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter(
                '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "event": %(message)s}'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def log_event(
        self,
        request_id: str,
        client_ip: str,
        method: str,
        path: str,
        attack_category: str,
        risk_score: int,
        action: str,
        latency_ms: float,
        details: dict[str, Any] | None = None,
    ):
        clean_details = redact_sensitive_dict(details or {})
        payload = {
            "request_id": request_id,
            "client_ip": client_ip,
            "method": method,
            "path": path,
            "category": attack_category,
            "risk_score": risk_score,
            "action": action,
            "latency_ms": round(latency_ms, 2),
            "details": clean_details,
        }
        self.logger.info(json.dumps(payload))


security_logger = SecurityEventLogger()
