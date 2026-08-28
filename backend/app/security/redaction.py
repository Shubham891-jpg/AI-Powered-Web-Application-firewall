"""
Sensitive Data & Credential Redaction Module (Phase 10).
Strips and masks credentials, authentication tokens, and secrets from audit logs and events.
"""

import json
import re
from typing import Any, Mapping

SENSITIVE_HEADER_KEYS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "api-key",
}

SENSITIVE_JSON_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "credit_card",
    "card_number",
    "cvv",
    "ssn",
}

# Regex for Bearer tokens and basic auth strings
BEARER_PATTERN = re.compile(r"Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*", re.IGNORECASE)
CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,16}\b")


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Redacts sensitive credentials from HTTP header dictionaries."""
    redacted = {}
    for k, v in headers.items():
        k_lower = k.lower()
        if k_lower in SENSITIVE_HEADER_KEYS:
            redacted[k] = "[REDACTED]"
        else:
            # Mask potential bearer tokens in any custom header values
            redacted[k] = BEARER_PATTERN.sub("Bearer [REDACTED]", v)
    return redacted


def redact_payload_text(payload: str) -> str:
    """Redacts passwords and secrets from raw or normalized payload strings."""
    if not payload:
        return ""

    # Attempt JSON parse for structural masking
    try:
        data = json.loads(payload)
        if isinstance(data, dict):
            masked = _redact_dict(data)
            return json.dumps(masked)
    except Exception:
        pass

    # Regex masking on plaintext
    text = BEARER_PATTERN.sub("Bearer [REDACTED]", payload)
    text = CREDIT_CARD_PATTERN.sub("[REDACTED_CC]", text)

    # Mask password key-value parameters: password=XYZ or "password": "XYZ"
    for key in SENSITIVE_JSON_KEYS:
        kv_regex = re.compile(rf'([?&"]{key}["=:\s]+)([^"&\s]+)', re.IGNORECASE)
        text = kv_regex.sub(r"\1[REDACTED]", text)

    return text


def _redact_dict(d: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out[k] = _redact_dict(v)
        elif isinstance(v, list):
            out[k] = [_redact_dict(item) if isinstance(item, dict) else item for item in v]
        elif any(sens in k.lower() for sens in SENSITIVE_JSON_KEYS):
            out[k] = "[REDACTED]"
        elif isinstance(v, str):
            out[k] = BEARER_PATTERN.sub("Bearer [REDACTED]", v)
        else:
            out[k] = v
    return out
