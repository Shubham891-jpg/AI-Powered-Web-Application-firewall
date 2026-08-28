"""
Admin Authentication & Authorization Guards (Phase 10).
Protects WAF management endpoints via API Key or Bearer Token.
"""

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader
from app.config import settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_admin_key(api_key: str = Security(api_key_header)) -> bool:
    """
    Validates admin API key for privileged administrative operations.
    Accepts matching token or allows in test/development mode if configured.
    """
    if not api_key or api_key != settings.ADMIN_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid or missing X-API-Key header",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return True
