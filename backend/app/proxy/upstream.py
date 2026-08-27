"""
Upstream target application connection pool and health checks.
"""

import time
from typing import Optional
import httpx

from app.config import settings

# Shared HTTP client for connection pooling
_http_client: Optional[httpx.AsyncClient] = None


def get_http_client() -> httpx.AsyncClient:
    """Returns or initializes the shared httpx.AsyncClient with connection pooling."""
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(
                timeout=settings.REQUEST_TIMEOUT_SECONDS,
                connect=3.0,
                write=10.0,
                pool=5.0,
            ),
            limits=httpx.Limits(
                max_keepalive_connections=50,
                max_connections=200,
                keepalive_expiry=30.0,
            ),
            follow_redirects=False,
        )
    return _http_client


async def close_http_client():
    """Closes the shared HTTP client."""
    global _http_client
    if _http_client and not _http_client.is_closed:
        await _http_client.aclose()
        _http_client = None


async def check_upstream_health() -> tuple[bool, float, str, int]:
    """
    Pings the configured protected application upstream target.
    Returns: (is_healthy, latency_ms, status_message, status_code)
    """
    start_time = time.perf_counter()
    target = settings.UPSTREAM_URL
    try:
        client = get_http_client()
        response = await client.get(target)
        latency = (time.perf_counter() - start_time) * 1000.0
        return (
            response.status_code < 500,
            round(latency, 2),
            f"Upstream returned HTTP {response.status_code}",
            response.status_code,
        )
    except httpx.ConnectError:
        latency = (time.perf_counter() - start_time) * 1000.0
        return False, round(latency, 2), f"Failed to connect to upstream at {target}", 503
    except httpx.TimeoutException:
        latency = (time.perf_counter() - start_time) * 1000.0
        return False, round(latency, 2), f"Connection timeout to upstream at {target}", 504
    except Exception as e:
        latency = (time.perf_counter() - start_time) * 1000.0
        return False, round(latency, 2), f"Error querying upstream: {e}", 500
