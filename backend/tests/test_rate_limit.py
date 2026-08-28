"""
Sliding-Window Rate Limiting & Burst Protection Unit Tests (Phase 8).
Tests sliding-window counter tracking, burst spike detection, in-memory fallback,
Redis pipeline commands, and HTTP 429 response headers.
"""

import json
import time
from unittest.mock import AsyncMock, patch
import pytest

from app.rate_limit.limiter import (
    SlidingWindowRateLimiter,
    RateLimitResult,
    create_rate_limited_response,
    _memory_cache,
)


@pytest.fixture(autouse=True)
def setup_rate_limit_env():
    """Clears in-memory cache and mocks Redis offline by default for pure unit testing."""
    _memory_cache.clear()
    with patch("app.rate_limit.limiter.get_redis_client", new=AsyncMock(return_value=None)):
        yield


@pytest.mark.asyncio
async def test_sliding_window_allows_under_limit():
    """Verifies that traffic below the rate limit threshold is allowed."""
    limiter = SlidingWindowRateLimiter(requests=5, window_seconds=10, burst_limit=10, burst_window=2.0)

    for i in range(5):
        res = await limiter.check_rate_limit("client-allow-test")
        assert res.allowed is True
        assert res.limit == 5
        assert res.current_count == i + 1
        assert res.remaining == 5 - (i + 1)
        assert res.is_burst is False


@pytest.mark.asyncio
async def test_sliding_window_blocks_over_limit():
    """Verifies that traffic exceeding the rate limit threshold is blocked."""
    limiter = SlidingWindowRateLimiter(requests=3, window_seconds=10, burst_limit=10, burst_window=2.0)

    # Exhaust limit
    for _ in range(3):
        res = await limiter.check_rate_limit("client-block-test")
        assert res.allowed is True

    # 4th request must be blocked
    res_blocked = await limiter.check_rate_limit("client-block-test")
    assert res_blocked.allowed is False
    assert res_blocked.remaining == 0
    assert res_blocked.current_count == 4


@pytest.mark.asyncio
async def test_sliding_window_burst_detection():
    """
    Verifies that a sudden burst of requests within a micro-window triggers burst protection,
    even if the total window limit has not yet been exceeded.
    """
    limiter = SlidingWindowRateLimiter(
        requests=100,      # High total limit
        window_seconds=60,
        burst_limit=3,     # Micro burst limit: max 3 requests in 2 seconds
        burst_window=2.0,
    )

    # First 3 hits allowed
    for _ in range(3):
        res = await limiter.check_rate_limit("burst-attacker-ip")
        assert res.allowed is True
        assert res.is_burst is False

    # 4th hit within the same instant triggers burst block!
    res_burst = await limiter.check_rate_limit("burst-attacker-ip")
    assert res_burst.allowed is False
    assert res_burst.is_burst is True
    assert res_burst.remaining == 0


@pytest.mark.asyncio
async def test_sliding_window_expiry():
    """Verifies that old requests expire out of the sliding window."""
    limiter = SlidingWindowRateLimiter(requests=2, window_seconds=1.0, burst_limit=10, burst_window=1.0)

    t0 = 1000.0
    with patch("time.time", return_value=t0):
        await limiter.check_rate_limit("expiring-client")
        await limiter.check_rate_limit("expiring-client")
        blocked = await limiter.check_rate_limit("expiring-client")
        assert blocked.allowed is False

    # Simulate passing 1.5 seconds later
    t1 = t0 + 1.5
    with patch("time.time", return_value=t1):
        allowed_again = await limiter.check_rate_limit("expiring-client")
        assert allowed_again.allowed is True


@pytest.mark.asyncio
async def test_client_ip_isolation():
    """Verifies that rate limits are tracked independently per client IP."""
    limiter = SlidingWindowRateLimiter(requests=2, window_seconds=10, burst_limit=10, burst_window=2.0)

    # Client A exhausts quota
    await limiter.check_rate_limit("198.51.100.1")
    await limiter.check_rate_limit("198.51.100.1")
    res_a = await limiter.check_rate_limit("198.51.100.1")
    assert res_a.allowed is False

    # Client B should still be allowed
    res_b = await limiter.check_rate_limit("198.51.100.2")
    assert res_b.allowed is True
    assert res_b.remaining == 1


def test_create_rate_limited_response_headers():
    """Verifies standard HTTP 429 response structure and RFC rate limit headers."""
    rate_res = RateLimitResult(
        allowed=False,
        limit=100,
        current_count=101,
        remaining=0,
        reset_seconds=60,
        retry_after=45,
        is_burst=False,
    )

    resp = create_rate_limited_response("req-rl-999", rate_res)
    assert resp.status_code == 429
    assert resp.headers["Retry-After"] == "45"
    assert resp.headers["X-RateLimit-Limit"] == "100"
    assert resp.headers["X-RateLimit-Remaining"] == "0"
    assert resp.headers["X-WAF-Action"] == "RATE_LIMITED"
    assert resp.headers["X-Request-ID"] == "req-rl-999"

    body = json.loads(resp.body)
    assert body["error"] == "Too Many Requests"
    assert body["retry_after"] == 45
    assert body["request_id"] == "req-rl-999"


@pytest.mark.asyncio
async def test_redis_pipeline_execution():
    """Verifies that Redis sorted set pipeline is invoked correctly when Redis is online."""
    from unittest.mock import MagicMock
    import app.rate_limit.limiter as limiter_mod
    limiter_mod._redis_available = True

    limiter = SlidingWindowRateLimiter(requests=10, window_seconds=60, burst_limit=5, burst_window=2.0)

    mock_pipe = MagicMock()
    mock_pipe.execute = AsyncMock(return_value=[0, 1, 4, 2, True])

    mock_redis = MagicMock()
    mock_redis.pipeline.return_value = mock_pipe

    with patch("app.rate_limit.limiter.get_redis_client", new=AsyncMock(return_value=mock_redis)):
        res = await limiter.check_rate_limit("redis-client-test")
        assert res.allowed is True
        assert res.current_count == 4
        assert res.remaining == 6
        assert res.is_burst is False

        mock_pipe.zremrangebyscore.assert_called_once()
        mock_pipe.zadd.assert_called_once()
        mock_pipe.zcard.assert_called_once()
        mock_pipe.zcount.assert_called_once()
        mock_pipe.expire.assert_called_once()
