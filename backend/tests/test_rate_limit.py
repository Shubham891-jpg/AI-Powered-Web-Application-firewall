"""
Tests for rate limiting logic.
"""

import pytest
from app.rate_limit.limiter import RateLimiter


@pytest.mark.asyncio
async def test_rate_limiter_defaults():
    limiter = RateLimiter(requests=5, window_seconds=10)
    # When Redis is not running in pure unit test mode, rate limiter fails-open safely
    allowed, count, remaining = await limiter.is_allowed("test-client-ip")
    assert allowed is True
    assert remaining >= 0
