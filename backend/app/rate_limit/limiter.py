"""
Redis connection management and Sliding-Window Rate Limiter.
"""

import time
from typing import Optional
import redis.asyncio as aioredis
from app.config import settings

# Global Redis client instance
redis_client: Optional[aioredis.Redis] = None


async def get_redis_client() -> Optional[aioredis.Redis]:
    """Returns the initialized Redis client or None if unavailable."""
    global redis_client
    if redis_client is None:
        try:
            redis_client = aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=2.0,
                socket_timeout=2.0,
            )
        except Exception:
            redis_client = None
    return redis_client


async def close_redis():
    """Closes Redis connection pool cleanly."""
    global redis_client
    if redis_client is not None:
        await redis_client.aclose()
        redis_client = None


async def check_redis_health() -> tuple[bool, float, str]:
    """
    Pings Redis server and returns (is_healthy, latency_ms, detail).
    Safe if Redis server is down or unreachable.
    """
    start_time = time.perf_counter()
    try:
        client = await get_redis_client()
        if client is None:
            return False, 0.0, "Redis client failed to initialize"
        pong = await client.ping()
        latency = (time.perf_counter() - start_time) * 1000.0
        if pong:
            return True, round(latency, 2), "Connected to Redis"
        return False, round(latency, 2), "Ping returned False"
    except Exception as e:
        latency = (time.perf_counter() - start_time) * 1000.0
        return False, round(latency, 2), str(e)


class RateLimiter:
    """Sliding-window counter rate limiter backed by Redis."""

    def __init__(self, requests: int = 100, window_seconds: int = 60):
        self.requests = requests
        self.window_seconds = window_seconds

    async def is_allowed(self, key: str) -> tuple[bool, int, int]:
        """
        Checks whether client key has exceeded rate limit.
        Returns: (allowed: bool, current_count: int, remaining: int)
        """
        client = await get_redis_client()
        if client is None:
            # Fail-open for rate limiting if Redis is unavailable, while logging warning
            return True, 0, self.requests

        now = time.time()
        window_start = now - self.window_seconds
        redis_key = f"waf:ratelimit:{key}"

        try:
            pipe = client.pipeline()
            # Remove timestamps older than window
            pipe.zremrangebyscore(redis_key, 0, window_start)
            # Add current request timestamp
            pipe.zadd(redis_key, {str(now): now})
            # Count requests in window
            pipe.zcard(redis_key)
            # Set TTL for auto cleanup
            pipe.expire(redis_key, self.window_seconds + 5)
            results = await pipe.execute()

            current_count = results[2]
            allowed = current_count <= self.requests
            remaining = max(0, self.requests - current_count)
            return allowed, current_count, remaining
        except Exception:
            # Graceful fallback if Redis encounters temporary error
            return True, 1, self.requests
