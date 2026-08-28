"""
Redis Sliding-Window Rate Limiter & Burst Protection (Phase 8).
Implements precise sliding-window rate limiting via Redis sorted sets with
in-memory fallback, multi-tier burst detection, and standard HTTP 429 response formatting.
"""

import collections
import time
from typing import Optional
from pydantic import BaseModel
from fastapi.responses import JSONResponse
import redis.asyncio as aioredis

from app.config import settings

# Global Redis client instance
redis_client: Optional[aioredis.Redis] = None

# In-memory fallback sliding window cache (ip -> list of timestamps)
_memory_cache: dict[str, list[float]] = collections.defaultdict(list)


class RateLimitResult(BaseModel):
    """Structured result of a rate limit check."""
    allowed: bool
    limit: int
    current_count: int
    remaining: int
    reset_seconds: int
    retry_after: int
    is_burst: bool = False


# Circuit breaker for Redis availability
_redis_available = True
_last_failure_time = 0.0


async def get_redis_client() -> Optional[aioredis.Redis]:
    """Returns the initialized Redis client or None if unavailable."""
    global redis_client, _redis_available, _last_failure_time
    now = time.time()
    if not _redis_available and (now - _last_failure_time < 5.0):
        return None

    if redis_client is None:
        try:
            redis_client = aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=0.2,
                socket_timeout=0.2,
            )
        except Exception:
            _redis_available = False
            _last_failure_time = now
            redis_client = None
    return redis_client


async def close_redis():
    """Closes Redis connection pool cleanly."""
    global redis_client
    if redis_client is not None:
        try:
            await redis_client.aclose()
        except Exception:
            pass
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


class SlidingWindowRateLimiter:
    """
    Two-Tier Sliding-Window Rate Limiter:
    1. Standard Window (e.g. 100 requests per 60 seconds)
    2. Instantaneous Burst Detection (e.g. 20 requests per 2 seconds)
    Utilizes Redis sorted sets (ZADD/ZREMRANGEBYSCORE) with transparent in-memory fallback.
    """

    def __init__(
        self,
        requests: int = 100,
        window_seconds: int = 60,
        burst_limit: int = 25,
        burst_window: float = 2.0,
    ):
        self.requests = requests
        self.window_seconds = window_seconds
        self.burst_limit = burst_limit
        self.burst_window = burst_window

    async def check_rate_limit(self, key: str) -> RateLimitResult:
        """
        Evaluates sliding-window and burst limits for client identifier (IP or app:ip).
        Attempts Redis first, seamlessly falls back to in-memory tracking on failure.
        """
        now = time.time()
        client = await get_redis_client()

        if client is not None:
            try:
                return await self._check_redis(client, key, now)
            except Exception:
                global _redis_available, _last_failure_time
                _redis_available = False
                _last_failure_time = now

        return self._check_memory(key, now)

    async def _check_redis(self, client: aioredis.Redis, key: str, now: float) -> RateLimitResult:
        """Evaluates limits atomically via Redis sorted sets."""
        redis_key = f"waf:ratelimit:{key}"
        window_start = now - self.window_seconds
        burst_start = now - self.burst_window

        pipe = client.pipeline()
        # 1. Prune timestamps older than window
        pipe.zremrangebyscore(redis_key, 0, window_start)
        # 2. Add current hit
        pipe.zadd(redis_key, {f"{now:.6f}": now})
        # 3. Count total hits in standard window
        pipe.zcard(redis_key)
        # 4. Count hits in micro burst window
        pipe.zcount(redis_key, burst_start, "+inf")
        # 5. Refresh TTL
        pipe.expire(redis_key, self.window_seconds + 5)

        results = await pipe.execute()
        total_count = results[2]
        burst_count = results[3]

        is_burst = burst_count > self.burst_limit
        is_window_exceeded = total_count > self.requests

        allowed = not (is_burst or is_window_exceeded)
        remaining = max(0, self.requests - total_count) if allowed else 0
        retry_after = int(self.burst_window) if is_burst else int(self.window_seconds - (now - window_start))

        return RateLimitResult(
            allowed=allowed,
            limit=self.requests,
            current_count=total_count,
            remaining=remaining,
            reset_seconds=self.window_seconds,
            retry_after=max(1, retry_after),
            is_burst=is_burst,
        )

    def _check_memory(self, key: str, now: float) -> RateLimitResult:
        """In-memory sliding window fallback when Redis is offline."""
        window_start = now - self.window_seconds
        burst_start = now - self.burst_window

        # Prune expired entries
        timestamps = [t for t in _memory_cache[key] if t > window_start]
        timestamps.append(now)
        _memory_cache[key] = timestamps

        total_count = len(timestamps)
        burst_count = sum(1 for t in timestamps if t >= burst_start)

        is_burst = burst_count > self.burst_limit
        is_window_exceeded = total_count > self.requests

        allowed = not (is_burst or is_window_exceeded)
        remaining = max(0, self.requests - total_count) if allowed else 0
        retry_after = int(self.burst_window) if is_burst else int(self.window_seconds)

        return RateLimitResult(
            allowed=allowed,
            limit=self.requests,
            current_count=total_count,
            remaining=remaining,
            reset_seconds=self.window_seconds,
            retry_after=max(1, retry_after),
            is_burst=is_burst,
        )


def create_rate_limited_response(request_id: str, rate_result: RateLimitResult) -> JSONResponse:
    """
    Standard HTTP 429 Too Many Requests response with RFC 6585 and draft headers.
    """
    now_epoch = int(time.time())
    reset_epoch = now_epoch + rate_result.retry_after

    reason = "Burst limit triggered (abnormal traffic spike)" if rate_result.is_burst else "Rate limit exceeded"

    return JSONResponse(
        status_code=429,
        content={
            "error": "Too Many Requests",
            "request_id": request_id,
            "message": f"{reason}. Please slow down your request rate.",
            "retry_after": rate_result.retry_after,
        },
        headers={
            "Retry-After": str(rate_result.retry_after),
            "X-RateLimit-Limit": str(rate_result.limit),
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": str(reset_epoch),
            "X-WAF-Action": "RATE_LIMITED",
            "X-Request-ID": request_id,
        },
    )


# Default singleton rate limiter
rate_limiter = SlidingWindowRateLimiter(
    requests=settings.RATE_LIMIT_REQUESTS,
    window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
    burst_limit=25,
    burst_window=2.0,
)
