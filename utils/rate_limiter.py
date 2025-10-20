"""
Rate Limiter with Token Budgets for API endpoints.

Implements Redis-backed rate limiting with:
- Per-user token budgets
- Per-endpoint rate limits
- Sliding window algorithm
- Token consumption tracking
"""

import hashlib
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

import redis.asyncio as redis

from utils.logging_config import get_security_logger

logger = get_security_logger('rate_limiter')


class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded"""

    def __init__(self, limit_type: str, retry_after: int):
        self.limit_type = limit_type
        self.retry_after = retry_after
        super().__init__(
            f'{limit_type} rate limit exceeded. Retry after {retry_after} seconds.'
        )


class RateLimiter:
    """
    Redis-backed rate limiter with token budgets.

    Supports multiple limit types:
    - Requests per minute/hour
    - Tokens per day/week
    - Concurrent requests

    Uses sliding window algorithm for smooth rate limiting.
    """

    def __init__(
        self,
        redis_client: Optional[redis.Redis] = None,
        redis_host: str = 'localhost',
        redis_port: int = 6379,
        redis_db: int = 0,
    ):
        """
        Initialize rate limiter.

        Args:
            redis_client: Existing Redis client (creates new if None)
            redis_host: Redis host
            redis_port: Redis port
            redis_db: Redis database number
        """
        self.redis = redis_client
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.redis_db = redis_db

    async def connect(self) -> None:
        """Connect to Redis"""
        if not self.redis:
            self.redis = await redis.Redis(
                host=self.redis_host,
                port=self.redis_port,
                db=self.redis_db,
                decode_responses=True,
            )
        logger.info(
            'rate_limiter_connected', host=self.redis_host, port=self.redis_port
        )

    async def close(self) -> None:
        """Close Redis connection"""
        if self.redis:
            await self.redis.close()
        logger.info('rate_limiter_closed')

    def _get_key(self, user_id: str, limit_type: str) -> str:
        """
        Generate Redis key for rate limit.

        Args:
            user_id: User identifier
            limit_type: Type of limit (e.g., 'requests_per_minute', 'tokens_daily')

        Returns:
            Redis key string
        """
        return f'ratelimit:{limit_type}:{user_id}'

    async def check_rate_limit(
        self,
        user_id: str,
        limit: int,
        window_seconds: int,
        cost: int = 1,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if rate limit allows the request (sliding window algorithm).

        Args:
            user_id: User identifier
            limit: Maximum number of requests in window
            window_seconds: Time window in seconds
            cost: Cost of this request (default 1)

        Returns:
            (allowed, info) tuple where:
            - allowed: True if request allowed
            - info: Dict with remaining, reset_at, retry_after
        """
        if not self.redis:
            await self.connect()

        key = self._get_key(user_id, f'sliding_{window_seconds}')
        current_time = time.time()
        window_start = current_time - window_seconds

        # Redis pipeline for atomic operations
        pipe = self.redis.pipeline()

        # Remove old entries outside the window
        pipe.zremrangebyscore(key, 0, window_start)

        # Count current requests in window
        pipe.zcard(key)

        # Execute pipeline
        results = await pipe.execute()
        current_count = results[1]

        # Check if limit exceeded
        if current_count + cost > limit:
            # Calculate retry_after
            oldest_entries = await self.redis.zrange(key, 0, 0, withscores=True)
            if oldest_entries:
                oldest_timestamp = oldest_entries[0][1]
                retry_after = int(oldest_timestamp + window_seconds - current_time) + 1
            else:
                retry_after = window_seconds

            logger.warning(
                'rate_limit_exceeded',
                user_id=user_id,
                limit=limit,
                current=current_count,
                window_seconds=window_seconds,
            )

            return False, {
                'allowed': False,
                'limit': limit,
                'remaining': 0,
                'reset_at': current_time + retry_after,
                'retry_after': retry_after,
            }

        # Add current request(s) to window
        for i in range(cost):
            pipe = self.redis.pipeline()
            pipe.zadd(key, {f'{current_time}_{i}': current_time})
            pipe.expire(key, window_seconds + 60)  # Extra buffer
            await pipe.execute()

        remaining = limit - (current_count + cost)

        logger.debug(
            'rate_limit_checked',
            user_id=user_id,
            allowed=True,
            remaining=remaining,
            limit=limit,
        )

        return True, {
            'allowed': True,
            'limit': limit,
            'remaining': remaining,
            'reset_at': current_time + window_seconds,
            'retry_after': 0,
        }

    async def check_token_budget(
        self,
        user_id: str,
        tokens_used: int,
        daily_limit: int,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if user has sufficient token budget.

        Args:
            user_id: User identifier
            tokens_used: Number of tokens to consume
            daily_limit: Daily token budget

        Returns:
            (allowed, info) tuple
        """
        if not self.redis:
            await self.connect()

        # Use daily buckets (resets at midnight UTC)
        today = datetime.now().strftime('%Y-%m-%d')
        key = self._get_key(user_id, f'tokens:{today}')

        # Get current token usage
        current_usage = await self.redis.get(key)
        current_usage = int(current_usage) if current_usage else 0

        # Check if budget exceeded
        if current_usage + tokens_used > daily_limit:
            # Calculate reset time (next midnight UTC)
            tomorrow = datetime.now().date() + timedelta(days=1)
            reset_at = datetime.combine(tomorrow, datetime.min.time()).timestamp()
            retry_after = int(reset_at - time.time())

            logger.warning(
                'token_budget_exceeded',
                user_id=user_id,
                daily_limit=daily_limit,
                current_usage=current_usage,
                tokens_requested=tokens_used,
            )

            return False, {
                'allowed': False,
                'daily_limit': daily_limit,
                'remaining': 0,
                'reset_at': reset_at,
                'retry_after': retry_after,
            }

        # Increment token usage
        pipe = self.redis.pipeline()
        pipe.incrby(key, tokens_used)

        # Calculate expiration as datetime timestamp
        expire_date = datetime.now().date() + timedelta(days=2)
        expire_datetime = datetime.combine(expire_date, datetime.min.time())
        pipe.expireat(key, int(expire_datetime.timestamp()))
        await pipe.execute()

        remaining = daily_limit - (current_usage + tokens_used)

        logger.info(
            'token_budget_checked',
            user_id=user_id,
            tokens_used=tokens_used,
            remaining=remaining,
            daily_limit=daily_limit,
        )

        # Calculate next midnight
        next_midnight = datetime.now().date() + timedelta(days=1)
        reset_timestamp = datetime.combine(
            next_midnight, datetime.min.time()
        ).timestamp()

        return True, {
            'allowed': True,
            'daily_limit': daily_limit,
            'remaining': remaining,
            'reset_at': reset_timestamp,
            'retry_after': 0,
        }

    async def get_usage_stats(self, user_id: str) -> Dict[str, Any]:
        """
        Get current usage statistics for a user.

        Args:
            user_id: User identifier

        Returns:
            Dictionary with usage stats
        """
        if not self.redis:
            await self.connect()

        # Token usage today
        today = datetime.now().strftime('%Y-%m-%d')
        token_key = self._get_key(user_id, f'tokens:{today}')
        tokens_used_today = await self.redis.get(token_key)
        tokens_used_today = int(tokens_used_today) if tokens_used_today else 0

        # Request count (last hour)
        request_key = self._get_key(user_id, 'sliding_3600')
        current_time = time.time()
        window_start = current_time - 3600
        await self.redis.zremrangebyscore(request_key, 0, window_start)
        requests_last_hour = await self.redis.zcard(request_key)

        stats = {
            'user_id': user_id,
            'tokens_used_today': tokens_used_today,
            'requests_last_hour': requests_last_hour,
            'timestamp': datetime.now().isoformat(),
        }

        logger.debug('usage_stats_retrieved', user_id=user_id, stats=stats)

        return stats

    async def reset_limits(
        self, user_id: str, limit_type: Optional[str] = None
    ) -> None:
        """
        Reset rate limits for a user (admin function).

        Args:
            user_id: User identifier
            limit_type: Specific limit type to reset (None = all)
        """
        if not self.redis:
            await self.connect()

        if limit_type:
            key = self._get_key(user_id, limit_type)
            await self.redis.delete(key)
            logger.warning('rate_limit_reset', user_id=user_id, limit_type=limit_type)
        else:
            # Reset all limits for user
            pattern = f'ratelimit:*:{user_id}'
            keys = []
            async for key in self.redis.scan_iter(match=pattern):
                keys.append(key)

            if keys:
                await self.redis.delete(*keys)

            logger.warning(
                'all_rate_limits_reset', user_id=user_id, keys_deleted=len(keys)
            )


# Default rate limit configurations
DEFAULT_LIMITS = {
    'requests_per_minute': 60,  # 60 requests/minute
    'requests_per_hour': 1000,  # 1000 requests/hour
    'tokens_per_day': 100000,  # 100K tokens/day
    'concurrent_requests': 10,  # Max 10 concurrent
}


# Endpoint-specific limits
ENDPOINT_LIMITS = {
    '/analyze': {
        'requests_per_minute': 20,
        'tokens_per_day': 50000,
    },
    '/analyze-with-image': {
        'requests_per_minute': 10,
        'tokens_per_day': 30000,
    },
    '/batch-analyze': {
        'requests_per_minute': 5,
        'tokens_per_day': 100000,
    },
}


async def check_limits(
    user_id: str,
    endpoint: str,
    tokens_used: int = 0,
    rate_limiter: Optional[RateLimiter] = None,
) -> Tuple[bool, Dict[str, Any]]:
    """
    Convenient function to check all applicable limits.

    Args:
        user_id: User identifier
        endpoint: API endpoint path
        tokens_used: Number of tokens consumed (if applicable)
        rate_limiter: RateLimiter instance (creates if None)

    Returns:
        (allowed, info) tuple

    Raises:
        RateLimitExceeded: If any limit is exceeded
    """
    if not rate_limiter:
        rate_limiter = RateLimiter()
        await rate_limiter.connect()

    # Get endpoint-specific limits or use defaults
    endpoint_config = ENDPOINT_LIMITS.get(endpoint, {})
    rpm_limit = endpoint_config.get(
        'requests_per_minute', DEFAULT_LIMITS['requests_per_minute']
    )
    token_limit = endpoint_config.get(
        'tokens_per_day', DEFAULT_LIMITS['tokens_per_day']
    )

    # Check requests per minute
    allowed, info = await rate_limiter.check_rate_limit(
        user_id=user_id,
        limit=rpm_limit,
        window_seconds=60,
        cost=1,
    )

    if not allowed:
        raise RateLimitExceeded('requests_per_minute', info['retry_after'])

    # Check token budget if tokens were used
    if tokens_used > 0:
        allowed, token_info = await rate_limiter.check_token_budget(
            user_id=user_id,
            tokens_used=tokens_used,
            daily_limit=token_limit,
        )

        if not allowed:
            raise RateLimitExceeded('tokens_per_day', token_info['retry_after'])

        info['token_info'] = token_info

    return True, info


# Example usage
if __name__ == '__main__':
    import asyncio

    async def test_rate_limiter():
        """Test rate limiter functionality"""
        limiter = RateLimiter()
        await limiter.connect()

        user_id = 'test_user_123'

        print('Testing Rate Limiter\n' + '=' * 50)

        # Test 1: Requests per minute
        print('\n1. Testing requests per minute (limit: 60)')
        for i in range(65):
            allowed, info = await limiter.check_rate_limit(
                user_id=user_id,
                limit=60,
                window_seconds=60,
            )
            if not allowed:
                print(
                    f'   Request {i + 1}: ❌ BLOCKED - Retry after {info["retry_after"]}s'
                )
                break
            elif i % 20 == 0:
                print(f'   Request {i + 1}: ✅ Allowed - {info["remaining"]} remaining')

        # Test 2: Token budget
        print('\n2. Testing token budget (limit: 1000)')
        allowed, info = await limiter.check_token_budget(
            user_id=user_id,
            tokens_used=500,
            daily_limit=1000,
        )
        print(f'   Used 500 tokens: ✅ {info["remaining"]} remaining')

        allowed, info = await limiter.check_token_budget(
            user_id=user_id,
            tokens_used=600,
            daily_limit=1000,
        )
        if not allowed:
            print(
                f'   Used 600 tokens: ❌ BLOCKED - Retry after {info["retry_after"]}s'
            )

        # Test 3: Usage stats
        print('\n3. Usage Statistics')
        stats = await limiter.get_usage_stats(user_id)
        print(f'   Tokens used today: {stats["tokens_used_today"]}')
        print(f'   Requests last hour: {stats["requests_last_hour"]}')

        # Cleanup
        await limiter.reset_limits(user_id)
        await limiter.close()

        print('\n' + '=' * 50)
        print('✅ Rate limiter test complete\n')

    asyncio.run(test_rate_limiter())
