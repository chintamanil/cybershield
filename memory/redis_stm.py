# Async Redis-based short-term memory for session context
import redis.asyncio as aioredis
import json
import logging
import os
from typing import Any, Optional, Dict

logger = logging.getLogger(__name__)

class RedisSTM:
    def __init__(self, host=None, port=None, db=None, ttl=None):
        """
        Initialize async Redis short-term memory

        Args:
            host: Redis host (defaults to env REDIS_HOST or localhost)
            port: Redis port (defaults to env REDIS_PORT or 6379)
            db: Redis database number (defaults to env REDIS_DB or 0)
            ttl: Time to live in seconds (defaults to env REDIS_TTL or 3600)
        """
        self.host = host or os.getenv('REDIS_HOST', 'localhost')
        self.port = int(port or os.getenv('REDIS_PORT', 6379))
        self.db = int(db or os.getenv('REDIS_DB', 0))
        self.ttl = int(ttl or os.getenv('REDIS_TTL', 3600))
        self._redis = None
        self._connection_url = f"redis://{self.host}:{self.port}/{self.db}"
        
    async def _get_redis(self) -> aioredis.Redis:
        """Get or create async Redis connection"""
        if self._redis is None or self._redis.connection_pool.connection_kwargs.get('db') != self.db:
            try:
                self._redis = aioredis.from_url(
                    self._connection_url,
                    decode_responses=True,
                    retry_on_timeout=True,
                    socket_keepalive=True
                )
                # Test connection
                await self._redis.ping()
                logger.info(f"Connected to Redis at {self.host}:{self.port}")
            except Exception as e:
                logger.error(f"Failed to connect to Redis: {e}")
                self._redis = None
                raise
        return self._redis
    
    async def close(self):
        """Close Redis connection"""
        if self._redis:
            await self._redis.close()
            
    async def __aenter__(self):
        await self._get_redis()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def get(self, key: str) -> Optional[Any]:
        """Get value from Redis asynchronously"""
        try:
            redis = await self._get_redis()
            value = await redis.get(key)
            if value:
                # Try to parse as JSON, fallback to string
                try:
                    return json.loads(value)
                except:
                    return value
            return None
        except Exception as e:
            logger.error(f"Error getting key {key}: {e}")
            return None

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in Redis with optional TTL asynchronously"""
        try:
            redis = await self._get_redis()
            # Serialize value to JSON if it's not a string
            if not isinstance(value, str):
                value = json.dumps(value)

            ttl = ttl or self.ttl
            await redis.set(key, value, ex=ttl)
            return True
        except Exception as e:
            logger.error(f"Error setting key {key}: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete key from Redis asynchronously"""
        try:
            redis = await self._get_redis()
            result = await redis.delete(key)
            return bool(result)
        except Exception as e:
            logger.error(f"Error deleting key {key}: {e}")
            return False

    async def exists(self, key: str) -> bool:
        """Check if key exists asynchronously"""
        try:
            redis = await self._get_redis()
            result = await redis.exists(key)
            return bool(result)
        except Exception as e:
            logger.error(f"Error checking key {key}: {e}")
            return False

    async def get_all(self, pattern: str = "*") -> Dict[str, Any]:
        """Get all keys matching pattern asynchronously"""
        try:
            redis = await self._get_redis()
            keys = await redis.keys(pattern)
            result = {}
            for key in keys:
                value = await self.get(key)
                if value is not None:
                    result[key] = value
            return result
        except Exception as e:
            logger.error(f"Error getting all keys: {e}")
            return {}

    async def clear(self) -> bool:
        """Clear all data asynchronously"""
        try:
            redis = await self._get_redis()
            await redis.flushdb()
            return True
        except Exception as e:
            logger.error(f"Error clearing Redis: {e}")
            return False

    async def is_connected(self) -> bool:
        """Check if Redis connection is active asynchronously"""
        try:
            redis = await self._get_redis()
            await redis.ping()
            return True
        except:
            return False
