"""
Async tests for Redis STM (Short-Term Memory)
"""

import unittest
import sys
import os
import asyncio
from unittest.mock import AsyncMock, patch

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from memory.redis_stm import RedisSTM


class TestRedisSTMAsync(unittest.IsolatedAsyncioTestCase):
    """Async test cases for RedisSTM class"""

    async def asyncSetUp(self):
        """Set up async test fixtures"""
        # Use a test database to avoid conflicts
        self.redis_stm = RedisSTM(host="localhost", port=6379, db=15, ttl=3600)

    async def asyncTearDown(self):
        """Clean up after async tests"""
        if self.redis_stm:
            try:
                # Clear test database
                await self.redis_stm.clear()
                await self.redis_stm.close()
            except:
                pass

    def test_initialization(self):
        """Test RedisSTM initialization"""
        redis_stm = RedisSTM(host="localhost", port=6379, db=15)
        self.assertEqual(redis_stm.host, "localhost")
        self.assertEqual(redis_stm.port, 6379)
        self.assertEqual(redis_stm.db, 15)
        self.assertEqual(redis_stm.ttl, 3600)

    @unittest.skipIf(not os.getenv("REDIS_AVAILABLE"), "Redis server not available")
    async def test_real_redis_connection(self):
        """Test real Redis connection (only if Redis is available)"""
        try:
            # Test connection
            self.assertTrue(await self.redis_stm.is_connected())
            
            # Test basic operations
            await self.redis_stm.set("test_key", "test_value")
            value = await self.redis_stm.get("test_key")
            self.assertEqual(value, "test_value")
            
            # Test deletion
            self.assertTrue(await self.redis_stm.delete("test_key"))
            value = await self.redis_stm.get("test_key")
            self.assertIsNone(value)
            
        except Exception as e:
            self.skipTest(f"Redis not available: {e}")

    async def test_mocked_redis_operations(self):
        """Test Redis operations with mocked aioredis"""
        mock_redis = AsyncMock()
        
        # Mock successful connection
        mock_redis.ping = AsyncMock(return_value=True)
        mock_redis.set = AsyncMock(return_value=True)
        mock_redis.get = AsyncMock(return_value="test_value")
        mock_redis.delete = AsyncMock(return_value=1)
        mock_redis.exists = AsyncMock(return_value=1)
        mock_redis.keys = AsyncMock(return_value=["test_key"])
        mock_redis.flushdb = AsyncMock(return_value=True)
        
        with patch('aioredis.from_url', return_value=mock_redis):
            redis_stm = RedisSTM()
            
            # Test set operation
            result = await redis_stm.set("test_key", "test_value")
            self.assertTrue(result)
            mock_redis.set.assert_called_once()
            
            # Test get operation
            value = await redis_stm.get("test_key")
            self.assertEqual(value, "test_value")
            mock_redis.get.assert_called_once_with("test_key")
            
            # Test delete operation
            result = await redis_stm.delete("test_key")
            self.assertTrue(result)
            mock_redis.delete.assert_called_once_with("test_key")
            
            # Test exists operation
            result = await redis_stm.exists("test_key")
            self.assertTrue(result)
            mock_redis.exists.assert_called_once_with("test_key")
            
            # Test clear operation
            result = await redis_stm.clear()
            self.assertTrue(result)
            mock_redis.flushdb.assert_called_once()

    async def test_json_serialization(self):
        """Test JSON serialization/deserialization"""
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(return_value=True)
        mock_redis.set = AsyncMock(return_value=True)
        
        test_data = {"key1": "value1", "key2": [1, 2, 3], "key3": {"nested": True}}
        
        with patch('aioredis.from_url', return_value=mock_redis):
            redis_stm = RedisSTM()
            
            # Test setting complex data
            result = await redis_stm.set("complex_key", test_data)
            self.assertTrue(result)
            
            # Verify that JSON serialization was called
            call_args = mock_redis.set.call_args
            self.assertIsInstance(call_args[0][1], str)  # Should be JSON string

    async def test_get_all_operations(self):
        """Test get_all functionality"""
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(return_value=True)
        mock_redis.keys = AsyncMock(return_value=["key1", "key2", "key3"])
        
        # Mock get method to return different values for different keys
        def mock_get(key):
            if key == "key1":
                return "value1"
            elif key == "key2":
                return '{"json": "data"}'
            elif key == "key3":
                return "value3"
            return None
        
        mock_redis.get = AsyncMock(side_effect=mock_get)
        
        with patch('aioredis.from_url', return_value=mock_redis):
            redis_stm = RedisSTM()
            
            # Test get_all
            result = await redis_stm.get_all("key*")
            
            self.assertEqual(len(result), 3)
            self.assertEqual(result["key1"], "value1")
            self.assertEqual(result["key2"], {"json": "data"})  # Should be parsed as JSON
            self.assertEqual(result["key3"], "value3")

    async def test_ttl_functionality(self):
        """Test TTL (Time To Live) functionality"""
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(return_value=True)
        mock_redis.set = AsyncMock(return_value=True)
        
        with patch('aioredis.from_url', return_value=mock_redis):
            redis_stm = RedisSTM(ttl=1800)  # 30 minutes
            
            # Test set with default TTL
            await redis_stm.set("test_key", "test_value")
            call_args = mock_redis.set.call_args
            self.assertEqual(call_args[1]['ex'], 1800)
            
            # Test set with custom TTL
            await redis_stm.set("test_key2", "test_value2", ttl=3600)
            call_args = mock_redis.set.call_args
            self.assertEqual(call_args[1]['ex'], 3600)

    async def test_connection_error_handling(self):
        """Test connection error handling"""
        with patch('aioredis.from_url', side_effect=Exception("Connection failed")):
            redis_stm = RedisSTM()
            
            # All operations should return safe defaults when connection fails
            self.assertIsNone(await redis_stm.get("test_key"))
            self.assertFalse(await redis_stm.set("test_key", "value"))
            self.assertFalse(await redis_stm.delete("test_key"))
            self.assertFalse(await redis_stm.exists("test_key"))
            self.assertEqual(await redis_stm.get_all(), {})
            self.assertFalse(await redis_stm.clear())
            self.assertFalse(await redis_stm.is_connected())

    async def test_context_manager(self):
        """Test async context manager functionality"""
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(return_value=True)
        mock_redis.close = AsyncMock()
        
        with patch('aioredis.from_url', return_value=mock_redis):
            async with RedisSTM() as redis_stm:
                self.assertIsNotNone(redis_stm)
                # Context manager should handle connection
            
            # Close should be called when exiting context
            mock_redis.close.assert_called_once()

    async def test_multiple_concurrent_operations(self):
        """Test multiple concurrent Redis operations"""
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(return_value=True)
        mock_redis.set = AsyncMock(return_value=True)
        mock_redis.get = AsyncMock(side_effect=lambda k: f"value_{k}")
        
        with patch('aioredis.from_url', return_value=mock_redis):
            redis_stm = RedisSTM()
            
            # Create multiple concurrent operations
            set_tasks = [
                redis_stm.set(f"key_{i}", f"value_{i}")
                for i in range(5)
            ]
            
            get_tasks = [
                redis_stm.get(f"key_{i}")
                for i in range(5)
            ]
            
            # Execute concurrently
            set_results = await asyncio.gather(*set_tasks)
            get_results = await asyncio.gather(*get_tasks)
            
            # All sets should succeed
            self.assertTrue(all(set_results))
            
            # All gets should return expected values
            for i, result in enumerate(get_results):
                self.assertEqual(result, f"value_key_{i}")

    async def test_large_data_handling(self):
        """Test handling of large data objects"""
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(return_value=True)
        mock_redis.set = AsyncMock(return_value=True)
        
        # Create large test data
        large_data = {
            "large_list": list(range(1000)),
            "large_dict": {f"key_{i}": f"value_{i}" for i in range(100)},
            "description": "This is a large test object for Redis storage"
        }
        
        with patch('aioredis.from_url', return_value=mock_redis):
            redis_stm = RedisSTM()
            
            # Should handle large data without issues
            result = await redis_stm.set("large_key", large_data)
            self.assertTrue(result)
            
            # Verify the data was serialized
            call_args = mock_redis.set.call_args
            self.assertIsInstance(call_args[0][1], str)
            # Should be a substantial JSON string
            self.assertGreater(len(call_args[0][1]), 1000)


# Performance and load testing
class TestRedisSTMPerformance(unittest.IsolatedAsyncioTestCase):
    """Performance tests for RedisSTM"""

    async def test_concurrent_writes_performance(self):
        """Test performance of concurrent writes"""
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(return_value=True)
        mock_redis.set = AsyncMock(return_value=True)
        
        with patch('aioredis.from_url', return_value=mock_redis):
            redis_stm = RedisSTM()
            
            import time
            start_time = time.time()
            
            # Perform 100 concurrent writes
            tasks = [
                redis_stm.set(f"perf_key_{i}", f"perf_value_{i}")
                for i in range(100)
            ]
            
            results = await asyncio.gather(*tasks)
            
            end_time = time.time()
            duration = end_time - start_time
            
            # All operations should succeed
            self.assertTrue(all(results))
            
            # Should complete reasonably quickly (mocked, so should be very fast)
            self.assertLess(duration, 1.0)
            
            # Verify all set operations were called
            self.assertEqual(mock_redis.set.call_count, 100)


if __name__ == '__main__':
    unittest.main(verbosity=2)