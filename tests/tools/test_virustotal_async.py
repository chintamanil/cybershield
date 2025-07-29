"""
Async tests for VirusTotal tool
"""

import unittest
import sys
import os
import asyncio
from unittest.mock import AsyncMock, patch

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from tools.virustotal import VirusTotalClient, lookup_ip, lookup_domain, lookup_hash


class TestVirusTotalClientAsync(unittest.IsolatedAsyncioTestCase):
    """Async test cases for VirusTotalClient class"""

    async def asyncSetUp(self):
        """Set up async test fixtures"""
        self.client = VirusTotalClient(api_key="test_key")

    async def asyncTearDown(self):
        """Clean up after async tests"""
        if self.client:
            await self.client.close()

    def test_client_initialization_with_key(self):
        """Test client initialization with API key"""
        client = VirusTotalClient(api_key="test_key")
        self.assertEqual(client.api_key, "test_key")
        self.assertEqual(client.base_url, "https://www.virustotal.com/api/v3")

    def test_client_initialization_without_key(self):
        """Test client initialization without API key"""
        with patch.dict(os.environ, {}, clear=True):
            client = VirusTotalClient()
            self.assertIsNone(client.api_key)

    @patch.dict(os.environ, {'VIRUSTOTAL_API_KEY': 'env_key'})
    def test_client_initialization_from_env(self):
        """Test client initialization from environment variable"""
        client = VirusTotalClient()
        self.assertEqual(client.api_key, "env_key")

    def test_ip_validation(self):
        """Test IP address validation"""
        # Valid IPs
        self.assertTrue(self.client._is_valid_ip("192.168.1.1"))
        self.assertTrue(self.client._is_valid_ip("8.8.8.8"))
        self.assertTrue(self.client._is_valid_ip("2001:db8::1"))

        # Invalid IPs
        self.assertFalse(self.client._is_valid_ip("999.999.999.999"))
        self.assertFalse(self.client._is_valid_ip("invalid_ip"))
        self.assertFalse(self.client._is_valid_ip(""))

    def test_hash_validation(self):
        """Test hash validation"""
        # Valid hashes
        self.assertTrue(self.client._is_valid_hash("5d41402abc4b2a76b9719d911017c592"))  # MD5
        self.assertTrue(self.client._is_valid_hash("356a192b7913b04c54574d18c28d46e6395428ab"))  # SHA1
        self.assertTrue(self.client._is_valid_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))  # SHA256

        # Invalid hashes
        self.assertFalse(self.client._is_valid_hash("invalid_hash"))
        self.assertFalse(self.client._is_valid_hash("123"))
        self.assertFalse(self.client._is_valid_hash(""))

    async def test_lookup_ip_invalid_format(self):
        """Test IP lookup with invalid format"""
        result = await self.client.lookup_ip("invalid_ip")
        self.assertEqual(result["error"], "Invalid IP address format")

    async def test_lookup_hash_invalid_format(self):
        """Test hash lookup with invalid format"""
        result = await self.client.lookup_file_hash("invalid_hash")
        self.assertEqual(result["error"], "Invalid hash format")

    async def test_no_api_key_error(self):
        """Test error handling when no API key is provided"""
        client = VirusTotalClient(api_key=None)
        result = await client.lookup_ip("8.8.8.8")
        self.assertEqual(result["error"], "VirusTotal API key not configured")
        await client.close()

    async def test_successful_ip_lookup(self):
        """Test successful async IP lookup"""
        # Mock aiohttp response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "data": {
                "attributes": {
                    "country": "US",
                    "as_owner": "Google LLC",
                    "reputation": 0,
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 80
                    },
                    "network": "8.8.8.0/24",
                    "regional_internet_registry": "ARIN"
                }
            }
        })

        with patch('aiohttp.ClientSession.request') as mock_request:
            mock_request.return_value.__aenter__.return_value = mock_response
            
            result = await self.client.lookup_ip("8.8.8.8")

            self.assertEqual(result["ip_address"], "8.8.8.8")
            self.assertEqual(result["country"], "US")
            self.assertEqual(result["as_owner"], "Google LLC")
            self.assertEqual(result["malicious_count"], 0)
            self.assertEqual(result["harmless_count"], 80)

    async def test_successful_domain_lookup(self):
        """Test successful async domain lookup"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "data": {
                "attributes": {
                    "categories": {"security": "Safe"},
                    "reputation": 100,
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 75
                    },
                    "creation_date": 1234567890,
                    "last_modification_date": 1234567890,
                    "last_dns_records": []
                }
            }
        })

        with patch('aiohttp.ClientSession.request') as mock_request:
            mock_request.return_value.__aenter__.return_value = mock_response
            
            result = await self.client.lookup_domain("google.com")

            self.assertEqual(result["domain"], "google.com")
            self.assertEqual(result["reputation"], 100)
            self.assertEqual(result["malicious_count"], 0)

    async def test_rate_limiting_handling(self):
        """Test async rate limiting handling"""
        # Mock responses for rate limiting scenario
        rate_limit_response = AsyncMock()
        rate_limit_response.status = 429
        rate_limit_response.headers = {"Retry-After": "1"}
        
        success_response = AsyncMock()
        success_response.status = 200
        success_response.json = AsyncMock(return_value={
            "data": {
                "attributes": {
                    "country": "US",
                    "last_analysis_stats": {}
                }
            }
        })

        with patch('aiohttp.ClientSession.request') as mock_request:
            mock_request.return_value.__aenter__.side_effect = [rate_limit_response, success_response]
            
            with patch('asyncio.sleep') as mock_sleep:
                result = await self.client.lookup_ip("8.8.8.8")
                mock_sleep.assert_called_once_with(1)
                self.assertEqual(result["ip_address"], "8.8.8.8")

    async def test_request_exception_handling(self):
        """Test async request exception handling"""
        with patch('aiohttp.ClientSession.request') as mock_request:
            mock_request.side_effect = Exception("Network error")
            
            result = await self.client.lookup_ip("8.8.8.8")
            self.assertIn("error", result)
            self.assertIn("Network error", result["error"])

    async def test_search_functionality(self):
        """Test async search functionality"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "data": [
                {
                    "id": "8.8.8.8",
                    "type": "ip_address",
                    "attributes": {"country": "US"}
                }
            ]
        })

        with patch('aiohttp.ClientSession.request') as mock_request:
            mock_request.return_value.__aenter__.return_value = mock_response
            
            result = await self.client.search("8.8.8.8")

            self.assertEqual(result["query"], "8.8.8.8")
            self.assertEqual(result["results_count"], 1)
            self.assertEqual(len(result["results"]), 1)

    async def test_context_manager(self):
        """Test async context manager functionality"""
        async with VirusTotalClient(api_key="test_key") as client:
            self.assertEqual(client.api_key, "test_key")
            # Context manager should handle session cleanup


class TestAsyncConvenienceFunctions(unittest.IsolatedAsyncioTestCase):
    """Test cases for async convenience functions"""

    async def test_lookup_ip_function(self):
        """Test async lookup_ip convenience function"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "data": {
                "attributes": {
                    "country": "US",
                    "last_analysis_stats": {}
                }
            }
        })

        with patch('aiohttp.ClientSession.request') as mock_request:
            mock_request.return_value.__aenter__.return_value = mock_response
            
            result = await lookup_ip("8.8.8.8")
            self.assertEqual(result["ip_address"], "8.8.8.8")

    async def test_lookup_domain_function(self):
        """Test async lookup_domain convenience function"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "data": {
                "attributes": {
                    "reputation": 100,
                    "last_analysis_stats": {}
                }
            }
        })

        with patch('aiohttp.ClientSession.request') as mock_request:
            mock_request.return_value.__aenter__.return_value = mock_response
            
            result = await lookup_domain("google.com")
            self.assertEqual(result["domain"], "google.com")

    async def test_lookup_hash_function(self):
        """Test async lookup_hash convenience function"""
        test_hash = "5d41402abc4b2a76b9719d911017c592"
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "data": {
                "attributes": {
                    "last_analysis_stats": {}
                }
            }
        })

        with patch('aiohttp.ClientSession.request') as mock_request:
            mock_request.return_value.__aenter__.return_value = mock_response
            
            result = await lookup_hash(test_hash)
            self.assertEqual(result["hash"], test_hash)


class TestAsyncErrorHandling(unittest.IsolatedAsyncioTestCase):
    """Test cases for async error handling"""

    async def asyncSetUp(self):
        """Set up test fixtures"""
        self.client = VirusTotalClient(api_key="test_key")

    async def asyncTearDown(self):
        """Clean up after tests"""
        await self.client.close()

    async def test_empty_domain_handling(self):
        """Test empty domain handling"""
        result = await self.client.lookup_domain("")
        self.assertEqual(result["error"], "Invalid domain format")

    async def test_domain_without_dot(self):
        """Test domain without dot handling"""
        result = await self.client.lookup_domain("invalid")
        self.assertEqual(result["error"], "Invalid domain format")

    async def test_http_error_handling(self):
        """Test async HTTP error handling"""
        mock_response = AsyncMock()
        mock_response.status = 404
        mock_response.raise_for_status.side_effect = Exception("Not found")

        with patch('aiohttp.ClientSession.request') as mock_request:
            mock_request.return_value.__aenter__.return_value = mock_response
            
            result = await self.client.lookup_ip("8.8.8.8")
            self.assertIn("error", result)


# Integration tests with real API (optional, requires API keys)
class TestVirusTotalRealAPI(unittest.IsolatedAsyncioTestCase):
    """Integration tests with real VirusTotal API (requires API key)"""

    def setUp(self):
        """Set up real API tests"""
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.skip_if_no_key = unittest.skipIf(
            not self.api_key, 
            "VIRUSTOTAL_API_KEY environment variable not set"
        )

    @unittest.skipIf(not os.getenv("VIRUSTOTAL_API_KEY"), "Real API key not provided")
    async def test_real_api_ip_lookup(self):
        """Test real API IP lookup (only runs with API key)"""
        async with VirusTotalClient(api_key=self.api_key) as client:
            result = await client.lookup_ip("8.8.8.8")
            
            # Basic checks for real API response
            self.assertNotIn("error", result)
            self.assertEqual(result["ip_address"], "8.8.8.8")
            self.assertIsInstance(result["country"], (str, type(None)))

    @unittest.skipIf(not os.getenv("VIRUSTOTAL_API_KEY"), "Real API key not provided")
    async def test_real_api_domain_lookup(self):
        """Test real API domain lookup (only runs with API key)"""
        async with VirusTotalClient(api_key=self.api_key) as client:
            result = await client.lookup_domain("google.com")
            
            # Basic checks for real API response
            self.assertNotIn("error", result)
            self.assertEqual(result["domain"], "google.com")

    @unittest.skipIf(not os.getenv("VIRUSTOTAL_API_KEY"), "Real API key not provided")
    async def test_real_api_concurrent_lookups(self):
        """Test concurrent real API lookups"""
        async with VirusTotalClient(api_key=self.api_key) as client:
            # Test concurrent lookups
            tasks = [
                client.lookup_ip("8.8.8.8"),
                client.lookup_ip("1.1.1.1"),
                client.lookup_domain("google.com")
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # All should succeed
            for result in results:
                self.assertNotIsInstance(result, Exception)
                self.assertNotIn("error", result)


if __name__ == '__main__':
    # Run async tests
    unittest.main(verbosity=2)