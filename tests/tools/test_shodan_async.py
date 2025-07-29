"""
Async tests for Shodan tool
"""

import unittest
import sys
import os
import asyncio
from unittest.mock import AsyncMock, patch

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from tools.shodan import ShodanClient, lookup_ip, search_shodan, get_host_count


class TestShodanClientAsync(unittest.IsolatedAsyncioTestCase):
    """Async test cases for ShodanClient class"""

    async def asyncSetUp(self):
        """Set up async test fixtures"""
        self.client = ShodanClient(api_key="test_key")

    async def asyncTearDown(self):
        """Clean up after async tests"""
        if self.client:
            await self.client.close()

    def test_client_initialization_with_key(self):
        """Test client initialization with API key"""
        client = ShodanClient(api_key="test_key")
        self.assertEqual(client.api_key, "test_key")
        self.assertEqual(client.base_url, "https://api.shodan.io")

    def test_client_initialization_without_key(self):
        """Test client initialization without API key"""
        with patch.dict(os.environ, {}, clear=True):
            client = ShodanClient()
            self.assertIsNone(client.api_key)

    @patch.dict(os.environ, {'SHODAN_API_KEY': 'env_key'})
    def test_client_initialization_from_env(self):
        """Test client initialization from environment variable"""
        client = ShodanClient()
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

    async def test_lookup_ip_invalid_format(self):
        """Test IP lookup with invalid format"""
        result = await self.client.lookup_ip("invalid_ip")
        self.assertEqual(result["error"], "Invalid IP address format")

    async def test_no_api_key_error(self):
        """Test error handling when no API key is provided"""
        client = ShodanClient(api_key=None)
        result = await client.lookup_ip("8.8.8.8")
        self.assertEqual(result["error"], "Shodan API key not configured")
        await client.close()

    async def test_successful_ip_lookup(self):
        """Test successful async IP lookup"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "ip_str": "8.8.8.8",
            "hostnames": ["dns.google"],
            "country_name": "United States",
            "country_code": "US",
            "city": "Mountain View",
            "region_code": "CA",
            "postal_code": "94035",
            "latitude": 37.386,
            "longitude": -122.0838,
            "org": "Google LLC",
            "isp": "Google LLC",
            "asn": "AS15169",
            "last_update": "2024-01-01T00:00:00.000000",
            "os": None,
            "ports": [53, 443],
            "data": [
                {
                    "port": 53,
                    "transport": "udp",
                    "product": "Google DNS",
                    "version": "1.0",
                    "_shodan": {"module": "dns-udp"},
                    "data": "DNS response",
                    "timestamp": "2024-01-01T00:00:00.000000"
                }
            ],
            "vulns": [],
            "tags": ["cdn"]
        })

        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__.return_value = mock_response
            
            result = await self.client.lookup_ip("8.8.8.8")

            self.assertEqual(result["ip_address"], "8.8.8.8")
            self.assertEqual(result["hostnames"], ["dns.google"])
            self.assertEqual(result["country_name"], "United States")
            self.assertEqual(result["organization"], "Google LLC")
            self.assertEqual(result["ports"], [53, 443])
            self.assertEqual(len(result["services"]), 1)

    async def test_successful_search(self):
        """Test successful async search"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "total": 1000,
            "matches": [
                {
                    "ip_str": "1.2.3.4",
                    "port": 80,
                    "product": "nginx",
                    "version": "1.18.0",
                    "org": "Example Corp",
                    "location": {
                        "country_name": "United States",
                        "city": "New York",
                        "latitude": 40.7128,
                        "longitude": -74.0060
                    },
                    "data": "HTTP/1.1 200 OK\\r\\nServer: nginx/1.18.0",
                    "timestamp": "2024-01-01T00:00:00.000000"
                }
            ],
            "facets": {
                "country": [
                    {"value": "US", "count": 500},
                    {"value": "CN", "count": 300}
                ]
            }
        })

        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__.return_value = mock_response
            
            result = await self.client.search("nginx", facets=["country"])

            self.assertEqual(result["query"], "nginx")
            self.assertEqual(result["total_results"], 1000)
            self.assertEqual(result["results_returned"], 1)
            self.assertEqual(len(result["results"]), 1)
            self.assertIn("facets", result)

    async def test_get_host_count(self):
        """Test async host count functionality"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "total": 5000,
            "facets": {
                "country": [
                    {"value": "US", "count": 2000},
                    {"value": "CN", "count": 1500}
                ]
            }
        })

        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__.return_value = mock_response
            
            result = await self.client.get_host_count("apache")

            self.assertEqual(result["query"], "apache")
            self.assertEqual(result["total_hosts"], 5000)
            self.assertIn("facets", result)

    async def test_rate_limiting_handling(self):
        """Test async rate limiting handling"""
        rate_limit_response = AsyncMock()
        rate_limit_response.status = 429
        rate_limit_response.headers = {"Retry-After": "1"}
        
        success_response = AsyncMock()
        success_response.status = 200
        success_response.json = AsyncMock(return_value={
            "ip_str": "8.8.8.8",
            "country_name": "United States"
        })

        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__.side_effect = [rate_limit_response, success_response]
            
            with patch('asyncio.sleep') as mock_sleep:
                result = await self.client.lookup_ip("8.8.8.8")
                mock_sleep.assert_called_once_with(1)
                self.assertEqual(result["ip_address"], "8.8.8.8")

    async def test_request_exception_handling(self):
        """Test async request exception handling"""
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.side_effect = Exception("Network error")
            
            result = await self.client.lookup_ip("8.8.8.8")
            self.assertIn("error", result)
            self.assertIn("Network error", result["error"])

    async def test_get_protocols(self):
        """Test async get protocols functionality"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "http": {"name": "HTTP", "port": 80},
            "https": {"name": "HTTPS", "port": 443},
            "ssh": {"name": "SSH", "port": 22}
        })

        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__.return_value = mock_response
            
            result = await self.client.get_protocols()

            self.assertIn("protocols", result)
            self.assertEqual(result["protocol_count"], 3)

    async def test_get_account_info(self):
        """Test async account info functionality"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "member": True,
            "credits": 1000,
            "display_name": "test_user",
            "created": "2020-01-01T00:00:00.000000"
        })

        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__.return_value = mock_response
            
            result = await self.client.get_account_info()

            self.assertTrue(result["member"])
            self.assertEqual(result["credits"], 1000)
            self.assertEqual(result["display_name"], "test_user")

    async def test_context_manager(self):
        """Test async context manager functionality"""
        async with ShodanClient(api_key="test_key") as client:
            self.assertEqual(client.api_key, "test_key")


class TestAsyncConvenienceFunctions(unittest.IsolatedAsyncioTestCase):
    """Test cases for async convenience functions"""

    async def test_lookup_ip_function(self):
        """Test async lookup_ip convenience function"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "ip_str": "8.8.8.8",
            "country_name": "United States"
        })

        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__.return_value = mock_response
            
            result = await lookup_ip("8.8.8.8")
            self.assertEqual(result["ip_address"], "8.8.8.8")

    async def test_search_shodan_function(self):
        """Test async search_shodan convenience function"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "total": 100,
            "matches": []
        })

        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__.return_value = mock_response
            
            result = await search_shodan("nginx")
            self.assertEqual(result["query"], "nginx")

    async def test_get_host_count_function(self):
        """Test async get_host_count convenience function"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "total": 5000
        })

        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__.return_value = mock_response
            
            result = await get_host_count("apache")
            self.assertEqual(result["query"], "apache")
            self.assertEqual(result["total_hosts"], 5000)


# Integration tests with real API (optional, requires API keys)
class TestShodanRealAPI(unittest.IsolatedAsyncioTestCase):
    """Integration tests with real Shodan API (requires API key)"""

    def setUp(self):
        """Set up real API tests"""
        self.api_key = os.getenv("SHODAN_API_KEY")

    @unittest.skipIf(not os.getenv("SHODAN_API_KEY"), "Real API key not provided")
    async def test_real_api_ip_lookup(self):
        """Test real API IP lookup (only runs with API key)"""
        async with ShodanClient(api_key=self.api_key) as client:
            result = await client.lookup_ip("8.8.8.8")
            
            # Basic checks for real API response
            self.assertNotIn("error", result)
            self.assertEqual(result["ip_address"], "8.8.8.8")
            self.assertIsInstance(result["country_name"], (str, type(None)))

    @unittest.skipIf(not os.getenv("SHODAN_API_KEY"), "Real API key not provided")
    async def test_real_api_search(self):
        """Test real API search (only runs with API key)"""
        async with ShodanClient(api_key=self.api_key) as client:
            result = await client.search("nginx", facets=["country"])
            
            # Basic checks for real API response
            self.assertNotIn("error", result)
            self.assertEqual(result["query"], "nginx")
            self.assertIsInstance(result["total_results"], int)

    @unittest.skipIf(not os.getenv("SHODAN_API_KEY"), "Real API key not provided")
    async def test_real_api_concurrent_lookups(self):
        """Test concurrent real API lookups"""
        async with ShodanClient(api_key=self.api_key) as client:
            # Test concurrent lookups (be careful not to exceed rate limits)
            tasks = [
                client.lookup_ip("8.8.8.8"),
                client.get_host_count("nginx")
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Check that we don't have exceptions (rate limiting might occur)
            for result in results:
                if not isinstance(result, Exception):
                    self.assertIsInstance(result, dict)


if __name__ == '__main__':
    unittest.main(verbosity=2)