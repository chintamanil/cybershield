"""
Async tests for AbuseIPDB tool
"""

import unittest
import sys
import os
import asyncio
from unittest.mock import AsyncMock, patch

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from tools.abuseipdb import AbuseIPDBClient, check_ip, check_subnet, get_blacklist


class TestAbuseIPDBClientAsync(unittest.IsolatedAsyncioTestCase):
    """Async test cases for AbuseIPDBClient class"""

    async def asyncSetUp(self):
        """Set up async test fixtures"""
        self.client = AbuseIPDBClient(api_key="test_key")

    async def asyncTearDown(self):
        """Clean up after async tests"""
        if self.client:
            await self.client.close()

    def test_client_initialization_with_key(self):
        """Test client initialization with API key"""
        client = AbuseIPDBClient(api_key="test_key")
        self.assertEqual(client.api_key, "test_key")
        self.assertEqual(client.base_url, "https://api.abuseipdb.com/api/v2")

    def test_client_initialization_without_key(self):
        """Test client initialization without API key"""
        with patch.dict(os.environ, {}, clear=True):
            client = AbuseIPDBClient()
            self.assertIsNone(client.api_key)

    @patch.dict(os.environ, {'ABUSEIPDB_API_KEY': 'env_key'})
    def test_client_initialization_from_env(self):
        """Test client initialization from environment variable"""
        client = AbuseIPDBClient()
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

    async def test_check_ip_invalid_format(self):
        """Test IP check with invalid format"""
        result = await self.client.check_ip("invalid_ip")
        self.assertEqual(result["error"], "Invalid IP address format")

    async def test_no_api_key_error(self):
        """Test error handling when no API key is provided"""
        client = AbuseIPDBClient(api_key=None)
        result = await client.check_ip("8.8.8.8")
        self.assertEqual(result["error"], "AbuseIPDB API key not configured")
        await client.close()

    async def test_successful_ip_check(self):
        """Test successful async IP check"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "data": {
                "ipAddress": "8.8.8.8",
                "isPublic": True,
                "ipVersion": 4,
                "isWhitelisted": False,
                "abuseConfidencePercentage": 0,
                "countryCode": "US",
                "countryName": "United States",
                "usageType": "Data Center/Web Hosting/Transit",
                "isp": "Google LLC",
                "domain": "google.com",
                "totalReports": 0,
                "numDistinctUsers": 0,
                "lastReportedAt": None
            }
        })

        with patch('aiohttp.ClientSession.request') as mock_request:
            mock_request.return_value.__aenter__.return_value = mock_response
            
            result = await self.client.check_ip("8.8.8.8")

            self.assertEqual(result["ip_address"], "8.8.8.8")
            self.assertTrue(result["is_public"])
            self.assertEqual(result["ip_version"], 4)
            self.assertFalse(result["is_whitelisted"])
            self.assertEqual(result["abuse_confidence"], 0)
            self.assertEqual(result["country_code"], "US")
            self.assertEqual(result["total_reports"], 0)

    async def test_successful_ip_check_with_verbose(self):
        """Test successful async IP check with verbose reports"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "data": {
                "ipAddress": "1.2.3.4",
                "isPublic": True,
                "ipVersion": 4,
                "isWhitelisted": False,
                "abuseConfidencePercentage": 75,
                "countryCode": "US",
                "countryName": "United States",
                "usageType": "Data Center/Web Hosting/Transit",
                "isp": "Example ISP",
                "domain": "example.com",
                "totalReports": 10,
                "numDistinctUsers": 5,
                "lastReportedAt": "2024-01-01T12:00:00+00:00",
                "reports": [
                    {
                        "reportedAt": "2024-01-01T12:00:00+00:00",
                        "comment": "Malicious activity detected",
                        "categories": [14],
                        "reporterId": 12345,
                        "reporterCountryCode": "US"
                    }
                ]
            }
        })

        with patch('aiohttp.ClientSession.request') as mock_request:
            mock_request.return_value.__aenter__.return_value = mock_response
            
            result = await self.client.check_ip("1.2.3.4", verbose=True)

            self.assertEqual(result["ip_address"], "1.2.3.4")
            self.assertEqual(result["abuse_confidence"], 75)
            self.assertEqual(result["total_reports"], 10)
            self.assertIn("reports", result)
            self.assertEqual(len(result["reports"]), 1)

    async def test_successful_subnet_check(self):
        """Test successful async subnet check"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "data": {
                "networkAddress": "192.168.1.0",
                "netmask": "255.255.255.0",
                "minAddress": "192.168.1.0",
                "maxAddress": "192.168.1.255",
                "numPossibleHosts": 256,
                "addressSpaceDesc": "Private Use",
                "reportedAddress": [
                    {
                        "ipAddress": "192.168.1.100",
                        "numReports": 5,
                        "mostRecentReport": "2024-01-01T12:00:00+00:00",
                        "abuseConfidencePercentage": 25
                    }
                ]
            }
        })

        with patch('aiohttp.ClientSession.request') as mock_request:
            mock_request.return_value.__aenter__.return_value = mock_response
            
            result = await self.client.check_subnet("192.168.1.0/24")

            self.assertEqual(result["network"], "192.168.1.0/24")
            self.assertEqual(result["network_address"], "192.168.1.0")
            self.assertEqual(result["netmask"], "255.255.255.0")
            self.assertEqual(result["num_possible_hosts"], 256)

    async def test_successful_ip_report(self):
        """Test successful async IP report"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "data": {
                "ipAddress": "1.2.3.4",
                "abuseConfidencePercentage": 100,
                "reportId": 67890
            }
        })

        with patch('aiohttp.ClientSession.request') as mock_request:
            mock_request.return_value.__aenter__.return_value = mock_response
            
            result = await self.client.report_ip("1.2.3.4", [14], "Test report")

            self.assertEqual(result["ip_address"], "1.2.3.4")
            self.assertEqual(result["abuse_confidence"], 100)
            self.assertEqual(result["report_id"], 67890)

    async def test_report_ip_invalid_format(self):
        """Test IP report with invalid format"""
        result = await self.client.report_ip("invalid_ip", [14], "Test")
        self.assertEqual(result["error"], "Invalid IP address format")

    async def test_report_ip_no_categories(self):
        """Test IP report with no categories"""
        result = await self.client.report_ip("1.2.3.4", [], "Test")
        self.assertEqual(result["error"], "At least one category must be specified")

    async def test_successful_blacklist_retrieval(self):
        """Test successful async blacklist retrieval"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "data": [
                {
                    "ipAddress": "1.2.3.4",
                    "countryCode": "CN",
                    "usageType": "Data Center/Web Hosting/Transit",
                    "isp": "Example ISP",
                    "domain": "example.com",
                    "abuseConfidencePercentage": 100,
                    "lastReportedAt": "2024-01-01T12:00:00+00:00"
                },
                {
                    "ipAddress": "5.6.7.8",
                    "countryCode": "RU",
                    "usageType": "Data Center/Web Hosting/Transit",
                    "isp": "Another ISP",
                    "domain": "another.com",
                    "abuseConfidencePercentage": 85,
                    "lastReportedAt": "2024-01-01T11:00:00+00:00"
                }
            ]
        })

        with patch('aiohttp.ClientSession.request') as mock_request:
            mock_request.return_value.__aenter__.return_value = mock_response
            
            result = await self.client.get_blacklist(confidence_minimum=75, limit=1000)

            self.assertEqual(result["confidence_minimum"], 75)
            self.assertEqual(result["limit"], 1000)
            self.assertEqual(result["total_count"], 2)
            self.assertEqual(len(result["blacklisted_ips"]), 2)
            self.assertEqual(result["blacklisted_ips"][0]["ip_address"], "1.2.3.4")

    async def test_successful_clear_address(self):
        """Test successful async address clearing"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={})

        with patch('aiohttp.ClientSession.request') as mock_request:
            mock_request.return_value.__aenter__.return_value = mock_response
            
            result = await self.client.clear_address("1.2.3.4")

            self.assertEqual(result["ip_address"], "1.2.3.4")
            self.assertTrue(result["success"])

    async def test_rate_limiting_handling(self):
        """Test async rate limiting handling"""
        rate_limit_response = AsyncMock()
        rate_limit_response.status = 429
        rate_limit_response.headers = {"Retry-After": "1"}
        
        success_response = AsyncMock()
        success_response.status = 200
        success_response.json = AsyncMock(return_value={
            "data": {
                "ipAddress": "8.8.8.8",
                "abuseConfidencePercentage": 0
            }
        })

        with patch('aiohttp.ClientSession.request') as mock_request:
            mock_request.return_value.__aenter__.side_effect = [rate_limit_response, success_response]
            
            with patch('asyncio.sleep') as mock_sleep:
                result = await self.client.check_ip("8.8.8.8")
                mock_sleep.assert_called_once_with(1)
                self.assertEqual(result["ip_address"], "8.8.8.8")

    async def test_request_exception_handling(self):
        """Test async request exception handling"""
        with patch('aiohttp.ClientSession.request') as mock_request:
            mock_request.side_effect = Exception("Network error")
            
            result = await self.client.check_ip("8.8.8.8")
            self.assertIn("error", result)
            self.assertIn("Network error", result["error"])

    def test_get_categories(self):
        """Test get categories functionality (static data)"""
        result = self.client.get_categories()
        
        self.assertIn("categories", result)
        self.assertIn("category_count", result)
        self.assertIsInstance(result["categories"], dict)
        self.assertGreater(result["category_count"], 0)
        # Check for some known categories
        self.assertIn(14, result["categories"])  # Port Scan
        self.assertIn(18, result["categories"])  # Brute-Force

    async def test_context_manager(self):
        """Test async context manager functionality"""
        async with AbuseIPDBClient(api_key="test_key") as client:
            self.assertEqual(client.api_key, "test_key")


class TestAsyncConvenienceFunctions(unittest.IsolatedAsyncioTestCase):
    """Test cases for async convenience functions"""

    async def test_check_ip_function(self):
        """Test async check_ip convenience function"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "data": {
                "ipAddress": "8.8.8.8",
                "abuseConfidencePercentage": 0
            }
        })

        with patch('aiohttp.ClientSession.request') as mock_request:
            mock_request.return_value.__aenter__.return_value = mock_response
            
            result = await check_ip("8.8.8.8")
            self.assertEqual(result["ip_address"], "8.8.8.8")

    async def test_check_subnet_function(self):
        """Test async check_subnet convenience function"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "data": {
                "networkAddress": "192.168.1.0",
                "netmask": "255.255.255.0"
            }
        })

        with patch('aiohttp.ClientSession.request') as mock_request:
            mock_request.return_value.__aenter__.return_value = mock_response
            
            result = await check_subnet("192.168.1.0/24")
            self.assertEqual(result["network"], "192.168.1.0/24")

    async def test_get_blacklist_function(self):
        """Test async get_blacklist convenience function"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "data": []
        })

        with patch('aiohttp.ClientSession.request') as mock_request:
            mock_request.return_value.__aenter__.return_value = mock_response
            
            result = await get_blacklist()
            self.assertIn("blacklisted_ips", result)


# Integration tests with real API (optional, requires API keys)
class TestAbuseIPDBRealAPI(unittest.IsolatedAsyncioTestCase):
    """Integration tests with real AbuseIPDB API (requires API key)"""

    def setUp(self):
        """Set up real API tests"""
        self.api_key = os.getenv("ABUSEIPDB_API_KEY")

    @unittest.skipIf(not os.getenv("ABUSEIPDB_API_KEY"), "Real API key not provided")
    async def test_real_api_ip_check(self):
        """Test real API IP check (only runs with API key)"""
        async with AbuseIPDBClient(api_key=self.api_key) as client:
            # Test with Google DNS (known good IP)
            result = await client.check_ip("8.8.8.8")
            
            # Basic checks for real API response
            self.assertNotIn("error", result)
            self.assertEqual(result["ip_address"], "8.8.8.8")
            self.assertIsInstance(result["abuse_confidence"], int)
            self.assertTrue(result["is_public"])

    @unittest.skipIf(not os.getenv("ABUSEIPDB_API_KEY"), "Real API key not provided")
    async def test_real_api_get_categories(self):
        """Test real API categories retrieval"""
        async with AbuseIPDBClient(api_key=self.api_key) as client:
            result = client.get_categories()
            
            # Categories should be available (static data)
            self.assertIn("categories", result)
            self.assertGreater(result["category_count"], 0)

    @unittest.skipIf(not os.getenv("ABUSEIPDB_API_KEY"), "Real API key not provided")
    async def test_real_api_concurrent_checks(self):
        """Test concurrent real API checks"""
        async with AbuseIPDBClient(api_key=self.api_key) as client:
            # Test concurrent checks (be mindful of rate limits)
            tasks = [
                client.check_ip("8.8.8.8"),
                client.check_ip("1.1.1.1")
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Check that we don't have exceptions (rate limiting might occur)
            for result in results:
                if not isinstance(result, Exception):
                    self.assertIsInstance(result, dict)
                    self.assertIn("ip_address", result)


if __name__ == '__main__':
    unittest.main(verbosity=2)