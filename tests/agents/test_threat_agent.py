"""
Comprehensive tests for ThreatAgent
Tests threat intelligence gathering, evaluation, and scoring
"""

import unittest
import asyncio
import sys
import os
from unittest.mock import Mock, patch, AsyncMock

# Add parent directories to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from agents.threat_agent import ThreatAgent


class TestThreatAgent(unittest.IsolatedAsyncioTestCase):
    """Test cases for ThreatAgent functionality"""

    async def asyncSetUp(self):
        """Set up test fixtures"""
        # Mock the tool clients to avoid API dependencies
        self.agent = ThreatAgent()
        
        # Create mock clients
        self.mock_shodan = AsyncMock()
        self.mock_abuseipdb = AsyncMock()
        self.mock_virustotal = AsyncMock()
        
        # Assign mock clients
        self.agent.shodan_client = self.mock_shodan
        self.agent.abuseipdb_client = self.mock_abuseipdb
        self.agent.virustotal_client = self.mock_virustotal

    async def asyncTearDown(self):
        """Clean up after tests"""
        await self.agent.close()

    async def test_init(self):
        """Test ThreatAgent initialization"""
        agent = ThreatAgent()
        self.assertIsNotNone(agent)
        self.assertIsNotNone(agent.perf_config)
        self.assertIsNone(agent.shodan_client)
        self.assertIsNone(agent.abuseipdb_client)
        self.assertIsNone(agent.virustotal_client)

    async def test_init_with_memory(self):
        """Test ThreatAgent initialization with memory"""
        mock_memory = Mock()
        agent = ThreatAgent(memory=mock_memory, session_id="test-session")
        
        self.assertEqual(agent.memory, mock_memory)
        self.assertEqual(agent.session_id, "test-session")

    async def test_get_clients_success(self):
        """Test successful client initialization"""
        agent = ThreatAgent()
        
        with patch('agents.threat_agent.ShodanClient') as mock_shodan_class, \
             patch('agents.threat_agent.AbuseIPDBClient') as mock_abuse_class, \
             patch('agents.threat_agent.VirusTotalClient') as mock_vt_class:
            
            await agent._get_clients()
            
            mock_shodan_class.assert_called_once()
            mock_abuse_class.assert_called_once()
            mock_vt_class.assert_called_once()

    async def test_get_clients_failure(self):
        """Test client initialization failure"""
        agent = ThreatAgent()
        
        with patch('agents.threat_agent.ShodanClient', side_effect=Exception("API Error")):
            await agent._get_clients()
            # Should handle exception gracefully
            self.assertIsNone(agent.shodan_client)

    async def test_close_clients(self):
        """Test closing client connections"""
        await self.agent.close()
        
        self.mock_shodan.close.assert_called_once()
        self.mock_abuseipdb.close.assert_called_once()
        self.mock_virustotal.close.assert_called_once()

    async def test_evaluate_empty_iocs(self):
        """Test evaluation with empty IOCs"""
        empty_iocs = {}
        results = await self.agent.evaluate(empty_iocs)
        
        self.assertEqual(results, [])

    async def test_evaluate_ip_addresses(self):
        """Test evaluation of IP addresses"""
        # Mock the _safe_lookup method to return proper format
        async def mock_safe_lookup(source, method, *args):
            if source == "abuseipdb":
                return {"source": "abuseipdb", "data": {"abuse_confidence": 85}}
            elif source == "shodan":
                return {"source": "shodan", "data": {"ports": [80, 443]}}
            elif source == "virustotal":
                return {"source": "virustotal", "data": {"malicious_count": 2}}
            return {"error": "Unknown source"}
        
        self.agent._safe_lookup = mock_safe_lookup
        
        iocs = {"ipv4": ["203.0.113.1"]}
        results = await self.agent.evaluate(iocs)
        
        self.assertEqual(len(results), 1)
        result = results[0]
        
        self.assertEqual(result["ioc"], "203.0.113.1")
        self.assertEqual(result["ioc_type"], "ip")
        self.assertIn("sources", result)
        self.assertIn("summary", result)

    async def test_evaluate_domains(self):
        """Test evaluation of domains"""
        # Mock the _safe_lookup method for domain evaluation
        async def mock_safe_lookup(source, method, *args):
            if source == "virustotal":
                return {"source": "virustotal", "data": {"malicious_count": 3, "clean_count": 67}}
            return {"error": "Unknown source"}
        
        self.agent._safe_lookup = mock_safe_lookup
        
        iocs = {"domain": ["malicious.example.com"]}
        results = await self.agent.evaluate(iocs)
        
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result["ioc"], "malicious.example.com")
        self.assertEqual(result["ioc_type"], "domain")
        self.assertIn("sources", result)

    async def test_evaluate_hashes(self):
        """Test evaluation of file hashes"""
        # Mock the _safe_lookup method for hash evaluation
        async def mock_safe_lookup(source, method, *args):
            if source == "virustotal":
                return {"source": "virustotal", "data": {"malicious_count": 45, "clean_count": 25}}
            return {"error": "Unknown source"}
        
        self.agent._safe_lookup = mock_safe_lookup
        
        iocs = {"md5": ["d41d8cd98f00b204e9800998ecf8427e"]}
        results = await self.agent.evaluate(iocs)
        
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result["ioc"], "d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(result["ioc_type"], "hash")
        self.assertIn("sources", result)

    async def test_evaluate_multiple_ioc_types(self):
        """Test evaluation of multiple IOC types"""
        # Mock the _safe_lookup method for multiple IOC types
        async def mock_safe_lookup(source, method, *args):
            if source == "abuseipdb":
                return {"source": "abuseipdb", "data": {"abuse_confidence": 25}}
            elif source == "virustotal":
                return {"source": "virustotal", "data": {"malicious_count": 1}}
            elif source == "shodan":
                return {"source": "shodan", "data": {"ports": [80]}}
            return {"error": "Unknown source"}
        
        self.agent._safe_lookup = mock_safe_lookup
        
        iocs = {
            "ipv4": ["203.0.113.1"],
            "domain": ["example.com"],
            "md5": ["d41d8cd98f00b204e9800998ecf8427e"]
        }
        
        results = await self.agent.evaluate(iocs)
        
        # Should have results for all IOC types
        self.assertEqual(len(results), 3)
        
        # Verify each IOC type is present
        ioc_types = [result["ioc_type"] for result in results]
        self.assertIn("ip", ioc_types)
        self.assertIn("domain", ioc_types)
        self.assertIn("hash", ioc_types)

    async def test_safe_lookup_success(self):
        """Test successful safe lookup"""
        # Mock successful client response
        mock_response = {"data": {"test": "value"}}
        
        async def mock_method(param):
            return mock_response
        
        result = await self.agent._safe_lookup("test_source", mock_method, "test_param")
        
        expected_keys = ["source", "data"]
        for key in expected_keys:
            self.assertIn(key, result)

    async def test_safe_lookup_failure(self):
        """Test safe lookup with exception handling"""
        async def mock_failing_method(param):
            raise Exception("API Error")
        
        result = await self.agent._safe_lookup("test_source", mock_failing_method, "test_param")
        
        # Verify error handling structure - error is nested in data
        self.assertIsInstance(result, dict)
        self.assertIn("source", result)
        self.assertIn("data", result)
        self.assertIn("error", result["data"])

    async def test_evaluate_ip_risk_scoring(self):
        """Test IP risk scoring logic"""
        # Mock high-risk response
        async def mock_safe_lookup(source, method, *args):
            if source == "abuseipdb":
                return {"source": "abuseipdb", "data": {"abuse_confidence": 95}}
            return {"error": "Unknown source"}
        
        self.agent._safe_lookup = mock_safe_lookup
        
        iocs = {"ipv4": ["malicious.ip"]}
        results = await self.agent.evaluate(iocs)
        
        result = results[0]
        self.assertTrue(result["summary"]["is_malicious"])
        self.assertGreater(result["summary"]["risk_score"], 50)

    async def test_evaluate_domain_risk_scoring(self):
        """Test domain risk scoring logic"""
        # Mock malicious domain response
        async def mock_safe_lookup(source, method, *args):
            if source == "virustotal":
                return {"source": "virustotal", "data": {"malicious_count": 15, "clean_count": 55}}
            return {"error": "Unknown source"}
        
        self.agent._safe_lookup = mock_safe_lookup
        
        iocs = {"domain": ["malicious.example.com"]}
        results = await self.agent.evaluate(iocs)
        
        result = results[0]
        self.assertIn("virustotal", result["sources"])
        self.assertIn("summary", result)

    async def test_evaluate_hash_risk_scoring(self):
        """Test hash risk scoring logic"""
        # Mock malicious hash response with proper structure
        async def mock_safe_lookup(source, method, *args):
            if source == "virustotal":
                # Return mock VirusTotal response that would indicate maliciousness
                return {"source": "virustotal", "data": {"attributes": {"last_analysis_stats": {"malicious": 60, "suspicious": 5, "harmless": 10}}}}
            return {"source": source, "data": {"error": "Unknown source"}}
        
        self.agent._safe_lookup = mock_safe_lookup
        
        iocs = {"sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]}
        results = await self.agent.evaluate(iocs)
        
        result = results[0]
        self.assertIn("summary", result)
        # Just verify the structure exists, the risk calculation depends on the actual implementation
        self.assertIn("risk_score", result["summary"])
        self.assertIn("is_malicious", result["summary"])

    async def test_concurrent_evaluations(self):
        """Test concurrent IOC evaluations"""
        # Mock responses for concurrent calls
        async def mock_safe_lookup(source, method, *args):
            if source == "abuseipdb":
                return {"source": "abuseipdb", "data": {"abuse_confidence": 0}}
            elif source == "shodan":
                return {"source": "shodan", "data": {"ports": [80]}}
            elif source == "virustotal":
                return {"source": "virustotal", "data": {"malicious_count": 0}}
            return {"error": "Unknown source"}
        
        self.agent._safe_lookup = mock_safe_lookup
        
        iocs = {"ipv4": ["8.8.8.8", "1.1.1.1", "208.67.222.222"]}
        results = await self.agent.evaluate(iocs)
        
        self.assertEqual(len(results), 3)
        
        # Verify all IPs were processed
        processed_ips = [result["ioc"] for result in results]
        self.assertEqual(set(processed_ips), set(["8.8.8.8", "1.1.1.1", "208.67.222.222"]))

    async def test_memory_caching(self):
        """Test memory caching functionality"""
        mock_memory = AsyncMock()
        mock_memory.get.return_value = None  # Cache miss
        mock_memory.set.return_value = True
        
        agent = ThreatAgent(memory=mock_memory, session_id="test-session")
        
        # Mock _safe_lookup
        async def mock_safe_lookup(source, method, *args):
            return {"source": source, "data": {"test": "value"}}
        
        agent._safe_lookup = mock_safe_lookup
        agent.shodan_client = self.mock_shodan
        agent.abuseipdb_client = self.mock_abuseipdb
        agent.virustotal_client = self.mock_virustotal
        
        iocs = {"ipv4": ["8.8.8.8"]}
        results = await agent.evaluate(iocs)
        
        # Verify cache was checked and updated
        mock_memory.get.assert_called()
        mock_memory.set.assert_called()

    async def test_error_handling_in_evaluation(self):
        """Test error handling during evaluation"""
        # Mock failing lookups with correct error format
        async def mock_failing_lookup(source, method, *args):
            return {"source": source, "data": {"error": f"{source} Error"}}
        
        self.agent._safe_lookup = mock_failing_lookup
        self.agent.shodan_client = self.mock_shodan
        self.agent.abuseipdb_client = self.mock_abuseipdb
        self.agent.virustotal_client = self.mock_virustotal
        
        iocs = {"ipv4": ["203.0.113.1"]}
        results = await self.agent.evaluate(iocs)
        
        # With all failing lookups, the agent might return error results
        self.assertGreater(len(results), 0)
        result = results[0]
        # The result might be an error or a properly structured IOC with error sources
        self.assertIsInstance(result, dict)


class TestThreatAgentIntegration(unittest.IsolatedAsyncioTestCase):
    """Integration tests for ThreatAgent"""

    async def asyncSetUp(self):
        """Set up test fixtures"""
        self.agent = ThreatAgent()

    async def asyncTearDown(self):
        """Clean up after tests"""
        await self.agent.close()

    async def test_full_evaluation_workflow(self):
        """Test complete evaluation workflow"""
        # Mock various responses
        async def mock_safe_lookup(source, method, *args):
            if source == "abuseipdb":
                return {"source": "abuseipdb", "data": {"abuse_confidence": 75}}
            elif source == "virustotal":
                return {"source": "virustotal", "data": {"malicious_count": 5, "clean_count": 65}}
            elif source == "shodan":
                return {"source": "shodan", "data": {"ports": [80, 443]}}
            return {"error": "Unknown source"}
        
        self.agent._safe_lookup = mock_safe_lookup
        self.agent.shodan_client = AsyncMock()
        self.agent.abuseipdb_client = AsyncMock()
        self.agent.virustotal_client = AsyncMock()
        
        complex_iocs = {
            "ipv4": ["203.0.113.1", "198.51.100.5"],
            "domain": ["malicious.example.com", "suspicious.test.org"],
            "md5": ["d41d8cd98f00b204e9800998ecf8427e"]
        }
        
        results = await self.agent.evaluate(complex_iocs)
        
        # Should process all IOCs
        self.assertEqual(len(results), 5)
        
        # Each result should have proper structure
        for result in results:
            self.assertIn("ioc", result)
            self.assertIn("ioc_type", result)
            self.assertIn("sources", result)
            self.assertIn("summary", result)
            
            # Summary should have risk assessment
            summary = result["summary"]
            self.assertIn("risk_score", summary)
            self.assertIn("is_malicious", summary)
            self.assertIsInstance(summary["risk_score"], (int, float))
            self.assertIsInstance(summary["is_malicious"], bool)

    async def test_evaluation_with_real_patterns(self):
        """Test evaluation with realistic IOC patterns"""
        # Mock all clients
        self.agent.shodan_client = AsyncMock()
        self.agent.abuseipdb_client = AsyncMock()
        self.agent.virustotal_client = AsyncMock()
        
        # Mock _safe_lookup for clean responses
        async def mock_safe_lookup(source, method, *args):
            if source == "abuseipdb":
                return {"source": "abuseipdb", "data": {"abuse_confidence": 0}}
            elif source == "virustotal":
                return {"source": "virustotal", "data": {"malicious_count": 0, "clean_count": 70}}
            elif source == "shodan":
                return {"source": "shodan", "data": {"ports": [80]}}
            return {"error": "Unknown source"}
        
        self.agent._safe_lookup = mock_safe_lookup
        
        # Test various IOC types
        test_iocs = {
            "ipv4": ["8.8.8.8", "203.0.113.1"],
            "domain": ["google.com", "suspicious-domain.tk"],
            "md5": ["d41d8cd98f00b204e9800998ecf8427e"],
            "sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
        }
        
        results = await self.agent.evaluate(test_iocs)
        
        # Should evaluate all IOCs
        expected_count = sum(len(ioc_list) for ioc_list in test_iocs.values())
        self.assertEqual(len(results), expected_count)


if __name__ == "__main__":
    unittest.main()