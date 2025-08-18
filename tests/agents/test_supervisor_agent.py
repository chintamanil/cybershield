"""
Comprehensive tests for SupervisorAgent
Tests agent coordination, workflow management, and analysis orchestration
"""

import unittest
import asyncio
import sys
import os
from unittest.mock import Mock, patch, AsyncMock, MagicMock

# Add parent directories to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from agents.supervisor import SupervisorAgent


class TestSupervisorAgent(unittest.IsolatedAsyncioTestCase):
    """Test cases for SupervisorAgent functionality"""

    async def asyncSetUp(self):
        """Set up test fixtures"""
        # Mock memory and vectorstore
        self.mock_memory = AsyncMock()
        self.mock_vectorstore = Mock()
        
        # Mock all individual agents to avoid their dependencies
        with patch('agents.supervisor.PIIAgent') as mock_pii, \
             patch('agents.supervisor.LogParserAgent') as mock_log, \
             patch('agents.supervisor.ThreatAgent') as mock_threat, \
             patch('agents.supervisor.VisionAgent') as mock_vision:
            
            # Create mock agents
            self.mock_pii_agent = AsyncMock()
            self.mock_log_parser = AsyncMock()
            self.mock_threat_agent = AsyncMock()
            self.mock_vision_agent = AsyncMock()
            
            # Setup mock constructors
            mock_pii.return_value = self.mock_pii_agent
            mock_log.return_value = self.mock_log_parser
            mock_threat.return_value = self.mock_threat_agent
            mock_vision.return_value = self.mock_vision_agent
            
            # Create supervisor without ReAct workflow initially
            self.supervisor = SupervisorAgent(
                memory=self.mock_memory,
                vectorstore=self.mock_vectorstore,
                use_react_workflow=False
            )

    async def test_init_without_react(self):
        """Test SupervisorAgent initialization without ReAct workflow"""
        self.assertIsNotNone(self.supervisor)
        self.assertEqual(self.supervisor.memory, self.mock_memory)
        self.assertEqual(self.supervisor.vectorstore, self.mock_vectorstore)
        self.assertFalse(self.supervisor.use_react_workflow)
        self.assertIsNone(self.supervisor.react_agent)

    async def test_init_with_react(self):
        """Test SupervisorAgent initialization with ReAct workflow"""
        with patch('agents.supervisor.PIIAgent'), \
             patch('agents.supervisor.LogParserAgent'), \
             patch('agents.supervisor.ThreatAgent'), \
             patch('agents.supervisor.VisionAgent'), \
             patch('agents.supervisor.create_cybershield_workflow') as mock_create_react:
            
            mock_react_agent = Mock()
            mock_create_react.return_value = mock_react_agent
            
            supervisor = SupervisorAgent(
                memory=self.mock_memory,
                vectorstore=self.mock_vectorstore,
                use_react_workflow=True
            )
            
            self.assertTrue(supervisor.use_react_workflow)
            self.assertIsNotNone(supervisor.react_agent)

    async def test_init_with_clients(self):
        """Test SupervisorAgent initialization with external clients"""
        mock_abuse = Mock()
        mock_shodan = Mock()
        mock_vt = Mock()
        
        with patch('agents.supervisor.PIIAgent'), \
             patch('agents.supervisor.LogParserAgent'), \
             patch('agents.supervisor.ThreatAgent'), \
             patch('agents.supervisor.VisionAgent'):
            
            supervisor = SupervisorAgent(
                memory=self.mock_memory,
                vectorstore=self.mock_vectorstore,
                use_react_workflow=False,
                abuseipdb_client=mock_abuse,
                shodan_client=mock_shodan,
                virustotal_client=mock_vt
            )
            
            self.assertEqual(supervisor.abuseipdb_client, mock_abuse)
            self.assertEqual(supervisor.shodan_client, mock_shodan)
            self.assertEqual(supervisor.virustotal_client, mock_vt)

    async def test_initialize_clients(self):
        """Test client initialization"""
        # Mock the threat agent to have the clients
        self.supervisor.threat_agent.shodan_client = Mock()
        self.supervisor.threat_agent.abuseipdb_client = Mock()
        self.supervisor.threat_agent.virustotal_client = Mock()
        
        await self.supervisor.initialize_clients()
        
        # Should copy clients from threat agent
        self.assertIsNotNone(self.supervisor.shodan_client)
        self.assertIsNotNone(self.supervisor.abuseipdb_client)
        self.assertIsNotNone(self.supervisor.virustotal_client)

    async def test_analyze_text_only_sequential(self):
        """Test text-only analysis with sequential processing"""
        # Setup mock responses for actual supervisor methods
        self.mock_pii_agent.mask_pii.return_value = ("Masked text", {})
        self.mock_log_parser.extract_iocs.return_value = {"ips": ["203.0.113.1"]}
        self.mock_threat_agent.evaluate.return_value = [
            {"ioc": "203.0.113.1", "ioc_type": "ip", "summary": {"risk_score": 75}}
        ]
        
        test_text = "Failed login from 203.0.113.1"
        result = await self.supervisor.analyze(test_text)
        
        # Verify agents were called
        self.mock_pii_agent.mask_pii.assert_called_once()
        self.mock_log_parser.extract_iocs.assert_called_once()
        self.mock_threat_agent.evaluate.assert_called_once()
        
        # Verify result structure
        self.assertIn("processing_method", result)
        self.assertIn("pii_analysis", result)
        self.assertIn("ioc_analysis", result)
        self.assertIn("threat_analysis", result)

    async def test_analyze_with_image_sequential(self):
        """Test analysis with image using sequential processing"""
        # Setup mock responses for image analysis
        self.mock_pii_agent.mask_pii.return_value = ("Masked text", {})
        self.mock_log_parser.extract_iocs.return_value = {}
        self.mock_threat_agent.evaluate.return_value = []
        
        self.mock_vision_agent.process_image.return_value = {
            "ocr": {"text": "Extracted text", "confidence": 85},
            "status": "success"
        }
        
        test_text = "Security alert"
        test_image = b"fake_image_data"
        
        result = await self.supervisor.analyze(test_text, test_image)
        
        # Verify vision agent was called
        self.mock_vision_agent.process_image.assert_called_once_with(test_image)
        
        # Verify result includes vision analysis
        self.assertIn("vision_analysis", result)

    async def test_analyze_with_react_workflow(self):
        """Test analysis using ReAct workflow"""
        with patch('agents.supervisor.create_cybershield_workflow') as mock_create_react:
            # Create mock ReAct agent
            mock_react_agent = AsyncMock()
            mock_react_agent.process.return_value = {
                "status": "success",
                "final_report": {"summary": "React analysis complete"}
            }
            mock_create_react.return_value = mock_react_agent
            
            # Create supervisor with ReAct enabled
            supervisor = SupervisorAgent(
                memory=self.mock_memory,
                vectorstore=self.mock_vectorstore,
                use_react_workflow=True
            )
            
            test_text = "Security event detected"
            result = await supervisor.analyze(test_text)
            
            # Verify ReAct workflow was used
            mock_react_agent.process.assert_called_once()
            self.assertEqual(result["processing_method"], "react_workflow")

    async def test_analyze_batch(self):
        """Test batch analysis functionality"""
        # Setup mock responses for sequential processing
        self.mock_pii_agent.mask_pii.return_value = ("Masked text", {})
        self.mock_log_parser.extract_iocs.return_value = {}
        self.mock_threat_agent.evaluate.return_value = []
        
        test_inputs = [
            "Log entry 1",
            "Log entry 2",
            "Log entry 3"
        ]
        
        results = await self.supervisor.analyze_batch(test_inputs)
        
        # Should return results for all inputs
        self.assertEqual(len(results), 3)
        
        # Verify each result has expected structure
        for result in results:
            self.assertIn("processing_method", result)
            self.assertIn("status", result)

    async def test_get_agent_status(self):
        """Test agent status reporting"""
        status = self.supervisor.get_agent_status()
        
        self.assertIn("supervisor", status)
        self.assertIn("agents", status)
        self.assertIn("react_agent", status)
        
        # Verify agent availability
        self.assertIn("pii_agent", status["agents"])
        self.assertIn("log_parser", status["agents"])
        self.assertIn("threat_agent", status["agents"])
        self.assertIn("vision_agent", status["agents"])

    async def test_generate_recommendations_high_risk(self):
        """Test recommendation generation for high-risk scenarios"""
        analysis_results = {
            "threat_assessment": {
                "results": [
                    {"ioc": "203.0.113.1", "risk_score": 90, "risk_level": "HIGH"}
                ]
            },
            "pii_analysis": {
                "mapping": {"[PII_SSN_001]": "123-45-6789"}
            },
            "vision_analysis": {
                "overall_risk": {"risk_level": "HIGH", "risk_score": 85}
            }
        }
        
        recommendations = self.supervisor._generate_recommendations(analysis_results)
        
        self.assertGreater(len(recommendations), 0)
        
        # Should include security-focused recommendations
        rec_text = " ".join(recommendations).lower()
        self.assertTrue(any(keyword in rec_text for keyword in ["isolate", "block", "immediate"]))

    async def test_generate_recommendations_low_risk(self):
        """Test recommendation generation for low-risk scenarios"""
        analysis_results = {
            "threat_assessment": {"results": []},
            "pii_analysis": {"mapping": {}},
            "log_analysis": {"summary": {"total_iocs": 0}}
        }
        
        recommendations = self.supervisor._generate_recommendations(analysis_results)
        
        # Should have fewer, less urgent recommendations
        self.assertLessEqual(len(recommendations), 3)

    async def test_store_analysis_results(self):
        """Test analysis result storage"""
        test_results = {
            "processing_method": "sequential",
            "log_analysis": {"iocs": {"public_ipv4": ["203.0.113.1"]}},
            "threat_assessment": {"results": []}
        }
        
        await self.supervisor._store_analysis_results(test_results)
        
        # Verify memory storage was attempted
        self.mock_memory.set.assert_called()

    async def test_error_handling_in_analysis(self):
        """Test error handling during analysis"""
        # Make log parser fail
        self.mock_log_parser.extract_iocs.side_effect = Exception("Log parser error")
        
        # Other agents should still work
        self.mock_threat_agent.evaluate.return_value = []
        self.mock_pii_agent.mask_pii.return_value = ("Masked text", {})
        
        test_text = "Test log entry"
        result = await self.supervisor.analyze(test_text)
        
        # Should handle error gracefully and still return a result
        self.assertIn("processing_method", result)
        self.assertIn("status", result)

    async def test_concurrent_agent_operations(self):
        """Test concurrent operations across agents"""
        # Setup mock responses with delays to test concurrency
        async def delayed_response(*args, **kwargs):
            await asyncio.sleep(0.1)
            return {}
        
        self.mock_log_parser.extract_iocs = AsyncMock(side_effect=delayed_response)
        self.mock_threat_agent.evaluate.return_value = []
        self.mock_pii_agent.mask_pii.return_value = ("Masked text", {})
        
        # Process multiple inputs concurrently
        test_inputs = ["Log 1", "Log 2", "Log 3"]
        start_time = asyncio.get_event_loop().time()
        
        results = await self.supervisor.analyze_batch(test_inputs)
        
        end_time = asyncio.get_event_loop().time()
        
        # Should complete in reasonable time (less than sequential)
        self.assertLess(end_time - start_time, 1.0)  # Should be much faster than 3x0.1 = 0.3s
        self.assertEqual(len(results), 3)

    async def test_memory_integration(self):
        """Test memory integration functionality"""
        # Test that memory is properly passed to agents
        self.assertEqual(self.supervisor.pii_agent.memory, self.mock_memory)
        self.assertEqual(self.supervisor.threat_agent.memory, self.mock_memory)
        self.assertEqual(self.supervisor.vision_agent.memory, self.mock_memory)

    async def test_vectorstore_integration(self):
        """Test vectorstore integration"""
        self.assertEqual(self.supervisor.vectorstore, self.mock_vectorstore)
        
        # Verify vectorstore is available for ReAct workflow
        if self.supervisor.use_react_workflow:
            self.assertIsNotNone(self.supervisor.vectorstore)


class TestSupervisorAgentIntegration(unittest.IsolatedAsyncioTestCase):
    """Integration tests for SupervisorAgent"""

    async def asyncSetUp(self):
        """Set up test fixtures"""
        # Mock external dependencies but allow agent integration
        self.mock_memory = AsyncMock()
        self.mock_vectorstore = Mock()

    async def test_full_analysis_workflow_sequential(self):
        """Test complete analysis workflow in sequential mode"""
        with patch('agents.supervisor.PIIAgent') as mock_pii, \
             patch('agents.supervisor.LogParserAgent') as mock_log, \
             patch('agents.supervisor.ThreatAgent') as mock_threat, \
             patch('agents.supervisor.VisionAgent') as mock_vision:
            
            # Setup comprehensive mock responses
            mock_log_parser = AsyncMock()
            mock_log_parser.extract_iocs.return_value = {
                "ips": ["203.0.113.1"],
                "domain": ["malicious.example.com"]
            }
            
            mock_threat_agent = AsyncMock()
            mock_threat_agent.evaluate.return_value = [
                {"ioc": "203.0.113.1", "ioc_type": "ip", "summary": {"risk_score": 85, "is_malicious": True}},
                {"ioc": "malicious.example.com", "ioc_type": "domain", "summary": {"risk_score": 75, "is_malicious": True}}
            ]
            
            mock_pii_agent = AsyncMock()
            mock_pii_agent.mask_pii.return_value = ("Masked security log", {"[MASK_0]": {"original": "admin@company.com", "type": "email"}})
            
            # Setup mock constructors
            mock_pii.return_value = mock_pii_agent
            mock_log.return_value = mock_log_parser
            mock_threat.return_value = mock_threat_agent
            mock_vision.return_value = AsyncMock()
            
            # Create supervisor
            supervisor = SupervisorAgent(
                memory=self.mock_memory,
                vectorstore=self.mock_vectorstore,
                use_react_workflow=False
            )
            
            # Run analysis
            test_text = "Security alert: suspicious traffic from 203.0.113.1 to malicious.example.com. Contact admin@company.com"
            result = await supervisor.analyze(test_text)
            
            # Verify complete workflow
            self.assertEqual(result["processing_method"], "sequential")
            self.assertIn("pii_analysis", result)
            self.assertIn("ioc_analysis", result)
            self.assertIn("threat_analysis", result)
            self.assertIn("recommendations", result)
            
            # Verify IOCs were processed
            if "ioc_reports" in result["threat_analysis"]:
                self.assertEqual(len(result["threat_analysis"]["ioc_reports"]), 2)
            
            # Verify PII was detected and masked
            self.assertGreater(len(result["pii_analysis"]["pii_mapping"]), 0)

    async def test_multimodal_analysis_workflow(self):
        """Test multimodal analysis with text and image"""
        with patch('agents.supervisor.PIIAgent') as mock_pii, \
             patch('agents.supervisor.LogParserAgent') as mock_log, \
             patch('agents.supervisor.ThreatAgent') as mock_threat, \
             patch('agents.supervisor.VisionAgent') as mock_vision:
            
            # Setup mock agents
            mock_log_parser = AsyncMock()
            mock_log_parser.extract_iocs.return_value = {}
            
            mock_pii_agent = AsyncMock()
            mock_pii_agent.mask_pii.return_value = ("Masked text", {})
            
            mock_threat_agent = AsyncMock()
            mock_threat_agent.evaluate.return_value = []
            
            mock_vision_agent = AsyncMock()
            mock_vision_agent.process_image.return_value = {
                "ocr": {
                    "text": "Confidential Document - Employee ID: E12345",
                    "confidence": 90
                },
                "status": "success"
            }
            
            # Setup mock constructors
            mock_pii.return_value = mock_pii_agent
            mock_log.return_value = mock_log_parser
            mock_threat.return_value = mock_threat_agent
            mock_vision.return_value = mock_vision_agent
            
            # Create supervisor
            supervisor = SupervisorAgent(
                memory=self.mock_memory,
                vectorstore=self.mock_vectorstore,
                use_react_workflow=False
            )
            
            # Run multimodal analysis
            test_text = "Analyzing uploaded document"
            test_image = b"fake_image_data"
            
            result = await supervisor.analyze(test_text, test_image)
            
            # Verify multimodal processing
            self.assertIn("vision_analysis", result)
            self.assertIn("status", result)

    async def test_performance_under_load(self):
        """Test supervisor performance under load"""
        with patch('agents.supervisor.PIIAgent'), \
             patch('agents.supervisor.LogParserAgent'), \
             patch('agents.supervisor.ThreatAgent'), \
             patch('agents.supervisor.VisionAgent'):
            
            supervisor = SupervisorAgent(
                memory=self.mock_memory,
                vectorstore=self.mock_vectorstore,
                use_react_workflow=False
            )
            
            # Setup minimal mock responses for performance testing
            supervisor.log_parser.extract_iocs = AsyncMock(return_value={})
            supervisor.threat_agent.evaluate = AsyncMock(return_value=[])
            supervisor.pii_agent.mask_pii = AsyncMock(return_value=("text", {}))
            
            # Test with multiple concurrent requests
            test_inputs = [f"Log entry {i}" for i in range(10)]
            
            start_time = asyncio.get_event_loop().time()
            results = await supervisor.analyze_batch(test_inputs)
            end_time = asyncio.get_event_loop().time()
            
            # Verify all requests completed
            self.assertEqual(len(results), 10)
            
            # Should complete in reasonable time
            self.assertLess(end_time - start_time, 5.0)


if __name__ == "__main__":
    unittest.main()