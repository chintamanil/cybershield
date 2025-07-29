#!/usr/bin/env python3
"""
Tests for the PII agent system
"""

import unittest
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from agents.pii_agent import PIIAgent


class TestPIIAgent(unittest.IsolatedAsyncioTestCase):
    """Async test cases for PIIAgent class"""
    
    async def asyncSetUp(self):
        """Set up async test fixtures"""
        self.pii_agent = PIIAgent()
    
    async def test_start_session(self):
        """Test PII session creation"""
        session_id = await self.pii_agent.start_session()
        self.assertIsNotNone(session_id)
        self.assertEqual(self.pii_agent.current_session, session_id)
    
    async def test_mask_pii_email(self):
        """Test email PII masking"""
        test_text = "Contact john.doe@example.com for assistance"
        session_id = await self.pii_agent.start_session()
        
        masked_text, mapping = await self.pii_agent.mask_pii(test_text, session_id)
        
        self.assertNotIn("john.doe@example.com", masked_text)
        self.assertGreater(len(mapping), 0)
        
        # Verify mapping contains email
        email_found = False
        for token, data in mapping.items():
            if data['type'] == 'email' and data['original'] == 'john.doe@example.com':
                email_found = True
                break
        self.assertTrue(email_found)
    
    async def test_mask_pii_ip_addresses(self):
        """Test IP address PII masking"""
        test_text = "Server at 192.168.1.100 and IPv6 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        session_id = await self.pii_agent.start_session()
        
        masked_text, mapping = await self.pii_agent.mask_pii(test_text, session_id)
        
        self.assertNotIn("192.168.1.100", masked_text)
        self.assertNotIn("2001:0db8:85a3:0000:0000:8a2e:0370:7334", masked_text)
        self.assertGreaterEqual(len(mapping), 2)
    
    async def test_mask_pii_phone_number(self):
        """Test phone number PII masking"""
        test_text = "Call us at (555) 123-4567"
        session_id = await self.pii_agent.start_session()
        
        masked_text, mapping = await self.pii_agent.mask_pii(test_text, session_id)
        
        self.assertNotIn("(555) 123-4567", masked_text)
        self.assertGreater(len(mapping), 0)
    
    async def test_mask_pii_multiple_types(self):
        """Test masking multiple PII types"""
        test_text = """
        User john.doe@example.com connected from 192.168.1.100
        Phone: (555) 123-4567
        MAC Address: 00:1B:44:11:3A:B7
        """
        session_id = await self.pii_agent.start_session()
        
        masked_text, mapping = await self.pii_agent.mask_pii(test_text, session_id)
        
        # Check that original PII is not in masked text
        self.assertNotIn("john.doe@example.com", masked_text)
        self.assertNotIn("192.168.1.100", masked_text)
        self.assertNotIn("(555) 123-4567", masked_text)
        self.assertNotIn("00:1B:44:11:3A:B7", masked_text)
        
        # Should have multiple mappings
        self.assertGreaterEqual(len(mapping), 4)
    
    async def test_unmask_text(self):
        """Test PII unmasking"""
        test_text = "Contact john.doe@example.com for help"
        session_id = await self.pii_agent.start_session()
        
        masked_text, mapping = await self.pii_agent.mask_pii(test_text, session_id)
        unmasked_text = await self.pii_agent.unmask_text(masked_text, session_id)
        
        self.assertEqual(test_text, unmasked_text)
    
    async def test_get_mapping(self):
        """Test individual PII mapping retrieval"""
        test_text = "Email: test@example.com"
        session_id = await self.pii_agent.start_session()
        
        masked_text, mapping = await self.pii_agent.mask_pii(test_text, session_id)
        
        # Get first token
        token = list(mapping.keys())[0]
        original = await self.pii_agent.get_mapping(token, session_id)
        
        self.assertEqual(original, mapping[token]['original'])
    
    async def test_end_session(self):
        """Test session cleanup"""
        session_id = await self.pii_agent.start_session()
        self.assertIsNotNone(session_id)
        
        await self.pii_agent.end_session(session_id)
        # Session should be cleaned up
    
    async def test_no_pii_text(self):
        """Test text with no PII"""
        test_text = "This is just normal text with no sensitive information"
        session_id = await self.pii_agent.start_session()
        
        masked_text, mapping = await self.pii_agent.mask_pii(test_text, session_id)
        
        self.assertEqual(test_text, masked_text)
        self.assertEqual(len(mapping), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)