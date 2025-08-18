"""
Comprehensive tests for PIIAgent
Tests PII detection, masking, unmasking, and session management
"""

import unittest
import asyncio
import sys
import os
from unittest.mock import Mock, patch, AsyncMock

# Add parent directories to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from agents.pii_agent import PIIAgent


class TestPIIAgent(unittest.IsolatedAsyncioTestCase):
    """Test cases for PIIAgent functionality"""

    async def asyncSetUp(self):
        """Set up test fixtures"""
        # Mock the PIISecureStore to avoid database dependencies
        with patch('agents.pii_agent.PIISecureStore') as mock_store_class:
            self.mock_store = Mock()
            mock_store_class.return_value = self.mock_store
            self.agent = PIIAgent()

    async def test_init(self):
        """Test PIIAgent initialization"""
        self.assertIsNotNone(self.agent)
        self.assertIsNotNone(self.agent.pii_store)
        self.assertIsNotNone(self.agent.perf_config)
        self.assertIsNone(self.agent.current_session)

    async def test_start_session_success(self):
        """Test successful session start"""
        self.mock_store.start_session.return_value = True
        
        session_id = await self.agent.start_session("test-session-123")
        
        self.assertEqual(session_id, "test-session-123")
        self.assertEqual(self.agent.current_session, "test-session-123")
        self.mock_store.start_session.assert_called_once_with("test-session-123")

    async def test_start_session_auto_generate_id(self):
        """Test session start with auto-generated ID"""
        self.mock_store.start_session.return_value = True
        
        session_id = await self.agent.start_session()
        
        self.assertIsNotNone(session_id)
        self.assertTrue(len(session_id) > 0)
        self.assertEqual(self.agent.current_session, session_id)
        self.mock_store.start_session.assert_called_once_with(session_id)

    async def test_start_session_failure(self):
        """Test session start failure"""
        self.mock_store.start_session.return_value = False
        
        session_id = await self.agent.start_session("test-session")
        
        self.assertIsNone(session_id)
        self.assertIsNone(self.agent.current_session)

    async def test_mask_pii_with_session(self):
        """Test PII masking with existing session"""
        # Mock the store methods
        self.mock_store.start_session.return_value = True
        self.mock_store.store_mapping.return_value = True
        
        test_text = "My SSN is 123-45-6789 and email is john@example.com"
        masked_text, mapping = await self.agent.mask_pii(test_text, "test-session")
        
        # Verify that PII was detected and masked
        self.assertNotEqual(masked_text, test_text)
        self.assertIsInstance(mapping, dict)
        
        # Verify SSN was masked
        self.assertNotIn("123-45-6789", masked_text)
        self.assertIn("[MASK_", masked_text)
        
        # Verify email was masked
        self.assertNotIn("john@example.com", masked_text)

    async def test_mask_pii_without_session(self):
        """Test PII masking without existing session"""
        self.mock_store.start_session.return_value = True
        self.mock_store.store_mapping.return_value = True
        
        test_text = "Call me at 555-123-4567"
        masked_text, mapping = await self.agent.mask_pii(test_text)
        
        # Should create a new session
        self.assertIsNotNone(self.agent.current_session)
        
        # Verify phone number was masked
        self.assertNotIn("555-123-4567", masked_text)
        self.assertIn("[MASK_", masked_text)

    async def test_mask_pii_no_pii_found(self):
        """Test text with no PII"""
        test_text = "This is a normal text without any sensitive information"
        masked_text, mapping = await self.agent.mask_pii(test_text, "test-session")
        
        # Text should remain unchanged
        self.assertEqual(masked_text, test_text)
        self.assertEqual(len(mapping), 0)

    async def test_mask_pii_multiple_types(self):
        """Test text with multiple PII types"""
        self.mock_store.store_mapping.return_value = True
        
        test_text = "Contact John Doe at john@example.com, SSN: 123-45-6789, phone: 555-123-4567"
        masked_text, mapping = await self.agent.mask_pii(test_text, "test-session")
        
        # All PII types should be masked
        self.assertNotIn("john@example.com", masked_text)
        self.assertNotIn("123-45-6789", masked_text)
        self.assertNotIn("555-123-4567", masked_text)
        
        # Should have multiple mappings
        self.assertGreater(len(mapping), 0)

    async def test_unmask_text_success(self):
        """Test successful text unmasking"""
        # Setup mock mappings
        mock_mappings = {
            "[MASK_0]": "john@example.com",
            "[MASK_1]": "123-45-6789"
        }
        self.mock_store.get_session_mappings.return_value = mock_mappings
        
        masked_text = "Contact [MASK_0] with SSN [MASK_1]"
        unmasked_text = await self.agent.unmask_text(masked_text, "test-session")
        
        expected_text = "Contact john@example.com with SSN 123-45-6789"
        self.assertEqual(unmasked_text, expected_text)

    async def test_unmask_text_no_session(self):
        """Test unmasking without session"""
        self.agent.current_session = "current-session"
        self.mock_store.get_session_mappings.return_value = {"[MASK_0]": "test@example.com"}
        
        masked_text = "Email: [MASK_0]"
        unmasked_text = await self.agent.unmask_text(masked_text)
        
        # Should use current session
        self.assertIn("test@example.com", unmasked_text)

    async def test_get_mapping_success(self):
        """Test successful mapping retrieval"""
        self.mock_store.get_mapping.return_value = "john@example.com"
        
        result = await self.agent.get_mapping("[MASK_0]", "test-session")
        
        self.assertEqual(result, "john@example.com")
        self.mock_store.get_mapping.assert_called_once_with("[MASK_0]")

    async def test_get_mapping_not_found(self):
        """Test mapping retrieval when not found"""
        self.mock_store.get_mapping.return_value = None
        
        result = await self.agent.get_mapping("[MASK_999]", "test-session")
        
        self.assertIsNone(result)

    async def test_end_session_success(self):
        """Test successful session end"""
        self.mock_store.end_session.return_value = True
        self.agent.current_session = "test-session"
        
        await self.agent.end_session("test-session")
        
        self.assertIsNone(self.agent.current_session)
        self.mock_store.end_session.assert_called_once()

    async def test_end_session_with_current(self):
        """Test ending current session"""
        self.mock_store.end_session.return_value = True
        self.agent.current_session = "current-session"
        
        await self.agent.end_session()
        
        self.assertIsNone(self.agent.current_session)
        self.mock_store.end_session.assert_called_once()

    async def test_cleanup_expired_sessions(self):
        """Test cleanup of expired sessions"""
        self.mock_store.cleanup_expired_sessions.return_value = 5
        
        await self.agent.cleanup_expired_sessions()
        
        self.mock_store.cleanup_expired_sessions.assert_called_once()

    async def test_mask_pii_edge_cases(self):
        """Test PII masking edge cases"""
        test_cases = [
            ("", ""),  # Empty string
            ("   ", "   "),  # Whitespace only
            ("No PII here", "No PII here"),  # No PII
            ("email@domain", "email@domain"),  # Invalid email format
        ]
        
        for input_text, expected in test_cases:
            masked_text, mapping = await self.agent.mask_pii(input_text, "test-session")
            self.assertEqual(masked_text, expected)
            self.assertEqual(len(mapping), 0)

    async def test_pii_patterns_coverage(self):
        """Test that all PII patterns are detected"""
        self.mock_store.store_mapping.return_value = True
        self.mock_store.start_session.return_value = True
        
        test_cases = [
            ("SSN: 123-45-6789", "ssn"),
            ("Email: user@domain.com", "email"),
            ("Phone: (555) 123-4567", "phone"),
            ("Phone: 555-123-4567", "phone"),
            ("Card: 4111-1111-1111-1111", "credit_card"),
        ]
        
        for text, pii_type in test_cases:
            masked_text, mapping = await self.agent.mask_pii(text, "test-session")
            
            # Verify that the text was masked
            self.assertNotEqual(masked_text, text)
            self.assertGreater(len(mapping), 0)
            
            # Verify the correct PII type was detected
            found_correct_type = any(
                data["type"] == pii_type for data in mapping.values()
            )
            self.assertTrue(found_correct_type, f"Expected {pii_type} pattern not found")


class TestPIIAgentIntegration(unittest.IsolatedAsyncioTestCase):
    """Integration tests for PIIAgent with real PII patterns"""

    async def asyncSetUp(self):
        """Set up test fixtures with real store"""
        # Use a mock for integration tests to avoid database dependencies
        with patch('agents.pii_agent.PIISecureStore') as mock_store_class:
            self.mock_store = Mock()
            mock_store_class.return_value = self.mock_store
            self.mock_store.start_session.return_value = True
            self.mock_store.store_mapping.return_value = True
            self.agent = PIIAgent()

    async def test_full_workflow(self):
        """Test complete PII workflow"""
        # Start session
        session_id = await self.agent.start_session()
        self.assertIsNotNone(session_id)
        
        # Mask PII
        original_text = "Contact John at john.doe@company.com or call 555-123-4567. SSN: 123-45-6789"
        masked_text, mapping = await self.agent.mask_pii(original_text, session_id)
        
        # Verify masking
        self.assertNotEqual(masked_text, original_text)
        self.assertGreater(len(mapping), 0)
        
        # Mock unmask functionality
        self.mock_store.get_session_mappings.return_value = {token: data["original"] for token, data in mapping.items()}
        unmasked_text = await self.agent.unmask_text(masked_text, session_id)
        
        # End session
        await self.agent.end_session(session_id)
        self.assertIsNone(self.agent.current_session)

    async def test_concurrent_sessions(self):
        """Test handling multiple concurrent sessions"""
        # Create multiple sessions
        session1 = await self.agent.start_session("session-1")
        session2 = await self.agent.start_session("session-2")
        
        self.assertEqual(session1, "session-1")
        self.assertEqual(session2, "session-2")
        
        # Test that each session can mask independently
        text1 = "Email: alice@example.com"
        text2 = "Email: bob@example.com"
        
        masked1, mapping1 = await self.agent.mask_pii(text1, session1)
        masked2, mapping2 = await self.agent.mask_pii(text2, session2)
        
        # Verify independent masking
        self.assertNotEqual(masked1, text1)
        self.assertNotEqual(masked2, text2)
        self.assertGreater(len(mapping1), 0)
        self.assertGreater(len(mapping2), 0)


if __name__ == "__main__":
    unittest.main()