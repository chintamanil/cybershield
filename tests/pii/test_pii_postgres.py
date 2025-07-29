#!/usr/bin/env python3
"""
Test PII system with PostgreSQL integration
"""

import logging
from agents.pii_agent import PIIAgent
import os
# Configure logging
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

def test_pii_with_postgres():
    """Test PII system with PostgreSQL backend"""

    print("🛡️ Testing CyberShield PII System with PostgreSQL")
    print("=" * 60)

    # Initialize PII agent
    pii_agent = PIIAgent()

    # Test data
    test_text = "User john.doe@example.com connected from 192.168.1.100 with phone (555) 123-4567"

    print(f"📝 Original: {test_text}")

    # Start session and mask PII
    session_id = pii_agent.start_session()
    masked_text, mapping = pii_agent.mask_pii(test_text, session_id)

    print(f"🎭 Masked: {masked_text}")
    print(f"📋 Found {len(mapping)} PII items:")

    for token, data in mapping.items():
        print(f"  {token} -> {data['original']} ({data['type']})")

    # Test retrieval from PostgreSQL
    print(f"\n🔍 Testing PostgreSQL retrieval:")
    for token in mapping.keys():
        original = pii_agent.get_mapping(token, session_id)
        print(f"  {token} -> {original}")

    # Test unmasking
    unmasked = pii_agent.unmask_text(masked_text, session_id)
    print(f"\n🔓 Unmasked: {unmasked}")

    # End session
    pii_agent.end_session(session_id)

    print(f"\n✅ Test completed successfully!")
    print(f"📊 Session ID: {session_id}")
    print("=" * 60)

if __name__ == "__main__":
    test_pii_with_postgres()