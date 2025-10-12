#!/usr/bin/env python3
"""
Debug script to test Redis IOC storage and retrieval.
Tests the actual IOC storage mechanism used by the context resolver.
"""
import asyncio
import uuid
from memory.redis_stm import RedisSTM
from memory.session_storage import SessionStorage

async def test_ioc_storage():
    """Test IOC storage and retrieval with order preservation"""
    print("\n=== Testing Redis IOC Storage and Retrieval ===\n")

    # Initialize Redis
    memory = RedisSTM()
    session_storage = SessionStorage(memory=memory, postgres_client=None)

    # Create test session
    session_id = str(uuid.uuid4())
    print(f"Test Session ID: {session_id}")

    # Test 1: Store first set of IOCs
    print("\n--- Test 1: Store first IOCs ---")
    iocs_1 = {
        "ips": ["203.0.113.50", "192.168.1.100"],
        "domains": ["malware-c2.example.com"],
        "hashes": ["d41d8cd98f00b204e9800998ecf8427e"]
    }

    success = await session_storage.store_iocs(
        session_id=session_id,
        iocs=iocs_1,
        merge=True
    )
    print(f"Storage result: {'✓ Success' if success else '✗ Failed'}")

    # Retrieve and verify
    retrieved_1 = await session_storage.get_iocs(session_id)
    print(f"Retrieved IOCs: {retrieved_1}")
    print(f"Last IP: {retrieved_1.get('ips', [])[-1] if retrieved_1 and retrieved_1.get('ips') else 'NONE'}")

    # Test 2: Store second set of IOCs (merge with existing)
    print("\n--- Test 2: Store second IOCs (merge mode) ---")
    iocs_2 = {
        "ips": ["198.51.100.25"],
        "domains": [],
        "hashes": []
    }

    success = await session_storage.store_iocs(
        session_id=session_id,
        iocs=iocs_2,
        merge=True
    )
    print(f"Storage result: {'✓ Success' if success else '✗ Failed'}")

    # Retrieve and verify order
    retrieved_2 = await session_storage.get_iocs(session_id)
    print(f"Retrieved IOCs: {retrieved_2}")

    if retrieved_2 and retrieved_2.get('ips'):
        ips = retrieved_2['ips']
        print(f"\nIP Order: {ips}")
        print(f"Most recent IP (last): {ips[-1]}")
        print(f"Expected: 198.51.100.25")
        print(f"Match: {'✓ CORRECT' if ips[-1] == '198.51.100.25' else '✗ WRONG'}")

        # Check for duplicates
        if len(ips) != len(set(ips)):
            print("⚠️  WARNING: Duplicates found in IP list!")
        else:
            print("✓ No duplicates")
    else:
        print("✗ ERROR: No IPs retrieved!")

    # Test 3: Context resolver fetch
    print("\n--- Test 3: Context Resolver Fetch ---")
    from workflows.context_resolver import ContextResolver
    resolver = ContextResolver(memory=memory, llm_client=None)

    context = await resolver._fetch_session_context(session_id)
    if context:
        iocs = context.get('iocs', {})
        print(f"Context IOCs: {iocs}")
        if iocs.get('ips'):
            print(f"Most recent IP via resolver: {iocs['ips'][-1]}")
    else:
        print("✗ ERROR: No context retrieved!")

    # Test 4: Pattern matching
    print("\n--- Test 4: Pattern Matching ---")
    test_input = "The same IP is now scanning ports 22, 23, 3389"

    needs_context = resolver._detect_context_references(test_input)
    print(f"Detected references: {needs_context}")

    if context and 'ip' in needs_context and context.get('iocs', {}).get('ips'):
        enriched_text, context_used = resolver._resolve_pronouns(
            test_input, context, needs_context
        )
        print(f"\nOriginal: {test_input}")
        print(f"Enriched: {enriched_text}")
        print(f"Context used: {context_used}")
        print(f"Expected IP: 198.51.100.25")
        print(f"Actual IP: {context_used.get('ip', 'NONE')}")
        print(f"Match: {'✓ CORRECT' if context_used.get('ip') == '198.51.100.25' else '✗ WRONG'}")
    else:
        print("✗ ERROR: Pattern matching conditions not met!")
        print(f"  - Has context: {bool(context)}")
        print(f"  - 'ip' in needs_context: {'ip' in needs_context}")
        print(f"  - Has IPs: {bool(context.get('iocs', {}).get('ips') if context else False)}")

    print("\n=== Test Complete ===\n")

if __name__ == "__main__":
    asyncio.run(test_ioc_storage())
