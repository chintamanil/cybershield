#!/usr/bin/env python3
"""
Comprehensive async test runner for CyberShield
Supports both mocked tests and real API integration tests
"""

import os
import sys
import asyncio
import unittest
import argparse
import logging
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

# Configure logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def check_api_keys():
    """Check which API keys are available for integration testing"""
    api_keys = {
        'VIRUSTOTAL_API_KEY': os.getenv('VIRUSTOTAL_API_KEY'),
        'SHODAN_API_KEY': os.getenv('SHODAN_API_KEY'),
        'ABUSEIPDB_API_KEY': os.getenv('ABUSEIPDB_API_KEY')
    }

    available = {k: v for k, v in api_keys.items() if v}
    missing = [k for k, v in api_keys.items() if not v]

    logger.info("API Key Status:")
    for key in available:
        logger.info(f"  ✅ {key}: Available")
    for key in missing:
        logger.info(f"  ❌ {key}: Missing")

    return available, missing


def run_mock_tests():
    """Run all async tests with mocked API calls"""
    logger.info("Running async tests with mocked API calls...")

    # Discover and run async tests
    test_loader = unittest.TestLoader()
    test_suite = unittest.TestSuite()

    # Add async test modules
    try:
        from tests.tools.test_virustotal_async import (
            TestVirusTotalClientAsync,
            TestAsyncConvenienceFunctions as VTAsyncConvenienceFunctions,
            TestAsyncErrorHandling
        )
        test_suite.addTests(test_loader.loadTestsFromTestCase(TestVirusTotalClientAsync))
        test_suite.addTests(test_loader.loadTestsFromTestCase(VTAsyncConvenienceFunctions))
        test_suite.addTests(test_loader.loadTestsFromTestCase(TestAsyncErrorHandling))
        logger.info("  ✅ Added VirusTotal async tests")
    except ImportError as e:
        logger.error(f"  ❌ Failed to import VirusTotal async tests: {e}")

    try:
        from tests.tools.test_shodan_async import (
            TestShodanClientAsync,
            TestAsyncConvenienceFunctions as ShodanAsyncConvenienceFunctions
        )
        test_suite.addTests(test_loader.loadTestsFromTestCase(TestShodanClientAsync))
        test_suite.addTests(test_loader.loadTestsFromTestCase(ShodanAsyncConvenienceFunctions))
        logger.info("  ✅ Added Shodan async tests")
    except ImportError as e:
        logger.error(f"  ❌ Failed to import Shodan async tests: {e}")

    try:
        from tests.tools.test_abuseipdb_async import (
            TestAbuseIPDBClientAsync,
            TestAsyncConvenienceFunctions as AbuseIPDBAsyncConvenienceFunctions
        )
        test_suite.addTests(test_loader.loadTestsFromTestCase(TestAbuseIPDBClientAsync))
        test_suite.addTests(test_loader.loadTestsFromTestCase(AbuseIPDBAsyncConvenienceFunctions))
        logger.info("  ✅ Added AbuseIPDB async tests")
    except ImportError as e:
        logger.error(f"  ❌ Failed to import AbuseIPDB async tests: {e}")

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2, buffer=True)
    result = runner.run(test_suite)

    return result.wasSuccessful()


def run_integration_tests(available_keys):
    """Run integration tests with real API calls"""
    logger.info("Running integration tests with real API calls...")

    if not available_keys:
        logger.warning("No API keys available - skipping integration tests")
        return True

    test_loader = unittest.TestLoader()
    test_suite = unittest.TestSuite()

    # Add integration test classes based on available keys
    if 'VIRUSTOTAL_API_KEY' in available_keys:
        try:
            from tests.tools.test_virustotal_async import TestVirusTotalRealAPI
            test_suite.addTests(test_loader.loadTestsFromTestCase(TestVirusTotalRealAPI))
            logger.info("  ✅ Added VirusTotal integration tests")
        except ImportError as e:
            logger.error(f"  ❌ Failed to import VirusTotal integration tests: {e}")

    if 'SHODAN_API_KEY' in available_keys:
        try:
            from tests.tools.test_shodan_async import TestShodanRealAPI
            test_suite.addTests(test_loader.loadTestsFromTestCase(TestShodanRealAPI))
            logger.info("  ✅ Added Shodan integration tests")
        except ImportError as e:
            logger.error(f"  ❌ Failed to import Shodan integration tests: {e}")

    if 'ABUSEIPDB_API_KEY' in available_keys:
        try:
            from tests.tools.test_abuseipdb_async import TestAbuseIPDBRealAPI
            test_suite.addTests(test_loader.loadTestsFromTestCase(TestAbuseIPDBRealAPI))
            logger.info("  ✅ Added AbuseIPDB integration tests")
        except ImportError as e:
            logger.error(f"  ❌ Failed to import AbuseIPDB integration tests: {e}")

    if test_suite.countTestCases() == 0:
        logger.warning("No integration tests to run")
        return True

    # Run integration tests with longer timeout
    runner = unittest.TextTestRunner(verbosity=2, buffer=True)
    result = runner.run(test_suite)

    return result.wasSuccessful()


async def run_manual_concurrent_test():
    """Run a manual test of concurrent API calls"""
    logger.info("Running manual concurrent API test...")

    available_keys, _ = check_api_keys()

    tasks = []

    # Only test with available API keys
    if 'VIRUSTOTAL_API_KEY' in available_keys:
        from tools.virustotal import VirusTotalClient
        async def test_vt():
            async with VirusTotalClient() as client:
                return await client.lookup_ip("8.8.8.8")
        tasks.append(("VirusTotal", test_vt()))

    if 'SHODAN_API_KEY' in available_keys:
        from tools.shodan import ShodanClient
        async def test_shodan():
            async with ShodanClient() as client:
                return await client.lookup_ip("8.8.8.8")
        tasks.append(("Shodan", test_shodan()))

    if 'ABUSEIPDB_API_KEY' in available_keys:
        from tools.abuseipdb import AbuseIPDBClient
        async def test_abuseipdb():
            async with AbuseIPDBClient() as client:
                return await client.check_ip("8.8.8.8")
        tasks.append(("AbuseIPDB", test_abuseipdb()))

    if not tasks:
        logger.warning("No API keys available for concurrent test")
        return True

    # Run concurrent lookups
    import time
    start_time = time.time()

    logger.info(f"Starting concurrent lookups for {len(tasks)} services...")
    results = await asyncio.gather(*[task[1] for task in tasks], return_exceptions=True)

    end_time = time.time()
    duration = end_time - start_time

    logger.info(f"Concurrent lookups completed in {duration:.2f} seconds")

    # Check results
    success = True
    for i, (service, result) in enumerate(zip([task[0] for task in tasks], results)):
        if isinstance(result, Exception):
            logger.error(f"  ❌ {service}: {result}")
            success = False
        elif isinstance(result, dict) and "error" not in result:
            logger.info(f"  ✅ {service}: Success")
        else:
            logger.warning(f"  ⚠️  {service}: {result.get('error', 'Unknown error')}")

    return success


def main():
    """Main test runner"""
    parser = argparse.ArgumentParser(description="CyberShield Async Test Runner")
    parser.add_argument(
        "--mode",
        choices=["mock", "integration", "concurrent", "all"],
        default="mock",
        help="Test mode to run"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("🚀 Starting CyberShield Async Test Suite")
    logger.info("=" * 60)

    # Check API key availability
    available_keys, missing_keys = check_api_keys()

    success = True

    if args.mode in ["mock", "all"]:
        logger.info("\n" + "="*60)
        logger.info("📝 MOCK TESTS")
        logger.info("="*60)
        success &= run_mock_tests()

    if args.mode in ["integration", "all"] and available_keys:
        logger.info("\n" + "="*60)
        logger.info("🌐 INTEGRATION TESTS")
        logger.info("="*60)
        success &= run_integration_tests(available_keys)

    if args.mode in ["concurrent", "all"] and available_keys:
        logger.info("\n" + "="*60)
        logger.info("🚀 CONCURRENT PERFORMANCE TEST")
        logger.info("="*60)
        success &= asyncio.run(run_manual_concurrent_test())

    # Summary
    logger.info("\n" + "="*60)
    logger.info("📊 TEST SUMMARY")
    logger.info("="*60)

    if success:
        logger.info("🎉 All tests passed!")
        if missing_keys:
            logger.info(f"💡 To run integration tests, set these environment variables:")
            for key in missing_keys:
                logger.info(f"   export {key}=your_api_key_here")
    else:
        logger.error("❌ Some tests failed!")

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())