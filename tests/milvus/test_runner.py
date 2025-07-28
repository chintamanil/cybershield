#!/usr/bin/env python3
"""
Test runner for all Milvus-related tests
"""

import unittest
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Import all test modules
from tests.milvus.test_milvus_viewer import (
    TestMilvusDataViewer, 
    TestInteractiveMilvusViewer, 
    TestMilvusIntegration
)
from tests.milvus.test_milvus_client import (
    TestMilvusClient,
    TestMilvusDataTypes,
    TestMilvusUtilities,
    TestMilvusConnectionParameters,
    TestMilvusErrorScenarios,
    TestMilvusImportValidation
)
from tests.milvus.test_milvus_ingestion import (
    TestMilvusIngestion,
    TestMilvusIngestionIntegration,
    TestMilvusDataPreprocessing
)


def create_test_suite():
    """Create a comprehensive test suite for all Milvus functionality"""
    
    # Create the main test suite
    suite = unittest.TestSuite()
    
    # Milvus Viewer Tests
    print("📋 Adding Milvus Viewer Tests...")
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestMilvusDataViewer))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestInteractiveMilvusViewer))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestMilvusIntegration))
    
    # Milvus Client Tests
    print("📋 Adding Milvus Client Tests...")
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestMilvusClient))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestMilvusDataTypes))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestMilvusUtilities))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestMilvusConnectionParameters))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestMilvusErrorScenarios))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestMilvusImportValidation))
    
    # Milvus Ingestion Tests
    print("📋 Adding Milvus Ingestion Tests...")
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestMilvusIngestion))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestMilvusIngestionIntegration))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestMilvusDataPreprocessing))
    
    return suite


def run_tests(verbosity=2):
    """Run all Milvus tests with detailed output"""
    
    print("🛡️ CyberShield Milvus Test Suite")
    print("=" * 60)
    print("Running comprehensive tests for Milvus functionality...")
    print()
    
    # Create and run the test suite
    suite = create_test_suite()
    runner = unittest.TextTestRunner(verbosity=verbosity, buffer=True)
    
    print(f"📊 Total Tests: {suite.countTestCases()}")
    print("=" * 60)
    
    # Run the tests
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 60)
    print("🏁 Test Results Summary")
    print("=" * 60)
    
    print(f"✅ Tests Run: {result.testsRun}")
    print(f"❌ Failures: {len(result.failures)}")
    print(f"💥 Errors: {len(result.errors)}")
    print(f"⏭️ Skipped: {len(result.skipped) if hasattr(result, 'skipped') else 0}")
    
    if result.failures:
        print(f"\n❌ Failed Tests:")
        for test, traceback in result.failures:
            print(f"  - {test}")
    
    if result.errors:
        print(f"\n💥 Error Tests:")
        for test, traceback in result.errors:
            print(f"  - {test}")
    
    # Calculate success rate
    success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100) if result.testsRun > 0 else 0
    print(f"\n📈 Success Rate: {success_rate:.1f}%")
    
    if result.wasSuccessful():
        print("\n🎉 All tests passed successfully!")
        return True
    else:
        print(f"\n⚠️ Some tests failed. Please review the results above.")
        return False


def run_specific_test_class(test_class_name, verbosity=2):
    """Run tests for a specific test class"""
    
    test_classes = {
        'viewer': [TestMilvusDataViewer, TestInteractiveMilvusViewer, TestMilvusIntegration],
        'client': [TestMilvusClient, TestMilvusDataTypes, TestMilvusUtilities, 
                  TestMilvusConnectionParameters, TestMilvusErrorScenarios, TestMilvusImportValidation],
        'ingestion': [TestMilvusIngestion, TestMilvusIngestionIntegration, TestMilvusDataPreprocessing]
    }
    
    if test_class_name not in test_classes:
        print(f"❌ Unknown test class: {test_class_name}")
        print(f"Available classes: {', '.join(test_classes.keys())}")
        return False
    
    print(f"🛡️ Running {test_class_name.title()} Tests")
    print("=" * 40)
    
    suite = unittest.TestSuite()
    for test_class in test_classes[test_class_name]:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(test_class))
    
    runner = unittest.TextTestRunner(verbosity=verbosity, buffer=True)
    result = runner.run(suite)
    
    return result.wasSuccessful()


def main():
    """Main function to run tests based on command line arguments"""
    
    if len(sys.argv) > 1:
        # Run specific test class
        test_class = sys.argv[1].lower()
        success = run_specific_test_class(test_class)
    else:
        # Run all tests
        success = run_tests()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()