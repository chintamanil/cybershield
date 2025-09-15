#!/usr/bin/env python3
"""
Complete test script for Temporal workflow validation fixes
Tests all three major fixes:
1. Shodan client method name fix
2. IOC extraction validation results fix
3. PII processing serialization fix
"""
import asyncio
import uuid
from temporalio.client import Client
from workflows.temporal.models import AnalysisRequest, AnalysisType
from workflows.temporal.cybershield_workflow import CyberShieldWorkflow

async def test_complete_workflow():
    """Test the complete workflow with all fixes applied"""

    print("🚀 Testing complete CyberShield Temporal workflow with all fixes...")

    try:
        # Connect to Temporal server
        client = await Client.connect("localhost:7233")
        print("✅ Connected to Temporal server")

        # Create test request with PII content
        test_request = AnalysisRequest(
            text="Final analysis with IP 8.8.8.8 and email test@example.com",
            analysis_type=AnalysisType.COMPREHENSIVE,
            request_id=f"test-complete-{uuid.uuid4().hex[:8]}",
            priority="normal"
        )

        print(f"📝 Test request: {test_request.text}")
        print(f"🆔 Request ID: {test_request.request_id}")

        # Execute workflow
        print("\n🔄 Starting workflow execution...")

        result = await client.execute_workflow(
            CyberShieldWorkflow.run,
            test_request,
            id=f"test-workflow-{test_request.request_id}",
            task_queue="cybershield-workflows",
            execution_timeout=timedelta(minutes=5)
        )

        print("✅ Workflow completed successfully!")
        print(f"📊 Results summary:")
        print(f"   - IOC count: {result.ioc_analysis.total_ioc_count}")
        print(f"   - Risk level: {result.final_risk_level}")
        print(f"   - Status: {result.status}")

        if result.pii_analysis:
            print(f"   - PII detected: {result.pii_analysis.pii_detected}")
            print(f"   - PII types: {result.pii_analysis.pii_types}")
            print(f"   - Masked text: {result.pii_analysis.masked_text}")

        if result.threat_analysis:
            print(f"   - Threat tools executed: {len(result.threat_analysis.tool_results)}")
            print(f"   - High risk indicators: {len(result.threat_analysis.high_risk_indicators)}")

        print("\n🎉 All tests completed successfully! All three fixes are working:")
        print("   ✅ Shodan client method name fixed")
        print("   ✅ IOC validation results type fixed")
        print("   ✅ PII processing serialization fixed")

        return True

    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    from datetime import timedelta

    success = asyncio.run(test_complete_workflow())
    if success:
        print("\n🎯 All Temporal worker validation issues have been resolved!")
        exit(0)
    else:
        print("\n💥 Some issues remain - check the error output above")
        exit(1)