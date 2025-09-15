#!/usr/bin/env python3
"""
Test script to execute a CyberShield Temporal workflow and verify it appears in the UI.
"""
import asyncio
import uuid
from temporalio.client import Client
from workflows.temporal.models import AnalysisRequest, AnalysisType
from workflows.temporal.cybershield_workflow import CyberShieldWorkflow


async def test_cybershield_workflow():
    """Execute a test CyberShield workflow"""
    print("🔧 Testing CyberShield Temporal Workflow...")

    try:
        # Connect to Temporal server
        client = await Client.connect("localhost:7233")
        print("✅ Connected to Temporal server")

        # Create test request
        request = AnalysisRequest(
            text="Test security analysis with IP 192.168.1.1 and suspicious hash d41d8cd98f00b204e9800998ecf8427e",
            analysis_type=AnalysisType.COMPREHENSIVE,
            image_data=None
        )

        # Generate unique workflow ID
        workflow_id = f"test-cybershield-{uuid.uuid4().hex[:8]}"

        print(f"🚀 Starting workflow: {workflow_id}")
        print(f"📝 Test input: {request.text[:50]}...")

        # Start the workflow
        handle = await client.start_workflow(
            CyberShieldWorkflow.run,
            request,
            id=workflow_id,
            task_queue="cybershield-workflows",
        )

        print(f"✅ Workflow started successfully!")
        print(f"🔗 Workflow ID: {workflow_id}")
        print(f"🌐 Check Temporal UI: http://localhost:8080/namespaces/default/workflows/{workflow_id}")

        # Wait for result with timeout
        print("⏳ Waiting for workflow to complete...")
        result = await asyncio.wait_for(handle.result(), timeout=120)  # 2 minute timeout

        print("✅ Workflow completed successfully!")
        print(f"📊 Status: {result.status}")
        print(f"🎯 Risk Level: {result.final_risk_level}")
        print(f"📈 IOCs Found: {result.ioc_analysis.total_ioc_count}")
        print(f"⏱️  Execution Time: {result.processing_summary.execution_time:.2f}s")

        return result

    except asyncio.TimeoutError:
        print("⏰ Workflow execution timed out after 2 minutes")
        print(f"🌐 Check workflow status in UI: http://localhost:8080/namespaces/default/workflows/{workflow_id}")
        return None
    except Exception as e:
        print(f"❌ Workflow execution failed: {e}")
        return None


if __name__ == "__main__":
    # Set up environment
    import os
    import sys

    # Add current directory to Python path for imports
    sys.path.insert(0, os.getcwd())

    # Run the test
    result = asyncio.run(test_cybershield_workflow())

    if result:
        print("\n🎉 Test completed successfully!")
    else:
        print("\n⚠️  Test completed with issues - check Temporal UI for details")