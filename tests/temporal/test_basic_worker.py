# Test basic temporal worker with minimal dependencies
import asyncio
from temporalio.client import Client
from temporalio.worker import Worker
from workflows.temporal.basic_workflow import BasicWorkflow, simple_analysis_activity


async def test_basic_worker():
    """Test the basic workflow worker"""
    print("🔧 Testing basic Temporal worker...")

    try:
        # Connect to Temporal server
        client = await Client.connect("localhost:7233")
        print("✅ Connected to Temporal server")

        # Create and start worker
        worker = Worker(
            client,
            task_queue="test-basic-queue",
            workflows=[BasicWorkflow],
            activities=[simple_analysis_activity],
        )

        print("✅ Worker created successfully")
        print("🔧 Starting worker validation...")

        # The worker will validate on start
        async with worker:
            print("✅ Worker validation passed!")
            print("🏃 Worker is running...")

            # Test a simple workflow execution
            handle = await client.start_workflow(
                BasicWorkflow.run,
                "Test input with IP 192.168.1.1 and domain example.com",
                id="test-basic-workflow",
                task_queue="test-basic-queue",
            )

            result = await handle.result()
            print(f"✅ Workflow completed: {result}")

    except Exception as e:
        print(f"❌ Worker test failed: {e}")


if __name__ == "__main__":
    asyncio.run(test_basic_worker())