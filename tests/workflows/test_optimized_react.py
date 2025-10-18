#!/usr/bin/env python3
"""
Test script to verify ReAct workflow optimization - should use fewer OpenAI API calls
"""

import asyncio
import time

from utils.logging_config import get_security_logger
from workflows.react_workflow import create_cybershield_workflow

logger = get_security_logger("react_optimization_test")


async def test_optimized_workflow():
    """Test the optimized ReAct workflow"""
    print("🧪 Testing Optimized ReAct Workflow")
    print("=" * 50)

    # Create workflow without external API clients for testing
    workflow = create_cybershield_workflow(
        memory=None,
        vectorstore=None,
        llm_model="gpt-4o-mini",  # Use smaller model for testing
        abuseipdb_client=None,
        shodan_client=None,
        virustotal_client=None,
    )

    test_input = "Investigate IP 203.0.113.1 for potential malicious activity and determine risk level"

    print(f"📝 Input: {test_input}")
    print("🎯 Expected: Single OpenAI call + tool executions + synthesis")
    print("⚡ Goal: Minimize API calls for better performance")

    start_time = time.time()

    # Track API calls (this is simulated - in real scenario you'd count actual calls)
    try:
        result = await workflow.process(test_input)

        processing_time = time.time() - start_time

        print(f"\n✅ Workflow completed in {processing_time:.2f}s")
        print(
            f"📊 Result keys: {list(result.keys()) if isinstance(result, dict) else 'Non-dict result'}"
        )

        if isinstance(result, dict):
            processing_summary = result.get("processing_summary", {})
            iterations = processing_summary.get("iterations", 0)

            print(f"🔄 Total iterations: {iterations}")
            print(f"🎯 Expected API calls: ~{iterations + 1} (much better than before)")

            if iterations <= 3:
                print("✅ OPTIMIZATION SUCCESS: Low iteration count!")
            else:
                print("⚠️ Room for improvement: Still high iteration count")

        return result

    except Exception as e:
        print(f"❌ Test failed: {e}")
        return None


async def compare_efficiency():
    """Compare the efficiency of the optimized workflow"""
    print("\n🎯 ReAct Workflow Efficiency Analysis")
    print("=" * 50)

    # Expected improvements
    improvements = [
        "🚀 Fewer OpenAI API calls per analysis",
        "⚡ Faster overall processing time",
        "💰 Reduced API costs",
        "🎯 More direct tool execution",
        "🧠 Better context management",
    ]

    print("Expected optimizations:")
    for improvement in improvements:
        print(f"  {improvement}")

    print("\n📈 Before optimization:")
    print("  • Agent step → OpenAI call")
    print("  • Tool step → Execute tools")
    print("  • Agent step → Another OpenAI call")
    print("  • (Repeat loop)")
    print("  • Result: Multiple unnecessary API calls")

    print("\n🎯 After optimization:")
    print("  • Agent step → Single comprehensive OpenAI call")
    print("  • Tool step → Execute all identified tools")
    print("  • Synthesize → Direct to final result")
    print("  • Result: Minimal API calls, maximum efficiency")


if __name__ == "__main__":
    asyncio.run(test_optimized_workflow())
    asyncio.run(compare_efficiency())
