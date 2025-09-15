# Routing activity for Temporal workflow
import time
from typing import Dict, Any, List

from temporalio import activity

from ..models import AnalysisRequest, AnalysisType


@activity.defn
async def route_analysis_activity(request: AnalysisRequest) -> Dict[str, Any]:
    """
    Route analysis request and determine which tools/analysis to use.
    Simplified version for Temporal sandbox compatibility.
    """
    activity_start_time = time.time()

    try:
        activity.heartbeat("Starting analysis routing")

        # Simple routing logic based on analysis type and content
        routing_decision = {
            "use_threat_intel": True,  # Always use threat intel for security analysis
            "use_vision": request.image_data is not None,  # Only if image provided
            "use_pii": True,  # Always check for PII
            "analysis_priority": "medium",  # Default priority
            "recommended_tools": []
        }

        # Determine tools based on analysis type
        if request.analysis_type == AnalysisType.COMPREHENSIVE:
            routing_decision["recommended_tools"] = [
                "virustotal", "abuseipdb", "shodan", "milvus_search"
            ]
            routing_decision["analysis_priority"] = "high"
        elif request.analysis_type == AnalysisType.THREAT_INTEL:
            routing_decision["recommended_tools"] = [
                "virustotal", "abuseipdb", "shodan"
            ]
        elif request.analysis_type == AnalysisType.BASIC:
            routing_decision["recommended_tools"] = ["virustotal"]
        else:
            routing_decision["recommended_tools"] = ["virustotal"]

        # Check content for specific indicators
        text_lower = request.text.lower()
        if any(word in text_lower for word in ["malware", "virus", "trojan", "suspicious"]):
            routing_decision["analysis_priority"] = "high"
            if "milvus_search" not in routing_decision["recommended_tools"]:
                routing_decision["recommended_tools"].append("milvus_search")

        # Processing time
        processing_time = time.time() - activity_start_time

        routing_decision.update({
            "processing_time_seconds": processing_time,
            "confidence": 0.9,  # High confidence for simple routing
            "routing_reasons": [
                f"Analysis type: {request.analysis_type.value}",
                f"Text length: {len(request.text)} characters",
                f"Has image: {request.image_data is not None}"
            ]
        })

        activity.heartbeat(f"Routing complete: {len(routing_decision['recommended_tools'])} tools recommended")

        return routing_decision

    except Exception as e:
        processing_time = time.time() - activity_start_time

        # Return minimal routing on error
        return {
            "use_threat_intel": True,
            "use_vision": False,
            "use_pii": True,
            "analysis_priority": "medium",
            "recommended_tools": ["virustotal"],  # Fallback to basic tool
            "processing_time_seconds": processing_time,
            "confidence": 0.1,  # Low confidence on error
            "error": str(e)
        }