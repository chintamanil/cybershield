# Results synthesis activity for Temporal workflow
import time
from typing import Dict, Any, Optional

from temporalio import activity

from ..models import (
    AnalysisRequest,
    AnalysisResult,
    IOCAnalysis,
    ThreatAnalysis,
    VisionAnalysis,
    PIIAnalysis,
    ProcessingSummary,
    RiskLevel
)


@activity.defn
async def synthesize_results_activity(synthesis_input: Dict[str, Any]) -> AnalysisResult:
    """
    Synthesize all analysis results into a comprehensive final report.
    Simplified version for Temporal sandbox compatibility.
    """
    activity_start_time = time.time()

    try:
        activity.heartbeat("Starting results synthesis")

        # Extract components from input
        request = synthesis_input["request"]
        ioc_analysis = synthesis_input.get("ioc_analysis")
        threat_analysis = synthesis_input.get("threat_analysis")
        vision_analysis = synthesis_input.get("vision_analysis")
        pii_analysis = synthesis_input.get("pii_analysis")

        # Calculate overall risk level
        risk_level = RiskLevel.LOW  # Default
        risk_score = 0.0

        if threat_analysis and hasattr(threat_analysis, 'risk_assessment'):
            risk_assessment = threat_analysis.risk_assessment
            if isinstance(risk_assessment, dict):
                high_risk = risk_assessment.get("high", 0)
                critical_risk = risk_assessment.get("critical", 0)

                if critical_risk > 0:
                    risk_level = RiskLevel.CRITICAL
                    risk_score = 0.9
                elif high_risk > 0:
                    risk_level = RiskLevel.HIGH
                    risk_score = 0.7
                elif risk_assessment.get("medium", 0) > 0:
                    risk_level = RiskLevel.MEDIUM
                    risk_score = 0.5
                else:
                    risk_level = RiskLevel.LOW
                    risk_score = 0.2

        # Generate recommendations
        recommendations = []
        if ioc_analysis and ioc_analysis.get('total_ioc_count', 0) > 0:
            recommendations.append(f"Found {ioc_analysis.get('total_ioc_count', 0)} indicators of compromise - investigate further")

        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            recommendations.append("High risk detected - immediate investigation recommended")
        elif risk_level == RiskLevel.MEDIUM:
            recommendations.append("Medium risk detected - monitor and review")
        else:
            recommendations.append("Low risk detected - standard monitoring sufficient")

        # Processing summary
        execution_time = time.time() - activity_start_time
        processing_summary = ProcessingSummary(
            workflow_id="temporal-workflow",
            execution_time=execution_time,
            tools_executed=[
                name for name in ["ioc_extraction", "threat_analysis", "vision_analysis", "pii_analysis"]
                if synthesis_input.get(name.replace("_extraction", "_analysis")) is not None
            ],
            cache_hits=0,  # Simplified
            api_calls_made=0,  # Simplified - not tracking in this version
            processing_stages=["extraction", "analysis", "synthesis"],
            performance_metrics={"total_time": execution_time}
        )

        activity.heartbeat(f"Synthesis complete - risk level: {risk_level.value}")

        # Create final result
        result = AnalysisResult(
            status="success",
            final_risk_level=risk_level,
            overall_confidence=0.8,  # Default confidence
            ioc_analysis=ioc_analysis,
            threat_analysis=threat_analysis,
            vision_analysis=vision_analysis,
            pii_analysis=pii_analysis,
            processing_summary=processing_summary
        )

        return result

    except Exception as e:
        execution_time = time.time() - activity_start_time
        activity.heartbeat(f"Results synthesis failed: {str(e)}")

        # Return error result
        error_summary = ProcessingSummary(
            workflow_id="temporal-workflow",
            execution_time=execution_time,
            tools_executed=[],
            cache_hits=0,
            api_calls_made=0,
            processing_stages=["error"],
            performance_metrics={"error": str(e)}
        )

        return AnalysisResult(
            status="error",
            final_risk_level=RiskLevel.LOW,
            overall_confidence=0.0,
            ioc_analysis=synthesis_input.get("ioc_analysis"),
            threat_analysis=synthesis_input.get("threat_analysis"),
            vision_analysis=synthesis_input.get("vision_analysis"),
            pii_analysis=synthesis_input.get("pii_analysis"),
            processing_summary=error_summary,
            error_details={"message": str(e)}
        )