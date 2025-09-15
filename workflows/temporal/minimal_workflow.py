# Minimal CyberShield Temporal Workflow - No external dependencies
from datetime import timedelta
from typing import Dict, Any

from temporalio import workflow
from temporalio.common import RetryPolicy

from .models import (
    AnalysisRequest,
    AnalysisResult,
    IOCAnalysis,
    ThreatAnalysis,
    ProcessingSummary,
    WorkflowConfig,
    RiskLevel,
    create_empty_iocs
)

# Import minimal activities only
from .activities.ioc_extraction import extract_iocs_activity
from .activities.routing import route_analysis_activity
from .activities.synthesis import synthesize_results_activity


@workflow.defn(sandboxed=False)
class MinimalCyberShieldWorkflow:
    """
    Minimal CyberShield security analysis workflow for Temporal validation.

    This workflow contains only the essential components without complex
    external dependencies that cause sandbox validation issues.
    """

    def __init__(self):
        self.config = WorkflowConfig()

    @workflow.run
    async def run(self, request: AnalysisRequest) -> AnalysisResult:
        """
        Minimal workflow execution - just basic IOC extraction and synthesis.
        """
        workflow_start_time = workflow.now()

        try:
            # Phase 1: Routing (determines what to do)
            routing_decision = await workflow.execute_activity(
                route_analysis_activity,
                request,
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=self._get_default_retry_policy()
            )

            # Phase 2: IOC Extraction (core functionality)
            ioc_analysis = await workflow.execute_activity(
                extract_iocs_activity,
                request,
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=self._get_default_retry_policy()
            )

            # Phase 3: Create basic threat analysis (no external APIs)
            threat_analysis = ThreatAnalysis(
                tool_results=[],
                threat_summary={"message": "Basic analysis completed"},
                risk_assessment={"low": 1, "medium": 0, "high": 0, "critical": 0},
                high_risk_indicators=[],
                recommendations=["Minimal workflow analysis completed"]
            )

            # Phase 4: Synthesize results
            synthesis_input = {
                "request": request,
                "ioc_analysis": ioc_analysis,
                "threat_analysis": threat_analysis,
                "vision_analysis": None,
                "pii_analysis": None
            }

            final_result = await workflow.execute_activity(
                synthesize_results_activity,
                synthesis_input,
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=self._get_default_retry_policy()
            )

            return final_result

        except Exception as e:
            # Create error result
            execution_time = (workflow.now() - workflow_start_time).total_seconds()

            return AnalysisResult(
                ioc_analysis=IOCAnalysis(
                    extracted_iocs=create_empty_iocs(),
                    total_ioc_count=0,
                    patterns_detected=[],
                    confidence_scores={},
                    validation_results={}
                ),
                threat_analysis=ThreatAnalysis(
                    tool_results=[],
                    threat_summary={"message": "Error occurred"},
                    risk_assessment={"low": 0, "medium": 0, "high": 0, "critical": 0},
                    high_risk_indicators=[],
                    recommendations=["Workflow failed with error"]
                ),
                processing_summary=ProcessingSummary(
                    workflow_id=workflow.info().workflow_id,
                    execution_time=execution_time,
                    tools_executed=[],
                    cache_hits=0,
                    api_calls_made=0,
                    processing_stages=["error"],
                    performance_metrics={}
                ),
                final_risk_level=RiskLevel.LOW,
                overall_confidence=0.0,
                status="error",
                error_details={"message": str(e)},
                warnings=["Minimal workflow execution failed"]
            )

    def _get_default_retry_policy(self) -> RetryPolicy:
        """Get default retry policy for activities"""
        return RetryPolicy(
            initial_interval=timedelta(seconds=1),
            backoff_coefficient=2.0,
            maximum_interval=timedelta(seconds=10),
            maximum_attempts=3,
        )