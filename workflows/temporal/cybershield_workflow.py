# CyberShield Temporal Workflow - Main orchestration logic
import asyncio
from datetime import timedelta
from typing import List, Optional, Dict, Any

from temporalio import workflow
from temporalio.common import RetryPolicy

from .models import (
    AnalysisRequest,
    AnalysisResult,
    IOCAnalysis,
    ThreatAnalysis,
    ThreatIntelResult,
    VisionAnalysis,
    PIIAnalysis,
    ProcessingSummary,
    WorkflowConfig,
    RiskLevel,
    AnalysisType,
    create_empty_iocs,
    merge_iocs,
    calculate_overall_risk_level
)

# Import all activities (sandboxed=False allows complex dependencies)
from .activities.ioc_extraction import extract_iocs_activity
from .activities.threat_intelligence import (
    virustotal_analysis_activity,
    abuseipdb_analysis_activity,
    shodan_analysis_activity,
    milvus_search_activity
)
from .activities.vision_processing import vision_analysis_activity
from .activities.pii_processing import pii_analysis_activity
from .activities.routing import route_analysis_activity
from .activities.synthesis import synthesize_results_activity

from utils.logging_config import get_security_logger

logger = get_security_logger("cybershield_workflow")


@workflow.defn(sandboxed=False)
class CyberShieldWorkflow:
    """
    Main CyberShield security analysis workflow using Temporal.

    This workflow replaces the LangGraph ReAct workflow with a more robust,
    durable execution model that handles failures gracefully and provides
    better observability.
    """

    def __init__(self):
        self.config = WorkflowConfig()

    @workflow.run
    async def run(self, request: AnalysisRequest) -> AnalysisResult:
        """
        Main workflow execution method.

        This orchestrates the entire security analysis pipeline:
        1. Input validation and routing
        2. IOC extraction
        3. Parallel threat intelligence gathering
        4. Vision analysis (if image provided)
        5. PII detection and masking
        6. Result synthesis and risk assessment
        """
        workflow_start_time = workflow.now()
        workflow_id = workflow.info().workflow_id

        logger.info(
            "Starting CyberShield workflow",
            workflow_id=workflow_id,
            analysis_type=str(request.analysis_type),
            has_image=request.image_data is not None,
            text_length=len(request.text)
        )

        try:
            # Phase 1: Routing and Analysis Planning
            routing_decision = await self._route_analysis(request)

            # Phase 2: IOC Extraction (foundational step)
            ioc_analysis = await self._extract_iocs(request)

            # Phase 3: Parallel Processing Based on Routing Decision
            if routing_decision.get("use_threat_intel", True):
                threat_analysis = await self._parallel_threat_intelligence(request, ioc_analysis)
            else:
                threat_analysis = self._create_empty_threat_analysis()

            # Phase 4: Optional Specialized Analysis
            vision_analysis = None
            pii_analysis = None

            if request.image_data and routing_decision.get("use_vision", True):
                vision_analysis = await self._vision_analysis(request)

            if routing_decision.get("use_pii_detection", True):
                pii_analysis = await self._pii_analysis(request)

            # Phase 5: Final Synthesis and Risk Assessment
            final_result = await self._synthesize_results(
                request,
                ioc_analysis,
                threat_analysis,
                vision_analysis,
                pii_analysis,
                workflow_start_time
            )

            # Calculate execution time
            execution_time = (workflow.now() - workflow_start_time).total_seconds()

            logger.info(
                "CyberShield workflow completed successfully",
                workflow_id=workflow_id,
                execution_time=execution_time,
                final_risk_level=str(final_result.final_risk_level),
                ioc_count=final_result.ioc_analysis.total_ioc_count
            )

            return final_result

        except Exception as e:
            execution_time = (workflow.now() - workflow_start_time).total_seconds()

            logger.error(
                "CyberShield workflow failed",
                workflow_id=workflow_id,
                execution_time=execution_time,
                error=str(e)
            )

            # Return error result instead of failing the workflow
            return self._create_error_result(request, str(e), execution_time)

    async def _route_analysis(self, request: AnalysisRequest) -> Dict[str, Any]:
        """Determine which analysis components to execute"""
        return await workflow.execute_activity(
            route_analysis_activity,
            request,
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=self._get_default_retry_policy(),
            heartbeat_timeout=timedelta(seconds=10)
        )

    async def _extract_iocs(self, request: AnalysisRequest) -> IOCAnalysis:
        """Extract Indicators of Compromise from input text"""
        return await workflow.execute_activity(
            extract_iocs_activity,
            request,
            start_to_close_timeout=timedelta(seconds=self.config.activity_timeout),
            retry_policy=self._get_default_retry_policy(),
            heartbeat_timeout=timedelta(seconds=self.config.heartbeat_timeout)
        )

    async def _parallel_threat_intelligence(
        self,
        request: AnalysisRequest,
        ioc_analysis: IOCAnalysis
    ) -> ThreatAnalysis:
        """Execute threat intelligence tools in parallel"""

        # Prepare activities to execute in parallel
        activities = []

        # Only execute tools that have IOCs to analyze
        if ioc_analysis.extracted_iocs.ips:
            activities.extend([
                workflow.execute_activity(
                    virustotal_analysis_activity,
                    ioc_analysis.extracted_iocs,
                    start_to_close_timeout=timedelta(seconds=self.config.activity_timeout),
                    retry_policy=self._get_api_retry_policy(),
                    heartbeat_timeout=timedelta(seconds=self.config.heartbeat_timeout)
                ),
                workflow.execute_activity(
                    abuseipdb_analysis_activity,
                    ioc_analysis.extracted_iocs,
                    start_to_close_timeout=timedelta(seconds=self.config.activity_timeout),
                    retry_policy=self._get_api_retry_policy(),
                    heartbeat_timeout=timedelta(seconds=self.config.heartbeat_timeout)
                ),
                workflow.execute_activity(
                    shodan_analysis_activity,
                    ioc_analysis.extracted_iocs,
                    start_to_close_timeout=timedelta(seconds=self.config.activity_timeout),
                    retry_policy=self._get_api_retry_policy(),
                    heartbeat_timeout=timedelta(seconds=self.config.heartbeat_timeout)
                )
            ])

        # Vector search for historical attack patterns
        if request.text:
            activities.append(
                workflow.execute_activity(
                    milvus_search_activity,
                    request.text,
                    start_to_close_timeout=timedelta(seconds=self.config.activity_timeout),
                    retry_policy=self._get_default_retry_policy(),
                    heartbeat_timeout=timedelta(seconds=self.config.heartbeat_timeout)
                )
            )

        if not activities:
            return self._create_empty_threat_analysis()

        logger.info(f"Executing {len(activities)} threat intelligence activities in parallel")

        # Execute all activities in parallel
        try:
            results = await asyncio.gather(*activities, return_exceptions=True)

            # Process results and handle exceptions
            successful_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.warning(f"Threat intelligence activity {i} failed: {result}")
                    # Create error result
                    error_result = ThreatIntelResult(
                        tool_name=f"activity_{i}",
                        status="error",
                        results=[],
                        execution_time=0.0,
                        error_message=str(result)
                    )
                    successful_results.append(error_result)
                else:
                    successful_results.append(result)

            # Aggregate all results into final threat analysis
            return await self._aggregate_threat_results(successful_results)

        except Exception as e:
            logger.error(f"Parallel threat intelligence execution failed: {e}")
            return self._create_empty_threat_analysis()

    async def _vision_analysis(self, request: AnalysisRequest) -> Optional[VisionAnalysis]:
        """Perform computer vision analysis on image data"""
        if not request.image_data:
            return None

        return await workflow.execute_activity(
            vision_analysis_activity,
            request.image_data,
            start_to_close_timeout=timedelta(seconds=self.config.activity_timeout * 2),  # Vision takes longer
            retry_policy=self._get_default_retry_policy(),
            heartbeat_timeout=timedelta(seconds=self.config.heartbeat_timeout)
        )

    async def _pii_analysis(self, request: AnalysisRequest) -> Optional[PIIAnalysis]:
        """Perform PII detection and masking"""
        return await workflow.execute_activity(
            pii_analysis_activity,
            request.text,
            start_to_close_timeout=timedelta(seconds=self.config.activity_timeout),
            retry_policy=self._get_default_retry_policy(),
            heartbeat_timeout=timedelta(seconds=self.config.heartbeat_timeout)
        )

    async def _synthesize_results(
        self,
        request: AnalysisRequest,
        ioc_analysis: IOCAnalysis,
        threat_analysis: ThreatAnalysis,
        vision_analysis: Optional[VisionAnalysis],
        pii_analysis: Optional[PIIAnalysis],
        workflow_start_time
    ) -> AnalysisResult:
        """Synthesize all analysis results into final report"""
        synthesis_input = {
            "request": request,
            "ioc_analysis": ioc_analysis,
            "threat_analysis": threat_analysis,
            "vision_analysis": vision_analysis,
            "pii_analysis": pii_analysis
        }

        return await workflow.execute_activity(
            synthesize_results_activity,
            synthesis_input,
            start_to_close_timeout=timedelta(seconds=self.config.activity_timeout),
            retry_policy=self._get_default_retry_policy(),
            heartbeat_timeout=timedelta(seconds=self.config.heartbeat_timeout)
        )

    async def _aggregate_threat_results(self, results: List[ThreatIntelResult]) -> ThreatAnalysis:
        """Aggregate individual threat intelligence results"""
        # This could also be an activity, but keeping it simple for now
        high_risk_indicators = []
        risk_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        recommendations = []

        for result in results:
            if result.status == "success":
                # Process each tool's results
                for item in result.results:
                    risk_level = self._assess_item_risk(result.tool_name, item)
                    risk_counts[risk_level] += 1

                    if risk_level in ["high", "critical"]:
                        high_risk_indicators.append({
                            "source": result.tool_name,
                            "indicator": item.get("indicator", "unknown"),
                            "risk_level": risk_level,
                            "details": item
                        })

        # Generate recommendations based on findings
        if risk_counts["critical"] > 0:
            recommendations.append("🚨 Critical threats detected - immediate action required")
        if risk_counts["high"] > 0:
            recommendations.append(f"⚠️ {risk_counts['high']} high-risk indicators found")
        if sum(risk_counts.values()) == 0:
            recommendations.append("✅ No significant security threats detected")

        return ThreatAnalysis(
            tool_results=results,
            threat_summary={
                "total_indicators": sum(risk_counts.values()),
                "risk_distribution": risk_counts
            },
            risk_assessment=risk_counts,
            high_risk_indicators=high_risk_indicators,
            recommendations=recommendations
        )

    def _assess_item_risk(self, tool_name: str, item: Dict[str, Any]) -> str:
        """Assess risk level for individual threat intelligence item"""
        # Simplified risk assessment - could be made more sophisticated
        if tool_name == "abuseipdb":
            confidence = item.get("abuse_confidence", 0)
            if confidence >= 75:
                return "critical"
            elif confidence >= 50:
                return "high"
            elif confidence >= 25:
                return "medium"
            else:
                return "low"

        elif tool_name == "virustotal":
            malicious_count = item.get("malicious_count", 0)
            if malicious_count >= 5:
                return "critical"
            elif malicious_count >= 3:
                return "high"
            elif malicious_count >= 1:
                return "medium"
            else:
                return "low"

        else:
            return "low"

    def _create_empty_threat_analysis(self) -> ThreatAnalysis:
        """Create empty threat analysis for cases where no threat intel is needed"""
        return ThreatAnalysis(
            tool_results=[],
            threat_summary={"message": "No threat intelligence analysis performed"},
            risk_assessment={"low": 0, "medium": 0, "high": 0, "critical": 0},
            high_risk_indicators=[],
            recommendations=["Analysis completed without threat intelligence tools"]
        )

    def _create_error_result(self, request: AnalysisRequest, error_msg: str, execution_time: float) -> AnalysisResult:
        """Create error result when workflow fails"""
        return AnalysisResult(
            ioc_analysis=IOCAnalysis(
                extracted_iocs=create_empty_iocs(),
                total_ioc_count=0,
                patterns_detected=[],
                confidence_scores={},
                validation_results={}
            ),
            threat_analysis=self._create_empty_threat_analysis(),
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
            error_details={"message": error_msg},
            warnings=["Workflow execution failed"]
        )

    def _get_default_retry_policy(self) -> RetryPolicy:
        """Get default retry policy for activities"""
        return RetryPolicy(
            initial_interval=timedelta(seconds=self.config.retry_initial_interval),
            backoff_coefficient=self.config.retry_backoff_coefficient,
            maximum_interval=timedelta(seconds=self.config.retry_maximum_interval),
            maximum_attempts=self.config.max_activity_retries,
        )

    def _get_api_retry_policy(self) -> RetryPolicy:
        """Get retry policy for external API calls (more aggressive retries)"""
        return RetryPolicy(
            initial_interval=timedelta(seconds=2),
            backoff_coefficient=2.0,
            maximum_interval=timedelta(seconds=120),
            maximum_attempts=7,  # More retries for API calls
        )


# Helper functions for workflow execution

def create_cybershield_workflow_id(request_id: str) -> str:
    """Create consistent workflow ID for CyberShield analysis"""
    return f"cybershield-analysis-{request_id}"


def get_task_queue_for_request(request: AnalysisRequest) -> str:
    """Get appropriate task queue based on analysis type"""
    if request.analysis_type == AnalysisType.VISION_ANALYSIS:
        return "cybershield-vision"
    elif request.analysis_type == AnalysisType.THREAT_INTEL:
        return "cybershield-threat"
    elif request.analysis_type == AnalysisType.PII_DETECTION:
        return "cybershield-pii"
    else:
        return "cybershield-workflows"