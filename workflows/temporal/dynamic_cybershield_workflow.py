# Dynamic CyberShield Temporal Workflow with LLM-based tool selection
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

# Import all activities
from .activities.ioc_extraction import extract_iocs_activity
from .activities.llm_tool_selection import (
    llm_select_tools_activity,
    evaluate_continue_analysis_activity,
    ToolSelectionResult
)
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

logger = get_security_logger("dynamic_cybershield_workflow")


# Activity registry for dynamic execution
THREAT_INTEL_ACTIVITIES = {
    "virustotal": virustotal_analysis_activity,
    "abuseipdb": abuseipdb_analysis_activity,
    "shodan": shodan_analysis_activity,
    "milvus_search": milvus_search_activity
}

ANALYSIS_ACTIVITIES = {
    "vision": vision_analysis_activity,
    "pii": pii_analysis_activity
}


@workflow.defn(sandboxed=False)
class DynamicCyberShieldWorkflow:
    """
    Enhanced CyberShield workflow with dynamic, LLM-based tool selection.

    This workflow combines Temporal's reliability with intelligent tool selection:
    - LLM decides which tools to use based on context
    - Tools can be executed in parallel, sequential, or staged patterns
    - Adaptive execution can stop early if critical threats found
    - Maintains all Temporal benefits (durability, observability, retries)
    """

    def __init__(self):
        self.config = WorkflowConfig()
        self.execution_history = []

    @workflow.run
    async def run(self, request: AnalysisRequest) -> AnalysisResult:
        """
        Dynamic workflow execution with LLM-driven tool selection.
        """
        workflow_start_time = workflow.now()
        workflow_id = workflow.info().workflow_id

        logger.info(
            "Starting Dynamic CyberShield workflow",
            workflow_id=workflow_id,
            analysis_type=str(request.analysis_type),
            has_image=request.image_data is not None,
            text_length=len(request.text)
        )

        try:
            # Phase 1: IOC Extraction (always needed for context)
            ioc_analysis = await self._extract_iocs(request)

            # Phase 2: LLM-based Tool Selection
            tool_selection = await self._select_tools_dynamically(request, ioc_analysis)

            logger.info(
                "LLM tool selection complete",
                selected_tools=tool_selection.selected_tools,
                strategy=tool_selection.execution_strategy,
                confidence=tool_selection.confidence,
                reasoning=tool_selection.reasoning
            )

            # Phase 3: Execute Selected Tools Based on Strategy
            if tool_selection.execution_strategy == "parallel":
                threat_analysis = await self._execute_tools_parallel(
                    request, ioc_analysis, tool_selection
                )
            elif tool_selection.execution_strategy == "sequential":
                threat_analysis = await self._execute_tools_sequential(
                    request, ioc_analysis, tool_selection
                )
            else:  # staged
                threat_analysis = await self._execute_tools_staged(
                    request, ioc_analysis, tool_selection
                )

            # Phase 4: Execute Additional Analysis if Selected
            vision_analysis = None
            pii_analysis = None

            if "vision" in tool_selection.selected_tools and request.image_data:
                vision_analysis = await self._vision_analysis(request)

            if "pii" in tool_selection.selected_tools:
                pii_analysis = await self._pii_analysis(request)

            # Phase 5: Final Synthesis
            final_result = await self._synthesize_results(
                request,
                ioc_analysis,
                threat_analysis,
                vision_analysis,
                pii_analysis,
                workflow_start_time,
                tool_selection
            )

            # Log execution metrics
            execution_time = (workflow.now() - workflow_start_time).total_seconds()

            logger.info(
                "Dynamic workflow completed successfully",
                workflow_id=workflow_id,
                execution_time=execution_time,
                tools_executed=tool_selection.selected_tools,
                final_risk_level=str(final_result.final_risk_level)
            )

            return final_result

        except Exception as e:
            execution_time = (workflow.now() - workflow_start_time).total_seconds()

            logger.error(
                "Dynamic workflow failed",
                workflow_id=workflow_id,
                execution_time=execution_time,
                error=str(e)
            )

            return self._create_error_result(request, str(e), execution_time)

    async def _extract_iocs(self, request: AnalysisRequest) -> IOCAnalysis:
        """Extract IOCs - needed for informed tool selection"""
        return await workflow.execute_activity(
            extract_iocs_activity,
            request,
            start_to_close_timeout=timedelta(seconds=self.config.activity_timeout),
            retry_policy=self._get_default_retry_policy(),
            heartbeat_timeout=timedelta(seconds=self.config.heartbeat_timeout)
        )

    async def _select_tools_dynamically(
        self,
        request: AnalysisRequest,
        ioc_analysis: IOCAnalysis
    ) -> ToolSelectionResult:
        """Use LLM to dynamically select appropriate tools"""
        return await workflow.execute_activity(
            llm_select_tools_activity,
            {"request": request, "ioc_analysis": ioc_analysis},
            start_to_close_timeout=timedelta(seconds=60),  # More time for LLM
            retry_policy=self._get_default_retry_policy(),
            heartbeat_timeout=timedelta(seconds=20)
        )

    async def _execute_tools_parallel(
        self,
        request: AnalysisRequest,
        ioc_analysis: IOCAnalysis,
        tool_selection: ToolSelectionResult
    ) -> ThreatAnalysis:
        """Execute selected tools in parallel (fastest)"""

        activities = []

        # Build activity list based on selected tools
        for tool_name in tool_selection.selected_tools:
            if tool_name in THREAT_INTEL_ACTIVITIES:
                activity_func = THREAT_INTEL_ACTIVITIES[tool_name]

                # Determine input based on tool
                if tool_name == "milvus_search":
                    activity_input = request.text
                else:
                    activity_input = ioc_analysis.extracted_iocs

                activities.append(
                    workflow.execute_activity(
                        activity_func,
                        activity_input,
                        start_to_close_timeout=timedelta(seconds=self.config.activity_timeout),
                        retry_policy=self._get_api_retry_policy(),
                        heartbeat_timeout=timedelta(seconds=self.config.heartbeat_timeout)
                    )
                )

        if not activities:
            return self._create_empty_threat_analysis()

        logger.info(f"Executing {len(activities)} tools in parallel")

        # Execute all activities in parallel
        results = await asyncio.gather(*activities, return_exceptions=True)

        # Process results
        successful_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.warning(f"Tool {i} failed: {result}")
                error_result = ThreatIntelResult(
                    tool_name=f"tool_{i}",
                    status="error",
                    results=[],
                    execution_time=0.0,
                    error_message=str(result)
                )
                successful_results.append(error_result)
            else:
                successful_results.append(result)

        return await self._aggregate_threat_results(successful_results)

    async def _execute_tools_sequential(
        self,
        request: AnalysisRequest,
        ioc_analysis: IOCAnalysis,
        tool_selection: ToolSelectionResult
    ) -> ThreatAnalysis:
        """Execute tools sequentially with early stopping capability"""

        results = []

        for tool_name in tool_selection.priority_order:
            if tool_name not in THREAT_INTEL_ACTIVITIES:
                continue

            activity_func = THREAT_INTEL_ACTIVITIES[tool_name]

            # Determine input
            if tool_name == "milvus_search":
                activity_input = request.text
            else:
                activity_input = ioc_analysis.extracted_iocs

            # Execute tool
            try:
                result = await workflow.execute_activity(
                    activity_func,
                    activity_input,
                    start_to_close_timeout=timedelta(seconds=self.config.activity_timeout),
                    retry_policy=self._get_api_retry_policy(),
                    heartbeat_timeout=timedelta(seconds=self.config.heartbeat_timeout)
                )
                results.append(result)

                # Check if we should continue
                should_continue = await workflow.execute_activity(
                    evaluate_continue_analysis_activity,
                    {"current_results": {tool_name: result}, "original_request": request},
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=self._get_default_retry_policy()
                )

                if not should_continue:
                    logger.info(f"Stopping analysis early after {tool_name}")
                    break

            except Exception as e:
                logger.warning(f"Tool {tool_name} failed: {e}")
                results.append(ThreatIntelResult(
                    tool_name=tool_name,
                    status="error",
                    results=[],
                    execution_time=0.0,
                    error_message=str(e)
                ))

        return await self._aggregate_threat_results(results)

    async def _execute_tools_staged(
        self,
        request: AnalysisRequest,
        ioc_analysis: IOCAnalysis,
        tool_selection: ToolSelectionResult
    ) -> ThreatAnalysis:
        """Execute tools in stages - hybrid approach"""

        # Stage 1: High priority tools in parallel
        high_priority = tool_selection.priority_order[:2] if len(tool_selection.priority_order) >= 2 else tool_selection.priority_order

        stage1_results = await self._execute_tools_parallel(
            request,
            ioc_analysis,
            ToolSelectionResult(
                selected_tools=high_priority,
                reasoning="Stage 1: High priority tools",
                priority_order=high_priority,
                confidence=tool_selection.confidence,
                execution_strategy="parallel"
            )
        )

        # Evaluate if we need to continue
        should_continue = await workflow.execute_activity(
            evaluate_continue_analysis_activity,
            {"current_results": {"stage1": stage1_results}, "original_request": request},
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=self._get_default_retry_policy()
        )

        if not should_continue:
            return stage1_results

        # Stage 2: Remaining tools if needed
        remaining_tools = [t for t in tool_selection.selected_tools if t not in high_priority]
        if remaining_tools:
            stage2_results = await self._execute_tools_parallel(
                request,
                ioc_analysis,
                ToolSelectionResult(
                    selected_tools=remaining_tools,
                    reasoning="Stage 2: Additional analysis",
                    priority_order=remaining_tools,
                    confidence=tool_selection.confidence,
                    execution_strategy="parallel"
                )
            )

            # Merge results from both stages
            all_results = stage1_results.tool_results + stage2_results.tool_results
            return await self._aggregate_threat_results(all_results)

        return stage1_results

    async def _vision_analysis(self, request: AnalysisRequest) -> Optional[VisionAnalysis]:
        """Perform vision analysis if selected"""
        if not request.image_data:
            return None

        return await workflow.execute_activity(
            vision_analysis_activity,
            request.image_data,
            start_to_close_timeout=timedelta(seconds=self.config.activity_timeout * 2),
            retry_policy=self._get_default_retry_policy(),
            heartbeat_timeout=timedelta(seconds=self.config.heartbeat_timeout)
        )

    async def _pii_analysis(self, request: AnalysisRequest) -> Optional[PIIAnalysis]:
        """Perform PII analysis if selected"""
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
        workflow_start_time,
        tool_selection: ToolSelectionResult
    ) -> AnalysisResult:
        """Enhanced synthesis with tool selection metadata"""

        synthesis_input = {
            "request": request,
            "ioc_analysis": ioc_analysis,
            "threat_analysis": threat_analysis,
            "vision_analysis": vision_analysis,
            "pii_analysis": pii_analysis,
            "tool_selection": {
                "selected_tools": tool_selection.selected_tools,
                "reasoning": tool_selection.reasoning,
                "strategy": tool_selection.execution_strategy,
                "confidence": tool_selection.confidence
            }
        }

        return await workflow.execute_activity(
            synthesize_results_activity,
            synthesis_input,
            start_to_close_timeout=timedelta(seconds=self.config.activity_timeout),
            retry_policy=self._get_default_retry_policy(),
            heartbeat_timeout=timedelta(seconds=self.config.heartbeat_timeout)
        )

    async def _aggregate_threat_results(self, results: List[ThreatIntelResult]) -> ThreatAnalysis:
        """Aggregate threat intelligence results"""
        high_risk_indicators = []
        risk_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        recommendations = []

        for result in results:
            if result.status == "success":
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

        # Generate recommendations
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
        """Create empty threat analysis"""
        return ThreatAnalysis(
            tool_results=[],
            threat_summary={"message": "No threat analysis performed"},
            risk_assessment={"low": 0, "medium": 0, "high": 0, "critical": 0},
            high_risk_indicators=[],
            recommendations=["No tools selected for analysis"]
        )

    def _create_error_result(self, request: AnalysisRequest, error_msg: str, execution_time: float) -> AnalysisResult:
        """Create error result"""
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
        """Default retry policy"""
        return RetryPolicy(
            initial_interval=timedelta(seconds=self.config.retry_initial_interval),
            backoff_coefficient=self.config.retry_backoff_coefficient,
            maximum_interval=timedelta(seconds=self.config.retry_maximum_interval),
            maximum_attempts=self.config.max_activity_retries,
        )

    def _get_api_retry_policy(self) -> RetryPolicy:
        """API retry policy with more aggressive retries"""
        return RetryPolicy(
            initial_interval=timedelta(seconds=2),
            backoff_coefficient=2.0,
            maximum_interval=timedelta(seconds=120),
            maximum_attempts=7,
        )