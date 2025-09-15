# Temporal service integration for FastAPI endpoints
import uuid
import time
from typing import Dict, Any, Optional
from datetime import timedelta

from temporalio.client import Client, WorkflowFailureError, WorkflowHandle
from temporalio.common import RetryPolicy

from workflows.temporal.models import (
    AnalysisRequest,
    AnalysisResult,
    AnalysisType,
    convert_langchain_state_to_request,
    convert_temporal_result_to_langchain
)
from workflows.temporal.cybershield_workflow import (
    CyberShieldWorkflow,
    create_cybershield_workflow_id,
    get_task_queue_for_request
)
from utils.temporal_config import get_temporal_client, get_config
from utils.logging_config import get_security_logger

logger = get_security_logger("temporal_service")


class TemporalWorkflowService:
    """Service class for executing CyberShield workflows via Temporal"""

    def __init__(self):
        self._client: Optional[Client] = None
        self.config = get_config()

    async def get_client(self) -> Client:
        """Get or create Temporal client"""
        if self._client is None:
            self._client = await get_temporal_client()
        return self._client

    async def execute_analysis(
        self,
        text: str,
        image_data: Optional[bytes] = None,
        analysis_type: str = "comprehensive",
        request_id: Optional[str] = None,
        user_id: Optional[str] = None,
        timeout_seconds: int = 1800  # 30 minutes
    ) -> Dict[str, Any]:
        """
        Execute CyberShield analysis workflow via Temporal.

        This replaces the LangGraph workflow execution with Temporal-based orchestration.
        """
        start_time = time.time()

        # Generate request ID if not provided
        if not request_id:
            request_id = f"cybershield-{uuid.uuid4().hex[:8]}"

        logger.info(
            "Starting Temporal workflow execution",
            request_id=request_id,
            analysis_type=analysis_type,
            has_image=image_data is not None,
            text_length=len(text)
        )

        try:
            # Create analysis request
            request = AnalysisRequest(
                text=text,
                image_data=image_data,
                analysis_type=AnalysisType(analysis_type),
                request_id=request_id,
                user_id=user_id,
                context={"start_time": start_time}
            )

            # Get Temporal client
            client = await self.get_client()

            # Create workflow ID and determine task queue
            workflow_id = create_cybershield_workflow_id(request_id)
            task_queue = get_task_queue_for_request(request)

            logger.info(
                "Executing Temporal workflow",
                workflow_id=workflow_id,
                task_queue=task_queue
            )

            # Start workflow
            handle = await client.start_workflow(
                CyberShieldWorkflow.run,
                request,
                id=workflow_id,
                task_queue=task_queue,
                execution_timeout=timedelta(seconds=timeout_seconds),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=1),
                    backoff_coefficient=2.0,
                    maximum_attempts=3,
                    maximum_interval=timedelta(seconds=60)
                )
            )

            # Wait for workflow completion
            result: AnalysisResult = await handle.result()

            execution_time = time.time() - start_time

            logger.info(
                "Temporal workflow completed successfully",
                workflow_id=workflow_id,
                execution_time=execution_time,
                final_risk_level=result.final_risk_level.value,
                status=result.status
            )

            # Convert result to FastAPI-compatible format
            return self._convert_result_to_api_response(result, execution_time)

        except WorkflowFailureError as e:
            execution_time = time.time() - start_time
            logger.error(
                f"Temporal workflow failed: {e}",
                request_id=request_id,
                execution_time=execution_time
            )

            return {
                "status": "error",
                "error": f"Workflow execution failed: {str(e)}",
                "request_id": request_id,
                "execution_time": execution_time,
                "processing_method": "temporal_workflow"
            }

        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(
                f"Temporal service error: {e}",
                request_id=request_id,
                execution_time=execution_time
            )

            return {
                "status": "error",
                "error": str(e),
                "request_id": request_id,
                "execution_time": execution_time,
                "processing_method": "temporal_workflow"
            }

    async def get_workflow_status(self, workflow_id: str) -> Dict[str, Any]:
        """Get status of a running workflow"""
        try:
            client = await self.get_client()
            handle = client.get_workflow_handle(workflow_id)

            # Get workflow info
            info = await handle.describe()

            return {
                "workflow_id": workflow_id,
                "status": info.status.name,
                "start_time": info.start_time.isoformat() if info.start_time else None,
                "execution_time": info.execution_time.isoformat() if info.execution_time else None,
                "task_queue": info.task_queue,
                "workflow_type": info.workflow_type
            }

        except Exception as e:
            logger.error(f"Failed to get workflow status: {e}")
            return {
                "workflow_id": workflow_id,
                "status": "unknown",
                "error": str(e)
            }

    async def cancel_workflow(self, workflow_id: str) -> Dict[str, Any]:
        """Cancel a running workflow"""
        try:
            client = await self.get_client()
            handle = client.get_workflow_handle(workflow_id)

            await handle.cancel()

            logger.info(f"Workflow {workflow_id} cancelled successfully")

            return {
                "workflow_id": workflow_id,
                "status": "cancelled",
                "message": "Workflow cancelled successfully"
            }

        except Exception as e:
            logger.error(f"Failed to cancel workflow: {e}")
            return {
                "workflow_id": workflow_id,
                "status": "error",
                "error": str(e)
            }

    async def execute_legacy_analysis(
        self,
        langchain_state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute analysis using legacy LangChain state format.

        This provides backward compatibility for existing endpoints.
        """
        logger.info("Executing legacy analysis via Temporal")

        try:
            # Convert LangChain state to Temporal request
            request = convert_langchain_state_to_request(langchain_state)

            # Execute via Temporal
            result = await self.execute_analysis(
                text=request.text,
                image_data=request.image_data,
                analysis_type=request.analysis_type.value,
                request_id=request.request_id
            )

            # Convert back to LangChain format if successful
            if result.get("status") == "success":
                # Create AnalysisResult from the response
                analysis_result = self._convert_api_response_to_result(result)
                return convert_temporal_result_to_langchain(analysis_result)
            else:
                return result

        except Exception as e:
            logger.error(f"Legacy analysis execution failed: {e}")
            return {
                "status": "error",
                "error": str(e),
                "processing_method": "temporal_workflow_legacy"
            }

    def _convert_result_to_api_response(
        self,
        result: AnalysisResult,
        execution_time: float
    ) -> Dict[str, Any]:
        """Convert AnalysisResult to API response format"""
        response = {
            "status": result.status,
            "final_risk_level": result.final_risk_level.value,
            "overall_confidence": result.overall_confidence,
            "execution_time": execution_time,
            "processing_method": "temporal_workflow",

            # Core analysis results
            "ioc_analysis": {
                "total_ioc_count": result.ioc_analysis.total_ioc_count,
                "extracted_iocs": {
                    "ips": result.ioc_analysis.extracted_iocs.ips,
                    "domains": result.ioc_analysis.extracted_iocs.domains,
                    "hashes": result.ioc_analysis.extracted_iocs.hashes,
                    "urls": result.ioc_analysis.extracted_iocs.urls,
                    "emails": result.ioc_analysis.extracted_iocs.emails,
                    "file_paths": result.ioc_analysis.extracted_iocs.file_paths
                },
                "patterns_detected": result.ioc_analysis.patterns_detected,
                "confidence_scores": result.ioc_analysis.confidence_scores
            },

            "threat_analysis": {
                "tool_results": [
                    {
                        "tool_name": tr.tool_name,
                        "status": tr.status,
                        "execution_time": tr.execution_time,
                        "results_count": len(tr.results),
                        "error_message": tr.error_message
                    }
                    for tr in result.threat_analysis.tool_results
                ],
                "threat_summary": result.threat_analysis.threat_summary,
                "risk_assessment": result.threat_analysis.risk_assessment,
                "high_risk_indicators": result.threat_analysis.high_risk_indicators,
                "recommendations": result.threat_analysis.recommendations
            },

            "processing_summary": {
                "workflow_id": result.processing_summary.workflow_id if result.processing_summary else "unknown",
                "tools_executed": result.processing_summary.tools_executed if result.processing_summary else [],
                "processing_stages": result.processing_summary.processing_stages if result.processing_summary else [],
                "performance_metrics": result.processing_summary.performance_metrics if result.processing_summary else {}
            }
        }

        # Add optional analysis results
        if result.vision_analysis:
            response["vision_analysis"] = {
                "ocr_text": result.vision_analysis.ocr_text,
                "detected_objects": result.vision_analysis.detected_objects,
                "security_assessment": result.vision_analysis.security_assessment,
                "pii_in_images": result.vision_analysis.pii_in_images,
                "confidence_scores": result.vision_analysis.confidence_scores
            }

        if result.pii_analysis:
            response["pii_analysis"] = {
                "pii_detected": result.pii_analysis.pii_detected,
                "pii_types": result.pii_analysis.pii_types,
                "pii_locations_count": len(result.pii_analysis.pii_locations),
                "confidence_scores": result.pii_analysis.confidence_scores
                # Note: Not including masked_text or pii_locations for security
            }

        # Add warnings and error details
        if result.warnings:
            response["warnings"] = result.warnings

        if result.error_details:
            response["error_details"] = result.error_details

        return response

    def _convert_api_response_to_result(self, api_response: Dict[str, Any]) -> AnalysisResult:
        """Convert API response back to AnalysisResult (for legacy compatibility)"""
        # This is a simplified conversion for legacy support
        # In practice, you might want to store the full AnalysisResult and retrieve it
        from workflows.temporal.models import (
            IOCAnalysis, ThreatAnalysis, IOCs, ProcessingSummary, RiskLevel
        )

        # Create basic structures from API response
        ioc_data = api_response.get("ioc_analysis", {})
        extracted_iocs_data = ioc_data.get("extracted_iocs", {})

        ioc_analysis = IOCAnalysis(
            extracted_iocs=IOCs(
                ips=extracted_iocs_data.get("ips", []),
                domains=extracted_iocs_data.get("domains", []),
                hashes=extracted_iocs_data.get("hashes", []),
                urls=extracted_iocs_data.get("urls", []),
                emails=extracted_iocs_data.get("emails", []),
                file_paths=extracted_iocs_data.get("file_paths", [])
            ),
            total_ioc_count=ioc_data.get("total_ioc_count", 0),
            patterns_detected=ioc_data.get("patterns_detected", []),
            confidence_scores=ioc_data.get("confidence_scores", {}),
            validation_results={}
        )

        threat_data = api_response.get("threat_analysis", {})
        threat_analysis = ThreatAnalysis(
            tool_results=[],  # Simplified for legacy compatibility
            threat_summary=threat_data.get("threat_summary", {}),
            risk_assessment=threat_data.get("risk_assessment", {}),
            high_risk_indicators=threat_data.get("high_risk_indicators", []),
            recommendations=threat_data.get("recommendations", [])
        )

        processing_data = api_response.get("processing_summary", {})
        processing_summary = ProcessingSummary(
            workflow_id=processing_data.get("workflow_id", "unknown"),
            execution_time=api_response.get("execution_time", 0.0),
            tools_executed=processing_data.get("tools_executed", []),
            cache_hits=0,
            api_calls_made=0,
            processing_stages=processing_data.get("processing_stages", []),
            performance_metrics=processing_data.get("performance_metrics", {})
        )

        return AnalysisResult(
            ioc_analysis=ioc_analysis,
            threat_analysis=threat_analysis,
            processing_summary=processing_summary,
            final_risk_level=RiskLevel(api_response.get("final_risk_level", "low")),
            overall_confidence=api_response.get("overall_confidence", 0.0),
            status=api_response.get("status", "success")
        )


# Global service instance
_temporal_service: Optional[TemporalWorkflowService] = None


async def get_temporal_service() -> TemporalWorkflowService:
    """Get global Temporal workflow service instance"""
    global _temporal_service

    if _temporal_service is None:
        _temporal_service = TemporalWorkflowService()

    return _temporal_service