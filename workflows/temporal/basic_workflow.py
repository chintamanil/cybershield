# Absolutely minimal Temporal workflow for validation testing
from datetime import timedelta
from typing import Dict, Any
from temporalio import workflow
from temporalio.common import RetryPolicy


@workflow.defn
class BasicWorkflow:
    """
    Basic workflow for testing Temporal validation - no external dependencies.
    """

    @workflow.run
    async def run(self, text_input: str) -> Dict[str, Any]:
        """
        Minimal workflow execution - just return basic analysis.
        """
        workflow_start_time = workflow.now()

        try:
            # Simple analysis without external dependencies
            simple_result = await workflow.execute_activity(
                simple_analysis_activity,
                text_input,
                start_to_close_timeout=timedelta(seconds=10),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=1),
                    maximum_attempts=2
                )
            )

            execution_time = (workflow.now() - workflow_start_time).total_seconds()

            return {
                "status": "success",
                "input_text": text_input,
                "analysis": simple_result,
                "execution_time": execution_time,
                "workflow_id": workflow.info().workflow_id
            }

        except Exception as e:
            execution_time = (workflow.now() - workflow_start_time).total_seconds()

            return {
                "status": "error",
                "error_message": str(e),
                "execution_time": execution_time,
                "workflow_id": workflow.info().workflow_id
            }


# Simple activity without external dependencies
from temporalio import activity

@activity.defn
async def simple_analysis_activity(text: str) -> Dict[str, Any]:
    """
    Basic text analysis activity with no external dependencies.
    """
    import re

    # Basic pattern matching without complex regex tools
    word_count = len(text.split())
    char_count = len(text)

    # Simple IP pattern detection
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    found_ips = re.findall(ip_pattern, text)

    # Simple domain pattern detection
    domain_pattern = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    found_domains = re.findall(domain_pattern, text)

    return {
        "word_count": word_count,
        "char_count": char_count,
        "found_ips": found_ips,
        "found_domains": found_domains,
        "contains_security_keywords": any(keyword in text.lower() for keyword in ["error", "failed", "attack", "malware"])
    }