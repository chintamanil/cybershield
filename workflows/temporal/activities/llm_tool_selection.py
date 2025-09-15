# LLM-based tool selection activity for dynamic Temporal workflows
import os
import time
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from temporalio import activity

from ..models import AnalysisRequest, AnalysisType, IOCAnalysis
from utils.logging_config import get_security_logger

logger = get_security_logger("llm_tool_selection")

# Activity registry mapping tool names to activity functions
ACTIVITY_REGISTRY = {
    "virustotal": "virustotal_analysis_activity",
    "abuseipdb": "abuseipdb_analysis_activity",
    "shodan": "shodan_analysis_activity",
    "milvus_search": "milvus_search_activity",
    "vision": "vision_analysis_activity",
    "pii": "pii_analysis_activity"
}

@dataclass
class ToolSelectionResult:
    """Result of LLM tool selection"""
    selected_tools: List[str]
    reasoning: str
    priority_order: List[str]
    confidence: float
    execution_strategy: str  # "parallel", "sequential", "staged"


@activity.defn
async def llm_select_tools_activity(
    request: AnalysisRequest,
    ioc_analysis: Optional[IOCAnalysis] = None
) -> ToolSelectionResult:
    """
    Use LLM to intelligently select which security tools to execute
    based on the analysis request and extracted IOCs.
    """
    activity_start_time = time.time()

    try:
        activity.heartbeat("Starting LLM tool selection")

        # Check if OpenAI is available
        openai_available = bool(os.getenv("OPENAI_API_KEY"))

        if openai_available:
            logger.info("Using OpenAI for intelligent tool selection")
            return await _llm_based_selection(request, ioc_analysis)
        else:
            logger.info("OpenAI not available, using rule-based selection")
            return await _rule_based_selection(request, ioc_analysis)

    except Exception as e:
        logger.error(f"Tool selection failed: {e}")
        # Fallback to basic selection
        return ToolSelectionResult(
            selected_tools=["virustotal"],
            reasoning="Error in tool selection, falling back to basic analysis",
            priority_order=["virustotal"],
            confidence=0.3,
            execution_strategy="parallel"
        )


async def _llm_based_selection(
    request: AnalysisRequest,
    ioc_analysis: Optional[IOCAnalysis]
) -> ToolSelectionResult:
    """Use OpenAI to select appropriate tools"""
    try:
        from langchain_openai import ChatOpenAI
        from langchain_core.messages import SystemMessage, HumanMessage

        llm = ChatOpenAI(
            model="gpt-4o-mini",
            temperature=0.1,
            max_tokens=500
        )

        # Build context for LLM
        context = _build_selection_context(request, ioc_analysis)

        system_prompt = """You are a cybersecurity tool selection expert. Based on the analysis request and extracted IOCs,
        select the most appropriate security tools to execute.

        Available tools:
        - virustotal: IP, domain, and hash reputation analysis
        - abuseipdb: IP abuse and reputation checking
        - shodan: Network reconnaissance and port scanning
        - milvus_search: Vector similarity search in threat database
        - vision: Image analysis and OCR extraction
        - pii: PII detection and masking

        Return a JSON object with:
        {
            "selected_tools": ["tool1", "tool2", ...],
            "reasoning": "Brief explanation of why these tools were selected",
            "priority_order": ["highest_priority_tool", "second_priority", ...],
            "confidence": 0.0-1.0,
            "execution_strategy": "parallel" or "sequential" or "staged"
        }

        Consider:
        1. Type and quantity of IOCs extracted
        2. Analysis type requested
        3. Presence of specific threat indicators
        4. Resource efficiency (don't over-analyze)
        5. Tool capabilities and limitations
        """

        human_prompt = f"""Analyze this request and select appropriate tools:

        Request Type: {request.analysis_type}
        Text: {request.text[:500]}...
        Has Image: {request.image_data is not None}

        Extracted IOCs:
        - IPs: {len(ioc_analysis.extracted_iocs.ips) if ioc_analysis else 0}
        - Domains: {len(ioc_analysis.extracted_iocs.domains) if ioc_analysis else 0}
        - Hashes: {len(ioc_analysis.extracted_iocs.hashes) if ioc_analysis else 0}
        - URLs: {len(ioc_analysis.extracted_iocs.urls) if ioc_analysis else 0}

        Context: {context}
        """

        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=human_prompt)
        ]

        response = await llm.ainvoke(messages)

        # Parse LLM response
        try:
            result_data = json.loads(response.content)

            # Validate selected tools
            valid_tools = [
                tool for tool in result_data.get("selected_tools", [])
                if tool in ACTIVITY_REGISTRY
            ]

            return ToolSelectionResult(
                selected_tools=valid_tools,
                reasoning=result_data.get("reasoning", "LLM-based selection"),
                priority_order=result_data.get("priority_order", valid_tools),
                confidence=float(result_data.get("confidence", 0.8)),
                execution_strategy=result_data.get("execution_strategy", "parallel")
            )

        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Failed to parse LLM response: {e}")
            # Fall back to rule-based selection
            return await _rule_based_selection(request, ioc_analysis)

    except Exception as e:
        logger.error(f"LLM selection failed: {e}")
        return await _rule_based_selection(request, ioc_analysis)


async def _rule_based_selection(
    request: AnalysisRequest,
    ioc_analysis: Optional[IOCAnalysis]
) -> ToolSelectionResult:
    """Fallback rule-based tool selection (current implementation)"""

    selected_tools = []
    reasoning_parts = []

    # Determine tools based on analysis type
    if request.analysis_type == AnalysisType.COMPREHENSIVE:
        selected_tools = ["virustotal", "abuseipdb", "shodan", "milvus_search"]
        reasoning_parts.append("Comprehensive analysis requested - using all threat intelligence tools")

    elif request.analysis_type == AnalysisType.THREAT_INTEL:
        # Select based on available IOCs
        if ioc_analysis and ioc_analysis.extracted_iocs.ips:
            selected_tools.extend(["virustotal", "abuseipdb", "shodan"])
            reasoning_parts.append(f"Found {len(ioc_analysis.extracted_iocs.ips)} IPs - using IP analysis tools")

        if ioc_analysis and ioc_analysis.extracted_iocs.domains:
            if "virustotal" not in selected_tools:
                selected_tools.append("virustotal")
            reasoning_parts.append(f"Found {len(ioc_analysis.extracted_iocs.domains)} domains - using domain analysis")

        if ioc_analysis and ioc_analysis.extracted_iocs.hashes:
            if "virustotal" not in selected_tools:
                selected_tools.append("virustotal")
            reasoning_parts.append(f"Found {len(ioc_analysis.extracted_iocs.hashes)} hashes - using hash analysis")

    elif request.analysis_type == AnalysisType.BASIC:
        selected_tools = ["virustotal"]
        reasoning_parts.append("Basic analysis - using essential tool only")

    # Add specialized tools based on content
    if request.image_data:
        selected_tools.append("vision")
        reasoning_parts.append("Image data present - adding vision analysis")

    # Check for threat keywords
    threat_keywords = ["malware", "virus", "attack", "suspicious", "threat"]
    if any(keyword in request.text.lower() for keyword in threat_keywords):
        if "milvus_search" not in selected_tools:
            selected_tools.append("milvus_search")
        reasoning_parts.append("Threat keywords detected - adding vector search")

    # Always check for PII
    selected_tools.append("pii")
    reasoning_parts.append("Adding PII detection for compliance")

    return ToolSelectionResult(
        selected_tools=selected_tools,
        reasoning=" | ".join(reasoning_parts) if reasoning_parts else "Rule-based selection",
        priority_order=selected_tools,  # Use order as priority
        confidence=0.7,
        execution_strategy="parallel"  # Default to parallel for speed
    )


def _build_selection_context(
    request: AnalysisRequest,
    ioc_analysis: Optional[IOCAnalysis]
) -> str:
    """Build context string for LLM decision making"""

    context_parts = []

    # Add threat indicators from text
    threat_indicators = []
    keywords = ["malware", "phishing", "ransomware", "botnet", "c2", "exploit"]
    for keyword in keywords:
        if keyword in request.text.lower():
            threat_indicators.append(keyword)

    if threat_indicators:
        context_parts.append(f"Threat indicators: {', '.join(threat_indicators)}")

    # Add IOC context
    if ioc_analysis:
        if ioc_analysis.patterns_detected:
            context_parts.append(f"Patterns: {', '.join(ioc_analysis.patterns_detected)}")

        # Check for high-risk IOCs
        if ioc_analysis.extracted_iocs.ips:
            # Check for private IPs vs public
            private_ips = [ip for ip in ioc_analysis.extracted_iocs.ips if ip.startswith(("10.", "192.168.", "172."))]
            public_ips = [ip for ip in ioc_analysis.extracted_iocs.ips if ip not in private_ips]

            if public_ips:
                context_parts.append(f"{len(public_ips)} public IPs detected")
            if private_ips:
                context_parts.append(f"{len(private_ips)} private IPs detected")

    return " | ".join(context_parts) if context_parts else "General security analysis"


@activity.defn
async def evaluate_continue_analysis_activity(
    context: Dict[str, Any]
) -> bool:
    """
    Evaluate whether to continue analysis based on current results.
    This enables adaptive workflows that can stop early if threats are found.
    """

    current_results = context.get("current_results", {})
    original_request = context.get("original_request")

    # Check if critical threats were found
    for tool, result in current_results.items():
        if isinstance(result, dict):
            # Check for high-risk indicators
            if result.get("risk_level") == "critical":
                logger.info(f"Critical threat found by {tool}, stopping analysis")
                return False

            # Check for high confidence malicious results
            if result.get("malicious_count", 0) > 5:
                logger.info(f"High malicious count from {tool}, stopping analysis")
                return False

    # Continue if no critical issues found
    return True