# Data models for Temporal workflow execution
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Union
from enum import Enum


class AnalysisType(str, Enum):
    """Types of analysis that can be performed"""
    BASIC = "basic"
    COMPREHENSIVE = "comprehensive"
    THREAT_INTEL = "threat_intel"
    VISION_ANALYSIS = "vision_analysis"
    PII_DETECTION = "pii_detection"


class RiskLevel(str, Enum):
    """Risk assessment levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class IOCs:
    """Indicators of Compromise extracted from input"""
    ips: List[str]
    domains: List[str]
    hashes: List[str]
    urls: List[str]
    emails: List[str]
    file_paths: List[str]


@dataclass
class AnalysisRequest:
    """Input request for CyberShield analysis workflow"""
    # Core input data
    text: str
    image_data: Optional[bytes] = None

    # Analysis configuration
    analysis_type: AnalysisType = AnalysisType.COMPREHENSIVE
    priority: str = "normal"  # low, normal, high, urgent

    # Tool selection (None means auto-select)
    enabled_tools: Optional[List[str]] = None
    disabled_tools: Optional[List[str]] = None

    # Metadata
    request_id: str = ""
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    context: Dict[str, Any] = None

    def __post_init__(self):
        if self.context is None:
            self.context = {}


@dataclass
class IOCAnalysis:
    """Results of IOC extraction and analysis"""
    extracted_iocs: IOCs
    total_ioc_count: int
    patterns_detected: List[str]
    confidence_scores: Dict[str, float]
    validation_results: Dict[str, bool]


@dataclass
class ThreatIntelResult:
    """Individual threat intelligence tool result"""
    tool_name: str
    status: str  # success, error, timeout
    results: List[Dict[str, Any]]
    execution_time: float
    error_message: Optional[str] = None


@dataclass
class ThreatAnalysis:
    """Aggregated threat intelligence analysis"""
    tool_results: List[ThreatIntelResult]
    threat_summary: Dict[str, Any]
    risk_assessment: Dict[str, Union[int, float]]
    high_risk_indicators: List[Dict[str, Any]]
    recommendations: List[str]


@dataclass
class VisionAnalysis:
    """Computer vision analysis results"""
    ocr_text: str
    detected_objects: List[Dict[str, Any]]
    security_assessment: Dict[str, Any]
    pii_in_images: List[str]
    confidence_scores: Dict[str, float]


@dataclass
class PIIAnalysis:
    """PII detection and masking results"""
    pii_detected: bool
    pii_types: List[str]
    masked_text: str
    pii_locations: List[Dict[str, Any]]
    confidence_scores: Dict[str, float]


@dataclass
class ProcessingSummary:
    """Summary of workflow execution"""
    workflow_id: str
    execution_time: float
    tools_executed: List[str]
    cache_hits: int
    api_calls_made: int
    processing_stages: List[str]
    performance_metrics: Dict[str, Any]


@dataclass
class AnalysisResult:
    """Complete analysis result from CyberShield workflow"""
    # Core analysis results
    ioc_analysis: IOCAnalysis
    threat_analysis: ThreatAnalysis

    # Optional analysis results (based on input type)
    vision_analysis: Optional[VisionAnalysis] = None
    pii_analysis: Optional[PIIAnalysis] = None

    # Workflow metadata
    processing_summary: ProcessingSummary = None
    final_risk_level: RiskLevel = RiskLevel.LOW
    overall_confidence: float = 0.0

    # Status and error handling
    status: str = "success"
    error_details: Optional[Dict[str, Any]] = None
    warnings: List[str] = None

    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []


@dataclass
class WorkflowConfig:
    """Configuration for workflow execution"""
    # Timeout settings (in seconds)
    workflow_timeout: int = 3600  # 1 hour
    activity_timeout: int = 300   # 5 minutes
    heartbeat_timeout: int = 30   # 30 seconds

    # Retry configuration
    max_activity_retries: int = 5
    retry_backoff_coefficient: float = 2.0
    retry_initial_interval: int = 1  # seconds
    retry_maximum_interval: int = 60  # seconds

    # Tool execution limits
    max_parallel_tools: int = 5
    max_iocs_per_tool: int = 10

    # Caching settings
    enable_caching: bool = True
    cache_ttl: int = 3600  # 1 hour

    # Feature flags
    enable_vision_analysis: bool = True
    enable_pii_detection: bool = True
    enable_vector_search: bool = True

    # Performance tuning
    batch_size: int = 32
    concurrent_requests: int = 10


# Helper functions for model validation and conversion

def validate_analysis_request(request: AnalysisRequest) -> List[str]:
    """Validate analysis request and return list of validation errors"""
    errors = []

    if not request.text and not request.image_data:
        errors.append("Either text or image_data must be provided")

    if request.text and len(request.text.strip()) == 0:
        errors.append("Text input cannot be empty")

    if request.enabled_tools and request.disabled_tools:
        overlap = set(request.enabled_tools) & set(request.disabled_tools)
        if overlap:
            errors.append(f"Tools cannot be both enabled and disabled: {overlap}")

    if request.priority not in ["low", "normal", "high", "urgent"]:
        errors.append(f"Invalid priority: {request.priority}")

    return errors


def create_empty_iocs() -> IOCs:
    """Create empty IOCs structure"""
    return IOCs(
        ips=[],
        domains=[],
        hashes=[],
        urls=[],
        emails=[],
        file_paths=[]
    )


def merge_iocs(ioc_list: List[IOCs]) -> IOCs:
    """Merge multiple IOCs structures into one"""
    merged = create_empty_iocs()

    for iocs in ioc_list:
        merged.ips.extend(iocs.ips)
        merged.domains.extend(iocs.domains)
        merged.hashes.extend(iocs.hashes)
        merged.urls.extend(iocs.urls)
        merged.emails.extend(iocs.emails)
        merged.file_paths.extend(iocs.file_paths)

    # Deduplicate
    merged.ips = list(set(merged.ips))
    merged.domains = list(set(merged.domains))
    merged.hashes = list(set(merged.hashes))
    merged.urls = list(set(merged.urls))
    merged.emails = list(set(merged.emails))
    merged.file_paths = list(set(merged.file_paths))

    return merged


def calculate_overall_risk_level(threat_analysis: ThreatAnalysis) -> RiskLevel:
    """Calculate overall risk level from threat analysis"""
    risk_counts = threat_analysis.risk_assessment

    critical_count = risk_counts.get("critical", 0)
    high_count = risk_counts.get("high", 0)
    medium_count = risk_counts.get("medium", 0)

    if critical_count > 0 or high_count >= 3:
        return RiskLevel.CRITICAL
    elif high_count > 0 or medium_count >= 5:
        return RiskLevel.HIGH
    elif medium_count > 0:
        return RiskLevel.MEDIUM
    else:
        return RiskLevel.LOW


def convert_langchain_state_to_request(langchain_state: Dict[str, Any]) -> AnalysisRequest:
    """Convert LangChain workflow state to Temporal AnalysisRequest"""
    return AnalysisRequest(
        text=langchain_state.get("input_text", ""),
        image_data=langchain_state.get("input_image"),
        analysis_type=AnalysisType.COMPREHENSIVE,
        request_id=langchain_state.get("request_id", ""),
        session_id=langchain_state.get("session_id"),
        context=langchain_state.get("context", {})
    )


def convert_temporal_result_to_langchain(result: AnalysisResult) -> Dict[str, Any]:
    """Convert Temporal AnalysisResult to LangChain-compatible format"""
    return {
        "final_report": {
            "ioc_analysis": {
                "ioc_count": result.ioc_analysis.total_ioc_count,
                "extracted_iocs": {
                    "ips": result.ioc_analysis.extracted_iocs.ips,
                    "domains": result.ioc_analysis.extracted_iocs.domains,
                    "hashes": result.ioc_analysis.extracted_iocs.hashes,
                    "urls": result.ioc_analysis.extracted_iocs.urls,
                    "emails": result.ioc_analysis.extracted_iocs.emails,
                }
            },
            "threat_analysis": {
                "threats": result.threat_analysis.high_risk_indicators,
                "risk_assessment": result.threat_analysis.risk_assessment,
                "recommendations": result.threat_analysis.recommendations,
            },
            "vision_analysis": result.vision_analysis.__dict__ if result.vision_analysis else None,
            "pii_analysis": result.pii_analysis.__dict__ if result.pii_analysis else None,
            "processing_summary": result.processing_summary.__dict__ if result.processing_summary else None,
            "final_risk_level": result.final_risk_level.value,
            "status": result.status,
            "processing_method": "temporal_workflow"
        }
    }