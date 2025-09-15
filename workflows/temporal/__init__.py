# Temporal workflow package for CyberShield
from .models import (
    AnalysisRequest,
    AnalysisResult,
    IOCAnalysis,
    ThreatAnalysis,
    WorkflowConfig
)

# Conditional import of workflow class (requires temporalio)
try:
    from .cybershield_workflow import CyberShieldWorkflow
    _workflow_available = True
except ImportError:
    CyberShieldWorkflow = None
    _workflow_available = False

__all__ = [
    "AnalysisRequest",
    "AnalysisResult",
    "IOCAnalysis",
    "ThreatAnalysis",
    "WorkflowConfig"
]

if _workflow_available:
    __all__.append("CyberShieldWorkflow")