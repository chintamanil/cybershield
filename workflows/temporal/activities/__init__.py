# Activities package for CyberShield Temporal workflows

# Conditional imports to handle missing temporalio dependency
try:
    from .ioc_extraction import extract_iocs_activity
    from .routing import route_analysis_activity
    from .synthesis import synthesize_results_activity
    from .threat_intelligence import (
        virustotal_analysis_activity,
        abuseipdb_analysis_activity,
        shodan_analysis_activity,
        milvus_search_activity
    )
    from .vision_processing import vision_analysis_activity
    from .pii_processing import pii_analysis_activity

    _activities_available = True

    __all__ = [
        "extract_iocs_activity",
        "route_analysis_activity",
        "synthesize_results_activity",
        "virustotal_analysis_activity",
        "abuseipdb_analysis_activity",
        "shodan_analysis_activity",
        "milvus_search_activity",
        "vision_analysis_activity",
        "pii_analysis_activity"
    ]

except ImportError:
    # temporalio not installed - activities not available
    _activities_available = False
    __all__ = []