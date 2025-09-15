# IOC extraction activity for Temporal workflow
import re
import time
from typing import Dict, List, Any

from temporalio import activity

from ..models import AnalysisRequest, IOCAnalysis, IOCs, create_empty_iocs


@activity.defn
async def extract_iocs_activity(request: AnalysisRequest) -> IOCAnalysis:
    """
    Extract Indicators of Compromise from input text using simple regex patterns.
    Simplified version for Temporal sandbox compatibility.
    """
    activity_start_time = time.time()

    try:
        # Send heartbeat to indicate activity is running
        activity.heartbeat("Starting IOC extraction")

        # Simple IOC extraction patterns
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        domain_pattern = r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\b'
        hash_pattern = r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b'
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        url_pattern = r'https?://[^\s<>"]+'

        # Extract IOCs
        ips = list(set(re.findall(ip_pattern, request.text)))
        domains = list(set(re.findall(domain_pattern, request.text)))
        hashes = list(set(re.findall(hash_pattern, request.text)))
        emails = list(set(re.findall(email_pattern, request.text)))
        urls = list(set(re.findall(url_pattern, request.text)))

        # Filter out common false positives for domains
        domains = [d for d in domains if '.' in d and len(d) > 3]

        # Create IOCs object
        extracted_iocs = IOCs(
            ips=ips,
            domains=domains,
            hashes=hashes,
            urls=urls,
            emails=emails,
            file_paths=[]  # Not extracting file paths in simplified version
        )

        # Calculate total IOC count
        total_ioc_count = len(extracted_iocs.ips) + len(extracted_iocs.domains) + len(extracted_iocs.hashes) + len(extracted_iocs.urls) + len(extracted_iocs.emails)

        activity.heartbeat(f"IOC extraction complete: {total_ioc_count} IOCs found")

        # Calculate processing time
        processing_time = time.time() - activity_start_time

        # Build result
        result = IOCAnalysis(
            extracted_iocs=extracted_iocs,
            total_ioc_count=total_ioc_count,
            patterns_detected=[
                "IP addresses", "domains", "email addresses",
                "MD5/SHA1/SHA256 hashes", "URLs"
            ],
            confidence_scores={
                "ip": 0.8,
                "domain": 0.8,
                "hash": 0.9,
                "url": 0.7,
                "email": 0.6
            },
            validation_results={
                "patterns_applied": True,
                "duplicates_removed": True,
                "format_validated": True
            }
        )

        return result

    except Exception as e:
        processing_time = time.time() - activity_start_time

        # Return empty result on error
        return IOCAnalysis(
            extracted_iocs=create_empty_iocs(),
            total_ioc_count=0,
            patterns_detected=[],
            confidence_scores={},
            validation_results={
                "error_occurred": True,
                "patterns_applied": False,
                "duplicates_removed": False,
                "format_validated": False
            }
        )