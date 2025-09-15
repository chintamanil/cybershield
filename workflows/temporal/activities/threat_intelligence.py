# Threat intelligence activities for Temporal workflow
import asyncio
import time
from typing import List, Dict, Any, Optional

from temporalio import activity

from ..models import IOCs, ThreatIntelResult
from tools.virustotal import VirusTotalClient
from tools.abuseipdb import AbuseIPDBClient
from tools.shodan import ShodanClient
from vectorstore.milvus_client import CyberShieldVectorStore
from utils.logging_config import get_security_logger

logger = get_security_logger("threat_intel_activities")


@activity.defn
async def virustotal_analysis_activity(iocs: IOCs) -> ThreatIntelResult:
    """Analyze IOCs using VirusTotal API"""
    activity_start_time = time.time()

    try:
        activity.heartbeat("Starting VirusTotal analysis")

        logger.info(
            "Starting VirusTotal analysis",
            ips_count=len(iocs.ips),
            domains_count=len(iocs.domains),
            hashes_count=len(iocs.hashes)
        )

        # Initialize VirusTotal client
        vt_client = VirusTotalClient()

        results = []

        # Process IPs (limit to prevent API quota exhaustion)
        for ip in iocs.ips[:5]:  # Limit to 5 IPs
            activity.heartbeat(f"Analyzing IP: {ip}")
            try:
                result = await vt_client.lookup_ip(ip)
                results.append({
                    "type": "ip",
                    "indicator": ip,
                    "result": result,
                    "malicious_count": result.get("last_analysis_stats", {}).get("malicious", 0),
                    "suspicious_count": result.get("last_analysis_stats", {}).get("suspicious", 0)
                })
            except Exception as e:
                logger.warning(f"VirusTotal IP lookup failed for {ip}: {e}")
                results.append({
                    "type": "ip",
                    "indicator": ip,
                    "error": str(e)
                })

        # Process domains
        for domain in iocs.domains[:5]:  # Limit to 5 domains
            activity.heartbeat(f"Analyzing domain: {domain}")
            try:
                result = await vt_client.lookup_domain(domain)
                results.append({
                    "type": "domain",
                    "indicator": domain,
                    "result": result,
                    "malicious_count": result.get("last_analysis_stats", {}).get("malicious", 0),
                    "suspicious_count": result.get("last_analysis_stats", {}).get("suspicious", 0)
                })
            except Exception as e:
                logger.warning(f"VirusTotal domain lookup failed for {domain}: {e}")
                results.append({
                    "type": "domain",
                    "indicator": domain,
                    "error": str(e)
                })

        # Process hashes
        for hash_val in iocs.hashes[:5]:  # Limit to 5 hashes
            activity.heartbeat(f"Analyzing hash: {hash_val[:8]}...")
            try:
                result = await vt_client.lookup_hash(hash_val)
                results.append({
                    "type": "hash",
                    "indicator": hash_val,
                    "result": result,
                    "malicious_count": result.get("last_analysis_stats", {}).get("malicious", 0),
                    "suspicious_count": result.get("last_analysis_stats", {}).get("suspicious", 0)
                })
            except Exception as e:
                logger.warning(f"VirusTotal hash lookup failed for {hash_val}: {e}")
                results.append({
                    "type": "hash",
                    "indicator": hash_val,
                    "error": str(e)
                })

        execution_time = time.time() - activity_start_time

        logger.info(
            "VirusTotal analysis completed",
            results_count=len(results),
            successful_lookups=len([r for r in results if "error" not in r]),
            execution_time=execution_time
        )

        return ThreatIntelResult(
            tool_name="virustotal",
            status="success",
            results=results,
            execution_time=execution_time
        )

    except Exception as e:
        execution_time = time.time() - activity_start_time
        logger.error(f"VirusTotal analysis failed: {e}", execution_time=execution_time)

        return ThreatIntelResult(
            tool_name="virustotal",
            status="error",
            results=[],
            execution_time=execution_time,
            error_message=str(e)
        )


@activity.defn
async def abuseipdb_analysis_activity(iocs: IOCs) -> ThreatIntelResult:
    """Analyze IP addresses using AbuseIPDB API"""
    activity_start_time = time.time()

    try:
        activity.heartbeat("Starting AbuseIPDB analysis")

        logger.info(
            "Starting AbuseIPDB analysis",
            ips_count=len(iocs.ips)
        )

        # AbuseIPDB only analyzes IP addresses
        if not iocs.ips:
            return ThreatIntelResult(
                tool_name="abuseipdb",
                status="success",
                results=[],
                execution_time=0.0
            )

        # Initialize AbuseIPDB client
        abuseipdb_client = AbuseIPDBClient()

        results = []

        # Process IPs (limit to prevent API quota exhaustion)
        for ip in iocs.ips[:10]:  # AbuseIPDB has higher limits than VirusTotal
            activity.heartbeat(f"Analyzing IP: {ip}")
            try:
                result = await abuseipdb_client.check_ip(ip)
                results.append({
                    "type": "ip",
                    "indicator": ip,
                    "result": result,
                    "abuse_confidence": result.get("abuse_confidence", 0),
                    "is_public": result.get("is_public", True),
                    "country_code": result.get("country_code", ""),
                    "total_reports": result.get("total_reports", 0)
                })
            except Exception as e:
                logger.warning(f"AbuseIPDB lookup failed for {ip}: {e}")
                results.append({
                    "type": "ip",
                    "indicator": ip,
                    "error": str(e)
                })

        execution_time = time.time() - activity_start_time

        logger.info(
            "AbuseIPDB analysis completed",
            results_count=len(results),
            successful_lookups=len([r for r in results if "error" not in r]),
            execution_time=execution_time
        )

        return ThreatIntelResult(
            tool_name="abuseipdb",
            status="success",
            results=results,
            execution_time=execution_time
        )

    except Exception as e:
        execution_time = time.time() - activity_start_time
        logger.error(f"AbuseIPDB analysis failed: {e}", execution_time=execution_time)

        return ThreatIntelResult(
            tool_name="abuseipdb",
            status="error",
            results=[],
            execution_time=execution_time,
            error_message=str(e)
        )


@activity.defn
async def shodan_analysis_activity(iocs: IOCs) -> ThreatIntelResult:
    """Analyze IP addresses using Shodan API"""
    activity_start_time = time.time()

    try:
        activity.heartbeat("Starting Shodan analysis")

        logger.info(
            "Starting Shodan analysis",
            ips_count=len(iocs.ips)
        )

        # Shodan only analyzes IP addresses
        if not iocs.ips:
            return ThreatIntelResult(
                tool_name="shodan",
                status="success",
                results=[],
                execution_time=0.0
            )

        # Initialize Shodan client
        shodan_client = ShodanClient()

        results = []

        # Process IPs (limit to prevent API quota exhaustion)
        for ip in iocs.ips[:5]:  # Shodan has lower limits
            activity.heartbeat(f"Analyzing IP: {ip}")
            try:
                result = await shodan_client.lookup_ip(ip)
                results.append({
                    "type": "ip",
                    "indicator": ip,
                    "result": result,
                    "ports": result.get("ports", []),
                    "organization": result.get("org", ""),
                    "country": result.get("country_name", ""),
                    "city": result.get("city", ""),
                    "hostnames": result.get("hostnames", [])
                })
            except Exception as e:
                logger.warning(f"Shodan lookup failed for {ip}: {e}")
                results.append({
                    "type": "ip",
                    "indicator": ip,
                    "error": str(e)
                })

        execution_time = time.time() - activity_start_time

        logger.info(
            "Shodan analysis completed",
            results_count=len(results),
            successful_lookups=len([r for r in results if "error" not in r]),
            execution_time=execution_time
        )

        return ThreatIntelResult(
            tool_name="shodan",
            status="success",
            results=results,
            execution_time=execution_time
        )

    except Exception as e:
        execution_time = time.time() - activity_start_time
        logger.error(f"Shodan analysis failed: {e}", execution_time=execution_time)

        return ThreatIntelResult(
            tool_name="shodan",
            status="error",
            results=[],
            execution_time=execution_time,
            error_message=str(e)
        )


@activity.defn
async def milvus_search_activity(query_text: str) -> ThreatIntelResult:
    """Search for similar attack patterns in Milvus vector database"""
    activity_start_time = time.time()

    try:
        activity.heartbeat("Starting Milvus vector search")

        logger.info(
            "Starting Milvus vector search",
            query_length=len(query_text)
        )

        # Initialize Milvus client
        try:
            vectorstore = CyberShieldVectorStore()
            await vectorstore.initialize()
        except Exception as e:
            logger.warning(f"Failed to initialize Milvus: {e}")
            return ThreatIntelResult(
                tool_name="milvus_search",
                status="error",
                results=[],
                execution_time=0.0,
                error_message=f"Milvus initialization failed: {e}"
            )

        results = []

        # Perform vector search for similar patterns
        activity.heartbeat("Executing vector similarity search")
        try:
            search_results = await vectorstore.search(
                query_text=query_text,
                limit=10,  # Limit results for performance
                threshold=0.7  # Similarity threshold
            )

            for result in search_results:
                results.append({
                    "type": "vector_match",
                    "similarity_score": result.get("score", 0.0),
                    "matched_text": result.get("text", ""),
                    "attack_type": result.get("attack_type", ""),
                    "severity": result.get("severity", ""),
                    "metadata": result.get("metadata", {})
                })

        except Exception as e:
            logger.warning(f"Milvus search failed: {e}")
            results.append({
                "type": "vector_match",
                "error": str(e)
            })

        execution_time = time.time() - activity_start_time

        logger.info(
            "Milvus search completed",
            results_count=len(results),
            successful_matches=len([r for r in results if "error" not in r]),
            execution_time=execution_time
        )

        return ThreatIntelResult(
            tool_name="milvus_search",
            status="success",
            results=results,
            execution_time=execution_time
        )

    except Exception as e:
        execution_time = time.time() - activity_start_time
        logger.error(f"Milvus search failed: {e}", execution_time=execution_time)

        return ThreatIntelResult(
            tool_name="milvus_search",
            status="error",
            results=[],
            execution_time=execution_time,
            error_message=str(e)
        )


# Helper functions

async def _get_client_instance(client_type: str):
    """Get singleton client instances to avoid recreating connections"""
    # This could be enhanced with proper dependency injection
    if client_type == "virustotal":
        return VirusTotalClient()
    elif client_type == "abuseipdb":
        return AbuseIPDBClient()
    elif client_type == "shodan":
        return ShodanClient()
    else:
        raise ValueError(f"Unknown client type: {client_type}")


def _assess_threat_level(tool_name: str, result: Dict[str, Any]) -> str:
    """Assess threat level from tool results"""
    if tool_name == "virustotal":
        malicious_count = result.get("malicious_count", 0)
        suspicious_count = result.get("suspicious_count", 0)

        if malicious_count >= 5:
            return "critical"
        elif malicious_count >= 3:
            return "high"
        elif malicious_count >= 1 or suspicious_count >= 5:
            return "medium"
        else:
            return "low"

    elif tool_name == "abuseipdb":
        abuse_confidence = result.get("abuse_confidence", 0)

        if abuse_confidence >= 75:
            return "critical"
        elif abuse_confidence >= 50:
            return "high"
        elif abuse_confidence >= 25:
            return "medium"
        else:
            return "low"

    elif tool_name == "shodan":
        ports = result.get("ports", [])
        # Simple risk assessment based on open ports
        high_risk_ports = [22, 23, 3389, 5900, 1433, 3306]
        if any(port in high_risk_ports for port in ports):
            return "medium"
        else:
            return "low"

    elif tool_name == "milvus_search":
        similarity_score = result.get("similarity_score", 0.0)
        severity = result.get("severity", "").lower()

        if severity in ["critical", "high"] and similarity_score >= 0.8:
            return "high"
        elif severity in ["medium"] and similarity_score >= 0.7:
            return "medium"
        else:
            return "low"

    return "low"