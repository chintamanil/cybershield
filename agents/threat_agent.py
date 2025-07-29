# ThreatAgent calls Shodan, AbuseIPDB, VirusTotal tools with async support
import asyncio
import logging
from typing import Dict, List, Any
from tools.shodan import ShodanClient
from tools.abuseipdb import AbuseIPDBClient
from tools.virustotal import VirusTotalClient

logger = logging.getLogger(__name__)

class ThreatAgent:
    def __init__(self, memory=None, session_id=None):
        self.memory = memory  # Async Redis STM
        self.session_id = session_id
        # Initialize tool clients (async context managers)
        self.shodan_client = None
        self.abuseipdb_client = None
        self.virustotal_client = None

    async def _get_clients(self):
        """Initialize async API clients"""
        if not self.shodan_client:
            try:
                self.shodan_client = ShodanClient()
                self.abuseipdb_client = AbuseIPDBClient()
                self.virustotal_client = VirusTotalClient()
                logger.info("Initialized threat intelligence clients")
            except Exception as e:
                logger.error(f"Failed to initialize tool clients: {e}")

    async def close(self):
        """Close all client connections"""
        if self.shodan_client:
            await self.shodan_client.close()
        if self.abuseipdb_client:
            await self.abuseipdb_client.close()
        if self.virustotal_client:
            await self.virustotal_client.close()

    async def evaluate(self, iocs: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """Evaluate IOCs using multiple threat intelligence sources concurrently"""
        logger.debug(f"ThreatAgent.evaluate called with iocs type: {type(iocs)}, value: {iocs}")
        await self._get_clients()
        results = []

        # Process IPs with concurrent lookups
        ip_tasks = []
        # Combine IPv4 and IPv6 addresses
        logger.debug("Processing IPs...")
        all_ips = iocs.get("ipv4", []) + iocs.get("ipv6", [])
        logger.debug(f"all_ips: {all_ips}")
        for ip in all_ips:
            ip_tasks.append(self._evaluate_ip(ip))

        if ip_tasks:
            ip_results = await asyncio.gather(*ip_tasks, return_exceptions=True)
            for result in ip_results:
                if isinstance(result, Exception):
                    logger.error(f"IP evaluation failed: {result}")
                    results.append({"error": str(result)})
                else:
                    results.append(result)

        # Process domains concurrently
        logger.debug("Processing domains...")
        domain_tasks = []
        domains = iocs.get("domain", [])
        logger.debug(f"domains: {domains}")
        for domain in domains:
            domain_tasks.append(self._evaluate_domain(domain))

        if domain_tasks:
            domain_results = await asyncio.gather(*domain_tasks, return_exceptions=True)
            for result in domain_results:
                if isinstance(result, Exception):
                    logger.error(f"Domain evaluation failed: {result}")
                    results.append({"error": str(result)})
                else:
                    results.append(result)

        # Process hashes concurrently
        logger.debug("Processing hashes...")
        hash_tasks = []
        # Combine all hash types
        all_hashes = iocs.get("md5", []) + iocs.get("sha1", []) + iocs.get("sha256", [])
        logger.debug(f"all_hashes: {all_hashes}")
        for hash_value in all_hashes:
            hash_tasks.append(self._evaluate_hash(hash_value))

        if hash_tasks:
            hash_results = await asyncio.gather(*hash_tasks, return_exceptions=True)
            for result in hash_results:
                if isinstance(result, Exception):
                    logger.error(f"Hash evaluation failed: {result}")
                    results.append({"error": str(result)})
                else:
                    results.append(result)

        logger.debug(f"ThreatAgent.evaluate returning: type={type(results)}, value={results}")
        return results

    async def _evaluate_ip(self, ip: str) -> Dict[str, Any]:
        """Evaluate a single IP address using all available sources"""
        cache_key = f"threat_intel:{ip}"

        # Check cache first
        if self.memory:
            try:
                cached_result = await self.memory.get(cache_key)
                if cached_result:
                    logger.info(f"Retrieved cached threat intel for IP {ip}")
                    return cached_result
            except Exception as e:
                logger.warning(f"Cache retrieval failed for {ip}: {e}")

        # Perform concurrent lookups
        tasks = []
        if self.shodan_client:
            tasks.append(self._safe_lookup("shodan", self.shodan_client.lookup_ip, ip))
            logger.debug("shodan threat intelligence clients for ip:"+ip)
        if self.abuseipdb_client:
            tasks.append(self._safe_lookup("abuseipdb", self.abuseipdb_client.check_ip, ip))
            logger.debug("abuseipdb threat intelligence clients for ip:"+ip)
        if self.virustotal_client:
            tasks.append(self._safe_lookup("virustotal", self.virustotal_client.lookup_ip, ip))
            logger.debug("virustotal threat intelligence clients for ip:"+ip)

        if not tasks:
            return {"error": "No threat intelligence clients available"}

        # Wait for all lookups to complete
        lookup_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Combine results
        result = {
            "ioc": ip,
            "ioc_type": "ip",
            "sources": {},
            "summary": {
                "risk_score": 0,
                "is_malicious": False,
                "confidence": 0
            }
        }
        logger.debug("lookup_results:"+str(lookup_results))
        for lookup_result in lookup_results:
            if isinstance(lookup_result, dict) and "source" in lookup_result:
                source = lookup_result["source"]
                data = lookup_result["data"]
                result["sources"][source] = data

                # Update summary based on source data
                if source == "abuseipdb" and "abuse_confidence" in data:
                    result["summary"]["risk_score"] = max(result["summary"]["risk_score"], data["abuse_confidence"])
                    if data["abuse_confidence"] > 50:
                        result["summary"]["is_malicious"] = True

                elif source == "virustotal" and "malicious_count" in data:
                    if data["malicious_count"] > 0:
                        result["summary"]["is_malicious"] = True
                        result["summary"]["risk_score"] = max(result["summary"]["risk_score"], 75)

        # Cache the result
        if self.memory:
            try:
                await self.memory.set(cache_key, result, ttl=1800)  # 30 minutes
                logger.info(f"Cached threat intel for IP {ip}")
            except Exception as e:
                logger.warning(f"Cache storage failed for {ip}: {e}")

        return result

    async def _evaluate_domain(self, domain: str) -> Dict[str, Any]:
        """Evaluate a domain using VirusTotal"""
        cache_key = f"threat_intel:domain:{domain}"

        if self.memory:
            try:
                cached_result = await self.memory.get(cache_key)
                if cached_result:
                    return cached_result
            except Exception as e:
                logger.warning(f"Cache retrieval failed for domain {domain}: {e}")

        result = {
            "ioc": domain,
            "ioc_type": "domain",
            "sources": {},
            "summary": {"risk_score": 0, "is_malicious": False}
        }

        if self.virustotal_client:
            try:
                vt_result = await self.virustotal_client.lookup_domain(domain)
                result["sources"]["virustotal"] = vt_result

                if "malicious_count" in vt_result and vt_result["malicious_count"] > 0:
                    result["summary"]["is_malicious"] = True
                    result["summary"]["risk_score"] = 75
            except Exception as e:
                result["sources"]["virustotal"] = {"error": str(e)}

        if self.memory:
            try:
                await self.memory.set(cache_key, result, ttl=1800)
            except Exception as e:
                logger.warning(f"Cache storage failed for domain {domain}: {e}")

        return result

    async def _evaluate_hash(self, hash_value: str) -> Dict[str, Any]:
        """Evaluate a file hash using VirusTotal"""
        cache_key = f"threat_intel:hash:{hash_value}"

        if self.memory:
            try:
                cached_result = await self.memory.get(cache_key)
                if cached_result:
                    return cached_result
            except Exception as e:
                logger.warning(f"Cache retrieval failed for hash {hash_value}: {e}")

        result = {
            "ioc": hash_value,
            "ioc_type": "hash",
            "sources": {},
            "summary": {"risk_score": 0, "is_malicious": False}
        }

        if self.virustotal_client:
            try:
                vt_result = await self.virustotal_client.lookup_file_hash(hash_value)
                result["sources"]["virustotal"] = vt_result

                if "malicious_count" in vt_result and vt_result["malicious_count"] > 0:
                    result["summary"]["is_malicious"] = True
                    result["summary"]["risk_score"] = min(100, vt_result["malicious_count"] * 10)
            except Exception as e:
                result["sources"]["virustotal"] = {"error": str(e)}

        if self.memory:
            try:
                await self.memory.set(cache_key, result, ttl=3600)  # 1 hour for hashes
            except Exception as e:
                logger.warning(f"Cache storage failed for hash {hash_value}: {e}")

        return result

    async def _safe_lookup(self, source: str, lookup_func, ioc: str) -> Dict[str, Any]:
        """Safely perform a lookup with error handling"""
        try:
            data = await lookup_func(ioc)
            return {"source": source, "data": data}
        except Exception as e:
            logger.error(f"{source} lookup failed for {ioc}: {e}")
            return {"source": source, "data": {"error": str(e)}}