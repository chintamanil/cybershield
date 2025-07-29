"""
VirusTotal API Integration Tool
Provides comprehensive malware analysis and threat intelligence
"""

import os
import logging
import asyncio
from typing import Dict, Any, Optional
import aiohttp
import ipaddress

logger = logging.getLogger(__name__)

class VirusTotalClient:
    """Async VirusTotal API client with comprehensive functionality"""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize VirusTotal client
        
        Args:
            api_key: VirusTotal API key (falls back to env var)
        """
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"
        self._session = None
        
        if not self.api_key:
            logger.warning("VirusTotal API key not provided - functionality will be limited")
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session with retry strategy"""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=30)
            connector = aiohttp.TCPConnector(limit=10, limit_per_host=5)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector
            )
        return self._session
    
    async def close(self):
        """Close the HTTP session"""
        if self._session and not self._session.closed:
            await self._session.close()
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    async def _make_request(self, endpoint: str, method: str = "GET", **kwargs) -> Dict[str, Any]:
        """
        Make authenticated async request to VirusTotal API
        
        Args:
            endpoint: API endpoint
            method: HTTP method
            **kwargs: Additional request parameters
            
        Returns:
            API response data
        """
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}
        
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        
        url = f"{self.base_url}/{endpoint}"
        session = await self._get_session()
        
        try:
            async with session.request(
                method=method,
                url=url,
                headers=headers,
                **kwargs
            ) as response:
                
                # Handle rate limiting
                if response.status == 429:
                    retry_after = int(response.headers.get("Retry-After", 60))
                    logger.warning(f"Rate limited. Waiting {retry_after} seconds")
                    await asyncio.sleep(retry_after)
                    return await self._make_request(endpoint, method, **kwargs)
                
                response.raise_for_status()
                return await response.json()
                
        except aiohttp.ClientError as e:
            logger.error(f"VirusTotal API request failed: {e}")
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"Unexpected error in VirusTotal request: {e}")
            return {"error": f"Unexpected error: {e}"}
    
    async def lookup_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Lookup IP address information
        
        Args:
            ip_address: IP address to analyze
            
        Returns:
            VirusTotal analysis results
        """
        if not self._is_valid_ip(ip_address):
            return {"error": "Invalid IP address format"}
        
        logger.info(f"Looking up IP address: {ip_address}")
        
        response = await self._make_request(f"ip_addresses/{ip_address}")
        
        if "error" in response:
            return response
        
        # Extract key information
        data = response.get("data", {})
        attributes = data.get("attributes", {})
        
        return {
            "ip_address": ip_address,
            "country": attributes.get("country"),
            "as_owner": attributes.get("as_owner"),
            "reputation": attributes.get("reputation", 0),
            "last_analysis_stats": attributes.get("last_analysis_stats", {}),
            "malicious_count": attributes.get("last_analysis_stats", {}).get("malicious", 0),
            "suspicious_count": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
            "harmless_count": attributes.get("last_analysis_stats", {}).get("harmless", 0),
            "network": attributes.get("network"),
            "regional_internet_registry": attributes.get("regional_internet_registry"),
            "whois": attributes.get("whois"),
            "raw_response": response
        }
    
    async def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """
        Lookup domain information
        
        Args:
            domain: Domain to analyze
            
        Returns:
            VirusTotal analysis results
        """
        if not domain or "." not in domain:
            return {"error": "Invalid domain format"}
        
        logger.info(f"Looking up domain: {domain}")
        
        response = await self._make_request(f"domains/{domain}")
        
        if "error" in response:
            return response
        
        data = response.get("data", {})
        attributes = data.get("attributes", {})
        
        return {
            "domain": domain,
            "categories": attributes.get("categories", {}),
            "reputation": attributes.get("reputation", 0),
            "last_analysis_stats": attributes.get("last_analysis_stats", {}),
            "malicious_count": attributes.get("last_analysis_stats", {}).get("malicious", 0),
            "suspicious_count": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
            "harmless_count": attributes.get("last_analysis_stats", {}).get("harmless", 0),
            "creation_date": attributes.get("creation_date"),
            "last_modification_date": attributes.get("last_modification_date"),
            "whois": attributes.get("whois"),
            "dns_records": attributes.get("last_dns_records", []),
            "raw_response": response
        }
    
    async def lookup_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Lookup file hash information
        
        Args:
            file_hash: MD5, SHA1, or SHA256 hash
            
        Returns:
            VirusTotal analysis results
        """
        if not self._is_valid_hash(file_hash):
            return {"error": "Invalid hash format"}
        
        logger.info(f"Looking up file hash: {file_hash}")
        
        response = await self._make_request(f"files/{file_hash}")
        
        if "error" in response:
            return response
        
        data = response.get("data", {})
        attributes = data.get("attributes", {})
        
        return {
            "hash": file_hash,
            "file_names": attributes.get("names", []),
            "file_type": attributes.get("type_description"),
            "size": attributes.get("size"),
            "reputation": attributes.get("reputation", 0),
            "last_analysis_stats": attributes.get("last_analysis_stats", {}),
            "malicious_count": attributes.get("last_analysis_stats", {}).get("malicious", 0),
            "suspicious_count": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
            "harmless_count": attributes.get("last_analysis_stats", {}).get("harmless", 0),
            "first_submission_date": attributes.get("first_submission_date"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "magic": attributes.get("magic"),
            "signature_info": attributes.get("signature_info", {}),
            "raw_response": response
        }
    
    async def search(self, query: str) -> Dict[str, Any]:
        """
        Search VirusTotal intelligence
        
        Args:
            query: Search query
            
        Returns:
            Search results
        """
        logger.info(f"Searching VirusTotal: {query}")
        
        params = {"query": query}
        response = await self._make_request("search", params=params)
        
        if "error" in response:
            return response
        
        data = response.get("data", [])
        
        return {
            "query": query,
            "results_count": len(data),
            "results": [
                {
                    "id": item.get("id"),
                    "type": item.get("type"),
                    "attributes": item.get("attributes", {})
                }
                for item in data
            ],
            "raw_response": response
        }
    
    def _is_valid_ip(self, ip_address: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False
    
    def _is_valid_hash(self, hash_value: str) -> bool:
        """Validate hash format (MD5, SHA1, SHA256)"""
        hash_value = hash_value.lower()
        
        # MD5: 32 hex chars
        if len(hash_value) == 32 and all(c in "0123456789abcdef" for c in hash_value):
            return True
        
        # SHA1: 40 hex chars
        if len(hash_value) == 40 and all(c in "0123456789abcdef" for c in hash_value):
            return True
        
        # SHA256: 64 hex chars
        if len(hash_value) == 64 and all(c in "0123456789abcdef" for c in hash_value):
            return True
        
        return False


# Legacy function for backward compatibility
async def lookup_virustotal(ip: str) -> Dict[str, Any]:
    """Legacy async function for IP lookup"""
    async with VirusTotalClient() as client:
        return await client.lookup_ip(ip)


# Convenience functions
async def lookup_ip(ip_address: str) -> Dict[str, Any]:
    """Async lookup IP address"""
    async with VirusTotalClient() as client:
        return await client.lookup_ip(ip_address)


async def lookup_domain(domain: str) -> Dict[str, Any]:
    """Async lookup domain"""
    async with VirusTotalClient() as client:
        return await client.lookup_domain(domain)


async def lookup_hash(file_hash: str) -> Dict[str, Any]:
    """Async lookup file hash"""
    async with VirusTotalClient() as client:
        return await client.lookup_file_hash(file_hash)


async def search_vt(query: str) -> Dict[str, Any]:
    """Async search VirusTotal"""
    async with VirusTotalClient() as client:
        return await client.search(query)