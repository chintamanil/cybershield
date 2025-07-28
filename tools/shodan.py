"""
Shodan API Integration Tool
Provides comprehensive network reconnaissance and device information
"""

import os
import logging
import asyncio
from typing import Dict, Any, Optional, List
import aiohttp
import ipaddress

logger = logging.getLogger(__name__)

class ShodanClient:
    """Async Shodan API client with comprehensive functionality"""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Shodan client
        
        Args:
            api_key: Shodan API key (falls back to env var)
        """
        self.api_key = api_key or os.getenv("SHODAN_API_KEY")
        self.base_url = "https://api.shodan.io"
        self._session = None
        
        if not self.api_key:
            logger.warning("Shodan API key not provided - functionality will be limited")
    
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
    
    async def _make_request(self, endpoint: str, **kwargs) -> Dict[str, Any]:
        """
        Make authenticated async request to Shodan API
        
        Args:
            endpoint: API endpoint
            **kwargs: Additional request parameters
            
        Returns:
            API response data
        """
        if not self.api_key:
            return {"error": "Shodan API key not configured"}
        
        # Add API key to parameters
        params = kwargs.get("params", {})
        params["key"] = self.api_key
        kwargs["params"] = params
        
        url = f"{self.base_url}/{endpoint}"
        session = await self._get_session()
        
        try:
            async with session.get(
                url=url,
                **kwargs
            ) as response:
                
                # Handle rate limiting
                if response.status == 429:
                    retry_after = int(response.headers.get("Retry-After", 60))
                    logger.warning(f"Rate limited. Waiting {retry_after} seconds")
                    await asyncio.sleep(retry_after)
                    return await self._make_request(endpoint, **kwargs)
                
                response.raise_for_status()
                return await response.json()
                
        except aiohttp.ClientError as e:
            logger.error(f"Shodan API request failed: {e}")
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"Unexpected error in Shodan request: {e}")
            return {"error": f"Unexpected error: {e}"}
    
    async def lookup_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Lookup IP address information
        
        Args:
            ip_address: IP address to analyze
            
        Returns:
            Shodan host information
        """
        if not self._is_valid_ip(ip_address):
            return {"error": "Invalid IP address format"}
        
        logger.info(f"Looking up IP address: {ip_address}")
        
        response = await self._make_request(f"shodan/host/{ip_address}")
        
        if "error" in response:
            return response
        
        # Extract key information
        return {
            "ip_address": ip_address,
            "hostnames": response.get("hostnames", []),
            "country_name": response.get("country_name"),
            "country_code": response.get("country_code"),
            "city": response.get("city"),
            "region_code": response.get("region_code"),
            "postal_code": response.get("postal_code"),
            "latitude": response.get("latitude"),
            "longitude": response.get("longitude"),
            "organization": response.get("org"),
            "isp": response.get("isp"),
            "asn": response.get("asn"),
            "last_update": response.get("last_update"),
            "os": response.get("os"),
            "ports": response.get("ports", []),
            "services": self._extract_services(response.get("data", [])),
            "vulnerabilities": self._extract_vulnerabilities(response.get("vulns", [])),
            "tags": response.get("tags", []),
            "raw_response": response
        }
    
    async def search(self, query: str, facets: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Search Shodan database
        
        Args:
            query: Search query
            facets: Optional facets to include in response
            
        Returns:
            Search results
        """
        logger.info(f"Searching Shodan: {query}")
        
        params = {"query": query}
        if facets:
            params["facets"] = ",".join(facets)
        
        response = await self._make_request("shodan/host/search", params=params)
        
        if "error" in response:
            return response
        
        matches = response.get("matches", [])
        
        return {
            "query": query,
            "total_results": response.get("total", 0),
            "results_returned": len(matches),
            "facets": response.get("facets", {}),
            "results": [
                {
                    "ip": match.get("ip_str"),
                    "port": match.get("port"),
                    "product": match.get("product"),
                    "version": match.get("version"),
                    "organization": match.get("org"),
                    "location": {
                        "country": match.get("location", {}).get("country_name"),
                        "city": match.get("location", {}).get("city"),
                        "latitude": match.get("location", {}).get("latitude"),
                        "longitude": match.get("location", {}).get("longitude")
                    },
                    "banner": match.get("data", "")[:200],  # Truncate banner
                    "timestamp": match.get("timestamp")
                }
                for match in matches
            ],
            "raw_response": response
        }
    
    async def get_host_count(self, query: str) -> Dict[str, Any]:
        """
        Get count of hosts matching query
        
        Args:
            query: Search query
            
        Returns:
            Host count information
        """
        logger.info(f"Getting host count for: {query}")
        
        params = {"query": query}
        response = await self._make_request("shodan/host/count", params=params)
        
        if "error" in response:
            return response
        
        return {
            "query": query,
            "total_hosts": response.get("total", 0),
            "facets": response.get("facets", {}),
            "raw_response": response
        }
    
    async def search_facets(self, query: str = "", facets: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Get facet information for search query
        
        Args:
            query: Search query (empty for all data)
            facets: List of facets to retrieve
            
        Returns:
            Facet information
        """
        if facets is None:
            facets = ["country", "org", "port", "asn"]
        
        logger.info(f"Getting facets for query: {query or 'all'}")
        
        params = {"facets": ",".join(facets)}
        if query:
            params["query"] = query
        
        response = await self._make_request("shodan/host/count", params=params)
        
        if "error" in response:
            return response
        
        return {
            "query": query or "all",
            "total_hosts": response.get("total", 0),
            "facets": response.get("facets", {}),
            "raw_response": response
        }
    
    async def get_protocols(self) -> Dict[str, Any]:
        """
        Get list of protocols that Shodan crawls
        
        Returns:
            Protocol information
        """
        logger.info("Getting Shodan protocols")
        
        response = await self._make_request("shodan/protocols")
        
        if "error" in response:
            return response
        
        return {
            "protocols": response,
            "protocol_count": len(response),
            "raw_response": response
        }
    
    async def get_ports(self) -> Dict[str, Any]:
        """
        Get list of ports that Shodan crawls
        
        Returns:
            Port information
        """
        logger.info("Getting Shodan ports")
        
        response = await self._make_request("shodan/ports")
        
        if "error" in response:
            return response
        
        return {
            "ports": response,
            "port_count": len(response),
            "raw_response": response
        }
    
    async def get_account_info(self) -> Dict[str, Any]:
        """
        Get account information
        
        Returns:
            Account details
        """
        logger.info("Getting account information")
        
        response = await self._make_request("account/profile")
        
        if "error" in response:
            return response
        
        return {
            "member": response.get("member", False),
            "credits": response.get("credits", 0),
            "display_name": response.get("display_name"),
            "created": response.get("created"),
            "raw_response": response
        }
    
    def _extract_services(self, data: List[Dict]) -> List[Dict]:
        """Extract service information from host data"""
        services = []
        
        for service in data:
            services.append({
                "port": service.get("port"),
                "protocol": service.get("transport"),
                "product": service.get("product"),
                "version": service.get("version"),
                "service": service.get("_shodan", {}).get("module"),
                "banner": service.get("data", "")[:100],  # Truncate banner
                "timestamp": service.get("timestamp")
            })
        
        return services
    
    def _extract_vulnerabilities(self, vulns: List[str]) -> List[Dict]:
        """Extract vulnerability information"""
        return [{"cve": vuln} for vuln in vulns]
    
    def _is_valid_ip(self, ip_address: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False


# Legacy function for backward compatibility
async def lookup_shodan(ip: str) -> Dict[str, Any]:
    """Legacy async function for IP lookup"""
    async with ShodanClient() as client:
        return await client.lookup_ip(ip)


# Convenience functions
async def lookup_ip(ip_address: str) -> Dict[str, Any]:
    """Async lookup IP address"""
    async with ShodanClient() as client:
        return await client.lookup_ip(ip_address)


async def search_shodan(query: str, facets: Optional[List[str]] = None) -> Dict[str, Any]:
    """Async search Shodan"""
    async with ShodanClient() as client:
        return await client.search(query, facets)


async def get_host_count(query: str) -> Dict[str, Any]:
    """Async get host count for query"""
    async with ShodanClient() as client:
        return await client.get_host_count(query)


async def get_account_info() -> Dict[str, Any]:
    """Async get account information"""
    async with ShodanClient() as client:
        return await client.get_account_info()