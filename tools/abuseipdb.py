"""
AbuseIPDB API Integration Tool
Provides IP reputation and abuse reporting capabilities
"""

import os
import asyncio
from typing import Dict, Any, Optional, List
import aiohttp
import ipaddress
from utils.logging_config import get_security_logger

logger = get_security_logger("abuseipdb")

class AbuseIPDBClient:
    """Async AbuseIPDB API client with comprehensive functionality"""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize AbuseIPDB client

        Args:
            api_key: AbuseIPDB API key (falls back to env var)
        """
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self._session = None

        if not self.api_key:
            logger.warning("AbuseIPDB API key not configured", functionality="limited")

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
        Make authenticated async request to AbuseIPDB API

        Args:
            endpoint: API endpoint
            method: HTTP method
            **kwargs: Additional request parameters

        Returns:
            API response data
        """
        if not self.api_key:
            return {"error": "AbuseIPDB API key not configured"}

        headers = {
            "Key": self.api_key,
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
            logger.error(f"AbuseIPDB API request failed: {e}")
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"Unexpected error in AbuseIPDB request: {e}")
            return {"error": f"Unexpected error: {e}"}

    async def check_ip(self, ip_address: str, max_age_days: int = 90, verbose: bool = False) -> Dict[str, Any]:
        """
        Check IP address reputation

        Args:
            ip_address: IP address to check
            max_age_days: Maximum age of reports to consider (30-365 days)
            verbose: Whether to include detailed report information

        Returns:
            IP reputation data
        """
        if not self._is_valid_ip(ip_address):
            return {"error": "Invalid IP address format"}

        # Validate max_age_days
        if not 30 <= max_age_days <= 365:
            max_age_days = 90

        logger.info(f"Checking IP reputation: {ip_address}")

        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": max_age_days,
            "verbose": str(verbose).lower()
        }

        response = await self._make_request("check", params=params)

        if "error" in response:
            return response

        data = response.get("data", {})

        result = {
            "ip_address": ip_address,
            "is_public": data.get("isPublic", False),
            "ip_version": data.get("ipVersion"),
            "is_whitelisted": data.get("isWhitelisted", False),
            "abuse_confidence": data.get("abuseConfidencePercentage", 0),
            "country_code": data.get("countryCode"),
            "country_name": data.get("countryName"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports", 0),
            "num_distinct_users": data.get("numDistinctUsers", 0),
            "last_reported_at": data.get("lastReportedAt"),
            "raw_response": response
        }
        logger.info(f"AbuseIPD IP result: {result}")
        # Add detailed reports if verbose
        if verbose and "reports" in data:
            result["reports"] = [
                {
                    "reported_at": report.get("reportedAt"),
                    "comment": report.get("comment"),
                    "categories": report.get("categories", []),
                    "reporter_id": report.get("reporterId"),
                    "reporter_country_code": report.get("reporterCountryCode")
                }
                for report in data["reports"]
            ]

        return result

    async def check_subnet(self, network: str, max_age_days: int = 90) -> Dict[str, Any]:
        """
        Check subnet reputation

        Args:
            network: Network in CIDR notation (e.g., 192.168.1.0/24)
            max_age_days: Maximum age of reports to consider

        Returns:
            Subnet reputation data
        """
        logger.info(f"Checking subnet reputation: {network}")

        params = {
            "network": network,
            "maxAgeInDays": max_age_days
        }

        response = await self._make_request("check-block", params=params)

        if "error" in response:
            return response

        data = response.get("data", {})

        return {
            "network": network,
            "network_address": data.get("networkAddress"),
            "netmask": data.get("netmask"),
            "min_address": data.get("minAddress"),
            "max_address": data.get("maxAddress"),
            "num_possible_hosts": data.get("numPossibleHosts"),
            "address_space_desc": data.get("addressSpaceDesc"),
            "reported_addresses": data.get("reportedAddress", []),
            "raw_response": response
        }

    async def report_ip(self, ip_address: str, categories: List[int], comment: str = "") -> Dict[str, Any]:
        """
        Report an IP address for abuse

        Args:
            ip_address: IP address to report
            categories: List of category IDs (see AbuseIPDB documentation)
            comment: Optional comment describing the abuse

        Returns:
            Report submission result
        """
        if not self._is_valid_ip(ip_address):
            return {"error": "Invalid IP address format"}

        if not categories:
            return {"error": "At least one category must be specified"}

        logger.info(f"Reporting IP address: {ip_address}")

        data = {
            "ip": ip_address,
            "categories": ",".join(map(str, categories)),
            "comment": comment
        }

        response = await self._make_request("report", method="POST", data=data)

        if "error" in response:
            return response

        data = response.get("data", {})

        return {
            "ip_address": ip_address,
            "abuse_confidence": data.get("abuseConfidencePercentage", 0),
            "report_id": data.get("reportId"),
            "raw_response": response
        }

    async def get_blacklist(self, confidence_minimum: int = 75, limit: int = 10000) -> Dict[str, Any]:
        """
        Get blacklisted IP addresses

        Args:
            confidence_minimum: Minimum confidence level (25-100)
            limit: Maximum number of IPs to return (1-10000)

        Returns:
            Blacklisted IP addresses
        """
        # Validate parameters
        confidence_minimum = max(25, min(100, confidence_minimum))
        limit = max(1, min(10000, limit))

        logger.info(f"Getting blacklist (confidence >= {confidence_minimum}, limit = {limit})")

        params = {
            "confidenceMinimum": confidence_minimum,
            "limit": limit,
            "plaintext": False  # Get JSON response
        }

        response = await self._make_request("blacklist", params=params)

        if "error" in response:
            return response

        data = response.get("data", [])

        return {
            "confidence_minimum": confidence_minimum,
            "limit": limit,
            "blacklisted_ips": [
                {
                    "ip_address": item.get("ipAddress"),
                    "country_code": item.get("countryCode"),
                    "usage_type": item.get("usageType"),
                    "isp": item.get("isp"),
                    "domain": item.get("domain"),
                    "abuse_confidence": item.get("abuseConfidencePercentage"),
                    "last_reported_at": item.get("lastReportedAt")
                }
                for item in data
            ],
            "total_count": len(data),
            "raw_response": response
        }

    async def clear_address(self, ip_address: str) -> Dict[str, Any]:
        """
        Clear your own IP address from reports (if you reported it by mistake)

        Args:
            ip_address: IP address to clear

        Returns:
            Clear operation result
        """
        if not self._is_valid_ip(ip_address):
            return {"error": "Invalid IP address format"}

        logger.info(f"Clearing IP address: {ip_address}")

        data = {"ipAddress": ip_address}

        response = await self._make_request("clear-address", method="DELETE", data=data)

        if "error" in response:
            return response

        return {
            "ip_address": ip_address,
            "success": True,
            "raw_response": response
        }

    def get_categories(self) -> Dict[str, Any]:
        """
        Get list of available report categories

        Returns:
            Category information
        """
        # AbuseIPDB categories (as of 2024)
        categories = {
            1: "DNS Compromise",
            2: "DNS Poisoning",
            3: "Fraud Orders",
            4: "DDoS Attack",
            5: "FTP Brute-Force",
            6: "Ping of Death",
            7: "Phishing",
            8: "Fraud VoIP",
            9: "Open Proxy",
            10: "Web Spam",
            11: "Email Spam",
            12: "Blog Spam",
            13: "VPN IP",
            14: "Port Scan",
            15: "Hacking",
            16: "SQL Injection",
            17: "Spoofing",
            18: "Brute-Force",
            19: "Bad Web Bot",
            20: "Exploited Host",
            21: "Web App Attack",
            22: "SSH",
            23: "IoT Targeted"
        }

        return {
            "categories": categories,
            "category_count": len(categories)
        }

    def _is_valid_ip(self, ip_address: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False


# Legacy function for backward compatibility
async def lookup_abuseipdb(ip: str) -> Dict[str, Any]:
    """Legacy async function for IP lookup"""
    async with AbuseIPDBClient() as client:
        return await client.check_ip(ip)


# Convenience functions
async def check_ip(ip_address: str, max_age_days: int = 90, verbose: bool = False) -> Dict[str, Any]:
    """Async check IP reputation"""
    async with AbuseIPDBClient() as client:
        return await client.check_ip(ip_address, max_age_days, verbose)


async def check_subnet(network: str, max_age_days: int = 90) -> Dict[str, Any]:
    """Async check subnet reputation"""
    async with AbuseIPDBClient() as client:
        return await client.check_subnet(network, max_age_days)


async def report_ip(ip_address: str, categories: List[int], comment: str = "") -> Dict[str, Any]:
    """Async report IP for abuse"""
    async with AbuseIPDBClient() as client:
        return await client.report_ip(ip_address, categories, comment)


async def get_blacklist(confidence_minimum: int = 75, limit: int = 10000) -> Dict[str, Any]:
    """Async get blacklisted IPs"""
    async with AbuseIPDBClient() as client:
        return await client.get_blacklist(confidence_minimum, limit)


def get_categories() -> Dict[str, Any]:
    """Get abuse categories (no async needed - static data)"""
    client = AbuseIPDBClient()
    return client.get_categories()