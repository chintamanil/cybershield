"""
Regex Checker Tool
Provides comprehensive pattern matching for cybersecurity IOCs and data validation
"""

import re
from typing import Dict, Any, List
import ipaddress
from urllib.parse import urlparse
from utils.logging_config import get_security_logger

logger = get_security_logger("regex_checker")

class IOCPatterns:
    """Comprehensive IOC (Indicator of Compromise) patterns"""

    # IP Address patterns
    IPV4_PATTERN = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    IPV6_PATTERN = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|::1\b'
    PRIVATE_IP_PATTERN = r'\b(?:10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.(?:[0-9]{1,3}\.)[0-9]{1,3}|192\.168\.(?:[0-9]{1,3}\.)[0-9]{1,3})\b'

    # Domain and URL patterns
    DOMAIN_PATTERN = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    URL_PATTERN = r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*)?(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?'
    SUSPICIOUS_TLD_PATTERN = r'\b\w+\.(?:tk|ml|ga|cf|bit|onion|i2p|biz|cc|pw)\b'

    # Hash patterns
    MD5_PATTERN = r'\b[a-fA-F0-9]{32}\b'
    SHA1_PATTERN = r'\b[a-fA-F0-9]{40}\b'
    SHA256_PATTERN = r'\b[a-fA-F0-9]{64}\b'
    SHA512_PATTERN = r'\b[a-fA-F0-9]{128}\b'

    # Email patterns
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    SUSPICIOUS_EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@(?:tempmail|guerrillamail|10minutemail|mailinator|throwaway)\.(?:com|org|net)\b'

    # File patterns
    EXECUTABLE_PATTERN = r'\b\w+\.(?:exe|scr|bat|cmd|com|pif|vbs|js|jar|app|dmg|pkg|deb|rpm)\b'
    DOCUMENT_PATTERN = r'\b\w+\.(?:doc|docx|xls|xlsx|ppt|pptx|pdf|rtf|odt|ods|odp)\b'
    ARCHIVE_PATTERN = r'\b\w+\.(?:zip|rar|7z|tar|gz|bz2|xz|cab|iso)\b'
    SCRIPT_PATTERN = r'\b\w+\.(?:ps1|py|pl|rb|sh|php|asp|aspx|jsp)\b'

    # Registry patterns (Windows)
    REGISTRY_PATTERN = r'(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_CLASSES_ROOT|HKCR)\\[\w\\]+(?:\\[\w\s]+)*'

    # Process patterns
    PROCESS_PATTERN = r'\b(?:powershell|cmd|wscript|cscript|regsvr32|rundll32|certutil|bitsadmin|schtasks|at|sc|net|wmic|taskkill|tasklist)\.exe\b'

    # Network patterns
    PORT_PATTERN = r'\b(?:[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])\b'
    MAC_ADDRESS_PATTERN = r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b'

    # Cryptocurrency patterns
    BITCOIN_ADDRESS_PATTERN = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|bc1[a-z0-9]{39,59}\b'
    ETHEREUM_ADDRESS_PATTERN = r'\b0x[a-fA-F0-9]{40}\b'

    # Suspicious patterns
    BASE64_PATTERN = r'\b[A-Za-z0-9+/]{20,}={0,2}\b'
    HEX_PATTERN = r'\b(?:0x)?[a-fA-F0-9]{8,}\b'

    # CVE pattern
    CVE_PATTERN = r'\bCVE-\d{4}-\d{4,7}\b'

    # Mutex patterns (common malware)
    MUTEX_PATTERN = r'\b(?:Global\\|Local\\)?[A-Za-z0-9_-]{8,32}\b'


class RegexChecker:
    """regex checker for cybersecurity analysis"""

    def __init__(self):
        """Initialize the regex checker"""
        self.patterns = IOCPatterns()
        self.compiled_patterns = self._compile_patterns()

    def _compile_patterns(self) -> Dict[str, re.Pattern]:
        """Compile all regex patterns for better performance"""
        return {
            'ipv4': re.compile(self.patterns.IPV4_PATTERN, re.IGNORECASE),
            'ipv6': re.compile(self.patterns.IPV6_PATTERN, re.IGNORECASE),
            'private_ip': re.compile(self.patterns.PRIVATE_IP_PATTERN, re.IGNORECASE),
            'domain': re.compile(self.patterns.DOMAIN_PATTERN, re.IGNORECASE),
            'url': re.compile(self.patterns.URL_PATTERN, re.IGNORECASE),
            'suspicious_tld': re.compile(self.patterns.SUSPICIOUS_TLD_PATTERN, re.IGNORECASE),
            'md5': re.compile(self.patterns.MD5_PATTERN),
            'sha1': re.compile(self.patterns.SHA1_PATTERN),
            'sha256': re.compile(self.patterns.SHA256_PATTERN),
            'sha512': re.compile(self.patterns.SHA512_PATTERN),
            'email': re.compile(self.patterns.EMAIL_PATTERN, re.IGNORECASE),
            'suspicious_email': re.compile(self.patterns.SUSPICIOUS_EMAIL_PATTERN, re.IGNORECASE),
            'executable': re.compile(self.patterns.EXECUTABLE_PATTERN, re.IGNORECASE),
            'document': re.compile(self.patterns.DOCUMENT_PATTERN, re.IGNORECASE),
            'archive': re.compile(self.patterns.ARCHIVE_PATTERN, re.IGNORECASE),
            'script': re.compile(self.patterns.SCRIPT_PATTERN, re.IGNORECASE),
            'registry': re.compile(self.patterns.REGISTRY_PATTERN, re.IGNORECASE),
            'process': re.compile(self.patterns.PROCESS_PATTERN, re.IGNORECASE),
            'port': re.compile(self.patterns.PORT_PATTERN),
            'mac_address': re.compile(self.patterns.MAC_ADDRESS_PATTERN, re.IGNORECASE),
            'bitcoin_address': re.compile(self.patterns.BITCOIN_ADDRESS_PATTERN),
            'ethereum_address': re.compile(self.patterns.ETHEREUM_ADDRESS_PATTERN),
            'base64': re.compile(self.patterns.BASE64_PATTERN),
            'hex': re.compile(self.patterns.HEX_PATTERN, re.IGNORECASE),
            'cve': re.compile(self.patterns.CVE_PATTERN, re.IGNORECASE),
            'mutex': re.compile(self.patterns.MUTEX_PATTERN, re.IGNORECASE)
        }

    def extract_all_iocs(self, text: str) -> Dict[str, List[str]]:
        """
        Extract all IOCs from text

        Args:
            text: Text to analyze

        Returns:
            Dictionary of IOC types and their matches
        """
        logger.info("Extracting all IOCs from text")

        results = {}

        for ioc_type, pattern in self.compiled_patterns.items():
            matches = pattern.findall(text)
            if matches:
                # Remove duplicates while preserving order
                unique_matches = list(dict.fromkeys(matches))
                results[ioc_type] = unique_matches

        # Post-process IP addresses to validate them
        if 'ipv4' in results:
            results['ipv4'] = self._validate_ipv4_addresses(results['ipv4'])

        # Categorize IPs as private/public
        if 'ipv4' in results:
            public_ips = []
            private_ips = []
            for ip in results['ipv4']:
                if self._is_private_ip(ip):
                    private_ips.append(ip)
                else:
                    public_ips.append(ip)

            if public_ips:
                results['public_ipv4'] = public_ips
            if private_ips:
                results['private_ipv4'] = private_ips

        return results

    def check_pattern(self, text: str, pattern_name: str) -> List[str]:
        """
        Check text against a specific pattern

        Args:
            text: Text to analyze
            pattern_name: Name of the pattern to check

        Returns:
            List of matches
        """
        if pattern_name not in self.compiled_patterns:
            return []

        pattern = self.compiled_patterns[pattern_name]
        matches = pattern.findall(text)

        # Remove duplicates while preserving order
        return list(dict.fromkeys(matches))

    def validate_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Validate and categorize IP address

        Args:
            ip_address: IP address to validate

        Returns:
            Validation results
        """
        try:
            ip_obj = ipaddress.ip_address(ip_address)

            return {
                "ip_address": ip_address,
                "is_valid": True,
                "version": ip_obj.version,
                "is_private": ip_obj.is_private,
                "is_reserved": ip_obj.is_reserved,
                "is_multicast": ip_obj.is_multicast,
                "is_loopback": ip_obj.is_loopback,
                "is_link_local": ip_obj.is_link_local,
                "compressed": str(ip_obj),
                "exploded": ip_obj.exploded if ip_obj.version == 6 else str(ip_obj)
            }
        except ValueError:
            return {
                "ip_address": ip_address,
                "is_valid": False,
                "error": "Invalid IP address format"
            }

    def validate_domain(self, domain: str) -> Dict[str, Any]:
        """
        Validate domain name

        Args:
            domain: Domain to validate

        Returns:
            Validation results
        """
        domain = domain.lower().strip()

        # Basic format check
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', domain):
            return {
                "domain": domain,
                "is_valid": False,
                "error": "Invalid domain format"
            }

        parts = domain.split('.')
        tld = parts[-1] if parts else ""

        # Check for suspicious TLDs
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'bit', 'onion', 'i2p', 'biz', 'cc', 'pw']
        is_suspicious_tld = tld in suspicious_tlds

        return {
            "domain": domain,
            "is_valid": True,
            "tld": tld,
            "subdomain_count": len(parts) - 2,
            "is_suspicious_tld": is_suspicious_tld,
            "length": len(domain),
            "has_numbers": bool(re.search(r'\d', domain)),
            "has_hyphens": '-' in domain
        }

    def validate_hash(self, hash_value: str) -> Dict[str, Any]:
        """
        Validate and identify hash type

        Args:
            hash_value: Hash to validate

        Returns:
            Hash validation results
        """
        hash_value = hash_value.strip().lower()

        # Remove common prefixes
        if hash_value.startswith('0x'):
            hash_value = hash_value[2:]

        hash_types = {
            32: 'MD5',
            40: 'SHA1',
            64: 'SHA256',
            128: 'SHA512'
        }

        # Check if it's a valid hex string
        if not re.match(r'^[a-f0-9]+$', hash_value):
            return {
                "hash": hash_value,
                "is_valid": False,
                "error": "Invalid hex format"
            }

        hash_length = len(hash_value)
        hash_type = hash_types.get(hash_length, "Unknown")

        return {
            "hash": hash_value,
            "is_valid": hash_type != "Unknown",
            "type": hash_type,
            "length": hash_length,
            "uppercase": hash_value.upper()
        }

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL for suspicious characteristics

        Args:
            url: URL to analyze

        Returns:
            URL analysis results
        """
        try:
            parsed = urlparse(url)

            # Extract components
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            path = parsed.path
            query = parsed.query
            fragment = parsed.fragment

            # Analyze domain
            domain_analysis = self.validate_domain(netloc) if netloc else {}

            # Suspicious characteristics
            suspicious_indicators = []

            if scheme not in ['http', 'https']:
                suspicious_indicators.append(f"Unusual scheme: {scheme}")

            if len(url) > 200:
                suspicious_indicators.append("Unusually long URL")

            if url.count('.') > 5:
                suspicious_indicators.append("Many subdomains")

            if re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', netloc):
                suspicious_indicators.append("IP address instead of domain")

            if re.search(r'[a-fA-F0-9]{8,}', netloc):
                suspicious_indicators.append("Hex-like domain")

            if query and len(query) > 100:
                suspicious_indicators.append("Long query string")

            return {
                "url": url,
                "is_valid": True,
                "scheme": scheme,
                "domain": netloc,
                "path": path,
                "query": query,
                "fragment": fragment,
                "domain_analysis": domain_analysis,
                "suspicious_indicators": suspicious_indicators,
                "risk_score": len(suspicious_indicators)
            }

        except Exception as e:
            return {
                "url": url,
                "is_valid": False,
                "error": str(e)
            }

    def _validate_ipv4_addresses(self, ips: List[str]) -> List[str]:
        """Validate IPv4 addresses and remove invalid ones"""
        valid_ips = []
        for ip in ips:
            try:
                ipaddress.IPv4Address(ip)
                valid_ips.append(ip)
            except ipaddress.AddressValueError:
                pass
        return valid_ips

    def _is_private_ip(self, ip_address: str) -> bool:
        """Check if IP address is private"""
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            return ip_obj.is_private
        except ValueError:
            return False


# Convenience functions
def extract_iocs(text: str) -> Dict[str, List[str]]:
    """Extract all IOCs from text"""
    checker = RegexChecker()
    return checker.extract_all_iocs(text)


def check_pattern(text: str, pattern_name: str) -> List[str]:
    """Check text against specific pattern"""
    checker = RegexChecker()
    return checker.check_pattern(text, pattern_name)


def validate_ip(ip_address: str) -> Dict[str, Any]:
    """Validate IP address"""
    checker = RegexChecker()
    return checker.validate_ip(ip_address)


def validate_domain(domain: str) -> Dict[str, Any]:
    """Validate domain"""
    checker = RegexChecker()
    return checker.validate_domain(domain)


def validate_hash(hash_value: str) -> Dict[str, Any]:
    """Validate hash"""
    checker = RegexChecker()
    return checker.validate_hash(hash_value)


def analyze_url(url: str) -> Dict[str, Any]:
    """Analyze URL"""
    checker = RegexChecker()
    return checker.analyze_url(url)