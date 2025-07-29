# LogParserAgent extracts IOCs from structured and unstructured logs
import re
import json
from typing import Dict, List, Any
from datetime import datetime
from utils.logging_config import get_security_logger

logger = get_security_logger("log_parser")

class LogParserAgent:
    """Enhanced log parser for extracting IOCs from various log formats"""

    def __init__(self, memory=None, session_id=None):
        self.memory = memory  # Optional Redis STM
        self.session_id = session_id  # Optional session binding
        
        # Comprehensive IOC patterns
        self.patterns = {
            'ipv4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b',
            'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            'port': r'\b(?:port|Port|PORT)\s*[=:]\s*(\d{1,5})\b',
            'protocol': r'\b(?:protocol|Protocol|PROTOCOL)\s*[=:]\s*([A-Za-z]+)\b',
            'username': r'\b(?:user|User|USER|username|Username|USERNAME)\s*[=:]\s*([a-zA-Z0-9._-]+)\b',
            'device': r'\b(?:device|Device|DEVICE|hostname|Hostname|HOSTNAME)\s*[=:]\s*([a-zA-Z0-9._-]+)\b',
            'url': r'https?://[^\s<>"{}|\\^`\[\]]+',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'mac_address': r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b',
            'timestamp': r'\b\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\b'
        }

        # Common log format patterns
        self.log_formats = {
            'key_value': r'(\w+)=([^\s]+)',
            'json': r'\{.*\}',
            'csv': r'([^,]+),([^,]+),([^,]+)',
            'syslog': r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+([^:]+):\s+(.*)$'
        }

    async def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """
        Extract IOCs from text using comprehensive patterns with memory caching

        Args:
            text: Input text/log entry

        Returns:
            Dictionary with extracted IOCs by type
        """
        logger.info(f"Extracting IOCs from text of length {len(text)}")

        # Check cache first if memory and session are available
        cache_key = None
        if self.memory and self.session_id:
            import hashlib
            text_hash = hashlib.md5(text.encode()).hexdigest()[:16]
            cache_key = f"iocs:{self.session_id}:{text_hash}"
            
            try:
                cached_result = await self.memory.get(cache_key)
                if cached_result:
                    logger.info(f"Retrieved cached IOCs for session {self.session_id}")
                    return json.loads(cached_result) if isinstance(cached_result, str) else cached_result
            except Exception as e:
                logger.warning(f"Cache retrieval failed: {e}")

        iocs = {}

        # Extract each IOC type
        for ioc_type, pattern in self.patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                # Handle both strings and tuples from regex groups
                unique_matches = []
                for match in matches:
                    if isinstance(match, tuple):
                        # Extract the first group if it's a tuple
                        if match[0]:
                            unique_matches.append(match[0].strip())
                    else:
                        # Direct string match
                        if match:
                            unique_matches.append(match.strip())

                # Remove duplicates and filter empty strings
                unique_matches = list(set([m for m in unique_matches if m]))
                if unique_matches:
                    iocs[ioc_type] = unique_matches

        # Enhanced extraction for structured logs
        structured_iocs = self._extract_structured_iocs(text)
        iocs.update(structured_iocs)

        # Clean up and validate results
        iocs = self._cleanup_iocs(iocs)

        # Cache results if memory and session are available
        if self.memory and self.session_id and cache_key:
            try:
                await self.memory.set(cache_key, iocs, ttl=3600)  # Cache for 1 hour
                logger.info(f"Cached IOC results for session {self.session_id}")
            except Exception as e:
                logger.warning(f"Cache storage failed: {e}")

        logger.info(f"Extracted {sum(len(v) for v in iocs.values())} IOCs across {len(iocs)} types")
        return iocs

    def _extract_structured_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extract IOCs from structured log formats"""
        structured_iocs = {}

        # Try to parse as JSON
        if re.match(self.log_formats['json'], text.strip()):
            try:
                json_data = json.loads(text)
                structured_iocs.update(self._extract_from_json(json_data))
            except json.JSONDecodeError:
                pass

        # Extract key-value pairs
        key_value_matches = re.findall(self.log_formats['key_value'], text)
        for key, value in key_value_matches:
            key_lower = key.lower()
            if any(ioc_type in key_lower for ioc_type in ['ip', 'src', 'dst', 'host']):
                if 'ip' not in structured_iocs:
                    structured_iocs['ip'] = []
                structured_iocs['ip'].append(value)
            elif any(ioc_type in key_lower for ioc_type in ['hash', 'md5', 'sha']):
                if 'hash' not in structured_iocs:
                    structured_iocs['hash'] = []
                structured_iocs['hash'].append(value)
            elif any(ioc_type in key_lower for ioc_type in ['port']):
                if 'port' not in structured_iocs:
                    structured_iocs['port'] = []
                structured_iocs['port'].append(value)
            elif any(ioc_type in key_lower for ioc_type in ['protocol', 'proto']):
                if 'protocol' not in structured_iocs:
                    structured_iocs['protocol'] = []
                structured_iocs['protocol'].append(value)

        return structured_iocs

    def _extract_from_json(self, json_data: Dict) -> Dict[str, List[str]]:
        """Extract IOCs from JSON structure"""
        iocs = {}

        def extract_from_dict(data, path=""):
            if isinstance(data, dict):
                for key, value in data.items():
                    current_path = f"{path}.{key}" if path else key
                    extract_from_dict(value, current_path)
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    current_path = f"{path}[{i}]"
                    extract_from_dict(item, current_path)
            elif isinstance(data, str):
                # Check if this string contains IOCs
                for ioc_type, pattern in self.patterns.items():
                    if re.search(pattern, data, re.IGNORECASE):
                        if ioc_type not in iocs:
                            iocs[ioc_type] = []
                        if data not in iocs[ioc_type]:
                            iocs[ioc_type].append(data)

        extract_from_dict(json_data)
        return iocs

    def _cleanup_iocs(self, iocs: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """Clean up and validate extracted IOCs"""
        cleaned = {}

        for ioc_type, values in iocs.items():
            if not values:
                continue

            # Remove duplicates and empty values
            unique_values = list(set([v.strip() for v in values if v.strip()]))

            # Validate based on type
            if ioc_type == 'ipv4':
                # Validate IP format
                valid_ips = [ip for ip in unique_values if self._is_valid_ip(ip)]
                if valid_ips:
                    cleaned['ips'] = valid_ips
            elif ioc_type in ['md5', 'sha1', 'sha256']:
                # Group all hashes
                if 'hashes' not in cleaned:
                    cleaned['hashes'] = []
                cleaned['hashes'].extend(unique_values)
            elif ioc_type == 'port':
                # Validate port numbers
                valid_ports = [port for port in unique_values if self._is_valid_port(port)]
                if valid_ports:
                    cleaned['ports'] = valid_ports
            else:
                cleaned[ioc_type] = unique_values

        return cleaned

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            return all(0 <= int(part) <= 255 for part in parts)
        except:
            return False

    def _is_valid_port(self, port: str) -> bool:
        """Validate port number"""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except:
            return False

    def parse_log_format(self, text: str) -> str:
        """Detect log format type"""
        if re.match(self.log_formats['json'], text.strip()):
            return 'json'
        elif re.search(self.log_formats['key_value'], text):
            return 'key_value'
        elif re.search(self.log_formats['syslog'], text):
            return 'syslog'
        else:
            return 'unstructured'

    async def extract_with_context(self, text: str) -> Dict[str, Any]:
        """Extract IOCs with additional context"""
        iocs = await self.extract_iocs(text)
        log_format = self.parse_log_format(text)

        return {
            'iocs': iocs,
            'log_format': log_format,
            'text_length': len(text),
            'extraction_timestamp': datetime.now().isoformat(),
            'summary': {
                'total_iocs': sum(len(v) for v in iocs.values()),
                'ioc_types': list(iocs.keys())
            }
        }

    async def get_session_iocs(self) -> Dict[str, List[str]]:
        """
        Retrieve all cached IOCs for the current session
        
        Returns:
            Dictionary with all IOCs found in this session
        """
        if not self.memory or not self.session_id:
            return {}
            
        try:
            session_key = f"session_iocs:{self.session_id}"
            cached_session_iocs = await self.memory.get(session_key)
            if cached_session_iocs:
                return cached_session_iocs if isinstance(cached_session_iocs, dict) else json.loads(cached_session_iocs)
        except Exception as e:
            logger.warning(f"Failed to retrieve session IOCs: {e}")
        
        return {}

    async def store_session_iocs(self, iocs: Dict[str, List[str]]) -> None:
        """
        Store IOCs at session level for cross-agent sharing
        
        Args:
            iocs: Dictionary of IOCs to store
        """
        if not self.memory or not self.session_id:
            return
            
        try:
            # Get existing session IOCs
            existing_iocs = await self.get_session_iocs()
            
            # Merge with new IOCs
            for ioc_type, ioc_list in iocs.items():
                if ioc_type in existing_iocs:
                    # Combine and deduplicate
                    combined = list(set(existing_iocs[ioc_type] + ioc_list))
                    existing_iocs[ioc_type] = combined
                else:
                    existing_iocs[ioc_type] = ioc_list
            
            # Store back to session
            session_key = f"session_iocs:{self.session_id}"
            await self.memory.set(session_key, existing_iocs, ttl=7200)  # 2 hours
            logger.info(f"Updated session IOCs for session {self.session_id}")
            
        except Exception as e:
            logger.warning(f"Failed to store session IOCs: {e}")

    async def clear_session_cache(self) -> None:
        """Clear all cached data for the current session"""
        if not self.memory or not self.session_id:
            return
            
        try:
            # Get all keys for this session
            session_key = f"session_iocs:{self.session_id}"
            
            # Clear session-specific caches
            await self.memory.delete(session_key)
            
            # For IOC cache keys with wildcards, get all matching keys
            pattern = f"iocs:{self.session_id}:*"
            all_keys = await self.memory.get_all(pattern)
            for key in all_keys.keys():
                await self.memory.delete(key)
            
            logger.info(f"Cleared cache for session {self.session_id}")
            
        except Exception as e:
            logger.warning(f"Failed to clear session cache: {e}")
