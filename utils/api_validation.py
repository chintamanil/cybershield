# API key validation and health check utilities
import os
import asyncio
from typing import Dict, Any, Optional
from utils.logging_config import get_security_logger

logger = get_security_logger("api_validation")


class APIKeyValidator:
    """Validate and test API keys for external services"""
    
    def __init__(self):
        self.api_keys = {
            "virustotal": os.getenv("VIRUSTOTAL_API_KEY"),
            "shodan": os.getenv("SHODAN_API_KEY"), 
            "abuseipdb": os.getenv("ABUSEIPDB_API_KEY"),
            "openai": os.getenv("OPENAI_API_KEY")
        }
    
    def check_api_keys(self) -> Dict[str, Any]:
        """Check which API keys are configured"""
        status = {}
        
        for service, key in self.api_keys.items():
            if key and key != "your_api_key_here" and len(key) > 10:
                status[service] = {
                    "configured": True,
                    "key_length": len(key),
                    "key_prefix": key[:8] + "..." if len(key) > 8 else "short"
                }
            else:
                status[service] = {
                    "configured": False,
                    "reason": "missing or placeholder key"
                }
        
        return status
    
    async def test_api_connections(self) -> Dict[str, Any]:
        """Test actual API connections"""
        results = {}
        
        # Test VirusTotal
        if self.api_keys["virustotal"]:
            results["virustotal"] = await self._test_virustotal()
        else:
            results["virustotal"] = {"status": "not_configured"}
        
        # Test Shodan
        if self.api_keys["shodan"]:
            results["shodan"] = await self._test_shodan()
        else:
            results["shodan"] = {"status": "not_configured"}
        
        # Test AbuseIPDB
        if self.api_keys["abuseipdb"]:
            results["abuseipdb"] = await self._test_abuseipdb()
        else:
            results["abuseipdb"] = {"status": "not_configured"}
        
        # Test OpenAI
        if self.api_keys["openai"]:
            results["openai"] = await self._test_openai()
        else:
            results["openai"] = {"status": "not_configured"}
        
        return results
    
    async def _test_virustotal(self) -> Dict[str, Any]:
        """Test VirusTotal API connection"""
        try:
            from tools.virustotal import VirusTotalClient
            
            async with VirusTotalClient(self.api_keys["virustotal"]) as vt:
                # Test with a known clean IP (Google DNS)
                result = await vt.lookup_ip("8.8.8.8")
                
                if "error" in result:
                    return {
                        "status": "error",
                        "error": result["error"],
                        "recommendation": "Check API key validity"
                    }
                else:
                    return {
                        "status": "success",
                        "message": "VirusTotal API is working",
                        "test_result": "IP lookup successful"
                    }
                    
        except Exception as e:
            return {
                "status": "error", 
                "error": str(e),
                "recommendation": "Check API key and network connectivity"
            }
    
    async def _test_shodan(self) -> Dict[str, Any]:
        """Test Shodan API connection"""
        try:
            from tools.shodan import ShodanClient
            
            async with ShodanClient(self.api_keys["shodan"]) as shodan:
                # Test with account info endpoint
                result = await shodan.get_account_info()
                
                if "error" in result:
                    return {
                        "status": "error",
                        "error": result["error"],
                        "recommendation": "Check API key validity"
                    }
                else:
                    return {
                        "status": "success",
                        "message": "Shodan API is working",
                        "credits": result.get("query_credits", "unknown")
                    }
                    
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "recommendation": "Check API key and network connectivity"
            }
    
    async def _test_abuseipdb(self) -> Dict[str, Any]:
        """Test AbuseIPDB API connection"""
        try:
            from tools.abuseipdb import AbuseIPDBClient
            
            async with AbuseIPDBClient(self.api_keys["abuseipdb"]) as abuse:
                # Test with a known clean IP (Google DNS)
                result = await abuse.check_ip("8.8.8.8")
                
                if "error" in result:
                    return {
                        "status": "error",
                        "error": result["error"],
                        "recommendation": "Check API key validity"
                    }
                else:
                    return {
                        "status": "success",
                        "message": "AbuseIPDB API is working",
                        "test_result": "IP lookup successful"
                    }
                    
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "recommendation": "Check API key and network connectivity"
            }
    
    async def _test_openai(self) -> Dict[str, Any]:
        """Test OpenAI API connection"""
        try:
            from utils.service_factory import LLMFactory
            
            llm = LLMFactory.create_llm()
            
            # Test with a simple prompt
            response = await asyncio.to_thread(llm.invoke, "Hello")
            
            if response and hasattr(response, 'content'):
                return {
                    "status": "success",
                    "message": "OpenAI API is working",
                    "test_result": "Simple prompt successful"
                }
            else:
                return {
                    "status": "error",
                    "error": "Invalid response format",
                    "recommendation": "Check API key and model access"
                }
                
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "recommendation": "Check API key and model access"
            }
    
    def get_setup_recommendations(self, test_results: Dict[str, Any]) -> Dict[str, str]:
        """Get setup recommendations based on test results"""
        recommendations = {}
        
        for service, result in test_results.items():
            if result.get("status") == "not_configured":
                recommendations[service] = f"Add {service.upper()}_API_KEY to .env file"
            elif result.get("status") == "error":
                recommendations[service] = result.get("recommendation", "Check API configuration")
            else:
                recommendations[service] = "API is working correctly ✅"
        
        return recommendations


# Global validator instance
api_validator = APIKeyValidator()