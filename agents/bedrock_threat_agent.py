"""
Enhanced Threat Agent using Fine-tuned Bedrock Models
Integrates custom cybersecurity models with existing CyberShield architecture
"""

import json
import boto3
import asyncio
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import logging
from datetime import datetime

# Import existing CyberShield components
from agents.threat_agent import ThreatAgent
from memory.redis_stm import RedisSTM
from utils.logging_config import get_security_logger

logger = get_security_logger("bedrock_threat_agent")

@dataclass
class BedrockModelConfig:
    """Configuration for Bedrock models"""
    base_model_id: str
    custom_model_arn: Optional[str] = None
    max_tokens: int = 1000
    temperature: float = 0.1
    top_p: float = 0.9

class BedrockThreatAgent(ThreatAgent):
    """Enhanced threat agent using fine-tuned Bedrock models"""
    
    def __init__(self, session_id: str, memory: RedisSTM, aws_region: str = "us-east-1"):
        super().__init__(session_id, memory)
        
        self.bedrock_runtime = boto3.client('bedrock-runtime', region_name=aws_region)
        self.aws_region = aws_region
        
        # Model configurations
        self.models = {
            "threat_classifier": BedrockModelConfig(
                base_model_id="anthropic.claude-3-haiku-20240307-v1:0",
                custom_model_arn=None,  # Will be set when custom model is available
                max_tokens=500,
                temperature=0.1
            ),
            "ioc_extractor": BedrockModelConfig(
                base_model_id="anthropic.claude-3-haiku-20240307-v1:0", 
                custom_model_arn=None,
                max_tokens=800,
                temperature=0.0
            ),
            "risk_assessor": BedrockModelConfig(
                base_model_id="anthropic.claude-3-sonnet-20240229-v1:0",
                max_tokens=1000,
                temperature=0.2
            )
        }
        
    async def set_custom_model(self, model_type: str, custom_model_arn: str):
        """Set custom fine-tuned model for specific tasks"""
        if model_type in self.models:
            self.models[model_type].custom_model_arn = custom_model_arn
            logger.info(f"Set custom model for {model_type}: {custom_model_arn}")
        else:
            raise ValueError(f"Unknown model type: {model_type}")

    async def invoke_bedrock_model(
        self, 
        model_type: str, 
        prompt: str, 
        context: Dict[str, Any] = None
    ) -> str:
        """Invoke Bedrock model with caching"""
        
        # Check cache first
        cache_key = f"bedrock:{model_type}:{hash(prompt)}"
        cached_result = await self.memory.get(cache_key)
        
        if cached_result:
            logger.info(f"Cache hit for {model_type} model")
            return cached_result
        
        # Get model configuration
        if model_type not in self.models:
            raise ValueError(f"Unknown model type: {model_type}")
        
        config = self.models[model_type]
        
        # Use custom model if available, otherwise base model
        model_id = config.custom_model_arn or config.base_model_id
        
        # Prepare the request
        request_body = {
            "anthropic_version": "bedrock-2023-05-31",
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "max_tokens": config.max_tokens,
            "temperature": config.temperature,
            "top_p": config.top_p
        }
        
        try:
            logger.info(f"Invoking {model_type} model: {model_id}")
            
            response = self.bedrock_runtime.invoke_model(
                modelId=model_id,
                body=json.dumps(request_body)
            )
            
            response_body = json.loads(response['body'].read())
            content = response_body['content'][0]['text']
            
            # Cache the result (30 minutes for model responses)
            await self.memory.set(cache_key, content, ttl=1800)
            
            logger.info(f"Successfully invoked {model_type} model")
            return content
            
        except Exception as e:
            logger.error(f"Failed to invoke {model_type} model: {e}")
            # Fallback to parent class implementation
            return await super().analyze_threat(prompt)

    async def analyze_threat_with_bedrock(self, ioc_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced threat analysis using fine-tuned Bedrock models"""
        
        logger.info(f"Starting Bedrock threat analysis for {len(ioc_data)} IOCs")
        
        # Step 1: Classify threats using custom model
        classification_prompt = self._create_classification_prompt(ioc_data)
        classification = await self.invoke_bedrock_model(
            "threat_classifier", 
            classification_prompt
        )
        
        # Step 2: Extract additional IOCs using custom model
        ioc_extraction_prompt = self._create_ioc_extraction_prompt(ioc_data)
        additional_iocs = await self.invoke_bedrock_model(
            "ioc_extractor",
            ioc_extraction_prompt
        )
        
        # Step 3: Comprehensive risk assessment
        risk_assessment_prompt = self._create_risk_assessment_prompt(ioc_data, classification)
        risk_assessment = await self.invoke_bedrock_model(
            "risk_assessor",
            risk_assessment_prompt
        )
        
        # Step 4: Combine with traditional threat intelligence
        traditional_analysis = await super().analyze_threat(ioc_data)
        
        # Step 5: Synthesize results
        enhanced_analysis = {
            "bedrock_classification": classification,
            "additional_iocs": additional_iocs,
            "bedrock_risk_assessment": risk_assessment,
            "traditional_analysis": traditional_analysis,
            "synthesis": await self._synthesize_analysis(
                classification, risk_assessment, traditional_analysis
            ),
            "confidence_score": self._calculate_confidence_score(
                classification, traditional_analysis
            ),
            "timestamp": datetime.utcnow().isoformat(),
            "model_versions": {
                model_type: config.custom_model_arn or config.base_model_id 
                for model_type, config in self.models.items()
            }
        }
        
        logger.info("Bedrock threat analysis completed")
        return enhanced_analysis

    def _create_classification_prompt(self, ioc_data: Dict[str, Any]) -> str:
        """Create classification prompt for fine-tuned model"""
        
        iocs = []
        for key, values in ioc_data.items():
            if isinstance(values, list):
                for value in values:
                    iocs.append(f"{key.upper()}: {value}")
            else:
                iocs.append(f"{key.upper()}: {values}")
        
        return f"""Analyze the following cybersecurity indicators and classify the threat:

Indicators of Compromise (IOCs):
{chr(10).join(iocs)}

Classify this threat and provide:
1. Primary threat category
2. Attack vector analysis  
3. Severity level (1-10)
4. Immediate actions required
5. IOC confidence assessment"""

    def _create_ioc_extraction_prompt(self, ioc_data: Dict[str, Any]) -> str:
        """Create IOC extraction prompt"""
        
        context = json.dumps(ioc_data, indent=2)
        
        return f"""Given the following cybersecurity context, identify any additional IOCs that might be related:

Current IOCs:
{context}

Extract and identify:
1. Related IP addresses or subnets
2. Associated domains or subdomains  
3. Similar file hashes or signatures
4. Related email addresses or accounts
5. Infrastructure patterns
6. Attack campaign indicators

Provide specific, actionable IOCs with confidence levels."""

    def _create_risk_assessment_prompt(
        self, 
        ioc_data: Dict[str, Any], 
        classification: str
    ) -> str:
        """Create comprehensive risk assessment prompt"""
        
        return f"""Conduct a comprehensive cybersecurity risk assessment:

IOC Data: {json.dumps(ioc_data, indent=2)}

Threat Classification: {classification}

Provide detailed analysis of:
1. Business impact assessment (1-10 scale)
2. Technical impact on infrastructure
3. Data exposure risk
4. Lateral movement potential
5. Persistence mechanisms
6. Recommended containment strategy
7. Recovery timeline estimate
8. Lessons learned and prevention

Focus on actionable intelligence for security operations team."""

    async def _synthesize_analysis(
        self, 
        bedrock_classification: str, 
        bedrock_risk: str, 
        traditional_analysis: Dict[str, Any]
    ) -> str:
        """Synthesize Bedrock and traditional analysis"""
        
        synthesis_prompt = f"""Synthesize the following cybersecurity analysis results:

Bedrock AI Classification:
{bedrock_classification}

Bedrock Risk Assessment:
{bedrock_risk}

Traditional Threat Intelligence:
{json.dumps(traditional_analysis, indent=2)}

Provide a unified executive summary with:
1. Consolidated threat assessment
2. Confidence level in findings
3. Priority recommendations
4. Resource allocation suggestions
5. Timeline for response actions"""

        return await self.invoke_bedrock_model("risk_assessor", synthesis_prompt)

    def _calculate_confidence_score(
        self, 
        bedrock_analysis: str, 
        traditional_analysis: Dict[str, Any]
    ) -> float:
        """Calculate confidence score for analysis"""
        
        confidence = 0.5  # Base confidence
        
        # Boost confidence if multiple sources agree
        traditional_threats = traditional_analysis.get('threat_intelligence', [])
        if len(traditional_threats) > 0:
            confidence += 0.2
        
        # Boost if IOCs are well-known
        if 'high confidence' in bedrock_analysis.lower():
            confidence += 0.2
            
        if 'known threat' in bedrock_analysis.lower():
            confidence += 0.1
            
        return min(confidence, 0.95)

    async def batch_analyze_threats(self, ioc_batch: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze multiple threats in parallel using Bedrock"""
        
        logger.info(f"Starting batch analysis of {len(ioc_batch)} threats")
        
        # Process in parallel with concurrency limit
        semaphore = asyncio.Semaphore(5)  # Limit concurrent requests
        
        async def analyze_single(ioc_data):
            async with semaphore:
                return await self.analyze_threat_with_bedrock(ioc_data)
        
        results = await asyncio.gather(*[
            analyze_single(ioc_data) for ioc_data in ioc_batch
        ])
        
        logger.info(f"Completed batch analysis of {len(results)} threats")
        return results

    async def get_model_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics for Bedrock models"""
        
        metrics = {
            "cache_hit_rate": await self._calculate_cache_hit_rate(),
            "average_response_time": await self._calculate_avg_response_time(),
            "model_versions": {
                model_type: config.custom_model_arn or config.base_model_id 
                for model_type, config in self.models.items()
            },
            "total_requests": await self._get_total_requests(),
            "error_rate": await self._calculate_error_rate()
        }
        
        return metrics

    async def _calculate_cache_hit_rate(self) -> float:
        """Calculate cache hit rate for Bedrock models"""
        # Implementation depends on Redis metrics
        return 0.75  # Placeholder

    async def _calculate_avg_response_time(self) -> float:
        """Calculate average response time for Bedrock models"""
        # Implementation depends on performance tracking
        return 0.45  # Placeholder (450ms)

    async def _get_total_requests(self) -> int:
        """Get total number of requests to Bedrock models"""
        # Implementation depends on metrics tracking
        return 1000  # Placeholder

    async def _calculate_error_rate(self) -> float:
        """Calculate error rate for Bedrock models"""
        # Implementation depends on error tracking
        return 0.02  # Placeholder (2% error rate)

# Usage example
async def main():
    """Example usage of Bedrock threat agent"""
    from memory.redis_stm import RedisSTM
    
    # Initialize memory and agent
    memory = RedisSTM()
    agent = BedrockThreatAgent("test_session", memory)
    
    # Set custom model (when available)
    # await agent.set_custom_model("threat_classifier", "arn:aws:bedrock:us-east-1:123456789012:custom-model/cybershield-security-analyst-v1")
    
    # Test threat analysis
    test_iocs = {
        "ips": ["203.0.113.42", "198.51.100.5"],
        "domains": ["malware-c2.example.com"],
        "hashes": ["d41d8cd98f00b204e9800998ecf8427e"]
    }
    
    result = await agent.analyze_threat_with_bedrock(test_iocs)
    print("Bedrock Analysis Result:")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    asyncio.run(main())