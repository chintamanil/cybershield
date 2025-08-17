"""
Bedrock Fine-tuning Manager for CyberShield
Manages the complete fine-tuning lifecycle
"""

import boto3
import json
import time
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime
import asyncio

logger = logging.getLogger(__name__)

@dataclass
class FineTuningConfig:
    """Configuration for fine-tuning job"""
    model_name: str
    base_model_id: str
    training_data_uri: str
    validation_data_uri: str
    output_model_name: str
    hyperparameters: Dict[str, Any]
    training_role_arn: str

class BedrockFineTuningManager:
    """Manages Bedrock fine-tuning jobs for CyberShield"""
    
    def __init__(self, aws_region: str = "us-east-1"):
        self.bedrock_client = boto3.client('bedrock', region_name=aws_region)
        self.aws_region = aws_region
        
    async def create_fine_tuning_job(self, config: FineTuningConfig) -> str:
        """Create a new fine-tuning job"""
        
        job_name = f"{config.model_name}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        try:
            response = self.bedrock_client.create_model_customization_job(
                jobName=job_name,
                customModelName=config.output_model_name,
                roleArn=config.training_role_arn,
                baseModelIdentifier=config.base_model_id,
                trainingDataConfig={
                    's3Uri': config.training_data_uri
                },
                validationDataConfig={
                    's3Uri': config.validation_data_uri
                },
                hyperParameters=config.hyperparameters,
                outputDataConfig={
                    's3Uri': f"s3://cybershield-bedrock-models/outputs/{job_name}/"
                },
                tags=[
                    {
                        'key': 'Project',
                        'value': 'CyberShield'
                    },
                    {
                        'key': 'Environment', 
                        'value': 'production'
                    },
                    {
                        'key': 'ModelType',
                        'value': 'cybersecurity-specialist'
                    }
                ]
            )
            
            job_arn = response['jobArn']
            logger.info(f"Fine-tuning job created: {job_name} (ARN: {job_arn})")
            return job_arn
            
        except Exception as e:
            logger.error(f"Failed to create fine-tuning job: {e}")
            raise

    async def monitor_training_job(self, job_arn: str) -> Dict[str, Any]:
        """Monitor fine-tuning job progress"""
        
        while True:
            try:
                response = self.bedrock_client.get_model_customization_job(
                    jobIdentifier=job_arn
                )
                
                status = response['status']
                job_name = response['jobName']
                
                logger.info(f"Job {job_name} status: {status}")
                
                if status == 'Completed':
                    logger.info(f"Fine-tuning completed successfully!")
                    return {
                        'status': 'completed',
                        'model_arn': response.get('outputModelArn'),
                        'job_details': response
                    }
                elif status == 'Failed':
                    logger.error(f"Fine-tuning failed: {response.get('failureMessage')}")
                    return {
                        'status': 'failed',
                        'error': response.get('failureMessage'),
                        'job_details': response
                    }
                elif status in ['InProgress', 'Stopping']:
                    # Check progress metrics if available
                    if 'trainingMetrics' in response:
                        metrics = response['trainingMetrics']
                        logger.info(f"Training metrics: {metrics}")
                    
                    await asyncio.sleep(300)  # Check every 5 minutes
                else:
                    logger.info(f"Job status: {status}, waiting...")
                    await asyncio.sleep(60)  # Check every minute
                    
            except Exception as e:
                logger.error(f"Error monitoring job: {e}")
                await asyncio.sleep(60)

    def get_recommended_hyperparameters(self, model_type: str, dataset_size: int) -> Dict[str, Any]:
        """Get recommended hyperparameters for CyberShield models"""
        
        base_params = {
            "epochCount": "3",
            "batchSize": "1", 
            "learningRate": "0.0001",
            "learningRateWarmupSteps": "0"
        }
        
        # Adjust based on dataset size
        if dataset_size < 100:
            base_params["epochCount"] = "5"
            base_params["learningRate"] = "0.0002"
        elif dataset_size > 1000:
            base_params["epochCount"] = "2"
            base_params["batchSize"] = "2"
        
        # Model-specific adjustments
        if model_type == "claude-3-haiku":
            base_params["learningRate"] = "0.00005"  # Lower for Claude
        elif model_type == "titan":
            base_params["batchSize"] = "4"  # Titan can handle larger batches
        
        return base_params

    async def create_cybersecurity_specialist_model(self) -> str:
        """Create a fine-tuned cybersecurity specialist model"""
        
        config = FineTuningConfig(
            model_name="cybershield-security-analyst",
            base_model_id="anthropic.claude-3-haiku-20240307-v1:0",  # Most cost-effective
            training_data_uri="s3://cybershield-bedrock-training/training-data/cybershield_train.jsonl",
            validation_data_uri="s3://cybershield-bedrock-training/training-data/cybershield_validation.jsonl",
            output_model_name="cybershield-security-analyst-v1",
            hyperparameters=self.get_recommended_hyperparameters("claude-3-haiku", 1000),
            training_role_arn="arn:aws:iam::ACCOUNT:role/cybershield-bedrock-finetuning"
        )
        
        # Create fine-tuning job
        job_arn = await self.create_fine_tuning_job(config)
        
        # Monitor progress
        result = await self.monitor_training_job(job_arn)
        
        if result['status'] == 'completed':
            model_arn = result['model_arn']
            logger.info(f"Cybersecurity specialist model ready: {model_arn}")
            
            # Test the model
            await self.test_fine_tuned_model(model_arn)
            
            return model_arn
        else:
            raise Exception(f"Fine-tuning failed: {result.get('error')}")

    async def test_fine_tuned_model(self, model_arn: str):
        """Test the fine-tuned model with cybersecurity scenarios"""
        
        bedrock_runtime = boto3.client('bedrock-runtime', region_name=self.aws_region)
        
        test_cases = [
            {
                "prompt": "Analyze this security incident: Failed login from 203.0.113.42 for user admin",
                "expected_keywords": ["threat", "risk", "block", "investigate"]
            },
            {
                "prompt": "Extract IOCs from: Malware hash d41d8cd98f00b204e9800998ecf8427e found on host 192.168.1.100",
                "expected_keywords": ["hash", "IOC", "malware", "host"]
            }
        ]
        
        logger.info("Testing fine-tuned model...")
        
        for i, test_case in enumerate(test_cases):
            try:
                response = bedrock_runtime.invoke_model(
                    modelId=model_arn,
                    body=json.dumps({
                        "anthropic_version": "bedrock-2023-05-31",
                        "messages": [
                            {
                                "role": "user",
                                "content": test_case["prompt"]
                            }
                        ],
                        "max_tokens": 500
                    })
                )
                
                response_body = json.loads(response['body'].read())
                content = response_body['content'][0]['text']
                
                logger.info(f"Test {i+1} Response: {content[:200]}...")
                
                # Check if expected keywords are present
                found_keywords = sum(1 for keyword in test_case["expected_keywords"] 
                                   if keyword.lower() in content.lower())
                
                logger.info(f"Test {i+1} Keywords found: {found_keywords}/{len(test_case['expected_keywords'])}")
                
            except Exception as e:
                logger.error(f"Test {i+1} failed: {e}")

    async def list_custom_models(self) -> List[Dict[str, Any]]:
        """List all custom models"""
        try:
            response = self.bedrock_client.list_custom_models()
            models = response.get('modelSummaries', [])
            
            logger.info(f"Found {len(models)} custom models")
            for model in models:
                logger.info(f"  - {model['modelName']} ({model['modelArn']})")
            
            return models
        except Exception as e:
            logger.error(f"Failed to list custom models: {e}")
            return []

    async def delete_custom_model(self, model_identifier: str):
        """Delete a custom model"""
        try:
            self.bedrock_client.delete_custom_model(
                modelIdentifier=model_identifier
            )
            logger.info(f"Deleted custom model: {model_identifier}")
        except Exception as e:
            logger.error(f"Failed to delete model {model_identifier}: {e}")
            raise

# Usage example
async def main():
    """Example usage of fine-tuning manager"""
    manager = BedrockFineTuningManager()
    
    # List existing models
    await manager.list_custom_models()
    
    # Create new cybersecurity specialist model
    try:
        model_arn = await manager.create_cybersecurity_specialist_model()
        print(f"Successfully created cybersecurity specialist model: {model_arn}")
    except Exception as e:
        print(f"Fine-tuning failed: {e}")

if __name__ == "__main__":
    asyncio.run(main())