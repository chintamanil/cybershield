# Environment configuration for dual local/AWS deployment
import os
import boto3
from typing import Dict, Any, Optional
from dataclasses import dataclass
from utils.logging_config import get_security_logger

logger = get_security_logger("environment_config")


@dataclass
class DatabaseConfig:
    """Database configuration for different environments"""
    host: str
    port: int
    database: str
    username: Optional[str] = None
    password: Optional[str] = None
    ssl_mode: str = "prefer"


@dataclass
class RedisConfig:
    """Redis configuration for different environments"""
    host: str
    port: int = 6379
    ssl: bool = False
    decode_responses: bool = True


@dataclass
class VectorStoreConfig:
    """Vector store configuration"""
    provider: str  # "milvus" or "opensearch"
    host: str
    port: int
    ssl: bool = False
    auth_required: bool = False


@dataclass
class LLMConfig:
    """LLM configuration"""
    provider: str  # "openai" or "bedrock"
    model_name: str
    api_key: Optional[str] = None
    region: Optional[str] = None


class EnvironmentDetector:
    """Detects current environment and provides appropriate configuration"""
    
    def __init__(self):
        self.environment = self._detect_environment()
        logger.info(f"Detected environment: {self.environment}")
    
    def _detect_environment(self) -> str:
        """Detect if running locally or on AWS"""
        
        # Check for AWS environment indicators
        if self._is_aws_environment():
            return "aws"
        
        # Check for explicit environment variable
        env = os.getenv("CYBERSHIELD_ENV", "local").lower()
        if env in ["aws", "cloud", "production"]:
            return "aws"
        elif env in ["local", "development", "dev"]:
            return "local"
        
        # Default to local
        return "local"
    
    def _is_aws_environment(self) -> bool:
        """Check various AWS environment indicators"""
        aws_indicators = [
            os.getenv("AWS_EXECUTION_ENV"),  # ECS/Lambda
            os.getenv("AWS_LAMBDA_FUNCTION_NAME"),  # Lambda
            os.getenv("ECS_CONTAINER_METADATA_URI"),  # ECS
            os.getenv("AWS_REGION"),  # General AWS
        ]
        
        # Check if we can access AWS metadata service (EC2/ECS)
        try:
            import requests
            response = requests.get(
                "http://169.254.169.254/latest/meta-data/instance-id",
                timeout=1
            )
            if response.status_code == 200:
                return True
        except:
            pass
        
        return any(indicator for indicator in aws_indicators)
    
    def is_local(self) -> bool:
        return self.environment == "local"
    
    def is_aws(self) -> bool:
        return self.environment == "aws"


class EnvironmentConfig:
    """Main configuration class that provides environment-specific settings"""
    
    def __init__(self):
        self.detector = EnvironmentDetector()
        self._load_config()
    
    def _load_config(self):
        """Load configuration based on detected environment"""
        if self.detector.is_local():
            self._load_local_config()
        else:
            self._load_aws_config()
    
    def _load_local_config(self):
        """Load local development configuration"""
        logger.info("Loading local development configuration")
        
        self.database = DatabaseConfig(
            host=os.getenv("POSTGRES_HOST", "localhost"),
            port=int(os.getenv("POSTGRES_PORT", "5432")),
            database=os.getenv("POSTGRES_DB", "cybershield"),
            username=os.getenv("POSTGRES_USER", "postgres"),
            password=os.getenv("POSTGRES_PASSWORD", "password")
        )
        
        self.redis = RedisConfig(
            host=os.getenv("REDIS_HOST", "localhost"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            ssl=False
        )
        
        self.vector_store = VectorStoreConfig(
            provider="milvus",
            host=os.getenv("MILVUS_HOST", "localhost"),
            port=int(os.getenv("MILVUS_PORT", "19530"))
        )
        
        self.llm = LLMConfig(
            provider="openai",
            model_name=os.getenv("OPENAI_MODEL", "gpt-4"),
            api_key=os.getenv("OPENAI_API_KEY")
        )
    
    def _load_aws_config(self):
        """Load AWS production configuration"""
        logger.info("Loading AWS production configuration")
        
        # Database configuration from AWS RDS
        self.database = DatabaseConfig(
            host=os.getenv("RDS_ENDPOINT", "cybershield-db.cluster-xxxxx.us-east-1.rds.amazonaws.com"),
            port=int(os.getenv("RDS_PORT", "5432")),
            database=os.getenv("RDS_DB_NAME", "cybershield"),
            ssl_mode="require"
            # Username/password loaded from Secrets Manager
        )
        
        # Redis configuration from AWS ElastiCache
        self.redis = RedisConfig(
            host=os.getenv("ELASTICACHE_ENDPOINT", "cybershield-cache.xxxxx.cache.amazonaws.com"),
            port=int(os.getenv("ELASTICACHE_PORT", "6379")),
            ssl=True
        )
        
        # Vector store configuration from AWS OpenSearch
        self.vector_store = VectorStoreConfig(
            provider="opensearch",
            host=os.getenv("OPENSEARCH_ENDPOINT", "search-cybershield-xxxxx.us-east-1.es.amazonaws.com"),
            port=443,
            ssl=True,
            auth_required=True
        )
        
        # LLM configuration for AWS Bedrock
        self.llm = LLMConfig(
            provider="bedrock",
            model_name=os.getenv("BEDROCK_MODEL", "anthropic.claude-3-5-sonnet-20241022-v2:0"),
            region=os.getenv("AWS_REGION", "us-east-1")
        )
    
    def get_api_keys(self) -> Dict[str, str]:
        """Get API keys based on environment"""
        if self.detector.is_local():
            return {
                "virustotal": os.getenv("VIRUSTOTAL_API_KEY"),
                "shodan": os.getenv("SHODAN_API_KEY"),
                "abuseipdb": os.getenv("ABUSEIPDB_API_KEY"),
                "openai": os.getenv("OPENAI_API_KEY")
            }
        else:
            # Load from AWS Secrets Manager
            return self._get_aws_secrets()
    
    def _get_aws_secrets(self) -> Dict[str, str]:
        """Load secrets from AWS Secrets Manager and Parameter Store"""
        secrets = {}
        
        try:
            import boto3
            import json
            
            # Load from Secrets Manager
            secrets_client = boto3.client('secretsmanager')
            secret_response = secrets_client.get_secret_value(
                SecretId='cybershield/api-keys'
            )
            secrets.update(json.loads(secret_response['SecretString']))
            
            # Load from Parameter Store for non-sensitive configs
            ssm_client = boto3.client('ssm')
            
            # Get configuration parameters
            config_params = [
                '/cybershield/config/log-level',
                '/cybershield/config/debug-mode',
                '/cybershield/config/max-workers'
            ]
            
            for param_name in config_params:
                try:
                    response = ssm_client.get_parameter(Name=param_name)
                    param_key = param_name.split('/')[-1].replace('-', '_').upper()
                    secrets[param_key] = response['Parameter']['Value']
                except ssm_client.exceptions.ParameterNotFound:
                    logger.debug(f"Parameter not found: {param_name}")
                except Exception as e:
                    logger.warning(f"Failed to get parameter {param_name}: {e}")
            
            return secrets
            
        except Exception as e:
            logger.error(f"Failed to load AWS secrets: {e}")
            return {}


# Global configuration instance
config = EnvironmentConfig()