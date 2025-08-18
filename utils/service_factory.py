# Service factory for creating environment-specific service instances
import redis
import psycopg2
from typing import Optional, Dict, Any
from utils.environment_config import config
from utils.logging_config import get_security_logger

logger = get_security_logger("service_factory")


class DatabaseFactory:
    """Factory for creating database connections based on environment"""

    @staticmethod
    def create_postgres_connection():
        """Create PostgreSQL connection for current environment"""
        db_config = config.database

        if config.detector.is_aws():
            # Use AWS RDS with credentials from Secrets Manager
            creds = DatabaseFactory._get_rds_credentials()
            return psycopg2.connect(
                host=db_config.host,
                port=db_config.port,
                database=db_config.database,
                user=creds["username"],
                password=creds["password"],
                sslmode=db_config.ssl_mode,
            )
        else:
            # Use local PostgreSQL
            return psycopg2.connect(
                host=db_config.host,
                port=db_config.port,
                database=db_config.database,
                user=db_config.username,
                password=db_config.password,
                sslmode=db_config.ssl_mode,
            )

    @staticmethod
    def _get_rds_credentials() -> Dict[str, str]:
        """Get RDS credentials from AWS Secrets Manager"""
        try:
            import boto3
            import json

            secrets_client = boto3.client("secretsmanager")
            secret_response = secrets_client.get_secret_value(
                SecretId="cybershield/rds/credentials"
            )
            return json.loads(secret_response["SecretString"])
        except Exception as e:
            logger.error(f"Failed to get RDS credentials: {e}")
            raise


class RedisFactory:
    """Factory for creating Redis connections based on environment"""

    @staticmethod
    def create_redis_connection():
        """Create Redis connection for current environment"""
        redis_config = config.redis

        logger.info(
            f"Creating Redis connection to {redis_config.host}:{redis_config.port}"
        )

        return redis.Redis(
            host=redis_config.host,
            port=redis_config.port,
            ssl=redis_config.ssl,
            decode_responses=redis_config.decode_responses,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
        )


class LLMFactory:
    """Factory for creating LLM instances based on environment"""

    @staticmethod
    def create_llm():
        """Create LLM instance for current environment"""
        llm_config = config.llm

        if llm_config.provider == "openai":
            from langchain_openai import ChatOpenAI

            logger.info("Creating OpenAI LLM client")
            return ChatOpenAI(
                model=llm_config.model_name,
                api_key=llm_config.api_key,
                temperature=0.1,
                max_tokens=4000,
            )

        elif llm_config.provider == "bedrock":
            from langchain_aws import ChatBedrock
            import boto3

            logger.info("Creating Bedrock LLM client")
            bedrock_client = boto3.client(
                service_name="bedrock-runtime", region_name=llm_config.region
            )

            return ChatBedrock(
                client=bedrock_client,
                model_id=llm_config.model_name,
                model_kwargs={"max_tokens": 4000, "temperature": 0.1, "top_p": 0.9},
            )

        else:
            raise ValueError(f"Unsupported LLM provider: {llm_config.provider}")

    @staticmethod
    def create_embeddings():
        """Create embeddings model for current environment"""
        llm_config = config.llm

        if llm_config.provider == "openai":
            from langchain_openai import OpenAIEmbeddings

            logger.info("Creating OpenAI embeddings")
            return OpenAIEmbeddings(
                api_key=llm_config.api_key, model="text-embedding-ada-002"
            )

        elif llm_config.provider == "bedrock":
            from langchain_aws import BedrockEmbeddings
            import boto3

            logger.info("Creating Bedrock embeddings")
            bedrock_client = boto3.client(
                service_name="bedrock-runtime", region_name=llm_config.region
            )

            return BedrockEmbeddings(
                client=bedrock_client, model_id="amazon.titan-embed-text-v1"
            )

        else:
            raise ValueError(f"Unsupported embeddings provider: {llm_config.provider}")


class VectorStoreFactory:
    """Factory for creating vector store instances based on environment"""

    @staticmethod
    def create_vector_store():
        """Create vector store instance for current environment"""
        vs_config = config.vector_store

        if vs_config.provider == "milvus":
            from vectorstore.milvus_vector_store import MilvusVectorStore

            logger.info("Creating Milvus vector store")
            return MilvusVectorStore(
                collection_name="cybersecurity_attacks",
                host=vs_config.host,
                port=str(vs_config.port),
            )

        elif vs_config.provider == "opensearch":
            from vectorstore.opensearch_vector_store import OpenSearchVectorStore

            logger.info("Creating OpenSearch vector store")
            return OpenSearchVectorStore(
                collection_name="cybersecurity_attacks",
                host=vs_config.host,
                port=vs_config.port,
            )

        else:
            raise ValueError(f"Unsupported vector store provider: {vs_config.provider}")


# Remove the old OpenSearchVectorStore class since it's now in opensearch_vector_store.py


class ServiceManager:
    """Centralized service manager for the application"""

    def __init__(self):
        self._redis = None
        self._postgres = None
        self._llm = None
        self._embeddings = None
        self._vector_store = None

        logger.info(
            f"ServiceManager initialized for {config.detector.environment} environment"
        )

    @property
    def redis(self):
        """Lazy-loaded Redis connection"""
        if self._redis is None:
            self._redis = RedisFactory.create_redis_connection()
        return self._redis

    @property
    def postgres(self):
        """Lazy-loaded PostgreSQL connection"""
        if self._postgres is None:
            self._postgres = DatabaseFactory.create_postgres_connection()
        return self._postgres

    @property
    def llm(self):
        """Lazy-loaded LLM instance"""
        if self._llm is None:
            self._llm = LLMFactory.create_llm()
        return self._llm

    @property
    def embeddings(self):
        """Lazy-loaded embeddings model"""
        if self._embeddings is None:
            self._embeddings = LLMFactory.create_embeddings()
        return self._embeddings

    @property
    def vector_store(self):
        """Lazy-loaded vector store"""
        if self._vector_store is None:
            self._vector_store = VectorStoreFactory.create_vector_store()
        return self._vector_store

    def health_check(self) -> Dict[str, bool]:
        """Check health of all services"""
        health = {}

        try:
            self.redis.ping()
            health["redis"] = True
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            health["redis"] = False

        try:
            self.postgres.cursor().execute("SELECT 1")
            health["postgres"] = True
        except Exception as e:
            logger.error(f"PostgreSQL health check failed: {e}")
            health["postgres"] = False

        try:
            # Simple LLM test
            response = self.llm.invoke("Test")
            health["llm"] = True
        except Exception as e:
            logger.error(f"LLM health check failed: {e}")
            health["llm"] = False

        health["vector_store"] = True  # Assume healthy for now

        return health


# Global service manager instance
services = ServiceManager()
