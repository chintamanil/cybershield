# Application initializer with environment-aware setup
import asyncio
from typing import Dict, Any
from utils.environment_config import config
from utils.service_factory import services
from utils.logging_config import get_security_logger

logger = get_security_logger("app_initializer")


class ApplicationInitializer:
    """Initialize application services based on environment"""

    def __init__(self):
        self.environment = config.detector.environment
        self.services_initialized = False

    async def initialize_services(self) -> Dict[str, Any]:
        """Initialize all services based on current environment"""
        logger.info(f"Initializing services for {self.environment} environment")

        initialization_results = {}

        # Initialize Redis
        try:
            services.redis.ping()
            initialization_results["redis"] = {
                "status": "success",
                "host": config.redis.host,
            }
            logger.info(f"Redis initialized successfully at {config.redis.host}")
        except Exception as e:
            initialization_results["redis"] = {"status": "error", "error": str(e)}
            logger.error(f"Redis initialization failed: {e}")

        # Initialize PostgreSQL
        try:
            cursor = services.postgres.cursor()
            cursor.execute("SELECT version()")
            version = cursor.fetchone()[0]
            cursor.close()
            initialization_results["postgres"] = {
                "status": "success",
                "version": version,
            }
            logger.info(f"PostgreSQL initialized successfully")
        except Exception as e:
            initialization_results["postgres"] = {"status": "error", "error": str(e)}
            logger.error(f"PostgreSQL initialization failed: {e}")

        # Initialize Vector Store
        try:
            if config.vector_store.provider == "milvus":
                await services.vector_store.connect()
                initialization_results["vector_store"] = {
                    "status": "success",
                    "provider": "milvus",
                    "host": config.vector_store.host,
                }
            else:
                # OpenSearch initialization
                initialization_results["vector_store"] = {
                    "status": "success",
                    "provider": "opensearch",
                    "host": config.vector_store.host,
                }
            logger.info(
                f"Vector store ({config.vector_store.provider}) initialized successfully"
            )
        except Exception as e:
            initialization_results["vector_store"] = {
                "status": "error",
                "error": str(e),
            }
            logger.error(f"Vector store initialization failed: {e}")

        # Initialize LLM
        try:
            # Test LLM with a simple query
            response = await asyncio.to_thread(services.llm.invoke, "Test")
            initialization_results["llm"] = {
                "status": "success",
                "provider": config.llm.provider,
                "model": config.llm.model_name,
            }
            logger.info(f"LLM ({config.llm.provider}) initialized successfully")
        except Exception as e:
            initialization_results["llm"] = {"status": "error", "error": str(e)}
            logger.error(f"LLM initialization failed: {e}")

        # Initialize Security Tools
        api_keys = config.get_api_keys()
        tool_status = {}

        for tool_name, api_key in api_keys.items():
            if api_key:
                tool_status[tool_name] = "configured"
            else:
                tool_status[tool_name] = "missing_key"

        initialization_results["security_tools"] = tool_status

        self.services_initialized = True
        logger.info("Service initialization completed")

        return initialization_results

    def get_health_status(self) -> Dict[str, Any]:
        """Get current health status of all services"""
        if not self.services_initialized:
            return {"status": "not_initialized"}

        health_status = services.health_check()
        health_status["environment"] = self.environment
        health_status["config"] = {
            "llm_provider": config.llm.provider,
            "vector_store_provider": config.vector_store.provider,
            "redis_host": config.redis.host,
            "postgres_host": config.database.host,
        }

        return health_status

    def get_environment_info(self) -> Dict[str, Any]:
        """Get information about current environment configuration"""
        return {
            "environment": self.environment,
            "detection_method": (
                "automatic" if config.detector._is_aws_environment() else "manual"
            ),
            "services": {
                "database": {
                    "provider": (
                        "RDS" if config.detector.is_aws() else "Local PostgreSQL"
                    ),
                    "host": config.database.host,
                    "ssl_enabled": config.database.ssl_mode == "require",
                },
                "cache": {
                    "provider": (
                        "ElastiCache" if config.detector.is_aws() else "Local Redis"
                    ),
                    "host": config.redis.host,
                    "ssl_enabled": config.redis.ssl,
                },
                "vector_store": {
                    "provider": config.vector_store.provider,
                    "host": config.vector_store.host,
                    "ssl_enabled": config.vector_store.ssl,
                },
                "llm": {
                    "provider": config.llm.provider,
                    "model": config.llm.model_name,
                    "region": config.llm.region if config.llm.region else "N/A",
                },
            },
        }


# Global initializer instance
app_initializer = ApplicationInitializer()
