# Temporal configuration and client setup for CyberShield
import os
import logging
from typing import Optional, Any
from dataclasses import dataclass

# Conditional imports to handle missing temporalio dependency
try:
    from temporalio.client import Client, TLSConfig
    from temporalio.worker import Worker
    from temporalio.runtime import PrometheusConfig, Runtime, TelemetryConfig
    _temporal_available = True
except ImportError:
    # Create placeholder classes when temporalio is not available
    Client = None
    TLSConfig = None
    Worker = None
    PrometheusConfig = None
    Runtime = None
    TelemetryConfig = None
    _temporal_available = False

from utils.logging_config import get_security_logger

logger = get_security_logger("temporal_config")


@dataclass
class TemporalConfig:
    """Configuration for Temporal client and worker"""
    # Connection settings
    target_host: str = "localhost:7233"
    namespace: str = "default"

    # Task queue configuration
    task_queue: str = "cybershield-workflows"

    # TLS configuration (for production)
    tls_cert_path: Optional[str] = None
    tls_key_path: Optional[str] = None
    tls_ca_path: Optional[str] = None

    # Worker configuration
    max_worker_activities: int = 100
    max_worker_workflows: int = 100
    max_concurrent_activities: int = 200
    max_concurrent_workflows: int = 200

    # Timeouts (in seconds)
    workflow_execution_timeout: int = 3600  # 1 hour
    activity_start_to_close_timeout: int = 300  # 5 minutes
    activity_schedule_to_close_timeout: int = 600  # 10 minutes
    activity_heartbeat_timeout: int = 30  # 30 seconds

    # Retry policies
    activity_maximum_attempts: int = 5
    workflow_maximum_attempts: int = 3

    # Development settings
    enable_prometheus: bool = False
    prometheus_bind_address: str = "0.0.0.0:9090"

    @classmethod
    def from_env(cls) -> "TemporalConfig":
        """Create configuration from environment variables"""
        return cls(
            target_host=os.getenv("TEMPORAL_TARGET_HOST", "localhost:7233"),
            namespace=os.getenv("TEMPORAL_NAMESPACE", "default"),
            task_queue=os.getenv("TEMPORAL_TASK_QUEUE", "cybershield-workflows"),

            # TLS settings for production
            tls_cert_path=os.getenv("TEMPORAL_TLS_CERT_PATH"),
            tls_key_path=os.getenv("TEMPORAL_TLS_KEY_PATH"),
            tls_ca_path=os.getenv("TEMPORAL_TLS_CA_PATH"),

            # Worker limits
            max_worker_activities=int(os.getenv("TEMPORAL_MAX_WORKER_ACTIVITIES", "100")),
            max_worker_workflows=int(os.getenv("TEMPORAL_MAX_WORKER_WORKFLOWS", "100")),
            max_concurrent_activities=int(os.getenv("TEMPORAL_MAX_CONCURRENT_ACTIVITIES", "200")),
            max_concurrent_workflows=int(os.getenv("TEMPORAL_MAX_CONCURRENT_WORKFLOWS", "200")),

            # Timeout configuration
            workflow_execution_timeout=int(os.getenv("TEMPORAL_WORKFLOW_TIMEOUT", "3600")),
            activity_start_to_close_timeout=int(os.getenv("TEMPORAL_ACTIVITY_TIMEOUT", "300")),
            activity_schedule_to_close_timeout=int(os.getenv("TEMPORAL_ACTIVITY_SCHEDULE_TIMEOUT", "600")),
            activity_heartbeat_timeout=int(os.getenv("TEMPORAL_ACTIVITY_HEARTBEAT_TIMEOUT", "30")),

            # Retry configuration
            activity_maximum_attempts=int(os.getenv("TEMPORAL_ACTIVITY_MAX_ATTEMPTS", "5")),
            workflow_maximum_attempts=int(os.getenv("TEMPORAL_WORKFLOW_MAX_ATTEMPTS", "3")),

            # Monitoring
            enable_prometheus=os.getenv("TEMPORAL_ENABLE_PROMETHEUS", "false").lower() == "true",
            prometheus_bind_address=os.getenv("TEMPORAL_PROMETHEUS_BIND_ADDRESS", "0.0.0.0:9090"),
        )


class TemporalClientManager:
    """Manages Temporal client connections and worker lifecycle"""

    def __init__(self, config: Optional[TemporalConfig] = None):
        self.config = config or TemporalConfig.from_env()
        self._client: Optional[Client] = None
        self._runtime: Optional[Runtime] = None

    async def get_client(self) -> Client:
        """Get or create Temporal client"""
        if self._client is None:
            self._client = await self._create_client()
        return self._client

    async def _create_client(self) -> Client:
        """Create Temporal client with proper configuration"""
        logger.info(
            "Creating Temporal client",
            target_host=self.config.target_host,
            namespace=self.config.namespace,
            has_tls=bool(self.config.tls_cert_path)
        )

        # Create runtime with telemetry if enabled
        runtime_config = {}
        if self.config.enable_prometheus:
            runtime_config["telemetry"] = TelemetryConfig(
                metrics=PrometheusConfig(bind_address=self.config.prometheus_bind_address)
            )

        if runtime_config:
            self._runtime = Runtime(**runtime_config)

        # Configure TLS if certificates are provided
        tls_config = None
        if self.config.tls_cert_path and self.config.tls_key_path:
            logger.info("Configuring TLS for Temporal client")
            tls_config = TLSConfig(
                client_cert_path=self.config.tls_cert_path,
                client_private_key_path=self.config.tls_key_path,
                server_root_ca_cert_path=self.config.tls_ca_path
            )

        try:
            client = await Client.connect(
                self.config.target_host,
                namespace=self.config.namespace,
                tls=tls_config,
                runtime=self._runtime
            )

            logger.info(
                "Temporal client connected successfully",
                namespace=self.config.namespace,
                target_host=self.config.target_host
            )

            return client

        except Exception as e:
            logger.error(f"Failed to connect to Temporal server: {e}")
            raise

    async def create_worker(
        self,
        workflows: list,
        activities: list,
        task_queue: Optional[str] = None
    ) -> Worker:
        """Create Temporal worker with workflows and activities"""
        client = await self.get_client()
        task_queue = task_queue or self.config.task_queue

        logger.info(
            "Creating Temporal worker",
            task_queue=task_queue,
            workflows_count=len(workflows),
            activities_count=len(activities),
            max_concurrent_activities=self.config.max_concurrent_activities,
            max_concurrent_workflows=self.config.max_concurrent_workflows
        )

        worker = Worker(
            client,
            task_queue=task_queue,
            workflows=workflows,
            activities=activities,
            max_concurrent_activities=self.config.max_concurrent_activities,
            max_concurrent_workflow_tasks=self.config.max_concurrent_workflows,
            max_cached_workflows=1000,  # Cache workflows for performance
            # max_heartbeat_throttle_interval_seconds=60,  # Removed - incompatible with this SDK version
            # default_heartbeat_throttle_interval_seconds=30,  # Removed - incompatible with this SDK version
        )

        return worker

    async def close(self):
        """Close Temporal client and runtime"""
        if self._runtime:
            await self._runtime.shutdown()
            self._runtime = None

        # Client doesn't need explicit closing in current SDK version
        self._client = None

        logger.info("Temporal client and runtime closed")


# Global client manager instance
_client_manager: Optional[TemporalClientManager] = None


async def get_temporal_client() -> Client:
    """Get global Temporal client instance"""
    global _client_manager

    if _client_manager is None:
        _client_manager = TemporalClientManager()

    return await _client_manager.get_client()


async def get_temporal_worker(workflows: list, activities: list, task_queue: Optional[str] = None) -> Worker:
    """Get configured Temporal worker"""
    global _client_manager

    if _client_manager is None:
        _client_manager = TemporalClientManager()

    return await _client_manager.create_worker(workflows, activities, task_queue)


async def close_temporal_connections():
    """Close global Temporal connections"""
    global _client_manager

    if _client_manager:
        await _client_manager.close()
        _client_manager = None


def get_config() -> TemporalConfig:
    """Get current Temporal configuration"""
    return TemporalConfig.from_env()


# Helper functions for common Temporal patterns

def get_workflow_id(prefix: str, identifier: str) -> str:
    """Generate consistent workflow ID"""
    return f"{prefix}-{identifier}"


def get_task_queue_for_analysis_type(analysis_type: str) -> str:
    """Get task queue based on analysis type"""
    base_queue = get_config().task_queue

    # Route different analysis types to specialized queues if needed
    if analysis_type in ["threat_intel", "ioc_analysis"]:
        return f"{base_queue}-threat"
    elif analysis_type in ["vision", "image_analysis"]:
        return f"{base_queue}-vision"
    elif analysis_type in ["pii", "sensitive_data"]:
        return f"{base_queue}-pii"
    else:
        return base_queue


# Environment validation
def validate_temporal_config():
    """Validate Temporal configuration and environment"""
    config = get_config()
    issues = []

    # Check required environment variables
    if not os.getenv("TEMPORAL_TARGET_HOST") and config.target_host == "localhost:7233":
        issues.append("TEMPORAL_TARGET_HOST not set, using localhost (development mode)")

    # Check TLS configuration consistency
    tls_vars = [config.tls_cert_path, config.tls_key_path]
    if any(tls_vars) and not all(tls_vars):
        issues.append("Incomplete TLS configuration - need both cert and key paths")

    # Check timeout values
    if config.activity_start_to_close_timeout > config.activity_schedule_to_close_timeout:
        issues.append("Activity start-to-close timeout should be less than schedule-to-close timeout")

    # Log configuration status
    if issues:
        for issue in issues:
            logger.warning(f"Temporal config issue: {issue}")
    else:
        logger.info("Temporal configuration validated successfully")

    return len(issues) == 0


# Functions that work without Temporal SDK

def is_temporal_available() -> bool:
    """Check if Temporal SDK is available"""
    return _temporal_available

def validate_temporal_config_safe():
    """Safe version of validate_temporal_config that works without SDK"""
    if not _temporal_available:
        logger.warning("Temporal SDK not available - cannot validate full configuration")
        return False
    return validate_temporal_config()

# Initialize configuration validation on import (safe version)
validate_temporal_config_safe()