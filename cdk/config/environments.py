"""
Environment-specific configuration for CyberShield CDK infrastructure.

Provides configuration classes for dev, staging, and production environments
with cost optimization and feature flags.
"""

import os
from dataclasses import dataclass, field
from typing import Literal

from dotenv import load_dotenv

from config.constants import (
    BACKEND_HEALTH_CHECK_PATH,
    DB_DEFAULT_NAME,
    DB_DEFAULT_USERNAME,
    DEFAULT_BACKUP_RETENTION_DAYS,
    DEFAULT_LOG_RETENTION_DAYS,
    DEFAULT_VPC_CIDR,
    FRONTEND_HEALTH_CHECK_PATH,
    PROJECT_NAME,
    REDIS_DEFAULT_PARAMETER_GROUP_FAMILY,
)

# Load environment variables
load_dotenv()

EnvironmentType = Literal["dev", "staging", "prod"]


@dataclass
class EnvironmentConfig:
    """Base configuration for all environments."""

    # Environment identification
    environment: EnvironmentType
    project_name: str = PROJECT_NAME
    aws_region: str = field(default_factory=lambda: os.getenv("AWS_REGION", "us-east-1"))
    aws_account_id: str = field(
        default_factory=lambda: os.getenv("AWS_ACCOUNT_ID", "")
    )

    # Domain configuration
    domain_name: str | None = field(
        default_factory=lambda: os.getenv("DOMAIN_NAME")
    )
    certificate_validation_method: str = "DNS"

    # Network configuration
    vpc_cidr: str = DEFAULT_VPC_CIDR
    enable_nat_gateway: bool = True
    enable_vpn_gateway: bool = False

    # Database configuration
    db_instance_class: str = "db.t3.micro"
    db_allocated_storage: int = 20
    db_engine_version: str = "15.7"
    db_name: str = DB_DEFAULT_NAME
    db_username: str = DB_DEFAULT_USERNAME
    backup_retention_days: int = DEFAULT_BACKUP_RETENTION_DAYS
    backup_window: str = "03:00-04:00"
    maintenance_window: str = "sun:04:00-sun:05:00"

    # Redis configuration
    redis_node_type: str = "cache.t3.micro"
    redis_engine_version: str = "7.0"
    redis_parameter_group_family: str = REDIS_DEFAULT_PARAMETER_GROUP_FAMILY
    enable_auth_token: bool = True
    enable_transit_encryption: bool = True
    enable_at_rest_encryption: bool = True

    # OpenSearch configuration
    enable_opensearch: bool = False
    opensearch_instance_type: str = "t3.small.search"
    opensearch_instance_count: int = 1
    opensearch_volume_size: int = 20
    opensearch_version: str = "OpenSearch_2.11"
    enable_zone_awareness: bool = False
    enable_encryption_at_rest: bool = True
    enable_node_to_node_encryption: bool = True

    # ECS configuration
    backend_cpu: int = 1024
    backend_memory: int = 2048
    backend_min_capacity: int = 1
    backend_max_capacity: int = 10
    backend_desired_count: int = 1

    frontend_cpu: int = 512
    frontend_memory: int = 1024
    frontend_min_capacity: int = 1
    frontend_max_capacity: int = 5
    frontend_desired_count: int = 1

    # Feature flags
    enable_spot_instances: bool = False
    enable_deletion_protection: bool = True
    enable_backup: bool = True
    enable_monitoring: bool = True
    enable_logging: bool = True
    enable_ecs_exec: bool = False
    enable_access_logs: bool = True
    enable_health_checks: bool = True
    enable_performance_insights: bool = False
    enable_efs_for_milvus: bool = False
    enable_bedrock_finetuning: bool = False
    enable_bedrock_vpc_endpoint: bool = False
    enable_auto_scaling: bool = True
    enable_container_insights: bool = True

    # Monitoring configuration
    cloudwatch_log_retention_days: int = DEFAULT_LOG_RETENTION_DAYS
    monitoring_interval: int = 60

    # Health check configuration
    backend_health_check_path: str = BACKEND_HEALTH_CHECK_PATH
    frontend_health_check_path: str = FRONTEND_HEALTH_CHECK_PATH

    # Application configuration
    environment_variables: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate and set default environment variables."""
        if not self.aws_account_id:
            raise ValueError("AWS_ACCOUNT_ID must be set in environment variables")

        # Set default environment variables if not provided
        if not self.environment_variables:
            self.environment_variables = {
                "DEBUG": "False",
                "ENVIRONMENT": self.environment,
                "LOG_LEVEL": "INFO",
                "APPLE_SILICON_ACCELERATION": "true",
            }

    @property
    def stack_name_prefix(self) -> str:
        """Generate stack name prefix based on project and environment."""
        return f"{self.project_name.title()}{self.environment.title()}"

    @property
    def common_tags(self) -> dict[str, str]:
        """Generate common tags for all resources."""
        return {
            "Project": self.project_name,
            "Environment": self.environment,
            "ManagedBy": "cdk",
            "Owner": f"{self.project_name}-{self.environment}-team",
            "MigratedFrom": "terraform",
        }


class DevelopmentConfig(EnvironmentConfig):
    """Development environment configuration with cost optimization."""

    def __init__(self) -> None:
        """Initialize development configuration with cost-optimized settings."""
        super().__init__(
            environment="dev",
            # Network - Cost optimized
            enable_nat_gateway=False,  # No NAT gateway to save costs
            # Database - Minimal resources
            db_instance_class="db.t3.micro",
            db_allocated_storage=20,
            backup_retention_days=1,  # Minimal backup retention
            # Redis - Minimal resources
            redis_node_type="cache.t3.micro",
            # OpenSearch - Disabled for dev
            enable_opensearch=False,
            # ECS - Minimal resources
            backend_cpu=256,
            backend_memory=512,
            backend_min_capacity=1,
            backend_max_capacity=2,
            frontend_cpu=256,
            frontend_memory=512,
            frontend_min_capacity=1,
            frontend_max_capacity=1,
            # Feature flags - Development focused
            enable_spot_instances=False,  # Consistency over cost in dev
            enable_deletion_protection=False,
            enable_monitoring=False,  # Disable enhanced monitoring
            enable_access_logs=False,
            enable_health_checks=False,
            enable_performance_insights=False,
            enable_auto_scaling=False,
            enable_container_insights=False,
            # Logging - Minimal retention
            cloudwatch_log_retention_days=1,
        )


class StagingConfig(EnvironmentConfig):
    """Staging environment configuration - production-like but cost-optimized."""

    def __init__(self) -> None:
        """Initialize staging configuration with balanced settings."""
        super().__init__(
            environment="staging",
            # Network - Production-like with NAT
            enable_nat_gateway=True,
            # Database - Small but reliable
            db_instance_class="db.t3.small",
            db_allocated_storage=20,
            backup_retention_days=3,
            # Redis - Small instance
            redis_node_type="cache.t3.small",
            # OpenSearch - Optional for staging
            enable_opensearch=False,
            # ECS - Moderate resources
            backend_cpu=512,
            backend_memory=1024,
            backend_min_capacity=1,
            backend_max_capacity=5,
            frontend_cpu=512,
            frontend_memory=1024,
            frontend_min_capacity=1,
            frontend_max_capacity=3,
            # Feature flags - Testing production features
            enable_spot_instances=True,  # Test spot instances
            enable_deletion_protection=False,
            enable_monitoring=True,
            enable_access_logs=True,
            enable_health_checks=True,
            enable_performance_insights=False,
            enable_auto_scaling=True,
            enable_container_insights=True,
            # Logging - Moderate retention
            cloudwatch_log_retention_days=7,
        )


class ProductionConfig(EnvironmentConfig):
    """Production environment configuration with reliability and performance focus."""

    def __init__(self) -> None:
        """Initialize production configuration with optimal settings."""
        super().__init__(
            environment="prod",
            # Network - Full production setup
            enable_nat_gateway=False,  # Use public subnets for ECR access
            # Database - Production grade
            db_instance_class="db.t3.micro",  # Cost-optimized but reliable
            db_allocated_storage=20,
            backup_retention_days=7,
            # Redis - Production grade
            redis_node_type="cache.t3.micro",
            # OpenSearch - Disabled (using containerized Milvus)
            enable_opensearch=False,
            enable_efs_for_milvus=True,  # Use EFS for Milvus persistence
            # ECS - Full production resources
            backend_cpu=256,  # Ultra cost-optimized
            backend_memory=512,
            backend_min_capacity=1,
            backend_max_capacity=2,
            frontend_cpu=256,
            frontend_memory=512,
            frontend_min_capacity=1,
            frontend_max_capacity=1,
            # Feature flags - Production reliability
            enable_spot_instances=True,  # Cost savings in production
            enable_deletion_protection=False,  # Allow deletion for cost control
            enable_monitoring=False,  # Disable enhanced RDS monitoring ($5/month)
            enable_access_logs=False,  # Disable ALB access logs (S3 costs)
            enable_health_checks=False,  # Disable Route53 health checks
            enable_performance_insights=False,
            enable_auto_scaling=True,
            enable_container_insights=True,
            # Logging - Minimal retention for cost
            cloudwatch_log_retention_days=1,
        )


def get_environment_config(environment: str | None = None) -> EnvironmentConfig:
    """
    Get environment configuration based on environment name.

    Args:
        environment: Environment name (dev, staging, prod).
                    If None, reads from ENVIRONMENT env var.

    Returns:
        EnvironmentConfig: Configuration for the specified environment.

    Raises:
        ValueError: If environment is invalid.
    """
    if environment is None:
        environment = os.getenv("ENVIRONMENT", "dev")

    environment = environment.lower()

    config_map: dict[str, type[EnvironmentConfig]] = {
        "dev": DevelopmentConfig,
        "staging": StagingConfig,
        "prod": ProductionConfig,
    }

    if environment not in config_map:
        raise ValueError(
            f"Invalid environment: {environment}. "
            f"Must be one of: {', '.join(config_map.keys())}"
        )

    return config_map[environment]()
