"""
Unit tests for Configuration System.

Tests environment configurations and constants.
"""

import pytest

from config.constants import (
    BACKEND_PORT,
    DEFAULT_VPC_CIDR,
    PROJECT_NAME,
    REDIS_PORT,
)
from config.environments import (
    DevelopmentConfig,
    ProductionConfig,
    StagingConfig,
    get_environment_config,
)


def test_development_config() -> None:
    """Test development environment configuration."""
    config = DevelopmentConfig()

    assert config.environment == "dev"
    assert config.project_name == PROJECT_NAME
    assert config.vpc_cidr == DEFAULT_VPC_CIDR
    assert config.enable_nat_gateway is False  # Cost optimization in dev
    assert config.enable_monitoring is False  # Disabled in dev
    assert config.cloudwatch_log_retention_days == 1  # Minimal retention


def test_staging_config() -> None:
    """Test staging environment configuration."""
    config = StagingConfig()

    assert config.environment == "staging"
    assert config.enable_nat_gateway is True  # Production-like
    assert config.enable_monitoring is True
    assert config.enable_spot_instances is True  # Test spot instances


def test_production_config() -> None:
    """Test production environment configuration."""
    config = ProductionConfig()

    assert config.environment == "prod"
    assert config.enable_nat_gateway is False  # Use public subnets for ECR
    assert config.enable_monitoring is False  # Cost-optimized
    assert config.enable_efs_for_milvus is True
    assert config.enable_opensearch is False  # Using containerized Milvus


def test_get_environment_config() -> None:
    """Test environment config factory function."""
    dev_config = get_environment_config("dev")
    assert isinstance(dev_config, DevelopmentConfig)
    assert dev_config.environment == "dev"

    staging_config = get_environment_config("staging")
    assert isinstance(staging_config, StagingConfig)
    assert staging_config.environment == "staging"

    prod_config = get_environment_config("prod")
    assert isinstance(prod_config, ProductionConfig)
    assert prod_config.environment == "prod"


def test_invalid_environment_raises_error() -> None:
    """Test that invalid environment raises ValueError."""
    with pytest.raises(ValueError, match="Invalid environment"):
        get_environment_config("invalid")


def test_common_tags_generated() -> None:
    """Test that common tags are generated correctly."""
    config = DevelopmentConfig()
    tags = config.common_tags

    assert tags["Project"] == PROJECT_NAME
    assert tags["Environment"] == "dev"
    assert tags["ManagedBy"] == "cdk"
    assert tags["MigratedFrom"] == "terraform"


def test_stack_name_prefix() -> None:
    """Test stack name prefix generation."""
    dev_config = DevelopmentConfig()
    assert dev_config.stack_name_prefix == "CybershieldDev"

    prod_config = ProductionConfig()
    assert prod_config.stack_name_prefix == "CybershieldProd"


def test_environment_variables_set() -> None:
    """Test that environment variables are set correctly."""
    config = DevelopmentConfig()

    assert "ENVIRONMENT" in config.environment_variables
    assert config.environment_variables["ENVIRONMENT"] == "dev"
    assert config.environment_variables["DEBUG"] == "False"
    assert config.environment_variables["LOG_LEVEL"] == "INFO"


def test_database_configuration() -> None:
    """Test database configuration values."""
    dev_config = DevelopmentConfig()

    assert dev_config.db_instance_class == "db.t3.micro"
    assert dev_config.db_allocated_storage == 20
    assert dev_config.backup_retention_days == 1  # Minimal in dev

    prod_config = ProductionConfig()
    assert prod_config.backup_retention_days == 7  # More in prod


def test_redis_configuration() -> None:
    """Test Redis configuration values."""
    config = DevelopmentConfig()

    assert config.redis_node_type == "cache.t3.micro"
    assert config.redis_engine_version == "7.0"
    assert config.enable_auth_token is True
    assert config.enable_transit_encryption is True


def test_ecs_configuration() -> None:
    """Test ECS configuration values."""
    dev_config = DevelopmentConfig()

    # Dev has minimal resources
    assert dev_config.backend_cpu == 256
    assert dev_config.backend_memory == 512
    assert dev_config.backend_min_capacity == 1
    assert dev_config.backend_max_capacity == 2

    prod_config = ProductionConfig()

    # Prod is also cost-optimized
    assert prod_config.backend_cpu == 256
    assert prod_config.backend_memory == 512
    assert prod_config.enable_auto_scaling is True


def test_cost_optimization_flags() -> None:
    """Test cost optimization feature flags."""
    dev_config = DevelopmentConfig()

    # Dev has aggressive cost optimization
    assert dev_config.enable_nat_gateway is False
    assert dev_config.enable_monitoring is False
    assert dev_config.enable_access_logs is False
    assert dev_config.cloudwatch_log_retention_days == 1

    prod_config = ProductionConfig()

    # Prod is cost-optimized but with necessary features
    assert prod_config.enable_monitoring is False  # Disabled for cost
    assert prod_config.enable_access_logs is False  # Disabled for cost
    assert prod_config.cloudwatch_log_retention_days == 1  # Minimal


def test_constants_defined() -> None:
    """Test that required constants are defined."""
    assert BACKEND_PORT == 8000
    assert REDIS_PORT == 6379
    assert PROJECT_NAME == "cybershield"
    assert DEFAULT_VPC_CIDR == "10.0.0.0/16"
