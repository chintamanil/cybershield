"""
Shared constants for CyberShield CDK infrastructure.
"""

from typing import Final

# Project Configuration
PROJECT_NAME: Final[str] = "cybershield"
PROJECT_DESCRIPTION: Final[str] = (
    "Advanced multi-agent AI cybersecurity platform"
)

# AWS Resource Naming
STACK_PREFIX: Final[str] = "CyberShield"

# Network Configuration
DEFAULT_VPC_CIDR: Final[str] = "10.0.0.0/16"
DEFAULT_AZS: Final[int] = 2

# Subnet CIDR Offsets
PUBLIC_SUBNET_OFFSET: Final[int] = 0
PRIVATE_SUBNET_OFFSET: Final[int] = 10
DATABASE_SUBNET_OFFSET: Final[int] = 20
CACHE_SUBNET_OFFSET: Final[int] = 30

# Container Ports
BACKEND_PORT: Final[int] = 8000
FRONTEND_PORT: Final[int] = 8501
POSTGRES_PORT: Final[int] = 5432
REDIS_PORT: Final[int] = 6379
OPENSEARCH_PORT: Final[int] = 9200

# Database Configuration
DB_ENGINE: Final[str] = "postgres"
DB_PORT: Final[int] = POSTGRES_PORT
DB_DEFAULT_NAME: Final[str] = "cybershield"
DB_DEFAULT_USERNAME: Final[str] = "cybershield_admin"

# Redis Configuration
REDIS_ENGINE: Final[str] = "redis"
REDIS_PORT_NUMBER: Final[int] = REDIS_PORT
REDIS_DEFAULT_PARAMETER_GROUP_FAMILY: Final[str] = "redis7"

# OpenSearch Configuration
OPENSEARCH_VERSION: Final[str] = "OpenSearch_2.11"
OPENSEARCH_DEFAULT_VOLUME_SIZE: Final[int] = 20

# ECS Configuration
ECS_TASK_FAMILY: Final[str] = "cybershield-task"
BACKEND_CONTAINER_NAME: Final[str] = "backend"
FRONTEND_CONTAINER_NAME: Final[str] = "frontend"

# Health Check Configuration
BACKEND_HEALTH_CHECK_PATH: Final[str] = "/health"
FRONTEND_HEALTH_CHECK_PATH: Final[str] = "/"
HEALTH_CHECK_INTERVAL_SECONDS: Final[int] = 30
HEALTH_CHECK_TIMEOUT_SECONDS: Final[int] = 5
HEALTH_CHECK_HEALTHY_THRESHOLD: Final[int] = 2
HEALTH_CHECK_UNHEALTHY_THRESHOLD: Final[int] = 3

# ALB Configuration
ALB_IDLE_TIMEOUT_SECONDS: Final[int] = 60
SSL_POLICY: Final[str] = "ELBSecurityPolicy-TLS13-1-2-2021-06"

# Monitoring Configuration
DEFAULT_LOG_RETENTION_DAYS: Final[int] = 14
METRIC_NAMESPACE: Final[str] = "CyberShield"

# Auto Scaling Configuration
CPU_TARGET_UTILIZATION: Final[int] = 70
MEMORY_TARGET_UTILIZATION: Final[int] = 80
SCALE_IN_COOLDOWN_SECONDS: Final[int] = 300
SCALE_OUT_COOLDOWN_SECONDS: Final[int] = 60

# Alarm Thresholds
CPU_ALARM_THRESHOLD: Final[int] = 85
MEMORY_ALARM_THRESHOLD: Final[int] = 85
RESPONSE_TIME_ALARM_THRESHOLD_MS: Final[int] = 2000
UNHEALTHY_HOST_THRESHOLD: Final[int] = 1
HTTP_5XX_THRESHOLD: Final[int] = 10

# Backup Configuration
DEFAULT_BACKUP_RETENTION_DAYS: Final[int] = 7
BACKUP_WINDOW: Final[str] = "03:00-04:00"
MAINTENANCE_WINDOW: Final[str] = "sun:04:00-sun:05:00"

# S3 Configuration
S3_LIFECYCLE_TRANSITION_STANDARD_IA_DAYS: Final[int] = 30
S3_LIFECYCLE_TRANSITION_GLACIER_DAYS: Final[int] = 90
S3_LIFECYCLE_EXPIRATION_DAYS: Final[int] = 365
S3_NONCURRENT_VERSION_EXPIRATION_DAYS: Final[int] = 90

# EFS Configuration
EFS_PROVISIONED_THROUGHPUT_MIBPS: Final[int] = 10
EFS_TRANSITION_TO_IA_DAYS: Final[int] = 7

# Tags
MANAGED_BY_TAG: Final[str] = "cdk"
TERRAFORM_MIGRATION_TAG: Final[str] = "migrated-from-terraform"

# Resource Limits
MAX_CONTAINER_CPU: Final[int] = 4096
MAX_CONTAINER_MEMORY: Final[int] = 8192
MIN_CONTAINER_CPU: Final[int] = 256
MIN_CONTAINER_MEMORY: Final[int] = 512

# API Path Patterns
API_PATH_PATTERNS: Final[list[str]] = [
    "/analyze",
    "/analyze-with-image",
    "/batch-analyze",
    "/upload-image",
    "/tools/*",
    "/health",
    "/status",
]

# Certificate Configuration
CERTIFICATE_VALIDATION_METHOD: Final[str] = "DNS"
CERTIFICATE_VALIDATION_TIMEOUT_MINUTES: Final[int] = 15

# Bedrock Configuration
BEDROCK_TRAINING_DATA_RETENTION_DAYS: Final[int] = 365
BEDROCK_MODEL_ARTIFACTS_RETENTION_DAYS: Final[int] = 730

# Environment-specific Multipliers
DEV_COST_MULTIPLIER: Final[float] = 0.5
STAGING_COST_MULTIPLIER: Final[float] = 0.75
PROD_COST_MULTIPLIER: Final[float] = 1.0
