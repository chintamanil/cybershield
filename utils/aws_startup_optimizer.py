#!/usr/bin/env python3
"""AWS-specific startup optimizations for CyberShield deployment"""

import os
from typing import Any

from utils.logging_config import get_security_logger

logger = get_security_logger("aws_startup_optimizer")


class AWSStartupOptimizer:
    """Optimizes application startup for AWS ECS deployment"""

    def __init__(self):
        self.is_aws = self._detect_aws_environment()
        self.optimization_cache = {}

    def _detect_aws_environment(self) -> bool:
        """Detect if running in AWS environment"""
        aws_indicators = [
            os.getenv("AWS_EXECUTION_ENV"),
            os.getenv("AWS_REGION"),
            os.getenv("ECS_CONTAINER_METADATA_URI"),
            os.getenv("AWS_LAMBDA_FUNCTION_NAME"),
        ]
        return any(aws_indicators)

    def optimize_for_aws(self) -> dict[str, Any]:
        """Apply AWS-specific optimizations"""
        if not self.is_aws:
            return {"aws_optimizations": False}

        optimizations = {
            "aws_optimizations": True,
            "environment": "aws",
            "optimizations_applied": [],
        }

        # 1. ECS Task CPU/Memory optimization
        if self._is_ecs_environment():
            cpu_opts = self._optimize_ecs_resources()
            optimizations.update(cpu_opts)
            optimizations["optimizations_applied"].append("ecs_resources")

        # 2. Network optimizations for AWS services
        network_opts = self._optimize_aws_networking()
        optimizations.update(network_opts)
        optimizations["optimizations_applied"].append("aws_networking")

        # 3. Memory management for container limits
        memory_opts = self._optimize_container_memory()
        optimizations.update(memory_opts)
        optimizations["optimizations_applied"].append("container_memory")

        # 4. Service discovery optimizations
        service_opts = self._optimize_service_discovery()
        optimizations.update(service_opts)
        optimizations["optimizations_applied"].append("service_discovery")

        logger.info(
            "AWS startup optimizations applied",
            optimizations=optimizations["optimizations_applied"],
            environment=optimizations["environment"],
        )

        return optimizations

    def _is_ecs_environment(self) -> bool:
        """Check if running in ECS"""
        return bool(os.getenv("ECS_CONTAINER_METADATA_URI"))

    def _optimize_ecs_resources(self) -> dict[str, Any]:
        """Optimize for ECS task resources"""
        # Get ECS task metadata
        try:
            import requests

            metadata_uri = os.getenv("ECS_CONTAINER_METADATA_URI")
            if metadata_uri:
                response = requests.get(f"{metadata_uri}/task", timeout=2)
                task_meta = response.json()

                # Extract CPU and memory limits
                cpu_limit = task_meta.get("Limits", {}).get("CPU", 0)
                memory_limit = task_meta.get("Limits", {}).get("Memory", 0)

                # Optimize worker count based on resources
                if cpu_limit >= 1024:  # 1 vCPU
                    worker_count = min(4, max(1, cpu_limit // 256))
                else:
                    worker_count = 1

                return {
                    "ecs_cpu_limit": cpu_limit,
                    "ecs_memory_limit": memory_limit,
                    "optimized_workers": worker_count,
                    "resource_optimization": True,
                }
        except Exception as e:
            logger.warning(f"ECS metadata optimization failed: {e}")

        return {"resource_optimization": False}

    def _optimize_aws_networking(self) -> dict[str, Any]:
        """Optimize networking for AWS services"""
        optimizations = {}

        # Use AWS internal endpoints when available
        aws_region = os.getenv("AWS_REGION", "us-east-1")

        # RDS optimization
        if os.getenv("RDS_ENDPOINT"):
            optimizations["rds_internal_endpoint"] = True
            optimizations["rds_region_optimized"] = aws_region

        # ElastiCache optimization
        if os.getenv("REDIS_HOST") and ".cache.amazonaws.com" in os.getenv(
            "REDIS_HOST", ""
        ):
            optimizations["elasticache_internal"] = True
            optimizations["redis_region_optimized"] = aws_region

        # OpenSearch optimization
        if os.getenv("OPENSEARCH_ENDPOINT") and ".es.amazonaws.com" in os.getenv(
            "OPENSEARCH_ENDPOINT", ""
        ):
            optimizations["opensearch_internal"] = True
            optimizations["opensearch_region_optimized"] = aws_region

        return optimizations

    def _optimize_container_memory(self) -> dict[str, Any]:
        """Optimize memory usage for container constraints"""
        import psutil

        try:
            # Get available memory
            memory_info = psutil.virtual_memory()
            available_mb = memory_info.available // 1024 // 1024

            # Conservative memory allocation (leave 25% headroom)
            max_memory_mb = int(available_mb * 0.75)

            # Set Python memory optimizations
            if max_memory_mb < 1024:  # Less than 1GB
                os.environ["PYTORCH_MPS_HIGH_WATERMARK_RATIO"] = "0.6"
                os.environ["TOKENIZERS_PARALLELISM"] = "false"
                batch_size = 8
            elif max_memory_mb < 2048:  # Less than 2GB
                os.environ["PYTORCH_MPS_HIGH_WATERMARK_RATIO"] = "0.7"
                batch_size = 16
            else:  # 2GB or more
                os.environ["PYTORCH_MPS_HIGH_WATERMARK_RATIO"] = "0.8"
                batch_size = 32

            return {
                "available_memory_mb": available_mb,
                "max_allocated_mb": max_memory_mb,
                "optimized_batch_size": batch_size,
                "memory_optimization": True,
            }

        except Exception as e:
            logger.warning(f"Memory optimization failed: {e}")
            return {"memory_optimization": False}

    def _optimize_service_discovery(self) -> dict[str, Any]:
        """Optimize AWS service discovery and connections"""
        optimizations = {}

        # Use AWS SDK optimizations
        os.environ["AWS_MAX_ATTEMPTS"] = "3"
        os.environ["AWS_RETRY_MODE"] = "adaptive"

        # Connection pooling optimizations
        os.environ["AWS_NODEJS_CONNECTION_REUSE_ENABLED"] = "1"

        # ECS service discovery optimization
        if self._is_ecs_environment():
            optimizations["ecs_service_discovery"] = True
            # Enable ECS service connect optimizations if available
            if os.getenv("AWS_ECS_SERVICE_CONNECT_ENDPOINT"):
                optimizations["service_connect_enabled"] = True

        return optimizations

    def get_optimized_startup_config(self) -> dict[str, Any]:
        """Get optimized configuration for application startup"""
        base_config = {
            "parallel_initialization": True,
            "lazy_loading": True,
            "model_caching": True,
            "connection_pooling": True,
        }

        if self.is_aws:
            aws_opts = self.optimize_for_aws()
            base_config.update(aws_opts)

            # AWS-specific startup optimizations
            base_config.update(
                {
                    "health_check_path": "/health",
                    "readiness_probe_delay": 30,
                    "liveness_probe_delay": 60,
                    "startup_timeout": 120,
                    "graceful_shutdown_timeout": 30,
                }
            )

        return base_config


# Global optimizer instance
aws_optimizer = AWSStartupOptimizer()


def apply_aws_optimizations():
    """Apply AWS optimizations during application startup"""
    return aws_optimizer.get_optimized_startup_config()
