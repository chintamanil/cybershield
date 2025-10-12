"""
Unit tests for Compute Stack.

Tests ECS cluster, services, and task definitions.
"""

import aws_cdk as cdk
import aws_cdk.assertions as assertions

from config.environments import DevelopmentConfig
from stacks.compute_stack import ComputeStack
from stacks.data_stack import DataStack
from stacks.iam_stack import IamStack
from stacks.load_balancer_stack import LoadBalancerStack
from stacks.network_stack import NetworkStack
from stacks.storage_stack import StorageStack
from stacks.dns_stack import DnsStack


def create_test_stacks(app: cdk.App, config: DevelopmentConfig) -> tuple:
    """Create all dependent stacks for testing."""
    env = cdk.Environment(account="123456789012", region="us-east-1")

    iam_stack = IamStack(app, "TestIamStack", config=config, env=env)
    network_stack = NetworkStack(app, "TestNetworkStack", config=config, env=env)
    dns_stack = DnsStack(app, "TestDnsStack", config=config, env=env)
    storage_stack = StorageStack(
        app, "TestStorageStack", config=config, network_stack=network_stack, env=env
    )
    data_stack = DataStack(
        app, "TestDataStack", config=config, network_stack=network_stack, env=env
    )
    load_balancer_stack = LoadBalancerStack(
        app,
        "TestLoadBalancerStack",
        config=config,
        network_stack=network_stack,
        dns_stack=dns_stack,
        env=env,
    )

    compute_stack = ComputeStack(
        app,
        "TestComputeStack",
        config=config,
        network_stack=network_stack,
        iam_stack=iam_stack,
        data_stack=data_stack,
        load_balancer_stack=load_balancer_stack,
        storage_stack=storage_stack,
        env=env,
    )

    return (compute_stack, network_stack, iam_stack)


def test_ecs_cluster_created() -> None:
    """Test that ECS cluster is created."""
    app = cdk.App()
    config = DevelopmentConfig()

    compute_stack, _, _ = create_test_stacks(app, config)
    template = assertions.Template.from_stack(compute_stack)

    # Assert ECS cluster exists
    template.has_resource_properties(
        "AWS::ECS::Cluster",
        {
            "ClusterName": f"{config.project_name}-{config.environment}",
        },
    )


def test_ecr_repository_created() -> None:
    """Test that ECR repository is created."""
    app = cdk.App()
    config = DevelopmentConfig()

    compute_stack, _, _ = create_test_stacks(app, config)
    template = assertions.Template.from_stack(compute_stack)

    # Assert ECR repository exists
    template.has_resource_properties(
        "AWS::ECR::Repository",
        {
            "ImageScanningConfiguration": {"ScanOnPush": True},
            "EncryptionConfiguration": {"EncryptionType": "AES256"},
        },
    )


def test_backend_task_definition_created() -> None:
    """Test that backend task definition is created with correct configuration."""
    app = cdk.App()
    config = DevelopmentConfig()

    compute_stack, _, _ = create_test_stacks(app, config)
    template = assertions.Template.from_stack(compute_stack)

    # Assert backend task definition exists
    template.has_resource_properties(
        "AWS::ECS::TaskDefinition",
        {
            "Cpu": str(config.backend_cpu),
            "Memory": str(config.backend_memory),
            "NetworkMode": "awsvpc",
            "RequiresCompatibilities": ["FARGATE"],
        },
    )


def test_frontend_task_definition_created() -> None:
    """Test that frontend task definition is created."""
    app = cdk.App()
    config = DevelopmentConfig()

    compute_stack, _, _ = create_test_stacks(app, config)
    template = assertions.Template.from_stack(compute_stack)

    # Check for multiple task definitions (backend + frontend)
    template.resource_count_is("AWS::ECS::TaskDefinition", 2)


def test_ecs_services_created() -> None:
    """Test that ECS services are created."""
    app = cdk.App()
    config = DevelopmentConfig()

    compute_stack, _, _ = create_test_stacks(app, config)
    template = assertions.Template.from_stack(compute_stack)

    # Assert both backend and frontend services exist
    template.resource_count_is("AWS::ECS::Service", 2)


def test_log_group_created() -> None:
    """Test that CloudWatch log group is created."""
    app = cdk.App()
    config = DevelopmentConfig()

    compute_stack, _, _ = create_test_stacks(app, config)
    template = assertions.Template.from_stack(compute_stack)

    # Assert log group exists
    template.has_resource_properties(
        "AWS::Logs::LogGroup",
        {
            "LogGroupName": f"/ecs/{config.project_name}-{config.environment}",
            "RetentionInDays": config.cloudwatch_log_retention_days,
        },
    )


def test_auto_scaling_disabled_in_dev() -> None:
    """Test that auto-scaling is disabled in dev environment."""
    app = cdk.App()
    config = DevelopmentConfig()

    compute_stack, _, _ = create_test_stacks(app, config)
    template = assertions.Template.from_stack(compute_stack)

    # Dev environment has auto-scaling disabled
    # So no ScalableTarget resources should exist
    template.resource_count_is("AWS::ApplicationAutoScaling::ScalableTarget", 0)


def test_task_uses_correct_iam_roles() -> None:
    """Test that tasks use correct IAM roles."""
    app = cdk.App()
    config = DevelopmentConfig()

    compute_stack, _, iam_stack = create_test_stacks(app, config)
    template = assertions.Template.from_stack(compute_stack)

    # Task definitions should reference IAM roles
    template.has_resource_properties(
        "AWS::ECS::TaskDefinition",
        {
            "ExecutionRoleArn": assertions.Match.any_value(),
            "TaskRoleArn": assertions.Match.any_value(),
        },
    )
