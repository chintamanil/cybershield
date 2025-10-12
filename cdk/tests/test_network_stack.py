"""
Unit tests for Network Stack.

Tests VPC, subnet, and security group configuration.
"""

import aws_cdk as cdk
import aws_cdk.assertions as assertions

from config.environments import DevelopmentConfig
from stacks.network_stack import NetworkStack


def test_vpc_created() -> None:
    """Test that VPC is created with correct CIDR."""
    app = cdk.App()
    config = DevelopmentConfig()

    stack = NetworkStack(
        app,
        "TestNetworkStack",
        config=config,
        env=cdk.Environment(account="123456789012", region="us-east-1"),
    )

    template = assertions.Template.from_stack(stack)

    # Assert VPC exists with correct CIDR
    template.has_resource_properties(
        "AWS::EC2::VPC",
        {
            "CidrBlock": config.vpc_cidr,
            "EnableDnsHostnames": True,
            "EnableDnsSupport": True,
        },
    )


def test_public_subnets_created() -> None:
    """Test that public subnets are created."""
    app = cdk.App()
    config = DevelopmentConfig()

    stack = NetworkStack(
        app,
        "TestNetworkStack",
        config=config,
        env=cdk.Environment(account="123456789012", region="us-east-1"),
    )

    template = assertions.Template.from_stack(stack)

    # Assert public subnets exist
    template.resource_count_is("AWS::EC2::Subnet", 8)  # 4 types × 2 AZs


def test_security_groups_created() -> None:
    """Test that all security groups are created."""
    app = cdk.App()
    config = DevelopmentConfig()

    stack = NetworkStack(
        app,
        "TestNetworkStack",
        config=config,
        env=cdk.Environment(account="123456789012", region="us-east-1"),
    )

    template = assertions.Template.from_stack(stack)

    # Assert security groups exist
    # ALB, ECS, RDS, Redis, (no EFS in dev, no OpenSearch in dev)
    template.resource_count_is("AWS::EC2::SecurityGroup", 4)


def test_alb_security_group_rules() -> None:
    """Test ALB security group has correct ingress rules."""
    app = cdk.App()
    config = DevelopmentConfig()

    stack = NetworkStack(
        app,
        "TestNetworkStack",
        config=config,
        env=cdk.Environment(account="123456789012", region="us-east-1"),
    )

    template = assertions.Template.from_stack(stack)

    # Check for HTTP ingress rule
    template.has_resource_properties(
        "AWS::EC2::SecurityGroupIngress",
        {
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80,
            "CidrIp": "0.0.0.0/0",
        },
    )

    # Check for HTTPS ingress rule
    template.has_resource_properties(
        "AWS::EC2::SecurityGroupIngress",
        {
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "CidrIp": "0.0.0.0/0",
        },
    )


def test_nat_gateway_disabled_in_dev() -> None:
    """Test that NAT Gateway is not created in dev environment."""
    app = cdk.App()
    config = DevelopmentConfig()

    stack = NetworkStack(
        app,
        "TestNetworkStack",
        config=config,
        env=cdk.Environment(account="123456789012", region="us-east-1"),
    )

    template = assertions.Template.from_stack(stack)

    # Assert no NAT Gateway in dev
    template.resource_count_is("AWS::EC2::NatGateway", 0)


def test_internet_gateway_created() -> None:
    """Test that Internet Gateway is created."""
    app = cdk.App()
    config = DevelopmentConfig()

    stack = NetworkStack(
        app,
        "TestNetworkStack",
        config=config,
        env=cdk.Environment(account="123456789012", region="us-east-1"),
    )

    template = assertions.Template.from_stack(stack)

    # Assert Internet Gateway exists
    template.resource_count_is("AWS::EC2::InternetGateway", 1)


def test_stack_has_tags() -> None:
    """Test that stack resources are tagged correctly."""
    app = cdk.App()
    config = DevelopmentConfig()

    stack = NetworkStack(
        app,
        "TestNetworkStack",
        config=config,
        env=cdk.Environment(account="123456789012", region="us-east-1"),
    )

    template = assertions.Template.from_stack(stack)

    # VPC should have project and environment tags
    template.has_resource_properties(
        "AWS::EC2::VPC",
        {
            "Tags": assertions.Match.array_with(
                [
                    {"Key": "Project", "Value": "cybershield"},
                    {"Key": "Environment", "Value": "dev"},
                ]
            ),
        },
    )
