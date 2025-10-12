#!/usr/bin/env python3
"""
CyberShield AWS CDK Application

Main entry point for deploying CyberShield infrastructure using AWS CDK.
This application orchestrates the deployment of all infrastructure stacks
in the correct dependency order.
"""

import os

import aws_cdk as cdk

from config.environments import get_environment_config
from stacks.compute_stack import ComputeStack
from stacks.data_stack import DataStack
from stacks.dns_stack import DnsStack
from stacks.iam_stack import IamStack
from stacks.load_balancer_stack import LoadBalancerStack
from stacks.monitoring_stack import MonitoringStack
from stacks.network_stack import NetworkStack
from stacks.storage_stack import StorageStack

# Import optional stacks
try:
    from stacks.bedrock_stack import BedrockStack

    BEDROCK_AVAILABLE = True
except ImportError:
    BEDROCK_AVAILABLE = False

# Get environment configuration
environment = os.getenv("ENVIRONMENT", "dev")
config = get_environment_config(environment)

# Initialize CDK app
app = cdk.App()

# Get environment from CDK context or environment variable
cdk_env = cdk.Environment(
    account=config.aws_account_id,
    region=config.aws_region,
)

# ============================================================================
# STACK DEPLOYMENT ORDER
# ============================================================================
# Stacks are deployed in dependency order:
# 1. IAM (no dependencies)
# 2. Network (no dependencies)
# 3. DNS (no dependencies)
# 4. Storage (no dependencies)
# 5. Data (depends on Network)
# 6. Load Balancer (depends on Network, DNS)
# 7. Compute (depends on Network, IAM, Data, Load Balancer, Storage)
# 8. Monitoring (depends on Compute)
# 9. Bedrock (optional, depends on Network)
# ============================================================================

# 1. IAM Stack - Creates roles and policies for ECS tasks
iam_stack = IamStack(
    app,
    f"{config.stack_name_prefix}IamStack",
    config=config,
    env=cdk_env,
    description=f"IAM roles and policies for {config.project_name} {config.environment}",
)

# 2. Network Stack - Creates VPC, subnets, and security groups
network_stack = NetworkStack(
    app,
    f"{config.stack_name_prefix}NetworkStack",
    config=config,
    env=cdk_env,
    description=f"Network infrastructure for {config.project_name} {config.environment}",
)

# 3. DNS Stack - Creates Route53 hosted zone and SSL certificates
dns_stack = DnsStack(
    app,
    f"{config.stack_name_prefix}DnsStack",
    config=config,
    env=cdk_env,
    description=f"DNS and SSL infrastructure for {config.project_name} {config.environment}",
)

# 4. Storage Stack - Creates S3 buckets and EFS (optional)
storage_stack = StorageStack(
    app,
    f"{config.stack_name_prefix}StorageStack",
    config=config,
    network_stack=network_stack,
    env=cdk_env,
    description=f"Storage infrastructure for {config.project_name} {config.environment}",
)

# 5. Data Stack - Creates RDS, ElastiCache, and optional OpenSearch
data_stack = DataStack(
    app,
    f"{config.stack_name_prefix}DataStack",
    config=config,
    network_stack=network_stack,
    env=cdk_env,
    description=f"Data layer infrastructure for {config.project_name} {config.environment}",
)

# 6. Load Balancer Stack - Creates ALB, target groups, and listeners
load_balancer_stack = LoadBalancerStack(
    app,
    f"{config.stack_name_prefix}LoadBalancerStack",
    config=config,
    network_stack=network_stack,
    dns_stack=dns_stack,
    env=cdk_env,
    description=f"Load balancer infrastructure for {config.project_name} {config.environment}",
)

# 7. Compute Stack - Creates ECR, ECS cluster, services, and auto-scaling
compute_stack = ComputeStack(
    app,
    f"{config.stack_name_prefix}ComputeStack",
    config=config,
    network_stack=network_stack,
    iam_stack=iam_stack,
    data_stack=data_stack,
    load_balancer_stack=load_balancer_stack,
    storage_stack=storage_stack,
    env=cdk_env,
    description=f"Compute infrastructure for {config.project_name} {config.environment}",
)

# 8. Monitoring Stack - Creates CloudWatch alarms and dashboards
monitoring_stack = MonitoringStack(
    app,
    f"{config.stack_name_prefix}MonitoringStack",
    config=config,
    compute_stack=compute_stack,
    load_balancer_stack=load_balancer_stack,
    data_stack=data_stack,
    env=cdk_env,
    description=f"Monitoring infrastructure for {config.project_name} {config.environment}",
)

# 9. Bedrock Stack (Optional) - Creates AI/ML fine-tuning resources
if config.enable_bedrock_finetuning and BEDROCK_AVAILABLE:
    bedrock_stack = BedrockStack(
        app,
        f"{config.stack_name_prefix}BedrockStack",
        config=config,
        network_stack=network_stack,
        env=cdk_env,
        description=f"Bedrock AI/ML infrastructure for {config.project_name} {config.environment}",
    )
    bedrock_stack.add_dependency(network_stack)

# ============================================================================
# STACK DEPENDENCIES
# ============================================================================
# Explicitly define stack dependencies to ensure proper deployment order

# Data stack depends on network
data_stack.add_dependency(network_stack)

# Load balancer depends on network and DNS
load_balancer_stack.add_dependency(network_stack)
if config.domain_name:
    load_balancer_stack.add_dependency(dns_stack)

# Storage stack depends on network (for EFS)
storage_stack.add_dependency(network_stack)

# Compute stack has multiple dependencies
compute_stack.add_dependency(network_stack)
compute_stack.add_dependency(iam_stack)
compute_stack.add_dependency(data_stack)
compute_stack.add_dependency(load_balancer_stack)
compute_stack.add_dependency(storage_stack)

# Monitoring depends on resources being monitored
monitoring_stack.add_dependency(compute_stack)
monitoring_stack.add_dependency(load_balancer_stack)
monitoring_stack.add_dependency(data_stack)

# ============================================================================
# TAGGING
# ============================================================================
# Apply common tags to all resources in the app
for key, value in config.common_tags.items():
    cdk.Tags.of(app).add(key, value)

# Add environment-specific tags
cdk.Tags.of(app).add("CdkVersion", cdk.VERSION)
cdk.Tags.of(app).add("DeployedBy", "cdk")

# ============================================================================
# OUTPUTS
# ============================================================================
# Key outputs are defined in individual stacks and can be accessed via:
# - aws cloudformation describe-stacks --stack-name <stack-name>
# - cdk deploy --outputs-file outputs.json

# Synthesize the CDK app
app.synth()
