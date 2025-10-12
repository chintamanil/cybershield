"""
IAM Stack for CyberShield

Creates IAM roles and policies for ECS tasks, including:
- ECS task execution role (for pulling images, logging)
- ECS task role (for application permissions)
- Policies for accessing AWS services (S3, RDS, ElastiCache, Bedrock, etc.)
"""

from aws_cdk import Stack, aws_iam as iam
from constructs import Construct

from config.environments import EnvironmentConfig


class IamStack(Stack):
    """Stack for IAM roles and policies."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        config: EnvironmentConfig,
        **kwargs: object,
    ) -> None:
        """
        Initialize IAM stack.

        Args:
            scope: CDK app or parent construct
            construct_id: Unique identifier for this stack
            config: Environment-specific configuration
            **kwargs: Additional stack properties
        """
        super().__init__(scope, construct_id, **kwargs)

        self.config = config

        # Create ECS task execution role
        self.ecs_task_execution_role = self._create_task_execution_role()

        # Create ECS task role
        self.ecs_task_role = self._create_task_role()

    def _create_task_execution_role(self) -> iam.Role:
        """
        Create ECS task execution role.

        This role is used by ECS to pull container images from ECR,
        write logs to CloudWatch, and retrieve secrets from Secrets Manager.

        Returns:
            iam.Role: ECS task execution role
        """
        role = iam.Role(
            self,
            "EcsTaskExecutionRole",
            role_name=f"{self.config.project_name}-{self.config.environment}-ecs-execution",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            description=f"ECS task execution role for {self.config.project_name} {self.config.environment}",
            managed_policies=[
                # AWS managed policy for ECS task execution
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AmazonECSTaskExecutionRolePolicy"
                ),
            ],
        )

        # Add permissions for ECR (private repositories)
        role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "ecr:GetAuthorizationToken",
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:BatchGetImage",
                ],
                resources=["*"],
            )
        )

        # Add permissions for CloudWatch Logs
        role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                resources=["*"],
            )
        )

        # Add permissions for Secrets Manager (if needed)
        role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "secretsmanager:GetSecretValue",
                    "ssm:GetParameters",
                ],
                resources=["*"],
            )
        )

        return role

    def _create_task_role(self) -> iam.Role:
        """
        Create ECS task role.

        This role is used by the application running in ECS containers
        to access AWS services (S3, RDS, ElastiCache, Bedrock, etc.).

        Returns:
            iam.Role: ECS task role
        """
        role = iam.Role(
            self,
            "EcsTaskRole",
            role_name=f"{self.config.project_name}-{self.config.environment}-ecs-task",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            description=f"ECS task role for {self.config.project_name} {self.config.environment}",
        )

        # S3 permissions for uploads and backups
        role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:DeleteObject",
                    "s3:ListBucket",
                ],
                resources=[
                    f"arn:aws:s3:::{self.config.project_name}-{self.config.environment}-*",
                    f"arn:aws:s3:::{self.config.project_name}-{self.config.environment}-*/*",
                ],
            )
        )

        # CloudWatch permissions for custom metrics and logs
        role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "cloudwatch:PutMetricData",
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                resources=["*"],
            )
        )

        # RDS permissions (limited to describe for connection string discovery)
        role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "rds:DescribeDBInstances",
                    "rds:DescribeDBClusters",
                ],
                resources=["*"],
            )
        )

        # ElastiCache permissions (limited to describe)
        role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "elasticache:DescribeCacheClusters",
                    "elasticache:DescribeReplicationGroups",
                ],
                resources=["*"],
            )
        )

        # Bedrock permissions (if enabled)
        if self.config.enable_bedrock_finetuning:
            role.add_to_policy(
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "bedrock:InvokeModel",
                        "bedrock:InvokeModelWithResponseStream",
                        "bedrock:ListFoundationModels",
                        "bedrock:GetFoundationModel",
                    ],
                    resources=["*"],
                )
            )

            # Bedrock fine-tuning permissions
            role.add_to_policy(
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "bedrock:CreateModelCustomizationJob",
                        "bedrock:GetModelCustomizationJob",
                        "bedrock:ListModelCustomizationJobs",
                        "bedrock:StopModelCustomizationJob",
                    ],
                    resources=["*"],
                )
            )

        # OpenSearch permissions (if enabled)
        if self.config.enable_opensearch:
            role.add_to_policy(
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "es:ESHttpGet",
                        "es:ESHttpPost",
                        "es:ESHttpPut",
                        "es:ESHttpHead",
                    ],
                    resources=[
                        f"arn:aws:es:{self.config.aws_region}:{self.config.aws_account_id}:domain/{self.config.project_name}-{self.config.environment}/*"
                    ],
                )
            )

        # ECS Exec permissions (if enabled)
        if self.config.enable_ecs_exec:
            role.add_to_policy(
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "ssmmessages:CreateControlChannel",
                        "ssmmessages:CreateDataChannel",
                        "ssmmessages:OpenControlChannel",
                        "ssmmessages:OpenDataChannel",
                    ],
                    resources=["*"],
                )
            )

        # EFS permissions (if enabled for Milvus)
        if self.config.enable_efs_for_milvus:
            role.add_to_policy(
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "elasticfilesystem:ClientMount",
                        "elasticfilesystem:ClientWrite",
                        "elasticfilesystem:ClientRootAccess",
                    ],
                    resources=["*"],
                    conditions={
                        "StringEquals": {
                            "elasticfilesystem:AccessPointArn": f"arn:aws:elasticfilesystem:{self.config.aws_region}:{self.config.aws_account_id}:access-point/*"
                        }
                    },
                )
            )

        # Systems Manager permissions for parameter store
        role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "ssm:GetParameter",
                    "ssm:GetParameters",
                    "ssm:GetParametersByPath",
                ],
                resources=[
                    f"arn:aws:ssm:{self.config.aws_region}:{self.config.aws_account_id}:parameter/{self.config.project_name}/{self.config.environment}/*"
                ],
            )
        )

        return role
