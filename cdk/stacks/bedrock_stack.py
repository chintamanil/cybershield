"""
Bedrock Stack for CyberShield

Creates AI/ML infrastructure including:
- S3 buckets for training data and model artifacts
- VPC endpoint for Bedrock (optional)
- IAM roles for Bedrock fine-tuning
- CloudWatch log groups for Bedrock
"""

from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_logs as logs,
    aws_s3 as s3,
)
from constructs import Construct

from config.constants import (
    BEDROCK_MODEL_ARTIFACTS_RETENTION_DAYS,
    BEDROCK_TRAINING_DATA_RETENTION_DAYS,
)
from config.environments import EnvironmentConfig


class BedrockStack(Stack):
    """Stack for Bedrock AI/ML infrastructure."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        config: EnvironmentConfig,
        network_stack: object,
        **kwargs: object,
    ) -> None:
        """
        Initialize Bedrock stack.

        Args:
            scope: CDK app or parent construct
            construct_id: Unique identifier for this stack
            config: Environment-specific configuration
            network_stack: Network stack for VPC
            **kwargs: Additional stack properties
        """
        super().__init__(scope, construct_id, **kwargs)

        self.config = config
        self.network_stack = network_stack

        # Create S3 buckets for training data and model artifacts
        self.training_data_bucket = self._create_training_data_bucket()
        self.model_artifacts_bucket = self._create_model_artifacts_bucket()

        # Create VPC endpoint for Bedrock (if enabled)
        if config.enable_bedrock_vpc_endpoint:
            self.bedrock_vpc_endpoint = self._create_bedrock_vpc_endpoint()

        # Create CloudWatch log group for Bedrock
        self.log_group = self._create_log_group()

    def _create_training_data_bucket(self) -> s3.Bucket:
        """
        Create S3 bucket for Bedrock training data.

        Returns:
            s3.Bucket: Training data bucket
        """
        bucket = s3.Bucket(
            self,
            "TrainingDataBucket",
            bucket_name=f"{self.config.project_name}-{self.config.environment}-bedrock-training",
            encryption=s3.BucketEncryption.S3_MANAGED,
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.RETAIN,
            auto_delete_objects=False,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="ExpireOldData",
                    enabled=True,
                    expiration=Duration.days(BEDROCK_TRAINING_DATA_RETENTION_DAYS),
                )
            ],
        )

        return bucket

    def _create_model_artifacts_bucket(self) -> s3.Bucket:
        """
        Create S3 bucket for Bedrock model artifacts.

        Returns:
            s3.Bucket: Model artifacts bucket
        """
        bucket = s3.Bucket(
            self,
            "ModelArtifactsBucket",
            bucket_name=f"{self.config.project_name}-{self.config.environment}-bedrock-models",
            encryption=s3.BucketEncryption.S3_MANAGED,
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.RETAIN,
            auto_delete_objects=False,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="TransitionOldModels",
                    enabled=True,
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(90),
                        )
                    ],
                    expiration=Duration.days(BEDROCK_MODEL_ARTIFACTS_RETENTION_DAYS),
                )
            ],
        )

        return bucket

    def _create_bedrock_vpc_endpoint(self) -> ec2.InterfaceVpcEndpoint:
        """
        Create VPC endpoint for Bedrock (private connectivity).

        Returns:
            ec2.InterfaceVpcEndpoint: Bedrock VPC endpoint
        """
        vpc_endpoint = ec2.InterfaceVpcEndpoint(
            self,
            "BedrockVpcEndpoint",
            vpc=self.network_stack.vpc,
            service=ec2.InterfaceVpcEndpointService(
                f"com.amazonaws.{self.config.aws_region}.bedrock-runtime",
                443,
            ),
            subnets=ec2.SubnetSelection(subnets=self.network_stack.private_subnets),
            private_dns_enabled=True,
        )

        return vpc_endpoint

    def _create_log_group(self) -> logs.LogGroup:
        """
        Create CloudWatch log group for Bedrock.

        Returns:
            logs.LogGroup: CloudWatch log group
        """
        log_group = logs.LogGroup(
            self,
            "BedrockLogGroup",
            log_group_name=f"/aws/bedrock/{self.config.project_name}-{self.config.environment}",
            retention=logs.RetentionDays(self.config.cloudwatch_log_retention_days)
            if self.config.cloudwatch_log_retention_days <= 30
            else logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.DESTROY,
        )

        return log_group

    @property
    def training_data_bucket_name(self) -> str:
        """Get training data bucket name."""
        return self.training_data_bucket.bucket_name

    @property
    def model_artifacts_bucket_name(self) -> str:
        """Get model artifacts bucket name."""
        return self.model_artifacts_bucket.bucket_name
