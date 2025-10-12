"""
Storage Stack for CyberShield

Creates storage infrastructure including:
- S3 buckets for uploads and backups
- EFS file system for Milvus (optional)
- Lifecycle policies and encryption
"""

from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    aws_efs as efs,
    aws_s3 as s3,
)
from constructs import Construct

from config.constants import (
    EFS_PROVISIONED_THROUGHPUT_MIBPS,
    EFS_TRANSITION_TO_IA_DAYS,
    S3_LIFECYCLE_EXPIRATION_DAYS,
    S3_LIFECYCLE_TRANSITION_GLACIER_DAYS,
    S3_LIFECYCLE_TRANSITION_STANDARD_IA_DAYS,
    S3_NONCURRENT_VERSION_EXPIRATION_DAYS,
)
from config.environments import EnvironmentConfig


class StorageStack(Stack):
    """Stack for storage infrastructure."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        config: EnvironmentConfig,
        network_stack: object,
        **kwargs: object,
    ) -> None:
        """
        Initialize Storage stack.

        Args:
            scope: CDK app or parent construct
            construct_id: Unique identifier for this stack
            config: Environment-specific configuration
            network_stack: Network stack for VPC and security groups
            **kwargs: Additional stack properties
        """
        super().__init__(scope, construct_id, **kwargs)

        self.config = config
        self.network_stack = network_stack

        # Create S3 buckets
        self.uploads_bucket = self._create_uploads_bucket()
        self.backups_bucket = self._create_backups_bucket()

        # Create EFS file system for Milvus (optional)
        self.milvus_file_system = None
        if config.enable_efs_for_milvus:
            self.milvus_file_system = self._create_milvus_efs()

    def _create_uploads_bucket(self) -> s3.Bucket:
        """
        Create S3 bucket for file uploads.

        Returns:
            s3.Bucket: S3 bucket for uploads
        """
        bucket = s3.Bucket(
            self,
            "UploadsBucket",
            bucket_name=f"{self.config.project_name}-{self.config.environment}-uploads",
            encryption=s3.BucketEncryption.S3_MANAGED,
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.RETAIN
            if self.config.enable_deletion_protection
            else RemovalPolicy.DESTROY,
            auto_delete_objects=not self.config.enable_deletion_protection,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="TransitionToIA",
                    enabled=True,
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INFREQUENT_ACCESS,
                            transition_after=Duration.days(
                                S3_LIFECYCLE_TRANSITION_STANDARD_IA_DAYS
                            ),
                        ),
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(
                                S3_LIFECYCLE_TRANSITION_GLACIER_DAYS
                            ),
                        ),
                    ],
                    expiration=Duration.days(S3_LIFECYCLE_EXPIRATION_DAYS),
                ),
                s3.LifecycleRule(
                    id="DeleteOldVersions",
                    enabled=True,
                    noncurrent_version_expiration=Duration.days(
                        S3_NONCURRENT_VERSION_EXPIRATION_DAYS
                    ),
                ),
            ],
        )

        return bucket

    def _create_backups_bucket(self) -> s3.Bucket:
        """
        Create S3 bucket for backups.

        Returns:
            s3.Bucket: S3 bucket for backups
        """
        bucket = s3.Bucket(
            self,
            "BackupsBucket",
            bucket_name=f"{self.config.project_name}-{self.config.environment}-backups",
            encryption=s3.BucketEncryption.S3_MANAGED,
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.RETAIN,  # Always retain backups
            auto_delete_objects=False,  # Never auto-delete backups
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="TransitionBackupsToGlacier",
                    enabled=True,
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(30),
                        ),
                        s3.Transition(
                            storage_class=s3.StorageClass.DEEP_ARCHIVE,
                            transition_after=Duration.days(90),
                        ),
                    ],
                ),
            ],
        )

        return bucket

    def _create_milvus_efs(self) -> efs.FileSystem | None:
        """
        Create EFS file system for Milvus vector database.

        Returns:
            efs.FileSystem: EFS file system or None if disabled
        """
        if not self.config.enable_efs_for_milvus:
            return None

        file_system = efs.FileSystem(
            self,
            "MilvusFileSystem",
            vpc=self.network_stack.vpc,
            file_system_name=f"{self.config.project_name}-{self.config.environment}-milvus",
            encrypted=True,
            performance_mode=efs.PerformanceMode.GENERAL_PURPOSE,
            throughput_mode=efs.ThroughputMode.PROVISIONED,
            provisioned_throughput_per_second=EFS_PROVISIONED_THROUGHPUT_MIBPS,
            lifecycle_policy=efs.LifecyclePolicy.AFTER_7_DAYS,
            removal_policy=RemovalPolicy.RETAIN
            if self.config.enable_deletion_protection
            else RemovalPolicy.DESTROY,
            security_group=self.network_stack.efs_security_group,
            vpc_subnets={"subnets": self.network_stack.private_subnets},
        )

        return file_system

    @property
    def uploads_bucket_name(self) -> str:
        """Get uploads bucket name."""
        return self.uploads_bucket.bucket_name

    @property
    def backups_bucket_name(self) -> str:
        """Get backups bucket name."""
        return self.backups_bucket.bucket_name

    @property
    def milvus_file_system_id(self) -> str | None:
        """Get Milvus EFS file system ID."""
        return (
            self.milvus_file_system.file_system_id if self.milvus_file_system else None
        )
