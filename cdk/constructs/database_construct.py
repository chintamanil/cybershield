"""
Reusable Database Construct

Provides high-level abstractions for creating databases with:
- PostgreSQL RDS instances
- ElastiCache Redis clusters
- Best practices and secure defaults
- Automated backups
- Monitoring integration
"""

from typing import Any

from aws_cdk import (
    Duration,
    RemovalPolicy,
    aws_ec2 as ec2,
    aws_elasticache as elasticache,
    aws_rds as rds,
    aws_secretsmanager as secretsmanager,
)
from constructs import Construct


class PostgresConstruct(Construct):
    """
    Reusable construct for PostgreSQL RDS instances.

    Encapsulates best practices for RDS including:
    - Secure credential management
    - Automated backups
    - Parameter groups
    - Monitoring options
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        vpc: ec2.IVpc,
        database_subnets: list[ec2.ISubnet],
        security_group: ec2.ISecurityGroup,
        instance_identifier: str,
        database_name: str,
        username: str = "admin",
        instance_class: str = "db.t3.micro",
        allocated_storage: int = 20,
        engine_version: str = "15.7",
        backup_retention_days: int = 7,
        backup_window: str = "03:00-04:00",
        maintenance_window: str = "sun:04:00-sun:05:00",
        enable_monitoring: bool = False,
        monitoring_interval: int = 60,
        enable_performance_insights: bool = False,
        deletion_protection: bool = False,
        **kwargs: Any,
    ) -> None:
        """
        Initialize PostgreSQL construct.

        Args:
            scope: Parent construct
            construct_id: Unique identifier
            vpc: VPC for database
            database_subnets: Subnets for database
            security_group: Security group
            instance_identifier: Database instance ID
            database_name: Initial database name
            username: Master username
            instance_class: RDS instance class
            allocated_storage: Storage size in GB
            engine_version: PostgreSQL version
            backup_retention_days: Backup retention period
            backup_window: Preferred backup window
            maintenance_window: Preferred maintenance window
            enable_monitoring: Enable enhanced monitoring
            monitoring_interval: Monitoring interval in seconds
            enable_performance_insights: Enable Performance Insights
            deletion_protection: Enable deletion protection
            **kwargs: Additional construct properties
        """
        super().__init__(scope, construct_id, **kwargs)

        # Create password secret
        self.password_secret = secretsmanager.Secret(
            self,
            "PasswordSecret",
            secret_name=f"{instance_identifier}-password",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                exclude_punctuation=True,
                include_space=False,
                password_length=32,
            ),
        )

        # Create subnet group
        subnet_group = rds.SubnetGroup(
            self,
            "SubnetGroup",
            subnet_group_name=f"{instance_identifier}-subnet-group",
            description=f"Subnet group for {instance_identifier}",
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnets=database_subnets),
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Create parameter group
        parameter_group = rds.ParameterGroup(
            self,
            "ParameterGroup",
            engine=rds.DatabaseInstanceEngine.postgres(
                version=rds.PostgresEngineVersion.of(engine_version, engine_version)
            ),
            description=f"Parameter group for {instance_identifier}",
            parameters={
                "shared_preload_libraries": "pg_stat_statements",
                "log_statement": "all",
                "log_min_duration_statement": "1000",
            },
        )

        # Create RDS instance
        self.instance = rds.DatabaseInstance(
            self,
            "Instance",
            instance_identifier=instance_identifier,
            engine=rds.DatabaseInstanceEngine.postgres(
                version=rds.PostgresEngineVersion.of(engine_version, engine_version)
            ),
            instance_type=rds.InstanceType.of(
                rds.InstanceClass.BURSTABLE3,
                rds.InstanceSize.MICRO
                if instance_class == "db.t3.micro"
                else rds.InstanceSize.SMALL,
            ),
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnets=database_subnets),
            security_groups=[security_group],
            subnet_group=subnet_group,
            parameter_group=parameter_group,
            database_name=database_name,
            credentials=rds.Credentials.from_password(
                username=username,
                password=self.password_secret.secret_value,
            ),
            allocated_storage=allocated_storage,
            storage_type=rds.StorageType.GP2,
            storage_encrypted=True,
            multi_az=False,
            backup_retention=Duration.days(backup_retention_days),
            preferred_backup_window=backup_window,
            preferred_maintenance_window=maintenance_window,
            deletion_protection=deletion_protection,
            removal_policy=RemovalPolicy.SNAPSHOT if backup_retention_days > 0 else RemovalPolicy.DESTROY,
            enabled_cloudwatch_logs_exports=["postgresql"],
            monitoring_interval=Duration.seconds(monitoring_interval)
            if enable_monitoring
            else None,
            enable_performance_insights=enable_performance_insights,
        )

    @property
    def endpoint(self) -> str:
        """Get database endpoint."""
        return self.instance.db_instance_endpoint_address

    @property
    def port(self) -> str:
        """Get database port."""
        return self.instance.db_instance_endpoint_port


class RedisConstruct(Construct):
    """
    Reusable construct for ElastiCache Redis clusters.

    Provides secure Redis instances with:
    - Subnet groups
    - Parameter groups
    - Encryption options
    - Backup configuration
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        vpc: ec2.IVpc,
        cache_subnets: list[ec2.ISubnet],
        security_group: ec2.ISecurityGroup,
        cluster_id: str,
        node_type: str = "cache.t3.micro",
        engine_version: str = "7.0",
        parameter_group_family: str = "redis7",
        backup_retention_days: int = 7,
        maintenance_window: str = "sun:04:00-sun:05:00",
        **kwargs: Any,
    ) -> None:
        """
        Initialize Redis construct.

        Args:
            scope: Parent construct
            construct_id: Unique identifier
            vpc: VPC for Redis
            cache_subnets: Subnets for Redis
            security_group: Security group
            cluster_id: Redis cluster ID
            node_type: Cache node type
            engine_version: Redis version
            parameter_group_family: Parameter group family
            backup_retention_days: Snapshot retention period
            maintenance_window: Preferred maintenance window
            **kwargs: Additional construct properties
        """
        super().__init__(scope, construct_id, **kwargs)

        # Create subnet group
        subnet_group = elasticache.CfnSubnetGroup(
            self,
            "SubnetGroup",
            cache_subnet_group_name=f"{cluster_id}-subnet-group",
            description=f"Subnet group for {cluster_id}",
            subnet_ids=[subnet.subnet_id for subnet in cache_subnets],
        )

        # Create parameter group
        parameter_group = elasticache.CfnParameterGroup(
            self,
            "ParameterGroup",
            cache_parameter_group_family=parameter_group_family,
            description=f"Parameter group for {cluster_id}",
            properties={
                "maxmemory-policy": "allkeys-lru",
            },
        )

        # Create Redis cluster
        self.cluster = elasticache.CfnCacheCluster(
            self,
            "Cluster",
            cache_cluster_id=cluster_id,
            engine="redis",
            engine_version=engine_version,
            cache_node_type=node_type,
            num_cache_nodes=1,
            vpc_security_group_ids=[security_group.security_group_id],
            cache_subnet_group_name=subnet_group.cache_subnet_group_name,
            cache_parameter_group_name=parameter_group.ref,
            auto_minor_version_upgrade=True,
            snapshot_retention_limit=backup_retention_days,
            preferred_maintenance_window=maintenance_window,
            az_mode="single-az",
        )

        self.cluster.add_dependency(subnet_group)
        self.cluster.add_dependency(parameter_group)

    @property
    def endpoint(self) -> str:
        """Get Redis endpoint."""
        return self.cluster.attr_redis_endpoint_address

    @property
    def port(self) -> str:
        """Get Redis port."""
        return self.cluster.attr_redis_endpoint_port
