"""
Data Stack for CyberShield

Creates data layer infrastructure including:
- RDS PostgreSQL database with automated backups
- ElastiCache Redis cluster for caching
- OpenSearch domain for logging and search (optional)
- Database subnet groups and parameter groups
"""

from aws_cdk import (
    Duration,
    RemovalPolicy,
    SecretValue,
    Stack,
    aws_elasticache as elasticache,
    aws_opensearchservice as opensearch,
    aws_rds as rds,
    aws_secretsmanager as secretsmanager,
)
from constructs import Construct

from config.environments import EnvironmentConfig


class DataStack(Stack):
    """Stack for data layer infrastructure."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        config: EnvironmentConfig,
        network_stack: object,
        **kwargs: object,
    ) -> None:
        """
        Initialize Data stack.

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

        # Create database password secret
        self.db_password_secret = self._create_db_password_secret()

        # Create RDS PostgreSQL database
        self.rds_instance = self._create_rds_instance()

        # Create ElastiCache Redis cluster
        self.redis_cluster = self._create_redis_cluster()

        # Create OpenSearch domain (optional)
        self.opensearch_domain = None
        if config.enable_opensearch:
            self.opensearch_domain = self._create_opensearch_domain()

    def _create_db_password_secret(self) -> secretsmanager.Secret:
        """
        Create secret for database password.

        Returns:
            secretsmanager.Secret: Database password secret
        """
        secret = secretsmanager.Secret(
            self,
            "DbPasswordSecret",
            secret_name=f"{self.config.project_name}/{self.config.environment}/db-password",
            description=f"PostgreSQL password for {self.config.project_name} {self.config.environment}",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                exclude_punctuation=True,
                include_space=False,
                password_length=32,
            ),
        )

        return secret

    def _create_rds_instance(self) -> rds.DatabaseInstance:
        """
        Create RDS PostgreSQL database instance.

        Returns:
            rds.DatabaseInstance: RDS PostgreSQL instance
        """
        # Create subnet group for RDS
        subnet_group = rds.SubnetGroup(
            self,
            "RdsSubnetGroup",
            subnet_group_name=f"{self.config.project_name}-{self.config.environment}-rds",
            description=f"Subnet group for {self.config.project_name} RDS",
            vpc=self.network_stack.vpc,
            vpc_subnets={"subnets": self.network_stack.database_subnets},
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Create parameter group for PostgreSQL
        parameter_group = rds.ParameterGroup(
            self,
            "RdsParameterGroup",
            engine=rds.DatabaseInstanceEngine.postgres(
                version=rds.PostgresEngineVersion.of(
                    self.config.db_engine_version, self.config.db_engine_version
                )
            ),
            description=f"Parameter group for {self.config.project_name} PostgreSQL",
            parameters={
                "shared_preload_libraries": "pg_stat_statements",
                "log_statement": "all",
                "log_min_duration_statement": "1000",  # Log queries > 1s
            },
        )

        # Create RDS instance
        instance = rds.DatabaseInstance(
            self,
            "RdsInstance",
            instance_identifier=f"{self.config.project_name}-{self.config.environment}-postgres",
            engine=rds.DatabaseInstanceEngine.postgres(
                version=rds.PostgresEngineVersion.of(
                    self.config.db_engine_version, self.config.db_engine_version
                )
            ),
            instance_type=rds.InstanceType.of(
                rds.InstanceClass.BURSTABLE3, rds.InstanceSize.MICRO
            )
            if self.config.db_instance_class == "db.t3.micro"
            else rds.InstanceType.of(
                rds.InstanceClass.BURSTABLE3, rds.InstanceSize.SMALL
            ),
            vpc=self.network_stack.vpc,
            vpc_subnets={"subnets": self.network_stack.database_subnets},
            security_groups=[self.network_stack.rds_security_group],
            subnet_group=subnet_group,
            parameter_group=parameter_group,
            database_name=self.config.db_name,
            credentials=rds.Credentials.from_password(
                username=self.config.db_username,
                password=self.db_password_secret.secret_value,
            ),
            allocated_storage=self.config.db_allocated_storage,
            storage_type=rds.StorageType.GP2,
            storage_encrypted=True,
            multi_az=False,  # Cost optimization
            backup_retention=Duration.days(self.config.backup_retention_days),
            preferred_backup_window=self.config.backup_window,
            preferred_maintenance_window=self.config.maintenance_window,
            deletion_protection=self.config.enable_deletion_protection,
            removal_policy=RemovalPolicy.SNAPSHOT
            if self.config.enable_backup
            else RemovalPolicy.DESTROY,
            enabled_cloudwatch_logs_exports=["postgresql"]
            if self.config.enable_logging
            else None,
            monitoring_interval=Duration.seconds(self.config.monitoring_interval)
            if self.config.enable_monitoring
            else None,
            enable_performance_insights=self.config.enable_performance_insights,
        )

        return instance

    def _create_redis_cluster(self) -> elasticache.CfnCacheCluster:
        """
        Create ElastiCache Redis cluster.

        Returns:
            elasticache.CfnCacheCluster: Redis cluster
        """
        # Create subnet group for Redis
        subnet_group = elasticache.CfnSubnetGroup(
            self,
            "RedisSubnetGroup",
            cache_subnet_group_name=f"{self.config.project_name}-{self.config.environment}-redis",
            description=f"Subnet group for {self.config.project_name} Redis",
            subnet_ids=[subnet.subnet_id for subnet in self.network_stack.cache_subnets],
        )

        # Create parameter group for Redis
        parameter_group = elasticache.CfnParameterGroup(
            self,
            "RedisParameterGroup",
            cache_parameter_group_family=self.config.redis_parameter_group_family,
            description=f"Parameter group for {self.config.project_name} Redis",
            properties={
                "maxmemory-policy": "allkeys-lru",
            },
        )

        # Create Redis cluster
        cluster = elasticache.CfnCacheCluster(
            self,
            "RedisCluster",
            cache_cluster_id=f"{self.config.project_name}-{self.config.environment}-redis",
            engine="redis",
            engine_version=self.config.redis_engine_version,
            cache_node_type=self.config.redis_node_type,
            num_cache_nodes=1,
            vpc_security_group_ids=[
                self.network_stack.redis_security_group.security_group_id
            ],
            cache_subnet_group_name=subnet_group.cache_subnet_group_name,
            cache_parameter_group_name=parameter_group.ref,
            auto_minor_version_upgrade=True,
            snapshot_retention_limit=self.config.backup_retention_days
            if self.config.enable_backup
            else 0,
            preferred_maintenance_window=self.config.maintenance_window,
            az_mode="single-az",  # Cost optimization
        )

        cluster.add_dependency(subnet_group)
        cluster.add_dependency(parameter_group)

        return cluster

    def _create_opensearch_domain(self) -> opensearch.Domain | None:
        """
        Create OpenSearch domain for logging and search.

        Returns:
            opensearch.Domain: OpenSearch domain or None if disabled
        """
        if not self.config.enable_opensearch:
            return None

        domain = opensearch.Domain(
            self,
            "OpenSearchDomain",
            domain_name=f"{self.config.project_name}-{self.config.environment}",
            version=opensearch.EngineVersion.OPENSEARCH_2_11,
            capacity=opensearch.CapacityConfig(
                data_node_instance_type=self.config.opensearch_instance_type,
                data_nodes=self.config.opensearch_instance_count,
            ),
            ebs=opensearch.EbsOptions(
                enabled=True,
                volume_size=self.config.opensearch_volume_size,
                volume_type=ec2.EbsDeviceVolumeType.GP2,
            ),
            zone_awareness=opensearch.ZoneAwarenessConfig(
                enabled=self.config.enable_zone_awareness,
                availability_zone_count=2 if self.config.enable_zone_awareness else 1,
            ),
            encryption_at_rest=opensearch.EncryptionAtRestOptions(
                enabled=self.config.enable_encryption_at_rest
            ),
            node_to_node_encryption=self.config.enable_node_to_node_encryption,
            enforce_https=True,
            vpc=self.network_stack.vpc,
            vpc_subnets=[{"subnets": self.network_stack.private_subnets}],
            security_groups=[self.network_stack.opensearch_security_group],
            removal_policy=RemovalPolicy.DESTROY
            if not self.config.enable_deletion_protection
            else RemovalPolicy.RETAIN,
        )

        return domain

    @property
    def rds_endpoint(self) -> str:
        """Get RDS endpoint address."""
        return self.rds_instance.db_instance_endpoint_address

    @property
    def rds_port(self) -> str:
        """Get RDS port."""
        return self.rds_instance.db_instance_endpoint_port

    @property
    def redis_endpoint(self) -> str:
        """Get Redis endpoint address."""
        return self.redis_cluster.attr_redis_endpoint_address

    @property
    def redis_port(self) -> str:
        """Get Redis port."""
        return self.redis_cluster.attr_redis_endpoint_port

    @property
    def opensearch_endpoint(self) -> str | None:
        """Get OpenSearch endpoint."""
        return (
            self.opensearch_domain.domain_endpoint if self.opensearch_domain else None
        )
