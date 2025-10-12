"""
Network Stack for CyberShield

Creates networking infrastructure including:
- VPC with public, private, database, and cache subnets
- Internet Gateway and NAT Gateways (optional)
- Security groups for ALB, ECS, RDS, Redis, and OpenSearch
- Network ACLs and route tables
"""

from aws_cdk import Stack, aws_ec2 as ec2
from constructs import Construct

from config.constants import (
    BACKEND_PORT,
    CACHE_SUBNET_OFFSET,
    DATABASE_SUBNET_OFFSET,
    DEFAULT_AZS,
    FRONTEND_PORT,
    OPENSEARCH_PORT,
    POSTGRES_PORT,
    PRIVATE_SUBNET_OFFSET,
    PUBLIC_SUBNET_OFFSET,
    REDIS_PORT,
)
from config.environments import EnvironmentConfig


class NetworkStack(Stack):
    """Stack for network infrastructure."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        config: EnvironmentConfig,
        **kwargs: object,
    ) -> None:
        """
        Initialize Network stack.

        Args:
            scope: CDK app or parent construct
            construct_id: Unique identifier for this stack
            config: Environment-specific configuration
            **kwargs: Additional stack properties
        """
        super().__init__(scope, construct_id, **kwargs)

        self.config = config

        # Create VPC
        self.vpc = self._create_vpc()

        # Create security groups
        self.alb_security_group = self._create_alb_security_group()
        self.ecs_security_group = self._create_ecs_security_group()
        self.rds_security_group = self._create_rds_security_group()
        self.redis_security_group = self._create_redis_security_group()
        if config.enable_opensearch:
            self.opensearch_security_group = self._create_opensearch_security_group()
        if config.enable_efs_for_milvus:
            self.efs_security_group = self._create_efs_security_group()

    def _create_vpc(self) -> ec2.Vpc:
        """
        Create VPC with subnets.

        Returns:
            ec2.Vpc: VPC with public, private, database, and cache subnets
        """
        # Define subnet configuration
        subnet_configuration: list[ec2.SubnetConfiguration] = [
            # Public subnets for ALB and (optionally) ECS tasks
            ec2.SubnetConfiguration(
                name="Public",
                subnet_type=ec2.SubnetType.PUBLIC,
                cidr_mask=24,
                map_public_ip_on_launch=True,
            ),
            # Private subnets for ECS tasks (if NAT gateway enabled)
            ec2.SubnetConfiguration(
                name="Private",
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                if self.config.enable_nat_gateway
                else ec2.SubnetType.PRIVATE_ISOLATED,
                cidr_mask=24,
            ),
            # Database subnets (isolated, no internet access)
            ec2.SubnetConfiguration(
                name="Database",
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                cidr_mask=24,
            ),
            # Cache subnets (isolated, no internet access)
            ec2.SubnetConfiguration(
                name="Cache",
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                cidr_mask=24,
            ),
        ]

        # Create VPC
        vpc = ec2.Vpc(
            self,
            "Vpc",
            vpc_name=f"{self.config.project_name}-{self.config.environment}-vpc",
            ip_addresses=ec2.IpAddresses.cidr(self.config.vpc_cidr),
            max_azs=DEFAULT_AZS,
            nat_gateways=DEFAULT_AZS if self.config.enable_nat_gateway else 0,
            subnet_configuration=subnet_configuration,
            enable_dns_hostnames=True,
            enable_dns_support=True,
        )

        return vpc

    def _create_alb_security_group(self) -> ec2.SecurityGroup:
        """
        Create security group for Application Load Balancer.

        Returns:
            ec2.SecurityGroup: ALB security group
        """
        sg = ec2.SecurityGroup(
            self,
            "AlbSecurityGroup",
            vpc=self.vpc,
            security_group_name=f"{self.config.project_name}-{self.config.environment}-alb-sg",
            description="Security group for Application Load Balancer",
            allow_all_outbound=True,
        )

        # Allow HTTP from internet
        sg.add_ingress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.tcp(80),
            description="HTTP from internet",
        )

        # Allow HTTPS from internet
        sg.add_ingress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.tcp(443),
            description="HTTPS from internet",
        )

        return sg

    def _create_ecs_security_group(self) -> ec2.SecurityGroup:
        """
        Create security group for ECS tasks.

        Returns:
            ec2.SecurityGroup: ECS security group
        """
        sg = ec2.SecurityGroup(
            self,
            "EcsSecurityGroup",
            vpc=self.vpc,
            security_group_name=f"{self.config.project_name}-{self.config.environment}-ecs-sg",
            description="Security group for ECS tasks",
            allow_all_outbound=True,
        )

        # Allow backend traffic from ALB
        sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(self.alb_security_group.security_group_id),
            connection=ec2.Port.tcp(BACKEND_PORT),
            description="Backend traffic from ALB",
        )

        # Allow frontend traffic from ALB
        sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(self.alb_security_group.security_group_id),
            connection=ec2.Port.tcp(FRONTEND_PORT),
            description="Frontend traffic from ALB",
        )

        return sg

    def _create_rds_security_group(self) -> ec2.SecurityGroup:
        """
        Create security group for RDS database.

        Returns:
            ec2.SecurityGroup: RDS security group
        """
        sg = ec2.SecurityGroup(
            self,
            "RdsSecurityGroup",
            vpc=self.vpc,
            security_group_name=f"{self.config.project_name}-{self.config.environment}-rds-sg",
            description="Security group for RDS PostgreSQL database",
            allow_all_outbound=True,
        )

        # Allow PostgreSQL from ECS
        sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(self.ecs_security_group.security_group_id),
            connection=ec2.Port.tcp(POSTGRES_PORT),
            description="PostgreSQL from ECS tasks",
        )

        return sg

    def _create_redis_security_group(self) -> ec2.SecurityGroup:
        """
        Create security group for Redis cluster.

        Returns:
            ec2.SecurityGroup: Redis security group
        """
        sg = ec2.SecurityGroup(
            self,
            "RedisSecurityGroup",
            vpc=self.vpc,
            security_group_name=f"{self.config.project_name}-{self.config.environment}-redis-sg",
            description="Security group for Redis cluster",
            allow_all_outbound=True,
        )

        # Allow Redis from ECS
        sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(self.ecs_security_group.security_group_id),
            connection=ec2.Port.tcp(REDIS_PORT),
            description="Redis from ECS tasks",
        )

        return sg

    def _create_opensearch_security_group(self) -> ec2.SecurityGroup:
        """
        Create security group for OpenSearch cluster.

        Returns:
            ec2.SecurityGroup: OpenSearch security group
        """
        sg = ec2.SecurityGroup(
            self,
            "OpenSearchSecurityGroup",
            vpc=self.vpc,
            security_group_name=f"{self.config.project_name}-{self.config.environment}-opensearch-sg",
            description="Security group for OpenSearch cluster",
            allow_all_outbound=True,
        )

        # Allow HTTPS from ECS
        sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(self.ecs_security_group.security_group_id),
            connection=ec2.Port.tcp(443),
            description="HTTPS from ECS tasks",
        )

        # Allow OpenSearch from ECS
        sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(self.ecs_security_group.security_group_id),
            connection=ec2.Port.tcp(OPENSEARCH_PORT),
            description="OpenSearch from ECS tasks",
        )

        return sg

    def _create_efs_security_group(self) -> ec2.SecurityGroup:
        """
        Create security group for EFS (Milvus storage).

        Returns:
            ec2.SecurityGroup: EFS security group
        """
        sg = ec2.SecurityGroup(
            self,
            "EfsSecurityGroup",
            vpc=self.vpc,
            security_group_name=f"{self.config.project_name}-{self.config.environment}-efs-sg",
            description="Security group for EFS (Milvus storage)",
            allow_all_outbound=True,
        )

        # Allow NFS from ECS
        sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(self.ecs_security_group.security_group_id),
            connection=ec2.Port.tcp(2049),
            description="NFS from ECS tasks",
        )

        return sg

    @property
    def public_subnets(self) -> list[ec2.ISubnet]:
        """Get public subnets."""
        return self.vpc.public_subnets

    @property
    def private_subnets(self) -> list[ec2.ISubnet]:
        """Get private subnets."""
        return self.vpc.private_subnets

    @property
    def isolated_subnets(self) -> list[ec2.ISubnet]:
        """Get isolated subnets."""
        return self.vpc.isolated_subnets

    @property
    def database_subnets(self) -> list[ec2.ISubnet]:
        """
        Get database subnets.

        Note: Database subnets are the first group of isolated subnets.
        """
        all_isolated = self.vpc.isolated_subnets
        num_azs = len(self.vpc.availability_zones)
        return all_isolated[:num_azs]

    @property
    def cache_subnets(self) -> list[ec2.ISubnet]:
        """
        Get cache subnets.

        Note: Cache subnets are the second group of isolated subnets.
        """
        all_isolated = self.vpc.isolated_subnets
        num_azs = len(self.vpc.availability_zones)
        return all_isolated[num_azs : num_azs * 2]
