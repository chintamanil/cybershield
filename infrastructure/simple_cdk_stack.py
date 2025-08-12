#!/usr/bin/env python3
# Simplified AWS CDK Infrastructure for CyberShield

from aws_cdk import (
    App, Stack, Environment,
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_ecs_patterns as ecs_patterns,
    aws_elasticache as elasticache,
    aws_rds as rds,
    aws_secretsmanager as secretsmanager,
    aws_ssm as ssm,
    aws_s3 as s3,
    aws_logs as logs,
    aws_kms as kms,
    aws_iam as iam,
    Duration, RemovalPolicy
)
from constructs import Construct


class CyberShieldStack(Stack):
    """Simplified AWS infrastructure for CyberShield"""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create VPC
        self.vpc = ec2.Vpc(
            self, "CyberShieldVPC",
            max_azs=2,
            nat_gateways=1,
            enable_dns_hostnames=True,
            enable_dns_support=True,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="Public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24
                ),
                ec2.SubnetConfiguration(
                    name="Private",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=24
                ),
                ec2.SubnetConfiguration(
                    name="Database",
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                    cidr_mask=24
                )
            ]
        )

        # Create KMS key for encryption
        self.kms_key = kms.Key(
            self, "CyberShieldKey",
            description="CyberShield encryption key",
            enable_key_rotation=True
        )

        # Create S3 bucket for data storage
        self.s3_bucket = s3.Bucket(
            self, "CyberShieldDataBucket",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.kms_key,
            versioned=True,
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="archive-old-data",
                    enabled=True,
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INFREQUENT_ACCESS,
                            transition_after=Duration.days(30)
                        ),
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(90)
                        )
                    ]
                )
            ]
        )

        # Create Secrets Manager secrets
        self.api_keys_secret = secretsmanager.Secret(
            self, "CyberShieldAPIKeys",
            description="API keys for external security services",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                secret_string_template='{"virustotal":"REPLACE_ME", "shodan":"REPLACE_ME", "abuseipdb":"REPLACE_ME", "openai":"REPLACE_ME"}',
                generate_string_key="placeholder"
            )
        )

        self.rds_credentials = secretsmanager.Secret(
            self, "CyberShieldRDSCredentials",
            description="RDS database credentials",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                secret_string_template='{"username": "cybershield"}',
                generate_string_key="password",
                exclude_characters=' %+~`#$&*()|[]{}:;<>?!\'/@"\\',
                password_length=32
            )
        )

        # Create RDS PostgreSQL
        self.database = rds.DatabaseInstance(
            self, "CyberShieldDB",
            engine=rds.DatabaseInstanceEngine.postgres(
                version=rds.PostgresEngineVersion.VER_15_4
            ),
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.T3, ec2.InstanceSize.MICRO
            ),
            credentials=rds.Credentials.from_secret(self.rds_credentials),
            database_name="cybershield",
            vpc=self.vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED
            ),
            backup_retention=Duration.days(7),
            deletion_protection=False,  # Allow deletion for testing
            storage_encrypted=True,
            storage_encryption_key=self.kms_key,
            monitoring_interval=Duration.minutes(5),
            cloudwatch_logs_exports=["postgresql"]
        )

        # Create ElastiCache Redis
        redis_subnet_group = elasticache.CfnSubnetGroup(
            self, "RedisSubnetGroup",
            description="Subnet group for Redis",
            subnet_ids=[subnet.subnet_id for subnet in self.vpc.private_subnets]
        )

        # Create security group for Redis
        redis_sg = ec2.SecurityGroup(
            self, "RedisSecurityGroup",
            vpc=self.vpc,
            description="Security group for Redis cluster",
            allow_all_outbound=False
        )

        self.redis_cluster = elasticache.CfnCacheCluster(
            self, "CyberShieldRedis",
            engine="redis",
            cache_node_type="cache.t3.micro",
            num_cache_nodes=1,
            cache_subnet_group_name=redis_subnet_group.ref,
            vpc_security_group_ids=[redis_sg.security_group_id]
        )

        # Create ECS Cluster
        self.ecs_cluster = ecs.Cluster(
            self, "CyberShieldCluster",
            vpc=self.vpc,
            container_insights=True
        )

        # Create CloudWatch Log Group
        self.log_group = logs.LogGroup(
            self, "CyberShieldLogs",
            log_group_name="/aws/cybershield/application",
            retention=logs.RetentionDays.ONE_MONTH,
            encryption_key=self.kms_key
        )

        # Create ECS Service
        self.ecs_service = ecs_patterns.ApplicationLoadBalancedFargateService(
            self, "CyberShieldService",
            cluster=self.ecs_cluster,
            memory_limit_mib=2048,
            cpu=1024,
            desired_count=1,  # Start with 1 for cost optimization
            task_image_options=ecs_patterns.ApplicationLoadBalancedTaskImageOptions(
                image=ecs.ContainerImage.from_asset("..", file="deployment/Dockerfile.aws"),
                container_port=8000,
                environment={
                    "CYBERSHIELD_ENV": "aws",
                    "AWS_DEFAULT_REGION": self.region,
                    "RDS_ENDPOINT": self.database.instance_endpoint.hostname,
                    "ELASTICACHE_ENDPOINT": self.redis_cluster.attr_redis_endpoint_address,
                    "S3_BUCKET": self.s3_bucket.bucket_name
                },
                secrets={
                    "API_KEYS": ecs.Secret.from_secrets_manager(self.api_keys_secret),
                    "DB_CREDENTIALS": ecs.Secret.from_secrets_manager(self.rds_credentials)
                },
                log_driver=ecs.LogDrivers.aws_logs(
                    stream_prefix="cybershield",
                    log_group=self.log_group
                )
            ),
            public_load_balancer=True
        )

        # Configure health checks
        self.ecs_service.target_group.configure_health_check(
            path="/health",
            healthy_http_codes="200",
            interval=Duration.seconds(30),
            timeout=Duration.seconds(10)
        )

        # Allow Redis access from ECS
        redis_sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(self.ecs_service.service.connections.security_groups[0].security_group_id),
            connection=ec2.Port.tcp(6379),
            description="Allow Redis access from ECS"
        )

        # Grant permissions to ECS task
        self._grant_ecs_permissions()

        # Output important values
        self._create_outputs()

    def _grant_ecs_permissions(self):
        """Grant necessary permissions to ECS task"""
        # Secrets Manager permissions
        self.api_keys_secret.grant_read(self.ecs_service.task_definition.task_role)
        self.rds_credentials.grant_read(self.ecs_service.task_definition.task_role)

        # CloudWatch Logs permissions
        self.log_group.grant_write(self.ecs_service.task_definition.task_role)

        # S3 permissions
        self.s3_bucket.grant_read_write(self.ecs_service.task_definition.task_role)

        # KMS permissions
        self.kms_key.grant_encrypt_decrypt(self.ecs_service.task_definition.task_role)

    def _create_outputs(self):
        """Create CloudFormation outputs"""
        from aws_cdk import CfnOutput
        
        CfnOutput(
            self, "LoadBalancerDNS",
            value=self.ecs_service.load_balancer.load_balancer_dns_name,
            description="Application Load Balancer DNS"
        )
        
        CfnOutput(
            self, "DatabaseEndpoint",
            value=self.database.instance_endpoint.hostname,
            description="RDS PostgreSQL endpoint"
        )
        
        CfnOutput(
            self, "RedisEndpoint",
            value=self.redis_cluster.attr_redis_endpoint_address,
            description="ElastiCache Redis endpoint"
        )
        
        CfnOutput(
            self, "S3Bucket",
            value=self.s3_bucket.bucket_name,
            description="S3 data bucket name"
        )


# CDK App
app = App()

CyberShieldStack(
    app, "CyberShieldStack",
    env=Environment(
        account="840656856721",
        region="us-east-1"
    )
)

app.synth()