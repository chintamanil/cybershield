#!/usr/bin/env python3
# Minimal AWS CDK Infrastructure for CyberShield - Bootstrap Only

from aws_cdk import (
    App, Stack, Environment,
    aws_ec2 as ec2,
    aws_rds as rds,
    aws_elasticache as elasticache,
    aws_secretsmanager as secretsmanager,
    aws_s3 as s3,
    aws_logs as logs,
    aws_kms as kms,
    Duration, RemovalPolicy
)
from constructs import Construct


class CyberShieldBootstrapStack(Stack):
    """Bootstrap AWS infrastructure for CyberShield"""

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
            removal_policy=RemovalPolicy.RETAIN
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

        # Create ElastiCache Redis subnet group
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

        # Create Redis cluster
        self.redis_cluster = elasticache.CfnCacheCluster(
            self, "CyberShieldRedis",
            engine="redis",
            cache_node_type="cache.t3.micro",
            num_cache_nodes=1,
            cache_subnet_group_name=redis_subnet_group.ref,
            vpc_security_group_ids=[redis_sg.security_group_id]
        )

        # Create CloudWatch Log Group
        self.log_group = logs.LogGroup(
            self, "CyberShieldLogs",
            log_group_name="/aws/cybershield/application",
            retention=logs.RetentionDays.ONE_MONTH,
            encryption_key=self.kms_key
        )

        # Output important values
        self._create_outputs()

    def _create_outputs(self):
        """Create CloudFormation outputs"""
        from aws_cdk import CfnOutput
        
        CfnOutput(
            self, "VPCId",
            value=self.vpc.vpc_id,
            description="VPC ID"
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

        CfnOutput(
            self, "APIKeysSecret",
            value=self.api_keys_secret.secret_arn,
            description="API Keys Secret ARN"
        )


# CDK App
app = App()

CyberShieldBootstrapStack(
    app, "CyberShieldBootstrapStack",
    env=Environment(
        account="840656856721",
        region="us-east-1"
    )
)

app.synth()