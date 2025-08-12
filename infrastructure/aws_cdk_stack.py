#!/usr/bin/env python3
# AWS CDK Infrastructure for CyberShield

from aws_cdk import (
    App, Stack, Environment,
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_ecs_patterns as ecs_patterns,
    aws_elasticache as elasticache,
    aws_rds as rds,
    aws_opensearchserverless as opensearch,
    aws_secretsmanager as secretsmanager,
    aws_ssm as ssm,
    aws_s3 as s3,
    aws_cloudfront as cloudfront,
    aws_wafv2 as wafv2,
    aws_logs as logs,
    aws_kms as kms,
    aws_iam as iam,
    Duration, RemovalPolicy
)
from constructs import Construct


class CyberShieldStack(Stack):
    """Complete AWS infrastructure for CyberShield"""

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
            secret_string_template='{"virustotal":"", "shodan":"", "abuseipdb":""}',
            generate_secret_string=secretsmanager.SecretStringGenerator(
                secret_string_template='{"virustotal":"REPLACE_ME", "shodan":"REPLACE_ME", "abuseipdb":"REPLACE_ME"}',
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

        # Create SSM parameters for configuration
        ssm.StringParameter(
            self, "LogLevel",
            parameter_name="/cybershield/config/log-level",
            string_value="INFO"
        )

        ssm.StringParameter(
            self, "DebugMode",
            parameter_name="/cybershield/config/debug-mode",
            string_value="false"
        )

        ssm.StringParameter(
            self, "MaxWorkers",
            parameter_name="/cybershield/config/max-workers",
            string_value="4"
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
            deletion_protection=True,
            storage_encrypted=True,
            storage_encryption_key=self.kms_key,
            monitoring_interval=Duration.minutes(5),
            performance_insights_encryption_key=self.kms_key,
            cloudwatch_logs_exports=["postgresql"]
        )

        # Create ElastiCache Redis
        redis_subnet_group = elasticache.CfnSubnetGroup(
            self, "RedisSubnetGroup",
            description="Subnet group for Redis",
            subnet_ids=[subnet.subnet_id for subnet in self.vpc.private_subnets]
        )

        self.redis_cluster = elasticache.CfnCacheCluster(
            self, "CyberShieldRedis",
            engine="redis",
            cache_node_type="cache.t3.micro",
            num_cache_nodes=1,
            cache_subnet_group_name=redis_subnet_group.ref,
            vpc_security_group_ids=[self._create_redis_security_group().security_group_id],
            at_rest_encryption_enabled=True,
            transit_encryption_enabled=True
        )

        # Create OpenSearch domain
        self.opensearch_domain = opensearch.Domain(
            self, "CyberShieldSearch",
            version=opensearch.EngineVersion.OPENSEARCH_2_11,
            capacity=opensearch.CapacityConfig(
                master_nodes=0,
                data_nodes=1,
                data_node_instance_type="t3.small.search"
            ),
            ebs=opensearch.EbsOptions(
                volume_size=20,
                volume_type=ec2.EbsDeviceVolumeType.GP3
            ),
            vpc=self.vpc,
            vpc_subnets=[ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
            )],
            security_groups=[self._create_opensearch_security_group()],
            encryption_at_rest=opensearch.EncryptionAtRestOptions(enabled=True),
            node_to_node_encryption=True,
            enforce_https=True,
            fine_grained_access_control=opensearch.AdvancedSecurityOptions(
                master_user_name="cybershield-admin"
            ),
            access_policies=[
                iam.PolicyStatement(
                    principals=[iam.AccountRootPrincipal()],
                    actions=["es:*"],
                    resources=["*"]
                )
            ]
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
            desired_count=2,
            task_image_options=ecs_patterns.ApplicationLoadBalancedTaskImageOptions(
                image=ecs.ContainerImage.from_asset(".", file="deployment/Dockerfile.aws"),
                container_port=8000,
                environment={
                    "CYBERSHIELD_ENV": "aws",
                    "AWS_DEFAULT_REGION": self.region,
                    "RDS_ENDPOINT": self.database.instance_endpoint.hostname,
                    "ELASTICACHE_ENDPOINT": self.redis_cluster.attr_redis_endpoint_address,
                    "OPENSEARCH_ENDPOINT": self.opensearch_domain.domain_endpoint,
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
            public_load_balancer=True,
            protocol=ecs_patterns.ApplicationProtocol.HTTPS,
            redirect_http=True,
            enable_logging=True
        )

        # Configure health checks
        self.ecs_service.target_group.configure_health_check(
            path="/health",
            healthy_http_codes="200",
            interval=Duration.seconds(30),
            timeout=Duration.seconds(10)
        )

        # Grant permissions to ECS task
        self._grant_ecs_permissions()

        # Create WAF for security
        self._create_waf()

        # Create CloudFront distribution
        self._create_cloudfront()

        # Output important values
        self._create_outputs()

    def _create_redis_security_group(self) -> ec2.SecurityGroup:
        """Create security group for Redis"""
        sg = ec2.SecurityGroup(
            self, "RedisSecurityGroup",
            vpc=self.vpc,
            description="Security group for Redis cluster",
            allow_all_outbound=False
        )
        
        sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(self.ecs_service.service.connections.security_groups[0].security_group_id),
            connection=ec2.Port.tcp(6379),
            description="Allow Redis access from ECS"
        )
        
        return sg

    def _create_opensearch_security_group(self) -> ec2.SecurityGroup:
        """Create security group for OpenSearch"""
        sg = ec2.SecurityGroup(
            self, "OpenSearchSecurityGroup",
            vpc=self.vpc,
            description="Security group for OpenSearch cluster",
            allow_all_outbound=False
        )
        
        sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(self.ecs_service.service.connections.security_groups[0].security_group_id),
            connection=ec2.Port.tcp(443),
            description="Allow HTTPS access from ECS"
        )
        
        return sg

    def _grant_ecs_permissions(self):
        """Grant necessary permissions to ECS task"""
        # Bedrock permissions
        self.ecs_service.task_definition.add_to_task_role_policy(
            iam.PolicyStatement(
                actions=[
                    "bedrock:InvokeModel",
                    "bedrock:InvokeModelWithResponseStream"
                ],
                resources=["*"]
            )
        )

        # Secrets Manager permissions
        self.api_keys_secret.grant_read(self.ecs_service.task_definition.task_role)
        self.rds_credentials.grant_read(self.ecs_service.task_definition.task_role)

        # SSM Parameter Store permissions
        self.ecs_service.task_definition.add_to_task_role_policy(
            iam.PolicyStatement(
                actions=["ssm:GetParameter", "ssm:GetParameters"],
                resources=[f"arn:aws:ssm:{self.region}:{self.account}:parameter/cybershield/*"]
            )
        )

        # CloudWatch Logs permissions
        self.log_group.grant_write(self.ecs_service.task_definition.task_role)

        # S3 permissions
        self.s3_bucket.grant_read_write(self.ecs_service.task_definition.task_role)

        # KMS permissions
        self.kms_key.grant_encrypt_decrypt(self.ecs_service.task_definition.task_role)

    def _create_waf(self):
        """Create WAF for application security"""
        # Create IP whitelist (customize as needed)
        ip_set = wafv2.CfnIPSet(
            self, "AllowedIPs",
            scope="CLOUDFRONT",
            ip_address_version="IPV4",
            addresses=["0.0.0.0/0"]  # Replace with your allowed IPs
        )

        # Create WAF rules
        self.waf = wafv2.CfnWebACL(
            self, "CyberShieldWAF",
            scope="CLOUDFRONT",
            default_action=wafv2.CfnWebACL.DefaultActionProperty(allow={}),
            rules=[
                wafv2.CfnWebACL.RuleProperty(
                    name="AWSManagedRulesCommonRuleSet",
                    priority=1,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesCommonRuleSet"
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="CommonRuleSetMetric",
                        sampled_requests_enabled=True
                    )
                ),
                wafv2.CfnWebACL.RuleProperty(
                    name="RateLimitRule",
                    priority=2,
                    action=wafv2.CfnWebACL.RuleActionProperty(block={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                            limit=2000,
                            aggregate_key_type="IP"
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="RateLimitMetric",
                        sampled_requests_enabled=True
                    )
                )
            ],
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="CyberShieldWAF",
                sampled_requests_enabled=True
            )
        )

    def _create_cloudfront(self):
        """Create CloudFront distribution"""
        self.cloudfront = cloudfront.Distribution(
            self, "CyberShieldCDN",
            default_behavior=cloudfront.BehaviorOptions(
                origin=cloudfront.HttpOrigin(
                    self.ecs_service.load_balancer.load_balancer_dns_name,
                    protocol_policy=cloudfront.OriginProtocolPolicy.HTTPS_ONLY
                ),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                origin_request_policy=cloudfront.OriginRequestPolicy.ALL_VIEWER,
                response_headers_policy=cloudfront.ResponseHeadersPolicy.SECURITY_HEADERS
            ),
            web_acl_id=self.waf.attr_arn,
            price_class=cloudfront.PriceClass.PRICE_CLASS_100,
            enable_logging=True,
            log_bucket=s3.Bucket(
                self, "CloudFrontLogsBucket",
                encryption=s3.BucketEncryption.S3_MANAGED
            )
        )

    def _create_outputs(self):
        """Create CloudFormation outputs"""
        from aws_cdk import CfnOutput
        
        CfnOutput(
            self, "LoadBalancerDNS",
            value=self.ecs_service.load_balancer.load_balancer_dns_name,
            description="Application Load Balancer DNS"
        )
        
        CfnOutput(
            self, "CloudFrontDomain",
            value=self.cloudfront.distribution_domain_name,
            description="CloudFront distribution domain"
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
            self, "OpenSearchEndpoint",
            value=self.opensearch_domain.domain_endpoint,
            description="OpenSearch domain endpoint"
        )


# CDK App
app = App()

CyberShieldStack(
    app, "CyberShieldStack",
    env=Environment(
        account="840656856721",  # Replace with your AWS account ID
        region="us-east-1"       # Replace with your preferred region
    )
)

app.synth()