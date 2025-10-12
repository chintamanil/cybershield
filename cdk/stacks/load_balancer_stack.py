"""
Load Balancer Stack for CyberShield

Creates load balancing infrastructure including:
- Application Load Balancer (ALB)
- Target groups for backend and frontend services
- HTTPS listeners with SSL/TLS termination
- Path-based routing rules
- Route53 DNS records
"""

from aws_cdk import (
    Duration,
    Stack,
    aws_certificatemanager as acm,
    aws_elasticloadbalancingv2 as elbv2,
    aws_route53 as route53,
    aws_route53_targets as targets,
)
from constructs import Construct

from config.constants import (
    ALB_IDLE_TIMEOUT_SECONDS,
    API_PATH_PATTERNS,
    BACKEND_PORT,
    FRONTEND_PORT,
    HEALTH_CHECK_HEALTHY_THRESHOLD,
    HEALTH_CHECK_INTERVAL_SECONDS,
    HEALTH_CHECK_TIMEOUT_SECONDS,
    HEALTH_CHECK_UNHEALTHY_THRESHOLD,
    SSL_POLICY,
)
from config.environments import EnvironmentConfig


class LoadBalancerStack(Stack):
    """Stack for load balancing infrastructure."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        config: EnvironmentConfig,
        network_stack: object,
        dns_stack: object,
        **kwargs: object,
    ) -> None:
        """
        Initialize Load Balancer stack.

        Args:
            scope: CDK app or parent construct
            construct_id: Unique identifier for this stack
            config: Environment-specific configuration
            network_stack: Network stack for VPC and security groups
            dns_stack: DNS stack for hosted zone and certificate
            **kwargs: Additional stack properties
        """
        super().__init__(scope, construct_id, **kwargs)

        self.config = config
        self.network_stack = network_stack
        self.dns_stack = dns_stack

        # Create Application Load Balancer
        self.alb = self._create_alb()

        # Create target groups
        self.backend_target_group = self._create_backend_target_group()
        self.frontend_target_group = self._create_frontend_target_group()

        # Create listeners and routing rules
        self._create_listeners()

        # Create DNS records if domain is configured
        if config.domain_name and dns_stack.hosted_zone:
            self._create_dns_records()

    def _create_alb(self) -> elbv2.ApplicationLoadBalancer:
        """
        Create Application Load Balancer.

        Returns:
            elbv2.ApplicationLoadBalancer: ALB
        """
        alb = elbv2.ApplicationLoadBalancer(
            self,
            "ApplicationLoadBalancer",
            load_balancer_name=f"{self.config.project_name}-{self.config.environment}-alb",
            vpc=self.network_stack.vpc,
            vpc_subnets={"subnets": self.network_stack.public_subnets},
            security_group=self.network_stack.alb_security_group,
            internet_facing=True,
            deletion_protection=self.config.enable_deletion_protection,
            idle_timeout=Duration.seconds(ALB_IDLE_TIMEOUT_SECONDS),
        )

        return alb

    def _create_backend_target_group(self) -> elbv2.ApplicationTargetGroup:
        """
        Create target group for backend service.

        Returns:
            elbv2.ApplicationTargetGroup: Backend target group
        """
        target_group = elbv2.ApplicationTargetGroup(
            self,
            "BackendTargetGroup",
            target_group_name=f"{self.config.project_name}-{self.config.environment}-backend-tg",
            vpc=self.network_stack.vpc,
            port=BACKEND_PORT,
            protocol=elbv2.ApplicationProtocol.HTTP,
            target_type=elbv2.TargetType.IP,
            health_check=elbv2.HealthCheck(
                enabled=True,
                path=self.config.backend_health_check_path,
                protocol=elbv2.Protocol.HTTP,
                port=str(BACKEND_PORT),
                interval=Duration.seconds(HEALTH_CHECK_INTERVAL_SECONDS),
                timeout=Duration.seconds(HEALTH_CHECK_TIMEOUT_SECONDS),
                healthy_threshold_count=HEALTH_CHECK_HEALTHY_THRESHOLD,
                unhealthy_threshold_count=HEALTH_CHECK_UNHEALTHY_THRESHOLD,
                healthy_http_codes="200",
            ),
            deregistration_delay=Duration.seconds(30),
        )

        return target_group

    def _create_frontend_target_group(self) -> elbv2.ApplicationTargetGroup:
        """
        Create target group for frontend service.

        Returns:
            elbv2.ApplicationTargetGroup: Frontend target group
        """
        target_group = elbv2.ApplicationTargetGroup(
            self,
            "FrontendTargetGroup",
            target_group_name=f"{self.config.project_name}-{self.config.environment}-frontend-tg",
            vpc=self.network_stack.vpc,
            port=FRONTEND_PORT,
            protocol=elbv2.ApplicationProtocol.HTTP,
            target_type=elbv2.TargetType.IP,
            health_check=elbv2.HealthCheck(
                enabled=True,
                path=self.config.frontend_health_check_path,
                protocol=elbv2.Protocol.HTTP,
                port=str(FRONTEND_PORT),
                interval=Duration.seconds(HEALTH_CHECK_INTERVAL_SECONDS),
                timeout=Duration.seconds(HEALTH_CHECK_TIMEOUT_SECONDS),
                healthy_threshold_count=HEALTH_CHECK_HEALTHY_THRESHOLD,
                unhealthy_threshold_count=HEALTH_CHECK_UNHEALTHY_THRESHOLD,
                healthy_http_codes="200",
            ),
            deregistration_delay=Duration.seconds(30),
            stickiness_cookie_duration=Duration.hours(1),
        )

        return target_group

    def _create_listeners(self) -> None:
        """Create HTTP and HTTPS listeners with routing rules."""
        if self.config.domain_name and self.dns_stack.certificate:
            # HTTPS listener with SSL/TLS termination
            https_listener = self.alb.add_listener(
                "HttpsListener",
                port=443,
                protocol=elbv2.ApplicationProtocol.HTTPS,
                ssl_policy=elbv2.SslPolicy(SSL_POLICY),
                certificates=[
                    elbv2.ListenerCertificate.from_certificate_manager(
                        self.dns_stack.certificate
                    )
                ],
                default_action=elbv2.ListenerAction.forward(
                    [self.frontend_target_group]
                ),
            )

            # Add backend routing rules (higher priority)
            for index, path_pattern in enumerate(API_PATH_PATTERNS):
                https_listener.add_action(
                    f"BackendRule{index}",
                    priority=100 + index,
                    conditions=[
                        elbv2.ListenerCondition.path_patterns([path_pattern])
                    ],
                    action=elbv2.ListenerAction.forward([self.backend_target_group]),
                )

            # HTTP listener redirects to HTTPS
            self.alb.add_listener(
                "HttpListener",
                port=80,
                protocol=elbv2.ApplicationProtocol.HTTP,
                default_action=elbv2.ListenerAction.redirect(
                    protocol="HTTPS",
                    port="443",
                    permanent=True,
                ),
            )
        else:
            # HTTP listener for non-SSL environments (dev/testing)
            http_listener = self.alb.add_listener(
                "HttpListener",
                port=80,
                protocol=elbv2.ApplicationProtocol.HTTP,
                default_action=elbv2.ListenerAction.forward(
                    [self.backend_target_group]
                ),
            )

    def _create_dns_records(self) -> None:
        """Create Route53 DNS records for the load balancer."""
        if not self.config.domain_name or not self.dns_stack.hosted_zone:
            return

        # Main domain A record
        route53.ARecord(
            self,
            "DomainARecord",
            zone=self.dns_stack.hosted_zone,
            record_name=self.config.domain_name,
            target=route53.RecordTarget.from_alias(
                targets.LoadBalancerTarget(self.alb)
            ),
        )

        # WWW subdomain A record
        route53.ARecord(
            self,
            "WwwARecord",
            zone=self.dns_stack.hosted_zone,
            record_name=f"www.{self.config.domain_name}",
            target=route53.RecordTarget.from_alias(
                targets.LoadBalancerTarget(self.alb)
            ),
        )

    @property
    def alb_dns_name(self) -> str:
        """Get ALB DNS name."""
        return self.alb.load_balancer_dns_name

    @property
    def alb_arn(self) -> str:
        """Get ALB ARN."""
        return self.alb.load_balancer_arn

    @property
    def backend_target_group_arn(self) -> str:
        """Get backend target group ARN."""
        return self.backend_target_group.target_group_arn

    @property
    def frontend_target_group_arn(self) -> str:
        """Get frontend target group ARN."""
        return self.frontend_target_group.target_group_arn
