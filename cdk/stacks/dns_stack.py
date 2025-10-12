"""
DNS Stack for CyberShield

Creates DNS infrastructure including:
- Route53 hosted zone
- SSL/TLS certificates via AWS Certificate Manager
- DNS validation records
- Optional health checks
"""

from aws_cdk import (
    Duration,
    Stack,
    aws_certificatemanager as acm,
    aws_route53 as route53,
)
from constructs import Construct

from config.environments import EnvironmentConfig


class DnsStack(Stack):
    """Stack for DNS and SSL/TLS certificates."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        config: EnvironmentConfig,
        **kwargs: object,
    ) -> None:
        """
        Initialize DNS stack.

        Args:
            scope: CDK app or parent construct
            construct_id: Unique identifier for this stack
            config: Environment-specific configuration
            **kwargs: Additional stack properties
        """
        super().__init__(scope, construct_id, **kwargs)

        self.config = config
        self.hosted_zone = None
        self.certificate = None

        # Only create DNS resources if domain name is provided
        if config.domain_name:
            self.hosted_zone = self._create_hosted_zone()
            self.certificate = self._create_certificate()

    def _create_hosted_zone(self) -> route53.HostedZone | None:
        """
        Create Route53 hosted zone.

        Returns:
            route53.HostedZone: Route53 hosted zone or None if no domain
        """
        if not self.config.domain_name:
            return None

        hosted_zone = route53.HostedZone(
            self,
            "HostedZone",
            zone_name=self.config.domain_name,
            comment=f"Hosted zone for {self.config.project_name} {self.config.environment}",
        )

        return hosted_zone

    def _create_certificate(self) -> acm.Certificate | None:
        """
        Create SSL/TLS certificate with DNS validation.

        Returns:
            acm.Certificate: SSL/TLS certificate or None if no domain
        """
        if not self.config.domain_name or not self.hosted_zone:
            return None

        # Create certificate with DNS validation
        certificate = acm.Certificate(
            self,
            "Certificate",
            domain_name=self.config.domain_name,
            subject_alternative_names=[
                f"*.{self.config.domain_name}",  # Wildcard for subdomains
                f"www.{self.config.domain_name}",  # WWW subdomain
            ],
            validation=acm.CertificateValidation.from_dns(self.hosted_zone),
        )

        return certificate

    @property
    def hosted_zone_id(self) -> str | None:
        """Get hosted zone ID."""
        return self.hosted_zone.hosted_zone_id if self.hosted_zone else None

    @property
    def hosted_zone_name(self) -> str | None:
        """Get hosted zone name."""
        return self.hosted_zone.zone_name if self.hosted_zone else None

    @property
    def certificate_arn(self) -> str | None:
        """Get certificate ARN."""
        return self.certificate.certificate_arn if self.certificate else None
