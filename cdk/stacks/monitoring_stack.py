"""
Monitoring Stack for CyberShield

Creates monitoring infrastructure including:
- CloudWatch alarms for ECS services
- CloudWatch alarms for ALB
- CloudWatch alarms for RDS and ElastiCache
- CloudWatch dashboard
"""

from aws_cdk import Stack, aws_cloudwatch as cloudwatch, aws_cloudwatch_actions as cw_actions
from constructs import Construct

from config.constants import (
    CPU_ALARM_THRESHOLD,
    HTTP_5XX_THRESHOLD,
    MEMORY_ALARM_THRESHOLD,
    METRIC_NAMESPACE,
    RESPONSE_TIME_ALARM_THRESHOLD_MS,
    UNHEALTHY_HOST_THRESHOLD,
)
from config.environments import EnvironmentConfig


class MonitoringStack(Stack):
    """Stack for monitoring infrastructure."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        config: EnvironmentConfig,
        compute_stack: object,
        load_balancer_stack: object,
        data_stack: object,
        **kwargs: object,
    ) -> None:
        """
        Initialize Monitoring stack.

        Args:
            scope: CDK app or parent construct
            construct_id: Unique identifier for this stack
            config: Environment-specific configuration
            compute_stack: Compute stack for ECS services
            load_balancer_stack: Load balancer stack for ALB
            data_stack: Data stack for RDS and Redis
            **kwargs: Additional stack properties
        """
        super().__init__(scope, construct_id, **kwargs)

        self.config = config
        self.compute_stack = compute_stack
        self.load_balancer_stack = load_balancer_stack
        self.data_stack = data_stack

        # Only create monitoring if enabled
        if config.enable_monitoring:
            self._create_ecs_alarms()
            self._create_alb_alarms()
            self._create_dashboard()

    def _create_ecs_alarms(self) -> None:
        """Create CloudWatch alarms for ECS services."""
        # Backend CPU alarm
        cloudwatch.Alarm(
            self,
            "BackendCpuAlarm",
            alarm_name=f"{self.config.project_name}-{self.config.environment}-backend-cpu-high",
            metric=cloudwatch.Metric(
                namespace="AWS/ECS",
                metric_name="CPUUtilization",
                dimensions_map={
                    "ServiceName": self.compute_stack.backend_service_name,
                    "ClusterName": self.compute_stack.cluster_name,
                },
                statistic="Average",
                period=cloudwatch.Duration.minutes(5),
            ),
            threshold=CPU_ALARM_THRESHOLD,
            evaluation_periods=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )

        # Backend memory alarm
        cloudwatch.Alarm(
            self,
            "BackendMemoryAlarm",
            alarm_name=f"{self.config.project_name}-{self.config.environment}-backend-memory-high",
            metric=cloudwatch.Metric(
                namespace="AWS/ECS",
                metric_name="MemoryUtilization",
                dimensions_map={
                    "ServiceName": self.compute_stack.backend_service_name,
                    "ClusterName": self.compute_stack.cluster_name,
                },
                statistic="Average",
                period=cloudwatch.Duration.minutes(5),
            ),
            threshold=MEMORY_ALARM_THRESHOLD,
            evaluation_periods=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )

        # Frontend CPU alarm
        cloudwatch.Alarm(
            self,
            "FrontendCpuAlarm",
            alarm_name=f"{self.config.project_name}-{self.config.environment}-frontend-cpu-high",
            metric=cloudwatch.Metric(
                namespace="AWS/ECS",
                metric_name="CPUUtilization",
                dimensions_map={
                    "ServiceName": self.compute_stack.frontend_service_name,
                    "ClusterName": self.compute_stack.cluster_name,
                },
                statistic="Average",
                period=cloudwatch.Duration.minutes(5),
            ),
            threshold=CPU_ALARM_THRESHOLD,
            evaluation_periods=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )

    def _create_alb_alarms(self) -> None:
        """Create CloudWatch alarms for Application Load Balancer."""
        # Response time alarm
        cloudwatch.Alarm(
            self,
            "AlbResponseTimeAlarm",
            alarm_name=f"{self.config.project_name}-{self.config.environment}-alb-response-time-high",
            metric=cloudwatch.Metric(
                namespace="AWS/ApplicationELB",
                metric_name="TargetResponseTime",
                dimensions_map={
                    "LoadBalancer": self.load_balancer_stack.alb.load_balancer_full_name,
                },
                statistic="Average",
                period=cloudwatch.Duration.minutes(5),
            ),
            threshold=RESPONSE_TIME_ALARM_THRESHOLD_MS / 1000,  # Convert to seconds
            evaluation_periods=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )

        # 5XX errors alarm
        cloudwatch.Alarm(
            self,
            "Alb5xxErrorsAlarm",
            alarm_name=f"{self.config.project_name}-{self.config.environment}-alb-5xx-errors-high",
            metric=cloudwatch.Metric(
                namespace="AWS/ApplicationELB",
                metric_name="HTTPCode_ELB_5XX_Count",
                dimensions_map={
                    "LoadBalancer": self.load_balancer_stack.alb.load_balancer_full_name,
                },
                statistic="Sum",
                period=cloudwatch.Duration.minutes(5),
            ),
            threshold=HTTP_5XX_THRESHOLD,
            evaluation_periods=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )

        # Unhealthy hosts alarm
        cloudwatch.Alarm(
            self,
            "AlbUnhealthyHostsAlarm",
            alarm_name=f"{self.config.project_name}-{self.config.environment}-alb-unhealthy-hosts",
            metric=cloudwatch.Metric(
                namespace="AWS/ApplicationELB",
                metric_name="UnHealthyHostCount",
                dimensions_map={
                    "LoadBalancer": self.load_balancer_stack.alb.load_balancer_full_name,
                    "TargetGroup": self.load_balancer_stack.backend_target_group.target_group_full_name,
                },
                statistic="Maximum",
                period=cloudwatch.Duration.minutes(1),
            ),
            threshold=UNHEALTHY_HOST_THRESHOLD,
            evaluation_periods=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )

    def _create_dashboard(self) -> None:
        """Create CloudWatch dashboard."""
        dashboard = cloudwatch.Dashboard(
            self,
            "Dashboard",
            dashboard_name=f"{self.config.project_name}-{self.config.environment}-overview",
        )

        # Add widgets for ECS metrics
        dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="ECS Service Metrics",
                left=[
                    cloudwatch.Metric(
                        namespace="AWS/ECS",
                        metric_name="CPUUtilization",
                        dimensions_map={
                            "ServiceName": self.compute_stack.backend_service_name,
                            "ClusterName": self.compute_stack.cluster_name,
                        },
                        statistic="Average",
                        label="Backend CPU",
                    ),
                    cloudwatch.Metric(
                        namespace="AWS/ECS",
                        metric_name="MemoryUtilization",
                        dimensions_map={
                            "ServiceName": self.compute_stack.backend_service_name,
                            "ClusterName": self.compute_stack.cluster_name,
                        },
                        statistic="Average",
                        label="Backend Memory",
                    ),
                ],
            )
        )

        # Add widgets for ALB metrics
        dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="ALB Metrics",
                left=[
                    cloudwatch.Metric(
                        namespace="AWS/ApplicationELB",
                        metric_name="RequestCount",
                        dimensions_map={
                            "LoadBalancer": self.load_balancer_stack.alb.load_balancer_full_name,
                        },
                        statistic="Sum",
                        label="Requests",
                    ),
                ],
                right=[
                    cloudwatch.Metric(
                        namespace="AWS/ApplicationELB",
                        metric_name="TargetResponseTime",
                        dimensions_map={
                            "LoadBalancer": self.load_balancer_stack.alb.load_balancer_full_name,
                        },
                        statistic="Average",
                        label="Response Time",
                    ),
                ],
            )
        )
