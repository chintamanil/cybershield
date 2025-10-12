"""
Reusable Monitoring Construct

Provides standardized monitoring patterns for:
- ECS service alarms
- ALB health alarms
- Database performance alarms
- CloudWatch dashboards
"""

from typing import Any

from aws_cdk import aws_cloudwatch as cloudwatch
from constructs import Construct


class EcsMonitoringConstruct(Construct):
    """
    Reusable construct for ECS service monitoring.

    Creates standard CloudWatch alarms for:
    - CPU utilization
    - Memory utilization
    - Task count
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        cluster_name: str,
        service_name: str,
        alarm_name_prefix: str,
        cpu_threshold: int = 85,
        memory_threshold: int = 85,
        evaluation_periods: int = 2,
        **kwargs: Any,
    ) -> None:
        """
        Initialize ECS monitoring construct.

        Args:
            scope: Parent construct
            construct_id: Unique identifier
            cluster_name: ECS cluster name
            service_name: ECS service name
            alarm_name_prefix: Prefix for alarm names
            cpu_threshold: CPU alarm threshold percentage
            memory_threshold: Memory alarm threshold percentage
            evaluation_periods: Number of evaluation periods
            **kwargs: Additional construct properties
        """
        super().__init__(scope, construct_id, **kwargs)

        # CPU utilization alarm
        self.cpu_alarm = cloudwatch.Alarm(
            self,
            "CpuAlarm",
            alarm_name=f"{alarm_name_prefix}-cpu-high",
            metric=cloudwatch.Metric(
                namespace="AWS/ECS",
                metric_name="CPUUtilization",
                dimensions_map={
                    "ServiceName": service_name,
                    "ClusterName": cluster_name,
                },
                statistic="Average",
                period=cloudwatch.Duration.minutes(5),
            ),
            threshold=cpu_threshold,
            evaluation_periods=evaluation_periods,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )

        # Memory utilization alarm
        self.memory_alarm = cloudwatch.Alarm(
            self,
            "MemoryAlarm",
            alarm_name=f"{alarm_name_prefix}-memory-high",
            metric=cloudwatch.Metric(
                namespace="AWS/ECS",
                metric_name="MemoryUtilization",
                dimensions_map={
                    "ServiceName": service_name,
                    "ClusterName": cluster_name,
                },
                statistic="Average",
                period=cloudwatch.Duration.minutes(5),
            ),
            threshold=memory_threshold,
            evaluation_periods=evaluation_periods,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )


class AlbMonitoringConstruct(Construct):
    """
    Reusable construct for ALB monitoring.

    Creates standard CloudWatch alarms for:
    - Target response time
    - Unhealthy hosts
    - HTTP 5XX errors
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        load_balancer_full_name: str,
        target_group_full_name: str,
        alarm_name_prefix: str,
        response_time_threshold_seconds: float = 2.0,
        unhealthy_host_threshold: int = 1,
        http_5xx_threshold: int = 10,
        evaluation_periods: int = 2,
        **kwargs: Any,
    ) -> None:
        """
        Initialize ALB monitoring construct.

        Args:
            scope: Parent construct
            construct_id: Unique identifier
            load_balancer_full_name: Full ALB name
            target_group_full_name: Full target group name
            alarm_name_prefix: Prefix for alarm names
            response_time_threshold_seconds: Response time threshold
            unhealthy_host_threshold: Unhealthy host count threshold
            http_5xx_threshold: HTTP 5XX error count threshold
            evaluation_periods: Number of evaluation periods
            **kwargs: Additional construct properties
        """
        super().__init__(scope, construct_id, **kwargs)

        # Response time alarm
        self.response_time_alarm = cloudwatch.Alarm(
            self,
            "ResponseTimeAlarm",
            alarm_name=f"{alarm_name_prefix}-response-time-high",
            metric=cloudwatch.Metric(
                namespace="AWS/ApplicationELB",
                metric_name="TargetResponseTime",
                dimensions_map={
                    "LoadBalancer": load_balancer_full_name,
                },
                statistic="Average",
                period=cloudwatch.Duration.minutes(5),
            ),
            threshold=response_time_threshold_seconds,
            evaluation_periods=evaluation_periods,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )

        # Unhealthy hosts alarm
        self.unhealthy_hosts_alarm = cloudwatch.Alarm(
            self,
            "UnhealthyHostsAlarm",
            alarm_name=f"{alarm_name_prefix}-unhealthy-hosts",
            metric=cloudwatch.Metric(
                namespace="AWS/ApplicationELB",
                metric_name="UnHealthyHostCount",
                dimensions_map={
                    "LoadBalancer": load_balancer_full_name,
                    "TargetGroup": target_group_full_name,
                },
                statistic="Maximum",
                period=cloudwatch.Duration.minutes(1),
            ),
            threshold=unhealthy_host_threshold,
            evaluation_periods=evaluation_periods,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )

        # HTTP 5XX errors alarm
        self.http_5xx_alarm = cloudwatch.Alarm(
            self,
            "Http5xxAlarm",
            alarm_name=f"{alarm_name_prefix}-5xx-errors-high",
            metric=cloudwatch.Metric(
                namespace="AWS/ApplicationELB",
                metric_name="HTTPCode_ELB_5XX_Count",
                dimensions_map={
                    "LoadBalancer": load_balancer_full_name,
                },
                statistic="Sum",
                period=cloudwatch.Duration.minutes(5),
            ),
            threshold=http_5xx_threshold,
            evaluation_periods=evaluation_periods,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
