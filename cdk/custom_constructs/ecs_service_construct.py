"""
Reusable ECS Service Construct

Provides a high-level abstraction for creating ECS Fargate services with:
- Auto-scaling configuration
- Load balancer integration
- CloudWatch logging
- Health checks
- Best practices built-in
"""

from typing import Any

from aws_cdk import Duration, aws_ec2 as ec2, aws_ecs as ecs, aws_logs as logs
from constructs import Construct


class EcsServiceConstruct(Construct):
    """
    Reusable construct for ECS Fargate services.

    This construct encapsulates common patterns for creating ECS services
    with auto-scaling, load balancer integration, and monitoring.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        cluster: ecs.ICluster,
        vpc: ec2.IVpc,
        security_groups: list[ec2.ISecurityGroup],
        task_execution_role: Any,
        task_role: Any,
        service_name: str,
        container_name: str,
        container_port: int,
        image: ecs.ContainerImage,
        cpu: int,
        memory: int,
        desired_count: int = 1,
        min_capacity: int = 1,
        max_capacity: int = 10,
        environment_variables: dict[str, str] | None = None,
        health_check_path: str = "/health",
        enable_auto_scaling: bool = True,
        cpu_target_utilization: int = 70,
        memory_target_utilization: int = 80,
        log_retention_days: int = 14,
        enable_exec: bool = False,
        use_spot_instances: bool = False,
        target_group: Any = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize ECS service construct.

        Args:
            scope: Parent construct
            construct_id: Unique identifier
            cluster: ECS cluster
            vpc: VPC for service
            security_groups: Security groups for tasks
            task_execution_role: IAM role for task execution
            task_role: IAM role for task
            service_name: Name of the service
            container_name: Name of the container
            container_port: Container port
            image: Container image
            cpu: CPU units (256, 512, 1024, etc.)
            memory: Memory in MB (512, 1024, 2048, etc.)
            desired_count: Desired task count
            min_capacity: Minimum tasks for auto-scaling
            max_capacity: Maximum tasks for auto-scaling
            environment_variables: Environment variables
            health_check_path: Health check endpoint
            enable_auto_scaling: Enable auto-scaling
            cpu_target_utilization: CPU target for scaling
            memory_target_utilization: Memory target for scaling
            log_retention_days: CloudWatch log retention
            enable_exec: Enable ECS Exec
            use_spot_instances: Use Fargate Spot
            target_group: ALB target group (optional)
            **kwargs: Additional construct properties
        """
        super().__init__(scope, construct_id, **kwargs)

        self.cluster = cluster
        self.service_name = service_name

        # Create log group
        self.log_group = logs.LogGroup(
            self,
            "LogGroup",
            log_group_name=f"/ecs/{service_name}",
            retention=logs.RetentionDays(log_retention_days)
            if log_retention_days <= 30
            else logs.RetentionDays.ONE_MONTH,
        )

        # Create task definition
        self.task_definition = ecs.FargateTaskDefinition(
            self,
            "TaskDefinition",
            family=service_name,
            cpu=cpu,
            memory_limit_mib=memory,
            execution_role=task_execution_role,
            task_role=task_role,
        )

        # Add container
        self.container = self.task_definition.add_container(
            container_name,
            container_name=container_name,
            image=image,
            environment=environment_variables or {},
            logging=ecs.LogDriver.aws_logs(
                stream_prefix=container_name,
                log_group=self.log_group,
            ),
            health_check=ecs.HealthCheck(
                command=[
                    "CMD-SHELL",
                    f"curl -f http://localhost:{container_port}{health_check_path} || exit 1",
                ],
                interval=Duration.seconds(30),
                timeout=Duration.seconds(5),
                retries=3,
                start_period=Duration.seconds(60),
            ),
        )

        # Add port mapping
        self.container.add_port_mappings(
            ecs.PortMapping(
                container_port=container_port,
                protocol=ecs.Protocol.TCP,
            )
        )

        # Create service
        self.service = ecs.FargateService(
            self,
            "Service",
            service_name=service_name,
            cluster=cluster,
            task_definition=self.task_definition,
            desired_count=desired_count,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            security_groups=security_groups,
            assign_public_ip=True,
            capacity_provider_strategies=[
                ecs.CapacityProviderStrategy(
                    capacity_provider="FARGATE_SPOT" if use_spot_instances else "FARGATE",
                    weight=1,
                )
            ],
            enable_execute_command=enable_exec,
            health_check_grace_period=Duration.seconds(60) if target_group else None,
        )

        # Attach to load balancer if target group provided
        if target_group:
            self.service.attach_to_application_target_group(target_group)

        # Configure auto-scaling
        if enable_auto_scaling:
            self._configure_auto_scaling(
                min_capacity,
                max_capacity,
                cpu_target_utilization,
                memory_target_utilization,
            )

    def _configure_auto_scaling(
        self,
        min_capacity: int,
        max_capacity: int,
        cpu_target: int,
        memory_target: int,
    ) -> None:
        """Configure auto-scaling for the service."""
        scaling = self.service.auto_scale_task_count(
            min_capacity=min_capacity,
            max_capacity=max_capacity,
        )

        # CPU-based scaling
        scaling.scale_on_cpu_utilization(
            "CpuScaling",
            target_utilization_percent=cpu_target,
            scale_in_cooldown=Duration.seconds(300),
            scale_out_cooldown=Duration.seconds(60),
        )

        # Memory-based scaling
        scaling.scale_on_memory_utilization(
            "MemoryScaling",
            target_utilization_percent=memory_target,
            scale_in_cooldown=Duration.seconds(300),
            scale_out_cooldown=Duration.seconds(60),
        )
