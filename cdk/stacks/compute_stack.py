"""
Compute Stack for CyberShield

Creates compute infrastructure including:
- ECR repository for container images
- ECS cluster with Fargate capacity providers
- ECS task definitions for backend and frontend
- ECS services with auto-scaling
- CloudWatch log groups
"""

from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    aws_applicationautoscaling as appscaling,
    aws_ec2 as ec2,
    aws_ecr as ecr,
    aws_ecs as ecs,
    aws_elasticloadbalancingv2 as elbv2,
    aws_logs as logs,
)
from constructs import Construct

from config.constants import (
    BACKEND_CONTAINER_NAME,
    BACKEND_PORT,
    CPU_TARGET_UTILIZATION,
    FRONTEND_CONTAINER_NAME,
    FRONTEND_PORT,
    MEMORY_TARGET_UTILIZATION,
    SCALE_IN_COOLDOWN_SECONDS,
    SCALE_OUT_COOLDOWN_SECONDS,
)
from config.environments import EnvironmentConfig


class ComputeStack(Stack):
    """Stack for compute infrastructure."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        config: EnvironmentConfig,
        network_stack: object,
        iam_stack: object,
        data_stack: object,
        load_balancer_stack: object,
        storage_stack: object,
        **kwargs: object,
    ) -> None:
        """
        Initialize Compute stack.

        Args:
            scope: CDK app or parent construct
            construct_id: Unique identifier for this stack
            config: Environment-specific configuration
            network_stack: Network stack for VPC and security groups
            iam_stack: IAM stack for task roles
            data_stack: Data stack for database connections
            load_balancer_stack: Load balancer stack for target groups
            storage_stack: Storage stack for EFS
            **kwargs: Additional stack properties
        """
        super().__init__(scope, construct_id, **kwargs)

        self.config = config
        self.network_stack = network_stack
        self.iam_stack = iam_stack
        self.data_stack = data_stack
        self.load_balancer_stack = load_balancer_stack
        self.storage_stack = storage_stack

        # Create ECR repository
        self.ecr_repository = self._create_ecr_repository()

        # Create ECS cluster
        self.ecs_cluster = self._create_ecs_cluster()

        # Create CloudWatch log group
        self.log_group = self._create_log_group()

        # Create backend task definition and service
        self.backend_task_definition = self._create_backend_task_definition()
        self.backend_service = self._create_backend_service()

        # Create frontend task definition and service
        self.frontend_task_definition = self._create_frontend_task_definition()
        self.frontend_service = self._create_frontend_service()

        # Configure auto-scaling
        if config.enable_auto_scaling:
            self._configure_backend_autoscaling()
            self._configure_frontend_autoscaling()

    def _create_ecr_repository(self) -> ecr.Repository:
        """
        Create ECR repository for container images.

        Returns:
            ecr.Repository: ECR repository
        """
        repository = ecr.Repository(
            self,
            "EcrRepository",
            repository_name=f"{self.config.project_name}-{self.config.environment}",
            image_scan_on_push=True,
            image_tag_mutability=ecr.TagMutability.MUTABLE,
            removal_policy=RemovalPolicy.RETAIN
            if self.config.enable_deletion_protection
            else RemovalPolicy.DESTROY,
            lifecycle_rules=[
                ecr.LifecycleRule(
                    description="Keep last 10 images",
                    max_image_count=10,
                    tag_prefix_list=["v"],
                )
            ],
        )

        return repository

    def _create_ecs_cluster(self) -> ecs.Cluster:
        """
        Create ECS cluster with Fargate capacity providers.

        Returns:
            ecs.Cluster: ECS cluster
        """
        cluster = ecs.Cluster(
            self,
            "EcsCluster",
            cluster_name=f"{self.config.project_name}-{self.config.environment}",
            vpc=self.network_stack.vpc,
            container_insights=self.config.enable_container_insights,
            enable_fargate_capacity_providers=True,
        )

        return cluster

    def _create_log_group(self) -> logs.LogGroup:
        """
        Create CloudWatch log group for ECS tasks.

        Returns:
            logs.LogGroup: CloudWatch log group
        """
        log_group = logs.LogGroup(
            self,
            "EcsLogGroup",
            log_group_name=f"/ecs/{self.config.project_name}-{self.config.environment}",
            retention=logs.RetentionDays(self.config.cloudwatch_log_retention_days)
            if self.config.cloudwatch_log_retention_days <= 30
            else logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.DESTROY,
        )

        return log_group

    def _create_backend_task_definition(self) -> ecs.FargateTaskDefinition:
        """
        Create ECS task definition for backend service.

        Returns:
            ecs.FargateTaskDefinition: Backend task definition
        """
        # Build environment variables
        environment_vars = {
            "ENVIRONMENT": self.config.environment,
            "REDIS_HOST": self.data_stack.redis_endpoint,
            "REDIS_PORT": self.data_stack.redis_port,
            "POSTGRES_HOST": self.data_stack.rds_endpoint,
            "POSTGRES_PORT": self.data_stack.rds_port,
            "POSTGRES_DB": self.config.db_name,
            "POSTGRES_USER": self.config.db_username,
            **self.config.environment_variables,
        }

        # Add OpenSearch endpoint if enabled
        if self.config.enable_opensearch and self.data_stack.opensearch_endpoint:
            environment_vars["OPENSEARCH_HOST"] = self.data_stack.opensearch_endpoint

        # Create task definition
        task_definition = ecs.FargateTaskDefinition(
            self,
            "BackendTaskDefinition",
            family=f"{self.config.project_name}-{self.config.environment}-backend",
            cpu=self.config.backend_cpu,
            memory_limit_mib=self.config.backend_memory,
            execution_role=self.iam_stack.ecs_task_execution_role,
            task_role=self.iam_stack.ecs_task_role,
        )

        # Add container
        container = task_definition.add_container(
            BACKEND_CONTAINER_NAME,
            container_name=BACKEND_CONTAINER_NAME,
            image=ecs.ContainerImage.from_registry("public.ecr.aws/docker/library/nginx:latest"),  # Placeholder
            environment=environment_vars,
            logging=ecs.LogDriver.aws_logs(
                stream_prefix="backend",
                log_group=self.log_group,
            ),
            health_check=ecs.HealthCheck(
                command=[
                    "CMD-SHELL",
                    f"curl -f http://localhost:{BACKEND_PORT}{self.config.backend_health_check_path} || exit 1",
                ],
                interval=Duration.seconds(30),
                timeout=Duration.seconds(5),
                retries=3,
                start_period=Duration.seconds(60),
            ),
        )

        # Add port mapping
        container.add_port_mappings(
            ecs.PortMapping(
                container_port=BACKEND_PORT,
                protocol=ecs.Protocol.TCP,
            )
        )

        return task_definition

    def _create_frontend_task_definition(self) -> ecs.FargateTaskDefinition:
        """
        Create ECS task definition for frontend service.

        Returns:
            ecs.FargateTaskDefinition: Frontend task definition
        """
        # Build environment variables
        environment_vars = {
            "ENVIRONMENT": self.config.environment,
            "BACKEND_URL": f"http://{self.load_balancer_stack.alb_dns_name}",
            **self.config.environment_variables,
        }

        # Create task definition
        task_definition = ecs.FargateTaskDefinition(
            self,
            "FrontendTaskDefinition",
            family=f"{self.config.project_name}-{self.config.environment}-frontend",
            cpu=self.config.frontend_cpu,
            memory_limit_mib=self.config.frontend_memory,
            execution_role=self.iam_stack.ecs_task_execution_role,
            task_role=self.iam_stack.ecs_task_role,
        )

        # Add container
        container = task_definition.add_container(
            FRONTEND_CONTAINER_NAME,
            container_name=FRONTEND_CONTAINER_NAME,
            image=ecs.ContainerImage.from_registry("public.ecr.aws/docker/library/nginx:latest"),  # Placeholder
            environment=environment_vars,
            logging=ecs.LogDriver.aws_logs(
                stream_prefix="frontend",
                log_group=self.log_group,
            ),
            health_check=ecs.HealthCheck(
                command=[
                    "CMD-SHELL",
                    f"curl -f http://localhost:{FRONTEND_PORT}{self.config.frontend_health_check_path} || exit 1",
                ],
                interval=Duration.seconds(30),
                timeout=Duration.seconds(5),
                retries=3,
                start_period=Duration.seconds(60),
            ),
        )

        # Add port mapping
        container.add_port_mappings(
            ecs.PortMapping(
                container_port=FRONTEND_PORT,
                protocol=ecs.Protocol.TCP,
            )
        )

        return task_definition

    def _create_backend_service(self) -> ecs.FargateService:
        """
        Create ECS Fargate service for backend.

        Returns:
            ecs.FargateService: Backend service
        """
        service = ecs.FargateService(
            self,
            "BackendService",
            service_name=f"{self.config.project_name}-{self.config.environment}-backend",
            cluster=self.ecs_cluster,
            task_definition=self.backend_task_definition,
            desired_count=self.config.backend_desired_count,
            vpc_subnets=ec2.SubnetSelection(subnets=self.network_stack.public_subnets),
            security_groups=[self.network_stack.ecs_security_group],
            assign_public_ip=True,
            capacity_provider_strategies=[
                ecs.CapacityProviderStrategy(
                    capacity_provider="FARGATE_SPOT" if self.config.enable_spot_instances else "FARGATE",
                    weight=1,
                )
            ],
            enable_execute_command=self.config.enable_ecs_exec,
            health_check_grace_period=Duration.seconds(60),
        )

        # Attach to load balancer
        service.attach_to_application_target_group(
            self.load_balancer_stack.backend_target_group
        )

        return service

    def _create_frontend_service(self) -> ecs.FargateService:
        """
        Create ECS Fargate service for frontend.

        Returns:
            ecs.FargateService: Frontend service
        """
        service = ecs.FargateService(
            self,
            "FrontendService",
            service_name=f"{self.config.project_name}-{self.config.environment}-frontend",
            cluster=self.ecs_cluster,
            task_definition=self.frontend_task_definition,
            desired_count=self.config.frontend_desired_count,
            vpc_subnets=ec2.SubnetSelection(subnets=self.network_stack.public_subnets),
            security_groups=[self.network_stack.ecs_security_group],
            assign_public_ip=True,
            capacity_provider_strategies=[
                ecs.CapacityProviderStrategy(
                    capacity_provider="FARGATE_SPOT" if self.config.enable_spot_instances else "FARGATE",
                    weight=1,
                )
            ],
            enable_execute_command=self.config.enable_ecs_exec,
            health_check_grace_period=Duration.seconds(60),
        )

        # Attach to load balancer
        service.attach_to_application_target_group(
            self.load_balancer_stack.frontend_target_group
        )

        return service

    def _configure_backend_autoscaling(self) -> None:
        """Configure auto-scaling for backend service."""
        scaling = self.backend_service.auto_scale_task_count(
            min_capacity=self.config.backend_min_capacity,
            max_capacity=self.config.backend_max_capacity,
        )

        # CPU-based scaling
        scaling.scale_on_cpu_utilization(
            "BackendCpuScaling",
            target_utilization_percent=CPU_TARGET_UTILIZATION,
            scale_in_cooldown=Duration.seconds(SCALE_IN_COOLDOWN_SECONDS),
            scale_out_cooldown=Duration.seconds(SCALE_OUT_COOLDOWN_SECONDS),
        )

        # Memory-based scaling
        scaling.scale_on_memory_utilization(
            "BackendMemoryScaling",
            target_utilization_percent=MEMORY_TARGET_UTILIZATION,
            scale_in_cooldown=Duration.seconds(SCALE_IN_COOLDOWN_SECONDS),
            scale_out_cooldown=Duration.seconds(SCALE_OUT_COOLDOWN_SECONDS),
        )

    def _configure_frontend_autoscaling(self) -> None:
        """Configure auto-scaling for frontend service."""
        scaling = self.frontend_service.auto_scale_task_count(
            min_capacity=self.config.frontend_min_capacity,
            max_capacity=self.config.frontend_max_capacity,
        )

        # CPU-based scaling
        scaling.scale_on_cpu_utilization(
            "FrontendCpuScaling",
            target_utilization_percent=CPU_TARGET_UTILIZATION,
            scale_in_cooldown=Duration.seconds(SCALE_IN_COOLDOWN_SECONDS),
            scale_out_cooldown=Duration.seconds(SCALE_OUT_COOLDOWN_SECONDS),
        )

    @property
    def cluster_name(self) -> str:
        """Get ECS cluster name."""
        return self.ecs_cluster.cluster_name

    @property
    def backend_service_name(self) -> str:
        """Get backend service name."""
        return self.backend_service.service_name

    @property
    def frontend_service_name(self) -> str:
        """Get frontend service name."""
        return self.frontend_service.service_name
