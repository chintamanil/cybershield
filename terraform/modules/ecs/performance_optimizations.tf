# ECS Performance Optimizations for Fast Startup

# Optimized ECS Service with enhanced configuration
resource "aws_ecs_service" "cybershield_optimized" {
  name            = "${var.project_name}-optimized"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.cybershield_optimized.arn
  desired_count   = var.backend_min_capacity
  
  # Enhanced deployment configuration for faster updates
  deployment_configuration {
    maximum_percent         = 200
    minimum_healthy_percent = 100
    
    deployment_circuit_breaker {
      enable   = true
      rollback = true
    }
  }
  
  # Network configuration with performance optimizations
  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.security_group_id]
    assign_public_ip = false
  }
  
  # Load balancer configuration
  dynamic "load_balancer" {
    for_each = var.target_group_arn != null ? [1] : []
    content {
      target_group_arn = var.target_group_arn
      container_name   = "cybershield"
      container_port   = 8000
    }
  }
  
  # Service discovery for internal communication
  service_registries {
    registry_arn = aws_service_discovery_service.cybershield.arn
  }
  
  # Auto scaling integration
  depends_on = [
    aws_ecs_task_definition.cybershield_optimized,
    aws_service_discovery_service.cybershield
  ]
  
  tags = var.tags
}

# Optimized Task Definition with performance tuning
resource "aws_ecs_task_definition" "cybershield_optimized" {
  family                   = "${var.project_name}-optimized"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.backend_cpu
  memory                   = var.backend_memory
  execution_role_arn       = var.execution_role_arn
  task_role_arn           = var.task_role_arn
  
  # Enhanced container definition with startup optimizations
  container_definitions = jsonencode([
    {
      name  = "cybershield"
      image = var.backend_image
      
      # Resource reservations for consistent performance
      cpu          = var.backend_cpu
      memory       = var.backend_memory
      memoryReservation = var.backend_memory * 0.8
      
      # Optimized port mappings
      portMappings = [
        {
          containerPort = 8000
          protocol      = "tcp"
          name          = "cybershield-http"
        }
      ]
      
      # Enhanced environment variables for performance
      environment = concat(var.environment_variables, [
        {
          name  = "AWS_REGION"
          value = data.aws_region.current.name
        },
        {
          name  = "ECS_OPTIMIZATION"
          value = "true"
        },
        {
          name  = "STARTUP_MODE"
          value = "aws_optimized"
        },
        {
          name  = "PYTHON_OPTIMIZATION"
          value = "1"
        },
        {
          name  = "UVICORN_WORKERS"
          value = tostring(max(1, var.backend_cpu / 256))
        },
        {
          name  = "BATCH_SIZE_OPTIMIZATION"
          value = tostring(var.backend_memory >= 2048 ? 32 : 16)
        }
      ])
      
      # Secrets management
      secrets = var.secrets
      
      # Enhanced health check configuration
      healthCheck = {
        command = [
          "CMD-SHELL",
          "curl -f http://localhost:8000/health || exit 1"
        ]
        interval    = 30
        timeout     = 10
        retries     = 3
        startPeriod = 60
      }
      
      # Optimized logging configuration
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.cybershield_optimized.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "ecs"
          "awslogs-datetime-format" = "%Y-%m-%d %H:%M:%S"
        }
      }
      
      # Performance optimizations
      linuxParameters = {
        capabilities = {
          add = ["NET_ADMIN"]
        }
        devices = []
        initProcessEnabled = true
        maxSwap = 0
        sharedMemorySize = 64
        swappiness = 0
        tmpfs = [
          {
            containerPath = "/tmp"
            mountOptions = ["rw", "noexec", "nosuid", "size=100m"]
            size = 100
          }
        ]
      }
      
      # Essential container flag
      essential = true
      
      # Startup dependency ordering
      dependsOn = []
    }
  ])
  
  # Placement constraints for performance
  placement_constraints {
    type = "distinctInstance"
  }
  
  tags = var.tags
}

# Service Discovery for internal communication
resource "aws_service_discovery_service" "cybershield" {
  name = "${var.project_name}-discovery"
  
  dns_config {
    namespace_id   = var.service_discovery_namespace_id
    routing_policy = "WEIGHTED"
    
    dns_records {
      ttl  = 10
      type = "A"
    }
  }
  
  health_check_grace_period_seconds = 30
  
  tags = var.tags
}

# CloudWatch Log Group with optimized retention
resource "aws_cloudwatch_log_group" "cybershield_optimized" {
  name              = "/ecs/${var.project_name}-optimized"
  retention_in_days = 7  # Shorter retention for cost optimization
  
  tags = var.tags
}

# Auto Scaling for performance under load
resource "aws_appautoscaling_target" "cybershield_optimized" {
  max_capacity       = var.backend_max_capacity
  min_capacity       = var.backend_min_capacity
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.cybershield_optimized.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
  
  tags = var.tags
}

# CPU-based auto scaling policy
resource "aws_appautoscaling_policy" "cpu_scaling" {
  name               = "${var.project_name}-cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.cybershield_optimized.resource_id
  scalable_dimension = aws_appautoscaling_target.cybershield_optimized.scalable_dimension
  service_namespace  = aws_appautoscaling_target.cybershield_optimized.service_namespace
  
  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 70.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

# Memory-based auto scaling policy
resource "aws_appautoscaling_policy" "memory_scaling" {
  name               = "${var.project_name}-memory-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.cybershield_optimized.resource_id
  scalable_dimension = aws_appautoscaling_target.cybershield_optimized.scalable_dimension
  service_namespace  = aws_appautoscaling_target.cybershield_optimized.service_namespace
  
  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }
    target_value       = 80.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

# Data sources
data "aws_region" "current" {}

# Outputs
output "optimized_service_name" {
  value = aws_ecs_service.cybershield_optimized.name
}

output "optimized_task_definition_arn" {
  value = aws_ecs_task_definition.cybershield_optimized.arn
}

output "service_discovery_arn" {
  value = aws_service_discovery_service.cybershield.arn
}