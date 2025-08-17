# ECS Module for CyberShield
# Manages container orchestration, services, and task definitions

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.100"
    }
  }
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ECS Cluster
resource "aws_ecs_cluster" "main" {
  name = "${var.project_name}-${var.environment}"

  configuration {
    execute_command_configuration {
      kms_key_id = var.enable_exec_command ? var.kms_key_id : null
      logging    = var.enable_exec_command ? "OVERRIDE" : "DEFAULT"

      dynamic "log_configuration" {
        for_each = var.enable_exec_command ? [1] : []
        content {
          cloud_watch_encryption_enabled = var.exec_command_log_encryption
          cloud_watch_log_group_name     = aws_cloudwatch_log_group.exec_command[0].name
        }
      }
    }
  }

  setting {
    name  = "containerInsights"
    value = var.enable_container_insights ? "enabled" : "disabled"
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-cluster"
    Type = "ecs-cluster"
  })
}

# ECS Cluster Capacity Providers
resource "aws_ecs_cluster_capacity_providers" "main" {
  cluster_name = aws_ecs_cluster.main.name

  capacity_providers = var.enable_fargate_spot ? ["FARGATE", "FARGATE_SPOT"] : ["FARGATE"]

  default_capacity_provider_strategy {
    base              = var.fargate_base_capacity
    weight            = var.fargate_weight
    capacity_provider = "FARGATE"
  }

  dynamic "default_capacity_provider_strategy" {
    for_each = var.enable_fargate_spot ? [1] : []
    content {
      base              = var.fargate_spot_base_capacity
      weight            = var.fargate_spot_weight
      capacity_provider = "FARGATE_SPOT"
    }
  }
}

# CloudWatch Log Group for ECS tasks
resource "aws_cloudwatch_log_group" "ecs_tasks" {
  name              = "/ecs/${var.project_name}-${var.environment}"
  retention_in_days = var.log_retention_days

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-ecs-logs"
    Type = "cloudwatch-log-group"
  })
}

# CloudWatch Log Group for ECS Exec Command
resource "aws_cloudwatch_log_group" "exec_command" {
  count             = var.enable_exec_command ? 1 : 0
  name              = "/ecs/${var.project_name}-${var.environment}/exec"
  retention_in_days = var.log_retention_days

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-exec-logs"
    Type = "cloudwatch-log-group"
  })
}

# Security Group for ECS Tasks
resource "aws_security_group" "ecs_tasks" {
  name_prefix = "${var.project_name}-${var.environment}-ecs-tasks-"
  vpc_id      = var.vpc_id
  description = "Security group for ECS tasks"

  # Allow inbound traffic from ALB
  ingress {
    from_port       = var.backend_container_port
    to_port         = var.backend_container_port
    protocol        = "tcp"
    security_groups = [var.alb_security_group_id]
    description     = "Backend traffic from ALB"
  }

  dynamic "ingress" {
    for_each = var.enable_frontend ? [1] : []
    content {
      from_port       = var.frontend_container_port
      to_port         = var.frontend_container_port
      protocol        = "tcp"
      security_groups = [var.alb_security_group_id]
      description     = "Frontend traffic from ALB"
    }
  }

  # Allow outbound traffic for database connections
  egress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "PostgreSQL database access"
  }

  # Allow outbound traffic for Redis connections
  egress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Redis cache access"
  }

  # Allow outbound traffic for OpenSearch connections
  dynamic "egress" {
    for_each = var.enable_opensearch ? [1] : []
    content {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = [var.vpc_cidr]
      description = "OpenSearch access"
    }
  }

  # Allow all outbound HTTPS for API calls
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS outbound for API calls"
  }

  # Allow all outbound HTTP for package downloads
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP outbound for package downloads"
  }

  # Allow outbound DNS
  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "DNS resolution"
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-ecs-tasks-sg"
    Type = "ecs-security-group"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Backend Task Definition
resource "aws_ecs_task_definition" "backend" {
  family                   = "${var.project_name}-${var.environment}-backend"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.backend_cpu
  memory                   = var.backend_memory
  execution_role_arn       = var.task_execution_role_arn
  task_role_arn           = var.task_role_arn

  container_definitions = jsonencode([
    {
      name  = "backend"
      image = "${var.ecr_repository_url}:${var.backend_image_tag}"
      
      essential = true
      
      portMappings = [
        {
          containerPort = var.backend_container_port
          protocol      = "tcp"
        }
      ]
      
      environment = [
        for key, value in var.backend_environment_variables : {
          name  = key
          value = tostring(value)
        }
      ]
      
      secrets = [
        for key, value in var.backend_secrets : {
          name      = key
          valueFrom = value
        }
      ]
      
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs_tasks.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "backend"
        }
      }
      
      healthCheck = {
        command = [
          "CMD-SHELL",
          "curl -f http://localhost:${var.backend_container_port}${var.backend_health_check_path} || exit 1"
        ]
        interval    = var.health_check_interval
        timeout     = var.health_check_timeout
        retries     = var.health_check_retries
        startPeriod = var.health_check_start_period
      }
      
      cpu         = var.backend_cpu
      memory      = var.backend_memory
      
      stopTimeout = var.stop_timeout
      
      ulimits = [
        {
          name      = "nofile"
          softLimit = 65536
          hardLimit = 65536
        }
      ]
      
      linuxParameters = {
        initProcessEnabled = true
      }
    }
  ])

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-backend-task-definition"
    Type = "ecs-task-definition"
  })
}

# Frontend Task Definition (if enabled)
resource "aws_ecs_task_definition" "frontend" {
  count                    = var.enable_frontend ? 1 : 0
  family                   = "${var.project_name}-${var.environment}-frontend"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.frontend_cpu
  memory                   = var.frontend_memory
  execution_role_arn       = var.task_execution_role_arn
  task_role_arn           = var.task_role_arn

  container_definitions = jsonencode([
    {
      name  = "frontend"
      image = "${var.ecr_repository_url}:${var.frontend_image_tag}"
      
      essential = true
      
      portMappings = [
        {
          containerPort = var.frontend_container_port
          protocol      = "tcp"
        }
      ]
      
      environment = [
        for key, value in var.frontend_environment_variables : {
          name  = key
          value = tostring(value)
        }
      ]
      
      secrets = [
        for key, value in var.frontend_secrets : {
          name      = key
          valueFrom = value
        }
      ]
      
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs_tasks.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "frontend"
        }
      }
      
      healthCheck = {
        command = [
          "CMD-SHELL",
          "curl -f http://localhost:${var.frontend_container_port}${var.frontend_health_check_path} || exit 1"
        ]
        interval    = var.health_check_interval
        timeout     = var.health_check_timeout
        retries     = var.health_check_retries
        startPeriod = var.health_check_start_period
      }
      
      cpu         = var.frontend_cpu
      memory      = var.frontend_memory
      
      stopTimeout = var.stop_timeout
    }
  ])

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-frontend-task-definition"
    Type = "ecs-task-definition"
  })
}

# Backend ECS Service
resource "aws_ecs_service" "backend" {
  name            = "${var.project_name}-${var.environment}-backend"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.backend.arn
  desired_count   = var.backend_desired_count

  capacity_provider_strategy {
    base              = var.fargate_base_capacity
    weight            = var.fargate_weight
    capacity_provider = "FARGATE"
  }

  dynamic "capacity_provider_strategy" {
    for_each = var.enable_fargate_spot ? [1] : []
    content {
      base              = var.fargate_spot_base_capacity
      weight            = var.fargate_spot_weight
      capacity_provider = "FARGATE_SPOT"
    }
  }

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = var.backend_target_group_arn
    container_name   = "backend"
    container_port   = var.backend_container_port
  }

  deployment_configuration {
    maximum_percent         = var.deployment_maximum_percent
    minimum_healthy_percent = var.deployment_minimum_healthy_percent
    
    deployment_circuit_breaker {
      enable   = var.enable_deployment_circuit_breaker
      rollback = var.enable_deployment_rollback
    }
  }

  enable_execute_command = var.enable_exec_command

  depends_on = [var.backend_target_group_arn]

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-backend-service"
    Type = "ecs-service"
  })

  lifecycle {
    ignore_changes = [desired_count]
  }
}

# Frontend ECS Service (if enabled)
resource "aws_ecs_service" "frontend" {
  count           = var.enable_frontend ? 1 : 0
  name            = "${var.project_name}-${var.environment}-frontend"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.frontend[0].arn
  desired_count   = var.frontend_desired_count

  capacity_provider_strategy {
    base              = var.fargate_base_capacity
    weight            = var.fargate_weight
    capacity_provider = "FARGATE"
  }

  dynamic "capacity_provider_strategy" {
    for_each = var.enable_fargate_spot ? [1] : []
    content {
      base              = var.fargate_spot_base_capacity
      weight            = var.fargate_spot_weight
      capacity_provider = "FARGATE_SPOT"
    }
  }

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = var.frontend_target_group_arn
    container_name   = "frontend"
    container_port   = var.frontend_container_port
  }

  deployment_configuration {
    maximum_percent         = var.deployment_maximum_percent
    minimum_healthy_percent = var.deployment_minimum_healthy_percent
    
    deployment_circuit_breaker {
      enable   = var.enable_deployment_circuit_breaker
      rollback = var.enable_deployment_rollback
    }
  }

  enable_execute_command = var.enable_exec_command

  depends_on = [var.frontend_target_group_arn]

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-frontend-service"
    Type = "ecs-service"
  })

  lifecycle {
    ignore_changes = [desired_count]
  }
}

# Auto Scaling Target for Backend
resource "aws_appautoscaling_target" "backend" {
  count              = var.enable_auto_scaling ? 1 : 0
  max_capacity       = var.backend_max_capacity
  min_capacity       = var.backend_min_capacity
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.backend.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-backend-autoscaling-target"
    Type = "autoscaling-target"
  })
}

# Auto Scaling Policy for Backend (CPU)
resource "aws_appautoscaling_policy" "backend_cpu" {
  count              = var.enable_auto_scaling ? 1 : 0
  name               = "${var.project_name}-${var.environment}-backend-cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.backend[0].resource_id
  scalable_dimension = aws_appautoscaling_target.backend[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.backend[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = var.cpu_target_value
    scale_in_cooldown  = var.scale_in_cooldown
    scale_out_cooldown = var.scale_out_cooldown
  }
}

# Auto Scaling Policy for Backend (Memory)
resource "aws_appautoscaling_policy" "backend_memory" {
  count              = var.enable_auto_scaling ? 1 : 0
  name               = "${var.project_name}-${var.environment}-backend-memory-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.backend[0].resource_id
  scalable_dimension = aws_appautoscaling_target.backend[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.backend[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }
    target_value       = var.memory_target_value
    scale_in_cooldown  = var.scale_in_cooldown
    scale_out_cooldown = var.scale_out_cooldown
  }
}

# Auto Scaling Target for Frontend (if enabled)
resource "aws_appautoscaling_target" "frontend" {
  count              = var.enable_frontend && var.enable_auto_scaling ? 1 : 0
  max_capacity       = var.frontend_max_capacity
  min_capacity       = var.frontend_min_capacity
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.frontend[0].name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-frontend-autoscaling-target"
    Type = "autoscaling-target"
  })
}

# CloudWatch Alarms for monitoring
resource "aws_cloudwatch_metric_alarm" "backend_cpu_high" {
  count               = var.enable_monitoring ? 1 : 0
  alarm_name          = "${var.project_name}-${var.environment}-backend-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = "300"
  statistic           = "Average"
  threshold           = var.cpu_alarm_threshold
  alarm_description   = "Backend service CPU utilization is high"
  alarm_actions       = var.alarm_actions

  dimensions = {
    ServiceName = aws_ecs_service.backend.name
    ClusterName = aws_ecs_cluster.main.name
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-backend-cpu-alarm"
    Type = "cloudwatch-alarm"
  })
}

resource "aws_cloudwatch_metric_alarm" "backend_memory_high" {
  count               = var.enable_monitoring ? 1 : 0
  alarm_name          = "${var.project_name}-${var.environment}-backend-memory-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = "300"
  statistic           = "Average"
  threshold           = var.memory_alarm_threshold
  alarm_description   = "Backend service memory utilization is high"
  alarm_actions       = var.alarm_actions

  dimensions = {
    ServiceName = aws_ecs_service.backend.name
    ClusterName = aws_ecs_cluster.main.name
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-backend-memory-alarm"
    Type = "cloudwatch-alarm"
  })
}