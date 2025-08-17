# Outputs for ECS Module

output "ecs_cluster_id" {
  description = "ID of the ECS cluster"
  value       = aws_ecs_cluster.main.id
}

output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = aws_ecs_cluster.main.name
}

output "ecs_cluster_arn" {
  description = "ARN of the ECS cluster"
  value       = aws_ecs_cluster.main.arn
}

output "backend_service_id" {
  description = "ID of the backend ECS service"
  value       = aws_ecs_service.backend.id
}

output "backend_service_name" {
  description = "Name of the backend ECS service"
  value       = aws_ecs_service.backend.name
}

output "backend_service_arn" {
  description = "ARN of the backend ECS service"
  value       = aws_ecs_service.backend.id
}

output "frontend_service_id" {
  description = "ID of the frontend ECS service"
  value       = var.enable_frontend ? aws_ecs_service.frontend[0].id : null
}

output "frontend_service_name" {
  description = "Name of the frontend ECS service"
  value       = var.enable_frontend ? aws_ecs_service.frontend[0].name : null
}

output "frontend_service_arn" {
  description = "ARN of the frontend ECS service"
  value       = var.enable_frontend ? aws_ecs_service.frontend[0].id : null
}

output "backend_task_definition_arn" {
  description = "ARN of the backend task definition"
  value       = aws_ecs_task_definition.backend.arn
}

output "backend_task_definition_family" {
  description = "Family of the backend task definition"
  value       = aws_ecs_task_definition.backend.family
}

output "backend_task_definition_revision" {
  description = "Revision of the backend task definition"
  value       = aws_ecs_task_definition.backend.revision
}

output "frontend_task_definition_arn" {
  description = "ARN of the frontend task definition"
  value       = var.enable_frontend ? aws_ecs_task_definition.frontend[0].arn : null
}

output "frontend_task_definition_family" {
  description = "Family of the frontend task definition"
  value       = var.enable_frontend ? aws_ecs_task_definition.frontend[0].family : null
}

output "frontend_task_definition_revision" {
  description = "Revision of the frontend task definition"
  value       = var.enable_frontend ? aws_ecs_task_definition.frontend[0].revision : null
}

output "ecs_security_group_id" {
  description = "ID of the ECS tasks security group"
  value       = aws_security_group.ecs_tasks.id
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for ECS tasks"
  value       = aws_cloudwatch_log_group.ecs_tasks.name
}

output "cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch log group for ECS tasks"
  value       = aws_cloudwatch_log_group.ecs_tasks.arn
}

output "exec_command_log_group_name" {
  description = "Name of the CloudWatch log group for ECS Exec"
  value       = var.enable_exec_command ? aws_cloudwatch_log_group.exec_command[0].name : null
}

output "backend_autoscaling_target_arn" {
  description = "ARN of the backend auto scaling target"
  value       = var.enable_auto_scaling ? aws_appautoscaling_target.backend[0].arn : null
}

output "frontend_autoscaling_target_arn" {
  description = "ARN of the frontend auto scaling target"
  value       = var.enable_frontend && var.enable_auto_scaling ? aws_appautoscaling_target.frontend[0].arn : null
}

output "backend_cpu_scaling_policy_arn" {
  description = "ARN of the backend CPU scaling policy"
  value       = var.enable_auto_scaling ? aws_appautoscaling_policy.backend_cpu[0].arn : null
}

output "backend_memory_scaling_policy_arn" {
  description = "ARN of the backend memory scaling policy"
  value       = var.enable_auto_scaling ? aws_appautoscaling_policy.backend_memory[0].arn : null
}

output "cloudwatch_alarms" {
  description = "CloudWatch alarm ARNs"
  value = var.enable_monitoring ? {
    backend_cpu_high    = aws_cloudwatch_metric_alarm.backend_cpu_high[0].arn
    backend_memory_high = aws_cloudwatch_metric_alarm.backend_memory_high[0].arn
  } : null
}

output "services_summary" {
  description = "Summary of ECS services"
  value = {
    backend = {
      name            = aws_ecs_service.backend.name
      desired_count   = aws_ecs_service.backend.desired_count
      task_definition = aws_ecs_task_definition.backend.arn
      container_port  = var.backend_container_port
      health_check    = var.backend_health_check_path
    }
    frontend = var.enable_frontend ? {
      name            = aws_ecs_service.frontend[0].name
      desired_count   = aws_ecs_service.frontend[0].desired_count
      task_definition = aws_ecs_task_definition.frontend[0].arn
      container_port  = var.frontend_container_port
      health_check    = var.frontend_health_check_path
    } : null
  }
}

output "cluster_configuration" {
  description = "ECS cluster configuration details"
  value = {
    name                   = aws_ecs_cluster.main.name
    container_insights     = var.enable_container_insights
    exec_command_enabled   = var.enable_exec_command
    capacity_providers     = var.enable_fargate_spot ? ["FARGATE", "FARGATE_SPOT"] : ["FARGATE"]
    fargate_weight        = var.fargate_weight
    fargate_spot_weight   = var.enable_fargate_spot ? var.fargate_spot_weight : null
  }
}

output "task_definitions" {
  description = "Task definition details"
  value = {
    backend = {
      family   = aws_ecs_task_definition.backend.family
      revision = aws_ecs_task_definition.backend.revision
      cpu      = var.backend_cpu
      memory   = var.backend_memory
      image    = "${var.ecr_repository_url}:${var.backend_image_tag}"
    }
    frontend = var.enable_frontend ? {
      family   = aws_ecs_task_definition.frontend[0].family
      revision = aws_ecs_task_definition.frontend[0].revision
      cpu      = var.frontend_cpu
      memory   = var.frontend_memory
      image    = "${var.ecr_repository_url}:${var.frontend_image_tag}"
    } : null
  }
}

output "networking_configuration" {
  description = "Networking configuration for ECS services"
  value = {
    vpc_id               = var.vpc_id
    private_subnet_ids   = var.private_subnet_ids
    security_group_id    = aws_security_group.ecs_tasks.id
    backend_port        = var.backend_container_port
    frontend_port       = var.frontend_container_port
  }
}

output "scaling_configuration" {
  description = "Auto scaling configuration"
  value = var.enable_auto_scaling ? {
    backend = {
      min_capacity    = var.backend_min_capacity
      max_capacity    = var.backend_max_capacity
      cpu_target      = var.cpu_target_value
      memory_target   = var.memory_target_value
      scale_in_cooldown  = var.scale_in_cooldown
      scale_out_cooldown = var.scale_out_cooldown
    }
    frontend = var.enable_frontend ? {
      min_capacity    = var.frontend_min_capacity
      max_capacity    = var.frontend_max_capacity
    } : null
  } : null
}

output "deployment_configuration" {
  description = "Deployment configuration details"
  value = {
    maximum_percent         = var.deployment_maximum_percent
    minimum_healthy_percent = var.deployment_minimum_healthy_percent
    circuit_breaker_enabled = var.enable_deployment_circuit_breaker
    rollback_enabled       = var.enable_deployment_rollback
  }
}

output "logging_configuration" {
  description = "Logging configuration details"
  value = {
    log_group_name      = aws_cloudwatch_log_group.ecs_tasks.name
    log_retention_days  = var.log_retention_days
    exec_logging_enabled = var.enable_exec_command
  }
}

output "monitoring_configuration" {
  description = "Monitoring configuration details"
  value = var.enable_monitoring ? {
    cpu_alarm_threshold    = var.cpu_alarm_threshold
    memory_alarm_threshold = var.memory_alarm_threshold
    container_insights     = var.enable_container_insights
    alarm_actions         = var.alarm_actions
  } : null
}