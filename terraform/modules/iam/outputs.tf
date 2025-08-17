# Outputs for IAM Module

output "ecs_task_execution_role_arn" {
  description = "ARN of the ECS task execution role"
  value       = aws_iam_role.ecs_task_execution_role.arn
}

output "ecs_task_execution_role_name" {
  description = "Name of the ECS task execution role"
  value       = aws_iam_role.ecs_task_execution_role.name
}

output "ecs_task_role_arn" {
  description = "ARN of the ECS task role"
  value       = aws_iam_role.ecs_task_role.arn
}

output "ecs_task_role_name" {
  description = "Name of the ECS task role"
  value       = aws_iam_role.ecs_task_role.name
}

output "ecs_service_role_arn" {
  description = "ARN of the ECS service role"
  value       = aws_iam_role.ecs_service_role.arn
}

output "ecs_service_role_name" {
  description = "Name of the ECS service role"
  value       = aws_iam_role.ecs_service_role.name
}

output "ecs_autoscaling_role_arn" {
  description = "ARN of the ECS auto-scaling role"
  value       = aws_iam_role.ecs_autoscaling_role.arn
}

output "ecs_autoscaling_role_name" {
  description = "Name of the ECS auto-scaling role"
  value       = aws_iam_role.ecs_autoscaling_role.name
}

output "cloudwatch_events_role_arn" {
  description = "ARN of the CloudWatch Events role"
  value       = var.enable_scheduled_tasks ? aws_iam_role.cloudwatch_events_role[0].arn : null
}

output "cloudwatch_events_role_name" {
  description = "Name of the CloudWatch Events role"
  value       = var.enable_scheduled_tasks ? aws_iam_role.cloudwatch_events_role[0].name : null
}

output "lambda_execution_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = var.enable_lambda_functions ? aws_iam_role.lambda_execution_role[0].arn : null
}

output "lambda_execution_role_name" {
  description = "Name of the Lambda execution role"
  value       = var.enable_lambda_functions ? aws_iam_role.lambda_execution_role[0].name : null
}

output "ec2_role_arn" {
  description = "ARN of the EC2 instance role"
  value       = var.enable_ec2_role ? aws_iam_role.ec2_role[0].arn : null
}

output "ec2_role_name" {
  description = "Name of the EC2 instance role"
  value       = var.enable_ec2_role ? aws_iam_role.ec2_role[0].name : null
}

output "ec2_instance_profile_arn" {
  description = "ARN of the EC2 instance profile"
  value       = var.enable_ec2_role ? aws_iam_instance_profile.ec2_profile[0].arn : null
}

output "ec2_instance_profile_name" {
  description = "Name of the EC2 instance profile"
  value       = var.enable_ec2_role ? aws_iam_instance_profile.ec2_profile[0].name : null
}

output "ecs_task_execution_policy_arn" {
  description = "ARN of the custom ECS task execution policy"
  value       = aws_iam_policy.ecs_task_execution_custom.arn
}

output "ecs_task_policy_arn" {
  description = "ARN of the custom ECS task policy"
  value       = aws_iam_policy.ecs_task_custom.arn
}

output "cloudwatch_events_policy_arn" {
  description = "ARN of the CloudWatch Events custom policy"
  value       = var.enable_scheduled_tasks ? aws_iam_policy.cloudwatch_events_custom[0].arn : null
}

output "lambda_custom_policy_arn" {
  description = "ARN of the Lambda custom policy"
  value       = var.enable_lambda_functions ? aws_iam_policy.lambda_custom[0].arn : null
}

output "iam_roles_summary" {
  description = "Summary of all IAM roles created"
  value = {
    ecs_task_execution = {
      arn  = aws_iam_role.ecs_task_execution_role.arn
      name = aws_iam_role.ecs_task_execution_role.name
    }
    ecs_task = {
      arn  = aws_iam_role.ecs_task_role.arn
      name = aws_iam_role.ecs_task_role.name
    }
    ecs_service = {
      arn  = aws_iam_role.ecs_service_role.arn
      name = aws_iam_role.ecs_service_role.name
    }
    ecs_autoscaling = {
      arn  = aws_iam_role.ecs_autoscaling_role.arn
      name = aws_iam_role.ecs_autoscaling_role.name
    }
    cloudwatch_events = var.enable_scheduled_tasks ? {
      arn  = aws_iam_role.cloudwatch_events_role[0].arn
      name = aws_iam_role.cloudwatch_events_role[0].name
    } : null
    lambda_execution = var.enable_lambda_functions ? {
      arn  = aws_iam_role.lambda_execution_role[0].arn
      name = aws_iam_role.lambda_execution_role[0].name
    } : null
    ec2_instance = var.enable_ec2_role ? {
      arn  = aws_iam_role.ec2_role[0].arn
      name = aws_iam_role.ec2_role[0].name
    } : null
  }
}

output "iam_policies_summary" {
  description = "Summary of all IAM policies created"
  value = {
    ecs_task_execution_custom = {
      arn  = aws_iam_policy.ecs_task_execution_custom.arn
      name = aws_iam_policy.ecs_task_execution_custom.name
    }
    ecs_task_custom = {
      arn  = aws_iam_policy.ecs_task_custom.arn
      name = aws_iam_policy.ecs_task_custom.name
    }
    cloudwatch_events_custom = var.enable_scheduled_tasks ? {
      arn  = aws_iam_policy.cloudwatch_events_custom[0].arn
      name = aws_iam_policy.cloudwatch_events_custom[0].name
    } : null
    lambda_custom = var.enable_lambda_functions ? {
      arn  = aws_iam_policy.lambda_custom[0].arn
      name = aws_iam_policy.lambda_custom[0].name
    } : null
  }
}

output "role_trust_relationships" {
  description = "Trust relationships for created roles"
  value = {
    ecs_task_execution = "ecs-tasks.amazonaws.com"
    ecs_task          = "ecs-tasks.amazonaws.com"
    ecs_service       = "ecs.amazonaws.com"
    ecs_autoscaling   = "application-autoscaling.amazonaws.com"
    cloudwatch_events = var.enable_scheduled_tasks ? "events.amazonaws.com" : null
    lambda_execution  = var.enable_lambda_functions ? "lambda.amazonaws.com" : null
    ec2_instance     = var.enable_ec2_role ? "ec2.amazonaws.com" : null
  }
}

output "managed_policy_attachments" {
  description = "AWS managed policies attached to roles"
  value = {
    ecs_task_execution = [
      "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    ]
    ecs_service = [
      "arn:aws:iam::aws:policy/service-role/AmazonECSServiceRolePolicy"
    ]
    ecs_autoscaling = [
      "arn:aws:iam::aws:policy/service-role/AmazonECSServiceRolePolicy"
    ]
    lambda_execution = var.enable_lambda_functions ? [
      "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    ] : null
    ec2_instance = var.enable_ec2_role ? [
      "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
      "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
    ] : null
  }
}