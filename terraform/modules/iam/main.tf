# IAM Module for CyberShield
# Manages roles, policies, and permissions for ECS, RDS, and other services

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

# ECS Task Execution Role
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "${var.project_name}-${var.environment}-ecs-task-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-ecs-task-execution-role"
    Type = "iam-role"
  })
}

# Attach AWS managed policy for ECS task execution
resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Custom policy for ECS task execution (CloudWatch logs, ECR, Secrets Manager)
resource "aws_iam_policy" "ecs_task_execution_custom" {
  name        = "${var.project_name}-${var.environment}-ecs-task-execution-custom"
  description = "Custom policy for ECS task execution"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/ecs/${var.project_name}-${var.environment}*"
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          "arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:${var.project_name}-${var.environment}/*"
        ]
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-ecs-task-execution-custom-policy"
    Type = "iam-policy"
  })
}

# Attach custom policy to ECS task execution role
resource "aws_iam_role_policy_attachment" "ecs_task_execution_custom" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = aws_iam_policy.ecs_task_execution_custom.arn
}

# ECS Task Role (for application permissions)
resource "aws_iam_role" "ecs_task_role" {
  name = "${var.project_name}-${var.environment}-ecs-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-ecs-task-role"
    Type = "iam-role"
  })
}

# Custom policy for ECS task (application permissions)
resource "aws_iam_policy" "ecs_task_custom" {
  name        = "${var.project_name}-${var.environment}-ecs-task-custom"
  description = "Custom policy for ECS task application permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # CloudWatch Logs
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/ecs/${var.project_name}-${var.environment}*"
      },
      # CloudWatch Metrics
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:ListMetrics"
        ]
        Resource = "*"
      },
      # S3 Access for uploads and backups
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${var.project_name}-${var.environment}-uploads-*",
          "arn:aws:s3:::${var.project_name}-${var.environment}-uploads-*/*",
          "arn:aws:s3:::${var.project_name}-${var.environment}-backups-*",
          "arn:aws:s3:::${var.project_name}-${var.environment}-backups-*/*"
        ]
      },
      # Parameter Store for configuration
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ]
        Resource = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/${var.project_name}/${var.environment}/*"
      },
      # Secrets Manager for sensitive configuration
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = "arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:${var.project_name}-${var.environment}/*"
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-ecs-task-custom-policy"
    Type = "iam-policy"
  })
}

# Attach custom policy to ECS task role
resource "aws_iam_role_policy_attachment" "ecs_task_custom" {
  role       = aws_iam_role.ecs_task_role.name
  policy_arn = aws_iam_policy.ecs_task_custom.arn
}

# ECS Service Role (for load balancer integration)
resource "aws_iam_role" "ecs_service_role" {
  name = "${var.project_name}-${var.environment}-ecs-service"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-ecs-service-role"
    Type = "iam-role"
  })
}

# Attach AWS managed policy for ECS service
resource "aws_iam_role_policy_attachment" "ecs_service_role_policy" {
  role       = aws_iam_role.ecs_service_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSServiceRolePolicy"
}

# Application Auto Scaling Role
resource "aws_iam_role" "ecs_autoscaling_role" {
  name = "${var.project_name}-${var.environment}-ecs-autoscaling"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "application-autoscaling.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-ecs-autoscaling-role"
    Type = "iam-role"
  })
}

# Attach AWS managed policy for Application Auto Scaling
resource "aws_iam_role_policy_attachment" "ecs_autoscaling_role_policy" {
  role       = aws_iam_role.ecs_autoscaling_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSServiceRolePolicy"
}

# CloudWatch Events Role for scheduled tasks
resource "aws_iam_role" "cloudwatch_events_role" {
  count = var.enable_scheduled_tasks ? 1 : 0
  name  = "${var.project_name}-${var.environment}-cloudwatch-events"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-cloudwatch-events-role"
    Type = "iam-role"
  })
}

# Custom policy for CloudWatch Events
resource "aws_iam_policy" "cloudwatch_events_custom" {
  count       = var.enable_scheduled_tasks ? 1 : 0
  name        = "${var.project_name}-${var.environment}-cloudwatch-events-custom"
  description = "Custom policy for CloudWatch Events to run ECS tasks"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecs:RunTask"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "ecs:cluster" = "arn:aws:ecs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:cluster/${var.project_name}-${var.environment}"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "iam:PassRole"
        ]
        Resource = [
          aws_iam_role.ecs_task_execution_role.arn,
          aws_iam_role.ecs_task_role.arn
        ]
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-cloudwatch-events-custom-policy"
    Type = "iam-policy"
  })
}

# Attach custom policy to CloudWatch Events role
resource "aws_iam_role_policy_attachment" "cloudwatch_events_custom" {
  count      = var.enable_scheduled_tasks ? 1 : 0
  role       = aws_iam_role.cloudwatch_events_role[0].name
  policy_arn = aws_iam_policy.cloudwatch_events_custom[0].arn
}

# Lambda Execution Role (if Lambda functions are needed)
resource "aws_iam_role" "lambda_execution_role" {
  count = var.enable_lambda_functions ? 1 : 0
  name  = "${var.project_name}-${var.environment}-lambda-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-lambda-execution-role"
    Type = "iam-role"
  })
}

# Attach AWS managed policy for Lambda basic execution
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  count      = var.enable_lambda_functions ? 1 : 0
  role       = aws_iam_role.lambda_execution_role[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Custom policy for Lambda functions
resource "aws_iam_policy" "lambda_custom" {
  count       = var.enable_lambda_functions ? 1 : 0
  name        = "${var.project_name}-${var.environment}-lambda-custom"
  description = "Custom policy for Lambda functions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.project_name}-${var.environment}*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteNetworkInterface",
          "ec2:AttachNetworkInterface",
          "ec2:DetachNetworkInterface"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-lambda-custom-policy"
    Type = "iam-policy"
  })
}

# Attach custom policy to Lambda execution role
resource "aws_iam_role_policy_attachment" "lambda_custom" {
  count      = var.enable_lambda_functions ? 1 : 0
  role       = aws_iam_role.lambda_execution_role[0].name
  policy_arn = aws_iam_policy.lambda_custom[0].arn
}

# Instance Profile for EC2 (if needed for debugging or management)
resource "aws_iam_role" "ec2_role" {
  count = var.enable_ec2_role ? 1 : 0
  name  = "${var.project_name}-${var.environment}-ec2"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-ec2-role"
    Type = "iam-role"
  })
}

# Instance profile for EC2 role
resource "aws_iam_instance_profile" "ec2_profile" {
  count = var.enable_ec2_role ? 1 : 0
  name  = "${var.project_name}-${var.environment}-ec2-profile"
  role  = aws_iam_role.ec2_role[0].name

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-ec2-instance-profile"
    Type = "iam-instance-profile"
  })
}

# Attach AWS managed policies to EC2 role
resource "aws_iam_role_policy_attachment" "ec2_ssm_managed" {
  count      = var.enable_ec2_role ? 1 : 0
  role       = aws_iam_role.ec2_role[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "ec2_cloudwatch_agent" {
  count      = var.enable_ec2_role ? 1 : 0
  role       = aws_iam_role.ec2_role[0].name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}