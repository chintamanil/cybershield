# Bedrock Fine-tuning Module for CyberShield
# Manages custom model training and deployment

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

# S3 Bucket for fine-tuning datasets
resource "aws_s3_bucket" "bedrock_training_data" {
  bucket = "${var.project_name}-${var.environment}-bedrock-training-${random_string.bucket_suffix.result}"

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-bedrock-training"
    Type = "bedrock-training-bucket"
  })
}

# Random suffix for unique bucket names
resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# Bucket versioning for training data
resource "aws_s3_bucket_versioning" "bedrock_training_data" {
  bucket = aws_s3_bucket.bedrock_training_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Server-side encryption for training data
resource "aws_s3_bucket_server_side_encryption_configuration" "bedrock_training_data" {
  bucket = aws_s3_bucket.bedrock_training_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_id != null ? var.kms_key_id : "alias/aws/s3"
    }
  }
}

# Block public access to training data
resource "aws_s3_bucket_public_access_block" "bedrock_training_data" {
  bucket = aws_s3_bucket.bedrock_training_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 Bucket for fine-tuned model artifacts
resource "aws_s3_bucket" "bedrock_model_artifacts" {
  bucket = "${var.project_name}-${var.environment}-bedrock-models-${random_string.bucket_suffix.result}"

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-bedrock-models"
    Type = "bedrock-model-artifacts"
  })
}

# IAM Role for Bedrock fine-tuning
resource "aws_iam_role" "bedrock_finetuning_role" {
  name = "${var.project_name}-${var.environment}-bedrock-finetuning"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "bedrock.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-bedrock-finetuning-role"
    Type = "iam-role"
  })
}

# IAM Policy for Bedrock fine-tuning access to S3
resource "aws_iam_policy" "bedrock_finetuning_policy" {
  name        = "${var.project_name}-${var.environment}-bedrock-finetuning"
  description = "Policy for Bedrock fine-tuning access to S3 buckets"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.bedrock_training_data.arn,
          "${aws_s3_bucket.bedrock_training_data.arn}/*",
          aws_s3_bucket.bedrock_model_artifacts.arn,
          "${aws_s3_bucket.bedrock_model_artifacts.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${data.aws_region.current.name}.amazonaws.com"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/bedrock/*"
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-bedrock-finetuning-policy"
    Type = "iam-policy"
  })
}

# Attach policy to role
resource "aws_iam_role_policy_attachment" "bedrock_finetuning_policy_attachment" {
  role       = aws_iam_role.bedrock_finetuning_role.name
  policy_arn = aws_iam_policy.bedrock_finetuning_policy.arn
}

# CloudWatch Log Group for Bedrock fine-tuning
resource "aws_cloudwatch_log_group" "bedrock_finetuning" {
  name              = "/aws/bedrock/finetuning/${var.project_name}-${var.environment}"
  retention_in_days = var.log_retention_days

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-bedrock-finetuning-logs"
    Type = "cloudwatch-log-group"
  })
}

# IAM Role for application to access Bedrock
resource "aws_iam_role" "bedrock_application_role" {
  name = "${var.project_name}-${var.environment}-bedrock-app"

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
    Name = "${var.project_name}-${var.environment}-bedrock-app-role"
    Type = "iam-role"
  })
}

# IAM Policy for application Bedrock access
resource "aws_iam_policy" "bedrock_application_policy" {
  name        = "${var.project_name}-${var.environment}-bedrock-app"
  description = "Policy for application to invoke Bedrock models"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ]
        Resource = [
          "arn:aws:bedrock:${data.aws_region.current.name}::foundation-model/*",
          "arn:aws:bedrock:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:custom-model/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "bedrock:ListFoundationModels",
          "bedrock:ListCustomModels",
          "bedrock:GetFoundationModel",
          "bedrock:GetCustomModel"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-bedrock-app-policy"
    Type = "iam-policy"
  })
}

# Attach application policy to role
resource "aws_iam_role_policy_attachment" "bedrock_application_policy_attachment" {
  role       = aws_iam_role.bedrock_application_role.name
  policy_arn = aws_iam_policy.bedrock_application_policy.arn
}

# VPC Endpoint for Bedrock (optional, for private connectivity)
resource "aws_vpc_endpoint" "bedrock" {
  count              = var.enable_vpc_endpoint ? 1 : 0
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.name}.bedrock-runtime"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.private_subnet_ids
  security_group_ids = [aws_security_group.bedrock_vpc_endpoint[0].id]

  private_dns_enabled = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream",
          "bedrock:ListFoundationModels",
          "bedrock:GetFoundationModel"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-bedrock-vpc-endpoint"
    Type = "vpc-endpoint"
  })
}

# Security Group for Bedrock VPC Endpoint
resource "aws_security_group" "bedrock_vpc_endpoint" {
  count       = var.enable_vpc_endpoint ? 1 : 0
  name_prefix = "${var.project_name}-${var.environment}-bedrock-endpoint-"
  vpc_id      = var.vpc_id
  description = "Security group for Bedrock VPC endpoint"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "HTTPS access from VPC"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-bedrock-endpoint-sg"
    Type = "security-group"
  })

  lifecycle {
    create_before_destroy = true
  }
}