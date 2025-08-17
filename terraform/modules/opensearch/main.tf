# OpenSearch Module for CyberShield
# Provides search capabilities for security analytics and log analysis

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

# Security group for OpenSearch
resource "aws_security_group" "opensearch" {
  name_prefix = "${var.project_name}-${var.environment}-opensearch-"
  vpc_id      = var.vpc_id
  description = "Security group for OpenSearch cluster"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "HTTPS access from VPC"
  }

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = var.allowed_security_group_ids
    description     = "HTTPS access from allowed security groups"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-opensearch-sg"
    Type = "opensearch-security-group"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# OpenSearch domain
resource "aws_opensearch_domain" "main" {
  domain_name    = "${var.project_name}-${var.environment}"
  engine_version = "OpenSearch_${var.opensearch_version}"

  cluster_config {
    instance_type            = var.instance_type
    instance_count           = var.instance_count
    dedicated_master_enabled = var.dedicated_master_enabled
    master_instance_type     = var.master_instance_type
    master_instance_count    = var.master_instance_count
    zone_awareness_enabled   = var.zone_awareness_enabled

    dynamic "zone_awareness_config" {
      for_each = var.zone_awareness_enabled ? [1] : []
      content {
        availability_zone_count = var.availability_zone_count
      }
    }

    warm_enabled = var.warm_enabled
    dynamic "warm_config" {
      for_each = var.warm_enabled ? [1] : []
      content {
        warm_instance_type  = var.warm_instance_type
        warm_instance_count = var.warm_instance_count
      }
    }

    cold_storage_options {
      enabled = var.cold_storage_enabled
    }
  }

  # EBS storage configuration
  ebs_options {
    ebs_enabled = true
    volume_type = var.volume_type
    volume_size = var.volume_size
    iops        = var.volume_type == "gp3" ? var.iops : null
    throughput  = var.volume_type == "gp3" ? var.throughput : null
  }

  # VPC configuration
  vpc_options {
    subnet_ids         = var.subnet_ids
    security_group_ids = [aws_security_group.opensearch.id]
  }

  # Encryption configuration
  encrypt_at_rest {
    enabled    = var.encrypt_at_rest
    kms_key_id = var.kms_key_id
  }

  node_to_node_encryption {
    enabled = var.node_to_node_encryption
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = var.tls_security_policy
  }

  # Advanced security options
  advanced_security_options {
    enabled                        = var.advanced_security_enabled
    anonymous_auth_enabled         = false
    internal_user_database_enabled = var.internal_user_database_enabled

    dynamic "master_user_options" {
      for_each = var.advanced_security_enabled && var.internal_user_database_enabled ? [1] : []
      content {
        master_user_name     = var.master_user_name
        master_user_password = var.master_user_password
      }
    }
  }

  # Snapshot configuration
  snapshot_options {
    automated_snapshot_start_hour = var.automated_snapshot_start_hour
  }

  # Log publishing configuration
  dynamic "log_publishing_options" {
    for_each = var.log_publishing_options
    content {
      cloudwatch_log_group_arn = log_publishing_options.value.cloudwatch_log_group_arn
      log_type                 = log_publishing_options.value.log_type
      enabled                  = log_publishing_options.value.enabled
    }
  }

  # Advanced options
  advanced_options = var.advanced_options

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-opensearch"
    Type = "opensearch-domain"
  })

  depends_on = [aws_iam_service_linked_role.opensearch]

  lifecycle {
    prevent_destroy = true
  }
}

# Service-linked role for OpenSearch
resource "aws_iam_service_linked_role" "opensearch" {
  count            = var.create_service_linked_role ? 1 : 0
  aws_service_name = "opensearchservice.amazonaws.com"
  description      = "Service-linked role for OpenSearch"
}

# CloudWatch log groups for OpenSearch logs
resource "aws_cloudwatch_log_group" "opensearch_index_slow_logs" {
  count             = var.enable_slow_logs ? 1 : 0
  name              = "/aws/opensearch/domains/${var.project_name}-${var.environment}/index-slow"
  retention_in_days = var.log_retention_days

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-opensearch-index-slow-logs"
    Type = "opensearch-log-group"
  })
}

resource "aws_cloudwatch_log_group" "opensearch_search_slow_logs" {
  count             = var.enable_slow_logs ? 1 : 0
  name              = "/aws/opensearch/domains/${var.project_name}-${var.environment}/search-slow"
  retention_in_days = var.log_retention_days

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-opensearch-search-slow-logs"
    Type = "opensearch-log-group"
  })
}

resource "aws_cloudwatch_log_group" "opensearch_application_logs" {
  count             = var.enable_application_logs ? 1 : 0
  name              = "/aws/opensearch/domains/${var.project_name}-${var.environment}/application"
  retention_in_days = var.log_retention_days

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-opensearch-application-logs"
    Type = "opensearch-log-group"
  })
}

# IAM policy for OpenSearch access
resource "aws_iam_policy" "opensearch_access" {
  count       = var.create_access_policy ? 1 : 0
  name        = "${var.project_name}-${var.environment}-opensearch-access"
  description = "IAM policy for OpenSearch access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "es:ESHttpDelete",
          "es:ESHttpGet",
          "es:ESHttpHead",
          "es:ESHttpPost",
          "es:ESHttpPut",
          "es:ESHttpPatch"
        ]
        Resource = "${aws_opensearch_domain.main.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "es:ESCrossClusterGet",
          "es:DescribeElasticsearchDomain",
          "es:DescribeElasticsearchDomains",
          "es:DescribeElasticsearchDomainConfig",
          "es:ListElasticsearchInstanceTypes",
          "es:ListElasticsearchVersions"
        ]
        Resource = aws_opensearch_domain.main.arn
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-opensearch-access-policy"
    Type = "opensearch-iam-policy"
  })
}

# CloudWatch alarms for monitoring
resource "aws_cloudwatch_metric_alarm" "cluster_status_red" {
  count               = var.enable_monitoring ? 1 : 0
  alarm_name          = "${var.project_name}-${var.environment}-opensearch-cluster-status-red"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "ClusterStatus.red"
  namespace           = "AWS/ES"
  period              = "60"
  statistic           = "Maximum"
  threshold           = "1"
  alarm_description   = "OpenSearch cluster status is red"
  alarm_actions       = var.alarm_actions

  dimensions = {
    DomainName = aws_opensearch_domain.main.domain_name
    ClientId   = data.aws_caller_identity.current.account_id
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-opensearch-cluster-red-alarm"
    Type = "opensearch-cloudwatch-alarm"
  })
}

resource "aws_cloudwatch_metric_alarm" "cluster_status_yellow" {
  count               = var.enable_monitoring ? 1 : 0
  alarm_name          = "${var.project_name}-${var.environment}-opensearch-cluster-status-yellow"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "5"
  metric_name         = "ClusterStatus.yellow"
  namespace           = "AWS/ES"
  period              = "60"
  statistic           = "Maximum"
  threshold           = "1"
  alarm_description   = "OpenSearch cluster status is yellow for 5 minutes"
  alarm_actions       = var.alarm_actions

  dimensions = {
    DomainName = aws_opensearch_domain.main.domain_name
    ClientId   = data.aws_caller_identity.current.account_id
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-opensearch-cluster-yellow-alarm"
    Type = "opensearch-cloudwatch-alarm"
  })
}

resource "aws_cloudwatch_metric_alarm" "cpu_utilization" {
  count               = var.enable_monitoring ? 1 : 0
  alarm_name          = "${var.project_name}-${var.environment}-opensearch-cpu-utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "3"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ES"
  period              = "300"
  statistic           = "Average"
  threshold           = var.cpu_alarm_threshold
  alarm_description   = "OpenSearch CPU utilization is high"
  alarm_actions       = var.alarm_actions

  dimensions = {
    DomainName = aws_opensearch_domain.main.domain_name
    ClientId   = data.aws_caller_identity.current.account_id
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-opensearch-cpu-alarm"
    Type = "opensearch-cloudwatch-alarm"
  })
}

resource "aws_cloudwatch_metric_alarm" "storage_utilization" {
  count               = var.enable_monitoring ? 1 : 0
  alarm_name          = "${var.project_name}-${var.environment}-opensearch-storage-utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "StorageUtilization"
  namespace           = "AWS/ES"
  period              = "300"
  statistic           = "Average"
  threshold           = var.storage_alarm_threshold
  alarm_description   = "OpenSearch storage utilization is high"
  alarm_actions       = var.alarm_actions

  dimensions = {
    DomainName = aws_opensearch_domain.main.domain_name
    ClientId   = data.aws_caller_identity.current.account_id
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-opensearch-storage-alarm"
    Type = "opensearch-cloudwatch-alarm"
  })
}