# ElastiCache Redis Module for CyberShield
# Creates Redis cluster, subnet group, and parameter group

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Random password for Redis AUTH token
resource "random_password" "auth_token" {
  count = var.enable_auth_token ? 1 : 0
  
  length  = 32
  special = false  # Redis AUTH token cannot contain special characters
}

# Store Redis credentials in Secrets Manager
resource "aws_secretsmanager_secret" "redis_credentials" {
  name_prefix             = "${var.project_name}-${var.environment}-redis-credentials"
  description             = "Redis credentials for ${var.project_name} ${var.environment}"
  recovery_window_in_days = 7
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-redis-secret"
    Type = "secret"
  })
}

resource "aws_secretsmanager_secret_version" "redis_credentials" {
  secret_id = aws_secretsmanager_secret.redis_credentials.id
  secret_string = jsonencode({
    endpoint    = aws_elasticache_replication_group.main.primary_endpoint_address
    port        = aws_elasticache_replication_group.main.port
    auth_token  = var.enable_auth_token ? random_password.auth_token[0].result : ""
    engine      = "redis"
    cluster_id  = aws_elasticache_replication_group.main.id
  })
}

# Cache Subnet Group
resource "aws_elasticache_subnet_group" "main" {
  name       = "${var.project_name}-${var.environment}-redis-subnet-group"
  subnet_ids = var.cache_subnet_ids
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-redis-subnet-group"
    Type = "cache-subnet-group"
  })
}

# Cache Parameter Group
resource "aws_elasticache_parameter_group" "main" {
  family = var.redis_parameter_group_family
  name   = "${var.project_name}-${var.environment}-${var.redis_parameter_group_family}"
  
  # Performance optimization parameters
  parameter {
    name  = "maxmemory-policy"
    value = "allkeys-lru"
  }
  
  parameter {
    name  = "timeout"
    value = "300"
  }
  
  parameter {
    name  = "tcp-keepalive"
    value = "300"
  }
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-${var.redis_parameter_group_family}"
    Type = "cache-parameter-group"
  })
}

# CloudWatch Log Groups for Redis
resource "aws_cloudwatch_log_group" "redis_slow" {
  name              = "/aws/elasticache/redis/${var.project_name}-${var.environment}/slow-log"
  retention_in_days = var.log_retention_days
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-redis-slow-logs"
    Type = "log-group"
  })
}

# Redis Replication Group
resource "aws_elasticache_replication_group" "main" {
  replication_group_id         = "${var.project_name}-${var.environment}-redis"
  description                  = "Redis cluster for ${var.project_name} ${var.environment}"
  
  # Engine Configuration
  engine               = "redis"
  engine_version       = var.redis_engine_version
  node_type            = var.redis_node_type
  parameter_group_name = aws_elasticache_parameter_group.main.name
  port                 = 6379
  
  # Cluster Configuration
  num_cache_clusters = var.num_cache_clusters
  
  # Network Configuration
  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [var.redis_security_group_id]
  
  # Security Configuration
  auth_token                    = var.enable_auth_token ? random_password.auth_token[0].result : null
  transit_encryption_enabled    = var.enable_transit_encryption
  at_rest_encryption_enabled    = var.enable_at_rest_encryption
  
  # Backup Configuration
  snapshot_retention_limit = var.snapshot_retention_limit
  snapshot_window         = var.snapshot_window
  
  # Maintenance Configuration
  maintenance_window          = var.maintenance_window
  auto_minor_version_upgrade  = var.auto_minor_version_upgrade
  
  # Logging Configuration
  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.redis_slow.name
    destination_type = "cloudwatch-logs"
    log_format       = "text"
    log_type         = "slow-log"
  }
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-redis"
    Type = "elasticache-replication-group"
  })
  
  lifecycle {
    prevent_destroy = false  # Set to true for production
    ignore_changes = [
      auth_token  # Ignore auth token changes to prevent drift
    ]
  }
}

# Security Group for Redis (defined in networking module but can be extended here)
resource "aws_security_group" "redis" {
  name_prefix = "${var.project_name}-${var.environment}-redis-extended-"
  vpc_id      = var.vpc_id
  
  description = "Extended security group for Redis cluster"
  
  # Allow Redis traffic from ECS security group (passed as variable)
  ingress {
    description     = "Redis from application"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [var.redis_security_group_id]
  }
  
  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-redis-extended-sg"
    Type = "security-group"
  })
  
  lifecycle {
    create_before_destroy = true
  }
}

# CloudWatch Alarms for Redis
resource "aws_cloudwatch_metric_alarm" "redis_cpu" {
  count = var.enable_monitoring ? 1 : 0
  
  alarm_name          = "${var.project_name}-${var.environment}-redis-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ElastiCache"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors Redis CPU utilization"
  alarm_actions       = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  
  dimensions = {
    CacheClusterId = "${aws_elasticache_replication_group.main.id}-001"
  }
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-redis-cpu-alarm"
    Type = "cloudwatch-alarm"
  })
}

resource "aws_cloudwatch_metric_alarm" "redis_memory" {
  count = var.enable_monitoring ? 1 : 0
  
  alarm_name          = "${var.project_name}-${var.environment}-redis-high-memory"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "DatabaseMemoryUsagePercentage"
  namespace           = "AWS/ElastiCache"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors Redis memory usage"
  alarm_actions       = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  
  dimensions = {
    CacheClusterId = "${aws_elasticache_replication_group.main.id}-001"
  }
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-redis-memory-alarm"
    Type = "cloudwatch-alarm"
  })
}

resource "aws_cloudwatch_metric_alarm" "redis_connections" {
  count = var.enable_monitoring ? 1 : 0
  
  alarm_name          = "${var.project_name}-${var.environment}-redis-high-connections"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CurrConnections"
  namespace           = "AWS/ElastiCache"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors Redis connection count"
  alarm_actions       = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  
  dimensions = {
    CacheClusterId = "${aws_elasticache_replication_group.main.id}-001"
  }
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-redis-connections-alarm"
    Type = "cloudwatch-alarm"
  })
}