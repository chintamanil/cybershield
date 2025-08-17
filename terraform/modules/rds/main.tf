# RDS Module for CyberShield PostgreSQL Database
# Creates RDS instance, subnet group, and parameter group

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Random password for database
resource "random_password" "db_password" {
  length  = 32
  special = true
}

# Store database password in Secrets Manager
resource "aws_secretsmanager_secret" "db_credentials" {
  name_prefix             = "${var.project_name}-${var.environment}-db-credentials"
  description             = "Database credentials for ${var.project_name} ${var.environment}"
  recovery_window_in_days = var.enable_backup ? 7 : 0
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-db-secret"
    Type = "secret"
  })
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    username = var.db_username
    password = random_password.db_password.result
    engine   = "postgres"
    host     = aws_db_instance.main.endpoint
    port     = aws_db_instance.main.port
    dbname   = var.db_name
  })
}

# DB Subnet Group
resource "aws_db_subnet_group" "main" {
  name       = "${var.project_name}-${var.environment}-db-subnet-group"
  subnet_ids = var.database_subnet_ids
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-db-subnet-group"
    Type = "db-subnet-group"
  })
}

# DB Parameter Group
resource "aws_db_parameter_group" "main" {
  family = "postgres15"
  name   = "${var.project_name}-${var.environment}-postgres15"
  
  # Performance optimization parameters
  parameter {
    name  = "shared_preload_libraries"
    value = "pg_stat_statements"
  }
  
  parameter {
    name  = "log_statement"
    value = "all"
  }
  
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"  # Log queries taking longer than 1 second
  }
  
  parameter {
    name  = "max_connections"
    value = "100"
  }
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-postgres15"
    Type = "db-parameter-group"
  })
}

# Enhanced Monitoring Role
resource "aws_iam_role" "rds_monitoring" {
  count = var.enable_monitoring ? 1 : 0
  
  name_prefix = "${var.project_name}-${var.environment}-rds-monitoring-"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-rds-monitoring-role"
    Type = "iam-role"
  })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  count = var.enable_monitoring ? 1 : 0
  
  role       = aws_iam_role.rds_monitoring[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# CloudWatch Log Group for RDS
resource "aws_cloudwatch_log_group" "rds" {
  name              = "/aws/rds/instance/${var.project_name}-${var.environment}-postgres/postgresql"
  retention_in_days = var.log_retention_days
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-rds-logs"
    Type = "log-group"
  })
}

# RDS Instance
resource "aws_db_instance" "main" {
  identifier = "${var.project_name}-${var.environment}-postgres"
  
  # Database Configuration
  engine               = "postgres"
  engine_version       = var.db_engine_version
  instance_class       = var.db_instance_class
  allocated_storage    = var.db_allocated_storage
  max_allocated_storage = var.db_allocated_storage * 2
  storage_type         = "gp2"
  storage_encrypted    = true
  
  # Database Details
  db_name  = var.db_name
  username = var.db_username
  password = random_password.db_password.result
  port     = 5432
  
  # Network Configuration
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [var.rds_security_group_id]
  publicly_accessible    = false
  
  # Parameter Group
  parameter_group_name = aws_db_parameter_group.main.name
  
  # Backup Configuration
  backup_retention_period = var.backup_retention_period
  backup_window          = var.backup_window
  maintenance_window     = var.maintenance_window
  delete_automated_backups = !var.enable_backup
  
  # Monitoring Configuration
  monitoring_interval = var.enable_monitoring ? var.monitoring_interval : 0
  monitoring_role_arn = var.enable_monitoring ? aws_iam_role.rds_monitoring[0].arn : null
  
  # Performance Insights
  performance_insights_enabled          = var.enable_performance_insights
  performance_insights_retention_period = var.enable_performance_insights ? 7 : null
  
  # Logging
  enabled_cloudwatch_logs_exports = ["postgresql"]
  
  # Security
  deletion_protection = var.enable_deletion_protection
  skip_final_snapshot = !var.enable_backup
  final_snapshot_identifier = var.enable_backup ? "${var.project_name}-${var.environment}-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}" : null
  
  # Auto Minor Version Upgrade
  auto_minor_version_upgrade = var.auto_minor_version_upgrade
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-postgres"
    Type = "rds-instance"
  })
  
  lifecycle {
    prevent_destroy = false  # Set to true for production
    ignore_changes = [
      password,  # Ignore password changes to prevent drift
      final_snapshot_identifier
    ]
  }
}

# CloudWatch Alarms for RDS
resource "aws_cloudwatch_metric_alarm" "database_cpu" {
  count = var.enable_monitoring ? 1 : 0
  
  alarm_name          = "${var.project_name}-${var.environment}-rds-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors RDS CPU utilization"
  alarm_actions       = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  
  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.id
  }
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-rds-cpu-alarm"
    Type = "cloudwatch-alarm"
  })
}

resource "aws_cloudwatch_metric_alarm" "database_connections" {
  count = var.enable_monitoring ? 1 : 0
  
  alarm_name          = "${var.project_name}-${var.environment}-rds-high-connections"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors RDS connection count"
  alarm_actions       = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  
  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.id
  }
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-rds-connections-alarm"
    Type = "cloudwatch-alarm"
  })
}

resource "aws_cloudwatch_metric_alarm" "database_free_storage" {
  count = var.enable_monitoring ? 1 : 0
  
  alarm_name          = "${var.project_name}-${var.environment}-rds-low-storage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = "2000000000"  # 2GB in bytes
  alarm_description   = "This metric monitors RDS free storage space"
  alarm_actions       = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  
  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.id
  }
  
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-rds-storage-alarm"
    Type = "cloudwatch-alarm"
  })
}