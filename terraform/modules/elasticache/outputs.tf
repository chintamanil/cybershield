# Outputs for ElastiCache Redis Module

output "cluster_id" {
  description = "ID of the Redis replication group"
  value       = aws_elasticache_replication_group.main.id
}

output "primary_endpoint_address" {
  description = "Primary endpoint address for Redis replication group"
  value       = aws_elasticache_replication_group.main.primary_endpoint_address
}

output "port" {
  description = "Redis port number"
  value       = aws_elasticache_replication_group.main.port
}

output "configuration_endpoint_address" {
  description = "Configuration endpoint for Redis cluster"
  value       = aws_elasticache_replication_group.main.configuration_endpoint_address
}

output "reader_endpoint_address" {
  description = "Reader endpoint address for Redis replication group"
  value       = aws_elasticache_replication_group.main.reader_endpoint_address
}

output "redis_security_group_id" {
  description = "Security group ID for Redis cluster"
  value       = aws_security_group.redis.id
}

output "redis_subnet_group_name" {
  description = "Name of the Redis subnet group"
  value       = aws_elasticache_subnet_group.main.name
}

output "redis_parameter_group_name" {
  description = "Name of the Redis parameter group"
  value       = aws_elasticache_parameter_group.main.name
}

output "redis_arn" {
  description = "ARN of the Redis replication group"
  value       = aws_elasticache_replication_group.main.arn
}

output "redis_engine_version_actual" {
  description = "Running version of the Redis engine"
  value       = aws_elasticache_replication_group.main.engine_version_actual
}

output "redis_connection_info" {
  description = "Redis connection information"
  value = {
    endpoint = aws_elasticache_replication_group.main.primary_endpoint_address
    port     = aws_elasticache_replication_group.main.port
    url      = "redis://${aws_elasticache_replication_group.main.primary_endpoint_address}:${aws_elasticache_replication_group.main.port}"
  }
  sensitive = false
}

output "redis_monitoring" {
  description = "Redis monitoring and management information"
  value = {
    cluster_id           = aws_elasticache_replication_group.main.id
    engine_version       = aws_elasticache_replication_group.main.engine_version_actual
    node_type           = aws_elasticache_replication_group.main.node_type
    num_cache_nodes     = aws_elasticache_replication_group.main.num_cache_clusters
    parameter_group     = aws_elasticache_parameter_group.main.name
    subnet_group        = aws_elasticache_subnet_group.main.name
    security_group      = aws_security_group.redis.id
    maintenance_window  = aws_elasticache_replication_group.main.maintenance_window
    snapshot_window     = aws_elasticache_replication_group.main.snapshot_window
    auth_token_enabled  = var.enable_auth_token
  }
}

output "secret_arn" {
  description = "ARN of the Redis credentials secret"
  value       = aws_secretsmanager_secret.redis_credentials.arn
}

output "secret_name" {
  description = "Name of the Redis credentials secret"
  value       = aws_secretsmanager_secret.redis_credentials.name
}