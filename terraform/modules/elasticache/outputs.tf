# Outputs for ElastiCache Redis Module

output "redis_cluster_id" {
  description = "ID of the Redis cluster"
  value       = aws_elasticache_cluster.redis.cluster_id
}

output "redis_endpoint" {
  description = "Redis endpoint for client connections"
  value       = aws_elasticache_cluster.redis.cache_nodes[0].address
}

output "redis_port" {
  description = "Redis port number"
  value       = aws_elasticache_cluster.redis.port
}

output "redis_configuration_endpoint" {
  description = "Configuration endpoint for Redis cluster"
  value       = aws_elasticache_cluster.redis.configuration_endpoint
}

output "redis_cache_nodes" {
  description = "List of cache node information"
  value = [
    for node in aws_elasticache_cluster.redis.cache_nodes : {
      id               = node.id
      address          = node.address
      port             = node.port
      availability_zone = node.availability_zone
    }
  ]
}

output "redis_security_group_id" {
  description = "Security group ID for Redis cluster"
  value       = aws_security_group.redis.id
}

output "redis_subnet_group_name" {
  description = "Name of the Redis subnet group"
  value       = aws_elasticache_subnet_group.redis.name
}

output "redis_parameter_group_name" {
  description = "Name of the Redis parameter group"
  value       = aws_elasticache_parameter_group.redis.name
}

output "redis_arn" {
  description = "ARN of the Redis cluster"
  value       = aws_elasticache_cluster.redis.arn
}

output "redis_engine_version_actual" {
  description = "Running version of the Redis engine"
  value       = aws_elasticache_cluster.redis.engine_version_actual
}

output "redis_connection_info" {
  description = "Redis connection information"
  value = {
    endpoint = aws_elasticache_cluster.redis.cache_nodes[0].address
    port     = aws_elasticache_cluster.redis.port
    url      = "redis://${aws_elasticache_cluster.redis.cache_nodes[0].address}:${aws_elasticache_cluster.redis.port}"
  }
  sensitive = false
}

output "redis_monitoring" {
  description = "Redis monitoring and management information"
  value = {
    cluster_id           = aws_elasticache_cluster.redis.cluster_id
    engine_version       = aws_elasticache_cluster.redis.engine_version_actual
    node_type           = aws_elasticache_cluster.redis.node_type
    num_cache_nodes     = aws_elasticache_cluster.redis.num_cache_nodes
    parameter_group     = aws_elasticache_parameter_group.redis.name
    subnet_group        = aws_elasticache_subnet_group.redis.name
    security_group      = aws_security_group.redis.id
    maintenance_window  = aws_elasticache_cluster.redis.maintenance_window
    snapshot_window     = aws_elasticache_cluster.redis.snapshot_window
    notification_topic  = aws_elasticache_cluster.redis.notification_topic_arn
  }
}