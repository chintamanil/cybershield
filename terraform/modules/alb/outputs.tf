# Outputs for ALB Module

output "alb_id" {
  description = "ID of the Application Load Balancer"
  value       = aws_lb.main.id
}

output "alb_arn" {
  description = "ARN of the Application Load Balancer"
  value       = aws_lb.main.arn
}

output "alb_arn_suffix" {
  description = "ARN suffix of the Application Load Balancer"
  value       = aws_lb.main.arn_suffix
}

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = aws_lb.main.dns_name
}

output "alb_zone_id" {
  description = "Zone ID of the Application Load Balancer"
  value       = aws_lb.main.zone_id
}

output "alb_security_group_id" {
  description = "ID of the ALB security group"
  value       = aws_security_group.alb.id
}

output "backend_target_group_arn" {
  description = "ARN of the backend target group"
  value       = aws_lb_target_group.backend.arn
}

output "backend_target_group_name" {
  description = "Name of the backend target group"
  value       = aws_lb_target_group.backend.name
}

output "backend_target_group_arn_suffix" {
  description = "ARN suffix of the backend target group"
  value       = aws_lb_target_group.backend.arn_suffix
}

output "frontend_target_group_arn" {
  description = "ARN of the frontend target group"
  value       = var.enable_frontend_target_group ? aws_lb_target_group.frontend[0].arn : null
}

output "frontend_target_group_name" {
  description = "Name of the frontend target group"
  value       = var.enable_frontend_target_group ? aws_lb_target_group.frontend[0].name : null
}

output "frontend_target_group_arn_suffix" {
  description = "ARN suffix of the frontend target group"
  value       = var.enable_frontend_target_group ? aws_lb_target_group.frontend[0].arn_suffix : null
}

output "certificate_arn" {
  description = "ARN of the SSL certificate"
  value       = var.domain_name != null ? aws_acm_certificate.main[0].arn : null
}

output "certificate_domain_name" {
  description = "Domain name of the SSL certificate"
  value       = var.domain_name != null ? aws_acm_certificate.main[0].domain_name : null
}

output "certificate_status" {
  description = "Status of the SSL certificate"
  value       = var.domain_name != null ? aws_acm_certificate.main[0].status : null
}

output "route53_record_name" {
  description = "Name of the Route53 A record"
  value       = var.domain_name != null ? aws_route53_record.main[0].name : null
}

output "route53_record_fqdn" {
  description = "FQDN of the Route53 A record"
  value       = var.domain_name != null ? aws_route53_record.main[0].fqdn : null
}

output "http_listener_arn" {
  description = "ARN of the HTTP listener"
  value       = aws_lb_listener.http.arn
}

output "https_listener_arn" {
  description = "ARN of the HTTPS listener"
  value       = var.domain_name != null ? aws_lb_listener.https[0].arn : null
}

output "http_direct_listener_arn" {
  description = "ARN of the HTTP direct listener (for non-SSL environments)"
  value       = var.domain_name == null ? aws_lb_listener.http_direct[0].arn : null
}

output "application_url" {
  description = "Application URL (HTTPS if domain provided, otherwise HTTP with ALB DNS)"
  value = var.domain_name != null ? "https://${var.domain_name}" : "http://${aws_lb.main.dns_name}"
}

output "backend_api_url" {
  description = "Backend API base URL"
  value = var.domain_name != null ? "https://${var.domain_name}" : "http://${aws_lb.main.dns_name}"
}

output "health_check_urls" {
  description = "Health check URLs for monitoring"
  value = {
    backend  = "${var.domain_name != null ? "https" : "http"}://${var.domain_name != null ? var.domain_name : aws_lb.main.dns_name}${var.backend_health_check_path}"
    frontend = var.enable_frontend_target_group ? "${var.domain_name != null ? "https" : "http"}://${var.domain_name != null ? var.domain_name : aws_lb.main.dns_name}${var.frontend_health_check_path}" : null
  }
}

output "cloudwatch_alarms" {
  description = "CloudWatch alarm ARNs"
  value = var.enable_monitoring ? {
    target_response_time = aws_cloudwatch_metric_alarm.target_response_time[0].arn
    unhealthy_hosts     = aws_cloudwatch_metric_alarm.unhealthy_hosts[0].arn
    http_5xx_errors     = aws_cloudwatch_metric_alarm.http_5xx_errors[0].arn
  } : null
}

output "target_groups" {
  description = "Target group information"
  value = {
    backend = {
      arn              = aws_lb_target_group.backend.arn
      name             = aws_lb_target_group.backend.name
      port             = aws_lb_target_group.backend.port
      protocol         = aws_lb_target_group.backend.protocol
      health_check_path = var.backend_health_check_path
    }
    frontend = var.enable_frontend_target_group ? {
      arn              = aws_lb_target_group.frontend[0].arn
      name             = aws_lb_target_group.frontend[0].name
      port             = aws_lb_target_group.frontend[0].port
      protocol         = aws_lb_target_group.frontend[0].protocol
      health_check_path = var.frontend_health_check_path
    } : null
  }
}

output "listeners" {
  description = "Listener information"
  value = {
    http = {
      arn      = aws_lb_listener.http.arn
      port     = aws_lb_listener.http.port
      protocol = aws_lb_listener.http.protocol
    }
    https = var.domain_name != null ? {
      arn         = aws_lb_listener.https[0].arn
      port        = aws_lb_listener.https[0].port
      protocol    = aws_lb_listener.https[0].protocol
      ssl_policy  = aws_lb_listener.https[0].ssl_policy
      certificate = aws_lb_listener.https[0].certificate_arn
    } : null
    http_direct = var.domain_name == null ? {
      arn      = aws_lb_listener.http_direct[0].arn
      port     = aws_lb_listener.http_direct[0].port
      protocol = aws_lb_listener.http_direct[0].protocol
    } : null
  }
}

output "ssl_configuration" {
  description = "SSL configuration details"
  value = var.domain_name != null ? {
    certificate_arn    = aws_acm_certificate.main[0].arn
    domain_name       = aws_acm_certificate.main[0].domain_name
    validation_method = var.certificate_validation_method
    ssl_policy        = var.ssl_policy
    status           = aws_acm_certificate.main[0].status
  } : null
}

output "dns_configuration" {
  description = "DNS configuration details"
  value = var.domain_name != null ? {
    domain_name = var.domain_name
    record_name = aws_route53_record.main[0].name
    record_type = aws_route53_record.main[0].type
    alias_target = {
      dns_name    = aws_lb.main.dns_name
      zone_id     = aws_lb.main.zone_id
    }
  } : null
}

output "load_balancer_summary" {
  description = "Complete load balancer summary"
  value = {
    name             = aws_lb.main.name
    dns_name         = aws_lb.main.dns_name
    zone_id          = aws_lb.main.zone_id
    application_url   = var.domain_name != null ? "https://${var.domain_name}" : "http://${aws_lb.main.dns_name}"
    scheme           = aws_lb.main.scheme
    type             = aws_lb.main.load_balancer_type
    vpc_id           = aws_lb.main.vpc_id
    subnets          = aws_lb.main.subnets
    security_groups  = aws_lb.main.security_groups
    ssl_enabled      = var.domain_name != null
    monitoring_enabled = var.enable_monitoring
    deletion_protection = var.enable_deletion_protection
  }
}