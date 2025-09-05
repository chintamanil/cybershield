# Route53 Module Outputs
output "hosted_zone_id" {
  description = "Route53 hosted zone ID"
  value       = aws_route53_zone.main.zone_id
}

output "hosted_zone_name_servers" {
  description = "Route53 hosted zone name servers"
  value       = aws_route53_zone.main.name_servers
}

output "certificate_arn" {
  description = "ACM certificate ARN"
  value       = aws_acm_certificate.main.arn
}

output "certificate_domain_validation_options" {
  description = "Certificate domain validation options"
  value       = aws_acm_certificate.main.domain_validation_options
}

output "health_check_id" {
  description = "Route53 health check ID"
  value       = var.create_health_check ? aws_route53_health_check.main[0].id : null
}