# Application Load Balancer Module for CyberShield
# Provides load balancing and SSL termination for the application

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.100"
    }
  }
}

# Data sources
data "aws_route53_zone" "main" {
  count        = var.domain_name != null ? 1 : 0
  name         = var.domain_name
  private_zone = false
}

# Security Group for Application Load Balancer
resource "aws_security_group" "alb" {
  name_prefix = "${var.project_name}-${var.environment}-alb-"
  vpc_id      = var.vpc_id
  description = "Security group for Application Load Balancer"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP access from internet"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS access from internet"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-alb-sg"
    Type = "alb-security-group"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Application Load Balancer
resource "aws_lb" "main" {
  name               = "${var.project_name}-${var.environment}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets           = var.public_subnet_ids

  enable_deletion_protection     = var.enable_deletion_protection
  enable_cross_zone_load_balancing = true
  enable_http2                   = true

  dynamic "access_logs" {
    for_each = var.enable_access_logs ? [1] : []
    content {
      bucket  = var.access_logs_bucket
      prefix  = var.access_logs_prefix
      enabled = true
    }
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-alb"
    Type = "application-load-balancer"
  })
}

# SSL Certificate (if domain is provided)
resource "aws_acm_certificate" "main" {
  count           = var.domain_name != null ? 1 : 0
  domain_name     = var.domain_name
  validation_method = var.certificate_validation_method

  dynamic "subject_alternative_names" {
    for_each = var.subject_alternative_names
    content {
      domain_name = subject_alternative_names.value
    }
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-certificate"
    Type = "ssl-certificate"
  })
}

# Certificate validation (DNS method)
resource "aws_route53_record" "cert_validation" {
  for_each = var.domain_name != null && var.certificate_validation_method == "DNS" ? {
    for dvo in aws_acm_certificate.main[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.main[0].zone_id
}

# Certificate validation completion
resource "aws_acm_certificate_validation" "main" {
  count           = var.domain_name != null && var.certificate_validation_method == "DNS" ? 1 : 0
  certificate_arn = aws_acm_certificate.main[0].arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]

  timeouts {
    create = "5m"
  }
}

# Target Group for Backend Service
resource "aws_lb_target_group" "backend" {
  name     = "${var.project_name}-${var.environment}-backend-tg"
  port     = var.backend_port
  protocol = "HTTP"
  vpc_id   = var.vpc_id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = var.health_check_healthy_threshold
    unhealthy_threshold = var.health_check_unhealthy_threshold
    timeout             = var.health_check_timeout
    interval            = var.health_check_interval
    path                = var.backend_health_check_path
    matcher             = var.health_check_matcher
    protocol            = "HTTP"
    port                = "traffic-port"
  }

  stickiness {
    type            = "lb_cookie"
    enabled         = var.enable_stickiness
    cookie_duration = var.stickiness_duration
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-backend-target-group"
    Type = "alb-target-group"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Target Group for Frontend Service (if enabled)
resource "aws_lb_target_group" "frontend" {
  count   = var.enable_frontend_target_group ? 1 : 0
  name    = "${var.project_name}-${var.environment}-frontend-tg"
  port    = var.frontend_port
  protocol = "HTTP"
  vpc_id  = var.vpc_id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = var.health_check_healthy_threshold
    unhealthy_threshold = var.health_check_unhealthy_threshold
    timeout             = var.health_check_timeout
    interval            = var.health_check_interval
    path                = var.frontend_health_check_path
    matcher             = var.health_check_matcher
    protocol            = "HTTP"
    port                = "traffic-port"
  }

  stickiness {
    type            = "lb_cookie"
    enabled         = var.enable_stickiness
    cookie_duration = var.stickiness_duration
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-frontend-target-group"
    Type = "alb-target-group"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# HTTP Listener (redirect to HTTPS)
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-http-listener"
    Type = "alb-listener"
  })
}

# HTTPS Listener
resource "aws_lb_listener" "https" {
  count             = var.domain_name != null ? 1 : 0
  load_balancer_arn = aws_lb.main.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = var.ssl_policy
  certificate_arn   = var.certificate_validation_method == "DNS" ? aws_acm_certificate_validation.main[0].certificate_arn : aws_acm_certificate.main[0].arn

  default_action {
    type             = "forward"
    target_group_arn = var.enable_frontend_target_group ? aws_lb_target_group.frontend[0].arn : aws_lb_target_group.backend.arn
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-https-listener"
    Type = "alb-listener"
  })
}

# HTTPS Listener Rules for Backend API
resource "aws_lb_listener_rule" "backend_api" {
  count        = var.domain_name != null ? length(var.backend_path_patterns) : 0
  listener_arn = aws_lb_listener.https[0].arn
  priority     = 100 + count.index

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.backend.arn
  }

  condition {
    path_pattern {
      values = [var.backend_path_patterns[count.index]]
    }
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-backend-rule-${count.index}"
    Type = "alb-listener-rule"
  })
}

# HTTP Listener for non-SSL environments
resource "aws_lb_listener" "http_direct" {
  count             = var.domain_name == null ? 1 : 0
  load_balancer_arn = aws_lb.main.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.backend.arn
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-http-direct-listener"
    Type = "alb-listener"
  })
}

# Route53 A Record (if domain is provided)
resource "aws_route53_record" "main" {
  count   = var.domain_name != null ? 1 : 0
  zone_id = data.aws_route53_zone.main[0].zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}

# Route53 AAAA Record for IPv6 (if enabled)
resource "aws_route53_record" "ipv6" {
  count   = var.domain_name != null && var.enable_ipv6 ? 1 : 0
  zone_id = data.aws_route53_zone.main[0].zone_id
  name    = var.domain_name
  type    = "AAAA"

  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}

# CloudWatch Alarms for monitoring
resource "aws_cloudwatch_metric_alarm" "target_response_time" {
  count               = var.enable_monitoring ? 1 : 0
  alarm_name          = "${var.project_name}-${var.environment}-alb-target-response-time"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = "300"
  statistic           = "Average"
  threshold           = var.response_time_alarm_threshold
  alarm_description   = "Average target response time is too high"
  alarm_actions       = var.alarm_actions

  dimensions = {
    LoadBalancer = aws_lb.main.arn_suffix
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-alb-response-time-alarm"
    Type = "cloudwatch-alarm"
  })
}

resource "aws_cloudwatch_metric_alarm" "unhealthy_hosts" {
  count               = var.enable_monitoring ? 1 : 0
  alarm_name          = "${var.project_name}-${var.environment}-alb-unhealthy-hosts"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = "300"
  statistic           = "Maximum"
  threshold           = var.unhealthy_host_alarm_threshold
  alarm_description   = "Number of unhealthy hosts is too high"
  alarm_actions       = var.alarm_actions

  dimensions = {
    TargetGroup  = aws_lb_target_group.backend.arn_suffix
    LoadBalancer = aws_lb.main.arn_suffix
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-alb-unhealthy-hosts-alarm"
    Type = "cloudwatch-alarm"
  })
}

resource "aws_cloudwatch_metric_alarm" "http_5xx_errors" {
  count               = var.enable_monitoring ? 1 : 0
  alarm_name          = "${var.project_name}-${var.environment}-alb-5xx-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "HTTPCode_ELB_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = "300"
  statistic           = "Sum"
  threshold           = var.http_5xx_alarm_threshold
  alarm_description   = "High number of 5xx errors from load balancer"
  alarm_actions       = var.alarm_actions
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = aws_lb.main.arn_suffix
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-alb-5xx-errors-alarm"
    Type = "cloudwatch-alarm"
  })
}