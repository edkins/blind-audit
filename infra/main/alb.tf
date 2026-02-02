# Application Load Balancer
resource "aws_lb" "main" {
  name               = "${var.project_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  tags = {
    Name = "${var.project_name}-alb"
  }
}

# ALB Security Group
resource "aws_security_group" "alb" {
  name        = "${var.project_name}-alb-sg"
  description = "Security group for ALB"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP from anywhere (redirects to HTTPS)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-alb-sg"
  }
}

# Target Groups - one per backend service
locals {
  services = {
    provider   = { port = 8080, path = "/provider*", health_path = "/provider/health" }
    challenger = { port = 8081, path = "/challenger*", health_path = "/challenger/health" }
    results    = { port = 8082, path = "/results*", health_path = "/results/health" }
  }
}

resource "aws_lb_target_group" "services" {
  for_each = local.services

  name     = "${var.project_name}-${each.key}"
  port     = each.value.port
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = each.value.health_path
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 3
  }

  tags = {
    Name = "${var.project_name}-${each.key}"
  }
}

# Register EC2 instance with each target group
resource "aws_lb_target_group_attachment" "services" {
  for_each = local.services

  target_group_arn = aws_lb_target_group.services[each.key].arn
  target_id        = aws_instance.enclave.id
  port             = each.value.port
}

# HTTP Listener (redirect to HTTPS)
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# HTTPS Listener - default action redirects / to /provider
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.main.certificate_arn

  default_action {
    type = "redirect"

    redirect {
      path        = "/provider"
      status_code = "HTTP_302"
    }
  }
}

# Health check rules (no auth required) - highest priority
resource "aws_lb_listener_rule" "health" {
  for_each = local.services

  listener_arn = aws_lb_listener.https.arn
  priority     = 10 + index(keys(local.services), each.key)

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.services[each.key].arn
  }

  condition {
    path_pattern {
      values = [each.value.health_path]
    }
  }
}

# Service routing rules (with Cognito auth)
resource "aws_lb_listener_rule" "services" {
  for_each = local.services

  listener_arn = aws_lb_listener.https.arn
  priority     = 100 + index(keys(local.services), each.key)

  action {
    type = "authenticate-cognito"

    authenticate_cognito {
      user_pool_arn       = aws_cognito_user_pool.main.arn
      user_pool_client_id = aws_cognito_user_pool_client.alb.id
      user_pool_domain    = aws_cognito_user_pool_domain.main.domain

      on_unauthenticated_request = "authenticate"
      scope                      = "openid email profile"
      session_cookie_name        = "AWSELBAuthSessionCookie"
      session_timeout            = 3600
    }

    order = 1
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.services[each.key].arn

    order = 2
  }

  condition {
    path_pattern {
      values = [each.value.path]
    }
  }
}
