# Route 53 Hosted Zone
# If you registered the domain through Route 53, the hosted zone already exists.
# If so, use a data source instead of creating a new one.

# Option A: Look up existing hosted zone (for domains registered in Route 53)
data "aws_route53_zone" "main" {
  count = var.create_hosted_zone ? 0 : 1
  name  = var.domain_name
}

# Option B: Create a new hosted zone (for domains registered elsewhere)
resource "aws_route53_zone" "main" {
  count = var.create_hosted_zone ? 1 : 0
  name  = var.domain_name

  tags = {
    Name = "${var.project_name}-zone"
  }
}

locals {
  zone_id = var.create_hosted_zone ? aws_route53_zone.main[0].zone_id : data.aws_route53_zone.main[0].zone_id
  
  # Use subdomain if specified, otherwise use apex domain
  app_fqdn = var.app_subdomain != "" ? "${var.app_subdomain}.${var.domain_name}" : var.domain_name
}

# ACM Certificate
resource "aws_acm_certificate" "main" {
  domain_name       = local.app_fqdn
  validation_method = "DNS"

  # Also cover www if using apex domain
  subject_alternative_names = var.app_subdomain == "" ? ["www.${var.domain_name}"] : []

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${var.project_name}-cert"
  }
}

# DNS records for certificate validation
resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.main.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = local.zone_id
}

# Wait for certificate validation to complete
resource "aws_acm_certificate_validation" "main" {
  certificate_arn         = aws_acm_certificate.main.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]

  timeouts {
    create = "10m"
  }
}

# A record pointing to ALB
resource "aws_route53_record" "app" {
  zone_id = local.zone_id
  name    = local.app_fqdn
  type    = "A"

  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}

# www redirect (if using apex domain)
resource "aws_route53_record" "www" {
  count = var.app_subdomain == "" ? 1 : 0

  zone_id = local.zone_id
  name    = "www.${var.domain_name}"
  type    = "A"

  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}
