# Instance outputs
output "instance_id" {
  description = "EC2 instance ID - add this to GitHub variables as INSTANCE_ID"
  value       = aws_instance.enclave.id
}

output "instance_private_ip" {
  description = "Private IP of the EC2 instance"
  value       = aws_instance.enclave.private_ip
}

# ALB outputs
output "alb_dns_name" {
  description = "DNS name of the ALB"
  value       = aws_lb.main.dns_name
}

output "app_url" {
  description = "URL to access the application"
  value       = "https://${local.app_fqdn}"
}

# DNS outputs
output "app_domain" {
  description = "Domain name for the application"
  value       = local.app_fqdn
}

output "certificate_arn" {
  description = "ARN of the ACM certificate"
  value       = aws_acm_certificate.main.arn
}

output "nameservers" {
  description = "Nameservers for the hosted zone (only if create_hosted_zone=true)"
  value       = var.create_hosted_zone ? aws_route53_zone.main[0].name_servers : null
}

# Cognito outputs
output "cognito_user_pool_id" {
  description = "Cognito User Pool ID"
  value       = aws_cognito_user_pool.main.id
}

output "cognito_domain" {
  description = "Cognito hosted UI domain"
  value       = "https://${aws_cognito_user_pool_domain.main.domain}.auth.${var.aws_region}.amazoncognito.com"
}

# ECR outputs
output "ecr_enclave_repo" {
  description = "ECR repository URL for enclave image"
  value       = aws_ecr_repository.enclave.repository_url
}

output "ecr_webserver_repo" {
  description = "ECR repository URL for webserver image"
  value       = aws_ecr_repository.webserver.repository_url
}

# SSM connect command
output "ssm_connect_command" {
  description = "Command to connect to the instance via SSM"
  value       = "aws ssm start-session --target ${aws_instance.enclave.id} --region ${var.aws_region}"
}

# GitHub Actions configuration summary
output "github_config" {
  description = "Values to configure in GitHub repository"
  value = {
    secrets = {
      AWS_ROLE_ARN = "(from bootstrap output)"
    }
    variables = {
      AWS_REGION   = var.aws_region
      INSTANCE_ID  = aws_instance.enclave.id
      ENCLAVE_REPO = aws_ecr_repository.enclave.name
      WEBSERVER_REPO = aws_ecr_repository.webserver.name
    }
  }
}
