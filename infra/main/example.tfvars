# Example Terraform variables
# Copy this to terraform.tfvars and fill in your values

# Required: Your domain name
domain_name = "example.com"

# Optional: Subdomain for the app (leave empty for apex domain)
# app_subdomain = "app"  # Would create app.example.com
app_subdomain = ""

# Set to true if your domain is NOT registered in Route 53
# (you'll need to update your domain's nameservers to the ones Terraform outputs)
create_hosted_zone = false

# AWS region
aws_region = "us-east-2"

# Project name (used for resource naming)
project_name = "tee-hackathon"

# EC2 instance type (must support Nitro Enclaves)
# See: https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html
instance_type = "m5.xlarge"

# Enclave resource allocation
enclave_cpu_count  = 2
enclave_memory_mib = 2048

# Additional Cognito callback URLs (for local development)
# allowed_callback_urls = ["http://localhost:3000/oauth2/idpresponse"]
