variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-2"
}

variable "project_name" {
  description = "Project name, used for resource naming"
  type        = string
  default     = "tee-hackathon"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "instance_type" {
  description = "EC2 instance type (must support Nitro Enclaves)"
  type        = string
  default     = "m5.xlarge" # Smallest enclave-capable instance
}

variable "enclave_cpu_count" {
  description = "Number of CPUs to allocate to enclave"
  type        = number
  default     = 2
}

variable "enclave_memory_mib" {
  description = "Memory in MiB to allocate to enclave"
  type        = number
  default     = 2048
}

# DNS Configuration
variable "domain_name" {
  description = "Root domain name (e.g., example.com)"
  type        = string
}

variable "app_subdomain" {
  description = "Subdomain for the app (e.g., 'app' for app.example.com). Leave empty to use apex domain."
  type        = string
  default     = ""
}

variable "create_hosted_zone" {
  description = "Create a new Route 53 hosted zone? Set to false if domain is already registered in Route 53."
  type        = bool
  default     = false
}

variable "allowed_callback_urls" {
  description = "Additional callback URLs for Cognito (e.g., localhost for dev)"
  type        = list(string)
  default     = []
}
