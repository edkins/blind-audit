terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # For a real project, you'd want remote state
  # backend "s3" {
  #   bucket = "your-terraform-state-bucket"
  #   key    = "main/terraform.tfstate"
  #   region = "us-east-2"
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = var.project_name
      ManagedBy = "terraform"
    }
  }
}

# Get current account ID
data "aws_caller_identity" "current" {}

# Get current region
data "aws_region" "current" {}

# Get the latest Amazon Linux 2023 AMI with Nitro Enclave support
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}
