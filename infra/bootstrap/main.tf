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
  #   key    = "bootstrap/terraform.tfstate"
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

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-2"
}

variable "project_name" {
  description = "Project name for tagging"
  type        = string
  default     = "tee-hackathon"
}

variable "github_repo" {
  description = "GitHub repository in format owner/repo"
  type        = string
}
