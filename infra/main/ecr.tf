# ECR Repository for the enclave image
resource "aws_ecr_repository" "enclave" {
  name                 = "${var.project_name}-enclave"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name = "${var.project_name}-enclave"
  }
}

# ECR Repository for the webserver image
resource "aws_ecr_repository" "webserver" {
  name                 = "${var.project_name}-webserver"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name = "${var.project_name}-webserver"
  }
}

# Lifecycle policy to keep only recent images (saves storage costs)
resource "aws_ecr_lifecycle_policy" "enclave" {
  repository = aws_ecr_repository.enclave.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 10 images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 10
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

resource "aws_ecr_lifecycle_policy" "webserver" {
  repository = aws_ecr_repository.webserver.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 10 images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 10
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}
