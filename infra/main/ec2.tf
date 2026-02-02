# EC2 Instance with Nitro Enclave support
resource "aws_instance" "enclave" {
  ami           = data.aws_ami.al2023.id
  instance_type = var.instance_type

  subnet_id                   = aws_subnet.private[0].id
  vpc_security_group_ids      = [aws_security_group.ec2.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2.name
  associate_public_ip_address = false

  # Enable Nitro Enclaves
  enclave_options {
    enabled = true
  }

  # Root volume
  root_block_device {
    volume_size           = 30
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  # User data for initial setup
  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    aws_region         = var.aws_region
    enclave_cpu_count  = var.enclave_cpu_count
    enclave_memory_mib = var.enclave_memory_mib
  }))

  tags = {
    Name = "${var.project_name}-enclave"
  }

  # Ensure instance is replaced if user_data changes
  lifecycle {
    create_before_destroy = true
  }
}

# Security Group for EC2
resource "aws_security_group" "ec2" {
  name        = "${var.project_name}-ec2-sg"
  description = "Security group for EC2 enclave instance"
  vpc_id      = aws_vpc.main.id

  # Allow traffic from ALB only
  ingress {
    description     = "HTTP from ALB"
    from_port       = 8080
    to_port         = 8082
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # Allow all outbound (for ECR pulls, package installs, etc.)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-ec2-sg"
  }
}
