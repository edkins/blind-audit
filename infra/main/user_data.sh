#!/bin/bash
set -e

# Log everything
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

echo "Starting user-data script..."

# Update system
dnf update -y

# Install Docker
dnf install -y docker jq
systemctl enable docker
systemctl start docker

# Install Nitro Enclaves CLI
dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel

# Configure enclave allocator
cat <<ALLOCATOR > /etc/nitro_enclaves/allocator.yaml
---
memory_mib: ${enclave_memory_mib}
cpu_count: ${enclave_cpu_count}
ALLOCATOR

# Enable and start the allocator
systemctl enable nitro-enclaves-allocator
systemctl start nitro-enclaves-allocator

# Add ec2-user to required groups
usermod -aG docker ec2-user
usermod -aG ne ec2-user

# Install SSM agent (should be present, but ensure it's running)
dnf install -y amazon-ssm-agent
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent

echo "User-data script completed successfully!"