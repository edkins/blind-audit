#!/bin/bash
set -e

# Log everything
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

echo "Starting user-data script..."

# Update system
dnf update -y

# Install Docker
dnf install -y docker
systemctl enable docker
systemctl start docker

# Install Nitro Enclaves CLI
dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel

# Configure enclave allocator
cat <<EOF > /etc/nitro_enclaves/allocator.yaml
---
memory_mib: ${enclave_memory_mib}
cpu_count: ${enclave_cpu_count}
EOF

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

# Create deploy script
cat <<'DEPLOY_SCRIPT' > /home/ec2-user/deploy.sh
#!/bin/bash
set -e

# Get AWS info dynamically
AWS_REGION="${aws_region}"
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ECR_REGISTRY="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"

IMAGE_TAG="${IMAGE_TAG:-latest}"
DEBUG_MODE="${DEBUG_MODE:-false}"
ENCLAVE_REPO="${ENCLAVE_REPO:-tee-hackathon-enclave}"
WEBSERVER_REPO="${WEBSERVER_REPO:-tee-hackathon-webserver}"

echo "=========================================="
echo "Deploying tag: $IMAGE_TAG"
echo "Debug mode: $DEBUG_MODE"
echo "ECR Registry: $ECR_REGISTRY"
echo "=========================================="

# Login to ECR
echo "Logging in to ECR..."
aws ecr get-login-password --region "$AWS_REGION" | docker login --username AWS --password-stdin "$ECR_REGISTRY"

# Pull both images
echo "Pulling images..."
docker pull "$ECR_REGISTRY/$ENCLAVE_REPO:$IMAGE_TAG"
docker pull "$ECR_REGISTRY/$WEBSERVER_REPO:$IMAGE_TAG"

# Tag for local use
docker tag "$ECR_REGISTRY/$ENCLAVE_REPO:$IMAGE_TAG" enclave:latest
docker tag "$ECR_REGISTRY/$WEBSERVER_REPO:$IMAGE_TAG" webserver:latest

# Stop existing webserver
echo "Stopping existing webserver..."
docker stop webserver 2>/dev/null || true
docker rm webserver 2>/dev/null || true

# Terminate existing enclave
echo "Terminating existing enclave..."
nitro-cli terminate-enclave --all || true

# Build enclave image
echo "Building enclave image..."
nitro-cli build-enclave --docker-uri enclave:latest --output-file /tmp/app.eif

# Run enclave
echo "Starting enclave..."
ENCLAVE_ARGS="--eif-path /tmp/app.eif --cpu-count ${enclave_cpu_count} --memory ${enclave_memory_mib}"
if [ "$DEBUG_MODE" = "true" ]; then
  ENCLAVE_ARGS="$ENCLAVE_ARGS --debug-mode"
  echo "Running in DEBUG MODE - attestation will indicate debug"
fi
nitro-cli run-enclave $ENCLAVE_ARGS

# Get enclave CID for webserver
ENCLAVE_CID=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveCID')
echo "Enclave CID: $ENCLAVE_CID"

# Start webserver
echo "Starting webserver..."
docker run -d \
  --name webserver \
  --restart unless-stopped \
  --network host \
  -e ENCLAVE_CID="$ENCLAVE_CID" \
  webserver:latest

echo "=========================================="
echo "Deploy complete!"
echo "=========================================="
nitro-cli describe-enclaves
docker ps
DEPLOY_SCRIPT

chmod +x /home/ec2-user/deploy.sh
chown ec2-user:ec2-user /home/ec2-user/deploy.sh

echo "User-data script completed successfully!"