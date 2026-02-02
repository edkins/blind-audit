#!/bin/bash
set -ex

# Parameters (passed as environment variables)
IMAGE_TAG="${IMAGE_TAG:-latest}"
DEBUG_MODE="${DEBUG_MODE:-false}"
ENCLAVE_REPO="${ENCLAVE_REPO:-blind-audit-enclave}"
WEBSERVER_REPO="${WEBSERVER_REPO:-blind-audit-webserver}"
AWS_REGION="${AWS_REGION:-us-east-2}"

# If running as root (via SSM), re-run as ec2-user
if [ "$(id -u)" = "0" ]; then
  chmod +rx "$0"
  exec sudo -u ec2-user -i \
    IMAGE_TAG="$IMAGE_TAG" \
    DEBUG_MODE="$DEBUG_MODE" \
    ENCLAVE_REPO="$ENCLAVE_REPO" \
    WEBSERVER_REPO="$WEBSERVER_REPO" \
    AWS_REGION="$AWS_REGION" \
    bash -e "$0"
fi

# Get AWS account ID dynamically
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ECR_REGISTRY="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"

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
ENCLAVE_ARGS="--eif-path /tmp/app.eif --cpu-count 2 --memory 2048"
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
