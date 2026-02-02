#!/bin/bash
set -ex

# Parameters (passed as environment variables)
IMAGE_TAG="${IMAGE_TAG:-latest}"
DEBUG_MODE="${DEBUG_MODE:-false}"
ENCLAVE_REPO="${ENCLAVE_REPO:-blind-audit-enclave}"
WEBSERVER_REPO="${WEBSERVER_REPO:-blind-audit-webserver}"
JUDGE_REPO="${JUDGE_REPO:-blind-audit-judge}"
CHALLENGER_REPO="${CHALLENGER_REPO:-blind-audit-challenger}"
AWS_REGION="${AWS_REGION:-us-east-2}"

# If running as root (via SSM), re-run as ec2-user
if [ "$(id -u)" = "0" ]; then
  # Copy script to a location ec2-user can access
  cp "$0" /tmp/deploy-run.sh
  chmod +rx /tmp/deploy-run.sh
  chown ec2-user /tmp/docker-compose.yml
  
  exec sudo -u ec2-user -i \
    IMAGE_TAG="$IMAGE_TAG" \
    DEBUG_MODE="$DEBUG_MODE" \
    ENCLAVE_REPO="$ENCLAVE_REPO" \
    WEBSERVER_REPO="$WEBSERVER_REPO" \
    JUDGE_REPO="$JUDGE_REPO" \
    CHALLENGER_REPO="$CHALLENGER_REPO" \
    AWS_REGION="$AWS_REGION" \
    bash -e /tmp/deploy-run.sh
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
docker pull "$ECR_REGISTRY/$JUDGE_REPO:$IMAGE_TAG"
docker pull "$ECR_REGISTRY/$CHALLENGER_REPO:$IMAGE_TAG"

# Tag for local use
docker tag "$ECR_REGISTRY/$ENCLAVE_REPO:$IMAGE_TAG" enclave:latest
docker tag "$ECR_REGISTRY/$WEBSERVER_REPO:$IMAGE_TAG" webserver:latest
docker tag "$ECR_REGISTRY/$JUDGE_REPO:$IMAGE_TAG" judge:latest
docker tag "$ECR_REGISTRY/$CHALLENGER_REPO:$IMAGE_TAG" challenger:latest

# Stop existing webserver
echo "Stopping existing webserver..."
docker stop webserver 2>/dev/null || true
docker rm webserver 2>/dev/null || true

# Stop existing services
echo "Stopping existing docker services..."
docker compose -f /tmp/docker-compose.yml down || true

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
export ENCLAVE_CID

cat <<'EOF' >/tmp/results/nginx.conf
server {
    listen 80;
    server_name localhost;
    
    root /usr/share/nginx/html;
    index index.html;
    
    # Serve static files
    location / {
        try_files $uri $uri/ /index.html;
        
        # Enable auto-index for JSON files
        autoindex on;
        autoindex_format json;
    }
    
    # CORS headers for API access
    location ~ \.json$ {
        add_header Access-Control-Allow-Origin *;
        add_header Content-Type application/json;
    }
}
EOF

# Start docker services
docker compose -f /tmp/docker-compose.yml up -d

echo "=========================================="
echo "Deploy complete!"
echo "=========================================="
nitro-cli describe-enclaves
docker ps
