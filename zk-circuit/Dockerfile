FROM node:20-bookworm

# Install dependencies
RUN apt-get update && apt-get install -y curl

# Install Circom
RUN curl -Lo /usr/local/bin/circom https://github.com/iden3/circom/releases/latest/download/circom-linux-amd64 && \
    chmod +x /usr/local/bin/circom

WORKDIR /app

# Install SnarkJS and CircomLib
COPY package.json .
RUN npm install

# Copy Circuit and Build Script
COPY merkle_proof.circom .
COPY build.sh .
RUN chmod +x build.sh

# Output directory
RUN mkdir -p /app/output

CMD ["./build.sh"]
