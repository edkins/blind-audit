FROM python:3.11-slim

# Install dependencies
RUN apt-get update && apt-get install -y curl \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app



RUN pip install flask cryptography requests anthropic openai google-genai pydantic

COPY app/ /app/

# Install Node modules locally
RUN npm init -y && npm install snarkjs circomlibjs && ls -la /app/node_modules

# Create results directory
RUN mkdir -p /results

EXPOSE 8081

CMD ["python3", "server.py"]