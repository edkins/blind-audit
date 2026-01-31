FROM python:3.11-slim

# Install dependencies
RUN apt-get update && apt-get install -y curl \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && npm install -g snarkjs \
    && rm -rf /var/lib/apt/lists/*

RUN pip install flask cryptography requests anthropic openai google-genai pydantic

WORKDIR /app

COPY app/ /app/

# Create results directory
RUN mkdir -p /results

EXPOSE 8081

CMD ["python3", "server.py"]