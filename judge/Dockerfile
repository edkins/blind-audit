FROM python:3.11-slim

# Install dependencies
RUN pip install flask cryptography requests anthropic openai

WORKDIR /app

COPY app/ /app/

# Create results directory
RUN mkdir -p /results

EXPOSE 8081

CMD ["python3", "server.py"]