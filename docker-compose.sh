cat <<'EOF' >/tmp/docker-compose.yml
services:
  # =============================================================================
  # Data Provider - runs the TEE (simulated), hosts dataset, accepts challenges
  # =============================================================================
  data-provider:
    # build:
    #   context: ./data-provider
    #   dockerfile: Dockerfile
    image: webserver:latest
    ports:
      - "8080:8080"
    volumes:
      - ./data-provider/dataset:/data
      - ./zk-circuit:/app/zk_artifacts:ro
    environment:
      - DATASET_PATH=/data
      - JUDGE_URL=http://judge:8081/submit
    networks:
      - frontend
      - internal
    privileged: true  # Required for access to AF_VSOCK
    command:
      python3 server.py --cid "${ENCLAVE_CID}" --port 8080

  # =============================================================================
  # Judge - verifies attestations, evaluates flagged documents with LLM
  # =============================================================================
  judge:
    # build:
    #   context: ./judge
    #   dockerfile: Dockerfile
    image: judge:latest
    ports:
      - "8083:8083"
    volumes:
      - results:/results
      - ./zk-circuit/verification_key.json:/app/zk_artifacts/verification_key.json:ro
    environment:
      - CA_ROOT_CERT=/certs/root-ca.pem
      - RESULTS_PATH=/results
      # You'll need to set this to your actual API key
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}
      - OPENAI_API_KEY=${OPENAI_API_KEY:-}
      - GEMMA_API_KEY=${GEMMA_API_KEY:-}
    networks:
      - internal

  # =============================================================================
  # Results Board - public display of verdicts
  # =============================================================================
  results-board:
    image: nginx:alpine
    ports:
      - "8082:80"
    volumes:
      - results:/usr/share/nginx/html:ro
      - ./results/nginx.conf:/etc/nginx/conf.d/default.conf:ro
    depends_on:
      - judge
    networks:
      - frontend

  challenger-ui:
    build:
      context: ./challenger/web
      dockerfile: Dockerfile
    ports:
      - "8081:80"
    volumes:
      - ./challenger/challenges:/challenges
      - ./compiled-wasm:/wasm:ro
    depends_on:
      - judge
    networks:
      - frontend

volumes:
  results:
    driver: local

networks:
  # Internal network: data-provider <-> judge communication only
  internal:
    driver: bridge
    # internal: true  # Disabled to allow LLM API access
  
  # Frontend network: external access to web UIs
  frontend:
    driver: bridge
EOF