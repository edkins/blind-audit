# Makefile for Nitro Enclave demo

ENCLAVE_IMAGE = enclave-server
ENCLAVE_EIF = enclave-server.eif

.PHONY: build-docker build-eif run-enclave stop-enclave test clean

# Build the Docker image for the enclave
build-docker:
	docker build -f Dockerfile.enclave -t $(ENCLAVE_IMAGE) .

# Convert Docker image to Enclave Image File
build-eif: build-docker
	nitro-cli build-enclave --docker-uri $(ENCLAVE_IMAGE):latest --output-file $(ENCLAVE_EIF)

# Run the enclave in debug mode (for development)
run-enclave-debug: build-eif
	nitro-cli terminate-enclave --all 2>/dev/null || true
	nitro-cli run-enclave \
		--eif-path $(ENCLAVE_EIF) \
		--cpu-count 2 \
		--memory 2000 \
		--debug-mode
	@echo ""
	@echo "Enclave started. To view console output:"
	@echo "  nitro-cli console --enclave-id \$$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')"
	@echo ""
	@echo "To test:"
	@echo "  python3 enclave_client.py --cid \$$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveCID') --test"

# Run the enclave in production mode (no debug console)
run-enclave: build-eif
	nitro-cli terminate-enclave --all 2>/dev/null || true
	nitro-cli run-enclave \
		--eif-path $(ENCLAVE_EIF) \
		--cpu-count 2 \
		--memory 512

# Stop all running enclaves
stop-enclave:
	nitro-cli terminate-enclave --all

# Show enclave info
info:
	nitro-cli describe-enclaves

# Attach to enclave console (debug mode only)
console:
	nitro-cli console --enclave-id $$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')

# Run test client
test:
	python3 enclave_client.py \
		--cid $$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveCID') \
		--test

# Clean up
clean:
	nitro-cli terminate-enclave --all 2>/dev/null || true
	rm -f $(ENCLAVE_EIF)
	docker rmi $(ENCLAVE_IMAGE) 2>/dev/null || true
