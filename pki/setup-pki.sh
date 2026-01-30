#!/bin/bash
set -e

CERTS_DIR="/certs"
DAYS_VALID=365

# Check if certs already exist
if [ -f "$CERTS_DIR/root-ca.pem" ]; then
    echo "Certificates already exist, skipping generation"
    exit 0
fi

echo "=== Generating Demo PKI for TEE Hackathon ==="

cd "$CERTS_DIR"

# =============================================================================
# 1. Root CA - This is the trust anchor (like Intel's root in real SGX)
# =============================================================================
echo "Generating Root CA..."

openssl genrsa -out root-ca.key 4096

openssl req -x509 -new -nodes \
    -key root-ca.key \
    -sha256 \
    -days $DAYS_VALID \
    -out root-ca.pem \
    -subj "/C=US/ST=Demo/L=Hackathon/O=Demo TEE Authority/CN=Demo Root CA"

# =============================================================================
# 2. Attestation Authority (Intermediate) - Like Intel's attestation signing
# =============================================================================
echo "Generating Attestation Authority (Intermediate CA)..."

openssl genrsa -out attestation-ca.key 4096

openssl req -new \
    -key attestation-ca.key \
    -out attestation-ca.csr \
    -subj "/C=US/ST=Demo/L=Hackathon/O=Demo TEE Authority/CN=Demo Attestation Authority"

# Create config for intermediate CA
cat > attestation-ca.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
EOF

openssl x509 -req \
    -in attestation-ca.csr \
    -CA root-ca.pem \
    -CAkey root-ca.key \
    -CAcreateserial \
    -out attestation-ca.pem \
    -days $DAYS_VALID \
    -sha256 \
    -extfile attestation-ca.ext

# =============================================================================
# 3. TEE Signing Key - This is what the "enclave" uses to sign quotes
#    In real SGX, this would be derived from hardware-fused keys
# =============================================================================
echo "Generating TEE Signing Key..."

openssl genrsa -out tee-signing.key 2048

openssl req -new \
    -key tee-signing.key \
    -out tee-signing.csr \
    -subj "/C=US/ST=Demo/L=Hackathon/O=Demo Data Provider/CN=TEE Enclave Signer"

# Create config for end-entity cert
cat > tee-signing.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning
# Custom extension to indicate this is a TEE attestation cert (demo purposes)
1.3.6.1.4.1.99999.1=ASN1:UTF8String:demo-tee-attestation
EOF

openssl x509 -req \
    -in tee-signing.csr \
    -CA attestation-ca.pem \
    -CAkey attestation-ca.key \
    -CAcreateserial \
    -out tee-signing.pem \
    -days $DAYS_VALID \
    -sha256 \
    -extfile tee-signing.ext

# =============================================================================
# 4. Create certificate chain file (for easy verification)
# =============================================================================
echo "Creating certificate chain..."

# Chain file: TEE cert -> Attestation CA -> Root CA
cat tee-signing.pem attestation-ca.pem > tee-chain.pem

# Full chain including root (for complete verification)
cat tee-signing.pem attestation-ca.pem root-ca.pem > full-chain.pem

# =============================================================================
# 5. Cleanup temporary files
# =============================================================================
rm -f *.csr *.ext *.srl

# =============================================================================
# 6. Set permissions
# =============================================================================
chmod 600 *.key
chmod 644 *.pem

echo ""
echo "=== PKI Generation Complete ==="
echo ""
echo "Files created:"
echo "  root-ca.pem        - Root CA certificate (give to Judge)"
echo "  root-ca.key        - Root CA private key (keep secret, not needed after setup)"
echo "  attestation-ca.pem - Intermediate CA certificate"
echo "  attestation-ca.key - Intermediate CA private key (keep secret)"
echo "  tee-signing.pem    - TEE signing certificate"
echo "  tee-signing.key    - TEE signing private key (Data Provider only)"
echo "  tee-chain.pem      - Certificate chain (TEE -> Attestation CA)"
echo "  full-chain.pem     - Full chain including root"
echo ""
echo "Trust model:"
echo "  - Judge trusts only: root-ca.pem"
echo "  - Data Provider has: tee-signing.key, tee-chain.pem"
echo "  - Challengers need:  nothing (they trust the Judge)"