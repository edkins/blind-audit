#!/bin/bash
set -e

echo "Compiling circuit..."
circom merkle_proof.circom --r1cs --wasm --sym --output .

echo "Generating Power of Tau (Trusted Setup Phase 1)..."
# Start a new powers of tau ceremony
npx snarkjs powersoftau new bn128 14 pot12_0000.ptau -v

# Contribute (randomness)
echo "randomentropy" | npx snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="First Contribution" -v

# Prepare phase 2
echo "Preparing Phase 2..."
npx snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau -v

echo "Generating ZKey (Phase 2)..."
npx snarkjs groth16 setup merkle_proof.r1cs pot12_final.ptau merkle_proof_0000.zkey

echo "Contribute entropy..."
echo "randomtext" | npx snarkjs zkey contribute merkle_proof_0000.zkey merkle_proof_final.zkey --name="1st Contributor" -v

echo "Exporting Verification Key..."
npx snarkjs zkey export verificationkey merkle_proof_final.zkey verification_key.json

echo "Copying artifacts to output..."
cp merkle_proof_js/merkle_proof.wasm /app/output/
cp merkle_proof_final.zkey /app/output/
cp verification_key.json /app/output/

echo "Done!"
