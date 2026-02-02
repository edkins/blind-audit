#!/usr/bin/env python3
"""
Nitro Enclave vsock client

Sends WASM modules + documents to the enclave and receives
attestation-backed responses.
"""

import socket
import struct
import hashlib
from dataclasses import dataclass
from typing import List, Optional
import json
import base64


# vsock constants
AF_VSOCK = 40
VMADDR_CID_ANY = 0xFFFFFFFF

ENCLAVE_PORT = 5000


@dataclass
class EnclaveResponse:
    """Response from the enclave"""
    status: int
    wasm_hash: bytes
    documents_hash: bytes
    result: bytes
    attestation_document: bytes
    
    @property
    def wasm_hash_hex(self) -> str:
        return self.wasm_hash.hex()
    
    @property
    def documents_hash_hex(self) -> str:
        return self.documents_hash.hex()
    
    def to_dict(self) -> dict:
        return {
            'status': self.status,
            'wasm_hash': self.wasm_hash_hex,
            'documents_hash': self.documents_hash_hex,
            'result': self.result.decode('utf-8', errors='replace'),
            'attestation_document': base64.b64encode(self.attestation_document).decode('ascii'),
        }


class EnclaveClient:
    """Client for communicating with the Nitro Enclave"""
    
    def __init__(self, enclave_cid: int, port: int = ENCLAVE_PORT):
        """
        Initialize the enclave client.
        
        Args:
            enclave_cid: The CID of the enclave (from nitro-cli run-enclave output)
            port: The vsock port the enclave is listening on
        """
        self.enclave_cid = enclave_cid
        self.port = port
        self.sock: Optional[socket.socket] = None
    
    def connect(self):
        """Connect to the enclave via vsock"""
        self.sock = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
        self.sock.connect((self.enclave_cid, self.port))
        print(f"Connected to enclave CID {self.enclave_cid} on port {self.port}")
    
    def close(self):
        """Close the connection"""
        if self.sock:
            self.sock.close()
            self.sock = None
    
    def __enter__(self):
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def _send_all(self, data: bytes):
        """Send all data to the socket"""
        total_sent = 0
        while total_sent < len(data):
            sent = self.sock.send(data[total_sent:])
            if sent == 0:
                raise RuntimeError("Socket connection broken")
            total_sent += sent
    
    def _recv_exact(self, n: int) -> bytes:
        """Receive exactly n bytes from the socket"""
        chunks = []
        received = 0
        while received < n:
            chunk = self.sock.recv(min(n - received, 65536))
            if not chunk:
                raise RuntimeError("Socket connection broken")
            chunks.append(chunk)
            received += len(chunk)
        return b''.join(chunks)
    
    def process(self, wasm_module: bytes, documents: List[bytes]) -> EnclaveResponse:
        """
        Send a WASM module and documents to the enclave for processing.
        
        Args:
            wasm_module: The WASM bytecode
            documents: List of document contents
            
        Returns:
            EnclaveResponse containing hashes, result, and attestation
        """
        if not self.sock:
            raise RuntimeError("Not connected to enclave")
        
        # Build the request
        # Format:
        #   [4 bytes] total_length (big-endian)
        #   [4 bytes] wasm_length (big-endian)
        #   [wasm_length bytes] wasm_module
        #   [4 bytes] num_documents (big-endian)
        #   For each document:
        #     [4 bytes] doc_length (big-endian)
        #     [doc_length bytes] document_data
        
        body = bytearray()
        
        # WASM module
        body.extend(struct.pack('>I', len(wasm_module)))
        body.extend(wasm_module)
        
        # Documents
        body.extend(struct.pack('>I', len(documents)))
        for doc in documents:
            body.extend(struct.pack('>I', len(doc)))
            body.extend(doc)
        
        # Prepend total length
        request = struct.pack('>I', len(body)) + bytes(body)
        
        print(f"Sending request: {len(wasm_module)} bytes WASM, {len(documents)} documents")
        
        # Send request
        self._send_all(request)
        
        # Receive response
        # Format:
        #   [4 bytes] total_length (big-endian)
        #   [4 bytes] status (0 = success)
        #   [32 bytes] wasm_hash
        #   [32 bytes] documents_hash
        #   [4 bytes] result_length
        #   [result_length bytes] result_data
        #   [4 bytes] attestation_length
        #   [attestation_length bytes] attestation_document
        
        length_bytes = self._recv_exact(4)
        total_length = struct.unpack('>I', length_bytes)[0]
        
        print(f"Receiving response: {total_length} bytes")
        
        response_data = self._recv_exact(total_length)
        offset = 0
        
        # Status
        status = struct.unpack('>I', response_data[offset:offset+4])[0]
        offset += 4
        
        # Hashes
        wasm_hash = response_data[offset:offset+32]
        offset += 32
        
        documents_hash = response_data[offset:offset+32]
        offset += 32
        
        # Result
        result_length = struct.unpack('>I', response_data[offset:offset+4])[0]
        offset += 4
        result = response_data[offset:offset+result_length]
        offset += result_length
        
        # Flagged document info (added by server)
        has_flagged = struct.unpack('>I', response_data[offset:offset+4])[0]
        offset += 4
        flagged_index = None
        flagged_hash = None
        if has_flagged:
            flagged_index = struct.unpack('>I', response_data[offset:offset+4])[0]
            offset += 4
            flagged_hash = response_data[offset:offset+32]
            offset += 32
        
        # Attestation
        attestation_length = struct.unpack('>I', response_data[offset:offset+4])[0]
        offset += 4
        attestation = response_data[offset:offset+attestation_length]
        
        return EnclaveResponse(
            status=status,
            wasm_hash=wasm_hash,
            documents_hash=documents_hash,
            result=result,
            attestation_document=attestation,
        )


def verify_attestation(attestation_document: bytes, expected_pcrs: dict = None) -> bool:
    """
    Verify an attestation document from the Nitro enclave.
    
    In production, this would:
    1. Parse the COSE_Sign1 structure
    2. Verify the signature against AWS Nitro Attestation CA
    3. Check PCR values match expected enclave measurements
    4. Verify any user data included in the attestation
    
    Args:
        attestation_document: The raw attestation document
        expected_pcrs: Dict of PCR index -> expected value
        
    Returns:
        True if attestation is valid
    """
    # TODO: Implement real attestation verification
    # See: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
    #
    # You'll need:
    # - cbor2 library to parse CBOR
    # - cryptography library for COSE signature verification
    # - AWS Nitro root certificate from:
    #   https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
    
    print("WARNING: Attestation verification not implemented")
    print(f"  Attestation document: {attestation_document[:50]}...")
    
    return True


# def get_cid() -> int:
#     """
#     Get the CID of the current Nitro Enclave.
    
#     Returns:
#         The enclave CID as an integer.

#     Throws:
#         RuntimeError if the CID cannot be determined (usually if there are no enclaves or multiple).
#     """
#     process = subprocess.run(['nitro-cli', 'describe-enclaves'], check=True, capture_output=True)
#     enclaves = json.loads(process.stdout)
#     if len(enclaves) != 1:
#         raise RuntimeError(f"Expected exactly one enclave to be running, got {len(enclaves)}")
#     return enclaves[0]['EnclaveCID']

# Example usage
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Send requests to Nitro Enclave')
    parser.add_argument('--cid', type=int, required=True,
                        help='Enclave CID (from nitro-cli describe-enclaves)')
    parser.add_argument('--wasm', type=str, default=None,
                        help='Path to WASM module file')
    parser.add_argument('--documents', type=str, nargs='*', default=[],
                        help='Paths to document files')
    parser.add_argument('--test', action='store_true',
                        help='Run with dummy test data')
    
    args = parser.parse_args()
    
    # Load or create test data
    if args.test:
        # Dummy WASM (not valid, just for testing the protocol)
        wasm_module = b'\x00asm\x01\x00\x00\x00' + b'dummy_wasm_content'
        
        # Dummy documents
        documents = [
            b'This is document 1 with some content.',
            b'This is document 2 with different content.',
            b'Document 3 contains potentially suspicious text.',
        ]
    else:
        # Load WASM module
        if args.wasm:
            with open(args.wasm, 'rb') as f:
                wasm_module = f.read()
        else:
            wasm_module = b'\x00asm\x01\x00\x00\x00'
        
        # Load documents
        documents = []
        for doc_path in args.documents:
            with open(doc_path, 'rb') as f:
                documents.append(f.read())
    
    print(f"WASM module: {len(wasm_module)} bytes")
    print(f"Documents: {len(documents)}")
    
    # Connect and process
    with EnclaveClient(args.cid) as client:
        response = client.process(wasm_module, documents)
        
        print("\n=== Response ===")
        print(f"Status: {response.status}")
        print(f"WASM hash: {response.wasm_hash_hex}")
        print(f"Documents hash: {response.documents_hash_hex}")
        print(f"Result: {response.result.decode('utf-8', errors='replace')}")
        print(f"Attestation: {len(response.attestation_document)} bytes")
        
        # Verify locally computed hash matches enclave's hash
        local_wasm_hash = hashlib.sha256(wasm_module).hexdigest()
        print(f"\nLocal WASM hash: {local_wasm_hash}")
        print(f"Hashes match: {local_wasm_hash == response.wasm_hash_hex}")
        
        # Verify attestation (placeholder)
        verify_attestation(response.attestation_document)
        
        # Output as JSON for further processing
        print("\n=== JSON Output ===")
        print(json.dumps(response.to_dict(), indent=2))