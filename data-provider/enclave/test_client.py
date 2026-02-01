#!/usr/bin/env python3
"""
Test client - connects via TCP for testing outside enclave

Usage:
    python3 test_client.py --host localhost --port 5000 --wasm module.wasm --documents doc1.txt doc2.txt
"""

import socket
import struct
import argparse


def send_request(sock, wasm_module: bytes, documents: list[bytes]) -> dict:
    """Send a request and receive response"""
    
    # Build request body
    body = bytearray()
    
    # WASM module
    body.extend(struct.pack('>I', len(wasm_module)))
    body.extend(wasm_module)
    
    # Documents
    body.extend(struct.pack('>I', len(documents)))
    for doc in documents:
        body.extend(struct.pack('>I', len(doc)))
        body.extend(doc)
    
    # Send with length prefix
    request = struct.pack('>I', len(body)) + bytes(body)
    print(f"Sending request: {len(wasm_module)} bytes WASM, {len(documents)} documents")
    sock.sendall(request)
    
    # Receive response
    length_bytes = sock.recv(4)
    if len(length_bytes) < 4:
        raise RuntimeError("Connection closed")
    
    total_length = struct.unpack('>I', length_bytes)[0]
    print(f"Receiving response: {total_length} bytes")
    
    # Read rest of response
    response_data = b''
    while len(response_data) < total_length:
        chunk = sock.recv(min(total_length - len(response_data), 65536))
        if not chunk:
            raise RuntimeError("Connection closed")
        response_data += chunk
    
    # Parse response
    offset = 0
    
    status = struct.unpack('>I', response_data[offset:offset+4])[0]
    offset += 4
    
    wasm_hash = response_data[offset:offset+32]
    offset += 32
    
    docs_hash = response_data[offset:offset+32]
    offset += 32
    
    result_len = struct.unpack('>I', response_data[offset:offset+4])[0]
    offset += 4
    result = response_data[offset:offset+result_len]
    offset += result_len
    
    attestation_len = struct.unpack('>I', response_data[offset:offset+4])[0]
    offset += 4
    attestation = response_data[offset:offset+attestation_len]
    
    return {
        'status': status,
        'wasm_hash': wasm_hash.hex(),
        'documents_hash': docs_hash.hex(),
        'result': result.decode('utf-8', errors='replace'),
        'attestation_length': attestation_len,
    }


def main():
    parser = argparse.ArgumentParser(description='Test client for WASM verifier')
    parser.add_argument('--host', default='localhost', help='Server host')
    parser.add_argument('--port', type=int, default=5000, help='Server port')
    parser.add_argument('--wasm', required=True, help='Path to WASM module')
    parser.add_argument('--documents', nargs='+', required=True, help='Paths to documents')
    
    args = parser.parse_args()
    
    # Load WASM module
    with open(args.wasm, 'rb') as f:
        wasm_module = f.read()
    print(f"Loaded WASM module: {len(wasm_module)} bytes")
    
    # Load documents
    documents = []
    for doc_path in args.documents:
        with open(doc_path, 'rb') as f:
            documents.append(f.read())
        print(f"Loaded document: {doc_path} ({len(documents[-1])} bytes)")
    
    # Connect
    print(f"\nConnecting to {args.host}:{args.port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.host, args.port))
    print("Connected")
    
    try:
        response = send_request(sock, wasm_module, documents)
        
        print("\n=== Response ===")
        print(f"Status: {response['status']}")
        print(f"Result: {response['result']}")
        print(f"Attestation length: {response['attestation_length']}")
        
    finally:
        sock.close()


if __name__ == '__main__':
    main()
