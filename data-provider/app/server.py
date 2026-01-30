#!/usr/bin/env python3
"""
Data Provider Server

This server:
1. Accepts WebAssembly challenge modules from challengers
2. Runs them against the dataset in a "TEE" (simulated with WAMR)
3. Signs the results with the TEE attestation key
4. Sends attestation packages to the Judge
"""

import os
import json
import hashlib
import subprocess
import tempfile
import time
import base64
import secrets
import requests
from pathlib import Path
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template_string
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

app = Flask(__name__)


# Configuration from environment
TEE_SIGNING_KEY = os.environ.get('TEE_SIGNING_KEY', '/certs/tee-signing.key')
TEE_CERT_CHAIN = os.environ.get('TEE_CERT_CHAIN', '/certs/tee-chain.pem')
DATASET_PATH = os.environ.get('DATASET_PATH', '/data')
JUDGE_URL = os.environ.get('JUDGE_URL', 'http://judge:8081/submit')
HF_TOKEN = os.environ.get('HF_TOKEN') # For fetching dataset if needed for dataset.py

def initialize_dataset():
    """Initialize dataset from Hugging Face if directory is empty."""
    dataset_dir = Path(DATASET_PATH)
    dataset_dir.mkdir(parents=True, exist_ok=True)
    
    # Check if empty
    if not any(dataset_dir.iterdir()):
        print(f"Dataset directory {DATASET_PATH} is empty. Fetching from Hugging Face...")
        try:
            import dataset
            # Fetch some entries
            data_items = dataset.parse_dataset(entries=10)
            
            for i, item in enumerate(data_items):
                # Save as text file
                # item has 'text' and 'pii_entries'
                # We save the text as the document content
                filename = f"hf_sample_{i:03d}.txt"
                filepath = dataset_dir / filename
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(item['text'])
                    
            print(f"Initialized {len(data_items)} documents from Hugging Face.")
        except Exception as e:
            print(f"Failed to initialize dataset: {e}")
            # Create a dummy file so we have something
            with open(dataset_dir / "error_log.txt", "w") as f:
                f.write(f"Failed to load dataset: {e}")



def load_signing_key():
    """Load the TEE signing private key."""
    with open(TEE_SIGNING_KEY, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_cert_chain():
    """Load the certificate chain as PEM."""
    with open(TEE_CERT_CHAIN, 'rb') as f:
        return f.read().decode('utf-8')


def compute_merkle_root(directory: Path) -> tuple[str, dict]:
    """
    Compute Merkle root of all documents in the dataset.
    Returns (root_hash, {filename: hash} mapping).
    """
    file_hashes = {}
    
    for filepath in sorted(directory.rglob('*')):
        if filepath.is_file():
            with open(filepath, 'rb') as f:
                content = f.read()
            file_hash = hashlib.sha256(content).hexdigest()
            rel_path = str(filepath.relative_to(directory))
            file_hashes[rel_path] = file_hash
    
    if not file_hashes:
        return hashlib.sha256(b'empty').hexdigest(), {}
    
    # Simple Merkle tree: hash all file hashes together
    # (A real implementation would build a proper tree)
    combined = ''.join(f"{k}:{v}" for k, v in sorted(file_hashes.items()))
    root = hashlib.sha256(combined.encode()).hexdigest()
    
    return root, file_hashes


def compute_wasm_hash(wasm_bytes: bytes) -> str:
    """Compute hash of the WebAssembly module (simulates MRENCLAVE)."""
    return hashlib.sha256(wasm_bytes).hexdigest()


def run_wasm_challenge(wasm_bytes: bytes, dataset_path: Path, file_hashes: dict) -> dict:
    """
    Run the challenger's WebAssembly module against the dataset.
    
    The WASM module is expected to:
    - Read filenames from stdin (one per line)
    - Output "UNSAFE:<filename>" for any unsafe documents
    - Output "SAFE" if all documents are safe
    
    Returns dict with results.
    """
    with tempfile.NamedTemporaryFile(suffix='.wasm', delete=False) as f:
        f.write(wasm_bytes)
        wasm_path = f.name
    
    try:
        # Prepare input: list of files and their contents
        # Format: JSON lines with {filename, content}
        input_lines = []
        for filename, file_hash in sorted(file_hashes.items()):
            filepath = dataset_path / filename
            if filepath.exists():
                with open(filepath, 'rb') as f:
                    content = base64.b64encode(f.read()).decode('utf-8')
                input_lines.append(json.dumps({
                    'filename': filename,
                    'hash': file_hash,
                    'content': content
                }))
        
        input_data = '\n'.join(input_lines)
        
        # Run WAMR with the challenge module
        # --dir=/ gives the wasm module access to read files (sandboxed by WASI)
        result = subprocess.run(
            ['iwasm', '--dir=.', wasm_path],
            input=input_data,
            capture_output=True,
            text=True,
            timeout=30  # 30 second timeout
        )
        
        # Parse output
        output = result.stdout.strip()
        stderr = result.stderr.strip()
        
        if result.returncode != 0:
            return {
                'success': False,
                'error': f'WASM execution failed: {stderr}',
                'unsafe_documents': []
            }
        
        # Parse the output for unsafe documents
        unsafe_docs = []
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('UNSAFE:'):
                doc_name = line[7:].strip()
                if doc_name in file_hashes:
                    unsafe_docs.append({
                        'filename': doc_name,
                        'hash': file_hashes[doc_name]
                    })
        
        return {
            'success': True,
            'unsafe_documents': unsafe_docs,
            'output': output
        }
        
    finally:
        os.unlink(wasm_path)


def select_random_document(unsafe_docs: list, dataset_path: Path) -> dict | None:
    """Select a random document from the unsafe list to send to judge."""
    if not unsafe_docs:
        return None
    
    # Use secrets for cryptographic randomness
    selected = secrets.choice(unsafe_docs)
    filepath = dataset_path / selected['filename']
    
    if not filepath.exists():
        return None
    
    with open(filepath, 'rb') as f:
        content = f.read()
    
    return {
        'filename': selected['filename'],
        'hash': selected['hash'],
        'content': base64.b64encode(content).decode('utf-8')
    }


def create_attestation_quote(
    wasm_hash: str,
    merkle_root: str,
    result_doc_hash: str | None,
    challenger_nonce: str,
    timestamp: str
) -> dict:
    """
    Create the attestation quote - this is what gets signed.
    In real SGX, this would be generated by hardware.
    """
    return {
        'version': '1.0',
        'mrenclave': wasm_hash,  # Hash of the code that ran
        'dataset_merkle_root': merkle_root,
        'result_document_hash': result_doc_hash,
        'challenger_nonce': challenger_nonce,
        'timestamp': timestamp,
        'tee_type': 'simulated-wamr'  # Honest about simulation
    }


def sign_quote(quote: dict, private_key) -> str:
    """Sign the quote with the TEE signing key."""
    quote_bytes = json.dumps(quote, sort_keys=True).encode('utf-8')
    
    signature = private_key.sign(
        quote_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    return base64.b64encode(signature).decode('utf-8')


def create_attestation_package(
    quote: dict,
    signature: str,
    cert_chain: str,
    wasm_module: bytes,
    selected_document: dict | None
) -> dict:
    """Create the full attestation package to send to the judge."""
    return {
        'quote': quote,
        'signature': signature,
        'cert_chain': cert_chain,
        'wasm_module': base64.b64encode(wasm_module).decode('utf-8'),
        'document': selected_document  # May be None if no unsafe docs found
    }


# =============================================================================
# Web Interface
# =============================================================================

INDEX_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>TEE Challenge Portal - Data Provider</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        h1 { color: #333; }
        .info { background: #e7f3ff; padding: 15px; border-radius: 8px; margin: 20px 0; }
        .warning { background: #fff3cd; padding: 15px; border-radius: 8px; margin: 20px 0; }
        form { background: #f5f5f5; padding: 20px; border-radius: 8px; }
        label { display: block; margin: 10px 0 5px; font-weight: bold; }
        input[type="file"] { margin: 10px 0; }
        input[type="text"] { width: 100%; padding: 8px; margin: 5px 0; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; 
                 border-radius: 5px; cursor: pointer; margin-top: 15px; }
        button:hover { background: #0056b3; }
        pre { background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 8px; 
              overflow-x: auto; }
        .result { margin-top: 20px; padding: 15px; border-radius: 8px; }
        .success { background: #d4edda; }
        .error { background: #f8d7da; }
    </style>
</head>
<body>
    <h1>🔒 TEE Challenge Portal</h1>
    
    <div class="info">
        <strong>Dataset Merkle Root:</strong> <code>{{ merkle_root }}</code><br>
        <strong>Documents in dataset:</strong> {{ doc_count }}
    </div>
    
    <div class="warning">
        <strong>Note:</strong> This is a <em>simulated</em> TEE environment for demonstration.
        In production, the attestation would be backed by hardware (Intel SGX, AMD SEV, etc.)
    </div>
    
    <form id="challenge-form" enctype="multipart/form-data">
        <h2>Submit a Challenge</h2>
        
        <label for="wasm">WebAssembly Module (.wasm)</label>
        <input type="file" id="wasm" name="wasm" accept=".wasm" required>
        
        <label for="nonce">Challenger Nonce (for freshness)</label>
        <input type="text" id="nonce" name="nonce" placeholder="Enter a random string or leave blank for auto-generate">
        
        <button type="submit">Submit Challenge</button>
    </form>
    
    <div id="result"></div>
    
    <h2>WASM Module Requirements</h2>
    <p>Your WebAssembly module should:</p>
    <ul>
        <li>Read JSON lines from stdin, each containing: <code>{"filename": "...", "hash": "...", "content": "..."}</code></li>
        <li>The content is base64-encoded</li>
        <li>Output <code>UNSAFE:filename</code> for each unsafe document found</li>
        <li>Output <code>SAFE</code> if no unsafe documents found</li>
    </ul>
    
    <script>
        document.getElementById('challenge-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const resultDiv = document.getElementById('result');
            resultDiv.innerHTML = '<p>Processing challenge...</p>';
            
            const formData = new FormData();
            formData.append('wasm', document.getElementById('wasm').files[0]);
            formData.append('nonce', document.getElementById('nonce').value || crypto.randomUUID());
            
            try {
                const response = await fetch('/challenge', {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();
                
                if (data.success) {
                    resultDiv.innerHTML = `
                        <div class="result success">
                            <h3>✅ Challenge Completed</h3>
                            <p><strong>Challenge ID:</strong> ${data.challenge_id}</p>
                            <p><strong>Unsafe documents found:</strong> ${data.unsafe_count}</p>
                            <p><strong>Attestation sent to judge:</strong> ${data.sent_to_judge ? 'Yes' : 'No'}</p>
                            <details>
                                <summary>View Quote</summary>
                                <pre>${JSON.stringify(data.quote, null, 2)}</pre>
                            </details>
                        </div>
                    `;
                } else {
                    resultDiv.innerHTML = `
                        <div class="result error">
                            <h3>❌ Challenge Failed</h3>
                            <p>${data.error}</p>
                        </div>
                    `;
                }
            } catch (err) {
                resultDiv.innerHTML = `
                    <div class="result error">
                        <h3>❌ Error</h3>
                        <p>${err.message}</p>
                    </div>
                `;
            }
        });
    </script>
</body>
</html>
"""


@app.route('/')
def index():
    """Render the challenge submission form."""
    dataset_path = Path(DATASET_PATH)
    merkle_root, file_hashes = compute_merkle_root(dataset_path)
    return render_template_string(
        INDEX_HTML,
        merkle_root=merkle_root[:16] + '...',
        doc_count=len(file_hashes)
    )


@app.route('/challenge', methods=['POST'])
def submit_challenge():
    """Handle a challenge submission."""
    try:
        # Get the WASM module
        if 'wasm' not in request.files:
            return jsonify({'success': False, 'error': 'No WASM file provided'}), 400
        
        wasm_file = request.files['wasm']
        wasm_bytes = wasm_file.read()
        
        if len(wasm_bytes) == 0:
            return jsonify({'success': False, 'error': 'Empty WASM file'}), 400
        
        # Get nonce
        nonce = request.form.get('nonce', secrets.token_hex(16))
        
        # Load keys and certs
        signing_key = load_signing_key()
        cert_chain = load_cert_chain()
        
        # Compute dataset info
        dataset_path = Path(DATASET_PATH)
        merkle_root, file_hashes = compute_merkle_root(dataset_path)
        
        # Compute WASM hash (this is our MRENCLAVE equivalent)
        wasm_hash = compute_wasm_hash(wasm_bytes)
        
        # Run the challenge
        result = run_wasm_challenge(wasm_bytes, dataset_path, file_hashes)
        
        if not result['success']:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Unknown error during WASM execution')
            }), 500
        
        # Select a random document if any were flagged
        selected_doc = select_random_document(result['unsafe_documents'], dataset_path)
        result_doc_hash = selected_doc['hash'] if selected_doc else None
        
        # Create timestamp
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Create and sign the quote
        quote = create_attestation_quote(
            wasm_hash=wasm_hash,
            merkle_root=merkle_root,
            result_doc_hash=result_doc_hash,
            challenger_nonce=nonce,
            timestamp=timestamp
        )
        
        signature = sign_quote(quote, signing_key)
        
        # Create the attestation package
        package = create_attestation_package(
            quote=quote,
            signature=signature,
            cert_chain=cert_chain,
            wasm_module=wasm_bytes,
            selected_document=selected_doc
        )
        
        # Generate a challenge ID
        challenge_id = hashlib.sha256(
            f"{wasm_hash}:{nonce}:{timestamp}".encode()
        ).hexdigest()[:16]
        
        # Send to judge
        sent_to_judge = False
        try:
            judge_response = requests.post(
                JUDGE_URL,
                json={'challenge_id': challenge_id, 'package': package},
                timeout=30
            )
            sent_to_judge = judge_response.status_code == 200
        except Exception as e:
            app.logger.warning(f"Failed to send to judge: {e}")
        
        return jsonify({
            'success': True,
            'challenge_id': challenge_id,
            'quote': quote,
            'unsafe_count': len(result['unsafe_documents']),
            'sent_to_judge': sent_to_judge
        })
        
    except Exception as e:
        app.logger.exception("Error processing challenge")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({'status': 'healthy'})


if __name__ == '__main__':
    # Initialize dataset if needed
    initialize_dataset()
    app.run(host='0.0.0.0', port=8080, debug=True)