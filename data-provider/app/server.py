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

from enclave_client import EnclaveClient, EnclaveResponse, get_cid

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

def reset_dataset_logic(source='SYNTHETIC', entries=10):
    """Reset the dataset directory with new data."""
    dataset_dir = Path(DATASET_PATH)
    
    # Clear existing
    for f in dataset_dir.glob('*'):
        if f.is_file():
            f.unlink()
            
    try:
        import dataset
        if source == 'HF':
            data_items = dataset.parse_dataset(entries=entries)
        else:
            data_items = dataset.generate_synthetic_dataset(entries=entries)
            
        for i, item in enumerate(data_items):
            filename = f"doc_{i:03d}.txt"  # Generic name
            filepath = dataset_dir / filename
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(item['text'])
        
        return len(data_items), None
    except Exception as e:
        return 0, str(e)



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
    Compute Merkle root using ZK-compatible Poseidon hash.
    Returns (root_hash, {filename: sha256_hash} mapping).
    """
    file_hashes = {}
    
    # 1. Compute SHA256 hashes of files (leaves)
    for filepath in sorted(directory.rglob('*')):
        if filepath.is_file():
            with open(filepath, 'rb') as f:
                content = f.read()
            file_hash = hashlib.sha256(content).hexdigest()
            rel_path = str(filepath.relative_to(directory))
            file_hashes[rel_path] = file_hash
    
    if not file_hashes:
        # Empty tree... handle gracefully or return dummy
        return "0", {}
    
    # 2. Dump hashes to JSON for zk_bridge.js
    # Sort by filename to ensure deterministic order
    sorted_hashes = [file_hashes[k] for k in sorted(file_hashes.keys())]
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump({"leaves": sorted_hashes}, f)
        leaves_json_path = f.name
        
    try:
        # 3. Call zk_bridge.js to compute root
        # We assume zk_bridge.js is in the same directory as server.py
        result = subprocess.run(
            ['node', 'zk_bridge.js', 'compute-root', leaves_json_path],
            capture_output=True,
            text=True,
            check=True
        )
        root = result.stdout.strip()
        app.logger.info(f"Computed ZK Merkle Root: {root}")
        return root, file_hashes
        
    except subprocess.CalledProcessError as e:
        app.logger.error(f"Failed to compute ZK root: {e.stderr}")
        raise
    finally:
        try:
            os.unlink(leaves_json_path)
        except:
            pass


def compute_wasm_hash(wasm_bytes: bytes) -> str:
    """Compute hash of the WebAssembly module (simulates MRENCLAVE)."""
    return hashlib.sha256(wasm_bytes).hexdigest()


def run_wasm_challenge(wasm_bytes: bytes, dataset_path: Path, file_hashes: dict) -> EnclaveResponse:
    """
    Run the challenger's WebAssembly module against the dataset.
    
    The WASM module is expected to:
    - Read filenames from stdin (one per line)
    - Output "UNSAFE:<filename>" for any unsafe documents
    - Output "SAFE" if all documents are safe
    
    Returns dict with results.
    """
    try:
        # Prepare input: list of files and their contents
        # Format: JSON lines with {filename, content}
        documents = []
        for filename, file_hash in sorted(file_hashes.items()):
            filepath = dataset_path / filename
            if filepath.exists():
                with open(filepath, 'rb') as f:
                    documents.append(f.read())

        cid = get_cid()
        app.logger.info(f"Using Enclave CID: {cid}")
        with EnclaveClient(cid) as client:
            return client.process(wasm_bytes, documents)

    finally:
        #os.unlink(wasm_path)
        pass


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
    
    <div style="margin-top: 30px; border-top: 1px solid #ccc; padding-top: 20px;">
        <h3>⚙️ Dataset Settings</h3>
        <p>Current Source: <span id="current-source">Unknown</span></p>
        <button onclick="resetDataset('SYNTHETIC')" style="background:#6c757d; margin-right:10px;">Load Synthetic Data</button>
        <button onclick="resetDataset('HF')" style="background:#17a2b8;">Load Hugging Face PII Data</button>
        <div id="dataset-status" style="margin-top: 10px; font-style: italic;"></div>
    </div>

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
                
                if (response.status === 429) {
                     resultDiv.innerHTML = `<div class="result error"><h3>⚠️ Rate Limit Exceeded</h3><p>Please wait before submitting again.</p></div>`;
                     return;
                }

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

        async function resetDataset(source) {
            const statusDiv = document.getElementById('dataset-status');
            statusDiv.innerText = `Loading ${source} dataset... please wait...`;
            statusDiv.style.color = 'blue';
            
            try {
                const res = await fetch('/api/reset_dataset', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({source: source})
                });
                const data = await res.json();
                
                if (data.success) {
                    statusDiv.innerText = `Success! Loaded ${data.count} documents.`;
                    statusDiv.style.color = 'green';
                    document.getElementById('current-source').innerText = source;
                    setTimeout(() => location.reload(), 2000);
                } else {
                    statusDiv.innerText = `Error: ${data.error}`;
                    statusDiv.style.color = 'red';
                }
            } catch (e) {
                statusDiv.innerText = `Error: ${e}`;
                statusDiv.style.color = 'red';
            }
        }
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

# Simple rate limiter (in-memory)
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 10
request_history = {} # IP -> [timestamp]

def check_rate_limit(ip):
    now = time.time()
    # Clean up old timestamps
    if ip in request_history:
        request_history[ip] = [t for t in request_history[ip] if t > now - RATE_LIMIT_WINDOW]
    else:
        request_history[ip] = []
        
    if len(request_history[ip]) >= RATE_LIMIT_MAX_REQUESTS:
        return False
        
    request_history[ip].append(now)
    return True


@app.route('/api/reset_dataset', methods=['POST'])
def api_reset_dataset():
    data = request.json
    source = data.get('source', 'SYNTHETIC')
    
    app.logger.info(f"Resetting dataset to {source}")
    count, error = reset_dataset_logic(source)
    
    if error:
        return jsonify({'success': False, 'error': error}), 500
        
    return jsonify({'success': True, 'count': count})


@app.route('/challenge', methods=['POST'])
def submit_challenge():
    """Handle a challenge submission."""
    try:
        # Rate Limit Check
        if not check_rate_limit(request.remote_addr):
            app.logger.warning(f"Rate limit exceeded for {request.remote_addr}")
            return jsonify({'success': False, 'error': 'Rate limit exceeded'}), 429

        app.logger.warning("Received new challenge submission")

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
        
        if result.status != 0:
            return jsonify({
                'success': False,
                'error': str(result)
            }), 500
        
        # Select a random document if any were flagged
        selected_doc = None   # TODO select_random_document(result['unsafe_documents'], dataset_path)
        result_doc_hash = selected_doc['hash'] if selected_doc else None
        
        # Generate ZK Proof if a document was selected
        zk_proof = None
        if selected_doc:
            try:
                # Find index of selected document
                sorted_files = sorted(file_hashes.keys())
                doc_index = sorted_files.index(selected_doc['filename'])
                
                # Dump leaves again (or cache them)
                sorted_hashes = [file_hashes[k] for k in sorted_files]
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                    json.dump({"leaves": sorted_hashes}, f)
                    leaves_json_path = f.name
                
                # Paths to ZK artifacts
                wasm_path = "/app/zk_artifacts/merkle_proof.wasm"
                zkey_path = "/app/zk_artifacts/merkle_proof_final.zkey"
                
                app.logger.info(f"Generating ZK proof for index {doc_index}...")
                
                proof_cmd = [
                    'node', 'zk_bridge.js', 'generate-proof',
                    leaves_json_path,
                    str(doc_index),
                    wasm_path,
                    zkey_path
                ]
                
                # Use temp file for output to avoid pipe deadlocks
                with tempfile.NamedTemporaryFile(mode='w+', delete=False) as out_f:
                    app.logger.info(f"Command inputs: {proof_cmd}")
                    
                    # Construct shell command
                    cmd_str = f"node zk_bridge.js generate-proof {leaves_json_path} {doc_index} {wasm_path} {zkey_path} > {out_f.name} 2>&1"
                    app.logger.info(f"Running shell command: {cmd_str}")
                    
                    exit_code = os.system(cmd_str)
                    
                    if exit_code != 0:
                        raise Exception(f"Command failed with exit code {exit_code}")
                        
                    out_f.seek(0)
                    zk_proof_output = out_f.read()
                
                # Cleanup temp file
                try:
                    os.unlink(out_f.name)
                except:
                    pass

                # Output should be JSON {proof: ..., publicSignals: ...}
                zk_proof = json.loads(zk_proof_output.strip())
                app.logger.info("ZK Proof generated successfully")
                
            except Exception as e:
                app.logger.error(f"Failed to generate ZK proof: {e}")
                app.logger.error(getattr(e, 'stderr', ''))
                # For now, maybe proceed without proof or fail?
                # Let's fail to enforce ZK
                return jsonify({'success': False, 'error': f"ZK Proof generation failed: {e}"}), 500
            finally:
                if 'leaves_json_path' in locals():
                    try: os.unlink(leaves_json_path)
                    except: pass
        
        # Create timestamp
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Generate a challenge ID
        challenge_id = hashlib.sha256(
            f"{wasm_hash}:{nonce}:{timestamp}".encode()
        ).hexdigest()[:16]
        
        # Send to judge
        sent_to_judge = False
        try:
            judge_response = requests.post(
                JUDGE_URL,
                json={'challenge_id': challenge_id, 'package': result},
                timeout=30
            )
            sent_to_judge = judge_response.status_code == 200
        except Exception as e:
            app.logger.warning(f"Failed to send to judge: {e}")
        
        return jsonify({
            'success': True,
            'challenge_id': challenge_id,
            'quote': base64.encodebytes(result.attestation_document).decode('utf-8'),
            'unsafe_count': -1,
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
    app.run(host='0.0.0.0', port=8000, debug=True)