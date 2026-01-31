import os
import time
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file

app = Flask(__name__)

# Configuration
CHALLENGES_DIR = Path("/challenges")
WASM_DIR = Path("/wasm")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/files', methods=['GET'])
def list_files():
    """List available source files."""
    files = []
    if CHALLENGES_DIR.exists():
        for f in CHALLENGES_DIR.glob("*.rs"):
            files.append(f.name)
    return jsonify(files)

@app.route('/load', methods=['GET'])
def load_file():
    filename = request.args.get('filename')
    if not filename:
        return "Missing filename", 400
    
    filepath = CHALLENGES_DIR / filename
    if not filepath.exists():
        # Return default template if file doesn't exist
        return """use std::io::{self, BufRead};

fn main() {
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        if let Ok(line_content) = line {
             // Parse logic here
             // println!("UNSAFE: filename");
        }
    }
}
"""
    
    with open(filepath, 'r') as f:
        return f.read()

@app.route('/save', methods=['POST'])
def save_file():
    data = request.json
    filename = data.get('filename')
    content = data.get('content')
    
    if not filename or not content:
        return jsonify({"success": False, "error": "Missing filename or content"}), 400
    
    if not filename.endswith('.rs'):
        filename += '.rs'
        
    try:
        with open(CHALLENGES_DIR / filename, 'w') as f:
            f.write(content)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/status', methods=['GET'])
def check_status():
    filename = request.args.get('filename')
    if not filename:
        return jsonify({"status": "error"})
        
    base_name = os.path.splitext(filename)[0]
    wasm_name = base_name + ".wasm"
    log_name = base_name + ".log"
    
    wasm_path = WASM_DIR / wasm_name
    log_path = WASM_DIR / log_name
    
    # Check for success first
    if wasm_path.exists():
        # Even if success, we might want the log? For now let's just say ready.
        return jsonify({
            "status": "ready",
            "timestamp": wasm_path.stat().st_mtime,
            "size": wasm_path.stat().st_size
        })
    
    # Check for logs/errors
    if log_path.exists():
        try:
            with open(log_path, 'r') as f:
                log_content = f.read()
                
            if "Compilation Failed" in log_content:
                return jsonify({
                    "status": "error",
                    "log": log_content
                })
            else:
                 return jsonify({
                    "status": "compiling",
                    "log": log_content
                })
        except Exception:
             pass

    return jsonify({"status": "pending"})

@app.route('/submit', methods=['POST'])
def submit_challenge():
    """Submit a compiled WASM file directly to the Data Provider."""
    import requests
    
    data = request.json
    filename = data.get('filename')
    
    if not filename:
        return jsonify({'success': False, 'error': 'Missing filename'}), 400
        
    wasm_name = os.path.splitext(filename)[0] + ".wasm"
    wasm_path = WASM_DIR / wasm_name
    
    if not wasm_path.exists():
        return jsonify({'success': False, 'error': 'WASM file not found. Compile it first.'}), 404
        
    try:
        # Send to Data Provider
        # We assume data-provider is resolvable via Docker DNS
        with open(wasm_path, 'rb') as f:
            files = {'wasm': (wasm_name, f, 'application/wasm')}
            # We can optionally pass a nonce or let the provider generate it
            resp = requests.post('http://data-provider:8080/challenge', files=files, timeout=30)
            
        return jsonify(resp.json()), resp.status_code
        
    except requests.RequestException as e:
        return jsonify({'success': False, 'error': f'Failed to contact Data Provider: {str(e)}'}), 502


@app.route('/download/<path:filename>')
def download_file(filename):
    return send_file(WASM_DIR / filename, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
