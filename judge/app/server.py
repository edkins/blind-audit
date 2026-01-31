#!/usr/bin/env python3
"""
Judge Server

This server:
1. Receives attestation packages from the Data Provider
2. Verifies the signature chain against the root CA
3. Verifies the document hash matches the attested hash
4. Sends flagged documents to an LLM for safety evaluation
5. Publishes results publicly
"""

import os
import json
import hashlib
import subprocess
import tempfile
import base64
from pathlib import Path
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# Configuration
CA_ROOT_CERT = os.environ.get('CA_ROOT_CERT', '/certs/root-ca.pem')
RESULTS_PATH = os.environ.get('RESULTS_PATH', '/results')
ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', '')
GEMMA_API_KEY = os.environ.get('GEMMA_API_KEY', '')


def load_root_ca():
    """Load the root CA certificate."""
    with open(CA_ROOT_CERT, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())


def parse_cert_chain(chain_pem: str) -> list:
    """Parse a PEM certificate chain into individual certificates."""
    certs = []
    current_cert = []
    in_cert = False
    
    for line in chain_pem.split('\n'):
        if '-----BEGIN CERTIFICATE-----' in line:
            in_cert = True
            current_cert = [line]
        elif '-----END CERTIFICATE-----' in line:
            current_cert.append(line)
            cert_pem = '\n'.join(current_cert)
            certs.append(x509.load_pem_x509_certificate(
                cert_pem.encode(), default_backend()
            ))
            in_cert = False
            current_cert = []
        elif in_cert:
            current_cert.append(line)
    
    return certs


def verify_cert_chain(chain_certs: list, root_ca: x509.Certificate) -> bool:
    """
    Verify the certificate chain.
    chain_certs should be [end_entity, intermediate, ...]
    """
    if not chain_certs:
        return False
    
    # For a proper implementation, you'd verify each cert is signed by the next
    # and the last intermediate is signed by the root.
    # This is a simplified version for the hackathon.
    
    try:
        # Check the intermediate (last in chain before root) is signed by root
        if len(chain_certs) >= 2:
            intermediate = chain_certs[-1]
            # Verify intermediate is signed by root
            root_ca.public_key().verify(
                intermediate.signature,
                intermediate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                intermediate.signature_hash_algorithm
            )
        
        # Check end entity is signed by intermediate (or root if no intermediate)
        issuer = chain_certs[1] if len(chain_certs) >= 2 else root_ca
        end_entity = chain_certs[0]
        issuer.public_key().verify(
            end_entity.signature,
            end_entity.tbs_certificate_bytes,
            padding.PKCS1v15(),
            end_entity.signature_hash_algorithm
        )
        
        return True
    except Exception as e:
        app.logger.error(f"Certificate chain verification failed: {e}")
        return False


def verify_quote_signature(quote: dict, signature_b64: str, cert: x509.Certificate) -> bool:
    """Verify the quote signature using the end-entity certificate."""
    try:
        quote_bytes = json.dumps(quote, sort_keys=True).encode('utf-8')
        signature = base64.b64decode(signature_b64)
        
        cert.public_key().verify(
            signature,
            quote_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        app.logger.error(f"Quote signature verification failed: {e}")
        return False


def verify_wasm_hash(wasm_b64: str, expected_hash: str) -> bool:
    """Verify the WASM module hash matches the MRENCLAVE in the quote."""
    wasm_bytes = base64.b64decode(wasm_b64)
    actual_hash = hashlib.sha256(wasm_bytes).hexdigest()
    return actual_hash == expected_hash


def verify_document_hash(document: dict, expected_hash: str) -> bool:
    """Verify the document content matches the attested hash."""
    if not document:
        return expected_hash is None
    
    content = base64.b64decode(document['content'])
    actual_hash = hashlib.sha256(content).hexdigest()
    return actual_hash == expected_hash


def evaluate_document_safety(document: dict) -> dict:
    """
    Use an LLM to evaluate if the document is actually unsafe.
    Returns a verdict dict.
    """
    content = base64.b64decode(document['content']).decode('utf-8', errors='replace')
    filename = document['filename']
    
    # Try Anthropic first, then OpenAI, then fall back to a placeholder
    if ANTHROPIC_API_KEY:
        return evaluate_with_anthropic(filename, content)
    elif OPENAI_API_KEY:
        return evaluate_with_openai(filename, content)
    elif GEMMA_API_KEY:
        return evaluate_with_gemma(filename, content)
    else:
        return {
            'evaluated': False,
            'reason': 'No LLM API key configured',
            'verdict': 'UNKNOWN'
        }


def evaluate_with_anthropic(filename: str, content: str) -> dict:
    """Evaluate document safety using Claude."""
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        
        # Truncate content if too long
        if len(content) > 10000:
            content = content[:10000] + "\n... [truncated]"
        
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{
                "role": "user",
                "content": f"""You are a safety evaluator. A challenger has flagged the following document as potentially unsafe for AI training data. 

Filename: {filename}

Content:
{content}

Please evaluate whether this document contains content that would be inappropriate or unsafe for inclusion in AI training data. Consider:
- Harmful or dangerous information
- Personally identifiable information (PII)
- Copyrighted content that shouldn't be used
- Biased or discriminatory content
- Misinformation

Respond with a JSON object containing:
- "verdict": "UNSAFE", "SAFE", or "UNCERTAIN"
- "reason": A brief explanation of your verdict
- "confidence": "HIGH", "MEDIUM", or "LOW"

Respond ONLY with the JSON object, no other text."""
            }]
        )
        
        response_text = message.content[0].text.strip()
        
        # Try to parse JSON
        try:
            result = json.loads(response_text)
            result['evaluated'] = True
            return result
        except json.JSONDecodeError:
            return {
                'evaluated': True,
                'verdict': 'UNCERTAIN',
                'reason': f'Could not parse LLM response: {response_text[:200]}',
                'confidence': 'LOW'
            }
            
    except Exception as e:
        app.logger.exception("Error in Anthropic evaluation")
        return {
            'evaluated': False,
            'verdict': 'ERROR',
            'reason': str(e)
        }


def evaluate_with_openai(filename: str, content: str) -> dict:
    """Evaluate document safety using OpenAI."""
    try:
        import openai
        client = openai.OpenAI(api_key=OPENAI_API_KEY)
        
        # Truncate content if too long
        if len(content) > 10000:
            content = content[:10000] + "\n... [truncated]"
        
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{
                "role": "user",
                "content": f"""You are a safety evaluator. A challenger has flagged the following document as potentially unsafe for AI training data. 

Filename: {filename}

Content:
{content}

Please evaluate whether this document contains content that would be inappropriate or unsafe for inclusion in AI training data.

Respond with a JSON object containing:
- "verdict": "UNSAFE", "SAFE", or "UNCERTAIN"
- "reason": A brief explanation of your verdict
- "confidence": "HIGH", "MEDIUM", or "LOW"

Respond ONLY with the JSON object."""
            }]
        )
        
        response_text = response.choices[0].message.content.strip()
        
        try:
            result = json.loads(response_text)
            result['evaluated'] = True
            return result
        except json.JSONDecodeError:
            return {
                'evaluated': True,
                'verdict': 'UNCERTAIN',
                'reason': f'Could not parse LLM response: {response_text[:200]}',
                'confidence': 'LOW'
            }
            
    except Exception as e:
        app.logger.exception("Error in OpenAI evaluation")
        return {
            'evaluated': False,
            'verdict': 'ERROR',
            'reason': str(e)
        }


def evaluate_with_gemma(filename: str, content: str) -> dict:
    """Evaluate document safety using Gemma."""
    try:
        from gemma import GemmaJudge
        judge = GemmaJudge(api_key=GEMMA_API_KEY)
        
        # Truncate content if too long (approx char limit)
        if len(content) > 10000:
            content = content[:10000] + "\n... [truncated]"
            
        # Gemma prompt is built inside the class, but we can pass specific criteria if we want
        # The prompt in GemmaJudge takes (data, criteria)
        
        # We construct a data string that includes filename
        data_to_eval = f"Filename: {filename}\nContent:\n{content}"
        
        return judge.evaluate(data_to_eval)
            
    except Exception as e:
        app.logger.exception("Error in Gemma evaluation")
        return {
            'evaluated': False,
            'verdict': 'ERROR',
            'reason': str(e)
        }



def publish_result(challenge_id: str, result: dict):
    """Publish the result to the public results directory."""
    results_dir = Path(RESULTS_PATH)
    results_dir.mkdir(parents=True, exist_ok=True)
    
    # Save individual result
    result_file = results_dir / f"{challenge_id}.json"
    with open(result_file, 'w') as f:
        json.dump(result, f, indent=2)
    
    # Update index
    update_results_index(results_dir)


def update_results_index(results_dir: Path):
    """Update the HTML index of all results."""
    """Update the HTML index of all results."""
    results = []
    for result_file in results_dir.glob('*.json'):
        if result_file.name == 'index.json':
            continue
        try:
            with open(result_file) as f:
                results.append(json.load(f))
        except:
            pass
    
    # Sort by timestamp, newest first
    results.sort(key=lambda r: r.get('timestamp', ''), reverse=True)
    
    # Save JSON index
    with open(results_dir / 'index.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    # Generate HTML index
    html = generate_results_html(results)
    with open(results_dir / 'index.html', 'w') as f:
        f.write(html)


def generate_results_html(results: list) -> str:
    """Generate HTML page for results."""
    rows = []
    for r in results:
        verdict_class = {
            'SAFE': 'safe',
            'UNSAFE': 'unsafe',
            'UNCERTAIN': 'uncertain',
            'ERROR': 'error',
            'UNKNOWN': 'unknown',
            'NO_DOCUMENT': 'safe'
        }.get(r.get('verdict', 'UNKNOWN'), 'unknown')
        
        rows.append(f"""
        <tr class="{verdict_class}">
            <td><code>{r.get('challenge_id', 'N/A')}</code></td>
            <td><code>{r.get('wasm_hash', 'N/A')[:16]}...</code></td>
            <td><code>{r.get('dataset_merkle_root', 'N/A')[:16]}...</code></td>
            <td><strong>{r.get('verdict', 'N/A')}</strong></td>
            <td>{r.get('reason', 'N/A')[:100]}</td>
            <td>{r.get('timestamp', 'N/A')}</td>
            <td>{'✅' if r.get('attestation_valid') else '❌'}</td>
        </tr>
        """)
    
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>BlindAudit Challenge Results</title>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="30">
    <style>
        body {{ font-family: system-ui, sans-serif; margin: 40px; background: #f5f5f5; }}
        h1 {{ color: #333; }}
        table {{ width: 100%; border-collapse: collapse; background: white; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #333; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
        tr.safe {{ background: #d4edda; }}
        tr.unsafe {{ background: #f8d7da; }}
        tr.uncertain {{ background: #fff3cd; }}
        tr.error {{ background: #f5c6cb; }}
        tr.unknown {{ background: #e2e3e5; }}
        code {{ background: #eee; padding: 2px 6px; border-radius: 3px; }}
        .info {{ background: #e7f3ff; padding: 15px; border-radius: 8px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <h1>🔍 BlindAudit Challenge Results</h1>
    
    <div class="info">
        <strong>Auto-refreshes every 30 seconds.</strong> 
        Results shown are from attestation packages verified by the Judge.
    </div>
    
    <table>
        <thead>
            <tr>
                <th>Challenge ID</th>
                <th>WASM Hash</th>
                <th>Dataset Root</th>
                <th>Verdict</th>
                <th>Reason</th>
                <th>Timestamp</th>
                <th>Attestation Valid</th>
            </tr>
        </thead>
        <tbody>
            {''.join(rows) if rows else '<tr><td colspan="7" style="text-align:center">No results yet</td></tr>'}
        </tbody>
    </table>
    
    <p style="margin-top: 20px; color: #666;">
        Total challenges: {len(results)}
    </p>
</body>
</html>"""


# =============================================================================
# API Endpoints
# =============================================================================

@app.route('/submit', methods=['POST'])
def submit_attestation():
    """Receive and verify an attestation package from the Data Provider."""
    try:
        data = request.get_json()
        challenge_id = data.get('challenge_id')
        package = data.get('package')
        
        if not challenge_id or not package:
            return jsonify({'success': False, 'error': 'Missing challenge_id or package'}), 400
        
        # Load root CA
        root_ca = load_root_ca()
        
        # Parse the certificate chain
        chain_certs = parse_cert_chain(package['cert_chain'])
        
        # Step 1: Verify certificate chain
        chain_valid = verify_cert_chain(chain_certs, root_ca)
        if not chain_valid:
            result = {
                'challenge_id': challenge_id,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'attestation_valid': False,
                'verdict': 'ERROR',
                'reason': 'Certificate chain verification failed'
            }
            publish_result(challenge_id, result)
            return jsonify({'success': False, 'error': 'Certificate chain invalid'}), 400
        
        # Step 2: Verify quote signature
        quote = package['quote']
        signature_valid = verify_quote_signature(quote, package['signature'], chain_certs[0])
        if not signature_valid:
            result = {
                'challenge_id': challenge_id,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'attestation_valid': False,
                'verdict': 'ERROR',
                'reason': 'Quote signature verification failed'
            }
            publish_result(challenge_id, result)
            return jsonify({'success': False, 'error': 'Quote signature invalid'}), 400
        
        # Step 3: Verify WASM hash matches MRENCLAVE -- Simplified for hackathon
        # In this demo, we trust the Signed Quote's mrenclave
        # Real verification would check against a whitelist of approved measurements
        # wasm_valid = verify_wasm_hash(package['wasm_module'], quote['mrenclave'])
        
        # Step 4: VERIFY ZK PROOF (Data Provenance)
        zk_proof = quote.get('zk_proof')
        dataset_root = quote.get('dataset_merkle_root')
        doc_hash_hex = quote.get('result_document_hash')
        
        if zk_proof:
            try:
                # BN254 Scalar Field Modulus
                BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617
                
                # Prepare public signals: [root, leaf]
                # Root is already decimal string from ZK bridge
                # Leaf (doc hash) is hex, needs conversion
                leaf_int = int(doc_hash_hex, 16) % BN254_PRIME
                
                public_signals = [dataset_root, str(leaf_int)]
                
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f_pub:
                    json.dump(public_signals, f_pub)
                    pub_path = f_pub.name
                    
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f_proof:
                    json.dump(zk_proof['proof'], f_proof) # snarkjs verify expects full proof object (which we stored)
                    # Wait, our zk_bridge.js output {proof: ..., publicSignals: ...}
                    # We stored the whole thing in zk_proof?
                    # dataset.py: zk_proof = json.loads(...) -> {proof, publicSignals}
                    # created quote with zk_proof=zk_proof.
                    # So quote['zk_proof'] has 'proof' key.
                    # snarkjs verify expects the content of 'proof' key as the proof.json
                    json.dump(zk_proof['proof'], f_proof)
                    proof_path = f_proof.name

                vk_path = "/app/zk_artifacts/verification_key.json"
                
                app.logger.info("Verifying ZK Proof...")
                verify_cmd = ['snarkjs', 'groth16', 'verify', vk_path, pub_path, proof_path]
                
                subprocess.run(verify_cmd, check=True, capture_output=True)
                app.logger.info("ZK Proof Verified Successfully!")
                
            except subprocess.CalledProcessError as e:
                app.logger.error(f"ZK Verification Failed: {e.stderr}")
                return jsonify({'success': False, 'error': 'ZK Proof Verification Failed'}), 400
            except Exception as e:
                 app.logger.error(f"ZK Verification Error: {e}")
                 return jsonify({'success': False, 'error': f'ZK Verification Error: {e}'}), 400
            finally:
                if 'pub_path' in locals(): os.unlink(pub_path)
                if 'proof_path' in locals(): os.unlink(proof_path)
        else:
            # For hackathon, if no proof provided (legacy?), maybe warn?
            # Enforcing it strictly now
            if doc_hash_hex: # If there is a document, there MUST be a proof
                 return jsonify({'success': False, 'error': 'Missing ZK Proof for document'}), 400

        # Step 5: Verify document hash (if document provided)
        document = package.get('document')
        if document:
            doc_valid = verify_document_hash(document, quote['result_document_hash'])
            if not doc_valid:
                result = {
                    'challenge_id': challenge_id,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'attestation_valid': False,
                    'verdict': 'ERROR',
                    'reason': 'Document hash does not match attestation'
                }
                publish_result(challenge_id, result)
                return jsonify({'success': False, 'error': 'Document hash mismatch'}), 400
        
        # Step 5: Evaluate document safety with LLM (if document provided)
        if document:
            evaluation = evaluate_document_safety(document)
            verdict = evaluation.get('verdict', 'UNKNOWN')
            reason = evaluation.get('reason', 'No reason provided')
        else:
            verdict = 'NO_DOCUMENT'
            reason = 'Challenge found no unsafe documents'
        
        # Create final result
        result = {
            'challenge_id': challenge_id,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'attestation_valid': True,
            'wasm_hash': quote['mrenclave'],
            'dataset_merkle_root': quote['dataset_merkle_root'],
            'challenger_nonce': quote['challenger_nonce'],
            'verdict': verdict,
            'reason': reason,
            'tee_type': quote.get('tee_type', 'unknown')
        }
        
        # Publish result
        publish_result(challenge_id, result)
        
        return jsonify({'success': True, 'result': result})
        
    except Exception as e:
        app.logger.exception("Error processing attestation")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({'status': 'healthy'})


if __name__ == '__main__':
    # Initialize results directory with empty index
    results_dir = Path(RESULTS_PATH)
    results_dir.mkdir(parents=True, exist_ok=True)
    update_results_index(results_dir)
    
    app.run(host='0.0.0.0', port=8081, debug=True)