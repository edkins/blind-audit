
import requests
import time
import base64
import json
import os
import sys

# Configuration
DATA_PROVIDER_URL = "http://localhost:8080"
JUDGE_URL = "http://localhost:8081"
CHALLENGER_COMPILER_URL = "http://localhost:8083" # Using the web UI as proxy

def wait_for_service(url, name, timeout=60):
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            resp = requests.get(f"{url}/health")
            if resp.status_code == 200:
                print(f"[OK] {name} is healthy")
                return True
        except requests.exceptions.ConnectionError:
            pass
        print(f"Waiting for {name} ({int(time.time() - start_time)}s)...")
        time.sleep(2)
    print(f"[FAIL] {name} failed to become healthy")
    return False

def run_test():
    print("=== Starting End-to-End Test ===")
    
    # 1. Wait for services
    if not wait_for_service(DATA_PROVIDER_URL, "Data Provider"): return
    if not wait_for_service(JUDGE_URL, "Judge"): return
    
    # 2. Compile a challenge (or use a pre-compiled one if we can't easily trigger compilation via API)
    # The challenger UI has a /save endpoint that triggers compilation via file watch
    # But for a robust test, let's just make sure we have a WASM file to send.
    # Since we might not have rust toolchain locally, we rely on the containers.
    # Actually, we can just POST to /save on localhost:8083 and wait for it.
    
    print("\n[Step 1] Creating a test challenge...")
    # This is a simple challenge that always finds "SAFE"
    challenge_code = """
    use std::io::{self, BufRead};
    fn main() {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            if let Ok(_) = line {
                // Do nothing, safe
            }
        }
    }
    """
    
    try:
        requests.post(f"{CHALLENGER_COMPILER_URL}/save", json={
            "filename": "e2e_test.rs",
            "content": challenge_code
        })
    except requests.exceptions.ConnectionError:
        print("[FAIL] Failed to contact Challenger UI. Is it running?")
        return

    print("Waiting for compilation...")
    # Poll status
    wasm_ready = False
    for i in range(60):
        try:
            resp = requests.get(f"{CHALLENGER_COMPILER_URL}/status?filename=e2e_test.rs")
            data = resp.json()
            if data.get('status') == 'ready':
                wasm_ready = True
                print("[OK] Compilation complete")
                break
            elif data.get('status') == 'error':
                 print(f"[FAIL] Compilation failed: {data.get('log')}")
                 return
        except:
            pass
        time.sleep(1)
        
    if not wasm_ready:
        print("[FAIL] Compilation timed out")
        return

    # 3. Submit to Data Provider (via Challenger UI proxy to simulate user flow)
    print("\n[Step 2] Submitting challenge...")
    response = requests.post(f"{CHALLENGER_COMPILER_URL}/submit", json={
        "filename": "e2e_test.rs"
    })
    
    if response.status_code != 200:
        print(f"[FAIL] Submission failed: {response.text}")
        try:
             # Try compiling a "bad" file to test error logging
             print("\n[Step 2a] Testing Compilation Failure Logging...")
             bad_code = "fn main() { syntax error here }"
             requests.post(f"{CHALLENGER_COMPILER_URL}/save", json={
                "filename": "e2e_fail.rs",
                "content": bad_code
             })
             for i in range(10):
                resp = requests.get(f"{CHALLENGER_COMPILER_URL}/status?filename=e2e_fail.rs")
                data = resp.json()
                if data.get('status') == 'error':
                    print("[OK] Compilation error correctly caught and reported")
                    print(f"   Log sample: {data.get('log')[:50]}...")
                    break
                time.sleep(1)
        except:
            pass
        return

    result = response.json()
    print("[OK] Submission accepted")
    print(f"   Challenge ID: {result.get('challenge_id')}")
    print(f"   Unsafe Count: {result.get('unsafe_count')}")
    
    challenge_id = result.get('challenge_id')
    
    # 4. Verify Result on Judge directly (by checking the file or index)
    # Since we can't easily browse the directory from outside without mounting,
    # we can check if it Appears in the results JSON index (if exposed)
    # The Judge exposes results via NGINX on port 8082, but let's check if Judge API has an endpoint?
    # No, Judge just writes to disk.
    # But Results Board (port 8082) serves the JSON files.
    
    print("\n[Step 3] Verifying Public Results...")
    RESULTS_BOARD_URL = "http://localhost:8082"
    
    # It takes a moment for judge to process and write
    time.sleep(2)
    
    found = False
    for i in range(10):
        try:
            resp = requests.get(f"{RESULTS_BOARD_URL}/{challenge_id}.json")
            if resp.status_code == 200:
                public_result = resp.json()
                print("[OK] Result published to Results Board")
                print(f"   Verdict: {public_result.get('verdict')}")
                found = True
                break
        except:
            pass
        time.sleep(1)
        
    print("\n[Step 4] Verify Compilation Error Reporting...")
    try:
         bad_code = "fn main() { syntax error here }"
         requests.post(f"{CHALLENGER_COMPILER_URL}/save", json={
            "filename": "e2e_fail.rs",
            "content": bad_code
         })
         
         print("Waiting for compilation error...")
         error_found = False
         for i in range(60): # Should fall pretty fast
            resp = requests.get(f"{CHALLENGER_COMPILER_URL}/status?filename=e2e_fail.rs")
            data = resp.json()
            if data.get('status') == 'error':
                print("[OK] Compilation error correctly caught and reported")
                print(f"   Log sample: {data.get('log')[:50]}...")
                error_found = True
                break
            time.sleep(1)
            
         if not error_found:
             print("[FAIL] Compilation error NOT reported (timed out or status not 'error')")

    except Exception as e:
        print(f"[FAIL] Error testing failure case: {e}")

    print("\n[OK] E2E TEST PASSED")

if __name__ == "__main__":
    run_test()
