import time
import requests
import json
import base64
from pathlib import Path

BASE_URL_PROVIDER = "http://localhost:8080"
BASE_URL_JUDGE = "http://localhost:8081"
BASE_URL_RESULTS = "http://localhost:8082"

def wait_for_services():
    print("Waiting for services...")
    for url in [BASE_URL_PROVIDER, BASE_URL_JUDGE]:
        for i in range(30):
            try:
                requests.get(f"{url}/health")
                break
            except:
                time.sleep(1)
        else:
            raise Exception(f"Service {url} not reachable")
    print("Services are up!")

def submit_challenge(wasm_path):
    print(f"Submitting challenge from {wasm_path}...")
    with open(wasm_path, 'rb') as f:
        files = {'wasm': f}
        data = {'nonce': 'test_nonce_' + str(time.time())}
        response = requests.post(f"{BASE_URL_PROVIDER}/challenge", files=files, data=data)
    
    if response.status_code != 200:
        print(f"Submission failed: {response.text}")
        return None
    
    return response.json()

def check_judge_result(challenge_id):
    print(f"Checking judge result for {challenge_id}...")
    # Results are published to a static file or we can query judge logs?
    # Judge doesn't have an API to get result by ID (except static JSONs).
    # We can check the Results Board URL: http://localhost:8082/{challenge_id}.json
    
    url = f"{BASE_URL_RESULTS}/{challenge_id}.json"
    for i in range(10):
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        time.sleep(1)
    
    print("Result not found on board")
    return None

def main():
    wait_for_services()
    
    # 1. Compile WASM (if not already?)
    # We assume 'compiled-wasm/pii_detector.wasm' exists (volume mounted from challenger-compiler)
    wasm_path = Path("compiled-wasm/pii_detector.wasm")
    if not wasm_path.exists():
        print("WASM not found! Waiting for compiler...")
        # Try waiting a bit
        time.sleep(10)
        if not wasm_path.exists():
             # Fallback: look in local dir if running locally?
             print("Please ensure pii_detector.wasm is built.")
             return

    # 2. Submit Challenge
    result = submit_challenge(wasm_path)
    if not result:
        print("Test Failed at submission")
        exit(1)
    
    challenge_id = result['challenge_id']
    quote = result['quote']
    
    print(f"Challenge ID: {challenge_id}")
    
    # 3. Check for ZK Proof in Quote (Client side check)
    if 'zk_proof' in quote and quote['zk_proof']:
        print("✅ ZK Proof present in quote")
    else:
        # PII detector should find unsafe docs
        if result['unsafe_count'] > 0:
            print("❌ ZK Proof MISSING despite unsafe docs found!")
            exit(1)
        else:
            print("⚠️ No unsafe docs found, so no ZK proof expected.")

    # 4. Check Judge Verdict
    judge_result = check_judge_result(challenge_id)
    if not judge_result:
        print("❌ Judge result not published")
        exit(1)
        
    print(f"Judge Verdict: {judge_result.get('verdict')}")
    print(f"Attestation Valid: {judge_result.get('attestation_valid')}")
    
    if judge_result.get('attestation_valid') is True:
        print("✅ Attestation Verified (Including ZK Proof)")
    else:
        print("❌ Attestation Verification Failed")
        print(f"Reason: {judge_result.get('reason')}")
        exit(1)

if __name__ == "__main__":
    main()
