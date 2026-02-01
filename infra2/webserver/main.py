#!/usr/bin/env python3
"""
Web server that runs on the EC2 instance and communicates with the Nitro Enclave.

The ALB forwards authenticated requests here. User identity is in the
x-amzn-oidc-identity and x-amzn-oidc-data headers.
"""

import os
import socket
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn

app = FastAPI(title="TEE Hackathon")

# Get enclave CID from environment (set by deploy script)
ENCLAVE_CID = int(os.environ.get("ENCLAVE_CID", 16))
VSOCK_PORT = 5000


def call_enclave(message: bytes) -> bytes:
    """Send a message to the enclave and get the response."""
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    try:
        sock.connect((ENCLAVE_CID, VSOCK_PORT))
        sock.sendall(message)
        response = sock.recv(4096)
        return response
    finally:
        sock.close()


@app.get("/health")
async def health():
    """Health check endpoint - no auth required (ALB uses this)."""
    return {"status": "healthy"}


@app.get("/")
async def root(request: Request):
    """Main endpoint - requires authentication via ALB/Cognito."""
    # Get user identity from ALB headers
    user_id = request.headers.get("x-amzn-oidc-identity", "unknown")

    return {
        "message": "Hello from TEE Hackathon!",
        "user_id": user_id,
        "enclave_cid": ENCLAVE_CID,
    }


@app.post("/enclave")
async def enclave_request(request: Request):
    """Send a request to the enclave."""
    user_id = request.headers.get("x-amzn-oidc-identity", "unknown")
    body = await request.body()

    try:
        response = call_enclave(body or b"ping")
        return {
            "user_id": user_id,
            "enclave_response": response.decode("utf-8", errors="replace"),
        }
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to communicate with enclave: {str(e)}"},
        )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
