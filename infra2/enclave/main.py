#!/usr/bin/env python3
"""
Nitro Enclave application.

This runs in complete isolation inside the enclave.
Communication with the outside world is only via vsock.
"""

import socket

# vsock constants
VSOCK_PORT = 5000
VMADDR_CID_ANY = 0xFFFFFFFF  # Listen on any CID


def main():
    print("Starting enclave application...")

    # Create vsock socket
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.bind((VMADDR_CID_ANY, VSOCK_PORT))
    sock.listen(5)

    print(f"Listening on vsock port {VSOCK_PORT}")

    while True:
        conn, addr = sock.accept()
        print(f"Connection from CID {addr[0]}")

        try:
            data = conn.recv(4096)
            if data:
                # TODO: Process the request
                # This is where your enclave logic goes
                response = b"Hello from enclave!"
                conn.sendall(response)
        finally:
            conn.close()


if __name__ == "__main__":
    main()
