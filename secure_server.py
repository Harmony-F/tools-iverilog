import json
import socket
import ssl
from pathlib import Path
from typing import Tuple

from user_db import verify_user

BASE_DIR = Path(__file__).resolve().parent
CERT_DIR = BASE_DIR / "certs"


HOST = "0.0.0.0"
PORT = 9443


def create_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(
        certfile=str(CERT_DIR / "server.pem"), keyfile=str(CERT_DIR / "server.key")
    )
    context.load_verify_locations(cafile=str(CERT_DIR / "ca.pem"))
    context.verify_mode = ssl.CERT_OPTIONAL
    # Favor strong AEAD ciphers provided by OpenSSL (e.g., AES-256-GCM)
    context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    return context


def handle_login(data: dict) -> Tuple[bool, str]:
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return False, "Username and password required"
    if verify_user(username, password):
        return True, "Login successful"
    return False, "Invalid credentials"


def handle_client(connection: ssl.SSLSocket, address: Tuple[str, int]) -> None:
    print(f"[*] Client connected: {address}")
    try:
        payload = connection.recv(4096)
        data = json.loads(payload.decode("utf-8"))
        success, message = handle_login(data)
        response = {"ok": success, "message": message}
        connection.sendall(json.dumps(response).encode("utf-8"))
        if not success:
            return
        # Once authenticated, echo encrypted payloads back to client.
        while True:
            payload = connection.recv(4096)
            if not payload:
                break
            try:
                data = json.loads(payload.decode("utf-8"))
            except json.JSONDecodeError:
                break
            message_text = data.get("message", "")
            reply = {"echo": message_text}
            connection.sendall(json.dumps(reply).encode("utf-8"))
    finally:
        print(f"[*] Client disconnected: {address}")
        connection.close()


def main() -> None:
    context = create_ssl_context()
    with socket.create_server((HOST, PORT)) as server_sock:
        with context.wrap_socket(server_sock, server_side=True) as tls_server:
            print(f"Secure server listening on https://{HOST}:{PORT}")
            while True:
                client_conn, addr = tls_server.accept()
                handle_client(client_conn, addr)


if __name__ == "__main__":
    main()
