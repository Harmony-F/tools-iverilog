import json
import socket
import ssl
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
CERT_DIR = BASE_DIR / "certs"
HOST = "localhost"
PORT = 9443


def create_ssl_context() -> ssl.SSLContext:
    certfile = CERT_DIR / "client.pem"
    keyfile = CERT_DIR / "client.key"
    cafile = CERT_DIR / "ca.pem"

    missing = [p for p in (certfile, keyfile, cafile) if not p.exists()]
    if missing:
        missing_list = ", ".join(p.name for p in missing)
        raise FileNotFoundError(
            f"缺少证书文件: {missing_list}。请先在仓库根目录运行 ./certs/gen_certs.sh 生成自签名证书。"
        )

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(cafile))
    context.check_hostname = True
    context.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    return context


def login_and_send(username: str, password: str, message: str) -> None:
    context = create_ssl_context()
    with socket.create_connection((HOST, PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=HOST) as tls:
            login_payload = json.dumps({"username": username, "password": password}).encode("utf-8")
            tls.sendall(login_payload)
            response = json.loads(tls.recv(4096).decode("utf-8"))
            print("Server response:", response)
            if not response.get("ok"):
                return
            tls.sendall(json.dumps({"message": message}).encode("utf-8"))
            reply = json.loads(tls.recv(4096).decode("utf-8"))
            print("Encrypted echo from server:", reply)


if __name__ == "__main__":
    login_and_send("demo", "password123", "Hello over TLS + AES-GCM!")
