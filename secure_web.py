import json
import ssl
import urllib.parse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Tuple

from user_db import verify_user

BASE_DIR = Path(__file__).resolve().parent
CERT_DIR = BASE_DIR / "certs"
WEB_DIR = BASE_DIR / "web"

HOST = "0.0.0.0"
PORT = 9444


def create_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(
        certfile=str(CERT_DIR / "server.pem"), keyfile=str(CERT_DIR / "server.key")
    )
    context.load_verify_locations(cafile=str(CERT_DIR / "ca.pem"))
    context.verify_mode = ssl.CERT_OPTIONAL
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    return context


class LoginHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def do_POST(self) -> None:
        if self.path != "/login":
            self.send_error(404)
            return

        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        data = urllib.parse.parse_qs(body)
        username = data.get("username", [""])[0]
        password = data.get("password", [""])[0]

        ok, message = self._handle_login(username, password)
        response = {"ok": ok, "message": message}

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode("utf-8"))

    def _handle_login(self, username: str, password: str) -> Tuple[bool, str]:
        if not username or not password:
            return False, "需要填写用户名和密码"
        if verify_user(username, password):
            return True, "登录成功，TLS 已加密"
        return False, "用户名或密码错误"

    def log_message(self, format: str, *args) -> None:  # type: ignore[override]
        # Keep console output concise.
        print("[web]", self.address_string(), format % args)


def main() -> None:
    context = create_ssl_context()
    httpd = ThreadingHTTPServer((HOST, PORT), LoginHandler)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print(f"HTTPS web UI running at https://localhost:{PORT} (self-signed CA)")
    print("Use certs/ca.pem to trust the certificate in your browser.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down web server...")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
