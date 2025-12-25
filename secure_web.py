import json
import ssl
import urllib.parse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Tuple

from user_db import verify_user_with_hashes

BASE_DIR = Path(__file__).resolve().parent
CERT_DIR = BASE_DIR / "certs"
WEB_DIR = BASE_DIR / "web"

HOST = "0.0.0.0"
PORT = 9444


def create_ssl_context() -> ssl.SSLContext:
    certfile = CERT_DIR / "server.pem"
    keyfile = CERT_DIR / "server.key"
    cafile = CERT_DIR / "ca.pem"

    missing = [p for p in (certfile, keyfile, cafile) if not p.exists()]
    if missing:
        missing_list = ", ".join(p.name for p in missing)
        raise FileNotFoundError(
            f"缺少证书文件: {missing_list}。请先在仓库根目录运行 ./certs/gen_certs.sh 生成自签名证书。"
        )

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
    context.load_verify_locations(cafile=str(cafile))
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

        ok, message, hashes = self._handle_login(username, password)
        response = {"ok": ok, "message": message}
        if hashes:
            response.update(hashes)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode("utf-8"))

    def _handle_login(self, username: str, password: str) -> Tuple[bool, str, dict | None]:
        if not username or not password:
            return False, "需要填写用户名和密码", None

        ok, details = verify_user_with_hashes(username, password)
        if ok:
            return True, "登录成功，TLS 已加密，并返回哈希结果", details
        return False, details.get("error", "用户名或密码错误"), None

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
