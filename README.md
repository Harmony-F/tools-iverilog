# Secure TLS Demo using OpenSSL

This repository contains a minimal, OpenSSL-backed TLS client/server pair that demonstrates secure authentication and encrypted transport. It shows how to generate certificates, hash user credentials, and exchange encrypted messages using Python's `ssl` module (which is powered by OpenSSL).

## Features
- Certificate Authority, server, and client certificates generated with OpenSSL.
- TLS 1.2+ transport secured with AEAD ciphers (AES-GCM or ChaCha20-Poly1305).
- Username/password hashing with PBKDF2-HMAC-SHA256 before storage.
- Client verifies the server certificate chain; mutual authentication is enabled by loading a client certificate.

## Setup
1. Install Python 3.11+ and OpenSSL.
2. Generate certificates:
   ```bash
   ./certs/gen_certs.sh
   ```
3. Create a demo user (already present in `data/users.json`, but you can add more):
   ```bash
   python user_db.py alice s3cret
   ```

## Running the demo
Start the TLS server (listens on `:9443`):
```bash
python secure_server.py
```

In another terminal, run the client to authenticate and send a message:
```bash
python secure_client.py
```
The client validates the server certificate with `ca.pem`, performs login by hashing the provided password on the server side, and sends/receives data encrypted by TLS using strong symmetric ciphers negotiated by OpenSSL.

## 中文演示：证书生成、校验证书与密码哈希
下面以中文简述核心流程，便于快速验证安全链路的关键步骤。

### 1. 生成数字证书
使用 `certs/gen_certs.sh` 自动完成 CA、服务器与客户端证书的生成（包含私钥与签名）。
```bash
./certs/gen_certs.sh
```
生成的文件：
- `certs/ca.pem`：自建根证书，用于验证其他证书。
- `certs/server.pem` / `certs/server.key`：服务器证书与私钥。
- `certs/client.pem` / `certs/client.key`：客户端证书与私钥。

### 2. 校验证书正确性
利用 OpenSSL 的 `verify` 命令，明确看到服务器证书经过根证书链校验成功：
```bash
openssl verify -CAfile certs/ca.pem certs/server.pem
```
返回 `certs/server.pem: OK` 即表示服务器证书由同一 CA 签发且链路完整。客户端程序 `secure_client.py` 也会在 TLS 握手时加载同一 `ca.pem` 并开启主机名校验，若证书无效握手会直接失败。

### 3. 账号密码哈希存储与校验
运行下述命令创建或更新用户，密码会先通过 PBKDF2-HMAC-SHA256（含随机盐与多次迭代）计算后写入 `data/users.json`，而不会存储明文：
```bash
python user_db.py demo password123
```
数据格式示例（包含 `salt`、`iterations`、`hash` 字段）：
```json
{
  "demo": {
    "salt": "<随机盐>",
    "iterations": 120000,
    "hash": "<PBKDF2 结果>"
  }
}
```
服务器在处理登录时会对客户端提交的密码重复相同的 PBKDF2 计算，并用常数时间比较函数校验哈希，只有哈希一致才视为密码正确。

### 4. 端到端 TLS 加密与登录验证演示
打开两个终端：

1) **终端 A（服务器）**
```bash
python secure_server.py
```
启动后会监听 `0.0.0.0:9443` 并等待 TLS 握手与登录请求。

2) **终端 B（客户端）**
```bash
python secure_client.py
```
客户端会：
- 加载 `ca.pem` 验证服务器证书并校验主机名；
- 发送包含用户名/密码的 JSON，服务器端用 PBKDF2-HMAC-SHA256 哈希校验；
- 登录成功后，在已协商的 TLS 信道（如 AES-GCM）中继续收发加密消息。

预期输出示例：

终端 B（客户端）：
```
Server response: {'ok': True, 'message': 'Login successful'}
Encrypted echo from server: {'echo': 'Hello over TLS + AES-GCM!'}
```

终端 A（服务器）：
```
[*] Client connected: ('127.0.0.1', 39014)
[*] Client disconnected: ('127.0.0.1', 39014)
```

如果证书不受信或密码错误，TLS 握手或登录会失败，客户端不会收到成功回执，终端将提示错误信息。

### 5. 将系统嵌入浏览器页面（HTTPS）
想用浏览器验证同样的链路，可启动内置的 HTTPS Web 服务器并访问本地页面：

1) 启动 Web 端：
```bash
python secure_web.py
```

2) 浏览器访问 https://localhost:9444 ，若浏览器提示证书不受信，请将 `certs/ca.pem` 导入信任或选择继续访问（因证书为本地自签名）。

页面中输入用户名/密码（例如 `demo` / `password123`），提交后请求会在 TLS 信道中发送到本地服务器，由服务器用 PBKDF2-HMAC-SHA256 哈希校验并返回结果，状态文本会实时显示登录是否成功。

## Files
- `certs/gen_certs.sh` – OpenSSL commands to build a CA, server, and client certificates.
- `user_db.py` – PBKDF2-based password hashing and verification helper.
- `secure_server.py` – TLS server that verifies hashed credentials and echoes messages over the encrypted channel.
- `secure_client.py` – TLS client that validates the server certificate, authenticates, and exchanges encrypted data.
