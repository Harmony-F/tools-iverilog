#!/usr/bin/env bash
set -euo pipefail
OUT_DIR="$(dirname "$0")"
cd "$OUT_DIR"

# Certificate Authority
openssl req -x509 -nodes -newkey rsa:4096 -days 3650 \
  -keyout ca.key -out ca.pem -subj "/C=US/ST=CA/L=Local/O=Example CA/OU=Edu/CN=Local-CA"

# Server certificate
openssl req -new -nodes -newkey rsa:4096 \
  -keyout server.key -out server.csr -subj "/C=US/ST=CA/L=Local/O=Secure Server/OU=Edu/CN=localhost"
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.pem -days 825 -sha256 -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

# Client certificate
openssl req -new -nodes -newkey rsa:4096 \
  -keyout client.key -out client.csr -subj "/C=US/ST=CA/L=Local/O=Client/OU=Edu/CN=client"
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out client.pem -days 825 -sha256

echo "Certificates generated under $(pwd)."
