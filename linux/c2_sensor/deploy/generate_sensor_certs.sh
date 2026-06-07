#!/usr/bin/env bash

set -euo pipefail

CERTS_DIR="../certs"
CA_DIR="$CERTS_DIR/ca"

echo "[*] Initializing Secure CA Infrastructure..."
mkdir -p "$CA_DIR"

CA_KEY="$CA_DIR/ca.key"
CA_CERT="$CA_DIR/ca.crt"

if [ ! -f "$CA_CERT" ]; then
    echo "[*] Generating 4096-bit RSA Root CA Key..."
    openssl genrsa -out "$CA_KEY" 4096 2>/dev/null

    echo "[*] Generating Root CA Certificate..."
    openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 \
        -out "$CA_CERT" -subj "/C=US/ST=Cyber/L=Grid/O=C2-Authority/CN=C2 Root CA" 2>/dev/null
else
    echo "[+] Root CA already exists. Utilizing existing CA."
fi

SERVER_KEY="$CERTS_DIR/key.pem"
SERVER_CSR="$CERTS_DIR/sensor.csr"
SERVER_CERT="$CERTS_DIR/cert.pem"
EXT_FILE="$CERTS_DIR/v3.ext"

echo "[*] Generating 4096-bit RSA Sensor Key..."
openssl genrsa -out "$SERVER_KEY" 4096 2>/dev/null

echo "[*] Generating Certificate Signing Request (CSR)..."
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" \
    -subj "/C=US/ST=Cyber/L=Grid/O=C2-Sensor/CN=localhost" 2>/dev/null

echo "[*] Creating v3 Extensions for SAN support..."
cat > "$EXT_FILE" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

echo "[*] Signing Sensor Certificate with Root CA..."
openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" \
    -CAcreateserial -out "$SERVER_CERT" -days 365 -sha256 -extfile "$EXT_FILE" 2>/dev/null

chmod 644 "$SERVER_KEY" "$SERVER_CERT"
rm -f "$SERVER_CSR" "$EXT_FILE"

echo "[+] Cryptographic infrastructure successfully deployed to $CERTS_DIR/"