#!/usr/bin/env bash
# generate_dashboard_certs.sh (Located inside dashboard/)
# Implements a local Certificate Authority (CA) with v3 extensions

set -euo pipefail

# Resolve script directory to ensure certs stay inside dashboard/certs/
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CERTS_DIR="$SCRIPT_DIR/certs"
CA_DIR="$CERTS_DIR/ca"

echo "[*] Initializing Secure Certificate Authority Infrastructure in $CERTS_DIR..."
mkdir -p "$CA_DIR"

# ==========================================
# 1. Root Certificate Authority (CA)
# ==========================================
CA_KEY="$CA_DIR/ca.key"
CA_CERT="$CA_DIR/ca.crt"

if [ ! -f "$CA_CERT" ]; then
    echo "[*] Generating 4096-bit RSA Root CA Key..."
    openssl genrsa -out "$CA_KEY" 4096 2>/dev/null

    echo "[*] Generating Root CA Certificate (Valid for 10 years)..."
    openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 \
        -out "$CA_CERT" -subj "/C=US/ST=Cyber/L=Grid/O=Sentinel-Authority/CN=Sentinel Root CA" 2>/dev/null
else
    echo "[+] Root CA already exists. Utilizing existing CA for signing operations."
fi

# ==========================================
# 2. Server Certificate Generation
# ==========================================
SERVER_KEY="$CERTS_DIR/dashboard_key.pem"
SERVER_CSR="$CERTS_DIR/dashboard.csr"
SERVER_CERT="$CERTS_DIR/dashboard_cert.pem"
EXT_FILE="$CERTS_DIR/v3.ext"

echo "[*] Generating 4096-bit RSA Server Key..."
openssl genrsa -out "$SERVER_KEY" 4096 2>/dev/null

echo "[*] Generating Certificate Signing Request (CSR)..."
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" \
    -subj "/C=US/ST=Cyber/L=Grid/O=Sentinel-Forensics/CN=localhost" 2>/dev/null

echo "[*] Creating v3 Extensions Configuration for SAN support..."
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

echo "[*] Signing Server Certificate with Root CA (Valid for 1 year)..."
openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" \
    -CAcreateserial -out "$SERVER_CERT" -days 365 -sha256 -extfile "$EXT_FILE" 2>/dev/null

# ==========================================
# 3. Cleanup & Security Permissions
# ==========================================
echo "[*] Enforcing strict key permissions..."
chmod 600 "$CA_KEY"

chown 10001:10001 "$SERVER_KEY"
chmod 600 "$SERVER_KEY"

chown 10001:10001 "$SERVER_CERT"
chmod 644 "$SERVER_CERT"

rm -f "$SERVER_CSR" "$EXT_FILE"

echo "=================================================================="
echo "[+] Cryptographic infrastructure successfully deployed."
echo "    Output Directory: $CERTS_DIR/"
echo "=================================================================="