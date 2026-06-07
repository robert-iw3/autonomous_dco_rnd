#!/bin/bash
set -euo pipefail

CA_NAME="${AUTHORITY_NAME:-Falco_CA}"
CA_PASS="${AUTHORITY_PASSWORD:-changeme}"
COMPANY="${COMPANY:-sentinel-nexus}"
DOMAIN="${DOMAIN_NAME:-falco.internal.local}"
COUNTRY="${COUNTRY_CODE:-US}"
STATE="${STATE:-VA}"
CITY="${CITY:-Site54}"
DAYS="${CERT_DAYS:-365}"
KEY_SIZE="${KEY_SIZE:-4096}"
OUT="/certs"

mkdir -p "$OUT"

if [ -f "$OUT/falco.pem" ] && [ -f "$OUT/sidekick.pem" ]; then
    echo "[certs] Certificates already exist. Skipping generation."
    exit 0
fi

echo "[certs] Generating PKI for ${DOMAIN} (${KEY_SIZE}-bit, ${DAYS} days)"

SUBJ="/C=${COUNTRY}/ST=${STATE}/L=${CITY}/O=${COMPANY}"

# -- 1. Certificate Authority -------------------------------------------------
echo "[certs] Creating CA: ${CA_NAME}"
openssl genrsa -aes256 -passout "pass:${CA_PASS}" -out "$OUT/ca.key" "$KEY_SIZE" 2>/dev/null
openssl req -new -x509 -days "$DAYS" -key "$OUT/ca.key" -passin "pass:${CA_PASS}" \
    -out "$OUT/ca.pem" -subj "${SUBJ}/CN=${CA_NAME}" 2>/dev/null

# -- 2. Falco Server Certificate (for webserver SSL) --------------------------
echo "[certs] Creating Falco server cert"
openssl genrsa -out "$OUT/falco_rsa.key.pem" "$KEY_SIZE" 2>/dev/null
openssl req -new -key "$OUT/falco_rsa.key.pem" \
    -out "$OUT/falco.csr" -subj "${SUBJ}/CN=falco" 2>/dev/null

cat > "$OUT/falco_ext.cnf" << EOF
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = falco
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -days "$DAYS" -in "$OUT/falco.csr" \
    -CA "$OUT/ca.pem" -CAkey "$OUT/ca.key" -passin "pass:${CA_PASS}" \
    -CAcreateserial -out "$OUT/falco.pem" \
    -extfile "$OUT/falco_ext.cnf" -extensions v3_req 2>/dev/null

cat "$OUT/falco_rsa.key.pem" "$OUT/falco.pem" > "$OUT/falco_bundle.pem"

# -- 3. Sidekick Server Certificate (for TLS server mode) ---------------------
echo "[certs] Creating Sidekick server cert"
openssl genrsa -out "$OUT/sidekick_rsa.key.pem" "$KEY_SIZE" 2>/dev/null
openssl req -new -key "$OUT/sidekick_rsa.key.pem" \
    -out "$OUT/sidekick.csr" -subj "${SUBJ}/CN=sidekick" 2>/dev/null

cat > "$OUT/sidekick_ext.cnf" << EOF
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = sidekick
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -days "$DAYS" -in "$OUT/sidekick.csr" \
    -CA "$OUT/ca.pem" -CAkey "$OUT/ca.key" -passin "pass:${CA_PASS}" \
    -CAcreateserial -out "$OUT/sidekick.pem" \
    -extfile "$OUT/sidekick_ext.cnf" -extensions v3_req 2>/dev/null

cat "$OUT/sidekick.pem" "$OUT/ca.pem" > "$OUT/sidekick_chain.pem"

# -- 4. Cleanup CSRs and temp files -------------------------------------------
rm -f "$OUT"/*.csr "$OUT"/*.cnf "$OUT"/*.srl

chmod 644 "$OUT"/*.pem
chmod 600 "$OUT"/*key*.pem "$OUT"/ca.key

echo "[certs] PKI generation complete:"
ls -la "$OUT"