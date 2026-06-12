#!/bin/bash
# Generate a self-signed cert for the mock Nexus ingress, valid for the compose
# service name `mock-ingress` (the gateway verifies the SAN over rustls). The same
# PEM is mounted into the gateway as the trusted CA (nexus.tls.ca_path).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS="$HERE/certs"
mkdir -p "$CERTS"

if [ -f "$CERTS/mock-cert.pem" ] && [ -f "$CERTS/mock-key.pem" ]; then
    echo "certs already present"
    exit 0
fi

# basicConstraints=CA:TRUE + serverAuth EKU so rustls (the gateway's TLS stack)
# accepts this self-signed cert BOTH as the trusted root (add_root_certificate)
# and as the server leaf it then validates.
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$CERTS/mock-key.pem" \
    -out "$CERTS/mock-cert.pem" \
    -days 365 -subj "/CN=mock-ingress" \
    -addext "subjectAltName=DNS:mock-ingress,DNS:localhost" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,keyCertSign" \
    -addext "extendedKeyUsage=serverAuth"
echo "generated $CERTS/mock-cert.pem (+ key)"
