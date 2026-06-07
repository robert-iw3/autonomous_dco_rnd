#!/usr/bin/env bash
# ==============================================================================
# Sentinel Nexus -- Local TLS Authority & Certificate Bootstrap
# Reads domains from nexus.conf. Idempotent -- safe to re-run.
# ==============================================================================

source "$(dirname "$0")/lib.sh"

log_step "TLS Certificate Bootstrap"
require_cmd openssl

DEST_DIR="$NEXUS_TLS_DIR"
DOMAINS=("$NEXUS_DOMAIN_N8N" "$NEXUS_DOMAIN_WEBUI" "$NEXUS_DOMAIN_SSO" "$NEXUS_DOMAIN_INGRESS")

# Remove duplicates
DOMAINS=($(printf '%s\n' "${DOMAINS[@]}" | sort -u))

# -- 1. Ensure destination directory --
if [[ ! -d "$DEST_DIR" ]]; then
    log_info "Creating ${DEST_DIR}..."
    sudo mkdir -p "$DEST_DIR"
    sudo chmod 700 "$DEST_DIR"
fi

# -- 2. Generate Root CA (idempotent) --
if [[ ! -f "$DEST_DIR/nexus-ca.crt" ]]; then
    log_info "Generating Root CA: ${NEXUS_CA_NAME}..."
    sudo openssl genrsa -out "$DEST_DIR/nexus-ca.key" "$NEXUS_TLS_CA_KEY_BITS"
    sudo openssl req -x509 -new -nodes \
        -key "$DEST_DIR/nexus-ca.key" \
        -sha256 -days "$NEXUS_TLS_DAYS_VALID" \
        -out "$DEST_DIR/nexus-ca.crt" \
        -subj "/C=US/ST=Nexus/L=CommandCenter/O=Sentinel/CN=${NEXUS_CA_NAME}"
    log_ok "Root CA generated."
else
    log_ok "Root CA already exists -- skipping."
fi

# -- 3. Generate per-domain certificates --
for DOMAIN in "${DOMAINS[@]}"; do
    BASENAME="${DOMAIN%%.*}"

    if [[ -f "$DEST_DIR/${BASENAME}.crt" ]] && [[ "${1:-}" != "--force" ]]; then
        log_ok "Certificate for ${DOMAIN} already exists -- skipping. Use --force to regenerate."
        continue
    fi

    log_info "Generating certificate for ${DOMAIN}..."

    sudo openssl genrsa -out "$DEST_DIR/${BASENAME}.key" "$NEXUS_TLS_CERT_KEY_BITS"

    sudo openssl req -new \
        -key "$DEST_DIR/${BASENAME}.key" \
        -out "$DEST_DIR/${BASENAME}.csr" \
        -subj "/C=US/ST=Nexus/L=CommandCenter/O=Sentinel/CN=${DOMAIN}"

    # SAN extension file
    local_ext=$(mktemp)
    cat > "$local_ext" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names

[alt_names]
DNS.1=${DOMAIN}
DNS.2=*.${DOMAIN}
EOF

    sudo openssl x509 -req \
        -in "$DEST_DIR/${BASENAME}.csr" \
        -CA "$DEST_DIR/nexus-ca.crt" \
        -CAkey "$DEST_DIR/nexus-ca.key" \
        -CAcreateserial \
        -out "$DEST_DIR/${BASENAME}.crt" \
        -days "$NEXUS_TLS_DAYS_VALID" \
        -sha256 \
        -extfile "$local_ext"

    sudo rm -f "$DEST_DIR/${BASENAME}.csr" "$local_ext"
    log_ok "Certificate signed for ${DOMAIN}"
done

# -- 4. Strict permissions --
sudo chmod 600 "$DEST_DIR"/*.key 2>/dev/null || true
sudo chmod 644 "$DEST_DIR"/*.crt 2>/dev/null || true

log_ok "TLS bootstrap complete."
log_info "Import ${DEST_DIR}/nexus-ca.crt into your OS/browser trusted root store to prevent SSL warnings."