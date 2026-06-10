#!/bin/bash
# ==============================================================================
# Sentinel Nexus -- Immutable Build Pipeline (Static / musl)
# ==============================================================================
# Target: x86_64-unknown-linux-musl (Zero-Dependency Static Binaries)
# ==============================================================================
set -e

C_CYAN="\033[1;36m"
C_GREEN="\033[1;32m"
C_YELLOW="\033[1;33m"
C_RED="\033[1;31m"
C_RESET="\033[0m"

echo -e "${C_CYAN}[*] Initializing Sentinel Nexus Deterministic Build Pipeline${C_RESET}"

# 1. Enforce musl for static compilation
if ! command -v cargo &> /dev/null; then
    echo -e "${C_RED}[!] Cargo not found. Please install Rust securely via your system's package manager or official channels.${C_RESET}"
    exit 1
fi

echo -e "${C_CYAN}[*] Ensuring x86_64-unknown-linux-musl (static) target is installed...${C_RESET}"
rustup target add x86_64-unknown-linux-musl

# 2. Clean Workspace
if [ "$1" == "--clean" ]; then
    echo -e "${C_CYAN}[*] Cleaning workspace...${C_RESET}"
    cargo clean
fi

# 3. Compile Statically
echo -e "${C_GREEN}[*] Compiling Release Workspace (Statically Linked)...${C_RESET}"
# Note: Requires 'musl-tools' installed on the build runner
cargo build --release --workspace --target x86_64-unknown-linux-musl

# 4. Stage Artifacts
echo -e "${C_CYAN}[*] Staging artifacts to ./dist/...${C_RESET}"
mkdir -p dist/

# Strip debug symbols to minimize binary size and prevent reverse engineering
STRIP_CMD=$(command -v x86_64-linux-musl-strip || command -v strip || echo "true")

for bin in core_ingress worker_qdrant worker_s3_archive worker_rules worker_soar worker_rlhf; do
    if [ -f "target/x86_64-unknown-linux-musl/release/$bin" ]; then
        cp "target/x86_64-unknown-linux-musl/release/$bin" dist/
        $STRIP_CMD "dist/$bin" 2>/dev/null || true
    fi
done

cp services/config/nexus.toml dist/

echo -e "${C_GREEN}[+] Build complete. Zero-dependency static artifacts staged in ./dist/${C_RESET}"