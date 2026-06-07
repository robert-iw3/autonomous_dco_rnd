#!/bin/bash
# deploy/supply_chain_scan.sh
# Optional pre-build supply chain audit via GuardDog
# Run:  ./deploy/supply_chain_scan.sh
# From run.sh:  SCAN_DEPS=1 ./run.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RUNTIME="${CONTAINER_RUNTIME:-podman}"
RESULTS_DIR="${PROJECT_ROOT}/guarddog-results"
CONTAINER_NAME="c2-guarddog-scan"
TIMEOUT=120

G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; C='\033[0;36m'; N='\033[0m'

cleanup() { $RUNTIME rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

echo -e "${C}[SCAN]${N} Supply chain audit starting..."

if ! $RUNTIME image exists guarddog-scanner 2>/dev/null && \
   ! $RUNTIME image inspect guarddog-scanner >/dev/null 2>&1; then
    echo -e "${C}[SCAN]${N} Building guarddog scanner image..."
    $RUNTIME build -t guarddog-scanner -f "$SCRIPT_DIR/guarddog.Dockerfile" "$SCRIPT_DIR" -q
fi

mkdir -p "$RESULTS_DIR"

MANIFESTS=()
cd "$PROJECT_ROOT"
for f in $(find . -maxdepth 3 \
    \( -name "requirements*.txt" -o -name "poetry.lock" -o -name "Pipfile.lock" \
       -o -name "package-lock.json" -o -name "yarn.lock" -o -name "go.mod" \) \
    -not -path "*/node_modules/*" -not -path "*/.venv/*" 2>/dev/null); do
    MANIFESTS+=("$f")
done

if [ ${#MANIFESTS[@]} -eq 0 ]; then
    echo -e "${Y}[SCAN]${N} No dependency manifests found. Skipping."
    exit 0
fi

echo -e "${C}[SCAN]${N} Found ${#MANIFESTS[@]} manifest(s):"
for m in "${MANIFESTS[@]}"; do echo "         $m"; done

$RUNTIME run --rm -d --name "$CONTAINER_NAME" \
    -v "$PROJECT_ROOT:/repo:ro,Z" \
    guarddog-scanner tail -f /dev/null >/dev/null

FINDINGS=0
for m in "${MANIFESTS[@]}"; do
    case "$(basename "$m")" in
        requirements*|poetry.lock|Pipfile.lock) ECO="pypi" ;;
        package-lock.json|yarn.lock|pnpm-lock.yaml) ECO="npm" ;;
        go.mod) ECO="go" ;;
        *) continue ;;
    esac

    SAFE_NAME=$(echo "$m" | sed 's|[/.]|_|g')
    OUT="$RESULTS_DIR/${SAFE_NAME}.json"

    echo -ne "${C}[SCAN]${N} $ECO ← $m ... "
    if $RUNTIME exec "$CONTAINER_NAME" \
        timeout "$TIMEOUT" guarddog "$ECO" verify "/repo/$m" \
        --output-format=json > "$OUT" 2>/dev/null; then
        echo -e "${G}clean${N}"
    else
        echo -e "${R}findings detected${N}"
        FINDINGS=$((FINDINGS + 1))
    fi
done

cleanup

if [ "$FINDINGS" -gt 0 ]; then
    echo -e "\n${Y}[SCAN]${N} ${R}$FINDINGS manifest(s) flagged.${N} Review: $RESULTS_DIR"
    echo -e "${Y}[SCAN]${N} This is advisory only -- build will proceed."
else
    echo -e "${G}[SCAN]${N} All dependencies clean."
fi

exit 0