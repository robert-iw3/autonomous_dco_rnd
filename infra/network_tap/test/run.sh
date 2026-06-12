#!/bin/bash
# network_tap infrastructure + deployment workbench.
# tier0 (pure Python): security, performance, interoperability, and 72h PCAP
# retention contracts across the real compose/config/scripts. No containers.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 -m pytest "$HERE/tier0" -v "$@"
