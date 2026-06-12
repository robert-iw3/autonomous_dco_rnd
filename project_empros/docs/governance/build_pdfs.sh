#!/usr/bin/env bash
# Build PDFs for the governance doc set (pandoc + xelatex).
# Step 1 regenerates the manifest-driven catalog + applicability matrix so the
# PDFs always reflect controls_manifest.yaml + frameworks_reference.yaml.
set -euo pipefail
cd "$(dirname "$0")"

if command -v python3 >/dev/null 2>&1; then
  python3 gen_governance.py || echo "WARN: gen_governance.py failed (need pyyaml); using existing generated docs"
fi

for md in *.md; do
  case "$md" in [Rr][Ee][Aa][Dd][Mm][Ee].md) continue;; esac
  pdf="${md%.md}.pdf"
  # wide cross-reference docs render in landscape at a smaller font so tables fit
  case "$md" in
    controls_catalog.md|applicability_matrix.md)
      geo='-V geometry:landscape -V geometry:margin=0.7in -V fontsize=9pt' ;;
    *)
      geo='-V geometry:margin=1in -V fontsize=11pt' ;;
  esac
  # shellcheck disable=SC2086
  pandoc "$md" -o "$pdf" --pdf-engine=xelatex --toc --toc-depth=2 \
    $geo -V colorlinks=true -V linkcolor=blue -V urlcolor=blue \
    -V mainfont="DejaVu Serif" -V documentclass=article -H _header.tex
  echo "built $pdf"
done
