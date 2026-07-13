#!/usr/bin/env bash
# Build PDFs for the governance doc set (pandoc + xelatex).
# Step 1 regenerates the manifest-driven catalog + applicability matrix so the
# PDFs always reflect controls_manifest.yaml + frameworks_reference.yaml.
set -euo pipefail
cd "$(dirname "$0")"

if command -v python3 >/dev/null 2>&1; then
  python3 gen_governance.py || echo "WARN: gen_governance.py failed (need pyyaml); using existing generated docs"
  # extract the code-evidence dossier + per-control artifacts + refresh SSP Annex B
  python3 gen_evidence.py || echo "WARN: gen_evidence.py failed (need pyyaml); using existing evidence"
fi

for md in *.md; do
  case "$md" in [Rr][Ee][Aa][Dd][Mm][Ee].md) continue;; esac
  pdf="${md%.md}.pdf"
  hdr=(-H _header.tex)
  # wide cross-reference docs render in landscape at a smaller font so tables fit;
  # the evidence dossier renders portrait at a smaller font with line-wrapped code.
  case "$md" in
    controls_catalog.md|applicability_matrix.md)
      geo='-V geometry:landscape -V geometry:margin=0.7in -V fontsize=9pt' ;;
    control_evidence.md)
      geo='-V geometry:margin=0.75in -V fontsize=9pt'
      hdr+=(-H _code.tex -H _prose.tex) ;;
    *)
      # portrait prose docs: allow inline-code/path hyphenation so nothing overruns
      geo='-V geometry:margin=1in -V fontsize=11pt'
      hdr+=(-H _prose.tex) ;;
  esac
  # shellcheck disable=SC2086
  pandoc "$md" -o "$pdf" --pdf-engine=xelatex --toc --toc-depth=2 \
    $geo -V colorlinks=true -V linkcolor=blue -V urlcolor=blue \
    -V mainfont="DejaVu Serif" -V monofont="DejaVu Sans Mono" \
    -V documentclass=article "${hdr[@]}"
  echo "built $pdf"
done
