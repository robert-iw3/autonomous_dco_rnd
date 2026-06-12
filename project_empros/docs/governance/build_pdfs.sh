#!/usr/bin/env bash
# Build PDFs for the governance doc set (pandoc + xelatex).
set -euo pipefail
cd "$(dirname "$0")"
for md in *.md; do
  case "$md" in [Rr][Ee][Aa][Dd][Mm][Ee].md) continue;; esac
  pdf="${md%.md}.pdf"
  pandoc "$md" -o "$pdf" --pdf-engine=xelatex --toc --toc-depth=2 \
    -V geometry:margin=1in -V colorlinks=true -V linkcolor=blue -V urlcolor=blue \
    -V fontsize=11pt -V mainfont="DejaVu Serif" -V documentclass=article -H _header.tex
  echo "built $pdf"
done
