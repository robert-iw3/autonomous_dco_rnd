"""
ingest.py -- Document parsing and chunking pipeline for worker_ti_ingest.

Supported formats:
  PDF     -- PyMuPDF text extraction (fast) with Docling fallback for layout-heavy docs
  STIX    -- stix2 bundle: extract indicators, relationships, and report descriptions
  Sigma   -- pyyaml: rule fields → structured text block
  JSONL   -- each line is a pre-formed text chunk
  IOC CSV -- ip/domain/hash/url rows → one chunk per row with context header

All parsers return List[str] (raw text chunks before embedding).
"""

import hashlib
import io
import json
import logging
import os
import re
from pathlib import Path
from typing import List, Tuple

logger = logging.getLogger(__name__)

CHUNK_MAX_TOKENS  = int(os.getenv("TI_CHUNK_MAX_TOKENS", "400"))
CHUNK_OVERLAP     = int(os.getenv("TI_CHUNK_OVERLAP", "40"))

# Rough token estimate: 1 token ≈ 4 chars (conservative for security text)
_CHARS_PER_TOKEN = 4


def _token_estimate(text: str) -> int:
    return max(1, len(text) // _CHARS_PER_TOKEN)


def _sliding_window(text: str, max_tokens: int = CHUNK_MAX_TOKENS,
                    overlap: int = CHUNK_OVERLAP) -> List[str]:
    """Split text into overlapping windows by estimated token count."""
    words = text.split()
    if not words:
        return []

    chunks: List[str] = []
    step   = max(1, max_tokens - overlap)
    i      = 0

    while i < len(words):
        chunk_words = words[i: i + max_tokens]
        chunk = " ".join(chunk_words)
        if _token_estimate(chunk) > 10:  # skip micro-fragments
            chunks.append(chunk)
        i += step

    return chunks


# -- PDF -----------------------------------------------------------------------

def parse_pdf(data: bytes) -> List[str]:
    """Extract text from PDF using PyMuPDF. Falls back to Docling if available."""
    try:
        import fitz  # PyMuPDF
    except ImportError:
        logger.warning("PyMuPDF not installed -- trying Docling")
        return _parse_pdf_docling(data)

    raw_chunks: List[str] = []
    try:
        doc = fitz.open(stream=data, filetype="pdf")
        for page_num, page in enumerate(doc, 1):
            text = page.get_text("text").strip()
            if text:
                header = f"[Page {page_num}] "
                for chunk in _sliding_window(text):
                    raw_chunks.append(header + chunk)
        doc.close()
        logger.info(f"  PDF: {len(doc)} pages → {len(raw_chunks)} chunks")
    except Exception as exc:
        logger.error(f"  PDF parse error: {exc}")

    return raw_chunks


def _parse_pdf_docling(data: bytes) -> List[str]:
    try:
        from docling.document_converter import DocumentConverter
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name

        converter = DocumentConverter()
        result    = converter.convert(tmp_path)
        text      = result.document.export_to_markdown()
        os.unlink(tmp_path)
        return _sliding_window(text)
    except Exception as exc:
        logger.error(f"  Docling parse error: {exc}")
        return []


# -- STIX ----------------------------------------------------------------------

def parse_stix(data: bytes) -> List[str]:
    """Parse STIX 2.x bundle. Extracts indicators, ATT&CK patterns, and report text."""
    try:
        bundle = json.loads(data)
    except json.JSONDecodeError as exc:
        logger.error(f"  STIX JSON parse error: {exc}")
        return []

    objects    = bundle.get("objects", [])
    chunks: List[str] = []

    for obj in objects:
        obj_type = obj.get("type", "")
        lines: List[str] = []

        if obj_type == "indicator":
            lines.append(f"STIX Indicator: {obj.get('name', '')}")
            lines.append(f"Pattern: {obj.get('pattern', '')}")
            if obj.get("description"):
                lines.append(f"Description: {obj['description']}")
            mitre = [ref for ref in obj.get("external_references", [])
                     if "mitre" in ref.get("source_name", "").lower()]
            for ref in mitre:
                lines.append(f"MITRE: {ref.get('external_id','')} -- {ref.get('url','')}")

        elif obj_type == "attack-pattern":
            lines.append(f"ATT&CK Technique: {obj.get('name', '')}")
            if obj.get("description"):
                lines.append(obj["description"][:800])
            for ref in obj.get("external_references", []):
                if ref.get("external_id", "").startswith("T"):
                    lines.append(f"ID: {ref['external_id']}")

        elif obj_type == "report":
            lines.append(f"TI Report: {obj.get('name', '')}")
            if obj.get("description"):
                lines.append(obj["description"])

        elif obj_type == "malware":
            lines.append(f"Malware: {obj.get('name', '')} ({', '.join(obj.get('malware_types', []))})")
            if obj.get("description"):
                lines.append(obj["description"][:600])

        elif obj_type == "threat-actor":
            lines.append(f"Threat Actor: {obj.get('name', '')} "
                         f"({', '.join(obj.get('aliases', []))})")
            if obj.get("description"):
                lines.append(obj["description"][:600])

        elif obj_type == "course-of-action":
            lines.append(f"Mitigation: {obj.get('name', '')}")
            if obj.get("description"):
                lines.append(obj["description"][:400])

        if lines:
            text = "\n".join(lines)
            for chunk in _sliding_window(text):
                chunks.append(chunk)

    logger.info(f"  STIX: {len(objects)} objects → {len(chunks)} chunks")
    return chunks


# -- Sigma ---------------------------------------------------------------------

def parse_sigma(data: bytes) -> List[str]:
    """Parse Sigma rule YAML into a structured text block."""
    try:
        import yaml
    except ImportError:
        logger.error("  pyyaml not installed -- cannot parse Sigma rules")
        return []

    try:
        rules = list(yaml.safe_load_all(data.decode("utf-8", errors="replace")))
    except yaml.YAMLError as exc:
        logger.error(f"  Sigma YAML parse error: {exc}")
        return []

    chunks: List[str] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        lines = [
            f"Sigma Rule: {rule.get('title', '')}",
            f"Status: {rule.get('status', '')}",
            f"Description: {rule.get('description', '')}",
            f"Tags: {', '.join(rule.get('tags', []))}",
            f"Log source: category={rule.get('logsource', {}).get('category', '')} "
            f"product={rule.get('logsource', {}).get('product', '')}",
        ]
        detection = rule.get("detection", {})
        for key, value in detection.items():
            lines.append(f"Detection.{key}: {json.dumps(value, default=str)[:300]}")

        for ref in rule.get("references", []):
            lines.append(f"Reference: {ref}")

        text = "\n".join(l for l in lines if l.split(": ", 1)[-1].strip())
        for chunk in _sliding_window(text):
            chunks.append(chunk)

    logger.info(f"  Sigma: {len(rules)} rules → {len(chunks)} chunks")
    return chunks


# -- JSONL ---------------------------------------------------------------------

def parse_jsonl(data: bytes) -> List[str]:
    """Each JSONL line becomes a chunk (or its 'text'/'content' field if present)."""
    chunks: List[str] = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            text = obj.get("text") or obj.get("content") or obj.get("chunk") or json.dumps(obj)
        except json.JSONDecodeError:
            text = line
        if _token_estimate(text) > 5:
            chunks.append(text[:CHUNK_MAX_TOKENS * _CHARS_PER_TOKEN])
    logger.info(f"  JSONL: {len(chunks)} chunks")
    return chunks


# -- IOC CSV -------------------------------------------------------------------

_IOC_PATTERNS = {
    "ipv4":   re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$"),
    "domain": re.compile(r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z]{2,})+$", re.I),
    "md5":    re.compile(r"^[0-9a-fA-F]{32}$"),
    "sha256": re.compile(r"^[0-9a-fA-F]{64}$"),
    "url":    re.compile(r"^https?://", re.I),
}


def _classify_ioc(value: str) -> str:
    for kind, pat in _IOC_PATTERNS.items():
        if pat.match(value.strip()):
            return kind
    return "unknown"


def parse_ioc_csv(data: bytes) -> List[str]:
    """Parse IOC CSV: one indicator per row, grouped into chunks of 20."""
    import csv

    rows: List[str] = []
    try:
        reader = csv.DictReader(io.StringIO(data.decode("utf-8", errors="replace")))
        fieldnames = reader.fieldnames or []

        for row in reader:
            # Try common IOC field names
            value = (row.get("indicator") or row.get("ioc") or row.get("value")
                     or row.get("ip") or row.get("domain") or row.get("hash")
                     or next(iter(row.values()), "")).strip()
            if not value:
                continue

            ioc_type = _classify_ioc(value)
            context  = row.get("description") or row.get("context") or row.get("tags") or ""
            rows.append(f"IOC [{ioc_type}]: {value}  {context}".strip())

    except Exception as exc:
        # Fallback: treat each line as raw IOC
        logger.warning(f"  CSV structured parse failed ({exc}) -- treating as raw IOC list")
        for line in data.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ioc_type = _classify_ioc(line)
                rows.append(f"IOC [{ioc_type}]: {line}")

    # Group into chunks of 20 indicators
    chunks = ["\n".join(rows[i: i + 20]) for i in range(0, len(rows), 20)]
    logger.info(f"  IOC CSV: {len(rows)} indicators → {len(chunks)} chunks")
    return chunks


# -- Format detection + dispatcher ---------------------------------------------

def detect_format(filename: str, data: bytes) -> str:
    """Detect document format from filename extension and magic bytes."""
    name = filename.lower()
    if name.endswith(".pdf"):
        return "pdf"
    if name.endswith((".stix", ".json")):
        # Check if it's a STIX bundle
        try:
            obj = json.loads(data[:4096])
            if obj.get("type") == "bundle" or any(
                o.get("type") in ("indicator", "attack-pattern", "report")
                for o in obj.get("objects", [])[:3]
            ):
                return "stix"
        except Exception:
            pass
        return "jsonl"
    if name.endswith((".yml", ".yaml")):
        return "sigma"
    if name.endswith((".jsonl", ".ndjson")):
        return "jsonl"
    if name.endswith(".csv"):
        return "ioc_csv"
    # Magic byte fallback
    if data[:4] == b"%PDF":
        return "pdf"
    return "jsonl"


def parse_document(filename: str, data: bytes) -> Tuple[str, List[str]]:
    """
    Parse document bytes into raw text chunks.

    Returns (format_detected, chunks).
    """
    fmt = detect_format(filename, data)
    dispatch = {
        "pdf":     parse_pdf,
        "stix":    parse_stix,
        "sigma":   parse_sigma,
        "jsonl":   parse_jsonl,
        "ioc_csv": parse_ioc_csv,
    }
    parser = dispatch.get(fmt, parse_jsonl)
    chunks = parser(data)
    return fmt, chunks


def doc_id(filename: str, data: bytes) -> str:
    """Stable document ID: SHA-256 of content."""
    return hashlib.sha256(data).hexdigest()
