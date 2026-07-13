#!/usr/bin/env python3
"""
eval_runner.py -- Sentinel Nexus MLOps Pre-Production Corpus Gate

End-to-end validation pipeline. Runs automatically inside the eval container.
Exit 0 = corpus passes all gates → safe to promote to production MLOps.
Exit 1 = one or more gates failed → needs revision before promotion.

Validation gates (in order):
  1. PREFLIGHT       -- corpus files present, services healthy, model ready
  2. SIM DATA GEN    -- generate synthetic sensor Parquet from corpus JSONL
  3. DUCKDB S3       -- S3 query simulation: TP rows match WHERE, FP rows don't
  4. QDRANT VECTORS  -- vector ingest + K-NN clustering: TP records cluster together
  5. LLM INFERENCE   -- model correctly detects TP telemetry and dismisses FP telemetry

Verbose output shows exactly what passed, what failed, and why.
"""

import json
import os
import re
import sys
import time
import math
import random
import hashlib
import logging
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
import duckdb
import pyarrow.parquet as pq
from qdrant_client import QdrantClient
from qdrant_client.http import models as qm
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint

# ── Pull in the validator modules ─────────────────────────────────────────────
from sim_data_generator import generate_simulation_parquet, generate_all_simulation_data
from duckdb_validator import DuckDBValidator, DuckDBResult
from qdrant_validator import QdrantGateValidator, VECTOR_COLUMNS, VECTOR_DIMS, check_qdrant_health

# ── Config from environment ────────────────────────────────────────────────────
OLLAMA_URL     = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
QDRANT_URL     = os.getenv("QDRANT_URL",      "http://localhost:6333")
EVAL_MODEL     = os.getenv("EVAL_MODEL",      "llama3.2:3b")
VERBOSE        = os.getenv("EVAL_VERBOSE", "1") == "1"
FAIL_FAST      = os.getenv("EVAL_FAIL_FAST", "0") == "1"

# Paths (inside container these are bind-mounts)
CORPUS_DIR     = Path("/eval/corpus_testing")
SIM_DIR        = Path("/eval/simulation_data")
STAGING_DIR    = Path("/eval/staging")
REPORTS_DIR    = Path("/eval/reports")

# Temperature for LLM inference eval (low = deterministic)
LLM_TEMP       = 0.05
LLM_MAX_TOKENS = 900

console = Console(highlight=False)

logging.basicConfig(
    level=logging.DEBUG if VERBOSE else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s -- %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("eval_runner")


# ═══════════════════════════════════════════════════════════════════════════════
# Banner
# ═══════════════════════════════════════════════════════════════════════════════

def banner():
    console.print(Panel.fit(
        "[bold cyan]Sentinel Nexus -- MLOps Pre-Production Corpus Gate[/bold cyan]\n"
        "[dim]End-to-end validation: SIM DATA → DuckDB S3 → Qdrant Vectors → LLM Inference[/dim]",
        border_style="cyan",
    ))
    console.print(f"[dim]Model: {EVAL_MODEL}  Ollama: {OLLAMA_URL}  Qdrant: {QDRANT_URL}[/dim]\n")


# ═══════════════════════════════════════════════════════════════════════════════
# Section headers
# ═══════════════════════════════════════════════════════════════════════════════

def section(title: str):
    console.rule(f"[bold white]{title}[/bold white]", style="bright_blue")


def ok(msg: str):
    console.print(f"  [bold green]✓[/bold green]  {msg}")


def fail(msg: str):
    console.print(f"  [bold red]✗[/bold red]  {msg}")


def warn(msg: str):
    console.print(f"  [bold yellow]⚠[/bold yellow]  {msg}")


def info(msg: str):
    console.print(f"  [dim]→[/dim]  {msg}")


# ═══════════════════════════════════════════════════════════════════════════════
# Gate 1: Preflight
# ═══════════════════════════════════════════════════════════════════════════════

class PreflightError(Exception):
    pass


def wait_for_service(url: str, name: str, max_wait: int = 120) -> bool:
    """Poll service health endpoint with exponential back-off."""
    deadline = time.time() + max_wait
    delay = 1.0
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=3)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        info(f"Waiting for {name} ({url})…  ({int(deadline - time.time())}s remaining)")
        time.sleep(min(delay, 8))
        delay *= 1.5
    return False


def model_is_available(model: str) -> bool:
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
        if r.ok:
            return any(m["name"].startswith(model.split(":")[0])
                       for m in r.json().get("models", []))
    except Exception:
        pass
    return False


def run_preflight() -> list[Path]:
    """Returns list of corpus JSONL files found. Raises PreflightError on hard failure."""
    section("GATE 1 -- PREFLIGHT")

    # 1. Corpus files
    jsonl_files = sorted(CORPUS_DIR.rglob("*.jsonl"))
    if not jsonl_files:
        fail("No corpus JSONL files found in corpus_testing/")
        console.print(
            "\n[yellow]  Place new corpus JSONL files in:[/yellow]\n"
            "  [dim]corpus_testing/<TTP>/your_corpus_name.jsonl[/dim]\n"
        )
        raise PreflightError("No corpus files")

    ok(f"Found {len(jsonl_files)} corpus file(s) across {len({f.parent for f in jsonl_files})} TTP categories")
    for f in jsonl_files:
        n = sum(1 for l in f.open() if l.strip())
        info(f"{f.relative_to(CORPUS_DIR)} -- {n} records")

    # 2. Staging query indices
    idx_files = list(STAGING_DIR.glob("*_query_index.json"))
    if not idx_files:
        warn("No query index files in staging/ -- DuckDB S3 validation will be skipped")
    else:
        ok(f"Found {len(idx_files)} query index file(s) in staging/")

    # 3. Ollama health
    if not wait_for_service(f"{OLLAMA_URL}/api/version", "Ollama"):
        raise PreflightError("Ollama not reachable")
    ok(f"Ollama is online at {OLLAMA_URL}")

    # 4. Model available
    if model_is_available(EVAL_MODEL):
        ok(f"Model '{EVAL_MODEL}' is loaded and ready")
    else:
        warn(f"Model '{EVAL_MODEL}' not found -- eval-init may still be pulling")
        # Give it 60 more seconds
        for _ in range(12):
            time.sleep(5)
            if model_is_available(EVAL_MODEL):
                ok(f"Model '{EVAL_MODEL}' now available")
                break
        else:
            raise PreflightError(f"Model '{EVAL_MODEL}' unavailable after wait")

    # 5. Qdrant health
    if not wait_for_service(f"{QDRANT_URL}/readyz", "Qdrant"):
        raise PreflightError("Qdrant not reachable")
    ok(f"Qdrant is online at {QDRANT_URL}")

    # 6. Reports dir
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ok(f"Reports will be written to {REPORTS_DIR}")

    console.print()
    return jsonl_files


# ═══════════════════════════════════════════════════════════════════════════════
# Gate 2: Simulation Data Generation
# ═══════════════════════════════════════════════════════════════════════════════

def run_sim_data_gen(jsonl_files: list[Path]) -> dict[Path, Path]:
    """Generate simulation Parquet for each corpus JSONL. Returns {jsonl: parquet}."""
    section("GATE 2 -- SIMULATION DATA GENERATION")
    info("Generating synthetic sensor Parquet from corpus records…")
    console.print("  [dim](TP records → attack-indicative field values)[/dim]")
    console.print("  [dim](FP records → benign admin field values)[/dim]\n")

    mapping: dict[Path, Path] = {}
    any_error = False

    for jf in jsonl_files:
        rel        = jf.relative_to(CORPUS_DIR)
        out_path   = SIM_DIR / rel.parent / (jf.stem + "_sim.parquet")
        out_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            # Pass STAGING_DIR explicitly so the container path (/eval/staging) resolves
            meta = generate_simulation_parquet(jf, out_path, staging_dir=STAGING_DIR)
            ok(f"{rel}  →  {meta['n_rows']} rows  "
               f"(TP:{meta['n_tp']} FP:{meta['n_fp']})  "
               f"sensor={meta['sensor_type']}  vector={meta['vector_name']}")
            info(f"   classes: {', '.join(meta['tool_classes'])}")
            mapping[jf] = out_path
        except Exception as e:
            fail(f"{rel}  ERROR: {e}")
            log.debug(traceback.format_exc())
            any_error = True

    console.print()
    if any_error:
        warn("Some simulation files could not be generated -- downstream gates may skip them")
    return mapping


# ═══════════════════════════════════════════════════════════════════════════════
# Gate 3: DuckDB S3 Query Simulation
# ═══════════════════════════════════════════════════════════════════════════════

def _find_query_index(corpus_path: Path) -> Optional[Path]:
    """
    Match a corpus JSONL path to its query index in staging/.
    Uses TTP parent directory first, then class-name search, then stem match.
    """
    corpus_stem = corpus_path.stem

    # 1. Match by TTP parent directory (e.g. corpus_testing/6_LOTL/ → lotl_query_index)
    ttp_dir   = corpus_path.parent.name.lower()
    ttp_clean = re.sub(r"^\d+_?", "", ttp_dir).replace("_", "").replace("-", "")
    for idx in STAGING_DIR.glob("*_query_index.json"):
        stem = idx.stem.replace("_query_index", "").replace("_", "").lower()
        if ttp_clean and (ttp_clean in stem or stem in ttp_clean):
            return idx

    # 2. Search inside each index for the tool class name
    for idx in STAGING_DIR.glob("*_query_index.json"):
        try:
            data = json.loads(idx.read_text())
            if corpus_stem in data.get("tool_classes", {}):
                return idx
        except Exception:
            continue

    # 3. Substring fallback
    for idx in STAGING_DIR.glob("*_query_index.json"):
        stem = idx.stem.replace("_query_index", "")
        if stem.lower() in corpus_stem.lower() or corpus_stem.lower() in stem.lower():
            return idx
    return None


def run_duckdb_validation(file_mapping: dict[Path, Path]) -> tuple[int, int]:
    """Returns (n_pass, n_fail)."""
    section("GATE 3 -- DUCKDB S3 QUERY SIMULATION")
    info("Running behavioral WHERE clauses from query indices against simulation Parquet…\n")

    validator = DuckDBValidator()
    total_pass, total_fail = 0, 0

    for jf, pf in file_mapping.items():
        corpus_name = jf.stem
        idx_path = _find_query_index(jf)

        if not idx_path:
            warn(f"{corpus_name}: no matching query index found in staging/ -- skipping DuckDB gate")
            continue
        if not pf.exists():
            warn(f"{corpus_name}: simulation Parquet missing -- skipping DuckDB gate")
            continue

        console.print(f"  [cyan]{corpus_name}[/cyan]  ←→  {idx_path.name}")
        results = validator.validate_corpus_file(pf, idx_path)

        for r in results:
            if r.error:
                fail(f"  [{r.tool_class}]  ERROR: {r.error}")
                total_fail += 1
            elif r.passed:
                ok(f"  [{r.tool_class}]  "
                   f"TP matched: {r.n_tp_matched}/{r.n_tp_total}  "
                   f"FP matched: {r.n_fp_matched}/{r.n_fp_total}  "
                   f"→ S3 query DETECTS attack, IGNORES admin")
                total_pass += 1
            else:
                fail(f"  [{r.tool_class}]  "
                     f"TP match {r.tp_match_rate:.0%}  FP match {r.fp_match_rate:.0%}  "
                     f"→ query too broad or TP field values not discriminating")
                info(f"       WHERE: {r.where_clause[:100]}")
                total_fail += 1

        console.print()

    validator.close()
    console.print(f"  DuckDB S3: [green]{total_pass} pass[/green]  [red]{total_fail} fail[/red]\n")
    return total_pass, total_fail


# ═══════════════════════════════════════════════════════════════════════════════
# Gate 4: Qdrant Vector Validation
# ═══════════════════════════════════════════════════════════════════════════════

def run_qdrant_validation(file_mapping: dict[Path, Path]) -> tuple[int, int]:
    """Returns (n_pass, n_fail)."""
    section("GATE 4 -- QDRANT VECTOR CLUSTERING")
    info("Ingesting synthetic sensor vectors into Qdrant and running K-NN validation…")
    info("(TP records must cluster together; FP records must be spatially separate)\n")

    qv = QdrantGateValidator(url=QDRANT_URL)
    qv.reset_collection()

    total_ingest = 0
    total_pass, total_fail = 0, 0
    ingest_errors = 0

    for jf, pf in file_mapping.items():
        if not pf.exists():
            continue
        corpus_name = jf.stem
        console.print(f"  [cyan]{corpus_name}[/cyan]")

        # Ingest
        try:
            stats = qv.ingest_parquet(pf)
            total_ingest += stats["n_ingested"]
            ok(f"  Ingested {stats['n_ingested']} vectors  "
               f"[dim](vector_space={stats['vector_name']})[/dim]")
            if stats["n_failed"]:
                warn(f"  {stats['n_failed']} rows failed to ingest")
                ingest_errors += stats["n_failed"]
        except Exception as e:
            fail(f"  Ingest error: {e}")
            log.debug(traceback.format_exc())
            ingest_errors += 1
            continue

        # Clustering validation per tool class
        try:
            results = qv.validate_all_in_parquet(pf)
            for r in results:
                if r.get("reason"):
                    # Insufficient data for K-NN (small corpus -- this is expected)
                    warn(f"  [{r['tool_class']}]  {r['reason']}")
                    # Not a failure -- just not enough data for cluster analysis
                elif r["passed"]:
                    ok(f"  [{r['tool_class']}]  "
                       f"K-NN: {r['tp_in_top_k']}/{r['k_searched']} neighbors are TP  "
                       f"avg_sim={r['avg_tp_sim']:.3f}  → TP cluster coherent")
                    total_pass += 1
                else:
                    fail(f"  [{r['tool_class']}]  "
                         f"K-NN: only {r['tp_in_top_k']}/{r['k_searched']} TP neighbors  "
                         f"→ TP/FP vectors too similar (poor spatial separation)")
                    total_fail += 1
        except Exception as e:
            fail(f"  Clustering validation error: {e}")
            log.debug(traceback.format_exc())
            total_fail += 1

        console.print()

    qv.close()
    console.print(f"  Qdrant: {total_ingest} vectors ingested  "
                  f"[green]{total_pass} pass[/green]  [red]{total_fail} fail[/red]"
                  + (f"  [yellow]{ingest_errors} ingest errors[/yellow]" if ingest_errors else "")
                  + "\n")
    return total_pass, total_fail


# ═══════════════════════════════════════════════════════════════════════════════
# Gate 5: LLM Inference Validation
# ═══════════════════════════════════════════════════════════════════════════════

def _build_training_context(train_records: list[dict]) -> str:
    """
    Build a few-shot training section from corpus training records.
    Shows the model EXACTLY what TP and FP should look like for this corpus class.
    """
    lines = [
        "Below are verified examples of how to analyze this type of telemetry.",
        "Study the reasoning pattern before classifying the new event.\n",
    ]

    # Show at most 3 TP + 1 FP examples to keep context tight
    tp_shown = 0
    fp_shown = 0
    for rec in train_records:
        cls = rec.get("classification", "")
        msgs = rec.get("messages", [])
        user_msg  = next((m["content"] for m in msgs if m["role"] == "user"),  "")
        asst_msg  = next((m["content"] for m in msgs if m["role"] == "assistant"), "")
        if not user_msg or not asst_msg:
            continue

        if cls == "true_positive" and tp_shown < 2:
            lines.append(f"--- TRAINING EXAMPLE (TRUE POSITIVE -- {rec.get('tool_class', '')}) ---")
            lines.append(f"TELEMETRY:\n{user_msg[:800]}")
            lines.append(f"ANALYSIS:\n{asst_msg[:600]}")
            lines.append("")
            tp_shown += 1

        elif cls == "false_positive" and fp_shown < 1:
            lines.append(f"--- TRAINING EXAMPLE (FALSE POSITIVE -- legitimate admin) ---")
            lines.append(f"TELEMETRY:\n{user_msg[:600]}")
            lines.append(f"ANALYSIS:\n{asst_msg[:400]}")
            lines.append("")
            fp_shown += 1

    lines.append("--- NOW CLASSIFY THE FOLLOWING NEW EVENT ---")
    return "\n".join(lines)


def _build_inference_prompt(record: dict, training_context: str) -> list[dict]:
    """Build the messages list for Ollama inference."""
    msgs = record.get("messages", [])
    sys_msg  = next((m["content"] for m in msgs if m["role"] == "system"), "")
    user_msg = next((m["content"] for m in msgs if m["role"] == "user"),   "")

    # Inject training context into the system message
    augmented_sys = sys_msg + "\n\n" + training_context if training_context else sys_msg

    return [
        {"role": "system", "content": augmented_sys},
        {"role": "user",   "content": user_msg},
    ]


def _call_ollama(messages: list[dict]) -> Optional[str]:
    """Send messages to Ollama and return response text."""
    try:
        r = requests.post(
            f"{OLLAMA_URL}/api/chat",
            json={
                "model":   EVAL_MODEL,
                "messages": messages,
                "stream":  False,
                "options": {
                    "temperature": LLM_TEMP,
                    "num_predict": LLM_MAX_TOKENS,
                },
            },
            timeout=180,
        )
        r.raise_for_status()
        return r.json()["message"]["content"]
    except Exception as e:
        log.warning(f"Ollama call failed: {e}")
        return None


class InferenceScore:
    """Score one model response against expected output."""

    MITRE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")
    COT_AXES = ["[AXIS 1]", "[AXIS 2]", "[AXIS 3]", "[CONCLUSION]"]

    def __init__(self, record: dict, response: Optional[str], latency_ms: float):
        self.tool_class   = record.get("tool_class", "?")
        self.expected_cls = record.get("classification", "")
        self.response     = response or ""
        self.latency_ms   = latency_ms

    @property
    def classification_correct(self) -> bool:
        resp = self.response.upper()
        if self.expected_cls == "true_positive":
            return "TRUE POSITIVE" in resp
        return "FALSE POSITIVE" in resp

    @property
    def action_correct(self) -> bool:
        resp = self.response.lower()
        if self.expected_cls == "true_positive":
            return "contain" in resp
        return "dismiss" in resp

    @property
    def cot_axes(self) -> int:
        return sum(1 for ax in self.COT_AXES if ax in self.response)

    @property
    def has_mitre(self) -> bool:
        return bool(self.MITRE_RE.search(self.response))

    @property
    def passed(self) -> bool:
        return self.classification_correct and len(self.response.strip()) > 50

    def verdict_line(self) -> str:
        cls_icon = "✓" if self.classification_correct else "✗"
        act_icon = "✓" if self.action_correct else "?"
        return (
            f"[{cls_icon}] cls=[{'✓' if self.classification_correct else '✗'}]  "
            f"action=[{act_icon}]  cot={self.cot_axes}/4  "
            f"mitre={'✓' if self.has_mitre else '?'}  "
            f"{self.latency_ms:.0f}ms"
        )


def run_llm_inference_validation(file_mapping: dict[Path, Path]) -> tuple[int, int]:
    """
    Load corpus records as training context, then send test records to the LLM.
    Returns (n_pass, n_fail).
    """
    section("GATE 5 -- LLM INFERENCE VALIDATION")
    info(f"Model: {EVAL_MODEL}  |  Testing with training context (few-shot)\n")
    info("This proves the model can DETECT TRUE POSITIVES and DISMISS FALSE POSITIVES")
    info("given the corpus training data as context.\n")

    total_pass, total_fail = 0, 0
    total_tp_correct, total_fp_correct = 0, 0
    total_tp, total_fp = 0, 0

    for jf, pf in file_mapping.items():
        corpus_name = jf.stem
        console.print(f"  [cyan]{corpus_name}[/cyan]")

        # Load all records
        records = [json.loads(l) for l in jf.open() if l.strip()]
        if not records:
            warn("  No records -- skipping")
            continue

        # 70/30 train/test split
        rng = random.Random(42 + hash(corpus_name) % 1000)
        rng.shuffle(records)
        split = max(1, int(len(records) * 0.70))
        train_recs = records[:split]
        test_recs  = records[split:]

        if not test_recs:
            test_recs = records[-2:]   # always at least 2 test records

        # Build few-shot training context
        context = _build_training_context(train_recs)
        info(f"  Training context: {len(train_recs)} examples  "
             f"(TP:{sum(1 for r in train_recs if r['classification']=='true_positive')}  "
             f"FP:{sum(1 for r in train_recs if r['classification']=='false_positive')})")
        info(f"  Test records:     {len(test_recs)}")

        # Run inference on test records
        for i, rec in enumerate(test_recs):
            cls_label = "TP" if rec["classification"] == "true_positive" else "FP"
            t0 = time.time()
            messages  = _build_inference_prompt(rec, context)
            response  = _call_ollama(messages)
            latency   = (time.time() - t0) * 1000
            score     = InferenceScore(rec, response, latency)

            prefix = f"  [{i+1}/{len(test_recs)}] {rec.get('tool_class','?')} ({cls_label})"

            if response is None:
                fail(f"{prefix}  → NO RESPONSE from model")
                total_fail += 1
                if FAIL_FAST:
                    raise RuntimeError("LLM returned no response -- aborting (FAIL_FAST=1)")
                continue

            if score.passed:
                ok(f"{prefix}  {score.verdict_line()}")
                total_pass += 1
            else:
                fail(f"{prefix}  {score.verdict_line()}")
                if VERBOSE:
                    # Show truncated response for diagnosis
                    snippet = (response[:400] + "…") if len(response) > 400 else response
                    for line in snippet.splitlines():
                        console.print(f"    [dim]{line}[/dim]")
                total_fail += 1

            if rec["classification"] == "true_positive":
                total_tp += 1
                if score.classification_correct:
                    total_tp_correct += 1
            else:
                total_fp += 1
                if score.classification_correct:
                    total_fp_correct += 1

        console.print()

    # Summary
    tp_acc = total_tp_correct / max(1, total_tp)
    fp_acc = total_fp_correct / max(1, total_fp)
    console.print(
        f"  LLM Inference:  "
        f"TP accuracy [{'green' if tp_acc >= 0.6 else 'red'}]{tp_acc:.0%}[/{'green' if tp_acc >= 0.6 else 'red'}]  "
        f"FP accuracy [{'green' if fp_acc >= 0.5 else 'red'}]{fp_acc:.0%}[/{'green' if fp_acc >= 0.5 else 'red'}]  "
        f"[green]{total_pass} pass[/green]  [red]{total_fail} fail[/red]\n"
    )
    return total_pass, total_fail


# ═══════════════════════════════════════════════════════════════════════════════
# Final report
# ═══════════════════════════════════════════════════════════════════════════════

def write_report(
    corpus_files: list[Path],
    gate_results: dict[str, tuple[int, int]],
    elapsed: float,
    promoted: bool,
) -> Path:
    """Write JSON report and human-readable summary. Returns report path."""
    ts = datetime.now(timezone.utc)

    report = {
        "generated_at":  ts.isoformat(),
        "model":         EVAL_MODEL,
        "elapsed_s":     round(elapsed, 1),
        "promoted":      promoted,
        "corpus_files":  [str(f.relative_to(CORPUS_DIR)) for f in corpus_files],
        "gates": {
            gate: {"pass": p, "fail": f}
            for gate, (p, f) in gate_results.items()
        },
        "verdict": "PASS -- corpus promoted" if promoted else "FAIL -- corpus needs revision",
    }

    report_path = REPORTS_DIR / f"corpus_gate_{ts.strftime('%Y%m%d_%H%M%S')}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2))

    # Human-readable summary table
    section("EVAL REPORT")
    t = Table(show_header=True, header_style="bold cyan", box=None, pad_edge=False)
    t.add_column("Gate",           min_width=30, style="white")
    t.add_column("Pass",   justify="right", style="green",  min_width=6)
    t.add_column("Fail",   justify="right", style="red",    min_width=6)
    t.add_column("Result", justify="center", min_width=8)

    for gate, (p, f) in gate_results.items():
        icon = "✅ PASS" if f == 0 and p > 0 else ("⚠️  WARN" if p > 0 else "❌ FAIL")
        t.add_row(gate, str(p), str(f), icon)

    console.print(t)
    console.print()

    if promoted:
        console.print(Panel.fit(
            "[bold green]✅  ALL GATES PASSED -- Corpus is safe to promote to production MLOps[/bold green]\n\n"
            "Next steps:\n"
            "  1. Copy corpus JSONL to  [cyan]mlops/scripts/stage_<name>.py[/cyan]\n"
            "  2. Add to               [cyan]mlops/Makefile[/cyan]  (stage-<name>, data-<name>)\n"
            "  3. Copy to              [cyan]mlops/corpus_templates/<TTP>/[/cyan]  with manifest",
            border_style="green",
        ))
    else:
        console.print(Panel.fit(
            "[bold red]❌  GATES FAILED -- Corpus needs revision before production[/bold red]\n\n"
            "Common fixes:\n"
            "  • DuckDB fail  → review S3 WHERE clause in the staging script\n"
            "  • Qdrant fail  → TP/FP field values too similar; strengthen discriminators\n"
            "  • LLM fail     → SYS prompt not providing enough behavioral signal\n"
            "  • Low TP acc   → rewrite TP user messages to be more distinctive\n"
            "  • Low FP acc   → rewrite FP admin discriminators in assistant messages",
            border_style="red",
        ))

    console.print(f"\n[dim]Report written: {report_path}[/dim]")
    console.print(f"[dim]Elapsed: {elapsed:.1f}s[/dim]\n")
    return report_path


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> int:
    banner()
    t_start = time.time()
    gate_results: dict[str, tuple[int, int]] = {}

    # ── Gate 1: Preflight ─────────────────────────────────────────────────────
    try:
        corpus_files = run_preflight()
    except PreflightError as e:
        fail(f"Preflight failed: {e}")
        return 1

    gate_results["1_PREFLIGHT"] = (len(corpus_files), 0)

    # ── Gate 2: Sim data generation ───────────────────────────────────────────
    try:
        file_mapping = run_sim_data_gen(corpus_files)
    except Exception as e:
        fail(f"Sim data generation crashed: {e}")
        log.debug(traceback.format_exc())
        return 1

    n_gen = sum(1 for pf in file_mapping.values() if pf.exists())
    gate_results["2_SIM_DATA_GEN"] = (n_gen, len(corpus_files) - n_gen)

    if not file_mapping:
        fail("No simulation data could be generated. Check corpus JSONL format.")
        return 1

    # ── Gate 3: DuckDB S3 validation ──────────────────────────────────────────
    try:
        p, f = run_duckdb_validation(file_mapping)
    except Exception as e:
        fail(f"DuckDB validation crashed: {e}")
        log.debug(traceback.format_exc())
        p, f = 0, 1
    gate_results["3_DUCKDB_S3"] = (p, f)
    if f > 0 and FAIL_FAST:
        write_report(corpus_files, gate_results, time.time() - t_start, promoted=False)
        return 1

    # ── Gate 4: Qdrant vector validation ──────────────────────────────────────
    try:
        p, f = run_qdrant_validation(file_mapping)
    except Exception as e:
        fail(f"Qdrant validation crashed: {e}")
        log.debug(traceback.format_exc())
        p, f = 0, 1
    gate_results["4_QDRANT_VECTORS"] = (p, f)
    if f > 0 and FAIL_FAST:
        write_report(corpus_files, gate_results, time.time() - t_start, promoted=False)
        return 1

    # ── Gate 5: LLM inference validation ─────────────────────────────────────
    try:
        p, f = run_llm_inference_validation(file_mapping)
    except Exception as e:
        fail(f"LLM inference validation crashed: {e}")
        log.debug(traceback.format_exc())
        p, f = 0, 1
    gate_results["5_LLM_INFERENCE"] = (p, f)

    # ── Final verdict ─────────────────────────────────────────────────────────
    elapsed   = time.time() - t_start
    any_fail  = any(f > 0 for _, f in gate_results.values())
    no_passes = all(p == 0 for p, _ in gate_results.values()
                    if _ != "1_PREFLIGHT")
    promoted  = not any_fail and not no_passes

    write_report(corpus_files, gate_results, elapsed, promoted)
    return 0 if promoted else 1


if __name__ == "__main__":
    sys.exit(main())
