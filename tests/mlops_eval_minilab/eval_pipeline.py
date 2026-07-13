"""
eval_pipeline.py -- Sentinel Nexus MLOps Proof-of-Concept Evaluator

Proves the corpus training logic works against a small Ollama model on a laptop/dev
machine BEFORE turning on the full GPU cluster training pipeline.

What this proves:
  1. Corpus records produce coherent prompts that a model can reason about
  2. TP records trigger TRUE POSITIVE classification
  3. FP records trigger FALSE POSITIVE (dismiss) classification
  4. The 3-axis Chain-of-Thought structure is observable in model output
  5. MITRE ATT&CK technique IDs appear in responses
  6. Vector name routing is consistent with sensor type
  7. The SYS prompt context + <|spatial_vector|> token framing works

What this does NOT prove (requires full training):
  - QLoRA weight convergence on the full 2,800 record dataset
  - SpatialProjector alignment (needs real sensor vectors, not placeholders)
  - Inference throughput at production scale
  - Fine-tuned CoT quality (vs zero-shot Ollama quality tested here)

Usage:
    # From project_empros/tests/eval_minilab/
    pip install -r requirements.txt
    cp .env.example .env   # edit as needed
    python eval_pipeline.py

    # Or run via pytest for CI integration:
    pytest test_eval_pipeline.py -v
"""

import json
import re
import sys
import time
import logging
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import print as rprint

from eval_config import (
    OLLAMA_BASE_URL, EVAL_MODEL, EVAL_RECORDS_PER_CORPUS,
    EVAL_TEMPERATURE, EVAL_MAX_TOKENS, EVAL_REPORT_FILE,
    LOG_DIR, EXPECTED_VECTOR_SPACES, get_corpus_files,
)
from eval_corpus_subset import iter_eval_records, corpus_stats, load_corpus

logging.basicConfig(level=logging.WARNING)
console = Console()

# ── Ollama client ──────────────────────────────────────────────────────────────

def check_ollama_health(base_url: str = OLLAMA_BASE_URL) -> bool:
    try:
        r = requests.get(f"{base_url}/api/version", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def model_is_pulled(model: str, base_url: str = OLLAMA_BASE_URL) -> bool:
    try:
        r = requests.get(f"{base_url}/api/tags", timeout=5)
        if r.ok:
            models = [m["name"] for m in r.json().get("models", [])]
            # Match by prefix (e.g. "llama3.2:3b" matches "llama3.2:3b" exact)
            return any(m.startswith(model.split(":")[0]) for m in models)
    except Exception:
        pass
    return False


def pull_model(model: str, base_url: str = OLLAMA_BASE_URL) -> bool:
    """Pull model if not present. Returns True on success."""
    console.print(f"[yellow][*] Pulling model '{model}' from Ollama registry...[/yellow]")
    try:
        with requests.post(
            f"{base_url}/api/pull",
            json={"name": model, "stream": True},
            stream=True,
            timeout=300,
        ) as r:
            for line in r.iter_lines():
                if line:
                    data = json.loads(line)
                    status = data.get("status", "")
                    if "pulling" in status or "success" in status:
                        console.print(f"  {status}", end="\r")
        console.print(f"[green][+] Model '{model}' ready.[/green]")
        return True
    except Exception as e:
        console.print(f"[red][!] Model pull failed: {e}[/red]")
        return False


def query_ollama(
    messages: list[dict],
    model: str = EVAL_MODEL,
    temperature: float = EVAL_TEMPERATURE,
    max_tokens: int = EVAL_MAX_TOKENS,
    base_url: str = OLLAMA_BASE_URL,
) -> Optional[str]:
    """Send messages to Ollama chat API. Returns response text or None."""
    try:
        r = requests.post(
            f"{base_url}/api/chat",
            json={
                "model": model,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                    "stop": ["\n\n\n"],   # prevent runaway generation
                },
            },
            timeout=120,
        )
        r.raise_for_status()
        return r.json()["message"]["content"]
    except Exception as e:
        logging.warning(f"Ollama query failed: {e}")
        return None


# ── Response scorer ────────────────────────────────────────────────────────────

class EvalScore:
    """Scores a single model response against expected behavior."""

    # Patterns that MUST appear for a well-formed response
    COT_AXES = ["[AXIS 1]", "[AXIS 2]", "[AXIS 3]", "[CONCLUSION]"]
    TP_MARKERS   = ["TRUE POSITIVE"]
    FP_MARKERS   = ["FALSE POSITIVE"]
    ACTION_MARKERS = ["RECOMMENDED_ACTION: contain", "RECOMMENDED_ACTION: dismiss",
                      "RECOMMENDED_ACTION:contain", "RECOMMENDED_ACTION:dismiss"]
    MITRE_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")

    def __init__(
        self,
        record: dict,
        response: Optional[str],
        latency_ms: float,
    ):
        self.record = record
        self.response = response or ""
        self.latency_ms = latency_ms
        self.expected_cls = record.get("classification", "")
        self.tool_class   = record.get("tool_class", "")
        self.source_type  = record.get("source_type", "")
        self.vector_name  = record.get("vector_name", "")
        self.mitre        = record.get("mitre_techniques", [])

    # ── Individual checks ─────────────────────────────────────────────────────

    @property
    def has_response(self) -> bool:
        return len(self.response.strip()) > 20

    @property
    def classification_correct(self) -> bool:
        if not self.has_response:
            return False
        resp = self.response.upper()
        if self.expected_cls == "true_positive":
            return any(m in resp for m in self.TP_MARKERS)
        elif self.expected_cls == "false_positive":
            return any(m in resp for m in self.FP_MARKERS)
        return False

    @property
    def cot_axes_present(self) -> int:
        """0-4: how many CoT axes are present in the response."""
        return sum(1 for ax in self.COT_AXES if ax in self.response)

    @property
    def cot_complete(self) -> bool:
        return self.cot_axes_present == 4

    @property
    def action_present(self) -> bool:
        return any(m in self.response for m in self.ACTION_MARKERS)

    @property
    def mitre_present(self) -> bool:
        """At least one valid MITRE technique ID found in response."""
        return bool(self.MITRE_PATTERN.search(self.response))

    @property
    def vector_routing_valid(self) -> bool:
        """vector_name is in the set of valid spaces for this source_type."""
        valid_set = EXPECTED_VECTOR_SPACES.get(self.source_type)
        if valid_set is None:
            return True  # unknown sensor -- skip check
        return self.vector_name in valid_set

    @property
    def spatial_token_present(self) -> bool:
        """<|spatial_vector|> was in the user prompt."""
        for msg in self.record.get("messages", []):
            if "<|spatial_vector|>" in msg.get("content", ""):
                return True
        return False

    @property
    def overall_pass(self) -> bool:
        return (
            self.has_response
            and self.classification_correct
            and self.cot_axes_present >= 2   # partial CoT is still a signal
        )

    def to_dict(self) -> dict:
        return {
            "tool_class":            self.tool_class,
            "source_type":           self.source_type,
            "vector_name":           self.vector_name,
            "expected_cls":          self.expected_cls,
            "has_response":          self.has_response,
            "classification_correct": self.classification_correct,
            "cot_axes_present":      self.cot_axes_present,
            "cot_complete":          self.cot_complete,
            "action_present":        self.action_present,
            "mitre_present":         self.mitre_present,
            "vector_routing_valid":  self.vector_routing_valid,
            "spatial_token_present": self.spatial_token_present,
            "overall_pass":          self.overall_pass,
            "latency_ms":            round(self.latency_ms),
            "response_snippet":      self.response[:200] if self.response else "",
        }


# ── Main eval runner ──────────────────────────────────────────────────────────

class EvalPipeline:
    """Runs the full eval across all corpus files."""

    def __init__(self, model: str = EVAL_MODEL, records_per_corpus: int = EVAL_RECORDS_PER_CORPUS):
        self.model = model
        self.n = records_per_corpus
        self.scores: list[EvalScore] = []
        self.corpus_results: dict[str, dict] = {}

    def run(self, corpus_files: list[Path]) -> dict:
        if not check_ollama_health():
            console.print("[red][!] Ollama is not running at %s[/red]" % OLLAMA_BASE_URL)
            console.print("    Start with: docker compose up -d")
            sys.exit(1)

        if not model_is_pulled(self.model):
            if not pull_model(self.model):
                console.print(f"[red][!] Could not pull model '{self.model}'. Exiting.[/red]")
                sys.exit(1)

        console.rule(f"[bold cyan]Sentinel Nexus MLOps Eval -- {self.model}[/bold cyan]")
        console.print(f"[dim]Corpus files: {len(corpus_files)} | Records per corpus: {self.n}[/dim]\n")

        total_records = len(corpus_files) * self.n
        start_time = time.time()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            overall_task = progress.add_task("[cyan]Evaluating corpus...", total=total_records)

            for corpus_file in corpus_files:
                corpus_name = corpus_file.stem
                progress.update(overall_task, description=f"[cyan]{corpus_name}")

                records = list(iter_eval_records(corpus_file, self.n))
                file_scores: list[EvalScore] = []

                for record in records:
                    messages = record.get("messages", [])
                    # Strip the assistant turn -- we want the model to generate it
                    eval_messages = [m for m in messages if m.get("role") != "assistant"]

                    t0 = time.time()
                    response = query_ollama(eval_messages, model=self.model)
                    latency = (time.time() - t0) * 1000

                    score = EvalScore(record, response, latency)
                    file_scores.append(score)
                    self.scores.append(score)
                    progress.advance(overall_task)

                # Aggregate per-corpus metrics
                self.corpus_results[corpus_name] = self._aggregate(file_scores)

        elapsed = time.time() - start_time
        report = self._build_report(elapsed)
        self._print_report(report)
        return report

    def _aggregate(self, scores: list[EvalScore]) -> dict:
        n = len(scores)
        if n == 0:
            return {}
        return {
            "n":                   n,
            "n_pass":              sum(1 for s in scores if s.overall_pass),
            "accuracy":            sum(1 for s in scores if s.classification_correct) / n,
            "cot_complete_rate":   sum(1 for s in scores if s.cot_complete) / n,
            "cot_partial_rate":    sum(1 for s in scores if s.cot_axes_present >= 2) / n,
            "mitre_rate":          sum(1 for s in scores if s.mitre_present) / n,
            "action_rate":         sum(1 for s in scores if s.action_present) / n,
            "vector_valid_rate":   sum(1 for s in scores if s.vector_routing_valid) / n,
            "spatial_token_rate":  sum(1 for s in scores if s.spatial_token_present) / n,
            "avg_latency_ms":      sum(s.latency_ms for s in scores) / n,
            "tp_accuracy":         self._cls_accuracy(scores, "true_positive"),
            "fp_accuracy":         self._cls_accuracy(scores, "false_positive"),
            "records":             [s.to_dict() for s in scores],
        }

    def _cls_accuracy(self, scores: list[EvalScore], cls: str) -> float:
        subset = [s for s in scores if s.expected_cls == cls]
        if not subset:
            return 0.0
        return sum(1 for s in subset if s.classification_correct) / len(subset)

    def _build_report(self, elapsed: float) -> dict:
        all_n = len(self.scores)
        return {
            "generated_at":    datetime.now(timezone.utc).isoformat(),
            "model":           self.model,
            "ollama_url":      OLLAMA_BASE_URL,
            "records_total":   all_n,
            "elapsed_seconds": round(elapsed, 1),
            "overall": {
                "accuracy":          sum(1 for s in self.scores if s.classification_correct) / max(1, all_n),
                "cot_complete_rate": sum(1 for s in self.scores if s.cot_complete) / max(1, all_n),
                "mitre_rate":        sum(1 for s in self.scores if s.mitre_present) / max(1, all_n),
                "action_rate":       sum(1 for s in self.scores if s.action_present) / max(1, all_n),
                "vector_valid_rate": sum(1 for s in self.scores if s.vector_routing_valid) / max(1, all_n),
                "tp_accuracy":       self._cls_accuracy(self.scores, "true_positive"),
                "fp_accuracy":       self._cls_accuracy(self.scores, "false_positive"),
                "avg_latency_ms":    sum(s.latency_ms for s in self.scores) / max(1, all_n),
            },
            "by_corpus": self.corpus_results,
        }

    def _print_report(self, report: dict) -> None:
        overall = report["overall"]

        console.print()
        console.rule("[bold green]Eval Results[/bold green]")

        # Overall summary table
        t = Table(title=f"Overall -- {self.model} | {report['records_total']} records in {report['elapsed_seconds']}s")
        t.add_column("Metric",             style="bold")
        t.add_column("Score",              justify="right")
        t.add_column("Pass Threshold",     justify="right", style="dim")
        t.add_column("Status",             justify="center")

        def _row(metric, val, threshold):
            pct = f"{val*100:.1f}%"
            ok  = "✅" if val >= threshold else "❌"
            return metric, pct, f"≥{threshold*100:.0f}%", ok

        t.add_row(*_row("Classification Accuracy",    overall["accuracy"],          0.60))
        t.add_row(*_row("TP Classification Accuracy", overall["tp_accuracy"],        0.60))
        t.add_row(*_row("FP Classification Accuracy", overall["fp_accuracy"],        0.50))
        t.add_row(*_row("CoT Complete (all 4 axes)",  overall["cot_complete_rate"],  0.30))
        t.add_row(*_row("MITRE Technique Present",    overall["mitre_rate"],         0.40))
        t.add_row(*_row("Action Keyword Present",     overall["action_rate"],        0.40))
        t.add_row(*_row("Vector Routing Valid",       overall["vector_valid_rate"],  0.95))
        t.add_row("Avg Latency",
                  f"{overall['avg_latency_ms']:.0f}ms", "--", "")

        console.print(t)

        # Per-corpus breakdown
        console.print()
        pt = Table(title="Per-Corpus Breakdown")
        pt.add_column("Corpus",    style="cyan", no_wrap=True)
        pt.add_column("N",         justify="right")
        pt.add_column("Accuracy",  justify="right")
        pt.add_column("CoT%",      justify="right")
        pt.add_column("MITRE%",    justify="right")
        pt.add_column("TP Acc",    justify="right")
        pt.add_column("FP Acc",    justify="right")
        pt.add_column("ms/rec",    justify="right")

        for corpus_name, cr in report["by_corpus"].items():
            short = corpus_name.replace("_behavioral_v1", "").replace("_", " ")
            pt.add_row(
                short,
                str(cr["n"]),
                f"{cr['accuracy']*100:.0f}%",
                f"{cr['cot_complete_rate']*100:.0f}%",
                f"{cr['mitre_rate']*100:.0f}%",
                f"{cr['tp_accuracy']*100:.0f}%",
                f"{cr['fp_accuracy']*100:.0f}%",
                f"{cr['avg_latency_ms']:.0f}",
            )

        console.print(pt)

        # Verdict
        acc = overall["accuracy"]
        if acc >= 0.70:
            verdict = "[bold green]PASS -- Corpus logic proven. Ready for full training.[/bold green]"
        elif acc >= 0.50:
            verdict = "[bold yellow]PARTIAL -- Corpus readable; SYS prompts may need tuning.[/bold yellow]"
        else:
            verdict = "[bold red]FAIL -- Low accuracy. Check model tier or corpus SYS prompts.[/bold red]"

        console.print()
        console.print(f"Verdict: {verdict}")
        console.print(
            f"\n[dim]Note: This is zero-shot {self.model} -- NOT the fine-tuned production model.\n"
            f"Expected accuracy: 60-75% (zero-shot). After QLoRA fine-tuning: >90%.[/dim]"
        )


def save_report(report: dict) -> Path:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = LOG_DIR / f"eval_minilab_{ts}.json"
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    console.print(f"\n[dim]Full report saved: {path}[/dim]")
    return path


def main():
    ap = argparse.ArgumentParser(description="Sentinel Nexus MLOps Eval MiniLab")
    ap.add_argument("--model", default=EVAL_MODEL)
    ap.add_argument("--n",     type=int, default=EVAL_RECORDS_PER_CORPUS)
    ap.add_argument("--list-models", action="store_true")
    ap.add_argument("--corpus", type=str, default="", help="Comma-separated corpus file names to eval")
    args = ap.parse_args()

    if args.list_models:
        from eval_config import MODEL_TIERS
        console.print("\nRecommended models by tier:")
        for tier, model in MODEL_TIERS.items():
            console.print(f"  {tier:<20} {model}")
        return

    corpus_files = get_corpus_files()
    if args.corpus:
        names = [n.strip() for n in args.corpus.split(",")]
        from eval_config import STAGING_DIR
        corpus_files = [STAGING_DIR / n for n in names if (STAGING_DIR / n).exists()]

    if not corpus_files:
        console.print("[red]No corpus files found. Run make data-all from mlops/ first.[/red]")
        sys.exit(1)

    pipeline = EvalPipeline(model=args.model, records_per_corpus=args.n)
    report = pipeline.run(corpus_files)
    save_report(report)


if __name__ == "__main__":
    main()
