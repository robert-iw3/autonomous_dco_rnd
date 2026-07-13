"""
eval_corpus_subset.py -- Stratified corpus sampler for the eval pipeline.

Selects a balanced, reproducible subset from each corpus file:
  - Stratified by classification (TP / FP)
  - Stratified by source_type (sysmon_sensor, linux_sentinel, etc.)
  - Reproducible: seeded random selection

Usage (standalone):
    python eval_corpus_subset.py --corpus ../../data/staging/lotl_behavioral_v1.jsonl
"""

import json
import random
import argparse
from pathlib import Path
from collections import defaultdict
from typing import Iterator


def load_corpus(path: Path) -> list[dict]:
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def stratified_sample(
    records: list[dict],
    n_total: int,
    seed: int = 42,
) -> list[dict]:
    """
    Return a balanced sample of n_total records from corpus.

    Stratification levels:
      1. classification (true_positive, false_positive) -- maintain the 5:1 ratio
         present in the corpus (10 TP : 2 FP per class)
      2. source_type -- at least one record per sensor type if possible

    Args:
        records:  All records from the JSONL file.
        n_total:  Target total samples (TP + FP combined).
        seed:     Random seed for reproducibility.
    """
    rng = random.Random(seed)

    # Bucket by (classification, source_type)
    buckets: dict[tuple, list] = defaultdict(list)
    for r in records:
        key = (r.get("classification", "unknown"), r.get("source_type", "unknown"))
        buckets[key].append(r)

    # Separate TP and FP
    tp_buckets = {k: v for k, v in buckets.items() if k[0] == "true_positive"}
    fp_buckets = {k: v for k, v in buckets.items() if k[0] == "false_positive"}

    # Maintain ~5:1 TP:FP ratio (matching corpus construction)
    n_fp = max(1, n_total // 6)
    n_tp = n_total - n_fp

    def _sample_from_buckets(bucket_map: dict, n: int) -> list[dict]:
        """Round-robin across sensor types, then fill from all buckets."""
        result = []
        all_items = [item for items in bucket_map.values() for item in items]
        rng.shuffle(all_items)

        # First pass: one from each sensor type (diversity guarantee)
        seen_sensors: set[str] = set()
        first_pass = []
        remainder = []
        for r in all_items:
            st = r.get("source_type", "unknown")
            if st not in seen_sensors:
                first_pass.append(r)
                seen_sensors.add(st)
            else:
                remainder.append(r)

        # Fill up to n
        pool = first_pass + remainder
        result = pool[:n]
        return result

    tp_sample = _sample_from_buckets(tp_buckets, n_tp)
    fp_sample = _sample_from_buckets(fp_buckets, n_fp)

    combined = tp_sample + fp_sample
    rng.shuffle(combined)
    return combined


def corpus_stats(records: list[dict]) -> dict:
    """Return breakdown by classification and source_type."""
    stats: dict = {"total": len(records), "by_classification": {}, "by_source": {}}
    for r in records:
        cls = r.get("classification", "unknown")
        src = r.get("source_type", "unknown")
        stats["by_classification"][cls] = stats["by_classification"].get(cls, 0) + 1
        stats["by_source"][src] = stats["by_source"].get(src, 0) + 1
    return stats


def iter_eval_records(path: Path, n: int, seed: int = 42) -> Iterator[dict]:
    """Load corpus file and yield n sampled records."""
    records = load_corpus(path)
    sample = stratified_sample(records, n, seed=seed)
    yield from sample


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Preview corpus subset for eval")
    ap.add_argument("--corpus", required=True, type=Path)
    ap.add_argument("--n", type=int, default=12)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    records = load_corpus(args.corpus)
    sample = stratified_sample(records, args.n, seed=args.seed)

    print(f"\nCorpus:  {args.corpus.name}")
    print(f"Total:   {len(records)} → sampled {len(sample)}")
    print(f"\nSample breakdown:")
    for cls, cnt in corpus_stats(sample)["by_classification"].items():
        print(f"  {cls:<20} {cnt}")
    for src, cnt in corpus_stats(sample)["by_source"].items():
        print(f"  {src:<30} {cnt}")
