"""
populate_examples.py -- Populate corpus_testing/ and simulation_data/ with examples.

Picks representative classes from the production staging corpus for every TTP
category and writes them into the eval minilab so that:
  1. Each category has working example corpus JSONL files
  2. Corresponding simulation Parquet files are pre-generated
  3. The eval can run immediately without any manual file placement

This is a ONE-TIME setup script. After running it, developers drop their new
corpus classes into corpus_testing/<TTP>/ and run `podman-compose up`.

Run from tests/mlops_eval_minilab/:
    python3 populate_examples.py
    python3 populate_examples.py --n-per-category 2 --seed 99
"""

import json
import random
import argparse
from pathlib import Path

from sim_data_generator import generate_simulation_parquet

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE         = Path(__file__).parent
STAGING_DIR  = BASE.parent.parent / "data" / "staging"
CORPUS_DIR   = BASE / "corpus_testing"
SIM_DIR      = BASE / "simulation_data"

# ── Category → JSONL file mapping ─────────────────────────────────────────────
CATEGORY_MAP = {
    "1_Recon":              "recon_behavioral_v1.jsonl",
    "2_Persistence":        "persistence_behavioral_v1.jsonl",
    "3_C2":                 "c2_behavioral_v1.jsonl",
    "4_Bypass_Detection":   "bypass_behavioral_v1.jsonl",
    "5_Lateral_Movement":   "lateral_movement_behavioral_v1.jsonl",
    "6_LOTL":               "lotl_behavioral_v1.jsonl",
    "6_Malware_Tradecraft":  "malware_behavioral_v1.jsonl",
    "7_Exfiltration":       "exfiltration_behavioral_v1.jsonl",
    "Active-Directory":     "active_directory_behavioral_v1.jsonl",
    "Windows_Exploitation": "windows_exploitation_behavioral_v1.jsonl",
    "Linux_Exploitation":   "linux_exploitation_behavioral_v1.jsonl",
}

# Preferred classes to use as examples -- representative across sensor types.
# Falls back to random selection if a preferred class isn't found.
PREFERRED_CLASSES = {
    "1_Recon":              ["NetworkPortScan", "ADDomainEnum", "WebFuzzing"],
    "2_Persistence":        ["RegistryRunKey", "LinuxCronPersistence", "ScheduledTask"],
    "3_C2":                 ["HTTPSBeaconInterval", "DNSSubdomainBeacon", "SMBNamedPipeBeacon"],
    "4_Bypass_Detection":   ["AMSIInProcessPatch", "BYOVDKernelBypass", "LSASSForkDump"],
    "5_Lateral_Movement":   ["PassTheHashLateral", "WMILateralExec", "RDPSessionHijack"],
    "6_LOTL":               ["BinaryProxyMshta", "WmicProxyExecution", "CertutilLOLBin"],
    "6_Malware_Tradecraft":  ["ProcessHollowingChain", "DGABeaconPattern", "RansomwarePreEncryption"],
    "7_Exfiltration":       ["HTTPSDataExfil", "DNSTunnelingExfil", "CloudStorageExfil"],
    "Active-Directory":     ["ADPasswordSprayLDAP", "DCSync", "KerberostingService"],
    "Windows_Exploitation": ["KernelDriverEoP", "CVE202640369NtQueryKernelLPE", "PrintNightmareSeImpersonation"],
    "Linux_Exploitation":   ["OverlayFSPrivEsc", "DockerSocketPrivesc", "EBPFKernelLPE"],
}


def load_corpus_by_class(jsonl_path: Path) -> dict[str, list[dict]]:
    """Load corpus records bucketed by tool_class."""
    by_class: dict[str, list] = {}
    with open(jsonl_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            cls = rec.get("tool_class", "unknown")
            by_class.setdefault(cls, []).append(rec)
    return by_class


def pick_records(
    by_class: dict[str, list[dict]],
    preferred: list[str],
    n_classes: int,
    n_per_class_tp: int,
    n_per_class_fp: int,
    seed: int,
) -> dict[str, list[dict]]:
    """
    For each selected class, return a balanced set of TP and FP records.
    Returns dict: {class_name: [records]}
    """
    rng = random.Random(seed)
    selected_classes: list[str] = []

    # First pick from preferred list (if available in corpus)
    for cls in preferred:
        if cls in by_class and len(selected_classes) < n_classes:
            selected_classes.append(cls)

    # Fill remainder randomly
    remaining = [c for c in by_class if c not in selected_classes]
    rng.shuffle(remaining)
    for cls in remaining:
        if len(selected_classes) >= n_classes:
            break
        selected_classes.append(cls)

    result: dict[str, list] = {}
    for cls in selected_classes:
        recs = by_class[cls]
        tp = [r for r in recs if r.get("classification") == "true_positive"]
        fp = [r for r in recs if r.get("classification") == "false_positive"]
        rng.shuffle(tp)
        rng.shuffle(fp)
        picked = tp[:n_per_class_tp] + fp[:n_per_class_fp]
        if picked:
            result[cls] = picked

    return result


def populate(
    n_classes_per_category: int = 2,
    n_tp_per_class: int = 4,
    n_fp_per_class: int = 2,
    seed: int = 42,
    force: bool = False,
):
    """
    Main population function. Creates corpus JSONL + simulation Parquet for
    every TTP category.

    Args:
        n_classes_per_category: How many tool classes per category to include
        n_tp_per_class:         TP records per class
        n_fp_per_class:         FP records per class
        seed:                   Random seed
        force:                  Overwrite existing files
    """
    print(f"\nSentinel Nexus -- Eval MiniLab Example Population")
    print(f"  {n_classes_per_category} classes per category  |  "
          f"{n_tp_per_class} TP + {n_fp_per_class} FP per class\n")

    total_written  = 0
    total_skipped  = 0
    total_errors   = 0

    for category, jsonl_name in sorted(CATEGORY_MAP.items()):
        jsonl_path = STAGING_DIR / jsonl_name
        if not jsonl_path.exists():
            print(f"  [SKIP] {category}: staging file not found ({jsonl_name})")
            continue

        by_class = load_corpus_by_class(jsonl_path)
        preferred = PREFERRED_CLASSES.get(category, [])
        picked = pick_records(
            by_class, preferred,
            n_classes_per_category, n_tp_per_class, n_fp_per_class, seed,
        )

        if not picked:
            print(f"  [SKIP] {category}: no records found")
            continue

        # Combine all selected classes into one JSONL per category
        # Also write one JSONL per class for granular testing
        cat_dir = CORPUS_DIR / category
        cat_dir.mkdir(parents=True, exist_ok=True)
        sim_cat_dir = SIM_DIR / category
        sim_cat_dir.mkdir(parents=True, exist_ok=True)

        for cls_name, recs in picked.items():
            out_jsonl   = cat_dir / f"{cls_name}.jsonl"
            out_parquet = sim_cat_dir / f"{cls_name}_sim.parquet"

            # Skip if exists and not forcing
            if out_jsonl.exists() and not force:
                total_skipped += 1
                continue

            # Write corpus JSONL
            with open(out_jsonl, "w") as f:
                for r in recs:
                    f.write(json.dumps(r) + "\n")

            # Generate simulation Parquet
            try:
                meta = generate_simulation_parquet(out_jsonl, out_parquet, seed=seed)
                n_tp = sum(1 for r in recs if r.get("classification") == "true_positive")
                n_fp = len(recs) - n_tp
                print(f"  ✓  {category}/{cls_name}.jsonl  "
                      f"[{meta['sensor_type']}]  "
                      f"TP:{n_tp}  FP:{n_fp}  "
                      f"→  {out_parquet.name}")
                total_written += 1
            except Exception as e:
                print(f"  ✗  {category}/{cls_name}  ERROR: {e}")
                total_errors += 1

    print(f"\n  Written: {total_written}  Skipped: {total_skipped}  Errors: {total_errors}")
    print(f"  corpus_testing/ and simulation_data/ are ready.")
    print(f"\n  Run:  cd tests/mlops_eval_minilab && podman-compose up\n")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Populate eval minilab examples")
    ap.add_argument("--n",      type=int,  default=2,     help="Classes per category")
    ap.add_argument("--n-tp",   type=int,  default=4,     help="TP records per class")
    ap.add_argument("--n-fp",   type=int,  default=2,     help="FP records per class")
    ap.add_argument("--seed",   type=int,  default=42)
    ap.add_argument("--force",  action="store_true",      help="Overwrite existing files")
    args = ap.parse_args()

    populate(
        n_classes_per_category=args.n,
        n_tp_per_class=args.n_tp,
        n_fp_per_class=args.n_fp,
        seed=args.seed,
        force=args.force,
    )
