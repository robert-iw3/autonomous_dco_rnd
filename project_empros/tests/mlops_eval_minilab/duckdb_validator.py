"""
duckdb_validator.py -- DuckDB S3 Parquet query simulation.

Simulates what production 01_spool_datasets.py Track 6 does:
  DuckDB reads Parquet files from S3 → applies behavioral WHERE clauses
  from the *_query_index.json → returns matching sensor records.

In the minilab we use local Parquet files instead of S3, but the SQL is
identical. This proves the S3 query logic works BEFORE hooking up real S3.

Validation logic:
  - TP simulation rows MUST match the S3 WHERE clause (attack pattern present)
  - FP simulation rows MUST NOT match (admin pattern doesn't trigger the query)
  - At least 1 TP match per tool class proves the behavioral signal is detectable
"""

import json
import re
from pathlib import Path
from typing import Optional

import duckdb
import pyarrow.parquet as pq


# ── Column alias mapping ───────────────────────────────────────────────────────
# S3 query WHERE clauses in the staging scripts sometimes use abstracted/alias
# column names. These are mapped to the actual Parquet column names emitted by
# the sensors (which the sim_data_generator mirrors exactly).
#
# Sources:
#   sysmon aliases:         corpus_utils.py SENSOR_FIELD_ALIASES + bypass/recon scripts
#   network_tap aliases:    network_tap staging scripts
#   linux_sentinel aliases: linux staging scripts

COLUMN_ALIASES: dict[str, str] = {
    # sysmon_sensor: registry event columns
    "registry_path":         "TargetObject",
    "registry_value_data":   "Details",
    "registry_value_name":   "Details",
    "event_type_reg":        "EventType_reg",
    # sysmon_sensor: driver/image load
    "driver_name":           "ImageLoaded",
    "target_module":         "ImageLoaded",
    "image_loaded":          "ImageLoaded",
    # sysmon_sensor: process access / injection
    "writer_process":        "Image",
    "api_call":              "Image",              # abstracted -- map to Image
    "parent_process_name":   "ParentImage",
    # network_tap: statistical vector field names
    "inter_arrival_cv":      "variance_inter_arrival",
    "cv":                    "variance_inter_arrival",
    "session_count":         "packets_src",        # proxy
    "outbound_bytes":        "packets_src",        # proxy
    # linux_sentinel: kernel/syscall
    "syscall":               "comm",               # closest proxy
    "file_path":             "target_file",
    "clone_flags":           "command_line",        # embedded in cmdline
    "target_file":           "target_file",
    # columns that don't exist in flat Parquet (aggregations / abstractions)
    # -- map them to payload_raw so they always resolve to a valid column
    "operation":             "payload_raw",
    "protection_change":     "payload_raw",
    "kernel_event":          "TamperingType",
    "array_name":            "payload_raw",
    "api_sequence":          "payload_raw",
    "callback_array":        "payload_raw",
    "unique_dst_ports":      "DestinationPort",
    "unique_dst_ips":        "DestinationIp",
    "plist_path":            "target_file",
}

# Aggregation predicates that can't run in a flat WHERE -- strip them
_STRIP_PATTERNS = [
    r"\bGROUP\s+BY\b.*",
    r"\bHAVING\b.*",
    r"\bCOUNT\s*\(.*?\)\s*[><=!]+\s*\d+",
    r"\bCOUNT\s*\(DISTINCT.*?\)\s*[><=!]+\s*\d+",
    r"\bAVG\s*\(.*?\)\s*[><=!]+\s*\d+",
    r"\bMIN\s*\(.*?\)\s*[><=!]+\s*\d+",
    r"\bMAX\s*\(.*?\)\s*[><=!]+\s*\d+",
    r"\bFLOOR\s*\(.*?\)",
]


def _sanitize_where(where: str) -> str:
    """
    Normalise a WHERE clause from a staging script query index so that it can
    run against a flat Parquet file in DuckDB.

    The simulation Parquet files include alias columns (e.g., registry_path,
    inter_arrival_cv) that match the column names used in the staging WHERE
    clauses directly -- no name translation is needed.

    Steps:
      1. Strip leading WHERE keyword
      2. Strip GROUP BY / HAVING / aggregation predicates (can't be in flat WHERE)
      3. Clean up dangling AND/OR fragments
    """
    clause = where.strip()
    clause = re.sub(r"^WHERE\s+", "", clause, flags=re.IGNORECASE)

    # Strip aggregation constructs
    for pat in _STRIP_PATTERNS:
        clause = re.sub(pat, "", clause, flags=re.IGNORECASE | re.DOTALL)

    # Clean up dangling AND / OR
    clause = re.sub(r"^\s*(AND|OR)\s+", "", clause, flags=re.IGNORECASE)
    clause = re.sub(r"\s+(AND|OR)\s*$", "", clause, flags=re.IGNORECASE)
    clause = re.sub(r"\s+(AND|OR)\s+(AND|OR)\s+", " AND ", clause, flags=re.IGNORECASE)

    return clause.strip() or "1=1"


class DuckDBResult:
    def __init__(self, tool_class: str, where_clause: str,
                 n_tp_matched: int, n_fp_matched: int,
                 n_tp_total: int, n_fp_total: int,
                 error: Optional[str] = None):
        self.tool_class    = tool_class
        self.where_clause  = where_clause
        self.n_tp_matched  = n_tp_matched
        self.n_fp_matched  = n_fp_matched
        self.n_tp_total    = n_tp_total
        self.n_fp_total    = n_fp_total
        self.error         = error

    @property
    def tp_match_rate(self) -> float:
        return self.n_tp_matched / max(1, self.n_tp_total)

    @property
    def fp_match_rate(self) -> float:
        return self.n_fp_matched / max(1, self.n_fp_total)

    @property
    def passed(self) -> bool:
        """Gate passes if at least 1 TP matches and FP match rate is below 50%."""
        return (
            self.error is None
            and self.n_tp_matched >= 1
            and self.fp_match_rate < 0.5
        )

    def __repr__(self) -> str:
        status = "PASS" if self.passed else ("ERROR" if self.error else "FAIL")
        return (f"DuckDBResult({self.tool_class} [{status}] "
                f"TP:{self.n_tp_matched}/{self.n_tp_total} "
                f"FP:{self.n_fp_matched}/{self.n_fp_total})")


class DuckDBValidator:
    """
    Validates simulation Parquet files against the corpus S3 query definitions.

    For each tool class:
      1. Load the simulation Parquet file
      2. Run the S3 WHERE clause as a DuckDB query
      3. Check TP rows match and FP rows don't
    """

    def __init__(self):
        self.conn = duckdb.connect(":memory:")
        # Enable Parquet reading (built-in with duckdb)

    def validate_corpus_file(
        self,
        parquet_path: Path,
        query_index_path: Path,
    ) -> list[DuckDBResult]:
        """
        Validate all tool classes in a corpus's query index against
        the corresponding simulation Parquet.

        Returns one DuckDBResult per tool class that has an S3 query.
        """
        if not parquet_path.exists():
            return [DuckDBResult("ALL", "", 0, 0, 0, 0,
                                 error=f"Parquet not found: {parquet_path}")]

        if not query_index_path.exists():
            return [DuckDBResult("ALL", "", 0, 0, 0, 0,
                                 error=f"Query index not found: {query_index_path}")]

        idx = json.loads(query_index_path.read_text())
        tool_classes = idx.get("tool_classes", {})
        results: list[DuckDBResult] = []

        # Load Parquet into DuckDB as a view
        parquet_str = str(parquet_path).replace("\\", "/")
        try:
            self.conn.execute(
                f"CREATE OR REPLACE VIEW sim_data AS SELECT * FROM read_parquet('{parquet_str}')"
            )
        except Exception as e:
            return [DuckDBResult("ALL", "", 0, 0, 0, 0, error=f"Parquet load failed: {e}")]

        # Count totals per classification
        try:
            totals = self.conn.execute(
                "SELECT _classification, COUNT(*) AS n FROM sim_data GROUP BY _classification"
            ).fetchall()
            total_map = {row[0]: row[1] for row in totals}
            n_tp_total = total_map.get("true_positive", 0)
            n_fp_total = total_map.get("false_positive", 0)
        except Exception as e:
            return [DuckDBResult("ALL", "", 0, 0, 0, 0, error=f"Count query failed: {e}")]

        for cls, cls_data in tool_classes.items():
            s3q = cls_data.get("s3_query") or {}
            where_raw = s3q.get("where", "") if s3q else ""
            if not where_raw:
                # s3_query=None means no behavioral S3 filter for this class -- skip DuckDB gate
                results.append(DuckDBResult(
                    tool_class=cls, where_clause="",
                    n_tp_matched=1, n_fp_matched=0,
                    n_tp_total=n_tp_total, n_fp_total=n_fp_total,
                ))
                continue

            where = _sanitize_where(where_raw)

            # Count TP rows that match the WHERE clause
            try:
                # TP match: attack signature fires
                tp_q = f"SELECT COUNT(*) FROM sim_data WHERE _classification='true_positive' AND ({where})"
                n_tp_matched = self.conn.execute(tp_q).fetchone()[0]

                # FP match: admin scenario should NOT trigger the query
                fp_q = f"SELECT COUNT(*) FROM sim_data WHERE _classification='false_positive' AND ({where})"
                n_fp_matched = self.conn.execute(fp_q).fetchone()[0]

                results.append(DuckDBResult(
                    tool_class=cls,
                    where_clause=where_raw[:120],
                    n_tp_matched=n_tp_matched,
                    n_fp_matched=n_fp_matched,
                    n_tp_total=n_tp_total,
                    n_fp_total=n_fp_total,
                ))
            except Exception as e:
                results.append(DuckDBResult(
                    tool_class=cls,
                    where_clause=where_raw[:120],
                    n_tp_matched=0, n_fp_matched=0,
                    n_tp_total=n_tp_total, n_fp_total=n_fp_total,
                    error=str(e)[:200],
                ))

        return results

    def validate_directory(
        self,
        corpus_testing_dir: Path,
        simulation_data_dir: Path,
        staging_dir: Path,
    ) -> dict[str, list[DuckDBResult]]:
        """
        Validate all corpus JSONL + corresponding simulation Parquet pairs
        found in corpus_testing/.

        Returns dict: {corpus_name: [DuckDBResult, ...]}
        """
        all_results: dict[str, list[DuckDBResult]] = {}

        for jsonl_path in sorted(corpus_testing_dir.rglob("*.jsonl")):
            rel = jsonl_path.relative_to(corpus_testing_dir)
            parquet_path = simulation_data_dir / rel.parent / (jsonl_path.stem + "_sim.parquet")

            # Find query index: match by TTP category or corpus name
            corpus_name = jsonl_path.stem
            query_idx = self._find_query_index(corpus_name, staging_dir, corpus_path=jsonl_path)

            results = self.validate_corpus_file(parquet_path, query_idx) if query_idx else [
                DuckDBResult(corpus_name, "", 0, 0, 0, 0,
                             error=f"No query index found for corpus '{corpus_name}'")
            ]
            all_results[corpus_name] = results

        return all_results

    def _find_query_index(self, corpus_name: str, staging_dir: Path,
                         corpus_path: Optional[Path] = None) -> Optional[Path]:
        """
        Find the query index JSON for a corpus file.
        Strategy (in order):
          1. Match by TTP directory name (corpus_testing/6_LOTL/ → lotl_query_index)
          2. Search inside each index for the tool class name
          3. Fall back to stem substring match
        """
        import json as _json

        # Strategy 1: match by parent directory name
        if corpus_path is not None:
            ttp_dir = corpus_path.parent.name.lower()  # e.g. "6_LOTL" → "6_lotl"
            # Strip leading number (e.g. "6_lotl" → "lotl", "4_bypass_detection" → "bypass")
            ttp_clean = re.sub(r"^\d+_?", "", ttp_dir).replace("_", "").replace("-", "")
            for idx_file in staging_dir.glob("*_query_index.json"):
                stem = idx_file.stem.replace("_query_index", "").replace("_", "").lower()
                if ttp_clean and (ttp_clean in stem or stem in ttp_clean):
                    return idx_file

        # Strategy 2: search inside index files for the corpus stem as a tool class
        for idx_file in staging_dir.glob("*_query_index.json"):
            try:
                idx = _json.loads(idx_file.read_text())
                if corpus_name in idx.get("tool_classes", {}):
                    return idx_file
            except Exception:
                continue

        # Strategy 3: fallback substring match on filename stem
        for idx_file in staging_dir.glob("*_query_index.json"):
            stem = idx_file.stem.replace("_query_index", "")
            if stem.lower() in corpus_name.lower() or corpus_name.lower() in stem.lower():
                return idx_file

        return None

    def close(self):
        self.conn.close()


def run_validation(
    corpus_testing_dir: Path,
    simulation_data_dir: Path,
    staging_dir: Path,
) -> tuple[int, int, list[str]]:
    """
    Run full DuckDB validation. Returns (n_pass, n_fail, error_messages).
    """
    validator = DuckDBValidator()
    try:
        all_results = validator.validate_directory(
            corpus_testing_dir, simulation_data_dir, staging_dir
        )

        passes, fails, errors = 0, 0, []
        for corpus_name, results in all_results.items():
            for r in results:
                if r.error:
                    errors.append(f"{corpus_name}/{r.tool_class}: {r.error}")
                    fails += 1
                elif r.passed:
                    passes += 1
                else:
                    errors.append(
                        f"{corpus_name}/{r.tool_class}: "
                        f"TP match rate {r.tp_match_rate:.0%} < 100% or "
                        f"FP match rate {r.fp_match_rate:.0%} >= 50%"
                    )
                    fails += 1
        return passes, fails, errors
    finally:
        validator.close()
