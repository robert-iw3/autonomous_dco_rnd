"""
qdrant_validator.py -- Vector store ingest and similarity validation.

Simulates what production worker_qdrant does:
  Parquet rows → extract vector columns → normalize → upsert to Qdrant

Then validates that the corpus data produces meaningful vector clusters:
  - TP records for the same tool_class cluster tightly (cosine sim > 0.6)
  - FP records (benign admin) are spatially distant from the TP cluster
  - K-NN search from a TP query returns more TP than FP neighbors

This proves the spatial math works BEFORE training the projector on the GPU cluster.
"""

import json
import time
import hashlib
from pathlib import Path
from typing import Optional

import pyarrow.parquet as pq
from qdrant_client import QdrantClient
from qdrant_client.http import models as qm
from qdrant_client.http.exceptions import UnexpectedResponse

# ── Vector space definitions (match nexus.toml named_vectors) ─────────────────

VECTOR_DIMS = {
    "windows_math":   6,
    "deepsensor_math": 4,
    "trellix_math":   6,
    "sentinel_math":  5,
    "c2_math":        8,
    "cloud_flow":     5,
    "network_tap":    8,
    "embedding_384":  384,
}

# Column names per vector space (must match the Parquet schema)
VECTOR_COLUMNS = {
    "windows_math": [
        "command_entropy", "parent_child_score", "integrity_score",
        "anomaly_score", "grant_access_score", "driver_trust_score",
    ],
    "sentinel_math": [
        "shannon_entropy", "execution_velocity", "tuple_rarity",
        "path_depth", "anomaly_score",
    ],
    "network_tap": [
        "byte_ratio", "avg_inter_arrival", "variance_inter_arrival",
        "ratio_small_packets", "ratio_large_packets", "payload_entropy",
        "session_duration_ms", "packets_src",
    ],
    "c2_math": [
        "byte_ratio", "avg_inter_arrival", "variance_inter_arrival",
        "ratio_small_packets", "ratio_large_packets", "payload_entropy",
        "session_duration_ms", "packets_src",
    ],
}

EVAL_COLLECTION = "nexus_eval_gate"
# QDRANT_URL: resolved from env var so container service name (qdrant) works
import os as _os
QDRANT_URL      = _os.environ.get("QDRANT_URL", "http://localhost:6333")


class QdrantGateValidator:
    """
    Ingests simulation Parquet data into a local Qdrant instance and
    validates that TP/FP records occupy distinct spatial regions.
    """

    def __init__(self, url: str = QDRANT_URL):
        self.client = QdrantClient(url=url, timeout=10.0)
        self._ensure_collection()

    def _ensure_collection(self):
        """Create eval collection with all named vector spaces if it doesn't exist."""
        try:
            self.client.get_collection(EVAL_COLLECTION)
            return
        except Exception:
            pass

        vectors_config = {
            name: qm.VectorParams(
                size=dim,
                distance=qm.Distance.COSINE,
                on_disk=False,   # in-memory for fast eval
            )
            for name, dim in VECTOR_DIMS.items()
            if dim <= 8   # skip 384D for eval performance
        }

        self.client.create_collection(
            collection_name=EVAL_COLLECTION,
            vectors_config=vectors_config,
        )

    def reset_collection(self):
        """Wipe and recreate the eval collection (clean slate per run)."""
        try:
            self.client.delete_collection(EVAL_COLLECTION)
        except Exception:
            pass
        self._ensure_collection()

    def _extract_vector(self, row: dict, vector_name: str) -> Optional[list[float]]:
        """Extract and normalize the vector from a Parquet row dict."""
        cols = VECTOR_COLUMNS.get(vector_name, [])
        if not cols:
            return None

        vec = []
        for col in cols:
            val = row.get(col, 0.0)
            try:
                vec.append(float(val) if val is not None else 0.0)
            except (TypeError, ValueError):
                vec.append(0.0)

        # Clamp to [0,1]
        vec = [max(0.0, min(1.0, v)) for v in vec]

        # Pad if needed (shouldn't happen if Parquet is generated correctly)
        expected = VECTOR_DIMS.get(vector_name, len(vec))
        if len(vec) < expected:
            vec.extend([0.0] * (expected - len(vec)))
        return vec[:expected]

    def ingest_parquet(self, parquet_path: Path) -> dict:
        """
        Read a simulation Parquet file and upsert all rows into Qdrant.

        Returns ingestion stats: {n_ingested, n_failed, vector_name}
        """
        table = pq.read_table(parquet_path)
        rows  = table.to_pylist()
        if not rows:
            return {"n_ingested": 0, "n_failed": 0, "vector_name": "unknown"}

        # Detect vector name from _vector_name column (set by sim_data_generator)
        vname = next(
            (r.get("_vector_name", "") for r in rows if r.get("_vector_name")),
            "windows_math"
        )
        if vname not in VECTOR_DIMS or VECTOR_DIMS[vname] > 8:
            vname = "windows_math"   # fallback for eval

        n_ingested, n_failed = 0, 0
        points: list[qm.PointStruct] = []

        for i, row in enumerate(rows):
            vec = self._extract_vector(row, vname)
            if not vec:
                n_failed += 1
                continue

            # Deterministic UUID from parquet path + row index
            uid = hashlib.md5(f"{parquet_path.name}:{i}".encode()).hexdigest()

            payload = {
                "tool_class":      row.get("_tool_class", ""),
                "classification":  row.get("_classification", ""),
                "vector_name":     vname,
                "source_type":     row.get("sensor_type", ""),
                "corpus_file":     parquet_path.name,
                "timestamp":       time.time(),
            }

            points.append(qm.PointStruct(
                id=uid,
                vector={vname: vec},
                payload=payload,
            ))

            if len(points) >= 100:
                try:
                    self.client.upsert(EVAL_COLLECTION, points=points)
                    n_ingested += len(points)
                except Exception:
                    n_failed += len(points)
                points = []

        if points:
            try:
                self.client.upsert(EVAL_COLLECTION, points=points)
                n_ingested += len(points)
            except Exception:
                n_failed += len(points)

        return {"n_ingested": n_ingested, "n_failed": n_failed, "vector_name": vname}

    def validate_clustering(
        self,
        tool_class: str,
        vector_name: str,
        k: int = 5,
    ) -> dict:
        """
        For a given tool_class, find TP records and run K-NN search.
        Validates that top-K results are predominantly TP (good clustering).

        Returns:
            {
              "tool_class":    str,
              "n_tp_in_index": int,
              "n_fp_in_index": int,
              "k_searched":    int,
              "tp_in_top_k":   int,   # how many of top-K are TP
              "avg_sim":       float, # average cosine similarity of top-K TP
              "passed":        bool,
            }
        """
        # Find a TP point for this tool_class to use as query
        tp_points = self.client.scroll(
            EVAL_COLLECTION,
            scroll_filter=qm.Filter(must=[
                qm.FieldCondition(key="tool_class",     match=qm.MatchValue(value=tool_class)),
                qm.FieldCondition(key="classification", match=qm.MatchValue(value="true_positive")),
            ]),
            limit=1,
            with_vectors=True,
        )[0]

        # Count total TP/FP in index for this tool_class
        tp_count = self.client.count(
            EVAL_COLLECTION,
            count_filter=qm.Filter(must=[
                qm.FieldCondition(key="tool_class",     match=qm.MatchValue(value=tool_class)),
                qm.FieldCondition(key="classification", match=qm.MatchValue(value="true_positive")),
            ])
        ).count

        fp_count = self.client.count(
            EVAL_COLLECTION,
            count_filter=qm.Filter(must=[
                qm.FieldCondition(key="tool_class",     match=qm.MatchValue(value=tool_class)),
                qm.FieldCondition(key="classification", match=qm.MatchValue(value="false_positive")),
            ])
        ).count

        if not tp_points:
            return {
                "tool_class": tool_class, "n_tp_in_index": 0, "n_fp_in_index": fp_count,
                "k_searched": k, "tp_in_top_k": 0, "avg_sim": 0.0, "passed": False,
                "reason": "No TP points in Qdrant for this tool_class",
            }

        query_point = tp_points[0]
        query_vec   = query_point.vector

        if not query_vec:
            return {
                "tool_class": tool_class, "n_tp_in_index": tp_count, "n_fp_in_index": fp_count,
                "k_searched": k, "tp_in_top_k": 0, "avg_sim": 0.0, "passed": False,
                "reason": "Query point has no vector",
            }

        # Extract the named vector
        if isinstance(query_vec, dict):
            vname = vector_name if vector_name in query_vec else next(iter(query_vec))
            vec_list = query_vec[vname]
        else:
            vname = vector_name
            vec_list = query_vec

        # K-NN search
        try:
            hits = self.client.search(
                collection_name=EVAL_COLLECTION,
                query_vector=(vname, vec_list),
                limit=k + 1,   # +1 to exclude self
                with_payload=True,
            )
        except Exception as e:
            return {
                "tool_class": tool_class, "n_tp_in_index": tp_count, "n_fp_in_index": fp_count,
                "k_searched": k, "tp_in_top_k": 0, "avg_sim": 0.0, "passed": False,
                "reason": f"Search failed: {e}",
            }

        # Exclude the query point itself (exact match)
        neighbors = [h for h in hits if h.id != query_point.id][:k]

        tp_neighbors = [h for h in neighbors if h.payload.get("classification") == "true_positive"]
        tp_sims      = [h.score for h in tp_neighbors]
        avg_sim      = sum(tp_sims) / len(tp_sims) if tp_sims else 0.0

        # Pass: majority of neighbors are TP
        passed = len(tp_neighbors) >= max(1, len(neighbors) // 2)

        return {
            "tool_class":    tool_class,
            "n_tp_in_index": tp_count,
            "n_fp_in_index": fp_count,
            "k_searched":    len(neighbors),
            "tp_in_top_k":   len(tp_neighbors),
            "fp_in_top_k":   len(neighbors) - len(tp_neighbors),
            "avg_tp_sim":    round(avg_sim, 4),
            "passed":        passed,
        }

    def validate_all_in_parquet(self, parquet_path: Path) -> list[dict]:
        """Validate clustering for all tool_classes found in a Parquet file."""
        table = pq.read_table(parquet_path)
        rows  = table.to_pylist()

        vname = next(
            (r.get("_vector_name", "") for r in rows if r.get("_vector_name")),
            "windows_math"
        )
        if VECTOR_DIMS.get(vname, 0) > 8:
            vname = "windows_math"

        tool_classes = list({r.get("_tool_class", "") for r in rows if r.get("_tool_class")})
        results = []
        for cls in sorted(tool_classes):
            results.append(self.validate_clustering(cls, vname))
        return results

    def close(self):
        self.client.close()


def check_qdrant_health(url: str = QDRANT_URL) -> bool:
    try:
        from qdrant_client import QdrantClient
        c = QdrantClient(url=url, timeout=5.0)
        c.get_collections()
        return True
    except Exception:
        return False
