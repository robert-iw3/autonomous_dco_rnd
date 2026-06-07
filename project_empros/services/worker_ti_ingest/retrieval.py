"""
retrieval.py -- TurboVec + BM25 hybrid retrieval engine for the TI corpus.

Architecture:
  - TurboVec IdMapIndex: in-process SIMD ANN search (16x memory compression vs float32)
  - BM25Okapi (rank_bm25): keyword/IOC exact-match recall
  - Hybrid score: ALPHA * turbovec_cosine + (1-ALPHA) * bm25_norm
  - Qdrant fetch-by-ID: retrieves chunk text + metadata after ANN gives IDs

Index lifecycle:
  warm_from_qdrant()        -- called once on service start
  add(chunk_id, vec, text)  -- after every ingest
  remove(chunk_id)          -- on document retraction
  persist() / load()        -- TurboVec .tq file for fast restart
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

ALPHA              = float(os.getenv("BM25_ALPHA", "0.65"))       # dense weight in hybrid
TURBOVEC_BITS      = int(os.getenv("TURBOVEC_BITS", "4"))          # 2 or 4
INDEX_PATH         = os.getenv("TI_TURBOVEC_INDEX", "/opt/ti_index/ti_index.tq")
QDRANT_TI_COLLECTION = os.getenv("QDRANT_TI_COLLECTION", "nexus_ti_corpus")
QDRANT_URL         = os.getenv("QDRANT_URL", "http://qdrant:6333")

# Embedding dimension depends on the chosen model (BGE-M3 = 1024D)
_EMBED_DIM: Optional[int] = None


@dataclass
class RetrievedChunk:
    chunk_id:    int
    doc_id:      str
    filename:    str
    source_type: str
    sensor_types: List[str]
    chunk_text:  str
    chunk_index: int
    dense_score: float
    bm25_score:  float
    hybrid_score: float


# -- TurboVec wrapper ----------------------------------------------------------

class TurboVecIndex:
    """Thin wrapper around turbovec.IdMapIndex with graceful fallback to numpy brute-force."""

    def __init__(self, dim: int, bit_width: int = 4):
        self._dim = dim
        self._bit_width = bit_width
        self._index = None
        self._fallback_vecs: Dict[int, np.ndarray] = {}
        self._use_fallback = False
        self._init_index()

    def _init_index(self) -> None:
        try:
            from turbovec import IdMapIndex
            self._index = IdMapIndex(dim=self._dim, bit_width=self._bit_width)
            logger.info(f"  TurboVec IdMapIndex initialised  "
                        f"(dim={self._dim}, bit_width={self._bit_width})")
        except ImportError:
            logger.warning("  turbovec not installed -- falling back to numpy brute-force ANN")
            self._use_fallback = True

    def add(self, vectors: np.ndarray, ids: np.ndarray) -> None:
        if self._use_fallback:
            for i, vec in zip(ids, vectors):
                self._fallback_vecs[int(i)] = vec.astype(np.float32)
            return
        self._index.add_with_ids(vectors.astype(np.float32), ids.astype(np.uint64))

    def remove(self, chunk_id: int) -> None:
        if self._use_fallback:
            self._fallback_vecs.pop(chunk_id, None)
            return
        try:
            self._index.remove(chunk_id)
        except Exception as exc:
            logger.warning(f"  TurboVec remove({chunk_id}) failed: {exc}")

    def search(self, query: np.ndarray, k: int,
               allowlist: Optional[np.ndarray] = None) -> Tuple[np.ndarray, np.ndarray]:
        """Returns (scores, ids) arrays of length min(k, corpus_size)."""
        if self._use_fallback:
            return self._fallback_search(query, k, allowlist)

        if len(self._fallback_vecs) == 0 and self._index is not None:
            # TurboVec path
            if allowlist is not None:
                scores, ids = self._index.search(
                    query.astype(np.float32).reshape(1, -1), k,
                    allowlist=allowlist.astype(np.uint64)
                )
            else:
                scores, ids = self._index.search(
                    query.astype(np.float32).reshape(1, -1), k
                )
            return scores[0], ids[0]

        return self._fallback_search(query, k, allowlist)

    def _fallback_search(self, query: np.ndarray, k: int,
                         allowlist: Optional[np.ndarray] = None) -> Tuple[np.ndarray, np.ndarray]:
        if not self._fallback_vecs:
            return np.array([]), np.array([], dtype=np.int64)

        ids_arr = np.array(list(self._fallback_vecs.keys()), dtype=np.int64)
        vecs    = np.stack(list(self._fallback_vecs.values()))

        if allowlist is not None:
            allowed_set = set(allowlist.tolist())
            mask        = np.array([i in allowed_set for i in ids_arr])
            ids_arr     = ids_arr[mask]
            vecs        = vecs[mask]

        if len(vecs) == 0:
            return np.array([]), np.array([], dtype=np.int64)

        q    = query.astype(np.float32)
        q   /= np.linalg.norm(q) + 1e-9
        norms = np.linalg.norm(vecs, axis=1, keepdims=True) + 1e-9
        sims  = (vecs / norms) @ q

        top_k   = min(k, len(sims))
        top_idx = np.argpartition(-sims, top_k - 1)[:top_k]
        top_idx = top_idx[np.argsort(-sims[top_idx])]
        return sims[top_idx], ids_arr[top_idx]

    def persist(self, path: str) -> None:
        if self._use_fallback or self._index is None:
            return
        try:
            import pathlib
            pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
            self._index.write(path)
            logger.info(f"  TurboVec index persisted → {path}")
        except Exception as exc:
            logger.warning(f"  TurboVec persist failed: {exc}")

    def load(self, path: str) -> bool:
        if self._use_fallback:
            return False
        try:
            from turbovec import IdMapIndex
            self._index = IdMapIndex.load(path)
            logger.info(f"  TurboVec index loaded from {path}")
            return True
        except Exception as exc:
            logger.warning(f"  TurboVec load failed ({exc}) -- starting empty")
            return False

    @property
    def size(self) -> int:
        if self._use_fallback:
            return len(self._fallback_vecs)
        if self._index is None:
            return 0
        try:
            return len(self._index)
        except Exception:
            return 0


# -- BM25 index ---------------------------------------------------------------

class BM25Index:
    """BM25Okapi index over chunk texts with incremental update support."""

    def __init__(self) -> None:
        self._corpus_ids:   List[int]       = []
        self._corpus_texts: List[List[str]] = []  # tokenized
        self._bm25 = None
        self._dirty = False

    def _tokenize(self, text: str) -> List[str]:
        import re
        # Split on non-alphanumeric, lowercase, keep CVE/IP patterns
        return [t.lower() for t in re.split(r"[\s,;|/\\\"'`]+", text) if len(t) > 1]

    def add(self, chunk_id: int, text: str) -> None:
        self._corpus_ids.append(chunk_id)
        self._corpus_texts.append(self._tokenize(text))
        self._dirty = True

    def remove(self, chunk_id: int) -> None:
        if chunk_id in self._corpus_ids:
            idx = self._corpus_ids.index(chunk_id)
            self._corpus_ids.pop(idx)
            self._corpus_texts.pop(idx)
            self._dirty = True

    def _rebuild(self) -> None:
        if not self._corpus_texts:
            self._bm25 = None
            self._dirty = False
            return
        try:
            from rank_bm25 import BM25Okapi
            self._bm25 = BM25Okapi(self._corpus_texts)
            self._dirty = False
        except ImportError:
            logger.warning("  rank_bm25 not installed -- BM25 component disabled")
            self._bm25 = None
            self._dirty = False

    def scores(self, query: str, top_n: int) -> Dict[int, float]:
        """Return {chunk_id: raw_bm25_score} for the top_n results."""
        if self._dirty:
            self._rebuild()
        if self._bm25 is None or not self._corpus_ids:
            return {}

        tokens     = self._tokenize(query)
        raw_scores = self._bm25.get_scores(tokens)

        top_idx   = np.argpartition(-raw_scores, min(top_n, len(raw_scores)) - 1)[:top_n]
        result    = {}
        for idx in top_idx:
            if raw_scores[idx] > 0:
                result[self._corpus_ids[idx]] = float(raw_scores[idx])
        return result

    @property
    def size(self) -> int:
        return len(self._corpus_ids)


# -- Embedding model -----------------------------------------------------------

class EmbeddingModel:
    """sentence-transformers wrapper with local model path support."""

    def __init__(self) -> None:
        model_path = os.getenv("TI_EMBED_MODEL", "BAAI/bge-m3")
        self._model = None
        self._dim: int = 1024
        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(model_path)
            self._dim   = self._model.get_sentence_embedding_dimension()
            logger.info(f"  Embedding model loaded: {model_path}  (dim={self._dim})")
        except Exception as exc:
            logger.error(f"  Embedding model failed to load ({exc}) -- using random fallback")

    def encode(self, texts: List[str], batch_size: int = 32) -> np.ndarray:
        if self._model is None:
            return np.random.randn(len(texts), self._dim).astype(np.float32)
        vecs = self._model.encode(texts, batch_size=batch_size, normalize_embeddings=True,
                                  show_progress_bar=False)
        return np.array(vecs, dtype=np.float32)

    @property
    def dim(self) -> int:
        return self._dim


# -- Hybrid retrieval engine ---------------------------------------------------

class HybridRetriever:
    """
    Combines TurboVec dense ANN + BM25 keyword retrieval.

    Hybrid score: ALPHA * dense_cosine + (1-ALPHA) * bm25_normalized
    where bm25_normalized = score / (score + 1)  maps BM25 range to [0,1).
    """

    def __init__(self) -> None:
        self._embed  = EmbeddingModel()
        self._tvec   = TurboVecIndex(dim=self._embed.dim, bit_width=TURBOVEC_BITS)
        self._bm25   = BM25Index()
        # chunk_id → metadata payload cache (populated during ingest for fast lookup)
        self._meta: Dict[int, dict] = {}

    def add_chunks(self, chunk_id_base: int, chunks: List[str], metadata: dict) -> List[int]:
        """
        Encode and index a batch of text chunks.

        Returns list of assigned chunk IDs.
        """
        if not chunks:
            return []

        vectors  = self._embed.encode(chunks)
        ids      = np.arange(chunk_id_base, chunk_id_base + len(chunks), dtype=np.uint64)

        self._tvec.add(vectors, ids)
        for i, (cid, text) in enumerate(zip(ids, chunks)):
            self._bm25.add(int(cid), text)
            self._meta[int(cid)] = {**metadata, "chunk_index": i, "chunk_text": text}

        return [int(i) for i in ids]

    def remove_doc(self, doc_id: str) -> int:
        """Remove all chunks belonging to a document. Returns count removed."""
        to_remove = [cid for cid, m in self._meta.items() if m.get("doc_id") == doc_id]
        for cid in to_remove:
            self._tvec.remove(cid)
            self._bm25.remove(cid)
            del self._meta[cid]
        return len(to_remove)

    def search(self, query: str, k: int = 5, top_n: int = 20,
               sensor_types: Optional[List[str]] = None) -> List[RetrievedChunk]:
        """
        Hybrid search: dense ANN + BM25 → merge → return top-k.

        sensor_types: if provided, only return chunks tagged for those sensors.
        """
        query_vec = self._embed.encode([query])[0]

        # Build allowlist from sensor_types filter
        allowlist = None
        if sensor_types:
            allowed_ids = [
                cid for cid, m in self._meta.items()
                if any(s in m.get("sensor_types", []) for s in sensor_types)
            ]
            if allowed_ids:
                allowlist = np.array(allowed_ids, dtype=np.uint64)
            else:
                return []  # no TI for these sensor types

        # Dense search
        dense_scores, dense_ids = self._tvec.search(query_vec, top_n, allowlist=allowlist)
        dense_map: Dict[int, float] = {
            int(cid): float(sc) for sc, cid in zip(dense_scores, dense_ids)
        }

        # BM25 search
        bm25_map = self._bm25.scores(query, top_n)
        # Filter bm25 results by allowlist
        if allowlist is not None:
            allowed_set = set(int(i) for i in allowlist)
            bm25_map    = {k: v for k, v in bm25_map.items() if k in allowed_set}

        # Merge candidate sets
        all_ids = set(dense_map.keys()) | set(bm25_map.keys())

        candidates: List[Tuple[int, float, float, float]] = []
        for cid in all_ids:
            ds  = dense_map.get(cid, 0.0)
            bs  = bm25_map.get(cid, 0.0)
            bn  = bs / (bs + 1.0)               # normalize to [0,1)
            hs  = ALPHA * ds + (1 - ALPHA) * bn
            candidates.append((cid, ds, bs, hs))

        candidates.sort(key=lambda x: x[3], reverse=True)
        top_candidates = candidates[:k]

        results: List[RetrievedChunk] = []
        for cid, ds, bs, hs in top_candidates:
            meta = self._meta.get(cid, {})
            results.append(RetrievedChunk(
                chunk_id=cid,
                doc_id=meta.get("doc_id", ""),
                filename=meta.get("filename", ""),
                source_type=meta.get("source_type", ""),
                sensor_types=meta.get("sensor_types", []),
                chunk_text=meta.get("chunk_text", ""),
                chunk_index=meta.get("chunk_index", 0),
                dense_score=ds,
                bm25_score=bs,
                hybrid_score=hs,
            ))
        return results

    def warm_from_qdrant(self) -> int:
        """
        Warm TurboVec and BM25 from Qdrant nexus_ti_corpus on startup.
        Returns total chunks loaded.
        """
        try:
            from qdrant_client import QdrantClient
        except ImportError:
            logger.warning("  qdrant-client not installed -- starting with empty index")
            return 0

        client = QdrantClient(url=QDRANT_URL)
        try:
            client.get_collection(QDRANT_TI_COLLECTION)
        except Exception:
            logger.info(f"  Qdrant collection '{QDRANT_TI_COLLECTION}' does not exist yet -- "
                        "starting with empty index")
            return 0

        loaded = 0
        offset = None

        while True:
            result = client.scroll(
                collection_name=QDRANT_TI_COLLECTION,
                limit=500,
                offset=offset,
                with_vectors=True,
                with_payload=True,
            )
            points, offset = result

            for point in points:
                payload = point.payload or {}
                vec_dict = point.vector or {}
                vec = vec_dict.get("ti_embed")
                if vec is None:
                    continue

                cid = int(point.id) if isinstance(point.id, int) else abs(hash(str(point.id)))
                text = payload.get("chunk_text", "")
                meta = {
                    "doc_id":       payload.get("doc_id", ""),
                    "filename":     payload.get("filename", ""),
                    "source_type":  payload.get("source_type", ""),
                    "sensor_types": payload.get("sensor_types", []),
                    "chunk_index":  payload.get("chunk_index", 0),
                    "chunk_text":   text,
                }

                arr = np.array(vec, dtype=np.float32).reshape(1, -1)
                self._tvec.add(arr, np.array([cid], dtype=np.uint64))
                self._bm25.add(cid, text)
                self._meta[cid] = meta
                loaded += 1

            if offset is None:
                break

        logger.info(f"  TI index warmed from Qdrant: {loaded} chunks")

        # Try to persist for fast future reload
        self._tvec.persist(INDEX_PATH)
        return loaded

    def persist(self) -> None:
        self._tvec.persist(INDEX_PATH)

    @property
    def corpus_size(self) -> int:
        return self._tvec.size

    def list_docs(self) -> List[dict]:
        """Return unique documents with chunk counts."""
        docs: Dict[str, dict] = {}
        for meta in self._meta.values():
            did = meta.get("doc_id", "")
            if did not in docs:
                docs[did] = {
                    "doc_id":       did,
                    "filename":     meta.get("filename", ""),
                    "source_type":  meta.get("source_type", ""),
                    "sensor_types": meta.get("sensor_types", []),
                    "chunk_count":  0,
                }
            docs[did]["chunk_count"] += 1
        return list(docs.values())
