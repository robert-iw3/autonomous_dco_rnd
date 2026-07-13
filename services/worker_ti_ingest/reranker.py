"""
reranker.py -- CrossEncoder reranker for post-retrieval precision improvement.

After hybrid ANN+BM25 retrieves top-N candidates, the CrossEncoder scores each
(query, chunk_text) pair jointly, reranking to top-K. Typical precision gain: +15-30%.

Model: cross-encoder/ms-marco-MiniLM-L-6-v2  (22M params, ~45ms for 20 candidates CPU)
Air-gap: model must be pre-downloaded to TI_RERANKER_MODEL path before deployment.

Usage:
    reranker = CrossEncoderReranker()
    results  = reranker.rerank(query, candidates, top_k=5)
"""

import logging
import os
from typing import List, Optional

logger = logging.getLogger(__name__)

RERANKER_MODEL   = os.getenv("TI_RERANKER_MODEL",
                              "cross-encoder/ms-marco-MiniLM-L-6-v2")
RERANKER_ENABLED = os.getenv("RERANKER_ENABLED", "true").lower() == "true"
TOP_N            = int(os.getenv("RERANKER_TOP_N", "20"))   # candidates fed to reranker
TOP_K            = int(os.getenv("RERANKER_TOP_K", "5"))    # final output count


class CrossEncoderReranker:
    """
    Wraps sentence-transformers CrossEncoder with graceful fallback.

    If the model is unavailable (not installed or model path missing),
    returns candidates unchanged ordered by hybrid score.
    """

    def __init__(self) -> None:
        self._model = None
        self._enabled = RERANKER_ENABLED
        if not self._enabled:
            logger.info("  CrossEncoder reranker disabled (RERANKER_ENABLED=false)")
            return
        self._load()

    def _load(self) -> None:
        try:
            from sentence_transformers import CrossEncoder
            self._model = CrossEncoder(RERANKER_MODEL, max_length=512)
            logger.info(f"  CrossEncoder reranker loaded: {RERANKER_MODEL}")
        except Exception as exc:
            logger.warning(
                f"  CrossEncoder failed to load ({exc}) -- falling back to hybrid-score ordering.\n"
                f"  Pre-download with: sentence-transformers download {RERANKER_MODEL}"
            )
            self._model = None

    def rerank(self, query: str, candidates: list, top_k: int = TOP_K) -> list:
        """
        Rerank candidate chunks by joint (query, chunk_text) relevance score.

        candidates: list of RetrievedChunk (or any object with .chunk_text attribute)
        Returns top_k candidates sorted by reranker score descending.
        Falls back to hybrid_score ordering if reranker unavailable.
        """
        if not candidates:
            return candidates

        # Trim to TOP_N before feeding reranker (limits latency)
        pool = candidates[:TOP_N]

        if self._model is None or not self._enabled:
            return pool[:top_k]

        try:
            pairs  = [(query, c.chunk_text) for c in pool]
            scores = self._model.predict(pairs, show_progress_bar=False)

            ranked = sorted(zip(pool, scores), key=lambda x: x[1], reverse=True)
            result = [chunk for chunk, _ in ranked[:top_k]]

            logger.debug(f"  Reranked {len(pool)} → {len(result)} chunks  "
                         f"(top score: {ranked[0][1]:.3f})")
            return result

        except Exception as exc:
            logger.warning(f"  Reranker inference error ({exc}) -- using hybrid score fallback")
            return pool[:top_k]
