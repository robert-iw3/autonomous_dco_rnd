"""
worker_ti_ingest -- Threat Intelligence ingestion and retrieval service.

Endpoints:
  POST   /ingest                  Upload a TI document (PDF, STIX, Sigma, JSONL, IOC CSV)
  GET    /status/{job_id}         Ingestion job progress
  GET    /corpus                  List indexed documents
  DELETE /document/{doc_id}       Retract a document from the index
  POST   /retrieve                Hybrid ANN+BM25 search with optional reranking
  GET    /health                  Liveness probe

Environment:
  QDRANT_URL              http://qdrant:6333
  QDRANT_TI_COLLECTION    nexus_ti_corpus
  TI_EMBED_MODEL          /opt/models/bge-m3  (or BAAI/bge-m3 for HF download)
  TI_RERANKER_MODEL       cross-encoder/ms-marco-MiniLM-L-6-v2
  TI_MAX_UPLOAD_MB        50
  NATS_URL                nats://nats:4222
  BM25_ALPHA              0.65
  RERANKER_ENABLED        true
  TRANSFORMERS_OFFLINE    1   (must be set for air-gap operation)
"""

import asyncio
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import Dict, List, Optional

import numpy as np
from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ingest import doc_id as compute_doc_id, parse_document
from retrieval import HybridRetriever
from reranker import CrossEncoderReranker

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MAX_UPLOAD_BYTES = int(os.getenv("TI_MAX_UPLOAD_MB", "50")) * 1_048_576
NATS_URL         = os.getenv("NATS_URL", "nats://nats:4222")
QDRANT_URL       = os.getenv("QDRANT_URL", "http://qdrant:6333")
QDRANT_TI_COL    = os.getenv("QDRANT_TI_COLLECTION", "nexus_ti_corpus")

# -- Singletons ----------------------------------------------------------------

retriever: HybridRetriever
reranker:  CrossEncoderReranker

# In-memory job registry  {job_id: JobStatus}
_jobs: Dict[str, dict] = {}

# Monotonically increasing chunk ID counter (process-lifetime; Qdrant IDs are stable)
_chunk_id_counter: int = 0


def _next_chunk_id_base(n: int) -> int:
    global _chunk_id_counter
    base             = _chunk_id_counter
    _chunk_id_counter += n
    return base


# -- Lifespan: warm index on start ---------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    global retriever, reranker, _chunk_id_counter
    logger.info("[*] worker_ti_ingest starting up...")

    retriever = HybridRetriever()
    reranker  = CrossEncoderReranker()

    # Warm TurboVec + BM25 from persistent Qdrant state
    loaded = await asyncio.get_event_loop().run_in_executor(
        None, retriever.warm_from_qdrant
    )
    _chunk_id_counter = loaded  # seed counter above existing IDs

    # Ensure Qdrant TI collection exists
    await asyncio.get_event_loop().run_in_executor(None, _ensure_qdrant_collection)

    logger.info(f"[+] worker_ti_ingest ready. Index size: {retriever.corpus_size} chunks")
    yield
    logger.info("[*] worker_ti_ingest shutting down...")
    retriever.persist()


app = FastAPI(
    title="Nexus TI Ingest",
    description="Threat Intelligence ingestion and retrieval for Sentinel Nexus",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# -- Qdrant helpers ------------------------------------------------------------

def _ensure_qdrant_collection() -> None:
    try:
        from qdrant_client import QdrantClient
        from qdrant_client.models import (
            Distance, VectorParams, ScalarQuantizationConfig, ScalarType,
            QuantizationConfig
        )

        client = QdrantClient(url=QDRANT_URL)
        existing = {c.name for c in client.get_collections().collections}

        if QDRANT_TI_COL not in existing:
            dim = retriever._embed.dim
            client.create_collection(
                collection_name=QDRANT_TI_COL,
                vectors_config={"ti_embed": VectorParams(size=dim, distance=Distance.COSINE)},
                quantization_config=QuantizationConfig(
                    scalar=ScalarQuantizationConfig(type=ScalarType.INT8, always_ram=True)
                ),
            )
            logger.info(f"  Qdrant collection '{QDRANT_TI_COL}' created (dim={dim})")
        else:
            logger.info(f"  Qdrant collection '{QDRANT_TI_COL}' already exists")
    except Exception as exc:
        logger.warning(f"  Qdrant collection setup failed: {exc} -- retrieval still works via TurboVec")


def _qdrant_upsert(chunk_ids: List[int], vectors: np.ndarray,
                   chunks: List[str], metadata: dict) -> None:
    try:
        from qdrant_client import QdrantClient
        from qdrant_client.models import PointStruct

        client = QdrantClient(url=QDRANT_URL)
        points = []

        for cid, vec, text in zip(chunk_ids, vectors, chunks):
            payload = {
                **metadata,
                "chunk_index": metadata.get("chunk_index_base", 0) + chunk_ids.index(cid),
                "chunk_text":  text,
            }
            points.append(PointStruct(
                id=cid,
                vector={"ti_embed": vec.tolist()},
                payload=payload,
            ))

        client.upsert(collection_name=QDRANT_TI_COL, points=points)
    except Exception as exc:
        logger.warning(f"  Qdrant upsert failed: {exc} -- TurboVec index still updated")


def _qdrant_delete_doc(doc_id: str) -> None:
    try:
        from qdrant_client import QdrantClient
        from qdrant_client.models import Filter, FieldCondition, MatchValue

        client = QdrantClient(url=QDRANT_URL)
        client.delete(
            collection_name=QDRANT_TI_COL,
            points_selector=Filter(
                must=[FieldCondition(key="doc_id", match=MatchValue(value=doc_id))]
            ),
        )
    except Exception as exc:
        logger.warning(f"  Qdrant delete doc failed: {exc}")


# -- NATS publisher (optional) -------------------------------------------------

async def _nats_publish(subject: str, payload: dict) -> None:
    try:
        import json
        import nats as nats_lib
        # Central NATS runs default-deny authorization — authenticate when
        # credentials are provisioned (swarm_node user, see ti_ingest quadlet env).
        user = os.getenv("NATS_USER", "")
        password = os.getenv("NATS_PASS", "")
        auth = {"user": user, "password": password} if user and password else {}
        nc = await nats_lib.connect(NATS_URL, **auth)
        await nc.publish(subject, json.dumps(payload).encode())
        await nc.close()
    except Exception:
        pass  # NATS is optional; don't fail the ingest


# -- Background ingest task ----------------------------------------------------

async def _run_ingest(job_id: str, filename: str, data: bytes,
                      sensor_types: List[str]) -> None:
    _jobs[job_id] = {"status": "processing", "filename": filename,
                     "chunks": 0, "error": None, "ts": time.time()}

    await _nats_publish("nexus.ti.status",
                        {"job_id": job_id, "status": "processing", "filename": filename})
    try:
        did = compute_doc_id(filename, data)

        # Parse document
        fmt, chunks = await asyncio.get_event_loop().run_in_executor(
            None, parse_document, filename, data
        )

        if not chunks:
            raise ValueError(f"No text extracted from {filename!r} (format={fmt})")

        chunk_id_base = _next_chunk_id_base(len(chunks))
        vectors       = await asyncio.get_event_loop().run_in_executor(
            None, retriever._embed.encode, chunks
        )

        metadata = {
            "doc_id":       did,
            "filename":     filename,
            "source_type":  fmt,
            "sensor_types": sensor_types,
            "ingest_ts":    int(time.time()),
        }

        # Add to TurboVec + BM25
        chunk_ids = retriever.add_chunks(chunk_id_base, chunks, metadata)

        # Persist to Qdrant (async, non-blocking for retrieval)
        asyncio.get_event_loop().run_in_executor(
            None, _qdrant_upsert, chunk_ids, vectors, chunks, metadata
        )

        _jobs[job_id].update({"status": "done", "chunks": len(chunk_ids),
                               "doc_id": did, "format": fmt})
        await _nats_publish("nexus.ti.status",
                            {"job_id": job_id, "status": "done", "filename": filename,
                             "chunks": len(chunk_ids), "doc_id": did})

        logger.info(f"[+] Ingest complete: {filename!r}  "
                    f"{len(chunk_ids)} chunks  doc_id={did[:16]}...")

    except Exception as exc:
        logger.error(f"  Ingest failed for {filename!r}: {exc}")
        _jobs[job_id].update({"status": "error", "error": str(exc)})
        await _nats_publish("nexus.ti.status",
                            {"job_id": job_id, "status": "error",
                             "filename": filename, "error": str(exc)})


# -- Request / response models -------------------------------------------------

class RetrieveRequest(BaseModel):
    query:        str            = Field(..., min_length=2, max_length=2000)
    k:            int            = Field(default=5,  ge=1, le=50)
    top_n:        int            = Field(default=20, ge=1, le=100)
    sensor_types: Optional[List[str]] = None
    rerank:       bool           = True


class RetrieveResult(BaseModel):
    chunk_id:     int
    doc_id:       str
    filename:     str
    source_type:  str
    sensor_types: List[str]
    chunk_text:   str
    chunk_index:  int
    dense_score:  float
    bm25_score:   float
    hybrid_score: float


# -- Endpoints -----------------------------------------------------------------

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "corpus_size": retriever.corpus_size,
        "docs": len(retriever.list_docs()),
    }


@app.post("/ingest", status_code=202)
async def ingest(
    background_tasks: BackgroundTasks,
    file:         UploadFile  = File(...),
    sensor_types: str         = Form(default=""),
):
    """
    Upload a TI document for ingestion.

    sensor_types: comma-separated list of sensor types this document is relevant to.
                  Empty = relevant to all sensors.
    Returns: {"job_id": "...", "filename": "..."} -- poll /status/{job_id} for progress.
    """
    data = await file.read()

    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds {MAX_UPLOAD_BYTES // 1_048_576} MB limit",
        )
    if not data:
        raise HTTPException(status_code=400, detail="Empty file")

    # Validate magic bytes (reject obvious non-documents)
    if data[:2] == b"MZ":  # PE executable
        raise HTTPException(status_code=415, detail="Executable files not accepted")

    parsed_sensors = [s.strip() for s in sensor_types.split(",") if s.strip()]
    job_id         = str(uuid.uuid4())

    background_tasks.add_task(
        _run_ingest, job_id, file.filename or "upload", data, parsed_sensors
    )

    return {"job_id": job_id, "filename": file.filename}


@app.get("/status/{job_id}")
async def status(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@app.get("/corpus")
async def corpus():
    docs  = retriever.list_docs()
    stats = {
        "total_docs":    len(docs),
        "total_chunks":  retriever.corpus_size,
        "last_ingest_ts": max((d.get("ingest_ts", 0) for d in docs), default=0),
    }
    return {"stats": stats, "documents": docs}


@app.delete("/document/{doc_id}", status_code=200)
async def delete_document(doc_id: str):
    removed = await asyncio.get_event_loop().run_in_executor(
        None, retriever.remove_doc, doc_id
    )
    if removed == 0:
        raise HTTPException(status_code=404, detail="Document not found in index")

    asyncio.get_event_loop().run_in_executor(None, _qdrant_delete_doc, doc_id)
    retriever.persist()

    return {"removed_chunks": removed, "doc_id": doc_id}


@app.post("/retrieve", response_model=List[RetrieveResult])
async def retrieve(req: RetrieveRequest):
    """
    Hybrid TI retrieval: TurboVec dense + BM25 keyword → optional CrossEncoder rerank.

    Returns top-k chunks relevant to the query, filtered to specified sensor_types.
    """
    candidates = await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: retriever.search(req.query, k=req.top_n,
                                 top_n=req.top_n, sensor_types=req.sensor_types),
    )

    if req.rerank and candidates:
        candidates = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: reranker.rerank(req.query, candidates, top_k=req.k),
        )
    else:
        candidates = candidates[:req.k]

    return [
        RetrieveResult(
            chunk_id=c.chunk_id,
            doc_id=c.doc_id,
            filename=c.filename,
            source_type=c.source_type,
            sensor_types=c.sensor_types,
            chunk_text=c.chunk_text,
            chunk_index=c.chunk_index,
            dense_score=round(c.dense_score, 4),
            bm25_score=round(c.bm25_score, 4),
            hybrid_score=round(c.hybrid_score, 4),
        )
        for c in candidates
    ]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8010, reload=False)
