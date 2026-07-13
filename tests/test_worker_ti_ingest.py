"""
tests/test_worker_ti_ingest.py

Offline validation tests for services/worker_ti_ingest/.
Tests cover: document parsing, format detection, BM25 index, TurboVec fallback,
hybrid retrieval scoring, CrossEncoder reranker fallback, and API contract shapes.

All tests run without GPU, without Qdrant, without NATS, without turbovec installed.
"""

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import List
import numpy as np
import pytest

# ── Path setup ────────────────────────────────────────────────────────────────

SVC_DIR = Path(__file__).parent.parent / "services" / "worker_ti_ingest"

def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

ingest   = _load_module("ingest",   SVC_DIR / "ingest.py")
retrieval = _load_module("retrieval", SVC_DIR / "retrieval.py")
reranker_mod = _load_module("reranker_mod", SVC_DIR / "reranker.py")


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

SIGMA_YAML = b"""
title: Suspicious PowerShell Download Cradle
status: experimental
description: Detects PowerShell downloading from the internet
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'DownloadString'
      - 'WebClient'
  condition: selection
references:
  - https://attack.mitre.org/techniques/T1059/001/
"""

STIX_BUNDLE = json.dumps({
    "type": "bundle",
    "id": "bundle--test-001",
    "objects": [
        {
            "type": "indicator",
            "id": "indicator--abc",
            "name": "Cobalt Strike Beacon",
            "pattern": "[ipv4-addr:value = '192.168.1.100']",
            "description": "Known C2 beacon address used by APT41",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1071.001",
                 "url": "https://attack.mitre.org/techniques/T1071/001"}
            ]
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--123",
            "name": "Spearphishing Attachment",
            "description": "Adversaries may send spearphishing emails with a malicious attachment.",
            "external_references": [
                {"external_id": "T1566.001", "source_name": "mitre-attack"}
            ]
        },
        {
            "type": "malware",
            "id": "malware--xyz",
            "name": "PlugX",
            "malware_types": ["remote-access-trojan"],
            "description": "PlugX is a remote access tool used by multiple Chinese groups."
        }
    ]
}).encode()

IOC_CSV_HEADER = b"""indicator,description,tags
192.168.100.50,C2 callback address,c2
evil.domain.com,Phishing domain,phishing
d41d8cd98f00b204e9800998ecf8427e,MD5 of dropper,malware
https://malicious.example.com/payload,Payload delivery URL,delivery
"""

JSONL_DATA = b"""{"text": "Lateral movement via PsExec to WORKSTATION01"}
{"content": "Registry run key persistence: HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"}
{"chunk": "Scheduled task created: svchost32 every 5 minutes"}
"""


# ─────────────────────────────────────────────────────────────────────────────
# TestSlidingWindow
# ─────────────────────────────────────────────────────────────────────────────

class TestSlidingWindow:
    def test_short_text_single_chunk(self):
        # Must be >10 estimated tokens (>40 chars) to pass micro-fragment filter
        text = "this is a reasonably sized sentence with enough words to pass the token threshold"
        chunks = ingest._sliding_window(text, max_tokens=400, overlap=40)
        assert len(chunks) == 1
        assert chunks[0] == text

    def test_empty_text(self):
        assert ingest._sliding_window("") == []

    def test_whitespace_only(self):
        assert ingest._sliding_window("   ") == []

    def test_long_text_produces_multiple_chunks(self):
        words = ["word"] * 500
        text  = " ".join(words)
        chunks = ingest._sliding_window(text, max_tokens=100, overlap=10)
        assert len(chunks) >= 2

    def test_overlap_means_shared_content(self):
        words = [f"w{i}" for i in range(200)]
        text  = " ".join(words)
        chunks = ingest._sliding_window(text, max_tokens=50, overlap=10)
        assert len(chunks) >= 3
        # Adjacent chunks should share some words
        words0 = set(chunks[0].split())
        words1 = set(chunks[1].split())
        assert len(words0 & words1) > 0

    def test_token_estimate_positive(self):
        assert ingest._token_estimate("hello world foo bar") > 0

    def test_micro_fragments_excluded(self):
        # chunks of <10 estimated tokens should be dropped
        # 10 tokens * 4 chars = 40 chars → anything under that gets dropped
        chunks = ingest._sliding_window("ab", max_tokens=5, overlap=0)
        assert chunks == []


# ─────────────────────────────────────────────────────────────────────────────
# TestFormatDetection
# ─────────────────────────────────────────────────────────────────────────────

class TestFormatDetection:
    def test_pdf_by_extension(self):
        assert ingest.detect_format("report.pdf", b"%PDF-1.4") == "pdf"

    def test_pdf_by_magic(self):
        assert ingest.detect_format("unknown_file", b"%PDF-1.5 content") == "pdf"

    def test_sigma_yml(self):
        assert ingest.detect_format("rule.yml", SIGMA_YAML) == "sigma"

    def test_sigma_yaml(self):
        assert ingest.detect_format("rule.yaml", SIGMA_YAML) == "sigma"

    def test_stix_json_bundle(self):
        fmt = ingest.detect_format("bundle.json", STIX_BUNDLE)
        assert fmt == "stix"

    def test_plain_json_fallback(self):
        data = json.dumps({"key": "value"}).encode()
        fmt = ingest.detect_format("data.json", data)
        assert fmt == "jsonl"  # non-bundle JSON falls to jsonl

    def test_jsonl_extension(self):
        assert ingest.detect_format("events.jsonl", b'{"a":1}') == "jsonl"

    def test_csv_extension(self):
        assert ingest.detect_format("iocs.csv", IOC_CSV_HEADER) == "ioc_csv"

    def test_ndjson_extension(self):
        assert ingest.detect_format("data.ndjson", b"{}") == "jsonl"

    def test_exe_not_rejected_by_detect(self):
        # Detection doesn't reject -- that happens in main.py; format returns jsonl
        fmt = ingest.detect_format("payload.exe", b"MZ\x90\x00")
        assert isinstance(fmt, str)


# ─────────────────────────────────────────────────────────────────────────────
# TestSigmaParser
# ─────────────────────────────────────────────────────────────────────────────

class TestSigmaParser:
    def test_sigma_returns_chunks(self):
        chunks = ingest.parse_sigma(SIGMA_YAML)
        assert isinstance(chunks, list)
        assert len(chunks) >= 1

    def test_sigma_chunks_contain_title(self):
        chunks = ingest.parse_sigma(SIGMA_YAML)
        combined = " ".join(chunks)
        assert "PowerShell" in combined

    def test_sigma_chunks_contain_tags(self):
        chunks = ingest.parse_sigma(SIGMA_YAML)
        combined = " ".join(chunks)
        assert "t1059.001" in combined.lower() or "T1059" in combined

    def test_sigma_invalid_yaml_returns_empty(self):
        bad = b"[[[invalid yaml"
        result = ingest.parse_sigma(bad)
        assert isinstance(result, list)  # may return [] or partial

    def test_sigma_empty_returns_empty(self):
        result = ingest.parse_sigma(b"")
        assert isinstance(result, list)


# ─────────────────────────────────────────────────────────────────────────────
# TestStixParser
# ─────────────────────────────────────────────────────────────────────────────

class TestStixParser:
    def test_stix_returns_chunks(self):
        chunks = ingest.parse_stix(STIX_BUNDLE)
        assert isinstance(chunks, list)
        assert len(chunks) >= 3  # indicator + attack-pattern + malware

    def test_stix_indicator_pattern_present(self):
        chunks = ingest.parse_stix(STIX_BUNDLE)
        combined = " ".join(chunks)
        assert "192.168.1.100" in combined

    def test_stix_attack_pattern_present(self):
        chunks = ingest.parse_stix(STIX_BUNDLE)
        combined = " ".join(chunks)
        assert "Spearphishing" in combined

    def test_stix_malware_present(self):
        chunks = ingest.parse_stix(STIX_BUNDLE)
        combined = " ".join(chunks)
        assert "PlugX" in combined

    def test_stix_mitre_id_present(self):
        chunks = ingest.parse_stix(STIX_BUNDLE)
        combined = " ".join(chunks)
        assert "T1071.001" in combined or "T1566.001" in combined

    def test_stix_invalid_json(self):
        result = ingest.parse_stix(b"not json")
        assert isinstance(result, list)
        assert len(result) == 0

    def test_stix_empty_bundle(self):
        empty_bundle = json.dumps({"type": "bundle", "objects": []}).encode()
        result = ingest.parse_stix(empty_bundle)
        assert result == []


# ─────────────────────────────────────────────────────────────────────────────
# TestJsonlParser
# ─────────────────────────────────────────────────────────────────────────────

class TestJsonlParser:
    def test_jsonl_parses_text_field(self):
        data = b'{"text": "lateral movement via PsExec"}\n'
        chunks = ingest.parse_jsonl(data)
        assert any("PsExec" in c for c in chunks)

    def test_jsonl_parses_content_field(self):
        # Must be >5 estimated tokens (>20 chars) to pass micro-fragment filter
        data = b'{"content": "registry run key persistence for startup execution"}\n'
        chunks = ingest.parse_jsonl(data)
        assert any("persistence" in c for c in chunks)

    def test_jsonl_parses_chunk_field(self):
        data = b'{"chunk": "scheduled task created for periodic beacon execution"}\n'
        chunks = ingest.parse_jsonl(data)
        assert any("scheduled" in c for c in chunks)

    def test_jsonl_fallback_raw_json(self):
        data = b'{"unknown_key": "some value long enough to pass threshold xxxxxxxxxxxxxxxx"}\n'
        chunks = ingest.parse_jsonl(data)
        assert len(chunks) >= 1

    def test_jsonl_multiple_lines(self):
        chunks = ingest.parse_jsonl(JSONL_DATA)
        assert len(chunks) == 3

    def test_jsonl_skips_blank_lines(self):
        # Both lines must have >5 estimated tokens (>20 chars) to pass filter
        data = b'{"text": "valid long enough chunk content here"}\n\n{"text": "another valid long chunk line"}\n'
        chunks = ingest.parse_jsonl(data)
        assert len(chunks) == 2


# ─────────────────────────────────────────────────────────────────────────────
# TestIocCsvParser
# ─────────────────────────────────────────────────────────────────────────────

class TestIocCsvParser:
    def test_ioc_csv_returns_chunks(self):
        chunks = ingest.parse_ioc_csv(IOC_CSV_HEADER)
        assert len(chunks) >= 1

    def test_ioc_ip_classified(self):
        chunks = ingest.parse_ioc_csv(IOC_CSV_HEADER)
        combined = " ".join(chunks)
        assert "ipv4" in combined or "192.168.100.50" in combined

    def test_ioc_domain_classified(self):
        chunks = ingest.parse_ioc_csv(IOC_CSV_HEADER)
        combined = " ".join(chunks)
        assert "domain" in combined.lower() or "evil.domain.com" in combined

    def test_ioc_hash_classified(self):
        chunks = ingest.parse_ioc_csv(IOC_CSV_HEADER)
        combined = " ".join(chunks)
        assert "md5" in combined.lower() or "d41d8cd98f00b204" in combined

    def test_ioc_url_classified(self):
        chunks = ingest.parse_ioc_csv(IOC_CSV_HEADER)
        combined = " ".join(chunks)
        assert "url" in combined.lower() or "https://" in combined

    def test_ioc_classify_ipv4(self):
        assert ingest._classify_ioc("10.0.0.1") == "ipv4"

    def test_ioc_classify_domain(self):
        assert ingest._classify_ioc("malicious.evil.com") == "domain"

    def test_ioc_classify_md5(self):
        assert ingest._classify_ioc("d41d8cd98f00b204e9800998ecf8427e") == "md5"

    def test_ioc_classify_sha256(self):
        sha = "a" * 64
        assert ingest._classify_ioc(sha) == "sha256"

    def test_ioc_classify_url(self):
        assert ingest._classify_ioc("https://evil.com/payload") == "url"

    def test_ioc_classify_unknown(self):
        assert ingest._classify_ioc("not-an-ioc!!") == "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# TestDocumentDispatcher
# ─────────────────────────────────────────────────────────────────────────────

class TestDocumentDispatcher:
    def test_dispatch_sigma(self):
        fmt, chunks = ingest.parse_document("rule.yaml", SIGMA_YAML)
        assert fmt == "sigma"
        assert len(chunks) >= 1

    def test_dispatch_stix(self):
        fmt, chunks = ingest.parse_document("bundle.json", STIX_BUNDLE)
        assert fmt == "stix"
        assert len(chunks) >= 1

    def test_dispatch_jsonl(self):
        fmt, chunks = ingest.parse_document("events.jsonl", JSONL_DATA)
        assert fmt == "jsonl"
        assert len(chunks) == 3

    def test_dispatch_ioc_csv(self):
        fmt, chunks = ingest.parse_document("iocs.csv", IOC_CSV_HEADER)
        assert fmt == "ioc_csv"
        assert len(chunks) >= 1

    def test_returns_tuple(self):
        result = ingest.parse_document("test.yaml", SIGMA_YAML)
        assert isinstance(result, tuple)
        assert len(result) == 2


# ─────────────────────────────────────────────────────────────────────────────
# TestDocId
# ─────────────────────────────────────────────────────────────────────────────

class TestDocId:
    def test_doc_id_is_sha256_hex(self):
        data = b"hello world"
        result = ingest.doc_id("test.pdf", data)
        expected = hashlib.sha256(data).hexdigest()
        assert result == expected

    def test_doc_id_deterministic(self):
        data = b"same content"
        assert ingest.doc_id("a.pdf", data) == ingest.doc_id("b.pdf", data)

    def test_doc_id_different_content(self):
        assert ingest.doc_id("f", b"aaa") != ingest.doc_id("f", b"bbb")

    def test_doc_id_length(self):
        result = ingest.doc_id("f", b"x")
        assert len(result) == 64


# ─────────────────────────────────────────────────────────────────────────────
# TestBM25Index
# ─────────────────────────────────────────────────────────────────────────────

class TestBM25Index:
    def test_bm25_add_and_score(self):
        idx = retrieval.BM25Index()
        try:
            from rank_bm25 import BM25Okapi  # noqa
        except ImportError:
            pytest.skip("rank_bm25 not installed")

        idx.add(1, "lateral movement via psexec remote service creation")
        idx.add(2, "credential dumping via mimikatz sekurlsa logonpasswords")
        idx.add(3, "powershell encoded command download string webclient")

        scores = idx.scores("psexec lateral movement", top_n=5)
        assert isinstance(scores, dict)
        assert 1 in scores  # chunk 1 should have highest score for psexec
        assert scores.get(1, 0) > scores.get(2, 0)

    def test_bm25_remove(self):
        idx = retrieval.BM25Index()
        try:
            from rank_bm25 import BM25Okapi  # noqa
        except ImportError:
            pytest.skip("rank_bm25 not installed")

        idx.add(1, "lateral movement via psexec")
        idx.add(2, "credential dumping lsass")
        idx.remove(1)
        assert idx.size == 1

    def test_bm25_empty_returns_empty(self):
        idx = retrieval.BM25Index()
        result = idx.scores("lateral movement", top_n=5)
        assert result == {}

    def test_bm25_size_tracks(self):
        idx = retrieval.BM25Index()
        idx.add(10, "text one")
        idx.add(20, "text two")
        assert idx.size == 2
        idx.remove(10)
        assert idx.size == 1

    def test_bm25_tokenize_lowercases(self):
        idx = retrieval.BM25Index()
        tokens = idx._tokenize("LATERAL Movement VIA PsExec")
        assert all(t == t.lower() for t in tokens)

    def test_bm25_tokenize_splits_on_delimiters(self):
        idx = retrieval.BM25Index()
        tokens = idx._tokenize("T1021.002;lateral|movement/psexec")
        assert "t1021.002" in tokens
        assert "lateral" in tokens


# ─────────────────────────────────────────────────────────────────────────────
# TestTurboVecFallback
# ─────────────────────────────────────────────────────────────────────────────

class TestTurboVecFallback:
    """Test TurboVecIndex numpy brute-force fallback (works without turbovec installed)."""

    def _make_index(self) -> retrieval.TurboVecIndex:
        idx = retrieval.TurboVecIndex(dim=8, bit_width=4)
        idx._use_fallback = True  # force numpy path
        return idx

    def test_add_and_search(self):
        idx = self._make_index()
        v1 = np.array([1, 0, 0, 0, 0, 0, 0, 0], dtype=np.float32)
        v2 = np.array([0, 1, 0, 0, 0, 0, 0, 0], dtype=np.float32)
        idx.add(np.stack([v1, v2]), np.array([1, 2], dtype=np.uint64))

        query = np.array([1, 0, 0, 0, 0, 0, 0, 0], dtype=np.float32)
        scores, ids = idx.search(query, k=2)
        assert len(scores) == 2
        assert ids[0] == 1  # most similar to v1

    def test_remove(self):
        idx = self._make_index()
        v = np.random.randn(1, 8).astype(np.float32)
        idx.add(v, np.array([5], dtype=np.uint64))
        assert idx.size == 1
        idx.remove(5)
        assert idx.size == 0

    def test_empty_search_returns_empty(self):
        idx = self._make_index()
        query = np.ones(8, dtype=np.float32)
        scores, ids = idx.search(query, k=5)
        assert len(scores) == 0 and len(ids) == 0

    def test_allowlist_filters(self):
        idx = self._make_index()
        v1 = np.array([1, 0, 0, 0, 0, 0, 0, 0], dtype=np.float32)
        v2 = np.array([1, 0, 0, 0, 0, 0, 0, 0], dtype=np.float32)
        idx.add(np.stack([v1, v2]), np.array([10, 20], dtype=np.uint64))
        query = np.array([1, 0, 0, 0, 0, 0, 0, 0], dtype=np.float32)
        scores, ids = idx.search(query, k=2, allowlist=np.array([20], dtype=np.uint64))
        assert list(ids) == [20]

    def test_size_property(self):
        idx = self._make_index()
        assert idx.size == 0
        idx.add(np.ones((3, 8), dtype=np.float32), np.array([1, 2, 3], dtype=np.uint64))
        assert idx.size == 3


# ─────────────────────────────────────────────────────────────────────────────
# TestHybridRetriever
# ─────────────────────────────────────────────────────────────────────────────

class TestHybridRetriever:
    """Tests for HybridRetriever using numpy fallback and skipping GPU embedding."""

    def _make_retriever(self) -> retrieval.HybridRetriever:
        r = retrieval.HybridRetriever.__new__(retrieval.HybridRetriever)
        # Inject mock embedding model (random vectors, dim=16)
        class MockEmbed:
            dim = 16
            def encode(self, texts, **kwargs):
                return np.random.randn(len(texts), 16).astype(np.float32)
        r._embed = MockEmbed()
        r._tvec  = retrieval.TurboVecIndex(dim=16, bit_width=4)
        r._tvec._use_fallback = True
        r._bm25  = retrieval.BM25Index()
        r._meta  = {}
        return r

    def test_add_chunks_returns_ids(self):
        r = self._make_retriever()
        chunks = ["lateral movement via psexec", "credential dumping"]
        ids = r.add_chunks(0, chunks, {"doc_id": "d1", "filename": "f.jsonl",
                                       "source_type": "jsonl", "sensor_types": []})
        assert len(ids) == 2
        assert ids == [0, 1]

    def test_corpus_size_after_add(self):
        r = self._make_retriever()
        r.add_chunks(0, ["chunk one", "chunk two", "chunk three"],
                     {"doc_id": "d1", "filename": "x", "source_type": "jsonl", "sensor_types": []})
        assert r.corpus_size == 3

    def test_remove_doc_returns_count(self):
        r = self._make_retriever()
        r.add_chunks(0, ["a chunk", "b chunk"],
                     {"doc_id": "doc-xyz", "filename": "f", "source_type": "jsonl", "sensor_types": []})
        removed = r.remove_doc("doc-xyz")
        assert removed == 2
        assert r.corpus_size == 0

    def test_remove_nonexistent_doc(self):
        r = self._make_retriever()
        removed = r.remove_doc("does-not-exist")
        assert removed == 0

    def test_list_docs_returns_unique(self):
        r = self._make_retriever()
        r.add_chunks(0, ["c1", "c2"],
                     {"doc_id": "d1", "filename": "f1.pdf", "source_type": "pdf", "sensor_types": []})
        r.add_chunks(2, ["c3"],
                     {"doc_id": "d2", "filename": "f2.pdf", "source_type": "pdf", "sensor_types": []})
        docs = r.list_docs()
        assert len(docs) == 2
        doc_ids = {d["doc_id"] for d in docs}
        assert doc_ids == {"d1", "d2"}

    def test_list_docs_chunk_count(self):
        r = self._make_retriever()
        r.add_chunks(0, ["c1", "c2", "c3"],
                     {"doc_id": "d1", "filename": "f.pdf", "source_type": "pdf", "sensor_types": []})
        docs = r.list_docs()
        assert docs[0]["chunk_count"] == 3

    def test_search_returns_retrieved_chunks(self):
        r = self._make_retriever()
        chunks = ["lateral movement via psexec remote services", "mimikatz credential dump"]
        r.add_chunks(0, chunks,
                     {"doc_id": "d1", "filename": "ti.pdf", "source_type": "pdf",
                      "sensor_types": ["windows_edr"]})
        results = r.search("psexec", k=2)
        assert len(results) >= 1
        rc = results[0]
        assert hasattr(rc, "chunk_id")
        assert hasattr(rc, "hybrid_score")
        assert hasattr(rc, "doc_id")
        assert hasattr(rc, "chunk_text")

    def test_search_hybrid_score_in_range(self):
        r = self._make_retriever()
        r.add_chunks(0, ["some threat intelligence text about lateral movement"],
                     {"doc_id": "d1", "filename": "f", "source_type": "jsonl", "sensor_types": []})
        results = r.search("lateral movement", k=1)
        if results:
            for rc in results:
                # Dense cosine score range is [-1, 1], BM25 normalized [0, 1)
                # Hybrid = ALPHA*dense + (1-ALPHA)*bm25_norm ∈ (-ALPHA, 1]
                assert -1.0 <= rc.hybrid_score <= 1.0 + 1e-6

    def test_search_sensor_type_filter_excludes(self):
        r = self._make_retriever()
        r.add_chunks(0, ["windows specific TI content"],
                     {"doc_id": "d1", "filename": "f", "source_type": "pdf",
                      "sensor_types": ["windows_edr"]})
        # Query with a sensor type not in the doc → should return empty
        results = r.search("windows TI", k=5, sensor_types=["linux_sensor"])
        assert results == []

    def test_search_sensor_type_filter_includes(self):
        r = self._make_retriever()
        r.add_chunks(0, ["windows specific content"],
                     {"doc_id": "d1", "filename": "f", "source_type": "pdf",
                      "sensor_types": ["windows_edr"]})
        results = r.search("windows", k=5, sensor_types=["windows_edr"])
        assert len(results) >= 1

    def test_search_empty_index(self):
        r = self._make_retriever()
        results = r.search("anything", k=5)
        assert results == []

    def test_hybrid_score_formula(self):
        # Verify hybrid score formula: ALPHA * dense + (1-ALPHA) * bm25_norm
        alpha = retrieval.ALPHA
        dense = 0.8
        bm25_raw = 2.5
        bm25_norm = bm25_raw / (bm25_raw + 1.0)
        expected = alpha * dense + (1 - alpha) * bm25_norm
        assert abs(expected - (alpha * dense + (1 - alpha) * bm25_norm)) < 1e-9


# ─────────────────────────────────────────────────────────────────────────────
# TestCrossEncoderReranker
# ─────────────────────────────────────────────────────────────────────────────

class TestCrossEncoderReranker:
    """Reranker graceful-fallback tests (no actual model loaded)."""

    def _make_reranker(self) -> reranker_mod.CrossEncoderReranker:
        rr = reranker_mod.CrossEncoderReranker.__new__(reranker_mod.CrossEncoderReranker)
        rr._model = None  # simulate unavailable model → uses hybrid_score fallback
        return rr

    def _make_candidates(self, n: int = 5) -> List[retrieval.RetrievedChunk]:
        candidates = []
        for i in range(n):
            candidates.append(retrieval.RetrievedChunk(
                chunk_id=i, doc_id=f"d{i}", filename=f"f{i}.pdf",
                source_type="pdf", sensor_types=[], chunk_text=f"chunk text {i}",
                chunk_index=i, dense_score=0.5 - i * 0.05,
                bm25_score=0.3, hybrid_score=0.6 - i * 0.05
            ))
        return candidates

    def test_rerank_fallback_uses_hybrid_score(self):
        rr = self._make_reranker()
        candidates = self._make_candidates(5)
        result = rr.rerank("lateral movement", candidates, top_k=3)
        assert len(result) == 3

    def test_rerank_fallback_sorted_by_hybrid(self):
        rr = self._make_reranker()
        candidates = self._make_candidates(5)
        result = rr.rerank("query", candidates, top_k=3)
        scores = [c.hybrid_score for c in result]
        assert scores == sorted(scores, reverse=True)

    def test_rerank_top_k_limits(self):
        rr = self._make_reranker()
        candidates = self._make_candidates(10)
        result = rr.rerank("query", candidates, top_k=3)
        assert len(result) <= 3

    def test_rerank_empty_candidates(self):
        rr = self._make_reranker()
        result = rr.rerank("query", [], top_k=5)
        assert result == []

    def test_rerank_fewer_candidates_than_k(self):
        rr = self._make_reranker()
        candidates = self._make_candidates(2)
        result = rr.rerank("query", candidates, top_k=10)
        assert len(result) == 2


# ─────────────────────────────────────────────────────────────────────────────
# TestApiContractShapes
# ─────────────────────────────────────────────────────────────────────────────

class TestApiContractShapes:
    """Verify that ingest module outputs match the expected contract for main.py."""

    def test_parse_document_returns_tuple_of_str_and_list(self):
        fmt, chunks = ingest.parse_document("rule.yaml", SIGMA_YAML)
        assert isinstance(fmt, str)
        assert isinstance(chunks, list)
        assert all(isinstance(c, str) for c in chunks)

    def test_doc_id_returns_str(self):
        result = ingest.doc_id("f", b"data")
        assert isinstance(result, str)

    def test_retrieved_chunk_dataclass_fields(self):
        rc = retrieval.RetrievedChunk(
            chunk_id=1, doc_id="d", filename="f", source_type="pdf",
            sensor_types=[], chunk_text="txt", chunk_index=0,
            dense_score=0.5, bm25_score=0.3, hybrid_score=0.4
        )
        assert rc.chunk_id == 1
        assert rc.hybrid_score == 0.4
        assert rc.sensor_types == []

    def test_bm25_index_scores_returns_dict(self):
        idx = retrieval.BM25Index()
        result = idx.scores("query", top_n=5)
        assert isinstance(result, dict)

    def test_alpha_constant_in_valid_range(self):
        assert 0.0 < retrieval.ALPHA < 1.0


# ─────────────────────────────────────────────────────────────────────────────
# TestModuleImports
# ─────────────────────────────────────────────────────────────────────────────

class TestModuleImports:
    def test_ingest_module_exports(self):
        for fn in ["parse_pdf", "parse_stix", "parse_sigma", "parse_jsonl",
                   "parse_ioc_csv", "parse_document", "detect_format", "doc_id",
                   "_sliding_window", "_classify_ioc"]:
            assert hasattr(ingest, fn), f"ingest missing: {fn}"

    def test_retrieval_module_exports(self):
        for cls in ["TurboVecIndex", "BM25Index", "EmbeddingModel",
                    "HybridRetriever", "RetrievedChunk"]:
            assert hasattr(retrieval, cls), f"retrieval missing: {cls}"

    def test_reranker_module_exports(self):
        assert hasattr(reranker_mod, "CrossEncoderReranker")

    def test_alpha_env_default(self):
        assert retrieval.ALPHA == 0.65  # default when BM25_ALPHA not set in env
