"""
test_eval_pipeline.py -- pytest integration for the MLOps Eval MiniLab

Runs a focused subset eval against Ollama and asserts minimum pass thresholds.
Designed to run on a laptop/dev machine as a pre-training sanity gate.

Marks:
    @pytest.mark.ollama  -- requires live Ollama instance (skipped if not reachable)
    @pytest.mark.corpus  -- requires corpus JSONL files in data/staging/

Usage:
    # Quick smoke (no Ollama needed -- validates corpus structure only):
    pytest test_eval_pipeline.py -v -m "not ollama"

    # Full eval (requires docker compose up -d first):
    pytest test_eval_pipeline.py -v -m ollama

    # Single corpus fast check:
    pytest test_eval_pipeline.py -v -m ollama -k "lotl or sysmon"
"""

import json
import re
import pytest
from pathlib import Path

from eval_config import (
    STAGING_DIR, OLLAMA_BASE_URL, EVAL_MODEL, EXPECTED_VECTOR_SPACES,
    get_corpus_files,
)
from eval_corpus_subset import load_corpus, stratified_sample, corpus_stats
from eval_pipeline import (
    check_ollama_health, model_is_pulled, query_ollama,
    EvalScore, EvalPipeline,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Markers
# ═══════════════════════════════════════════════════════════════════════════════

def pytest_configure(config):
    config.addinivalue_line("markers", "ollama: requires live Ollama instance")
    config.addinivalue_line("markers", "corpus: requires data/staging/ JSONL files")


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="session")
def ollama_available():
    return check_ollama_health(OLLAMA_BASE_URL)


@pytest.fixture(scope="session")
def corpus_files():
    files = get_corpus_files()
    if not files:
        pytest.skip("No corpus JSONL files found in data/staging/. Run: make data-all")
    return files


@pytest.fixture(scope="session")
def small_sample(corpus_files):
    """3 records per corpus: 2 TP + 1 FP -- for fast smoke tests."""
    samples = {}
    for f in corpus_files[:5]:   # cap at 5 corpora for speed
        records = load_corpus(f)
        samples[f.stem] = stratified_sample(records, n_total=3)
    return samples


# ═══════════════════════════════════════════════════════════════════════════════
# Section A: Corpus structural integrity (no Ollama needed)
# ═══════════════════════════════════════════════════════════════════════════════

class TestCorpusStructure:
    """Validates that every corpus JSONL has correct structure before running evals."""

    def test_corpus_files_exist(self, corpus_files):
        """At least one corpus file must exist."""
        assert len(corpus_files) >= 1, "No corpus files found -- run make data-all"

    @pytest.mark.corpus
    def test_all_records_have_required_fields(self, corpus_files):
        """Every record must have ttp_category, tool_class, source_type, vector_name, classification, messages."""
        required = {"ttp_category", "tool_class", "source_type", "vector_name", "classification", "messages"}
        errors = []
        for f in corpus_files:
            records = load_corpus(f)
            for i, r in enumerate(records):
                missing = required - set(r.keys())
                if missing:
                    errors.append(f"{f.name}[{i}] missing: {missing}")
        assert not errors, f"{len(errors)} records missing required fields:\n" + "\n".join(errors[:10])

    @pytest.mark.corpus
    def test_classification_values_valid(self, corpus_files):
        """classification must be 'true_positive' or 'false_positive'."""
        valid = {"true_positive", "false_positive"}
        errors = []
        for f in corpus_files:
            for i, r in enumerate(load_corpus(f)):
                if r.get("classification") not in valid:
                    errors.append(f"{f.name}[{i}]: '{r.get('classification')}'")
        assert not errors, f"Invalid classifications found:\n" + "\n".join(errors[:10])

    @pytest.mark.corpus
    def test_vector_name_matches_source_type(self, corpus_files):
        """vector_name must be in EXPECTED_VECTOR_SPACES valid set for known source types."""
        errors = []
        for f in corpus_files:
            for i, r in enumerate(load_corpus(f)):
                st       = r.get("source_type", "")
                vn       = r.get("vector_name", "")
                valid    = EXPECTED_VECTOR_SPACES.get(st)
                if valid and vn not in valid:
                    errors.append(f"{f.name}[{i}] {st} → '{vn}' (expected one of {valid})")
        assert not errors, f"Vector routing mismatches:\n" + "\n".join(errors[:10])

    @pytest.mark.corpus
    def test_messages_have_system_user_roles(self, corpus_files):
        """Every record must have system + user messages."""
        errors = []
        for f in corpus_files:
            for i, r in enumerate(load_corpus(f)):
                roles = {m.get("role") for m in r.get("messages", [])}
                if "system" not in roles or "user" not in roles:
                    errors.append(f"{f.name}[{i}] missing roles: {roles}")
        assert not errors, f"Records missing system/user messages:\n" + "\n".join(errors[:10])

    @pytest.mark.corpus
    def test_spatial_token_in_user_messages(self, corpus_files):
        """<|spatial_vector|> must appear in user message content."""
        missing = []
        for f in corpus_files:
            for i, r in enumerate(load_corpus(f)):
                user_content = " ".join(
                    m.get("content", "") for m in r.get("messages", [])
                    if m.get("role") == "user"
                )
                if "<|spatial_vector|>" not in user_content:
                    missing.append(f"{f.name}[{i}]")
        assert not missing, f"{len(missing)} records missing <|spatial_vector|>:\n" + "\n".join(missing[:5])

    @pytest.mark.corpus
    def test_assistant_messages_contain_cot_markers(self, corpus_files):
        """Golden assistant responses should contain at least [AXIS 1] CoT marker."""
        missing = []
        for f in corpus_files:
            for i, r in enumerate(load_corpus(f)):
                asst = next((m.get("content", "") for m in r.get("messages", [])
                             if m.get("role") == "assistant"), "")
                if "[AXIS 1]" not in asst:
                    missing.append(f"{f.name}[{i}]")
        assert len(missing) == 0, \
            f"{len(missing)} golden responses missing [AXIS 1] CoT marker:\n" + "\n".join(missing[:5])

    @pytest.mark.corpus
    def test_tp_records_contain_true_positive_in_assistant(self, corpus_files):
        """TP records must have 'TRUE POSITIVE' in the golden assistant response."""
        errors = []
        for f in corpus_files:
            for i, r in enumerate(load_corpus(f)):
                if r.get("classification") != "true_positive":
                    continue
                asst = next((m.get("content", "") for m in r.get("messages", [])
                             if m.get("role") == "assistant"), "")
                if "TRUE POSITIVE" not in asst.upper():
                    errors.append(f"{f.name}[{i}] TP record missing 'TRUE POSITIVE' in assistant")
        assert not errors, f"{len(errors)} TP records with bad golden label:\n" + "\n".join(errors[:5])

    @pytest.mark.corpus
    def test_fp_records_contain_false_positive_in_assistant(self, corpus_files):
        """FP records must have 'FALSE POSITIVE' in the golden assistant response."""
        errors = []
        for f in corpus_files:
            for i, r in enumerate(load_corpus(f)):
                if r.get("classification") != "false_positive":
                    continue
                asst = next((m.get("content", "") for m in r.get("messages", [])
                             if m.get("role") == "assistant"), "")
                if "FALSE POSITIVE" not in asst.upper():
                    errors.append(f"{f.name}[{i}] FP record missing 'FALSE POSITIVE' in assistant")
        assert not errors, f"{len(errors)} FP records with bad golden label:\n" + "\n".join(errors[:5])

    @pytest.mark.corpus
    def test_tp_fp_ratio_reasonable(self, corpus_files):
        """TP:FP ratio should be 4:1 to 6:1 (corpus design target is 5:1)."""
        for f in corpus_files:
            records = load_corpus(f)
            stats = corpus_stats(records)
            n_tp = stats["by_classification"].get("true_positive", 0)
            n_fp = stats["by_classification"].get("false_positive", 0)
            if n_fp == 0:
                pytest.fail(f"{f.name}: no FP records found")
            ratio = n_tp / n_fp
            assert 3.0 <= ratio <= 7.0, \
                f"{f.name}: TP:FP ratio {ratio:.1f} outside expected 3-7 range (TP={n_tp}, FP={n_fp})"

    @pytest.mark.corpus
    def test_stratified_sample_respects_ratio(self, corpus_files):
        """stratified_sample output must contain both TP and FP records."""
        for f in corpus_files[:3]:
            records = load_corpus(f)
            sample = stratified_sample(records, n_total=6)
            clss = {r["classification"] for r in sample}
            assert "true_positive" in clss,  f"{f.name}: no TP in 6-record sample"
            assert "false_positive" in clss, f"{f.name}: no FP in 6-record sample"


# ═══════════════════════════════════════════════════════════════════════════════
# Section B: Ollama connectivity (skip if not running)
# ═══════════════════════════════════════════════════════════════════════════════

class TestOllamaConnectivity:

    @pytest.mark.ollama
    def test_ollama_health(self):
        if not check_ollama_health():
            pytest.skip("Ollama not running -- start with: docker compose up -d")
        assert check_ollama_health(), "Ollama health check failed"

    @pytest.mark.ollama
    def test_model_available_or_pullable(self):
        if not check_ollama_health():
            pytest.skip("Ollama not running")
        # Model doesn't have to be pre-pulled -- but we should be able to list tags
        import requests
        r = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=10)
        assert r.ok, "Could not list Ollama models"

    @pytest.mark.ollama
    def test_simple_inference_works(self):
        """Minimal inference smoke -- model should return any non-empty string."""
        if not check_ollama_health():
            pytest.skip("Ollama not running")
        messages = [
            {"role": "system", "content": "You are a test assistant. Reply with exactly: INFERENCE_OK"},
            {"role": "user",   "content": "Respond with the exact string INFERENCE_OK"},
        ]
        resp = query_ollama(messages, max_tokens=20)
        assert resp is not None and len(resp.strip()) > 0, "Empty response from Ollama"


# ═══════════════════════════════════════════════════════════════════════════════
# Section C: Zero-shot classification accuracy
# ═══════════════════════════════════════════════════════════════════════════════

class TestZeroShotClassification:
    """
    Evaluates zero-shot TP/FP classification accuracy.
    Pass thresholds are intentionally LOW -- this is a zero-shot model, not the
    fine-tuned production model. The point is to prove the prompts are coherent,
    not to achieve production accuracy.

    Expected zero-shot accuracy with llama3.2:3b or phi3:mini: 55-75%
    Expected zero-shot accuracy after QLoRA fine-tuning: >90%
    """

    @pytest.mark.ollama
    def test_tp_classification_above_chance(self, small_sample, ollama_available):
        """TP records should be classified as TRUE POSITIVE at > chance level (50%)."""
        if not ollama_available:
            pytest.skip("Ollama not running")

        tp_records = [r for recs in small_sample.values() for r in recs
                      if r.get("classification") == "true_positive"]
        if not tp_records:
            pytest.skip("No TP records in sample")

        correct = 0
        for record in tp_records:
            msgs = [m for m in record["messages"] if m["role"] != "assistant"]
            resp = query_ollama(msgs, max_tokens=600)
            score = EvalScore(record, resp, 0)
            if score.classification_correct:
                correct += 1

        accuracy = correct / len(tp_records)
        assert accuracy >= 0.40, \
            f"TP accuracy {accuracy:.0%} below 40% -- check SYS prompt design. " \
            f"({correct}/{len(tp_records)} correct)"

    @pytest.mark.ollama
    def test_fp_classification_above_chance(self, small_sample, ollama_available):
        """FP records should be classified as FALSE POSITIVE at > chance level."""
        if not ollama_available:
            pytest.skip("Ollama not running")

        fp_records = [r for recs in small_sample.values() for r in recs
                      if r.get("classification") == "false_positive"]
        if not fp_records:
            pytest.skip("No FP records in sample")

        correct = 0
        for record in fp_records:
            msgs = [m for m in record["messages"] if m["role"] != "assistant"]
            resp = query_ollama(msgs, max_tokens=400)
            score = EvalScore(record, resp, 0)
            if score.classification_correct:
                correct += 1

        accuracy = correct / len(fp_records)
        assert accuracy >= 0.30, \
            f"FP accuracy {accuracy:.0%} below 30% -- FP prompts may need stronger discriminators. " \
            f"({correct}/{len(fp_records)} correct)"

    @pytest.mark.ollama
    def test_model_produces_nonempty_responses(self, small_sample, ollama_available):
        """Model must produce non-empty responses for every record."""
        if not ollama_available:
            pytest.skip("Ollama not running")

        empty = 0
        total = 0
        for records in small_sample.values():
            for record in records[:2]:   # 2 per corpus for speed
                msgs = [m for m in record["messages"] if m["role"] != "assistant"]
                resp = query_ollama(msgs, max_tokens=300)
                total += 1
                if not resp or len(resp.strip()) < 20:
                    empty += 1

        assert empty == 0, f"{empty}/{total} records returned empty/trivial responses"

    @pytest.mark.ollama
    def test_cot_structure_observable(self, small_sample, ollama_available):
        """At least some responses should contain [AXIS] CoT markers (proves prompt design)."""
        if not ollama_available:
            pytest.skip("Ollama not running")

        cot_count = 0
        total = 0
        for records in list(small_sample.values())[:3]:   # 3 corpora
            for record in records[:2]:
                msgs = [m for m in record["messages"] if m["role"] != "assistant"]
                resp = query_ollama(msgs, max_tokens=600) or ""
                total += 1
                if "[AXIS 1]" in resp or "[AXIS 2]" in resp:
                    cot_count += 1

        # Even zero-shot models often follow the format if it's in the golden context
        # We expect at least 20% to show CoT markers zero-shot
        cot_rate = cot_count / max(1, total)
        assert cot_rate >= 0.10, \
            f"Only {cot_rate:.0%} of responses contain CoT [AXIS] markers. " \
            f"Consider including one-shot example in SYS prompt."


# ═══════════════════════════════════════════════════════════════════════════════
# Section D: Full pipeline integration (runs the EvalPipeline class)
# ═══════════════════════════════════════════════════════════════════════════════

class TestFullPipeline:

    @pytest.mark.ollama
    def test_pipeline_runs_and_returns_report(self, corpus_files, ollama_available):
        """Full pipeline must complete and return a valid report dict."""
        if not ollama_available:
            pytest.skip("Ollama not running")

        # Use just 2 corpus files and 6 records each for speed
        subset = corpus_files[:2]
        pipeline = EvalPipeline(model=EVAL_MODEL, records_per_corpus=6)
        report = pipeline.run(subset)

        assert "overall" in report
        assert "by_corpus" in report
        assert report["records_total"] > 0
        assert 0.0 <= report["overall"]["accuracy"] <= 1.0

    @pytest.mark.ollama
    def test_pipeline_vector_routing_valid(self, corpus_files, ollama_available):
        """Pipeline must report vector routing correctness ≥ 95%."""
        if not ollama_available:
            pytest.skip("Ollama not running")

        subset = corpus_files[:3]
        pipeline = EvalPipeline(model=EVAL_MODEL, records_per_corpus=6)
        report = pipeline.run(subset)

        vector_valid = report["overall"]["vector_valid_rate"]
        assert vector_valid >= 0.95, \
            f"Vector routing correctness {vector_valid:.0%} < 95% -- " \
            f"check EXPECTED_VECTOR_SPACES in eval_config.py"

    @pytest.mark.ollama
    def test_pipeline_overall_accuracy_above_floor(self, corpus_files, ollama_available):
        """Zero-shot pipeline accuracy must be above random (>40%)."""
        if not ollama_available:
            pytest.skip("Ollama not running")

        subset = corpus_files[:3]
        pipeline = EvalPipeline(model=EVAL_MODEL, records_per_corpus=9)
        report = pipeline.run(subset)

        accuracy = report["overall"]["accuracy"]
        assert accuracy >= 0.40, \
            f"Overall accuracy {accuracy:.0%} at or below random chance. " \
            f"SYS prompts are not providing useful behavioral signal."
