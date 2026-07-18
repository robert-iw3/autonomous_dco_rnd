"""
Track 10 (SIEM Analysis) corpus builder — detection_training/ into training signal.

Proves the mlops spooler side of WS-J: real rules parse across all three source
dialects (Sigma / KQL / YARA-L) with their MITRE + false-positive metadata, the
three SFT example families are well-formed chat records, the held-out split is
stable and disjoint from the SFT set (the leakage control the `siem_analysis`
benchmark depends on), and the spool writes both output files.
"""
import importlib.util as ilu
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent.parent
SCRIPTS = ROOT / "mlops" / "scripts"

spec = ilu.spec_from_file_location("siem_analysis_track", str(SCRIPTS / "siem_analysis_track.py"))
track = ilu.module_from_spec(spec)
sys.modules["siem_analysis_track"] = track
spec.loader.exec_module(track)

DETECTIONS = track.load_detections()


class TestCorpusLoading:
    def test_all_three_sources_parse(self):
        dialects = {d["dialect"] for d in DETECTIONS}
        assert {"sigma", "kql", "yaral"} <= dialects
        assert len(DETECTIONS) >= 300, "expected the real detection_training/ volume"

    def test_rules_carry_mitre_and_metadata(self):
        with_mitre = [d for d in DETECTIONS if d["mitre"]]
        assert len(with_mitre) >= len(DETECTIONS) // 2
        assert all(d["title"] for d in DETECTIONS)
        assert all(d["path"].startswith("detection_training/") for d in DETECTIONS)

    def test_sigma_parser_extracts_structured_fields(self):
        sigma = next(d for d in DETECTIONS if d["dialect"] == "sigma"
                     and "AS-REP" in d["title"])
        assert sigma["product"] == "windows"
        assert "T1558.004" in sigma["mitre"]
        assert sigma["fp_notes"], "falsepositives block must be captured"
        assert "selection" in sigma["logic"]


class TestHoldoutSplit:
    def test_split_is_stable_and_disjoint(self):
        train1, held1 = track.split_holdout(DETECTIONS)
        train2, held2 = track.split_holdout(DETECTIONS)
        assert [d["path"] for d in held1] == [d["path"] for d in held2]
        assert not ({d["path"] for d in train1} & {d["path"] for d in held1})

    def test_holdout_fraction_is_sane(self):
        _, held = track.split_holdout(DETECTIONS)
        frac = len(held) / len(DETECTIONS)
        assert 0.03 <= frac <= 0.2, f"holdout fraction {frac:.2f} out of range"

    def test_leakage_control_no_heldout_rule_in_sft(self):
        train, held = track.split_holdout(DETECTIONS)
        examples = [ex for det in train[:50] for ex in track.build_examples(det)]
        heldout_paths = {d["path"] for d in held}
        assert all(ex["source_path"] not in heldout_paths for ex in examples)


class TestExampleFamilies:
    def test_three_families_well_formed(self):
        exs = track.build_examples(DETECTIONS[0])
        assert [e["kind"] for e in exs] == ["detection_comprehension",
                                           "query_authoring", "result_analysis"]
        for e in exs:
            assert e["track"] == "siem_analysis"
            roles = [m["role"] for m in e["messages"]]
            assert roles == ["system", "user", "assistant"]
            assert all(m["content"].strip() for m in e["messages"])

    def test_result_analysis_answer_is_grounded_json(self):
        det = next(d for d in DETECTIONS if d["mitre"])
        analysis = next(e for e in track.build_examples(det)
                        if e["kind"] == "result_analysis")
        finding = json.loads(analysis["messages"][2]["content"])
        assert finding["verdict"] == "true_positive"
        assert finding["mitre_techniques"] == det["mitre"]
        assert finding["affected_entities"], "the finding must name affected entities"
        prompt = analysis["messages"][1]["content"]
        for entity in finding["affected_entities"]:
            assert entity in prompt, f"entity {entity} not grounded in the prompt rows"

    def test_representative_rows_are_deterministic(self):
        det = DETECTIONS[0]
        assert track._representative_rows(det) == track._representative_rows(det)


class TestSpool:
    def test_spool_writes_sft_and_eval_files(self, tmp_path):
        counts = track.spool(train_out=tmp_path / "sft.jsonl",
                             eval_out=tmp_path / "eval.jsonl")
        assert counts["sft_examples"] == counts["train_rules"] * 3
        assert counts["eval_cases"] == counts["heldout_rules"] > 0
        sft = [json.loads(l) for l in (tmp_path / "sft.jsonl").read_text().splitlines()]
        cases = [json.loads(l) for l in (tmp_path / "eval.jsonl").read_text().splitlines()]
        assert len(sft) == counts["sft_examples"]
        sft_paths = {r["source_path"] for r in sft}
        eval_paths = {c["source_path"] for c in cases}
        assert not (sft_paths & eval_paths), "held-out rules leaked into the SFT set"
        assert all(c["classification"] == "true_positive" for c in cases)

    def test_registry_declares_the_benchmark(self):
        import tomllib
        reg = tomllib.loads((ROOT / "mlops" / "benchmarks" / "registry.toml").read_text())
        bench = reg["benchmarks"]["siem_analysis"]
        assert bench["axis"] == "siem_analysis" and bench["gates"] is True
        assert bench["scorer"] == "accuracy"
