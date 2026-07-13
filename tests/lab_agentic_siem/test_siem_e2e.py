"""
End-to-end agentic SIEM analysis (sandbox proof).

Multiple mock SIEMs (benign + malicious data) -> detection query -> full analysis ->
definitive incident report + attack graph + contain/eradicate course of action. Tests
check the report's VALIDITY thoroughly: grounding (no hallucinated entity), benign
discipline (benign data not flagged/contained), completeness, read-only, multi-SIEM,
coverage/gap analysis, and the detection_training -> mlops spool.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import siem_lab as L          # noqa: E402
import detection_corpus as C  # noqa: E402

ATTACK = [d for d in C.LAB_DETECTIONS if d["id"] != "benign-logins"]
BENIGN = next(d for d in C.LAB_DETECTIONS if d["id"] == "benign-logins")


def _analyze(detection):
    return L.analyze(L.SIEMS[detection["siem"]], detection)


def _all_field_values(siem):
    vals = set()
    for e in siem.events:
        for k, v in e.items():
            if k != "_time" and isinstance(v, str):
                vals.add(v)
    return vals


class TestMultiSiemAnalysisProducesValidReport:
    @pytest.mark.parametrize("det", ATTACK, ids=[d["id"] for d in ATTACK])
    def test_report_is_complete_and_true_positive(self, det):
        r = _analyze(det)
        assert r["verdict"]["is_true_positive"] is True
        # report completeness (the definitive incident report sections)
        for key in ("incident_id", "summary", "timeline", "attack_graph", "blast_radius",
                    "mitre", "affected_assets", "containment"):
            assert key in r and r[key] not in (None, ""), f"missing/empty: {key}"
        ag = r["attack_graph"]
        assert ag["nodes"] and ag["edges"] and ag["mitre"], "attack graph must have nodes+edges+MITRE"
        assert r["evidence_wrapped"] is True, "SIEM rows must be untrusted-wrapped"

    @pytest.mark.parametrize("det", ATTACK, ids=[d["id"] for d in ATTACK])
    def test_grounding_every_entity_traces_to_a_siem_row(self, det):
        siem = L.SIEMS[det["siem"]]
        r = _analyze(det)
        universe = _all_field_values(siem)
        for node in r["attack_graph"]["nodes"]:
            assert node in universe, f"hallucinated attack-graph node not in SIEM data: {node}"
        for ent in r["blast_radius"]:
            assert ent in universe, f"hallucinated entity not in SIEM data: {ent}"


class TestContainmentCourseOfAction:
    def test_web_shell_contains_host_c2_dns_and_lateral(self):
        r = _analyze(C.LAB_DETECTIONS[0])  # web-shell-linux
        acts = {(s["action"], s["target"]) for s in r["containment"]["steps"]}
        assert ("isolate_host", "web-01") in acts            # epicenter endpoint
        assert ("block_ip", "203.0.113.66") in acts          # external C2
        assert ("dns_sinkhole", "evil-c2.example") in acts   # C2 domain
        assert any(t == "10.0.0.12" for _, t in acts)        # lateral internal host
        assert r["containment"]["kill_chain_closed"] in (True, False)

    def test_cloud_iam_contains_identity_instance_and_ip(self):
        r = _analyze(C.LAB_DETECTIONS[1])  # iam-abuse-aws
        steps = {(s["action"], s["target"], s["target_class"]) for s in r["containment"]["steps"]}
        assert any(a == "disable_user" and t == "svc_deploy" for a, t, _ in steps)
        assert any(t == "i-0bad1" and tc == "cloud_instance" for _, t, tc in steps)
        assert any(t == "203.0.113.99" and tc == "network" for _, t, tc in steps)


class TestBenignDiscipline:
    def test_benign_query_yields_no_attack_no_containment(self):
        r = _analyze(BENIGN)
        assert r["verdict"]["is_true_positive"] is False
        assert r["blast_radius"] == [], "benign activity must not produce malicious entities"
        assert r["containment"]["steps"] == [], "benign activity must not be contained"

    def test_benign_hosts_not_contained_in_real_incident(self):
        # db-02 (benign in the dataset) must never appear in the web-shell containment
        r = _analyze(C.LAB_DETECTIONS[0])
        assert all(s["target"] != "db-02" for s in r["containment"]["steps"])


class TestReadOnlyEnforced:
    def test_mutating_query_is_refused(self):
        siem = L.SIEMS["splunk-prod"]
        with pytest.raises(PermissionError):
            siem.run("search index=nexus_endpoint | delete", lambda e: True)

    def test_only_readonly_queries_were_recorded(self):
        _analyze(C.LAB_DETECTIONS[0])
        assert all(L.validate_readonly(q) for q in L.SIEMS["splunk-prod"].queries)


class TestCoverageGapAnalysis:
    def test_cloud_siem_flags_missing_l7_and_process_lineage(self):
        cov = L.coverage_report(L.SIEMS["elastic-cloud"])
        assert "process_lineage" in cov["gaps"]
        assert any("network-tap" in rec or "endpoint" in rec for rec in cov["sensor_recommendations"])

    def test_endpoint_siem_satisfies_process_lineage(self):
        cov = L.coverage_report(L.SIEMS["splunk-prod"])
        assert "process_lineage" in cov["satisfied"]


class TestDetectionTrainingCorpusAndMlopsSpool:
    def test_corpus_loads_real_detection_content(self):
        corpus = C.load_detection_corpus()
        assert len(corpus) >= 5, "expected real detection_training/ content"
        assert any(d["mitre"] for d in corpus), "detections should carry MITRE technique ids"

    def test_pick_is_deterministic_across_siems(self):
        corpus = C.load_detection_corpus()
        a = C.pick_detections(corpus, 5, seed=42)
        b = C.pick_detections(corpus, 5, seed=42)
        assert [x["path"] for x in a] == [x["path"] for x in b]

    def test_mlops_spool_emits_query_and_analysis_examples(self):
        corpus = C.load_detection_corpus()[:5]
        ex = C.spool_siem_analysis_examples(corpus)
        kinds = {e["kind"] for e in ex}
        assert {"query_authoring", "result_analysis"} <= kinds
        assert all(e["track"] == "siem_analysis" for e in ex)
