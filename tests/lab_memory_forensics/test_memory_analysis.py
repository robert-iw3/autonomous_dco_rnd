"""worker_memory — bridges the proven IR memory workflow to the agentic stack.

Proves: image-format routing; drives the EXISTING analyzer with --adjudicate;
consumes shared-schema findings + _status.json (TP-class via the verdict ladder)
into swarm enrichment; the WORM archive (GOVERNANCE for the privacy-sensitive image
so an operator can purge it, COMPLIANCE for the record); verified intake from the
gateway (custody re-check before analysis); and operator-gated image deletion.
Pure (stdlib only).
"""
import asyncio
import hashlib
import sys
from pathlib import Path

import pytest

WM = Path(__file__).parent.parent.parent / "services" / "worker_memory"
sys.path.insert(0, str(WM))

import memory_analysis as m  # noqa: E402
import evidence_intake as ei  # noqa: E402


def _f(ftype, target, verdict, mitre=""):
    return {"Type": ftype, "Target": target, "Verdict": verdict, "MITRE": mitre}


# ── image-format routing + analyzer invocation ──────────────────────────────
class TestRoutingAndAnalyzer:
    def test_aff4_memprocfs_raw_volatility(self):
        assert m.analysis_engine("memory_HOST.aff4") == "memprocfs"
        assert m.analysis_engine("mem.raw") == "volatility3"

    def test_drives_existing_analyzer(self):
        cmd = m.build_analyzer_command("linux", "/img/m.raw", "/reports", fetch_symbols=True)
        assert "linux/threat_hunting/Analyze-Memory-Linux.sh" in cmd
        assert "--adjudicate" in cmd and "--fetch-symbols" in cmd
        assert "windows/threat_hunting/Analyze-Memory.ps1" in \
            m.build_analyzer_command("windows", "/i.aff4", "/r")

    def test_unknown_os(self):
        with pytest.raises(m.MemoryAnalysisError):
            m.build_analyzer_command("aix", "/i", "/r")


# ── consume shared schema → enrichment ───────────────────────────────────────
class TestEnrichment:
    def test_tp_class_and_threat(self):
        findings = [_f("Injected Code", "pid:9", "True Positive", "T1055"),
                    _f("x", "y", "Indeterminate")]
        assert len(m.tp_class_findings(findings)) == 1
        assert m.memory_threat(findings) is True
        assert m.memory_threat([], {"tp_count": 2}) is True
        assert m.memory_threat([_f("x", "y", "Indeterminate")], {"tp_count": 0}) is False

    def test_enrichment_envelope(self):
        env = m.to_enrichment("INC", "h", "windows",
                              [_f("Live C2", "203.0.113.9", "Likely True Positive", "T1071")],
                              {"status": "COMPLETED", "tp_count": 1})
        assert env["source"] == "memory_forensics" and env["memory_threat"] is True
        assert env["mitre"] == ["T1071"]


# ── WORM archive: GOVERNANCE image (operator-purgeable), COMPLIANCE record ───
class TestLockModes:
    def test_image_is_governance_record_is_compliance(self):
        assert m.lock_mode_for("image") == "GOVERNANCE"
        for k in ("findings", "status", "custody"):
            assert m.lock_mode_for(k) == "COMPLIANCE"

    def test_params_reflect_kind(self):
        img = m.s3_object_lock_params("b", "k", kind="image")
        rec = m.s3_object_lock_params("b", "k", kind="findings")
        assert img["ObjectLockMode"] == "GOVERNANCE" and rec["ObjectLockMode"] == "COMPLIANCE"
        assert img["ObjectLockRetainUntilDate"].endswith("Z")

    def test_key_no_traversal(self):
        parts = m.archive_key("INC", "h/../etc", "image").split("/")
        assert parts[0] == "memory" and len(parts) == 4 and "/" not in parts[2]


# ── operator-gated image deletion (post-investigation cleanup) ───────────────
class TestOperatorDeletion:
    def test_eligible_only_when_concluded(self):
        assert m.cleanup_eligible("closed") and m.cleanup_eligible("CONCLUDED")
        assert not m.cleanup_eligible("investigating") and not m.cleanup_eligible("")

    def test_delete_params_bypass_governance(self):
        p = m.operator_delete_image_params("b", "memory/INC/h/image")
        assert p["BypassGovernanceRetention"] is True and p["Key"].endswith("/image")

    def test_audit_record(self):
        rec = m.deletion_audit_record("INC", "h", "memory/INC/h/image", "alice@soc")
        assert rec["action"] == "memory_image_deleted" and rec["operator"] == "alice@soc"


# ── verified intake (evidence_intake) ────────────────────────────────────────
class TestEvidenceIntake:
    def _handle(self, body, **over):
        h = {"incident_id": "INC", "host": "h", "os_family": "linux",
             "kind": "memory_image", "sha256": hashlib.sha256(body).hexdigest(),
             "s3_key": "memory/INC/h/image"}
        h.update(over)
        return h

    def test_custody_sha256_match(self):
        body = b"RAMIMAGE"
        ok, why = ei.verify_pulled_object(body, self._handle(body))
        assert ok and why == ""

    def test_custody_mismatch_rejected(self):
        ok, why = ei.verify_pulled_object(b"tampered", self._handle(b"original"))
        assert not ok and "sha256" in why

    def test_missing_handle_fields(self):
        ok, why = ei.verify_pulled_object(b"x", {"incident_id": "INC"})
        assert not ok and "missing" in why

    def test_unknown_kind(self):
        body = b"x"
        ok, why = ei.verify_pulled_object(body, self._handle(body, kind="rootkit"))
        assert not ok and "kind" in why

    def test_hmac_primitive_parity(self):
        body, secret = b"body", "shared"
        good = __import__("hmac").new(secret.encode(), body, hashlib.sha256).hexdigest()
        assert ei.verify_hmac(secret, body, good) and not ei.verify_hmac(secret, body, "00")


# ── orchestration: verified pull → analyze → enrich; operator cleanup ────────
class _S3:
    def __init__(self, objects=None):
        self.objects = dict(objects or {})
        self.puts, self.deletes = [], []

    def get_object(self, Bucket, Key):
        return {"Body": _Body(self.objects[Key])}

    def put_object(self, **kw):
        self.puts.append(kw)

    def delete_object(self, **kw):
        self.deletes.append(kw)


class _Body:
    def __init__(self, b):
        self._b = b

    def read(self):
        return self._b


class TestOrchestration:
    def test_verified_intake_analyzes_and_enriches(self, monkeypatch):
        import main as wm
        image = b"\x00AFF4-IMAGE\x00"
        key = "memory/INC-9/ws-7/image"
        s3 = _S3({key: image})
        monkeypatch.setattr(wm, "run_memory_analyzer",
                            lambda osf, path, hf: ([_f("Injected Code", "pid:9", "True Positive", "T1055")],
                                                   {"status": "COMPLETED", "tp_count": 1}))
        published = []

        async def _pub(s, b):
            published.append((s, b))

        handle = {"incident_id": "INC-9", "host": "ws-7", "os_family": "windows",
                  "kind": "memory_image", "sha256": hashlib.sha256(image).hexdigest(),
                  "s3_key": key}
        enr = asyncio.run(wm.handle_intake(handle, s3=s3, publish=_pub))
        assert enr["memory_threat"] is True
        assert published[0][0] == "nexus.memory.enrichment"
        # findings + status written to the COMPLIANCE record (image already in WORM)
        kinds = [p["Key"].rsplit("/", 1)[-1] for p in s3.puts]
        assert set(kinds) == {"findings", "status"}
        assert all(p["ObjectLockMode"] == "COMPLIANCE" for p in s3.puts)

    def test_tampered_object_refused(self, monkeypatch):
        import main as wm
        key = "memory/INC/h/image"
        s3 = _S3({key: b"TAMPERED"})
        handle = {"incident_id": "INC", "host": "h", "os_family": "linux",
                  "kind": "memory_image", "sha256": hashlib.sha256(b"ORIGINAL").hexdigest(),
                  "s3_key": key}

        async def _pub(s, b):
            pass

        with pytest.raises(ValueError):
            asyncio.run(wm.handle_intake(handle, s3=s3, publish=_pub))

    def test_operator_cleanup_deletes_image_with_audit(self):
        import main as wm
        s3 = _S3()
        audited = []

        async def _audit(b):
            audited.append(b)

        ev = {"incident_id": "INC", "host": "h", "operator": "alice@soc",
              "investigation_status": "closed"}
        rec = asyncio.run(wm.handle_operator_cleanup(ev, s3=s3, audit=_audit))
        assert s3.deletes and s3.deletes[0]["BypassGovernanceRetention"] is True
        assert rec["action"] == "memory_image_deleted" and audited

    def test_cleanup_refused_when_not_concluded_or_no_operator(self):
        import main as wm
        s3 = _S3()

        async def _audit(b):
            pass

        with pytest.raises(PermissionError):
            asyncio.run(wm.handle_operator_cleanup(
                {"incident_id": "I", "host": "h", "operator": "a", "investigation_status": "investigating"},
                s3=s3, audit=_audit))
        with pytest.raises(PermissionError):
            asyncio.run(wm.handle_operator_cleanup(
                {"incident_id": "I", "host": "h", "operator": "", "investigation_status": "closed"},
                s3=s3, audit=_audit))
        assert not s3.deletes
