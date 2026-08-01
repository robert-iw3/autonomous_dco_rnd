"""
The boundary with the DFIR platform — what this stack accepts from it, and what it refuses.

Proves the three properties the contract rests on (sealed, flat, allow-listed), that the
verdict ladder here still matches the platform's two mirrors, that a projection maps into
the enrichment the swarm already consumes, and that the drift tracker classifies a change to
the platform's contract surface correctly.

Pure: no network, no platform checkout required (the checkout-backed test skips without one).
"""
import asyncio
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "integrations"))
sys.path.insert(0, str(ROOT / "services" / "worker_memory"))

import dfir_platform.contract as contract  # noqa: E402
import dfir_platform.platform_drift as drift  # noqa: E402
import memory_analysis as ma  # noqa: E402

KEY = "shared-out-of-band"


def _run(**over):
    run = {"run_id": 41, "incident_id": "INC-9", "investigation": "Op Quiet Harbor",
           "hostname": "ws-7", "machine_id": "8f21", "platform": "windows",
           "run_kind": "initial", "overall_status": "COMPLETED", "tp_count": 1,
           "compromised": True, "custody_verified": True,
           "collected_at": "2026-08-01T09:14:00Z", "toolkit_version": "2.4.1"}
    run.update(over)
    return run


def _finding(**over):
    f = {"finding_type": "Injected Code", "target": "pid:9", "verdict": "True Positive",
         "confidence": "High", "mitre": ["T1055"], "tier": "endpoint", "source": "memory"}
    f.update(over)
    return f


def _bundle(run=None, findings=None, key=KEY, **envelope):
    payload = {"run": run if run is not None else _run(),
               "findings": findings if findings is not None else [_finding()]}
    bundle = {"contract": contract.CONTRACT, "version": contract.VERSION,
              "produced_at": "2026-08-01T09:20:00Z", "payload": payload}
    bundle.update(envelope)
    if key is not None and "seal" not in envelope:
        bundle["seal"] = {"alg": "HMAC-SHA256", "value": contract.seal_value(payload, key)}
    return bundle


# ── sealed ───────────────────────────────────────────────────────────────────
class TestSeal:
    def test_valid_seal_accepted(self):
        assert contract.accept(_bundle(), KEY)

    def test_tampered_payload_refused(self):
        b = _bundle()
        b["payload"]["findings"][0]["verdict"] = "False Positive"
        with pytest.raises(contract.ProjectionError, match="seal"):
            contract.accept(b, KEY)

    def test_wrong_key_refused(self):
        with pytest.raises(contract.ProjectionError, match="seal"):
            contract.accept(_bundle(), "not-the-key")

    def test_unsealed_refused_by_default(self):
        b = _bundle(key=None)
        with pytest.raises(contract.ProjectionError):
            contract.accept(b, "")

    def test_unsealed_opt_out_is_explicit(self):
        assert contract.accept(_bundle(key=None), "", allow_unsealed=True)

    def test_unsupported_alg_refused(self):
        b = _bundle(seal={"alg": "none", "value": "x"})
        with pytest.raises(contract.ProjectionError, match="alg"):
            contract.accept(b, KEY)

    def test_seal_is_checked_before_structure(self):
        """An unsealed bundle is never parsed for meaning: the refusal names the seal even
        when the payload is also malformed."""
        b = _bundle(run=_run(hostname=""), key=None)
        with pytest.raises(contract.ProjectionError, match="seal"):
            contract.accept(b, KEY)


# ── flat: no nested object anywhere ──────────────────────────────────────────
class TestNoSmugglingChannel:
    def test_nested_object_in_run_refused(self):
        ok, why = contract.validate(_bundle(run=_run(machine_id={"blob": "..."}), key=None))
        assert not ok and "nested" in why

    def test_nested_object_in_finding_refused(self):
        ok, why = contract.validate(
            _bundle(findings=[_finding(target={"pid": 9, "dump": "..."})], key=None))
        assert not ok and "nested" in why

    def test_nested_object_inside_a_list_refused(self):
        ok, why = contract.validate(
            _bundle(findings=[_finding(mitre=[{"id": "T1055", "dump": "..."}])], key=None))
        assert not ok and "non-scalar" in why

    def test_oversize_string_refused(self):
        ok, why = contract.validate(
            _bundle(findings=[_finding(target="A" * (contract.MAX_STR + 1))], key=None))
        assert not ok and "exceeds" in why

    def test_unknown_payload_section_refused(self):
        b = _bundle(key=None)
        b["payload"]["regions"] = []
        ok, why = contract.validate(b)
        assert not ok and "unknown section" in why


# ── allow-listed ─────────────────────────────────────────────────────────────
class TestAllowList:
    def test_unknown_field_refused_not_ignored(self):
        ok, why = contract.validate(_bundle(findings=[_finding(raw={"strings": []})], key=None))
        assert not ok and "unknown field" in why

    @pytest.mark.parametrize("field", ["raw", "subject_path", "evidence", "offset"])
    def test_evidence_bearing_finding_fields_are_not_on_the_list(self, field):
        assert field not in contract.FINDING_FIELDS

    @pytest.mark.parametrize("field", ["bucket", "object_key", "etag", "size_bytes",
                                       "status_json", "custody_summary"])
    def test_storage_fields_are_not_on_the_list(self, field):
        assert field not in contract.RUN_FIELDS

    def test_required_fields_enforced(self):
        ok, why = contract.validate(_bundle(run=_run(incident_id=""), key=None))
        assert not ok and "incident_id" in why

    def test_wrong_contract_or_major_version_refused(self):
        ok, why = contract.validate(_bundle(key=None, contract="something.else"))
        assert not ok and "bundle" in why
        ok, why = contract.validate(_bundle(key=None, version="2.0"))
        assert not ok and "version" in why


# ── the shared verdict ladder ────────────────────────────────────────────────
class TestVerdictLadder:
    def test_off_ladder_verdict_refused(self):
        ok, why = contract.validate(_bundle(findings=[_finding(verdict="Probably Bad")], key=None))
        assert not ok and "ladder" in why

    def test_ladder_matches_the_pinned_platform_surface(self):
        """This is the third mirror of a ladder the toolkit owns. The pinned baseline is
        what keeps all three in step without importing the platform."""
        baseline = drift.load_baseline()
        assert list(contract.VERDICTS) == baseline["toolkit_verdicts"]
        assert list(contract.VERDICTS) == baseline["backend_verdicts"]

    def test_ladder_matches_the_enrichment_core(self):
        assert tuple(contract.VERDICTS) == tuple(ma.VERDICTS)


# ── identity and re-delivery ─────────────────────────────────────────────────
class TestIdentity:
    def test_id_is_stable_across_key_order(self):
        a = _bundle()
        b = _bundle()
        b["payload"] = {"findings": b["payload"]["findings"], "run": b["payload"]["run"]}
        assert contract.bundle_id(a) == contract.bundle_id(b)

    def test_id_changes_with_content(self):
        assert contract.bundle_id(_bundle()) != contract.bundle_id(
            _bundle(findings=[_finding(target="pid:11")]))


# ── the adapter into the enrichment the swarm already reads ──────────────────
class TestAdapter:
    def test_maps_into_the_toolkit_finding_schema(self):
        findings = contract.to_toolkit_findings(_bundle())
        assert findings == [{"Type": "Injected Code", "Target": "pid:9",
                             "Verdict": "True Positive", "MITRE": "T1055"}]

    def test_status_is_the_platforms_own_count(self):
        assert contract.to_status(_bundle(run=_run(tp_count=3))) == {
            "status": "COMPLETED", "tp_count": 3}

    def test_enrichment_envelope_is_unchanged(self):
        """The envelope the swarm consumes is produced by the same core as before — the
        projection only changes where the findings came from."""
        b = _bundle()
        desc = contract.descriptor(b)
        env = ma.to_enrichment(desc["incident_id"], desc["host"], desc["os_family"],
                               contract.to_toolkit_findings(b), contract.to_status(b))
        assert env["source"] == "memory_forensics"
        assert env["memory_threat"] is True
        assert env["mitre"] == ["T1055"]
        assert env["tp_count"] == 1

    def test_empty_findings_is_a_result_not_an_error(self):
        b = _bundle(run=_run(tp_count=0, compromised=False), findings=[])
        assert contract.accept(b, KEY)
        env = ma.to_enrichment("INC-9", "ws-7", "windows",
                               contract.to_toolkit_findings(b), contract.to_status(b))
        assert env["memory_threat"] is False


# ── drift classification ─────────────────────────────────────────────────────
class TestDrift:
    def _base(self):
        return {"toolkit_verdicts": list(contract.VERDICTS),
                "backend_verdicts": list(contract.VERDICTS),
                "models": {m: sorted(f) for m, f in drift.MAPPED_FIELDS.items()},
                "routes": ["findings", "runs"]}

    def test_clean_when_nothing_moved(self):
        base = self._base()
        assert drift.compare(base, base) == {"affecting": [], "incidental": []}

    def test_changed_ladder_is_contract_affecting(self):
        base = self._base()
        now = json.loads(json.dumps(base))
        now["toolkit_verdicts"].append("Confirmed")
        now["backend_verdicts"].append("Confirmed")
        assert drift.compare(base, now)["affecting"]

    def test_diverged_mirrors_are_contract_affecting(self):
        base = self._base()
        now = json.loads(json.dumps(base))
        now["backend_verdicts"] = now["backend_verdicts"][:-1]
        assert any("diverged" in a for a in drift.compare(base, now)["affecting"])

    def test_renamed_mapped_field_is_contract_affecting(self):
        base = self._base()
        now = json.loads(json.dumps(base))
        now["models"]["Finding"] = [f for f in now["models"]["Finding"] if f != "verdict"]
        now["models"]["Finding"].append("adjudication")
        result = drift.compare(base, now)
        assert any("verdict" in a for a in result["affecting"])

    def test_added_unmapped_field_is_incidental(self):
        base = self._base()
        now = json.loads(json.dumps(base))
        now["models"]["Finding"].append("analyst_priority")
        result = drift.compare(base, now)
        assert not result["affecting"] and result["incidental"]

    def test_route_change_is_incidental(self):
        base = self._base()
        now = json.loads(json.dumps(base))
        now["routes"].append("campaigns/")
        result = drift.compare(base, now)
        assert not result["affecting"] and result["incidental"]

    def test_pinned_baseline_still_matches_a_real_checkout(self):
        """Runs only where a platform checkout is present. This is the test that turns the
        platform's own development into a signal here rather than a surprise."""
        try:
            current = drift.fingerprint(drift.DEFAULT_PLATFORM)
        except drift.PlatformNotFound:
            pytest.skip("no DFIR platform checkout on this host")
        result = drift.compare(drift.load_baseline(), current)
        assert not result["affecting"], result["affecting"]


# ── the worker: projection → enrichment on the bus ───────────────────────────
class _Bus:
    def __init__(self):
        self.published = []

    async def publish(self, subject, body):
        self.published.append((subject, json.loads(body)))

    def subjects(self):
        return [s for s, _ in self.published]


class _Source:
    """A transport stand-in: yields what it holds, records what was acknowledged."""

    def __init__(self, items):
        self.items = list(items)
        self.acked = []

    def poll(self):
        return iter(self.items)

    def ack(self, ref):
        self.acked.append(ref)


class TestWorker:
    def _raw(self, bundle):
        return json.dumps(bundle).encode()

    def test_projection_becomes_enrichment(self):
        import main as wm
        bus = _Bus()
        env = asyncio.run(wm.handle_projection(self._raw(_bundle()), publish=bus.publish,
                                               hmac_key=KEY))
        assert bus.subjects() == ["nexus.memory.enrichment"]
        assert env["memory_threat"] is True
        assert env["projection_id"] and env["platform_run_id"] == 41
        assert env["custody_verified"] is True

    def test_refused_bundle_goes_to_the_dlq(self):
        import main as wm
        bus = _Bus()
        bad = _bundle()
        bad["payload"]["run"]["machine_id"] = {"blob": "..."}
        bad["seal"]["value"] = contract.seal_value(bad["payload"], KEY)
        with pytest.raises(contract.ProjectionError):
            asyncio.run(wm.handle_projection(self._raw(bad), publish=bus.publish,
                                             dlq=bus.publish, hmac_key=KEY))
        assert bus.subjects() == ["nexus.dlq.memory_projection"]
        assert "nested" in bus.published[0][1]["reason"]

    def test_tampered_bundle_never_reaches_the_swarm(self):
        import main as wm
        bus = _Bus()
        tampered = _bundle()
        tampered["payload"]["findings"][0]["verdict"] = "False Positive"
        with pytest.raises(contract.ProjectionError):
            asyncio.run(wm.handle_projection(self._raw(tampered), publish=bus.publish,
                                             dlq=bus.publish, hmac_key=KEY))
        assert "nexus.memory.enrichment" not in bus.subjects()

    def test_redelivery_publishes_once(self):
        import main as wm
        bus = _Bus()
        raw = self._raw(_bundle())
        ledger = set()
        first = asyncio.run(wm.handle_projection(raw, publish=bus.publish, seen=ledger,
                                                 hmac_key=KEY))
        second = asyncio.run(wm.handle_projection(raw, publish=bus.publish, seen=ledger,
                                                  hmac_key=KEY))
        assert first is not None and second is None
        assert bus.subjects() == ["nexus.memory.enrichment"]

    def test_drain_acks_only_what_it_resolved(self):
        import main as wm
        bus = _Bus()
        good, bad = self._raw(_bundle()), b"{not json"
        source = _Source([("good.json", good), ("bad.json", bad)])
        published = asyncio.run(wm.drain(source, publish=bus.publish, dlq=bus.publish,
                                         hmac_key=KEY))
        assert published == 1
        # Both are released: the good one published, the bad one recorded in the DLQ.
        assert source.acked == ["good.json", "bad.json"]

    def test_publish_failure_leaves_the_bundle_held(self):
        import main as wm

        async def _boom(subject, body):
            raise RuntimeError("bus down")

        source = _Source([("good.json", self._raw(_bundle()))])
        published = asyncio.run(wm.drain(source, publish=_boom, hmac_key=KEY))
        assert published == 0 and source.acked == []

    def test_seen_ledger_survives_a_restart(self, tmp_path):
        import main as wm
        path = tmp_path / "seen"
        ledger = wm.SeenLedger(str(path))
        ledger.add("abc123")
        assert "abc123" in wm.SeenLedger(str(path))
