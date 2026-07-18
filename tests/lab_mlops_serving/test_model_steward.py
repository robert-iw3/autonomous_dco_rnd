"""
Registry/promotion contract - publisher and steward against the same seam.

The training plane's publisher (mlops/scripts/13_publish_model.py) and the
serving plane's steward (services/model_steward/) share exactly one contract:
the registry bucket layout and manifest.json. This lab proves the seam offline:

  * manifest round-trip - a manifest the publisher builds is accepted by the
    steward's validator, and both sides agree on the required-gate vocabulary;
  * rejection - missing gates, absent scores, bad SHA-384, unknown quant, and
    tampered/unvouched artifacts are all refused (no scores, no swap);
  * promotion flow - verify -> pin -> probe with rollback re-pin restoring the
    byte-identical prior version on probe failure;
  * fail-open serving - boot with the registry unreachable keeps serving the
    pinned local version.
"""
import importlib.util as ilu
import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent.parent
SCRIPTS = PROJECT_ROOT / "mlops" / "scripts"
STEWARD_DIR = PROJECT_ROOT / "services" / "model_steward"
sys.path.insert(0, str(STEWARD_DIR))

import manifest as mf          # noqa: E402  (steward's verification side)
import steward as st           # noqa: E402


def _load_publisher():
    spec = ilu.spec_from_file_location("publish_model", str(SCRIPTS / "13_publish_model.py"))
    mod = ilu.module_from_spec(spec)
    sys.modules["publish_model"] = mod
    spec.loader.exec_module(mod)
    return mod


pub = _load_publisher()


def _artifact_dir(tmp_path, content=b"weights-v1"):
    d = tmp_path / "artifacts"
    d.mkdir(exist_ok=True)
    (d / "adapter_model.safetensors").write_bytes(content)
    (d / "adapter_config.json").write_text('{"r": 16}')
    return d


def _manifest(tmp_path, **overrides):
    d = _artifact_dir(tmp_path)
    m = pub.build_manifest(
        model_id="model_c", version="20260718T1400-c41",
        base_model={"hf_id": "meta-llama/Llama-3.1-8B-Instruct", "revision": "abc"},
        artifact_type="lora_adapter", quant="nf4-4bit", artifact_dir=d,
        gate_scores={"hard_negative_heldout": 0.97, "tier0_canary": 0.9},
        gates_passed=["tier0", "garak", "pyrit", "regression", "alignment"],
        rsi_cycle_id="cycle-1", bench_versions={"hard_negative_heldout": "f" * 96},
    )
    m.update(overrides)
    return d, m


# ── round-trip: publisher builds, steward accepts ────────────────────────────

class TestManifestRoundTrip:
    def test_publisher_manifest_passes_both_validators(self, tmp_path):
        _, m = _manifest(tmp_path)
        assert pub.validate_manifest(m) == []
        assert mf.validate_manifest(m) == []

    def test_both_planes_share_the_contract_vocabulary(self):
        assert pub.MANIFEST_SCHEMA == mf.MANIFEST_SCHEMA
        assert pub.REQUIRED_GATES == mf.REQUIRED_GATES
        assert pub.MODEL_IDS == mf.MODEL_IDS
        assert pub.ARTIFACT_TYPES == mf.ARTIFACT_TYPES
        assert pub.VALID_QUANT == mf.VALID_QUANT
        assert pub.VERSION_RE.pattern == mf.VERSION_RE.pattern

    def test_artifacts_verify_against_manifest(self, tmp_path):
        d, m = _manifest(tmp_path)
        (d / "manifest.json").write_text(json.dumps(m))
        ok, errors = mf.verify_artifacts(m, d)
        assert ok, errors

    def test_serialized_roundtrip(self, tmp_path):
        _, m = _manifest(tmp_path)
        assert mf.validate_manifest(json.loads(json.dumps(m))) == []


# ── rejection: no scores, no swap ────────────────────────────────────────────

class TestManifestRejection:
    def test_missing_gate_refused(self, tmp_path):
        _, m = _manifest(tmp_path, gates_passed=["tier0", "garak", "pyrit"])
        errs = mf.validate_manifest(m)
        assert any("gates_passed missing" in e for e in errs)
        assert any("regression" in e for e in errs)

    def test_empty_gate_scores_refused(self, tmp_path):
        _, m = _manifest(tmp_path, gate_scores={})
        assert any("gate_scores" in e for e in mf.validate_manifest(m))

    def test_unknown_quant_refused(self, tmp_path):
        _, m = _manifest(tmp_path, quant="int3-experimental")
        assert any("quant" in e for e in mf.validate_manifest(m))

    def test_malformed_version_refused(self, tmp_path):
        _, m = _manifest(tmp_path, version="latest")
        assert any("version" in e for e in mf.validate_manifest(m))

    def test_bad_digest_format_refused(self, tmp_path):
        _, m = _manifest(tmp_path)
        m["sha384_manifest"]["adapter_config.json"] = "deadbeef"
        assert any("SHA-384" in e for e in mf.validate_manifest(m))

    def test_missing_provenance_refused(self, tmp_path):
        _, m = _manifest(tmp_path, rsi_cycle_id="")
        assert any("rsi_cycle_id" in e for e in mf.validate_manifest(m))

    def test_tampered_artifact_fails_verification(self, tmp_path):
        d, m = _manifest(tmp_path)
        (d / "adapter_model.safetensors").write_bytes(b"tampered")
        ok, errors = mf.verify_artifacts(m, d)
        assert not ok and any("mismatch" in e for e in errors)

    def test_missing_artifact_fails_verification(self, tmp_path):
        d, m = _manifest(tmp_path)
        (d / "adapter_model.safetensors").unlink()
        ok, errors = mf.verify_artifacts(m, d)
        assert not ok and any("missing from pull" in e for e in errors)

    def test_unvouched_file_fails_verification(self, tmp_path):
        d, m = _manifest(tmp_path)
        (d / "extra_payload.bin").write_bytes(b"who put this here")
        ok, errors = mf.verify_artifacts(m, d)
        assert not ok and any("not vouched" in e for e in errors)


# ── local store: pin / rollback / prune ──────────────────────────────────────

def _stage_version(store, model_id, version, content):
    vdir = store.version_dir(model_id, version)
    vdir.mkdir(parents=True)
    (vdir / "weights.bin").write_bytes(content)
    return vdir


class TestLocalStore:
    def test_pin_and_current(self, tmp_path):
        store = st.LocalStore(tmp_path)
        _stage_version(store, "model_c", "20260701T0900-aa1", b"v1")
        store.pin("model_c", "20260701T0900-aa1")
        assert store.current_version("model_c") == "20260701T0900-aa1"
        assert (store.current_path("model_c") / "weights.bin").read_bytes() == b"v1"

    def test_rollback_restores_byte_identical_prior_version(self, tmp_path):
        store = st.LocalStore(tmp_path)
        _stage_version(store, "model_c", "20260701T0900-aa1", b"known-good-bytes")
        _stage_version(store, "model_c", "20260718T1400-bb2", b"candidate-bytes")
        store.pin("model_c", "20260701T0900-aa1")
        store.pin("model_c", "20260718T1400-bb2")
        rolled = store.rollback("model_c")
        assert rolled == "20260701T0900-aa1"
        assert (store.current_path("model_c") / "weights.bin").read_bytes() \
            == b"known-good-bytes"

    def test_rollback_without_prior_version_is_refused(self, tmp_path):
        store = st.LocalStore(tmp_path)
        _stage_version(store, "model_c", "20260701T0900-aa1", b"v1")
        store.pin("model_c", "20260701T0900-aa1")
        assert store.rollback("model_c") is None

    def test_pin_unknown_version_raises(self, tmp_path):
        store = st.LocalStore(tmp_path)
        with pytest.raises(FileNotFoundError):
            store.pin("model_c", "20260701T0900-zz9")

    def test_prune_keeps_pinned_and_recent(self, tmp_path):
        store = st.LocalStore(tmp_path)
        versions = [f"2026070{i}T0900-v{i}" for i in range(1, 6)]
        for v in versions:
            _stage_version(store, "model_c", v, b"x")
        store.pin("model_c", versions[0])
        store.pin("model_c", versions[4])
        removed = store.prune("model_c", keep=3)
        remaining = store.list_versions("model_c")
        assert versions[0] in remaining and versions[4] in remaining
        assert len(remaining) == 3 and len(removed) == 2


# ── promotion flow ───────────────────────────────────────────────────────────

def _fetch_from(src_dir, manifest):
    """Registry stand-in: fetch copies the staged artifact dir + manifest."""
    def fetch(model_id, version, dest):
        dest = Path(dest)
        for p in src_dir.iterdir():
            (dest / p.name).write_bytes(p.read_bytes())
        (dest / "manifest.json").write_text(json.dumps(manifest))
    return fetch


class TestPromotionFlow:
    def _promote(self, tmp_path, manifest_overrides=None, probe_ok=True):
        d, m = _manifest(tmp_path)
        m.update(manifest_overrides or {})
        store = st.LocalStore(tmp_path / "store")
        activations = []

        def activate(model_id, current_path):
            activations.append((model_id, Path(current_path).resolve().name))
            return probe_ok

        payload = {"schema": "models_promote_v1", "model_id": "model_c",
                   "version": m["version"], "bucket": "nexus-model-registry"}
        ack = st.handle_promotion(payload, store, _fetch_from(d, m), activate)
        return store, ack, activations

    def test_verified_promotion_is_acked_and_serving(self, tmp_path):
        store, ack, activations = self._promote(tmp_path)
        assert ack["subject"] == st.SUBJECT_PROMOTED
        assert store.current_version("model_c") == "20260718T1400-c41"
        assert activations, "the serving unit must be restarted"

    def test_unverifiable_manifest_is_rejected_and_not_pinned(self, tmp_path):
        store, ack, activations = self._promote(
            tmp_path, {"gates_passed": ["tier0"]})
        assert ack["subject"] == st.SUBJECT_REJECTED
        assert "unverifiable" in ack["body"]["reason"]
        assert store.current_version("model_c") is None
        assert not activations, "an unverified version must never be activated"

    def test_probe_failure_rolls_back_to_prior_version(self, tmp_path):
        d, m = _manifest(tmp_path)
        store = st.LocalStore(tmp_path / "store")
        _stage_version(store, "model_c", "20260701T0900-aa1", b"known-good")
        store.pin("model_c", "20260701T0900-aa1")

        calls = {"n": 0}

        def activate(model_id, current_path):
            calls["n"] += 1
            return calls["n"] > 1   # candidate probe fails, rollback probe passes

        payload = {"schema": "models_promote_v1", "model_id": "model_c",
                   "version": m["version"]}
        ack = st.handle_promotion(payload, store, _fetch_from(d, m), activate)
        assert ack["subject"] == st.SUBJECT_REJECTED
        assert ack["body"]["rolled_back_to"] == "20260701T0900-aa1"
        assert store.current_version("model_c") == "20260701T0900-aa1"
        assert (store.current_path("model_c") / "weights.bin").read_bytes() == b"known-good"

    def test_registry_pull_failure_is_rejected(self, tmp_path):
        store = st.LocalStore(tmp_path / "store")

        def fetch(model_id, version, dest):
            raise ConnectionError("registry unreachable")

        payload = {"schema": "models_promote_v1", "model_id": "model_c",
                   "version": "20260718T1400-c41"}
        ack = st.handle_promotion(payload, store, fetch, lambda m, p: True)
        assert ack["subject"] == st.SUBJECT_REJECTED
        assert "pull failed" in ack["body"]["reason"]

    def test_manifest_identity_mismatch_is_rejected(self, tmp_path):
        store, ack, _ = self._promote(tmp_path, {"model_id": "model_b"})
        assert ack["subject"] == st.SUBJECT_REJECTED

    def test_malformed_promote_message_is_rejected(self, tmp_path):
        store = st.LocalStore(tmp_path / "store")
        ack = st.handle_promotion({"schema": "wrong"}, store,
                                  lambda *a: None, lambda m, p: True)
        assert ack["subject"] == st.SUBJECT_REJECTED
        assert "malformed" in ack["body"]["reason"]


# ── fail-open serving: boot with the registry down ───────────────────────────

class TestBootWithRegistryDown:
    def test_pinned_local_version_keeps_serving(self, tmp_path):
        store = st.LocalStore(tmp_path)
        _stage_version(store, "model_c", "20260701T0900-aa1", b"v1")
        store.pin("model_c", "20260701T0900-aa1")
        status = st.boot_status(store, registry_reachable=False)
        assert status["registry_reachable"] is False
        assert status["models"]["model_c"]["serving"] is True
        assert status["models"]["model_c"]["current"] == "20260701T0900-aa1"

    def test_empty_store_reports_not_serving_without_crashing(self, tmp_path):
        status = st.boot_status(st.LocalStore(tmp_path), registry_reachable=False)
        assert all(not m["serving"] for m in status["models"].values())


# ── publisher-side gates ─────────────────────────────────────────────────────

class TestPublisherGates:
    def test_frozen_judge_calibration_blocks_publish(self, tmp_path):
        cal = tmp_path / "judge_calibration.json"
        cal.write_text(json.dumps({"kappa": 0.3, "threshold": 0.6, "frozen": True}))
        frozen, reason = pub.judge_promotion_frozen(cal)
        assert frozen and "recalibrate" in reason

    def test_absent_calibration_is_inert(self, tmp_path):
        frozen, _ = pub.judge_promotion_frozen(tmp_path / "nope.json")
        assert not frozen

    def test_gate_scores_looked_up_by_cycle_id(self, tmp_path):
        ledger = tmp_path / "rsi_ledger_v1.jsonl"
        rows = [{"cycle_id": "c1", "gate_scores": {"m": 0.9}, "deployed": True},
                {"cycle_id": "c2", "gate_scores": {"m": 0.95}, "deployed": True}]
        ledger.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
        assert pub.gate_scores_from_ledger("c1", ledger) == {"m": 0.9}
        assert pub.gate_scores_from_ledger("missing", ledger) == {}

    def test_promote_payload_locates_the_version(self, tmp_path):
        _, m = _manifest(tmp_path)
        payload = pub.promote_payload(m, bucket="nexus-model-registry")
        assert payload["schema"] == "models_promote_v1"
        assert payload["prefix"] == "model_c/20260718T1400-c41/"
        parsed, reason = st.parse_promote(payload)
        assert parsed is not None, reason
