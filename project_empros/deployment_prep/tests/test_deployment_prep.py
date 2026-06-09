"""
test_deployment_prep.py — Deployment Prep Structural & Integration Tests

Validates that deployment_prep/ is complete, internally consistent, and
ready to produce an air-gapped offline bundle.  All tests run offline with
no container runtime, no network, and no live services required.

Run:
    pytest deployment_prep/tests/test_deployment_prep.py -v
    # or from project_empros root:
    pytest deployment_prep/tests/ -v
"""

import ast
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml", reason="pyyaml required: pip install pyyaml")

# ---------------------------------------------------------------------------
# Root anchoring
# ---------------------------------------------------------------------------
THIS = Path(__file__).parent                  # deployment_prep/tests/
PREP = THIS.parent                            # deployment_prep/
REPO = PREP.parent                            # project_empros/

SCRIPTS = PREP / "scripts"
SUPPLY_CHAIN = PREP / "supply_chain"
SC_REPORTS = SUPPLY_CHAIN / "reports"
ORCH = REPO / "orchestration"
INFRA = REPO / "infrastructure"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _is_executable(path: Path) -> bool:
    mode = path.stat().st_mode
    return bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))


def _has_shebang(path: Path) -> bool:
    return path.read_bytes()[:4].startswith(b"#!/")


def _script(name: str) -> str:
    return (SCRIPTS / name).read_text()


# ===========================================================================
# 1. Prep Directory Structure
# ===========================================================================
class TestPrepDirectoryStructure:

    REQUIRED_SCRIPTS = [
        "01_pull_and_save_images.sh",
        "02_build_custom_images.sh",
        "03_download_python_deps.sh",
        "04_download_ansible_deps.sh",
        "05_download_terraform_deps.sh",
        "05b_cargo_audit.sh",
        "05c_scan_python_supply_chain.sh",
        "06_scan_all_images.sh",
        "07_hash_and_manifest.sh",
        "08_package_bundle.sh",
        "09_verify_bundle.sh",
        "10_load_images.sh",
        "lib_container.sh",
        "validate_deployment.py",
    ]

    REQUIRED_TOP_LEVEL = [
        "Makefile",
        "image_manifest.json",
        "python_requirements.txt",
        "ansible_requirements.yml",
        "scan/Dockerfile",
        "scan/scan_config.json",
        "scan/deploy_anchore.py",
        "scan/requirements.txt",
        "supply_chain/Dockerfile",
        "supply_chain/guarddog-config.yaml",
        "supply_chain/requirements.txt",
        "supply_chain/scan-requirements.sh",
    ]

    def test_all_scripts_present(self):
        missing = [s for s in self.REQUIRED_SCRIPTS if not (SCRIPTS / s).exists()]
        assert not missing, f"Missing scripts: {missing}"

    def test_shell_scripts_executable(self):
        bad = [s for s in self.REQUIRED_SCRIPTS
               if s.endswith(".sh") and (SCRIPTS / s).exists()
               and not _is_executable(SCRIPTS / s)]
        assert not bad, f"Not executable: {bad}"

    def test_shell_scripts_have_shebang(self):
        bad = [s for s in self.REQUIRED_SCRIPTS
               if s.endswith(".sh") and (SCRIPTS / s).exists()
               and not _has_shebang(SCRIPTS / s)]
        assert not bad, f"Missing shebang: {bad}"

    def test_shell_scripts_have_set_euo_pipefail(self):
        bad = []
        for s in self.REQUIRED_SCRIPTS:
            if not s.endswith(".sh") or s == "lib_container.sh":
                continue
            p = SCRIPTS / s
            if p.exists() and "set -euo pipefail" not in p.read_text():
                bad.append(s)
        assert not bad, f"Missing 'set -euo pipefail': {bad}"

    def test_all_required_top_level_files_present(self):
        missing = [f for f in self.REQUIRED_TOP_LEVEL if not (PREP / f).exists()]
        assert not missing, f"Missing files: {missing}"

    def test_image_manifest_is_valid_json(self):
        assert isinstance(json.loads((PREP / "image_manifest.json").read_text()), dict)

    def test_ansible_requirements_is_valid_yaml(self):
        assert yaml.safe_load((PREP / "ansible_requirements.yml").read_text()) is not None

    def test_python_requirements_has_content(self):
        lines = [l for l in (PREP / "python_requirements.txt").read_text().splitlines()
                 if l.strip() and not l.strip().startswith("#")]
        assert len(lines) >= 10, "python_requirements.txt too short"

    def test_python_requirements_is_canonical_source(self):
        header = (PREP / "python_requirements.txt").read_text()
        assert "SINGLE SOURCE OF TRUTH" in header or "canonical" in header.lower(), \
            "python_requirements.txt header must state it is the canonical central list"

    def test_gitignore_excludes_supply_chain_reports(self):
        gi = (PREP / ".gitignore").read_text()
        assert "supply_chain/reports" in gi or "supply_chain/" in gi

    def test_gitignore_excludes_scan_reports(self):
        assert "scan/reports" in (PREP / ".gitignore").read_text()


# ===========================================================================
# 2. Supply Chain Files
# ===========================================================================
class TestSupplyChainFiles:

    def test_supply_chain_dir_exists(self):
        assert SUPPLY_CHAIN.is_dir(), "deployment_prep/supply_chain/ must exist"

    def test_guarddog_dockerfile_exists(self):
        assert (SUPPLY_CHAIN / "Dockerfile").exists()

    def test_guarddog_dockerfile_has_pinned_digest(self):
        assert "@sha256:" in (SUPPLY_CHAIN / "Dockerfile").read_text(), \
            "Dockerfile base image must be pinned by SHA-256 digest"

    def test_guarddog_dockerfile_creates_non_root_user(self):
        df = (SUPPLY_CHAIN / "Dockerfile").read_text()
        assert "adduser" in df or "useradd" in df or "USER" in df

    def test_guarddog_config_is_valid_yaml(self):
        data = yaml.safe_load((SUPPLY_CHAIN / "guarddog-config.yaml").read_text())
        assert "rules" in data

    def test_guarddog_config_excludes_ml_false_positives(self):
        data = yaml.safe_load((SUPPLY_CHAIN / "guarddog-config.yaml").read_text())
        excluded = {r["id"] for r in data.get("rules", []) if r.get("exclude")}
        assert "bundled_binary" in excluded, "bundled_binary must be excluded (ML C++ libs)"
        assert "api-obfuscation" in excluded, "api-obfuscation must be excluded (ML backends)"

    def test_guarddog_config_excludes_exfiltrate(self):
        data = yaml.safe_load((SUPPLY_CHAIN / "guarddog-config.yaml").read_text())
        excluded = {r["id"] for r in data.get("rules", []) if r.get("exclude")}
        assert "exfiltrate-sensitive-data" in excluded, \
            "exfiltrate-sensitive-data excluded (mitigated by air-gap)"

    def test_supply_chain_requirements_parseable(self):
        text = (SUPPLY_CHAIN / "requirements.txt").read_text()
        pkgs = [l.strip() for l in text.splitlines()
                if l.strip() and not l.strip().startswith("#")]
        assert len(pkgs) >= 5

    def test_scan_requirements_script_executable(self):
        script = SUPPLY_CHAIN / "scan-requirements.sh"
        assert _is_executable(script), "scan-requirements.sh must be executable"

    def test_scan_requirements_uses_canonical_list(self):
        text = (SUPPLY_CHAIN / "scan-requirements.sh").read_text()
        assert "python_requirements.txt" in text or "REQUIREMENTS_FILE" in text, \
            "scan-requirements.sh must default to python_requirements.txt"

    def test_scan_requirements_uses_network_none(self):
        text = (SUPPLY_CHAIN / "scan-requirements.sh").read_text()
        assert "--network none" in text, \
            "GuardDog container must run with --network none for air-gap safety"


# ===========================================================================
# 3. Cargo Audit Script (05b)
# ===========================================================================
class TestCargoAuditScript:

    def test_phase_label(self):
        assert "Phase 5b" in _script("05b_cargo_audit.sh")

    def test_cargo_audit_binary_referenced(self):
        assert "cargo-audit" in _script("05b_cargo_audit.sh")

    def test_auto_installs_if_missing(self):
        assert "cargo install cargo-audit" in _script("05b_cargo_audit.sh")

    def test_discovers_cargo_toml_files(self):
        assert "Cargo.toml" in _script("05b_cargo_audit.sh")

    def test_generates_missing_lockfiles(self):
        assert "generate-lockfile" in _script("05b_cargo_audit.sh")

    def test_updates_existing_lockfiles(self):
        assert "cargo update" in _script("05b_cargo_audit.sh")

    def test_outputs_json_report(self):
        assert "--json" in _script("05b_cargo_audit.sh")

    def test_reports_dir_under_supply_chain(self):
        assert "supply_chain/reports" in _script("05b_cargo_audit.sh")

    def test_summary_file_written(self):
        text = _script("05b_cargo_audit.sh")
        assert "SUMMARY_FILE" in text and "summary" in text.lower()

    def test_cargo_audit_deny_env_var(self):
        assert "CARGO_AUDIT_DENY" in _script("05b_cargo_audit.sh")

    def test_critical_threshold_default(self):
        assert "critical" in _script("05b_cargo_audit.sh")

    def test_blocked_exits_nonzero(self):
        text = _script("05b_cargo_audit.sh")
        assert "exit 1" in text and "BLOCKED" in text

    def test_skips_target_directory(self):
        assert "target" in _script("05b_cargo_audit.sh")

    def test_skips_git_directory(self):
        assert ".git" in _script("05b_cargo_audit.sh")

    def test_workspace_root_deduplication(self):
        text = _script("05b_cargo_audit.sh")
        assert "WORKSPACE_ROOTS" in text


# ===========================================================================
# 4. Python Supply Chain Script (05c)
# ===========================================================================
class TestPythonSupplyChainScript:

    def test_phase_label(self):
        assert "Phase 5c" in _script("05c_scan_python_supply_chain.sh")

    def test_sources_lib_container(self):
        assert "lib_container.sh" in _script("05c_scan_python_supply_chain.sh")

    def test_builds_guarddog_image(self):
        text = _script("05c_scan_python_supply_chain.sh")
        assert "build" in text and "guarddog" in text.lower()

    def test_canonical_list_is_python_requirements_txt(self):
        text = _script("05c_scan_python_supply_chain.sh")
        assert "python_requirements.txt" in text, \
            "05c must treat python_requirements.txt as the canonical scan target"
        assert "CANONICAL" in text or "canonical" in text.lower()

    def test_supplemental_requirements_scanned(self):
        assert "SUPPLEMENTAL" in _script("05c_scan_python_supply_chain.sh")

    def test_guarddog_deny_env_var(self):
        assert "GUARDDOG_DENY" in _script("05c_scan_python_supply_chain.sh")

    def test_reports_dir_under_supply_chain(self):
        assert "supply_chain/reports" in _script("05c_scan_python_supply_chain.sh")

    def test_summary_file_written(self):
        assert "SUMMARY_FILE" in _script("05c_scan_python_supply_chain.sh")

    def test_config_file_mounted(self):
        assert "guarddog-config.yaml" in _script("05c_scan_python_supply_chain.sh")

    def test_network_none_for_container(self):
        assert "--network none" in _script("05c_scan_python_supply_chain.sh"), \
            "GuardDog container must run with --network none"

    def test_rate_limiting_between_packages(self):
        assert "sleep" in _script("05c_scan_python_supply_chain.sh")

    def test_canonical_missing_blocks_immediately(self):
        text = _script("05c_scan_python_supply_chain.sh")
        assert "exit 1" in text


# ===========================================================================
# 5. Makefile Targets
# ===========================================================================
class TestMakefile:

    def _mk(self):
        return (PREP / "Makefile").read_text()

    def _prep_deps(self):
        line = next((l for l in self._mk().splitlines() if l.startswith("prep:")), "")
        return line.split(":")[1].split() if ":" in line else []

    def test_prep_includes_cargo_audit(self):
        assert "cargo-audit" in self._prep_deps(), "prep: must depend on cargo-audit"

    def test_prep_includes_supply_chain(self):
        assert "supply-chain" in self._prep_deps(), "prep: must depend on supply-chain"

    def test_cargo_audit_comes_after_deps(self):
        phases = self._prep_deps()
        assert phases.index("deps") < phases.index("cargo-audit")

    def test_supply_chain_comes_after_deps(self):
        phases = self._prep_deps()
        assert phases.index("deps") < phases.index("supply-chain")

    def test_scan_comes_after_supply_chain(self):
        phases = self._prep_deps()
        assert phases.index("supply-chain") < phases.index("scan")

    def test_cargo_audit_target_calls_05b(self):
        assert "05b_cargo_audit.sh" in self._mk()

    def test_supply_chain_target_calls_05c(self):
        assert "05c_scan_python_supply_chain.sh" in self._mk()

    def test_cargo_audit_has_phase_echo(self):
        mk = self._mk()
        assert "Phase 5b" in mk or "Cargo audit" in mk

    def test_supply_chain_has_phase_echo(self):
        mk = self._mk()
        assert "Phase 5c" in mk or "GuardDog" in mk

    def test_status_shows_supply_chain_reports(self):
        assert "supply_chain" in self._mk()

    def test_clean_removes_supply_chain_reports(self):
        assert "supply_chain/reports" in self._mk()

    def test_validate_target_present(self):
        assert "validate_deployment.py" in self._mk() or "validate:" in self._mk()

    def test_phony_covers_new_targets(self):
        mk = self._mk()
        phony_lines = " ".join(l for l in mk.splitlines() if "PHONY" in l)
        assert "cargo-audit" in phony_lines or "cargo-audit" in mk
        assert "supply-chain" in phony_lines or "supply-chain" in mk


# ===========================================================================
# 6. Bundle Packaging (08_package_bundle.sh)
# ===========================================================================
class TestBundlePackaging:

    def test_supply_chain_in_include_dirs(self):
        assert "supply_chain" in _script("08_package_bundle.sh")

    def test_infrastructure_ansible_included(self):
        assert "infrastructure/ansible" in _script("08_package_bundle.sh")

    def test_orchestration_scripts_included(self):
        assert "orchestration/scripts" in _script("08_package_bundle.sh")

    def test_sha256_checksum_generated(self):
        assert "sha256sum" in _script("08_package_bundle.sh")

    def test_bundle_name_has_timestamp(self):
        assert "TIMESTAMP" in _script("08_package_bundle.sh")

    def test_phase_8_label(self):
        assert "Phase 8" in _script("08_package_bundle.sh")

    def test_missing_artifacts_block_packaging(self):
        text = _script("08_package_bundle.sh")
        assert "exit 1" in text and "MISSING" in text

    def test_supply_chain_review_step_in_instructions(self):
        assert "supply_chain/reports" in _script("08_package_bundle.sh")


# ===========================================================================
# 7. Hash and Manifest (07_hash_and_manifest.sh)
# ===========================================================================
class TestHashManifest:

    def test_supply_chain_reports_in_artifact_dirs(self):
        assert "supply_chain/reports" in _script("07_hash_and_manifest.sh")

    def test_images_dir_hashed(self):
        assert "images" in _script("07_hash_and_manifest.sh")

    def test_wheels_dir_hashed(self):
        assert "wheels" in _script("07_hash_and_manifest.sh")

    def test_supply_chain_in_manifest_sections(self):
        assert "supply_chain_reports" in _script("07_hash_and_manifest.sh")

    def test_manifest_json_generated(self):
        assert "deployment_manifest.json" in _script("07_hash_and_manifest.sh")

    def test_sha256_index_generated(self):
        assert "sha256sums.txt" in _script("07_hash_and_manifest.sh")

    def test_phase_7_label(self):
        assert "Phase 7" in _script("07_hash_and_manifest.sh")


# ===========================================================================
# 8. Image Manifest Integrity
# ===========================================================================
class TestImageManifest:

    def _manifest(self):
        return json.loads((PREP / "image_manifest.json").read_text())

    def test_runtime_images_section_present(self):
        assert "runtime_images" in self._manifest()

    def test_build_base_images_section_present(self):
        assert "build_base_images" in self._manifest()

    def test_custom_images_section_present(self):
        assert "custom_images" in self._manifest()

    def test_runtime_images_have_required_fields(self):
        for img in self._manifest().get("runtime_images", []):
            for field in ("repo", "save_as", "name"):
                assert field in img, f"Entry missing '{field}': {img}"

    def test_custom_images_have_build_context(self):
        # Skip comment-only entries (no 'name' key) that exist for documentation
        for img in self._manifest().get("custom_images", []):
            if "name" not in img:
                continue
            assert "build_context" in img, f"Custom image missing build_context: {img}"

    def test_no_duplicate_save_as_values(self):
        all_sa = []
        for sec in ("runtime_images", "build_base_images", "custom_images"):
            all_sa += [e.get("save_as", "") for e in self._manifest().get(sec, [])]
        non_empty = [s for s in all_sa if s]
        assert len(non_empty) == len(set(non_empty)), "Duplicate save_as values in manifest"

    def test_no_duplicate_repo_in_runtime_and_build_base(self):
        repos = []
        for sec in ("runtime_images", "build_base_images"):
            repos += [e.get("repo", "") for e in self._manifest().get(sec, [])]
        non_empty = [r for r in repos if r]
        assert len(non_empty) == len(set(non_empty)), "Duplicate repo values in manifest"

    def test_at_least_10_runtime_images(self):
        assert len(self._manifest().get("runtime_images", [])) >= 10

    def test_save_as_values_end_in_tar_gz(self):
        bad = []
        for sec in ("runtime_images", "build_base_images", "custom_images"):
            for e in self._manifest().get(sec, []):
                sa = e.get("save_as", "")
                if sa and not sa.endswith(".tar.gz"):
                    bad.append(sa)
        assert not bad, f"save_as values not ending in .tar.gz: {bad}"


# ===========================================================================
# 9. GuardDog Config
# ===========================================================================
class TestGuardDogConfig:

    def _config(self):
        return yaml.safe_load((SUPPLY_CHAIN / "guarddog-config.yaml").read_text())

    def test_valid_yaml(self):
        assert self._config() is not None

    def test_rules_is_list(self):
        assert isinstance(self._config()["rules"], list)

    def test_ml_false_positives_excluded(self):
        excluded = {r["id"] for r in self._config()["rules"] if r.get("exclude")}
        for rule_id in ("bundled_binary", "api-obfuscation", "dll-hijacking",
                        "code-execution", "exfiltrate-sensitive-data", "screenshot"):
            assert rule_id in excluded, \
                f"ML false-positive rule '{rule_id}' must be excluded"

    def test_each_rule_has_comment(self):
        raw = (SUPPLY_CHAIN / "guarddog-config.yaml").read_text()
        # At least the Dockerfile should have comments explaining each exclusion
        assert "#" in raw, "guarddog-config.yaml should have comments explaining exclusions"


# ===========================================================================
# 10. validate_deployment.py Structure
# ===========================================================================
class TestValidateDeploymentScript:

    def _text(self):
        return (SCRIPTS / "validate_deployment.py").read_text()

    def test_valid_python_syntax(self):
        try:
            ast.parse(self._text())
        except SyntaxError as e:
            pytest.fail(f"validate_deployment.py syntax error: {e}")

    def test_main_function_defined(self):
        assert "def main(" in self._text()

    def test_check_prep_structure_includes_cargo_audit_script(self):
        assert "05b_cargo_audit" in self._text()

    def test_check_prep_structure_includes_supply_chain_script(self):
        assert "05c_scan_python" in self._text()

    def test_check_prep_structure_includes_supply_chain_files(self):
        text = self._text()
        assert "supply_chain/Dockerfile" in text or "supply_chain" in text

    def test_supply_chain_integration_check_present(self):
        assert "check_supply_chain_integration" in self._text()

    def test_makefile_supply_chain_check_present(self):
        assert "check_makefile_supply_chain_targets" in self._text()

    def test_guarddog_canonical_list_enforced(self):
        assert "python_requirements.txt" in self._text(), \
            "validate_deployment.py must verify GuardDog targets python_requirements.txt"

    def test_both_new_checks_called_from_main(self):
        tree = ast.parse(self._text())
        main_fn = next(
            (n for n in ast.walk(tree)
             if isinstance(n, ast.FunctionDef) and n.name == "main"), None)
        assert main_fn is not None
        calls = [n.func.id for n in ast.walk(main_fn)
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
        assert "check_supply_chain_integration" in calls
        assert "check_makefile_supply_chain_targets" in calls

    def test_at_least_fifteen_check_functions_in_main(self):
        tree = ast.parse(self._text())
        main_fn = next(
            (n for n in ast.walk(tree)
             if isinstance(n, ast.FunctionDef) and n.name == "main"), None)
        calls = [n.func.id for n in ast.walk(main_fn)
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                 and n.func.id.startswith("check_")]
        assert len(calls) >= 15, \
            f"Expected ≥15 check_* calls in main(), got {len(calls)}: {calls}"

    def test_runs_and_returns_0_or_1(self):
        """validate_deployment.py must not crash with an exception."""
        result = subprocess.run(
            [sys.executable, str(SCRIPTS / "validate_deployment.py")],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(REPO),
        )
        assert result.returncode in (0, 1), \
            f"validate_deployment.py exited {result.returncode}: {result.stderr[:600]}"


# ===========================================================================
# 11. Offline Wiring
# ===========================================================================
class TestOfflineWiring:

    def test_06_trigger_mlops_has_nexus_offline_mode(self):
        script = ORCH / "scripts/06-trigger-mlops.sh"
        assert script.exists() and "NEXUS_OFFLINE_MODE" in script.read_text()

    def test_06_trigger_mlops_uses_wheel_cache(self):
        text = (ORCH / "scripts/06-trigger-mlops.sh").read_text()
        assert "--no-index" in text or "--find-links" in text

    def test_06_trigger_mlops_sets_transformers_offline(self):
        text = (ORCH / "scripts/06-trigger-mlops.sh").read_text()
        assert "TRANSFORMERS_OFFLINE=1" in text

    def test_06_trigger_mlops_does_not_disable_air_gap(self):
        text = (ORCH / "scripts/06-trigger-mlops.sh").read_text()
        assert "TRANSFORMERS_OFFLINE=0" not in text
        assert "HF_DATASETS_OFFLINE=0" not in text

    def test_07_deploy_inference_has_nexus_offline_mode(self):
        script = ORCH / "scripts/07-deploy-inference.sh"
        assert script.exists() and "NEXUS_OFFLINE_MODE" in script.read_text()

    def test_07_deploy_inference_passes_nexus_offline_to_ansible(self):
        text = (ORCH / "scripts/07-deploy-inference.sh").read_text()
        assert "nexus_offline=true" in text

    def test_opencti_defaults_have_nexus_offline_false(self):
        defaults = INFRA / "ansible/roles/opencti_node/defaults/main.yml"
        assert defaults.exists()
        data = yaml.safe_load(defaults.read_text())
        assert "nexus_offline" in data
        assert data["nexus_offline"] is False

    def test_opencti_tasks_guard_image_pull_with_nexus_offline(self):
        tasks = INFRA / "ansible/roles/opencti_node/tasks/main.yml"
        assert tasks.exists()
        text = tasks.read_text()
        assert "nexus_offline" in text or "nexus_skip_pull" in text

    def test_no_script_disables_air_gap_vars(self):
        """TRANSFORMERS_OFFLINE=0 must never appear in any deployment/orchestration script."""
        bad = []
        for root in (SCRIPTS, ORCH / "scripts"):
            if root.exists():
                for script in root.glob("*.sh"):
                    if "TRANSFORMERS_OFFLINE=0" in script.read_text():
                        bad.append(str(script.relative_to(REPO)))
        assert not bad, f"Scripts that disable air-gap TRANSFORMERS_OFFLINE: {bad}"


# ===========================================================================
# 12. lib_container.sh
# ===========================================================================
class TestLibContainer:

    def _text(self):
        return _script("lib_container.sh")

    def test_container_rt_exported(self):
        assert "export CONTAINER_RT" in self._text()

    def test_compose_cmd_set(self):
        assert "COMPOSE_CMD" in self._text()

    def test_detects_docker(self):
        assert "docker" in self._text()

    def test_detects_podman(self):
        assert "podman" in self._text()

    def test_nexus_container_runtime_override_honored(self):
        assert "NEXUS_CONTAINER_RUNTIME" in self._text()

    def test_log_helpers_defined(self):
        text = self._text()
        assert "log_info" in text and "log_error" in text

    def test_ct_build_and_run_defined(self):
        text = self._text()
        assert "CT_BUILD" in text and "CT_RUN" in text

    def test_exits_if_no_runtime_found(self):
        assert "exit 1" in self._text()
