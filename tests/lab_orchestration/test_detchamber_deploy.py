"""
Lab orchestration -- Phase 6: Det Chamber deploy stage.

The platform must build + deploy the Det Chamber as a first-class pipeline stage,
configured per environment, and provision its (Windows + Linux) sandbox VMs via the
ansible roles. These contracts keep the deploy wired into the CI pipeline.
"""

from pathlib import Path

ORCH = Path(__file__).resolve().parents[2] / "orchestration"
INFRA = Path(__file__).resolve().parents[2] / "infrastructure"
ROOT = Path(__file__).resolve().parents[2]

DEPLOY = ORCH / "scripts" / "07b-deploy-detchamber.sh"
MASTER_CI = ORCH / "pipelines" / "master-ci.yml"
DEV = ORCH / "environments" / "dev.yaml"
PROD = ORCH / "environments" / "production.yaml"
DC_PLAY = INFRA / "ansible" / "det_chamber.yml"


def test_deploy_script_exists_and_is_bash():
    assert DEPLOY.exists(), "orchestration/scripts/07b-deploy-detchamber.sh must exist"
    t = DEPLOY.read_text()
    assert t.startswith("#!"), "must be a shell script"
    assert "set -euo pipefail" in t, "must use strict bash mode like the other deploy scripts"
    assert "ansible-playbook" in t and "det_chamber" in t, "must run the det_chamber ansible play"


def test_master_ci_has_detchamber_stage():
    t = MASTER_CI.read_text()
    assert "deploy_detchamber" in t, "master-ci.yml must declare a deploy_detchamber stage"
    assert "07b-deploy-detchamber.sh" in t, "a CI job must invoke the deploy script"


def test_environments_carry_detchamber_config():
    for env in (DEV, PROD):
        t = env.read_text()
        assert "detchamber_enabled" in t, f"{env.name} must set detchamber_enabled"
        assert "quarantine_bucket" in t, f"{env.name} must set the quarantine_bucket"


def test_build_stages_intake_image():
    t = (ROOT / "build.sh").read_text()
    assert "det_chamber" in t and "intake" in t.lower(), \
        "build.sh must build/stage the det_chamber intake image"


def test_ansible_play_includes_both_sandbox_roles():
    assert DC_PLAY.exists(), "infrastructure/ansible/det_chamber.yml must exist (DC-N5)"
    t = DC_PLAY.read_text()
    assert "det_chamber_sandbox" in t and "det_chamber_linux" in t, \
        "the play must provision both the Windows pool and the Linux sandbox"
