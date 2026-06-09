"""
Tier-2 -- Terraform convergence checks for the Azure deploy/ stacks.

Convergence is split into two layers:

  - `terraform init` + `terraform validate`:  runs here in CI (no credentials
    needed; validates provider schema, resource types, and interpolation).
  - `terraform fmt -check`:                   style gate, also runs here.
  - `terraform apply`:                        deferred to the gated real-Azure run
    (requires live credentials and subscription access).
"""
import os
import shutil
import subprocess
import pytest

pytestmark = pytest.mark.tier2

@pytest.fixture
def tf_workdir(tf_dir, tmp_path, _plugin_cache):
    if not shutil.which("terraform"):
        pytest.skip("terraform not installed (present in the tier2 container)")
    dst = tmp_path / "tf"
    shutil.copytree(tf_dir, dst)
    return dst

def _tf(workdir, *args, cache=None):
    env = {**os.environ}
    if cache:
        env["TF_PLUGIN_CACHE_DIR"] = cache
    # Suppress colour output and prevent interactive prompts.
    env.setdefault("TF_CLI_ARGS", "-no-color")
    return subprocess.run(
        ["terraform", *args],
        cwd=workdir, env=env,
        capture_output=True, text=True,
    )

class TestTerraformConverges:
    def test_init_and_validate(self, tf_workdir, connector_name, _plugin_cache):
        r = _tf(tf_workdir, "init", "-no-color", "-input=false",
                "-backend=false", cache=_plugin_cache)
        assert r.returncode == 0, (
            f"{connector_name}: terraform init failed\n{r.stderr[-2000:]}"
        )
        r = _tf(tf_workdir, "validate", "-no-color")
        assert r.returncode == 0, (
            f"{connector_name}: terraform validate failed\n{r.stderr[-2000:]}"
        )

    def test_fmt_clean(self, tf_dir, connector_name):
        if not shutil.which("terraform"):
            pytest.skip("terraform not installed")
        r = subprocess.run(
            ["terraform", "fmt", "-check", "-recursive", tf_dir],
            capture_output=True, text=True,
        )
        assert r.returncode == 0, (
            f"{connector_name}: `terraform fmt` would reformat:\n{r.stdout}"
        )