"""
Tier2 — IaC convergence: terraform init / validate / fmt.
"""
import os
import subprocess
import pytest

from _iac_parse import has_explicit_backend

def _run(cmd, cwd, env=None):
    result = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True,
        env={**os.environ, **(env or {})},
    )
    return result

class TestTerraformInit:
    def test_init_backend_false(self, tf_dir, _plugin_cache):
        """terraform init -backend=false must succeed (providers download ok)."""
        r = _run(
            ["terraform", "init", "-backend=false", "-no-color"],
            tf_dir,
            {"TF_PLUGIN_CACHE_DIR": _plugin_cache},
        )
        assert r.returncode == 0, (
            f"terraform init failed:\nSTDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}"
        )

class TestTerraformValidate:
    def test_validate(self, tf_dir, _plugin_cache):
        """terraform validate must report no errors."""
        _run(["terraform", "init", "-backend=false", "-no-color"], tf_dir,
             {"TF_PLUGIN_CACHE_DIR": _plugin_cache})
        r = _run(["terraform", "validate", "-no-color"], tf_dir)
        assert r.returncode == 0, (
            f"terraform validate failed:\nSTDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}"
        )

class TestTerraformFmt:
    def test_fmt_clean(self, tf_dir, _plugin_cache):
        """terraform fmt -check -recursive must report no files needing formatting."""
        r = _run(
            ["terraform", "fmt", "-check", "-recursive", "-no-color"],
            tf_dir,
        )
        assert r.returncode == 0, (
            f"terraform fmt check failed — these files need formatting:\n{r.stdout}"
        )

class TestBackendDeclared:
    def test_explicit_local_backend(self, tf_src):
        """An explicit `backend \"local\" {}` block must be present."""
        assert has_explicit_backend(tf_src, "local"), (
            "No explicit 'backend \"local\" {}' found in Terraform config. "
            "On-premises VMware deployments must declare their backend explicitly."
        )